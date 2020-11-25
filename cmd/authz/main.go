package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	xormadapter "github.com/casbin/xorm-adapter"
	kitprometheus "github.com/go-kit/kit/metrics/prometheus"
	"github.com/mainflux/mainflux"
	"github.com/mainflux/mainflux/authn"
	api "github.com/mainflux/mainflux/authn/api"
	"github.com/mainflux/mainflux/authn/postgres"
	"github.com/mainflux/mainflux/authz"
	grpcapi "github.com/mainflux/mainflux/authz/api/grpc"
	httpapi "github.com/mainflux/mainflux/authz/api/http"
	"github.com/mainflux/mainflux/logger"
	"github.com/opentracing/opentracing-go"
	stdprometheus "github.com/prometheus/client_golang/prometheus"
	jconfig "github.com/uber/jaeger-client-go/config"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	defLogLevel      = "error"
	defDBHost        = "localhost"
	defDBPort        = "5432"
	defDBUser        = "mainflux"
	defDBPass        = "mainflux"
	defDB            = "authz"
	defDBSSLMode     = "disable"
	defDBSSLCert     = ""
	defDBSSLKey      = ""
	defDBSSLRootCert = ""
	defHTTPPort      = "8189"
	defGRPCPort      = "8187"
	defSecret        = "authz"
	defServerCert    = ""
	defServerKey     = ""
	defJaegerURL     = ""

	envLogLevel      = "MF_AUTHZ_LOG_LEVEL"
	envDBHost        = "MF_AUTHZ_DB_HOST"
	envDBPort        = "MF_AUTHZ_DB_PORT"
	envDBUser        = "MF_AUTHZ_DB_USER"
	envDBPass        = "MF_AUTHZ_DB_PASS"
	envDB            = "MF_AUTHZ_DB"
	envDBSSLMode     = "MF_AUTHZ_DB_SSL_MODE"
	envDBSSLCert     = "MF_AUTHZ_DB_SSL_CERT"
	envDBSSLKey      = "MF_AUTHZ_DB_SSL_KEY"
	envDBSSLRootCert = "MF_AUTHZ_DB_SSL_ROOT_CERT"
	envHTTPPort      = "MF_AUTHZ_HTTP_PORT"
	envGRPCPort      = "MF_AUTHZ_GRPC_PORT"
	envSecret        = "MF_AUTHZ_SECRET"
	envServerCert    = "MF_AUTHZ_SERVER_CERT"
	envServerKey     = "MF_AUTHZ_SERVER_KEY"
	envJaegerURL     = "MF_JAEGER_URL"
)

type config struct {
	logLevel   string
	dbConfig   postgres.Config
	httpPort   string
	grpcPort   string
	secret     string
	serverCert string
	serverKey  string
	jaegerURL  string
	resetURL   string
}

func main() {
	cfg := loadConfig()

	logger, err := logger.New(os.Stdout, cfg.logLevel)
	if err != nil {
		log.Fatalf(err.Error())
	}

	dbConfig := cfg.dbConfig
	connStr := fmt.Sprintf("user=%s password=%s host=%s port=%s sslmode=disable", dbConfig.User, dbConfig.Pass, dbConfig.Host, dbConfig.Port)
	adapter, err := xormadapter.NewAdapter("postgres", connStr)
	if err != nil {
		log.Fatalf(err.Error())
	}

	m, err := model.NewModelFromString("model.conf")
	if err != nil {
		log.Fatalf(err.Error())
	}

	enf, err := casbin.NewSyncedEnforcer(m, adapter)
	if err != nil {
		log.Fatalf(err.Error())
	}

	tracer, closer := initJaeger("authz", cfg.jaegerURL, logger)
	defer closer.Close()

	svc := newService(enf, cfg.secret, logger)
	errs := make(chan error, 2)

	go startHTTPServer(tracer, svc, cfg.httpPort, cfg.serverCert, cfg.serverKey, logger, errs)
	go startGRPCServer(tracer, svc, cfg.grpcPort, cfg.serverCert, cfg.serverKey, logger, errs)

	go func() {
		c := make(chan os.Signal)
		signal.Notify(c, syscall.SIGINT)
		errs <- fmt.Errorf("%s", <-c)
	}()

	err = <-errs
	logger.Error(fmt.Sprintf("Authorization service terminated: %s", err))
}

func loadConfig() config {
	dbConfig := postgres.Config{
		Host:        mainflux.Env(envDBHost, defDBHost),
		Port:        mainflux.Env(envDBPort, defDBPort),
		User:        mainflux.Env(envDBUser, defDBUser),
		Pass:        mainflux.Env(envDBPass, defDBPass),
		Name:        mainflux.Env(envDB, defDB),
		SSLMode:     mainflux.Env(envDBSSLMode, defDBSSLMode),
		SSLCert:     mainflux.Env(envDBSSLCert, defDBSSLCert),
		SSLKey:      mainflux.Env(envDBSSLKey, defDBSSLKey),
		SSLRootCert: mainflux.Env(envDBSSLRootCert, defDBSSLRootCert),
	}

	return config{
		logLevel:   mainflux.Env(envLogLevel, defLogLevel),
		dbConfig:   dbConfig,
		httpPort:   mainflux.Env(envHTTPPort, defHTTPPort),
		grpcPort:   mainflux.Env(envGRPCPort, defGRPCPort),
		secret:     mainflux.Env(envSecret, defSecret),
		serverCert: mainflux.Env(envServerCert, defServerCert),
		serverKey:  mainflux.Env(envServerKey, defServerKey),
		jaegerURL:  mainflux.Env(envJaegerURL, defJaegerURL),
	}

}

func initJaeger(svcName, url string, logger logger.Logger) (opentracing.Tracer, io.Closer) {
	if url == "" {
		return opentracing.NoopTracer{}, ioutil.NopCloser(nil)
	}

	tracer, closer, err := jconfig.Configuration{
		ServiceName: svcName,
		Sampler: &jconfig.SamplerConfig{
			Type:  "const",
			Param: 1,
		},
		Reporter: &jconfig.ReporterConfig{
			LocalAgentHostPort: url,
			LogSpans:           true,
		},
	}.NewTracer()
	if err != nil {
		logger.Error(fmt.Sprintf("Failed to init Jaeger: %s", err))
		os.Exit(1)
	}

	return tracer, closer
}

func newService(enf *casbin.Enforcer, logger logger.Logger) authn.Service {
	svc := authz.New(enf, logger)
	svc = api.LoggingMiddleware(svc, logger)
	svc = api.MetricsMiddleware(
		svc,
		kitprometheus.NewCounterFrom(stdprometheus.CounterOpts{
			Namespace: "authz",
			Subsystem: "api",
			Name:      "request_count",
			Help:      "Number of requests received.",
		}, []string{"method"}),
		kitprometheus.NewSummaryFrom(stdprometheus.SummaryOpts{
			Namespace: "authz",
			Subsystem: "api",
			Name:      "request_latency_microseconds",
			Help:      "Total duration of requests in microseconds.",
		}, []string{"method"}),
	)

	return svc
}

func startHTTPServer(tracer opentracing.Tracer, svc authn.Service, port string, certFile string, keyFile string, logger logger.Logger, errs chan error) {
	p := fmt.Sprintf(":%s", port)
	if certFile != "" || keyFile != "" {
		logger.Info(fmt.Sprintf("Authorization service started using https, cert %s key %s, exposed port %s", certFile, keyFile, port))
		errs <- http.ListenAndServeTLS(p, certFile, keyFile, httpapi.MakeHandler(svc, tracer))
		return
	}
	logger.Info(fmt.Sprintf("Authorization service started using http, exposed port %s", port))
	errs <- http.ListenAndServe(p, httpapi.MakeHandler(svc, tracer))

}

func startGRPCServer(tracer opentracing.Tracer, svc authn.Service, port string, certFile string, keyFile string, logger logger.Logger, errs chan error) {
	p := fmt.Sprintf(":%s", port)
	listener, err := net.Listen("tcp", p)
	if err != nil {
		logger.Error(fmt.Sprintf("Failed to listen on port %s: %s", port, err))
	}

	var server *grpc.Server
	if certFile != "" || keyFile != "" {
		creds, err := credentials.NewServerTLSFromFile(certFile, keyFile)
		if err != nil {
			logger.Error(fmt.Sprintf("Failed to load authz certificates: %s", err))
			os.Exit(1)
		}
		logger.Info(fmt.Sprintf("Authorization gRPC service started using https on port %s with cert %s key %s", port, certFile, keyFile))
		server = grpc.NewServer(grpc.Creds(creds))
	} else {
		logger.Info(fmt.Sprintf("Authorization gRPC service started using http on port %s", port))
		server = grpc.NewServer()
	}

	mainflux.RegisterAuthNServiceServer(server, grpcapi.NewServer(tracer, svc))
	logger.Info(fmt.Sprintf("Authorization gRPC service started, exposed port %s", port))
	errs <- server.Serve(listener)
}
