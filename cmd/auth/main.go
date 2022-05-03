package main

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"time"

	kitprometheus "github.com/go-kit/kit/metrics/prometheus"
	"github.com/jmoiron/sqlx"
	"github.com/mainflux/mainflux"
	"github.com/mainflux/mainflux/auth"
	api "github.com/mainflux/mainflux/auth/api"
	grpcapi "github.com/mainflux/mainflux/auth/api/grpc"
	httpapi "github.com/mainflux/mainflux/auth/api/http"
	"github.com/mainflux/mainflux/auth/jwt"
	"github.com/mainflux/mainflux/auth/keto"
	"github.com/mainflux/mainflux/auth/postgres"
	"github.com/mainflux/mainflux/auth/tracing"
	"github.com/mainflux/mainflux/internal/apiutil/mfserver"
	"github.com/mainflux/mainflux/internal/apiutil/mfserver/grpcserver"
	"github.com/mainflux/mainflux/internal/apiutil/mfserver/httpserver"
	"github.com/mainflux/mainflux/logger"
	"github.com/mainflux/mainflux/pkg/uuid"
	"github.com/opentracing/opentracing-go"
	acl "github.com/ory/keto/proto/ory/keto/acl/v1alpha1"
	stdprometheus "github.com/prometheus/client_golang/prometheus"
	jconfig "github.com/uber/jaeger-client-go/config"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
)

const (
	stopWaitTime  = 5 * time.Second
	httpProtocol  = "http"
	httpsProtocol = "https"
	serviceName   = "Authentication"

	defListenAddress = ""
	defLogLevel      = "error"
	defDBHost        = "localhost"
	defDBPort        = "5432"
	defDBUser        = "mainflux"
	defDBPass        = "mainflux"
	defDB            = "auth"
	defDBSSLMode     = "disable"
	defDBSSLCert     = ""
	defDBSSLKey      = ""
	defDBSSLRootCert = ""
	defHTTPPort      = "8180"
	defGRPCPort      = "8181"
	defSecret        = "auth"
	defServerCert    = ""
	defServerKey     = ""
	defJaegerURL     = ""
	defKetoReadHost  = "mainflux-keto"
	defKetoWriteHost = "mainflux-keto"
	defKetoReadPort  = "4466"
	defKetoWritePort = "4467"
	defLoginDuration = "10h"

	envLogLevel      = "MF_AUTH_LOG_LEVEL"
	envDBHost        = "MF_AUTH_DB_HOST"
	envDBPort        = "MF_AUTH_DB_PORT"
	envDBUser        = "MF_AUTH_DB_USER"
	envDBPass        = "MF_AUTH_DB_PASS"
	envDB            = "MF_AUTH_DB"
	envDBSSLMode     = "MF_AUTH_DB_SSL_MODE"
	envDBSSLCert     = "MF_AUTH_DB_SSL_CERT"
	envDBSSLKey      = "MF_AUTH_DB_SSL_KEY"
	envDBSSLRootCert = "MF_AUTH_DB_SSL_ROOT_CERT"
	envHTTPPort      = "MF_AUTH_HTTP_PORT"
	envGRPCPort      = "MF_AUTH_GRPC_PORT"
	envSecret        = "MF_AUTH_SECRET"
	envServerCert    = "MF_AUTH_SERVER_CERT"
	envServerKey     = "MF_AUTH_SERVER_KEY"
	envJaegerURL     = "MF_JAEGER_URL"
	envKetoReadHost  = "MF_KETO_READ_REMOTE_HOST"
	envKetoWriteHost = "MF_KETO_WRITE_REMOTE_HOST"
	envKetoReadPort  = "MF_KETO_READ_REMOTE_PORT"
	envKetoWritePort = "MF_KETO_WRITE_REMOTE_PORT"
	envLoginDuration = "MF_AUTH_LOGIN_TOKEN_DURATION"
)

type config struct {
	logLevel      string
	dbConfig      postgres.Config
	httpPort      string
	grpcPort      string
	secret        string
	serverCert    string
	serverKey     string
	jaegerURL     string
	resetURL      string
	ketoReadHost  string
	ketoWriteHost string
	ketoWritePort string
	ketoReadPort  string
	loginDuration time.Duration
}

type tokenConfig struct {
	hmacSampleSecret []byte // secret for signing token
	tokenDuration    string // token in duration in min
}

func main() {
	cfg := loadConfig()
	ctx, cancel := context.WithCancel(context.Background())
	g, ctx := errgroup.WithContext(ctx)
	logger, err := logger.New(os.Stdout, cfg.logLevel)
	if err != nil {
		log.Fatalf(err.Error())
	}

	db := connectToDB(cfg.dbConfig, logger)
	defer db.Close()

	tracer, closer := initJaeger("auth", cfg.jaegerURL, logger)
	defer closer.Close()

	dbTracer, dbCloser := initJaeger("auth_db", cfg.jaegerURL, logger)
	defer dbCloser.Close()

	readerConn, writerConn := initKeto(cfg.ketoReadHost, cfg.ketoReadPort, cfg.ketoWriteHost, cfg.ketoWritePort, logger)

	svc := newService(db, dbTracer, cfg.secret, logger, readerConn, writerConn, cfg.loginDuration)

	hs := httpserver.New(ctx, cancel, serviceName, defListenAddress, cfg.httpPort, httpapi.MakeHandler(svc, tracer, logger), cfg.serverCert, cfg.serverKey, logger)
	gs := grpcserver.New(ctx, cancel, serviceName, defListenAddress, cfg.httpPort, grpcapi.NewServer(tracer, svc), cfg.serverCert, cfg.serverKey, logger)

	g.Go(func() error {
		return hs.Start()
	})
	g.Go(func() error {
		return gs.Start()
	})

	g.Go(func() error {
		return mfserver.ServerStopSignalHandler(ctx, cancel, logger, hs, gs)
	})
	if err := g.Wait(); err != nil {
		logger.Error(fmt.Sprintf("Authentication service terminated: %s", err))
	}
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

	loginDuration, err := time.ParseDuration(mainflux.Env(envLoginDuration, defLoginDuration))
	if err != nil {
		log.Fatal(err)
	}

	return config{
		logLevel:      mainflux.Env(envLogLevel, defLogLevel),
		dbConfig:      dbConfig,
		httpPort:      mainflux.Env(envHTTPPort, defHTTPPort),
		grpcPort:      mainflux.Env(envGRPCPort, defGRPCPort),
		secret:        mainflux.Env(envSecret, defSecret),
		serverCert:    mainflux.Env(envServerCert, defServerCert),
		serverKey:     mainflux.Env(envServerKey, defServerKey),
		jaegerURL:     mainflux.Env(envJaegerURL, defJaegerURL),
		ketoReadHost:  mainflux.Env(envKetoReadHost, defKetoReadHost),
		ketoWriteHost: mainflux.Env(envKetoWriteHost, defKetoWriteHost),
		ketoReadPort:  mainflux.Env(envKetoReadPort, defKetoReadPort),
		ketoWritePort: mainflux.Env(envKetoWritePort, defKetoWritePort),
		loginDuration: loginDuration,
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

func initKeto(hostReadAddress, readPort, hostWriteAddress, writePort string, logger logger.Logger) (readerConnection, writerConnection *grpc.ClientConn) {
	readConn, err := grpc.Dial(fmt.Sprintf("%s:%s", hostReadAddress, readPort), grpc.WithInsecure())
	if err != nil {
		logger.Error(fmt.Sprintf("Failed to dial %s:%s for Keto Read Service: %s", hostReadAddress, readPort, err))
		os.Exit(1)
	}

	writeConn, err := grpc.Dial(fmt.Sprintf("%s:%s", hostWriteAddress, writePort), grpc.WithInsecure())
	if err != nil {
		logger.Error(fmt.Sprintf("Failed to dial %s:%s for Keto Write Service: %s", hostWriteAddress, writePort, err))
		os.Exit(1)
	}

	return readConn, writeConn
}

func connectToDB(dbConfig postgres.Config, logger logger.Logger) *sqlx.DB {
	db, err := postgres.Connect(dbConfig)
	if err != nil {
		logger.Error(fmt.Sprintf("Failed to connect to postgres: %s", err))
		os.Exit(1)
	}
	return db
}

func newService(db *sqlx.DB, tracer opentracing.Tracer, secret string, logger logger.Logger, readerConn, writerConn *grpc.ClientConn, duration time.Duration) auth.Service {
	database := postgres.NewDatabase(db)
	keysRepo := tracing.New(postgres.New(database), tracer)

	groupsRepo := postgres.NewGroupRepo(database)
	groupsRepo = tracing.GroupRepositoryMiddleware(tracer, groupsRepo)

	pa := keto.NewPolicyAgent(acl.NewCheckServiceClient(readerConn), acl.NewWriteServiceClient(writerConn), acl.NewReadServiceClient(readerConn))

	idProvider := uuid.New()
	t := jwt.New(secret)

	svc := auth.New(keysRepo, groupsRepo, idProvider, t, pa, duration)
	svc = api.LoggingMiddleware(svc, logger)
	svc = api.MetricsMiddleware(
		svc,
		kitprometheus.NewCounterFrom(stdprometheus.CounterOpts{
			Namespace: "auth",
			Subsystem: "api",
			Name:      "request_count",
			Help:      "Number of requests received.",
		}, []string{"method"}),
		kitprometheus.NewSummaryFrom(stdprometheus.SummaryOpts{
			Namespace: "auth",
			Subsystem: "api",
			Name:      "request_latency_microseconds",
			Help:      "Total duration of requests in microseconds.",
		}, []string{"method"}),
	)

	return svc
}
