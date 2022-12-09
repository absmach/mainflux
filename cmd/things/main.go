// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/jmoiron/sqlx"
	"github.com/mainflux/mainflux"
	authapi "github.com/mainflux/mainflux/auth/api/grpc"
	apiutil "github.com/mainflux/mainflux/internal/init"
	mfdatabase "github.com/mainflux/mainflux/internal/init/db"
	"github.com/mainflux/mainflux/internal/init/mfserver"
	"github.com/mainflux/mainflux/internal/init/mfserver/grpcserver"
	"github.com/mainflux/mainflux/internal/init/mfserver/httpserver"
	"github.com/mainflux/mainflux/logger"
	"github.com/mainflux/mainflux/pkg/uuid"
	"github.com/mainflux/mainflux/things"
	"github.com/mainflux/mainflux/things/api"
	authgrpcapi "github.com/mainflux/mainflux/things/api/auth/grpc"
	authhttpapi "github.com/mainflux/mainflux/things/api/auth/http"
	thhttpapi "github.com/mainflux/mainflux/things/api/things/http"
	"github.com/mainflux/mainflux/things/postgres"
	rediscache "github.com/mainflux/mainflux/things/redis"
	localusers "github.com/mainflux/mainflux/things/standalone"
	"github.com/mainflux/mainflux/things/tracing"
	opentracing "github.com/opentracing/opentracing-go"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
)

const (
	svcName      = "things"
	stopWaitTime = 5 * time.Second

	defListenAddress   = ""
	defLogLevel        = "error"
	defDBHost          = "localhost"
	defDBPort          = "5432"
	defDBUser          = "mainflux"
	defDBPass          = "mainflux"
	defDB              = "things"
	defDBSSLMode       = "disable"
	defDBSSLCert       = ""
	defDBSSLKey        = ""
	defDBSSLRootCert   = ""
	defClientTLS       = "false"
	defCACerts         = ""
	defCacheURL        = "localhost:6379"
	defCachePass       = ""
	defCacheDB         = "0"
	defESURL           = "localhost:6379"
	defESPass          = ""
	defESDB            = "0"
	defHTTPPort        = "8182"
	defAuthHTTPPort    = "8989"
	defAuthGRPCPort    = "8181"
	defServerCert      = ""
	defServerKey       = ""
	defStandaloneEmail = ""
	defStandaloneToken = ""
	defJaegerURL       = ""
	defAuthURL         = "localhost:8181"
	defAuthTimeout     = "1s"

	envLogLevel        = "MF_THINGS_LOG_LEVEL"
	envDBHost          = "MF_THINGS_DB_HOST"
	envDBPort          = "MF_THINGS_DB_PORT"
	envDBUser          = "MF_THINGS_DB_USER"
	envDBPass          = "MF_THINGS_DB_PASS"
	envDB              = "MF_THINGS_DB"
	envDBSSLMode       = "MF_THINGS_DB_SSL_MODE"
	envDBSSLCert       = "MF_THINGS_DB_SSL_CERT"
	envDBSSLKey        = "MF_THINGS_DB_SSL_KEY"
	envDBSSLRootCert   = "MF_THINGS_DB_SSL_ROOT_CERT"
	envClientTLS       = "MF_THINGS_CLIENT_TLS"
	envCACerts         = "MF_THINGS_CA_CERTS"
	envCacheURL        = "MF_THINGS_CACHE_URL"
	envCachePass       = "MF_THINGS_CACHE_PASS"
	envCacheDB         = "MF_THINGS_CACHE_DB"
	envESURL           = "MF_THINGS_ES_URL"
	envESPass          = "MF_THINGS_ES_PASS"
	envESDB            = "MF_THINGS_ES_DB"
	envHTTPPort        = "MF_THINGS_HTTP_PORT"
	envAuthHTTPPort    = "MF_THINGS_AUTH_HTTP_PORT"
	envAuthGRPCPort    = "MF_THINGS_AUTH_GRPC_PORT"
	envServerCert      = "MF_THINGS_SERVER_CERT"
	envServerKey       = "MF_THINGS_SERVER_KEY"
	envStandaloneEmail = "MF_THINGS_STANDALONE_EMAIL"
	envStandaloneToken = "MF_THINGS_STANDALONE_TOKEN"
	envJaegerURL       = "MF_JAEGER_URL"
	envAuthURL         = "MF_AUTH_GRPC_URL"
	envAuthTimeout     = "MF_AUTH_GRPC_TIMEOUT"
)

type config struct {
	logLevel        string
	dbConfig        postgres.Config
	clientTLS       bool
	caCerts         string
	cacheURL        string
	cachePass       string
	cacheDB         string
	esURL           string
	esPass          string
	esDB            string
	httpPort        string
	authHTTPPort    string
	authGRPCPort    string
	serverCert      string
	serverKey       string
	standaloneEmail string
	standaloneToken string
	jaegerURL       string
	authURL         string
	authTimeout     time.Duration
}

func main() {
	cfg := loadConfig()
	ctx, cancel := context.WithCancel(context.Background())
	g, ctx := errgroup.WithContext(ctx)

	logger, err := logger.New(os.Stdout, cfg.logLevel)
	if err != nil {
		log.Fatalf(err.Error())
	}

	thingsTracer, thingsCloser := apiutil.Jaeger("things", cfg.jaegerURL, logger)
	defer thingsCloser.Close()

	cacheClient := mfdatabase.ConnectToRedis(cfg.cacheURL, cfg.cachePass, cfg.cacheDB, logger)

	esClient := mfdatabase.ConnectToRedis(cfg.esURL, cfg.esPass, cfg.esDB, logger)

	db := connectToDB(cfg.dbConfig, logger)
	defer db.Close()

	authTracer, authCloser := apiutil.Jaeger("auth", cfg.jaegerURL, logger)
	defer authCloser.Close()

	auth, close := createAuthClient(cfg, authTracer, logger)
	if close != nil {
		defer close()
	}

	dbTracer, dbCloser := apiutil.Jaeger("things_db", cfg.jaegerURL, logger)
	defer dbCloser.Close()

	cacheTracer, cacheCloser := apiutil.Jaeger("things_cache", cfg.jaegerURL, logger)
	defer cacheCloser.Close()

	svc := newService(auth, dbTracer, cacheTracer, db, cacheClient, esClient, logger)

	registerThingsServiceServer := func(srv *grpc.Server) {
		mainflux.RegisterThingsServiceServer(srv, authgrpcapi.NewServer(thingsTracer, svc))

	}

	hs1 := httpserver.New(ctx, cancel, "thing-http", defListenAddress, cfg.httpPort, thhttpapi.MakeHandler(thingsTracer, svc, logger), cfg.serverCert, cfg.serverKey, logger)
	hs2 := httpserver.New(ctx, cancel, "auth-http", defListenAddress, cfg.authHTTPPort, authhttpapi.MakeHandler(thingsTracer, svc, logger), cfg.serverCert, cfg.serverKey, logger)
	gs := grpcserver.New(ctx, cancel, svcName, defListenAddress, cfg.authGRPCPort, registerThingsServiceServer, cfg.serverCert, cfg.serverKey, logger)
	g.Go(func() error {
		return hs1.Start()
	})
	g.Go(func() error {
		return hs2.Start()
	})
	g.Go(func() error {
		return gs.Start()
	})

	g.Go(func() error {
		return mfserver.ServerStopSignalHandler(ctx, cancel, logger, svcName, hs1, hs2, gs)
	})

	if err := g.Wait(); err != nil {
		logger.Error(fmt.Sprintf("Things service terminated: %s", err))
	}
}

func loadConfig() config {
	tls, err := strconv.ParseBool(mainflux.Env(envClientTLS, defClientTLS))
	if err != nil {
		log.Fatalf("Invalid value passed for %s\n", envClientTLS)
	}

	authTimeout, err := time.ParseDuration(mainflux.Env(envAuthTimeout, defAuthTimeout))
	if err != nil {
		log.Fatalf("Invalid %s value: %s", envAuthTimeout, err.Error())
	}

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
		logLevel:        mainflux.Env(envLogLevel, defLogLevel),
		dbConfig:        dbConfig,
		clientTLS:       tls,
		caCerts:         mainflux.Env(envCACerts, defCACerts),
		cacheURL:        mainflux.Env(envCacheURL, defCacheURL),
		cachePass:       mainflux.Env(envCachePass, defCachePass),
		cacheDB:         mainflux.Env(envCacheDB, defCacheDB),
		esURL:           mainflux.Env(envESURL, defESURL),
		esPass:          mainflux.Env(envESPass, defESPass),
		esDB:            mainflux.Env(envESDB, defESDB),
		httpPort:        mainflux.Env(envHTTPPort, defHTTPPort),
		authHTTPPort:    mainflux.Env(envAuthHTTPPort, defAuthHTTPPort),
		authGRPCPort:    mainflux.Env(envAuthGRPCPort, defAuthGRPCPort),
		serverCert:      mainflux.Env(envServerCert, defServerCert),
		serverKey:       mainflux.Env(envServerKey, defServerKey),
		standaloneEmail: mainflux.Env(envStandaloneEmail, defStandaloneEmail),
		standaloneToken: mainflux.Env(envStandaloneToken, defStandaloneToken),
		jaegerURL:       mainflux.Env(envJaegerURL, defJaegerURL),
		authURL:         mainflux.Env(envAuthURL, defAuthURL),
		authTimeout:     authTimeout,
	}
}

func connectToDB(dbConfig postgres.Config, logger logger.Logger) *sqlx.DB {
	db, err := postgres.Connect(dbConfig)
	if err != nil {
		logger.Error(fmt.Sprintf("Failed to connect to postgres: %s", err))
		os.Exit(1)
	}
	return db
}

func createAuthClient(cfg config, tracer opentracing.Tracer, logger logger.Logger) (mainflux.AuthServiceClient, func() error) {
	if cfg.standaloneEmail != "" && cfg.standaloneToken != "" {
		return localusers.NewAuthService(cfg.standaloneEmail, cfg.standaloneToken), nil
	}

	conn := apiutil.ConnectToAuth(cfg.clientTLS, cfg.caCerts, cfg.authURL, svcName, logger)
	return authapi.NewClient(tracer, conn, cfg.authTimeout), conn.Close
}

func newService(auth mainflux.AuthServiceClient, dbTracer opentracing.Tracer, cacheTracer opentracing.Tracer, db *sqlx.DB, cacheClient *redis.Client, esClient *redis.Client, logger logger.Logger) things.Service {
	database := postgres.NewDatabase(db)

	thingsRepo := postgres.NewThingRepository(database)
	thingsRepo = tracing.ThingRepositoryMiddleware(dbTracer, thingsRepo)

	channelsRepo := postgres.NewChannelRepository(database)
	channelsRepo = tracing.ChannelRepositoryMiddleware(dbTracer, channelsRepo)

	chanCache := rediscache.NewChannelCache(cacheClient)
	chanCache = tracing.ChannelCacheMiddleware(cacheTracer, chanCache)

	thingCache := rediscache.NewThingCache(cacheClient)
	thingCache = tracing.ThingCacheMiddleware(cacheTracer, thingCache)
	idProvider := uuid.New()

	svc := things.New(auth, thingsRepo, channelsRepo, chanCache, thingCache, idProvider)
	svc = rediscache.NewEventStoreMiddleware(svc, esClient)
	svc = api.LoggingMiddleware(svc, logger)
	counter, latency := apiutil.MakeMetrics(svcName, "api")
	svc = api.MetricsMiddleware(svc, counter, latency)

	return svc
}
