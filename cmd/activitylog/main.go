// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

// Package main contains activity log main function to start the activity log service.
package main

import (
	"context"
	"log"
	"log/slog"
	"net/url"
	"os"

	chclient "github.com/absmach/callhome/pkg/client"
	"github.com/absmach/magistrala"
	"github.com/absmach/magistrala/activitylog"
	"github.com/absmach/magistrala/activitylog/api"
	"github.com/absmach/magistrala/activitylog/middleware"
	activitylogpg "github.com/absmach/magistrala/activitylog/postgres"
	"github.com/absmach/magistrala/internal"
	jaegerclient "github.com/absmach/magistrala/internal/clients/jaeger"
	pgclient "github.com/absmach/magistrala/internal/clients/postgres"
	"github.com/absmach/magistrala/internal/postgres"
	"github.com/absmach/magistrala/internal/server"
	httpserver "github.com/absmach/magistrala/internal/server/http"
	mglog "github.com/absmach/magistrala/logger"
	"github.com/absmach/magistrala/pkg/auth"
	"github.com/absmach/magistrala/pkg/events/store"
	"github.com/absmach/magistrala/pkg/uuid"
	"github.com/caarlos0/env/v10"
	"github.com/jmoiron/sqlx"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/sync/errgroup"
)

const (
	svcName        = "activity_log"
	envPrefixDB    = "MG_ACTIVITY_LOG_"
	envPrefixHTTP  = "MG_ACTIVITY_LOG_HTTP_"
	envPrefixAuth  = "MG_AUTH_GRPC_"
	defDB          = "activities"
	defSvcHTTPPort = "9021"
)

type config struct {
	LogLevel      string  `env:"MG_ACTIVITY_LOG_LOG_LEVEL"   envDefault:"info"`
	ESURL         string  `env:"MG_ES_URL"                   envDefault:"nats://localhost:4222"`
	JaegerURL     url.URL `env:"MG_JAEGER_URL"               envDefault:"http://jaeger:14268/api/traces"`
	SendTelemetry bool    `env:"MG_SEND_TELEMETRY"           envDefault:"true"`
	InstanceID    string  `env:"MG_ACTIVITY_LOG_INSTANCE_ID" envDefault:""`
	TraceRatio    float64 `env:"MG_JAEGER_TRACE_RATIO"       envDefault:"1.0"`
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	g, ctx := errgroup.WithContext(ctx)

	cfg := config{}
	if err := env.Parse(&cfg); err != nil {
		log.Fatalf("failed to load %s configuration : %s", svcName, err)
	}

	logger, err := mglog.New(os.Stdout, cfg.LogLevel)
	if err != nil {
		log.Fatalf("failed to init logger: %s", err)
	}

	var exitCode int
	defer mglog.ExitWithError(&exitCode)

	if cfg.InstanceID == "" {
		if cfg.InstanceID, err = uuid.New().ID(); err != nil {
			logger.Error("failed to generate instanceID: %s", err)
			exitCode = 1
			return
		}
	}

	dbConfig := pgclient.Config{Name: defDB}
	if err := env.ParseWithOptions(&dbConfig, env.Options{Prefix: envPrefixDB}); err != nil {
		logger.Error("failed to load %s Postgres configuration : %s", svcName, err)
		exitCode = 1
		return
	}
	db, err := pgclient.Setup(dbConfig, *activitylogpg.Migration())
	if err != nil {
		logger.Error(err.Error())
		exitCode = 1
		return
	}
	defer db.Close()

	authConfig := auth.Config{}
	if err := env.ParseWithOptions(&authConfig, env.Options{Prefix: envPrefixAuth}); err != nil {
		logger.Error("failed to load %s auth configuration : %s", svcName, err)
		exitCode = 1
		return
	}

	ac, acHandler, err := auth.Setup(authConfig)
	if err != nil {
		logger.Error(err.Error())
		exitCode = 1
		return
	}
	defer acHandler.Close()

	logger.Info("Successfully connected to auth grpc server " + acHandler.Secure())

	tp, err := jaegerclient.NewProvider(ctx, svcName, cfg.JaegerURL, cfg.InstanceID, cfg.TraceRatio)
	if err != nil {
		logger.Error("Failed to init Jaeger: %s", err)
		exitCode = 1
		return
	}
	defer func() {
		if err := tp.Shutdown(ctx); err != nil {
			logger.Error("Error shutting down tracer provider: %v", err)
		}
	}()
	tracer := tp.Tracer(svcName)

	svc := newService(db, dbConfig, ac, logger, tracer)

	subscriber, err := store.NewSubscriber(ctx, cfg.ESURL, logger)
	if err != nil {
		logger.Error("failed to create subscriber: %s", err)
		exitCode = 1
		return
	}

	logger.Info("Subscribed to Event Store")

	if err := activitylog.Start(ctx, svcName, subscriber, svc); err != nil {
		logger.Error("failed to start %s service: %s", svcName, err)
		exitCode = 1
		return
	}

	httpServerConfig := server.Config{Port: defSvcHTTPPort}
	if err := env.ParseWithOptions(&httpServerConfig, env.Options{Prefix: envPrefixHTTP}); err != nil {
		logger.Error("failed to load %s HTTP server configuration : %s", svcName, err)
		exitCode = 1
		return
	}

	hs := httpserver.New(ctx, cancel, svcName, httpServerConfig, api.MakeHandler(svc, logger, svcName, cfg.InstanceID), logger)

	if cfg.SendTelemetry {
		chc := chclient.New(svcName, magistrala.Version, logger, cancel)
		go chc.CallHome(ctx)
	}

	g.Go(func() error {
		return hs.Start()
	})

	g.Go(func() error {
		return server.StopSignalHandler(ctx, cancel, logger, svcName, hs)
	})

	if err := g.Wait(); err != nil {
		logger.Error("%s service terminated: %s", svcName, err)
	}
}

func newService(db *sqlx.DB, dbConfig pgclient.Config, authClient magistrala.AuthServiceClient, logger *slog.Logger, tracer trace.Tracer) activitylog.Service {
	database := postgres.NewDatabase(db, dbConfig, tracer)
	repo := activitylogpg.NewRepository(database)

	svc := activitylog.NewService(repo, authClient)
	svc = middleware.LoggingMiddleware(svc, logger)
	counter, latency := internal.MakeMetrics("activitylog", "activity_writer")
	svc = middleware.MetricsMiddleware(svc, counter, latency)
	svc = middleware.Tracing(svc, tracer)

	return svc
}
