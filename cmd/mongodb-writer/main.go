// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

// Package main contains mongodb-writer main function to start the mongodb-writer service.
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	chclient "github.com/mainflux/callhome/pkg/client"
	"github.com/mainflux/mainflux"
	"github.com/mainflux/mainflux/consumers"
	consumerTracing "github.com/mainflux/mainflux/consumers/tracing"
	"github.com/mainflux/mainflux/consumers/writers/api"
	"github.com/mainflux/mainflux/consumers/writers/mongodb"
	"github.com/mainflux/mainflux/internal"
	jaegerClient "github.com/mainflux/mainflux/internal/clients/jaeger"
	mongoClient "github.com/mainflux/mainflux/internal/clients/mongo"
	"github.com/mainflux/mainflux/internal/env"
	"github.com/mainflux/mainflux/internal/server"
	httpserver "github.com/mainflux/mainflux/internal/server/http"
	mflog "github.com/mainflux/mainflux/logger"
	"github.com/mainflux/mainflux/pkg/messaging/brokers"
	"github.com/mainflux/mainflux/pkg/messaging/tracing"
	"github.com/mainflux/mainflux/pkg/uuid"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/sync/errgroup"
)

const (
	svcName        = "mongodb-writer"
	envPrefixDB    = "MF_MONGO_"
	envPrefixHTTP  = "MF_MONGO_WRITER_HTTP_"
	defSvcHTTPPort = "9008"
)

type config struct {
	LogLevel      string `env:"MF_MONGO_WRITER_LOG_LEVEL"     envDefault:"info"`
	ConfigPath    string `env:"MF_MONGO_WRITER_CONFIG_PATH"   envDefault:"/config.toml"`
	BrokerURL     string `env:"MF_BROKER_URL"                 envDefault:"nats://localhost:4222"`
	JaegerURL     string `env:"MF_JAEGER_URL"                 envDefault:"localhost:6831"`
	SendTelemetry bool   `env:"MF_SEND_TELEMETRY"             envDefault:"true"`
	InstanceID    string `env:"MF_MONGO_WRITER_INSTANCE_ID"   envDefault:""`
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	g, ctx := errgroup.WithContext(ctx)

	cfg := config{}
	if err := env.Parse(&cfg); err != nil {
		log.Fatalf("failed to load %s configuration : %s", svcName, err)
	}

	logger, err := mflog.New(os.Stdout, cfg.LogLevel)
	if err != nil {
		log.Fatalf("failed to init logger: %s", err)
	}

	var exitCode int
	defer mflog.ExitWithError(&exitCode)

	instanceID := cfg.InstanceID
	if instanceID == "" {
		instanceID, err = uuid.New().ID()
		if err != nil {
			logger.Error(fmt.Sprintf("Failed to generate instanceID: %s", err))
			exitCode = 1
			return
		}
	}

	tp, err := jaegerClient.NewProvider(svcName, cfg.JaegerURL, instanceID)
	if err != nil {
		logger.Error(fmt.Sprintf("Failed to init Jaeger: %s", err))
		exitCode = 1
		return
	}
	defer func() {
		if err := tp.Shutdown(ctx); err != nil {
			logger.Error(fmt.Sprintf("Error shutting down tracer provider: %v", err))
		}
	}()
	tracer := tp.Tracer(svcName)

	pubSub, err := brokers.NewPubSub(cfg.BrokerURL, "", logger)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to connect to message broker: %s", err))
		exitCode = 1
		return
	}
	pubSub = tracing.NewPubSub(tracer, pubSub)
	defer pubSub.Close()

	db, err := mongoClient.Setup(envPrefixDB)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to setup mongo database : %s", err))
		exitCode = 1
		return
	}

	httpServerConfig := server.Config{Port: defSvcHTTPPort}
	if err := env.Parse(&httpServerConfig, env.Options{Prefix: envPrefixHTTP}); err != nil {
		logger.Error(fmt.Sprintf("failed to load %s HTTP server configuration : %s", svcName, err))
		exitCode = 1
		return
	}

	repo := newService(db, logger)
	repo = consumerTracing.NewBlocking(tracer, repo, httpServerConfig)

	if err := consumers.Start(ctx, svcName, pubSub, repo, cfg.ConfigPath, logger); err != nil {
		logger.Error(fmt.Sprintf("failed to start MongoDB writer: %s", err))
		exitCode = 1
		return
	}

	hs := httpserver.New(ctx, cancel, svcName, httpServerConfig, api.MakeHandler(svcName, instanceID), logger)

	if cfg.SendTelemetry {
		chc := chclient.New(svcName, mainflux.Version, logger, cancel)
		go chc.CallHome(ctx)
	}

	g.Go(func() error {
		return hs.Start()
	})

	g.Go(func() error {
		return server.StopSignalHandler(ctx, cancel, logger, svcName, hs)
	})

	if err := g.Wait(); err != nil {
		logger.Error(fmt.Sprintf("MongoDB writer service terminated: %s", err))
	}
}

func newService(db *mongo.Database, logger mflog.Logger) consumers.BlockingConsumer {
	repo := mongodb.New(db)
	repo = api.LoggingMiddleware(repo, logger)
	counter, latency := internal.MakeMetrics("mongodb", "message_writer")
	repo = api.MetricsMiddleware(repo, counter, latency)
	return repo
}
