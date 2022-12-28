// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/mainflux/mainflux/internal"
	authClient "github.com/mainflux/mainflux/internal/client/grpc/auth"
	thingsClient "github.com/mainflux/mainflux/internal/client/grpc/things"
	mongoClient "github.com/mainflux/mainflux/internal/client/mongo"
	"github.com/mainflux/mainflux/internal/env"
	"github.com/mainflux/mainflux/internal/server"
	httpserver "github.com/mainflux/mainflux/internal/server/http"
	"github.com/mainflux/mainflux/logger"
	"github.com/mainflux/mainflux/readers"
	"github.com/mainflux/mainflux/readers/api"
	"github.com/mainflux/mainflux/readers/mongodb"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/sync/errgroup"
)

const (
	svcName       = "mongodb-reader"
	envPrefix     = "MF_MONGO_READER_"
	envPrefixHttp = "MF_MONGO_READER_HTTP_"
)

type config struct {
	logLevel  string `env:"MF_MONGO_READER_LOG_LEVEL"   envDefault:"debug"`
	jaegerURL string `env:"MF_JAEGER_URL"               envDefault:"debug"`
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	g, ctx := errgroup.WithContext(ctx)

	cfg := config{}
	if err := env.Parse(&cfg); err != nil {
		log.Fatalf("Failed to load %s configuration : %s", svcName, err.Error())
	}

	logger, err := logger.New(os.Stdout, cfg.logLevel)
	if err != nil {
		log.Fatalf(err.Error())
	}

	db, err := mongoClient.Setup(envPrefix)
	if err != nil {
		log.Fatalf("Failed to setup mongo database : %s", err.Error())
	}

	repo := newService(db, logger)

	tc, thingsGrpcClient, thingsTracerCloser, thingsGrpcSecure, err := thingsClient.Setup(envPrefix, cfg.jaegerURL)
	if err != nil {
		log.Fatal(err.Error())
	}
	defer thingsGrpcClient.Close()
	defer thingsTracerCloser.Close()
	logger.Info("Successfully connected to things grpc server " + thingsGrpcSecure)

	auth, authGrpcClient, authTracerCloser, authGrpcSecure, err := authClient.Setup(envPrefix, cfg.jaegerURL)
	if err != nil {
		log.Fatal(err.Error())
	}
	defer authGrpcClient.Close()
	defer authTracerCloser.Close()
	logger.Info("Successfully connected to auth grpc server " + authGrpcSecure)

	httpServerConfig := server.Config{}
	if err := env.Parse(&httpServerConfig, env.Options{Prefix: envPrefixHttp, AltPrefix: envPrefix}); err != nil {
		log.Fatalf(fmt.Sprintf("Failed to load %s HTTP server configuration : %s", svcName, err.Error()))
	}

	hs := httpserver.New(ctx, cancel, svcName, httpServerConfig, api.MakeHandler(repo, tc, auth, svcName, logger), logger)
	g.Go(func() error {
		return hs.Start()
	})

	g.Go(func() error {
		return server.StopSignalHandler(ctx, cancel, logger, svcName, hs)
	})

	if err := g.Wait(); err != nil {
		logger.Error(fmt.Sprintf("MongoDB reader service terminated: %s", err))
	}

}

func newService(db *mongo.Database, logger logger.Logger) readers.MessageRepository {
	repo := mongodb.New(db)
	repo = api.LoggingMiddleware(repo, logger)
	counter, latency := internal.MakeMetrics("mongodb", "message_reader")
	repo = api.MetricsMiddleware(repo, counter, latency)

	return repo
}
