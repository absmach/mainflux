// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	r "github.com/go-redis/redis/v8"
	"github.com/mainflux/mainflux"
	"github.com/mainflux/mainflux/internal"
	mfdatabase "github.com/mainflux/mainflux/internal/db"
	"github.com/mainflux/mainflux/internal/server"
	"github.com/mainflux/mainflux/internal/server/httpserver"
	"github.com/mainflux/mainflux/logger"
	"github.com/mainflux/mainflux/opcua"
	"github.com/mainflux/mainflux/opcua/api"
	"github.com/mainflux/mainflux/opcua/db"
	"github.com/mainflux/mainflux/opcua/gopcua"
	"github.com/mainflux/mainflux/opcua/redis"
	"github.com/mainflux/mainflux/pkg/messaging/nats"
	"golang.org/x/sync/errgroup"
)

const (
	stopWaitTime = 5 * time.Second
	svcName      = "opc-ua-adapter"

	defLogLevel       = "error"
	defHTTPPort       = "8180"
	defOPCIntervalMs  = "1000"
	defOPCPolicy      = ""
	defOPCMode        = ""
	defOPCCertFile    = ""
	defOPCKeyFile     = ""
	defNatsURL        = "nats://localhost:4222"
	defESURL          = "localhost:6379"
	defESPass         = ""
	defESDB           = "0"
	defESConsumerName = "opcua"
	defRouteMapURL    = "localhost:6379"
	defRouteMapPass   = ""
	defRouteMapDB     = "0"

	envLogLevel       = "MF_OPCUA_ADAPTER_LOG_LEVEL"
	envHTTPPort       = "MF_OPCUA_ADAPTER_HTTP_PORT"
	envOPCIntervalMs  = "MF_OPCUA_ADAPTER_INTERVAL_MS"
	envOPCPolicy      = "MF_OPCUA_ADAPTER_POLICY"
	envOPCMode        = "MF_OPCUA_ADAPTER_MODE"
	envOPCCertFile    = "MF_OPCUA_ADAPTER_CERT_FILE"
	envOPCKeyFile     = "MF_OPCUA_ADAPTER_KEY_FILE"
	envNatsURL        = "MF_NATS_URL"
	envESURL          = "MF_THINGS_ES_URL"
	envESPass         = "MF_THINGS_ES_PASS"
	envESDB           = "MF_THINGS_ES_DB"
	envESConsumerName = "MF_OPCUA_ADAPTER_EVENT_CONSUMER"
	envRouteMapURL    = "MF_OPCUA_ADAPTER_ROUTE_MAP_URL"
	envRouteMapPass   = "MF_OPCUA_ADAPTER_ROUTE_MAP_PASS"
	envRouteMapDB     = "MF_OPCUA_ADAPTER_ROUTE_MAP_DB"

	thingsRMPrefix     = "thing"
	channelsRMPrefix   = "channel"
	connectionRMPrefix = "connection"
)

type config struct {
	httpPort       string
	opcuaConfig    opcua.Config
	natsURL        string
	logLevel       string
	esURL          string
	esPass         string
	esDB           string
	esConsumerName string
	routeMapURL    string
	routeMapPass   string
	routeMapDB     string
}

func main() {
	cfg := loadConfig()
	httpCtx, httpCancel := context.WithCancel(context.Background())
	g, httpCtx := errgroup.WithContext(httpCtx)

	logger, err := logger.New(os.Stdout, cfg.logLevel)
	if err != nil {
		log.Fatalf(err.Error())
	}

	rmConn := mfdatabase.ConnectToRedis(cfg.routeMapURL, cfg.routeMapPass, cfg.routeMapDB, logger)
	defer rmConn.Close()

	thingRM := newRouteMapRepositoy(rmConn, thingsRMPrefix, logger)
	chanRM := newRouteMapRepositoy(rmConn, channelsRMPrefix, logger)
	connRM := newRouteMapRepositoy(rmConn, connectionRMPrefix, logger)

	esConn := mfdatabase.ConnectToRedis(cfg.esURL, cfg.esPass, cfg.esDB, logger)
	defer esConn.Close()

	pubSub, err := nats.NewPubSub(cfg.natsURL, "", logger)
	if err != nil {
		logger.Error(fmt.Sprintf("Failed to connect to NATS: %s", err))
		os.Exit(1)
	}
	defer pubSub.Close()

	ctx := context.Background()
	sub := gopcua.NewSubscriber(ctx, pubSub, thingRM, chanRM, connRM, logger)
	browser := gopcua.NewBrowser(ctx, logger)

	svc := newService(sub, browser, thingRM, chanRM, connRM, cfg.opcuaConfig, logger)

	go subscribeToStoredSubs(sub, cfg.opcuaConfig, logger)
	go subscribeToThingsES(svc, esConn, cfg.esConsumerName, logger)

	hs := httpserver.New(httpCtx, httpCancel, svcName, "", cfg.httpPort, api.MakeHandler(svc, logger), cfg.opcuaConfig.CertFile, cfg.opcuaConfig.KeyFile, logger)
	g.Go(func() error {
		return hs.Start()
	})

	g.Go(func() error {
		return server.ServerStopSignalHandler(httpCtx, httpCancel, logger, svcName, hs)
	})

	if err := g.Wait(); err != nil {
		logger.Error(fmt.Sprintf("OPC-UA adapter service terminated: %s", err))
	}
}

func loadConfig() config {
	oc := opcua.Config{
		Interval: mainflux.Env(envOPCIntervalMs, defOPCIntervalMs),
		Policy:   mainflux.Env(envOPCPolicy, defOPCPolicy),
		Mode:     mainflux.Env(envOPCMode, defOPCMode),
		CertFile: mainflux.Env(envOPCCertFile, defOPCCertFile),
		KeyFile:  mainflux.Env(envOPCKeyFile, defOPCKeyFile),
	}
	return config{
		httpPort:       mainflux.Env(envHTTPPort, defHTTPPort),
		opcuaConfig:    oc,
		natsURL:        mainflux.Env(envNatsURL, defNatsURL),
		logLevel:       mainflux.Env(envLogLevel, defLogLevel),
		esURL:          mainflux.Env(envESURL, defESURL),
		esPass:         mainflux.Env(envESPass, defESPass),
		esDB:           mainflux.Env(envESDB, defESDB),
		esConsumerName: mainflux.Env(envESConsumerName, defESConsumerName),
		routeMapURL:    mainflux.Env(envRouteMapURL, defRouteMapURL),
		routeMapPass:   mainflux.Env(envRouteMapPass, defRouteMapPass),
		routeMapDB:     mainflux.Env(envRouteMapDB, defRouteMapDB),
	}
}

func subscribeToStoredSubs(sub opcua.Subscriber, cfg opcua.Config, logger logger.Logger) {
	// Get all stored subscriptions
	nodes, err := db.ReadAll()
	if err != nil {
		logger.Warn(fmt.Sprintf("Read stored subscriptions failed: %s", err))
	}

	for _, n := range nodes {
		cfg.ServerURI = n.ServerURI
		cfg.NodeID = n.NodeID
		go func() {
			if err := sub.Subscribe(context.Background(), cfg); err != nil {
				logger.Warn(fmt.Sprintf("Subscription failed: %s", err))
			}
		}()
	}
}

func subscribeToOpcuaServer(gc opcua.Subscriber, cfg opcua.Config, logger logger.Logger) {
	if err := gc.Subscribe(context.Background(), cfg); err != nil {
		logger.Warn(fmt.Sprintf("OPC-UA Subscription failed: %s", err))
	}
}

func subscribeToThingsES(svc opcua.Service, client *r.Client, prefix string, logger logger.Logger) {
	eventStore := redis.NewEventStore(svc, client, prefix, logger)
	if err := eventStore.Subscribe(context.Background(), "mainflux.things"); err != nil {
		logger.Warn(fmt.Sprintf("Failed to subscribe to Redis event source: %s", err))
	}
}

func newRouteMapRepositoy(client *r.Client, prefix string, logger logger.Logger) opcua.RouteMapRepository {
	logger.Info(fmt.Sprintf("Connected to %s Redis Route-map", prefix))
	return redis.NewRouteMapRepository(client, prefix)
}

func newService(sub opcua.Subscriber, browser opcua.Browser, thingRM, chanRM, connRM opcua.RouteMapRepository, opcuaConfig opcua.Config, logger logger.Logger) opcua.Service {
	svc := opcua.New(sub, browser, thingRM, chanRM, connRM, opcuaConfig, logger)
	svc = api.LoggingMiddleware(svc, logger)
	counter, latency := internal.MakeMetrics(svcName, "api")
	svc = api.MetricsMiddleware(svc, counter, latency)

	return svc
}
