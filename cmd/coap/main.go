// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

// Package main contains coap-adapter main function to start the coap-adapter service.
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	chclient "github.com/mainflux/callhome/pkg/client"
	"github.com/mainflux/mainflux"
	"github.com/mainflux/mainflux/coap"
	"github.com/mainflux/mainflux/coap/api"
	"github.com/mainflux/mainflux/coap/tracing"
	"github.com/mainflux/mainflux/internal"
	authapi "github.com/mainflux/mainflux/internal/clients/grpc/auth"
	jaegerclient "github.com/mainflux/mainflux/internal/clients/jaeger"
	"github.com/mainflux/mainflux/internal/env"
	"github.com/mainflux/mainflux/internal/server"
	coapserver "github.com/mainflux/mainflux/internal/server/coap"
	httpserver "github.com/mainflux/mainflux/internal/server/http"
	mflog "github.com/mainflux/mainflux/logger"
	"github.com/mainflux/mainflux/pkg/messaging/brokers"
	brokerstracing "github.com/mainflux/mainflux/pkg/messaging/brokers/tracing"
	"github.com/mainflux/mainflux/pkg/uuid"
	mp "github.com/mainflux/mproxy/pkg/coap"
	"github.com/mainflux/mproxy/pkg/session"
	"github.com/mainflux/mproxy/pkg/tls"
	"golang.org/x/sync/errgroup"
)

const (
	svcName        = "coap_adapter"
	envPrefix      = "MF_COAP_ADAPTER_"
	envPrefixHTTP  = "MF_COAP_ADAPTER_HTTP_"
	defSvcHTTPPort = "5683"
	defSvcCoAPPort = "5683"
	targetHost     = ""
	targetPort     = "5684"
)

type config struct {
	LogLevel      string  `env:"MF_COAP_ADAPTER_LOG_LEVEL"   envDefault:"info"`
	BrokerURL     string  `env:"MF_MESSAGE_BROKER_URL"       envDefault:"nats://localhost:4222"`
	JaegerURL     string  `env:"MF_JAEGER_URL"               envDefault:"http://jaeger:14268/api/traces"`
	SendTelemetry bool    `env:"MF_SEND_TELEMETRY"           envDefault:"true"`
	InstanceID    string  `env:"MF_COAP_ADAPTER_INSTANCE_ID" envDefault:""`
	TraceRatio    float64 `env:"MF_JAEGER_TRACE_RATIO"       envDefault:"1.0"`
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

	if cfg.InstanceID == "" {
		if cfg.InstanceID, err = uuid.New().ID(); err != nil {
			logger.Error(fmt.Sprintf("failed to generate instanceID: %s", err))
			exitCode = 1
			return
		}
	}

	httpServerConfig := server.Config{Port: defSvcHTTPPort}
	if err := env.Parse(&httpServerConfig, env.Options{Prefix: envPrefixHTTP}); err != nil {
		logger.Error(fmt.Sprintf("failed to load %s HTTP server configuration : %s", svcName, err))
		exitCode = 1
		return
	}

	coapServerConfig := server.Config{Port: defSvcCoAPPort}
	if err := env.Parse(&coapServerConfig, env.Options{Prefix: envPrefix}); err != nil {
		logger.Error(fmt.Sprintf("failed to load %s CoAP server configuration : %s", svcName, err))
		exitCode = 1
		return
	}

	auth, aHandler, err := authapi.SetupAuthz(svcName)
	targetCoAPServerCfg := server.Config{
		Host: targetHost,
		Port: targetPort,
	}

	if err != nil {
		logger.Error(err.Error())
		exitCode = 1
		return
	}
	defer aHandler.Close()

	logger.Info("Successfully connected to things grpc server " + aHandler.Secure())

	tp, err := jaegerclient.NewProvider(svcName, cfg.JaegerURL, cfg.InstanceID, cfg.TraceRatio)
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

	nps, err := brokers.NewPubSub(ctx, cfg.BrokerURL, logger)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to connect to message broker: %s", err))
		exitCode = 1
		return
	}
	defer nps.Close()
	nps = brokerstracing.NewPubSub(targetCoAPServerCfg, tracer, nps)

	svc := coap.New(auth, nps)

	svc = tracing.New(tracer, svc)

	svc = api.LoggingMiddleware(svc, logger)

	counter, latency := internal.MakeMetrics(svcName, "api")
	svc = api.MetricsMiddleware(svc, counter, latency)

	hs := httpserver.New(ctx, cancel, svcName, targetCoAPServerCfg, api.MakeHandler(cfg.InstanceID), logger)

	cs := coapserver.New(ctx, cancel, svcName, targetCoAPServerCfg, api.MakeCoAPHandler(svc, logger), logger)

	if cfg.SendTelemetry {
		chc := chclient.New(svcName, mainflux.Version, logger, cancel)
		go chc.CallHome(ctx)
	}

	g.Go(func() error {
		return hs.Start()
	})
	g.Go(func() error {
		g.Go(func() error {
			return cs.Start()
		})
		return proxyCoAP(ctx, coapServerConfig, logger, coap.NewHandler(nps, logger, auth))
	})
	g.Go(func() error {
		return server.StopSignalHandler(ctx, cancel, logger, svcName, hs, cs)
	})

	if err := g.Wait(); err != nil {
		logger.Error(fmt.Sprintf("CoAP adapter service terminated: %s", err))
	}
}

func proxyCoAP(ctx context.Context, cfg server.Config, logger mflog.Logger, handler session.Handler) error {
	address := fmt.Sprintf("%s:%s", cfg.Host, cfg.Port)
	target := fmt.Sprintf("%s:%s", targetHost, targetPort)
	mp, err := mp.NewProxy(address, target, logger, handler)
	if err != nil {
		return err
	}

	errCh := make(chan error)

	switch {
	case cfg.CertFile != "" || cfg.KeyFile != "":
		tlscfg, err := tls.LoadTLSCfg(cfg.ServerCAFile, cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return err
		}
		go func() {
			errCh <- mp.ListenTLS(tlscfg)
		}()
	default:
		go func() {
			errCh <- mp.Listen()
		}()
	}

	select {
	case <-ctx.Done():
		logger.Info(fmt.Sprintf("proxy MQTT shutdown at %s", target))
		return nil
	case err := <-errCh:
		return err
	}
}
