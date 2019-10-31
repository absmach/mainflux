// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/mainflux/mainflux"
	"github.com/mainflux/mainflux/logger"
	"github.com/mainflux/mainflux/transformers/senml"
	"github.com/mainflux/mainflux/transformers/senml/api"
	"github.com/mainflux/mainflux/transformers/senml/nats"
	broker "github.com/nats-io/go-nats"

	kitprometheus "github.com/go-kit/kit/metrics/prometheus"
	stdprometheus "github.com/prometheus/client_golang/prometheus"
)

const (
	defNatsURL  string = broker.DefaultURL
	defLogLevel string = "error"
	defPort     string = "8180"
	envNatsURL  string = "MF_NATS_URL"
	envLogLevel string = "MF_SENML_TRANSFORMER_LOG_LEVEL"
	envPort     string = "MF_SENML_TRANSFORMER_PORT"
)

type config struct {
	NatsURL  string
	LogLevel string
	Port     string
}

func main() {
	cfg := loadConfig()

	logger, err := logger.New(os.Stdout, cfg.LogLevel)
	if err != nil {
		log.Fatalf(err.Error())
	}
	nc, err := broker.Connect(cfg.NatsURL)
	if err != nil {
		logger.Error(fmt.Sprintf("Failed to connect to NATS: %s", err))
		os.Exit(1)
	}
	defer nc.Close()

	svc := senml.New()
	svc = api.LoggingMiddleware(svc, logger)
	svc = api.MetricsMiddleware(
		svc,
		kitprometheus.NewCounterFrom(stdprometheus.CounterOpts{
			Namespace: "senml",
			Subsystem: "transfomer",
			Name:      "request_count",
			Help:      "Number of requests received.",
		}, []string{"method"}),
		kitprometheus.NewSummaryFrom(stdprometheus.SummaryOpts{
			Namespace: "senml",
			Subsystem: "transformer",
			Name:      "request_latency_microseconds",
			Help:      "Total duration of requests in microseconds.",
		}, []string{"method"}),
	)

	errs := make(chan error, 2)

	go func() {
		p := fmt.Sprintf(":%s", cfg.Port)
		logger.Info(fmt.Sprintf("SenML Transformer service started, exposed port %s", cfg.Port))
		errs <- http.ListenAndServe(p, api.MakeHandler())
	}()

	go func() {
		c := make(chan os.Signal)
		signal.Notify(c, syscall.SIGINT)
		errs <- fmt.Errorf("%s", <-c)
	}()

	nats.Subscribe(svc, nc, logger)

	err = <-errs
	logger.Error(fmt.Sprintf("SenML Transformer service terminated: %s", err))
}

func loadConfig() config {
	return config{
		NatsURL:  mainflux.Env(envNatsURL, defNatsURL),
		LogLevel: mainflux.Env(envLogLevel, defLogLevel),
		Port:     mainflux.Env(envPort, defPort),
	}
}
