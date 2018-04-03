package main

import (
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/go-kit/kit/log"
	"github.com/mainflux/mainflux"
	"github.com/mainflux/mainflux/normalizer"
	nats "github.com/nats-io/go-nats"

	kitprometheus "github.com/go-kit/kit/metrics/prometheus"
	stdprometheus "github.com/prometheus/client_golang/prometheus"
)

const (
	defNatsURL string = nats.DefaultURL
	defPort    string = "8180"
	envNatsURL string = "MF_NATS_URL"
	envPort    string = "MF_NORMALIZER_PORT"
)

type config struct {
	NatsURL string
	Port    string
}

func main() {
	cfg := config{
		NatsURL: mainflux.Env(envNatsURL, defNatsURL),
		Port:    mainflux.Env(envPort, defPort),
	}

	logger := log.NewJSONLogger(log.NewSyncWriter(os.Stdout))
	logger = log.With(logger, "ts", log.DefaultTimestampUTC)

	nc, err := nats.Connect(cfg.NatsURL)
	if err != nil {
		logger.Log("error", fmt.Sprintf("Failed to connect: %s", err))
		os.Exit(1)
	}
	defer nc.Close()

	errs := make(chan error, 2)

	go func() {
		p := fmt.Sprintf(":%s", cfg.Port)
		logger.Log("message", fmt.Sprintf("Normalizer service started, exposed port %s", cfg.Port))
		errs <- http.ListenAndServe(p, normalizer.MakeHandler())
	}()

	go func() {
		c := make(chan os.Signal)
		signal.Notify(c, syscall.SIGINT)
		errs <- fmt.Errorf("%s", <-c)
	}()

	counter := kitprometheus.NewCounterFrom(stdprometheus.CounterOpts{
		Namespace: "normalizer",
		Subsystem: "api",
		Name:      "request_count",
		Help:      "Number of requests received.",
	}, []string{"method"})

	latency := kitprometheus.NewSummaryFrom(stdprometheus.SummaryOpts{
		Namespace: "normalizer",
		Subsystem: "api",
		Name:      "request_latency_microseconds",
		Help:      "Total duration of requests in microseconds.",
	}, []string{"method"})

	normalizer.Subscribe(nc, logger, counter, latency)
	logger.Log("terminated", <-errs)
}
