package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	kitprometheus "github.com/go-kit/kit/metrics/prometheus"
	"github.com/mainflux/mainflux"
	log "github.com/mainflux/mainflux/logger"
	"github.com/mainflux/mainflux/writers"
	mongodb "github.com/mainflux/mainflux/writers/mongodb"
	"github.com/mongodb/mongo-go-driver/mongo"
	nats "github.com/nats-io/go-nats"
	stdprometheus "github.com/prometheus/client_golang/prometheus"
)

const (
	name       = "mongodb-writer"
	defNatsURL = nats.DefaultURL
	defPort    = "8180"
	defDBName  = "mainflux"
	defDBHost  = "localhost"
	defDBPort  = "27017"
	defDBUser  = "mainflux"
	defDBPass  = "mainflux"

	envNatsURL = "MF_NATS_URL"
	envPort    = "MF_MONGO_WRITER_PORT"
	envDBName  = "MF_MONGO_WRITER_DB_NAME"
	envDBHost  = "MF_MONGO_WRITER_DB_HOST"
	envDBPort  = "MF_MONGO_WRITER_DB_PORT"
	envDBUser  = "MF_MONGO_WRITER_DB_USER"
	envDBPass  = "MF_MONGO_WRITER_DB_PASS"
)

type config struct {
	NatsURL string
	Port    string
	DBName  string
	DBHost  string
	DBPort  string
	DBUser  string
	DBPass  string
}

func main() {
	cfg := loadConfigs()
	logger := log.New(os.Stdout)

	nc, err := nats.Connect(cfg.NatsURL)
	if err != nil {
		logger.Error(fmt.Sprintf("Failed to connect to NATS: %s", err))
		os.Exit(1)
	}
	defer nc.Close()

	ms, err := connect("mongodb://"+cfg.DBHost+":"+cfg.DBPort, cfg.DBName)
	if err != nil {
		logger.Error("Failed to connect to Mongo.")
		os.Exit(1)
	}

	repo, err := mongodb.New(ms)
	if err != nil {
		logger.Error(fmt.Sprintf("Failed to create MongoDB writer: %s", err.Error()))
		os.Exit(1)
	}

	counter, latency := makeMetrices()
	if err := writers.Start(name, nc, logger, repo, counter, latency); err != nil {
		logger.Error(fmt.Sprintf("Failed to start message writer: %s", err))
		os.Exit(1)
	}

	errs := make(chan error, 2)
	go func() {
		c := make(chan os.Signal)
		signal.Notify(c, syscall.SIGINT)
		errs <- fmt.Errorf("%s", <-c)
	}()

	go startHTTPService(cfg.Port, logger, errs)

	err = <-errs
	logger.Error(fmt.Sprintf("Mongodb writer service terminated: %s", err))
}

func loadConfigs() config {
	cfg := config{
		NatsURL: mainflux.Env(envNatsURL, defNatsURL),
		Port:    mainflux.Env(envPort, defPort),
		DBName:  mainflux.Env(envDBName, defDBName),
		DBHost:  mainflux.Env(envDBHost, defDBHost),
		DBPort:  mainflux.Env(envDBPort, defDBPort),
		DBUser:  mainflux.Env(envDBUser, defDBUser),
		DBPass:  mainflux.Env(envDBPass, defDBPass),
	}

	return cfg
}

func connect(addr string, dbName string) (*mongo.Database, error) {
	client, err := mongo.Connect(context.Background(), addr, nil)

	if err != nil {
		return nil, err
	}

	db := client.Database(dbName)
	return db, nil
}

func makeMetrices() (*kitprometheus.Counter, *kitprometheus.Summary) {
	counter := kitprometheus.NewCounterFrom(stdprometheus.CounterOpts{
		Namespace: "mongodb",
		Subsystem: "message_writer",
		Name:      "request_count",
		Help:      "Number of database inserts.",
	}, []string{"method"})

	latency := kitprometheus.NewSummaryFrom(stdprometheus.SummaryOpts{
		Namespace: "mongodb",
		Subsystem: "message_writer",
		Name:      "request_latency_microseconds",
		Help:      "Total duration of inserts in microseconds.",
	}, []string{"method"})

	return counter, latency
}

func startHTTPService(port string, logger log.Logger, errs chan error) {
	p := fmt.Sprintf(":%s", port)
	logger.Info(fmt.Sprintf("Mongodb writer service started, exposed port %s", p))
	errs <- http.ListenAndServe(p, mongodb.MakeHandler())
}
