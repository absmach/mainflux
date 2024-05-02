// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package coap

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/absmach/magistrala/internal/server"
	gocoap "github.com/plgd-dev/go-coap/v3"
	"github.com/plgd-dev/go-coap/v3/mux"
	"github.com/plgd-dev/go-coap/v3/options"
	udpServer "github.com/plgd-dev/go-coap/v3/udp/server"
)

const (
	stopWaitTime = 5 * time.Second
)

type Server struct {
	server.BaseServer
	handler mux.HandlerFunc
}

var _ server.Server = (*Server)(nil)

func New(ctx context.Context, cancel context.CancelFunc, name string, config server.Config, handler mux.HandlerFunc, logger *slog.Logger) server.Server {
	listenFullAddress := fmt.Sprintf("%s:%s", config.Host, config.Port)
	return &Server{
		BaseServer: server.BaseServer{
			Ctx:     ctx,
			Cancel:  cancel,
			Name:    name,
			Address: listenFullAddress,
			Config:  config,
			Logger:  logger,
		},
		handler: handler,
	}
}

type udpNilMonitor struct{}

func (u *udpNilMonitor) UDPServerApply(cfg *udpServer.Config) {
	cfg.CreateInactivityMonitor = nil
}

var _ udpServer.Option = (*udpNilMonitor)(nil)

func NewUDPNilMonitor() udpServer.Option {
	return &udpNilMonitor{}
}

func (s *Server) Start() error {
	errCh := make(chan error)
	s.Logger.Info(fmt.Sprintf("%s service started using http, exposed port %s", s.Name, s.Address))
	s.Logger.Info(fmt.Sprintf("%s service %s server listening at %s without TLS", s.Name, s.Protocol, s.Address))

	opts := []any{}
	opts = append(opts, options.WithMux(s.handler), NewUDPNilMonitor())
	go func() {
		errCh <- gocoap.ListenAndServeWithOptions("udp", s.Address, opts...)
	}()

	select {
	case <-s.Ctx.Done():
		return s.Stop()
	case err := <-errCh:
		return err
	}
}

func (s *Server) Stop() error {
	defer s.Cancel()
	c := make(chan bool)
	defer close(c)
	select {
	case <-c:
	case <-time.After(stopWaitTime):
	}
	s.Logger.Info(fmt.Sprintf("%s service shutdown of http at %s", s.Name, s.Address))
	return nil
}
