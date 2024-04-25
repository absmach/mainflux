// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package coap

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/absmach/magistrala/internal/server"
	"github.com/plgd-dev/go-coap/v3/mux"
	"github.com/plgd-dev/go-coap/v3/net"
	"github.com/plgd-dev/go-coap/v3/options"
	"github.com/plgd-dev/go-coap/v3/udp"
	udpClient "github.com/plgd-dev/go-coap/v3/udp/client"
)

// const (
// 	stopWaitTime = 5 * time.Second
// )

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

func (s *Server) Start() error {
	errCh := make(chan error)
	s.Logger.Info(fmt.Sprintf("%s service started using http, exposed port %s", s.Name, s.Address))
	s.Logger.Info(fmt.Sprintf("%s service %s server listening at %s without TLS", s.Name, s.Protocol, s.Address))
	l, err := net.NewListenUDP("udp", s.Address)
	if err != nil {
		return err
	}
	defer l.Close()

	s.Logger.Info(fmt.Sprintf("CoAP proxy server started at %s without DTLS", s.Address))

	dummyInactiveFunc := func(cc *udpClient.Conn) {
		// This function intentionally left blank.
	}
	cs := udp.NewServer(
		options.WithMux(mux.HandlerFunc(s.handler)),
		options.WithKeepAlive(10, 10*time.Minute, dummyInactiveFunc),
	)

	go func() {
		errCh <- cs.Serve(l)
	}()

	select {
	case <-s.Ctx.Done():
		s.Logger.Info(fmt.Sprintf("CoAP proxy server at %s without DTLS exiting ...", s.Address))
		l.Close()
	case err := <-errCh:
		s.Logger.Error(fmt.Sprintf("CoAP proxy server at %s without DTLS exiting with errors: %s", s.Address, err.Error()))
		return err
	}
	return nil
	// select {
	// case <-s.Ctx.Done():
	// 	return s.Stop()
	// case err := <-errCh:
	// 	return err
	// }
}

func (s *Server) Stop() error {
	// 	defer s.Cancel()
	// 	c := make(chan bool)
	// 	defer close(c)
	// 	select {
	// 	case <-c:
	// 	case <-time.After(stopWaitTime):
	// 	}
	// 	s.Logger.Info(fmt.Sprintf("%s service shutdown of http at %s", s.Name, s.Address))
	return nil
}
