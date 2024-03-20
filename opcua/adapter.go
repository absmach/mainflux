// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package opcua

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"

	"github.com/absmach/magistrala/opcua/db"
)

// Service specifies an API that must be fullfiled by the domain service
// implementation, and all of its decorators (e.g. logging & metrics).
type Service interface {
	// CreateThing creates thingID:OPC-UA-nodeID route-map
	CreateThing(ctx context.Context, thingID, nodeID string) error

	// UpdateThing updates thingID:OPC-UA-nodeID route-map
	UpdateThing(ctx context.Context, thingID, nodeID string) error

	// RemoveThing removes thingID:OPC-UA-nodeID route-map
	RemoveThing(ctx context.Context, thingID string) error

	// CreateChannel creates channelID:OPC-UA-serverURI route-map
	CreateChannel(ctx context.Context, chanID, serverURI string) error

	// UpdateChannel updates channelID:OPC-UA-serverURI route-map
	UpdateChannel(ctx context.Context, chanID, serverURI string) error

	// RemoveChannel removes channelID:OPC-UA-serverURI route-map
	RemoveChannel(ctx context.Context, chanID string) error

	// ConnectThing creates thingID:channelID route-map
	ConnectThing(ctx context.Context, chanID string, thingIDs []string) error

	// DisconnectThing removes thingID:channelID route-map
	DisconnectThing(ctx context.Context, chanID string, thingIDs []string) error

	// Browse browses available nodes for a given OPC-UA Server URI and NodeID
	Browse(ctx context.Context, serverURI, namespace, identifier, identifierType string) ([]BrowsedNode, error)
}

// Config OPC-UA Server.
type Config struct {
	ServerURI string
	NodeID    string
	Interval  string `env:"MG_OPCUA_ADAPTER_INTERVAL_MS"     envDefault:"1000"`
	Policy    string `env:"MG_OPCUA_ADAPTER_POLICY"          envDefault:""`
	Mode      string `env:"MG_OPCUA_ADAPTER_MODE"            envDefault:""`
	CertFile  string `env:"MG_OPCUA_ADAPTER_CERT_FILE"       envDefault:""`
	KeyFile   string `env:"MG_OPCUA_ADAPTER_KEY_FILE"        envDefault:""`
}

var _ Service = (*adapterService)(nil)

type adapterService struct {
	subscriber Subscriber
	browser    Browser
	thingsRM   RouteMapRepository
	channelsRM RouteMapRepository
	connectRM  RouteMapRepository
	cfg        Config
	logger     *slog.Logger
}

// New instantiates the OPC-UA adapter implementation.
func New(sub Subscriber, brow Browser, thingsRM, channelsRM, connectRM RouteMapRepository, cfg Config, log *slog.Logger) Service {
	return &adapterService{
		subscriber: sub,
		browser:    brow,
		thingsRM:   thingsRM,
		channelsRM: channelsRM,
		connectRM:  connectRM,
		cfg:        cfg,
		logger:     log,
	}
}

func (as *adapterService) CreateThing(ctx context.Context, thingID, nodeID string) error {
	return as.thingsRM.Save(ctx, thingID, nodeID)
}

func (as *adapterService) UpdateThing(ctx context.Context, thingID, nodeID string) error {
	return as.thingsRM.Save(ctx, thingID, nodeID)
}

func (as *adapterService) RemoveThing(ctx context.Context, thingID string) error {
	return as.thingsRM.Remove(ctx, thingID)
}

func (as *adapterService) CreateChannel(ctx context.Context, chanID, serverURI string) error {
	return as.channelsRM.Save(ctx, chanID, serverURI)
}

func (as *adapterService) UpdateChannel(ctx context.Context, chanID, serverURI string) error {
	return as.channelsRM.Save(ctx, chanID, serverURI)
}

func (as *adapterService) RemoveChannel(ctx context.Context, chanID string) error {
	return as.channelsRM.Remove(ctx, chanID)
}

func (as *adapterService) ConnectThing(ctx context.Context, chanID string, thingIDs []string) error {
	serverURI, err := as.channelsRM.Get(ctx, chanID)
	if err != nil {
		return err
	}

	for _, thingID := range thingIDs {
		nodeID, err := as.thingsRM.Get(ctx, thingID)
		if err != nil {
			return err
		}

		as.cfg.NodeID = nodeID
		as.cfg.ServerURI = serverURI

		c := fmt.Sprintf("%s:%s", chanID, thingID)
		if err := as.connectRM.Save(ctx, c, c); err != nil {
			return err
		}

		go func() {
			if err := as.subscriber.Subscribe(ctx, as.cfg); err != nil {
				as.logger.Warn("subscription failed", slog.String("error", err.Error()))
			}
		}()

		// Store subscription details
		if err := db.Save(serverURI, nodeID); err != nil {
			return err
		}
	}

	return nil
}

func (as *adapterService) Browse(ctx context.Context, serverURI, namespace, identifier, identifierType string) ([]BrowsedNode, error) {
	var nodeID string

	switch identifierType {
	case "string":
		nodeID = fmt.Sprintf("ns=%s;s=%s", namespace, identifier)
	case "numeric":
		numericIdentifier, err := strconv.Atoi(identifier) // Convert identifier to int
		if err != nil {
			nodeID = fmt.Sprintf("ns=%s;s=%s", namespace, identifier)
			args := []any{
				slog.String("namespace", namespace),
				slog.String("identifier", identifier),
				slog.String("error", err.Error()),
			}
			as.logger.Warn("failed to parse numeric identifier", args...)
			break
		}
		nodeID = fmt.Sprintf("ns=%s;i=%d", namespace, numericIdentifier)
	case "guid":
		nodeID = fmt.Sprintf("ns=%s;g=%s", namespace, identifier)
	case "opaque":
		nodeID = fmt.Sprintf("ns=%s;b=%s", namespace, identifier)
	default:
		nodeID = fmt.Sprintf("ns=%s;s=%s", namespace, identifier)
	}

	nodes, err := as.browser.Browse(serverURI, nodeID)
	if err != nil {
		return nil, err
	}
	return nodes, nil
}

func (as *adapterService) DisconnectThing(ctx context.Context, chanID string, thingIDs []string) error {
	for _, thingID := range thingIDs {
		c := fmt.Sprintf("%s:%s", chanID, thingID)
		if err := as.connectRM.Remove(ctx, c); err != nil {
			return err
		}
	}
	return nil
}
