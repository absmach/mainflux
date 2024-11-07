// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"time"

	"github.com/absmach/magistrala/clients"
)

// Config represents Configuration entity. It wraps information about external entity
// as well as info about corresponding Magistrala entities.
// MGThing represents corresponding Magistrala Thing ID.
// MGKey is key of corresponding Magistrala Thing.
// MGChannels is a list of Magistrala Channels corresponding Magistrala Thing connects to.
type Config struct {
	ClientID    string    `json:"client_id"`
	DomainID    string    `json:"domain_id,omitempty"`
	Name        string    `json:"name,omitempty"`
	ClientCert  string    `json:"client_cert,omitempty"`
	ClientKey   string    `json:"client_key,omitempty"`
	CACert      string    `json:"ca_cert,omitempty"`
	ThingKey    string    `json:"thing_key"`
	Channels    []Channel `json:"channels,omitempty"`
	ExternalID  string    `json:"external_id"`
	ExternalKey string    `json:"external_key"`
	Content     string    `json:"content,omitempty"`
	State       State     `json:"state"`
}

// Channel represents Magistrala channel corresponding Magistrala Thing is connected to.
type Channel struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	DomainID    string                 `json:"domain_id"`
	Parent      string                 `json:"parent_id,omitempty"`
	Description string                 `json:"description,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at,omitempty"`
	UpdatedBy   string                 `json:"updated_by,omitempty"`
	Status      clients.Status         `json:"status"`
}

// Filter is used for the search filters.
type Filter struct {
	FullMatch    map[string]string
	PartialMatch map[string]string
}

// ConfigsPage contains page related metadata as well as list of Configs that
// belong to this page.
type ConfigsPage struct {
	Total   uint64   `json:"total"`
	Offset  uint64   `json:"offset"`
	Limit   uint64   `json:"limit"`
	Configs []Config `json:"configs"`
}

// ConfigRepository specifies a Config persistence API.
//
//go:generate mockery --name ConfigRepository --output=./mocks --filename configs.go --quiet --note "Copyright (c) Abstract Machines"
type ConfigRepository interface {
	// Save persists the Config. Successful operation is indicated by non-nil
	// error response.
	Save(ctx context.Context, cfg Config, chsConnIDs []string) (string, error)

	// RetrieveByID retrieves the Config having the provided identifier, that is owned
	// by the specified user.
	RetrieveByID(ctx context.Context, domainID, id string) (Config, error)

	// RetrieveAll retrieves a subset of Configs that are owned
	// by the specific user, with given filter parameters.
	RetrieveAll(ctx context.Context, domainID string, thingIDs []string, filter Filter, offset, limit uint64) ConfigsPage

	// RetrieveByExternalID returns Config for given external ID.
	RetrieveByExternalID(ctx context.Context, externalID string) (Config, error)

	// Update updates an existing Config. A non-nil error is returned
	// to indicate operation failure.
	Update(ctx context.Context, cfg Config) error

	// UpdateCerts updates and returns an existing Config certificate and domainID.
	// A non-nil error is returned to indicate operation failure.
	UpdateCert(ctx context.Context, domainID, thingID, clientCert, clientKey, caCert string) (Config, error)

	// UpdateConnections updates a list of Channels the Config is connected to
	// adding new Channels if needed.
	UpdateConnections(ctx context.Context, domainID, id string, channels []Channel, connections []string) error

	// Remove removes the Config having the provided identifier, that is owned
	// by the specified user.
	Remove(ctx context.Context, domainID, id string) error

	// ChangeState changes of the Config, that is owned by the specific user.
	ChangeState(ctx context.Context, domainID, id string, state State) error

	// ListExisting retrieves those channels from the given list that exist in DB.
	ListExisting(ctx context.Context, domainID string, ids []string) ([]Channel, error)

	// Methods RemoveThing, UpdateChannel, and RemoveChannel are related to
	// event sourcing. That's why these methods surpass ownership check.

	// RemoveThing removes Config of the Thing with the given ID.
	RemoveThing(ctx context.Context, id string) error

	// UpdateChannel updates channel with the given ID.
	UpdateChannel(ctx context.Context, c Channel) error

	// RemoveChannel removes channel with the given ID.
	RemoveChannel(ctx context.Context, id string) error

	// ConnectThing changes state of the Config when the corresponding Thing is connected to the Channel.
	ConnectThing(ctx context.Context, channelID, thingID string) error

	// DisconnectThing changes state of the Config when the corresponding Thing is disconnected from the Channel.
	DisconnectThing(ctx context.Context, channelID, thingID string) error
}
