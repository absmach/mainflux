// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

// Package coap contains the domain concept definitions needed to support
// SuperMQ CoAP adapter service functionality. All constant values are taken
// from RFC, and could be adjusted based on specific use case.
package coap

import (
	"context"
	"fmt"

	grpcChannelsV1 "github.com/absmach/supermq/api/grpc/channels/v1"
	"github.com/absmach/supermq/pkg/connections"
	"github.com/absmach/supermq/pkg/errors"
	svcerr "github.com/absmach/supermq/pkg/errors/service"
	"github.com/absmach/supermq/pkg/messaging"
	"github.com/absmach/supermq/pkg/policies"
)

var errFailedToDisconnectClient = errors.New("failed to disconnect client")

const chansPrefix = "channels"

// Service specifies CoAP service API.
type Service interface {
	// Publish publishes message to specified channel.
	// Key is used to authorize publisher.
	Publish(ctx context.Context, clientID string, msg *messaging.Message) error

	// Subscribes to channel with specified id, subtopic and adds subscription to
	// service map of subscriptions under given ID.
	Subscribe(ctx context.Context, clientID, chanID, subtopic string, c Client) error

	// Unsubscribe method is used to stop observing resource.
	Unsubscribe(ctx context.Context, clientID, chanID, subptopic, token string) error
}

var _ Service = (*adapterService)(nil)

// Observers is a map of maps,.
type adapterService struct {
	channels grpcChannelsV1.ChannelsServiceClient
	pubsub   messaging.PubSub
}

// New instantiates the CoAP adapter implementation.
func New(channels grpcChannelsV1.ChannelsServiceClient, pubsub messaging.PubSub) Service {
	as := &adapterService{
		channels: channels,
		pubsub:   pubsub,
	}

	return as
}

func (svc *adapterService) Publish(ctx context.Context, clientID string, msg *messaging.Message) error {
	authzRes, err := svc.channels.Authorize(ctx, &grpcChannelsV1.AuthzReq{
		ClientId:   clientID,
		ClientType: policies.ClientType,
		Type:       uint32(connections.Publish),
		ChannelId:  msg.GetChannel(),
	})
	if err != nil {
		return errors.Wrap(svcerr.ErrAuthorization, err)
	}
	if !authzRes.Authorized {
		return svcerr.ErrAuthorization
	}

	msg.Publisher = clientID

	return svc.pubsub.Publish(ctx, msg.GetChannel(), msg)
}

func (svc *adapterService) Subscribe(ctx context.Context, clientID, chanID, subtopic string, c Client) error {
	authzRes, err := svc.channels.Authorize(ctx, &grpcChannelsV1.AuthzReq{
		ClientId:   clientID,
		ClientType: policies.ClientType,
		Type:       uint32(connections.Subscribe),
		ChannelId:  chanID,
	})
	if err != nil {
		return errors.Wrap(svcerr.ErrAuthorization, err)
	}
	if !authzRes.Authorized {
		return svcerr.ErrAuthorization
	}

	subject := fmt.Sprintf("%s.%s", chansPrefix, chanID)
	if subtopic != "" {
		subject = fmt.Sprintf("%s.%s", subject, subtopic)
	}

	authzc := newAuthzClient(clientID, chanID, subtopic, svc.channels, c)
	subCfg := messaging.SubscriberConfig{
		ID:      c.Token(),
		Topic:   subject,
		Handler: authzc,
	}
	return svc.pubsub.Subscribe(ctx, subCfg)
}

func (svc *adapterService) Unsubscribe(ctx context.Context, clientID, chanID, subtopic, token string) error {
	authzRes, err := svc.channels.Authorize(ctx, &grpcChannelsV1.AuthzReq{
		DomainId:   "",
		ClientId:   clientID,
		ClientType: policies.ClientType,
		Type:       uint32(connections.Subscribe),
		ChannelId:  chanID,
	})
	if err != nil {
		return errors.Wrap(svcerr.ErrAuthorization, err)
	}
	if !authzRes.Authorized {
		return svcerr.ErrAuthorization
	}

	subject := fmt.Sprintf("%s.%s", chansPrefix, chanID)
	if subtopic != "" {
		subject = fmt.Sprintf("%s.%s", subject, subtopic)
	}

	return svc.pubsub.Unsubscribe(ctx, token, subject)
}

func (svc *adapterService) DisconnectHandler(ctx context.Context, chanID, subtopic, token string) error {
	subject := fmt.Sprintf("%s.%s", chansPrefix, chanID)
	if subtopic != "" {
		subject = fmt.Sprintf("%s.%s", subject, subtopic)
	}

	return svc.pubsub.Unsubscribe(ctx, token, subject)
}

type authzClient interface {
	// Handle handles incoming messages.
	Handle(m *messaging.Message) error

	// Cancel cancels the client.
	Cancel() error
}

type ac struct {
	clientID  string
	channelID string
	subTopic  string
	channels  grpcChannelsV1.ChannelsServiceClient
	client    Client
}

func newAuthzClient(clientID, channelID, subTopic string, channels grpcChannelsV1.ChannelsServiceClient, client Client) authzClient {
	return ac{clientID, channelID, subTopic, channels, client}
}

func (a ac) Handle(m *messaging.Message) error {
	res, err := a.channels.Authorize(context.Background(), &grpcChannelsV1.AuthzReq{ClientId: a.clientID, ClientType: policies.ClientType, ChannelId: a.channelID, Type: uint32(connections.Subscribe)})
	if err != nil {
		if disErr := a.Cancel(); disErr != nil {
			return errors.Wrap(err, errors.Wrap(errFailedToDisconnectClient, disErr))
		}
		return err
	}
	if !res.GetAuthorized() {
		err := svcerr.ErrAuthorization
		if disErr := a.Cancel(); disErr != nil {
			return errors.Wrap(err, errors.Wrap(errFailedToDisconnectClient, disErr))
		}
		return err
	}
	return a.client.Handle(m)
}

func (a ac) Cancel() error {
	return a.client.Cancel()
}
