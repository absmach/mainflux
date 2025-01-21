// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package events

import (
	"context"

	"github.com/absmach/supermq/coap"
	"github.com/absmach/supermq/pkg/events"
	"github.com/absmach/supermq/pkg/events/store"
	"github.com/absmach/supermq/pkg/messaging"
)

const streamID = "supermq.coap"

type eventStore struct {
	events events.Publisher
	svc    coap.Service
}

// NewEventStoreMiddleware returns wrapper around coap service that sends
// events to event store.
func NewEventStoreMiddleware(ctx context.Context, svc coap.Service, url string) (coap.Service, error) {
	publisher, err := store.NewPublisher(ctx, url, streamID)
	if err != nil {
		return nil, err
	}

	return &eventStore{
		svc:    svc,
		events: publisher,
	}, nil
}

func (es *eventStore) Publish(ctx context.Context, clientID string, msg *messaging.Message) error {
	err := es.svc.Publish(ctx, clientID, msg)
	if err != nil {
		return err
	}

	event := clientPublishEvent{
		ClientID:  clientID,
		ChannelID: msg.GetChannel(),
		Topic:     msg.GetSubtopic(),
	}
	if err := es.events.Publish(ctx, event); err != nil {
		return err
	}

	return nil
}

func (es *eventStore) Subscribe(ctx context.Context, clientID, channelID, subtopic string, c coap.Client) error {
	err := es.svc.Subscribe(ctx, clientID, channelID, subtopic, c)
	if err != nil {
		return err
	}

	event := clientSubscribeEvent{
		ClientID:  clientID,
		ChannelID: channelID,
		Topic:     subtopic,
	}
	if err := es.events.Publish(ctx, event); err != nil {
		return err
	}

	return nil
}

func (es *eventStore) Unsubscribe(ctx context.Context, clientID, channelID, subtopic, token string) error {
	err := es.svc.Unsubscribe(ctx, clientID, channelID, subtopic, token)
	if err != nil {
		return err
	}

	event := clientUnsubscribeEvent{
		ClientID:  clientID,
		ChannelID: channelID,
		Topic:     subtopic,
	}
	if err := es.events.Publish(ctx, event); err != nil {
		return err
	}

	return nil
}
