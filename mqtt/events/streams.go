// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package events

import (
	"context"

	"github.com/absmach/supermq/pkg/events"
	"github.com/absmach/supermq/pkg/events/store"
)

const streamID = "supermq.mqtt"

//go:generate mockery --name EventStore --output=../mocks --filename events.go --quiet --note "Copyright (c) Abstract Machines"
type EventStore interface {
	Connect(ctx context.Context, clientID, connID string) error
	Disconnect(ctx context.Context, clientID, connID string) error
	Publish(ctx context.Context, clientID, channelID, topic string) error
	Subscribe(ctx context.Context, clientID, channelID, connID, subtopic string) error
	Unsubscribe(ctx context.Context, clientID, channelID, connID, subtopic string) error
}

// EventStore is a struct used to store event streams in Redis.
type eventStore struct {
	publisher events.Publisher
	instance  string
}

// NewEventStore returns wrapper around mProxy service that sends
// events to event store.
func NewEventStore(ctx context.Context, url, instance string) (EventStore, error) {
	publisher, err := store.NewPublisher(ctx, url, streamID)
	if err != nil {
		return nil, err
	}

	return &eventStore{
		instance:  instance,
		publisher: publisher,
	}, nil
}

// Connect issues event on MQTT CONNECT.
func (es *eventStore) Connect(ctx context.Context, clientID, connID string) error {
	ev := mqttEvent{
		clientID:  clientID,
		operation: clientConnect,
		connID:    connID,
		instance:  es.instance,
	}

	return es.publisher.Publish(ctx, ev)
}

// Disconnect issues event on MQTT CONNECT.
func (es *eventStore) Disconnect(ctx context.Context, clientID, connID string) error {
	ev := mqttEvent{
		clientID:  clientID,
		operation: clientDisconnect,
		connID:    connID,
		instance:  es.instance,
	}

	return es.publisher.Publish(ctx, ev)
}

// Publish issues event on MQTT PUBLISH.
func (es *eventStore) Publish(ctx context.Context, clientID, channelID, topic string) error {
	ev := mqttEvent{
		clientID:  clientID,
		operation: clientPublish,
		channelID: channelID,
		topic:     topic,
		instance:  es.instance,
	}

	return es.publisher.Publish(ctx, ev)
}

// Subscribe issues event on MQTT SUBSCRIBE.
func (es *eventStore) Subscribe(ctx context.Context, clientID, channelID, connID, subtopic string) error {
	ev := mqttEvent{
		clientID:  clientID,
		operation: clientSubscribe,
		channelID: channelID,
		connID:    connID,
		topic:     subtopic,
		instance:  es.instance,
	}

	return es.publisher.Publish(ctx, ev)
}

// Unsubscribe issues event on MQTT UNSUBSCRIBE.
func (es *eventStore) Unsubscribe(ctx context.Context, clientID, channelID, connID, subtopic string) error {
	ev := mqttEvent{
		clientID:  clientID,
		operation: clientUnsubscribe,
		channelID: channelID,
		connID:    connID,
		topic:     subtopic,
		instance:  es.instance,
	}

	return es.publisher.Publish(ctx, ev)
}
