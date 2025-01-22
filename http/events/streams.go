// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package events

import (
	"context"

	"github.com/absmach/supermq/pkg/events"
	"github.com/absmach/supermq/pkg/events/store"
)

const streamID = "supermq.http"

//go:generate mockery --name EventStore --output=../mocks --filename events.go --quiet --note "Copyright (c) Abstract Machines"
type EventStore interface {
	Connect(ctx context.Context, clientID string) error
	Publish(ctx context.Context, clientID, channelID, topic string) error
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

func (es *eventStore) Connect(ctx context.Context, clientID string) error {
	ev := httpEvent{
		clientID:  clientID,
		operation: clientConnect,
		instance:  es.instance,
	}

	return es.publisher.Publish(ctx, ev)
}

func (es *eventStore) Publish(ctx context.Context, clientID, channelID, topic string) error {
	ev := httpEvent{
		clientID:  clientID,
		operation: clientPublish,
		channelID: channelID,
		topic:     topic,
		instance:  es.instance,
	}

	return es.publisher.Publish(ctx, ev)
}
