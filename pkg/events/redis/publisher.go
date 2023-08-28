// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package redis

import (
	"context"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/mainflux/mainflux/pkg/events"
)

type eventStore struct {
	client            *redis.Client
	unpublishedEvents chan *redis.XAddArgs
	streamID          string
	streamLen         int64
	mu                sync.Mutex
}

func NewEventStore(ctx context.Context, url, streamID string, streamLen int64) (events.Publisher, error) {
	opts, err := redis.ParseURL(url)
	if err != nil {
		return nil, err
	}

	es := &eventStore{
		client:            redis.NewClient(opts),
		unpublishedEvents: make(chan *redis.XAddArgs, events.MaxUnpublishedEvents),
		streamID:          streamID,
		streamLen:         streamLen,
	}

	go es.StartPublishingRoutine(ctx)

	return es, nil
}

func (es *eventStore) Publish(ctx context.Context, event events.Event) error {
	values, err := event.Encode()
	if err != nil {
		return err
	}
	values["occurred_at"] = time.Now().UnixNano()

	record := &redis.XAddArgs{
		Stream:       es.streamID,
		MaxLenApprox: es.streamLen,
		Values:       values,
	}

	if err := es.checkRedisConnection(ctx); err != nil {
		es.mu.Lock()
		defer es.mu.Unlock()

		select {
		case es.unpublishedEvents <- record:
		default:
			// If the channel is full (rarely happens), drop the events.
			return nil
		}

		return nil
	}

	return es.client.XAdd(ctx, record).Err()
}

func (es *eventStore) StartPublishingRoutine(ctx context.Context) {
	defer close(es.unpublishedEvents)

	ticker := time.NewTicker(events.UnpublishedEventsCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := es.checkRedisConnection(ctx); err == nil {
				es.mu.Lock()
				for i := len(es.unpublishedEvents) - 1; i >= 0; i-- {
					record := <-es.unpublishedEvents
					if err := es.client.XAdd(ctx, record).Err(); err != nil {
						es.unpublishedEvents <- record

						break
					}
				}
				es.mu.Unlock()
			}
		case <-ctx.Done():
			return
		}
	}
}

func (es *eventStore) Close() error {
	return es.client.Close()
}

func (es *eventStore) checkRedisConnection(ctx context.Context) error {
	// A timeout is used to avoid blocking the main thread
	ctx, cancel := context.WithTimeout(ctx, events.ConnCheckInterval)
	defer cancel()

	return es.client.Ping(ctx).Err()
}
