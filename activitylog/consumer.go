// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package activitylog

import (
	"context"
	"time"

	"github.com/absmach/magistrala/pkg/events"
	"github.com/absmach/magistrala/pkg/events/store"
)

// Start method starts consuming messages received from Event store.
func Start(ctx context.Context, consumer string, sub events.Subscriber, service Service) error {
	subCfg := events.SubscriberConfig{
		Consumer: consumer,
		Stream:   store.StreamAllEvents,
		Handler:  Handle(service),
	}

	return sub.Subscribe(ctx, subCfg)
}

func Handle(service Service) handleFunc {
	return func(ctx context.Context, event events.Event) error {
		data, err := event.Encode()
		if err != nil {
			return err
		}

		id, ok := data["id"].(string)
		if !ok {
			return nil
		}
		delete(data, "id")

		operation, ok := data["operation"].(string)
		if !ok {
			return nil
		}
		delete(data, "operation")

		occurredAt, ok := data["occurred_at"].(float64)
		if !ok {
			return nil
		}
		delete(data, "occurred_at")

		activity := Activity{
			ID:         id,
			Operation:  operation,
			OccurredAt: time.Unix(0, int64(occurredAt)),
			Payload:    data,
		}

		return service.Save(ctx, activity)
	}
}

type handleFunc func(ctx context.Context, event events.Event) error

func (h handleFunc) Handle(ctx context.Context, event events.Event) error {
	return h(ctx, event)
}

func (h handleFunc) Cancel() error {
	return nil
}
