// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package notify

import "context"

// Subscription represents a user Subscription.
type Subscription struct {
	ID      string
	OwnerID string
	Contact string
	Topic   string
}

// SubscriptionsRepository specifies a Subscription persistence API.
type SubscriptionsRepository interface {
	// Save persists a subscription. Successful operation is indicated by non-nil
	// error response.
	Save(ctx context.Context, sub Subscription) (string, error)

	// Retrieve retrieves the subscription for the given id.
	Retrieve(ctx context.Context, id string) (Subscription, error)

	// Remove removes the subscription having the provided identifier, that is owned
	// by the specified user.
	RetrieveAll(ctx context.Context, topic, contact string) ([]Subscription, error)

	// Remove removes the subscription having the provided an ID.
	Remove(ctx context.Context, id string) error
}
