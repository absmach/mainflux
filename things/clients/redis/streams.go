// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package redis

import (
	"context"

	"github.com/go-redis/redis/v8"
	mfclients "github.com/mainflux/mainflux/pkg/clients"
	"github.com/mainflux/mainflux/things/clients"
)

const (
	streamID  = "mainflux.things"
	streamLen = 1000
)

var _ clients.Service = (*eventStore)(nil)

type eventStore struct {
	svc    clients.Service
	client *redis.Client
}

// NewEventStoreMiddleware returns wrapper around things service that sends
// events to event store.
func NewEventStoreMiddleware(svc clients.Service, client *redis.Client) clients.Service {
	return eventStore{
		svc:    svc,
		client: client,
	}
}

func (es eventStore) CreateThings(ctx context.Context, token string, thing ...mfclients.Client) ([]mfclients.Client, error) {
	sths, err := es.svc.CreateThings(ctx, token, thing...)
	if err != nil {
		return sths, err
	}
	for _, th := range sths {
		event := createClientEvent{
			id:       th.ID,
			owner:    th.Owner,
			name:     th.Name,
			metadata: th.Metadata,
		}
		record := &redis.XAddArgs{
			Stream:       streamID,
			MaxLenApprox: streamLen,
			Values:       event.Encode(),
		}
		if err := es.client.XAdd(ctx, record).Err(); err != nil {
			return sths, err
		}
	}
	return sths, nil
}

func (es eventStore) UpdateClient(ctx context.Context, token string, thing mfclients.Client) (mfclients.Client, error) {
	cli, err := es.svc.UpdateClient(ctx, token, thing)
	if err != nil {
		return mfclients.Client{}, err
	}

	event := updateClientEvent{
		id:       cli.ID,
		name:     cli.Name,
		metadata: cli.Metadata,
	}
	record := &redis.XAddArgs{
		Stream:       streamID,
		MaxLenApprox: streamLen,
		Values:       event.Encode(),
	}
	if err := es.client.XAdd(ctx, record).Err(); err != nil {
		return mfclients.Client{}, err
	}

	return cli, nil
}

func (es eventStore) UpdateClientOwner(ctx context.Context, token string, thing mfclients.Client) (mfclients.Client, error) {
	cli, err := es.svc.UpdateClientOwner(ctx, token, thing)
	if err != nil {
		return mfclients.Client{}, err
	}

	event := updateClientEvent{
		owner: cli.Owner,
	}
	record := &redis.XAddArgs{
		Stream:       streamID,
		MaxLenApprox: streamLen,
		Values:       event.Encode(),
	}
	if err := es.client.XAdd(ctx, record).Err(); err != nil {
		return mfclients.Client{}, err
	}

	return cli, nil
}

func (es eventStore) UpdateClientTags(ctx context.Context, token string, thing mfclients.Client) (mfclients.Client, error) {
	cli, err := es.svc.UpdateClientTags(ctx, token, thing)
	if err != nil {
		return mfclients.Client{}, err
	}

	event := updateClientEvent{
		tags: cli.Tags,
	}
	record := &redis.XAddArgs{
		Stream:       streamID,
		MaxLenApprox: streamLen,
		Values:       event.Encode(),
	}
	if err := es.client.XAdd(ctx, record).Err(); err != nil {
		return mfclients.Client{}, err
	}

	return cli, nil
}

// UpdateClientSecret doesn't send event because key shouldn't be sent over stream.
// Maybe we can start publishing this event at some point, without key value
// in order to notify adapters to disconnect connected things after key update.
func (es eventStore) UpdateClientSecret(ctx context.Context, token, id, key string) (mfclients.Client, error) {
	return es.svc.UpdateClientSecret(ctx, token, id, key)
}

func (es eventStore) ShareClient(ctx context.Context, token, thingID string, actions, userIDs []string) error {
	return es.svc.ShareClient(ctx, token, thingID, actions, userIDs)
}

func (es eventStore) ViewClient(ctx context.Context, token, id string) (mfclients.Client, error) {
	return es.svc.ViewClient(ctx, token, id)
}

func (es eventStore) ListClients(ctx context.Context, token string, pm mfclients.Page) (mfclients.ClientsPage, error) {
	return es.svc.ListClients(ctx, token, pm)
}

func (es eventStore) ListClientsByGroup(ctx context.Context, token, chID string, pm mfclients.Page) (mfclients.MembersPage, error) {
	return es.svc.ListClientsByGroup(ctx, token, chID, pm)
}

func (es eventStore) EnableClient(ctx context.Context, token, id string) (mfclients.Client, error) {
	cli, err := es.svc.EnableClient(ctx, token, id)
	if err != nil {
		return mfclients.Client{}, err
	}

	event := removeClientEvent{
		id: id,
	}
	record := &redis.XAddArgs{
		Stream:       streamID,
		MaxLenApprox: streamLen,
		Values:       event.Encode(),
	}
	if err := es.client.XAdd(ctx, record).Err(); err != nil {
		return mfclients.Client{}, err
	}

	return cli, nil
}

func (es eventStore) DisableClient(ctx context.Context, token, id string) (mfclients.Client, error) {
	cli, err := es.svc.DisableClient(ctx, token, id)
	if err != nil {
		return mfclients.Client{}, err
	}

	event := removeClientEvent{
		id: id,
	}
	record := &redis.XAddArgs{
		Stream:       streamID,
		MaxLenApprox: streamLen,
		Values:       event.Encode(),
	}
	if err := es.client.XAdd(ctx, record).Err(); err != nil {
		return mfclients.Client{}, err
	}

	return cli, nil
}

func (es eventStore) Identify(ctx context.Context, key string) (string, error) {
	return es.svc.Identify(ctx, key)
}
