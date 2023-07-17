// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package redis

import (
	"context"

	"github.com/go-redis/redis/v8"
	mfredis "github.com/mainflux/mainflux/internal/clients/redis"
	mfgroups "github.com/mainflux/mainflux/pkg/groups"
	"github.com/mainflux/mainflux/things/groups"
)

const (
	streamID  = "mainflux.things"
	streamLen = 1000
)

var _ groups.Service = (*eventStore)(nil)

type eventStore struct {
	mfredis.Publisher
	svc    groups.Service
	client *redis.Client
}

// NewEventStoreMiddleware returns wrapper around things service that sends
// events to event store.
func NewEventStoreMiddleware(ctx context.Context, svc groups.Service, client *redis.Client) groups.Service {
	es := &eventStore{
		svc:       svc,
		client:    client,
		Publisher: mfredis.NewEventStore(client, streamID, streamLen),
	}

	go es.StartPublishingRoutine(ctx)

	return es
}

func (es *eventStore) CreateGroups(ctx context.Context, token string, groups ...mfgroups.Group) ([]mfgroups.Group, error) {
	gs, err := es.svc.CreateGroups(ctx, token, groups...)
	if err != nil {
		return gs, err
	}

	for _, group := range gs {
		event := createGroupEvent{
			group,
		}
		if err := es.Publish(ctx, event); err != nil {
			return gs, err
		}
	}
	return gs, nil
}

func (es *eventStore) UpdateGroup(ctx context.Context, token string, group mfgroups.Group) (mfgroups.Group, error) {
	group, err := es.svc.UpdateGroup(ctx, token, group)
	if err != nil {
		return mfgroups.Group{}, err
	}

	event := updateGroupEvent{
		group,
	}
	if err := es.Publish(ctx, event); err != nil {
		return group, err
	}

	return group, nil
}

func (es *eventStore) ViewGroup(ctx context.Context, token, id string) (mfgroups.Group, error) {
	group, err := es.svc.ViewGroup(ctx, token, id)
	if err != nil {
		return mfgroups.Group{}, err
	}
	event := viewGroupEvent{
		group,
	}
	if err := es.Publish(ctx, event); err != nil {
		return group, err
	}

	return group, nil
}

func (es *eventStore) ListGroups(ctx context.Context, token string, pm mfgroups.GroupsPage) (mfgroups.GroupsPage, error) {
	gp, err := es.svc.ListGroups(ctx, token, pm)
	if err != nil {
		return mfgroups.GroupsPage{}, err
	}
	event := listGroupEvent{
		pm,
	}
	if err := es.Publish(ctx, event); err != nil {
		return gp, err
	}

	return gp, nil
}

func (es *eventStore) ListMemberships(ctx context.Context, token, clientID string, pm mfgroups.GroupsPage) (mfgroups.MembershipsPage, error) {
	mp, err := es.svc.ListMemberships(ctx, token, clientID, pm)
	if err != nil {
		return mfgroups.MembershipsPage{}, err
	}
	event := listGroupMembershipEvent{
		pm, clientID,
	}
	if err := es.Publish(ctx, event); err != nil {
		return mp, err
	}

	return mp, nil
}

func (es *eventStore) EnableGroup(ctx context.Context, token, id string) (mfgroups.Group, error) {
	cli, err := es.svc.EnableGroup(ctx, token, id)
	if err != nil {
		return mfgroups.Group{}, err
	}

	return es.delete(ctx, cli)
}

func (es *eventStore) DisableGroup(ctx context.Context, token, id string) (mfgroups.Group, error) {
	cli, err := es.svc.DisableGroup(ctx, token, id)
	if err != nil {
		return mfgroups.Group{}, err
	}

	return es.delete(ctx, cli)
}

func (es *eventStore) delete(ctx context.Context, group mfgroups.Group) (mfgroups.Group, error) {
	event := removeGroupEvent{
		id:        group.ID,
		updatedAt: group.UpdatedAt,
		updatedBy: group.UpdatedBy,
		status:    group.Status.String(),
	}
	if err := es.Publish(ctx, event); err != nil {
		return group, err
	}

	return group, nil
}
