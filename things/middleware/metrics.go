// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"context"
	"time"

	"github.com/absmach/magistrala/pkg/authn"
	mgclients "github.com/absmach/magistrala/pkg/clients"
	rmMW "github.com/absmach/magistrala/pkg/roles/rolemanager/middleware"
	"github.com/absmach/magistrala/things"
	"github.com/go-kit/kit/metrics"
)

var _ things.Service = (*metricsMiddleware)(nil)

type metricsMiddleware struct {
	counter metrics.Counter
	latency metrics.Histogram
	svc     things.Service
	rmMW.RoleManagerMetricsMiddleware
}

// MetricsMiddleware returns a new metrics middleware wrapper.
func MetricsMiddleware(svc things.Service, counter metrics.Counter, latency metrics.Histogram) things.Service {
	return &metricsMiddleware{
		counter:                      counter,
		latency:                      latency,
		svc:                          svc,
		RoleManagerMetricsMiddleware: rmMW.NewRoleManagerMetricsMiddleware("things", svc, counter, latency),
	}
}

func (ms *metricsMiddleware) CreateThings(ctx context.Context, session authn.Session, clients ...mgclients.Client) ([]mgclients.Client, error) {
	defer func(begin time.Time) {
		ms.counter.With("method", "register_things").Add(1)
		ms.latency.With("method", "register_things").Observe(time.Since(begin).Seconds())
	}(time.Now())
	return ms.svc.CreateThings(ctx, session, clients...)
}

func (ms *metricsMiddleware) ViewClient(ctx context.Context, session authn.Session, id string) (mgclients.Client, error) {
	defer func(begin time.Time) {
		ms.counter.With("method", "view_thing").Add(1)
		ms.latency.With("method", "view_thing").Observe(time.Since(begin).Seconds())
	}(time.Now())
	return ms.svc.ViewClient(ctx, session, id)
}

func (ms *metricsMiddleware) ListClients(ctx context.Context, session authn.Session, reqUserID string, pm mgclients.Page) (mgclients.ClientsPage, error) {
	defer func(begin time.Time) {
		ms.counter.With("method", "list_things").Add(1)
		ms.latency.With("method", "list_things").Observe(time.Since(begin).Seconds())
	}(time.Now())
	return ms.svc.ListClients(ctx, session, reqUserID, pm)
}

func (ms *metricsMiddleware) UpdateClient(ctx context.Context, session authn.Session, client mgclients.Client) (mgclients.Client, error) {
	defer func(begin time.Time) {
		ms.counter.With("method", "update_thing_name_and_metadata").Add(1)
		ms.latency.With("method", "update_thing_name_and_metadata").Observe(time.Since(begin).Seconds())
	}(time.Now())
	return ms.svc.UpdateClient(ctx, session, client)
}

func (ms *metricsMiddleware) UpdateClientTags(ctx context.Context, session authn.Session, client mgclients.Client) (mgclients.Client, error) {
	defer func(begin time.Time) {
		ms.counter.With("method", "update_thing_tags").Add(1)
		ms.latency.With("method", "update_thing_tags").Observe(time.Since(begin).Seconds())
	}(time.Now())
	return ms.svc.UpdateClientTags(ctx, session, client)
}

func (ms *metricsMiddleware) UpdateClientSecret(ctx context.Context, session authn.Session, oldSecret, newSecret string) (mgclients.Client, error) {
	defer func(begin time.Time) {
		ms.counter.With("method", "update_thing_secret").Add(1)
		ms.latency.With("method", "update_thing_secret").Observe(time.Since(begin).Seconds())
	}(time.Now())
	return ms.svc.UpdateClientSecret(ctx, session, oldSecret, newSecret)
}

func (ms *metricsMiddleware) EnableClient(ctx context.Context, session authn.Session, id string) (mgclients.Client, error) {
	defer func(begin time.Time) {
		ms.counter.With("method", "enable_thing").Add(1)
		ms.latency.With("method", "enable_thing").Observe(time.Since(begin).Seconds())
	}(time.Now())
	return ms.svc.EnableClient(ctx, session, id)
}

func (ms *metricsMiddleware) DisableClient(ctx context.Context, session authn.Session, id string) (mgclients.Client, error) {
	defer func(begin time.Time) {
		ms.counter.With("method", "disable_thing").Add(1)
		ms.latency.With("method", "disable_thing").Observe(time.Since(begin).Seconds())
	}(time.Now())
	return ms.svc.DisableClient(ctx, session, id)
}

func (ms *metricsMiddleware) Identify(ctx context.Context, key string) (string, error) {
	defer func(begin time.Time) {
		ms.counter.With("method", "identify_thing").Add(1)
		ms.latency.With("method", "identify_thing").Observe(time.Since(begin).Seconds())
	}(time.Now())
	return ms.svc.Identify(ctx, key)
}

func (ms *metricsMiddleware) Authorize(ctx context.Context, req things.AuthzReq) (id string, err error) {
	defer func(begin time.Time) {
		ms.counter.With("method", "authorize").Add(1)
		ms.latency.With("method", "authorize").Observe(time.Since(begin).Seconds())
	}(time.Now())
	return ms.svc.Authorize(ctx, req)
}

func (ms *metricsMiddleware) DeleteClient(ctx context.Context, session authn.Session, id string) error {
	defer func(begin time.Time) {
		ms.counter.With("method", "delete_client").Add(1)
		ms.latency.With("method", "delete_client").Observe(time.Since(begin).Seconds())
	}(time.Now())
	return ms.svc.DeleteClient(ctx, session, id)
}

func (ms *metricsMiddleware) RetrieveById(ctx context.Context, id string) (mgclients.Client, error) {
	defer func(begin time.Time) {
		ms.counter.With("method", "retrieve_by_id").Add(1)
		ms.latency.With("method", "retrieve_by_id").Observe(time.Since(begin).Seconds())
	}(time.Now())
	return ms.svc.RetrieveById(ctx, id)
}

func (ms *metricsMiddleware) RetrieveByIds(ctx context.Context, ids []string) (mgclients.ClientsPage, error) {
	defer func(begin time.Time) {
		ms.counter.With("method", "retrieve_by_ids").Add(1)
		ms.latency.With("method", "retrieve_by_ids").Observe(time.Since(begin).Seconds())
	}(time.Now())
	return ms.svc.RetrieveByIds(ctx, ids)
}
func (ms *metricsMiddleware) AddConnections(ctx context.Context, conns []things.Connection) error {
	defer func(begin time.Time) {
		ms.counter.With("method", "add_connections").Add(1)
		ms.latency.With("method", "add_connections").Observe(time.Since(begin).Seconds())
	}(time.Now())
	return ms.svc.AddConnections(ctx, conns)
}
func (ms *metricsMiddleware) RemoveConnections(ctx context.Context, conns []things.Connection) error {
	defer func(begin time.Time) {
		ms.counter.With("method", "remove_connections").Add(1)
		ms.latency.With("method", "remove_connections").Observe(time.Since(begin).Seconds())
	}(time.Now())
	return ms.svc.RemoveConnections(ctx, conns)
}
func (ms *metricsMiddleware) RemoveChannelConnections(ctx context.Context, channelID string) error {
	defer func(begin time.Time) {
		ms.counter.With("method", "remove_channel_connections").Add(1)
		ms.latency.With("method", "remove_channel_connections").Observe(time.Since(begin).Seconds())
	}(time.Now())
	return ms.svc.RemoveChannelConnections(ctx, channelID)
}
