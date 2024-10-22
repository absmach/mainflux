// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package tracing

import (
	"context"

	"github.com/absmach/magistrala/pkg/authn"
	mgclients "github.com/absmach/magistrala/pkg/clients"
	rmTrace "github.com/absmach/magistrala/pkg/roles/rolemanager/tracing"
	"github.com/absmach/magistrala/things"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

var _ things.Service = (*tracingMiddleware)(nil)

type tracingMiddleware struct {
	tracer trace.Tracer
	svc    things.Service
	rmTrace.RoleManagerTracing
}

// New returns a new group service with tracing capabilities.
func New(svc things.Service, tracer trace.Tracer) things.Service {
	return &tracingMiddleware{
		tracer:             tracer,
		svc:                svc,
		RoleManagerTracing: rmTrace.NewRoleManagerTracing("group", svc, tracer),
	}
}

// CreateThings traces the "CreateThings" operation of the wrapped policies.Service.
func (tm *tracingMiddleware) CreateThings(ctx context.Context, session authn.Session, clis ...mgclients.Client) ([]mgclients.Client, error) {
	ctx, span := tm.tracer.Start(ctx, "svc_create_client")
	defer span.End()

	return tm.svc.CreateThings(ctx, session, clis...)
}

// ViewClient traces the "ViewClient" operation of the wrapped policies.Service.
func (tm *tracingMiddleware) ViewClient(ctx context.Context, session authn.Session, id string) (mgclients.Client, error) {
	ctx, span := tm.tracer.Start(ctx, "svc_view_client", trace.WithAttributes(attribute.String("id", id)))
	defer span.End()
	return tm.svc.ViewClient(ctx, session, id)
}

// ListClients traces the "ListClients" operation of the wrapped policies.Service.
func (tm *tracingMiddleware) ListClients(ctx context.Context, session authn.Session, reqUserID string, pm mgclients.Page) (mgclients.ClientsPage, error) {
	ctx, span := tm.tracer.Start(ctx, "svc_list_clients")
	defer span.End()
	return tm.svc.ListClients(ctx, session, reqUserID, pm)
}

// UpdateClient traces the "UpdateClient" operation of the wrapped policies.Service.
func (tm *tracingMiddleware) UpdateClient(ctx context.Context, session authn.Session, cli mgclients.Client) (mgclients.Client, error) {
	ctx, span := tm.tracer.Start(ctx, "svc_update_client_name_and_metadata", trace.WithAttributes(attribute.String("id", cli.ID)))
	defer span.End()

	return tm.svc.UpdateClient(ctx, session, cli)
}

// UpdateClientTags traces the "UpdateClientTags" operation of the wrapped policies.Service.
func (tm *tracingMiddleware) UpdateClientTags(ctx context.Context, session authn.Session, cli mgclients.Client) (mgclients.Client, error) {
	ctx, span := tm.tracer.Start(ctx, "svc_update_client_tags", trace.WithAttributes(
		attribute.String("id", cli.ID),
		attribute.StringSlice("tags", cli.Tags),
	))
	defer span.End()

	return tm.svc.UpdateClientTags(ctx, session, cli)
}

// UpdateClientSecret traces the "UpdateClientSecret" operation of the wrapped policies.Service.
func (tm *tracingMiddleware) UpdateClientSecret(ctx context.Context, session authn.Session, oldSecret, newSecret string) (mgclients.Client, error) {
	ctx, span := tm.tracer.Start(ctx, "svc_update_client_secret")
	defer span.End()

	return tm.svc.UpdateClientSecret(ctx, session, oldSecret, newSecret)
}

// EnableClient traces the "EnableClient" operation of the wrapped policies.Service.
func (tm *tracingMiddleware) EnableClient(ctx context.Context, session authn.Session, id string) (mgclients.Client, error) {
	ctx, span := tm.tracer.Start(ctx, "svc_enable_client", trace.WithAttributes(attribute.String("id", id)))
	defer span.End()

	return tm.svc.EnableClient(ctx, session, id)
}

// DisableClient traces the "DisableClient" operation of the wrapped policies.Service.
func (tm *tracingMiddleware) DisableClient(ctx context.Context, session authn.Session, id string) (mgclients.Client, error) {
	ctx, span := tm.tracer.Start(ctx, "svc_disable_client", trace.WithAttributes(attribute.String("id", id)))
	defer span.End()

	return tm.svc.DisableClient(ctx, session, id)
}

// ListMemberships traces the "ListMemberships" operation of the wrapped policies.Service.
func (tm *tracingMiddleware) Identify(ctx context.Context, key string) (string, error) {
	ctx, span := tm.tracer.Start(ctx, "svc_identify", trace.WithAttributes(attribute.String("key", key)))
	defer span.End()

	return tm.svc.Identify(ctx, key)
}

// Authorize traces the "Authorize" operation of the wrapped things.Service.
func (tm *tracingMiddleware) Authorize(ctx context.Context, req things.AuthzReq) (string, error) {
	ctx, span := tm.tracer.Start(ctx, "connect", trace.WithAttributes(attribute.String("thingKey", req.ThingKey), attribute.String("channelID", req.ChannelID)))
	defer span.End()

	return tm.svc.Authorize(ctx, req)
}

// DeleteClient traces the "DeleteClient" operation of the wrapped things.Service.
func (tm *tracingMiddleware) DeleteClient(ctx context.Context, session authn.Session, id string) error {
	ctx, span := tm.tracer.Start(ctx, "delete_client", trace.WithAttributes(attribute.String("id", id)))
	defer span.End()
	return tm.svc.DeleteClient(ctx, session, id)
}

func (tm *tracingMiddleware) RetrieveById(ctx context.Context, id string) (mgclients.Client, error) {
	ctx, span := tm.tracer.Start(ctx, "retrieve_by_id", trace.WithAttributes(attribute.String("id", id)))
	defer span.End()
	return tm.svc.RetrieveById(ctx, id)
}

func (tm *tracingMiddleware) RetrieveByIds(ctx context.Context, ids []string) (mgclients.ClientsPage, error) {
	ctx, span := tm.tracer.Start(ctx, "retrieve_by_ids", trace.WithAttributes(attribute.StringSlice("ids", ids)))
	defer span.End()
	return tm.svc.RetrieveByIds(ctx, ids)
}

func (tm *tracingMiddleware) AddConnections(ctx context.Context, conns []things.Connection) error {
	ctx, span := tm.tracer.Start(ctx, "add_connections")
	defer span.End()
	return tm.svc.AddConnections(ctx, conns)
}
func (tm *tracingMiddleware) RemoveConnections(ctx context.Context, conns []things.Connection) error {
	ctx, span := tm.tracer.Start(ctx, "remove_connections")
	defer span.End()
	return tm.svc.RemoveConnections(ctx, conns)
}
