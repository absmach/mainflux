// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	kithttp "github.com/go-kit/kit/transport/http"
	"github.com/mainflux/mainflux/internal/api"
	"github.com/mainflux/mainflux/internal/apiutil"
	gapi "github.com/mainflux/mainflux/internal/groups/api"
	"github.com/mainflux/mainflux/logger"
	"github.com/mainflux/mainflux/pkg/errors"
	"github.com/mainflux/mainflux/pkg/groups"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

func groupsHandler(svc groups.Service, r *chi.Mux, logger logger.Logger) http.Handler {
	opts := []kithttp.ServerOption{
		kithttp.ServerErrorEncoder(apiutil.LoggingErrorEncoder(logger, api.EncodeError)),
	}
	r.Route("/channels", func(r chi.Router) {
		r.Post("/", otelhttp.NewHandler(kithttp.NewServer(
			gapi.CreateGroupEndpoint(svc),
			gapi.DecodeGroupCreate,
			api.EncodeResponse,
			opts...,
		), "create_channel").ServeHTTP)

		r.Get("/{groupID}", otelhttp.NewHandler(kithttp.NewServer(
			gapi.ViewGroupEndpoint(svc),
			gapi.DecodeGroupRequest,
			api.EncodeResponse,
			opts...,
		), "view_channel").ServeHTTP)

		r.Put("/{groupID}", otelhttp.NewHandler(kithttp.NewServer(
			gapi.UpdateGroupEndpoint(svc),
			gapi.DecodeGroupUpdate,
			api.EncodeResponse,
			opts...,
		), "update_channel").ServeHTTP)

		r.Get("/", otelhttp.NewHandler(kithttp.NewServer(
			gapi.ListGroupsEndpoint(svc, "users"),
			gapi.DecodeListGroupsRequest,
			api.EncodeResponse,
			opts...,
		), "list_channels").ServeHTTP)

		r.Post("/{groupID}/enable", otelhttp.NewHandler(kithttp.NewServer(
			gapi.EnableGroupEndpoint(svc),
			gapi.DecodeChangeGroupStatus,
			api.EncodeResponse,
			opts...,
		), "enable_channel").ServeHTTP)

		r.Post("/{groupID}/disable", otelhttp.NewHandler(kithttp.NewServer(
			gapi.DisableGroupEndpoint(svc),
			gapi.DecodeChangeGroupStatus,
			api.EncodeResponse,
			opts...,
		), "disable_channel").ServeHTTP)

		// Instead of having this endpoint /channels/{groupID}/members separately,
		// we can have two separate endpoints for each member kind
		// users (/channels/{groupID}/users) & user_groups (/channels/{groupID}/groups)
		r.Post("/{groupID}/members", otelhttp.NewHandler(kithttp.NewServer(
			assignUsersGroupsEndpoint(svc),
			decodeAssignUsersGroupsRequest,
			api.EncodeResponse,
			opts...,
		), "assign_members").ServeHTTP)

		// Instead of having this endpoint /channels/{groupID}/members separately,
		// we can have two separate endpoints for each member kind
		// users (/channels/{groupID}/users) & user_groups (/channels/{groupID}/groups)
		r.Delete("/{groupID}/members", otelhttp.NewHandler(kithttp.NewServer(
			unassignUsersGroupsEndpoint(svc),
			decodeUnassignUsersGroupsRequest,
			api.EncodeResponse,
			opts...,
		), "unassign_members").ServeHTTP)

		// Request to add users to a channel
		// This endpoint can be used alternative to /channels/{groupID}/members
		r.Post("/{groupID}/users", otelhttp.NewHandler(kithttp.NewServer(
			assignUsersEndpoint(svc),
			decodeAssignUsersRequest,
			api.EncodeResponse,
			opts...,
		), "assign_users").ServeHTTP)

		// Request to remove users from a channel
		// This endpoint can be used alternative to /channels/{groupID}/members
		r.Delete("/{groupID}/users", otelhttp.NewHandler(kithttp.NewServer(
			unassignUsersEndpoint(svc),
			decodeUnassignUsersRequest,
			api.EncodeResponse,
			opts...,
		), "unassign_users").ServeHTTP)

		// Request to add user_groups to a channel
		// This endpoint can be used alternative to /channels/{groupID}/members
		r.Post("/{groupID}/groups", otelhttp.NewHandler(kithttp.NewServer(
			assignUserGroupsEndpoint(svc),
			decodeAssignUserGroupsRequest,
			api.EncodeResponse,
			opts...,
		), "assign_groups").ServeHTTP)

		// Request to remove user_groups from a channel
		// This endpoint can be used alternative to /channels/{groupID}/members
		r.Delete("/{groupID}/groups", otelhttp.NewHandler(kithttp.NewServer(
			unassignUserGroupsEndpoint(svc),
			decodeUnassignUserGroupsRequest,
			api.EncodeResponse,
			opts...,
		), "unassign_groups").ServeHTTP)

		r.Post("/{groupID}/things/{thingID}", otelhttp.NewHandler(kithttp.NewServer(
			connectChannelThingEndpoint(svc),
			decodeConnectChannelThingRequest,
			api.EncodeResponse,
			opts...,
		), "connect_channel_thing").ServeHTTP)

		r.Delete("/{groupID}/things/{thingID}", otelhttp.NewHandler(kithttp.NewServer(
			disconnectChannelThingEndpoint(svc),
			decodeDisconnectChannelThingRequest,
			api.EncodeResponse,
			opts...,
		), "disconnect_channel_thing").ServeHTTP)
	})

	// Ideal location: things service,  things endpoint
	// Reason for placing here :
	// SpiceDB provides list of channel ids to which thing id attached
	// and channel service can access spiceDB and get this channel ids list with given thing id.
	// Request to get list of channels to which thingID ({memberID}) belongs
	r.Get("/things/{memberID}/channels", otelhttp.NewHandler(kithttp.NewServer(
		gapi.ListGroupsEndpoint(svc, "things"),
		gapi.DecodeListGroupsRequest,
		api.EncodeResponse,
		opts...,
	), "list_channel_by_things").ServeHTTP)

	// Ideal location: users service, users endpoint
	// Reason for placing here :
	// SpiceDB provides list of channel ids attached to given user id
	// and channel service can access spiceDB and get this user ids list with given thing id.
	// Request to get list of channels to which userID ({memberID}) have permission.
	r.Get("/users/{memberID}/channels", otelhttp.NewHandler(kithttp.NewServer(
		gapi.ListGroupsEndpoint(svc, "users"),
		gapi.DecodeListGroupsRequest,
		api.EncodeResponse,
		opts...,
	), "list_channel_by_things").ServeHTTP)

	// Ideal location: users service, groups endpoint
	// SpiceDB provides list of channel ids attached to given user_group id
	// and channel service can access spiceDB and get this user ids list with given user_group id.
	// Request to get list of channels to which user_group_id ({memberID}) attached.
	r.Get("/groups/{memberID}/channels", otelhttp.NewHandler(kithttp.NewServer(
		gapi.ListGroupsEndpoint(svc, "groups"),
		gapi.DecodeListGroupsRequest,
		api.EncodeResponse,
		opts...,
	), "list_channel_by_things").ServeHTTP)

	// Connect channel and thing
	r.Post("/connect", otelhttp.NewHandler(kithttp.NewServer(
		connectEndpoint(svc),
		decodeConnectRequest,
		api.EncodeResponse,
		opts...,
	), "connect").ServeHTTP)

	// Disconnect channel and thing
	r.Post("/disconnect", otelhttp.NewHandler(kithttp.NewServer(
		disconnectEndpoint(svc),
		decodeDisconnectRequest,
		api.EncodeResponse,
		opts...,
	), "disconnect").ServeHTTP)

	return r
}

func decodeAssignUsersGroupsRequest(_ context.Context, r *http.Request) (interface{}, error) {
	req := assignUsersGroupsRequest{
		token:   apiutil.ExtractBearerToken(r),
		groupID: chi.URLParam(r, "groupID"),
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, errors.Wrap(apiutil.ErrValidation, errors.Wrap(err, errors.ErrMalformedEntity))
	}
	return req, nil
}

func decodeUnassignUsersGroupsRequest(_ context.Context, r *http.Request) (interface{}, error) {
	req := unassignUsersGroupsRequest{
		token:   apiutil.ExtractBearerToken(r),
		groupID: chi.URLParam(r, "groupID"),
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, errors.Wrap(apiutil.ErrValidation, errors.Wrap(err, errors.ErrMalformedEntity))
	}
	return req, nil
}

func decodeAssignUsersRequest(_ context.Context, r *http.Request) (interface{}, error) {
	req := assignUsersRequest{
		token:   apiutil.ExtractBearerToken(r),
		groupID: chi.URLParam(r, "groupID"),
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, errors.Wrap(apiutil.ErrValidation, errors.Wrap(err, errors.ErrMalformedEntity))
	}
	return req, nil
}

func decodeUnassignUsersRequest(_ context.Context, r *http.Request) (interface{}, error) {
	req := unassignUsersRequest{
		token:   apiutil.ExtractBearerToken(r),
		groupID: chi.URLParam(r, "groupID"),
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, errors.Wrap(apiutil.ErrValidation, errors.Wrap(err, errors.ErrMalformedEntity))
	}
	return req, nil
}

func decodeAssignUserGroupsRequest(_ context.Context, r *http.Request) (interface{}, error) {
	req := assignUserGroupsRequest{
		token:   apiutil.ExtractBearerToken(r),
		groupID: chi.URLParam(r, "groupID"),
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, errors.Wrap(apiutil.ErrValidation, errors.Wrap(err, errors.ErrMalformedEntity))
	}
	return req, nil
}

func decodeUnassignUserGroupsRequest(_ context.Context, r *http.Request) (interface{}, error) {
	req := unassignUserGroupsRequest{
		token:   apiutil.ExtractBearerToken(r),
		groupID: chi.URLParam(r, "groupID"),
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, errors.Wrap(apiutil.ErrValidation, errors.Wrap(err, errors.ErrMalformedEntity))
	}
	return req, nil
}

func decodeConnectChannelThingRequest(_ context.Context, r *http.Request) (interface{}, error) {
	req := connectChannelThingRequest{
		token:     apiutil.ExtractBearerToken(r),
		ThingID:   chi.URLParam(r, "thingID"),
		ChannelID: chi.URLParam(r, "groupID"),
	}
	return req, nil
}

func decodeDisconnectChannelThingRequest(_ context.Context, r *http.Request) (interface{}, error) {
	req := disconnectChannelThingRequest{
		token:     apiutil.ExtractBearerToken(r),
		ThingID:   chi.URLParam(r, "thingID"),
		ChannelID: chi.URLParam(r, "groupID"),
	}
	return req, nil
}

func decodeConnectRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if !strings.Contains(r.Header.Get("Content-Type"), api.ContentType) {
		return nil, errors.Wrap(apiutil.ErrValidation, apiutil.ErrUnsupportedContentType)
	}

	req := connectChannelThingRequest{
		token: apiutil.ExtractBearerToken(r),
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, errors.Wrap(apiutil.ErrValidation, errors.Wrap(errors.ErrMalformedEntity, err))
	}
	return req, nil
}

func decodeDisconnectRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if !strings.Contains(r.Header.Get("Content-Type"), api.ContentType) {
		return nil, errors.Wrap(apiutil.ErrValidation, apiutil.ErrUnsupportedContentType)
	}

	req := disconnectChannelThingRequest{
		token: apiutil.ExtractBearerToken(r),
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, errors.Wrap(apiutil.ErrValidation, errors.Wrap(errors.ErrMalformedEntity, err))
	}
	return req, nil
}