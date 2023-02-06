package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	kithttp "github.com/go-kit/kit/transport/http"
	"github.com/go-zoo/bone"
	"github.com/mainflux/mainflux/clients/groups"
	"github.com/mainflux/mainflux/internal/api"
	"github.com/mainflux/mainflux/internal/apiutil"
	"github.com/mainflux/mainflux/logger"
	"github.com/mainflux/mainflux/pkg/errors"
	"go.opentelemetry.io/contrib/instrumentation/github.com/go-kit/kit/otelkit"
)

// MakeGroupsHandler returns a HTTP handler for API endpoints.
func MakeGroupsHandler(svc groups.Service, mux *bone.Mux, logger logger.Logger) {
	opts := []kithttp.ServerOption{
		kithttp.ServerErrorEncoder(apiutil.LoggingErrorEncoder(logger, api.EncodeError)),
	}
	mux.Post("/groups", kithttp.NewServer(
		otelkit.EndpointMiddleware(otelkit.WithOperation("create_group"))(createGroupEndpoint(svc)),
		decodeGroupCreate,
		api.EncodeResponse,
		opts...,
	))

	mux.Get("/groups/:id", kithttp.NewServer(
		otelkit.EndpointMiddleware(otelkit.WithOperation("view_group"))(viewGroupEndpoint(svc)),
		decodeGroupRequest,
		api.EncodeResponse,
		opts...,
	))

	mux.Put("/groups/:id", kithttp.NewServer(
		otelkit.EndpointMiddleware(otelkit.WithOperation("update_group"))(updateGroupEndpoint(svc)),
		decodeGroupUpdate,
		api.EncodeResponse,
		opts...,
	))

	mux.Get("/users/:id/memberships", kithttp.NewServer(
		otelkit.EndpointMiddleware(otelkit.WithOperation("list_memberships"))(listMembershipsEndpoint(svc)),
		decodeListMembershipRequest,
		api.EncodeResponse,
		opts...,
	))

	mux.Get("/groups", kithttp.NewServer(
		otelkit.EndpointMiddleware(otelkit.WithOperation("list_groups"))(listGroupsEndpoint(svc)),
		decodeListGroupsRequest,
		api.EncodeResponse,
		opts...,
	))

	mux.Get("/groups/:id/children", kithttp.NewServer(
		otelkit.EndpointMiddleware(otelkit.WithOperation("list_children"))(listGroupsEndpoint(svc)),
		decodeListChildrenRequest,
		api.EncodeResponse,
		opts...,
	))

	mux.Get("/groups/:id/parents", kithttp.NewServer(
		otelkit.EndpointMiddleware(otelkit.WithOperation("list_parents"))(listGroupsEndpoint(svc)),
		decodeListParentsRequest,
		api.EncodeResponse,
		opts...,
	))

	mux.Post("/groups/:id/enable", kithttp.NewServer(
		otelkit.EndpointMiddleware(otelkit.WithOperation("enable_group"))(enableGroupEndpoint(svc)),
		decodeChangeGroupStatus,
		api.EncodeResponse,
		opts...,
	))

	mux.Post("/groups/:id/disable", kithttp.NewServer(
		otelkit.EndpointMiddleware(otelkit.WithOperation("disable_group"))(disableGroupEndpoint(svc)),
		decodeChangeGroupStatus,
		api.EncodeResponse,
		opts...,
	))
}

func decodeListMembershipRequest(_ context.Context, r *http.Request) (interface{}, error) {
	s, err := apiutil.ReadStringQuery(r, api.StatusKey, api.DefGroupStatus)
	if err != nil {
		return nil, err
	}
	level, err := apiutil.ReadNumQuery[uint64](r, api.LevelKey, api.DefLevel)
	if err != nil {
		return nil, err
	}
	offset, err := apiutil.ReadNumQuery[uint64](r, api.OffsetKey, api.DefOffset)
	if err != nil {
		return nil, err
	}
	limit, err := apiutil.ReadNumQuery[uint64](r, api.LimitKey, api.DefLimit)
	if err != nil {
		return nil, err
	}
	parentID, err := apiutil.ReadStringQuery(r, api.ParentKey, "")
	if err != nil {
		return nil, err
	}
	ownerID, err := apiutil.ReadStringQuery(r, api.OwnerKey, "")
	if err != nil {
		return nil, err
	}
	name, err := apiutil.ReadStringQuery(r, api.NameKey, "")
	if err != nil {
		return nil, err
	}
	meta, err := apiutil.ReadMetadataQuery(r, api.MetadataKey, nil)
	if err != nil {
		return nil, err
	}
	dir, err := apiutil.ReadNumQuery[int64](r, api.DirKey, -1)
	if err != nil {
		return nil, err
	}
	st, err := groups.ToStatus(s)
	if err != nil {
		return nil, err
	}
	req := listMembershipReq{
		token:    apiutil.ExtractBearerToken(r),
		clientID: bone.GetValue(r, "id"),
		GroupsPage: groups.GroupsPage{
			Level: level,
			ID:    parentID,
			Page: groups.Page{
				Offset:   offset,
				Limit:    limit,
				OwnerID:  ownerID,
				Name:     name,
				Metadata: meta,
				Status:   st,
			},
			Direction: dir,
		},
	}
	return req, nil

}

func decodeListGroupsRequest(_ context.Context, r *http.Request) (interface{}, error) {
	s, err := apiutil.ReadStringQuery(r, api.StatusKey, api.DefGroupStatus)
	if err != nil {
		return nil, err
	}
	level, err := apiutil.ReadNumQuery[uint64](r, api.LevelKey, api.DefLevel)
	if err != nil {
		return nil, err
	}
	offset, err := apiutil.ReadNumQuery[uint64](r, api.OffsetKey, api.DefOffset)
	if err != nil {
		return nil, err
	}
	limit, err := apiutil.ReadNumQuery[uint64](r, api.LimitKey, api.DefLimit)
	if err != nil {
		return nil, err
	}
	parentID, err := apiutil.ReadStringQuery(r, api.ParentKey, "")
	if err != nil {
		return nil, err
	}
	ownerID, err := apiutil.ReadStringQuery(r, api.OwnerKey, "")
	if err != nil {
		return nil, err
	}
	name, err := apiutil.ReadStringQuery(r, api.NameKey, "")
	if err != nil {
		return nil, err
	}
	meta, err := apiutil.ReadMetadataQuery(r, api.MetadataKey, nil)
	if err != nil {
		return nil, err
	}
	tree, err := apiutil.ReadBoolQuery(r, api.TreeKey, false)
	if err != nil {
		return nil, err
	}
	dir, err := apiutil.ReadNumQuery[int64](r, api.DirKey, -1)
	if err != nil {
		return nil, err
	}
	st, err := groups.ToStatus(s)
	if err != nil {
		return nil, err
	}
	req := listGroupsReq{
		token: apiutil.ExtractBearerToken(r),
		tree:  tree,
		GroupsPage: groups.GroupsPage{
			Level: level,
			ID:    parentID,
			Page: groups.Page{
				Offset:   offset,
				Limit:    limit,
				OwnerID:  ownerID,
				Name:     name,
				Metadata: meta,
				Status:   st,
			},
			Direction: dir,
		},
	}
	return req, nil
}

func decodeListParentsRequest(_ context.Context, r *http.Request) (interface{}, error) {
	s, err := apiutil.ReadStringQuery(r, api.StatusKey, api.DefGroupStatus)
	if err != nil {
		return nil, err
	}
	level, err := apiutil.ReadNumQuery[uint64](r, api.LevelKey, api.DefLevel)
	if err != nil {
		return nil, err
	}
	offset, err := apiutil.ReadNumQuery[uint64](r, api.OffsetKey, api.DefOffset)
	if err != nil {
		return nil, err
	}
	limit, err := apiutil.ReadNumQuery[uint64](r, api.LimitKey, api.DefLimit)
	if err != nil {
		return nil, err
	}
	ownerID, err := apiutil.ReadStringQuery(r, api.OwnerKey, "")
	if err != nil {
		return nil, err
	}
	name, err := apiutil.ReadStringQuery(r, api.NameKey, "")
	if err != nil {
		return nil, err
	}
	meta, err := apiutil.ReadMetadataQuery(r, api.MetadataKey, nil)
	if err != nil {
		return nil, err
	}
	tree, err := apiutil.ReadBoolQuery(r, api.TreeKey, false)
	if err != nil {
		return nil, err
	}
	st, err := groups.ToStatus(s)
	if err != nil {
		return nil, err
	}
	req := listGroupsReq{
		token: apiutil.ExtractBearerToken(r),
		tree:  tree,
		GroupsPage: groups.GroupsPage{
			Level: level,
			ID:    bone.GetValue(r, "id"),
			Page: groups.Page{
				Offset:   offset,
				Limit:    limit,
				OwnerID:  ownerID,
				Name:     name,
				Metadata: meta,
				Status:   st,
			},
			Direction: 1,
		},
	}
	return req, nil
}

func decodeListChildrenRequest(_ context.Context, r *http.Request) (interface{}, error) {
	s, err := apiutil.ReadStringQuery(r, api.StatusKey, api.DefGroupStatus)
	if err != nil {
		return nil, err
	}
	level, err := apiutil.ReadNumQuery[uint64](r, api.LevelKey, api.DefLevel)
	if err != nil {
		return nil, err
	}
	offset, err := apiutil.ReadNumQuery[uint64](r, api.OffsetKey, api.DefOffset)
	if err != nil {
		return nil, err
	}
	limit, err := apiutil.ReadNumQuery[uint64](r, api.LimitKey, api.DefLimit)
	if err != nil {
		return nil, err
	}
	ownerID, err := apiutil.ReadStringQuery(r, api.OwnerKey, "")
	if err != nil {
		return nil, err
	}
	name, err := apiutil.ReadStringQuery(r, api.NameKey, "")
	if err != nil {
		return nil, err
	}
	meta, err := apiutil.ReadMetadataQuery(r, api.MetadataKey, nil)
	if err != nil {
		return nil, err
	}
	tree, err := apiutil.ReadBoolQuery(r, api.TreeKey, false)
	if err != nil {
		return nil, err
	}
	st, err := groups.ToStatus(s)
	if err != nil {
		return nil, err
	}
	req := listGroupsReq{
		token: apiutil.ExtractBearerToken(r),
		tree:  tree,
		GroupsPage: groups.GroupsPage{
			Level: level,
			ID:    bone.GetValue(r, "id"),
			Page: groups.Page{
				Offset:   offset,
				Limit:    limit,
				OwnerID:  ownerID,
				Name:     name,
				Metadata: meta,
				Status:   st,
			},
			Direction: -1,
		},
	}
	return req, nil
}

func decodeGroupCreate(_ context.Context, r *http.Request) (interface{}, error) {
	if !strings.Contains(r.Header.Get("Content-Type"), api.ContentType) {
		return nil, errors.ErrUnsupportedContentType
	}
	var g groups.Group
	if err := json.NewDecoder(r.Body).Decode(&g); err != nil {
		return nil, errors.Wrap(errors.ErrMalformedEntity, err)
	}
	req := createGroupReq{
		Group: g,
		token: apiutil.ExtractBearerToken(r),
	}

	return req, nil
}

func decodeGroupUpdate(_ context.Context, r *http.Request) (interface{}, error) {
	if !strings.Contains(r.Header.Get("Content-Type"), api.ContentType) {
		return nil, errors.ErrUnsupportedContentType
	}
	req := updateGroupReq{
		id:    bone.GetValue(r, "id"),
		token: apiutil.ExtractBearerToken(r),
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, errors.Wrap(errors.ErrMalformedEntity, err)
	}
	return req, nil
}

func decodeGroupRequest(_ context.Context, r *http.Request) (interface{}, error) {
	req := groupReq{
		token: apiutil.ExtractBearerToken(r),
		id:    bone.GetValue(r, "id"),
	}
	return req, nil
}

func decodeChangeGroupStatus(_ context.Context, r *http.Request) (interface{}, error) {
	req := changeGroupStatusReq{
		token: apiutil.ExtractBearerToken(r),
		id:    bone.GetValue(r, "id"),
	}

	return req, nil
}
