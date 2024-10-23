// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package grpc

import (
	"context"

	mgauth "github.com/absmach/magistrala/auth"
	grpcCommonV1 "github.com/absmach/magistrala/internal/grpc/common/v1"
	grpcThingsV1 "github.com/absmach/magistrala/internal/grpc/things/v1"
	"github.com/absmach/magistrala/pkg/apiutil"
	"github.com/absmach/magistrala/pkg/errors"
	svcerr "github.com/absmach/magistrala/pkg/errors/service"
	"github.com/absmach/magistrala/things"
	kitgrpc "github.com/go-kit/kit/transport/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var _ grpcThingsV1.ThingsServiceServer = (*grpcServer)(nil)

type grpcServer struct {
	grpcThingsV1.UnimplementedThingsServiceServer
	authorize         kitgrpc.Handler
	retrieveEntity    kitgrpc.Handler
	retrieveEntities  kitgrpc.Handler
	addConnections    kitgrpc.Handler
	removeConnections kitgrpc.Handler
}

// NewServer returns new AuthServiceServer instance.
func NewServer(svc things.Service) grpcThingsV1.ThingsServiceServer {
	return &grpcServer{
		authorize: kitgrpc.NewServer(
			authorizeEndpoint(svc),
			decodeAuthorizeRequest,
			encodeAuthorizeResponse,
		),
		retrieveEntity: kitgrpc.NewServer(
			getEntityBasicEndpoint(svc),
			decodeRetrieveEntityRequest,
			encodeRetrieveEntityResponse,
		),
		retrieveEntities: kitgrpc.NewServer(
			getEntitiesBasicEndpoint(svc),
			decodeGetEntitiesBasicRequest,
			encodeGetEntitiesBasicResponse,
		),
		addConnections: kitgrpc.NewServer(
			addConnectionsEndpoint(svc),
			decodeAddConnectionsRequest,
			encodeAddConnectionsResponse,
		),
		removeConnections: kitgrpc.NewServer(
			removeConnectionsEndpoint(svc),
			decodeRemoveConnectionsRequest,
			encodeRemoveConnectionsResponse,
		),
	}
}

func (s *grpcServer) Authorize(ctx context.Context, req *grpcThingsV1.AuthzReq) (*grpcThingsV1.AuthzRes, error) {
	_, res, err := s.authorize.ServeGRPC(ctx, req)
	if err != nil {
		return nil, encodeError(err)
	}
	return res.(*grpcThingsV1.AuthzRes), nil
}

func decodeAuthorizeRequest(_ context.Context, grpcReq interface{}) (interface{}, error) {
	req := grpcReq.(*grpcThingsV1.AuthzReq)
	return authorizeReq{
		ThingID:    req.GetThingId(),
		ThingKey:   req.GetThingKey(),
		ChannelID:  req.GetChannelId(),
		Permission: req.GetPermission(),
	}, nil
}

func encodeAuthorizeResponse(_ context.Context, grpcRes interface{}) (interface{}, error) {
	res := grpcRes.(authorizeRes)
	return &grpcThingsV1.AuthzRes{Authorized: res.authorized, Id: res.id}, nil
}

func (s *grpcServer) RetrieveEntity(ctx context.Context, req *grpcCommonV1.RetrieveEntityReq) (*grpcCommonV1.RetrieveEntityRes, error) {
	_, res, err := s.retrieveEntity.ServeGRPC(ctx, req)
	if err != nil {
		return nil, encodeError(err)
	}
	return res.(*grpcCommonV1.RetrieveEntityRes), nil
}

func decodeRetrieveEntityRequest(_ context.Context, grpcReq interface{}) (interface{}, error) {
	req := grpcReq.(*grpcCommonV1.RetrieveEntityReq)
	return getEntityBasicReq{
		Id: req.GetId(),
	}, nil
}

func encodeRetrieveEntityResponse(_ context.Context, grpcRes interface{}) (interface{}, error) {
	res := grpcRes.(getEntityBasicRes)

	return &grpcCommonV1.RetrieveEntityRes{
		Entity: &grpcCommonV1.EntityBasic{
			Id:       res.id,
			DomainId: res.domain,
			Status:   uint32(res.status),
		},
	}, nil
}

func (s *grpcServer) RetrieveEntities(ctx context.Context, req *grpcCommonV1.RetrieveEntitiesReq) (*grpcCommonV1.RetrieveEntitiesRes, error) {
	_, res, err := s.retrieveEntities.ServeGRPC(ctx, req)
	if err != nil {
		return nil, encodeError(err)
	}
	return res.(*grpcCommonV1.RetrieveEntitiesRes), nil
}

func decodeGetEntitiesBasicRequest(_ context.Context, grpcReq interface{}) (interface{}, error) {
	req := grpcReq.(*grpcCommonV1.RetrieveEntitiesReq)
	return getEntitiesBasicReq{
		Ids: req.GetIds(),
	}, nil
}

func encodeGetEntitiesBasicResponse(_ context.Context, grpcRes interface{}) (interface{}, error) {
	res := grpcRes.(getEntitiesBasicRes)

	entities := []*grpcCommonV1.EntityBasic{}
	for _, thing := range res.things {
		entities = append(entities, &grpcCommonV1.EntityBasic{
			Id:       thing.id,
			DomainId: thing.domain,
			Status:   uint32(thing.status),
		})
	}
	return &grpcCommonV1.RetrieveEntitiesRes{Total: res.total, Limit: res.limit, Offset: res.offset, Entities: entities}, nil
}

func (s *grpcServer) AddConnections(ctx context.Context, req *grpcCommonV1.AddConnectionsReq) (*grpcCommonV1.AddConnectionsRes, error) {
	_, res, err := s.addConnections.ServeGRPC(ctx, req)
	if err != nil {
		return nil, encodeError(err)
	}
	return res.(*grpcCommonV1.AddConnectionsRes), nil
}

func decodeAddConnectionsRequest(_ context.Context, grpcReq interface{}) (interface{}, error) {
	req := grpcReq.(*grpcCommonV1.AddConnectionsReq)

	conns := []connection{}
	for _, c := range req.Connections {
		conns = append(conns, connection{
			thingID:   c.GetThingId(),
			channelID: c.GetChannelId(),
			domainID:  c.GetDomainId(),
		})
	}
	return connectionsReq{
		connections: conns,
	}, nil
}

func encodeAddConnectionsResponse(_ context.Context, grpcRes interface{}) (interface{}, error) {
	res := grpcRes.(connectionsRes)

	return &grpcCommonV1.AddConnectionsRes{Ok: res.ok}, nil
}

func (s *grpcServer) RemoveConnections(ctx context.Context, req *grpcCommonV1.RemoveConnectionsReq) (*grpcCommonV1.RemoveConnectionsRes, error) {
	_, res, err := s.removeConnections.ServeGRPC(ctx, req)
	if err != nil {
		return nil, encodeError(err)
	}
	return res.(*grpcCommonV1.RemoveConnectionsRes), nil
}

func decodeRemoveConnectionsRequest(_ context.Context, grpcReq interface{}) (interface{}, error) {
	req := grpcReq.(*grpcCommonV1.RemoveConnectionsReq)

	conns := []connection{}
	for _, c := range req.Connections {
		conns = append(conns, connection{
			thingID:   c.GetThingId(),
			channelID: c.GetChannelId(),
			domainID:  c.GetDomainId(),
		})
	}
	return connectionsReq{
		connections: conns,
	}, nil
}

func encodeRemoveConnectionsResponse(_ context.Context, grpcRes interface{}) (interface{}, error) {
	res := grpcRes.(connectionsRes)

	return &grpcCommonV1.RemoveConnectionsRes{Ok: res.ok}, nil
}

func encodeError(err error) error {
	switch {
	case errors.Contains(err, nil):
		return nil
	case errors.Contains(err, errors.ErrMalformedEntity),
		err == apiutil.ErrInvalidAuthKey,
		err == apiutil.ErrMissingID,
		err == apiutil.ErrMissingMemberType,
		err == apiutil.ErrMissingPolicySub,
		err == apiutil.ErrMissingPolicyObj,
		err == apiutil.ErrMalformedPolicyAct:
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Contains(err, svcerr.ErrAuthentication),
		errors.Contains(err, mgauth.ErrKeyExpired),
		err == apiutil.ErrMissingEmail,
		err == apiutil.ErrBearerToken:
		return status.Error(codes.Unauthenticated, err.Error())
	case errors.Contains(err, svcerr.ErrAuthorization):
		return status.Error(codes.PermissionDenied, err.Error())
	default:
		return status.Error(codes.Internal, err.Error())
	}
}
