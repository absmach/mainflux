// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package grpc

import (
	"context"
	"fmt"
	"time"

	"github.com/absmach/magistrala"
	"github.com/absmach/magistrala/pkg/errors"
	svcerr "github.com/absmach/magistrala/pkg/errors/service"
	"github.com/go-kit/kit/endpoint"
	kitgrpc "github.com/go-kit/kit/transport/grpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const svcName = "magistrala.AuthzService"

var _ magistrala.AuthzServiceClient = (*grpcClient)(nil)

type grpcClient struct {
	timeout           time.Duration
	authorize         endpoint.Endpoint
	verifyConnections endpoint.Endpoint
}

// NewClient returns new gRPC client instance.
func NewClient(conn *grpc.ClientConn, timeout time.Duration) magistrala.AuthzServiceClient {
	return &grpcClient{
		authorize: kitgrpc.NewClient(
			conn,
			svcName,
			"Authorize",
			encodeAuthorizeRequest,
			decodeAuthorizeResponse,
			magistrala.AuthorizeRes{},
		).Endpoint(),
		verifyConnections: kitgrpc.NewClient(
			conn,
			svcName,
			"VerifyConnections",
			encodeVerifyConnectionsRequest,
			decodeVerifyConnectionsResponse,
			magistrala.VerifyConnectionsRes{},
		).Endpoint(),

		timeout: timeout,
	}
}

func (client grpcClient) Authorize(ctx context.Context, req *magistrala.AuthorizeReq, _ ...grpc.CallOption) (r *magistrala.AuthorizeRes, err error) {
	ctx, cancel := context.WithTimeout(ctx, client.timeout)
	defer cancel()

	res, err := client.authorize(ctx, req)
	if err != nil {
		return &magistrala.AuthorizeRes{}, decodeError(err)
	}

	ar := res.(authorizeRes)
	return &magistrala.AuthorizeRes{Authorized: ar.authorized, Id: ar.id}, nil
}

func decodeAuthorizeResponse(_ context.Context, grpcRes interface{}) (interface{}, error) {
	res := grpcRes.(*magistrala.AuthorizeRes)
	return authorizeRes{authorized: res.Authorized, id: res.Id}, nil
}

func encodeAuthorizeRequest(_ context.Context, grpcReq interface{}) (interface{}, error) {
	req := grpcReq.(*magistrala.AuthorizeReq)
	return &magistrala.AuthorizeReq{
		Domain:      req.GetDomain(),
		SubjectType: req.GetSubjectType(),
		Subject:     req.GetSubject(),
		SubjectKind: req.GetSubjectKind(),
		Relation:    req.GetRelation(),
		Permission:  req.GetPermission(),
		ObjectType:  req.GetObjectType(),
		Object:      req.GetObject(),
	}, nil
}

func (client grpcClient) VerifyConnections(ctx context.Context, req *magistrala.VerifyConnectionsReq, opts ...grpc.CallOption) (*magistrala.VerifyConnectionsRes, error) {
	ctx, cancel := context.WithTimeout(ctx, client.timeout)
	defer cancel()

	res, err := client.verifyConnections(ctx, req)
	if err != nil {
		return &magistrala.VerifyConnectionsRes{}, decodeError(err)
	}

	vc := res.(verifyConnectionsRes)
	connections := []*magistrala.Connectionstatus{}
	for _, rq := range vc.Connections {
		connections = append(connections, &magistrala.Connectionstatus{
			ThingId:   rq.ThingId,
			ChannelId: rq.ChannelId,
			Status:    rq.Status,
		})
	}
	return &magistrala.VerifyConnectionsRes{
		Status:      vc.Status,
		Connections: connections,
	}, nil
}

func decodeVerifyConnectionsResponse(_ context.Context, grpcRes interface{}) (interface{}, error) {
	res := grpcRes.(*magistrala.VerifyConnectionsRes)
	connections := []ConnectionStatus{}

	for _, r := range res.GetConnections() {
		connections = append(connections, ConnectionStatus{
			ThingId:   r.ThingId,
			ChannelId: r.ChannelId,
			Status:    r.Status,
		})
	}
	return verifyConnectionsRes{
		Status:      res.Status,
		Connections: connections,
	}, nil
}

func encodeVerifyConnectionsRequest(_ context.Context, grpcReq interface{}) (interface{}, error) {
	reqs := grpcReq.(*magistrala.VerifyConnectionsReq)
	return &magistrala.VerifyConnectionsReq{
		ThingsId: reqs.GetThingsId(),
		GroupsId: reqs.GetGroupsId(),
	}, nil
}

func decodeError(err error) error {
	if st, ok := status.FromError(err); ok {
		switch st.Code() {
		case codes.Unauthenticated:
			return errors.Wrap(svcerr.ErrAuthentication, errors.New(st.Message()))
		case codes.PermissionDenied:
			return errors.Wrap(svcerr.ErrAuthorization, errors.New(st.Message()))
		case codes.InvalidArgument:
			return errors.Wrap(errors.ErrMalformedEntity, errors.New(st.Message()))
		case codes.FailedPrecondition:
			return errors.Wrap(errors.ErrMalformedEntity, errors.New(st.Message()))
		case codes.NotFound:
			return errors.Wrap(svcerr.ErrNotFound, errors.New(st.Message()))
		case codes.AlreadyExists:
			return errors.Wrap(svcerr.ErrConflict, errors.New(st.Message()))
		case codes.OK:
			if msg := st.Message(); msg != "" {
				return errors.Wrap(errors.ErrUnidentified, errors.New(msg))
			}
			return nil
		default:
			return errors.Wrap(fmt.Errorf("unexpected gRPC status: %s (status code:%v)", st.Code().String(), st.Code()), errors.New(st.Message()))
		}
	}
	return err
}
