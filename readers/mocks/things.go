// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package mocks

import (
	"context"

	"github.com/golang/protobuf/ptypes/empty"

	"github.com/mainflux/mainflux"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	errUnauthenticated = status.Error(codes.Unauthenticated, "missing credentials provided")
	errUnauthorized    = status.Error(codes.PermissionDenied, "unauthorized access")
)

var _ mainflux.ThingsServiceClient = (*thingsServiceMock)(nil)

type thingsServiceMock struct{}

// NewThingsService returns mock implementation of things service
func NewThingsService() mainflux.ThingsServiceClient {
	return thingsServiceMock{}
}

func (svc thingsServiceMock) CanAccessByKey(ctx context.Context, in *mainflux.AccessByKeyReq, opts ...grpc.CallOption) (*mainflux.ThingID, error) {
	token := in.GetToken()
	if token == "invalid" {
		return nil, errUnauthorized
	}

	if token == "" {
		return nil, errUnauthenticated
	}

	return &mainflux.ThingID{Value: token}, nil
}

func (svc thingsServiceMock) CanAccessByID(context.Context, *mainflux.AccessByIDReq, ...grpc.CallOption) (*empty.Empty, error) {
	panic("not implemented")
}

func (svc thingsServiceMock) Identify(context.Context, *mainflux.Token, ...grpc.CallOption) (*mainflux.ThingID, error) {
	panic("not implemented")
}
