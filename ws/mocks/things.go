package mocks

import (
	"context"

	"github.com/mainflux/mainflux"
	"github.com/mainflux/mainflux/things"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var _ mainflux.ThingsServiceClient = (*thingsClient)(nil)

// ErrToken is used to simulate internal server error.
const ErrToken = "unavailable"

type thingsClient struct {
	things map[string]uint64
}

// NewThingsClient returns mock implementation of things service client.
func NewThingsClient(data map[string]uint64) mainflux.ThingsServiceClient {
	return &thingsClient{data}
}

func (tc thingsClient) CanAccess(ctx context.Context, req *mainflux.AccessReq, opts ...grpc.CallOption) (*mainflux.ThingID, error) {
	key := req.GetToken()

	// Since there is no appropriate way to simulate internal server error,
	// we had to use this obscure approach. ErrorToken simulates gRPC
	// call which returns internal server error.
	if key == ErrToken {
		return nil, status.Error(codes.Internal, "internal server error")
	}
	if key == "" {
		return nil, things.ErrUnauthorizedAccess
	}

	id, ok := tc.things[key]
	if !ok {
		return nil, status.Error(codes.PermissionDenied, "invalid credentials provided")
	}

	return &mainflux.ThingID{Value: id}, nil
}

func (tc thingsClient) Identify(ctx context.Context, req *mainflux.Token, opts ...grpc.CallOption) (*mainflux.ThingID, error) {
	return nil, nil
}
