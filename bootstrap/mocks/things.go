// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package mocks

import (
	"context"
	"strconv"
	"sync"

	mfclients "github.com/mainflux/mainflux/internal/mainflux/clients"
	"github.com/mainflux/mainflux/pkg/errors"
	"github.com/mainflux/mainflux/things/clients"
	upolicies "github.com/mainflux/mainflux/users/policies"
)

var _ clients.Service = (*mainfluxThings)(nil)

type mainfluxThings struct {
	mu      sync.Mutex
	counter uint64
	things  map[string]clients.Client
	auth    upolicies.AuthServiceClient
}

// NewThingsService returns Mainflux Things service mock.
// Only methods used by SDK are mocked.
func NewThingsService(things map[string]clients.Client, auth upolicies.AuthServiceClient) clients.Service {
	return &mainfluxThings{
		things: things,
		auth:   auth,
	}
}

func (svc *mainfluxThings) CreateThings(_ context.Context, owner string, ths ...clients.Client) ([]clients.Client, error) {
	svc.mu.Lock()
	defer svc.mu.Unlock()

	userID, err := svc.auth.Identify(context.Background(), &upolicies.Token{Value: owner})
	if err != nil {
		return []clients.Client{}, errors.ErrAuthentication
	}
	for i := range ths {
		svc.counter++
		ths[i].Owner = userID.GetId()
		ths[i].ID = strconv.FormatUint(svc.counter, 10)
		ths[i].Credentials.Secret = ths[i].ID
		svc.things[ths[i].ID] = ths[i]
	}

	return ths, nil
}

func (svc *mainfluxThings) ViewClient(_ context.Context, owner, id string) (clients.Client, error) {
	svc.mu.Lock()
	defer svc.mu.Unlock()

	userID, err := svc.auth.Identify(context.Background(), &upolicies.Token{Value: owner})
	if err != nil {
		return clients.Client{}, errors.ErrAuthentication
	}

	if t, ok := svc.things[id]; ok && t.Owner == userID.GetId() {
		return t, nil

	}

	return clients.Client{}, errors.ErrNotFound
}

func (svc *mainfluxThings) EnableClient(ctx context.Context, token, id string) (clients.Client, error) {
	svc.mu.Lock()
	defer svc.mu.Unlock()

	userID, err := svc.auth.Identify(context.Background(), &upolicies.Token{Value: token})
	if err != nil {
		return clients.Client{}, errors.ErrAuthentication
	}

	if t, ok := svc.things[id]; !ok || t.Owner != userID.GetId() {
		return clients.Client{}, errors.ErrNotFound
	}
	if t, ok := svc.things[id]; ok && t.Owner == userID.GetId() {
		t.Status = mfclients.EnabledStatus
		return t, nil
	}
	return clients.Client{}, nil
}

func (svc *mainfluxThings) DisableClient(ctx context.Context, token, id string) (clients.Client, error) {
	svc.mu.Lock()
	defer svc.mu.Unlock()

	userID, err := svc.auth.Identify(context.Background(), &upolicies.Token{Value: token})
	if err != nil {
		return clients.Client{}, errors.ErrAuthentication
	}

	if t, ok := svc.things[id]; !ok || t.Owner != userID.GetId() {
		return clients.Client{}, errors.ErrNotFound
	}
	if t, ok := svc.things[id]; ok && t.Owner == userID.GetId() {
		t.Status = mfclients.DisabledStatus
		return t, nil
	}
	return clients.Client{}, nil
}

func (svc *mainfluxThings) UpdateClient(context.Context, string, clients.Client) (clients.Client, error) {
	panic("not implemented")
}

func (svc *mainfluxThings) UpdateClientSecret(context.Context, string, string, string) (clients.Client, error) {
	panic("not implemented")
}

func (svc *mainfluxThings) UpdateClientOwner(context.Context, string, clients.Client) (clients.Client, error) {
	panic("not implemented")
}

func (svc *mainfluxThings) UpdateClientTags(context.Context, string, clients.Client) (clients.Client, error) {
	panic("not implemented")
}

func (svc *mainfluxThings) ListClients(context.Context, string, clients.Page) (clients.ClientsPage, error) {
	panic("not implemented")
}

func (svc *mainfluxThings) ListClientsByGroup(context.Context, string, string, clients.Page) (clients.MembersPage, error) {
	panic("not implemented")
}

func (svc *mainfluxThings) Identify(context.Context, string) (string, error) {
	panic("not implemented")
}

func (svc *mainfluxThings) ShareClient(ctx context.Context, token, thingID string, actions, userIDs []string) error {
	panic("not implemented")
}
