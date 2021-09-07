// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package commands

import (
	"errors"
)

var (
	// ErrMalformedEntity indicates malformed entity specification (e.g.
	// invalid username or password).
	ErrMalformedEntity = errors.New("malformed entity specification")

	// ErrUnauthorizedAccess indicates missing or invalid credentials provided
	// when accessing a protected resource.
	ErrUnauthorizedAccess = errors.New("missing or invalid credentials provided")
)

// Service specifies an API that must be fullfiled by the domain service
// implementation, and all of its decorators (e.g. logging & metrics).
type Service interface {
	// ViewCommands compares a given string with secret
	CreateCommands(string) (string, error)
	ViewCommands(string) (string, error)
	ListCommands(string) (string, error)
	UpdateCommands(string) (string, error)
	RemoveCommands(string) (string, error)
}

type commandsService struct {
	secret string
}

var _ Service = (*commandsService)(nil)

// New instantiates the commands service implementation.
func New(secret string) Service {
	return &commandsService{
		secret: secret,
	}
}
func (ks *commandsService) CreateCommands(secret string) (string, error) {
	if ks.secret != secret {
		return "", ErrUnauthorizedAccess
	}
	return "Hello World :)", nil
}

func (ks *commandsService) ViewCommands(secret string) (string, error) {
	if ks.secret != secret {
		return "", ErrUnauthorizedAccess
	}
	return "Hello World :)", nil
}

func (ks *commandsService) ListCommands(secret string) (string, error) {
	if ks.secret != secret {
		return "", ErrUnauthorizedAccess
	}
	return "Hello World :)", nil
}

func (ks *commandsService) UpdateCommands(secret string) (string, error) {
	if ks.secret != secret {
		return "", ErrUnauthorizedAccess
	}
	return "Hello World :)", nil
}

func (ks *commandsService) RemoveCommands(secret string) (string, error) {
	if ks.secret != secret {
		return "", ErrUnauthorizedAccess
	}
	return "Hello World :)", nil
}
