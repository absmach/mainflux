// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package service

import "github.com/absmach/magistrala/pkg/errors"

// Wrapper for Service errors.
var (
	// ErrAuthentication indicates failure occurred while authenticating the entity.
	ErrAuthentication = errors.New("failed to perform authentication over the entity")

	// ErrAuthorization indicates failure occurred while authorizing the entity.
	ErrAuthorization = errors.New("failed to perform authorization over the entity")

	// ErrDomainAuthorization indicates failure occurred while authorizing the domain.
	ErrDomainAuthorization = errors.New("failed to perform authorization over the domain")

	// ErrLogin indicates wrong login credentials.
	ErrLogin = errors.New("invalid user id or secret")

	// ErrMalformedEntity indicates a malformed entity specification.
	ErrMalformedEntity = errors.New("malformed entity specification")

	// ErrNotFound indicates a non-existent entity request.
	ErrNotFound = errors.New("entity not found")

	// ErrConflict indicates that entity already exists.
	ErrConflict = errors.New("entity already exists")

	// ErrCreateEntity indicates error in creating entity or entities.
	ErrCreateEntity = errors.New("failed to create entity in the db")

	// ErrRemoveEntity indicates error in removing entity.
	ErrRemoveEntity = errors.New("failed to remove entity")

	// ErrViewEntity indicates error in viewing entity or entities.
	ErrViewEntity = errors.New("view entity failed")

	// ErrUpdateEntity indicates error in updating entity or entities.
	ErrUpdateEntity = errors.New("update entity failed")

	// ErrInvalidStatus indicates an invalid status.
	ErrInvalidStatus = errors.New("invalid status")

	// ErrInvalidRole indicates that an invalid role.
	ErrInvalidRole = errors.New("invalid client role")

	// ErrInvalidPolicy indicates that an invalid policy.
	ErrInvalidPolicy = errors.New("invalid policy")

	// ErrRecoveryToken indicates error in generating password recovery token.
	ErrRecoveryToken = errors.New("failed to generate password recovery token")

	// ErrFailedPolicyUpdate indicates a failure to update user policy.
	ErrFailedPolicyUpdate = errors.New("failed to update user policy")

	// ErrAddPolicies indicates failed to add policies.
	ErrAddPolicies = errors.New("failed to add policies")

	// ErrDeletePolicies indicates failed to delete policies.
	ErrDeletePolicies = errors.New("failed to delete policies")

	// ErrIssueToken indicates a failure to issue token.
	ErrIssueToken = errors.New("failed to issue token")

	// ErrPasswordFormat indicates weak password.
	ErrPasswordFormat = errors.New("password does not meet the requirements")

	// ErrFailedUpdateRole indicates a failure to update user role.
	ErrFailedUpdateRole = errors.New("failed to update user role")

	// ErrFailedDelete indicates a failure to delete domain.
	ErrFailedDelete = errors.New("failed to delete domain")
)
