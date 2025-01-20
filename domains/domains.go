// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package domains

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/absmach/supermq/pkg/authn"
	svcerr "github.com/absmach/supermq/pkg/errors/service"
	"github.com/absmach/supermq/pkg/roles"
)

// Status represents Domain status.
type Status uint8

// Possible Domain status values.
const (
	// EnabledStatus represents enabled Domain.
	EnabledStatus Status = iota
	// DisabledStatus represents disabled Domain.
	DisabledStatus
	// FreezeStatus represents domain is in freezed state.
	FreezeStatus
	// DeletedStatus represents domain is in deleted state.
	DeletedStatus

	// AllStatus is used for querying purposes to list Domains irrespective
	// of their status - enabled, disabled, freezed, deleting. It is never stored in the
	// database as the actual domain status and should always be the larger than freeze status
	// value in this enumeration.
	AllStatus
)

// String representation of the possible status values.
const (
	Disabled = "disabled"
	Enabled  = "enabled"
	Freezed  = "freezed"
	Deleted  = "deleted"
	All      = "all"
	Unknown  = "unknown"
)

// String converts client/group status to string literal.
func (s Status) String() string {
	switch s {
	case DisabledStatus:
		return Disabled
	case EnabledStatus:
		return Enabled
	case AllStatus:
		return All
	case FreezeStatus:
		return Freezed
	case DeletedStatus:
		return Deleted
	default:
		return Unknown
	}
}

// ToStatus converts string value to a valid Domain status.
func ToStatus(status string) (Status, error) {
	switch status {
	case "", Enabled:
		return EnabledStatus, nil
	case Disabled:
		return DisabledStatus, nil
	case Freezed:
		return FreezeStatus, nil
	case Deleted:
		return DeletedStatus, nil
	case All:
		return AllStatus, nil
	}
	return Status(0), svcerr.ErrInvalidStatus
}

// Custom Marshaller for Domains status.
func (s Status) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

// Custom Unmarshaler for Domains status.
func (s *Status) UnmarshalJSON(data []byte) error {
	str := strings.Trim(string(data), "\"")
	val, err := ToStatus(str)
	*s = val
	return err
}

// Metadata represents arbitrary JSON.
type Metadata map[string]interface{}

type DomainReq struct {
	Name      *string    `json:"name,omitempty"`
	Metadata  *Metadata  `json:"metadata,omitempty"`
	Tags      *[]string  `json:"tags,omitempty"`
	Alias     *string    `json:"alias,omitempty"`
	Status    *Status    `json:"status,omitempty"`
	UpdatedBy *string    `json:"updated_by,omitempty"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
}
type Domain struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Metadata  Metadata  `json:"metadata,omitempty"`
	Tags      []string  `json:"tags,omitempty"`
	Alias     string    `json:"alias,omitempty"`
	Status    Status    `json:"status"`
	RoleID    string    `json:"role_id,omitempty"`
	RoleName  string    `json:"role_name,omitempty"`
	Actions   []string  `json:"actions,omitempty"`
	CreatedBy string    `json:"created_by,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedBy string    `json:"updated_by,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

type Page struct {
	Total    uint64   `json:"total"`
	Offset   uint64   `json:"offset"`
	Limit    uint64   `json:"limit"`
	Name     string   `json:"name,omitempty"`
	Order    string   `json:"-"`
	Dir      string   `json:"-"`
	Metadata Metadata `json:"metadata,omitempty"`
	Tag      string   `json:"tag,omitempty"`
	RoleName string   `json:"role_name,omitempty"`
	RoleID   string   `json:"role_id,omitempty"`
	Actions  []string `json:"actions,omitempty"`
	Status   Status   `json:"status,omitempty"`
	ID       string   `json:"id,omitempty"`
	IDs      []string `json:"-"`
	Identity string   `json:"identity,omitempty"`
	UserID   string   `json:"-"`
}

type DomainsPage struct {
	Total   uint64   `json:"total"`
	Offset  uint64   `json:"offset"`
	Limit   uint64   `json:"limit"`
	Domains []Domain `json:"domains"`
}

func (page DomainsPage) MarshalJSON() ([]byte, error) {
	type Alias DomainsPage
	a := struct {
		Alias
	}{
		Alias: Alias(page),
	}

	if a.Domains == nil {
		a.Domains = make([]Domain, 0)
	}

	return json.Marshal(a)
}

//go:generate mockery --name Service --output=./mocks --filename service.go --quiet --note "Copyright (c) Abstract Machines"
type Service interface {
	CreateDomain(ctx context.Context, sesssion authn.Session, d Domain) (Domain, []roles.RoleProvision, error)
	RetrieveDomain(ctx context.Context, sesssion authn.Session, id string) (Domain, error)
	UpdateDomain(ctx context.Context, sesssion authn.Session, id string, d DomainReq) (Domain, error)
	EnableDomain(ctx context.Context, sesssion authn.Session, id string) (Domain, error)
	DisableDomain(ctx context.Context, sesssion authn.Session, id string) (Domain, error)
	FreezeDomain(ctx context.Context, sesssion authn.Session, id string) (Domain, error)
	ListDomains(ctx context.Context, sesssion authn.Session, page Page) (DomainsPage, error)
	roles.RoleManager
}

// Repository specifies Domain persistence API.
//
//go:generate mockery --name Repository --output=./mocks --filename repository.go  --quiet --note "Copyright (c) Abstract Machines"
type Repository interface {
	// Save creates db insert transaction for the given domain.
	Save(ctx context.Context, d Domain) (Domain, error)

	// RetrieveByID retrieves Domain by its unique ID.
	RetrieveByID(ctx context.Context, id string) (Domain, error)

	RetrieveByUserAndID(ctx context.Context, userID, id string) (Domain, error)

	// RetrieveAllByIDs retrieves for given Domain IDs.
	RetrieveAllByIDs(ctx context.Context, pm Page) (DomainsPage, error)

	// Update updates the client name and metadata.
	Update(ctx context.Context, id string, d DomainReq) (Domain, error)

	// Delete
	Delete(ctx context.Context, id string) error

	// ListDomains list all the domains
	ListDomains(ctx context.Context, pm Page) (DomainsPage, error)

	roles.Repository
}

// Cache contains domains caching interface.
//
//go:generate mockery --name Cache --output=./mocks --filename cache.go --quiet --note "Copyright (c) Abstract Machines"
type Cache interface {
	// Save stores pair domain status and  domain id.
	Save(ctx context.Context, domainID string, status Status) error

	// Status returns domain status for given domain ID.
	Status(ctx context.Context, domainID string) (Status, error)

	// Removes domain from cache.
	Remove(ctx context.Context, domainID string) error
}
