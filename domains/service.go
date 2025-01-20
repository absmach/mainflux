// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package domains

import (
	"context"
	"time"

	"github.com/absmach/supermq"
	"github.com/absmach/supermq/pkg/authn"
	"github.com/absmach/supermq/pkg/errors"
	svcerr "github.com/absmach/supermq/pkg/errors/service"
	"github.com/absmach/supermq/pkg/policies"
	"github.com/absmach/supermq/pkg/roles"
)

var (
	errCreateDomainPolicy = errors.New("failed to create domain policy")
	errRollbackRepo       = errors.New("failed to rollback repo")
)

type service struct {
	repo       Repository
	cache      Cache
	policy     policies.Service
	idProvider supermq.IDProvider
	roles.ProvisionManageService
}

var _ Service = (*service)(nil)

func New(repo Repository, cache Cache, policy policies.Service, idProvider supermq.IDProvider, sidProvider supermq.IDProvider, availableActions []roles.Action, builtInRoles map[roles.BuiltInRoleName][]roles.Action) (Service, error) {
	rpms, err := roles.NewProvisionManageService(policies.DomainType, repo, policy, sidProvider, availableActions, builtInRoles)
	if err != nil {
		return nil, err
	}

	return &service{
		repo:                   repo,
		cache:                  cache,
		policy:                 policy,
		idProvider:             idProvider,
		ProvisionManageService: rpms,
	}, nil
}

func (svc service) CreateDomain(ctx context.Context, session authn.Session, d Domain) (retDo Domain, retRps []roles.RoleProvision, retErr error) {
	d.CreatedBy = session.UserID

	domainID, err := svc.idProvider.ID()
	if err != nil {
		return Domain{}, []roles.RoleProvision{}, errors.Wrap(svcerr.ErrCreateEntity, err)
	}
	d.ID = domainID

	if d.Status != DisabledStatus && d.Status != EnabledStatus {
		return Domain{}, []roles.RoleProvision{}, svcerr.ErrInvalidStatus
	}

	d.CreatedAt = time.Now()

	// Domain is created in repo first, because Roles table have foreign key relation with Domain ID
	dom, err := svc.repo.Save(ctx, d)
	if err != nil {
		return Domain{}, []roles.RoleProvision{}, errors.Wrap(svcerr.ErrCreateEntity, err)
	}
	defer func() {
		if retErr != nil {
			if errRollBack := svc.repo.Delete(ctx, domainID); errRollBack != nil {
				retErr = errors.Wrap(retErr, errors.Wrap(errRollbackRepo, errRollBack))
			}
		}
	}()

	newBuiltInRoleMembers := map[roles.BuiltInRoleName][]roles.Member{
		BuiltInRoleAdmin: {roles.Member(session.UserID)},
	}

	optionalPolicies := []policies.Policy{
		{
			Subject:     policies.SuperMQObject,
			SubjectType: policies.PlatformType,
			Relation:    "organization",
			Object:      d.ID,
			ObjectType:  policies.DomainType,
		},
	}

	rps, err := svc.AddNewEntitiesRoles(ctx, domainID, session.UserID, []string{domainID}, optionalPolicies, newBuiltInRoleMembers)
	if err != nil {
		return Domain{}, []roles.RoleProvision{}, errors.Wrap(errCreateDomainPolicy, err)
	}

	return dom, rps, nil
}

func (svc service) RetrieveDomain(ctx context.Context, session authn.Session, id string) (Domain, error) {
	var domain Domain
	var err error
	switch session.SuperAdmin {
	case true:
		domain, err = svc.repo.RetrieveByID(ctx, id)
	default:
		domain, err = svc.repo.RetrieveByUserAndID(ctx, session.UserID, id)
	}
	if err != nil {
		return Domain{}, errors.Wrap(svcerr.ErrViewEntity, err)
	}
	return domain, nil
}

func (svc service) UpdateDomain(ctx context.Context, session authn.Session, id string, d DomainReq) (Domain, error) {
	updatedAt := time.Now()
	d.UpdatedAt = &updatedAt
	d.UpdatedBy = &session.UserID
	dom, err := svc.repo.Update(ctx, id, d)
	if err != nil {
		return Domain{}, errors.Wrap(svcerr.ErrUpdateEntity, err)
	}
	return dom, nil
}

func (svc service) EnableDomain(ctx context.Context, session authn.Session, id string) (Domain, error) {
	status := EnabledStatus
	updatedAt := time.Now()
	dom, err := svc.repo.Update(ctx, id, DomainReq{Status: &status, UpdatedBy: &session.UserID, UpdatedAt: &updatedAt})
	if err != nil {
		return Domain{}, errors.Wrap(svcerr.ErrUpdateEntity, err)
	}
	if err := svc.cache.Remove(ctx, id); err != nil {
		return dom, errors.Wrap(svcerr.ErrRemoveEntity, err)
	}

	return dom, nil
}

func (svc service) DisableDomain(ctx context.Context, session authn.Session, id string) (Domain, error) {
	status := DisabledStatus
	updatedAt := time.Now()
	dom, err := svc.repo.Update(ctx, id, DomainReq{Status: &status, UpdatedBy: &session.UserID, UpdatedAt: &updatedAt})
	if err != nil {
		return Domain{}, errors.Wrap(svcerr.ErrUpdateEntity, err)
	}
	if err := svc.cache.Remove(ctx, id); err != nil {
		return dom, errors.Wrap(svcerr.ErrRemoveEntity, err)
	}

	return dom, nil
}

// Only SuperAdmin can freeze the domain.
func (svc service) FreezeDomain(ctx context.Context, session authn.Session, id string) (Domain, error) {
	status := FreezeStatus
	updatedAt := time.Now()
	dom, err := svc.repo.Update(ctx, id, DomainReq{Status: &status, UpdatedBy: &session.UserID, UpdatedAt: &updatedAt})
	if err != nil {
		return Domain{}, errors.Wrap(svcerr.ErrUpdateEntity, err)
	}
	if err := svc.cache.Remove(ctx, id); err != nil {
		return dom, errors.Wrap(svcerr.ErrRemoveEntity, err)
	}

	return dom, nil
}

func (svc service) ListDomains(ctx context.Context, session authn.Session, p Page) (DomainsPage, error) {
	p.UserID = session.UserID
	if session.SuperAdmin {
		p.UserID = ""
	}

	dp, err := svc.repo.ListDomains(ctx, p)
	if err != nil {
		return DomainsPage{}, errors.Wrap(svcerr.ErrViewEntity, err)
	}
	return dp, nil
}
