// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"context"

	"github.com/absmach/magistrala/pkg/authn"
	"github.com/absmach/magistrala/pkg/authz"
	mgauthz "github.com/absmach/magistrala/pkg/authz"
	"github.com/absmach/magistrala/pkg/errors"
	svcerr "github.com/absmach/magistrala/pkg/errors/service"
	"github.com/absmach/magistrala/pkg/policies"
	rmMW "github.com/absmach/magistrala/pkg/roles/rolemanager/middleware"
	"github.com/absmach/magistrala/pkg/svcutil"
	"github.com/absmach/magistrala/things"
)

var (
	errView                    = errors.New("not authorized to view client")
	errUpdate                  = errors.New("not authorized to update client")
	errUpdateTags              = errors.New("not authorized to update client tags")
	errUpdateSecret            = errors.New("not authorized to update client secret")
	errEnable                  = errors.New("not authorized to enable client")
	errDisable                 = errors.New("not authorized to disable client")
	errDelete                  = errors.New("not authorized to delete client")
	errSetParentGroup          = errors.New("not authorized to set parent group to client")
	errRemoveParentGroup       = errors.New("not authorized to remove parent group from client")
	errDomainCreateClients     = errors.New("not authorized to create client in domain")
	errGroupSetChildClients    = errors.New("not authorized to set child client for group")
	errGroupRemoveChildClients = errors.New("not authorized to remove child client for group")
)

var _ things.Service = (*authorizationMiddleware)(nil)

type authorizationMiddleware struct {
	svc    things.Service
	repo   things.Repository
	authz  mgauthz.Authorization
	opp    svcutil.OperationPerm
	extOpp svcutil.ExternalOperationPerm
	rmMW.RoleManagerAuthorizationMiddleware
}

// AuthorizationMiddleware adds authorization to the clients service.
func AuthorizationMiddleware(entityType string, svc things.Service, authz mgauthz.Authorization, repo things.Repository, thingsOpPerm, rolesOpPerm map[svcutil.Operation]svcutil.Permission, extOpPerm map[svcutil.ExternalOperation]svcutil.Permission) (things.Service, error) {
	opp := things.NewOperationPerm()
	if err := opp.AddOperationPermissionMap(thingsOpPerm); err != nil {
		return nil, err
	}
	if err := opp.Validate(); err != nil {
		return nil, err
	}
	ram, err := rmMW.NewRoleManagerAuthorizationMiddleware(policies.ThingType, svc, authz, rolesOpPerm)
	if err != nil {
		return nil, err
	}
	extOpp := things.NewExternalOperationPerm()
	if err := extOpp.AddOperationPermissionMap(extOpPerm); err != nil {
		return nil, err
	}
	if err := extOpp.Validate(); err != nil {
		return nil, err
	}
	return &authorizationMiddleware{
		svc:                                svc,
		authz:                              authz,
		repo:                               repo,
		opp:                                opp,
		extOpp:                             extOpp,
		RoleManagerAuthorizationMiddleware: ram,
	}, nil
}

func (am *authorizationMiddleware) CreateClients(ctx context.Context, session authn.Session, client ...things.Client) ([]things.Client, error) {
	if err := am.extAuthorize(ctx, things.DomainOpCreateThing, authz.PolicyReq{
		Domain:      session.DomainID,
		SubjectType: policies.UserType,
		Subject:     session.DomainUserID,
		ObjectType:  policies.DomainType,
		Object:      session.DomainID,
	}); err != nil {
		return []things.Client{}, errors.Wrap(err, errDomainCreateClients)
	}

	return am.svc.CreateClients(ctx, session, client...)
}

func (am *authorizationMiddleware) View(ctx context.Context, session authn.Session, id string) (things.Client, error) {
	if err := am.authorize(ctx, things.OpViewThing, authz.PolicyReq{
		Domain:      session.DomainID,
		SubjectType: policies.UserType,
		Subject:     session.DomainUserID,
		ObjectType:  policies.ThingType,
		Object:      id,
	}); err != nil {
		return things.Client{}, errors.Wrap(err, errView)
	}
	return am.svc.View(ctx, session, id)
}

func (am *authorizationMiddleware) ListClients(ctx context.Context, session authn.Session, reqUserID string, pm things.Page) (things.ClientsPage, error) {
	if err := am.checkSuperAdmin(ctx, session.UserID); err != nil {
		session.SuperAdmin = true
	}

	return am.svc.ListClients(ctx, session, reqUserID, pm)
}

func (am *authorizationMiddleware) Update(ctx context.Context, session authn.Session, client things.Client) (things.Client, error) {
	if err := am.authorize(ctx, things.OpUpdateThing, authz.PolicyReq{
		Domain:      session.DomainID,
		SubjectType: policies.UserType,
		Subject:     session.DomainUserID,
		ObjectType:  policies.ThingType,
		Object:      client.ID,
	}); err != nil {
		return things.Client{}, errors.Wrap(err, errUpdate)
	}

	return am.svc.Update(ctx, session, client)
}

func (am *authorizationMiddleware) UpdateTags(ctx context.Context, session authn.Session, client things.Client) (things.Client, error) {
	if err := am.authorize(ctx, things.OpUpdateThingTags, authz.PolicyReq{
		Domain:      session.DomainID,
		SubjectType: policies.UserType,
		Subject:     session.DomainUserID,
		ObjectType:  policies.ThingType,
		Object:      client.ID,
	}); err != nil {
		return things.Client{}, errors.Wrap(err, errUpdateTags)
	}

	return am.svc.UpdateTags(ctx, session, client)
}

func (am *authorizationMiddleware) UpdateSecret(ctx context.Context, session authn.Session, id, key string) (things.Client, error) {
	if err := am.authorize(ctx, things.OpUpdateThingSecret, authz.PolicyReq{
		Domain:      session.DomainID,
		SubjectType: policies.UserType,
		Subject:     session.DomainUserID,
		ObjectType:  policies.ThingType,
		Object:      id,
	}); err != nil {
		return things.Client{}, errors.Wrap(err, errUpdateSecret)
	}
	return am.svc.UpdateSecret(ctx, session, id, key)
}

func (am *authorizationMiddleware) Enable(ctx context.Context, session authn.Session, id string) (things.Client, error) {
	if err := am.authorize(ctx, things.OpEnableThing, authz.PolicyReq{
		Domain:      session.DomainID,
		SubjectType: policies.UserType,
		Subject:     session.DomainUserID,
		ObjectType:  policies.ThingType,
		Object:      id,
	}); err != nil {
		return things.Client{}, errors.Wrap(err, errEnable)
	}

	return am.svc.Enable(ctx, session, id)
}

func (am *authorizationMiddleware) Disable(ctx context.Context, session authn.Session, id string) (things.Client, error) {
	if err := am.authorize(ctx, things.OpDisableThing, authz.PolicyReq{
		Domain:      session.DomainID,
		SubjectType: policies.UserType,
		Subject:     session.DomainUserID,
		ObjectType:  policies.ThingType,
		Object:      id,
	}); err != nil {
		return things.Client{}, errors.Wrap(err, errDisable)
	}
	return am.svc.Disable(ctx, session, id)
}

func (am *authorizationMiddleware) Delete(ctx context.Context, session authn.Session, id string) error {
	if err := am.authorize(ctx, things.OpDeleteThing, authz.PolicyReq{
		Domain:      session.DomainID,
		SubjectType: policies.UserType,
		Subject:     session.DomainUserID,
		ObjectType:  policies.ThingType,
		Object:      id,
	}); err != nil {
		return errors.Wrap(err, errDelete)
	}

	return am.svc.Delete(ctx, session, id)
}

func (am *authorizationMiddleware) SetParentGroup(ctx context.Context, session authn.Session, parentGroupID string, id string) error {
	if err := am.authorize(ctx, things.OpSetParentGroup, authz.PolicyReq{
		Domain:      session.DomainID,
		SubjectType: policies.UserType,
		Subject:     session.DomainUserID,
		ObjectType:  policies.ThingType,
		Object:      id,
	}); err != nil {
		return errors.Wrap(err, errSetParentGroup)
	}

	if err := am.extAuthorize(ctx, things.GroupOpSetChildThing, authz.PolicyReq{
		Domain:      session.DomainID,
		SubjectType: policies.UserType,
		Subject:     session.DomainUserID,
		ObjectType:  policies.GroupType,
		Object:      parentGroupID,
	}); err != nil {
		return errors.Wrap(err, errGroupSetChildClients)
	}
	return am.svc.SetParentGroup(ctx, session, parentGroupID, id)
}

func (am *authorizationMiddleware) RemoveParentGroup(ctx context.Context, session authn.Session, id string) error {
	if err := am.authorize(ctx, things.OpRemoveParentGroup, authz.PolicyReq{
		Domain:      session.DomainID,
		SubjectType: policies.UserType,
		Subject:     session.DomainUserID,
		ObjectType:  policies.ThingType,
		Object:      id,
	}); err != nil {
		return errors.Wrap(err, errRemoveParentGroup)
	}

	th, err := am.repo.RetrieveByID(ctx, id)
	if err != nil {
		return errors.Wrap(svcerr.ErrRemoveEntity, err)
	}

	if th.ParentGroup != "" {
		if err := am.extAuthorize(ctx, things.GroupOpSetChildThing, authz.PolicyReq{
			Domain:      session.DomainID,
			SubjectType: policies.UserType,
			Subject:     session.DomainUserID,
			ObjectType:  policies.GroupType,
			Object:      th.ParentGroup,
		}); err != nil {
			return errors.Wrap(err, errGroupRemoveChildClients)
		}
		return am.svc.RemoveParentGroup(ctx, session, id)
	}
	return nil
}

func (am *authorizationMiddleware) authorize(ctx context.Context, op svcutil.Operation, req authz.PolicyReq) error {
	perm, err := am.opp.GetPermission(op)
	if err != nil {
		return err
	}

	req.Permission = perm.String()

	if err := am.authz.Authorize(ctx, req); err != nil {
		return err
	}

	return nil
}

func (am *authorizationMiddleware) extAuthorize(ctx context.Context, extOp svcutil.ExternalOperation, req authz.PolicyReq) error {
	perm, err := am.extOpp.GetPermission(extOp)
	if err != nil {
		return err
	}

	req.Permission = perm.String()

	if err := am.authz.Authorize(ctx, req); err != nil {
		return err
	}

	return nil
}

func (am *authorizationMiddleware) checkSuperAdmin(ctx context.Context, userID string) error {
	if err := am.authz.Authorize(ctx, mgauthz.PolicyReq{
		SubjectType: policies.UserType,
		Subject:     userID,
		Permission:  policies.AdminPermission,
		ObjectType:  policies.PlatformType,
		Object:      policies.MagistralaObject,
	}); err != nil {
		return err
	}
	return nil
}
