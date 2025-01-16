// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"context"

	smqauth "github.com/absmach/supermq/auth"
	"github.com/absmach/supermq/clients"
	"github.com/absmach/supermq/pkg/authn"
	"github.com/absmach/supermq/pkg/errors"
	svcerr "github.com/absmach/supermq/pkg/errors/service"
	smqpat "github.com/absmach/supermq/pkg/pat"
	"github.com/absmach/supermq/pkg/roles"
)

var _ clients.Service = (*patMiddleware)(nil)

type patMiddleware struct {
	svc clients.Service
	pat smqpat.Authorization
}

func PATMiddleware(svc clients.Service, pat smqpat.Authorization) clients.Service {
	return &patMiddleware{
		svc: svc,
		pat: pat,
	}
}

func (pm *patMiddleware) authorizePAT(ctx context.Context, session authn.Session, platformEntityType smqauth.PlatformEntityType, optionalDomainEntityType smqauth.DomainEntityType, OptionalDomainID string, operation smqauth.OperationType, entityIDs []string) error {
	if session.Type != authn.PersonalAccessToken {
		return nil
	}
	if session.ID == "" || session.UserID == "" {
		return errors.Wrap(svcerr.ErrAuthentication, errors.New("invalid PAT credentials"))
	}

	if err := pm.pat.AuthorizePAT(ctx, smqpat.PatReq{
		UserID:                   session.UserID,
		PatID:                    session.ID,
		PlatformEntityType:       platformEntityType,
		OptionalDomainEntityType: optionalDomainEntityType,
		OptionalDomainID:         OptionalDomainID,
		Operation:                operation,
		EntityIDs:                entityIDs,
	}); err != nil {
		return errors.Wrap(svcerr.ErrUnauthorizedPAT, err)
	}

	return nil
}

func (pm *patMiddleware) CreateClients(ctx context.Context, session authn.Session, client ...clients.Client) ([]clients.Client, []roles.RoleProvision, error) {
	if err := pm.authorizePAT(ctx,
		session,
		smqauth.PlatformDomainsScope,
		smqauth.DomainClientsScope,
		session.DomainID,
		smqauth.CreateOp,
		smqauth.AnyIDs{}.Values(),
	); err != nil {
		return []clients.Client{}, []roles.RoleProvision{}, errors.Wrap(svcerr.ErrUnauthorizedPAT, err)
	}

	return pm.svc.CreateClients(ctx, session, client...)
}

func (pm *patMiddleware) View(ctx context.Context, session authn.Session, id string) (clients.Client, error) {
	if err := pm.authorizePAT(ctx,
		session,
		smqauth.PlatformDomainsScope,
		smqauth.DomainClientsScope,
		session.DomainID,
		smqauth.ReadOp,
		[]string{id},
	); err != nil {
		return clients.Client{}, errors.Wrap(svcerr.ErrUnauthorizedPAT, err)
	}

	return pm.svc.View(ctx, session, id)
}

func (pm *patMiddleware) ListClients(ctx context.Context, session authn.Session, reqUserID string, pg clients.Page) (clients.ClientsPage, error) {
	if err := pm.authorizePAT(ctx,
		session,
		smqauth.PlatformDomainsScope,
		smqauth.DomainClientsScope,
		session.DomainID,
		smqauth.ListOp,
		smqauth.AnyIDs{}.Values(),
	); err != nil {
		return clients.ClientsPage{}, errors.Wrap(svcerr.ErrUnauthorizedPAT, err)
	}

	return pm.svc.ListClients(ctx, session, reqUserID, pg)
}

func (pm *patMiddleware) Update(ctx context.Context, session authn.Session, client clients.Client) (clients.Client, error) {
	if err := pm.authorizePAT(ctx,
		session,
		smqauth.PlatformDomainsScope,
		smqauth.DomainClientsScope,
		session.DomainID,
		smqauth.UpdateOp,
		[]string{client.ID},
	); err != nil {
		return clients.Client{}, errors.Wrap(svcerr.ErrUnauthorizedPAT, err)
	}

	return pm.svc.Update(ctx, session, client)
}

func (pm *patMiddleware) UpdateTags(ctx context.Context, session authn.Session, client clients.Client) (clients.Client, error) {
	if err := pm.authorizePAT(ctx,
		session,
		smqauth.PlatformDomainsScope,
		smqauth.DomainClientsScope,
		session.DomainID,
		smqauth.UpdateOp,
		[]string{client.ID},
	); err != nil {
		return clients.Client{}, errors.Wrap(svcerr.ErrUnauthorizedPAT, err)
	}

	return pm.svc.UpdateTags(ctx, session, client)
}

func (pm *patMiddleware) UpdateSecret(ctx context.Context, session authn.Session, id, key string) (clients.Client, error) {
	if err := pm.authorizePAT(ctx,
		session,
		smqauth.PlatformDomainsScope,
		smqauth.DomainClientsScope,
		session.DomainID,
		smqauth.UpdateOp,
		[]string{id},
	); err != nil {
		return clients.Client{}, errors.Wrap(svcerr.ErrUnauthorizedPAT, err)
	}

	return pm.svc.UpdateSecret(ctx, session, id, key)
}

func (pm *patMiddleware) Enable(ctx context.Context, session authn.Session, id string) (clients.Client, error) {
	if err := pm.authorizePAT(ctx,
		session,
		smqauth.PlatformDomainsScope,
		smqauth.DomainClientsScope,
		session.DomainID,
		smqauth.UpdateOp,
		[]string{id},
	); err != nil {
		return clients.Client{}, errors.Wrap(svcerr.ErrUnauthorizedPAT, err)
	}

	return pm.svc.Enable(ctx, session, id)
}

func (pm *patMiddleware) Disable(ctx context.Context, session authn.Session, id string) (clients.Client, error) {
	if err := pm.authorizePAT(ctx,
		session,
		smqauth.PlatformDomainsScope,
		smqauth.DomainClientsScope,
		session.DomainID,
		smqauth.UpdateOp,
		[]string{id},
	); err != nil {
		return clients.Client{}, errors.Wrap(svcerr.ErrUnauthorizedPAT, err)
	}

	return pm.svc.Disable(ctx, session, id)
}

func (pm *patMiddleware) Delete(ctx context.Context, session authn.Session, id string) error {
	if err := pm.authorizePAT(ctx,
		session,
		smqauth.PlatformDomainsScope,
		smqauth.DomainClientsScope,
		session.DomainID,
		smqauth.DeleteOp,
		[]string{id},
	); err != nil {
		return errors.Wrap(svcerr.ErrUnauthorizedPAT, err)
	}

	return pm.svc.Delete(ctx, session, id)
}

func (pm *patMiddleware) SetParentGroup(ctx context.Context, session authn.Session, parentGroupID string, id string) error {
	if err := pm.authorizePAT(ctx,
		session,
		smqauth.PlatformDomainsScope,
		smqauth.DomainGroupsScope,
		session.DomainID,
		smqauth.UpdateOp,
		[]string{id},
	); err != nil {
		return errors.Wrap(svcerr.ErrUnauthorizedPAT, err)
	}

	return pm.svc.SetParentGroup(ctx, session, parentGroupID, id)
}

func (pm *patMiddleware) RemoveParentGroup(ctx context.Context, session authn.Session, id string) error {
	if err := pm.authorizePAT(ctx,
		session,
		smqauth.PlatformDomainsScope,
		smqauth.DomainGroupsScope,
		session.DomainID,
		smqauth.DeleteOp,
		[]string{id},
	); err != nil {
		return errors.Wrap(svcerr.ErrUnauthorizedPAT, err)
	}

	return pm.svc.RemoveParentGroup(ctx, session, id)
}

func (pm *patMiddleware) AddRole(ctx context.Context, session authn.Session, entityID string, roleName string, optionalActions []string, optionalMembers []string) (roles.RoleProvision, error) {
	if err := pm.authorizePAT(ctx,
		session,
		smqauth.PlatformDomainsScope,
		smqauth.DomainClientsScope,
		session.DomainID,
		smqauth.CreateOp,
		[]string{entityID},
	); err != nil {
		return roles.RoleProvision{}, errors.Wrap(svcerr.ErrUnauthorizedPAT, err)
	}

	return pm.svc.AddRole(ctx, session, entityID, roleName, optionalActions, optionalMembers)
}

func (pm *patMiddleware) ListAvailableActions(ctx context.Context, session authn.Session) ([]string, error) {
	if err := pm.authorizePAT(ctx,
		session,
		smqauth.PlatformDomainsScope,
		smqauth.DomainClientsScope,
		session.DomainID,
		smqauth.ListOp,
		smqauth.AnyIDs{}.Values(),
	); err != nil {
		return []string{}, errors.Wrap(svcerr.ErrUnauthorizedPAT, err)
	}

	return pm.svc.ListAvailableActions(ctx, session)
}

func (pm *patMiddleware) RemoveMemberFromAllRoles(ctx context.Context, session authn.Session, member string) error {
	if err := pm.authorizePAT(ctx,
		session,
		smqauth.PlatformDomainsScope,
		smqauth.DomainClientsScope,
		session.DomainID,
		smqauth.DeleteOp,
		smqauth.AnyIDs{}.Values(),
	); err != nil {
		return errors.Wrap(svcerr.ErrUnauthorizedPAT, err)
	}

	return pm.svc.RemoveMemberFromAllRoles(ctx, session, member)
}

func (pm *patMiddleware) RemoveRole(ctx context.Context, session authn.Session, entityID, roleID string) error {
	if err := pm.authorizePAT(ctx,
		session,
		smqauth.PlatformDomainsScope,
		smqauth.DomainClientsScope,
		session.DomainID,
		smqauth.DeleteOp,
		[]string{entityID},
	); err != nil {
		return errors.Wrap(svcerr.ErrUnauthorizedPAT, err)
	}

	return pm.svc.RemoveRole(ctx, session, entityID, roleID)
}

func (pm *patMiddleware) RetrieveAllRoles(ctx context.Context, session authn.Session, entityID string, limit, offset uint64) (roles.RolePage, error) {
	if err := pm.authorizePAT(ctx,
		session,
		smqauth.PlatformDomainsScope,
		smqauth.DomainClientsScope,
		session.DomainID,
		smqauth.ListOp,
		[]string{entityID},
	); err != nil {
		return roles.RolePage{}, errors.Wrap(svcerr.ErrUnauthorizedPAT, err)
	}

	return pm.svc.RetrieveAllRoles(ctx, session, entityID, limit, offset)
}

func (pm *patMiddleware) RetrieveRole(ctx context.Context, session authn.Session, entityID, roleID string) (roles.Role, error) {
	if err := pm.authorizePAT(ctx,
		session,
		smqauth.PlatformDomainsScope,
		smqauth.DomainClientsScope,
		session.DomainID,
		smqauth.ReadOp,
		[]string{entityID},
	); err != nil {
		return roles.Role{}, errors.Wrap(svcerr.ErrUnauthorizedPAT, err)
	}

	return pm.svc.RetrieveRole(ctx, session, entityID, roleID)
}

func (pm *patMiddleware) RoleAddActions(ctx context.Context, session authn.Session, entityID, roleID string, actions []string) ([]string, error) {
	if err := pm.authorizePAT(ctx,
		session,
		smqauth.PlatformDomainsScope,
		smqauth.DomainClientsScope,
		session.DomainID,
		smqauth.UpdateOp,
		[]string{entityID},
	); err != nil {
		return []string{}, errors.Wrap(svcerr.ErrUnauthorizedPAT, err)
	}

	return pm.svc.RoleAddActions(ctx, session, entityID, roleID, actions)
}

func (pm *patMiddleware) RoleListActions(ctx context.Context, session authn.Session, entityID, roleID string) ([]string, error) {
	if err := pm.authorizePAT(ctx,
		session,
		smqauth.PlatformDomainsScope,
		smqauth.DomainClientsScope,
		session.DomainID,
		smqauth.ReadOp,
		[]string{entityID},
	); err != nil {
		return []string{}, errors.Wrap(svcerr.ErrUnauthorizedPAT, err)
	}

	return pm.svc.RoleListActions(ctx, session, entityID, roleID)
}

func (pm *patMiddleware) RoleCheckActionsExists(ctx context.Context, session authn.Session, entityID, roleID string, actions []string) (bool, error) {
	if err := pm.authorizePAT(ctx,
		session,
		smqauth.PlatformDomainsScope,
		smqauth.DomainClientsScope,
		session.DomainID,
		smqauth.ReadOp,
		[]string{entityID},
	); err != nil {
		return false, errors.Wrap(svcerr.ErrUnauthorizedPAT, err)
	}

	return pm.svc.RoleCheckActionsExists(ctx, session, entityID, roleID, actions)
}

func (pm *patMiddleware) RoleRemoveActions(ctx context.Context, session authn.Session, entityID, roleID string, actions []string) error {
	if err := pm.authorizePAT(ctx,
		session,
		smqauth.PlatformDomainsScope,
		smqauth.DomainClientsScope,
		session.DomainID,
		smqauth.DeleteOp,
		[]string{entityID},
	); err != nil {
		return errors.Wrap(svcerr.ErrUnauthorizedPAT, err)
	}

	return pm.svc.RoleRemoveActions(ctx, session, entityID, roleID, actions)
}

func (pm *patMiddleware) RoleRemoveAllActions(ctx context.Context, session authn.Session, entityID, roleID string) error {
	if err := pm.authorizePAT(ctx,
		session,
		smqauth.PlatformDomainsScope,
		smqauth.DomainClientsScope,
		session.DomainID,
		smqauth.DeleteOp,
		[]string{entityID},
	); err != nil {
		return errors.Wrap(svcerr.ErrUnauthorizedPAT, err)
	}

	return pm.svc.RoleRemoveAllActions(ctx, session, entityID, roleID)
}

func (pm *patMiddleware) RoleAddMembers(ctx context.Context, session authn.Session, entityID, roleID string, members []string) ([]string, error) {
	if err := pm.authorizePAT(ctx,
		session,
		smqauth.PlatformDomainsScope,
		smqauth.DomainClientsScope,
		session.DomainID,
		smqauth.UpdateOp,
		[]string{entityID},
	); err != nil {
		return []string{}, errors.Wrap(svcerr.ErrUnauthorizedPAT, err)
	}

	return pm.svc.RoleAddMembers(ctx, session, entityID, roleID, members)
}

func (pm *patMiddleware) RoleListMembers(ctx context.Context, session authn.Session, entityID, roleID string, limit, offset uint64) (roles.MembersPage, error) {
	if err := pm.authorizePAT(ctx,
		session,
		smqauth.PlatformDomainsScope,
		smqauth.DomainClientsScope,
		session.DomainID,
		smqauth.ReadOp,
		[]string{entityID},
	); err != nil {
		return roles.MembersPage{}, errors.Wrap(svcerr.ErrUnauthorizedPAT, err)
	}

	return pm.svc.RoleListMembers(ctx, session, entityID, roleID, limit, offset)
}

func (pm *patMiddleware) RoleCheckMembersExists(ctx context.Context, session authn.Session, entityID, roleID string, members []string) (bool, error) {
	if err := pm.authorizePAT(ctx,
		session,
		smqauth.PlatformDomainsScope,
		smqauth.DomainClientsScope,
		session.DomainID,
		smqauth.ReadOp,
		[]string{entityID},
	); err != nil {
		return false, errors.Wrap(svcerr.ErrUnauthorizedPAT, err)
	}

	return pm.svc.RoleCheckMembersExists(ctx, session, entityID, roleID, members)
}

func (pm *patMiddleware) RoleRemoveMembers(ctx context.Context, session authn.Session, entityID, roleID string, members []string) error {
	if err := pm.authorizePAT(ctx,
		session,
		smqauth.PlatformDomainsScope,
		smqauth.DomainClientsScope,
		session.DomainID,
		smqauth.DeleteOp,
		[]string{entityID},
	); err != nil {
		return errors.Wrap(svcerr.ErrUnauthorizedPAT, err)
	}

	return pm.svc.RoleRemoveMembers(ctx, session, entityID, roleID, members)
}

func (pm *patMiddleware) RoleRemoveAllMembers(ctx context.Context, session authn.Session, entityID, roleID string) error {
	if err := pm.authorizePAT(ctx,
		session,
		smqauth.PlatformDomainsScope,
		smqauth.DomainClientsScope,
		session.DomainID,
		smqauth.DeleteOp,
		[]string{entityID},
	); err != nil {
		return errors.Wrap(svcerr.ErrUnauthorizedPAT, err)
	}

	return pm.svc.RoleRemoveAllMembers(ctx, session, entityID, roleID)
}

func (pm *patMiddleware) UpdateRoleName(ctx context.Context, session authn.Session, entityID, roleID, newRoleName string) (roles.Role, error) {
	if err := pm.authorizePAT(ctx,
		session,
		smqauth.PlatformDomainsScope,
		smqauth.DomainClientsScope,
		session.DomainID,
		smqauth.UpdateOp,
		[]string{entityID},
	); err != nil {
		return roles.Role{}, errors.Wrap(svcerr.ErrUnauthorizedPAT, err)
	}

	return pm.svc.UpdateRoleName(ctx, session, entityID, roleID, newRoleName)
}
