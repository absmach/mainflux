// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"context"

	grpcTokenV1 "github.com/absmach/supermq/api/grpc/token/v1"
	smqauth "github.com/absmach/supermq/auth"
	"github.com/absmach/supermq/pkg/authn"
	"github.com/absmach/supermq/pkg/errors"
	svcerr "github.com/absmach/supermq/pkg/errors/service"
	smqpat "github.com/absmach/supermq/pkg/pat"
	"github.com/absmach/supermq/pkg/policies"
	"github.com/absmach/supermq/users"
)

const emptyDomain = ""

var _ users.Service = (*patMiddleware)(nil)

type patMiddleware struct {
	svc users.Service
	pat smqpat.Authorization
}

// PATMiddleware adds PAT validation to the users service.
func PATMiddleware(svc users.Service, pat smqpat.Authorization) users.Service {
	return &patMiddleware{
		svc: svc,
		pat: pat,
	}
}

// authorizePAT validates Personal Access Token if present in the session
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

func (pm *patMiddleware) Register(ctx context.Context, session authn.Session, user users.User, selfRegister bool) (users.User, error) {
	return pm.svc.Register(ctx, session, user, selfRegister)
}

func (pm *patMiddleware) View(ctx context.Context, session authn.Session, id string) (users.User, error) {
	if err := pm.authorizePAT(ctx, session, smqauth.PlatformUsersScope, smqauth.DomainNullScope, emptyDomain, smqauth.ReadOp, []string{id}); err != nil {
		return users.User{}, err
	}
	return pm.svc.View(ctx, session, id)
}

func (pm *patMiddleware) ViewProfile(ctx context.Context, session authn.Session) (users.User, error) {
	if err := pm.authorizePAT(ctx, session, smqauth.PlatformUsersScope, smqauth.DomainNullScope, emptyDomain, smqauth.ReadOp, []string{session.UserID}); err != nil {
		return users.User{}, err
	}
	return pm.svc.ViewProfile(ctx, session)
}

func (pm *patMiddleware) ListUsers(ctx context.Context, session authn.Session, page users.Page) (users.UsersPage, error) {
	if err := pm.authorizePAT(ctx, session, smqauth.PlatformUsersScope, smqauth.DomainNullScope, emptyDomain, smqauth.ListOp, smqauth.AnyIDs{}.Values()); err != nil {
		return users.UsersPage{}, err
	}
	return pm.svc.ListUsers(ctx, session, page)
}

func (pm *patMiddleware) ListMembers(ctx context.Context, session authn.Session, objectKind, objectID string, page users.Page) (users.MembersPage, error) {
	switch objectKind {
	case policies.GroupsKind:
		if err := pm.authorizePAT(ctx, session, smqauth.PlatformUsersScope, smqauth.DomainGroupsScope, session.DomainID, smqauth.ListOp, smqauth.AnyIDs{}.Values()); err != nil {
			return users.MembersPage{}, err
		}
	case policies.DomainsKind:
		if err := pm.authorizePAT(ctx, session, smqauth.PlatformUsersScope, smqauth.DomainManagementScope, session.DomainID, smqauth.ListOp, smqauth.AnyIDs{}.Values()); err != nil {
			return users.MembersPage{}, err
		}
	case policies.ClientsKind:
		if err := pm.authorizePAT(ctx, session, smqauth.PlatformUsersScope, smqauth.DomainClientsScope, session.DomainID, smqauth.ListOp, smqauth.AnyIDs{}.Values()); err != nil {
			return users.MembersPage{}, err
		}
	default:
		return users.MembersPage{}, svcerr.ErrAuthorization
	}

	return pm.svc.ListMembers(ctx, session, objectKind, objectID, page)
}

func (pm *patMiddleware) SearchUsers(ctx context.Context, page users.Page) (users.UsersPage, error) {
	return pm.svc.SearchUsers(ctx, page)
}

func (pm *patMiddleware) Update(ctx context.Context, session authn.Session, user users.User) (users.User, error) {
	if err := pm.authorizePAT(ctx, session, smqauth.PlatformUsersScope, smqauth.DomainNullScope, emptyDomain, smqauth.UpdateOp, []string{user.ID}); err != nil {
		return users.User{}, err
	}
	return pm.svc.Update(ctx, session, user)
}

func (pm *patMiddleware) UpdateTags(ctx context.Context, session authn.Session, user users.User) (users.User, error) {
	if err := pm.authorizePAT(ctx, session, smqauth.PlatformUsersScope, smqauth.DomainNullScope, emptyDomain, smqauth.UpdateOp, []string{user.ID}); err != nil {
		return users.User{}, err
	}
	return pm.svc.UpdateTags(ctx, session, user)
}

func (pm *patMiddleware) UpdateEmail(ctx context.Context, session authn.Session, id, email string) (users.User, error) {
	if err := pm.authorizePAT(ctx, session, smqauth.PlatformUsersScope, smqauth.DomainNullScope, emptyDomain, smqauth.UpdateOp, []string{id}); err != nil {
		return users.User{}, err
	}
	return pm.svc.UpdateEmail(ctx, session, id, email)
}

func (pm *patMiddleware) UpdateUsername(ctx context.Context, session authn.Session, id, username string) (users.User, error) {
	if err := pm.authorizePAT(ctx, session, smqauth.PlatformUsersScope, smqauth.DomainNullScope, emptyDomain, smqauth.UpdateOp, []string{id}); err != nil {
		return users.User{}, err
	}
	return pm.svc.UpdateUsername(ctx, session, id, username)
}

func (pm *patMiddleware) UpdateProfilePicture(ctx context.Context, session authn.Session, user users.User) (users.User, error) {
	if err := pm.authorizePAT(ctx, session, smqauth.PlatformUsersScope, smqauth.DomainNullScope, emptyDomain, smqauth.UpdateOp, []string{user.ID}); err != nil {
		return users.User{}, err
	}
	return pm.svc.UpdateProfilePicture(ctx, session, user)
}

func (pm *patMiddleware) GenerateResetToken(ctx context.Context, email, host string) error {
	return pm.svc.GenerateResetToken(ctx, email, host)
}

func (pm *patMiddleware) UpdateSecret(ctx context.Context, session authn.Session, oldSecret, newSecret string) (users.User, error) {
	if err := pm.authorizePAT(ctx, session, smqauth.PlatformUsersScope, smqauth.DomainNullScope, emptyDomain, smqauth.UpdateOp, []string{session.UserID}); err != nil {
		return users.User{}, err
	}
	return pm.svc.UpdateSecret(ctx, session, oldSecret, newSecret)
}

func (pm *patMiddleware) ResetSecret(ctx context.Context, session authn.Session, secret string) error {
	return pm.svc.ResetSecret(ctx, session, secret)
}

func (pm *patMiddleware) SendPasswordReset(ctx context.Context, host, email, user, token string) error {
	return pm.svc.SendPasswordReset(ctx, host, email, user, token)
}

func (pm *patMiddleware) UpdateRole(ctx context.Context, session authn.Session, user users.User) (users.User, error) {
	if err := pm.authorizePAT(ctx, session, smqauth.PlatformUsersScope, smqauth.DomainNullScope, emptyDomain, smqauth.UpdateOp, []string{user.ID}); err != nil {
		return users.User{}, err
	}
	return pm.svc.UpdateRole(ctx, session, user)
}

func (pm *patMiddleware) Enable(ctx context.Context, session authn.Session, id string) (users.User, error) {
	if err := pm.authorizePAT(ctx, session, smqauth.PlatformUsersScope, smqauth.DomainNullScope, emptyDomain, smqauth.UpdateOp, []string{id}); err != nil {
		return users.User{}, err
	}
	return pm.svc.Enable(ctx, session, id)
}

func (pm *patMiddleware) Disable(ctx context.Context, session authn.Session, id string) (users.User, error) {
	if err := pm.authorizePAT(ctx, session, smqauth.PlatformUsersScope, smqauth.DomainNullScope, emptyDomain, smqauth.UpdateOp, []string{id}); err != nil {
		return users.User{}, err
	}
	return pm.svc.Disable(ctx, session, id)
}

func (pm *patMiddleware) Delete(ctx context.Context, session authn.Session, id string) error {
	if err := pm.authorizePAT(ctx, session, smqauth.PlatformUsersScope, smqauth.DomainNullScope, emptyDomain, smqauth.DeleteOp, []string{id}); err != nil {
		return err
	}
	return pm.svc.Delete(ctx, session, id)
}

func (pm *patMiddleware) Identify(ctx context.Context, session authn.Session) (string, error) {
	return pm.svc.Identify(ctx, session)
}

func (pm *patMiddleware) IssueToken(ctx context.Context, username, secret string) (*grpcTokenV1.Token, error) {
	return pm.svc.IssueToken(ctx, username, secret)
}

func (pm *patMiddleware) RefreshToken(ctx context.Context, session authn.Session, refreshToken string) (*grpcTokenV1.Token, error) {
	return pm.svc.RefreshToken(ctx, session, refreshToken)
}

func (pm *patMiddleware) OAuthCallback(ctx context.Context, user users.User) (users.User, error) {
	return pm.svc.OAuthCallback(ctx, user)
}

func (pm *patMiddleware) OAuthAddUserPolicy(ctx context.Context, user users.User) error {
	return pm.svc.OAuthAddUserPolicy(ctx, user)
}
