package groups

import (
	"context"
	"time"

	"github.com/mainflux/mainflux"
	"github.com/mainflux/mainflux/internal/apiutil"
	mfclients "github.com/mainflux/mainflux/internal/mainflux"
	"github.com/mainflux/mainflux/internal/mainflux/groups"
	mfgroups "github.com/mainflux/mainflux/internal/mainflux/groups"
	"github.com/mainflux/mainflux/pkg/errors"
	"github.com/mainflux/mainflux/users/jwt"
	"github.com/mainflux/mainflux/users/policies"
)

// Possible token types are access and refresh tokens.
const (
	RefreshToken      = "refresh"
	AccessToken       = "access"
	MyKey             = "mine"
	groupsObjectKey   = "groups"
	updateRelationKey = "g_update"
	listRelationKey   = "g_list"
	deleteRelationKey = "g_delete"
	entityType        = "group"
)

// Service unites Clients and Group services.
type Service interface {
	GroupService
}

type service struct {
	groups     GroupRepository
	policies   policies.PolicyRepository
	tokens     jwt.TokenRepository
	idProvider mainflux.IDProvider
}

// NewService returns a new Clients service implementation.
func NewService(g GroupRepository, p policies.PolicyRepository, t jwt.TokenRepository, idp mainflux.IDProvider) Service {
	return service{
		groups:     g,
		policies:   p,
		tokens:     t,
		idProvider: idp,
	}
}

func (svc service) CreateGroup(ctx context.Context, token string, g mfgroups.Group) (mfgroups.Group, error) {
	ownerID, err := svc.identify(ctx, token)
	if err != nil {
		return mfgroups.Group{}, err
	}
	groupID, err := svc.idProvider.ID()
	if err != nil {
		return mfgroups.Group{}, err
	}
	if g.Status != mfclients.EnabledStatus && g.Status != mfclients.DisabledStatus {
		return mfgroups.Group{}, apiutil.ErrInvalidStatus
	}
	if g.Owner == "" {
		g.Owner = ownerID
	}

	g.ID = groupID
	g.CreatedAt = time.Now()

	return svc.groups.Save(ctx, g)
}

func (svc service) ViewGroup(ctx context.Context, token string, id string) (groups.Group, error) {
	if err := svc.authorizeByToken(ctx, entityType, policies.Policy{Subject: token, Object: id, Actions: []string{listRelationKey}}); err != nil {
		return groups.Group{}, err
	}

	return svc.groups.RetrieveByID(ctx, id)
}

func (svc service) ListGroups(ctx context.Context, token string, gm GroupsPage) (GroupsPage, error) {
	id, err := svc.identify(ctx, token)
	if err != nil {
		return GroupsPage{}, err
	}
	gm.Subject = id
	gm.OwnerID = id
	gm.Action = listRelationKey
	return svc.groups.RetrieveAll(ctx, gm)
}

func (svc service) ListMemberships(ctx context.Context, token, clientID string, gm GroupsPage) (MembershipsPage, error) {
	id, err := svc.identify(ctx, token)
	if err != nil {
		return MembershipsPage{}, err
	}
	// If the user is admin, fetch all members from the database.
	if err := svc.authorizeByID(ctx, entityType, policies.Policy{Subject: id, Object: groupsObjectKey, Actions: []string{listRelationKey}}); err == nil {
		return svc.groups.Memberships(ctx, clientID, gm)
	}

	gm.Subject = id
	gm.Action = listRelationKey
	return svc.groups.Memberships(ctx, clientID, gm)
}

func (svc service) UpdateGroup(ctx context.Context, token string, g groups.Group) (groups.Group, error) {
	id, err := svc.identify(ctx, token)
	if err != nil {
		return groups.Group{}, err
	}
	if err := svc.authorizeByID(ctx, entityType, policies.Policy{Subject: id, Object: g.ID, Actions: []string{updateRelationKey}}); err != nil {
		return groups.Group{}, err
	}
	g.UpdatedAt = time.Now()
	g.UpdatedBy = id

	return svc.groups.Update(ctx, g)
}

func (svc service) EnableGroup(ctx context.Context, token, id string) (groups.Group, error) {
	group := groups.Group{
		ID:        id,
		Status:    mfclients.EnabledStatus,
		UpdatedAt: time.Now(),
	}
	group, err := svc.changeGroupStatus(ctx, token, group)
	if err != nil {
		return mfgroups.Group{}, err
	}
	return group, nil
}

func (svc service) DisableGroup(ctx context.Context, token, id string) (groups.Group, error) {
	group := groups.Group{
		ID:        id,
		Status:    mfclients.DisabledStatus,
		UpdatedAt: time.Now(),
	}
	group, err := svc.changeGroupStatus(ctx, token, group)
	if err != nil {
		return mfgroups.Group{}, err
	}
	return group, nil
}

func (svc service) authorizeByID(ctx context.Context, entityType string, p policies.Policy) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if err := svc.policies.CheckAdmin(ctx, p.Subject); err == nil {
		return nil
	}
	return svc.policies.Evaluate(ctx, entityType, p)
}

func (svc service) authorizeByToken(ctx context.Context, entityType string, p policies.Policy) error {
	if err := p.Validate(); err != nil {
		return err
	}
	id, err := svc.identify(ctx, p.Subject)
	if err != nil {
		return err
	}
	if err = svc.policies.CheckAdmin(ctx, id); err == nil {
		return nil
	}
	p.Subject = id
	return svc.policies.Evaluate(ctx, entityType, p)
}

func (svc service) changeGroupStatus(ctx context.Context, token string, group groups.Group) (groups.Group, error) {
	id, err := svc.identify(ctx, token)
	if err != nil {
		return mfgroups.Group{}, err
	}
	if err := svc.authorizeByID(ctx, entityType, policies.Policy{Subject: id, Object: group.ID, Actions: []string{deleteRelationKey}}); err != nil {
		return groups.Group{}, err
	}
	dbGroup, err := svc.groups.RetrieveByID(ctx, group.ID)
	if err != nil {
		return groups.Group{}, err
	}
	if dbGroup.Status == group.Status {
		return groups.Group{}, mfclients.ErrStatusAlreadyAssigned
	}

	group.UpdatedBy = id
	return svc.groups.ChangeStatus(ctx, group)
}

func (svc service) identify(ctx context.Context, tkn string) (string, error) {
	claims, err := svc.tokens.Parse(ctx, tkn)
	if err != nil {
		return "", errors.Wrap(errors.ErrAuthentication, err)
	}
	if claims.Type != AccessToken {
		return "", errors.ErrAuthentication
	}

	return claims.ClientID, nil
}
