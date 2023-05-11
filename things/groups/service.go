package groups

import (
	"context"
	"time"

	"github.com/mainflux/mainflux"
	"github.com/mainflux/mainflux/internal/apiutil"
	mfclients "github.com/mainflux/mainflux/pkg/clients"
	"github.com/mainflux/mainflux/pkg/errors"
	"github.com/mainflux/mainflux/pkg/groups"
	upolicies "github.com/mainflux/mainflux/users/policies"
)

// Possible token types are access and refresh tokens.
const (
	thingsObjectKey   = "things"
	updateRelationKey = "g_update"
	listRelationKey   = "g_list"
	deleteRelationKey = "g_delete"
	entityType        = "group"
)

type service struct {
	auth       upolicies.AuthServiceClient
	groups     groups.Repository
	idProvider mainflux.IDProvider
}

// NewService returns a new Clients service implementation.
func NewService(auth upolicies.AuthServiceClient, g groups.Repository, idp mainflux.IDProvider) Service {
	return service{
		auth:       auth,
		groups:     g,
		idProvider: idp,
	}
}

func (svc service) CreateGroups(ctx context.Context, token string, gs ...groups.Group) ([]groups.Group, error) {
	res, err := svc.auth.Identify(ctx, &upolicies.Token{Value: token})
	if err != nil {
		return []groups.Group{}, errors.Wrap(errors.ErrAuthentication, err)
	}

	var grps []groups.Group
	for _, g := range gs {
		if g.ID == "" {
			groupID, err := svc.idProvider.ID()
			if err != nil {
				return []groups.Group{}, err
			}
			g.ID = groupID
		}
		if g.Owner == "" {
			g.Owner = res.GetId()
		}

		if g.Status != mfclients.EnabledStatus && g.Status != mfclients.DisabledStatus {
			return []groups.Group{}, apiutil.ErrInvalidStatus
		}

		g.CreatedAt = time.Now()
		g.UpdatedAt = g.CreatedAt
		g.UpdatedBy = g.Owner
		grp, err := svc.groups.Save(ctx, g)
		if err != nil {
			return []groups.Group{}, err
		}
		grps = append(grps, grp)
	}
	return grps, nil
}

func (svc service) ViewGroup(ctx context.Context, token string, id string) (groups.Group, error) {
	if err := svc.authorize(ctx, token, id, listRelationKey); err != nil {
		return groups.Group{}, errors.Wrap(errors.ErrNotFound, err)
	}
	return svc.groups.RetrieveByID(ctx, id)
}

func (svc service) ListGroups(ctx context.Context, token string, gm groups.GroupsPage) (groups.GroupsPage, error) {
	res, err := svc.auth.Identify(ctx, &upolicies.Token{Value: token})
	if err != nil {
		return groups.GroupsPage{}, errors.Wrap(errors.ErrAuthentication, err)
	}

	// If the user is admin, fetch all channels from the database.
	if err := svc.authorize(ctx, token, thingsObjectKey, listRelationKey); err == nil {
		page, err := svc.groups.RetrieveAll(ctx, gm)
		if err != nil {
			return groups.GroupsPage{}, err
		}
		return page, err
	}

	gm.Subject = res.GetId()
	gm.OwnerID = res.GetId()
	gm.Action = "g_list"
	return svc.groups.RetrieveAll(ctx, gm)
}

func (svc service) ListMemberships(ctx context.Context, token, clientID string, gm groups.GroupsPage) (groups.MembershipsPage, error) {
	res, err := svc.auth.Identify(ctx, &upolicies.Token{Value: token})
	if err != nil {
		return groups.MembershipsPage{}, errors.Wrap(errors.ErrAuthentication, err)
	}

	// If the user is admin, fetch all channels from the database.
	if err := svc.authorize(ctx, token, thingsObjectKey, listRelationKey); err == nil {
		return svc.groups.Memberships(ctx, clientID, gm)
	}

	gm.OwnerID = res.GetId()
	return svc.groups.Memberships(ctx, clientID, gm)
}

func (svc service) UpdateGroup(ctx context.Context, token string, g groups.Group) (groups.Group, error) {
	res, err := svc.auth.Identify(ctx, &upolicies.Token{Value: token})
	if err != nil {
		return groups.Group{}, errors.Wrap(errors.ErrAuthentication, err)
	}

	if err := svc.authorize(ctx, token, g.ID, updateRelationKey); err != nil {
		return groups.Group{}, errors.Wrap(errors.ErrNotFound, err)
	}

	g.Owner = res.GetId()
	g.UpdatedAt = time.Now()
	g.UpdatedBy = res.GetId()

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
		return groups.Group{}, errors.Wrap(groups.ErrEnableGroup, err)
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
		return groups.Group{}, errors.Wrap(groups.ErrDisableGroup, err)
	}
	return group, nil
}

func (svc service) changeGroupStatus(ctx context.Context, token string, group groups.Group) (groups.Group, error) {
	res, err := svc.auth.Identify(ctx, &upolicies.Token{Value: token})
	if err != nil {
		return groups.Group{}, errors.Wrap(errors.ErrAuthentication, err)
	}
	if err := svc.authorize(ctx, token, group.ID, deleteRelationKey); err != nil {
		return groups.Group{}, errors.Wrap(errors.ErrNotFound, err)
	}
	dbGroup, err := svc.groups.RetrieveByID(ctx, group.ID)
	if err != nil {
		return groups.Group{}, err
	}

	if dbGroup.Status == group.Status {
		return groups.Group{}, mfclients.ErrStatusAlreadyAssigned
	}
	group.UpdatedBy = res.GetId()
	return svc.groups.ChangeStatus(ctx, group)
}

func (svc service) identifyUser(ctx context.Context, token string) (string, error) {
	req := &upolicies.Token{Value: token}
	res, err := svc.auth.Identify(ctx, req)
	if err != nil {
		return "", errors.Wrap(errors.ErrAuthorization, err)
	}
	return res.GetId(), nil
}

func (svc service) authorize(ctx context.Context, subject, object string, relation string) error {
	// Check if the client is the owner of the group.
	userID, err := svc.identifyUser(ctx, subject)
	if err != nil {
		return err
	}
	dbGroup, err := svc.groups.RetrieveByID(ctx, object)
	if err != nil {
		return err
	}
	if dbGroup.Owner == userID {
		return nil
	}
	req := &upolicies.AuthorizeReq{
		Sub:        subject,
		Obj:        object,
		Act:        relation,
		EntityType: entityType,
	}
	res, err := svc.auth.Authorize(ctx, req)
	if err != nil {
		return errors.Wrap(errors.ErrAuthorization, err)
	}
	if !res.GetAuthorized() {
		return errors.ErrAuthorization
	}
	return nil
}
