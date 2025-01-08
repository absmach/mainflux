package consumer

import (
	"context"
	"fmt"

	"github.com/absmach/supermq/pkg/errors"
	repoerr "github.com/absmach/supermq/pkg/errors/repository"
	"github.com/absmach/supermq/pkg/roles"
)

const (
	errAddEntityRoleEvent              = "failed to consume %s add role event : %w"
	errUpdateEntityRoleEvent           = "failed to consume %s update role event : %w"
	errRemoveEntityRoleEvent           = "failed to consume %s remove role event : %w"
	errAddEntityRoleActionsEvent       = "failed to consume %s add role actions event : %w"
	errRemoveEntityRoleActionsEvent    = "failed to consume %s remove role actions event : %w"
	errRemoveEntityRoleAllActionsEvent = "failed to consume %s remove role all actions event : %w"
	errAddEntityRoleMembersEvent       = "failed to consume %s add role members event : %w"
	errRemoveEntityRoleMembersEvent    = "failed to consume %s remove role members event : %w"
	errRemoveEntityRoleAllMembersEvent = "failed to consume %s remove role all members event : %w"
)

type EventHandler struct {
	entityType string
	repo       roles.Repository
}

func NewEventHandler(entityType string, repo roles.Repository) EventHandler {
	return EventHandler{
		entityType: entityType,
		repo:       repo,
	}
}
func (es *EventHandler) AddEntityRoleHandler(ctx context.Context, data map[string]interface{}) error {
	rps, err := ToRoleProvision(data)
	if err != nil {
		return fmt.Errorf(errAddEntityRoleEvent, es.entityType, err)
	}
	if _, err := es.repo.AddRoles(ctx, []roles.RoleProvision{rps}); err != nil {
		if !errors.Contains(err, repoerr.ErrConflict) {
			return fmt.Errorf(errAddEntityRoleEvent, es.entityType, err)
		}
	}

	return nil
}

func (es *EventHandler) UpdateEntityRoleHandler(ctx context.Context, data map[string]interface{}) error {

	ro, err := ToRole(data)
	if err != nil {
		return fmt.Errorf(errUpdateEntityRoleEvent, es.entityType, err)
	}

	if _, err = es.repo.UpdateRole(ctx, ro); err != nil {
		return fmt.Errorf(errUpdateEntityRoleEvent, es.entityType, err)
	}

	return nil
}

func (es *EventHandler) RemoveEntityRoleHandler(ctx context.Context, data map[string]interface{}) error {

	id, ok := data["role_id"].(string)
	if !ok {
		return fmt.Errorf(errRemoveEntityRoleEvent, es.entityType, errRoleID)
	}

	if err := es.repo.RemoveRoles(ctx, []string{id}); err != nil {
		return fmt.Errorf(errRemoveEntityRoleEvent, es.entityType, err)
	}

	return nil
}

func (es *EventHandler) AddEntityRoleActionsHandler(ctx context.Context, data map[string]interface{}) error {
	id, ok := data["role_id"].(string)
	if !ok {
		return fmt.Errorf(errAddEntityRoleActionsEvent, es.entityType, errRoleID)
	}
	iacts, ok := data["actions"].([]interface{})
	if !ok {
		return fmt.Errorf(errAddEntityRoleActionsEvent, es.entityType, errActions)
	}
	acts, err := ToStrings(iacts)
	if err != nil {
		return fmt.Errorf(errAddEntityRoleActionsEvent, es.entityType, err)
	}

	if _, err := es.repo.RoleAddActions(ctx, roles.Role{ID: id}, acts); err != nil {
		return fmt.Errorf(errAddEntityRoleActionsEvent, es.entityType, err)
	}

	return nil
}

func (es *EventHandler) RemoveEntityRoleActionsHandler(ctx context.Context, data map[string]interface{}) error {
	id, ok := data["role_id"].(string)
	if !ok {
		return fmt.Errorf(errAddEntityRoleActionsEvent, es.entityType, errRoleID)
	}
	iacts, ok := data["actions"].([]interface{})
	if !ok {
		return fmt.Errorf(errAddEntityRoleActionsEvent, es.entityType, errActions)
	}
	acts, err := ToStrings(iacts)
	if err != nil {
		return fmt.Errorf(errAddEntityRoleActionsEvent, es.entityType, err)
	}

	if err := es.repo.RoleRemoveActions(ctx, roles.Role{ID: id}, acts); err != nil {
		return fmt.Errorf(errAddEntityRoleActionsEvent, es.entityType, err)
	}
	return nil
}

func (es *EventHandler) RemoveAllEntityRoleActionsHandler(ctx context.Context, data map[string]interface{}) error {
	id, ok := data["role_id"].(string)
	if !ok {
		return fmt.Errorf(errRemoveEntityRoleAllActionsEvent, es.entityType, errRoleID)
	}

	if err := es.repo.RoleRemoveAllActions(ctx, roles.Role{ID: id}); err != nil {
		return fmt.Errorf(errRemoveEntityRoleAllActionsEvent, es.entityType, err)
	}
	return nil
}

func (es *EventHandler) AddEntityRoleMembersHandler(ctx context.Context, data map[string]interface{}) error {
	id, ok := data["role_id"].(string)
	if !ok {
		return fmt.Errorf(errAddEntityRoleMembersEvent, es.entityType, errRoleID)
	}
	imems, ok := data["members"].([]interface{})
	if !ok {
		return fmt.Errorf(errAddEntityRoleMembersEvent, es.entityType, errMembers)
	}
	mems, err := ToStrings(imems)
	if err != nil {
		return fmt.Errorf(errAddEntityRoleMembersEvent, es.entityType, err)
	}

	if _, err := es.repo.RoleAddMembers(ctx, roles.Role{ID: id}, mems); err != nil {
		return fmt.Errorf(errAddEntityRoleMembersEvent, es.entityType, err)
	}

	return nil
}

func (es *EventHandler) RemoveEntityRoleMembersHandler(ctx context.Context, data map[string]interface{}) error {
	id, ok := data["role_id"].(string)
	if !ok {
		return fmt.Errorf(errRemoveEntityRoleMembersEvent, es.entityType, errRoleID)
	}
	imems, ok := data["members"].([]interface{})
	if !ok {
		return fmt.Errorf(errRemoveEntityRoleMembersEvent, es.entityType, errMembers)
	}
	mems, err := ToStrings(imems)
	if err != nil {
		return fmt.Errorf(errRemoveEntityRoleMembersEvent, es.entityType, err)
	}

	if err := es.repo.RoleRemoveMembers(ctx, roles.Role{ID: id}, mems); err != nil {
		return fmt.Errorf(errRemoveEntityRoleMembersEvent, es.entityType, err)
	}

	return nil
}

func (es *EventHandler) RemoveAllEntityRoleMembersHandler(ctx context.Context, data map[string]interface{}) error {
	id, ok := data["role_id"].(string)
	if !ok {
		return fmt.Errorf(errRemoveEntityRoleAllMembersEvent, es.entityType, errRoleID)
	}

	if err := es.repo.RoleRemoveAllMembers(ctx, roles.Role{ID: id}); err != nil {
		return fmt.Errorf(errRemoveEntityRoleAllMembersEvent, es.entityType, err)
	}
	return nil
}

func (es *EventHandler) RemoveMemberFromAllEntityHandler(ctx context.Context, data map[string]interface{}) error {
	return nil
}