// Code generated by mockery v2.43.2. DO NOT EDIT.

// Copyright (c) Abstract Machines

package mocks

import (
	context "context"

	groups "github.com/absmach/magistrala/pkg/groups"
	mock "github.com/stretchr/testify/mock"

	roles "github.com/absmach/magistrala/pkg/roles"
)

// Service is an autogenerated mock type for the Service type
type Service struct {
	mock.Mock
}

// AddChildrenGroups provides a mock function with given fields: ctx, token, id, childrenGroupIDs
func (_m *Service) AddChildrenGroups(ctx context.Context, token string, id string, childrenGroupIDs []string) error {
	ret := _m.Called(ctx, token, id, childrenGroupIDs)

	if len(ret) == 0 {
		panic("no return value specified for AddChildrenGroups")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, []string) error); ok {
		r0 = rf(ctx, token, id, childrenGroupIDs)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// AddParentGroup provides a mock function with given fields: ctx, token, id, parentID
func (_m *Service) AddParentGroup(ctx context.Context, token string, id string, parentID string) error {
	ret := _m.Called(ctx, token, id, parentID)

	if len(ret) == 0 {
		panic("no return value specified for AddParentGroup")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string) error); ok {
		r0 = rf(ctx, token, id, parentID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// AddRole provides a mock function with given fields: ctx, token, entityID, roleName, optionalActions, optionalMembers
func (_m *Service) AddRole(ctx context.Context, token string, entityID string, roleName string, optionalActions []string, optionalMembers []string) (roles.Role, error) {
	ret := _m.Called(ctx, token, entityID, roleName, optionalActions, optionalMembers)

	if len(ret) == 0 {
		panic("no return value specified for AddRole")
	}

	var r0 roles.Role
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string, []string, []string) (roles.Role, error)); ok {
		return rf(ctx, token, entityID, roleName, optionalActions, optionalMembers)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string, []string, []string) roles.Role); ok {
		r0 = rf(ctx, token, entityID, roleName, optionalActions, optionalMembers)
	} else {
		r0 = ret.Get(0).(roles.Role)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string, string, []string, []string) error); ok {
		r1 = rf(ctx, token, entityID, roleName, optionalActions, optionalMembers)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// CreateGroup provides a mock function with given fields: ctx, token, kind, g
func (_m *Service) CreateGroup(ctx context.Context, token string, kind string, g groups.Group) (groups.Group, error) {
	ret := _m.Called(ctx, token, kind, g)

	if len(ret) == 0 {
		panic("no return value specified for CreateGroup")
	}

	var r0 groups.Group
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, groups.Group) (groups.Group, error)); ok {
		return rf(ctx, token, kind, g)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string, groups.Group) groups.Group); ok {
		r0 = rf(ctx, token, kind, g)
	} else {
		r0 = ret.Get(0).(groups.Group)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string, groups.Group) error); ok {
		r1 = rf(ctx, token, kind, g)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// DeleteGroup provides a mock function with given fields: ctx, token, id
func (_m *Service) DeleteGroup(ctx context.Context, token string, id string) error {
	ret := _m.Called(ctx, token, id)

	if len(ret) == 0 {
		panic("no return value specified for DeleteGroup")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string) error); ok {
		r0 = rf(ctx, token, id)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DisableGroup provides a mock function with given fields: ctx, token, id
func (_m *Service) DisableGroup(ctx context.Context, token string, id string) (groups.Group, error) {
	ret := _m.Called(ctx, token, id)

	if len(ret) == 0 {
		panic("no return value specified for DisableGroup")
	}

	var r0 groups.Group
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string) (groups.Group, error)); ok {
		return rf(ctx, token, id)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string) groups.Group); ok {
		r0 = rf(ctx, token, id)
	} else {
		r0 = ret.Get(0).(groups.Group)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string) error); ok {
		r1 = rf(ctx, token, id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// EnableGroup provides a mock function with given fields: ctx, token, id
func (_m *Service) EnableGroup(ctx context.Context, token string, id string) (groups.Group, error) {
	ret := _m.Called(ctx, token, id)

	if len(ret) == 0 {
		panic("no return value specified for EnableGroup")
	}

	var r0 groups.Group
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string) (groups.Group, error)); ok {
		return rf(ctx, token, id)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string) groups.Group); ok {
		r0 = rf(ctx, token, id)
	} else {
		r0 = ret.Get(0).(groups.Group)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string) error); ok {
		r1 = rf(ctx, token, id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ListAvailableActions provides a mock function with given fields: ctx, token
func (_m *Service) ListAvailableActions(ctx context.Context, token string) ([]string, error) {
	ret := _m.Called(ctx, token)

	if len(ret) == 0 {
		panic("no return value specified for ListAvailableActions")
	}

	var r0 []string
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) ([]string, error)); ok {
		return rf(ctx, token)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) []string); ok {
		r0 = rf(ctx, token)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]string)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, token)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ListChildrenGroups provides a mock function with given fields: ctx, token, id, gm
func (_m *Service) ListChildrenGroups(ctx context.Context, token string, id string, gm groups.Page) (groups.Page, error) {
	ret := _m.Called(ctx, token, id, gm)

	if len(ret) == 0 {
		panic("no return value specified for ListChildrenGroups")
	}

	var r0 groups.Page
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, groups.Page) (groups.Page, error)); ok {
		return rf(ctx, token, id, gm)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string, groups.Page) groups.Page); ok {
		r0 = rf(ctx, token, id, gm)
	} else {
		r0 = ret.Get(0).(groups.Page)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string, groups.Page) error); ok {
		r1 = rf(ctx, token, id, gm)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ListGroups provides a mock function with given fields: ctx, token, gm
func (_m *Service) ListGroups(ctx context.Context, token string, gm groups.Page) (groups.Page, error) {
	ret := _m.Called(ctx, token, gm)

	if len(ret) == 0 {
		panic("no return value specified for ListGroups")
	}

	var r0 groups.Page
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, groups.Page) (groups.Page, error)); ok {
		return rf(ctx, token, gm)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, groups.Page) groups.Page); ok {
		r0 = rf(ctx, token, gm)
	} else {
		r0 = ret.Get(0).(groups.Page)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, groups.Page) error); ok {
		r1 = rf(ctx, token, gm)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ListParentGroups provides a mock function with given fields: ctx, token, id, gm
func (_m *Service) ListParentGroups(ctx context.Context, token string, id string, gm groups.Page) (groups.Page, error) {
	ret := _m.Called(ctx, token, id, gm)

	if len(ret) == 0 {
		panic("no return value specified for ListParentGroups")
	}

	var r0 groups.Page
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, groups.Page) (groups.Page, error)); ok {
		return rf(ctx, token, id, gm)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string, groups.Page) groups.Page); ok {
		r0 = rf(ctx, token, id, gm)
	} else {
		r0 = ret.Get(0).(groups.Page)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string, groups.Page) error); ok {
		r1 = rf(ctx, token, id, gm)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RemoveAllChildrenGroups provides a mock function with given fields: ctx, token, id
func (_m *Service) RemoveAllChildrenGroups(ctx context.Context, token string, id string) error {
	ret := _m.Called(ctx, token, id)

	if len(ret) == 0 {
		panic("no return value specified for RemoveAllChildrenGroups")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string) error); ok {
		r0 = rf(ctx, token, id)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// RemoveChildrenGroups provides a mock function with given fields: ctx, token, id, childrenGroupIDs
func (_m *Service) RemoveChildrenGroups(ctx context.Context, token string, id string, childrenGroupIDs []string) error {
	ret := _m.Called(ctx, token, id, childrenGroupIDs)

	if len(ret) == 0 {
		panic("no return value specified for RemoveChildrenGroups")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, []string) error); ok {
		r0 = rf(ctx, token, id, childrenGroupIDs)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// RemoveParentGroup provides a mock function with given fields: ctx, token, id
func (_m *Service) RemoveParentGroup(ctx context.Context, token string, id string) error {
	ret := _m.Called(ctx, token, id)

	if len(ret) == 0 {
		panic("no return value specified for RemoveParentGroup")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string) error); ok {
		r0 = rf(ctx, token, id)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// RemoveRole provides a mock function with given fields: ctx, token, entityID, roleName
func (_m *Service) RemoveRole(ctx context.Context, token string, entityID string, roleName string) error {
	ret := _m.Called(ctx, token, entityID, roleName)

	if len(ret) == 0 {
		panic("no return value specified for RemoveRole")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string) error); ok {
		r0 = rf(ctx, token, entityID, roleName)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// RetrieveAllRoles provides a mock function with given fields: ctx, token, entityID, limit, offset
func (_m *Service) RetrieveAllRoles(ctx context.Context, token string, entityID string, limit uint64, offset uint64) (roles.RolePage, error) {
	ret := _m.Called(ctx, token, entityID, limit, offset)

	if len(ret) == 0 {
		panic("no return value specified for RetrieveAllRoles")
	}

	var r0 roles.RolePage
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, uint64, uint64) (roles.RolePage, error)); ok {
		return rf(ctx, token, entityID, limit, offset)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string, uint64, uint64) roles.RolePage); ok {
		r0 = rf(ctx, token, entityID, limit, offset)
	} else {
		r0 = ret.Get(0).(roles.RolePage)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string, uint64, uint64) error); ok {
		r1 = rf(ctx, token, entityID, limit, offset)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RetrieveRole provides a mock function with given fields: ctx, token, entityID, roleName
func (_m *Service) RetrieveRole(ctx context.Context, token string, entityID string, roleName string) (roles.Role, error) {
	ret := _m.Called(ctx, token, entityID, roleName)

	if len(ret) == 0 {
		panic("no return value specified for RetrieveRole")
	}

	var r0 roles.Role
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string) (roles.Role, error)); ok {
		return rf(ctx, token, entityID, roleName)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string) roles.Role); ok {
		r0 = rf(ctx, token, entityID, roleName)
	} else {
		r0 = ret.Get(0).(roles.Role)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string, string) error); ok {
		r1 = rf(ctx, token, entityID, roleName)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RoleAddActions provides a mock function with given fields: ctx, token, entityID, roleName, actions
func (_m *Service) RoleAddActions(ctx context.Context, token string, entityID string, roleName string, actions []string) ([]string, error) {
	ret := _m.Called(ctx, token, entityID, roleName, actions)

	if len(ret) == 0 {
		panic("no return value specified for RoleAddActions")
	}

	var r0 []string
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string, []string) ([]string, error)); ok {
		return rf(ctx, token, entityID, roleName, actions)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string, []string) []string); ok {
		r0 = rf(ctx, token, entityID, roleName, actions)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]string)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string, string, []string) error); ok {
		r1 = rf(ctx, token, entityID, roleName, actions)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RoleAddMembers provides a mock function with given fields: ctx, token, entityID, roleName, members
func (_m *Service) RoleAddMembers(ctx context.Context, token string, entityID string, roleName string, members []string) ([]string, error) {
	ret := _m.Called(ctx, token, entityID, roleName, members)

	if len(ret) == 0 {
		panic("no return value specified for RoleAddMembers")
	}

	var r0 []string
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string, []string) ([]string, error)); ok {
		return rf(ctx, token, entityID, roleName, members)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string, []string) []string); ok {
		r0 = rf(ctx, token, entityID, roleName, members)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]string)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string, string, []string) error); ok {
		r1 = rf(ctx, token, entityID, roleName, members)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RoleCheckActionsExists provides a mock function with given fields: ctx, token, entityID, roleName, actions
func (_m *Service) RoleCheckActionsExists(ctx context.Context, token string, entityID string, roleName string, actions []string) (bool, error) {
	ret := _m.Called(ctx, token, entityID, roleName, actions)

	if len(ret) == 0 {
		panic("no return value specified for RoleCheckActionsExists")
	}

	var r0 bool
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string, []string) (bool, error)); ok {
		return rf(ctx, token, entityID, roleName, actions)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string, []string) bool); ok {
		r0 = rf(ctx, token, entityID, roleName, actions)
	} else {
		r0 = ret.Get(0).(bool)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string, string, []string) error); ok {
		r1 = rf(ctx, token, entityID, roleName, actions)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RoleCheckMembersExists provides a mock function with given fields: ctx, token, entityID, roleName, members
func (_m *Service) RoleCheckMembersExists(ctx context.Context, token string, entityID string, roleName string, members []string) (bool, error) {
	ret := _m.Called(ctx, token, entityID, roleName, members)

	if len(ret) == 0 {
		panic("no return value specified for RoleCheckMembersExists")
	}

	var r0 bool
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string, []string) (bool, error)); ok {
		return rf(ctx, token, entityID, roleName, members)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string, []string) bool); ok {
		r0 = rf(ctx, token, entityID, roleName, members)
	} else {
		r0 = ret.Get(0).(bool)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string, string, []string) error); ok {
		r1 = rf(ctx, token, entityID, roleName, members)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RoleListActions provides a mock function with given fields: ctx, token, entityID, roleName
func (_m *Service) RoleListActions(ctx context.Context, token string, entityID string, roleName string) ([]string, error) {
	ret := _m.Called(ctx, token, entityID, roleName)

	if len(ret) == 0 {
		panic("no return value specified for RoleListActions")
	}

	var r0 []string
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string) ([]string, error)); ok {
		return rf(ctx, token, entityID, roleName)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string) []string); ok {
		r0 = rf(ctx, token, entityID, roleName)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]string)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string, string) error); ok {
		r1 = rf(ctx, token, entityID, roleName)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RoleListMembers provides a mock function with given fields: ctx, token, entityID, roleName, limit, offset
func (_m *Service) RoleListMembers(ctx context.Context, token string, entityID string, roleName string, limit uint64, offset uint64) (roles.MembersPage, error) {
	ret := _m.Called(ctx, token, entityID, roleName, limit, offset)

	if len(ret) == 0 {
		panic("no return value specified for RoleListMembers")
	}

	var r0 roles.MembersPage
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string, uint64, uint64) (roles.MembersPage, error)); ok {
		return rf(ctx, token, entityID, roleName, limit, offset)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string, uint64, uint64) roles.MembersPage); ok {
		r0 = rf(ctx, token, entityID, roleName, limit, offset)
	} else {
		r0 = ret.Get(0).(roles.MembersPage)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string, string, uint64, uint64) error); ok {
		r1 = rf(ctx, token, entityID, roleName, limit, offset)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RoleRemoveActions provides a mock function with given fields: ctx, token, entityID, roleName, actions
func (_m *Service) RoleRemoveActions(ctx context.Context, token string, entityID string, roleName string, actions []string) error {
	ret := _m.Called(ctx, token, entityID, roleName, actions)

	if len(ret) == 0 {
		panic("no return value specified for RoleRemoveActions")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string, []string) error); ok {
		r0 = rf(ctx, token, entityID, roleName, actions)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// RoleRemoveAllActions provides a mock function with given fields: ctx, token, entityID, roleName
func (_m *Service) RoleRemoveAllActions(ctx context.Context, token string, entityID string, roleName string) error {
	ret := _m.Called(ctx, token, entityID, roleName)

	if len(ret) == 0 {
		panic("no return value specified for RoleRemoveAllActions")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string) error); ok {
		r0 = rf(ctx, token, entityID, roleName)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// RoleRemoveAllMembers provides a mock function with given fields: ctx, token, entityID, roleName
func (_m *Service) RoleRemoveAllMembers(ctx context.Context, token string, entityID string, roleName string) error {
	ret := _m.Called(ctx, token, entityID, roleName)

	if len(ret) == 0 {
		panic("no return value specified for RoleRemoveAllMembers")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string) error); ok {
		r0 = rf(ctx, token, entityID, roleName)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// RoleRemoveMembers provides a mock function with given fields: ctx, token, entityID, roleName, members
func (_m *Service) RoleRemoveMembers(ctx context.Context, token string, entityID string, roleName string, members []string) error {
	ret := _m.Called(ctx, token, entityID, roleName, members)

	if len(ret) == 0 {
		panic("no return value specified for RoleRemoveMembers")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string, []string) error); ok {
		r0 = rf(ctx, token, entityID, roleName, members)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// UpdateGroup provides a mock function with given fields: ctx, token, g
func (_m *Service) UpdateGroup(ctx context.Context, token string, g groups.Group) (groups.Group, error) {
	ret := _m.Called(ctx, token, g)

	if len(ret) == 0 {
		panic("no return value specified for UpdateGroup")
	}

	var r0 groups.Group
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, groups.Group) (groups.Group, error)); ok {
		return rf(ctx, token, g)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, groups.Group) groups.Group); ok {
		r0 = rf(ctx, token, g)
	} else {
		r0 = ret.Get(0).(groups.Group)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, groups.Group) error); ok {
		r1 = rf(ctx, token, g)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// UpdateRoleName provides a mock function with given fields: ctx, token, entityID, oldRoleName, newRoleName
func (_m *Service) UpdateRoleName(ctx context.Context, token string, entityID string, oldRoleName string, newRoleName string) (roles.Role, error) {
	ret := _m.Called(ctx, token, entityID, oldRoleName, newRoleName)

	if len(ret) == 0 {
		panic("no return value specified for UpdateRoleName")
	}

	var r0 roles.Role
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string, string) (roles.Role, error)); ok {
		return rf(ctx, token, entityID, oldRoleName, newRoleName)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string, string) roles.Role); ok {
		r0 = rf(ctx, token, entityID, oldRoleName, newRoleName)
	} else {
		r0 = ret.Get(0).(roles.Role)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string, string, string) error); ok {
		r1 = rf(ctx, token, entityID, oldRoleName, newRoleName)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ViewGroup provides a mock function with given fields: ctx, token, id
func (_m *Service) ViewGroup(ctx context.Context, token string, id string) (groups.Group, error) {
	ret := _m.Called(ctx, token, id)

	if len(ret) == 0 {
		panic("no return value specified for ViewGroup")
	}

	var r0 groups.Group
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string) (groups.Group, error)); ok {
		return rf(ctx, token, id)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string) groups.Group); ok {
		r0 = rf(ctx, token, id)
	} else {
		r0 = ret.Get(0).(groups.Group)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string) error); ok {
		r1 = rf(ctx, token, id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ViewParentGroup provides a mock function with given fields: ctx, token, id
func (_m *Service) ViewParentGroup(ctx context.Context, token string, id string) (groups.Group, error) {
	ret := _m.Called(ctx, token, id)

	if len(ret) == 0 {
		panic("no return value specified for ViewParentGroup")
	}

	var r0 groups.Group
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string) (groups.Group, error)); ok {
		return rf(ctx, token, id)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string) groups.Group); ok {
		r0 = rf(ctx, token, id)
	} else {
		r0 = ret.Get(0).(groups.Group)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string) error); ok {
		r1 = rf(ctx, token, id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// NewService creates a new instance of Service. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewService(t interface {
	mock.TestingT
	Cleanup(func())
}) *Service {
	mock := &Service{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
