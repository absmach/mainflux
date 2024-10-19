// Code generated by mockery v2.43.2. DO NOT EDIT.

// Copyright (c) Abstract Machines

package mocks

import (
	context "context"

	authn "github.com/absmach/magistrala/pkg/authn"

	groups "github.com/absmach/magistrala/pkg/groups"

	mock "github.com/stretchr/testify/mock"

	roles "github.com/absmach/magistrala/pkg/roles"
)

// Service is an autogenerated mock type for the Service type
type Service struct {
	mock.Mock
}

// AddChildrenGroups provides a mock function with given fields: ctx, session, id, childrenGroupIDs
func (_m *Service) AddChildrenGroups(ctx context.Context, session authn.Session, id string, childrenGroupIDs []string) error {
	ret := _m.Called(ctx, session, id, childrenGroupIDs)

	if len(ret) == 0 {
		panic("no return value specified for AddChildrenGroups")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, authn.Session, string, []string) error); ok {
		r0 = rf(ctx, session, id, childrenGroupIDs)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// AddParentGroup provides a mock function with given fields: ctx, session, id, parentID
func (_m *Service) AddParentGroup(ctx context.Context, session authn.Session, id string, parentID string) error {
	ret := _m.Called(ctx, session, id, parentID)

	if len(ret) == 0 {
		panic("no return value specified for AddParentGroup")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, authn.Session, string, string) error); ok {
		r0 = rf(ctx, session, id, parentID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// AddRole provides a mock function with given fields: ctx, session, entityID, roleName, optionalActions, optionalMembers
func (_m *Service) AddRole(ctx context.Context, session authn.Session, entityID string, roleName string, optionalActions []string, optionalMembers []string) (roles.Role, error) {
	ret := _m.Called(ctx, session, entityID, roleName, optionalActions, optionalMembers)

	if len(ret) == 0 {
		panic("no return value specified for AddRole")
	}

	var r0 roles.Role
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, authn.Session, string, string, []string, []string) (roles.Role, error)); ok {
		return rf(ctx, session, entityID, roleName, optionalActions, optionalMembers)
	}
	if rf, ok := ret.Get(0).(func(context.Context, authn.Session, string, string, []string, []string) roles.Role); ok {
		r0 = rf(ctx, session, entityID, roleName, optionalActions, optionalMembers)
	} else {
		r0 = ret.Get(0).(roles.Role)
	}

	if rf, ok := ret.Get(1).(func(context.Context, authn.Session, string, string, []string, []string) error); ok {
		r1 = rf(ctx, session, entityID, roleName, optionalActions, optionalMembers)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// CreateGroup provides a mock function with given fields: ctx, session, g
func (_m *Service) CreateGroup(ctx context.Context, session authn.Session, g groups.Group) (groups.Group, error) {
	ret := _m.Called(ctx, session, g)

	if len(ret) == 0 {
		panic("no return value specified for CreateGroup")
	}

	var r0 groups.Group
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, authn.Session, groups.Group) (groups.Group, error)); ok {
		return rf(ctx, session, g)
	}
	if rf, ok := ret.Get(0).(func(context.Context, authn.Session, groups.Group) groups.Group); ok {
		r0 = rf(ctx, session, g)
	} else {
		r0 = ret.Get(0).(groups.Group)
	}

	if rf, ok := ret.Get(1).(func(context.Context, authn.Session, groups.Group) error); ok {
		r1 = rf(ctx, session, g)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// DeleteGroup provides a mock function with given fields: ctx, session, id
func (_m *Service) DeleteGroup(ctx context.Context, session authn.Session, id string) error {
	ret := _m.Called(ctx, session, id)

	if len(ret) == 0 {
		panic("no return value specified for DeleteGroup")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, authn.Session, string) error); ok {
		r0 = rf(ctx, session, id)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DisableGroup provides a mock function with given fields: ctx, session, id
func (_m *Service) DisableGroup(ctx context.Context, session authn.Session, id string) (groups.Group, error) {
	ret := _m.Called(ctx, session, id)

	if len(ret) == 0 {
		panic("no return value specified for DisableGroup")
	}

	var r0 groups.Group
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, authn.Session, string) (groups.Group, error)); ok {
		return rf(ctx, session, id)
	}
	if rf, ok := ret.Get(0).(func(context.Context, authn.Session, string) groups.Group); ok {
		r0 = rf(ctx, session, id)
	} else {
		r0 = ret.Get(0).(groups.Group)
	}

	if rf, ok := ret.Get(1).(func(context.Context, authn.Session, string) error); ok {
		r1 = rf(ctx, session, id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// EnableGroup provides a mock function with given fields: ctx, session, id
func (_m *Service) EnableGroup(ctx context.Context, session authn.Session, id string) (groups.Group, error) {
	ret := _m.Called(ctx, session, id)

	if len(ret) == 0 {
		panic("no return value specified for EnableGroup")
	}

	var r0 groups.Group
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, authn.Session, string) (groups.Group, error)); ok {
		return rf(ctx, session, id)
	}
	if rf, ok := ret.Get(0).(func(context.Context, authn.Session, string) groups.Group); ok {
		r0 = rf(ctx, session, id)
	} else {
		r0 = ret.Get(0).(groups.Group)
	}

	if rf, ok := ret.Get(1).(func(context.Context, authn.Session, string) error); ok {
		r1 = rf(ctx, session, id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ListAvailableActions provides a mock function with given fields: ctx, session
func (_m *Service) ListAvailableActions(ctx context.Context, session authn.Session) ([]string, error) {
	ret := _m.Called(ctx, session)

	if len(ret) == 0 {
		panic("no return value specified for ListAvailableActions")
	}

	var r0 []string
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, authn.Session) ([]string, error)); ok {
		return rf(ctx, session)
	}
	if rf, ok := ret.Get(0).(func(context.Context, authn.Session) []string); ok {
		r0 = rf(ctx, session)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]string)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, authn.Session) error); ok {
		r1 = rf(ctx, session)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ListChildrenGroups provides a mock function with given fields: ctx, session, id, pm
func (_m *Service) ListChildrenGroups(ctx context.Context, session authn.Session, id string, pm groups.PageMeta) (groups.Page, error) {
	ret := _m.Called(ctx, session, id, pm)

	if len(ret) == 0 {
		panic("no return value specified for ListChildrenGroups")
	}

	var r0 groups.Page
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, authn.Session, string, groups.PageMeta) (groups.Page, error)); ok {
		return rf(ctx, session, id, pm)
	}
	if rf, ok := ret.Get(0).(func(context.Context, authn.Session, string, groups.PageMeta) groups.Page); ok {
		r0 = rf(ctx, session, id, pm)
	} else {
		r0 = ret.Get(0).(groups.Page)
	}

	if rf, ok := ret.Get(1).(func(context.Context, authn.Session, string, groups.PageMeta) error); ok {
		r1 = rf(ctx, session, id, pm)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ListGroups provides a mock function with given fields: ctx, session, pm
func (_m *Service) ListGroups(ctx context.Context, session authn.Session, pm groups.PageMeta) (groups.Page, error) {
	ret := _m.Called(ctx, session, pm)

	if len(ret) == 0 {
		panic("no return value specified for ListGroups")
	}

	var r0 groups.Page
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, authn.Session, groups.PageMeta) (groups.Page, error)); ok {
		return rf(ctx, session, pm)
	}
	if rf, ok := ret.Get(0).(func(context.Context, authn.Session, groups.PageMeta) groups.Page); ok {
		r0 = rf(ctx, session, pm)
	} else {
		r0 = ret.Get(0).(groups.Page)
	}

	if rf, ok := ret.Get(1).(func(context.Context, authn.Session, groups.PageMeta) error); ok {
		r1 = rf(ctx, session, pm)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RemoveActionsFromAllRoles provides a mock function with given fields: ctx, session, actions
func (_m *Service) RemoveActionsFromAllRoles(ctx context.Context, session authn.Session, actions []string) error {
	ret := _m.Called(ctx, session, actions)

	if len(ret) == 0 {
		panic("no return value specified for RemoveActionsFromAllRoles")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, authn.Session, []string) error); ok {
		r0 = rf(ctx, session, actions)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// RemoveActionsFromRoles provides a mock function with given fields: ctx, session, actions, roleNames
func (_m *Service) RemoveActionsFromRoles(ctx context.Context, session authn.Session, actions []string, roleNames []string) error {
	ret := _m.Called(ctx, session, actions, roleNames)

	if len(ret) == 0 {
		panic("no return value specified for RemoveActionsFromRoles")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, authn.Session, []string, []string) error); ok {
		r0 = rf(ctx, session, actions, roleNames)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// RemoveAllChildrenGroups provides a mock function with given fields: ctx, session, id
func (_m *Service) RemoveAllChildrenGroups(ctx context.Context, session authn.Session, id string) error {
	ret := _m.Called(ctx, session, id)

	if len(ret) == 0 {
		panic("no return value specified for RemoveAllChildrenGroups")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, authn.Session, string) error); ok {
		r0 = rf(ctx, session, id)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// RemoveChildrenGroups provides a mock function with given fields: ctx, session, id, childrenGroupIDs
func (_m *Service) RemoveChildrenGroups(ctx context.Context, session authn.Session, id string, childrenGroupIDs []string) error {
	ret := _m.Called(ctx, session, id, childrenGroupIDs)

	if len(ret) == 0 {
		panic("no return value specified for RemoveChildrenGroups")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, authn.Session, string, []string) error); ok {
		r0 = rf(ctx, session, id, childrenGroupIDs)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// RemoveMembersFromAllRoles provides a mock function with given fields: ctx, session, members
func (_m *Service) RemoveMembersFromAllRoles(ctx context.Context, session authn.Session, members []string) error {
	ret := _m.Called(ctx, session, members)

	if len(ret) == 0 {
		panic("no return value specified for RemoveMembersFromAllRoles")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, authn.Session, []string) error); ok {
		r0 = rf(ctx, session, members)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// RemoveMembersFromRoles provides a mock function with given fields: ctx, session, members, roleNames
func (_m *Service) RemoveMembersFromRoles(ctx context.Context, session authn.Session, members []string, roleNames []string) error {
	ret := _m.Called(ctx, session, members, roleNames)

	if len(ret) == 0 {
		panic("no return value specified for RemoveMembersFromRoles")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, authn.Session, []string, []string) error); ok {
		r0 = rf(ctx, session, members, roleNames)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// RemoveParentGroup provides a mock function with given fields: ctx, session, id
func (_m *Service) RemoveParentGroup(ctx context.Context, session authn.Session, id string) error {
	ret := _m.Called(ctx, session, id)

	if len(ret) == 0 {
		panic("no return value specified for RemoveParentGroup")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, authn.Session, string) error); ok {
		r0 = rf(ctx, session, id)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// RemoveRole provides a mock function with given fields: ctx, session, entityID, roleName
func (_m *Service) RemoveRole(ctx context.Context, session authn.Session, entityID string, roleName string) error {
	ret := _m.Called(ctx, session, entityID, roleName)

	if len(ret) == 0 {
		panic("no return value specified for RemoveRole")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, authn.Session, string, string) error); ok {
		r0 = rf(ctx, session, entityID, roleName)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// RetrieveAllRoles provides a mock function with given fields: ctx, session, entityID, limit, offset
func (_m *Service) RetrieveAllRoles(ctx context.Context, session authn.Session, entityID string, limit uint64, offset uint64) (roles.RolePage, error) {
	ret := _m.Called(ctx, session, entityID, limit, offset)

	if len(ret) == 0 {
		panic("no return value specified for RetrieveAllRoles")
	}

	var r0 roles.RolePage
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, authn.Session, string, uint64, uint64) (roles.RolePage, error)); ok {
		return rf(ctx, session, entityID, limit, offset)
	}
	if rf, ok := ret.Get(0).(func(context.Context, authn.Session, string, uint64, uint64) roles.RolePage); ok {
		r0 = rf(ctx, session, entityID, limit, offset)
	} else {
		r0 = ret.Get(0).(roles.RolePage)
	}

	if rf, ok := ret.Get(1).(func(context.Context, authn.Session, string, uint64, uint64) error); ok {
		r1 = rf(ctx, session, entityID, limit, offset)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RetrieveGroupHierarchy provides a mock function with given fields: ctx, session, id, hm
func (_m *Service) RetrieveGroupHierarchy(ctx context.Context, session authn.Session, id string, hm groups.HierarchyPageMeta) (groups.HierarchyPage, error) {
	ret := _m.Called(ctx, session, id, hm)

	if len(ret) == 0 {
		panic("no return value specified for RetrieveGroupHierarchy")
	}

	var r0 groups.HierarchyPage
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, authn.Session, string, groups.HierarchyPageMeta) (groups.HierarchyPage, error)); ok {
		return rf(ctx, session, id, hm)
	}
	if rf, ok := ret.Get(0).(func(context.Context, authn.Session, string, groups.HierarchyPageMeta) groups.HierarchyPage); ok {
		r0 = rf(ctx, session, id, hm)
	} else {
		r0 = ret.Get(0).(groups.HierarchyPage)
	}

	if rf, ok := ret.Get(1).(func(context.Context, authn.Session, string, groups.HierarchyPageMeta) error); ok {
		r1 = rf(ctx, session, id, hm)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RetrieveRole provides a mock function with given fields: ctx, session, entityID, roleName
func (_m *Service) RetrieveRole(ctx context.Context, session authn.Session, entityID string, roleName string) (roles.Role, error) {
	ret := _m.Called(ctx, session, entityID, roleName)

	if len(ret) == 0 {
		panic("no return value specified for RetrieveRole")
	}

	var r0 roles.Role
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, authn.Session, string, string) (roles.Role, error)); ok {
		return rf(ctx, session, entityID, roleName)
	}
	if rf, ok := ret.Get(0).(func(context.Context, authn.Session, string, string) roles.Role); ok {
		r0 = rf(ctx, session, entityID, roleName)
	} else {
		r0 = ret.Get(0).(roles.Role)
	}

	if rf, ok := ret.Get(1).(func(context.Context, authn.Session, string, string) error); ok {
		r1 = rf(ctx, session, entityID, roleName)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RoleAddActions provides a mock function with given fields: ctx, session, entityID, roleName, actions
func (_m *Service) RoleAddActions(ctx context.Context, session authn.Session, entityID string, roleName string, actions []string) ([]string, error) {
	ret := _m.Called(ctx, session, entityID, roleName, actions)

	if len(ret) == 0 {
		panic("no return value specified for RoleAddActions")
	}

	var r0 []string
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, authn.Session, string, string, []string) ([]string, error)); ok {
		return rf(ctx, session, entityID, roleName, actions)
	}
	if rf, ok := ret.Get(0).(func(context.Context, authn.Session, string, string, []string) []string); ok {
		r0 = rf(ctx, session, entityID, roleName, actions)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]string)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, authn.Session, string, string, []string) error); ok {
		r1 = rf(ctx, session, entityID, roleName, actions)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RoleAddMembers provides a mock function with given fields: ctx, session, entityID, roleName, members
func (_m *Service) RoleAddMembers(ctx context.Context, session authn.Session, entityID string, roleName string, members []string) ([]string, error) {
	ret := _m.Called(ctx, session, entityID, roleName, members)

	if len(ret) == 0 {
		panic("no return value specified for RoleAddMembers")
	}

	var r0 []string
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, authn.Session, string, string, []string) ([]string, error)); ok {
		return rf(ctx, session, entityID, roleName, members)
	}
	if rf, ok := ret.Get(0).(func(context.Context, authn.Session, string, string, []string) []string); ok {
		r0 = rf(ctx, session, entityID, roleName, members)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]string)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, authn.Session, string, string, []string) error); ok {
		r1 = rf(ctx, session, entityID, roleName, members)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RoleCheckActionsExists provides a mock function with given fields: ctx, session, entityID, roleName, actions
func (_m *Service) RoleCheckActionsExists(ctx context.Context, session authn.Session, entityID string, roleName string, actions []string) (bool, error) {
	ret := _m.Called(ctx, session, entityID, roleName, actions)

	if len(ret) == 0 {
		panic("no return value specified for RoleCheckActionsExists")
	}

	var r0 bool
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, authn.Session, string, string, []string) (bool, error)); ok {
		return rf(ctx, session, entityID, roleName, actions)
	}
	if rf, ok := ret.Get(0).(func(context.Context, authn.Session, string, string, []string) bool); ok {
		r0 = rf(ctx, session, entityID, roleName, actions)
	} else {
		r0 = ret.Get(0).(bool)
	}

	if rf, ok := ret.Get(1).(func(context.Context, authn.Session, string, string, []string) error); ok {
		r1 = rf(ctx, session, entityID, roleName, actions)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RoleCheckMembersExists provides a mock function with given fields: ctx, session, entityID, roleName, members
func (_m *Service) RoleCheckMembersExists(ctx context.Context, session authn.Session, entityID string, roleName string, members []string) (bool, error) {
	ret := _m.Called(ctx, session, entityID, roleName, members)

	if len(ret) == 0 {
		panic("no return value specified for RoleCheckMembersExists")
	}

	var r0 bool
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, authn.Session, string, string, []string) (bool, error)); ok {
		return rf(ctx, session, entityID, roleName, members)
	}
	if rf, ok := ret.Get(0).(func(context.Context, authn.Session, string, string, []string) bool); ok {
		r0 = rf(ctx, session, entityID, roleName, members)
	} else {
		r0 = ret.Get(0).(bool)
	}

	if rf, ok := ret.Get(1).(func(context.Context, authn.Session, string, string, []string) error); ok {
		r1 = rf(ctx, session, entityID, roleName, members)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RoleListActions provides a mock function with given fields: ctx, session, entityID, roleName
func (_m *Service) RoleListActions(ctx context.Context, session authn.Session, entityID string, roleName string) ([]string, error) {
	ret := _m.Called(ctx, session, entityID, roleName)

	if len(ret) == 0 {
		panic("no return value specified for RoleListActions")
	}

	var r0 []string
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, authn.Session, string, string) ([]string, error)); ok {
		return rf(ctx, session, entityID, roleName)
	}
	if rf, ok := ret.Get(0).(func(context.Context, authn.Session, string, string) []string); ok {
		r0 = rf(ctx, session, entityID, roleName)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]string)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, authn.Session, string, string) error); ok {
		r1 = rf(ctx, session, entityID, roleName)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RoleListMembers provides a mock function with given fields: ctx, session, entityID, roleName, limit, offset
func (_m *Service) RoleListMembers(ctx context.Context, session authn.Session, entityID string, roleName string, limit uint64, offset uint64) (roles.MembersPage, error) {
	ret := _m.Called(ctx, session, entityID, roleName, limit, offset)

	if len(ret) == 0 {
		panic("no return value specified for RoleListMembers")
	}

	var r0 roles.MembersPage
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, authn.Session, string, string, uint64, uint64) (roles.MembersPage, error)); ok {
		return rf(ctx, session, entityID, roleName, limit, offset)
	}
	if rf, ok := ret.Get(0).(func(context.Context, authn.Session, string, string, uint64, uint64) roles.MembersPage); ok {
		r0 = rf(ctx, session, entityID, roleName, limit, offset)
	} else {
		r0 = ret.Get(0).(roles.MembersPage)
	}

	if rf, ok := ret.Get(1).(func(context.Context, authn.Session, string, string, uint64, uint64) error); ok {
		r1 = rf(ctx, session, entityID, roleName, limit, offset)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RoleRemoveActions provides a mock function with given fields: ctx, session, entityID, roleName, actions
func (_m *Service) RoleRemoveActions(ctx context.Context, session authn.Session, entityID string, roleName string, actions []string) error {
	ret := _m.Called(ctx, session, entityID, roleName, actions)

	if len(ret) == 0 {
		panic("no return value specified for RoleRemoveActions")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, authn.Session, string, string, []string) error); ok {
		r0 = rf(ctx, session, entityID, roleName, actions)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// RoleRemoveAllActions provides a mock function with given fields: ctx, session, entityID, roleName
func (_m *Service) RoleRemoveAllActions(ctx context.Context, session authn.Session, entityID string, roleName string) error {
	ret := _m.Called(ctx, session, entityID, roleName)

	if len(ret) == 0 {
		panic("no return value specified for RoleRemoveAllActions")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, authn.Session, string, string) error); ok {
		r0 = rf(ctx, session, entityID, roleName)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// RoleRemoveAllMembers provides a mock function with given fields: ctx, session, entityID, roleName
func (_m *Service) RoleRemoveAllMembers(ctx context.Context, session authn.Session, entityID string, roleName string) error {
	ret := _m.Called(ctx, session, entityID, roleName)

	if len(ret) == 0 {
		panic("no return value specified for RoleRemoveAllMembers")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, authn.Session, string, string) error); ok {
		r0 = rf(ctx, session, entityID, roleName)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// RoleRemoveMembers provides a mock function with given fields: ctx, session, entityID, roleName, members
func (_m *Service) RoleRemoveMembers(ctx context.Context, session authn.Session, entityID string, roleName string, members []string) error {
	ret := _m.Called(ctx, session, entityID, roleName, members)

	if len(ret) == 0 {
		panic("no return value specified for RoleRemoveMembers")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, authn.Session, string, string, []string) error); ok {
		r0 = rf(ctx, session, entityID, roleName, members)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// UpdateGroup provides a mock function with given fields: ctx, session, g
func (_m *Service) UpdateGroup(ctx context.Context, session authn.Session, g groups.Group) (groups.Group, error) {
	ret := _m.Called(ctx, session, g)

	if len(ret) == 0 {
		panic("no return value specified for UpdateGroup")
	}

	var r0 groups.Group
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, authn.Session, groups.Group) (groups.Group, error)); ok {
		return rf(ctx, session, g)
	}
	if rf, ok := ret.Get(0).(func(context.Context, authn.Session, groups.Group) groups.Group); ok {
		r0 = rf(ctx, session, g)
	} else {
		r0 = ret.Get(0).(groups.Group)
	}

	if rf, ok := ret.Get(1).(func(context.Context, authn.Session, groups.Group) error); ok {
		r1 = rf(ctx, session, g)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// UpdateRoleName provides a mock function with given fields: ctx, session, entityID, oldRoleName, newRoleName
func (_m *Service) UpdateRoleName(ctx context.Context, session authn.Session, entityID string, oldRoleName string, newRoleName string) (roles.Role, error) {
	ret := _m.Called(ctx, session, entityID, oldRoleName, newRoleName)

	if len(ret) == 0 {
		panic("no return value specified for UpdateRoleName")
	}

	var r0 roles.Role
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, authn.Session, string, string, string) (roles.Role, error)); ok {
		return rf(ctx, session, entityID, oldRoleName, newRoleName)
	}
	if rf, ok := ret.Get(0).(func(context.Context, authn.Session, string, string, string) roles.Role); ok {
		r0 = rf(ctx, session, entityID, oldRoleName, newRoleName)
	} else {
		r0 = ret.Get(0).(roles.Role)
	}

	if rf, ok := ret.Get(1).(func(context.Context, authn.Session, string, string, string) error); ok {
		r1 = rf(ctx, session, entityID, oldRoleName, newRoleName)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ViewGroup provides a mock function with given fields: ctx, session, id
func (_m *Service) ViewGroup(ctx context.Context, session authn.Session, id string) (groups.Group, error) {
	ret := _m.Called(ctx, session, id)

	if len(ret) == 0 {
		panic("no return value specified for ViewGroup")
	}

	var r0 groups.Group
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, authn.Session, string) (groups.Group, error)); ok {
		return rf(ctx, session, id)
	}
	if rf, ok := ret.Get(0).(func(context.Context, authn.Session, string) groups.Group); ok {
		r0 = rf(ctx, session, id)
	} else {
		r0 = ret.Get(0).(groups.Group)
	}

	if rf, ok := ret.Get(1).(func(context.Context, authn.Session, string) error); ok {
		r1 = rf(ctx, session, id)
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
