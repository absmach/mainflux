// Code generated by mockery v2.43.2. DO NOT EDIT.

// Copyright (c) Abstract Machines

package mocks

import (
	context "context"

	domains "github.com/absmach/supermq/domains"
	mock "github.com/stretchr/testify/mock"

	roles "github.com/absmach/supermq/pkg/roles"
)

// Repository is an autogenerated mock type for the Repository type
type Repository struct {
	mock.Mock
}

// AddRoles provides a mock function with given fields: ctx, rps
func (_m *Repository) AddRoles(ctx context.Context, rps []roles.RoleProvision) ([]roles.Role, error) {
	ret := _m.Called(ctx, rps)

	if len(ret) == 0 {
		panic("no return value specified for AddRoles")
	}

	var r0 []roles.Role
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, []roles.RoleProvision) ([]roles.Role, error)); ok {
		return rf(ctx, rps)
	}
	if rf, ok := ret.Get(0).(func(context.Context, []roles.RoleProvision) []roles.Role); ok {
		r0 = rf(ctx, rps)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]roles.Role)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, []roles.RoleProvision) error); ok {
		r1 = rf(ctx, rps)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Delete provides a mock function with given fields: ctx, id
func (_m *Repository) Delete(ctx context.Context, id string) error {
	ret := _m.Called(ctx, id)

	if len(ret) == 0 {
		panic("no return value specified for Delete")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string) error); ok {
		r0 = rf(ctx, id)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// ListDomains provides a mock function with given fields: ctx, pm
func (_m *Repository) ListDomains(ctx context.Context, pm domains.Page) (domains.DomainsPage, error) {
	ret := _m.Called(ctx, pm)

	if len(ret) == 0 {
		panic("no return value specified for ListDomains")
	}

	var r0 domains.DomainsPage
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, domains.Page) (domains.DomainsPage, error)); ok {
		return rf(ctx, pm)
	}
	if rf, ok := ret.Get(0).(func(context.Context, domains.Page) domains.DomainsPage); ok {
		r0 = rf(ctx, pm)
	} else {
		r0 = ret.Get(0).(domains.DomainsPage)
	}

	if rf, ok := ret.Get(1).(func(context.Context, domains.Page) error); ok {
		r1 = rf(ctx, pm)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RemoveMemberFromAllRoles provides a mock function with given fields: ctx, memberID
func (_m *Repository) RemoveMemberFromAllRoles(ctx context.Context, memberID string) error {
	ret := _m.Called(ctx, memberID)

	if len(ret) == 0 {
		panic("no return value specified for RemoveMemberFromAllRoles")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string) error); ok {
		r0 = rf(ctx, memberID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// RemoveRoles provides a mock function with given fields: ctx, roleIDs
func (_m *Repository) RemoveRoles(ctx context.Context, roleIDs []string) error {
	ret := _m.Called(ctx, roleIDs)

	if len(ret) == 0 {
		panic("no return value specified for RemoveRoles")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, []string) error); ok {
		r0 = rf(ctx, roleIDs)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// RetrieveAllByIDs provides a mock function with given fields: ctx, pm
func (_m *Repository) RetrieveAllByIDs(ctx context.Context, pm domains.Page) (domains.DomainsPage, error) {
	ret := _m.Called(ctx, pm)

	if len(ret) == 0 {
		panic("no return value specified for RetrieveAllByIDs")
	}

	var r0 domains.DomainsPage
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, domains.Page) (domains.DomainsPage, error)); ok {
		return rf(ctx, pm)
	}
	if rf, ok := ret.Get(0).(func(context.Context, domains.Page) domains.DomainsPage); ok {
		r0 = rf(ctx, pm)
	} else {
		r0 = ret.Get(0).(domains.DomainsPage)
	}

	if rf, ok := ret.Get(1).(func(context.Context, domains.Page) error); ok {
		r1 = rf(ctx, pm)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RetrieveAllRoles provides a mock function with given fields: ctx, entityID, limit, offset
func (_m *Repository) RetrieveAllRoles(ctx context.Context, entityID string, limit uint64, offset uint64) (roles.RolePage, error) {
	ret := _m.Called(ctx, entityID, limit, offset)

	if len(ret) == 0 {
		panic("no return value specified for RetrieveAllRoles")
	}

	var r0 roles.RolePage
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, uint64, uint64) (roles.RolePage, error)); ok {
		return rf(ctx, entityID, limit, offset)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, uint64, uint64) roles.RolePage); ok {
		r0 = rf(ctx, entityID, limit, offset)
	} else {
		r0 = ret.Get(0).(roles.RolePage)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, uint64, uint64) error); ok {
		r1 = rf(ctx, entityID, limit, offset)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RetrieveByID provides a mock function with given fields: ctx, id
func (_m *Repository) RetrieveByID(ctx context.Context, id string) (domains.Domain, error) {
	ret := _m.Called(ctx, id)

	if len(ret) == 0 {
		panic("no return value specified for RetrieveByID")
	}

	var r0 domains.Domain
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) (domains.Domain, error)); ok {
		return rf(ctx, id)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) domains.Domain); ok {
		r0 = rf(ctx, id)
	} else {
		r0 = ret.Get(0).(domains.Domain)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RetrieveByUserAndID provides a mock function with given fields: ctx, userID, id
func (_m *Repository) RetrieveByUserAndID(ctx context.Context, userID string, id string) (domains.Domain, error) {
	ret := _m.Called(ctx, userID, id)

	if len(ret) == 0 {
		panic("no return value specified for RetrieveByUserAndID")
	}

	var r0 domains.Domain
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string) (domains.Domain, error)); ok {
		return rf(ctx, userID, id)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string) domains.Domain); ok {
		r0 = rf(ctx, userID, id)
	} else {
		r0 = ret.Get(0).(domains.Domain)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string) error); ok {
		r1 = rf(ctx, userID, id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RetrieveEntitiesRolesActionsMembers provides a mock function with given fields: ctx, entityIDs
func (_m *Repository) RetrieveEntitiesRolesActionsMembers(ctx context.Context, entityIDs []string) ([]roles.EntityActionRole, []roles.EntityMemberRole, error) {
	ret := _m.Called(ctx, entityIDs)

	if len(ret) == 0 {
		panic("no return value specified for RetrieveEntitiesRolesActionsMembers")
	}

	var r0 []roles.EntityActionRole
	var r1 []roles.EntityMemberRole
	var r2 error
	if rf, ok := ret.Get(0).(func(context.Context, []string) ([]roles.EntityActionRole, []roles.EntityMemberRole, error)); ok {
		return rf(ctx, entityIDs)
	}
	if rf, ok := ret.Get(0).(func(context.Context, []string) []roles.EntityActionRole); ok {
		r0 = rf(ctx, entityIDs)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]roles.EntityActionRole)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, []string) []roles.EntityMemberRole); ok {
		r1 = rf(ctx, entityIDs)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).([]roles.EntityMemberRole)
		}
	}

	if rf, ok := ret.Get(2).(func(context.Context, []string) error); ok {
		r2 = rf(ctx, entityIDs)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// RetrieveEntityRole provides a mock function with given fields: ctx, entityID, roleID
func (_m *Repository) RetrieveEntityRole(ctx context.Context, entityID string, roleID string) (roles.Role, error) {
	ret := _m.Called(ctx, entityID, roleID)

	if len(ret) == 0 {
		panic("no return value specified for RetrieveEntityRole")
	}

	var r0 roles.Role
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string) (roles.Role, error)); ok {
		return rf(ctx, entityID, roleID)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string) roles.Role); ok {
		r0 = rf(ctx, entityID, roleID)
	} else {
		r0 = ret.Get(0).(roles.Role)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string) error); ok {
		r1 = rf(ctx, entityID, roleID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RetrieveRole provides a mock function with given fields: ctx, roleID
func (_m *Repository) RetrieveRole(ctx context.Context, roleID string) (roles.Role, error) {
	ret := _m.Called(ctx, roleID)

	if len(ret) == 0 {
		panic("no return value specified for RetrieveRole")
	}

	var r0 roles.Role
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) (roles.Role, error)); ok {
		return rf(ctx, roleID)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) roles.Role); ok {
		r0 = rf(ctx, roleID)
	} else {
		r0 = ret.Get(0).(roles.Role)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, roleID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RoleAddActions provides a mock function with given fields: ctx, role, actions
func (_m *Repository) RoleAddActions(ctx context.Context, role roles.Role, actions []string) ([]string, error) {
	ret := _m.Called(ctx, role, actions)

	if len(ret) == 0 {
		panic("no return value specified for RoleAddActions")
	}

	var r0 []string
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, roles.Role, []string) ([]string, error)); ok {
		return rf(ctx, role, actions)
	}
	if rf, ok := ret.Get(0).(func(context.Context, roles.Role, []string) []string); ok {
		r0 = rf(ctx, role, actions)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]string)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, roles.Role, []string) error); ok {
		r1 = rf(ctx, role, actions)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RoleAddMembers provides a mock function with given fields: ctx, role, members
func (_m *Repository) RoleAddMembers(ctx context.Context, role roles.Role, members []string) ([]string, error) {
	ret := _m.Called(ctx, role, members)

	if len(ret) == 0 {
		panic("no return value specified for RoleAddMembers")
	}

	var r0 []string
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, roles.Role, []string) ([]string, error)); ok {
		return rf(ctx, role, members)
	}
	if rf, ok := ret.Get(0).(func(context.Context, roles.Role, []string) []string); ok {
		r0 = rf(ctx, role, members)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]string)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, roles.Role, []string) error); ok {
		r1 = rf(ctx, role, members)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RoleCheckActionsExists provides a mock function with given fields: ctx, roleID, actions
func (_m *Repository) RoleCheckActionsExists(ctx context.Context, roleID string, actions []string) (bool, error) {
	ret := _m.Called(ctx, roleID, actions)

	if len(ret) == 0 {
		panic("no return value specified for RoleCheckActionsExists")
	}

	var r0 bool
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, []string) (bool, error)); ok {
		return rf(ctx, roleID, actions)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, []string) bool); ok {
		r0 = rf(ctx, roleID, actions)
	} else {
		r0 = ret.Get(0).(bool)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, []string) error); ok {
		r1 = rf(ctx, roleID, actions)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RoleCheckMembersExists provides a mock function with given fields: ctx, roleID, members
func (_m *Repository) RoleCheckMembersExists(ctx context.Context, roleID string, members []string) (bool, error) {
	ret := _m.Called(ctx, roleID, members)

	if len(ret) == 0 {
		panic("no return value specified for RoleCheckMembersExists")
	}

	var r0 bool
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, []string) (bool, error)); ok {
		return rf(ctx, roleID, members)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, []string) bool); ok {
		r0 = rf(ctx, roleID, members)
	} else {
		r0 = ret.Get(0).(bool)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, []string) error); ok {
		r1 = rf(ctx, roleID, members)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RoleListActions provides a mock function with given fields: ctx, roleID
func (_m *Repository) RoleListActions(ctx context.Context, roleID string) ([]string, error) {
	ret := _m.Called(ctx, roleID)

	if len(ret) == 0 {
		panic("no return value specified for RoleListActions")
	}

	var r0 []string
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) ([]string, error)); ok {
		return rf(ctx, roleID)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) []string); ok {
		r0 = rf(ctx, roleID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]string)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, roleID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RoleListMembers provides a mock function with given fields: ctx, roleID, limit, offset
func (_m *Repository) RoleListMembers(ctx context.Context, roleID string, limit uint64, offset uint64) (roles.MembersPage, error) {
	ret := _m.Called(ctx, roleID, limit, offset)

	if len(ret) == 0 {
		panic("no return value specified for RoleListMembers")
	}

	var r0 roles.MembersPage
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, uint64, uint64) (roles.MembersPage, error)); ok {
		return rf(ctx, roleID, limit, offset)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, uint64, uint64) roles.MembersPage); ok {
		r0 = rf(ctx, roleID, limit, offset)
	} else {
		r0 = ret.Get(0).(roles.MembersPage)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, uint64, uint64) error); ok {
		r1 = rf(ctx, roleID, limit, offset)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RoleRemoveActions provides a mock function with given fields: ctx, role, actions
func (_m *Repository) RoleRemoveActions(ctx context.Context, role roles.Role, actions []string) error {
	ret := _m.Called(ctx, role, actions)

	if len(ret) == 0 {
		panic("no return value specified for RoleRemoveActions")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, roles.Role, []string) error); ok {
		r0 = rf(ctx, role, actions)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// RoleRemoveAllActions provides a mock function with given fields: ctx, role
func (_m *Repository) RoleRemoveAllActions(ctx context.Context, role roles.Role) error {
	ret := _m.Called(ctx, role)

	if len(ret) == 0 {
		panic("no return value specified for RoleRemoveAllActions")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, roles.Role) error); ok {
		r0 = rf(ctx, role)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// RoleRemoveAllMembers provides a mock function with given fields: ctx, role
func (_m *Repository) RoleRemoveAllMembers(ctx context.Context, role roles.Role) error {
	ret := _m.Called(ctx, role)

	if len(ret) == 0 {
		panic("no return value specified for RoleRemoveAllMembers")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, roles.Role) error); ok {
		r0 = rf(ctx, role)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// RoleRemoveMembers provides a mock function with given fields: ctx, role, members
func (_m *Repository) RoleRemoveMembers(ctx context.Context, role roles.Role, members []string) error {
	ret := _m.Called(ctx, role, members)

	if len(ret) == 0 {
		panic("no return value specified for RoleRemoveMembers")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, roles.Role, []string) error); ok {
		r0 = rf(ctx, role, members)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Save provides a mock function with given fields: ctx, d
func (_m *Repository) Save(ctx context.Context, d domains.Domain) (domains.Domain, error) {
	ret := _m.Called(ctx, d)

	if len(ret) == 0 {
		panic("no return value specified for Save")
	}

	var r0 domains.Domain
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, domains.Domain) (domains.Domain, error)); ok {
		return rf(ctx, d)
	}
	if rf, ok := ret.Get(0).(func(context.Context, domains.Domain) domains.Domain); ok {
		r0 = rf(ctx, d)
	} else {
		r0 = ret.Get(0).(domains.Domain)
	}

	if rf, ok := ret.Get(1).(func(context.Context, domains.Domain) error); ok {
		r1 = rf(ctx, d)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Update provides a mock function with given fields: ctx, id, userID, d
func (_m *Repository) Update(ctx context.Context, id string, userID string, d domains.DomainReq) (domains.Domain, error) {
	ret := _m.Called(ctx, id, userID, d)

	if len(ret) == 0 {
		panic("no return value specified for Update")
	}

	var r0 domains.Domain
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, domains.DomainReq) (domains.Domain, error)); ok {
		return rf(ctx, id, userID, d)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string, domains.DomainReq) domains.Domain); ok {
		r0 = rf(ctx, id, userID, d)
	} else {
		r0 = ret.Get(0).(domains.Domain)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string, domains.DomainReq) error); ok {
		r1 = rf(ctx, id, userID, d)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// UpdateRole provides a mock function with given fields: ctx, ro
func (_m *Repository) UpdateRole(ctx context.Context, ro roles.Role) (roles.Role, error) {
	ret := _m.Called(ctx, ro)

	if len(ret) == 0 {
		panic("no return value specified for UpdateRole")
	}

	var r0 roles.Role
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, roles.Role) (roles.Role, error)); ok {
		return rf(ctx, ro)
	}
	if rf, ok := ret.Get(0).(func(context.Context, roles.Role) roles.Role); ok {
		r0 = rf(ctx, ro)
	} else {
		r0 = ret.Get(0).(roles.Role)
	}

	if rf, ok := ret.Get(1).(func(context.Context, roles.Role) error); ok {
		r1 = rf(ctx, ro)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// NewRepository creates a new instance of Repository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewRepository(t interface {
	mock.TestingT
	Cleanup(func())
}) *Repository {
	mock := &Repository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
