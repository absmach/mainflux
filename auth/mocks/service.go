// Code generated by mockery v2.43.2. DO NOT EDIT.

// Copyright (c) Abstract Machines

package mocks

import (
	context "context"

	auth "github.com/absmach/magistrala/auth"

	mock "github.com/stretchr/testify/mock"

	policies "github.com/absmach/magistrala/pkg/policies"
)

// Service is an autogenerated mock type for the Service type
type Service struct {
	mock.Mock
}

// AssignUsers provides a mock function with given fields: ctx, token, id, userIds, relation
func (_m *Service) AssignUsers(ctx context.Context, token string, id string, userIds []string, relation string) error {
	ret := _m.Called(ctx, token, id, userIds, relation)

	if len(ret) == 0 {
		panic("no return value specified for AssignUsers")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, []string, string) error); ok {
		r0 = rf(ctx, token, id, userIds, relation)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Authorize provides a mock function with given fields: ctx, pr
func (_m *Service) Authorize(ctx context.Context, pr policies.Policy) error {
	ret := _m.Called(ctx, pr)

	if len(ret) == 0 {
		panic("no return value specified for Authorize")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, policies.Policy) error); ok {
		r0 = rf(ctx, pr)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// ChangeDomainStatus provides a mock function with given fields: ctx, token, id, d
func (_m *Service) ChangeDomainStatus(ctx context.Context, token string, id string, d auth.DomainReq) (auth.Domain, error) {
	ret := _m.Called(ctx, token, id, d)

	if len(ret) == 0 {
		panic("no return value specified for ChangeDomainStatus")
	}

	var r0 auth.Domain
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, auth.DomainReq) (auth.Domain, error)); ok {
		return rf(ctx, token, id, d)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string, auth.DomainReq) auth.Domain); ok {
		r0 = rf(ctx, token, id, d)
	} else {
		r0 = ret.Get(0).(auth.Domain)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string, auth.DomainReq) error); ok {
		r1 = rf(ctx, token, id, d)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// CreateDomain provides a mock function with given fields: ctx, token, d
func (_m *Service) CreateDomain(ctx context.Context, token string, d auth.Domain) (auth.Domain, error) {
	ret := _m.Called(ctx, token, d)

	if len(ret) == 0 {
		panic("no return value specified for CreateDomain")
	}

	var r0 auth.Domain
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, auth.Domain) (auth.Domain, error)); ok {
		return rf(ctx, token, d)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, auth.Domain) auth.Domain); ok {
		r0 = rf(ctx, token, d)
	} else {
		r0 = ret.Get(0).(auth.Domain)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, auth.Domain) error); ok {
		r1 = rf(ctx, token, d)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// DeleteUserFromDomains provides a mock function with given fields: ctx, id
func (_m *Service) DeleteUserFromDomains(ctx context.Context, id string) error {
	ret := _m.Called(ctx, id)

	if len(ret) == 0 {
		panic("no return value specified for DeleteUserFromDomains")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string) error); ok {
		r0 = rf(ctx, id)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Identify provides a mock function with given fields: ctx, token
func (_m *Service) Identify(ctx context.Context, token string) (auth.Key, error) {
	ret := _m.Called(ctx, token)

	if len(ret) == 0 {
		panic("no return value specified for Identify")
	}

	var r0 auth.Key
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) (auth.Key, error)); ok {
		return rf(ctx, token)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) auth.Key); ok {
		r0 = rf(ctx, token)
	} else {
		r0 = ret.Get(0).(auth.Key)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, token)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Issue provides a mock function with given fields: ctx, token, key
func (_m *Service) Issue(ctx context.Context, token string, key auth.Key) (auth.Token, error) {
	ret := _m.Called(ctx, token, key)

	if len(ret) == 0 {
		panic("no return value specified for Issue")
	}

	var r0 auth.Token
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, auth.Key) (auth.Token, error)); ok {
		return rf(ctx, token, key)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, auth.Key) auth.Token); ok {
		r0 = rf(ctx, token, key)
	} else {
		r0 = ret.Get(0).(auth.Token)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, auth.Key) error); ok {
		r1 = rf(ctx, token, key)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ListDomains provides a mock function with given fields: ctx, token, page
func (_m *Service) ListDomains(ctx context.Context, token string, page auth.Page) (auth.DomainsPage, error) {
	ret := _m.Called(ctx, token, page)

	if len(ret) == 0 {
		panic("no return value specified for ListDomains")
	}

	var r0 auth.DomainsPage
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, auth.Page) (auth.DomainsPage, error)); ok {
		return rf(ctx, token, page)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, auth.Page) auth.DomainsPage); ok {
		r0 = rf(ctx, token, page)
	} else {
		r0 = ret.Get(0).(auth.DomainsPage)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, auth.Page) error); ok {
		r1 = rf(ctx, token, page)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ListUserDomains provides a mock function with given fields: ctx, token, userID, page
func (_m *Service) ListUserDomains(ctx context.Context, token string, userID string, page auth.Page) (auth.DomainsPage, error) {
	ret := _m.Called(ctx, token, userID, page)

	if len(ret) == 0 {
		panic("no return value specified for ListUserDomains")
	}

	var r0 auth.DomainsPage
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, auth.Page) (auth.DomainsPage, error)); ok {
		return rf(ctx, token, userID, page)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string, auth.Page) auth.DomainsPage); ok {
		r0 = rf(ctx, token, userID, page)
	} else {
		r0 = ret.Get(0).(auth.DomainsPage)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string, auth.Page) error); ok {
		r1 = rf(ctx, token, userID, page)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RetrieveDomain provides a mock function with given fields: ctx, token, id
func (_m *Service) RetrieveDomain(ctx context.Context, token string, id string) (auth.Domain, error) {
	ret := _m.Called(ctx, token, id)

	if len(ret) == 0 {
		panic("no return value specified for RetrieveDomain")
	}

	var r0 auth.Domain
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string) (auth.Domain, error)); ok {
		return rf(ctx, token, id)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string) auth.Domain); ok {
		r0 = rf(ctx, token, id)
	} else {
		r0 = ret.Get(0).(auth.Domain)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string) error); ok {
		r1 = rf(ctx, token, id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RetrieveDomainPermissions provides a mock function with given fields: ctx, token, id
func (_m *Service) RetrieveDomainPermissions(ctx context.Context, token string, id string) (policies.Permissions, error) {
	ret := _m.Called(ctx, token, id)

	if len(ret) == 0 {
		panic("no return value specified for RetrieveDomainPermissions")
	}

	var r0 policies.Permissions
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string) (policies.Permissions, error)); ok {
		return rf(ctx, token, id)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string) policies.Permissions); ok {
		r0 = rf(ctx, token, id)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(policies.Permissions)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string) error); ok {
		r1 = rf(ctx, token, id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RetrieveJWKS provides a mock function with given fields:
func (_m *Service) RetrieveJWKS() (auth.JWKS, error) {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for RetrieveJWKS")
	}

	var r0 auth.JWKS
	var r1 error
	if rf, ok := ret.Get(0).(func() (auth.JWKS, error)); ok {
		return rf()
	}
	if rf, ok := ret.Get(0).(func() auth.JWKS); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(auth.JWKS)
	}

	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RetrieveKey provides a mock function with given fields: ctx, token, id
func (_m *Service) RetrieveKey(ctx context.Context, token string, id string) (auth.Key, error) {
	ret := _m.Called(ctx, token, id)

	if len(ret) == 0 {
		panic("no return value specified for RetrieveKey")
	}

	var r0 auth.Key
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string) (auth.Key, error)); ok {
		return rf(ctx, token, id)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string) auth.Key); ok {
		r0 = rf(ctx, token, id)
	} else {
		r0 = ret.Get(0).(auth.Key)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string) error); ok {
		r1 = rf(ctx, token, id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Revoke provides a mock function with given fields: ctx, token, id
func (_m *Service) Revoke(ctx context.Context, token string, id string) error {
	ret := _m.Called(ctx, token, id)

	if len(ret) == 0 {
		panic("no return value specified for Revoke")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string) error); ok {
		r0 = rf(ctx, token, id)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// RevokeToken provides a mock function with given fields: ctx, token
func (_m *Service) RevokeToken(ctx context.Context, token string) error {
	ret := _m.Called(ctx, token)

	if len(ret) == 0 {
		panic("no return value specified for RevokeToken")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string) error); ok {
		r0 = rf(ctx, token)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// UnassignUser provides a mock function with given fields: ctx, token, id, userID
func (_m *Service) UnassignUser(ctx context.Context, token string, id string, userID string) error {
	ret := _m.Called(ctx, token, id, userID)

	if len(ret) == 0 {
		panic("no return value specified for UnassignUser")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string) error); ok {
		r0 = rf(ctx, token, id, userID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// UpdateDomain provides a mock function with given fields: ctx, token, id, d
func (_m *Service) UpdateDomain(ctx context.Context, token string, id string, d auth.DomainReq) (auth.Domain, error) {
	ret := _m.Called(ctx, token, id, d)

	if len(ret) == 0 {
		panic("no return value specified for UpdateDomain")
	}

	var r0 auth.Domain
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, auth.DomainReq) (auth.Domain, error)); ok {
		return rf(ctx, token, id, d)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string, auth.DomainReq) auth.Domain); ok {
		r0 = rf(ctx, token, id, d)
	} else {
		r0 = ret.Get(0).(auth.Domain)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string, auth.DomainReq) error); ok {
		r1 = rf(ctx, token, id, d)
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
