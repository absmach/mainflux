// Code generated by mockery v2.43.2. DO NOT EDIT.

// Copyright (c) Abstract Machines

package mocks

import (
	context "context"

	groups "github.com/absmach/supermq/groups"
	mock "github.com/stretchr/testify/mock"
)

// Service is an autogenerated mock type for the Service type
type Service struct {
	mock.Mock
}

// RetrieveById provides a mock function with given fields: ctx, id
func (_m *Service) RetrieveById(ctx context.Context, id string) (groups.Group, error) {
	ret := _m.Called(ctx, id)

	if len(ret) == 0 {
		panic("no return value specified for RetrieveById")
	}

	var r0 groups.Group
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) (groups.Group, error)); ok {
		return rf(ctx, id)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) groups.Group); ok {
		r0 = rf(ctx, id)
	} else {
		r0 = ret.Get(0).(groups.Group)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, id)
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
