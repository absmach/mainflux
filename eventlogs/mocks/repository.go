// Code generated by mockery v2.38.0. DO NOT EDIT.

// Copyright (c) Abstract Machines

package mocks

import (
	context "context"

	eventlogs "github.com/absmach/magistrala/eventlogs"
	mock "github.com/stretchr/testify/mock"
)

// Repository is an autogenerated mock type for the Repository type
type Repository struct {
	mock.Mock
}

// RetrieveAll provides a mock function with given fields: ctx, page
func (_m *Repository) RetrieveAll(ctx context.Context, page eventlogs.Page) (eventlogs.EventsPage, error) {
	ret := _m.Called(ctx, page)

	if len(ret) == 0 {
		panic("no return value specified for RetrieveAll")
	}

	var r0 eventlogs.EventsPage
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, eventlogs.Page) (eventlogs.EventsPage, error)); ok {
		return rf(ctx, page)
	}
	if rf, ok := ret.Get(0).(func(context.Context, eventlogs.Page) eventlogs.EventsPage); ok {
		r0 = rf(ctx, page)
	} else {
		r0 = ret.Get(0).(eventlogs.EventsPage)
	}

	if rf, ok := ret.Get(1).(func(context.Context, eventlogs.Page) error); ok {
		r1 = rf(ctx, page)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Save provides a mock function with given fields: ctx, event
func (_m *Repository) Save(ctx context.Context, event eventlogs.Event) error {
	ret := _m.Called(ctx, event)

	if len(ret) == 0 {
		panic("no return value specified for Save")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, eventlogs.Event) error); ok {
		r0 = rf(ctx, event)
	} else {
		r0 = ret.Error(0)
	}

	return r0
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
