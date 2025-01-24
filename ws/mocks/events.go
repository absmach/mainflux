// Code generated by mockery v2.43.2. DO NOT EDIT.

// Copyright (c) Abstract Machines

package mocks

import (
	context "context"

	mock "github.com/stretchr/testify/mock"
)

// EventStore is an autogenerated mock type for the EventStore type
type EventStore struct {
	mock.Mock
}

// Publish provides a mock function with given fields: ctx, clientID, channelID, topic
func (_m *EventStore) Publish(ctx context.Context, clientID string, channelID string, topic string) error {
	ret := _m.Called(ctx, clientID, channelID, topic)

	if len(ret) == 0 {
		panic("no return value specified for Publish")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string) error); ok {
		r0 = rf(ctx, clientID, channelID, topic)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Subscribe provides a mock function with given fields: ctx, clientID, channelID, subtopic
func (_m *EventStore) Subscribe(ctx context.Context, clientID string, channelID string, subtopic string) error {
	ret := _m.Called(ctx, clientID, channelID, subtopic)

	if len(ret) == 0 {
		panic("no return value specified for Subscribe")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string) error); ok {
		r0 = rf(ctx, clientID, channelID, subtopic)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Unsubscribe provides a mock function with given fields: ctx, clientID, channelID, subtopic
func (_m *EventStore) Unsubscribe(ctx context.Context, clientID string, channelID string, subtopic string) error {
	ret := _m.Called(ctx, clientID, channelID, subtopic)

	if len(ret) == 0 {
		panic("no return value specified for Unsubscribe")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string) error); ok {
		r0 = rf(ctx, clientID, channelID, subtopic)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// NewEventStore creates a new instance of EventStore. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewEventStore(t interface {
	mock.TestingT
	Cleanup(func())
}) *EventStore {
	mock := &EventStore{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}