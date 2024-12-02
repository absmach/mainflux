// Code generated by mockery v2.43.2. DO NOT EDIT.

// Copyright (c) Abstract Machines

package mocks

import (
	bootstrap "github.com/absmach/supermq/bootstrap"
	mock "github.com/stretchr/testify/mock"
)

// ConfigReader is an autogenerated mock type for the ConfigReader type
type ConfigReader struct {
	mock.Mock
}

// ReadConfig provides a mock function with given fields: _a0, _a1
func (_m *ConfigReader) ReadConfig(_a0 bootstrap.Config, _a1 bool) (interface{}, error) {
	ret := _m.Called(_a0, _a1)

	if len(ret) == 0 {
		panic("no return value specified for ReadConfig")
	}

	var r0 interface{}
	var r1 error
	if rf, ok := ret.Get(0).(func(bootstrap.Config, bool) (interface{}, error)); ok {
		return rf(_a0, _a1)
	}
	if rf, ok := ret.Get(0).(func(bootstrap.Config, bool) interface{}); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(interface{})
		}
	}

	if rf, ok := ret.Get(1).(func(bootstrap.Config, bool) error); ok {
		r1 = rf(_a0, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// NewConfigReader creates a new instance of ConfigReader. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewConfigReader(t interface {
	mock.TestingT
	Cleanup(func())
}) *ConfigReader {
	mock := &ConfigReader{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
