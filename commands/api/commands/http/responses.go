// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package http

import (
	"net/http"

	"github.com/mainflux/mainflux"
)

var _ mainflux.Response = (*createCommandRes)(nil)
var _ mainflux.Response = (*viewCommandRes)(nil)
var _ mainflux.Response = (*listCommandRes)(nil)
var _ mainflux.Response = (*updateCommandRes)(nil)
var _ mainflux.Response = (*removeCommandRes)(nil)

type createCommandRes struct {
	command string `json:"greeting"`
	channel string
	// time    Time
}

func (res createCommandRes) Code() int {
	return http.StatusOK
}

func (res createCommandRes) Headers() map[string]string {
	return map[string]string{}
}

func (res createCommandRes) Empty() bool {
	return false
}

type viewCommandRes struct {
	Greeting string `json:"greeting"`
}

func (res viewCommandRes) Code() int {
	return http.StatusOK
}

func (res viewCommandRes) Headers() map[string]string {
	return map[string]string{}
}

func (res viewCommandRes) Empty() bool {
	return false
}

type listCommandRes struct {
	Greeting string `json:"greeting"`
}

func (res listCommandRes) Code() int {
	return http.StatusOK
}

func (res listCommandRes) Headers() map[string]string {
	return map[string]string{}
}

func (res listCommandRes) Empty() bool {
	return false
}

type updateCommandRes struct {
	Greeting string `json:"greeting"`
}

func (res updateCommandRes) Code() int {
	return http.StatusOK
}

func (res updateCommandRes) Headers() map[string]string {
	return map[string]string{}
}

func (res updateCommandRes) Empty() bool {
	return false
}

type removeCommandRes struct {
	Greeting string `json:"greeting"`
}

func (res removeCommandRes) Code() int {
	return http.StatusOK
}

func (res removeCommandRes) Headers() map[string]string {
	return map[string]string{}
}

func (res removeCommandRes) Empty() bool {
	return false
}
