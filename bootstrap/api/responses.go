//
// Copyright (c) 2018
// Mainflux
//
// SPDX-License-Identifier: Apache-2.0
//

package http

import (
	"fmt"
	"net/http"
	"nov/bootstrap"

	"github.com/mainflux/mainflux"
)

var (
	_ mainflux.Response = (*identityRes)(nil)
	_ mainflux.Response = (*removeRes)(nil)
	_ mainflux.Response = (*thingRes)(nil)
	_ mainflux.Response = (*viewRes)(nil)
)

type identityRes struct {
	id uint64
}

func (res identityRes) Headers() map[string]string {
	return map[string]string{
		"X-thing-id": fmt.Sprint(res.id),
	}
}

func (res identityRes) Code() int {
	return http.StatusOK
}

func (res identityRes) Empty() bool {
	return true
}

type removeRes struct{}

func (res removeRes) Code() int {
	return http.StatusNoContent
}

func (res removeRes) Headers() map[string]string {
	return map[string]string{}
}

func (res removeRes) Empty() bool {
	return true
}

type thingRes struct {
	id      string
	created bool
}

func (res thingRes) Code() int {
	if res.created {
		return http.StatusCreated
	}

	return http.StatusOK
}

func (res thingRes) Headers() map[string]string {
	if res.created {
		return map[string]string{
			"Location": fmt.Sprintf("/things/%s", res.id),
		}
	}

	return map[string]string{}
}

func (res thingRes) Empty() bool {
	return true
}

type viewRes struct {
	ID         string           `json:"id"`
	Key        string           `json:"key"`
	Owner      string           `json:"-"`
	MainfluxID string           `json:"mainflux_id"`
	ExternalID string           `json:"external_id,omitempty"`
	Status     bootstrap.Status `json:"status"`
}

func (res viewRes) Code() int {
	return http.StatusOK
}

func (res viewRes) Headers() map[string]string {
	return map[string]string{}
}

func (res viewRes) Empty() bool {
	return false
}
