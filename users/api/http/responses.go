// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package http

import (
	"net/http"

	"github.com/mainflux/mainflux"
)

var (
	_ mainflux.Response = (*tokenRes)(nil)
	_ mainflux.Response = (*identityRes)(nil)
	_ mainflux.Response = (*resetPassRes)(nil)
)

// MailSent message response when link is sent
const MailSent = "Email with reset link is sent"

type tokenRes struct {
	Token string `json:"token,omitempty"`
}

func (res tokenRes) Code() int {
	return http.StatusCreated
}

func (res tokenRes) Headers() map[string]string {
	return map[string]string{}
}

func (res tokenRes) Empty() bool {
	return res.Token == ""
}

type identityRes struct {
	Email    string                 `json:"email"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

func (res identityRes) Code() int {
	return http.StatusOK
}

func (res identityRes) Headers() map[string]string {
	return map[string]string{}
}

func (res identityRes) Empty() bool {
	return false
}

type resetPasswRes struct {
	Msg string `json:"msg"`
}

func (res resetPasswRes) Code() int {
	return http.StatusCreated
}

func (res resetPasswRes) Headers() map[string]string {
	return map[string]string{}
}

func (res resetPasswRes) Empty() bool {
	return false
}
