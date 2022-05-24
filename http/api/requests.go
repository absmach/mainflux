// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package api

import (
	initutil "github.com/mainflux/mainflux/internal/init"
	"github.com/mainflux/mainflux/pkg/messaging"
)

type publishReq struct {
	msg   messaging.Message
	token string
}

func (req publishReq) validate() error {
	if req.token == "" {
		return initutil.ErrBearerToken
	}

	return nil
}
