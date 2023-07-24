// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	grpcclient "github.com/mainflux/mainflux/internal/clients/grpc"
	mflog "github.com/mainflux/mainflux/logger"
)

func Close(log mflog.Logger, clientHandler grpcclient.ClientHandler) {
	if err := clientHandler.Close(); err != nil {
		log.Warn(err.Error())
	}
}
