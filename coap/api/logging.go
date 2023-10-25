// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

//go:build !test

package api

import (
	"context"
	"fmt"
	"time"

	"github.com/mainflux/mainflux/coap"
	mflog "github.com/mainflux/mainflux/logger"
)

var _ coap.Service = (*loggingMiddleware)(nil)

type loggingMiddleware struct {
	logger mflog.Logger
	svc    coap.Service
}

// LoggingMiddleware adds logging facilities to the adapter.
func LoggingMiddleware(svc coap.Service, logger mflog.Logger) coap.Service {
	return &loggingMiddleware{logger, svc}
}

// Subscribe logs the subscribe request. It logs the channel ID, subtopic (if any) and the time it took to complete the request.
// If the request fails, it logs the error.
func (lm *loggingMiddleware) Subscribe(ctx context.Context, key, chanID, subtopic string, c coap.Client) (err error) {
	defer func(begin time.Time) {
		destChannel := chanID
		if subtopic != "" {
			destChannel = fmt.Sprintf("%s.%s", destChannel, subtopic)
		}
		message := fmt.Sprintf("Method subscribe to %s for client %s took %s to complete", destChannel, c.Token(), time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.Subscribe(ctx, key, chanID, subtopic, c)
}

// Unsubscribe logs the unsubscribe request. It logs the channel ID, subtopic (if any) and the time it took to complete the request.
// If the request fails, it logs the error.
func (lm *loggingMiddleware) Unsubscribe(ctx context.Context, key, chanID, subtopic, token string) (err error) {
	defer func(begin time.Time) {
		destChannel := chanID
		if subtopic != "" {
			destChannel = fmt.Sprintf("%s.%s", destChannel, subtopic)
		}
		message := fmt.Sprintf("Method unsubscribe for the client %s from the channel %s took %s to complete", token, destChannel, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.Unsubscribe(ctx, key, chanID, subtopic, token)
}
