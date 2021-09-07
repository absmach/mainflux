// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

// +build !test

package api

import (
	"time"

	"github.com/go-kit/kit/metrics"
	"github.com/mainflux/mainflux/commands"
)

var _ commands.Service = (*metricsMiddleware)(nil)

type metricsMiddleware struct {
	counter metrics.Counter
	latency metrics.Histogram
	svc     commands.Service
}

// MetricsMiddleware instruments core service by tracking request count and
// latency.
func MetricsMiddleware(svc commands.Service, counter metrics.Counter, latency metrics.Histogram) commands.Service {
	return &metricsMiddleware{
		counter: counter,
		latency: latency,
		svc:     svc,
	}
}

func (ms *metricsMiddleware) CreateCommands(secret string) (response string, err error) {
	defer func(begin time.Time) {
		ms.counter.With("method", "createCommands").Add(1)
		ms.latency.With("method", "createCommands").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return ms.svc.ViewCommands(secret)
}

func (ms *metricsMiddleware) ViewCommands(secret string) (response string, err error) {
	defer func(begin time.Time) {
		ms.counter.With("method", "viewCommands").Add(1)
		ms.latency.With("method", "viewCommands").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return ms.svc.ViewCommands(secret)
}

func (ms *metricsMiddleware) ListCommands(secret string) (response string, err error) {
	defer func(begin time.Time) {
		ms.counter.With("method", "listCommands").Add(1)
		ms.latency.With("method", "listCommands").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return ms.svc.ListCommands(secret)
}

func (ms *metricsMiddleware) UpdateCommands(secret string) (response string, err error) {
	defer func(begin time.Time) {
		ms.counter.With("method", "updateCommands").Add(1)
		ms.latency.With("method", "updateCommands").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return ms.svc.UpdateCommands(secret)
}

func (ms *metricsMiddleware) RemoveCommands(secret string) (response string, err error) {
	defer func(begin time.Time) {
		ms.counter.With("method", "removeCommands").Add(1)
		ms.latency.With("method", "removeCommands").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return ms.svc.RemoveCommands(secret)
}
