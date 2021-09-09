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

func (ms *metricsMiddleware) CreateCommand(secret string) (response string, err error) {
	defer func(begin time.Time) {
		ms.counter.With("method", "createCommand").Add(1)
		ms.latency.With("method", "createCommand").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return ms.svc.CreateCommand(secret)
}

func (ms *metricsMiddleware) ViewCommand(secret string) (response string, err error) {
	defer func(begin time.Time) {
		ms.counter.With("method", "viewCommand").Add(1)
		ms.latency.With("method", "viewCommand").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return ms.svc.ViewCommand(secret)
}

func (ms *metricsMiddleware) ListCommand(secret string) (response string, err error) {
	defer func(begin time.Time) {
		ms.counter.With("method", "listCommand").Add(1)
		ms.latency.With("method", "listCommand").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return ms.svc.ListCommand(secret)
}

func (ms *metricsMiddleware) UpdateCommand(secret string) (response string, err error) {
	defer func(begin time.Time) {
		ms.counter.With("method", "updateCommand").Add(1)
		ms.latency.With("method", "updateCommand").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return ms.svc.UpdateCommand(secret)
}

func (ms *metricsMiddleware) RemoveCommand(secret string) (response string, err error) {
	defer func(begin time.Time) {
		ms.counter.With("method", "removeCommand").Add(1)
		ms.latency.With("method", "removeCommand").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return ms.svc.RemoveCommand(secret)
}
