// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package events

import "github.com/absmach/supermq/pkg/events"

const (
	httpPrefix    = "http"
	clientPublish = httpPrefix + ".client_publish"
	clientConnect = httpPrefix + ".client_connect"
)

var _ events.Event = (*httpEvent)(nil)

type httpEvent struct {
	operation string
	channelID string
	clientID  string
	topic     string
	instance  string
}

func (ce httpEvent) Encode() (map[string]interface{}, error) {
	val := map[string]interface{}{
		"operation":  ce.operation,
		"channel_id": ce.channelID,
		"client_id":  ce.clientID,
		"topic":      ce.topic,
	}
	return val, nil
}
