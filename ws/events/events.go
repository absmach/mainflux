// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package events

import "github.com/absmach/supermq/pkg/events"

const (
	wsPrefix          = "websocket"
	clientPublish     = wsPrefix + ".client_publish"
	clientSubscribe   = wsPrefix + ".client_subscribe"
	clientUnsubscribe = wsPrefix + ".client_unsubscribe"
)

var _ events.Event = (*wsEvent)(nil)

type wsEvent struct {
	operation string
	channelID string
	clientID  string
	topic     string
	instance  string
}

func (me wsEvent) Encode() (map[string]interface{}, error) {
	return map[string]interface{}{
		"operation":  me.operation,
		"channel_id": me.channelID,
		"client_id":  me.clientID,
		"topic":      me.topic,
	}, nil
}
