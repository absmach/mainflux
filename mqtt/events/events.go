// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package events

import "github.com/absmach/supermq/pkg/events"

const (
	mqttPrefix        = "http"
	clientPublish     = mqttPrefix + ".client_publish"
	clientSubscribe   = mqttPrefix + ".client_subscribe"
	clientUnsubscribe = mqttPrefix + ".client_unsubscribe"
	clientConnect     = mqttPrefix + ".client_connect"
	clientDisconnect  = mqttPrefix + ".client_disconnect"
)

var _ events.Event = (*mqttEvent)(nil)

type mqttEvent struct {
	operation string
	channelID string
	clientID  string
	topic     string
	instance  string
}

func (me mqttEvent) Encode() (map[string]interface{}, error) {
	return map[string]interface{}{
		"operation":  me.operation,
		"channel_id": me.channelID,
		"client_id":  me.clientID,
		"topic":      me.topic,
	}, nil
}
