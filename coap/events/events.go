// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package events

const (
	coapPrefix        = "coap"
	clientPublish     = coapPrefix + ".client_publish"
	clientSubscribe   = coapPrefix + ".client_subscribe"
	clientUnsubscribe = coapPrefix + ".client_unsubscribe"
)

type coapEvent struct {
	operation string
	channelID string
	clientID  string
	connID    string
	topic     string
}

func (ce coapEvent) Encode() (map[string]interface{}, error) {
	val := map[string]interface{}{
		"operation":  ce.operation,
		"channel_id": ce.channelID,
		"client_id":  ce.clientID,
		"conn_id":    ce.connID,
		"topic":      ce.topic,
	}
	return val, nil
}
