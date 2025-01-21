// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package events

const (
	coapPrefix        = "coap"
	clientPublish     = coapPrefix + ".client_publish"
	clientSubscribe   = coapPrefix + ".client_subscribe"
	clientUnsubscribe = coapPrefix + ".client_unsubscribe"
)

type clientPublishEvent struct {
	ChannelID string
	ClientID  string
	Topic     string
}

func (cpe clientPublishEvent) Encode() (map[string]interface{}, error) {
	val := map[string]interface{}{
		"operation":  clientPublish,
		"channel_id": cpe.ChannelID,
		"client_id":  cpe.ClientID,
		"topic":      cpe.Topic,
	}
	return val, nil
}

type clientSubscribeEvent struct {
	ChannelID string
	ClientID  string
	Topic     string
}

func (cse clientSubscribeEvent) Encode() (map[string]interface{}, error) {
	val := map[string]interface{}{
		"operation":  clientSubscribe,
		"channel_id": cse.ChannelID,
		"client_id":  cse.ClientID,
		"topic":      cse.Topic,
	}
	return val, nil
}

type clientUnsubscribeEvent struct {
	ChannelID string
	ClientID  string
	Topic     string
}

func (cse clientUnsubscribeEvent) Encode() (map[string]interface{}, error) {
	val := map[string]interface{}{
		"operation":  clientUnsubscribe,
		"channel_id": cse.ChannelID,
		"client_id":  cse.ClientID,
		"topic":      cse.Topic,
	}
	return val, nil
}
