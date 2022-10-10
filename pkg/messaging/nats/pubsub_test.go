// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package nats_test

import (
	"fmt"
	"testing"

	"github.com/gogo/protobuf/proto"
	"github.com/mainflux/mainflux/pkg/messaging"
	"github.com/mainflux/mainflux/pkg/messaging/nats"
	"github.com/stretchr/testify/assert"
)

const (
	topic       = "topic"
	chansPrefix = "channels"
	channel     = "9b7b1b3f-b1b0-46a8-a717-b8213f9eda3b"
	subtopic    = "engine"
	clientID    = "9b7b1b3f-b1b0-46a8-a717-b8213f9eda3b"
)

var (
	msgChan = make(chan messaging.Message)
	data    = []byte("payload")
)

func TestPublisher(t *testing.T) {
	// Subscribing with topic, and with subtopic, so that we can publish messages
	conn, err := newConn()
	assert.Nil(t, err, fmt.Sprintf("got unexpected error: %s", err))

	topicSub, err := conn.Subscribe(fmt.Sprintf("%s.%s", chansPrefix, topic), natsHandler(handler{false, "clientIDD"}))
	assert.Nil(t, err, fmt.Sprintf("got unexpected error: %s", err))
	subtopicSub, err := conn.Subscribe(fmt.Sprintf("%s.%s.%s", chansPrefix, topic, subtopic), natsHandler(handler{false, "clientIDD"}))
	assert.Nil(t, err, fmt.Sprintf("got unexpected error: %s", err))

	t.Cleanup(func() {
		topicSub.Unsubscribe()
		subtopicSub.Unsubscribe()
	})

	cases := []struct {
		desc     string
		channel  string
		subtopic string
		payload  []byte
	}{
		{
			desc:    "publish message with nil payload",
			payload: nil,
		},
		{
			desc:    "publish message with string payload",
			payload: data,
		},
		{
			desc:    "publish message with channel",
			payload: data,
			channel: channel,
		},
		{
			desc:     "publish message with subtopic",
			payload:  data,
			subtopic: subtopic,
		},
		{
			desc:     "publish message with channel and subtopic",
			payload:  data,
			channel:  channel,
			subtopic: subtopic,
		},
	}

	for _, tc := range cases {
		expectedMsg := messaging.Message{
			Channel:  tc.channel,
			Subtopic: tc.subtopic,
			Payload:  tc.payload,
		}
		err = pubsub.Publish(topic, expectedMsg)
		assert.Nil(t, err, fmt.Sprintf("%s: got unexpected error: %s", tc.desc, err))

		receivedMsg := <-msgChan
		assert.Equal(t, expectedMsg, receivedMsg, fmt.Sprintf("%s: expected %+v got %+v\n", tc.desc, expectedMsg, receivedMsg))
	}
}

func TestSubscribe(t *testing.T) {
	conn, err := newConn()
	assert.Nil(t, err, fmt.Sprintf("got unexpected error: %s", err))

	cases := []struct {
		desc     string
		topic    string
		clientID string
		err      error
		handler  messaging.MessageHandler
	}{
		{
			desc:     "Subscribe to a topic with an ID",
			topic:    topic,
			clientID: "clientid1",
			err:      nil,
			handler:  handler{false, "clientid1"},
		},
		{
			desc:     "Subscribe to the same topic with a different ID",
			topic:    topic,
			clientID: "clientid2",
			err:      nil,
			handler:  handler{false, "clientid2"},
		},
		{
			desc:     "Subscribe to an already subscribed topic with an ID",
			topic:    topic,
			clientID: "clientid1",
			err:      nil,
			handler:  handler{false, "clientid1"},
		},
		{
			desc:     "Subscribe to a topic with a subtopic with an ID",
			topic:    fmt.Sprintf("%s.%s", topic, subtopic),
			clientID: "clientid1",
			err:      nil,
			handler:  handler{false, "clientid1"},
		},
		{
			desc:     "Subscribe to an already subscribed topic with a subtopic with an ID",
			topic:    fmt.Sprintf("%s.%s", topic, subtopic),
			clientID: "clientid1",
			err:      nil,
			handler:  handler{false, "clientid1"},
		},
		{
			desc:     "Subscribe to an empty topic with an ID",
			topic:    "",
			clientID: "clientid1",
			err:      nats.ErrEmptyTopic,
			handler:  handler{false, "clientid1"},
		},
		{
			desc:     "Subscribe to a topic with empty id",
			topic:    topic,
			clientID: "",
			err:      nats.ErrEmptyID,
			handler:  handler{false, ""},
		},
	}
	for _, tc := range cases {
		err := pubsub.Subscribe(tc.clientID, tc.topic, tc.handler)
		assert.Equal(t, tc.err, err, fmt.Sprintf("%s: expected: %s, but got: %s", tc.desc, tc.err, err))

		if tc.err == nil {
			_, err := conn.Subscribe(tc.topic, natsHandler(handler{false, "clientIDD"}))
			assert.Nil(t, err, fmt.Sprintf("got unexpected error: %s", err))

			expectedMsg := messaging.Message{
				Publisher: "CLIENTID",
				Channel:   channel,
				Subtopic:  subtopic,
				Payload:   data,
			}

			data, err := proto.Marshal(&expectedMsg)
			assert.Nil(t, err, fmt.Sprintf("got unexpected error: %s", err))

			err = conn.Publish(tc.topic, data)
			assert.Nil(t, err, fmt.Sprintf("got unexpected error: %s", err))

			receivedMsg := <-msgChan
			assert.Equal(t, expectedMsg.Payload, receivedMsg.Payload, fmt.Sprintf("%s: expected %+v got %+v\n", tc.desc, expectedMsg, receivedMsg))
		}
	}
}

func TestUnsubscribe(t *testing.T) {
	cases := []struct {
		desc     string
		topic    string
		clientID string
		err      error
		pubsub   bool //true for subscribe and false for unsubscribe
		handler  messaging.MessageHandler
	}{
		{
			desc:     "Subscribe to a topic with an ID",
			topic:    fmt.Sprintf("%s.%s", chansPrefix, topic),
			clientID: "clientid4",
			err:      nil,
			pubsub:   true,
			handler:  handler{false, "clientid4"},
		},
		{
			desc:     "Subscribe to the same topic with a different ID",
			topic:    fmt.Sprintf("%s.%s", chansPrefix, topic),
			clientID: "clientid9",
			err:      nil,
			pubsub:   true,
			handler:  handler{false, "clientid9"},
		},
		{
			desc:     "Unsubscribe from a topic with an ID",
			topic:    fmt.Sprintf("%s.%s", chansPrefix, topic),
			clientID: "clientid4",
			err:      nil,
			pubsub:   false,
			handler:  handler{false, "clientid4"},
		},
		{
			desc:     "Unsubscribe from same topic with different ID",
			topic:    fmt.Sprintf("%s.%s", chansPrefix, topic),
			clientID: "clientid9",
			err:      nil,
			pubsub:   false,
			handler:  handler{false, "clientid9"},
		},
		{
			desc:     "Unsubscribe from a non-existent topic with an ID",
			topic:    "h",
			clientID: "clientid4",
			err:      nats.ErrNotSubscribed,
			pubsub:   false,
			handler:  handler{false, "clientid4"},
		},
		{
			desc:     "Unsubscribe from an already unsubscribed topic with an ID",
			topic:    fmt.Sprintf("%s.%s", chansPrefix, topic),
			clientID: "clientid4",
			err:      nats.ErrNotSubscribed,
			pubsub:   false,
			handler:  handler{false, "clientid4"},
		},
		{
			desc:     "Subscribe to a topic with a subtopic with an ID",
			topic:    fmt.Sprintf("%s.%s.%s", chansPrefix, topic, subtopic),
			clientID: "clientidd4",
			err:      nil,
			pubsub:   true,
			handler:  handler{false, "clientidd4"},
		},
		{
			desc:     "Unsubscribe from a topic with a subtopic with an ID",
			topic:    fmt.Sprintf("%s.%s.%s", chansPrefix, topic, subtopic),
			clientID: "clientidd4",
			err:      nil,
			pubsub:   false,
			handler:  handler{false, "clientidd4"},
		},
		{
			desc:     "Unsubscribe from an already unsubscribed topic with a subtopic with an ID",
			topic:    fmt.Sprintf("%s.%s.%s", chansPrefix, topic, subtopic),
			clientID: "clientid4",
			err:      nats.ErrNotSubscribed,
			pubsub:   false,
			handler:  handler{false, "clientid4"},
		},
		{
			desc:     "Unsubscribe from an empty topic with an ID",
			topic:    "",
			clientID: "clientid4",
			err:      nats.ErrEmptyTopic,
			pubsub:   false,
			handler:  handler{false, "clientid4"},
		},
		{
			desc:     "Unsubscribe from a topic with empty ID",
			topic:    fmt.Sprintf("%s.%s", chansPrefix, topic),
			clientID: "",
			err:      nats.ErrEmptyID,
			pubsub:   false,
			handler:  handler{false, ""},
		},
	}
	for _, tc := range cases {
		switch tc.pubsub {
		case true:
			err := pubsub.Subscribe(tc.clientID, tc.topic, tc.handler)
			assert.Equal(t, err, tc.err, fmt.Sprintf("%s: expected: %s, but got: %s", tc.desc, tc.err, err))
		default:
			err := pubsub.Unsubscribe(tc.clientID, tc.topic)
			assert.Equal(t, err, tc.err, fmt.Sprintf("%s: expected: %s, but got: %s", tc.desc, tc.err, err))
		}
	}
}

func TestPubSub(t *testing.T) {
	cases := []struct {
		desc     string
		topic    string
		clientID string
		err      error
		handler  messaging.MessageHandler
	}{
		{
			desc:     "Subscribe to a topic with an ID",
			topic:    topic,
			clientID: clientID,
			err:      nil,
			handler:  handler{false, clientID},
		},
		{
			desc:     "Subscribe to the same topic with a different ID",
			topic:    topic,
			clientID: clientID + "1",
			err:      nil,
			handler:  handler{false, clientID + "1"},
		},
		{
			desc:     "Subscribe to a topic with a subtopic with an ID",
			topic:    fmt.Sprintf("%s.%s", topic, subtopic),
			clientID: clientID + "2",
			err:      nil,
			handler:  handler{false, clientID + "2"},
		},
		{
			desc:     "Subscribe to an empty topic with an ID",
			topic:    "",
			clientID: clientID,
			err:      nats.ErrEmptyTopic,
			handler:  handler{false, clientID},
		},
		{
			desc:     "Subscribe to a topic with empty id",
			topic:    topic,
			clientID: "",
			err:      nats.ErrEmptyID,
			handler:  handler{false, ""},
		},
	}
	for _, tc := range cases {
		subject := ""
		if tc.topic != "" {
			subject = fmt.Sprintf("%s.%s", chansPrefix, tc.topic)
		}
		err := pubsub.Subscribe(tc.clientID, subject, tc.handler)

		switch tc.err {
		case nil:
			assert.Nil(t, err, fmt.Sprintf("%s got unexpected error: %s", tc.desc, err))

			// if no error, publish message, and receive after subscribing
			expectedMsg := messaging.Message{
				Channel: channel,
				Payload: data,
			}

			err = pubsub.Publish(tc.topic, expectedMsg)
			assert.Nil(t, err, fmt.Sprintf("%s got unexpected error: %s", tc.desc, err))

			receivedMsg := <-msgChan
			assert.Equal(t, expectedMsg.Payload, receivedMsg.Payload, fmt.Sprintf("%s: expected %+v got %+v\n", tc.desc, expectedMsg, receivedMsg))

			err = pubsub.Unsubscribe(tc.clientID, fmt.Sprintf("%s.%s", chansPrefix, tc.topic))
			assert.Nil(t, err, fmt.Sprintf("%s got unexpected error: %s", tc.desc, err))
		default:
			assert.Equal(t, tc.err, err, fmt.Sprintf("%s: expected: %s, but got: %s", tc.desc, err, tc.err))
		}
	}
}

type handler struct {
	fail      bool
	publisher string
}

func (h handler) Handle(msg messaging.Message) error {
	if msg.Publisher != h.publisher {
		msgChan <- msg
	}
	return nil
}

func (h handler) Cancel() error {
	if h.fail {
		return nats.ErrFailed
	}
	return nil
}
