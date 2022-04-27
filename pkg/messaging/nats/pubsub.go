// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package nats

import (
	"errors"
	"fmt"
	"sync"

	"github.com/gogo/protobuf/proto"

	log "github.com/mainflux/mainflux/logger"
	"github.com/mainflux/mainflux/pkg/messaging"
	broker "github.com/nats-io/nats.go"
)

const chansPrefix = "channels"

// SubjectAllChannels represents subject to subscribe for all the channels.
const SubjectAllChannels = "channels.>"

var (
	errAlreadySubscribed = errors.New("already subscribed to topic")
	errNotSubscribed     = errors.New("not subscribed")
	errEmptyTopic        = errors.New("empty topic")
	errEmptyID           = errors.New("empty ID")
)

var _ messaging.PubSub = (*pubsub)(nil)

// PubSub wraps messaging Publisher exposing
// Close() method for NATS connection.
type PubSub interface {
	messaging.PubSub
	Close()
}

type pubsub struct {
	conn          *broker.Conn
	logger        log.Logger
	mu            sync.Mutex
	queue         string
	subscriptions map[string]map[string]*broker.Subscription
}

// NewPubSub returns NATS message publisher/subscriber.
// Parameter queue specifies the queue for the Subscribe method.
// If queue is specified (is not an empty string), Subscribe method
// will execute NATS QueueSubscribe which is conceptually different
// from ordinary subscribe. For more information, please take a look
// here: https://docs.nats.io/developing-with-nats/receiving/queues.
// If the queue is empty, Subscribe will be used.
func NewPubSub(url, queue string, logger log.Logger) (PubSub, error) {
	conn, err := broker.Connect(url)
	if err != nil {
		return nil, err
	}
	ret := &pubsub{
		conn:          conn,
		queue:         queue,
		logger:        logger,
		subscriptions: make(map[string]map[string]*broker.Subscription),
	}
	return ret, nil
}

func (ps *pubsub) Publish(topic string, msg messaging.Message) error {
	data, err := proto.Marshal(&msg)
	if err != nil {
		return err
	}

	subject := fmt.Sprintf("%s.%s", chansPrefix, topic)
	if msg.Subtopic != "" {
		subject = fmt.Sprintf("%s.%s", subject, msg.Subtopic)
	}
	if err := ps.conn.Publish(subject, data); err != nil {
		return err
	}

	return nil
}

func (ps *pubsub) Subscribe(id, topic string, handler messaging.MessageHandler) error {
	if id == "" {
		return errEmptyID
	}
	if topic == "" {
		return errEmptyTopic
	}
	ps.mu.Lock()
	defer ps.mu.Unlock()
	// If there are no subscription, create an empty map assigned to the topic.
	subscription, ok := ps.subscriptions[topic]
	if !ok {
		subscription = map[string]*broker.Subscription{}
	}
	// If subscription exists return already subscribed.
	if _, ok := subscription[id]; ok {
		return errAlreadySubscribed
	}
	nh := ps.natsHandler(handler)

	if ps.queue != "" {
		sub, err := ps.conn.QueueSubscribe(topic, ps.queue, nh)
		if err != nil {
			return err
		}
		subscription[id] = sub
		return nil
	}
	sub, err := ps.conn.Subscribe(topic, nh)
	if err != nil {
		return err
	}
	subscription[id] = sub
	return nil
}

func (ps *pubsub) Unsubscribe(id, topic string) error {
	if id == "" {
		return errEmptyID
	}
	if topic == "" {
		return errEmptyTopic
	}
	ps.mu.Lock()
	defer ps.mu.Unlock()

	subscriptions, ok := ps.subscriptions[topic]
	if !ok {
		return errNotSubscribed
	}
	if current, ok := subscriptions[id]; ok {
		if err := current.Unsubscribe(); err != nil {
			return err
		}
	}

	delete(subscriptions, id)
	// If there are no observers left for the endpint, remove the map.
	if len(subscriptions) == 0 {
		delete(ps.subscriptions, topic)
	}
	return nil
}

func (ps *pubsub) Close() {
	ps.conn.Close()
}

func (ps *pubsub) natsHandler(h messaging.MessageHandler) broker.MsgHandler {
	return func(m *broker.Msg) {
		var msg messaging.Message
		if err := proto.Unmarshal(m.Data, &msg); err != nil {
			ps.logger.Warn(fmt.Sprintf("Failed to unmarshal received message: %s", err))
			return
		}
		if err := h(msg); err != nil {
			ps.logger.Warn(fmt.Sprintf("Failed to handle Mainflux message: %s", err))
		}
	}
}
