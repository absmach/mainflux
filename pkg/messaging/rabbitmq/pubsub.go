// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package rabbitmq

import (
	"errors"
	"fmt"
	"sync"

	"github.com/gogo/protobuf/proto"
	log "github.com/mainflux/mainflux/logger"
	"github.com/mainflux/mainflux/pkg/messaging"
	amqp "github.com/rabbitmq/amqp091-go"
)

const (
	chansPrefix = "channels"
	// SubjectAllChannels represents subject to subscribe for all the channels.
	SubjectAllChannels = "channels.>"
	exchangeName       = "mainflux-exchange"
	exchangeKind       = "direct"
)

var (
	ErrAlreadySubscribed = errors.New("already subscribed to topic")
	ErrNotSubscribed     = errors.New("not subscribed")
	ErrEmptyTopic        = errors.New("empty topic")
	ErrEmptyID           = errors.New("empty id")
)

var _ messaging.PubSub = (*pubsub)(nil)

// PubSub wraps messaging Publisher exposing
// Close() method for RabbitMQ connection.
type PubSub interface {
	messaging.PubSub
	Close()
}

type subscription struct {
	cancel func() error
}
type pubsub struct {
	publisher
	logger        log.Logger
	subscriptions map[string]map[string]subscription
	mu            sync.Mutex
}

// NewPubSub returns RabbitMQ message publisher/subscriber.
func NewPubSub(url, queueName string, logger log.Logger) (PubSub, error) {
	endpoint := fmt.Sprintf("amqp://%s", url)
	conn, err := amqp.Dial(endpoint)
	if err != nil {
		return nil, err
	}
	ch, err := conn.Channel()
	if err != nil {
		return nil, err
	}
	if err := ch.ExchangeDeclare(exchangeName, amqp.ExchangeDirect, true, false, false, false, nil); err != nil {
		return nil, err
	}
	ret := &pubsub{
		publisher: publisher{
			conn: conn,
			ch:   ch,
		},
		logger:        logger,
		subscriptions: make(map[string]map[string]subscription),
	}
	return ret, nil
}

func (ps *pubsub) Subscribe(id, topic string, handler messaging.MessageHandler) error {
	if id == "" {
		return ErrEmptyID
	}
	if topic == "" {
		return ErrEmptyTopic
	}
	ps.mu.Lock()
	defer ps.mu.Unlock()
	// Check topic
	s, ok := ps.subscriptions[topic]
	switch ok {
	case true:
		// Check topic ID
		if _, ok := s[id]; ok {
			return ErrAlreadySubscribed
		}
	default:
		s = make(map[string]subscription)
		ps.subscriptions[topic] = s
	}
	_, err := ps.ch.QueueDeclare(topic, true, true, true, false, nil)
	if err != nil {
		return err
	}
	if err := ps.ch.QueueBind(topic, topic, exchangeName, false, nil); err != nil {
		return err
	}
	msgs, err := ps.ch.Consume(topic, id, true, false, false, false, nil)
	if err != nil {
		return err
	}

	go ps.handle(msgs, handler)
	s[id] = subscription{
		cancel: handler.Cancel,
	}

	return nil
}

func (ps *pubsub) Unsubscribe(id, topic string) error {
	defer ps.ch.Cancel(id, false)
	if id == "" {
		return ErrEmptyID
	}
	if topic == "" {
		return ErrEmptyTopic
	}
	ps.mu.Lock()
	defer ps.mu.Unlock()

	// Check topic
	s, ok := ps.subscriptions[topic]
	if !ok {
		return ErrNotSubscribed
	}
	// Check topic ID
	current, ok := s[id]
	if !ok {
		return ErrNotSubscribed
	}
	if err := ps.ch.QueueUnbind(topic, topic, exchangeName, nil); err != nil {
		return err
	}
	if current.cancel != nil {
		if err := current.cancel(); err != nil {
			return err
		}
	}

	delete(s, id)
	if len(s) == 0 {
		delete(ps.subscriptions, topic)
	}
	return nil
}

func (ps *pubsub) handle(deliveries <-chan amqp.Delivery, h messaging.MessageHandler) {
	for d := range deliveries {
		var msg messaging.Message
		if err := proto.Unmarshal(d.Body, &msg); err != nil {
			ps.logger.Warn(fmt.Sprintf("Failed to unmarshal received message: %s", err))
			return
		}
		if err := h.Handle(msg); err != nil {
			ps.logger.Warn(fmt.Sprintf("Failed to handle Mainflux message: %s", err))
			return
		}
	}
}
