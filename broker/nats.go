// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package broker

import (
	"context"
	"fmt"

	"github.com/gogo/protobuf/proto"
	"github.com/mainflux/mainflux/errors"
	"github.com/nats-io/nats.go"
)

// Nats specifies a NATS message API.
type Nats interface {
	// Publish publishes message to the msessage broker.
	Publish(context.Context, string, Message) error

	// Subscribe subscribes to the message broker for a given channel ID and subtopic.
	Subscribe(string, string, func(msg *nats.Msg)) (*nats.Subscription, error)

	// Subscribe subscribes to the message broker for a given channel ID and subtopic.
	QueueSubscribe(string, string, func(msg *nats.Msg)) (*nats.Subscription, error)

	// Close closes NATS connection.
	Close()
}

// SubjectAllChannels allows to subscribe to all subjects of all channels
const (
	prefix             = "channel"
	SubjectAllChannels = "channel.>"
)

var errNatsConn = errors.New("Failed to connect to NATS")

var _ Nats = (*broker)(nil)

type broker struct {
	conn *nats.Conn
}

// New returns NATS message broker.
func New(url string) (Nats, error) {
	nc, err := nats.Connect(url)
	if err != nil {
		return nil, errors.Wrap(errNatsConn, err)
	}

	return &broker{
		conn: nc,
	}, nil
}

func (b broker) Publish(_ context.Context, _ string, msg Message) error {
	data, err := proto.Marshal(&msg)
	if err != nil {
		return err
	}

	subject := fmt.Sprintf("%s.%s", prefix, msg.Channel)
	if msg.Subtopic != "" {
		subject = fmt.Sprintf("%s.%s", subject, msg.Subtopic)
	}
	return b.conn.Publish(subject, data)
}

func fmtSubject(chanID, subtopic string) string {
	subject := fmt.Sprintf("%s.%s", prefix, chanID)
	if subtopic != "" {
		subject = fmt.Sprintf("%s.%s", subject, subtopic)
	}
	return subject
}

func (b broker) Subscribe(chanID, subtopic string, f func(msg *nats.Msg)) (*nats.Subscription, error) {
	subject := fmtSubject(chanID, subtopic)
	sub, err := b.conn.Subscribe(subject, f)
	if err != nil {
		return nil, err
	}

	return sub, nil
}

func (b broker) QueueSubscribe(subject, queue string, f func(msg *nats.Msg)) (*nats.Subscription, error) {
	sub, err := b.conn.QueueSubscribe(subject, queue, f)
	if err != nil {
		return nil, err
	}

	return sub, nil
}

func (b broker) Close() {
	b.conn.Close()
}
