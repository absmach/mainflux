// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package rabbitmq

import (
	"context"
	"fmt"
	"strings"

	"github.com/mainflux/mainflux/pkg/messaging"
	amqp "github.com/rabbitmq/amqp091-go"
	"google.golang.org/protobuf/proto"
)

var _ messaging.Publisher = (*publisher)(nil)

type publisher struct {
	conn   *amqp.Connection
	ch     *amqp.Channel
	prefix string
}

// NewPublisher returns RabbitMQ message Publisher.
func NewPublisher(url string, opts ...messaging.Option) (messaging.Publisher, error) {
	conn, err := amqp.Dial(url)
	if err != nil {
		return nil, err
	}
	ch, err := conn.Channel()
	if err != nil {
		return nil, err
	}
	if err := ch.ExchangeDeclare(exchangeName, amqp.ExchangeTopic, true, false, false, false, nil); err != nil {
		return nil, err
	}

	ret := &publisher{
		conn:   conn,
		ch:     ch,
		prefix: chansPrefix,
	}

	for _, opt := range opts {
		if err := opt(url, ret.prefix); err != nil {
			return nil, err
		}
	}

	return ret, nil
}

func (pub *publisher) Publish(ctx context.Context, topic string, msg *messaging.Message) error {
	if topic == "" {
		return ErrEmptyTopic
	}
	data, err := proto.Marshal(msg)
	if err != nil {
		return err
	}

	subject := fmt.Sprintf("%s.%s", pub.prefix, topic)
	if msg.Subtopic != "" {
		subject = fmt.Sprintf("%s.%s", subject, msg.Subtopic)
	}
	subject = formatTopic(subject)

	err = pub.ch.PublishWithContext(
		ctx,
		exchangeName,
		subject,
		false,
		false,
		amqp.Publishing{
			Headers:     amqp.Table{},
			ContentType: "application/octet-stream",
			AppId:       "mainflux-publisher",
			Body:        data,
		})

	if err != nil {
		return err
	}

	return nil
}

func (pub *publisher) Close() error {
	if err := pub.ch.Close(); err != nil {
		return err
	}
	return pub.conn.Close()
}

func formatTopic(topic string) string {
	return strings.ReplaceAll(topic, ">", "#")
}
