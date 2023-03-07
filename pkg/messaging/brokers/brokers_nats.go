//go:build !rabbitmq
// +build !rabbitmq

// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package brokers

import (
	"log"

	"github.com/mainflux/mainflux/logger"
	"github.com/mainflux/mainflux/pkg/messaging"
	"github.com/mainflux/mainflux/pkg/messaging/nats"
	"github.com/opentracing/opentracing-go"
)

// SubjectAllChannels represents subject to subscribe for all the channels.
const SubjectAllChannels = "channels.>"

func init() {
	log.Println("The binary was build using Nats as the message broker")
}

func NewPublisher(url string) (messaging.Publisher, error) {
	pb, err := nats.NewPublisher(url)
	if err != nil {
		return nil, err
	}
	return pb, nil

}

func NewPubSub(url, queue string, logger logger.Logger, tracer opentracing.Tracer) (messaging.PubSub, error) {
	pb, err := nats.NewPubSub(url, queue, logger, tracer)
	if err != nil {
		return nil, err
	}
	return pb, nil
}
