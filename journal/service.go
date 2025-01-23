// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package journal

import (
	"context"
	"fmt"
	"time"

	"github.com/absmach/supermq"
	smqauthn "github.com/absmach/supermq/pkg/authn"
	"github.com/absmach/supermq/pkg/errors"
	svcerr "github.com/absmach/supermq/pkg/errors/service"
)

const (
	clientCreate    = "client.create"
	clientRemove    = "client.remove"
	coapSubscribe   = "coap.client_subscribe"
	coapUnsubscribe = "coap.client_unsubscribe"
	coapPublish     = "coap.client_publish"
	httpPublish     = "http.client_publish"
	mqttSubscribe   = "mqtt.client_subscribe"
	mqttUnsubscribe = "mqtt.client_unsubscribe"
	mqttPublish     = "mqtt.client_publish"
	mqttDisconnect  = "mqtt.client_disconnect"
	wsSubscribe     = "ws.client_subscribe"
	wsUnsubscribe   = "ws.client_unsubscribe"
	wsPublish       = "ws.client_publish"
)

type service struct {
	idProvider supermq.IDProvider
	repository Repository
}

func NewService(idp supermq.IDProvider, repository Repository) Service {
	return &service{
		idProvider: idp,
		repository: repository,
	}
}

func (svc *service) Save(ctx context.Context, journal Journal) error {
	id, err := svc.idProvider.ID()
	if err != nil {
		return err
	}
	journal.ID = id

	if err := svc.repository.Save(ctx, journal); err != nil {
		return err
	}
	if err := svc.handleTelemetry(ctx, journal); err != nil {
		return err
	}

	return nil
}

func (svc *service) RetrieveAll(ctx context.Context, session smqauthn.Session, page Page) (JournalsPage, error) {
	journalPage, err := svc.repository.RetrieveAll(ctx, page)
	if err != nil {
		return JournalsPage{}, errors.Wrap(svcerr.ErrViewEntity, err)
	}

	return journalPage, nil
}

func (svc *service) RetrieveClientTelemetry(ctx context.Context, session smqauthn.Session, clientID string) (ClientTelemetry, error) {
	ct, err := svc.repository.RetrieveClientTelemetry(ctx, clientID, session.DomainID)
	if err != nil {
		return ClientTelemetry{}, errors.Wrap(svcerr.ErrViewEntity, err)
	}

	return ct, nil
}

func (svc *service) handleTelemetry(ctx context.Context, journal Journal) error {
	switch journal.Operation {
	case clientCreate:
		return svc.addClientTelemetry(ctx, journal)

	case clientRemove:
		return svc.removeClientTelemetry(ctx, journal)

	case coapSubscribe, mqttSubscribe, wsSubscribe:
		return svc.addSubscription(ctx, journal)

	case coapUnsubscribe, mqttUnsubscribe, wsUnsubscribe:
		return svc.removeSubscription(ctx, journal)

	case coapPublish, httpPublish, mqttPublish, wsPublish:
		return svc.updateMessageCount(ctx, journal)

	case mqttDisconnect:
		return svc.removeSubscriptionWithConnID(ctx, journal)

	default:
		return nil
	}
}

func (svc *service) addClientTelemetry(ctx context.Context, journal Journal) error {
	ce, err := toClientEvent(journal)
	if err != nil {
		return err
	}
	ct := ClientTelemetry{
		ClientID:  ce.id,
		DomainID:  ce.domain,
		FirstSeen: ce.createdAt,
		LastSeen:  ce.createdAt,
	}
	return svc.repository.SaveClientTelemetry(ctx, ct)
}

func (svc *service) removeClientTelemetry(ctx context.Context, journal Journal) error {
	ce, err := toClientEvent(journal)
	if err != nil {
		return err
	}
	return svc.repository.DeleteClientTelemetry(ctx, ce.id, ce.domain)
}

func (svc *service) addSubscription(ctx context.Context, journal Journal) error {
	ae, err := toAdapterEvent(journal)
	if err != nil {
		return err
	}
	sub := fmt.Sprintf("%s:%s:%s", ae.connID, ae.channelID, ae.topic)
	return svc.repository.AddSubscription(ctx, ae.clientID, sub)
}

func (svc *service) removeSubscription(ctx context.Context, journal Journal) error {
	ae, err := toAdapterEvent(journal)
	if err != nil {
		return err
	}
	sub := fmt.Sprintf("%s:%s:%s", ae.connID, ae.channelID, ae.topic)
	return svc.repository.RemoveSubscription(ctx, ae.clientID, sub)
}

func (svc *service) updateMessageCount(ctx context.Context, journal Journal) error {
	ae, err := toAdapterEvent(journal)
	if err != nil {
		return err
	}
	if err := svc.repository.IncrementInboundMessages(ctx, ae.clientID); err != nil {
		return err
	}
	if err := svc.repository.IncrementOutboundMessages(ctx, ae.channelID, ae.topic); err != nil {
		return err
	}
	return nil
}

func (svc *service) removeSubscriptionWithConnID(ctx context.Context, journal Journal) error {
	ae, err := toAdapterEvent(journal)
	if err != nil {
		return err
	}

	return svc.repository.RemoveSubscriptionWithConnID(ctx, ae.connID, ae.clientID)
}

type clientEvent struct {
	id        string
	domain    string
	createdAt time.Time
}

func toClientEvent(journal Journal) (clientEvent, error) {
	var createdAt time.Time
	var err error
	id, ok := journal.Attributes["id"].(string)
	if !ok {
		return clientEvent{}, fmt.Errorf("invalid id attribute")
	}
	domain, ok := journal.Attributes["domain"].(string)
	if !ok {
		return clientEvent{}, fmt.Errorf("invalid domain attribute")
	}
	createdAtStr := journal.Attributes["created_at"].(string)
	if createdAtStr == "" {
		createdAt, err = time.Parse(time.RFC3339, createdAtStr)
		if err != nil {
			return clientEvent{}, fmt.Errorf("invalid created_at format")
		}
	}
	return clientEvent{
		id:        id,
		domain:    domain,
		createdAt: createdAt,
	}, nil
}

type adapterEvent struct {
	clientID  string
	connID    string
	channelID string
	topic     string
}

func toAdapterEvent(journal Journal) (adapterEvent, error) {
	clientID := journal.Attributes["client_id"].(string)
	connID := journal.Attributes["conn_id"].(string)
	channelID := journal.Attributes["channel_id"].(string)
	topic := journal.Attributes["topic"].(string)
	return adapterEvent{
		clientID:  clientID,
		connID:    connID,
		channelID: channelID,
		topic:     topic,
	}, nil
}
