// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package mqtt

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/absmach/mgate/pkg/session"
	grpcChannelsV1 "github.com/absmach/supermq/api/grpc/channels/v1"
	grpcClientsV1 "github.com/absmach/supermq/api/grpc/clients/v1"
	"github.com/absmach/supermq/mqtt/events"
	"github.com/absmach/supermq/pkg/connections"
	"github.com/absmach/supermq/pkg/errors"
	svcerr "github.com/absmach/supermq/pkg/errors/service"
	"github.com/absmach/supermq/pkg/messaging"
	"github.com/absmach/supermq/pkg/policies"
)

var _ session.Handler = (*handler)(nil)

const protocol = "mqtt"

// Log message formats.
const (
	LogInfoSubscribed   = "subscribed with client_id %s to topics %s"
	LogInfoUnsubscribed = "unsubscribed client_id %s from topics %s"
	LogInfoConnected    = "connected with client_id %s"
	LogInfoDisconnected = "disconnected client_id %s and username %s"
	LogInfoPublished    = "published with client_id %s to the topic %s"
)

// Error wrappers for MQTT errors.
var (
	ErrMalformedSubtopic            = errors.New("malformed subtopic")
	ErrClientNotInitialized         = errors.New("client is not initialized")
	ErrMalformedTopic               = errors.New("malformed topic")
	ErrMissingClientID              = errors.New("client_id not found")
	ErrMissingTopicPub              = errors.New("failed to publish due to missing topic")
	ErrMissingTopicSub              = errors.New("failed to subscribe due to missing topic")
	ErrFailedConnect                = errors.New("failed to connect")
	ErrFailedSubscribe              = errors.New("failed to subscribe")
	ErrFailedUnsubscribe            = errors.New("failed to unsubscribe")
	ErrFailedPublish                = errors.New("failed to publish")
	ErrFailedDisconnect             = errors.New("failed to disconnect")
	ErrFailedPublishDisconnectEvent = errors.New("failed to publish disconnect event")
	ErrFailedParseSubtopic          = errors.New("failed to parse subtopic")
	ErrFailedPublishConnectEvent    = errors.New("failed to publish connect event")
	ErrFailedPublishToMsgBroker     = errors.New("failed to publish to supermq message broker")
	ErrFailedPublishEvent           = errors.New("failed to publish event")
	ErrFailedSubscribeEvent         = errors.New("failed to publish subscribe event")
	ErrFailedUnsubscribeEvent       = errors.New("failed to publish unsubscribe event")
	errMissingTopicSub              = errors.New("failed to subscribe due to missing topic")
)

var (
	errInvalidUserId = errors.New("invalid user id")
	channelRegExp    = regexp.MustCompile(`^\/?channels\/([\w\-]+)\/messages(\/[^?]*)?(\?.*)?$`)
)

// Event implements events.Event interface.
type handler struct {
	publisher messaging.Publisher
	clients   grpcClientsV1.ClientsServiceClient
	channels  grpcChannelsV1.ChannelsServiceClient
	logger    *slog.Logger
	es        events.EventStore
}

// NewHandler creates new Handler entity.
func NewHandler(publisher messaging.Publisher, es events.EventStore, logger *slog.Logger, clients grpcClientsV1.ClientsServiceClient, channels grpcChannelsV1.ChannelsServiceClient) session.Handler {
	return &handler{
		es:        es,
		logger:    logger,
		publisher: publisher,
		clients:   clients,
		channels:  channels,
	}
}

// AuthConnect is called on device connection,
// prior forwarding to the MQTT broker.
func (h *handler) AuthConnect(ctx context.Context) error {
	s, ok := session.FromContext(ctx)
	if !ok {
		return ErrClientNotInitialized
	}

	if s.ID == "" {
		return ErrMissingClientID
	}

	pwd := string(s.Password)

	res, err := h.clients.Authenticate(ctx, &grpcClientsV1.AuthnReq{ClientSecret: pwd})
	if err != nil {
		return errors.Wrap(svcerr.ErrAuthentication, err)
	}
	if !res.GetAuthenticated() {
		return svcerr.ErrAuthentication
	}

	if s.Username != "" && res.GetId() != s.Username {
		return errInvalidUserId
	}

	if err := h.es.Connect(ctx, s.Username, s.ID); err != nil {
		h.logger.Error(errors.Wrap(ErrFailedPublishConnectEvent, err).Error())
	}

	return nil
}

// AuthPublish is called on device publish,
// prior forwarding to the MQTT broker.
func (h *handler) AuthPublish(ctx context.Context, topic *string, payload *[]byte) error {
	if topic == nil {
		return ErrMissingTopicPub
	}
	s, ok := session.FromContext(ctx)
	if !ok {
		return ErrClientNotInitialized
	}

	return h.authAccess(ctx, string(s.Username), *topic, connections.Publish)
}

// AuthSubscribe is called on device subscribe,
// prior forwarding to the MQTT broker.
func (h *handler) AuthSubscribe(ctx context.Context, topics *[]string) error {
	s, ok := session.FromContext(ctx)
	if !ok {
		return ErrClientNotInitialized
	}
	if topics == nil || *topics == nil {
		return ErrMissingTopicSub
	}

	for _, topic := range *topics {
		if err := h.authAccess(ctx, string(s.Username), topic, connections.Subscribe); err != nil {
			return err
		}
	}

	return nil
}

// Connect - after client successfully connected.
func (h *handler) Connect(ctx context.Context) error {
	s, ok := session.FromContext(ctx)
	if !ok {
		return errors.Wrap(ErrFailedConnect, ErrClientNotInitialized)
	}
	h.logger.Info(fmt.Sprintf(LogInfoConnected, s.ID))
	return nil
}

// Publish - after client successfully published.
func (h *handler) Publish(ctx context.Context, topic *string, payload *[]byte) error {
	s, ok := session.FromContext(ctx)
	if !ok {
		return errors.Wrap(ErrFailedPublish, ErrClientNotInitialized)
	}
	h.logger.Info(fmt.Sprintf(LogInfoPublished, s.ID, *topic))
	// Topics are in the format:
	// channels/<channel_id>/messages/<subtopic>/.../ct/<content_type>

	chanID, subtopic, err := parseTopic(*topic)
	if err != nil {
		return err
	}

	msg := messaging.Message{
		Protocol:  protocol,
		Channel:   chanID,
		Subtopic:  subtopic,
		Publisher: s.Username,
		Payload:   *payload,
		Created:   time.Now().UnixNano(),
	}

	if err := h.publisher.Publish(ctx, msg.GetChannel(), &msg); err != nil {
		return errors.Wrap(ErrFailedPublishToMsgBroker, err)
	}
	if err := h.es.Publish(ctx, msg.Publisher, msg.Channel, msg.Subtopic); err != nil {
		return errors.Wrap(ErrFailedPublishEvent, err)
	}

	return nil
}

// Subscribe - after client successfully subscribed.
func (h *handler) Subscribe(ctx context.Context, topics *[]string) error {
	s, ok := session.FromContext(ctx)
	if !ok {
		return errors.Wrap(ErrFailedSubscribe, ErrClientNotInitialized)
	}

	for _, topic := range *topics {
		channelID, subTopic, err := parseTopic(topic)
		if err != nil {
			return err
		}
		if err := h.es.Subscribe(ctx, s.Username, channelID, s.ID, subTopic); err != nil {
			return errors.Wrap(ErrFailedUnsubscribeEvent, err)
		}
	}

	h.logger.Info(fmt.Sprintf(LogInfoSubscribed, s.ID, strings.Join(*topics, ",")))

	return nil
}

// Unsubscribe - after client unsubscribed.
func (h *handler) Unsubscribe(ctx context.Context, topics *[]string) error {
	s, ok := session.FromContext(ctx)
	if !ok {
		return errors.Wrap(ErrFailedUnsubscribe, ErrClientNotInitialized)
	}

	if topics == nil || *topics == nil {
		return errMissingTopicSub
	}

	for _, topic := range *topics {
		channelID, subTopic, err := parseTopic(topic)
		if err != nil {
			return err
		}
		if err := h.es.Unsubscribe(ctx, s.Username, channelID, s.ID, subTopic); err != nil {
			return errors.Wrap(ErrFailedUnsubscribeEvent, err)
		}
	}

	h.logger.Info(fmt.Sprintf(LogInfoUnsubscribed, s.ID, strings.Join(*topics, ",")))
	return nil
}

// Disconnect - connection with broker or client lost.
func (h *handler) Disconnect(ctx context.Context) error {
	s, ok := session.FromContext(ctx)
	if !ok {
		return errors.Wrap(ErrFailedDisconnect, ErrClientNotInitialized)
	}
	h.logger.Error(fmt.Sprintf(LogInfoDisconnected, s.ID, s.Password))
	if err := h.es.Disconnect(ctx, s.Username, s.ID); err != nil {
		return errors.Wrap(ErrFailedPublishDisconnectEvent, err)
	}
	return nil
}

func (h *handler) authAccess(ctx context.Context, clientID, topic string, msgType connections.ConnType) error {
	// Topics are in the format:
	// channels/<channel_id>/messages/<subtopic>/.../ct/<content_type>
	chanID, _, err := parseTopic(topic)
	if err != nil {
		return err
	}

	ar := &grpcChannelsV1.AuthzReq{
		Type:       uint32(msgType),
		ClientId:   clientID,
		ClientType: policies.ClientType,
		ChannelId:  chanID,
	}
	res, err := h.channels.Authorize(ctx, ar)
	if err != nil {
		return err
	}
	if !res.GetAuthorized() {
		return svcerr.ErrAuthorization
	}

	return nil
}

func parseTopic(topic string) (string, string, error) {
	channelParts := channelRegExp.FindStringSubmatch(topic)
	if len(channelParts) < 2 {
		return "", "", errors.Wrap(ErrFailedPublish, ErrMalformedTopic)
	}

	chanID := channelParts[1]
	subtopic := channelParts[2]

	subtopic, err := parseSubtopic(subtopic)
	if err != nil {
		return "", "", errors.Wrap(ErrFailedParseSubtopic, err)
	}

	return chanID, subtopic, nil
}

func parseSubtopic(subtopic string) (string, error) {
	if subtopic == "" {
		return subtopic, nil
	}

	subtopic, err := url.QueryUnescape(subtopic)
	if err != nil {
		return "", ErrMalformedSubtopic
	}
	subtopic = strings.ReplaceAll(subtopic, "/", ".")

	elems := strings.Split(subtopic, ".")
	filteredElems := []string{}
	for _, elem := range elems {
		if elem == "" {
			continue
		}

		if len(elem) > 1 && (strings.Contains(elem, "*") || strings.Contains(elem, ">")) {
			return "", ErrMalformedSubtopic
		}

		filteredElems = append(filteredElems, elem)
	}

	subtopic = strings.Join(filteredElems, ".")
	return subtopic, nil
}
