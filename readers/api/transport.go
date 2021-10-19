// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	kithttp "github.com/go-kit/kit/transport/http"
	"github.com/go-zoo/bone"
	"github.com/mainflux/mainflux"
	"github.com/mainflux/mainflux/internal/httputil"
	"github.com/mainflux/mainflux/pkg/errors"
	"github.com/mainflux/mainflux/readers"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	contentType    = "application/json"
	offsetKey      = "offset"
	limitKey       = "limit"
	formatKey      = "format"
	subtopicKey    = "subtopic"
	publisherKey   = "publisher"
	protocolKey    = "protocol"
	nameKey        = "name"
	valueKey       = "v"
	stringValueKey = "vs"
	dataValueKey   = "vd"
	comparatorKey  = "comparator"
	fromKey        = "from"
	toKey          = "to"
	defLimit       = 10
	defOffset      = 0
	defFormat      = "messages"
	thingToken     = "Thing "
	userToken      = "Bearer "
)

var (
	errUnauthorizedAccess  = errors.New("missing or invalid credentials provided")
	errCannotAuthorizeUser = errors.New("authorization failed")
	errThingAccess         = errors.New("thing has no permission")
	errUserAccess          = errors.New("user has no permission")
	errWrongToken          = errors.New("incorrect or missing Authorization header")
	thingsAuth             mainflux.ThingsServiceClient
	usersAuth              mainflux.AuthServiceClient
)

// MakeHandler returns a HTTP handler for API endpoints.
func MakeHandler(svc readers.MessageRepository, tc mainflux.ThingsServiceClient, uc mainflux.AuthServiceClient, svcName string) http.Handler {
	thingsAuth = tc
	usersAuth = uc

	opts := []kithttp.ServerOption{
		kithttp.ServerErrorEncoder(encodeError),
	}

	mux := bone.New()
	mux.Get("/channels/:chanID/messages", kithttp.NewServer(
		listMessagesEndpoint(svc),
		decodeList,
		encodeResponse,
		opts...,
	))

	mux.GetFunc("/health", mainflux.Health(svcName))
	mux.Handle("/metrics", promhttp.Handler())

	return mux
}

func decodeList(ctx context.Context, r *http.Request) (interface{}, error) {
	chanID := bone.GetValue(r, "chanID")
	if chanID == "" {
		return nil, errors.ErrInvalidQueryParams
	}

	if err := authorize(ctx, r, chanID); err != nil {
		return nil, err
	}

	offset, err := httputil.ReadUintQuery(r, offsetKey, defOffset)
	if err != nil {
		return nil, err
	}

	limit, err := httputil.ReadUintQuery(r, limitKey, defLimit)
	if err != nil {
		return nil, err
	}

	format, err := httputil.ReadStringQuery(r, formatKey, defFormat)
	if err != nil {
		return nil, err
	}

	subtopic, err := httputil.ReadStringQuery(r, subtopicKey, "")
	if err != nil {
		return nil, err
	}

	publisher, err := httputil.ReadStringQuery(r, publisherKey, "")
	if err != nil {
		return nil, err
	}

	protocol, err := httputil.ReadStringQuery(r, protocolKey, "")
	if err != nil {
		return nil, err
	}

	name, err := httputil.ReadStringQuery(r, nameKey, "")
	if err != nil {
		return nil, err
	}

	v, err := httputil.ReadFloatQuery(r, valueKey, 0)
	if err != nil {
		return nil, err
	}

	comparator, err := httputil.ReadStringQuery(r, comparatorKey, "")
	if err != nil {
		return nil, err
	}

	vs, err := httputil.ReadStringQuery(r, stringValueKey, "")
	if err != nil {
		return nil, err
	}

	vd, err := httputil.ReadStringQuery(r, dataValueKey, "")
	if err != nil {
		return nil, err
	}

	from, err := httputil.ReadFloatQuery(r, fromKey, 0)
	if err != nil {
		return nil, err
	}

	to, err := httputil.ReadFloatQuery(r, toKey, 0)
	if err != nil {
		return nil, err
	}

	req := listMessagesReq{
		chanID: chanID,
		pageMeta: readers.PageMetadata{
			Offset:      offset,
			Limit:       limit,
			Format:      format,
			Subtopic:    subtopic,
			Publisher:   publisher,
			Protocol:    protocol,
			Name:        name,
			Value:       v,
			Comparator:  comparator,
			StringValue: vs,
			DataValue:   vd,
			From:        from,
			To:          to,
		},
	}

	vb, err := readBoolValueQuery(r, "vb")
	if err != nil && err != errors.ErrNotFoundParam {
		return nil, err
	}
	if err == nil {
		req.pageMeta.BoolValue = vb
	}

	return req, nil
}

func encodeResponse(_ context.Context, w http.ResponseWriter, response interface{}) error {
	w.Header().Set("Content-Type", contentType)

	if ar, ok := response.(mainflux.Response); ok {
		for k, v := range ar.Headers() {
			w.Header().Set(k, v)
		}

		w.WriteHeader(ar.Code())

		if ar.Empty() {
			return nil
		}
	}

	return json.NewEncoder(w).Encode(response)
}

func encodeError(_ context.Context, err error, w http.ResponseWriter) {
	switch {
	case errors.Contains(err, nil):
	case errors.Contains(err, errors.ErrInvalidQueryParams):
		w.WriteHeader(http.StatusBadRequest)
	case errors.Contains(err, errors.ErrAuthentication):
		w.WriteHeader(http.StatusUnauthorized)
	default:
		w.WriteHeader(http.StatusInternalServerError)
	}
	errorVal, ok := err.(errors.Error)
	if ok {
		w.Header().Set("Content-Type", contentType)
		if err := json.NewEncoder(w).Encode(errorRes{Err: errorVal.Msg()}); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		}
	}
}

func authorize(ctx context.Context, r *http.Request, chanID string) (err error) {
	token := r.Header.Get("Authorization")
	if token == "" {
		return errors.ErrAuthentication
	}
	if strings.HasPrefix(token, thingToken) {
		token = strings.ReplaceAll(token, thingToken, "")
		if _, err := thingsAuth.CanAccessByKey(ctx, &mainflux.AccessByKeyReq{Token: token, ChanID: chanID}); err != nil {
			return errors.Wrap(errUnauthorizedAccess, errThingAccess)
		}
		return nil
	}

	if strings.HasPrefix(token, userToken) {
		token = strings.ReplaceAll(token, userToken, "")
		user, err := usersAuth.Identify(ctx, &mainflux.Token{Value: token})
		if err != nil {
			e, ok := status.FromError(err)
			if ok && e.Code() == codes.PermissionDenied {
				return errUnauthorizedAccess
			}
			return errors.Wrap(errUnauthorizedAccess, errCannotAuthorizeUser)
		}
		_, err = thingsAuth.IsChannelOwner(ctx, &mainflux.ChannelOwnerReq{Owner: user.Email, ChanID: chanID})
		if err != nil {
			e, ok := status.FromError(err)
			if ok && e.Code() == codes.PermissionDenied {
				return errors.Wrap(errUnauthorizedAccess, errUserAccess)
			}
			return err
		}
		return nil
	}

	return errors.Wrap(errUnauthorizedAccess, errWrongToken)

}

func readBoolValueQuery(r *http.Request, key string) (bool, error) {
	vals := bone.GetQuery(r, key)
	if len(vals) > 1 {
		return false, errors.ErrInvalidQueryParams
	}

	if len(vals) == 0 {
		return false, errors.ErrNotFoundParam
	}

	b, err := strconv.ParseBool(vals[0])
	if err != nil {
		return false, errors.ErrInvalidQueryParams
	}

	return b, nil
}
