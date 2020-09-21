// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package http_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/opentracing/opentracing-go/mocktracer"

	"github.com/mainflux/mainflux/pkg/uuid"
	"github.com/mainflux/mainflux/things"
	httpapi "github.com/mainflux/mainflux/things/api/auth/http"
	"github.com/mainflux/mainflux/things/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	contentType = "application/json"
	email       = "user@example.com"
	token       = "token"
	wrong       = "wrong_value"
	wrongID     = "0"
)

var (
	thing = things.Thing{
		Name:     "test_app",
		Metadata: map[string]interface{}{"test": "data"},
	}
	channel = things.Channel{
		Name:     "test_chan",
		Metadata: map[string]interface{}{"test": "data"},
	}
)

type testRequest struct {
	client      *http.Client
	method      string
	url         string
	contentType string
	body        io.Reader
}

func (tr testRequest) make() (*http.Response, error) {
	req, err := http.NewRequest(tr.method, tr.url, tr.body)
	if err != nil {
		return nil, err
	}
	if tr.contentType != "" {
		req.Header.Set("Content-Type", tr.contentType)
	}
	return tr.client.Do(req)
}

func toJSON(data interface{}) string {
	jsonData, _ := json.Marshal(data)
	return string(jsonData)
}

func newService(tokens map[string]string) things.Service {
	auth := mocks.NewAuthService(tokens)
	conns := make(chan mocks.Connection)
	thingsRepo := mocks.NewThingRepository(conns)
	channelsRepo := mocks.NewChannelRepository(thingsRepo, conns)
	chanCache := mocks.NewChannelCache()
	thingCache := mocks.NewThingCache()
	uuidProvider := uuid.NewMock()

	return things.New(auth, thingsRepo, channelsRepo, chanCache, thingCache, uuidProvider)
}

func newServer(svc things.Service) *httptest.Server {
	mux := httpapi.MakeHandler(mocktracer.New(), svc)
	return httptest.NewServer(mux)
}

func TestIdentify(t *testing.T) {
	svc := newService(map[string]string{token: email})
	ts := newServer(svc)
	defer ts.Close()

	ths, err := svc.CreateThings(context.Background(), token, thing)
	require.Nil(t, err, fmt.Sprintf("failed to create thing: %s", err))
	th := ths[0]

	ir := identifyReq{Token: th.Key}
	data := toJSON(ir)

	nonexistentData := toJSON(identifyReq{Token: wrong})

	cases := map[string]struct {
		contentType string
		req         string
		status      int
	}{
		"identify existing thing": {
			contentType: contentType,
			req:         data,
			status:      http.StatusOK,
		},
		"identify non-existent thing": {
			contentType: contentType,
			req:         nonexistentData,
			status:      http.StatusNotFound,
		},
		"identify with missing content type": {
			contentType: wrong,
			req:         data,
			status:      http.StatusUnsupportedMediaType,
		},
		"identify with empty JSON request": {
			contentType: contentType,
			req:         "{}",
			status:      http.StatusUnauthorized,
		},
		"identify with invalid JSON request": {
			contentType: contentType,
			req:         "",
			status:      http.StatusBadRequest,
		},
	}

	for desc, tc := range cases {
		req := testRequest{
			client:      ts.Client(),
			method:      http.MethodPost,
			url:         fmt.Sprintf("%s/identify", ts.URL),
			contentType: tc.contentType,
			body:        strings.NewReader(tc.req),
		}
		res, err := req.make()
		assert.Nil(t, err, fmt.Sprintf("%s: unexpected error %s", desc, err))
		assert.Equal(t, tc.status, res.StatusCode, fmt.Sprintf("%s: expected status code %d got %d", desc, tc.status, res.StatusCode))
	}
}

func TestCanAccessByKey(t *testing.T) {
	svc := newService(map[string]string{token: email})
	ts := newServer(svc)
	defer ts.Close()

	sths, err := svc.CreateThings(context.Background(), token, thing)
	require.Nil(t, err, fmt.Sprintf("failed to create thing: %s", err))
	sth := sths[0]

	schs, err := svc.CreateChannels(context.Background(), token, channel)
	require.Nil(t, err, fmt.Sprintf("failed to create channel: %s", err))
	sch := schs[0]

	err = svc.Connect(context.Background(), token, []string{sch.ID}, []string{sth.ID})
	require.Nil(t, err, fmt.Sprintf("failed to connect thing and channel: %s", err))

	car := canAccessByKeyReq{
		Token: sth.Key,
	}
	data := toJSON(car)

	cases := map[string]struct {
		contentType string
		chanID      string
		req         string
		status      int
	}{
		"check access for connected thing and channel": {
			contentType: contentType,
			chanID:      sch.ID,
			req:         data,
			status:      http.StatusOK,
		},
		"check access for not connected thing and channel": {
			contentType: contentType,
			chanID:      wrong,
			req:         data,
			status:      http.StatusForbidden,
		},
		"check access with invalid content type": {
			contentType: wrong,
			chanID:      sch.ID,
			req:         data,
			status:      http.StatusUnsupportedMediaType,
		},
		"check access with empty JSON request": {
			contentType: contentType,
			chanID:      sch.ID,
			req:         "{}",
			status:      http.StatusUnauthorized,
		},
		"check access with invalid JSON request": {
			contentType: contentType,
			chanID:      sch.ID,
			req:         "}",
			status:      http.StatusBadRequest,
		},
		"check access with empty request": {
			contentType: contentType,
			chanID:      sch.ID,
			req:         "",
			status:      http.StatusBadRequest,
		},
	}

	for desc, tc := range cases {
		req := testRequest{
			client:      ts.Client(),
			method:      http.MethodPost,
			url:         fmt.Sprintf("%s/channels/%s/access-by-key", ts.URL, tc.chanID),
			contentType: tc.contentType,
			body:        strings.NewReader(tc.req),
		}
		res, err := req.make()
		assert.Nil(t, err, fmt.Sprintf("%s: unexpected error %s", desc, err))
		assert.Equal(t, tc.status, res.StatusCode, fmt.Sprintf("%s: expected status code %d got %d", desc, tc.status, res.StatusCode))
	}
}

func TestCanAccessByID(t *testing.T) {
	svc := newService(map[string]string{token: email})
	ts := newServer(svc)
	defer ts.Close()

	sths, err := svc.CreateThings(context.Background(), token, thing)
	require.Nil(t, err, fmt.Sprintf("failed to create thing: %s", err))
	sth := sths[0]

	schs, err := svc.CreateChannels(context.Background(), token, channel)
	require.Nil(t, err, fmt.Sprintf("failed to create channel: %s", err))
	sch := schs[0]

	err = svc.Connect(context.Background(), token, []string{sch.ID}, []string{sth.ID})
	require.Nil(t, err, fmt.Sprintf("failed to connect thing and channel: %s", err))

	car := canAccessByIDReq{
		ThingID: sth.ID,
	}
	data := toJSON(car)

	cases := map[string]struct {
		contentType string
		chanID      string
		req         string
		status      int
	}{
		"check access for connected thing and channel": {
			contentType: contentType,
			chanID:      sch.ID,
			req:         data,
			status:      http.StatusOK,
		},
		"check access for not connected thing and channel": {
			contentType: contentType,
			chanID:      wrong,
			req:         data,
			status:      http.StatusForbidden,
		},
		"check access with invalid content type": {
			contentType: wrong,
			chanID:      sch.ID,
			req:         data,
			status:      http.StatusUnsupportedMediaType,
		},
		"check access with empty JSON request": {
			contentType: contentType,
			chanID:      sch.ID,
			req:         "{}",
			status:      http.StatusUnauthorized,
		},
		"check access with invalid JSON request": {
			contentType: contentType,
			chanID:      sch.ID,
			req:         "}",
			status:      http.StatusBadRequest,
		},
		"check access with empty request": {
			contentType: contentType,
			chanID:      sch.ID,
			req:         "",
			status:      http.StatusBadRequest,
		},
	}

	for desc, tc := range cases {
		req := testRequest{
			client:      ts.Client(),
			method:      http.MethodPost,
			url:         fmt.Sprintf("%s/channels/%s/access-by-id", ts.URL, tc.chanID),
			contentType: tc.contentType,
			body:        strings.NewReader(tc.req),
		}
		res, err := req.make()
		assert.Nil(t, err, fmt.Sprintf("%s: unexpected error %s", desc, err))
		assert.Equal(t, tc.status, res.StatusCode, fmt.Sprintf("%s: expected status code %d got %d", desc, tc.status, res.StatusCode))
	}
}

type identifyReq struct {
	Token string `json:"token"`
}

type canAccessByKeyReq struct {
	Token string `json:"token"`
}

type canAccessByIDReq struct {
	ThingID string `json:"thing_id"`
}
