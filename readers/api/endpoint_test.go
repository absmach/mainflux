// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package api_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mainflux/mainflux"
	"github.com/mainflux/mainflux/pkg/transformers/senml"
	"github.com/mainflux/mainflux/pkg/uuid"
	"github.com/mainflux/mainflux/readers"
	"github.com/mainflux/mainflux/readers/api"
	"github.com/mainflux/mainflux/readers/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	svcName       = "test-service"
	token         = "1"
	invalid       = "invalid"
	numOfMessages = 42
	valueFields   = 5
	mqttProt      = "mqtt"
)

var (
	v   float64 = 5
	vs          = "value"
	vb          = true
	vd          = "dataValue"
	sum float64 = 42

	idProvider = uuid.New()
)

func newMessageRepo(chanID, pubID string) readers.MessageRepository {
	var messages []readers.Message
	for i := 0; i < numOfMessages; i++ {
		// Mix possible values as well as value sum.
		msg := senml.Message{
			Channel:   chanID,
			Publisher: pubID,
			Protocol:  mqttProt,
		}

		count := i % valueFields
		switch count {
		case 0:
			msg.Value = &v
		case 1:
			msg.BoolValue = &vb
		case 2:
			msg.StringValue = &vs
		case 3:
			msg.DataValue = &vd
		case 4:
			msg.Name = "msgName"
			msg.Sum = &sum
		}

		messages = append(messages, msg)
	}

	return mocks.NewMessageRepository(map[string][]readers.Message{
		chanID: messages,
	})
}

func newServer(repo readers.MessageRepository, tc mainflux.ThingsServiceClient) *httptest.Server {
	mux := api.MakeHandler(repo, tc, svcName)
	return httptest.NewServer(mux)
}

type testRequest struct {
	client *http.Client
	method string
	url    string
	token  string
}

func (tr testRequest) make() (*http.Response, error) {
	req, err := http.NewRequest(tr.method, tr.url, nil)
	if err != nil {
		return nil, err
	}
	if tr.token != "" {
		req.Header.Set("Authorization", tr.token)
	}

	return tr.client.Do(req)
}

func TestReadAll(t *testing.T) {
	chanID, err := idProvider.ID()
	require.Nil(t, err, fmt.Sprintf("got unexpected error: %s", err))
	pubID, err := idProvider.ID()
	require.Nil(t, err, fmt.Sprintf("got unexpected error: %s", err))

	svc := mocks.NewThingsService()
	repo := newMessageRepo(chanID, pubID)
	ts := newServer(repo, svc)
	defer ts.Close()

	cases := map[string]struct {
		url    string
		token  string
		status int
	}{
		"read page with valid offset and limit": {
			url:    fmt.Sprintf("%s/channels/%s/messages?offset=0&limit=10", ts.URL, chanID),
			token:  token,
			status: http.StatusOK,
		},
		"read page with negative offset": {
			url:    fmt.Sprintf("%s/channels/%s/messages?offset=-1&limit=10", ts.URL, chanID),
			token:  token,
			status: http.StatusBadRequest,
		},
		"read page with negative limit": {
			url:    fmt.Sprintf("%s/channels/%s/messages?offset=0&limit=-10", ts.URL, chanID),
			token:  token,
			status: http.StatusBadRequest,
		},
		"read page with zero limit": {
			url:    fmt.Sprintf("%s/channels/%s/messages?offset=0&limit=0", ts.URL, chanID),
			token:  token,
			status: http.StatusBadRequest,
		},
		"read page with non-integer offset": {
			url:    fmt.Sprintf("%s/channels/%s/messages?offset=abc&limit=10", ts.URL, chanID),
			token:  token,
			status: http.StatusBadRequest,
		},
		"read page with non-integer limit": {
			url:    fmt.Sprintf("%s/channels/%s/messages?offset=0&limit=abc", ts.URL, chanID),
			token:  token,
			status: http.StatusBadRequest,
		},
		"read page with invalid channel id": {
			url:    fmt.Sprintf("%s/channels//messages?offset=0&limit=10", ts.URL),
			token:  token,
			status: http.StatusBadRequest,
		},
		"read page with invalid token": {
			url:    fmt.Sprintf("%s/channels/%s/messages?offset=0&limit=10", ts.URL, chanID),
			token:  invalid,
			status: http.StatusForbidden,
		},
		"read page with multiple offset": {
			url:    fmt.Sprintf("%s/channels/%s/messages?offset=0&offset=1&limit=10", ts.URL, chanID),
			token:  token,
			status: http.StatusBadRequest,
		},
		"read page with multiple limit": {
			url:    fmt.Sprintf("%s/channels/%s/messages?offset=0&limit=20&limit=10", ts.URL, chanID),
			token:  token,
			status: http.StatusBadRequest,
		},
		"read page with empty token": {
			url:    fmt.Sprintf("%s/channels/%s/messages?offset=0&limit=10", ts.URL, chanID),
			token:  "",
			status: http.StatusForbidden,
		},
		"read page with default offset": {
			url:    fmt.Sprintf("%s/channels/%s/messages?limit=10", ts.URL, chanID),
			token:  token,
			status: http.StatusOK,
		},
		"read page with default limit": {
			url:    fmt.Sprintf("%s/channels/%s/messages?offset=0", ts.URL, chanID),
			token:  token,
			status: http.StatusOK,
		},
		"read page with fornat": {
			url:    fmt.Sprintf("%s/channels/%s/messages?format=messages", ts.URL, chanID),
			token:  token,
			status: http.StatusOK,
		},
		"read page with subtopic": {
			url:    fmt.Sprintf("%s/channels/%s/messages?subtopic=%f", ts.URL, chanID, v),
			token:  token,
			status: http.StatusOK,
		},
		"read page with publisher": {
			url:    fmt.Sprintf("%s/channels/%s/messages?publisher=%s", ts.URL, chanID, pubID),
			token:  token,
			status: http.StatusOK,
		},
		"read page with protocol": {
			url:    fmt.Sprintf("%s/channels/%s/messages?protocol=http", ts.URL, chanID),
			token:  token,
			status: http.StatusOK,
		},
		"read page with name": {
			url:    fmt.Sprintf("%s/channels/%s/messages?name=msgName", ts.URL, chanID),
			token:  token,
			status: http.StatusOK,
		},
		"read page with value": {
			url:    fmt.Sprintf("%s/channels/%s/messages?v=%f", ts.URL, chanID, v),
			token:  token,
			status: http.StatusOK,
		},
		"read page with non-float value": {
			url:    fmt.Sprintf("%s/channels/%s/messages?v=ab01", ts.URL, chanID),
			token:  token,
			status: http.StatusBadRequest,
		},
		"read page with boolean value": {
			url:    fmt.Sprintf("%s/channels/%s/messages?vb=%t", ts.URL, chanID, vb),
			token:  token,
			status: http.StatusOK,
		},
		"read page with non-bool boolean value": {
			url:    fmt.Sprintf("%s/channels/%s/messages?vb=yes", ts.URL, chanID),
			token:  token,
			status: http.StatusBadRequest,
		},
		"read page with string value": {
			url:    fmt.Sprintf("%s/channels/%s/messages?vs=%s", ts.URL, chanID, vd),
			token:  token,
			status: http.StatusOK,
		},
		"read page with data value": {
			url:    fmt.Sprintf("%s/channels/%s/messages?vd=%s", ts.URL, chanID, vd),
			token:  token,
			status: http.StatusOK,
		},
		"read page with from": {
			url:    fmt.Sprintf("%s/channels/%s/messages?from=1608651539.673909", ts.URL, chanID),
			token:  token,
			status: http.StatusOK,
		},
		"read page with non-float from": {
			url:    fmt.Sprintf("%s/channels/%s/messages?from=ABCD", ts.URL, chanID),
			token:  token,
			status: http.StatusBadRequest,
		},
		"read page with to": {
			url:    fmt.Sprintf("%s/channels/%s/messages?to=1508651539.673909", ts.URL, chanID),
			token:  token,
			status: http.StatusOK,
		},
		"read page with non-float to": {
			url:    fmt.Sprintf("%s/channels/%s/messages?to=ABCD", ts.URL, chanID),
			token:  token,
			status: http.StatusBadRequest,
		},
	}

	for desc, tc := range cases {
		req := testRequest{
			client: ts.Client(),
			method: http.MethodGet,
			url:    tc.url,
			token:  tc.token,
		}
		res, err := req.make()
		assert.Nil(t, err, fmt.Sprintf("%s: unexpected error %s", desc, err))
		assert.Equal(t, tc.status, res.StatusCode, fmt.Sprintf("%s: expected %d got %d", desc, tc.status, res.StatusCode))
	}
}
