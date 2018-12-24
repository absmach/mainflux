//
// Copyright (c) 2018
// Mainflux
//
// SPDX-License-Identifier: Apache-2.0
//

package api_test

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/mainflux/mainflux/bootstrap"
	bsapi "github.com/mainflux/mainflux/bootstrap/api"

	"github.com/mainflux/mainflux/bootstrap/mocks"

	mfsdk "github.com/mainflux/mainflux/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mainflux/mainflux"
	"github.com/mainflux/mainflux/things"
	thingsapi "github.com/mainflux/mainflux/things/api/http"
)

const (
	validToken   = "validToken"
	invalidToken = "invalidToken"
	email        = "test@example.com"
	unknown      = "unknown"
	channelsNum  = 3
	contentType  = "application/json"
	token        = "token"
	wrongID      = "wrong_id"
)

type config struct {
	ID          string          `json:"id,omitempty"`
	Owner       string          `json:"owner,omitempty"`
	MFKey       string          `json:"mainflux_key,omitempty"`
	MFThing     string          `json:"mainflux_id,omitempty"`
	MFChannels  []string        `json:"mainflux_channels,omitempty"`
	ExternalID  string          `json:"external_id"`
	ExternalKey string          `json:"external_key,omitempty"`
	Content     string          `json:"content,omitempty"`
	State       bootstrap.State `json:"state,omitempty"`
}

var cfg = config{
	ExternalID:  "external-id",
	ExternalKey: "external-key",
	MFChannels:  []string{"1"},
	Content:     "config",
}

type testRequest struct {
	client      *http.Client
	method      string
	url         string
	contentType string
	token       string
	body        io.Reader
}

func (tr testRequest) make() (*http.Response, error) {
	req, err := http.NewRequest(tr.method, tr.url, tr.body)
	if err != nil {
		return nil, err
	}
	if tr.token != "" {
		req.Header.Set("Authorization", tr.token)
	}
	if tr.contentType != "" {
		req.Header.Set("Content-Type", tr.contentType)
	}
	return tr.client.Do(req)
}

func newService(users mainflux.UsersServiceClient, unknown map[string]string, url string) bootstrap.Service {
	things := mocks.NewConfigsRepository(unknown)
	config := mfsdk.Config{
		BaseURL: url,
	}

	sdk := mfsdk.NewSDK(config)
	return bootstrap.New(users, things, sdk)
}

func newThingsService(users mainflux.UsersServiceClient) things.Service {
	channels := make(map[string]things.Channel, channelsNum)
	for i := 0; i < channelsNum; i++ {
		id := strconv.Itoa(i + 1)
		channels[id] = things.Channel{
			ID:     id,
			Owner:  email,
			Things: []things.Thing{},
		}
	}

	return mocks.NewThingsService(map[string]things.Thing{}, channels, users)
}

func newThingsServer(svc things.Service) *httptest.Server {
	mux := thingsapi.MakeHandler(svc)
	return httptest.NewServer(mux)
}

func newBootstrapServer(svc bootstrap.Service) *httptest.Server {
	mux := bsapi.MakeHandler(svc, bootstrap.NewConfigReader())
	return httptest.NewServer(mux)
}

func toJSON(data interface{}) string {
	jsonData, _ := json.Marshal(data)
	return string(jsonData)
}

func TestAdd(t *testing.T) {
	users := mocks.NewUsersService(map[string]string{validToken: email})

	ts := newThingsServer(newThingsService(users))
	svc := newService(users, nil, ts.URL)
	bs := newBootstrapServer(svc)

	data := toJSON(cfg)

	invalidChannels := cfg
	invalidChannels.MFChannels = []string{wrongID}
	wrongData := toJSON(invalidChannels)

	cases := []struct {
		desc        string
		req         string
		auth        string
		contentType string
		status      int
		location    string
	}{
		{
			desc:        "add a config unauthorized",
			req:         data,
			auth:        invalidToken,
			contentType: contentType,
			status:      http.StatusForbidden,
			location:    "",
		},
		{
			desc:        "add a valid config",
			req:         data,
			auth:        validToken,
			contentType: contentType,
			status:      http.StatusCreated,
			location:    "/configs/1",
		},
		{
			desc:        "add a config with wring content type",
			req:         data,
			auth:        validToken,
			contentType: "",
			status:      http.StatusUnsupportedMediaType,
			location:    "",
		},
		{
			desc:        "add an existing config",
			req:         data,
			auth:        validToken,
			contentType: contentType,
			status:      http.StatusConflict,
			location:    "",
		},
		{
			desc:        "add a config with invalid channels",
			req:         wrongData,
			auth:        validToken,
			contentType: contentType,
			status:      http.StatusBadRequest,
			location:    "",
		},
		{
			desc:        "add a config with invalid request format",
			req:         "}",
			auth:        validToken,
			contentType: contentType,
			status:      http.StatusBadRequest,
			location:    "",
		},
		{
			desc:        "add a config with empty JSON",
			req:         "{}",
			auth:        validToken,
			contentType: contentType,
			status:      http.StatusBadRequest,
			location:    "",
		},
		{
			desc:        "add a config with an empty request",
			req:         "",
			auth:        validToken,
			contentType: contentType,
			status:      http.StatusBadRequest,
			location:    "",
		},
	}

	for _, tc := range cases {
		req := testRequest{
			client:      bs.Client(),
			method:      http.MethodPost,
			url:         fmt.Sprintf("%s/configs", bs.URL),
			contentType: tc.contentType,
			token:       tc.auth,
			body:        strings.NewReader(tc.req),
		}
		res, err := req.make()
		assert.Nil(t, err, fmt.Sprintf("%s: unexpected error %s", tc.desc, err))

		location := res.Header.Get("Location")
		assert.Equal(t, tc.status, res.StatusCode, fmt.Sprintf("%s: expected status code %d got %d", tc.desc, tc.status, res.StatusCode))
		assert.Equal(t, tc.location, location, fmt.Sprintf("%s: expected location '%s' got '%s'", tc.desc, tc.location, location))
	}
}

func TestView(t *testing.T) {
	users := mocks.NewUsersService(map[string]string{validToken: email})

	ts := newThingsServer(newThingsService(users))
	svc := newService(users, nil, ts.URL)
	bs := newBootstrapServer(svc)

	c := bootstrap.Config{
		ExternalID:  cfg.ExternalID,
		ExternalKey: cfg.ExternalKey,
		MFChannels:  cfg.MFChannels,
		Content:     cfg.Content,
	}

	saved, err := svc.Add(validToken, c)
	require.Nil(t, err, fmt.Sprintf("Saving config expected to succeed: %s.\n", err))

	s := cfg
	s.ID = saved.ID
	s.MFThing = saved.MFThing
	s.MFKey = saved.MFKey
	s.State = saved.State
	data := toJSON(s)

	cases := []struct {
		desc   string
		auth   string
		id     string
		status int
		res    string
	}{
		{
			desc:   "view a config unauthorized",
			auth:   invalidToken,
			id:     saved.ID,
			status: http.StatusForbidden,
			res:    "",
		},
		{
			desc:   "view a config",
			auth:   validToken,
			id:     saved.ID,
			status: http.StatusOK,
			res:    data,
		},
		{
			desc:   "view a non-existing config",
			auth:   validToken,
			id:     wrongID,
			status: http.StatusNotFound,
			res:    "",
		},
		{
			desc:   "view a config with an empty token",
			auth:   "",
			id:     saved.ID,
			status: http.StatusForbidden,
			res:    "",
		},
	}

	for _, tc := range cases {
		req := testRequest{
			client: bs.Client(),
			method: http.MethodGet,
			url:    fmt.Sprintf("%s/configs/%s", bs.URL, tc.id),
			token:  tc.auth,
		}
		res, err := req.make()
		assert.Nil(t, err, fmt.Sprintf("%s: unexpected error %s", tc.desc, err))

		assert.Equal(t, tc.status, res.StatusCode, fmt.Sprintf("%s: expected status code %d got %d", tc.desc, tc.status, res.StatusCode))
		body, err := ioutil.ReadAll(res.Body)
		assert.Nil(t, err, fmt.Sprintf("%s: unexpected error %s", tc.desc, err))
		data := strings.Trim(string(body), "\n")
		assert.Equal(t, tc.res, data, fmt.Sprintf("%s: expected response '%s' got '%s'", tc.desc, tc.res, data))
	}
}

func TestUpdate(t *testing.T) {
	users := mocks.NewUsersService(map[string]string{validToken: email})

	ts := newThingsServer(newThingsService(users))
	svc := newService(users, nil, ts.URL)
	bs := newBootstrapServer(svc)

	c := bootstrap.Config{
		ExternalID:  cfg.ExternalID,
		ExternalKey: cfg.ExternalKey,
		MFChannels:  cfg.MFChannels,
		Content:     cfg.Content,
	}

	saved, err := svc.Add(validToken, c)
	require.Nil(t, err, fmt.Sprintf("Saving config expected to succeed: %s.\n", err))

	update := cfg
	update.MFChannels = []string{"2", "3"}
	update.Content = "new config"
	update.State = bootstrap.Active

	data := toJSON(update)

	invalidChannels := cfg
	invalidChannels.MFChannels = []string{wrongID}

	wrongData := toJSON(invalidChannels)

	cases := []struct {
		desc        string
		req         string
		id          string
		auth        string
		contentType string
		status      int
	}{
		{
			desc:        "update a config unauthorized",
			req:         data,
			id:          saved.ID,
			auth:        invalidToken,
			contentType: contentType,
			status:      http.StatusForbidden,
		},
		{
			desc:        "update a valid config",
			req:         data,
			id:          saved.ID,
			auth:        validToken,
			contentType: contentType,
			status:      http.StatusOK,
		},
		{
			desc:        "add a config with wring content type",
			req:         data,
			id:          saved.ID,
			auth:        validToken,
			contentType: "",
			status:      http.StatusUnsupportedMediaType,
		},
		{
			desc:        "update a non-existing config",
			req:         data,
			id:          wrongID,
			auth:        validToken,
			contentType: contentType,
			status:      http.StatusNotFound,
		},
		{
			desc:        "add a config with invalid channels",
			req:         wrongData,
			id:          saved.ID,
			auth:        validToken,
			contentType: contentType,
			status:      http.StatusBadRequest,
		},
		{
			desc:        "add a config with invalid request format",
			req:         "}",
			id:          saved.ID,
			auth:        validToken,
			contentType: contentType,
			status:      http.StatusBadRequest,
		},
		{
			desc:        "add a config with empty JSON",
			req:         "{}",
			id:          saved.ID,
			auth:        validToken,
			contentType: contentType,
			status:      http.StatusBadRequest,
		},
		{
			desc:        "add a config with an empty request",
			id:          saved.ID,
			req:         "",
			auth:        validToken,
			contentType: contentType,
			status:      http.StatusBadRequest,
		},
	}

	for _, tc := range cases {
		req := testRequest{
			client:      bs.Client(),
			method:      http.MethodPut,
			url:         fmt.Sprintf("%s/configs/%s", bs.URL, tc.id),
			contentType: tc.contentType,
			token:       tc.auth,
			body:        strings.NewReader(tc.req),
		}
		res, err := req.make()
		assert.Nil(t, err, fmt.Sprintf("%s: unexpected error %s", tc.desc, err))
		assert.Equal(t, tc.status, res.StatusCode, fmt.Sprintf("%s: expected status code %d got %d", tc.desc, tc.status, res.StatusCode))
	}
}

func TestList(t *testing.T) {
	configNum := 100
	changedStateNum := 20
	var active, inactive []config
	list := make([]config, configNum)

	users := mocks.NewUsersService(map[string]string{validToken: email})
	ts := newThingsServer(newThingsService(users))
	svc := newService(users, nil, ts.URL)
	bs := newBootstrapServer(svc)

	c := bootstrap.Config{
		ExternalID:  cfg.ExternalID,
		ExternalKey: cfg.ExternalKey,
		MFChannels:  cfg.MFChannels,
		Content:     cfg.Content,
	}

	for i := 0; i < configNum; i++ {
		c.ExternalID = strconv.Itoa(i)
		c.ExternalKey = fmt.Sprintf("%s%s", c.ExternalKey, strconv.Itoa(i))
		saved, err := svc.Add(validToken, c)
		require.Nil(t, err, fmt.Sprintf("Saving config expected to succeed: %s.\n", err))
		s := config{
			ID:          saved.ID,
			ExternalID:  saved.ExternalID,
			ExternalKey: saved.ExternalKey,
			MFThing:     saved.MFThing,
			MFKey:       saved.MFKey,
			MFChannels:  saved.MFChannels,
			Content:     saved.Content,
			State:       saved.State,
		}
		list[i] = s
	}

	// Change state of first 20 elements for filtering tests.
	for i := 0; i < changedStateNum; i++ {
		state := bootstrap.Active
		if i%2 == 0 {
			state = bootstrap.Inactive
		}
		err := svc.ChangeState(validToken, list[i].ID, state)
		require.Nil(t, err, fmt.Sprintf("Changing state expected to succeed: %s.\n", err))
		list[i].State = state
		if state == bootstrap.Inactive {
			inactive = append(inactive, list[i])
			continue
		}
		active = append(active, list[i])
	}

	cases := []struct {
		desc   string
		auth   string
		url    string
		status int
		res    []config
	}{
		{
			desc:   "view a list unauthorized",
			auth:   invalidToken,
			url:    fmt.Sprintf("%s/configs?offset=%d&limit=%d", bs.URL, 0, 10),
			status: http.StatusForbidden,
			res:    nil,
		},
		{
			desc:   "view a list",
			auth:   validToken,
			url:    fmt.Sprintf("%s/configs?offset=%d&limit=%d", bs.URL, 0, 10),
			status: http.StatusOK,
			res:    list[0:10],
		},
		{
			desc:   "view a last page",
			auth:   validToken,
			url:    fmt.Sprintf("%s/configs?offset=%d&limit=%d", bs.URL, 100, 10),
			status: http.StatusOK,
			res:    list[100:],
		},
		{
			desc:   "view a list with no specified limit and offset",
			auth:   validToken,
			url:    fmt.Sprintf("%s/configs", bs.URL),
			status: http.StatusOK,
			res:    list[0:10],
		},
		{
			desc:   "view a list with no specified limit",
			auth:   validToken,
			url:    fmt.Sprintf("%s/configs?offset=%d", bs.URL, 10),
			status: http.StatusOK,
			res:    list[10:20],
		},
		{
			desc:   "view a list with no specified offset",
			auth:   validToken,
			url:    fmt.Sprintf("%s/configs?limit=%d", bs.URL, 10),
			status: http.StatusOK,
			res:    list[0:10],
		},
		{
			desc:   "view a list with limit < 0",
			auth:   validToken,
			url:    fmt.Sprintf("%s/configs?limit=%d", bs.URL, -10),
			status: http.StatusBadRequest,
			res:    nil,
		},
		{
			desc:   "view a list with offset < 0",
			auth:   validToken,
			url:    fmt.Sprintf("%s/configs?offset=%d", bs.URL, -10),
			status: http.StatusBadRequest,
			res:    nil,
		},
		{
			desc:   "view first 10 active",
			auth:   validToken,
			url:    fmt.Sprintf("%s/configs?offset=%d&limit=%d&state=%d", bs.URL, 0, 20, bootstrap.Active),
			status: http.StatusOK,
			res:    active,
		},
		{
			desc:   "view first 10 inactive",
			auth:   validToken,
			url:    fmt.Sprintf("%s/configs?offset=%d&limit=%d&state=%d", bs.URL, 0, 20, bootstrap.Inactive),
			status: http.StatusOK,
			res:    inactive,
		},
		{
			desc:   "view first 5 active",
			auth:   validToken,
			url:    fmt.Sprintf("%s/configs?offset=%d&limit=%d&state=%d", bs.URL, 0, 10, bootstrap.Active),
			status: http.StatusOK,
			res:    active[:5],
		},
		{
			desc:   "view last 5 inactive",
			auth:   validToken,
			url:    fmt.Sprintf("%s/configs?offset=%d&limit=%d&state=%d", bs.URL, 10, 10, bootstrap.Inactive),
			status: http.StatusOK,
			res:    inactive[5:],
		},
	}

	for _, tc := range cases {
		req := testRequest{
			client: bs.Client(),
			method: http.MethodGet,
			url:    tc.url,
			token:  tc.auth,
		}
		res, err := req.make()
		assert.Nil(t, err, fmt.Sprintf("%s: unexpected error %s", tc.desc, err))

		assert.Equal(t, tc.status, res.StatusCode, fmt.Sprintf("%s: expected status code %d got %d", tc.desc, tc.status, res.StatusCode))
		var body map[string][]config

		json.NewDecoder(res.Body).Decode(&body)
		assert.Nil(t, err, fmt.Sprintf("%s: unexpected error %s", tc.desc, err))
		assert.ElementsMatch(t, tc.res, body["configs"], fmt.Sprintf("%s: expected response '%s' got '%s'", tc.desc, tc.res, body["configs"]))
	}
}

func TestUnknown(t *testing.T) {
	unknownNum := 10
	unknown := make([]config, unknownNum)
	unknownConfigs := make(map[string]string, unknownNum)
	// Save some unknown elements.
	for i := 0; i < unknownNum; i++ {
		u := config{
			ExternalID:  fmt.Sprintf("key-%s", strconv.Itoa(i)),
			ExternalKey: fmt.Sprintf("%s%s", cfg.ExternalKey, strconv.Itoa(i)),
		}
		unknownConfigs[u.ExternalID] = u.ExternalKey
		unknown[i] = u
	}

	users := mocks.NewUsersService(map[string]string{validToken: email})
	ts := newThingsServer(newThingsService(users))
	svc := newService(users, unknownConfigs, ts.URL)
	bs := newBootstrapServer(svc)

	cases := []struct {
		desc   string
		auth   string
		url    string
		status int
		res    []config
	}{
		{
			desc:   "view unknown unauthorized",
			auth:   invalidToken,
			url:    fmt.Sprintf("%s/unknown?offset=%d&limit=%d", bs.URL, 0, 5),
			status: http.StatusForbidden,
			res:    nil,
		},
		{
			desc:   "view a list of unknown",
			auth:   validToken,
			url:    fmt.Sprintf("%s/unknown?offset=%d&limit=%d", bs.URL, 0, 5),
			status: http.StatusOK,
			res:    unknown[:5],
		},
		{
			desc:   "view unknown with no page paremeters",
			auth:   validToken,
			url:    fmt.Sprintf("%s/unknown", bs.URL),
			status: http.StatusOK,
			res:    unknown[:10],
		},
	}

	for _, tc := range cases {
		req := testRequest{
			client: bs.Client(),
			method: http.MethodGet,
			url:    tc.url,
			token:  tc.auth,
		}
		res, err := req.make()
		assert.Nil(t, err, fmt.Sprintf("%s: unexpected error %s", tc.desc, err))

		assert.Equal(t, tc.status, res.StatusCode, fmt.Sprintf("%s: expected status code %d got %d", tc.desc, tc.status, res.StatusCode))
		var body map[string][]config

		json.NewDecoder(res.Body).Decode(&body)
		assert.Nil(t, err, fmt.Sprintf("%s: unexpected error %s", tc.desc, err))
		assert.ElementsMatch(t, tc.res, body["configs"], fmt.Sprintf("%s: expected response '%s' got '%s'", tc.desc, tc.res, body["configs"]))
	}
}

func TestChangeState(t *testing.T) {
	users := mocks.NewUsersService(map[string]string{validToken: email})

	ts := newThingsServer(newThingsService(users))
	svc := newService(users, nil, ts.URL)
	bs := newBootstrapServer(svc)

	c := bootstrap.Config{
		ExternalID:  cfg.ExternalID,
		ExternalKey: cfg.ExternalKey,
		MFChannels:  cfg.MFChannels,
		Content:     cfg.Content,
	}

	saved, err := svc.Add(validToken, c)
	require.Nil(t, err, fmt.Sprintf("Saving config expected to succeed: %s.\n", err))

	cases := []struct {
		desc        string
		id          string
		auth        string
		state       bootstrap.State
		contentType string
		status      int
	}{
		{
			desc:        "change a state unauthorized",
			id:          saved.ID,
			auth:        invalidToken,
			state:       bootstrap.Active,
			contentType: contentType,
			status:      http.StatusForbidden,
		},
		{
			desc:        "change a state invalid content type",
			id:          saved.ID,
			auth:        validToken,
			state:       bootstrap.Active,
			contentType: "",
			status:      http.StatusUnsupportedMediaType,
		},
		{
			desc:        "change a state",
			id:          saved.ID,
			auth:        validToken,
			state:       bootstrap.Active,
			contentType: contentType,
			status:      http.StatusOK,
		},
		{
			desc:        "change a state of non-existing config",
			id:          wrongID,
			auth:        validToken,
			state:       bootstrap.Active,
			contentType: contentType,
			status:      http.StatusNotFound,
		},
		{
			desc:        "change a state to invalid value",
			id:          saved.ID,
			auth:        validToken,
			state:       bootstrap.State(45),
			contentType: contentType,
			status:      http.StatusBadRequest,
		},
	}

	for _, tc := range cases {
		req := testRequest{
			client:      bs.Client(),
			method:      http.MethodPut,
			url:         fmt.Sprintf("%s/state/%s", bs.URL, tc.id),
			token:       tc.auth,
			contentType: tc.contentType,
			body:        strings.NewReader(fmt.Sprintf("{\"state\": %d}", tc.state)),
		}
		res, err := req.make()
		assert.Nil(t, err, fmt.Sprintf("%s: unexpected error %s", tc.desc, err))
		assert.Equal(t, tc.status, res.StatusCode, fmt.Sprintf("%s: expected status code %d got %d", tc.desc, tc.status, res.StatusCode))
	}
}

func TestRemove(t *testing.T) {
	users := mocks.NewUsersService(map[string]string{validToken: email})

	ts := newThingsServer(newThingsService(users))
	svc := newService(users, nil, ts.URL)
	bs := newBootstrapServer(svc)

	c := bootstrap.Config{
		ExternalID:  cfg.ExternalID,
		ExternalKey: cfg.ExternalKey,
		MFChannels:  cfg.MFChannels,
		Content:     cfg.Content,
	}

	saved, err := svc.Add(validToken, c)
	require.Nil(t, err, fmt.Sprintf("Saving config expected to succeed: %s.\n", err))

	cases := []struct {
		desc   string
		id     string
		auth   string
		status int
	}{
		{
			desc:   "remove unauthorized",
			id:     saved.ID,
			auth:   invalidToken,
			status: http.StatusForbidden,
		},
		{
			desc:   "remove non-existing config",
			id:     "non-existing",
			auth:   validToken,
			status: http.StatusNoContent,
		},
		{
			desc:   "remove config",
			id:     saved.ID,
			auth:   validToken,
			status: http.StatusNoContent,
		},
		{
			desc:   "remove removed config",
			id:     wrongID,
			auth:   validToken,
			status: http.StatusNoContent,
		},
	}

	for _, tc := range cases {
		req := testRequest{
			client: bs.Client(),
			method: http.MethodDelete,
			url:    fmt.Sprintf("%s/configs/%s", bs.URL, tc.id),
			token:  tc.auth,
		}
		res, err := req.make()
		assert.Nil(t, err, fmt.Sprintf("%s: unexpected error %s", tc.desc, err))
		assert.Equal(t, tc.status, res.StatusCode, fmt.Sprintf("%s: expected status code %d got %d", tc.desc, tc.status, res.StatusCode))
	}
}
