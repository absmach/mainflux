package sdk_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-zoo/bone"
	"github.com/mainflux/mainflux/internal/apiutil"
	"github.com/mainflux/mainflux/internal/testsutil"
	"github.com/mainflux/mainflux/logger"
	"github.com/mainflux/mainflux/pkg/errors"
	sdk "github.com/mainflux/mainflux/pkg/sdk/go"
	"github.com/mainflux/mainflux/users/clients"
	"github.com/mainflux/mainflux/users/clients/api"
	"github.com/mainflux/mainflux/users/clients/mocks"
	cmocks "github.com/mainflux/mainflux/users/clients/mocks"
	"github.com/mainflux/mainflux/users/jwt"
	pmocks "github.com/mainflux/mainflux/users/policies/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func newClientServer(svc clients.Service) *httptest.Server {
	logger := logger.NewMock()
	mux := bone.New()
	api.MakeClientsHandler(svc, mux, logger)
	return httptest.NewServer(mux)
}

func TestCreateClient(t *testing.T) {
	cRepo := new(cmocks.ClientRepository)
	pRepo := new(pmocks.PolicyRepository)
	tokenizer := jwt.NewTokenRepo([]byte(secret), accessDuration, refreshDuration)

	svc := clients.NewService(cRepo, pRepo, tokenizer, emailer, phasher, idProvider, passRegex)
	ts := newClientServer(svc)
	defer ts.Close()

	user := sdk.User{
		Credentials: sdk.Credentials{Identity: "identity", Secret: "secret"},
		Status:      clients.EnabledStatus.String(),
	}
	conf := sdk.Config{
		UsersURL: ts.URL,
	}
	clientSDK := sdk.NewSDK(conf)

	cases := []struct {
		desc     string
		client   sdk.User
		response sdk.User
		token    string
		err      errors.SDKError
	}{
		{
			desc:     "register new user",
			client:   user,
			response: user,
			token:    token,
			err:      nil,
		},
		{
			desc:     "register existing user",
			client:   user,
			response: sdk.User{},
			token:    token,
			err:      errors.NewSDKErrorWithStatus(sdk.ErrFailedCreation, http.StatusInternalServerError),
		},
		{
			desc: "register user with invalid identity",
			client: sdk.User{
				Credentials: sdk.Credentials{
					Identity: invalidIdentity, Secret: "password"},
			},
			response: sdk.User{},
			token:    token,
			err:      errors.NewSDKErrorWithStatus(sdk.ErrFailedCreation, http.StatusInternalServerError),
		},
		{
			desc: "register user with empty secret",
			client: sdk.User{
				Credentials: sdk.Credentials{
					Identity: Identity + "2", Secret: ""},
			},
			response: sdk.User{},
			token:    token,
			err:      errors.NewSDKErrorWithStatus(apiutil.ErrMissingSecret, http.StatusBadRequest),
		},
		{
			desc: "register user with no secret",
			client: sdk.User{
				Credentials: sdk.Credentials{
					Identity: Identity + "2"},
			},
			response: sdk.User{},
			token:    token,
			err:      errors.NewSDKErrorWithStatus(apiutil.ErrMissingSecret, http.StatusBadRequest),
		},
		{
			desc: "register user with empty identity",
			client: sdk.User{
				Credentials: sdk.Credentials{
					Identity: "",
					Secret:   secret},
			},
			response: sdk.User{},
			token:    token,
			err:      errors.NewSDKErrorWithStatus(errors.ErrMalformedEntity, http.StatusBadRequest),
		},
		{
			desc: "register user with no identity",
			client: sdk.User{
				Credentials: sdk.Credentials{
					Secret: secret},
			},
			response: sdk.User{},
			token:    token,
			err:      errors.NewSDKErrorWithStatus(errors.ErrMalformedEntity, http.StatusBadRequest),
		},
		{
			desc:     "register empty user",
			client:   sdk.User{},
			response: sdk.User{},
			token:    token,
			err:      errors.NewSDKErrorWithStatus(apiutil.ErrMissingSecret, http.StatusBadRequest),
		},
		{
			desc: "register user with every field defined",
			client: sdk.User{
				ID:          generateUUID(t),
				Name:        "name",
				Tags:        []string{"tag1", "tag2"},
				Owner:       "owner",
				Credentials: user.Credentials,
				Metadata:    validMetadata,
				CreatedAt:   time.Now(),
				UpdatedAt:   time.Now(),
				Status:      clients.EnabledStatus.String(),
			},
			response: sdk.User{
				ID:          generateUUID(t),
				Name:        "name",
				Tags:        []string{"tag1", "tag2"},
				Owner:       "owner",
				Credentials: user.Credentials,
				Metadata:    validMetadata,
				CreatedAt:   time.Now(),
				UpdatedAt:   time.Now(),
				Status:      clients.EnabledStatus.String(),
			},
			token: token,
			err:   nil,
		},
	}
	for _, tc := range cases {
		repoCall := pRepo.On("Evaluate", mock.Anything, mock.Anything, mock.Anything).Return(nil)
		repoCall1 := cRepo.On("Save", mock.Anything, mock.Anything).Return(tc.response, tc.err)

		rClient, err := clientSDK.CreateUser(tc.client, tc.token)
		tc.response.ID = rClient.ID
		tc.response.CreatedAt = rClient.CreatedAt
		tc.response.UpdatedAt = rClient.UpdatedAt
		rClient.Credentials.Secret = tc.response.Credentials.Secret
		assert.Equal(t, tc.err, err, fmt.Sprintf("%s: expected error %s, got %s", tc.desc, tc.err, err))
		assert.Equal(t, tc.response, rClient, fmt.Sprintf("%s: expected %v got %v\n", tc.desc, tc.response, rClient))

		repoCall.Unset()
		repoCall1.Unset()
	}
}

func TestListClients(t *testing.T) {
	cRepo := new(cmocks.ClientRepository)
	pRepo := new(pmocks.PolicyRepository)
	tokenizer := jwt.NewTokenRepo([]byte(secret), accessDuration, refreshDuration)

	svc := clients.NewService(cRepo, pRepo, tokenizer, emailer, phasher, idProvider, passRegex)
	ts := newClientServer(svc)
	defer ts.Close()

	var cls []sdk.User
	conf := sdk.Config{
		UsersURL: ts.URL,
	}
	clientSDK := sdk.NewSDK(conf)

	for i := 10; i < 100; i++ {
		cl := sdk.User{
			ID:   generateUUID(t),
			Name: fmt.Sprintf("client_%d", i),
			Credentials: sdk.Credentials{
				Identity: fmt.Sprintf("identity_%d", i),
				Secret:   fmt.Sprintf("password_%d", i),
			},
			Metadata: sdk.Metadata{"name": fmt.Sprintf("client_%d", i)},
			Status:   clients.EnabledStatus.String(),
		}
		if i == 50 {
			cl.Owner = "clientowner"
			cl.Status = clients.DisabledStatus.String()
			cl.Tags = []string{"tag1", "tag2"}
		}
		cls = append(cls, cl)
	}

	cases := []struct {
		desc       string
		token      string
		status     string
		total      uint64
		offset     uint64
		limit      uint64
		name       string
		identifier string
		ownerID    string
		tag        string
		metadata   sdk.Metadata
		err        errors.SDKError
		response   []sdk.User
	}{
		{
			desc:     "get a list of users",
			token:    token,
			limit:    limit,
			offset:   offset,
			total:    total,
			err:      nil,
			response: cls[offset:limit],
		},
		{
			desc:     "get a list of users with invalid token",
			token:    invalidToken,
			offset:   offset,
			limit:    limit,
			err:      errors.NewSDKErrorWithStatus(sdk.ErrFailedList, http.StatusInternalServerError),
			response: nil,
		},
		{
			desc:     "get a list of users with empty token",
			token:    "",
			offset:   offset,
			limit:    limit,
			err:      errors.NewSDKErrorWithStatus(sdk.ErrFailedList, http.StatusInternalServerError),
			response: nil,
		},
		{
			desc:     "get a list of users with zero limit",
			token:    token,
			offset:   offset,
			limit:    0,
			err:      errors.NewSDKErrorWithStatus(apiutil.ErrLimitSize, http.StatusInternalServerError),
			response: nil,
		},
		{
			desc:     "get a list of users with limit greater than max",
			token:    token,
			offset:   offset,
			limit:    110,
			err:      errors.NewSDKErrorWithStatus(apiutil.ErrLimitSize, http.StatusInternalServerError),
			response: []sdk.User(nil),
		},
		{
			desc:       "get a list of users with same identity",
			token:      token,
			offset:     0,
			limit:      1,
			err:        nil,
			identifier: Identity,
			metadata:   sdk.Metadata{},
			response:   []sdk.User{cls[89]},
		},
		{
			desc:       "get a list of users with same identity and metadata",
			token:      token,
			offset:     0,
			limit:      1,
			err:        nil,
			identifier: Identity,
			metadata: sdk.Metadata{
				"name": "client99",
			},
			response: []sdk.User{cls[89]},
		},
		{
			desc:   "list users with given metadata",
			token:  generateValidToken(t, svc, cRepo),
			offset: 0,
			limit:  1,
			metadata: sdk.Metadata{
				"name": "client99",
			},
			response: []sdk.User{cls[89]},
			err:      nil,
		},
		{
			desc:     "list users with given name",
			token:    generateValidToken(t, svc, cRepo),
			offset:   0,
			limit:    1,
			name:     "client10",
			response: []sdk.User{cls[0]},
			err:      nil,
		},
		{
			desc:     "list users with given owner",
			token:    generateValidToken(t, svc, cRepo),
			offset:   0,
			limit:    1,
			ownerID:  "clientowner",
			response: []sdk.User{cls[50]},
			err:      nil,
		},
		{
			desc:     "list users with given status",
			token:    generateValidToken(t, svc, cRepo),
			offset:   0,
			limit:    1,
			status:   clients.DisabledStatus.String(),
			response: []sdk.User{cls[50]},
			err:      nil,
		},
		{
			desc:     "list users with given tag",
			token:    generateValidToken(t, svc, cRepo),
			offset:   0,
			limit:    1,
			tag:      "tag1",
			response: []sdk.User{cls[50]},
			err:      nil,
		},
	}

	for _, tc := range cases {
		pm := sdk.PageMetadata{
			Status:   tc.status,
			Total:    total,
			Offset:   uint64(tc.offset),
			Limit:    uint64(tc.limit),
			Name:     tc.name,
			OwnerID:  tc.ownerID,
			Metadata: tc.metadata,
			Tag:      tc.tag,
		}

		repoCall := pRepo.On("Evaluate", mock.Anything, mock.Anything, mock.Anything).Return(nil)
		repoCall1 := cRepo.On("RetrieveAll", mock.Anything, mock.Anything).Return(clients.ClientsPage{Page: convertClientPage(pm), Clients: convertClients(tc.response)}, tc.err)

		page, err := clientSDK.Users(pm, generateValidToken(t, svc, cRepo))
		assert.Equal(t, tc.err, err, fmt.Sprintf("%s: expected error %s, got %s", tc.desc, tc.err, err))
		assert.Equal(t, tc.response, page.Users, fmt.Sprintf("%s: expected %v got %v\n", tc.desc, tc.response, page))

		repoCall.Unset()
		repoCall1.Unset()
	}
}

func TestListMembers(t *testing.T) {
	cRepo := new(cmocks.ClientRepository)
	pRepo := new(pmocks.PolicyRepository)
	tokenizer := jwt.NewTokenRepo([]byte(secret), accessDuration, refreshDuration)

	svc := clients.NewService(cRepo, pRepo, tokenizer, emailer, phasher, idProvider, passRegex)
	ts := newClientServer(svc)
	defer ts.Close()

	conf := sdk.Config{
		UsersURL: ts.URL,
	}
	clientSDK := sdk.NewSDK(conf)

	var nClients = uint64(10)
	var aClients = []sdk.User{}

	for i := uint64(1); i < nClients; i++ {
		client := sdk.User{
			Name: fmt.Sprintf("member_%d@example.com", i),
			Credentials: sdk.Credentials{
				Identity: fmt.Sprintf("member_%d@example.com", i),
				Secret:   "password",
			},
			Tags:     []string{"tag1", "tag2"},
			Metadata: sdk.Metadata{"role": "client"},
			Status:   clients.EnabledStatus.String(),
		}
		aClients = append(aClients, client)
	}

	cases := []struct {
		desc     string
		token    string
		groupID  string
		page     sdk.PageMetadata
		response []sdk.User
		err      errors.SDKError
	}{
		{
			desc:     "list clients with authorized token",
			token:    generateValidToken(t, svc, cRepo),
			groupID:  testsutil.GenerateUUID(t, idProvider),
			page:     sdk.PageMetadata{},
			response: aClients,
			err:      nil,
		},
		{
			desc:    "list clients with offset and limit",
			token:   generateValidToken(t, svc, cRepo),
			groupID: testsutil.GenerateUUID(t, idProvider),
			page: sdk.PageMetadata{
				Offset: 4,
				Limit:  nClients,
			},
			response: aClients[4:],
			err:      nil,
		},
		{
			desc:    "list clients with given name",
			token:   generateValidToken(t, svc, cRepo),
			groupID: testsutil.GenerateUUID(t, idProvider),
			page: sdk.PageMetadata{
				Name:   Identity,
				Offset: 6,
				Limit:  nClients,
			},
			response: aClients[6:],
			err:      nil,
		},

		{
			desc:    "list clients with given ownerID",
			token:   generateValidToken(t, svc, cRepo),
			groupID: testsutil.GenerateUUID(t, idProvider),
			page: sdk.PageMetadata{
				OwnerID: user.Owner,
				Offset:  6,
				Limit:   nClients,
			},
			response: aClients[6:],
			err:      nil,
		},
		{
			desc:    "list clients with given subject",
			token:   generateValidToken(t, svc, cRepo),
			groupID: testsutil.GenerateUUID(t, idProvider),
			page: sdk.PageMetadata{
				Subject: subject,
				Offset:  6,
				Limit:   nClients,
			},
			response: aClients[6:],
			err:      nil,
		},
		{
			desc:    "list clients with given object",
			token:   generateValidToken(t, svc, cRepo),
			groupID: testsutil.GenerateUUID(t, idProvider),
			page: sdk.PageMetadata{
				Object: object,
				Offset: 6,
				Limit:  nClients,
			},
			response: aClients[6:],
			err:      nil,
		},
		{
			desc:     "list clients with an invalid token",
			token:    invalidToken,
			groupID:  testsutil.GenerateUUID(t, idProvider),
			page:     sdk.PageMetadata{},
			response: []sdk.User{},
			err:      errors.NewSDKErrorWithStatus(errors.ErrAuthentication, http.StatusUnauthorized),
		},
		{
			desc:     "list clients with an invalid id",
			token:    generateValidToken(t, svc, cRepo),
			groupID:  mocks.WrongID,
			page:     sdk.PageMetadata{},
			response: []sdk.User{},
			err:      errors.NewSDKErrorWithStatus(errors.ErrNotFound, http.StatusNotFound),
		},
	}

	for _, tc := range cases {
		repoCall := pRepo.On("Evaluate", mock.Anything, mock.Anything, mock.Anything).Return(nil)
		repoCall1 := cRepo.On("Members", mock.Anything, mock.Anything, mock.Anything).Return(clients.MembersPage{Members: convertClients(tc.response)}, tc.err)

		membersPage, err := clientSDK.Members(tc.groupID, tc.page, tc.token)
		assert.Equal(t, tc.err, err, fmt.Sprintf("%s: expected error %s, got %s", tc.desc, tc.err, err))
		assert.Equal(t, tc.response, membersPage, fmt.Sprintf("%s: expected %v got %v\n", tc.desc, tc.response, membersPage))

		repoCall.Unset()
		repoCall1.Unset()

	}
}

func TestClient(t *testing.T) {
	cRepo := new(cmocks.ClientRepository)
	pRepo := new(pmocks.PolicyRepository)
	tokenizer := jwt.NewTokenRepo([]byte(secret), accessDuration, refreshDuration)

	svc := clients.NewService(cRepo, pRepo, tokenizer, emailer, phasher, idProvider, passRegex)
	ts := newClientServer(svc)
	defer ts.Close()

	user = sdk.User{
		Name:        "clientname",
		Tags:        []string{"tag1", "tag2"},
		Credentials: sdk.Credentials{Identity: "clientidentity", Secret: secret},
		Metadata:    validMetadata,
		Status:      clients.EnabledStatus.String(),
	}
	conf := sdk.Config{
		UsersURL: ts.URL,
	}
	clientSDK := sdk.NewSDK(conf)

	cases := []struct {
		desc     string
		token    string
		clientID string
		response sdk.User
		err      errors.SDKError
	}{
		{
			desc:     "view client successfully",
			response: user,
			token:    generateValidToken(t, svc, cRepo),
			clientID: generateUUID(t),
			err:      nil,
		},
		{
			desc:     "view client with an invalid token",
			response: sdk.User{},
			token:    invalidToken,
			clientID: user.ID,
			err:      errors.NewSDKErrorWithStatus(errors.ErrAuthentication, http.StatusUnauthorized),
		},
		{
			desc:     "view client with valid token and invalid client id",
			response: sdk.User{},
			token:    generateValidToken(t, svc, cRepo),
			clientID: mocks.WrongID,
			err:      errors.NewSDKErrorWithStatus(errors.ErrNotFound, http.StatusNotFound),
		},
		{
			desc:     "view client with an invalid token and invalid client id",
			response: sdk.User{},
			token:    invalidToken,
			clientID: mocks.WrongID,
			err:      errors.NewSDKErrorWithStatus(errors.ErrAuthentication, http.StatusUnauthorized),
		},
	}

	for _, tc := range cases {
		repoCall := pRepo.On("Evaluate", mock.Anything, mock.Anything, mock.Anything).Return(nil)
		repoCall1 := cRepo.On("RetrieveByID", mock.Anything, mock.Anything).Return(convertClient(tc.response), tc.err)

		rClient, err := clientSDK.User(tc.token, tc.clientID)
		assert.Equal(t, tc.err, err, fmt.Sprintf("%s: expected error %s, got %s", tc.desc, tc.err, err))
		assert.Equal(t, tc.response, rClient, fmt.Sprintf("%s: expected %v got %v\n", tc.desc, tc.response, rClient))

		repoCall1.Unset()
		repoCall.Unset()
	}
}

func TestUpdateClient(t *testing.T) {
	cRepo := new(cmocks.ClientRepository)
	pRepo := new(pmocks.PolicyRepository)
	tokenizer := jwt.NewTokenRepo([]byte(secret), accessDuration, refreshDuration)

	svc := clients.NewService(cRepo, pRepo, tokenizer, emailer, phasher, idProvider, passRegex)
	ts := newClientServer(svc)
	defer ts.Close()

	conf := sdk.Config{
		UsersURL: ts.URL,
	}
	clientSDK := sdk.NewSDK(conf)

	user = sdk.User{
		ID:          generateUUID(t),
		Name:        "clientname",
		Tags:        []string{"tag1", "tag2"},
		Credentials: sdk.Credentials{Identity: "clientidentity", Secret: secret},
		Metadata:    validMetadata,
		Status:      clients.EnabledStatus.String(),
	}

	client1 := user
	client1.Name = "Updated client"

	client2 := user
	client2.Metadata = sdk.Metadata{"role": "test"}
	client2.ID = invalidIdentity

	cases := []struct {
		desc     string
		client   sdk.User
		response sdk.User
		token    string
		err      errors.SDKError
	}{
		{
			desc:     "update client name with valid token",
			client:   client1,
			response: client1,
			token:    generateValidToken(t, svc, cRepo),
			err:      nil,
		},
		{
			desc:     "update client name with invalid token",
			client:   client1,
			response: sdk.User{},
			token:    invalidToken,
			err:      errors.NewSDKErrorWithStatus(errors.ErrAuthentication, http.StatusUnauthorized),
		},
		{
			desc:     "update client name with invalid id",
			client:   client2,
			response: sdk.User{},
			token:    generateValidToken(t, svc, cRepo),
			err:      errors.NewSDKErrorWithStatus(sdk.ErrFailedUpdate, http.StatusInternalServerError),
		},
	}

	for _, tc := range cases {
		repoCall := pRepo.On("Evaluate", mock.Anything, mock.Anything, mock.Anything).Return(nil)
		repoCall1 := cRepo.On("Update", mock.Anything, mock.Anything).Return(convertClient(tc.response), tc.err)

		uClient, err := clientSDK.UpdateUser(tc.client, tc.token)
		assert.Equal(t, tc.err, err, fmt.Sprintf("%s: expected error %s, got %s", tc.desc, tc.err, err))
		assert.Equal(t, tc.response, uClient, fmt.Sprintf("%s: expected %v got %v\n", tc.desc, tc.response, uClient))

		repoCall1.Unset()
		repoCall.Unset()
	}
}

func TestUpdateClientTags(t *testing.T) {
	cRepo := new(cmocks.ClientRepository)
	pRepo := new(pmocks.PolicyRepository)
	tokenizer := jwt.NewTokenRepo([]byte(secret), accessDuration, refreshDuration)

	svc := clients.NewService(cRepo, pRepo, tokenizer, emailer, phasher, idProvider, passRegex)
	ts := newClientServer(svc)
	defer ts.Close()

	conf := sdk.Config{
		UsersURL: ts.URL,
	}
	clientSDK := sdk.NewSDK(conf)

	user = sdk.User{
		ID:          generateUUID(t),
		Name:        "clientname",
		Tags:        []string{"tag1", "tag2"},
		Credentials: sdk.Credentials{Identity: "clientidentity", Secret: secret},
		Metadata:    validMetadata,
		Status:      clients.EnabledStatus.String(),
	}

	client1 := user
	client1.Tags = []string{"updatedTag1", "updatedTag2"}

	client2 := user
	client2.ID = invalidIdentity

	cases := []struct {
		desc     string
		client   sdk.User
		response sdk.User
		token    string
		err      error
	}{
		{
			desc:     "update client name with valid token",
			client:   user,
			response: client1,
			token:    generateValidToken(t, svc, cRepo),
			err:      nil,
		},
		{
			desc:     "update client name with invalid token",
			client:   client1,
			response: sdk.User{},
			token:    invalidToken,
			err:      errors.NewSDKErrorWithStatus(errors.ErrAuthentication, http.StatusUnauthorized),
		},
		{
			desc:     "update client name with invalid id",
			client:   client2,
			response: sdk.User{},
			token:    generateValidToken(t, svc, cRepo),
			err:      errors.NewSDKErrorWithStatus(sdk.ErrFailedUpdate, http.StatusInternalServerError),
		},
	}

	for _, tc := range cases {
		repoCall := pRepo.On("Evaluate", mock.Anything, mock.Anything, mock.Anything).Return(nil)
		repoCall1 := cRepo.On("UpdateTags", mock.Anything, mock.Anything).Return(convertClient(tc.response), tc.err)

		uClient, err := clientSDK.UpdateUserTags(tc.client, tc.token)
		assert.Equal(t, tc.err, err, fmt.Sprintf("%s: expected error %s, got %s", tc.desc, tc.err, err))
		assert.Equal(t, tc.response, uClient, fmt.Sprintf("%s: expected %v got %v\n", tc.desc, tc.response, uClient))

		repoCall1.Unset()
		repoCall.Unset()
	}
}

func TestUpdateClientIdentity(t *testing.T) {
	cRepo := new(cmocks.ClientRepository)
	pRepo := new(pmocks.PolicyRepository)
	tokenizer := jwt.NewTokenRepo([]byte(secret), accessDuration, refreshDuration)

	svc := clients.NewService(cRepo, pRepo, tokenizer, emailer, phasher, idProvider, passRegex)
	ts := newClientServer(svc)
	defer ts.Close()

	conf := sdk.Config{
		UsersURL: ts.URL,
	}
	clientSDK := sdk.NewSDK(conf)

	user = sdk.User{
		ID:          generateUUID(t),
		Name:        "clientname",
		Tags:        []string{"tag1", "tag2"},
		Credentials: sdk.Credentials{Identity: "updatedclientidentity", Secret: secret},
		Metadata:    validMetadata,
		Status:      clients.EnabledStatus.String(),
	}

	client2 := user
	client2.Metadata = sdk.Metadata{"role": "test"}
	client2.ID = invalidIdentity

	cases := []struct {
		desc     string
		client   sdk.User
		response sdk.User
		token    string
		err      errors.SDKError
	}{
		{
			desc:     "update client name with valid token",
			client:   user,
			response: user,
			token:    generateValidToken(t, svc, cRepo),
			err:      nil,
		},
		{
			desc:     "update client name with invalid token",
			client:   user,
			response: sdk.User{},
			token:    invalidToken,
			err:      errors.NewSDKErrorWithStatus(errors.ErrAuthentication, http.StatusUnauthorized),
		},
		{
			desc:     "update client name with invalid id",
			client:   client2,
			response: sdk.User{},
			token:    generateValidToken(t, svc, cRepo),
			err:      errors.NewSDKErrorWithStatus(sdk.ErrFailedUpdate, http.StatusInternalServerError),
		},
	}

	for _, tc := range cases {
		repoCall := pRepo.On("Evaluate", mock.Anything, mock.Anything, mock.Anything).Return(nil)
		repoCall1 := cRepo.On("RetrieveByID", mock.Anything, mock.Anything).Return(convertClient(tc.client), tc.err)
		repoCall2 := cRepo.On("UpdateIdentity", mock.Anything, mock.Anything).Return(convertClient(tc.response), tc.err)

		uClient, err := clientSDK.UpdateUserIdentity(tc.client, tc.token)
		assert.Equal(t, tc.err, err, fmt.Sprintf("%s: expected error %s, got %s", tc.desc, tc.err, err))
		assert.Equal(t, tc.response, uClient, fmt.Sprintf("%s: expected %v got %v\n", tc.desc, tc.response, uClient))

		repoCall1.Unset()
		repoCall2.Unset()
		repoCall.Unset()
	}
}

func TestUpdateClientSecret(t *testing.T) {
	cRepo := new(cmocks.ClientRepository)
	pRepo := new(pmocks.PolicyRepository)
	tokenizer := jwt.NewTokenRepo([]byte(secret), accessDuration, refreshDuration)

	svc := clients.NewService(cRepo, pRepo, tokenizer, emailer, phasher, idProvider, passRegex)
	ts := newClientServer(svc)
	defer ts.Close()

	conf := sdk.Config{
		UsersURL: ts.URL,
	}
	clientSDK := sdk.NewSDK(conf)

	user.ID = generateUUID(t)
	rclient := user
	rclient.Credentials.Secret, _ = phasher.Hash(user.Credentials.Secret)

	repoCall := cRepo.On("RetrieveByIdentity", context.Background(), mock.Anything).Return(convertClient(rclient), nil)
	token, err := svc.IssueToken(context.Background(), user.Credentials.Identity, user.Credentials.Secret)
	assert.Nil(t, err, fmt.Sprintf("Issue token expected nil got %s\n", err))
	repoCall.Unset()

	cases := []struct {
		desc      string
		oldSecret string
		newSecret string
		token     string
		response  sdk.User
		err       error
	}{
		{
			desc:      "update client secret with valid token",
			oldSecret: user.Credentials.Secret,
			newSecret: "newSecret",
			token:     token.AccessToken,
			response:  rclient,
			err:       nil,
		},
		{
			desc:      "update client secret with invalid token",
			oldSecret: user.Credentials.Secret,
			newSecret: "newPassword",
			token:     "non-existent",
			response:  sdk.User{},
			err:       errors.NewSDKErrorWithStatus(errors.ErrAuthentication, http.StatusUnauthorized),
		},
		{
			desc:      "update client secret with wrong old secret",
			oldSecret: "oldSecret",
			newSecret: "newSecret",
			token:     token.AccessToken,
			response:  sdk.User{},
			err:       errors.NewSDKErrorWithStatus(apiutil.ErrInvalidSecret, http.StatusBadRequest),
		},
	}

	for _, tc := range cases {
		repoCall := pRepo.On("Evaluate", mock.Anything, mock.Anything, mock.Anything).Return(nil)
		repoCall1 := cRepo.On("RetrieveByID", mock.Anything, mock.Anything).Return(convertClient(tc.response), tc.err)
		repoCall2 := cRepo.On("RetrieveByIdentity", mock.Anything, mock.Anything).Return(convertClient(tc.response), tc.err)
		repoCall3 := cRepo.On("UpdateSecret", mock.Anything, mock.Anything).Return(convertClient(tc.response), tc.err)
		uClient, err := clientSDK.UpdatePassword(user.ID, tc.oldSecret, tc.newSecret, tc.token)
		assert.Equal(t, tc.err, err, fmt.Sprintf("%s: expected error %s, got %s", tc.desc, tc.err, err))
		assert.Equal(t, tc.response, uClient, fmt.Sprintf("%s: expected %v got %v\n", tc.desc, tc.response, uClient))
		repoCall1.Unset()
		repoCall2.Unset()
		repoCall3.Unset()
		repoCall.Unset()
	}
}

func TestUpdateClientOwner(t *testing.T) {
	cRepo := new(cmocks.ClientRepository)
	pRepo := new(pmocks.PolicyRepository)
	tokenizer := jwt.NewTokenRepo([]byte(secret), accessDuration, refreshDuration)

	svc := clients.NewService(cRepo, pRepo, tokenizer, emailer, phasher, idProvider, passRegex)
	ts := newClientServer(svc)
	defer ts.Close()

	conf := sdk.Config{
		UsersURL: ts.URL,
	}
	clientSDK := sdk.NewSDK(conf)

	user = sdk.User{
		ID:          generateUUID(t),
		Name:        "clientname",
		Tags:        []string{"tag1", "tag2"},
		Credentials: sdk.Credentials{Identity: "clientidentity", Secret: secret},
		Metadata:    validMetadata,
		Status:      clients.EnabledStatus.String(),
		Owner:       "owner",
	}

	client2 := user
	client2.ID = invalidIdentity

	cases := []struct {
		desc     string
		client   sdk.User
		response sdk.User
		token    string
		err      errors.SDKError
	}{
		{
			desc:     "update client name with valid token",
			client:   user,
			response: user,
			token:    generateValidToken(t, svc, cRepo),
			err:      nil,
		},
		{
			desc:     "update client name with invalid token",
			client:   client2,
			response: sdk.User{},
			token:    invalidToken,
			err:      errors.NewSDKErrorWithStatus(errors.ErrAuthentication, http.StatusUnauthorized),
		},
		{
			desc:     "update client name with invalid id",
			client:   client2,
			response: sdk.User{},
			token:    generateValidToken(t, svc, cRepo),
			err:      errors.NewSDKErrorWithStatus(sdk.ErrFailedUpdate, http.StatusInternalServerError),
		},
	}

	for _, tc := range cases {
		repoCall := pRepo.On("Evaluate", mock.Anything, mock.Anything, mock.Anything).Return(nil)
		repoCall1 := cRepo.On("UpdateOwner", mock.Anything, mock.Anything).Return(convertClient(tc.response), tc.err)

		uClient, err := clientSDK.UpdateUserOwner(tc.client, tc.token)
		assert.Equal(t, tc.err, err, fmt.Sprintf("%s: expected error %s, got %s", tc.desc, tc.err, err))
		assert.Equal(t, tc.response, uClient, fmt.Sprintf("%s: expected %v got %v\n", tc.desc, tc.response, uClient))

		repoCall1.Unset()
		repoCall.Unset()
	}
}

func TestEnableClient(t *testing.T) {
	cRepo := new(cmocks.ClientRepository)
	pRepo := new(pmocks.PolicyRepository)
	tokenizer := jwt.NewTokenRepo([]byte(secret), accessDuration, refreshDuration)

	svc := clients.NewService(cRepo, pRepo, tokenizer, emailer, phasher, idProvider, passRegex)
	ts := newClientServer(svc)
	defer ts.Close()

	conf := sdk.Config{
		UsersURL: ts.URL,
	}
	clientSDK := sdk.NewSDK(conf)

	enabledClient1 := sdk.User{ID: testsutil.GenerateUUID(t, idProvider), Credentials: sdk.Credentials{Identity: "client1@example.com", Secret: "password"}, Status: clients.EnabledStatus.String()}
	disabledClient1 := sdk.User{ID: testsutil.GenerateUUID(t, idProvider), Credentials: sdk.Credentials{Identity: "client3@example.com", Secret: "password"}, Status: clients.DisabledStatus.String()}
	endisabledClient1 := disabledClient1
	endisabledClient1.Status = clients.EnabledStatus.String()
	endisabledClient1.ID = testsutil.GenerateUUID(t, idProvider)

	cases := []struct {
		desc     string
		id       string
		token    string
		client   sdk.User
		response sdk.User
		err      errors.SDKError
	}{
		{
			desc:     "enable disabled client",
			id:       disabledClient1.ID,
			token:    generateValidToken(t, svc, cRepo),
			client:   disabledClient1,
			response: endisabledClient1,
			err:      nil,
		},
		{
			desc:     "enable enabled client",
			id:       enabledClient1.ID,
			token:    generateValidToken(t, svc, cRepo),
			client:   enabledClient1,
			response: sdk.User{},
			err:      errors.NewSDKErrorWithStatus(sdk.ErrFailedEnable, http.StatusInternalServerError),
		},
		{
			desc:     "enable non-existing client",
			id:       mocks.WrongID,
			token:    generateValidToken(t, svc, cRepo),
			client:   sdk.User{},
			response: sdk.User{},
			err:      errors.NewSDKErrorWithStatus(sdk.ErrFailedEnable, http.StatusNotFound),
		},
	}

	for _, tc := range cases {
		repoCall := pRepo.On("Evaluate", mock.Anything, mock.Anything, mock.Anything).Return(nil)
		repoCall1 := cRepo.On("RetrieveByID", mock.Anything, mock.Anything).Return(convertClient(tc.client), tc.err)
		repoCall2 := cRepo.On("ChangeStatus", mock.Anything, mock.Anything, mock.Anything).Return(convertClient(tc.response), tc.err)

		eClient, err := clientSDK.EnableUser(tc.id, tc.token)
		assert.Equal(t, tc.err, err, fmt.Sprintf("%s: expected error %s, got %s", tc.desc, tc.err, err))
		assert.Equal(t, tc.response, eClient, fmt.Sprintf("%s: expected %v got %v\n", tc.desc, tc.response, eClient))

		repoCall1.Unset()
		repoCall2.Unset()
		repoCall.Unset()
	}

	cases2 := []struct {
		desc     string
		token    string
		status   string
		metadata sdk.Metadata
		response sdk.UsersPage
		size     uint64
	}{
		{
			desc:   "list enabled clients",
			status: clients.EnabledStatus.String(),
			size:   2,
			response: sdk.UsersPage{
				Users: []sdk.User{enabledClient1, endisabledClient1},
			},
		},
		{
			desc:   "list disabled clients",
			status: clients.DisabledStatus.String(),
			size:   1,
			response: sdk.UsersPage{
				Users: []sdk.User{disabledClient1},
			},
		},
		{
			desc:   "list enabled and disabled clients",
			status: clients.AllStatus.String(),
			size:   3,
			response: sdk.UsersPage{
				Users: []sdk.User{enabledClient1, disabledClient1, endisabledClient1},
			},
		},
	}

	for _, tc := range cases2 {
		pm := sdk.PageMetadata{
			Total:  100,
			Offset: 0,
			Limit:  100,
			Status: tc.status,
		}

		repoCall := pRepo.On("Evaluate", mock.Anything, mock.Anything, mock.Anything).Return(nil)
		repoCall1 := cRepo.On("RetrieveAll", mock.Anything, mock.Anything).Return(convertClientsPage(tc.response), nil)

		clientsPage, err := clientSDK.Users(pm, generateValidToken(t, svc, cRepo))
		assert.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))
		size := uint64(len(clientsPage.Users))
		assert.Equal(t, tc.size, size, fmt.Sprintf("%s: expected size %d got %d\n", tc.desc, tc.size, size))

		repoCall1.Unset()
		repoCall.Unset()
	}
}

func TestDisableClient(t *testing.T) {
	cRepo := new(cmocks.ClientRepository)
	pRepo := new(pmocks.PolicyRepository)
	tokenizer := jwt.NewTokenRepo([]byte(secret), accessDuration, refreshDuration)

	svc := clients.NewService(cRepo, pRepo, tokenizer, emailer, phasher, idProvider, passRegex)
	ts := newClientServer(svc)
	defer ts.Close()

	conf := sdk.Config{
		UsersURL: ts.URL,
	}
	clientSDK := sdk.NewSDK(conf)

	enabledClient1 := sdk.User{ID: testsutil.GenerateUUID(t, idProvider), Credentials: sdk.Credentials{Identity: "client1@example.com", Secret: "password"}, Status: clients.EnabledStatus.String()}
	disabledClient1 := sdk.User{ID: testsutil.GenerateUUID(t, idProvider), Credentials: sdk.Credentials{Identity: "client3@example.com", Secret: "password"}, Status: clients.DisabledStatus.String()}
	disenabledClient1 := enabledClient1
	disenabledClient1.Status = clients.DisabledStatus.String()
	disenabledClient1.ID = testsutil.GenerateUUID(t, idProvider)

	cases := []struct {
		desc     string
		id       string
		token    string
		client   sdk.User
		response sdk.User
		err      errors.SDKError
	}{
		{
			desc:     "disable enabled client",
			id:       enabledClient1.ID,
			token:    generateValidToken(t, svc, cRepo),
			client:   enabledClient1,
			response: disenabledClient1,
			err:      nil,
		},
		{
			desc:     "disable disabled client",
			id:       disabledClient1.ID,
			token:    generateValidToken(t, svc, cRepo),
			client:   disabledClient1,
			response: sdk.User{},
			err:      errors.NewSDKErrorWithStatus(sdk.ErrFailedDisable, http.StatusInternalServerError),
		},
		{
			desc:     "disable non-existing client",
			id:       mocks.WrongID,
			client:   sdk.User{},
			token:    generateValidToken(t, svc, cRepo),
			response: sdk.User{},
			err:      errors.NewSDKErrorWithStatus(sdk.ErrFailedDisable, http.StatusNotFound),
		},
	}

	for _, tc := range cases {
		repoCall := pRepo.On("Evaluate", mock.Anything, mock.Anything, mock.Anything).Return(nil)
		repoCall1 := cRepo.On("RetrieveByID", mock.Anything, mock.Anything).Return(convertClient(tc.client), tc.err)
		repoCall2 := cRepo.On("ChangeStatus", mock.Anything, mock.Anything, mock.Anything).Return(convertClient(tc.response), tc.err)

		dClient, err := clientSDK.DisableUser(tc.id, tc.token)
		assert.Equal(t, tc.err, err, fmt.Sprintf("%s: expected error %s, got %s", tc.desc, tc.err, err))
		assert.Equal(t, tc.response, dClient, fmt.Sprintf("%s: expected %v got %v\n", tc.desc, tc.response, dClient))

		repoCall1.Unset()
		repoCall2.Unset()
		repoCall.Unset()
	}

	cases2 := []struct {
		desc     string
		token    string
		status   string
		metadata sdk.Metadata
		response sdk.UsersPage
		size     uint64
	}{
		{
			desc:   "list enabled clients",
			status: clients.EnabledStatus.String(),
			size:   2,
			response: sdk.UsersPage{
				Users: []sdk.User{enabledClient1, disenabledClient1},
			},
		},
		{
			desc:   "list disabled clients",
			status: clients.DisabledStatus.String(),
			size:   1,
			response: sdk.UsersPage{
				Users: []sdk.User{disabledClient1},
			},
		},
		{
			desc:   "list enabled and disabled clients",
			status: clients.AllStatus.String(),
			size:   3,
			response: sdk.UsersPage{
				Users: []sdk.User{enabledClient1, disabledClient1, disenabledClient1},
			},
		},
	}

	for _, tc := range cases2 {
		pm := sdk.PageMetadata{
			Total:  100,
			Offset: 0,
			Limit:  100,
			Status: tc.status,
		}
		repoCall := pRepo.On("Evaluate", mock.Anything, mock.Anything, mock.Anything).Return(nil)
		repoCall1 := cRepo.On("RetrieveAll", mock.Anything, mock.Anything).Return(convertClientsPage(tc.response), nil)

		page, err := clientSDK.Users(pm, generateValidToken(t, svc, cRepo))
		assert.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))
		size := uint64(len(page.Users))
		assert.Equal(t, tc.size, size, fmt.Sprintf("%s: expected size %d got %d\n", tc.desc, tc.size, size))

		repoCall1.Unset()
		repoCall.Unset()
	}
}
