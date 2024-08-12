// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package sdk

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/absmach/magistrala/pkg/apiutil"
	"github.com/absmach/magistrala/pkg/clients"
	"github.com/absmach/magistrala/pkg/errors"
)

const (
	permissionsEndpoint = "permissions"
	thingsEndpoint      = "things"
	connectEndpoint     = "connect"
	disconnectEndpoint  = "disconnect"
	identifyEndpoint    = "identify"
	shareEndpoint       = "share"
	unshareEndpoint     = "unshare"
)

// Thing represents magistrala thing.
type Thing struct {
	ID          string                 `json:"id,omitempty"`
	Name        string                 `json:"name,omitempty"`
	Credentials Credentials            `json:"credentials"`
	Tags        []string               `json:"tags,omitempty"`
	DomainID    string                 `json:"domain_id,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt   time.Time              `json:"created_at,omitempty"`
	UpdatedAt   time.Time              `json:"updated_at,omitempty"`
	Status      string                 `json:"status,omitempty"`
	Permissions []string               `json:"permissions,omitempty"`
	ThingsID    []string               `json:"things_id,omitempty"`
}

type ConnectionStatus struct {
	ChannelID string        `json:"channel_id"`
	ThingID   string        `json:"thing_id"`
	Status    clients.State `json:"status"`
}

func (sdk mgSDK) CreateThing(thing Thing, token string) (Thing, errors.SDKError) {
	data, err := json.Marshal(thing)
	if err != nil {
		return Thing{}, errors.NewSDKError(err)
	}

	url := fmt.Sprintf("%s/%s", sdk.thingsURL, thingsEndpoint)

	_, body, sdkerr := sdk.processRequest(http.MethodPost, url, token, data, nil, http.StatusCreated)
	if sdkerr != nil {
		return Thing{}, sdkerr
	}

	thing = Thing{}
	if err := json.Unmarshal(body, &thing); err != nil {
		return Thing{}, errors.NewSDKError(err)
	}

	return thing, nil
}

func (sdk mgSDK) CreateThings(things []Thing, token string) ([]Thing, errors.SDKError) {
	data, err := json.Marshal(things)
	if err != nil {
		return []Thing{}, errors.NewSDKError(err)
	}

	url := fmt.Sprintf("%s/%s/%s", sdk.thingsURL, thingsEndpoint, "bulk")

	_, body, sdkerr := sdk.processRequest(http.MethodPost, url, token, data, nil, http.StatusOK)
	if sdkerr != nil {
		return []Thing{}, sdkerr
	}

	var ctr createThingsRes
	if err := json.Unmarshal(body, &ctr); err != nil {
		return []Thing{}, errors.NewSDKError(err)
	}

	return ctr.Things, nil
}

func (sdk mgSDK) Things(pm PageMetadata, token string) (ThingsPage, errors.SDKError) {
	url, err := sdk.withQueryParams(sdk.thingsURL, thingsEndpoint, pm)
	if err != nil {
		return ThingsPage{}, errors.NewSDKError(err)
	}

	_, body, sdkerr := sdk.processRequest(http.MethodGet, url, token, nil, nil, http.StatusOK)
	if sdkerr != nil {
		return ThingsPage{}, sdkerr
	}

	var cp ThingsPage
	if err := json.Unmarshal(body, &cp); err != nil {
		return ThingsPage{}, errors.NewSDKError(err)
	}

	return cp, nil
}

func (sdk mgSDK) ThingsByChannel(chanID string, pm PageMetadata, token string) (ThingsPage, errors.SDKError) {
	url, err := sdk.withQueryParams(sdk.thingsURL, fmt.Sprintf("channels/%s/%s", chanID, thingsEndpoint), pm)
	if err != nil {
		return ThingsPage{}, errors.NewSDKError(err)
	}

	_, body, sdkerr := sdk.processRequest(http.MethodGet, url, token, nil, nil, http.StatusOK)
	if sdkerr != nil {
		return ThingsPage{}, sdkerr
	}

	var tp ThingsPage
	if err := json.Unmarshal(body, &tp); err != nil {
		return ThingsPage{}, errors.NewSDKError(err)
	}

	return tp, nil
}

func (sdk mgSDK) VerifyConnections(pm PageMetadata, token string) (ConnectionsPage, errors.SDKError) {
	data, err := json.Marshal(pm)
	if err != nil {
		return ConnectionsPage{}, errors.NewSDKError(err)
	}

	url := fmt.Sprintf("%s/%s/verify-connections", sdk.thingsURL, thingsEndpoint)

	_, body, sdkerr := sdk.processRequest(http.MethodPost, url, token, data, nil, http.StatusOK)
	if sdkerr != nil {
		return ConnectionsPage{}, sdkerr
	}

	var cp ConnectionsPage
	if err := json.Unmarshal(body, &cp); err != nil {
		return ConnectionsPage{}, errors.NewSDKError(err)
	}

	return cp, nil
}

func (sdk mgSDK) Thing(id, token string) (Thing, errors.SDKError) {
	if id == "" {
		return Thing{}, errors.NewSDKError(apiutil.ErrMissingID)
	}
	url := fmt.Sprintf("%s/%s/%s", sdk.thingsURL, thingsEndpoint, id)

	_, body, sdkerr := sdk.processRequest(http.MethodGet, url, token, nil, nil, http.StatusOK)
	if sdkerr != nil {
		return Thing{}, sdkerr
	}

	var t Thing
	if err := json.Unmarshal(body, &t); err != nil {
		return Thing{}, errors.NewSDKError(err)
	}

	return t, nil
}

func (sdk mgSDK) ThingPermissions(id, token string) (Thing, errors.SDKError) {
	url := fmt.Sprintf("%s/%s/%s/%s", sdk.thingsURL, thingsEndpoint, id, permissionsEndpoint)

	_, body, sdkerr := sdk.processRequest(http.MethodGet, url, token, nil, nil, http.StatusOK)
	if sdkerr != nil {
		return Thing{}, sdkerr
	}

	var t Thing
	if err := json.Unmarshal(body, &t); err != nil {
		return Thing{}, errors.NewSDKError(err)
	}

	return t, nil
}

func (sdk mgSDK) UpdateThing(t Thing, token string) (Thing, errors.SDKError) {
	if t.ID == "" {
		return Thing{}, errors.NewSDKError(apiutil.ErrMissingID)
	}
	url := fmt.Sprintf("%s/%s/%s", sdk.thingsURL, thingsEndpoint, t.ID)

	data, err := json.Marshal(t)
	if err != nil {
		return Thing{}, errors.NewSDKError(err)
	}

	_, body, sdkerr := sdk.processRequest(http.MethodPatch, url, token, data, nil, http.StatusOK)
	if sdkerr != nil {
		return Thing{}, sdkerr
	}

	t = Thing{}
	if err := json.Unmarshal(body, &t); err != nil {
		return Thing{}, errors.NewSDKError(err)
	}

	return t, nil
}

func (sdk mgSDK) UpdateThingTags(t Thing, token string) (Thing, errors.SDKError) {
	data, err := json.Marshal(t)
	if err != nil {
		return Thing{}, errors.NewSDKError(err)
	}

	url := fmt.Sprintf("%s/%s/%s/tags", sdk.thingsURL, thingsEndpoint, t.ID)

	_, body, sdkerr := sdk.processRequest(http.MethodPatch, url, token, data, nil, http.StatusOK)
	if sdkerr != nil {
		return Thing{}, sdkerr
	}

	t = Thing{}
	if err := json.Unmarshal(body, &t); err != nil {
		return Thing{}, errors.NewSDKError(err)
	}

	return t, nil
}

func (sdk mgSDK) UpdateThingSecret(id, secret, token string) (Thing, errors.SDKError) {
	ucsr := updateThingSecretReq{Secret: secret}

	data, err := json.Marshal(ucsr)
	if err != nil {
		return Thing{}, errors.NewSDKError(err)
	}

	url := fmt.Sprintf("%s/%s/%s/secret", sdk.thingsURL, thingsEndpoint, id)

	_, body, sdkerr := sdk.processRequest(http.MethodPatch, url, token, data, nil, http.StatusOK)
	if sdkerr != nil {
		return Thing{}, sdkerr
	}

	var t Thing
	if err = json.Unmarshal(body, &t); err != nil {
		return Thing{}, errors.NewSDKError(err)
	}

	return t, nil
}

func (sdk mgSDK) EnableThing(id, token string) (Thing, errors.SDKError) {
	return sdk.changeThingStatus(id, enableEndpoint, token)
}

func (sdk mgSDK) DisableThing(id, token string) (Thing, errors.SDKError) {
	return sdk.changeThingStatus(id, disableEndpoint, token)
}

func (sdk mgSDK) changeThingStatus(id, status, token string) (Thing, errors.SDKError) {
	url := fmt.Sprintf("%s/%s/%s/%s", sdk.thingsURL, thingsEndpoint, id, status)

	_, body, sdkerr := sdk.processRequest(http.MethodPost, url, token, nil, nil, http.StatusOK)
	if sdkerr != nil {
		return Thing{}, sdkerr
	}

	t := Thing{}
	if err := json.Unmarshal(body, &t); err != nil {
		return Thing{}, errors.NewSDKError(err)
	}

	return t, nil
}

func (sdk mgSDK) ShareThing(thingID string, req UsersRelationRequest, token string) errors.SDKError {
	data, err := json.Marshal(req)
	if err != nil {
		return errors.NewSDKError(err)
	}

	url := fmt.Sprintf("%s/%s/%s/%s", sdk.thingsURL, thingsEndpoint, thingID, shareEndpoint)

	_, _, sdkerr := sdk.processRequest(http.MethodPost, url, token, data, nil, http.StatusCreated)
	return sdkerr
}

func (sdk mgSDK) UnshareThing(thingID string, req UsersRelationRequest, token string) errors.SDKError {
	data, err := json.Marshal(req)
	if err != nil {
		return errors.NewSDKError(err)
	}

	url := fmt.Sprintf("%s/%s/%s/%s", sdk.thingsURL, thingsEndpoint, thingID, unshareEndpoint)

	_, _, sdkerr := sdk.processRequest(http.MethodPost, url, token, data, nil, http.StatusNoContent)
	return sdkerr
}

func (sdk mgSDK) ListThingUsers(thingID string, pm PageMetadata, token string) (UsersPage, errors.SDKError) {
	url, err := sdk.withQueryParams(sdk.usersURL, fmt.Sprintf("%s/%s/%s", thingsEndpoint, thingID, usersEndpoint), pm)
	if err != nil {
		return UsersPage{}, errors.NewSDKError(err)
	}

	_, body, sdkerr := sdk.processRequest(http.MethodGet, url, token, nil, nil, http.StatusOK)
	if sdkerr != nil {
		return UsersPage{}, sdkerr
	}
	up := UsersPage{}
	if err := json.Unmarshal(body, &up); err != nil {
		return UsersPage{}, errors.NewSDKError(err)
	}

	return up, nil
}

func (sdk mgSDK) DeleteThing(id, token string) errors.SDKError {
	if id == "" {
		return errors.NewSDKError(apiutil.ErrMissingID)
	}
	url := fmt.Sprintf("%s/%s/%s", sdk.thingsURL, thingsEndpoint, id)
	_, _, sdkerr := sdk.processRequest(http.MethodDelete, url, token, nil, nil, http.StatusNoContent)
	return sdkerr
}
