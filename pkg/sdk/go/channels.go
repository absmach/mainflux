// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package sdk

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/mainflux/mainflux/pkg/errors"
)

const channelsEndpoint = "channels"

func (sdk mfSDK) CreateChannel(c Channel, token string) (string, error) {
	data, err := json.Marshal(c)
	if err != nil {
		return "", err
	}

	url := fmt.Sprintf("%s/%s", sdk.thingsURL, channelsEndpoint)

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return "", err
	}

	resp, err := sdk.sendRequest(req, token, string(CTJSON))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if err = errors.CheckError(resp, http.StatusCreated); err != nil {
		return "", err
	}

	id := strings.TrimPrefix(resp.Header.Get("Location"), fmt.Sprintf("/%s/", channelsEndpoint))
	return id, nil
}

func (sdk mfSDK) CreateChannels(chs []Channel, token string) ([]Channel, error) {
	data, err := json.Marshal(chs)
	if err != nil {
		return []Channel{}, err
	}

	url := fmt.Sprintf("%s/%s/%s", sdk.thingsURL, channelsEndpoint, "bulk")

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return []Channel{}, err
	}

	resp, err := sdk.sendRequest(req, token, string(CTJSON))
	if err != nil {
		return []Channel{}, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return []Channel{}, err
	}

	if resp.StatusCode != http.StatusCreated {
		return []Channel{}, encodeError(body, resp.StatusCode)
	}

	var ccr createChannelsRes
	if err := json.Unmarshal(body, &ccr); err != nil {
		return []Channel{}, err
	}

	return ccr.Channels, nil
}

func (sdk mfSDK) Channels(token string, pm PageMetadata) (ChannelsPage, error) {
	url, err := sdk.withQueryParams(sdk.thingsURL, channelsEndpoint, pm)

	if err != nil {
		return ChannelsPage{}, err
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return ChannelsPage{}, err
	}

	resp, err := sdk.sendRequest(req, token, string(CTJSON))
	if err != nil {
		return ChannelsPage{}, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return ChannelsPage{}, err
	}

	if resp.StatusCode != http.StatusOK {
		return ChannelsPage{}, encodeError(body, resp.StatusCode)
	}

	var cp ChannelsPage
	if err := json.Unmarshal(body, &cp); err != nil {
		return ChannelsPage{}, err
	}

	return cp, nil
}

func (sdk mfSDK) ChannelsByThing(token, thingID string, offset, limit uint64, disconn bool) (ChannelsPage, error) {
	url := fmt.Sprintf("%s/things/%s/channels?offset=%d&limit=%d&disconnected=%t", sdk.thingsURL, thingID, offset, limit, disconn)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return ChannelsPage{}, err
	}

	resp, err := sdk.sendRequest(req, token, string(CTJSON))
	if err != nil {
		return ChannelsPage{}, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return ChannelsPage{}, err
	}

	if resp.StatusCode != http.StatusOK {
		return ChannelsPage{}, encodeError(body, resp.StatusCode)
	}

	var cp ChannelsPage
	if err := json.Unmarshal(body, &cp); err != nil {
		return ChannelsPage{}, err
	}

	return cp, nil
}

func (sdk mfSDK) Channel(id, token string) (Channel, error) {
	url := fmt.Sprintf("%s/%s/%s", sdk.thingsURL, channelsEndpoint, id)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return Channel{}, err
	}

	resp, err := sdk.sendRequest(req, token, string(CTJSON))
	if err != nil {
		return Channel{}, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return Channel{}, err
	}

	if resp.StatusCode != http.StatusOK {
		return Channel{}, encodeError(body, resp.StatusCode)
	}

	var c Channel
	if err := json.Unmarshal(body, &c); err != nil {
		return Channel{}, err
	}

	return c, nil
}

func (sdk mfSDK) UpdateChannel(c Channel, token string) error {
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/%s/%s", sdk.thingsURL, channelsEndpoint, c.ID)

	req, err := http.NewRequest(http.MethodPut, url, bytes.NewReader(data))
	if err != nil {
		return err
	}

	resp, err := sdk.sendRequest(req, token, string(CTJSON))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return errors.CheckError(resp, http.StatusOK)
}

func (sdk mfSDK) DeleteChannel(id, token string) error {
	url := fmt.Sprintf("%s/%s/%s", sdk.thingsURL, channelsEndpoint, id)

	req, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		return err
	}

	resp, err := sdk.sendRequest(req, token, string(CTJSON))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return errors.CheckError(resp, http.StatusNoContent)
}
