//
// Copyright (c) 2018
// Mainflux
//
// SPDX-License-Identifier: Apache-2.0
//

package sdk

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// Default msgContentType is SenML
var msgContentType = contentTypeSenMLJSON

// SendMessage - send message on Mainflux channel
func SendMessage(id, msg, token string) error {
	url := serverAddr + "/http/channels/" + id + "/messages"

	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(msg))
	if err != nil {
		return err
	}

	resp, err := sendRequest(req, token, msgContentType)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s", resp.StatusCode)
	}

	return nil
}

// SetContentType - set message content type.
// Available options are SenML JSON, custom JSON and custom binary (octet-stream).
func SetContentType(ct string) error {
	if ct != contentTypeJSON && ct != contentTypeSenMLJSON && ct != contentTypeBinary {
		return errors.New("Unknown Content Type")
	}

	msgContentType = ct

	return nil
}
