// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package cli_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/absmach/magistrala/cli"
	"github.com/absmach/magistrala/pkg/errors"
	svcerr "github.com/absmach/magistrala/pkg/errors/service"
	mgsdk "github.com/absmach/magistrala/pkg/sdk/go"
	sdkmocks "github.com/absmach/magistrala/pkg/sdk/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

const(
	config = "config"
	connection = "connection"
	whitelistCmd = "whitelist"
	bootStrapCmd = "bootstrap"
)

var bootConfig = mgsdk.BootstrapConfig{
	ThingID:  thing.ID,
	Channels: []string{channel.ID},
	Name:     "Test Bootstrap",
}

func TestCreateBootstrapConfigCmd(t *testing.T) {
	sdkMock := new(sdkmocks.SDK)
	cli.SetSDK(sdkMock)
	bootCmd := cli.NewBootstrapCmd()
	rootCmd := setFlags(bootCmd)

	jsonConfig := fmt.Sprintf("{\"external_id\":\"09:6:0:sb:sa\", \"thing_id\": \"%s\", \"external_key\":\"key\", \"name\": \"%s\", \"channels\":[\"%s\"]}", thing.ID, "Test Bootstrap", channel.ID)
	invalidJson := fmt.Sprintf("{\"external_id\":\"09:6:0:sb:sa\", \"thing_id\": \"%s\", \"external_key\":\"key\", \"name\": \"%s\", \"channels\":[\"%s\"]", thing.ID, "Test Bootdtrap", channel.ID)
	cases := []struct {
		desc          string
		args          []string
		logType       outputLog
		response      string
		sdkErr        errors.SDKError
		errLogMessage string
		id            string
	}{
		{
			desc: "create bootstrap config successfully",
			args: []string{
				jsonConfig,
				validToken,
			},
			logType:  createLog,
			id:       thing.ID,
			response: fmt.Sprintf("\ncreated: %s\n\n", thing.ID),
		},
		{
			desc: "create bootstrap config with invald args",
			args: []string{
				jsonConfig,
				validToken,
				extraArg,
			},
			logType: usageLog,
		},
		{
			desc: "create bootstrap config with invald json",
			args: []string{
				invalidJson,
				validToken,
			},
			sdkErr:        errors.NewSDKError(errors.New("unexpected end of JSON input")),
			errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.New("unexpected end of JSON input")),
			logType:       errLog,
		},
		{
			desc: "create bootstrap config with invald json",
			args: []string{
				jsonConfig,
				invalidToken,
			},
			sdkErr:        errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusUnauthorized),
			errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusUnauthorized)),
			logType:       errLog,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkMock.On("AddBootstrap", mock.Anything, mock.Anything).Return(tc.id, tc.sdkErr)
			out := executeCommand(t, rootCmd, append([]string{createCmd}, tc.args...)...)

			switch tc.logType {
			case createLog:
				assert.Equal(t, tc.response, out, fmt.Sprintf("%s unexpected error response: expected %s got errLogMessage:%s", tc.desc, tc.response, out))
			case errLog:
				assert.Equal(t, tc.errLogMessage, out, fmt.Sprintf("%s unexpected error response: expected %s got errLogMessage:%s", tc.desc, tc.errLogMessage, out))
			case usageLog:
				assert.False(t, strings.Contains(out, rootCmd.Use), fmt.Sprintf("%s invalid usage: %s", tc.desc, out))
			}
			sdkCall.Unset()
		})
	}

}

func TestGetBootstrapConfigCmd(t *testing.T) {
	sdkMock := new(sdkmocks.SDK)
	cli.SetSDK(sdkMock)
	bootCmd := cli.NewBootstrapCmd()
	rootCmd := setFlags(bootCmd)

	var boot mgsdk.BootstrapConfig
	var page mgsdk.BootstrapPage

	cases := []struct {
		desc          string
		args          []string
		sdkErr        errors.SDKError
		page          mgsdk.BootstrapPage
		boot          mgsdk.BootstrapConfig
		logType       outputLog
		errLogMessage string
	}{
		{
			desc: "get all bootstrap config successfully",
			args: []string{
				all,
				token,
			},
			page: mgsdk.BootstrapPage{
				PageRes: mgsdk.PageRes{
					Total:  1,
					Offset: 0,
					Limit:  10,
				},
				Configs: []mgsdk.BootstrapConfig{bootConfig},
			},
			logType: entityLog,
		},
		{
			desc: "get bootstrap config with id",
			args: []string{
				channel.ID,
				token,
			},
			logType: entityLog,
			boot:    bootConfig,
		},
		{
			desc: "get bootstrap config with invalid args",
			args: []string{
				all,
				token,
				extraArg,
			},
			logType: usageLog,
		},
		{
			desc: "get all bootstrap config with invalid token",
			args: []string{
				all,
				invalidToken,
			},
			logType:       errLog,
			sdkErr:        errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusForbidden),
			errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusForbidden)),
		},
		{
			desc: "get bootstrap config with invalid id",
			args: []string{
				invalidID,
				token,
			},
			sdkErr:        errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusForbidden),
			errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusForbidden)),
			logType:       errLog,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkMock.On("ViewBootstrap", tc.args[0], tc.args[1]).Return(tc.boot, tc.sdkErr)
			sdkCall1 := sdkMock.On("Bootstraps", mock.Anything, tc.args[1]).Return(tc.page, tc.sdkErr)

			out := executeCommand(t, rootCmd, append([]string{getCmd}, tc.args...)...)

			switch tc.logType {
			case entityLog:
				if tc.args[0] == all {
					err := json.Unmarshal([]byte(out), &page)
					assert.Nil(t, err)
					assert.Equal(t, tc.page, page, fmt.Sprintf("%v unexpected response, expected: %v, got: %v", tc.desc, tc.page, page))
				} else {
					err := json.Unmarshal([]byte(out), &boot)
					assert.Nil(t, err)
					assert.Equal(t, tc.boot, boot, fmt.Sprintf("%v unexpected response, expected: %v, got: %v", tc.desc, tc.boot, boot))
				}
			case errLog:
				assert.Equal(t, tc.errLogMessage, out, fmt.Sprintf("%s unexpected error response: expected %s got errLogMessage:%s", tc.desc, tc.errLogMessage, out))
			case usageLog:
				assert.False(t, strings.Contains(out, rootCmd.Use), fmt.Sprintf("%s invalid usage: %s", tc.desc, out))
			}
			sdkCall.Unset()
			sdkCall1.Unset()
		})
	}
}

func TestRemoveBootstrapConfigCmd(t *testing.T) {
	sdkMock := new(sdkmocks.SDK)
	cli.SetSDK(sdkMock)
	bootCmd := cli.NewBootstrapCmd()
	rootCmd := setFlags(bootCmd)

	cases := []struct {
		desc          string
		args          []string
		sdkErr        errors.SDKError
		logType       outputLog
		errLogMessage string
	}{
		{
			desc: "remove bootstrap config successfully",
			args: []string{
				thing.ID,
				token,
			},
			logType: okLog,
		},
		{
			desc: "remove bootstrap config with invalid args",
			args: []string{
				thing.ID,
				token,
				extraArg,
			},
			logType: usageLog,
		},
		{
			desc: "remove bootstrap config with invalid thing id",
			args: []string{
				invalidID,
				token,
			},
			sdkErr:        errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusForbidden),
			errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusForbidden)),
			logType:       errLog,
		},
		{
			desc: "remove bootstrap config with invalid token",
			args: []string{
				thing.ID,
				invalidToken,
			},
			sdkErr:        errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusForbidden),
			errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusForbidden)),
			logType:       errLog,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkMock.On("RemoveBootstrap", tc.args[0], tc.args[1]).Return(tc.sdkErr)
			out := executeCommand(t, rootCmd, append([]string{rmCmd}, tc.args...)...)

			switch tc.logType {
			case okLog:
				assert.True(t, strings.Contains(out, "ok"), fmt.Sprintf("%s unexpected response: expected success message, got: %v", tc.desc, out))
			case errLog:
				assert.Equal(t, tc.errLogMessage, out, fmt.Sprintf("%s unexpected error response: expected %s got errLogMessage:%s", tc.desc, tc.errLogMessage, out))
			case usageLog:
				assert.False(t, strings.Contains(out, rootCmd.Use), fmt.Sprintf("%s invalid usage: %s", tc.desc, out))
			}
			sdkCall.Unset()
		})
	}
}

func TestUpdateBootstrapConfigCmd(t *testing.T) {
	sdkMock := new(sdkmocks.SDK)
	cli.SetSDK(sdkMock)
	bootCmd := cli.NewBootstrapCmd()
	rootCmd := setFlags(bootCmd)

	newConfigJson := "{\"name\" : \"New Bootstrap\"}"
	cases := []struct {
		desc          string
		args          []string
		boot       mgsdk.BootstrapConfig
		sdkErr        errors.SDKError
		errLogMessage string
		logType       outputLog
	}{
		{
			desc: "update bootstrap config successfully",
			args: []string{
				config,
				newConfigJson,
				token,
			},
			logType: okLog,
		},
		// {
		// 	desc: "update bootstrap config with invalid args",
		// 	args: []string{
		// 		newConfigJson,
		// 		token,
		// 	},
		// 	logType: usageLog,
		// },
		// {
		// 	desc: "update bootstrap config with invalid channel id",
		// 	args: []string{
		// 		invalidID,
		// 		newConfigJson,
		// 		token,
		// 	},
		// 	sdkErr:        errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusForbidden),
		// 	errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusForbidden)),
		// 	logType:       errLog,
		// },
		// {
		// 	desc: "update bootstrap config with invalid json syntax",
		// 	args: []string{
		// 		channel.ID,
		// 		"{\"name\" : \"channel1\"",
		// 		token,
		// 	},
		// 	sdkErr:        errors.NewSDKError(errors.New("unexpected end of JSON input")),
		// 	errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.New("unexpected end of JSON input")),
		// 	logType:       errLog,
		// },
	}
	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			var boot mgsdk.BootstrapConfig
			sdkCall := sdkMock.On("UpdateBootstrap", mock.Anything, mock.Anything).Return(tc.sdkErr)
			out := executeCommand(t, rootCmd, append([]string{updCmd}, tc.args...)...)

			switch tc.logType {
			case entityLog:
				err := json.Unmarshal([]byte(out), &boot)
				assert.Nil(t, err)
				assert.Equal(t, tc.boot, boot, fmt.Sprintf("%s unexpected response: expected: %v, got: %v", tc.desc, tc.boot, boot))
			case okLog:
				assert.True(t, strings.Contains(out, "ok"), fmt.Sprintf("%s unexpected response: expected success message, got: %v", tc.desc, out))
			case usageLog:
				assert.False(t, strings.Contains(out, rootCmd.Use), fmt.Sprintf("%s invalid usage: %s", tc.desc, out))
			case errLog:
				assert.Equal(t, tc.errLogMessage, out, fmt.Sprintf("%s unexpected error response: expected %s got errLogMessage:%s", tc.desc, tc.errLogMessage, out))
			}
			sdkCall.Unset()
		})
	}
}

func TestWhitelistConfig(t *testing.T) {
	sdkMock := new(sdkmocks.SDK)
	cli.SetSDK(sdkMock)
	bootCmd := cli.NewBootstrapCmd()
	rootCmd := setFlags(bootCmd)

	// jsonConfig := fmt.Sprintf("{\"thing_id\": \"%s\", \"state\":\"%s\"}", thing.ID, "1")

	cases := []struct{
		desc string
		args []string
		logType outputLog
		errLogMessage string
		sdkErr errors.SDKError
	}{
		{
			desc: "whitelist config successfully",
			args: []string{
				"{\"name\":\"testchannel\", \"key1\":\"value1\"}",
				validToken,
			},
			logType: okLog,
		},
	}

	for _,tc := range  cases{
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkMock.On("Whitelist", mock.Anything, mock.Anything,tc.args[1]).Return(tc.sdkErr)
			out := executeCommand(t, rootCmd, append([]string{whitelistCmd}, tc.args...)...)
			switch tc.logType {
			case okLog:
				assert.True(t, strings.Contains(out, "ok"), fmt.Sprintf("%s unexpected response: expected success message, got: %v", tc.desc, out))
			case usageLog:
				assert.False(t, strings.Contains(out, rootCmd.Use), fmt.Sprintf("%s invalid usage: %s", tc.desc, out))
			case errLog:
				assert.Equal(t, tc.errLogMessage, out, fmt.Sprintf("%s unexpected error response: expected %s got errLogMessage:%s", tc.desc, tc.errLogMessage, out))
			}
			sdkCall.Unset()
		})
	}
}