// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"

	mfxsdk "github.com/mainflux/mainflux/pkg/sdk/go"
	"github.com/spf13/cobra"
)

var cmdThings = []cobra.Command{
	{
		Use:   "create <JSON_thing> <user_auth_token>",
		Short: "Create thing",
		Long:  `Create new thing, generate his UUID and store it`,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 2 {
				logUsage(cmd.Use)
				return
			}

			var thing mfxsdk.Thing
			if err := json.Unmarshal([]byte(args[0]), &thing); err != nil {
				logError(err)
				return
			}

			id, err := sdk.CreateThing(thing, args[1])
			if err != nil {
				logError(err)
				return
			}

			logCreated(id)
		},
	},
	{
		Use:   "get [all | name <thing_name> | metadata <metadata_json_string> | <thing_id>] <user_auth_token>",
		Short: "Get things",
		Long: `Get all things, group by id, group by name or group by metadata.
		all - lists all things
		name <thing_name> - list all things with <thing_name> 
		metadata <metadata_json_string> - list all things with <metadata_json_string>
		<thing_id> - shows thing with provided <thing_id>`,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) < 2 {
				logUsage(cmd.Use)
				return
			}
			pageMetadata := mfxsdk.PageMetadata{
				Name:     "",
				Offset:   uint64(Offset),
				Limit:    uint64(Limit),
				Metadata: make(map[string]interface{}),
			}
			if args[0] == "all" {
				l, err := sdk.Things(args[1], pageMetadata)
				if err != nil {
					logError(err)
					return
				}
				logJSON(l)
				return
			}
			if args[0] == "name" {
				pageMetadata.Name = args[1]
				l, err := sdk.Things(args[2], pageMetadata)
				if err != nil {
					logError(err)
					return
				}
				logJSON(l)
				return
			}
			if args[0] == "metadata" {
				var metadata map[string]interface{}
				if err := json.Unmarshal([]byte(args[1]), &metadata); err != nil {
					logError(err)
					return
				}
				pageMetadata.Metadata = metadata
				l, err := sdk.Things(args[2], pageMetadata)
				if err != nil {
					logError(err)
					return
				}
				logJSON(l)
				return
			}
			if len(args) > 2 {
				logUsage(cmd.Use)
				return
			}
			t, err := sdk.Thing(args[0], args[1])
			if err != nil {
				logError(err)
				return
			}

			logJSON(t)
		},
	},
	{
		Use:   "delete <thing_id> <user_auth_token>",
		Short: "Delete thing",
		Long:  `Removes thing from database`,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 2 {
				logUsage(cmd.Use)
				return
			}

			if err := sdk.DeleteThing(args[0], args[1]); err != nil {
				logError(err)
				return
			}

			logOK()
		},
	},
	{
		Use:   "update <JSON_string> <user_auth_token>",
		Short: "Update thing",
		Long:  `Update thing record`,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 2 {
				logUsage(cmd.Use)
				return
			}

			var thing mfxsdk.Thing
			if err := json.Unmarshal([]byte(args[0]), &thing); err != nil {
				logError(err)
				return
			}

			if err := sdk.UpdateThing(thing, args[1]); err != nil {
				logError(err)
				return
			}

			logOK()
		},
	},
	{
		Use:   "connect <thing_id> <channel_id> <user_auth_token>",
		Short: "Connect thing",
		Long:  `Connect thing to the channel`,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 3 {
				logUsage(cmd.Use)
				return
			}

			connIDs := mfxsdk.ConnectionIDs{
				ChannelIDs: []string{args[1]},
				ThingIDs:   []string{args[0]},
			}
			if err := sdk.Connect(connIDs, args[2]); err != nil {
				logError(err)
				return
			}

			logOK()
		},
	},
	{
		Use:   "disconnect <thing_id> <channel_id> <user_auth_token>",
		Short: "Disconnect thing",
		Long:  `Disconnect thing to the channel`,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 3 {
				logUsage(cmd.Use)
				return
			}

			if err := sdk.DisconnectThing(args[0], args[1], args[2]); err != nil {
				logError(err)
				return
			}

			logOK()
		},
	},
	{
		Use:   "connections <thing_id> <user_auth_token>",
		Short: "Connected list",
		Long:  `List of Channels connected to Thing`,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 2 {
				logUsage(cmd.Use)
				return
			}

			cl, err := sdk.ChannelsByThing(args[1], args[0], uint64(Offset), uint64(Limit), true)
			if err != nil {
				logError(err)
				return
			}

			logJSON(cl)
		},
	},
	{
		Use:   "not-connected <thing_id> <user_auth_token>",
		Short: "Not-connected list",
		Long:  `List of Channels not connected to a Thing`,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 2 {
				logUsage(cmd.Use)
				return
			}

			cl, err := sdk.ChannelsByThing(args[1], args[0], uint64(Offset), uint64(Limit), false)
			if err != nil {
				logError(err)
				return
			}

			logJSON(cl)
		},
	},
}

// NewThingsCmd returns things command.
func NewThingsCmd() *cobra.Command {
	cmd := cobra.Command{
		Use:   "things [create | get | update | delete | connect | disconnect | connections | not-connected]",
		Short: "Things management",
		Long:  `Things management: create, get, update or delete Thing, connect or disconnect Thing from Channel and get the list of Channels connected or disconnected from a Thing`,
	}

	for i := range cmdThings {
		cmd.AddCommand(&cmdThings[i])
	}

	return &cmd
}
