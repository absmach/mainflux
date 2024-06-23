// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"

	mgclients "github.com/absmach/magistrala/pkg/clients"
	mgxsdk "github.com/absmach/magistrala/pkg/sdk/go"
	"github.com/spf13/cobra"
)

var cmdThings = []cobra.Command{
	{
		Use:   "create <JSON_thing> <user_auth_token>",
		Short: "Create thing",
		Long: "Creates new thing with provided name and metadata\n" +
			"Usage:\n" +
			"\tmagistrala-cli things create '{\"name\":\"new thing\", \"metadata\":{\"key\": \"value\"}}' $USERTOKEN\n",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 2 {
				logUsage(cmd.Use)
				return
			}

			var thing mgxsdk.Thing
			if err := json.Unmarshal([]byte(args[0]), &thing); err != nil {
				logError(err)
				return
			}
			thing.Status = mgclients.EnabledStatus.String()
			thing, err := sdk.CreateThing(thing, args[1])
			if err != nil {
				logError(err)
				return
			}

			logJSON(thing)
		},
	},
	{
		Use:   "get [all | <thing_id>] <user_auth_token>",
		Short: "Get things",
		Long: "Get all things or get thing by id. Things can be filtered by name or metadata\n" +
			"Usage:\n" +
			"\tmagistrala-cli things get all $USERTOKEN - lists all things\n" +
			"\tmagistrala-cli things get all $USERTOKEN --offset=10 --limit=10 - lists all things with offset and limit\n" +
			"\tmagistrala-cli things get <thing_id> $USERTOKEN - shows thing with provided <thing_id>\n",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 2 {
				logUsage(cmd.Use)
				return
			}
			metadata, err := convertMetadata(Metadata)
			if err != nil {
				logError(err)
				return
			}
			pageMetadata := mgxsdk.PageMetadata{
				Name:     Name,
				Offset:   Offset,
				Limit:    Limit,
				Metadata: metadata,
			}
			if args[0] == all {
				l, err := sdk.Things(pageMetadata, args[1])
				if err != nil {
					logError(err)
					return
				}
				logJSON(l)
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
		Long: "Delete thing by id\n" +
			"Usage:\n" +
			"\tmagistrala-cli things delete <thing_id> $USERTOKEN - delete thing with <thing_id>\n",
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
		Use:   "identify <thing_key>",
		Short: "Identify thing",
		Long: "Validates thing's key and returns its ID\n" +
			"Usage:\n" +
			"\tmagistrala-cli things identify <thing_key>\n",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 1 {
				logUsage(cmd.Use)
				return
			}

			i, err := sdk.IdentifyThing(args[0])
			if err != nil {
				logError(err)
				return
			}

			logJSON(i)
		},
	},
	{
		Use:   "update [<thing_id> <JSON_string> | tags <thing_id> <tags> | secret <thing_id> <secret> ] <user_auth_token>",
		Short: "Update thing",
		Long: "Updates thing with provided id, name and metadata, or updates thing tags, secret\n" +
			"Usage:\n" +
			"\tmagistrala-cli things update <thing_id> '{\"name\":\"new name\", \"metadata\":{\"key\": \"value\"}}' $USERTOKEN\n" +
			"\tmagistrala-cli things update tags <thing_id> '{\"tag1\":\"value1\", \"tag2\":\"value2\"}' $USERTOKEN\n" +
			"\tmagistrala-cli things update secret <thing_id> <newsecret> $USERTOKEN\n",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 4 && len(args) != 3 {
				logUsage(cmd.Use)
				return
			}

			var thing mgxsdk.Thing
			if args[0] == "tags" {
				if err := json.Unmarshal([]byte(args[2]), &thing.Tags); err != nil {
					logError(err)
					return
				}
				thing.ID = args[1]
				thing, err := sdk.UpdateThingTags(thing, args[3])
				if err != nil {
					logError(err)
					return
				}

				logJSON(thing)
				return
			}

			if args[0] == "secret" {
				thing, err := sdk.UpdateThingSecret(args[1], args[2], args[3])
				if err != nil {
					logError(err)
					return
				}

				logJSON(thing)
				return
			}

			if err := json.Unmarshal([]byte(args[1]), &thing); err != nil {
				logError(err)
				return
			}
			thing.ID = args[0]
			thing, err := sdk.UpdateThing(thing, args[2])
			if err != nil {
				logError(err)
				return
			}

			logJSON(thing)
		},
	},
	{
		Use:   "enable <thing_id> <user_auth_token>",
		Short: "Change thing status to enabled",
		Long: "Change thing status to enabled\n" +
			"Usage:\n" +
			"\tmagistrala-cli things enable <thing_id> $USERTOKEN\n",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 2 {
				logUsage(cmd.Use)
				return
			}

			thing, err := sdk.EnableThing(args[0], args[1])
			if err != nil {
				logError(err)
				return
			}

			logJSON(thing)
		},
	},
	{
		Use:   "disable <thing_id> <user_auth_token>",
		Short: "Change thing status to disabled",
		Long: "Change thing status to disabled\n" +
			"Usage:\n" +
			"\tmagistrala-cli things disable <thing_id> $USERTOKEN\n",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 2 {
				logUsage(cmd.Use)
				return
			}

			thing, err := sdk.DisableThing(args[0], args[1])
			if err != nil {
				logError(err)
				return
			}

			logJSON(thing)
		},
	},
	{
		Use:   "share <thing_id> <user_id> <relation> <user_auth_token>",
		Short: "Share thing with a user",
		Long: "Share thing with a user\n" +
			"Usage:\n" +
			"\tmagistrala-cli things share <thing_id> <user_id> <relation> $USERTOKEN\n",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 4 {
				logUsage(cmd.Use)
				return
			}
			req := mgxsdk.UsersRelationRequest{
				Relation: args[2],
				UserIDs:  []string{args[1]},
			}
			err := sdk.ShareThing(args[0], req, args[3])
			if err != nil {
				logError(err)
				return
			}

			logOK()
		},
	},
	{
		Use:   "unshare <thing_id> <user_id> <relation> <user_auth_token>",
		Short: "Unshare thing with a user",
		Long: "Unshare thing with a user\n" +
			"Usage:\n" +
			"\tmagistrala-cli things share  <thing_id> <user_id> <relation> $USERTOKEN\n",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 4 {
				logUsage(cmd.Use)
				return
			}
			req := mgxsdk.UsersRelationRequest{
				Relation: args[2],
				UserIDs:  []string{args[1]},
			}
			err := sdk.UnshareThing(args[0], req, args[3])
			if err != nil {
				logError(err)
				return
			}

			logOK()
		},
	},
	{
		Use:   "connect <thing_id> <channel_id> <user_auth_token>",
		Short: "Connect thing",
		Long: "Connect thing to the channel\n" +
			"Usage:\n" +
			"\tmagistrala-cli things connect <thing_id> <channel_id> $USERTOKEN\n",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 3 {
				logUsage(cmd.Use)
				return
			}

			connIDs := mgxsdk.Connection{
				ChannelID: args[1],
				ThingID:   args[0],
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
		Long: "Disconnect thing to the channel\n" +
			"Usage:\n" +
			"\tmagistrala-cli things disconnect <thing_id> <channel_id> $USERTOKEN\n",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 3 {
				logUsage(cmd.Use)
				return
			}

			connIDs := mgxsdk.Connection{
				ThingID:   args[0],
				ChannelID: args[1],
			}
			if err := sdk.Disconnect(connIDs, args[2]); err != nil {
				logError(err)
				return
			}

			logOK()
		},
	},
	{
		Use:   "connections <thing_id> <user_auth_token>",
		Short: "Connected list",
		Long: "List of Channels connected to Thing\n" +
			"Usage:\n" +
			"\tmagistrala-cli connections <thing_id> $USERTOKEN\n",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 2 {
				logUsage(cmd.Use)
				return
			}
			pm := mgxsdk.PageMetadata{
				Offset: Offset,
				Limit:  Limit,
			}
			cl, err := sdk.ChannelsByThing(args[0], pm, args[1])
			if err != nil {
				logError(err)
				return
			}

			logJSON(cl)
		},
	},
	{
		Use:   "users <thing_id> <user_auth_token>",
		Short: "List users",
		Long: "List users of a thing\n" +
			"Usage:\n" +
			"\tmagistrala-cli things users <thing_id> $USERTOKEN\n",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 2 {
				logUsage(cmd.Use)
				return
			}
			pm := mgxsdk.PageMetadata{
				Offset: Offset,
				Limit:  Limit,
			}
			ul, err := sdk.ListThingUsers(args[0], pm, args[1])
			if err != nil {
				logError(err)
				return
			}

			logJSON(ul)
		},
	},
	{
		Use:   "search <query> <user_auth_token>",
		Short: "Search things",
		Long: "Search things by name, id or tags\n" +
			"Usage:\n" +
			"\tmagistrala-cli things search <query> <user_auth_token>\n",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 2 {
				logUsage(cmd.Use)
				return
			}

			values, err := url.ParseQuery(args[0])
			if err != nil {
				logError(fmt.Errorf("Failed to parse query: %s", err))
			}

			pm := mgxsdk.PageMetadata{
				Name:     values.Get("name"),
				Tag:      values.Get("tags"),
				Identity: values.Get("id"),
			}

			if off, err := strconv.Atoi(values.Get("offset")); err == nil {
				pm.Offset = uint64(off)
			}

			if lim, err := strconv.Atoi(values.Get("limit")); err == nil {
				pm.Limit = uint64(lim)
			}

			things, err := sdk.SearchThings(pm, args[1])
			if err != nil {
				logError(err)
				return
			}

			logJSON(things)
		},
	},
}

// NewThingsCmd returns things command.
func NewThingsCmd() *cobra.Command {
	cmd := cobra.Command{
		Use:   "things [create | get | update | delete | share | connect | disconnect | connections | not-connected | users ]",
		Short: "Things management",
		Long:  `Things management: create, get, update, delete or share Thing, connect or disconnect Thing from Channel and get the list of Channels connected or disconnected from a Thing`,
	}

	for i := range cmdThings {
		cmd.AddCommand(&cmdThings[i])
	}

	return &cmd
}
