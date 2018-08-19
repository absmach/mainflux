//
// Copyright (c) 2018
// Mainflux
//
// SPDX-License-Identifier: Apache-2.0
//

package main

import (
	"log"

	"github.com/mainflux/mainflux/cli"
	"github.com/mainflux/mainflux/sdk/go"
	"github.com/spf13/cobra"
)

func main() {

	conf := struct {
		host     string
		port     string
		insecure bool
	}{
		"localhost",
		"",
		false,
	}

	// Root
	var rootCmd = &cobra.Command{
		Use: "mainflux-cli",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			var proto string

			if conf.insecure {
				proto = "http"
			} else {
				proto = "https"
				sdk.SetCerts()
			}

			sdk.SetServerAddr(proto, conf.host, conf.port)
		},
	}

	// API commands
	versionCmd := cli.NewVersionCmd()
	usersCmd := cli.NewUsersCmd()
	thingsCmd := cli.NewThingsCmd()
	channelsCmd := cli.NewChannelsCmd()
	messagesCmd := cli.NewMessagesCmd()

	// Root Commands
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(usersCmd)
	rootCmd.AddCommand(thingsCmd)
	rootCmd.AddCommand(channelsCmd)
	rootCmd.AddCommand(messagesCmd)

	// Root Flags
	rootCmd.PersistentFlags().StringVarP(
		&conf.host, "host", "m", conf.host, "HTTP Host address")
	rootCmd.PersistentFlags().StringVarP(
		&conf.port, "port", "p", conf.port, "HTTP Host Port")
	rootCmd.PersistentFlags().BoolVarP(
		&conf.insecure, "insecure", "i", false, "do not use TLS")

	// Client and Channels Flags
	rootCmd.PersistentFlags().IntVarP(
		&cli.Limit, "limit", "l", 100, "limit query parameter")
	rootCmd.PersistentFlags().IntVarP(
		&cli.Offset, "offset", "o", 0, "offset query parameter")

	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
