// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package writers

import (
	"fmt"
	"io/ioutil"
	"log"

	"github.com/BurntSushi/toml"
	"github.com/gogo/protobuf/proto"
	"github.com/mainflux/mainflux"
	"github.com/mainflux/mainflux/logger"
	"github.com/mainflux/mainflux/transformers"
	"github.com/mainflux/mainflux/transformers/senml"
	nats "github.com/nats-io/nats.go"
)

type consumer struct {
	nc          *nats.Conn
	channels    map[string]bool
	subtopics   map[string]bool
	repo        MessageRepository
	transformer transformers.Transformer
	logger      logger.Logger
}

func getDefaultFilter() map[string]bool {
	return map[string]bool{"*": true}
}

// Start method starts consuming messages received from NATS.
// This method transforms messages to SenML format before
// using MessageRepository to store them.
func Start(nc *nats.Conn, repo MessageRepository, transformer transformers.Transformer, queue string, channels map[string]bool, subtopics map[string]bool, logger logger.Logger) error {
	c := consumer{
		nc:          nc,
		channels:    channels,
		subtopics:   subtopics,
		repo:        repo,
		transformer: transformer,
		logger:      logger,
	}

	_, err := nc.QueueSubscribe(mainflux.InputChannels, queue, c.consume)
	return err
}

func (c *consumer) consume(m *nats.Msg) {
	var msg mainflux.Message
	if err := proto.Unmarshal(m.Data, &msg); err != nil {
		c.logger.Warn(fmt.Sprintf("Failed to unmarshal received message: %s", err))
		return
	}

	t, err := c.transformer.Transform(msg)
	if err != nil {
		c.logger.Warn(fmt.Sprintf("Failed to tranform received message: %s", err))
		return
	}
	norm, ok := t.([]senml.Message)
	if !ok {
		c.logger.Warn("Invalid message format from the Transformer output.")
		return
	}
	var msgs []senml.Message
	for _, v := range norm {
		if c.channelExists(v.Channel) {
			if c.subtopicExists(v.Subtopic) {
				msgs = append(msgs, v)
			}
		}
	}

	if msgs == nil {
		c.logger.Debug("No message to saved.")
		return
	}

	if err := c.repo.Save(msgs...); err != nil {
		c.logger.Warn(fmt.Sprintf("Failed to save message: %s", err))
		return
	}
}

func (c *consumer) channelExists(channel string) bool {
	if _, ok := c.channels["*"]; ok {
		return true
	}

	_, found := c.channels[channel]
	return found
}

func (c *consumer) subtopicExists(subtopic string) bool {
	if _, ok := c.subtopics["*"]; ok {
		return true
	}

	_, found := c.subtopics[subtopic]
	return found
}

type filterConfig struct {
	List []string `toml:"filter"`
}

type channelsConfig struct {
	Channels filterConfig `toml:"channels"`
}

func LoadChannelsConfig(chanConfigPath string) map[string]bool {
	data, err := ioutil.ReadFile(chanConfigPath)
	if err != nil {
		log.Print(fmt.Sprintf("Failed to open configuration file: %s", err))
		log.Print(fmt.Sprintf("Default configuration is loaded"))
		return getDefaultFilter()
	}

	var channelsCfg channelsConfig
	if err := toml.Unmarshal(data, &channelsCfg); err != nil {
		log.Print(fmt.Sprintf("Failed to unmarshal configuration file: %s", err))
		log.Print(fmt.Sprintf("Default configuration is loaded"))
		return getDefaultFilter()
	}

	channels := map[string]bool{}
	for _, ch := range channelsCfg.Channels.List {
		channels[ch] = true
	}

	return channels
}

type subtopicsConfig struct {
	Subtopics filterConfig `toml:"subtopics"`
}

func LoadSubtopicsConfig(subtopicConfigPath string) map[string]bool {
	data, err := ioutil.ReadFile(subtopicConfigPath)
	if err != nil {
		log.Print(fmt.Sprintf("Failed to open configuration file: %s", err))
		log.Print(fmt.Sprintf("Default configuration is loaded"))
		return getDefaultFilter()
	}

	var subtopicCfg subtopicsConfig
	if err := toml.Unmarshal(data, &subtopicCfg); err != nil {
		log.Print(fmt.Sprintf("Failed to unmarshal configuration file: %s", err))
		log.Print(fmt.Sprintf("Default configuration is loaded"))
		return getDefaultFilter()
	}

	subtopics := map[string]bool{}
	for _, ch := range subtopicCfg.Subtopics.List {
		subtopics[ch] = true
	}

	return subtopics
}
