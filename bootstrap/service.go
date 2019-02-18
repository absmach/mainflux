//
// Copyright (c) 2018
// Mainflux
//
// SPDX-License-Identifier: Apache-2.0
//

package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/mainflux/mainflux"
	mfsdk "github.com/mainflux/mainflux/sdk/go"
)

const (
	thingType = "device"
	chanName  = "channel"
)

var (
	// ErrNotFound indicates a non-existent entity request.
	ErrNotFound = errors.New("non-existent entity")

	// ErrMalformedEntity indicates malformed entity specification.
	ErrMalformedEntity = errors.New("malformed entity specification")

	// ErrUnauthorizedAccess indicates missing or invalid credentials provided
	// when accessing a protected resource.
	ErrUnauthorizedAccess = errors.New("missing or invalid credentials provided")

	// ErrConflict indicates that entity with the same ID or external ID already exists.
	ErrConflict = errors.New("entity already exists")

	// ErrThings indicates failure to communicate with Mainflux Things service.
	// It can be due to networking error or invalid/unauthorized request.
	ErrThings = errors.New("error receiving response from Things service")
)

var _ Service = (*bootstrapService)(nil)

// Service specifies an API that must be fulfilled by the domain service
// implementation, and all of its decorators (e.g. logging & metrics).
type Service interface {
	// Add adds new Thing to the user identified by the provided key.
	Add(string, Config) (Config, error)

	// View returns Thing with given ID belonging to the user identified by the given key.
	View(string, string) (Config, error)

	// Update updates editable fields of the provided Thing.
	Update(string, Config) error

	// List returns subset of Configs with given search params that belong to the
	// user identified by the given key.
	List(string, Filter, uint64, uint64) (ConfigsPage, error)

	// Remove removes Config with specified key that belongs to the user identified by the given key.
	Remove(string, string) error

	// Bootstrap returns Config to the Thing with provided external ID using external key.
	Bootstrap(string, string) (Config, error)

	// ChangeState changes state of the Thing with given ID and owner.
	ChangeState(string, string, State) error

	// UpdateChannel updates Channel with data received from an event.
	UpdateChannel(Channel) error

	// RemoveConfig removes Configuration with id received from an event.
	RemoveConfig(string) error

	// RemoveChannel removes Channel with id received from an event.
	RemoveChannel(string) error
}

// ConfigReader is used to parse Config into format which will be encoded
// as a JSON and consumed from the client side. The purpose of this interface
// is to provide convenient way to generate custom configuration response
// based on the specific Config which will be consumed by the client.
type ConfigReader interface {
	ReadConfig(Config) (mainflux.Response, error)
}

type bootstrapService struct {
	users   mainflux.UsersServiceClient
	configs ConfigRepository
	sdk     mfsdk.SDK
}

// New returns new Bootstrap service.
func New(users mainflux.UsersServiceClient, configs ConfigRepository, sdk mfsdk.SDK) Service {
	return &bootstrapService{
		configs: configs,
		sdk:     sdk,
		users:   users,
	}
}

func (bs bootstrapService) Add(key string, cfg Config) (Config, error) {
	owner, err := bs.identify(key)
	if err != nil {
		return Config{}, err
	}

	var toConnect []string
	for _, ch := range cfg.MFChannels {
		toConnect = append(toConnect, ch.ID)
	}
	// Check if channels exist. This is the way to prevent invalid configuration to be saved.
	connected, err := bs.configs.Exist(key, toConnect)
	if err != nil {
		return Config{}, err
	}

	cfg.MFChannels, err = bs.connectionChannels(toConnect, connected, key)
	id := cfg.MFThing
	mfThing, err := bs.thing(key, id)
	if err != nil {
		return Config{}, err
	}

	cfg.MFThing = mfThing.ID
	cfg.Owner = owner
	cfg.State = Inactive
	cfg.MFKey = mfThing.Key
	saved, err := bs.configs.Save(cfg, toConnect)

	if err != nil {
		if id == "" {
			bs.sdk.DeleteThing(cfg.MFThing, key)
		}
		return Config{}, err
	}

	cfg.MFThing = saved

	return cfg, nil
}

func (bs bootstrapService) View(key, id string) (Config, error) {
	owner, err := bs.identify(key)
	if err != nil {
		return Config{}, err
	}

	cfg, err := bs.configs.RetrieveByID(owner, id)
	if err != nil {
		return Config{}, err
	}

	for i, ch := range cfg.MFChannels {
		if err := json.Unmarshal(ch.Metadata.([]byte), &cfg.MFChannels[i].Metadata); err != nil {
			return Config{}, err
		}
	}

	return cfg, nil
}

func (bs bootstrapService) Update(key string, cfg Config) error {
	owner, err := bs.identify(key)
	if err != nil {
		return err
	}

	cfg.Owner = owner

	t, err := bs.configs.RetrieveByID(owner, cfg.MFThing)
	if err != nil {
		return err
	}

	id := t.MFThing
	add, remove, common := bs.updateList(t, cfg)
	channels, err := bs.updateChannels(t.MFChannels, add, remove, key)
	if err != nil {
		return err
	}

	cfg.MFChannels = channels
	var connect, disconnect []string

	switch t.State {
	case Active:
		if cfg.State == Inactive {
			disconnect = append(remove, common...)
			break
		}
		connect = add
		disconnect = remove
	default:
		if cfg.State == Active {
			connect = append(add, common...)
		}
	}

	for _, c := range disconnect {
		if err := bs.sdk.DisconnectThing(id, c, key); err != nil {
			if err == mfsdk.ErrNotFound {
				continue
			}
			return ErrThings
		}
	}

	for _, c := range connect {
		if err := bs.sdk.ConnectThing(id, c, key); err != nil {
			if err == mfsdk.ErrNotFound {
				return ErrMalformedEntity
			}
			return ErrThings
		}
	}

	return bs.configs.Update(cfg, append(connect, common...))
}

func (bs bootstrapService) List(key string, filter Filter, offset, limit uint64) (ConfigsPage, error) {
	owner, err := bs.identify(key)
	if err != nil {
		return ConfigsPage{}, err
	}

	if filter.Unknown {
		return bs.configs.RetrieveUnknown(offset, limit), nil
	}

	return bs.configs.RetrieveAll(owner, filter, offset, limit), nil
}

func (bs bootstrapService) Remove(key, id string) error {
	owner, err := bs.identify(key)
	if err != nil {
		return err
	}

	return bs.configs.Remove(owner, id)
}

func (bs bootstrapService) Bootstrap(externalKey, externalID string) (Config, error) {
	cfg, err := bs.configs.RetrieveByExternalID(externalKey, externalID)
	if err != nil {
		if err == ErrNotFound {
			bs.configs.SaveUnknown(externalKey, externalID)
		}
		return Config{}, ErrNotFound
	}

	for i, ch := range cfg.MFChannels {
		if err := json.Unmarshal(ch.Metadata.([]byte), &cfg.MFChannels[i].Metadata); err != nil {
			return Config{}, err
		}
	}

	return cfg, nil
}

func (bs bootstrapService) ChangeState(key, id string, state State) error {
	owner, err := bs.identify(key)
	if err != nil {
		return err
	}

	thing, err := bs.configs.RetrieveByID(owner, id)
	if err != nil {
		return err
	}

	if thing.State == state {
		return nil
	}

	switch state {
	case Active:
		for _, c := range thing.MFChannels {
			if err := bs.sdk.ConnectThing(thing.MFThing, c.ID, key); err != nil {
				return ErrThings
			}
		}
	case Inactive:
		for _, c := range thing.MFChannels {
			if err := bs.sdk.DisconnectThing(thing.MFThing, c.ID, key); err != nil {
				if err == mfsdk.ErrNotFound {
					continue
				}
				return ErrThings
			}
		}
	}

	return bs.configs.ChangeState(owner, id, state)
}

func (bs bootstrapService) UpdateChannel(channel Channel) error {
	return bs.configs.UpdateChannel(channel)
}

func (bs bootstrapService) RemoveConfig(id string) error {
	return bs.configs.Remove("", id)
}

func (bs bootstrapService) RemoveChannel(id string) error {
	return bs.configs.RemoveChannel(id)
}

// Method thing retrieves Mainflux Thing creating one if an empty ID is passed.
func (bs bootstrapService) thing(key, id string) (mfsdk.Thing, error) {
	thingID := id
	var err error

	if id == "" {
		thingID, err = bs.sdk.CreateThing(mfsdk.Thing{Type: thingType}, key)
		if err != nil {
			return mfsdk.Thing{}, err
		}
	}

	thing, err := bs.sdk.Thing(thingID, key)
	if err != nil {
		if err == mfsdk.ErrNotFound {
			return mfsdk.Thing{}, ErrNotFound
		}

		if id != "" {
			bs.sdk.DeleteThing(thingID, key)
		}

		return mfsdk.Thing{}, ErrThings
	}

	return thing, nil
}

func (bs bootstrapService) identify(token string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	res, err := bs.users.Identify(ctx, &mainflux.Token{Value: token})
	if err != nil {
		return "", ErrUnauthorizedAccess
	}

	return res.GetValue(), nil
}

// Method updateList accepts two configs and returns three lists:
// 1) IDs of Channels to be added
// 2) IDs of Channels to be removed
// 3) IDs of common Channels for these two configs
func (bs bootstrapService) updateList(cfg1 Config, cfg2 Config) (add, remove, common []string) {
	var disconnect map[string]bool
	disconnect = make(map[string]bool, len(cfg1.MFChannels))
	for _, c := range cfg1.MFChannels {
		disconnect[c.ID] = true
	}

	for _, c := range cfg2.MFChannels {
		if disconnect[c.ID] {
			// Don't disconnect common elements.
			delete(disconnect, c.ID)
			common = append(common, c.ID)
			continue
		}
		// Connect new elements.
		add = append(add, c.ID)
	}

	for v := range disconnect {
		remove = append(remove, v)
	}

	return
}

func (bs bootstrapService) updateChannels(chs []Channel, add, remove []string, key string) ([]Channel, error) {
	channels := make(map[string]Channel, len(chs))
	for _, ch := range chs {
		channels[ch.ID] = ch
	}

	for _, ch := range remove {
		delete(channels, ch)
	}

	for _, id := range add {
		ch, err := bs.sdk.Channel(id, key)
		if err != nil {
			return []Channel{}, ErrMalformedEntity
		}

		newCh := Channel{
			ID:       ch.ID,
			Name:     ch.Name,
			Metadata: ch.Metadata,
		}

		channels[id] = newCh
	}

	var ret []Channel
	for _, v := range channels {
		ret = append(ret, v)
	}

	return ret, nil
}

func (bs bootstrapService) connectionChannels(channels, connections []string, key string) ([]Channel, error) {
	add := make(map[string]bool, len(channels))
	for _, ch := range channels {
		add[ch] = true
	}

	for _, ch := range connections {
		if add[ch] == true {
			delete(add, ch)
		}
	}

	var ret []Channel
	for id := range add {
		ch, err := bs.sdk.Channel(id, key)
		if err != nil {
			return nil, ErrMalformedEntity
		}

		ret = append(ret, Channel{
			ID:       ch.ID,
			Name:     ch.Name,
			Metadata: ch.Metadata,
		})
	}

	return ret, nil
}
