package bootstrap

import (
	"context"
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

	// List returns subset of Things with given state that belong to the user identified by the given key.
	List(string, Filter, uint64, uint64) ([]Config, error)

	// Remove removes Thing with specified key that belongs to the user identified by the given key.
	Remove(string, string) error

	// Bootstrap returns configuration to the Thing with provided external ID using external key.
	Bootstrap(string, string) (Config, error)

	// ChangeState changes state of the Thing with given ID and owner.
	ChangeState(string, string, State) error
}

// ConfigReader is used to parse Config into format which will be encoded
// as a JSON and consumed from the client side. The purpose of this interface
// is to provide convenient way to generate custom configuration response
// based on the specific Config which will be consumed form the client side.
type ConfigReader interface {
	ReadConfig(Config) (mainflux.Response, error)
}

type bootstrapService struct {
	things ConfigRepository
	sdk    mfsdk.SDK
	users  mainflux.UsersServiceClient
}

// New returns new Bootstrap service.
func New(users mainflux.UsersServiceClient, things ConfigRepository, sdk mfsdk.SDK) Service {
	return &bootstrapService{
		things: things,
		sdk:    sdk,
		users:  users,
	}
}

func (bs bootstrapService) Add(key string, thing Config) (Config, error) {
	owner, err := bs.identify(key)
	if err != nil {
		return Config{}, err
	}

	// Check if channels exist. This is the way to prevent invalid configuration to be saved.
	// However, channels deletion wil eventually cause this; since Bootstrap service is not
	// using events from the Things service at the moment.
	for _, c := range thing.MFChannels {
		if _, err := bs.sdk.Channel(c, key); err != nil {
			return Config{}, ErrMalformedEntity
		}
	}

	mfThing, err := bs.add(key)
	if err != nil {
		return Config{}, err
	}

	thing.Owner = owner
	thing.State = Created
	thing.MFThing = mfThing.ID
	thing.MFKey = mfThing.Key

	id, err := bs.things.Save(thing)
	if err != nil {
		return Config{}, err
	}

	thing.ID = id
	return thing, nil
}

func (bs bootstrapService) View(key, id string) (Config, error) {
	owner, err := bs.identify(key)
	if err != nil {
		return Config{}, err
	}
	return bs.things.RetrieveByID(owner, id)
}

func (bs bootstrapService) Update(key string, thing Config) error {
	owner, err := bs.identify(key)
	if err != nil {
		return err
	}

	thing.Owner = owner

	t, err := bs.things.RetrieveByID(owner, thing.ID)
	if err != nil {
		return err
	}

	id := t.MFThing
	var connect []string
	var disconnect map[string]bool

	switch t.State {
	case Active:
		disconnect = make(map[string]bool, len(t.MFChannels))
		for _, c := range t.MFChannels {
			disconnect[c] = true
		}

		for _, c := range thing.MFChannels {
			if thing.State == Active {
				if disconnect[c] {
					// Don't disconnect common elements.
					delete(disconnect, c)
					continue
				}
				// Connect new elements.
				connect = append(connect, c)
			}
		}

	default:
		if thing.State == Active {
			// Connect all new elements.
			connect = thing.MFChannels
		}
	}

	for c := range disconnect {
		err := bs.sdk.DisconnectThing(id, c, key)
		if err == mfsdk.ErrNotFound {
			return ErrNotFound
		}
		if err != nil {
			return ErrThings
		}
	}

	for _, c := range connect {
		err := bs.sdk.ConnectThing(id, c, key)
		if err == mfsdk.ErrNotFound {
			return ErrNotFound
		}
		if err != nil {
			return ErrThings
		}
	}

	return bs.things.Update(thing)
}

func (bs bootstrapService) List(key string, filter Filter, offset, limit uint64) ([]Config, error) {
	owner, err := bs.identify(key)
	if err != nil {
		return []Config{}, err
	}
	if filter == nil {
		return []Config{}, ErrMalformedEntity
	}
	if _, ok := filter["unknown"]; ok {
		return bs.things.RetrieveUnknown(offset, limit), nil
	}

	return bs.things.RetrieveAll(owner, filter, offset, limit), nil
}

func (bs bootstrapService) Remove(key, id string) error {
	owner, err := bs.identify(key)
	if err != nil {
		return err
	}

	thing, err := bs.things.RetrieveByID(owner, id)
	if err == ErrNotFound {
		return bs.things.Remove(owner, id)
	}
	if err != nil {
		return err
	}

	if err := bs.sdk.DeleteThing(thing.MFThing, key); err != nil {
		return ErrThings
	}

	return bs.things.Remove(owner, id)
}

func (bs bootstrapService) Bootstrap(externalKey, externalID string) (Config, error) {
	thing, err := bs.things.RetrieveByExternalID(externalKey, externalID)
	if err != nil {
		if err == ErrNotFound {
			return Config{}, bs.things.SaveUnknown(externalKey, externalID)
		}
		return Config{}, ErrNotFound
	}

	return thing, nil
}

func (bs bootstrapService) ChangeState(key, id string, state State) error {
	owner, err := bs.identify(key)
	if err != nil {
		return err
	}

	thing, err := bs.things.RetrieveByID(owner, id)
	if err != nil {
		return err
	}

	switch state {
	case Active:
		for i, c := range thing.MFChannels {
			if err := bs.sdk.ConnectThing(thing.MFThing, c, key); err != nil {
				bs.connectionFallback(thing.MFThing, key, thing.MFChannels[:i], false)
				return ErrThings
			}
		}
	case Inactive:
		for i, c := range thing.MFChannels {
			if err := bs.sdk.DisconnectThing(thing.MFThing, c, key); err != nil {
				bs.connectionFallback(thing.MFThing, key, thing.MFChannels[:i], true)
				return ErrThings
			}
		}
	}

	return bs.things.ChangeState(owner, id, state)
}

func (bs bootstrapService) add(key string) (mfsdk.Thing, error) {
	thingID, err := bs.sdk.CreateThing(mfsdk.Thing{Type: thingType}, key)
	if err != nil {
		return mfsdk.Thing{}, err
	}

	thing, err := bs.sdk.Thing(thingID, key)
	if err != nil {
		return mfsdk.Thing{}, bs.sdk.DeleteThing(thingID, key)
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

func (bs bootstrapService) connectionFallback(id string, key string, channels []string, connect bool) {
	for _, c := range channels {
		if connect {
			bs.sdk.ConnectThing(id, c, key)
			continue
		}

		bs.sdk.DisconnectThing(id, c, key)
	}
}
