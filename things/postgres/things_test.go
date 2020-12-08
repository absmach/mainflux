// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package postgres_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/mainflux/mainflux/pkg/errors"
	uuidProvider "github.com/mainflux/mainflux/pkg/uuid"
	"github.com/mainflux/mainflux/things"
	"github.com/mainflux/mainflux/things/postgres"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const maxNameSize = 1024

var invalidName = strings.Repeat("m", maxNameSize+1)

func TestThingsSave(t *testing.T) {
	dbMiddleware := postgres.NewDatabase(db)
	thingRepo := postgres.NewThingRepository(dbMiddleware)

	email := "thing-save@example.com"

	nonexistentThingKey, err := uuidProvider.New().ID()
	require.Nil(t, err, fmt.Sprintf("got unexpected error: %s", err))

	ths := []things.Thing{}
	for i := 1; i <= 5; i++ {
		thid, err := uuidProvider.New().ID()
		require.Nil(t, err, fmt.Sprintf("got unexpected error: %s", err))
		thkey, err := uuidProvider.New().ID()
		require.Nil(t, err, fmt.Sprintf("got unexpected error: %s", err))

		thing := things.Thing{
			ID:    thid,
			Owner: email,
			Key:   thkey,
		}
		ths = append(ths, thing)
	}
	thkey := ths[0].Key
	thid := ths[0].ID

	cases := []struct {
		desc   string
		things []things.Thing
		err    error
	}{
		{
			desc:   "create new things",
			things: ths,
			err:    nil,
		},
		{
			desc:   "create things that already exist",
			things: ths,
			err:    things.ErrConflict,
		},
		{
			desc: "create thing with invalid ID",
			things: []things.Thing{
				{ID: "invalid", Owner: email, Key: thkey},
			},
			err: things.ErrMalformedEntity,
		},
		{
			desc: "create thing with invalid name",
			things: []things.Thing{
				{ID: thid, Owner: email, Key: thkey, Name: invalidName},
			},
			err: things.ErrMalformedEntity,
		},
		{
			desc: "create thing with invalid Key",
			things: []things.Thing{
				{ID: thid, Owner: email, Key: nonexistentThingKey},
			},
			err: things.ErrConflict,
		},
		{
			desc:   "create things with conflicting keys",
			things: ths,
			err:    things.ErrConflict,
		},
	}

	for _, tc := range cases {
		_, err := thingRepo.Save(context.Background(), tc.things...)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
	}
}

func TestThingUpdate(t *testing.T) {
	dbMiddleware := postgres.NewDatabase(db)
	thingRepo := postgres.NewThingRepository(dbMiddleware)

	email := "thing-update@example.com"
	validName := "mfx_device"

	thid, err := uuidProvider.New().ID()
	require.Nil(t, err, fmt.Sprintf("got unexpected error: %s", err))
	thkey, err := uuidProvider.New().ID()
	require.Nil(t, err, fmt.Sprintf("got unexpected error: %s", err))

	thing := things.Thing{
		ID:    thid,
		Owner: email,
		Key:   thkey,
	}

	sths, err := thingRepo.Save(context.Background(), thing)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	thing.ID = sths[0].ID

	nonexistentThingID, err := uuidProvider.New().ID()
	require.Nil(t, err, fmt.Sprintf("got unexpected error: %s", err))

	cases := []struct {
		desc  string
		thing things.Thing
		err   error
	}{
		{
			desc:  "update existing thing",
			thing: thing,
			err:   nil,
		},
		{
			desc: "update non-existing thing with existing user",
			thing: things.Thing{
				ID:    nonexistentThingID,
				Owner: email,
			},
			err: things.ErrNotFound,
		},
		{
			desc: "update existing thing ID with non-existing user",
			thing: things.Thing{
				ID:    thing.ID,
				Owner: wrongValue,
			},
			err: things.ErrNotFound,
		},
		{
			desc: "update non-existing thing with non-existing user",
			thing: things.Thing{
				ID:    nonexistentThingID,
				Owner: wrongValue,
			},
			err: things.ErrNotFound,
		},
		{
			desc: "update thing with valid name",
			thing: things.Thing{
				ID:    thid,
				Owner: email,
				Key:   thkey,
				Name:  validName,
			},
			err: nil,
		},
		{
			desc: "update thing with invalid name",
			thing: things.Thing{
				ID:    thid,
				Owner: email,
				Key:   thkey,
				Name:  invalidName,
			},
			err: things.ErrMalformedEntity,
		},
	}

	for _, tc := range cases {
		err := thingRepo.Update(context.Background(), tc.thing)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
	}
}

func TestUpdateKey(t *testing.T) {
	email := "thing-update=key@example.com"
	newKey := "new-key"
	dbMiddleware := postgres.NewDatabase(db)
	thingRepo := postgres.NewThingRepository(dbMiddleware)

	id, err := uuidProvider.New().ID()
	require.Nil(t, err, fmt.Sprintf("got unexpected error: %s", err))
	key, err := uuidProvider.New().ID()
	require.Nil(t, err, fmt.Sprintf("got unexpected error: %s", err))
	th1 := things.Thing{
		ID:    id,
		Owner: email,
		Key:   key,
	}
	ths, err := thingRepo.Save(context.Background(), th1)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s\n", err))
	th1.ID = ths[0].ID

	id, err = uuidProvider.New().ID()
	require.Nil(t, err, fmt.Sprintf("got unexpected error: %s", err))
	key, err = uuidProvider.New().ID()
	require.Nil(t, err, fmt.Sprintf("got unexpected error: %s", err))
	th2 := things.Thing{
		ID:    id,
		Owner: email,
		Key:   key,
	}
	ths, err = thingRepo.Save(context.Background(), th2)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s\n", err))
	th2.ID = ths[0].ID

	nonexistentThingID, err := uuidProvider.New().ID()
	require.Nil(t, err, fmt.Sprintf("got unexpected error: %s", err))

	cases := []struct {
		desc  string
		owner string
		id    string
		key   string
		err   error
	}{
		{
			desc:  "update key of an existing thing",
			owner: th2.Owner,
			id:    th2.ID,
			key:   newKey,
			err:   nil,
		},
		{
			desc:  "update key of a non-existing thing with existing user",
			owner: th2.Owner,
			id:    nonexistentThingID,
			key:   newKey,
			err:   things.ErrNotFound,
		},
		{
			desc:  "update key of an existing thing with non-existing user",
			owner: wrongValue,
			id:    th2.ID,
			key:   newKey,
			err:   things.ErrNotFound,
		},
		{
			desc:  "update key of a non-existing thing with non-existing user",
			owner: wrongValue,
			id:    nonexistentThingID,
			key:   newKey,
			err:   things.ErrNotFound,
		},
		{
			desc:  "update key with existing key value",
			owner: th2.Owner,
			id:    th2.ID,
			key:   th1.Key,
			err:   things.ErrConflict,
		},
	}

	for _, tc := range cases {
		err := thingRepo.UpdateKey(context.Background(), tc.owner, tc.id, tc.key)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
	}
}

func TestSingleThingRetrieval(t *testing.T) {
	email := "thing-single-retrieval@example.com"
	dbMiddleware := postgres.NewDatabase(db)
	thingRepo := postgres.NewThingRepository(dbMiddleware)

	id, err := uuidProvider.New().ID()
	require.Nil(t, err, fmt.Sprintf("got unexpected error: %s", err))
	key, err := uuidProvider.New().ID()
	require.Nil(t, err, fmt.Sprintf("got unexpected error: %s", err))
	th := things.Thing{
		ID:    id,
		Owner: email,
		Key:   key,
	}

	ths, err := thingRepo.Save(context.Background(), th)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s\n", err))
	th.ID = ths[0].ID

	nonexistentThingID, err := uuidProvider.New().ID()
	require.Nil(t, err, fmt.Sprintf("got unexpected error: %s", err))

	cases := map[string]struct {
		owner string
		ID    string
		err   error
	}{
		"retrieve thing with existing user": {
			owner: th.Owner,
			ID:    th.ID,
			err:   nil,
		},
		"retrieve non-existing thing with existing user": {
			owner: th.Owner,
			ID:    nonexistentThingID,
			err:   things.ErrNotFound,
		},
		"retrieve thing with non-existing owner": {
			owner: wrongValue,
			ID:    th.ID,
			err:   things.ErrNotFound,
		},
		"retrieve thing with malformed ID": {
			owner: th.Owner,
			ID:    wrongValue,
			err:   things.ErrNotFound,
		},
	}

	for desc, tc := range cases {
		_, err := thingRepo.RetrieveByID(context.Background(), tc.owner, tc.ID)
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", desc, tc.err, err))
	}
}

func TestThingRetrieveByKey(t *testing.T) {
	email := "thing-retrieved-by-key@example.com"
	dbMiddleware := postgres.NewDatabase(db)
	thingRepo := postgres.NewThingRepository(dbMiddleware)

	id, err := uuidProvider.New().ID()
	require.Nil(t, err, fmt.Sprintf("got unexpected error: %s", err))
	key, err := uuidProvider.New().ID()
	require.Nil(t, err, fmt.Sprintf("got unexpected error: %s", err))

	th := things.Thing{
		ID:    id,
		Owner: email,
		Key:   key,
	}

	ths, err := thingRepo.Save(context.Background(), th)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s\n", err))
	th.ID = ths[0].ID

	cases := map[string]struct {
		key string
		ID  string
		err error
	}{
		"retrieve existing thing by key": {
			key: th.Key,
			ID:  th.ID,
			err: nil,
		},
		"retrieve non-existent thing by key": {
			key: wrongValue,
			ID:  "",
			err: things.ErrNotFound,
		},
	}

	for desc, tc := range cases {
		id, err := thingRepo.RetrieveByKey(context.Background(), tc.key)
		assert.Equal(t, tc.ID, id, fmt.Sprintf("%s: expected %s got %s\n", desc, tc.ID, id))
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected %s got %s\n", desc, tc.err, err))
	}
}

func TestMultiThingRetrieval(t *testing.T) {
	dbMiddleware := postgres.NewDatabase(db)
	thingRepo := postgres.NewThingRepository(dbMiddleware)

	email := "thing-multi-retrieval@example.com"
	name := "thing_name"
	metadata := things.Metadata{
		"field": "value",
	}
	wrongMeta := things.Metadata{
		"wrong": "wrong",
	}

	up := uuidProvider.New()
	offset := uint64(1)
	nameNum := uint64(3)
	metaNum := uint64(3)
	nameMetaNum := uint64(2)

	n := uint64(10)
	for i := uint64(0); i < n; i++ {
		id, err := up.ID()
		require.Nil(t, err, fmt.Sprintf("got unexpected error: %s", err))
		key, err := up.ID()
		require.Nil(t, err, fmt.Sprintf("got unexpected error: %s", err))
		th := things.Thing{
			Owner: email,
			ID:    id,
			Key:   key,
		}

		// Create Things with name.
		if i < nameNum {
			th.Name = fmt.Sprintf("%s-%d", name, i)
		}
		// Create Things with metadata.
		if i >= nameNum && i < nameNum+metaNum {
			th.Metadata = metadata
		}
		// Create Things with name and metadata.
		if i >= n-nameMetaNum {
			th.Metadata = metadata
			th.Name = name
		}

		_, err = thingRepo.Save(context.Background(), th)
		require.Nil(t, err, fmt.Sprintf("unexpected error: %s\n", err))
	}

	cases := map[string]struct {
		owner    string
		pageMeta things.PageMetadata
		size     uint64
	}{
		"retrieve all things with existing owner": {
			owner: email,
			pageMeta: things.PageMetadata{
				Offset: 0,
				Limit:  n,
				Total:  n,
			},
			size: n,
		},
		"retrieve subset of things with existing owner": {
			owner: email,
			pageMeta: things.PageMetadata{
				Offset: n / 2,
				Limit:  n,
				Total:  n,
			},
			size: n / 2,
		},
		"retrieve things with non-existing owner": {
			owner: wrongValue,
			pageMeta: things.PageMetadata{
				Offset: 0,
				Limit:  n,
				Total:  0,
			},
			size: 0,
		},
		"retrieve things with existing name": {
			owner: email,
			pageMeta: things.PageMetadata{
				Offset: 1,
				Limit:  n,
				Name:   name,
				Total:  nameNum + nameMetaNum,
			},
			size: nameNum + nameMetaNum - offset,
		},
		"retrieve things with non-existing name": {
			owner: email,
			pageMeta: things.PageMetadata{
				Offset: 0,
				Limit:  n,
				Name:   "wrong",
				Total:  0,
			},
			size: 0,
		},
		"retrieve things with existing metadata": {
			owner: email,
			pageMeta: things.PageMetadata{
				Offset:   0,
				Limit:    n,
				Total:    metaNum + nameMetaNum,
				Metadata: metadata,
			},
			size: metaNum + nameMetaNum,
		},
		"retrieve things with non-existing metadata": {
			owner: email,
			pageMeta: things.PageMetadata{
				Offset:   0,
				Limit:    n,
				Total:    0,
				Metadata: wrongMeta,
			},
			size: 0,
		},
		"retrieve all things with existing name and metadata": {
			owner: email,
			pageMeta: things.PageMetadata{
				Offset:   0,
				Limit:    n,
				Total:    nameMetaNum,
				Name:     name,
				Metadata: metadata,
			},
			size: nameMetaNum,
		},
		"retrieve things sorted by ascendent name": {
			owner: email,
			pageMeta: things.PageMetadata{
				Offset: 0,
				Limit:  n,
				Total:  n,
				Order:  "name",
				Dir:    "asc",
			},
			size: n,
		},
		"retrieve things sorted by descendent name": {
			owner: email,
			pageMeta: things.PageMetadata{
				Offset: 0,
				Limit:  n,
				Total:  n,
				Order:  "name",
				Dir:    "desc",
			},
			size: n,
		},
	}

	for desc, tc := range cases {
		page, err := thingRepo.RetrieveAll(context.Background(), tc.owner, tc.pageMeta)
		size := uint64(len(page.Things))
		assert.Equal(t, tc.size, size, fmt.Sprintf("%s: expected size %d got %d\n", desc, tc.size, size))
		assert.Equal(t, tc.pageMeta.Total, page.Total, fmt.Sprintf("%s: expected total %d got %d\n", desc, tc.pageMeta.Total, page.Total))
		assert.Nil(t, err, fmt.Sprintf("%s: expected no error got %d\n", desc, err))
		// Check if name have been sorted properly
		switch tc.pageMeta.Order {
		case "name":
			current := page.Things[0]
			for _, res := range page.Things {
				if tc.pageMeta.Dir == "asc" {
					assert.GreaterOrEqual(t, res.Name, current.Name)
				}
				if tc.pageMeta.Dir == "desc" {
					assert.GreaterOrEqual(t, current.Name, res.Name)
				}
				current = res
			}
		default:
			continue
		}
	}
}

func TestMultiThingRetrievalByChannel(t *testing.T) {
	email := "thing-multi-retrieval-by-channel@example.com"
	up := uuidProvider.New()
	dbMiddleware := postgres.NewDatabase(db)
	thingRepo := postgres.NewThingRepository(dbMiddleware)
	channelRepo := postgres.NewChannelRepository(dbMiddleware)

	n := uint64(10)
	thsDisconNum := uint64(1)

	chid, err := up.ID()
	require.Nil(t, err, fmt.Sprintf("got unexpected error: %s", err))

	chs, err := channelRepo.Save(context.Background(), things.Channel{
		ID:    chid,
		Owner: email,
	})
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))
	cid := chs[0].ID
	for i := uint64(0); i < n; i++ {
		thid, err := up.ID()
		require.Nil(t, err, fmt.Sprintf("got unexpected error: %s", err))
		thkey, err := up.ID()
		require.Nil(t, err, fmt.Sprintf("got unexpected error: %s", err))
		th := things.Thing{
			ID:    thid,
			Owner: email,
			Key:   thkey,
		}

		ths, err := thingRepo.Save(context.Background(), th)
		require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))
		thid = ths[0].ID

		// Don't connnect last Thing
		if i == n-thsDisconNum {
			break
		}

		err = channelRepo.Connect(context.Background(), email, []string{cid}, []string{thid})
		require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))
	}

	nonexistentChanID, err := up.ID()
	require.Nil(t, err, fmt.Sprintf("got unexpected error: %s", err))

	cases := map[string]struct {
		owner     string
		channel   string
		offset    uint64
		limit     uint64
		connected bool
		size      uint64
		err       error
	}{
		"retrieve all things by channel with existing owner": {
			owner:     email,
			channel:   cid,
			offset:    0,
			limit:     n,
			connected: true,
			size:      n - thsDisconNum,
		},
		"retrieve subset of things by channel with existing owner": {
			owner:     email,
			channel:   cid,
			offset:    n / 2,
			limit:     n,
			connected: true,
			size:      (n / 2) - thsDisconNum,
		},
		"retrieve things by channel with non-existing owner": {
			owner:     wrongValue,
			channel:   cid,
			offset:    0,
			limit:     n,
			connected: true,
			size:      0,
		},
		"retrieve things by non-existing channel": {
			owner:     email,
			channel:   nonexistentChanID,
			offset:    0,
			limit:     n,
			connected: true,
			size:      0,
		},
		"retrieve things with malformed UUID": {
			owner:     email,
			channel:   wrongValue,
			offset:    0,
			limit:     n,
			connected: true,
			size:      0,
			err:       things.ErrNotFound,
		},
		"retrieve all non connected things by channel with existing owner": {
			owner:     email,
			channel:   cid,
			offset:    0,
			limit:     n,
			connected: false,
			size:      thsDisconNum,
		},
	}

	for desc, tc := range cases {
		page, err := thingRepo.RetrieveByChannel(context.Background(), tc.owner, tc.channel, tc.offset, tc.limit, tc.connected)
		size := uint64(len(page.Things))
		assert.Equal(t, tc.size, size, fmt.Sprintf("%s: expected size %d got %d\n", desc, tc.size, size))
		assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("%s: expected no error got %d\n", desc, err))
	}
}

func TestThingRemoval(t *testing.T) {
	email := "thing-removal@example.com"
	dbMiddleware := postgres.NewDatabase(db)
	thingRepo := postgres.NewThingRepository(dbMiddleware)

	id, err := uuidProvider.New().ID()
	require.Nil(t, err, fmt.Sprintf("got unexpected error: %s", err))
	key, err := uuidProvider.New().ID()
	require.Nil(t, err, fmt.Sprintf("got unexpected error: %s", err))
	thing := things.Thing{
		ID:    id,
		Owner: email,
		Key:   key,
	}

	ths, _ := thingRepo.Save(context.Background(), thing)
	thing.ID = ths[0].ID

	// show that the removal works the same for both existing and non-existing
	// (removed) thing
	for i := 0; i < 2; i++ {
		err := thingRepo.Remove(context.Background(), email, thing.ID)
		require.Nil(t, err, fmt.Sprintf("#%d: failed to remove thing due to: %s", i, err))

		_, err = thingRepo.RetrieveByID(context.Background(), email, thing.ID)
		require.True(t, errors.Contains(err, things.ErrNotFound), fmt.Sprintf("#%d: expected %s got %s", i, things.ErrNotFound, err))
	}
}
