// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package influxdb

import (
	"math"
	"time"

	"github.com/mainflux/mainflux/consumers"
	"github.com/mainflux/mainflux/pkg/errors"
	"github.com/mainflux/mainflux/pkg/transformers/json"
	"github.com/mainflux/mainflux/pkg/transformers/senml"

	influxdb2 "github.com/influxdata/influxdb-client-go/v2"
	write "github.com/influxdata/influxdb-client-go/v2/api/write"
)

const senmlPoints = "messages"

var errSaveMessage = errors.New("failed to save message to influxdb database")

var _ consumers.Consumer = (*influxRepo)(nil)

type repoConfig struct {
	bucket string
	org    string
}
type influxRepo struct {
	client influxdb2.Client
	cfg    repoConfig
}

// New returns new InfluxDB writer.
func New(client influxdb2.Client, orgName string, bucketName string) consumers.Consumer {
	return &influxRepo{
		client: client,
		cfg: repoConfig{
			org:    orgName,
			bucket: bucketName,
		},
	}
}

func (repo *influxRepo) Consume(message interface{}) error {

	//pts, err := influxdb2.NewBatchPoints(repo.cfg)
	//if err != nil {
	//	return errors.Wrap(errSaveMessage, err)
	//}
	var err error
	var pts []write.Point
	switch m := message.(type) {
	case json.Messages:
		pts, err = repo.jsonPoint(m)
	default:
		pts, err = repo.senmlPoint(m)
	}
	if err != nil {
		return err
	}

	writeAPI := repo.client.WriteAPI(repo.cfg.org, repo.cfg.bucket)
	for _, point := range pts {
		writeAPI.WritePoint(&point)
	}

	writeAPI.Flush()
	return nil
}

func (repo *influxRepo) senmlPoint(messages interface{}) ([]write.Point, error) {
	msgs, ok := messages.([]senml.Message)
	if !ok {
		return nil, errSaveMessage
	}
	var pts []write.Point
	for _, msg := range msgs {
		tgs, flds := senmlTags(msg), senmlFields(msg)

		sec, dec := math.Modf(msg.Time)
		t := time.Unix(int64(sec), int64(dec*(1e9)))

		pt := influxdb2.NewPoint(senmlPoints, tgs, flds, t)
		pts = append(pts, *pt)
	}

	return pts, nil
}

func (repo *influxRepo) jsonPoint(msgs json.Messages) ([]write.Point, error) {
	var pts []write.Point
	for i, m := range msgs.Data {
		t := time.Unix(0, m.Created+int64(i))

		flat, err := json.Flatten(m.Payload)
		if err != nil {
			return nil, errors.Wrap(json.ErrTransform, err)
		}
		m.Payload = flat

		// Copy first-level fields so that the original Payload is unchanged.
		fields := make(map[string]interface{})
		for k, v := range m.Payload {
			fields[k] = v
		}
		// At least one known field need to exist so that COUNT can be performed.
		fields["protocol"] = m.Protocol
		pt := influxdb2.NewPoint(msgs.Format, jsonTags(m), fields, t)
		pts = append(pts, *pt)
	}

	return pts, nil
}
