package influxdb_test

import (
	"fmt"
	"os"
	"testing"
	"time"

	influxdata "github.com/influxdata/influxdb/client/v2"
	"github.com/mainflux/mainflux/pkg/transformers/senml"
	"github.com/mainflux/mainflux/readers"
	reader "github.com/mainflux/mainflux/readers/influxdb"
	writer "github.com/mainflux/mainflux/writers/influxdb"

	log "github.com/mainflux/mainflux/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testDB     = "test"
	chanID     = "1"
	subtopic   = "topic"
	msgsNum    = 100
	fromToNum  = 4
	msgsValNum = 20
	n          = 10
)

var (
	val       float64 = 5
	stringVal         = "value"
	boolVal           = true
	dataVal           = "dataValue"
	sum       float64 = 42
)

var (
	valueFields = 5
	port        string
	client      influxdata.Client
	testLog, _  = log.New(os.Stdout, log.Info.String())

	clientCfg = influxdata.HTTPConfig{
		Username: "test",
		Password: "test",
	}

	m = senml.Message{
		Channel:    chanID,
		Publisher:  "1",
		Protocol:   "mqtt",
		Name:       "name",
		Unit:       "U",
		Time:       123456,
		UpdateTime: 1234,
	}
)

func TestReadAll(t *testing.T) {
	writer := writer.New(client, testDB)

	messages := []senml.Message{}
	valSubtopicMsgs := []senml.Message{}
	boolMsgs := []senml.Message{}
	stringMsgs := []senml.Message{}
	dataMsgs := []senml.Message{}

	now := time.Now().UnixNano()
	for i := 0; i < msgsNum; i++ {
		// Mix possible values as well as value sum.
		msg := m
		msg.Time = float64(now)/1e9 - float64(i)

		count := i % valueFields
		switch count {
		case 0:
			msg.Subtopic = subtopic
			msg.Value = &val
			valSubtopicMsgs = append(valSubtopicMsgs, msg)
		case 1:
			msg.BoolValue = &boolVal
			boolMsgs = append(boolMsgs, msg)
		case 2:
			msg.StringValue = &stringVal
			stringMsgs = append(stringMsgs, msg)
		case 3:
			msg.DataValue = &dataVal
			dataMsgs = append(dataMsgs, msg)
		case 4:
			msg.Sum = &sum
		}

		messages = append(messages, msg)
	}

	err := writer.Save(messages...)
	require.Nil(t, err, fmt.Sprintf("failed to store message to InfluxDB: %s", err))

	reader := reader.New(client, testDB)
	require.Nil(t, err, fmt.Sprintf("Creating new InfluxDB reader expected to succeed: %s.\n", err))

	cases := map[string]struct {
		chanID string
		offset uint64
		limit  uint64
		query  map[string]string
		page   readers.MessagesPage
	}{
		"read message page for existing channel": {
			chanID: chanID,
			offset: 0,
			limit:  n,
			page: readers.MessagesPage{
				Total:    msgsNum,
				Offset:   0,
				Limit:    n,
				Messages: messages[0:10],
			},
		},
		"read message page for non-existent channel": {
			chanID: "2",
			offset: 0,
			limit:  n,
			page: readers.MessagesPage{
				Total:    0,
				Offset:   0,
				Limit:    n,
				Messages: []senml.Message{},
			},
		},
		"read message last page": {
			chanID: chanID,
			offset: 95,
			limit:  n,
			page: readers.MessagesPage{
				Total:    msgsNum,
				Offset:   95,
				Limit:    n,
				Messages: messages[95:msgsNum],
			},
		},
		"read message with non-existent subtopic": {
			chanID: chanID,
			offset: 0,
			limit:  msgsNum,
			query:  map[string]string{"subtopic": "not-present"},
			page: readers.MessagesPage{
				Total:    0,
				Offset:   0,
				Limit:    msgsNum,
				Messages: []senml.Message{},
			},
		},
		"read message with subtopic": {
			chanID: chanID,
			offset: 0,
			limit:  n,
			query:  map[string]string{"subtopic": subtopic},
			page: readers.MessagesPage{
				Total:    uint64(len(valSubtopicMsgs)),
				Offset:   0,
				Limit:    n,
				Messages: valSubtopicMsgs[0:10],
			},
		},
		"read message with value": {
			chanID: chanID,
			offset: 0,
			limit:  n,
			query:  map[string]string{"value": fmt.Sprintf("%f", val)},
			page: readers.MessagesPage{
				Total:    msgsValNum,
				Offset:   0,
				Limit:    n,
				Messages: valSubtopicMsgs[0:10],
			},
		},
		"read message with v": {
			chanID: chanID,
			offset: 0,
			limit:  n,
			query:  map[string]string{"v": fmt.Sprintf("%f", val)},
			page: readers.MessagesPage{
				Total:    msgsValNum,
				Offset:   0,
				Limit:    n,
				Messages: valSubtopicMsgs[0:n],
			},
		},
		"read message with vb": {
			chanID: chanID,
			offset: 0,
			limit:  n,
			query:  map[string]string{"vb": fmt.Sprintf("%t", boolVal)},
			page: readers.MessagesPage{
				Total:    msgsValNum,
				Offset:   0,
				Limit:    n,
				Messages: boolMsgs[0:n],
			},
		},
		"read message with vs": {
			chanID: chanID,
			offset: 0,
			limit:  n,
			query:  map[string]string{"vs": stringVal},
			page: readers.MessagesPage{
				Total:    msgsValNum,
				Offset:   0,
				Limit:    n,
				Messages: stringMsgs[0:n],
			},
		},
		"read message with vd": {
			chanID: chanID,
			offset: 0,
			limit:  n,
			query:  map[string]string{"vd": dataVal},
			page: readers.MessagesPage{
				Total:    msgsValNum,
				Offset:   0,
				Limit:    n,
				Messages: dataMsgs[0:n],
			},
		},
		"read message with from/to": {
			chanID: chanID,
			offset: 0,
			limit:  n,
			query: map[string]string{
				"from": fmt.Sprintf("%f", messages[fromToNum].Time),
				"to":   fmt.Sprintf("%f", messages[0].Time),
			},
			page: readers.MessagesPage{
				Total:    fromToNum,
				Offset:   0,
				Limit:    n,
				Messages: messages[1:5],
			},
		},
	}

	for desc, tc := range cases {
		result, err := reader.ReadAll(tc.chanID, tc.offset, tc.limit, tc.query)
		assert.Nil(t, err, fmt.Sprintf("%s: expected no error got %s", desc, err))
		assert.ElementsMatch(t, tc.page.Messages, result.Messages, fmt.Sprintf("%s: expected: %v \n-------------\n got: %v", desc, tc.page.Messages, result.Messages))

		assert.Equal(t, tc.page.Total, result.Total, fmt.Sprintf("%s: expected %d got %d", desc, tc.page.Total, result.Total))
	}
}
