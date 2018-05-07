package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/asaskevich/govalidator"
	kithttp "github.com/go-kit/kit/transport/http"
	"github.com/go-zoo/bone"
	"github.com/mainflux/mainflux"
	"github.com/mainflux/mainflux/clients"
	clientsapi "github.com/mainflux/mainflux/clients/api/grpc"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const protocol string = "http"

var (
	errMalformedData = errors.New("malformed SenML data")
	errNotFound      = errors.New("non-existent entity")
	auth             clientsapi.ClientsServiceClient
)

// MakeHandler returns a HTTP handler for API endpoints.
func MakeHandler(svc mainflux.MessagePublisher, mc clientsapi.ClientsServiceClient) http.Handler {
	auth = mc

	opts := []kithttp.ServerOption{
		kithttp.ServerErrorEncoder(encodeError),
	}

	r := bone.New()

	r.Post("/channels/:id/messages", kithttp.NewServer(
		sendMessageEndpoint(svc),
		decodeRequest,
		encodeResponse,
		opts...,
	))

	r.GetFunc("/version", mainflux.Version("http"))
	r.Handle("/metrics", promhttp.Handler())

	return r
}

func decodeRequest(_ context.Context, r *http.Request) (interface{}, error) {
	publisher, err := authorize(r)
	if err != nil {
		return nil, err
	}

	payload, err := decodePayload(r.Body)
	if err != nil {
		return nil, err
	}

	msg := mainflux.RawMessage{
		Publisher:   publisher,
		Protocol:    protocol,
		ContentType: r.Header.Get("Content-Type"),
		Channel:     bone.GetValue(r, "id"),
		Payload:     payload,
	}

	return msg, nil
}

func authorize(r *http.Request) (string, error) {
	apiKey := r.Header.Get("Authorization")

	if apiKey == "" {
		return "", clients.ErrUnauthorizedAccess
	}

	// extract ID from /channels/:id/messages
	c := strings.Split(r.URL.Path, "/")[2]
	if !govalidator.IsUUID(c) {
		return "", errNotFound
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	id, err := auth.CanAccess(ctx, &clientsapi.AccessReq{apiKey, c})
	if err != nil {
		return "", err
	}

	return id.GetValue(), nil
}

func decodePayload(body io.ReadCloser) ([]byte, error) {
	payload, err := ioutil.ReadAll(body)
	if err != nil {
		return nil, errMalformedData
	}
	defer body.Close()

	return payload, nil
}

func encodeResponse(_ context.Context, w http.ResponseWriter, response interface{}) error {
	w.WriteHeader(http.StatusAccepted)
	return nil
}

func encodeError(_ context.Context, err error, w http.ResponseWriter) {
	switch err {
	case errMalformedData:
		w.WriteHeader(http.StatusBadRequest)
	case errNotFound:
		w.WriteHeader(http.StatusNotFound)
	case clients.ErrUnauthorizedAccess:
		w.WriteHeader(http.StatusForbidden)
	default:
		fmt.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
	}
}
