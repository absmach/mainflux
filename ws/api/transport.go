package api

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/go-kit/kit/log"
	"github.com/go-zoo/bone"
	"github.com/gorilla/websocket"
	"github.com/mainflux/mainflux"
	manager "github.com/mainflux/mainflux/manager/client"
	"github.com/mainflux/mainflux/ws"
	broker "github.com/nats-io/go-nats"
)

var (
	errUnauthorizedAccess = errors.New("missing or invalid credentials provided")
	upgrader              = websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}
	auth   manager.ManagerClient
	nc     *broker.Conn
	logger log.Logger
)

// MakeHandler returns http handler with handshake endpoint.
func MakeHandler(svc mainflux.MessagePubSub, mc manager.ManagerClient, bc *broker.Conn, l log.Logger) http.Handler {
	auth = mc
	nc = bc
	logger = l

	mux := bone.New()
	mux.GetFunc("/channels/:id/messages", handshake(svc))

	return mux
}

func handshake(svc mainflux.MessagePubSub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sub, err := authorize(r)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Create new ws connection.
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			logger.Log("error", fmt.Sprintf("Failed to upgrade connection to websocket: %s", err))
			return
		}
		socket := ws.NewSocket(conn)

		_, err = svc.Subscribe(
			sub,
			func(msg mainflux.RawMessage) error {
				return socket.Write(msg)
			},
			func() ([]byte, error) {
				_, payload, err := socket.ReadMessage()
				return payload, err
			},
		)
		if err != nil {
			logger.Log("error", fmt.Sprintf("Failed to subscribe to NATS subject: %s", err))
			w.WriteHeader(http.StatusBadRequest)
			return
		}
	}
}

func authorize(r *http.Request) (mainflux.Subscription, error) {
	apiKeys := bone.GetQuery(r, "auth")
	if len(apiKeys) == 0 {
		return mainflux.Subscription{}, errUnauthorizedAccess
	}
	apiKey := apiKeys[0]

	// extract ID from /channels/:id/messages
	chanID := bone.GetValue(r, "id")

	pubID, err := auth.CanAccess(chanID, apiKey)
	if err != nil {
		logger.Log("error", "Failed to authorize: %s", err)
		return mainflux.Subscription{}, errUnauthorizedAccess
	}

	return mainflux.Subscription{pubID, chanID}, nil
}
