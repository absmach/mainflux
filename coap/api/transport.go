package api

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/mainflux/mainflux/coap"
	manager "github.com/mainflux/mainflux/manager/client"

	mux "github.com/dereulenspiegel/coap-mux"
	gocoap "github.com/dustin/go-coap"
	"github.com/mainflux/mainflux"
)

var (
	errBadRequest = errors.New("bad request")
	errBadOption  = errors.New("bad option")
	auth          manager.ManagerClient
	maxPktLen     = 1500
	network       = "udp"
	protocol      = "coap"
)

// Approximately number of supported requests per second
const timestamp = int64(time.Millisecond) * 31

// NotFoundHandler handles erroneously formed requests.
func NotFoundHandler(l *net.UDPConn, a *net.UDPAddr, m *gocoap.Message) *gocoap.Message {
	if m.IsConfirmable() {
		return &gocoap.Message{
			Type: gocoap.Acknowledgement,
			Code: gocoap.NotFound,
		}
	}
	return nil
}

// MakeHandler function return new CoAP server with GET, POST and NOT_FOUND handlers.
func MakeHandler(svc coap.Service) gocoap.Handler {
	r := mux.NewRouter()
	r.Handle("/channels/{id}/messages", gocoap.FuncHandler(receive(svc))).Methods(gocoap.POST)
	r.Handle("/channels/{id}/messages", gocoap.FuncHandler(observe(svc))).Methods(gocoap.GET)
	r.NotFoundHandler = gocoap.FuncHandler(NotFoundHandler)
	return r
}

func receive(svc coap.Service) func(conn *net.UDPConn, addr *net.UDPAddr, msg *gocoap.Message) *gocoap.Message {
	return func(conn *net.UDPConn, addr *net.UDPAddr, msg *gocoap.Message) *gocoap.Message {
		var res *gocoap.Message
		if msg.IsConfirmable() {
			res = &gocoap.Message{
				Type:      gocoap.Acknowledgement,
				Code:      gocoap.Content,
				MessageID: msg.MessageID,
				Token:     msg.Token,
				Payload:   []byte{},
			}
			res.SetOption(gocoap.ContentFormat, gocoap.AppJSON)
		}

		if len(msg.Payload) == 0 && msg.IsConfirmable() {
			res.Code = gocoap.BadRequest
			return res
		}

		cid := mux.Var(msg, "id")
		publisher, err := authorize(msg, res, cid)
		if err != nil {
			res.Code = gocoap.Unauthorized
			return res
		}

		rawMsg := mainflux.RawMessage{
			Channel:   cid,
			Publisher: publisher,
			Protocol:  protocol,
			Payload:   msg.Payload,
		}

		if err := svc.Publish(rawMsg); err != nil {
			res.Code = gocoap.InternalServerError
		}
		return res
	}
}

func observe(svc coap.Service) func(conn *net.UDPConn, addr *net.UDPAddr, msg *gocoap.Message) *gocoap.Message {
	return func(conn *net.UDPConn, addr *net.UDPAddr, msg *gocoap.Message) *gocoap.Message {
		var res *gocoap.Message
		if msg.IsConfirmable() {
			res = &gocoap.Message{
				Type:      gocoap.Acknowledgement,
				Code:      gocoap.Content,
				MessageID: msg.MessageID,
				Token:     msg.Token,
				Payload:   []byte{},
			}
			res.SetOption(gocoap.ContentFormat, gocoap.AppJSON)
		}

		cid := mux.Var(msg, "id")
		publisher, err := authorize(msg, res, cid)

		if err != nil {
			res.Code = gocoap.Unauthorized
			return res
		}

		if value, ok := msg.Option(gocoap.Observe).(uint32); ok && value == 1 {
			id := fmt.Sprintf("%s-%x", publisher, msg.Token)
			if err := svc.Unsubscribe(id); err != nil {
				res.Code = gocoap.InternalServerError
			}
		}

		if value, ok := msg.Option(gocoap.Observe).(uint32); ok && value == 0 {
			ch := make(chan mainflux.RawMessage)
			id := fmt.Sprintf("%s-%x", publisher, msg.Token)
			if err := svc.Subscribe(cid, id, ch); err != nil {
				res.Code = gocoap.InternalServerError
				return res
			}
			go handleSub(svc, id, conn, addr, msg, ch)
			res.AddOption(gocoap.Observe, 0)
		}
		return res
	}
}

func sendMessage(conn *net.UDPConn, addr *net.UDPAddr, msg *gocoap.Message) error {
	var err error
	buff := new(bytes.Buffer)
	now := time.Now().UnixNano() / timestamp
	if err = binary.Write(buff, binary.BigEndian, now); err != nil {
		return err
	}
	observeVal := buff.Bytes()
	msg.SetOption(gocoap.Observe, observeVal[len(observeVal)-3:])

	timeout := time.Duration(5)
	// Try to transmit 3 times; each time duplicate timeout between attempts.
	for i := 0; i < 3; i++ {
		err = gocoap.Transmit(conn, addr, *msg)
		if err != nil {
			time.Sleep(timeout * time.Millisecond)
			timeout *= 2
			continue
		}
		return nil
	}
	return err
}

func handleSub(svc coap.Service, id string, conn *net.UDPConn, addr *net.UDPAddr, msg *gocoap.Message, ch chan mainflux.RawMessage) {
	ticker := time.NewTicker(24 * time.Hour)
	res := &gocoap.Message{
		Type:      gocoap.NonConfirmable,
		Code:      gocoap.Content,
		MessageID: msg.MessageID,
		Token:     msg.Token,
		Payload:   []byte{},
	}
	res.SetOption(gocoap.ContentFormat, gocoap.AppJSON)
	res.SetOption(gocoap.LocationPath, msg.Path())

loop:
	for {
		select {
		case <-ticker.C:
			res.Type = gocoap.Confirmable
			if err := sendMessage(conn, addr, res); err != nil {
				svc.Unsubscribe(id)
				break loop
			}
			svc.SetTimeout(id, time.Second)
		case rawMsg, ok := <-ch:
			if !ok {
				break loop
			}
			res.Type = gocoap.NonConfirmable
			res.Payload = rawMsg.Payload
			if err := sendMessage(conn, addr, res); err != nil {
				svc.Unsubscribe(id)
				break loop
			}
		}
	}
	ticker.Stop()
}
