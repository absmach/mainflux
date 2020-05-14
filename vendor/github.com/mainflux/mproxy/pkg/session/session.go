package session

import (
	"net"

	"github.com/eclipse/paho.mqtt.golang/packets"
	"github.com/mainflux/mainflux/errors"
	"github.com/mainflux/mainflux/logger"
)

const (
	up direction = iota
	down
)

var (
	errBroker = errors.New("error between mProxy and MQTT broker")
	errClient = errors.New("error between mProxy and MQTT client")
)

type direction int

// Session represents MQTT Proxy session between client and broker.
type Session struct {
	logger   logger.Logger
	inbound  net.Conn
	outbound net.Conn
	handler  Handler
	Client   Client
}

// New creates a new Session.
func New(inbound, outbound net.Conn, handler Handler, logger logger.Logger) *Session {
	return &Session{
		logger:   logger,
		inbound:  inbound,
		outbound: outbound,
		handler:  handler,
	}
}

// Stream starts proxying traffic between client and broker.
func (s *Session) Stream() error {
	// In parallel read from client, send to broker
	// and read from broker, send to client.
	errs := make(chan error, 2)

	go s.stream(up, s.inbound, s.outbound, errs)
	go s.stream(down, s.outbound, s.inbound, errs)

	// Handle whichever error happens first.
	// The other routine won't be blocked when writing
	// to the errors channel because it is buffered.
	// Connections are closed in the caller method.
	err := <-errs

	s.handler.Disconnect(&s.Client)
	return err
}

func (s *Session) stream(dir direction, r, w net.Conn, errs chan error) {
	for {
		// Read from one connection
		pkt, err := packets.ReadPacket(r)
		if err != nil {
			errs <- wrap(dir, err)
			return
		}

		if dir == up {
			if err := s.authorize(pkt); err != nil {
				errs <- wrap(dir, err)
				return
			}
		}

		// Send to another
		if err := pkt.Write(w); err != nil {
			errs <- wrap(dir, err)
			return
		}

		if dir == up {
			s.notify(pkt)
		}
	}
}

func (s *Session) authorize(pkt packets.ControlPacket) error {
	switch p := pkt.(type) {
	case *packets.ConnectPacket:
		s.Client = Client{
			ID:       p.ClientIdentifier,
			Username: p.Username,
			Password: p.Password,
		}
		if err := s.handler.AuthConnect(&s.Client); err != nil {
			return err
		}
		// Copy back to the packet in case values are changed by Event handler.
		// This is specific to CONN, as only that package type has credentials.
		p.ClientIdentifier = s.Client.ID
		p.Username = s.Client.Username
		p.Password = s.Client.Password
		return nil
	case *packets.PublishPacket:
		return s.handler.AuthPublish(&s.Client, &p.TopicName, &p.Payload)
	case *packets.SubscribePacket:
		return s.handler.AuthSubscribe(&s.Client, &p.Topics)
	default:
		return nil
	}
}

func (s *Session) notify(pkt packets.ControlPacket) {
	switch p := pkt.(type) {
	case *packets.ConnectPacket:
		s.handler.Connect(&s.Client)
	case *packets.PublishPacket:
		s.handler.Publish(&s.Client, &p.TopicName, &p.Payload)
	case *packets.SubscribePacket:
		s.handler.Subscribe(&s.Client, &p.Topics)
	case *packets.UnsubscribePacket:
		s.handler.Unsubscribe(&s.Client, &p.Topics)
	default:
		return
	}
}

func wrap(dir direction, err error) error {
	switch dir {
	case up:
		return errors.Wrap(errClient, err)
	case down:
		return errors.Wrap(errBroker, err)
	default:
		return err
	}
}
