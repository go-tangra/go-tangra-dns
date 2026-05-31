package event

import (
	"context"
	"encoding/json"
	"sync"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/redis/go-redis/v9"
	"github.com/tx7do/kratos-bootstrap/bootstrap"

	appViewer "github.com/go-tangra/go-tangra-common/viewer"
)

// Subscriber listens to IPAM Redis pub/sub events and dispatches them to
// the Handler. Mirrors go-tangra-deployer's event subscriber.
type Subscriber struct {
	log     *log.Helper
	rdb     *redis.Client
	handler *Handler

	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	running bool
	mu      sync.Mutex
}

// NewSubscriber creates the subscriber.
func NewSubscriber(ctx *bootstrap.Context, rdb *redis.Client, handler *Handler) *Subscriber {
	return &Subscriber{
		log:     ctx.NewLoggerHelper("dns/event/subscriber"),
		rdb:     rdb,
		handler: handler,
	}
}

// channels are the Redis channels this service subscribes to.
func channels() []string {
	return []string{
		IPAMTopicPrefix + "." + IPAMIPAddressCreated,
		IPAMTopicPrefix + "." + IPAMIPAddressDeleted,
	}
}

// Start begins consuming events. Safe to call when Redis is unavailable
// (it logs and becomes a no-op).
func (s *Subscriber) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return nil
	}
	if s.rdb == nil {
		s.log.Warn("Redis client not available, event subscriber disabled")
		return nil
	}

	// Background ops use a system viewer context to bypass ent tenant
	// privacy checks (tenant scoping is applied explicitly via the event's
	// tenant_id).
	base := appViewer.NewSystemViewerContext(context.Background())
	s.ctx, s.cancel = context.WithCancel(base)
	s.running = true

	chans := channels()
	s.log.Infof("starting event subscriber for channels: %v", chans)

	pubsub := s.rdb.Subscribe(s.ctx, chans...)
	s.wg.Add(1)
	go s.listen(pubsub)
	return nil
}

// Stop halts the subscriber.
func (s *Subscriber) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return nil
	}
	s.log.Info("stopping event subscriber")
	s.cancel()
	s.wg.Wait()
	s.running = false
	return nil
}

func (s *Subscriber) listen(pubsub *redis.PubSub) {
	defer s.wg.Done()
	defer pubsub.Close()

	ch := pubsub.Channel()
	for {
		select {
		case <-s.ctx.Done():
			return
		case msg, ok := <-ch:
			if !ok {
				return
			}
			s.handleMessage(msg)
		}
	}
}

func (s *Subscriber) handleMessage(msg *redis.Message) {
	var env Envelope
	if err := json.Unmarshal([]byte(msg.Payload), &env); err != nil {
		s.log.Errorf("failed to unmarshal event from %s: %v", msg.Channel, err)
		return
	}

	switch env.Type {
	case IPAMIPAddressCreated:
		d, ok := s.decode(env)
		if !ok {
			return
		}
		if err := s.handler.HandleIPAddressCreated(s.ctx, d); err != nil {
			s.log.Errorf("failed to handle ip_address.created: %v", err)
		}
	case IPAMIPAddressDeleted:
		d, ok := s.decode(env)
		if !ok {
			return
		}
		if err := s.handler.HandleIPAddressDeleted(s.ctx, d); err != nil {
			s.log.Errorf("failed to handle ip_address.deleted: %v", err)
		}
	default:
		// Not a topic we handle.
	}
}

// decode unmarshals the envelope's data payload, defaulting the tenant from
// the envelope when the inner payload omits it.
func (s *Subscriber) decode(env Envelope) (*IPAddressData, bool) {
	var d IPAddressData
	if err := json.Unmarshal(env.Data, &d); err != nil {
		s.log.Errorf("failed to decode %s data: %v", env.Type, err)
		return nil, false
	}
	if d.TenantID == 0 {
		d.TenantID = env.TenantID
	}
	return &d, true
}
