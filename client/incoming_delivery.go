package client

import (
	"context"
	"crypto/tls"
	"net/http"

	"github.com/solodyagin/outgate-sdk/delivery"
	"github.com/solodyagin/outgate-sdk/httpsig"
	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
)

func (c Config) sessionHandler(registration v1.Register) (http.Handler, error) {
	if c.IncomingDelivery == nil {
		return c.Handler, nil
	}
	config := *c.IncomingDelivery
	config.StripPrefix = registration.PathMode == "strip"
	mounts := make(map[string]bool, len(registration.Paths))
	for _, path := range registration.Paths {
		prefix, err := v1.NormalizePrefix(path)
		if err != nil {
			return nil, err
		}
		mounts[prefix] = true
	}
	prepare := config.Prepare
	config.Prepare = func(ctx context.Context, peer *tls.ConnectionState, metadata httpsig.Request) (delivery.Key, delivery.Binding, error) {
		key, binding, err := prepare(ctx, peer, metadata)
		if err != nil {
			return delivery.Key{}, delivery.Binding{}, err
		}
		if binding.Target != registration.ServiceID || binding.Instance != registration.InstanceID || binding.Version != registration.Version || !mounts[binding.Prefix] {
			return delivery.Key{}, delivery.Binding{}, delivery.ErrDelivery
		}
		return key, binding, nil
	}
	return delivery.NewHandler(config, c.Handler)
}
