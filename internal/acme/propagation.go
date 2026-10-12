package acme

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

var errDNSPropagation = errors.New("DNS proof is not yet publicly visible; check DNS delegation and outbound DNS connectivity")

type txtLookup func(context.Context, string) ([]string, error)

// Use independent public recursive resolvers, rather than a split-horizon local
// resolver. A successful write to the provider API does not imply DNS visibility.
func publicTXTLookup(address string) txtLookup {
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}}
	return resolver.LookupTXT
}

func waitDNSPropagation(ctx context.Context, name, value string) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	return waitTXT(ctx, name, value, 5*time.Second, []txtLookup{publicTXTLookup("1.1.1.1:53"), publicTXTLookup("8.8.8.8:53")})
}

// Require the exact challenge value at every resolver in the same polling round.
// Stale TXT records and transient lookup failures never authorize validation.
func waitTXT(ctx context.Context, name, value string, interval time.Duration, lookups []txtLookup) error {
	name = strings.TrimSuffix(name, ".") + "."
	for {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("%w: %w", errDNSPropagation, err)
		}
		visible := len(lookups) > 0
		for _, lookup := range lookups {
			attempt, cancel := context.WithTimeout(ctx, 5*time.Second)
			records, err := lookup(attempt, name)
			cancel()
			found := false
			if err == nil {
				for _, record := range records {
					if record == value {
						found = true
						break
					}
				}
			}
			visible = visible && found
		}
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("%w: %w", errDNSPropagation, err)
		}
		if visible {
			return nil
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fmt.Errorf("%w: %w", errDNSPropagation, ctx.Err())
		case <-timer.C:
		}
	}
}
