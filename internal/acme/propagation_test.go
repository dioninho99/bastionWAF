package acme

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestWaitTXTWaitsForExactValueAtAllResolvers(t *testing.T) {
	calls := 0
	first := func(ctx context.Context, name string) ([]string, error) {
		if name != "_acme-challenge.example.test." {
			t.Fatalf("unexpected query %s", name)
		}
		calls++
		if calls == 1 {
			return nil, errors.New("temporary DNS failure")
		}
		if calls == 2 {
			return []string{"old-proof"}, nil
		}
		return []string{"old-proof", "expected-proof"}, nil
	}
	secondCalls := 0
	second := func(context.Context, string) ([]string, error) {
		secondCalls++
		if secondCalls < 4 {
			return nil, nil
		}
		return []string{"expected-proof"}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := waitTXT(ctx, "_acme-challenge.example.test", "expected-proof", time.Millisecond, []txtLookup{first, second}); err != nil {
		t.Fatal(err)
	}
	if calls != 4 || secondCalls != 4 {
		t.Fatalf("returned before both resolvers agreed: %d %d", calls, secondCalls)
	}
}
func TestWaitTXTTimeoutAndCancellation(t *testing.T) {
	for _, cancelImmediately := range []bool{false, true} {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		if cancelImmediately {
			cancel()
		}
		err := waitTXT(ctx, "example.test", "expected", time.Millisecond, []txtLookup{func(ctx context.Context, _ string) ([]string, error) { <-ctx.Done(); return nil, ctx.Err() }})
		cancel()
		if !errors.Is(err, errDNSPropagation) {
			t.Fatalf("missing actionable error: %v", err)
		}
		if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
			t.Fatalf("missing cancellation cause: %v", err)
		}
	}
}
