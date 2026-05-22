package cache

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fedot/oidc-proxy/internal/token"
)

func TestCacheReturnsMemoizedResult(t *testing.T) {
	var calls int32
	inner := func(_ context.Context, tok string) (*token.Verified, error) {
		atomic.AddInt32(&calls, 1)
		return &token.Verified{Subject: "alice", Email: "alice@example.com", Expiry: time.Now().Add(time.Hour)}, nil
	}
	verify := Wrap(inner, New(8))

	for i := 0; i < 5; i++ {
		v, err := verify(context.Background(), "the-jwt")
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		if v.Subject != "alice" {
			t.Fatalf("Subject = %q", v.Subject)
		}
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("inner verifier was called %d times, want 1", got)
	}
}

func TestCacheExpiresAtTokenExp(t *testing.T) {
	c := New(8)

	var calls int32
	inner := func(_ context.Context, tok string) (*token.Verified, error) {
		atomic.AddInt32(&calls, 1)
		// 50ms lifetime — short enough to expire within the test but long
		// enough that a same-tick cache hit isn't racy.
		return &token.Verified{Subject: "alice", Expiry: time.Now().Add(50 * time.Millisecond)}, nil
	}
	verify := Wrap(inner, c)

	if _, err := verify(context.Background(), "tok"); err != nil {
		t.Fatalf("first call: %v", err)
	}
	if _, err := verify(context.Background(), "tok"); err != nil {
		t.Fatalf("second call (cache hit): %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("expected 1 inner call before expiry, got %d", got)
	}

	time.Sleep(100 * time.Millisecond) // past expiry
	if _, err := verify(context.Background(), "tok"); err != nil {
		t.Fatalf("post-expiry call: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("expected 2 inner calls after expiry, got %d", got)
	}
}

func TestCacheDoesNotMemoizeErrors(t *testing.T) {
	var calls int32
	inner := func(_ context.Context, tok string) (*token.Verified, error) {
		atomic.AddInt32(&calls, 1)
		return nil, errors.New("nope")
	}
	verify := Wrap(inner, New(8))

	for i := 0; i < 3; i++ {
		if _, err := verify(context.Background(), "tok"); err == nil {
			t.Fatalf("expected error")
		}
	}
	if got := atomic.LoadInt32(&calls); got != 3 {
		t.Fatalf("inner was called %d times, want 3 (errors not cached)", got)
	}
}

func TestCacheEvictsWhenFull(t *testing.T) {
	c := New(2)
	inner := func(_ context.Context, tok string) (*token.Verified, error) {
		return &token.Verified{Subject: tok, Expiry: time.Now().Add(time.Hour)}, nil
	}
	verify := Wrap(inner, c)

	for _, tok := range []string{"a", "b", "c"} {
		if _, err := verify(context.Background(), tok); err != nil {
			t.Fatalf("verify(%q): %v", tok, err)
		}
	}
	if c.Len() > 2 {
		t.Fatalf("cache grew to %d entries past maxSize=2", c.Len())
	}
}

func TestCacheKeyDistinguishesTokens(t *testing.T) {
	if key("abc") == key("abd") {
		t.Fatalf("key collides on trivial inputs")
	}
}
