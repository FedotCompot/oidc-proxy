package main

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestCacheReturnsMemoizedResult(t *testing.T) {
	var calls int32
	inner := func(_ context.Context, tok string) (*VerifiedToken, error) {
		atomic.AddInt32(&calls, 1)
		return &VerifiedToken{Subject: "alice", Email: "alice@example.com", Expiry: time.Now().Add(time.Hour)}, nil
	}
	verify := withCache(inner, newTokenCache(8))

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
	c := newTokenCache(8)

	var calls int32
	inner := func(_ context.Context, tok string) (*VerifiedToken, error) {
		atomic.AddInt32(&calls, 1)
		// 50ms lifetime — short enough to expire within the test but long
		// enough that a same-tick cache hit isn't racy.
		return &VerifiedToken{Subject: "alice", Expiry: time.Now().Add(50 * time.Millisecond)}, nil
	}
	verify := withCache(inner, c)

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
	inner := func(_ context.Context, tok string) (*VerifiedToken, error) {
		atomic.AddInt32(&calls, 1)
		return nil, errors.New("nope")
	}
	verify := withCache(inner, newTokenCache(8))

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
	c := newTokenCache(2)
	inner := func(_ context.Context, tok string) (*VerifiedToken, error) {
		return &VerifiedToken{Subject: tok, Expiry: time.Now().Add(time.Hour)}, nil
	}
	verify := withCache(inner, c)

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
	if cacheKey("abc") == cacheKey("abd") {
		t.Fatalf("cacheKey collides on trivial inputs")
	}
}

func TestCachedVerifyFromHandler(t *testing.T) {
	// /verify should benefit from caching: two consecutive verify requests
	// with the same id_token cookie should only hit the inner verifier once.
	s := newTestServer(t)
	var calls int32
	inner := func(_ context.Context, tok string) (*VerifiedToken, error) {
		atomic.AddInt32(&calls, 1)
		if tok != "valid" {
			return nil, errors.New("bad")
		}
		return &VerifiedToken{Subject: "alice", Email: "alice@example.com", Expiry: time.Now().Add(time.Hour)}, nil
	}
	s.verifyFn = withCache(inner, newTokenCache(8))

	for i := 0; i < 4; i++ {
		req := newAuthedRequest(s, "valid")
		w := recordVerify(s, req)
		if w.Code != 200 {
			t.Fatalf("iteration %d: status = %d", i, w.Code)
		}
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("inner verifier called %d times across 4 /verify requests, want 1", got)
	}
}
