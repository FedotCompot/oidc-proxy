package web

import (
	"testing"
	"time"
)

func TestRateLimiterFixedWindow(t *testing.T) {
	rl := newRateLimiter(3, time.Minute)

	for i := range 3 {
		if !rl.allow("1.2.3.4") {
			t.Fatalf("hit %d blocked before limit", i+1)
		}
	}
	if rl.allow("1.2.3.4") {
		t.Fatal("4th hit within window should be blocked")
	}
	// A distinct key has its own budget.
	if !rl.allow("5.6.7.8") {
		t.Fatal("distinct key should not be limited")
	}
}

func TestRateLimiterNilAllows(t *testing.T) {
	var rl *rateLimiter
	if !rl.allow("anything") {
		t.Fatal("nil limiter (feature disabled) must allow")
	}
}

func TestRateLimiterExpiredWindowResets(t *testing.T) {
	rl := newRateLimiter(1, time.Nanosecond)
	if !rl.allow("k") {
		t.Fatal("first hit blocked")
	}
	time.Sleep(time.Millisecond) // let the 1ns window lapse
	if !rl.allow("k") {
		t.Fatal("hit after window lapse should be allowed again")
	}
}
