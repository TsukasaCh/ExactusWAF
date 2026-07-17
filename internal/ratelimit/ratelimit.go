// Package ratelimit menyediakan pembatas laju per-IP menggunakan token bucket.
package ratelimit

import (
	"sync"
	"time"
)

type bucket struct {
	tokens   float64
	lastSeen time.Time
}

// Limiter membatasi jumlah permintaan per IP.
type Limiter struct {
	mu       sync.Mutex
	buckets  map[string]*bucket
	rate     float64 // token per detik
	capacity float64 // ukuran bucket (burst)
}

// New membuat Limiter. requestsPerMinute dikonversi ke rate per detik.
func New(requestsPerMinute, burst int) *Limiter {
	l := &Limiter{
		buckets:  make(map[string]*bucket),
		rate:     float64(requestsPerMinute) / 60.0,
		capacity: float64(burst),
	}
	go l.janitor()
	return l
}

// Allow mengembalikan true jika IP masih boleh melakukan permintaan.
func (l *Limiter) Allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	b, ok := l.buckets[ip]
	if !ok {
		l.buckets[ip] = &bucket{tokens: l.capacity - 1, lastSeen: now}
		return true
	}

	// Isi ulang token sesuai waktu berlalu.
	elapsed := now.Sub(b.lastSeen).Seconds()
	b.tokens += elapsed * l.rate
	if b.tokens > l.capacity {
		b.tokens = l.capacity
	}
	b.lastSeen = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// janitor membersihkan bucket lama agar tidak bocor memori.
func (l *Limiter) janitor() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		l.mu.Lock()
		cutoff := time.Now().Add(-10 * time.Minute)
		for ip, b := range l.buckets {
			if b.lastSeen.Before(cutoff) {
				delete(l.buckets, ip)
			}
		}
		l.mu.Unlock()
	}
}
