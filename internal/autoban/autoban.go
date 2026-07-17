// Package autoban memblokir sementara IP yang berulang kali menyerang.
package autoban

import (
	"sync"
	"time"
)

type record struct {
	strikes   []time.Time // waktu tiap serangan (dalam jendela)
	bannedTil time.Time   // kapan ban berakhir (zero = tidak diban)
}

// Banner melacak pelanggaran per IP dan menjatuhkan ban sementara.
type Banner struct {
	mu         sync.Mutex
	records    map[string]*record
	maxStrikes int
	window     time.Duration
	banDur     time.Duration
}

// New membuat Banner. Nil bila fitur dimatikan (semua metode aman terhadap nil).
func New(enabled bool, maxStrikes, windowMinutes, banMinutes int) *Banner {
	if !enabled {
		return nil
	}
	b := &Banner{
		records:    make(map[string]*record),
		maxStrikes: maxStrikes,
		window:     time.Duration(windowMinutes) * time.Minute,
		banDur:     time.Duration(banMinutes) * time.Minute,
	}
	go b.janitor()
	return b
}

// IsBanned mengembalikan true bila IP sedang dalam masa ban.
func (b *Banner) IsBanned(ip string) bool {
	if b == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	r, ok := b.records[ip]
	if !ok {
		return false
	}
	return time.Now().Before(r.bannedTil)
}

// Strike mencatat satu serangan dari IP. Mengembalikan true HANYA saat IP
// baru saja menembus batas dan berubah menjadi terban (agar bisa dinotifikasi
// sekali saja).
func (b *Banner) Strike(ip string) (justBanned bool) {
	if b == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	r, ok := b.records[ip]
	if !ok {
		r = &record{}
		b.records[ip] = r
	}

	// Sudah dalam masa ban -> jangan hitung ulang / notifikasi ulang.
	if now.Before(r.bannedTil) {
		return false
	}

	// Buang strike lama di luar jendela waktu.
	cutoff := now.Add(-b.window)
	kept := r.strikes[:0]
	for _, t := range r.strikes {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	r.strikes = append(kept, now)

	if len(r.strikes) >= b.maxStrikes {
		r.bannedTil = now.Add(b.banDur)
		r.strikes = nil
		return true
	}
	return false
}

// BanMinutes mengembalikan durasi ban dalam menit (untuk pesan).
func (b *Banner) BanMinutes() int {
	if b == nil {
		return 0
	}
	return int(b.banDur.Minutes())
}

func (b *Banner) janitor() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		b.mu.Lock()
		now := time.Now()
		for ip, r := range b.records {
			// Hapus catatan yang bannya lewat dan tak punya strike aktif.
			if now.After(r.bannedTil) && len(r.strikes) == 0 {
				delete(b.records, ip)
			}
		}
		b.mu.Unlock()
	}
}
