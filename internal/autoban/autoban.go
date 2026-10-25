// Package autoban memblokir sementara IP yang berulang kali menyerang.
package autoban

import (
	"strings"
	"sync"
	"time"
)

type record struct {
	strikes   []time.Time // waktu tiap serangan (dalam jendela)
	bannedTil time.Time   // kapan ban berakhir (zero = tidak diban)
}

// Banner melacak pelanggaran per IP dan menjatuhkan ban sementara. Selalu
// dikonstruksi (meski fitur dimatikan) agar auto-ban bisa dinyalakan/dimatikan
// dan disetel ulang dari konsol tanpa restart.
type Banner struct {
	mu         sync.Mutex
	records    map[string]*record
	enabled    bool
	maxStrikes int
	window     time.Duration
	banDur     time.Duration
}

// New membuat Banner. Selalu non-nil; bila enabled=false fitur pasif (tidak
// mencatat strike / tidak menjatuhkan ban), tapi bisa dinyalakan via SetConfig.
func New(enabled bool, maxStrikes, windowMinutes, banMinutes int) *Banner {
	if maxStrikes <= 0 {
		maxStrikes = 5
	}
	if windowMinutes <= 0 {
		windowMinutes = 10
	}
	if banMinutes <= 0 {
		banMinutes = 60
	}
	b := &Banner{
		records:    make(map[string]*record),
		enabled:    enabled,
		maxStrikes: maxStrikes,
		window:     time.Duration(windowMinutes) * time.Minute,
		banDur:     time.Duration(banMinutes) * time.Minute,
	}
	go b.janitor()
	return b
}

// SetConfig mengganti pengaturan auto-ban saat berjalan (dari konsol).
func (b *Banner) SetConfig(enabled bool, maxStrikes, windowMinutes, banMinutes int) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.enabled = enabled
	if maxStrikes > 0 {
		b.maxStrikes = maxStrikes
	}
	if windowMinutes > 0 {
		b.window = time.Duration(windowMinutes) * time.Minute
	}
	if banMinutes > 0 {
		b.banDur = time.Duration(banMinutes) * time.Minute
	}
}

// IsBanned mengembalikan true bila IP sedang dalam masa ban.
func (b *Banner) IsBanned(ip string) bool {
	if b == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.enabled {
		return false
	}
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
	if !b.enabled {
		return false
	}

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
	b.mu.Lock()
	defer b.mu.Unlock()
	return int(b.banDur.Minutes())
}

// Enabled mengembalikan true bila auto-ban aktif (aman terhadap nil).
func (b *Banner) Enabled() bool {
	if b == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.enabled
}

// BanInfo adalah satu entri ban aktif untuk ditampilkan di konsol Shield.
type BanInfo struct {
	Key         string    `json:"key"`          // kunci internal (untuk buka blokir)
	IP          string    `json:"ip"`           // IP yang terlihat
	Until       time.Time `json:"until"`        // kapan ban berakhir
	SecondsLeft int       `json:"seconds_left"` // sisa waktu ban (detik)
}

// List mengembalikan semua ban yang masih aktif, terbaru berakhir di urutan awal.
func (b *Banner) List() []BanInfo {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	var out []BanInfo
	for key, r := range b.records {
		if now.Before(r.bannedTil) {
			ip, _, _ := cutKey(key)
			out = append(out, BanInfo{
				Key: key, IP: ip, Until: r.bannedTil,
				SecondsLeft: int(time.Until(r.bannedTil).Seconds()),
			})
		}
	}
	return out
}

// Unban mencabut ban untuk sebuah kunci. Mengembalikan true bila ada yang dicabut.
func (b *Banner) Unban(key string) bool {
	if b == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	r, ok := b.records[key]
	if !ok || !time.Now().Before(r.bannedTil) {
		return false
	}
	delete(b.records, key)
	return true
}

// cutKey memisahkan IP dari sidik jari User-Agent pada kunci ban ("ip" atau "ip|hash").
func cutKey(key string) (ip, ua string, hasUA bool) {
	return strings.Cut(key, "|")
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
