// Package notify mengirim pemberitahuan serangan ke Telegram (opsional).
package notify

import (
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Notifier mengirim pesan Telegram secara asinkron agar tidak memperlambat
// penanganan permintaan.
type Notifier struct {
	botToken string
	chatID   string
	queue    chan string
	client   *http.Client
}

// New membuat Notifier. Mengembalikan nil bila dimatikan (metode aman thd nil).
func New(enabled bool, botToken, chatID string) *Notifier {
	if !enabled || botToken == "" || chatID == "" {
		return nil
	}
	n := &Notifier{
		botToken: botToken,
		chatID:   chatID,
		queue:    make(chan string, 100),
		client:   &http.Client{Timeout: 10 * time.Second},
	}
	go n.worker()
	return n
}

// Send mengantre pesan. Bila antrean penuh, pesan diabaikan (tidak memblokir).
func (n *Notifier) Send(msg string) {
	if n == nil {
		return
	}
	select {
	case n.queue <- msg:
	default: // antrean penuh, lewati agar tidak menghambat
	}
}

func (n *Notifier) worker() {
	for msg := range n.queue {
		n.deliver(msg)
		// Hormati batas laju Telegram (~30 pesan/detik) dengan jeda aman.
		time.Sleep(1200 * time.Millisecond)
	}
}

func (n *Notifier) deliver(text string) {
	api := "https://api.telegram.org/bot" + n.botToken + "/sendMessage"
	form := url.Values{}
	form.Set("chat_id", n.chatID)
	form.Set("text", text)
	form.Set("parse_mode", "HTML")

	resp, err := n.client.PostForm(api, form)
	if err != nil {
		log.Printf("[notify] gagal kirim Telegram: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		log.Printf("[notify] Telegram menolak (HTTP %d) - cek bot_token & chat_id", resp.StatusCode)
	}
}

// Escape membersihkan teks agar aman untuk parse_mode HTML Telegram.
func Escape(s string) string {
	r := strings.NewReplacer("<", "&lt;", ">", "&gt;", "&", "&amp;")
	return r.Replace(s)
}
