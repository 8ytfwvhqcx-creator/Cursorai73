package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// Régions commerciales AWS pour STS GetCallerIdentity (ordre: us-east-1 en premier).
var awsSTSCandidateRegions = []string{
	"us-east-1", "us-east-2", "us-west-1", "us-west-2",
	"eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-central-2", "eu-north-1",
	"ap-south-1", "ap-south-2", "ap-southeast-1", "ap-southeast-2", "ap-southeast-3", "ap-southeast-4",
	"ap-northeast-1", "ap-northeast-2", "ap-northeast-3",
	"ca-central-1", "sa-east-1",
	"me-south-1", "me-central-1", "af-south-1",
}

const validationHTTPTimeout = 15 * time.Second

var validationClient = &http.Client{
	Timeout: validationHTTPTimeout,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:    32,
		IdleConnTimeout: 90 * time.Second,
	},
}

// validateSendGrid appelle l’API SendGrid (crédits) — clé valide si HTTP 200.
func validateSendGrid(apiKey string) (ok bool, quota string, detail string) {
	ctx, cancel := context.WithTimeout(context.Background(), validationHTTPTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.sendgrid.com/v3/user/credits", nil)
	if err != nil {
		return false, "", err.Error()
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Accept", "application/json")
	resp, err := validationClient.Do(req)
	if err != nil {
		return false, "", err.Error()
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if resp.StatusCode != http.StatusOK {
		return false, "", fmt.Sprintf("HTTP %d: %s", resp.StatusCode, truncate(string(body), 200))
	}
	var m map[string]interface{}
	if err := json.Unmarshal(body, &m); err != nil {
		return true, "OK (parse partiel)", string(body)
	}
	quota = formatSendGridCredits(m)
	return true, quota, string(body)
}

func formatSendGridCredits(m map[string]interface{}) string {
	parts := []string{}
	if v, ok := m["remain"]; ok {
		parts = append(parts, fmt.Sprintf("reste=%v", v))
	}
	if v, ok := m["total"]; ok {
		parts = append(parts, fmt.Sprintf("total=%v", v))
	}
	if v, ok := m["used"]; ok {
		parts = append(parts, fmt.Sprintf("utilisé=%v", v))
	}
	if v, ok := m["reset_frequency"]; ok {
		parts = append(parts, fmt.Sprintf("reset=%v", v))
	}
	if len(parts) == 0 {
		return "crédits OK"
	}
	return strings.Join(parts, ", ")
}

// validateBrevo GET /v3/account
func validateBrevo(apiKey string) (ok bool, quota string, detail string) {
	ctx, cancel := context.WithTimeout(context.Background(), validationHTTPTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.brevo.com/v3/account", nil)
	if err != nil {
		return false, "", err.Error()
	}
	req.Header.Set("api-key", apiKey)
	req.Header.Set("Accept", "application/json")
	resp, err := validationClient.Do(req)
	if err != nil {
		return false, "", err.Error()
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if resp.StatusCode != http.StatusOK {
		return false, "", fmt.Sprintf("HTTP %d: %s", resp.StatusCode, truncate(string(body), 200))
	}
	quota = fmt.Sprintf("rate-limit restant: %s", resp.Header.Get("X-Sib-RateLimit-Remaining"))
	if quota == "rate-limit restant: " {
		quota = "compte OK"
	}
	return true, quota, string(body)
}

// validateAWS teste STS sur chaque région jusqu’au premier succès.
func validateAWS(accessKeyID, secretAccessKey string) (ok bool, region string, arn string, account string, userID string, tried string) {
	var lastErr string
	for _, reg := range awsSTSCandidateRegions {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		cfg, err := config.LoadDefaultConfig(ctx,
			config.WithRegion(reg),
			config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKeyID, secretAccessKey, "")),
		)
		cancel()
		if err != nil {
			lastErr = err.Error()
			continue
		}
		svc := sts.NewFromConfig(cfg)
		ctx2, cancel2 := context.WithTimeout(context.Background(), 8*time.Second)
		out, err := svc.GetCallerIdentity(ctx2, &sts.GetCallerIdentityInput{})
		cancel2()
		if err != nil {
			lastErr = err.Error()
			continue
		}
		arn = aws.ToString(out.Arn)
		account = aws.ToString(out.Account)
		userID = aws.ToString(out.UserId)
		return true, reg, arn, account, userID, strings.Join(awsSTSCandidateRegions, ", ")
	}
	return false, "", "", "", "", lastErr
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// validatePostmark — token serveur Postmark
func validatePostmark(serverToken string) (ok bool, detail string) {
	ctx, cancel := context.WithTimeout(context.Background(), validationHTTPTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.postmarkapp.com/server", nil)
	if err != nil {
		return false, err.Error()
	}
	req.Header.Set("X-Postmark-Server-Token", serverToken)
	req.Header.Set("Accept", "application/json")
	resp, err := validationClient.Do(req)
	if err != nil {
		return false, err.Error()
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Sprintf("HTTP %d", resp.StatusCode)
	}
	return true, truncate(string(body), 500)
}

// validateSparkPost — GET /api/v1/account (US puis EU)
func validateSparkPost(apiKey string) (ok bool, detail string) {
	endpoints := []string{
		"https://api.sparkpost.com/api/v1/account",
		"https://api.eu.sparkpost.com/api/v1/account",
	}
	var last string
	for _, ep := range endpoints {
		ctx, cancel := context.WithTimeout(context.Background(), validationHTTPTimeout)
		req, err := http.NewRequestWithContext(ctx, "GET", ep, nil)
		if err != nil {
			cancel()
			return false, err.Error()
		}
		req.Header.Set("Authorization", apiKey)
		req.Header.Set("Accept", "application/json")
		resp, err := validationClient.Do(req)
		cancel()
		if err != nil {
			last = err.Error()
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			last = fmt.Sprintf("HTTP %d", resp.StatusCode)
			continue
		}
		return true, fmt.Sprintf("%s | %s", ep, truncate(string(body), 400))
	}
	return false, last
}

// validateMailchimp — apikey format xxx-us10
func validateMailchimp(apiKey string) (ok bool, detail string) {
	parts := strings.Split(apiKey, "-")
	if len(parts) < 2 {
		return false, "format mc invalide"
	}
	dc := parts[len(parts)-1]
	if len(dc) < 2 {
		return false, "datacenter absent"
	}
	url := fmt.Sprintf("https://%s.api.mailchimp.com/3.0/", dc)
	ctx, cancel := context.WithTimeout(context.Background(), validationHTTPTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false, err.Error()
	}
	auth := base64.StdEncoding.EncodeToString([]byte("anystring:" + apiKey))
	req.Header.Set("Authorization", "Basic "+auth)
	req.Header.Set("Accept", "application/json")
	resp, err := validationClient.Do(req)
	if err != nil {
		return false, err.Error()
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Sprintf("HTTP %d", resp.StatusCode)
	}
	return true, truncate(string(body), 400)
}
