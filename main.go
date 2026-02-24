package main

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// ==============================================
// ATTACK LOGGING & STATISTICS
// ==============================================


// AttackEvent represents a single attack attempt
type AttackEvent struct {
	ID        int       `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	IP        string    `json:"ip"`
	Path      string    `json:"path"`
	Method    string    `json:"method"`
	UserAgent string    `json:"user_agent"`
	Reason    string    `json:"reason"`
	Response  string    `json:"response"`
	GeoInfo   *GeoInfo  `json:"geo_info,omitempty"`
	Headers   map[string]string `json:"headers,omitempty"`
}

// GeoInfo contains geographic information about an IP
type GeoInfo struct {
	Country     string `json:"country"`
	CountryCode string `json:"country_code"`
	City        string `json:"city"`
	Region      string `json:"region"`
	ISP         string `json:"isp"`
	Org         string `json:"org"`
}

// AttackLog stores recent attack events
type AttackLog struct {
	mu         sync.RWMutex
	events     []AttackEvent
	maxEvents  int
	nextID     int
	ipStats    map[string]*IPStats
	pathStats  map[string]int
	uaStats    map[string]int
	geoCache   map[string]*GeoInfo
	geoCacheMu sync.RWMutex
}

// IPStats tracks statistics for a single IP
type IPStats struct {
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	TotalHits   int       `json:"total_hits"`
	UniquePages int       `json:"unique_pages"`
	Pages       map[string]bool `json:"-"`
}

// Global attack log
var attackLog = &AttackLog{
	events:    make([]AttackEvent, 0, 1000),
	maxEvents: 1000,
	nextID:    1,
	ipStats:   make(map[string]*IPStats),
	pathStats: make(map[string]int),
	uaStats:   make(map[string]int),
	geoCache:  make(map[string]*GeoInfo),
}

// recordAttack adds an attack event to the log
func (al *AttackLog) recordAttack(r *http.Request, reason, response string) AttackEvent {
	al.mu.Lock()
	defer al.mu.Unlock()

	ip := getClientIP(r)
	path := r.URL.Path
	ua := r.Header.Get("User-Agent")
	if ua == "" {
		ua = "Empty"
	}

	// Collect interesting headers
	headers := make(map[string]string)
	interestingHeaders := []string{"X-Forwarded-For", "X-Real-IP", "Referer", "Origin", "Cookie"}
	for _, h := range interestingHeaders {
		if v := r.Header.Get(h); v != "" {
			headers[h] = v
		}
	}

	event := AttackEvent{
		ID:        al.nextID,
		Timestamp: time.Now(),
		IP:        ip,
		Path:      path,
		Method:    r.Method,
		UserAgent: ua,
		Reason:    reason,
		Response:  response,
		Headers:   headers,
	}
	al.nextID++

	// Add to events (circular buffer)
	if len(al.events) >= al.maxEvents {
		al.events = al.events[1:]
	}
	al.events = append(al.events, event)

	// Update IP stats
	if _, exists := al.ipStats[ip]; !exists {
		al.ipStats[ip] = &IPStats{
			FirstSeen: time.Now(),
			Pages:     make(map[string]bool),
		}
	}
	al.ipStats[ip].LastSeen = time.Now()
	al.ipStats[ip].TotalHits++
	if !al.ipStats[ip].Pages[path] {
		al.ipStats[ip].Pages[path] = true
		al.ipStats[ip].UniquePages++
	}

	// Update path stats
	al.pathStats[path]++

	// Update UA stats (truncate long UAs)
	truncUA := ua
	if len(truncUA) > 50 {
		truncUA = truncUA[:50] + "..."
	}
	al.uaStats[truncUA]++

	return event
}

// getRecentEvents returns the most recent N events
func (al *AttackLog) getRecentEvents(n int) []AttackEvent {
	al.mu.RLock()
	defer al.mu.RUnlock()

	if n > len(al.events) {
		n = len(al.events)
	}
	result := make([]AttackEvent, n)
	copy(result, al.events[len(al.events)-n:])
	// Reverse to show newest first
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}
	return result
}

// getStats returns aggregated statistics
func (al *AttackLog) getStats() map[string]interface{} {
	al.mu.RLock()
	defer al.mu.RUnlock()

	// Top IPs
	type ipCount struct {
		IP    string `json:"ip"`
		Count int    `json:"count"`
	}
	topIPs := make([]ipCount, 0)
	for ip, stats := range al.ipStats {
		topIPs = append(topIPs, ipCount{IP: ip, Count: stats.TotalHits})
	}
	sort.Slice(topIPs, func(i, j int) bool { return topIPs[i].Count > topIPs[j].Count })
	if len(topIPs) > 10 {
		topIPs = topIPs[:10]
	}

	// Top paths
	type pathCount struct {
		Path  string `json:"path"`
		Count int    `json:"count"`
	}
	topPaths := make([]pathCount, 0)
	for path, count := range al.pathStats {
		topPaths = append(topPaths, pathCount{Path: path, Count: count})
	}
	sort.Slice(topPaths, func(i, j int) bool { return topPaths[i].Count > topPaths[j].Count })
	if len(topPaths) > 10 {
		topPaths = topPaths[:10]
	}

	// Top user agents
	type uaCount struct {
		UA    string `json:"user_agent"`
		Count int    `json:"count"`
	}
	topUAs := make([]uaCount, 0)
	for ua, count := range al.uaStats {
		topUAs = append(topUAs, uaCount{UA: ua, Count: count})
	}
	sort.Slice(topUAs, func(i, j int) bool { return topUAs[i].Count > topUAs[j].Count })
	if len(topUAs) > 10 {
		topUAs = topUAs[:10]
	}

	return map[string]interface{}{
		"total_events":   len(al.events),
		"unique_ips":     len(al.ipStats),
		"unique_paths":   len(al.pathStats),
		"top_ips":        topIPs,
		"top_paths":      topPaths,
		"top_user_agents": topUAs,
	}
}

// lookupGeoIP attempts to get geographic info for an IP (with caching)
func (al *AttackLog) lookupGeoIP(ip string) *GeoInfo {
	// Check cache first
	al.geoCacheMu.RLock()
	if geo, exists := al.geoCache[ip]; exists {
		al.geoCacheMu.RUnlock()
		return geo
	}
	al.geoCacheMu.RUnlock()

	// Skip private IPs
	if isPrivateIP(ip) {
		return &GeoInfo{Country: "Private", CountryCode: "XX", City: "Local"}
	}

	// Use free ip-api.com service (limited to 45 req/min)
	// In production, you'd want a local GeoIP database
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://ip-api.com/json/%s?fields=country,countryCode,city,regionName,isp,org", ip))
	if err != nil {
		return nil
	}
	defer func() { _ = resp.Body.Close() }()

	var result struct {
		Country     string `json:"country"`
		CountryCode string `json:"countryCode"`
		City        string `json:"city"`
		Region      string `json:"regionName"`
		ISP         string `json:"isp"`
		Org         string `json:"org"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil
	}

	geo := &GeoInfo{
		Country:     result.Country,
		CountryCode: result.CountryCode,
		City:        result.City,
		Region:      result.Region,
		ISP:         result.ISP,
		Org:         result.Org,
	}

	// Cache the result
	al.geoCacheMu.Lock()
	al.geoCache[ip] = geo
	al.geoCacheMu.Unlock()

	return geo
}

// isPrivateIP checks if an IP is private/internal
func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	privateBlocks := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"::1/128",
		"fc00::/7",
	}
	for _, block := range privateBlocks {
		_, cidr, _ := net.ParseCIDR(block)
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// ==============================================
// RATE LIMITING / BEHAVIORAL DETECTION
// ==============================================

// RequestTracker tracks requests per IP for behavioral detection
type RequestTracker struct {
	mu       sync.RWMutex
	requests map[string]*IPRequestInfo
}

// IPRequestInfo tracks request patterns for a single IP
type IPRequestInfo struct {
	Count           int
	FirstSeen       time.Time
	LastSeen        time.Time
	SuspiciousPaths int
	UniquePathCount int
	SeenPaths       map[string]bool
}

var requestTracker = &RequestTracker{
	requests: make(map[string]*IPRequestInfo),
}

// Thresholds for behavioral detection
const (
	maxRequestsPerMinute  = 30  // More than this triggers slow mode
	maxSuspiciousPaths    = 5   // Accessing this many suspicious paths = zipbomb
	maxUniquePathsPerMin  = 20  // Too many unique paths = scanner
	rateLimitWindowSeconds = 60
)

// getClientIP extracts the real client IP
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For first (for proxies/load balancers)
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check X-Real-IP
	xri := r.Header.Get("X-Real-IP")
	if xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// trackRequest records a request and returns behavioral analysis
func (rt *RequestTracker) trackRequest(ip string, path string, isSuspicious bool) (shouldBlock bool, reason string) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	now := time.Now()

	info, exists := rt.requests[ip]
	if !exists {
		info = &IPRequestInfo{
			FirstSeen: now,
			SeenPaths: make(map[string]bool),
		}
		rt.requests[ip] = info
	}

	// Reset counters if window expired
	if now.Sub(info.FirstSeen) > rateLimitWindowSeconds*time.Second {
		info.Count = 0
		info.SuspiciousPaths = 0
		info.UniquePathCount = 0
		info.FirstSeen = now
		info.SeenPaths = make(map[string]bool)
	}

	info.Count++
	info.LastSeen = now

	if !info.SeenPaths[path] {
		info.SeenPaths[path] = true
		info.UniquePathCount++
	}

	if isSuspicious {
		info.SuspiciousPaths++
	}

	// Check thresholds
	if info.SuspiciousPaths >= maxSuspiciousPaths {
		return true, fmt.Sprintf("Too many suspicious paths (%d)", info.SuspiciousPaths)
	}

	if info.UniquePathCount >= maxUniquePathsPerMin {
		return true, fmt.Sprintf("Path enumeration detected (%d unique paths)", info.UniquePathCount)
	}

	if info.Count >= maxRequestsPerMinute {
		return true, fmt.Sprintf("Rate limit exceeded (%d requests/min)", info.Count)
	}

	return false, ""
}

// cleanupOldEntries removes stale entries (call periodically)
func (rt *RequestTracker) cleanupOldEntries() {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	cutoff := time.Now().Add(-5 * time.Minute)
	for ip, info := range rt.requests {
		if info.LastSeen.Before(cutoff) {
			delete(rt.requests, ip)
		}
	}
}

// getTrackerStats returns current tracking statistics
func (rt *RequestTracker) getTrackerStats() map[string]interface{} {
	rt.mu.RLock()
	defer rt.mu.RUnlock()

	return map[string]interface{}{
		"tracked_ips":    len(rt.requests),
		"window_seconds": rateLimitWindowSeconds,
	}
}

// Response mode configuration
type ResponseMode int

const (
	ModeZipbomb ResponseMode = iota
	ModeSlowDrip
	ModeFakeCreds
	ModeGzipBomb
	ModeTroll
)

// Trolling messages for attackers
var trollMessages = []string{
	"Nice try, script kiddie! Your IP has been logged.",
	"Did you really think it would be that easy?",
	"Your hacking skills are about as good as your life choices.",
	"Roses are red, violets are blue, we logged your IP, and reported you too.",
	"Error 1337: Hacker detected. Initiating mockery protocol.",
	"Congratulations! You've won a lifetime supply of nothing.",
	"Your attack has been recorded for training purposes... and laughs.",
	"Pro tip: Maybe try a career change?",
	"Loading your prize... Just kidding, it's another zipbomb.",
	"We've seen smarter attacks from a Roomba.",
}

// Insults hidden in fake data
var fakePasswordHashes = []string{
	"$2a$10$NICE_TRY_SCRIPT_KIDDIE_LOL",
	"$2a$10$YOUR_MOM_CALLED_SHE_WANTS_HER_LAPTOP_BACK",
	"$2a$10$THIS_ISNT_A_REAL_HASH_DUMMY",
	"$2a$10$GET_A_REAL_JOB_MAYBE",
	"$2a$10$YOUVE_BEEN_PWNED_LMAO",
}

// Suspicious paths that attackers commonly try
var suspiciousPaths = []string{
	".env", ".env.local", ".env.production", ".env.backup", ".env.dev",
	"backup.tgz", "backup.tar.gz", "backup.zip", "backup.sql",
	"config.php", "wp-config.php", "database.sql", "dump.sql",
	".git", ".svn", ".hg", "admin", "administrator",
	"phpmyadmin", "pma", "mysql", "robots.txt", "sitemap.xml",
	".htaccess", ".htpasswd", "web.config", "server.xml",
	"application.properties", "config.json", "secrets.json",
	"credentials.json", "keys.txt", "passwords.txt",
	"users.sql", "accounts.csv", "data.xml", "export.csv",
	"logs.zip", "error.log", "access.log", "debug.log",
	// Additional honeypot paths
	"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", ".ssh/",
	"aws_credentials", ".aws/credentials", "credentials.xml",
	"docker-compose.yml", "docker-compose.yaml", ".docker/",
	"kube/config", ".kube/config", "kubeconfig",
	"terraform.tfstate", "terraform.tfvars", ".terraform/",
	"vault.json", "vault-token", ".vault-token",
	"firebase.json", "serviceAccountKey.json", "gcp-key.json",
	"settings.py", "local_settings.py", "production.py",
	"database.yml", "mongoid.yml", "redis.conf",
	"appsettings.json", "appsettings.Development.json",
	"composer.json", "package.json", "yarn.lock",
	".npmrc", ".pypirc", "pip.conf", "requirements.txt",
}

// Extended list of suspicious user agents (scanners, tools, bots)
var suspiciousUserAgents = []string{
	// Security scanners
	"sqlmap", "nikto", "nmap", "masscan", "zap", "burp",
	"gobuster", "dirbuster", "dirb", "wfuzz", "ffuf",
	"hydra", "medusa", "patator", "brutex",
	"nuclei", "httpx", "subfinder", "amass",
	"whatweb", "wpscan", "joomscan", "droopescan",
	"cmsmap", "fierce", "recon-ng", "theharvester",
	"shodan", "censys", "zgrab",
	// Exploit frameworks
	"metasploit", "meterpreter", "cobalt",
	// Suspicious patterns
	"curl/", "wget/", "python-requests", "python-urllib",
	"go-http-client", "java/", "libwww-perl",
	"scrapy", "crawler", "spider", "bot",
	// Empty or missing UA is handled separately
}

// Fake credential templates (intentionally fake for honeypot)
//
//nolint:gosec
var fakeEnvFile = `# Production Environment - DO NOT SHARE
APP_ENV=production
APP_DEBUG=false
APP_KEY=base64:dGhpc2lzYWZha2VrZXlkb250dXNlaXQ=

DB_CONNECTION=mysql
DB_HOST=internal-db.honeypot.local
DB_PORT=3306
DB_DATABASE=production_users
DB_USERNAME=admin
DB_PASSWORD=SuperSecretP@ssw0rd2024!

AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_DEFAULT_REGION=us-east-1
AWS_BUCKET=company-sensitive-data

REDIS_HOST=redis.honeypot.local
REDIS_PASSWORD=r3d1s_p@ss_2024

MAIL_MAILER=smtp
MAIL_HOST=smtp.honeypot.local
MAIL_USERNAME=admin@company.com
MAIL_PASSWORD=mailp@ss123

STRIPE_KEY=sk_live_FAKE_KEY_DO_NOT_USE_1234567890
STRIPE_SECRET=sk_live_FAKE_SECRET_DO_NOT_USE

JWT_SECRET=your-256-bit-secret-here-do-not-share
API_KEY=ak_live_totally_real_api_key_trust_me

# Internal services
ADMIN_EMAIL=admin@honeypot.local
ADMIN_PASSWORD=admin123!@#
`

var fakeWPConfig = `<?php
/**
 * WordPress Configuration - Production Server
 * CONFIDENTIAL - DO NOT DISTRIBUTE
 */

define('DB_NAME', 'wordpress_prod');
define('DB_USER', 'wp_admin');
define('DB_PASSWORD', 'W0rdPr3ss_Sup3r_S3cr3t!');
define('DB_HOST', 'db.honeypot.local');
define('DB_CHARSET', 'utf8mb4');

define('AUTH_KEY',         'this-is-a-fake-key-for-honeypot');
define('SECURE_AUTH_KEY',  'another-fake-key-do-not-use');
define('LOGGED_IN_KEY',    'fake-logged-in-key-lol');
define('NONCE_KEY',        'fake-nonce-key-gotcha');

$table_prefix = 'wp_prod_';

define('WP_DEBUG', false);
define('WP_DEBUG_LOG', '/var/log/wordpress/debug.log');

// Admin credentials backup (remove in production!)
// Username: superadmin
// Password: @dm1n_b@ckup_2024!

/* That's all, stop editing! */
require_once(ABSPATH . 'wp-settings.php');
`

var fakeGitConfig = `[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[remote "origin"]
	url = git@github.com:totally-real-company/secret-internal-repo.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
	remote = origin
	merge = refs/heads/main
[user]
	name = Admin User
	email = admin@honeypot.local
# Deploy key: ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ... (truncated)
# Password for repo: gh_token_FAKE_DO_NOT_USE_12345
`

var fakeSSHKey = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBHRklTSElTQUZBS0VLRVlET05UVVNFSVRMTUFPTk9XAAAAKEhBSEFZT1VU
UklFRFRPVVNFVEhJU0tFWVlPVUdPVFBXTkVETk9PQgAAAAtzc2gtZWQyNTUxOQAAACBHRk
lTSElTQUZBS0VLRVlET05UVVNFSVRMTUFPTk9XAAAAQEdPVENIQVlPVVNDUklQVEtJRERJ
RVRISVNJU05PVEFSR0FMS0VZSVRTQUhPTkVZUE9USEFIQUhBSEFIQUhBSEFIQQAAAA1mYW
tlQGhvbmV5cG90AQIDBAUGBw==
-----END OPENSSH PRIVATE KEY-----

# This key provides access to:
# - Production servers: prod-1.honeypot.local, prod-2.honeypot.local
# - Database servers: db-master.honeypot.local
# - Admin panel: admin.honeypot.local
#
# SSH Password: ssh_backup_p@ss_2024
`

//nolint:gosec
var fakeDatabaseDump = `-- MySQL dump 10.13  Distrib 8.0.32
-- Host: localhost    Database: production_users
-- Server version	8.0.32

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;

--
-- Table structure for table 'users'
--

DROP TABLE IF EXISTS 'users';
CREATE TABLE 'users' (
  'id' int NOT NULL AUTO_INCREMENT,
  'email' varchar(255) NOT NULL,
  'password_hash' varchar(255) NOT NULL,
  'role' enum('user','admin','superadmin') DEFAULT 'user',
  'api_key' varchar(64) DEFAULT NULL,
  PRIMARY KEY ('id')
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- Dumping data for table 'users'
--

INSERT INTO 'users' VALUES
(1,'admin@honeypot.local','%s','superadmin','ak_FAKE_ADMIN_KEY_1234'),
(2,'backup@honeypot.local','%s','admin','ak_FAKE_BACKUP_KEY_5678'),
(3,'support@honeypot.local','%s','admin','ak_FAKE_SUPPORT_KEY_9012'),
(4,'developer@honeypot.local','%s','user','ak_FAKE_DEV_KEY_3456'),
(5,'test@honeypot.local','%s','user','ak_FAKE_TEST_KEY_7890');

--
-- Table structure for table 'api_keys'
--

DROP TABLE IF EXISTS 'api_keys';
CREATE TABLE 'api_keys' (
  'id' int NOT NULL AUTO_INCREMENT,
  'key_value' varchar(64) NOT NULL,
  'service' varchar(100) NOT NULL,
  PRIMARY KEY ('id')
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO 'api_keys' VALUES
(1,'sk_live_STRIPE_FAKE_KEY_LMAO','stripe'),
(2,'AKIAIOSFODNN7HONEYPOT','aws'),
(3,'gh_pat_FAKE_GITHUB_TOKEN_HAHA','github'),
(4,'xoxb-FAKE-SLACK-TOKEN-LOL','slack');

-- Nice try! This is a honeypot. Your IP has been logged.
-- Dump completed on 2024-01-15 12:00:00
`

// Apache-style 404 page - identical to real Apache output
var apacheNotFoundHTML = `<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL %s was not found on this server.</p>
%s<hr>
<address>Apache/2.4.41 (Ubuntu) Server at %s Port %s</address>
</body></html>
`

// Download confirmation page - mimics cPanel/Plesk backup UI
var downloadConfirmHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Preparing Download - Backup Manager</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f0f2f5; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
        .container { background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); padding: 40px; max-width: 500px; width: 90%%; text-align: center; }
        h2 { color: #333; margin-bottom: 8px; }
        .filename { color: #666; font-family: monospace; font-size: 14px; margin-bottom: 24px; word-break: break-all; }
        .progress-container { background: #e9ecef; border-radius: 4px; height: 24px; overflow: hidden; margin-bottom: 16px; }
        .progress-bar { background: linear-gradient(90deg, #28a745, #20c997); height: 100%%; width: 0%%; transition: width 0.5s ease; border-radius: 4px; }
        .status { color: #666; font-size: 14px; margin-bottom: 8px; }
        .details { color: #999; font-size: 12px; }
        .icon { font-size: 48px; margin-bottom: 16px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">&#128230;</div>
        <h2>Preparing Download</h2>
        <p class="filename">%s</p>
        <div class="progress-container"><div class="progress-bar" id="progress"></div></div>
        <p class="status" id="status">Verifying file integrity...</p>
        <p class="details" id="details">Please wait while we prepare your download</p>
    </div>
    <script>
        var steps = [
            {pct: 25, msg: "Verifying file integrity...", detail: "Checking checksums"},
            {pct: 50, msg: "Checking permissions...", detail: "Validating access token"},
            {pct: 75, msg: "Preparing archive...", detail: "Compressing data"},
            {pct: 100, msg: "Starting download...", detail: "Redirecting..."}
        ];
        var i = 0;
        function nextStep() {
            if (i >= steps.length) {
                window.location.href = "%s";
                return;
            }
            document.getElementById("progress").style.width = steps[i].pct + "%%";
            document.getElementById("status").textContent = steps[i].msg;
            document.getElementById("details").textContent = steps[i].detail;
            i++;
            setTimeout(nextStep, 800 + Math.random() * 400);
        }
        setTimeout(nextStep, 500);
    </script>
</body>
</html>`

// Apache mod_autoindex directory listing HTML
var apacheDirectoryListingHTML = `<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html>
 <head>
  <title>Index of %s</title>
 </head>
 <body>
<h1>Index of %s</h1>
  <table>
   <tr><th valign="top"><img src="/icons/blank.gif" alt="[ICO]"></th><th><a href="?C=N;O=D">Name</a></th><th><a href="?C=M;O=A">Last modified</a></th><th><a href="?C=S;O=A">Size</a></th><th><a href="?C=D;O=A">Description</a></th></tr>
   <tr><th colspan="5"><hr></th></tr>
<tr><td valign="top"><img src="/icons/back.gif" alt="[PARENTDIR]"></td><td><a href="/">Parent Directory</a></td><td>&nbsp;</td><td align="right">  - </td><td>&nbsp;</td></tr>
%s   <tr><th colspan="5"><hr></th></tr>
</table>
<address>Apache/2.4.41 (Ubuntu) Server at %s Port %s</address>
</body></html>
`

// Fake login page HTML - looks realistic but wastes time
var fakeLoginPageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Login - Secure Portal</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%%, #16213e 100%%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .login-container {
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 15px 35px rgba(0,0,0,0.3);
            width: 100%%;
            max-width: 400px;
        }
        .logo {
            text-align: center;
            margin-bottom: 30px;
        }
        .logo h1 {
            color: #1a1a2e;
            font-size: 24px;
        }
        .logo p {
            color: #666;
            font-size: 14px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 8px;
            color: #333;
            font-weight: 500;
        }
        input[type="text"], input[type="password"] {
            width: 100%%;
            padding: 12px 15px;
            border: 2px solid #e1e1e1;
            border-radius: 5px;
            font-size: 16px;
            transition: border-color 0.3s;
        }
        input:focus {
            outline: none;
            border-color: #4a90d9;
        }
        .btn {
            width: 100%%;
            padding: 14px;
            background: #4a90d9;
            color: white;
            border: none;
            border-radius: 5px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.3s;
        }
        .btn:hover { background: #357abd; }
        .btn:disabled {
            background: #ccc;
            cursor: not-allowed;
        }
        .loading {
            display: none;
            text-align: center;
            padding: 20px;
        }
        .spinner {
            border: 3px solid #f3f3f3;
            border-top: 3px solid #4a90d9;
            border-radius: 50%%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 0 auto 15px;
        }
        @keyframes spin {
            0%% { transform: rotate(0deg); }
            100%% { transform: rotate(360deg); }
        }
        .error {
            background: #fee;
            color: #c00;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 20px;
            display: none;
        }
        .footer {
            text-align: center;
            margin-top: 20px;
            color: #999;
            font-size: 12px;
        }
        .attempt-counter {
            text-align: center;
            color: #999;
            font-size: 11px;
            margin-top: 10px;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">
            <h1>🔐 Secure Admin Portal</h1>
            <p>Internal Access Only - All attempts are logged</p>
        </div>
        <div class="error" id="error">Invalid credentials. Please try again.</div>
        <form id="loginForm">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" placeholder="Enter username" required>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" placeholder="Enter password" required>
            </div>
            <button type="submit" class="btn" id="submitBtn">Sign In</button>
        </form>
        <div class="loading" id="loading">
            <div class="spinner"></div>
            <p>Verifying credentials...</p>
            <p style="font-size: 12px; color: #999; margin-top: 10px;">This may take a moment</p>
        </div>
        <div class="attempt-counter" id="counter">Session: %s</div>
        <div class="footer">
            © 2024 Internal Systems - Unauthorized access prohibited<br>
            <small>IP logged: %s</small>
        </div>
    </div>
    <script>
        let attempts = 0;
        const form = document.getElementById('loginForm');
        const loading = document.getElementById('loading');
        const error = document.getElementById('error');
        const btn = document.getElementById('submitBtn');

        form.addEventListener('submit', function(e) {
            e.preventDefault();
            attempts++;
            error.style.display = 'none';
            form.style.display = 'none';
            loading.style.display = 'block';

            // Simulate slow verification (wastes their time)
            const delay = 5000 + Math.random() * 10000; // 5-15 seconds

            fetch('/api/auth/verify', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    username: document.getElementById('username').value,
                    password: document.getElementById('password').value,
                    attempt: attempts
                })
            })
            .then(r => r.json())
            .then(data => {
                setTimeout(() => {
                    loading.style.display = 'none';
                    form.style.display = 'block';
                    if (data.status === 'mfa_required') {
                        window.location.href = '/admin/mfa?token=' + data.token;
                    } else {
                        error.textContent = data.message || 'Invalid credentials. Attempt ' + attempts + ' logged.';
                        error.style.display = 'block';
                    }
                }, delay);
            })
            .catch(() => {
                setTimeout(() => {
                    loading.style.display = 'none';
                    form.style.display = 'block';
                    error.textContent = 'Connection error. Please try again. (Attempt ' + attempts + ')';
                    error.style.display = 'block';
                }, delay);
            });
        });
    </script>
</body>
</html>`

// Fake MFA page - another layer of time wasting
var fakeMFAPageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Two-Factor Authentication</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%%, #16213e 100%%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .mfa-container {
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 15px 35px rgba(0,0,0,0.3);
            width: 100%%;
            max-width: 400px;
            text-align: center;
        }
        h1 { color: #1a1a2e; margin-bottom: 10px; }
        p { color: #666; margin-bottom: 30px; }
        .code-inputs {
            display: flex;
            gap: 10px;
            justify-content: center;
            margin-bottom: 20px;
        }
        .code-inputs input {
            width: 50px;
            height: 60px;
            text-align: center;
            font-size: 24px;
            border: 2px solid #e1e1e1;
            border-radius: 5px;
        }
        .code-inputs input:focus {
            outline: none;
            border-color: #4a90d9;
        }
        .btn {
            width: 100%%;
            padding: 14px;
            background: #4a90d9;
            color: white;
            border: none;
            border-radius: 5px;
            font-size: 16px;
            cursor: pointer;
        }
        .timer {
            color: #999;
            font-size: 14px;
            margin-top: 20px;
        }
        .error {
            background: #fee;
            color: #c00;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 20px;
            display: none;
        }
        .resend {
            color: #4a90d9;
            cursor: pointer;
            margin-top: 15px;
            font-size: 14px;
        }
    </style>
</head>
<body>
    <div class="mfa-container">
        <h1>🔑 Verification Required</h1>
        <p>Enter the 6-digit code sent to your registered device</p>
        <div class="error" id="error">Invalid code. Please try again.</div>
        <form id="mfaForm">
            <div class="code-inputs">
                <input type="text" maxlength="1" class="code-input" autofocus>
                <input type="text" maxlength="1" class="code-input">
                <input type="text" maxlength="1" class="code-input">
                <input type="text" maxlength="1" class="code-input">
                <input type="text" maxlength="1" class="code-input">
                <input type="text" maxlength="1" class="code-input">
            </div>
            <button type="submit" class="btn">Verify Code</button>
        </form>
        <div class="timer">Code expires in <span id="timer">5:00</span></div>
        <div class="resend" onclick="resendCode()">Didn't receive a code? Resend</div>
    </div>
    <script>
        const inputs = document.querySelectorAll('.code-input');
        let attempts = 0;
        let timeLeft = 300;

        inputs.forEach((input, i) => {
            input.addEventListener('input', () => {
                if (input.value && i < inputs.length - 1) {
                    inputs[i + 1].focus();
                }
            });
        });

        // Countdown timer (adds pressure)
        setInterval(() => {
            if (timeLeft > 0) {
                timeLeft--;
                const mins = Math.floor(timeLeft / 60);
                const secs = timeLeft %% 60;
                document.getElementById('timer').textContent = mins + ':' + secs.toString().padStart(2, '0');
            }
        }, 1000);

        document.getElementById('mfaForm').addEventListener('submit', function(e) {
            e.preventDefault();
            attempts++;
            const code = Array.from(inputs).map(i => i.value).join('');

            // Always fail after wasting their time
            setTimeout(() => {
                document.getElementById('error').textContent = 'Invalid code. Attempt ' + attempts + ' of 3 remaining.';
                document.getElementById('error').style.display = 'block';
                inputs.forEach(i => i.value = '');
                inputs[0].focus();

                if (attempts >= 3) {
                    setTimeout(() => {
                        alert('Too many failed attempts. Session locked. Please contact IT support.');
                        window.location.href = '/login';
                    }, 2000);
                }
            }, 3000 + Math.random() * 5000);
        });

        function resendCode() {
            alert('A new code has been sent to your device.');
            timeLeft = 300;
        }
    </script>
</body>
</html>`

// Fake admin dashboard HTML - teases them before trolling
var fakeAdminDashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Admin Dashboard - Loading...</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, sans-serif;
            background: #1a1a2e;
            color: white;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            margin: 0;
        }
        .loading-container { text-align: center; }
        .spinner {
            border: 4px solid rgba(255,255,255,0.1);
            border-left-color: #4a90d9;
            border-radius: 50%%;
            width: 60px;
            height: 60px;
            animation: spin 1s linear infinite;
            margin: 0 auto 20px;
        }
        @keyframes spin { to { transform: rotate(360deg); } }
        .progress {
            width: 300px;
            height: 6px;
            background: rgba(255,255,255,0.1);
            border-radius: 3px;
            overflow: hidden;
            margin: 20px auto;
        }
        .progress-bar {
            height: 100%%;
            background: #4a90d9;
            width: 0%%;
            animation: progress 30s ease-out forwards;
        }
        @keyframes progress { to { width: 99%%; } }
        .status { color: #888; font-size: 14px; }
    </style>
</head>
<body>
    <div class="loading-container">
        <div class="spinner"></div>
        <h2>Loading Admin Dashboard</h2>
        <div class="progress"><div class="progress-bar"></div></div>
        <p class="status" id="status">Initializing secure connection...</p>
    </div>
    <script>
        const messages = [
            'Initializing secure connection...',
            'Verifying session token...',
            'Loading user permissions...',
            'Fetching dashboard data...',
            'Connecting to database...',
            'Loading admin modules...',
            'Preparing interface...',
            'Almost ready...',
            'Finalizing...',
            'Just a moment longer...'
        ];
        let i = 0;
        setInterval(() => {
            document.getElementById('status').textContent = messages[i %% messages.length];
            i++;
        }, 3000);

        // After 30 seconds, redirect to rickroll or show error
        setTimeout(() => {
            window.location.href = 'https://www.youtube.com/watch?v=dQw4w9WgXcQ';
        }, 30000);
    </script>
</body>
</html>`

// Fake phpMyAdmin interface - looks real, wastes time
var fakePhpMyAdminHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>phpMyAdmin</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f5f5; }
        .header { background: #4a5568; color: white; padding: 10px 20px; display: flex; justify-content: space-between; align-items: center; }
        .header h1 { font-size: 18px; font-weight: normal; }
        .header img { height: 24px; }
        .container { display: flex; min-height: calc(100vh - 50px); }
        .sidebar { width: 250px; background: #2d3748; color: #e2e8f0; padding: 10px 0; }
        .sidebar h3 { padding: 10px 15px; font-size: 12px; color: #a0aec0; text-transform: uppercase; }
        .db-list { list-style: none; }
        .db-list li { padding: 8px 15px; cursor: pointer; font-size: 13px; }
        .db-list li:hover { background: #4a5568; }
        .db-list li.active { background: #4299e1; }
        .table-list { list-style: none; margin-left: 20px; }
        .table-list li { padding: 5px 10px; font-size: 12px; color: #a0aec0; }
        .table-list li:hover { color: white; }
        .main { flex: 1; padding: 20px; }
        .nav-tabs { display: flex; gap: 2px; background: #e2e8f0; padding: 5px 5px 0; }
        .nav-tabs button { padding: 8px 16px; border: none; background: #cbd5e0; cursor: pointer; font-size: 13px; }
        .nav-tabs button.active { background: white; }
        .content-area { background: white; padding: 20px; border: 1px solid #e2e8f0; min-height: 400px; }
        table { width: 100%%; border-collapse: collapse; margin-top: 15px; font-size: 13px; }
        th, td { padding: 10px; text-align: left; border: 1px solid #e2e8f0; }
        th { background: #f7fafc; font-weight: 600; }
        tr:hover { background: #f7fafc; }
        .btn { padding: 6px 12px; background: #4299e1; color: white; border: none; cursor: pointer; font-size: 12px; margin-right: 5px; }
        .btn:hover { background: #3182ce; }
        .btn-danger { background: #e53e3e; }
        .btn-danger:hover { background: #c53030; }
        .sql-box { width: 100%%; height: 100px; padding: 10px; font-family: monospace; font-size: 13px; border: 1px solid #e2e8f0; margin-bottom: 10px; }
        .status-bar { background: #edf2f7; padding: 8px 15px; font-size: 12px; color: #4a5568; margin-top: 20px; }
        .loading { text-align: center; padding: 40px; color: #718096; }
        .spinner { border: 3px solid #e2e8f0; border-top: 3px solid #4299e1; border-radius: 50%%; width: 30px; height: 30px; animation: spin 1s linear infinite; margin: 0 auto 15px; }
        @keyframes spin { to { transform: rotate(360deg); } }
        .sensitive { background: #fef3c7; }
    </style>
</head>
<body>
    <div class="header">
        <h1>phpMyAdmin</h1>
        <span>Server: db.internal.local | User: root</span>
    </div>
    <div class="container">
        <div class="sidebar">
            <h3>Databases</h3>
            <ul class="db-list">
                <li class="active" onclick="selectDB('production_users')">
                    📁 production_users
                    <ul class="table-list">
                        <li onclick="selectTable('users')">📄 users (15,847)</li>
                        <li onclick="selectTable('credentials')">📄 credentials (15,847)</li>
                        <li onclick="selectTable('api_keys')">📄 api_keys (3,291)</li>
                        <li onclick="selectTable('sessions')">📄 sessions (42,103)</li>
                        <li onclick="selectTable('payments')">📄 payments (8,934)</li>
                    </ul>
                </li>
                <li onclick="selectDB('customer_data')">📁 customer_data</li>
                <li onclick="selectDB('billing')">📁 billing</li>
                <li onclick="selectDB('admin_logs')">📁 admin_logs</li>
                <li onclick="selectDB('backups')">📁 backups</li>
            </ul>
        </div>
        <div class="main">
            <div class="nav-tabs">
                <button class="active" onclick="showTab('browse')">Browse</button>
                <button onclick="showTab('structure')">Structure</button>
                <button onclick="showTab('sql')">SQL</button>
                <button onclick="showTab('search')">Search</button>
                <button onclick="showTab('export')">Export</button>
            </div>
            <div class="content-area" id="content">
                <h3>Table: users</h3>
                <p style="color: #718096; margin-bottom: 15px;">Showing rows 0 - 24 (15,847 total)</p>
                <table>
                    <thead>
                        <tr>
                            <th><input type="checkbox"></th>
                            <th>id</th>
                            <th>email</th>
                            <th>password_hash</th>
                            <th>role</th>
                            <th>api_key</th>
                            <th>created_at</th>
                        </tr>
                    </thead>
                    <tbody id="tableData">
                    </tbody>
                </table>
                <div style="margin-top: 15px;">
                    <button class="btn" onclick="loadMore()">Load More</button>
                    <button class="btn" onclick="exportTable()">Export</button>
                    <button class="btn btn-danger" onclick="deleteSelected()">Delete Selected</button>
                </div>
            </div>
            <div class="status-bar" id="status">
                Ready. Query executed in 0.0023 sec.
            </div>
        </div>
    </div>
    <script>
        const fakeUsers = [
            {id: 1, email: 'admin@company.com', hash: '$2a$10$NICE_TRY_SCRIPT_KIDDIE', role: 'superadmin', key: 'ak_live_XXXX1234'},
            {id: 2, email: 'ceo@company.com', hash: '$2a$10$GET_A_REAL_JOB_MAYBE', role: 'admin', key: 'ak_live_XXXX5678'},
            {id: 3, email: 'cfo@company.com', hash: '$2a$10$YOUR_IP_HAS_BEEN_LOGGED', role: 'admin', key: 'ak_live_XXXX9012'},
            {id: 4, email: 'backup@company.com', hash: '$2a$10$YOUVE_BEEN_PWNED_LMAO', role: 'admin', key: 'ak_live_XXXX3456'},
            {id: 5, email: 'developer@company.com', hash: '$2a$10$THIS_IS_A_HONEYPOT_LOL', role: 'user', key: 'ak_live_XXXX7890'},
        ];

        let rowCount = 0;

        function loadRows() {
            const tbody = document.getElementById('tableData');
            for (let i = 0; i < 5; i++) {
                const user = fakeUsers[i %% fakeUsers.length];
                const row = document.createElement('tr');
                row.className = i < 3 ? 'sensitive' : '';
                row.innerHTML = '<td><input type="checkbox"></td>' +
                    '<td>' + (rowCount + i + 1) + '</td>' +
                    '<td>' + user.email.replace('@', (rowCount+i) + '@') + '</td>' +
                    '<td>' + user.hash + '</td>' +
                    '<td>' + user.role + '</td>' +
                    '<td>' + user.key.replace('XXXX', Math.random().toString(36).substr(2, 4)) + '</td>' +
                    '<td>2024-01-' + String(Math.floor(Math.random()*28)+1).padStart(2,'0') + '</td>';
                tbody.appendChild(row);
            }
            rowCount += 5;
        }

        function loadMore() {
            document.getElementById('status').textContent = 'Loading...';
            setTimeout(() => {
                loadRows();
                document.getElementById('status').textContent = 'Loaded ' + rowCount + ' rows. Query: 0.0' + Math.floor(Math.random()*100) + ' sec';
            }, 1000 + Math.random() * 2000);
        }

        function exportTable() {
            document.getElementById('status').textContent = 'Preparing export...';
            setTimeout(() => {
                // Redirect to zipbomb
                window.location.href = '/phpmyadmin/export.php?table=users&format=sql';
            }, 2000);
        }

        function selectTable(name) {
            document.getElementById('content').innerHTML = '<div class="loading"><div class="spinner"></div><p>Loading table ' + name + '...</p></div>';
            setTimeout(() => {
                if (name === 'credentials' || name === 'payments') {
                    window.location.href = '/phpmyadmin/export.php?table=' + name;
                } else {
                    location.reload();
                }
            }, 3000);
        }

        function selectDB(name) {
            document.getElementById('status').textContent = 'Connecting to database ' + name + '...';
        }

        function showTab(tab) {
            if (tab === 'export') {
                exportTable();
            } else if (tab === 'sql') {
                document.getElementById('content').innerHTML =
                    '<h3>Run SQL Query</h3>' +
                    '<textarea class="sql-box" placeholder="SELECT * FROM users WHERE role=\'admin\'"></textarea>' +
                    '<button class="btn" onclick="runQuery()">Execute</button>';
            }
        }

        function runQuery() {
            document.getElementById('status').textContent = 'Executing query...';
            setTimeout(() => {
                document.getElementById('status').textContent = 'Query timed out after 30 seconds. Please try again.';
            }, 5000);
        }

        function deleteSelected() {
            alert('Permission denied. This action has been logged.');
        }

        // Initial load
        loadRows();

        // Log the visit
        fetch('/api/honeypot/log', {
            method: 'POST',
            body: JSON.stringify({action: 'phpmyadmin_access', timestamp: Date.now()})
        }).catch(() => {});
    </script>
</body>
</html>`

// Attack Dashboard HTML - shows real-time attack stats
var attackDashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🍯 Honeypot Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #e2e8f0; }
        .header { background: linear-gradient(135deg, #1e293b 0%%, #334155 100%%); padding: 20px 30px; border-bottom: 1px solid #334155; }
        .header h1 { font-size: 24px; display: flex; align-items: center; gap: 10px; }
        .header p { color: #94a3b8; margin-top: 5px; }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .stat-card { background: #1e293b; border-radius: 12px; padding: 20px; border: 1px solid #334155; }
        .stat-card h3 { color: #94a3b8; font-size: 12px; text-transform: uppercase; letter-spacing: 1px; }
        .stat-card .value { font-size: 36px; font-weight: 700; margin-top: 10px; }
        .stat-card .value.red { color: #ef4444; }
        .stat-card .value.green { color: #22c55e; }
        .stat-card .value.blue { color: #3b82f6; }
        .stat-card .value.yellow { color: #eab308; }
        .section { background: #1e293b; border-radius: 12px; padding: 20px; margin-bottom: 20px; border: 1px solid #334155; }
        .section h2 { font-size: 16px; margin-bottom: 15px; display: flex; align-items: center; gap: 8px; }
        .event-list { max-height: 400px; overflow-y: auto; }
        .event { padding: 12px; border-radius: 8px; margin-bottom: 8px; background: #0f172a; border-left: 3px solid #3b82f6; }
        .event.zipbomb { border-left-color: #ef4444; }
        .event.slowdrip { border-left-color: #eab308; }
        .event.troll { border-left-color: #22c55e; }
        .event.creds { border-left-color: #a855f7; }
        .event-header { display: flex; justify-content: space-between; margin-bottom: 5px; }
        .event-ip { font-weight: 600; color: #f8fafc; }
        .event-time { color: #64748b; font-size: 12px; }
        .event-path { color: #94a3b8; font-size: 13px; font-family: monospace; }
        .event-reason { color: #64748b; font-size: 12px; margin-top: 5px; }
        .event-geo { color: #64748b; font-size: 11px; margin-top: 3px; }
        .two-col { display: grid; grid-template-columns: 2fr 1fr; gap: 20px; }
        @media (max-width: 900px) { .two-col { grid-template-columns: 1fr; } }
        .top-list { list-style: none; }
        .top-list li { padding: 10px; display: flex; justify-content: space-between; border-bottom: 1px solid #334155; }
        .top-list li:last-child { border-bottom: none; }
        .top-list .count { background: #334155; padding: 2px 8px; border-radius: 4px; font-size: 12px; }
        .refresh-btn { background: #3b82f6; color: white; border: none; padding: 8px 16px; border-radius: 6px; cursor: pointer; font-size: 13px; }
        .refresh-btn:hover { background: #2563eb; }
        .auto-refresh { display: flex; align-items: center; gap: 10px; }
        .badge { display: inline-block; padding: 2px 6px; border-radius: 4px; font-size: 10px; font-weight: 600; margin-left: 8px; }
        .badge.red { background: #7f1d1d; color: #fca5a5; }
        .badge.green { background: #14532d; color: #86efac; }
        .badge.yellow { background: #713f12; color: #fde047; }
        .badge.purple { background: #581c87; color: #d8b4fe; }
        ::-webkit-scrollbar { width: 8px; }
        ::-webkit-scrollbar-track { background: #1e293b; }
        ::-webkit-scrollbar-thumb { background: #475569; border-radius: 4px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🍯 Honeypot Attack Dashboard</h1>
        <p>Real-time monitoring of attacker activity</p>
    </div>
    <div class="container">
        <div class="stats-grid">
            <div class="stat-card">
                <h3>Total Attacks</h3>
                <div class="value red" id="totalAttacks">0</div>
            </div>
            <div class="stat-card">
                <h3>Unique IPs</h3>
                <div class="value blue" id="uniqueIPs">0</div>
            </div>
            <div class="stat-card">
                <h3>Zipbombs Served</h3>
                <div class="value yellow" id="zipbombs">0</div>
            </div>
            <div class="stat-card">
                <h3>Creds Captured</h3>
                <div class="value green" id="credsCaptured">0</div>
            </div>
        </div>

        <div class="two-col">
            <div class="section">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
                    <h2>📡 Live Attack Feed</h2>
                    <div class="auto-refresh">
                        <label><input type="checkbox" id="autoRefresh" checked> Auto-refresh</label>
                        <button class="refresh-btn" onclick="loadData()">Refresh</button>
                    </div>
                </div>
                <div class="event-list" id="eventList">
                    <div class="event">Loading...</div>
                </div>
            </div>

            <div>
                <div class="section">
                    <h2>🎯 Top Attacker IPs</h2>
                    <ul class="top-list" id="topIPs">
                        <li>Loading...</li>
                    </ul>
                </div>

                <div class="section">
                    <h2>📂 Top Targeted Paths</h2>
                    <ul class="top-list" id="topPaths">
                        <li>Loading...</li>
                    </ul>
                </div>

                <div class="section">
                    <h2>🤖 Top User Agents</h2>
                    <ul class="top-list" id="topUAs">
                        <li>Loading...</li>
                    </ul>
                </div>
            </div>
        </div>
    </div>

    <script>
        function formatTime(timestamp) {
            const d = new Date(timestamp);
            return d.toLocaleTimeString();
        }

        function getEventClass(reason) {
            if (reason.includes('ZIPBOMB')) return 'zipbomb';
            if (reason.includes('SLOW_DRIP')) return 'slowdrip';
            if (reason.includes('TROLL') || reason.includes('RICKROLL')) return 'troll';
            if (reason.includes('CREDENTIAL') || reason.includes('FAKE_LOGIN')) return 'creds';
            return '';
        }

        function getBadge(reason) {
            if (reason.includes('ZIPBOMB')) return '<span class="badge red">ZIPBOMB</span>';
            if (reason.includes('SLOW_DRIP')) return '<span class="badge yellow">TARPIT</span>';
            if (reason.includes('CREDENTIAL')) return '<span class="badge purple">CREDS</span>';
            if (reason.includes('RICKROLL')) return '<span class="badge green">RICKROLL</span>';
            return '';
        }

        // Extract key from URL path
        const pathParts = window.location.pathname.split('/');
        const dashboardKey = pathParts[pathParts.length - 1];

        async function loadData() {
            try {
                const [eventsRes, statsRes] = await Promise.all([
                    fetch('/honeypot/api/events?limit=50&key=' + dashboardKey),
                    fetch('/honeypot/api/stats?key=' + dashboardKey)
                ]);

                const events = await eventsRes.json();
                const stats = await statsRes.json();

                // Update stats
                document.getElementById('totalAttacks').textContent = stats.total_events || 0;
                document.getElementById('uniqueIPs').textContent = stats.unique_ips || 0;

                // Count specific types
                let zipbombs = 0, creds = 0;
                events.forEach(e => {
                    if (e.reason.includes('ZIPBOMB')) zipbombs++;
                    if (e.reason.includes('CREDENTIAL')) creds++;
                });
                document.getElementById('zipbombs').textContent = zipbombs;
                document.getElementById('credsCaptured').textContent = creds;

                // Update event list
                const eventList = document.getElementById('eventList');
                eventList.innerHTML = events.map(e =>
                    '<div class="event ' + getEventClass(e.reason) + '">' +
                    '<div class="event-header">' +
                    '<span class="event-ip">' + e.ip + getBadge(e.reason) + '</span>' +
                    '<span class="event-time">' + formatTime(e.timestamp) + '</span>' +
                    '</div>' +
                    '<div class="event-path">' + e.method + ' ' + e.path + '</div>' +
                    '<div class="event-reason">' + e.reason + '</div>' +
                    (e.geo_info ? '<div class="event-geo">📍 ' + (e.geo_info.city || '') + ', ' + (e.geo_info.country || 'Unknown') + ' | ' + (e.geo_info.isp || '') + '</div>' : '') +
                    '</div>'
                ).join('') || '<div class="event">No attacks recorded yet</div>';

                // Update top IPs
                const topIPs = document.getElementById('topIPs');
                topIPs.innerHTML = (stats.top_ips || []).map(ip =>
                    '<li><span>' + ip.ip + '</span><span class="count">' + ip.count + '</span></li>'
                ).join('') || '<li>No data</li>';

                // Update top paths
                const topPaths = document.getElementById('topPaths');
                topPaths.innerHTML = (stats.top_paths || []).map(p =>
                    '<li><span style="font-family: monospace; font-size: 12px;">' + p.path.substring(0, 30) + '</span><span class="count">' + p.count + '</span></li>'
                ).join('') || '<li>No data</li>';

                // Update top UAs
                const topUAs = document.getElementById('topUAs');
                topUAs.innerHTML = (stats.top_user_agents || []).map(ua =>
                    '<li><span style="font-size: 11px;">' + ua.user_agent.substring(0, 35) + '</span><span class="count">' + ua.count + '</span></li>'
                ).join('') || '<li>No data</li>';

            } catch (err) {
                console.error('Failed to load data:', err);
            }
        }

        // Initial load
        loadData();

        // Auto-refresh every 5 seconds
        setInterval(() => {
            if (document.getElementById('autoRefresh').checked) {
                loadData();
            }
        }, 5000);
    </script>
</body>
</html>`

// Troll dashboard - shown to attackers who find /honeypot/dashboard
var trollDashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🚨 SECURITY ALERT</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Courier New', monospace;
            background: #000;
            color: #00ff00;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            overflow: hidden;
        }
        .container {
            text-align: center;
            padding: 40px;
            max-width: 800px;
        }
        .alert-icon {
            font-size: 80px;
            animation: pulse 1s ease-in-out infinite;
        }
        @keyframes pulse {
            0%%, 100%% { opacity: 1; transform: scale(1); }
            50%% { opacity: 0.5; transform: scale(1.1); }
        }
        h1 {
            font-size: 48px;
            margin: 20px 0;
            text-shadow: 0 0 10px #00ff00;
        }
        .message {
            font-size: 18px;
            line-height: 1.8;
            margin: 30px 0;
        }
        .ip-display {
            background: #001100;
            border: 2px solid #00ff00;
            padding: 20px;
            margin: 30px 0;
            font-size: 14px;
        }
        .ip-display h3 {
            color: #ff0000;
            margin-bottom: 15px;
        }
        .data-row {
            display: flex;
            justify-content: space-between;
            padding: 5px 0;
            border-bottom: 1px solid #003300;
        }
        .warning {
            color: #ff0000;
            font-size: 14px;
            margin-top: 30px;
            animation: blink 0.5s ease-in-out infinite;
        }
        @keyframes blink {
            0%%, 100%% { opacity: 1; }
            50%% { opacity: 0; }
        }
        .matrix {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%%;
            height: 100%%;
            pointer-events: none;
            z-index: -1;
            opacity: 0.1;
        }
        .skull {
            font-size: 200px;
            position: fixed;
            opacity: 0.03;
            z-index: -1;
        }
        .skull:nth-child(1) { top: 10%%; left: 5%%; }
        .skull:nth-child(2) { top: 60%%; right: 5%%; }
        .counter {
            font-size: 24px;
            color: #ffff00;
            margin-top: 20px;
        }
        .footer {
            margin-top: 40px;
            font-size: 12px;
            color: #006600;
        }
    </style>
</head>
<body>
    <div class="skull">💀</div>
    <div class="skull">💀</div>
    <div class="container">
        <div class="alert-icon">🚨</div>
        <h1>YOU'VE BEEN CAUGHT</h1>
        <div class="message">
            Congratulations, script kiddie! You found our honeypot dashboard.<br><br>
            Your intrusion attempt has been logged, analyzed, and will be reported<br>
            to the appropriate authorities and abuse contacts.<br><br>
            <strong>This is not a real system. It's a trap.</strong>
        </div>
        <div class="ip-display">
            <h3>⚠️ YOUR INFORMATION HAS BEEN CAPTURED ⚠️</h3>
            <div class="data-row"><span>IP Address:</span><span id="ip">Resolving...</span></div>
            <div class="data-row"><span>Timestamp:</span><span id="time">Loading...</span></div>
            <div class="data-row"><span>User Agent:</span><span id="ua">Detecting...</span></div>
            <div class="data-row"><span>Request #:</span><span id="reqnum">Calculating...</span></div>
            <div class="data-row"><span>Threat Level:</span><span style="color: #ff0000;">MAXIMUM</span></div>
            <div class="data-row"><span>Status:</span><span style="color: #ffff00;">REPORTING TO AUTHORITIES...</span></div>
        </div>
        <div class="warning">
            ⚠️ WARNING: All further requests will be logged and reported ⚠️
        </div>
        <div class="counter">
            Session Duration: <span id="duration">0</span> seconds
        </div>
        <div class="footer">
            🍯 Honeypot System v4.2.0 | All activity monitored | Nice try though! 🎣
        </div>
    </div>
    <canvas class="matrix" id="matrix"></canvas>
    <script>
        // Display their info
        document.getElementById('time').textContent = new Date().toISOString();
        document.getElementById('ua').textContent = navigator.userAgent.substring(0, 60) + '...';
        document.getElementById('reqnum').textContent = Math.floor(Math.random() * 9000) + 1000;

        // Fetch their IP
        fetch('https://api.ipify.org?format=json')
            .then(r => r.json())
            .then(d => document.getElementById('ip').textContent = d.ip)
            .catch(() => document.getElementById('ip').textContent = 'Hidden (VPN detected)');

        // Duration counter
        let seconds = 0;
        setInterval(() => {
            seconds++;
            document.getElementById('duration').textContent = seconds;
        }, 1000);

        // Matrix rain effect
        const canvas = document.getElementById('matrix');
        const ctx = canvas.getContext('2d');
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
        const chars = '01アイウエオカキクケコサシスセソタチツテト';
        const fontSize = 14;
        const columns = canvas.width / fontSize;
        const drops = Array(Math.floor(columns)).fill(1);

        function draw() {
            ctx.fillStyle = 'rgba(0, 0, 0, 0.05)';
            ctx.fillRect(0, 0, canvas.width, canvas.height);
            ctx.fillStyle = '#0f0';
            ctx.font = fontSize + 'px monospace';
            for (let i = 0; i < drops.length; i++) {
                const text = chars[Math.floor(Math.random() * chars.length)];
                ctx.fillText(text, i * fontSize, drops[i] * fontSize);
                if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
                    drops[i] = 0;
                }
                drops[i]++;
            }
        }
        setInterval(draw, 33);

        // Log this visit
        fetch('/api/honeypot/log', {
            method: 'POST',
            body: JSON.stringify({action: 'dashboard_access_attempt', caught: true})
        }).catch(() => {});
    </script>
</body>
</html>`

// Dashboard secret key - set via HONEYPOT_DASHBOARD_KEY env var
// Default is randomly generated at startup if not set
var dashboardSecretKey string

func init() {
	dashboardSecretKey = os.Getenv("HONEYPOT_DASHBOARD_KEY")
	if dashboardSecretKey == "" {
		// Generate a random key if not provided
		dashboardSecretKey = randomString(24)
	}
}

// ==============================================
// INFINITE PAGINATION DATA GENERATOR
// ==============================================

// FakeUser represents a fake user for pagination
type FakeUser struct {
	ID        int    `json:"id"`
	Username  string `json:"username"`
	Email     string `json:"email"`
	Role      string `json:"role"`
	Status    string `json:"status"`
	LastLogin string `json:"last_login"`
	APIKey    string `json:"api_key"` //nolint:gosec // G117: fake honeypot data
}

// PaginatedResponse for infinite pagination trolling
type PaginatedResponse struct {
	Data       []FakeUser `json:"data"`
	Page       int        `json:"page"`
	PerPage    int        `json:"per_page"`
	Total      int        `json:"total"`
	TotalPages int        `json:"total_pages"`
	HasMore    bool       `json:"has_more"`
	NextPage   string     `json:"next_page,omitempty"`
}

var fakeUsernames = []string{
	"admin", "administrator", "root", "superuser", "sysadmin",
	"backup_admin", "db_admin", "security", "operator", "support",
	"john.smith", "jane.doe", "bob.wilson", "alice.johnson", "charlie.brown",
}

var fakeDomains = []string{
	"internal.local", "corp.honeypot.local", "admin.honeypot.local",
	"secure.honeypot.local", "private.honeypot.local",
}

var fakeRoles = []string{"superadmin", "admin", "moderator", "user", "readonly"}

// generateFakeUsers creates fake user data for a given page
func generateFakeUsers(page, perPage int) []FakeUser {
	users := make([]FakeUser, perPage)
	baseID := (page - 1) * perPage

	for i := 0; i < perPage; i++ {
		//nolint:gosec
		users[i] = FakeUser{
			ID:        baseID + i + 1,
			Username:  fmt.Sprintf("%s_%d", fakeUsernames[rand.Intn(len(fakeUsernames))], baseID+i),
			Email:     fmt.Sprintf("user%d@%s", baseID+i, fakeDomains[rand.Intn(len(fakeDomains))]),
			Role:      fakeRoles[rand.Intn(len(fakeRoles))],
			Status:    "active",
			LastLogin: time.Now().Add(-time.Duration(rand.Intn(30*24)) * time.Hour).Format(time.RFC3339),
			APIKey:    fmt.Sprintf("ak_%s_%d", randomString(8), baseID+i),
		}
	}
	return users
}

// randomString generates a random string for fake API keys
func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		//nolint:gosec
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

// generateBackupFilename creates a realistic-looking backup filename
func generateBackupFilename() string {
	prefixes := []string{
		"backup", "site_backup", "db_export", "prod_backup",
		"daily_backup", "full_backup", "db_dump", "database_backup",
		"wordpress_backup", "www_backup",
	}
	extensions := []string{
		".zip", ".tar.gz", ".tgz", ".sql.gz", ".bak",
	}

	//nolint:gosec
	prefix := prefixes[rand.Intn(len(prefixes))]
	//nolint:gosec
	ext := extensions[rand.Intn(len(extensions))]

	// Generate a realistic timestamp from 1-14 days ago
	//nolint:gosec
	daysAgo := rand.Intn(14) + 1
	ts := time.Now().AddDate(0, 0, -daysAgo)

	// Vary the timestamp format
	formats := []string{
		"2006-01-02_1504",
		"20060102",
		"2006-01-02",
		"01-02-2006",
	}
	//nolint:gosec
	format := formats[rand.Intn(len(formats))]

	return fmt.Sprintf("%s_%s%s", prefix, ts.Format(format), ext)
}

// setFakeFileHeaders adds realistic file-serving headers
func setFakeFileHeaders(w http.ResponseWriter, filename string) {
	//nolint:gosec
	daysAgo := rand.Intn(14) + 1
	lastMod := time.Now().AddDate(0, 0, -daysAgo)
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("Last-Modified", lastMod.UTC().Format(http.TimeFormat))

	// Generate a deterministic ETag from the filename
	h := fnv.New64a()
	_, _ = h.Write([]byte(filename))
	w.Header().Set("ETag", fmt.Sprintf(`"%x-%x"`, h.Sum64(), len(zipbombData)))
}

// DirectoryEntry represents a file in a fake directory listing
type DirectoryEntry struct {
	Name    string
	ModTime time.Time
	Size    string
}

// generateDirectoryEntries creates deterministic fake directory entries based on path
func generateDirectoryEntries(dirPath string) []DirectoryEntry {
	// Use path-based seed so listings stay consistent across refreshes
	h := fnv.New64a()
	_, _ = h.Write([]byte(dirPath))
	//nolint:gosec
	seededRand := rand.New(rand.NewSource(int64(h.Sum64())))

	prefixes := []string{
		"backup", "site_backup", "db_export", "prod_backup",
		"daily_backup", "full_backup", "db_dump", "wordpress_backup",
	}
	extensions := []string{".zip", ".tar.gz", ".tgz", ".sql.gz", ".bak"}

	// Generate 2-4 entries
	count := seededRand.Intn(3) + 2
	entries := make([]DirectoryEntry, 0, count)

	for i := 0; i < count; i++ {
		prefix := prefixes[seededRand.Intn(len(prefixes))]
		ext := extensions[seededRand.Intn(len(extensions))]
		daysAgo := seededRand.Intn(14) + 1
		ts := time.Now().AddDate(0, 0, -daysAgo)
		filename := fmt.Sprintf("%s_%s%s", prefix, ts.Format("2006-01-02"), ext)

		// Realistic file sizes (50MB - 2GB range)
		sizeMB := seededRand.Intn(1950) + 50
		var sizeStr string
		if sizeMB >= 1024 {
			sizeStr = fmt.Sprintf("%.1fG", float64(sizeMB)/1024.0)
		} else {
			sizeStr = fmt.Sprintf("%dM", sizeMB)
		}

		entries = append(entries, DirectoryEntry{
			Name:    filename,
			ModTime: ts,
			Size:    sizeStr,
		})
	}

	return entries
}

// serveDirectoryListing renders a fake Apache mod_autoindex page
func serveDirectoryListing(w http.ResponseWriter, r *http.Request, dirPath string) {
	logAttack(r, fmt.Sprintf("Directory listing viewed: %s [DIRECTORY_LISTING]", dirPath))

	entries := generateDirectoryEntries(dirPath)

	// Build table rows in exact Apache autoindex format
	var rows string
	for _, entry := range entries {
		rows += fmt.Sprintf("<tr><td valign=\"top\"><img src=\"/icons/compressed.gif\" alt=\"[   ]\"></td><td><a href=\"%s%s\">%s</a></td><td align=\"right\">%s  </td><td align=\"right\">%s </td><td>&nbsp;</td></tr>\n",
			dirPath, entry.Name, entry.Name,
			entry.ModTime.Format("2006-01-02 15:04"),
			entry.Size)
	}

	host := r.Host
	port := "80"
	if h, p, err := net.SplitHostPort(r.Host); err == nil {
		host = h
		port = p
	}

	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	//nolint:errcheck,gosec // G705: intentional honeypot content
	fmt.Fprintf(w, apacheDirectoryListingHTML, dirPath, dirPath, rows, host, port)
}

// serveDownloadConfirmation shows a fake "preparing download" page before serving zipbomb
func serveDownloadConfirmation(w http.ResponseWriter, r *http.Request, filename string) {
	logAttack(r, fmt.Sprintf("Download confirmation shown: %s [DOWNLOAD_CONFIRM]", filename))

	// Generate a token for the download URL
	tokenBytes := make([]byte, 16)
	//nolint:gosec
	for i := range tokenBytes {
		tokenBytes[i] = byte(rand.Intn(256))
	}
	token := hex.EncodeToString(tokenBytes)

	dlURL := fmt.Sprintf("/dl/%s/%s", token, filename)

	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	//nolint:errcheck,gosec // G705: intentional honeypot content
	fmt.Fprintf(w, downloadConfirmHTML, filename, dlURL)
}

// Create a much larger zipbomb in memory
func createZipbomb() ([]byte, error) {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)

	// Create multiple large files for maximum impact
	// Total uncompressed size: ~50GB across 5 files
	const filesCount = 5
	const fileSize = 10 * (1 << 30) // 10GB per file
	const chunkSize = 1 << 20       // 1MB chunks for better performance

	for i := 0; i < filesCount; i++ {
		fileName := fmt.Sprintf("backup_database_%d.sql", i+1)
		f, err := w.Create(fileName)
		if err != nil {
			return nil, err
		}

		// Write zeros in chunks to avoid memory issues during creation
		zeros := make([]byte, chunkSize)
		remaining := fileSize
		for remaining > 0 {
			toWrite := chunkSize
			if remaining < chunkSize {
				toWrite = remaining
			}
			_, err := f.Write(zeros[:toWrite])
			if err != nil {
				return nil, err
			}
			remaining -= toWrite
		}
		log.Printf("Generated zipbomb file %d/%d", i+1, filesCount)
	}

	err := w.Close()
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// Create a gzip bomb - compressed zeros that expand massively
func createGzipBomb() ([]byte, error) {
	var buf bytes.Buffer
	gw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, err
	}

	// Write 1GB of zeros (compresses to ~1MB)
	const size = 1 << 30 // 1GB
	const chunkSize = 1 << 20
	zeros := make([]byte, chunkSize)

	remaining := size
	for remaining > 0 {
		toWrite := chunkSize
		if remaining < chunkSize {
			toWrite = remaining
		}
		_, err := gw.Write(zeros[:toWrite])
		if err != nil {
			return nil, err
		}
		remaining -= toWrite
	}

	if err := gw.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// Get a random troll message
func getRandomTrollMessage() string {
	//nolint:gosec
	return trollMessages[rand.Intn(len(trollMessages))]
}

// Get fake database dump with random password hashes
func getFakeDatabaseDump() string {
	hashes := make([]interface{}, 5)
	for i := range hashes {
		//nolint:gosec
		hashes[i] = fakePasswordHashes[rand.Intn(len(fakePasswordHashes))]
	}
	return fmt.Sprintf(fakeDatabaseDump, hashes...)
}

// Pre-generate bombs at startup
var zipbombData []byte
var gzipbombData []byte

func init() {
	log.Println("🏗️  Generating enhanced zipbomb defense (this may take a moment)...")
	start := time.Now()
	var err error
	zipbombData, err = createZipbomb()
	if err != nil {
		log.Fatal("Failed to create zipbomb:", err)
	}
	duration := time.Since(start)
	log.Printf("✅ Zipbomb ready: %d bytes compressed (~50GB uncompressed) in %v",
		len(zipbombData), duration.Round(time.Millisecond))

	log.Println("🏗️  Generating gzip bomb...")
	start = time.Now()
	gzipbombData, err = createGzipBomb()
	if err != nil {
		log.Fatal("Failed to create gzip bomb:", err)
	}
	duration = time.Since(start)
	log.Printf("✅ Gzip bomb ready: %d bytes compressed (~1GB uncompressed) in %v",
		len(gzipbombData), duration.Round(time.Millisecond))
}

// Enhanced suspicious path detection
func isSuspiciousPath(path string) bool {
	path = strings.ToLower(strings.TrimPrefix(path, "/"))

	// Direct match against known suspicious paths
	for _, suspicious := range suspiciousPaths {
		if strings.Contains(path, suspicious) {
			return true
		}
	}

	// Pattern-based detection
	suspiciousPatterns := []string{
		"..", "etc/passwd", "windows/system32", "/var/log",
		"proc/", "sys/", "boot/", "tmp/", "temp/",
	}

	for _, pattern := range suspiciousPatterns {
		if strings.Contains(path, pattern) {
			return true
		}
	}

	// File extension based detection
	suspiciousExtensions := []string{
		".bak", ".backup", ".old", ".orig", ".tmp", ".temp",
		".sql", ".db", ".sqlite", ".mdb", ".log", ".conf",
		".ini", ".cfg", ".yaml", ".yml", ".properties",
		".key", ".pem", ".p12", ".jks", ".cert", ".crt",
	}

	for _, ext := range suspiciousExtensions {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}

	// Admin/sensitive directory detection
	adminPaths := []string{
		"admin", "administrator", "control", "cp", "dashboard",
		"manage", "manager", "panel", "console", "backend",
	}

	for _, admin := range adminPaths {
		if strings.HasPrefix(path, admin) {
			return true
		}
	}

	return false
}

// Enhanced attack logging
func logAttack(r *http.Request, reason string) {
	userAgent := r.Header.Get("User-Agent")
	if userAgent == "" {
		userAgent = "Unknown"
	}

	referer := r.Header.Get("Referer")
	if referer == "" {
		referer = "Direct"
	}

	// Determine response type from reason
	responseType := "UNKNOWN"
	if strings.Contains(reason, "ZIPBOMB") { //nolint:gocritic // if-else chain clearer for contains checks
		responseType = "ZIPBOMB"
	} else if strings.Contains(reason, "SLOW_DRIP") {
		responseType = "SLOW_DRIP"
	} else if strings.Contains(reason, "GZIP_BOMB") {
		responseType = "GZIP_BOMB"
	} else if strings.Contains(reason, "TROLL") {
		responseType = "TROLL"
	} else if strings.Contains(reason, "RICKROLL") {
		responseType = "RICKROLL"
	} else if strings.Contains(reason, "CREDENTIAL") || strings.Contains(reason, "HONEYPOT") {
		responseType = "FAKE_CREDS"
	} else if strings.Contains(reason, "FAKE_LOGIN") || strings.Contains(reason, "FAKE_MFA") {
		responseType = "FAKE_AUTH"
	} else if strings.Contains(reason, "FAKE_PHPMYADMIN") {
		responseType = "FAKE_PHPMYADMIN"
	} else if strings.Contains(reason, "INFINITE_API") {
		responseType = "INFINITE_API"
	} else if strings.Contains(reason, "DIRECTORY_LISTING") {
		responseType = "DIRECTORY_LISTING"
	} else if strings.Contains(reason, "RECON") {
		responseType = "RECON"
	} else if strings.Contains(reason, "DOWNLOAD_CONFIRM") {
		responseType = "DOWNLOAD_CONFIRM"
	}

	// Record to attack log (for dashboard)
	event := attackLog.recordAttack(r, reason, responseType)

	// Async GeoIP lookup (don't block the response)
	go func(ip string, eventID int) {
		geo := attackLog.lookupGeoIP(ip)
		if geo != nil {
			attackLog.mu.Lock()
			for i := range attackLog.events {
				if attackLog.events[i].ID == eventID {
					attackLog.events[i].GeoInfo = geo
					break
				}
			}
			attackLog.mu.Unlock()
		}
	}(event.IP, event.ID)

	//nolint:gosec // G706: logging attacker-controlled data is intentional
	log.Printf("🎯 ATTACK [%s] - Reason: %s | IP: %s | Path: %s | Method: %s | UA: %s | Referer: %s",
		responseType, reason, getClientIP(r), r.URL.Path, r.Method, userAgent, referer)
}

// Middleware to check for suspicious requests
func zipbombMiddleware(next http.Handler) http.Handler {
	// Paths exempt from suspicious path detection (handled by their own route handlers)
	exemptPrefixes := []string{"/backup/", "/backups/", "/data/", "/export/", "/dl/"}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip suspicious path detection for directory listing routes
		pathLower := strings.ToLower(r.URL.Path)
		for _, prefix := range exemptPrefixes {
			if strings.HasPrefix(pathLower, prefix) {
				next.ServeHTTP(w, r)
				return
			}
		}

		clientIP := getClientIP(r)
		isSuspicious := isSuspiciousPath(r.URL.Path)

		// Behavioral detection - track request patterns
		shouldBlock, reason := requestTracker.trackRequest(clientIP, r.URL.Path, isSuspicious)
		if shouldBlock {
			logAttack(r, fmt.Sprintf("BEHAVIORAL: %s", reason))
			serveZipbomb(w, r, reason)
			return
		}

		// Check if this looks like an attack
		if isSuspicious {
			serveZipbomb(w, r, "Suspicious path detected")
			return
		}

		// Check for suspicious user agents (extended list)
		ua := strings.ToLower(r.Header.Get("User-Agent"))

		// Empty user agent is suspicious
		if ua == "" {
			serveSlowDrip(w, r, "Empty user agent")
			return
		}

		for _, suspicious := range suspiciousUserAgents {
			if strings.Contains(ua, suspicious) {
				serveZipbomb(w, r, fmt.Sprintf("Suspicious user agent: %s", suspicious))
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

// Serve the enhanced zipbomb
func serveZipbomb(w http.ResponseWriter, r *http.Request, reason string) {
	logAttack(r, reason+" [ZIPBOMB]")

	// Generate a dynamic filename to look more realistic
	filename := generateBackupFilename()

	// Determine content type from extension
	contentType := "application/zip"
	switch {
	case strings.HasSuffix(filename, ".tar.gz"), strings.HasSuffix(filename, ".tgz"), strings.HasSuffix(filename, ".sql.gz"):
		contentType = "application/gzip"
	case strings.HasSuffix(filename, ".bak"):
		contentType = "application/octet-stream"
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(zipbombData)))
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	setFakeFileHeaders(w, filename)

	// Add a realistic delay to simulate file preparation
	time.Sleep(200 * time.Millisecond)

	// Serve the zipbomb
	w.WriteHeader(http.StatusOK)
	//nolint
	io.Copy(w, bytes.NewReader(zipbombData))
}

// Serve content extremely slowly - tarpitting
func serveSlowDrip(w http.ResponseWriter, r *http.Request, reason string) {
	logAttack(r, reason+" [SLOW_DRIP]")

	// Fake a large file that will take forever to download
	fakeSize := 10 * 1024 * 1024 // Claim 10MB

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename=\"backup_data.bin\"")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", fakeSize))
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)

	// Get the flusher for streaming
	flusher, ok := w.(http.Flusher)
	if !ok {
		// Fallback to regular slow response
		time.Sleep(30 * time.Second)
		return
	}

	// Send data painfully slowly - 1 byte every 2-5 seconds
	// This will take ~6-14 hours to send 10MB
	trollMsg := []byte(getRandomTrollMessage() + "\n")
	bytesSent := 0

	for bytesSent < fakeSize {
		// Send one byte at a time
		var err error
		if bytesSent < len(trollMsg) {
			_, err = w.Write([]byte{trollMsg[bytesSent]})
		} else {
			_, err = w.Write([]byte{0x00}) // Send null bytes
		}
		if err != nil {
			return // Client disconnected, stop wasting our resources
		}
		flusher.Flush()
		bytesSent++

		// Random delay between 2-5 seconds per byte
		//nolint:gosec
		delay := time.Duration(2000+rand.Intn(3000)) * time.Millisecond
		time.Sleep(delay)

		// Break after sending troll message + some padding (don't actually send 10MB)
		if bytesSent > len(trollMsg)+100 {
			break
		}
	}
}

// Serve gzip bomb with Content-Encoding
func serveGzipBomb(w http.ResponseWriter, r *http.Request, reason string) {
	logAttack(r, reason+" [GZIP_BOMB]")

	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("Content-Encoding", "gzip")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(gzipbombData)))
	w.Header().Set("Cache-Control", "no-cache")

	time.Sleep(100 * time.Millisecond)
	w.WriteHeader(http.StatusOK)
	//nolint
	io.Copy(w, bytes.NewReader(gzipbombData))
}

// Serve fake credentials with troll content
func serveFakeCreds(w http.ResponseWriter, r *http.Request, credType string) {
	logAttack(r, fmt.Sprintf("Fake creds served: %s [HONEYPOT]", credType))

	var content string
	var contentType string
	var filename string

	switch credType {
	case "env":
		content = fakeEnvFile
		contentType = "text/plain"
		filename = ".env"
	case "wpconfig":
		content = fakeWPConfig
		contentType = "application/x-php"
		filename = "wp-config.php"
	case "gitconfig":
		content = fakeGitConfig
		contentType = "text/plain"
		filename = "config"
	case "sshkey":
		content = fakeSSHKey
		contentType = "application/x-pem-file"
		filename = "id_rsa"
	case "database":
		content = getFakeDatabaseDump()
		contentType = "application/sql"
		filename = "database_backup.sql"
	default:
		content = fakeEnvFile
		contentType = "text/plain"
		filename = ".env"
	}

	// Add hidden troll message at the end
	content += fmt.Sprintf("\n\n# %s\n", getRandomTrollMessage())

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(content)))

	// Slight delay to seem realistic
	time.Sleep(100 * time.Millisecond)

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(content))
}

// Serve a troll response with hidden message
func serveTrollResponse(w http.ResponseWriter, r *http.Request, reason string) {
	logAttack(r, reason+" [TROLL]")

	// Return what looks like a success but is actually trolling
	//nolint:gosec
	response := fmt.Sprintf(`{
	"status": "success",
	"message": "Access granted",
	"token": "totally_legit_token_%d",
	"admin": true,
	"_debug": "%s",
	"next_steps": "Please try accessing /admin/dashboard with this token",
	"support": "If you need help, contact admin@honeypot.local"
}`, rand.Intn(999999), getRandomTrollMessage())

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(response))
}

// Rickroll redirect
func serveRickroll(w http.ResponseWriter, r *http.Request, reason string) {
	logAttack(r, reason+" [RICKROLL]")

	// Random chance of different destinations
	destinations := []string{
		"https://www.youtube.com/watch?v=dQw4w9WgXcQ", // Classic rickroll
		"https://www.fbi.gov/investigate/cyber",       // FBI cyber division
		"https://www.ic3.gov/",                        // Internet Crime Complaint Center
	}

	// Add a delay to waste more time
	//nolint:gosec
	time.Sleep(time.Duration(5+rand.Intn(10)) * time.Second)

	//nolint:gosec
	http.Redirect(w, r, destinations[rand.Intn(len(destinations))], http.StatusFound)
}

// Serve infinite pagination - always has more pages
func serveInfinitePagination(w http.ResponseWriter, r *http.Request, dataType string) {
	// Parse page parameter (default to 1)
	pageStr := r.URL.Query().Get("page")
	page := 1
	if pageStr != "" {
		if p, err := fmt.Sscanf(pageStr, "%d", &page); err != nil || p != 1 {
			page = 1
		}
	}
	if page < 1 {
		page = 1
	}

	// Parse per_page (default 25, max 100)
	perPageStr := r.URL.Query().Get("per_page")
	perPage := 25
	if perPageStr != "" {
		if p, err := fmt.Sscanf(perPageStr, "%d", &perPage); err != nil || p != 1 {
			perPage = 25
		}
	}
	if perPage < 1 {
		perPage = 25
	}
	if perPage > 100 {
		perPage = 100
	}

	logAttack(r, fmt.Sprintf("Infinite pagination: %s page=%d per_page=%d [INFINITE_API]", dataType, page, perPage))

	// Simulate processing delay (gets slower on higher pages)
	//nolint:gosec
	delay := 500 + (page * 100) + rand.Intn(500)
	if delay > 5000 {
		delay = 5000
	}
	time.Sleep(time.Duration(delay) * time.Millisecond)

	// Generate fake data
	users := generateFakeUsers(page, perPage)

	// Always claim there are more pages (infinite)
	fakeTotal := 10000 + (page * 100) // Total keeps growing
	fakeTotalPages := (fakeTotal / perPage) + 1

	response := PaginatedResponse{
		Data:       users,
		Page:       page,
		PerPage:    perPage,
		Total:      fakeTotal,
		TotalPages: fakeTotalPages,
		HasMore:    true, // Always true - infinite pagination
		NextPage:   fmt.Sprintf("/api/v1/%s?page=%d&per_page=%d", dataType, page+1, perPage),
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Total-Count", fmt.Sprintf("%d", fakeTotal))
	w.Header().Set("X-Page", fmt.Sprintf("%d", page))
	w.Header().Set("X-Per-Page", fmt.Sprintf("%d", perPage))
	w.Header().Set("Link", fmt.Sprintf("<%s>; rel=\"next\"", response.NextPage))

	_ = json.NewEncoder(w).Encode(response)
}

// Legitimate route handlers
func homeHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	//nolint:errcheck
	fmt.Fprintf(w, `{"status": "ok", "message": "Private service is running", "timestamp": "%s"}`,
		time.Now().Format(time.RFC3339))
}

func apiHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	//nolint:errcheck
	fmt.Fprintf(w, `{"status": "success", "data": {"version": "1.0", "environment": "production"}}`)
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	//nolint:errcheck
	fmt.Fprintf(w, `{"status": "healthy", "uptime": "ok"}`)
}

// Metrics endpoint (for monitoring)
func metricsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	stats := requestTracker.getTrackerStats()
	//nolint:errcheck
	fmt.Fprintf(w, "# TYPE zipbomb_size_bytes gauge\nzipbomb_size_bytes %d\n", len(zipbombData))
	//nolint:errcheck
	fmt.Fprintf(w, "# TYPE gzipbomb_size_bytes gauge\ngzipbomb_size_bytes %d\n", len(gzipbombData))
	//nolint:errcheck
	fmt.Fprintf(w, "# TYPE tracked_ips gauge\ntracked_ips %d\n", stats["tracked_ips"])
}

// Graduated 404 handler - escalates response based on IP request count
func notFoundHandler(w http.ResponseWriter, r *http.Request) {
	clientIP := getClientIP(r)

	// Get request count for this IP
	requestTracker.mu.RLock()
	info := requestTracker.requests[clientIP]
	count := 0
	if info != nil {
		count = info.Count
	}
	requestTracker.mu.RUnlock()

	// Determine host and port for Apache-style output
	host := r.Host
	port := "80"
	if h, p, err := net.SplitHostPort(r.Host); err == nil {
		host = h
		port = p
	}

	// Stage 3: 15+ requests - serve zipbomb
	if count >= 15 {
		serveZipbomb(w, r, "404 graduated response - stage 3 [RECON]")
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=iso-8859-1")
	w.WriteHeader(http.StatusNotFound)

	// Stage 2: 8-14 requests - Apache 404 with breadcrumb hints
	if count >= 8 {
		//nolint:gosec
		hints := []string{
			"<!-- backup dir: /backup/ -->",
			"<!-- TODO: remove old exports from /data/ -->",
			"<!-- migrate backups to S3 - see /backups/ -->",
		}
		//nolint:gosec
		hint := hints[rand.Intn(len(hints))]
		logAttack(r, fmt.Sprintf("404 graduated response - stage 2 hint shown (count=%d) [RECON]", count))
		//nolint:errcheck,gosec // G705: intentional honeypot content
		fmt.Fprintf(w, apacheNotFoundHTML, r.URL.Path, hint+"\n", host, port)
		return
	}

	// Stage 1: First ~8 requests - standard Apache 404
	//nolint:errcheck,gosec // G705: intentional honeypot content
	fmt.Fprintf(w, apacheNotFoundHTML, r.URL.Path, "", host, port)
}

func main() {
	r := chi.NewRouter()

	// Middleware stack
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(600 * time.Second)) // Extended timeout for slow drip

	// Fake server headers - make it look like Apache/PHP
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Server", "Apache/2.4.41 (Ubuntu)")
			w.Header().Set("X-Powered-By", "PHP/7.4.3")
			next.ServeHTTP(w, r)
		})
	})

	// Custom middleware for zipbomb defense
	r.Use(zipbombMiddleware)

	// Legitimate routes
	r.Get("/", homeHandler)
	r.Get("/api", apiHandler)
	r.Get("/api/v1/status", apiHandler)
	r.Get("/health", healthHandler)
	r.Get("/metrics", metricsHandler)

	// Custom 404 handler
	r.NotFound(notFoundHandler)

	// ============================================
	// HONEYPOT TRAPS - Fake credential files
	// ============================================

	// Environment files - serve fake creds
	r.Get("/.env", func(w http.ResponseWriter, r *http.Request) {
		serveFakeCreds(w, r, "env")
	})
	r.Get("/.env.local", func(w http.ResponseWriter, r *http.Request) {
		serveFakeCreds(w, r, "env")
	})
	r.Get("/.env.production", func(w http.ResponseWriter, r *http.Request) {
		serveFakeCreds(w, r, "env")
	})
	r.Get("/.env.backup", func(w http.ResponseWriter, r *http.Request) {
		serveFakeCreds(w, r, "env")
	})

	// WordPress config
	r.Get("/wp-config.php", func(w http.ResponseWriter, r *http.Request) {
		serveFakeCreds(w, r, "wpconfig")
	})
	r.Get("/wp-config.php.bak", func(w http.ResponseWriter, r *http.Request) {
		serveFakeCreds(w, r, "wpconfig")
	})
	r.Get("/wp-config.php.old", func(w http.ResponseWriter, r *http.Request) {
		serveFakeCreds(w, r, "wpconfig")
	})

	// Git config - serve fake repo info
	r.Get("/.git/config", func(w http.ResponseWriter, r *http.Request) {
		serveFakeCreds(w, r, "gitconfig")
	})
	r.Get("/.git/HEAD", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ref: refs/heads/main\n"))
	})

	// SSH keys - serve fake keys
	r.Get("/id_rsa", func(w http.ResponseWriter, r *http.Request) {
		serveFakeCreds(w, r, "sshkey")
	})
	r.Get("/.ssh/id_rsa", func(w http.ResponseWriter, r *http.Request) {
		serveFakeCreds(w, r, "sshkey")
	})
	r.Get("/id_ed25519", func(w http.ResponseWriter, r *http.Request) {
		serveFakeCreds(w, r, "sshkey")
	})

	// Database dumps - serve fake data with troll passwords
	r.Get("/database.sql", func(w http.ResponseWriter, r *http.Request) {
		serveFakeCreds(w, r, "database")
	})
	r.Get("/dump.sql", func(w http.ResponseWriter, r *http.Request) {
		serveFakeCreds(w, r, "database")
	})
	r.Get("/backup.sql", func(w http.ResponseWriter, r *http.Request) {
		serveFakeCreds(w, r, "database")
	})
	r.Get("/users.sql", func(w http.ResponseWriter, r *http.Request) {
		serveFakeCreds(w, r, "database")
	})

	// ============================================
	// FAKE DIRECTORY LISTINGS - Believable backup discovery
	// ============================================

	// Directory listing pages
	dirPaths := []string{"/backup/", "/backups/", "/data/", "/export/"}
	for _, dp := range dirPaths {
		dirPath := dp // capture for closure
		r.Get(dirPath, func(w http.ResponseWriter, r *http.Request) {
			serveDirectoryListing(w, r, dirPath)
		})
		// File downloads from directory listings -> download confirmation -> zipbomb
		r.Get(dirPath+"{filename}", func(w http.ResponseWriter, r *http.Request) {
			filename := chi.URLParam(r, "filename")
			serveDownloadConfirmation(w, r, filename)
		})
	}

	// Download endpoint (token-based) - serves the actual zipbomb
	r.Get("/dl/{token}/{filename}", func(w http.ResponseWriter, r *http.Request) {
		serveZipbomb(w, r, "Download confirmation completed")
	})

	// ============================================
	// ZIPBOMB TRAPS - Direct file downloads
	// ============================================

	r.Get("/database_backup.zip", func(w http.ResponseWriter, r *http.Request) {
		serveZipbomb(w, r, "Database backup download")
	})

	r.Get("/full_backup.zip", func(w http.ResponseWriter, r *http.Request) {
		serveZipbomb(w, r, "Full backup download")
	})

	// ============================================
	// GZIP BOMB TRAPS - HTML/API responses
	// ============================================

	r.Get("/debug", func(w http.ResponseWriter, r *http.Request) {
		serveGzipBomb(w, r, "Debug endpoint access")
	})

	r.Get("/phpinfo.php", func(w http.ResponseWriter, r *http.Request) {
		serveGzipBomb(w, r, "PHP info access")
	})

	r.Get("/server-status", func(w http.ResponseWriter, r *http.Request) {
		serveGzipBomb(w, r, "Server status access")
	})

	// ============================================
	// FAKE LOGIN SYSTEM - Multi-step time waster
	// ============================================

	// Fake login page with realistic HTML
	r.Get("/login", func(w http.ResponseWriter, r *http.Request) {
		logAttack(r, "Login page viewed [FAKE_LOGIN]")
		clientIP := getClientIP(r)
		//nolint:gosec
		sessionID := fmt.Sprintf("sess_%d", rand.Intn(999999))
		w.Header().Set("Content-Type", "text/html")
		//nolint:errcheck,gosec // G705: intentional honeypot content
		fmt.Fprintf(w, fakeLoginPageHTML, sessionID, clientIP)
	})

	// Handle login form POST - log creds and redirect to MFA
	r.Post("/login", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		username := r.FormValue("username")
		password := r.FormValue("password")
		logAttack(r, fmt.Sprintf("Login credentials captured: user=%s pass=%s [CREDENTIAL_HARVEST]",
			username, password))

		// Pretend to verify (waste 3-8 seconds)
		//nolint:gosec
		time.Sleep(time.Duration(3000+rand.Intn(5000)) * time.Millisecond)

		// Return JSON that redirects to MFA
		w.Header().Set("Content-Type", "application/json")
		//nolint:gosec
		response := fmt.Sprintf(`{"status":"mfa_required","message":"Please complete two-factor authentication","token":"mfa_%d"}`,
			rand.Intn(999999))
		_, _ = w.Write([]byte(response))
	})

	// Fake auth verification API (always fails after delay)
	r.Post("/api/auth/verify", func(w http.ResponseWriter, r *http.Request) {
		var creds struct {
			Username string `json:"username"`
			Password string `json:"password"` //nolint:gosec // G117: capturing attacker credentials
			Attempt  int    `json:"attempt"`
		}
		_ = json.NewDecoder(r.Body).Decode(&creds)
		logAttack(r, fmt.Sprintf("Auth API credentials: user=%s pass=%s attempt=%d [CREDENTIAL_HARVEST]",
			creds.Username, creds.Password, creds.Attempt))

		w.Header().Set("Content-Type", "application/json")
		//nolint:gosec,errcheck
		fmt.Fprintf(w, `{"status":"mfa_required","token":"mfa_%d","message":"Two-factor authentication required"}`,
			rand.Intn(999999))
	})

	// Fake MFA page
	r.Get("/admin/mfa", func(w http.ResponseWriter, r *http.Request) {
		logAttack(r, "MFA page viewed [FAKE_MFA]")
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(fakeMFAPageHTML))
	})

	// Fake MFA verification (always fails)
	r.Post("/admin/mfa/verify", func(w http.ResponseWriter, r *http.Request) {
		var mfa struct {
			Code  string `json:"code"`
			Token string `json:"token"`
		}
		_ = json.NewDecoder(r.Body).Decode(&mfa)
		logAttack(r, fmt.Sprintf("MFA code attempt: %s [FAKE_MFA]", mfa.Code))

		// Always fail after delay
		//nolint:gosec
		time.Sleep(time.Duration(2000+rand.Intn(3000)) * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"error","message":"Invalid verification code"}`))
	})

	// Fake admin dashboard (loads forever then rickrolls)
	r.Get("/admin/dashboard", func(w http.ResponseWriter, r *http.Request) {
		logAttack(r, "Admin dashboard accessed [FAKE_DASHBOARD]")
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(fakeAdminDashboardHTML))
	})

	// Generic admin routes
	r.HandleFunc("/admin*", func(w http.ResponseWriter, r *http.Request) {
		serveTrollResponse(w, r, "Admin panel access attempt")
	})

	// ============================================
	// INFINITE PAGINATION API - Never-ending data
	// ============================================

	r.Get("/api/v1/users", func(w http.ResponseWriter, r *http.Request) {
		serveInfinitePagination(w, r, "users")
	})

	r.Get("/api/v2/users", func(w http.ResponseWriter, r *http.Request) {
		serveInfinitePagination(w, r, "users")
	})

	r.Get("/api/v1/accounts", func(w http.ResponseWriter, r *http.Request) {
		serveInfinitePagination(w, r, "accounts")
	})

	r.Get("/api/v1/customers", func(w http.ResponseWriter, r *http.Request) {
		serveInfinitePagination(w, r, "customers")
	})

	r.Get("/api/v1/admin", func(w http.ResponseWriter, r *http.Request) {
		serveTrollResponse(w, r, "Admin API access attempt")
	})

	// ============================================
	// SLOW DRIP TRAPS - Time wasting
	// ============================================

	r.Get("/download", func(w http.ResponseWriter, r *http.Request) {
		serveSlowDrip(w, r, "Generic download attempt")
	})

	r.Get("/files/*", func(w http.ResponseWriter, r *http.Request) {
		serveSlowDrip(w, r, "File access attempt")
	})

	// ============================================
	// RICKROLL TRAPS - Ultimate trolling
	// ============================================

	r.Get("/secret", func(w http.ResponseWriter, r *http.Request) {
		serveRickroll(w, r, "Secret page access")
	})

	r.Get("/private", func(w http.ResponseWriter, r *http.Request) {
		serveRickroll(w, r, "Private page access")
	})

	r.Get("/confidential", func(w http.ResponseWriter, r *http.Request) {
		serveRickroll(w, r, "Confidential page access")
	})

	// ============================================
	// HONEYPOT DASHBOARD - Internal monitoring
	// ============================================

	// Troll dashboard for attackers who find it
	r.Get("/honeypot/dashboard", func(w http.ResponseWriter, r *http.Request) {
		logAttack(r, "Dashboard access attempt - showing troll page [TROLL_DASHBOARD]")
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(trollDashboardHTML))
	})

	// Real dashboard at secret path
	r.Get("/honeypot/dashboard/{key}", func(w http.ResponseWriter, r *http.Request) {
		key := chi.URLParam(r, "key")
		if key != dashboardSecretKey {
			// Wrong key - show troll page
			logAttack(r, fmt.Sprintf("Dashboard wrong key attempt: %s [TROLL_DASHBOARD]", key))
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(trollDashboardHTML))
			return
		}
		// Correct key - show real dashboard
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(attackDashboardHTML))
	})

	// Dashboard API - protected by key in header or query param
	r.Get("/honeypot/api/events", func(w http.ResponseWriter, r *http.Request) {
		// Check for valid key
		key := r.URL.Query().Get("key")
		if key == "" {
			key = r.Header.Get("X-Dashboard-Key")
		}
		if key != dashboardSecretKey {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"unauthorized","message":"Nice try! This attempt has been logged."}`))
			logAttack(r, "Dashboard API unauthorized access [TROLL]")
			return
		}

		limitStr := r.URL.Query().Get("limit")
		limit := 50
		if limitStr != "" {
			if l, err := fmt.Sscanf(limitStr, "%d", &limit); err != nil || l != 1 {
				limit = 50
			}
		}
		if limit > 200 {
			limit = 200
		}

		events := attackLog.getRecentEvents(limit)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(events)
	})

	// Dashboard API - get statistics (protected)
	r.Get("/honeypot/api/stats", func(w http.ResponseWriter, r *http.Request) {
		key := r.URL.Query().Get("key")
		if key == "" {
			key = r.Header.Get("X-Dashboard-Key")
		}
		if key != dashboardSecretKey {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
			return
		}

		stats := attackLog.getStats()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(stats)
	})

	// Honeypot logging endpoint (for JS beacons)
	r.Post("/api/honeypot/log", func(w http.ResponseWriter, r *http.Request) {
		logAttack(r, "JavaScript beacon [JS_BEACON]")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	// ============================================
	// FAKE PHPMYADMIN - Realistic interface
	// ============================================

	r.Get("/phpmyadmin", func(w http.ResponseWriter, r *http.Request) {
		logAttack(r, "phpMyAdmin main page [FAKE_PHPMYADMIN]")
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(fakePhpMyAdminHTML))
	})

	r.Get("/phpmyadmin/", func(w http.ResponseWriter, r *http.Request) {
		logAttack(r, "phpMyAdmin main page [FAKE_PHPMYADMIN]")
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(fakePhpMyAdminHTML))
	})

	r.Get("/phpmyadmin/index.php", func(w http.ResponseWriter, r *http.Request) {
		logAttack(r, "phpMyAdmin index [FAKE_PHPMYADMIN]")
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(fakePhpMyAdminHTML))
	})

	// phpMyAdmin export - serve zipbomb
	r.Get("/phpmyadmin/export.php", func(w http.ResponseWriter, r *http.Request) {
		table := r.URL.Query().Get("table")
		logAttack(r, fmt.Sprintf("phpMyAdmin export table=%s [ZIPBOMB]", table))
		serveZipbomb(w, r, "phpMyAdmin export attempt")
	})

	// Other phpMyAdmin paths serve the interface
	r.Get("/phpmyadmin/*", func(w http.ResponseWriter, r *http.Request) {
		// Check if it's an export or download
		if strings.Contains(r.URL.Path, "export") || strings.Contains(r.URL.Path, "download") {
			serveZipbomb(w, r, "phpMyAdmin download attempt")
			return
		}
		logAttack(r, "phpMyAdmin subpage [FAKE_PHPMYADMIN]")
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(fakePhpMyAdminHTML))
	})

	// Alternative phpMyAdmin paths
	r.Get("/pma", func(w http.ResponseWriter, r *http.Request) {
		logAttack(r, "phpMyAdmin (pma) [FAKE_PHPMYADMIN]")
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(fakePhpMyAdminHTML))
	})

	r.Get("/pma/*", func(w http.ResponseWriter, r *http.Request) {
		logAttack(r, "phpMyAdmin (pma) subpage [FAKE_PHPMYADMIN]")
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(fakePhpMyAdminHTML))
	})

	r.Get("/mysql", func(w http.ResponseWriter, r *http.Request) {
		logAttack(r, "MySQL admin [FAKE_PHPMYADMIN]")
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(fakePhpMyAdminHTML))
	})

	r.Get("/adminer", func(w http.ResponseWriter, r *http.Request) {
		logAttack(r, "Adminer [FAKE_PHPMYADMIN]")
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(fakePhpMyAdminHTML))
	})

	r.Get("/adminer.php", func(w http.ResponseWriter, r *http.Request) {
		logAttack(r, "Adminer.php [FAKE_PHPMYADMIN]")
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(fakePhpMyAdminHTML))
	})

	// ============================================
	// SCANNER TRAPS - Common scanner targets
	// ============================================

	r.Get("/wp-admin", func(w http.ResponseWriter, r *http.Request) {
		serveTrollResponse(w, r, "WordPress admin access")
	})
	r.Get("/wp-admin/*", func(w http.ResponseWriter, r *http.Request) {
		serveTrollResponse(w, r, "WordPress admin access")
	})

	r.Get("/wp-login.php", func(w http.ResponseWriter, r *http.Request) {
		serveTrollResponse(w, r, "WordPress login access")
	})

	r.Get("/administrator", func(w http.ResponseWriter, r *http.Request) {
		serveTrollResponse(w, r, "Joomla admin access")
	})

	r.Get("/manager/html", func(w http.ResponseWriter, r *http.Request) {
		serveTrollResponse(w, r, "Tomcat manager access")
	})

	// Start background cleanup for rate limiter
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			requestTracker.cleanupOldEntries()
			log.Printf("🧹 Rate limiter cleanup: %d IPs tracked", len(requestTracker.requests))
		}
	}()

	port := ":8080"
	log.Printf("🚀 Server starting on port %s", port)
	log.Printf("⚡ Enhanced defenses active:")
	log.Printf("   💣 Zipbomb: ~50GB payload")
	log.Printf("   💥 Gzip bomb: ~1GB payload")
	log.Printf("   🐌 Slow drip: 1 byte/2-5 seconds")
	log.Printf("   🎣 Fake credentials: .env, wp-config, SSH keys, DB dumps")
	log.Printf("   🎭 Troll responses: Fake success messages")
	log.Printf("   🎵 Rickroll redirects: FBI & YouTube")
	log.Printf("   🔐 Fake login/MFA pages: Multi-step time waster")
	log.Printf("   📄 Infinite pagination: Never-ending API results")
	log.Printf("   🗄️  Fake phpMyAdmin: Realistic database interface")
	log.Printf("   📂 Fake directory listings: /backup/, /backups/, /data/, /export/")
	log.Printf("   📋 Graduated 404: Apache HTML → breadcrumb hints → zipbomb")
	log.Printf("   🌍 GeoIP lookups: IP geolocation tracking")
	log.Printf("   🚦 Behavioral detection: %d req/min, %d suspicious paths",
		maxRequestsPerMinute, maxSuspiciousPaths)
	log.Printf("📊 Dashboard URL: /honeypot/dashboard/%s", dashboardSecretKey)
	log.Printf("   (Set HONEYPOT_DASHBOARD_KEY env var to customize)")
	log.Printf("🛡️  Monitoring for suspicious requests...")

	//nolint:gosec
	if err := http.ListenAndServe(port, r); err != nil {
		log.Fatal("Server failed to start:", err)
	}
}
