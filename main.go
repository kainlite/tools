package main

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// Suspicious paths that attackers commonly try
var suspiciousPaths = []string{
	".env", ".env.local", ".env.production", ".env.backup",
	"backup.tgz", "backup.tar.gz", "backup.zip", "backup.sql",
	"config.php", "wp-config.php", "database.sql", "dump.sql",
	".git", ".svn", ".hg", "admin", "administrator",
	"phpmyadmin", "pma", "mysql", "robots.txt", "sitemap.xml",
	".htaccess", ".htpasswd", "web.config", "server.xml",
	"application.properties", "config.json", "secrets.json",
	"credentials.json", "keys.txt", "passwords.txt",
	"users.sql", "accounts.csv", "data.xml", "export.csv",
	"logs.zip", "error.log", "access.log", "debug.log",
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

// Pre-generate the zipbomb at startup
var zipbombData []byte

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

	log.Printf("🎯 ZIPBOMB DEPLOYED - Reason: %s | IP: %s | Path: %s | Method: %s | UA: %s | Referer: %s",
		reason, r.RemoteAddr, r.URL.Path, r.Method, userAgent, referer)
}

// Middleware to check for suspicious requests
func zipbombMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if this looks like an attack
		if isSuspiciousPath(r.URL.Path) {
			serveZipbomb(w, r, "Suspicious path detected")
			return
		}

		// Check for suspicious user agents
		ua := strings.ToLower(r.Header.Get("User-Agent"))
		suspiciousUAs := []string{"sqlmap", "nikto", "nmap", "masscan", "zap", "burp"}
		for _, suspicious := range suspiciousUAs {
			if strings.Contains(ua, suspicious) {
				serveZipbomb(w, r, "Suspicious user agent")
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

// Serve the enhanced zipbomb
func serveZipbomb(w http.ResponseWriter, r *http.Request, reason string) {
	logAttack(r, reason)

	// Make it look like a legitimate backup file
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", "attachment; filename=\"database_backup_full.zip\"")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(zipbombData)))
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	// Add a realistic delay to simulate file preparation
	time.Sleep(200 * time.Millisecond)

	// Serve the zipbomb
	w.WriteHeader(http.StatusOK)
	//nolint
	io.Copy(w, bytes.NewReader(zipbombData))
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
	//nolint:errcheck
	fmt.Fprintf(w, "# TYPE zipbomb_size_bytes gauge\nzipbomb_size_bytes %d\n", len(zipbombData))
}

// Custom 404 handler that serves zipbomb
func notFoundHandler(w http.ResponseWriter, r *http.Request) {
	serveZipbomb(w, r, "404 - Invalid endpoint")
}

func main() {
	r := chi.NewRouter()

	// Middleware stack
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))

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

	// Specific traps for common attack vectors
	r.HandleFunc("/.env*", func(w http.ResponseWriter, r *http.Request) {
		serveZipbomb(w, r, "Environment file access attempt")
	})

	r.HandleFunc("/backup*", func(w http.ResponseWriter, r *http.Request) {
		serveZipbomb(w, r, "Backup file access attempt")
	})

	r.HandleFunc("/admin*", func(w http.ResponseWriter, r *http.Request) {
		serveZipbomb(w, r, "Admin panel access attempt")
	})

	port := ":8080"
	log.Printf("🚀 Server starting on port %s", port)
	log.Printf("⚡ Enhanced zipbomb defense active (~50GB payload)")
	log.Printf("🛡️  Monitoring for suspicious requests...")

	//nolint:gosec
	if err := http.ListenAndServe(port, r); err != nil {
		log.Fatal("Server failed to start:", err)
	}
}
