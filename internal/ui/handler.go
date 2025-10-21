package ui

import (
	"bytes"
	"html"
	"io"
	"log"
	"net/http"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

// SPAHandler serves an embedded single-page app with sensible fallbacks.
// - Serves static assets when present
// - Falls back to index.html for client-routed paths
type SPAHandler struct {
	root  http.FileSystem
	title string
}

// NewSPAHandler returns an SPA handler without title overrides.
func NewSPAHandler(root http.FileSystem) *SPAHandler {
	return NewSPAHandlerWithTitle(root, "")
}

// NewSPAHandlerWithTitle returns an SPA handler that injects the provided title into index.html responses.
func NewSPAHandlerWithTitle(root http.FileSystem, title string) *SPAHandler {
	return &SPAHandler{root: root, title: strings.TrimSpace(title)}
}

func (h *SPAHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Normalize path
	reqPath := path.Clean(r.URL.Path)
	if reqPath == "/" {
		reqPath = "/index.html"
	}

	// Try to serve the requested file
	if h.serveIfExists(w, r, strings.TrimPrefix(reqPath, "/")) {
		return
	}

	// Fallback to index.html for SPA routes
	if h.serveIfExists(w, r, "index.html") {
		return
	}

	// Last resort
	http.NotFound(w, r)
}

func (h *SPAHandler) serveIfExists(w http.ResponseWriter, r *http.Request, rel string) bool {
	f, err := h.root.Open(rel)
	if err != nil {
		return false
	}
	defer f.Close()

	// Basic content-type hint for common assets
	switch ext := strings.ToLower(filepath.Ext(rel)); ext {
	case ".js":
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	case ".css":
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	case ".html":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	case ".json":
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
	case ".svg":
		w.Header().Set("Content-Type", "image/svg+xml; charset=utf-8")
	case ".png":
		w.Header().Set("Content-Type", "image/png")
	case ".jpg", ".jpeg":
		w.Header().Set("Content-Type", "image/jpeg")
	case ".webp":
		w.Header().Set("Content-Type", "image/webp")
	case ".ico":
		w.Header().Set("Content-Type", "image/x-icon")
	}

	// Caching policy: long-lived for immutable hashed assets, no-store for HTML
	// Next.js hashed assets typically live under /_next/static/
	if strings.HasPrefix("/"+rel, "/_next/static/") {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else if strings.HasSuffix(strings.ToLower(rel), ".html") {
		w.Header().Set("Cache-Control", "no-store")
	}

	if strings.EqualFold(rel, "index.html") {
		data, err := io.ReadAll(f)
		if err != nil {
			log.Printf("ui: failed to read %s: %v", rel, err)
			return false
		}
		if h.title != "" {
			data = injectTitle(data, h.title)
		}
		if _, err := w.Write(data); err != nil {
			log.Printf("ui: failed to write %s: %v", rel, err)
			return false
		}
		return true
	}

	if _, err := io.Copy(w, f); err != nil {
		log.Printf("ui: failed to stream %s: %v", rel, err)
		return false
	}
	return true
}

func injectTitle(data []byte, title string) []byte {
	if len(data) == 0 {
		return data
	}
	escaped := html.EscapeString(title)
	jsLiteral := strconv.Quote(title)
	needle := []byte("<title>Leash</title>")
	titleTag := []byte(`<title data-leash-injected="true">` + escaped + "</title>")
	scriptTag := []byte(`<script data-leash-title>(function(t){if(!t)return;window.__LEASH_TITLE_TEXT=t;window.__leashRefreshTitle=function(){document.title=t;setTimeout(function(){document.title=t;},0);};window.__leashRefreshTitle();})(` + jsLiteral + `);</script>`)
	injection := append(append(make([]byte, 0, len(titleTag)+len(scriptTag)), titleTag...), scriptTag...)

	if bytes.Contains(data, needle) {
		return bytes.Replace(data, needle, injection, 1)
	}

	if bytes.Contains(data, []byte("<head>")) {
		replacement := append(make([]byte, 0, len("<head>")+len(injection)), []byte("<head>")...)
		replacement = append(replacement, injection...)
		return bytes.Replace(data, []byte("<head>"), replacement, 1)
	}

	if idx := bytes.Index(data, []byte("<head")); idx != -1 {
		end := bytes.IndexByte(data[idx:], '>')
		if end != -1 {
			end += idx + 1
			buf := make([]byte, 0, len(data)+len(injection))
			buf = append(buf, data[:end]...)
			buf = append(buf, injection...)
			buf = append(buf, data[end:]...)
			return buf
		}
	}

	buf := make([]byte, 0, len(injection)+len(data))
	buf = append(buf, injection...)
	buf = append(buf, data...)
	return buf
}
