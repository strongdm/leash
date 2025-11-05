package proxy

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/andybalholm/brotli"
)

const (
	maxSecretBodyBytes = 4 << 20 // 4 MiB limit for decoded bodies
)

var errBodyTooLarge = errors.New("secret body exceeds replacement limit")

type secretsBroadcaster interface {
	EmitJSON(event string, payload any)
}

type secretEntry struct {
	id               string
	placeholder      string
	placeholderBytes []byte
	value            string
	valueBytes       []byte
}

func (p *MITMProxy) applySecrets(req *http.Request) {
	if p == nil || req == nil || p.secretsManager == nil {
		return
	}

	snapshot := p.secretsManager.Snapshot()
	if len(snapshot.Placeholders) == 0 {
		return
	}

	entries := make([]secretEntry, 0, len(snapshot.Placeholders))
	for placeholder, entry := range snapshot.Placeholders {
		entries = append(entries, secretEntry{
			id:               entry.ID,
			placeholder:      placeholder,
			placeholderBytes: []byte(placeholder),
			value:            entry.Value,
			valueBytes:       []byte(entry.Value),
		})
	}

	totalCounts := make(map[string]int)
	if req.URL != nil {
		if path := req.URL.Path; path != "" {
			if replaced, delta := replaceString(path, entries); delta != nil {
				req.URL.Path = replaced
				req.URL.RawPath = ""
				mergeCounts(totalCounts, delta)
			}
		}
		if rawQuery := req.URL.RawQuery; rawQuery != "" {
			if replaced, delta := replaceString(rawQuery, entries); delta != nil {
				req.URL.RawQuery = replaced
				mergeCounts(totalCounts, delta)
			}
		}
	}
	if headerCounts := replaceHeaderValues(req.Header, entries); len(headerCounts) > 0 {
		mergeCounts(totalCounts, headerCounts)
	}

	if err := p.replaceBody(req, entries, totalCounts); err != nil {
		log.Printf("secrets: skipping body replacement (%v)", err)
	}

	if len(totalCounts) == 0 {
		return
	}

	updates := p.secretsManager.ReplaceStats(totalCounts)
	if len(updates) == 0 || p.secretsEvents == nil {
		return
	}
	for id, activations := range updates {
		p.secretsEvents.EmitJSON("secret.activation", map[string]any{
			"id":          id,
			"activations": activations,
		})
	}
}

func (p *MITMProxy) replaceBody(req *http.Request, entries []secretEntry, counts map[string]int) error {
	if req.Body == nil || req.Body == http.NoBody {
		return nil
	}

	encoding := strings.ToLower(strings.TrimSpace(req.Header.Get("Content-Encoding")))
	supported := encoding == "" || encoding == "identity" || encoding == "gzip" || encoding == "deflate" || encoding == "br"
	if !supported {
		return nil
	}

	originalContentLength := req.ContentLength
	originalContentLengthHeader := req.Header.Get("Content-Length")
	originalTransferEncoding := append([]string(nil), req.TransferEncoding...)

	raw, err := io.ReadAll(req.Body)
	if err != nil {
		return err
	}
	_ = req.Body.Close()

	restoreOriginal := func() {
		req.Body = io.NopCloser(bytes.NewReader(raw))
		req.ContentLength = originalContentLength
		if originalContentLengthHeader == "" {
			req.Header.Del("Content-Length")
		} else {
			req.Header.Set("Content-Length", originalContentLengthHeader)
		}
		req.TransferEncoding = append([]string(nil), originalTransferEncoding...)
	}

	switch encoding {
	case "", "identity":
		if len(raw) > maxSecretBodyBytes {
			restoreOriginal()
			return errBodyTooLarge
		}
		updated, changed, delta := replacePlainBody(raw, entries)
		if !changed {
			restoreOriginal()
			return nil
		}
		mergeCounts(counts, delta)
		setBody(req, updated)
		req.Header.Del("Content-Encoding")
	case "gzip":
		updated, changed, delta, err := replaceGzipBody(raw, entries)
		if err != nil {
			restoreOriginal()
			return err
		}
		if !changed {
			restoreOriginal()
			return nil
		}
		mergeCounts(counts, delta)
		setBody(req, updated)
		req.Header.Set("Content-Encoding", encoding)
	case "deflate":
		updated, changed, delta, err := replaceDeflateBody(raw, entries)
		if err != nil {
			restoreOriginal()
			return err
		}
		if !changed {
			restoreOriginal()
			return nil
		}
		mergeCounts(counts, delta)
		setBody(req, updated)
		req.Header.Set("Content-Encoding", encoding)
	case "br":
		updated, changed, delta, err := replaceBrotliBody(raw, entries)
		if err != nil {
			restoreOriginal()
			return err
		}
		if !changed {
			restoreOriginal()
			return nil
		}
		mergeCounts(counts, delta)
		setBody(req, updated)
		req.Header.Set("Content-Encoding", encoding)
	}
	return nil
}

func replaceHeaderValues(header http.Header, entries []secretEntry) map[string]int {
	if len(entries) == 0 {
		return nil
	}
	var totals map[string]int
	for key, values := range header {
		updated := false
		newValues := make([]string, len(values))
		for i, value := range values {
			replaced, delta := replaceString(value, entries)
			if delta != nil {
				if totals == nil {
					totals = make(map[string]int)
				}
				mergeCounts(totals, delta)
				newValues[i] = replaced
				updated = true
			} else {
				newValues[i] = value
			}
		}
		if updated {
			header[key] = newValues
		}
	}
	return totals
}

func replaceString(value string, entries []secretEntry) (string, map[string]int) {
	replaced := value
	var counts map[string]int
	changed := false
	for _, entry := range entries {
		if !strings.Contains(replaced, entry.placeholder) {
			continue
		}
		n := strings.Count(replaced, entry.placeholder)
		if n == 0 {
			continue
		}
		if counts == nil {
			counts = make(map[string]int)
		}
		counts[entry.id] += n
		replaced = strings.ReplaceAll(replaced, entry.placeholder, entry.value)
		changed = true
	}
	if !changed {
		return value, nil
	}
	return replaced, counts
}

func replacePlainBody(data []byte, entries []secretEntry) ([]byte, bool, map[string]int) {
	replaced := data
	var counts map[string]int
	changed := false
	for _, entry := range entries {
		if !bytes.Contains(replaced, entry.placeholderBytes) {
			continue
		}
		n := bytes.Count(replaced, entry.placeholderBytes)
		if n == 0 {
			continue
		}
		if counts == nil {
			counts = make(map[string]int)
		}
		counts[entry.id] += n
		replaced = bytes.ReplaceAll(replaced, entry.placeholderBytes, entry.valueBytes)
		changed = true
	}
	if !changed {
		return data, false, nil
	}
	return replaced, true, counts
}

func replaceGzipBody(raw []byte, entries []secretEntry) ([]byte, bool, map[string]int, error) {
	reader, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, false, nil, err
	}
	defer reader.Close()

	limited := &io.LimitedReader{R: reader, N: maxSecretBodyBytes + 1}
	decoded, err := io.ReadAll(limited)
	if err != nil {
		return nil, false, nil, err
	}
	if limited.N <= 0 {
		return nil, false, nil, errBodyTooLarge
	}

	replaced, changed, counts := replacePlainBody(decoded, entries)
	if !changed {
		return raw, false, nil, nil
	}

	var buf bytes.Buffer
	writer := gzip.NewWriter(&buf)
	if _, err := writer.Write(replaced); err != nil {
		writer.Close()
		return nil, false, nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, false, nil, err
	}

	return buf.Bytes(), true, counts, nil
}

func replaceDeflateBody(raw []byte, entries []secretEntry) ([]byte, bool, map[string]int, error) {
	reader, err := zlib.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, false, nil, err
	}
	defer reader.Close()

	limited := &io.LimitedReader{R: reader, N: maxSecretBodyBytes + 1}
	decoded, err := io.ReadAll(limited)
	if err != nil {
		return nil, false, nil, err
	}
	if limited.N <= 0 {
		return nil, false, nil, errBodyTooLarge
	}

	replaced, changed, counts := replacePlainBody(decoded, entries)
	if !changed {
		return raw, false, nil, nil
	}

	var buf bytes.Buffer
	writer := zlib.NewWriter(&buf)
	if _, err := writer.Write(replaced); err != nil {
		writer.Close()
		return nil, false, nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, false, nil, err
	}

	return buf.Bytes(), true, counts, nil
}

func replaceBrotliBody(raw []byte, entries []secretEntry) ([]byte, bool, map[string]int, error) {
	reader := brotli.NewReader(bytes.NewReader(raw))
	limited := &io.LimitedReader{R: reader, N: maxSecretBodyBytes + 1}
	decoded, err := io.ReadAll(limited)
	if err != nil {
		return nil, false, nil, err
	}
	if limited.N <= 0 {
		return nil, false, nil, errBodyTooLarge
	}

	replaced, changed, counts := replacePlainBody(decoded, entries)
	if !changed {
		return raw, false, nil, nil
	}

	var buf bytes.Buffer
	writer := brotli.NewWriter(&buf)
	if _, err := writer.Write(replaced); err != nil {
		writer.Close()
		return nil, false, nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, false, nil, err
	}

	return buf.Bytes(), true, counts, nil
}

func mergeCounts(dst map[string]int, src map[string]int) {
	if len(src) == 0 {
		return
	}
	for key, value := range src {
		dst[key] += value
	}
}

func setBody(req *http.Request, data []byte) {
	req.Body = io.NopCloser(bytes.NewReader(data))
	req.ContentLength = int64(len(data))
	req.Header.Set("Content-Length", strconv.Itoa(len(data)))
	req.TransferEncoding = nil
	req.Header.Del("Transfer-Encoding")
}
