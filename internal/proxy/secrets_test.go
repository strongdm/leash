package proxy

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"io"
	"net/http"
	"strconv"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/strongdm/leash/internal/secrets"
)

type stubBroadcaster struct {
	events []map[string]any
}

func (s *stubBroadcaster) EmitJSON(event string, payload any) {
	if event != "secret.activation" {
		return
	}
	msg, ok := payload.(map[string]any)
	if !ok {
		return
	}
	s.events = append(s.events, msg)
}

func TestApplySecretsHeaders(t *testing.T) {
	t.Parallel()
	mgr := secrets.NewManager()
	secret, err := mgr.Upsert("alpha", "", "hunter2")
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	stub := &stubBroadcaster{}
	proxy := &MITMProxy{}
	proxy.SetSecretsProvider(mgr, stub)

	req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
	req.Header.Set("Authorization", "Bearer "+secret.Placeholder)

	hits := proxy.applySecrets(req)

	if len(hits) != 1 || hits[0] != "alpha" {
		t.Fatalf("expected secret hit alpha, got %#v", hits)
	}

	if got := req.Header.Get("Authorization"); got != "Bearer hunter2" {
		t.Fatalf("expected header replaced, got %q", got)
	}
	if mgr.GetAll()["alpha"].Activations != 1 {
		t.Fatalf("expected activation count 1")
	}
	if len(stub.events) != 1 {
		t.Fatalf("expected 1 activation event, got %d", len(stub.events))
	}
	if id, ok := stub.events[0]["id"].(string); !ok || id != "alpha" {
		t.Fatalf("expected event id alpha, got %#v", stub.events[0]["id"])
	}
	if activations, ok := stub.events[0]["activations"].(int); !ok || activations != 1 {
		t.Fatalf("expected activations 1, got %#v", stub.events[0]["activations"])
	}
}

func TestApplySecretsURL(t *testing.T) {
	t.Parallel()
	mgr := secrets.NewManager()
	secret, err := mgr.Upsert("pathy", "", "12345678901234567890")
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	stub := &stubBroadcaster{}
	proxy := &MITMProxy{}
	proxy.SetSecretsProvider(mgr, stub)

	req, _ := http.NewRequest(http.MethodGet, "http://example.com/"+secret.Placeholder+"?id="+secret.Placeholder, nil)

	proxy.applySecrets(req)

	if req.URL.Path != "/12345678901234567890" {
		t.Fatalf("expected path replaced, got %q", req.URL.Path)
	}
	if req.URL.RawQuery != "id=12345678901234567890" {
		t.Fatalf("expected query replaced, got %q", req.URL.RawQuery)
	}
	gotSecret := mgr.GetAll()["pathy"]
	if gotSecret.Activations != 2 {
		t.Fatalf("expected 2 activations (path + query), got %d", gotSecret.Activations)
	}
	if len(stub.events) != 1 {
		t.Fatalf("expected 1 activation event, got %d", len(stub.events))
	}
	if activations, ok := stub.events[0]["activations"].(int); !ok || activations != 2 {
		t.Fatalf("expected activations 2, got %#v", stub.events[0]["activations"])
	}
}

func TestApplySecretsBodyPlain(t *testing.T) {
	t.Parallel()
	mgr := secrets.NewManager()
	secret, err := mgr.Upsert("beta", "", "s3cr3t")
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	stub := &stubBroadcaster{}
	proxy := &MITMProxy{}
	proxy.SetSecretsProvider(mgr, stub)

	payload := []byte("prefix " + secret.Placeholder + " suffix")
	req, _ := http.NewRequest(http.MethodPost, "http://example.com", io.NopCloser(bytes.NewReader(payload)))
	req.ContentLength = int64(len(payload))
	req.Header.Set("Content-Length", strconv.Itoa(len(payload)))

	proxy.applySecrets(req)

	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read body failed: %v", err)
	}
	if string(body) != "prefix s3cr3t suffix" {
		t.Fatalf("expected body replacement, got %q", string(body))
	}
	if req.Header.Get("Content-Length") != strconv.Itoa(len(body)) {
		t.Fatalf("expected content-length %d, got %s", len(body), req.Header.Get("Content-Length"))
	}
	if mgr.GetAll()["beta"].Activations != 1 {
		t.Fatalf("expected activation count 1")
	}
}

func TestApplySecretsBodyGzip(t *testing.T) {
	t.Parallel()
	mgr := secrets.NewManager()
	secret, err := mgr.Upsert("gamma", "", "value")
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	proxy := &MITMProxy{}
	proxy.SetSecretsProvider(mgr, &stubBroadcaster{})

	plain := []byte("json:" + secret.Placeholder)
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write(plain); err != nil {
		t.Fatalf("gzip write failed: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip close failed: %v", err)
	}

	req, _ := http.NewRequest(http.MethodPost, "http://example.com", io.NopCloser(bytes.NewReader(buf.Bytes())))
	req.Header.Set("Content-Encoding", "gzip")
	req.ContentLength = int64(buf.Len())
	req.Header.Set("Content-Length", strconv.Itoa(buf.Len()))

	proxy.applySecrets(req)

	compressed, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read body failed: %v", err)
	}
	reader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatalf("gzip reader failed: %v", err)
	}
	decompressed, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("gzip read failed: %v", err)
	}
	_ = reader.Close()
	if string(decompressed) != "json:value" {
		t.Fatalf("expected decompressed payload replaced, got %q", string(decompressed))
	}
	if req.Header.Get("Content-Encoding") != "gzip" {
		t.Fatalf("expected content-encoding gzip, got %q", req.Header.Get("Content-Encoding"))
	}
}

func TestApplySecretsBodyDeflate(t *testing.T) {
	t.Parallel()
	mgr := secrets.NewManager()
	secret, err := mgr.Upsert("delta", "", "val")
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	proxy := &MITMProxy{}
	proxy.SetSecretsProvider(mgr, &stubBroadcaster{})

	plain := []byte("payload:" + secret.Placeholder)
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	if _, err := zw.Write(plain); err != nil {
		t.Fatalf("deflate write failed: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("deflate close failed: %v", err)
	}

	req, _ := http.NewRequest(http.MethodPost, "http://example.com", io.NopCloser(bytes.NewReader(buf.Bytes())))
	req.Header.Set("Content-Encoding", "deflate")
	req.ContentLength = int64(buf.Len())
	req.Header.Set("Content-Length", strconv.Itoa(buf.Len()))

	proxy.applySecrets(req)

	compressed, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read body failed: %v", err)
	}
	reader, err := zlib.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatalf("deflate reader failed: %v", err)
	}
	decompressed, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("deflate read failed: %v", err)
	}
	_ = reader.Close()
	if string(decompressed) != "payload:val" {
		t.Fatalf("expected decompressed payload replaced, got %q", string(decompressed))
	}
}

func TestApplySecretsBodyBrotli(t *testing.T) {
	t.Parallel()
	mgr := secrets.NewManager()
	secret, err := mgr.Upsert("epsilon", "", "token")
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	proxy := &MITMProxy{}
	proxy.SetSecretsProvider(mgr, &stubBroadcaster{})

	plain := []byte("bro:" + secret.Placeholder)
	var buf bytes.Buffer
	bw := brotli.NewWriter(&buf)
	if _, err := bw.Write(plain); err != nil {
		t.Fatalf("brotli write failed: %v", err)
	}
	if err := bw.Close(); err != nil {
		t.Fatalf("brotli close failed: %v", err)
	}

	req, _ := http.NewRequest(http.MethodPost, "http://example.com", io.NopCloser(bytes.NewReader(buf.Bytes())))
	req.Header.Set("Content-Encoding", "br")
	req.ContentLength = int64(buf.Len())
	req.Header.Set("Content-Length", strconv.Itoa(buf.Len()))

	proxy.applySecrets(req)

	compressed, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read body failed: %v", err)
	}
	reader := brotli.NewReader(bytes.NewReader(compressed))
	decompressed, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("brotli read failed: %v", err)
	}
	if string(decompressed) != "bro:token" {
		t.Fatalf("expected brotli payload replaced, got %q", string(decompressed))
	}
}

func TestApplySecretsBodyTooLarge(t *testing.T) {
	t.Parallel()
	mgr := secrets.NewManager()
	secret, err := mgr.Upsert("zeta", "", "VALUE")
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	proxy := &MITMProxy{}
	proxy.SetSecretsProvider(mgr, &stubBroadcaster{})

	big := bytes.Repeat([]byte("A"), maxSecretBodyBytes+len(secret.Placeholder)+1)
	copy(big[len(big)-len(secret.Placeholder):], secret.Placeholder)
	req, _ := http.NewRequest(http.MethodPost, "http://example.com", io.NopCloser(bytes.NewReader(big)))
	req.ContentLength = int64(len(big))
	req.Header.Set("Content-Length", strconv.Itoa(len(big)))

	proxy.applySecrets(req)

	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read body failed: %v", err)
	}
	if !bytes.Contains(body, []byte(secret.Placeholder)) {
		t.Fatalf("expected body unchanged when too large")
	}
	if mgr.GetAll()["zeta"].Activations != 0 {
		t.Fatalf("expected no activation increment")
	}
}

func TestApplySecretsUnsupportedEncoding(t *testing.T) {
	t.Parallel()
	mgr := secrets.NewManager()
	secret, err := mgr.Upsert("eta", "", "VALUE")
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	proxy := &MITMProxy{}
	proxy.SetSecretsProvider(mgr, &stubBroadcaster{})

	payload := []byte(secret.Placeholder)
	req, _ := http.NewRequest(http.MethodPost, "http://example.com", io.NopCloser(bytes.NewReader(payload)))
	req.Header.Set("Content-Encoding", "zstd")
	req.ContentLength = int64(len(payload))
	req.Header.Set("Content-Length", strconv.Itoa(len(payload)))

	proxy.applySecrets(req)

	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read body failed: %v", err)
	}
	if string(body) != secret.Placeholder {
		t.Fatalf("expected body unchanged, got %q", string(body))
	}
	if mgr.GetAll()["eta"].Activations != 0 {
		t.Fatalf("expected no activation increment")
	}
}

func TestApplySecretsChunkedBody(t *testing.T) {
	t.Parallel()
	mgr := secrets.NewManager()
	secret, err := mgr.Upsert("theta", "", "VALUE")
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	proxy := &MITMProxy{}
	proxy.SetSecretsProvider(mgr, &stubBroadcaster{})

	payload := []byte(secret.Placeholder)
	req, _ := http.NewRequest(http.MethodPost, "http://example.com", io.NopCloser(bytes.NewReader(payload)))
	req.ContentLength = -1
	req.TransferEncoding = []string{"chunked"}
	req.Header.Set("Transfer-Encoding", "chunked")

	proxy.applySecrets(req)

	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read body failed: %v", err)
	}
	if string(body) != "VALUE" {
		t.Fatalf("expected body replaced, got %q", string(body))
	}
	if req.Header.Get("Content-Length") != strconv.Itoa(len(body)) {
		t.Fatalf("expected content-length set, got %s", req.Header.Get("Content-Length"))
	}
	if len(req.TransferEncoding) != 0 || req.Header.Get("Transfer-Encoding") != "" {
		t.Fatalf("expected transfer-encoding cleared")
	}
}
