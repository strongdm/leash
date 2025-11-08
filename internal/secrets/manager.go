package secrets

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"sync"
)

var (
	idRegex                 = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)
	placeholderAlphabet     = []byte("abcdefghijklmnopqrstuvwxyz0123456789")
	errInvalidPlaceholderCh = errors.New("invalid placeholder length")
)

const minPlaceholderLength = 32

const (
	maxPlaceholderAttempts = 64
)

// ErrInvalidID indicates the provided identifier failed validation.
var ErrInvalidID = errors.New("invalid id")

// ErrNotFound is returned when a secret cannot be located.
var ErrNotFound = errors.New("secret not found")

// ErrConflict indicates an operation would overwrite an existing secret.
var ErrConflict = errors.New("secret already exists")

// Secret represents an immutable snapshot of an in-memory secret.
type Secret struct {
	ID          string
	Value       string
	Placeholder string
	Activations int
}

type secretEntry struct {
	id          string
	value       string
	placeholder string
	activations int
}

func (e *secretEntry) snapshot() Secret {
	return Secret{
		ID:          e.id,
		Value:       e.value,
		Placeholder: e.placeholder,
		Activations: e.activations,
	}
}

// PlaceholderSnapshot provides a lookup record for placeholder replacement.
type PlaceholderSnapshot struct {
	ID    string
	Value string
}

// Snapshot captures a consistent view of the manager state.
type Snapshot struct {
	Secrets      map[string]Secret
	Placeholders map[string]PlaceholderSnapshot
}

// Manager stores secrets in-memory with concurrency safety.
type Manager struct {
	mu               sync.RWMutex
	secrets          map[string]*secretEntry
	placeholderIndex map[string]string
}

// NewManager constructs an empty Manager instance.
func NewManager() *Manager {
	return &Manager{
		secrets:          make(map[string]*secretEntry),
		placeholderIndex: make(map[string]string),
	}
}

// GetAll returns a copy of the secret map keyed by ID.
func (m *Manager) GetAll() map[string]Secret {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make(map[string]Secret, len(m.secrets))
	for id, entry := range m.secrets {
		out[id] = entry.snapshot()
	}
	return out
}

// Snapshot returns the full secret set along with placeholder lookups.
func (m *Manager) Snapshot() Snapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()

	secrets := make(map[string]Secret, len(m.secrets))
	placeholders := make(map[string]PlaceholderSnapshot, len(m.placeholderIndex))

	for id, entry := range m.secrets {
		secret := entry.snapshot()
		secrets[id] = secret
		placeholders[secret.Placeholder] = PlaceholderSnapshot{
			ID:    secret.ID,
			Value: secret.Value,
		}
	}

	return Snapshot{
		Secrets:      secrets,
		Placeholders: placeholders,
	}
}

// Upsert creates, updates, or renames a secret and returns the resulting state.
func (m *Manager) Upsert(pathID, bodyID, value string) (Secret, error) {
	canonicalPathID := strings.TrimSpace(pathID)
	bodyID = strings.TrimSpace(bodyID)

	targetID := bodyID
	if targetID == "" {
		targetID = canonicalPathID
	}
	targetID = strings.TrimSpace(targetID)

	if targetID == "" {
		return Secret{}, ErrInvalidID
	}
	if !idRegex.MatchString(targetID) {
		return Secret{}, ErrInvalidID
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	var existing *secretEntry
	var ok bool
	if canonicalPathID != "" {
		existing, ok = m.secrets[canonicalPathID]
	}
	switch {
	case ok:
		return m.updateExisting(existing, canonicalPathID, targetID, value)
	default:
		return m.createNew(targetID, value)
	}
}

// Delete removes a secret by ID.
func (m *Manager) Delete(id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return ErrInvalidID
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	entry, ok := m.secrets[id]
	if !ok {
		return ErrNotFound
	}

	delete(m.placeholderIndex, entry.placeholder)
	delete(m.secrets, id)
	return nil
}

// ReplaceStats increments activation counts for the provided ids.
// Returns a map of id -> total activations after the increment.
func (m *Manager) ReplaceStats(increments map[string]int) map[string]int {
	if len(increments) == 0 {
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	updated := make(map[string]int, len(increments))
	for id, delta := range increments {
		if delta <= 0 {
			continue
		}
		entry, ok := m.secrets[id]
		if !ok {
			continue
		}
		entry.activations += delta
		updated[id] = entry.activations
	}
	if len(updated) == 0 {
		return nil
	}
	return updated
}

// LookupByPlaceholder resolves the secret for the provided placeholder.
func (m *Manager) LookupByPlaceholder(placeholder string) (id string, value string, ok bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	id, ok = m.placeholderIndex[placeholder]
	if !ok {
		return "", "", false
	}
	entry := m.secrets[id]
	if entry == nil {
		return "", "", false
	}
	return entry.id, entry.value, true
}

func (m *Manager) updateExisting(entry *secretEntry, originalID, targetID, value string) (Secret, error) {
	if entry == nil {
		return Secret{}, ErrNotFound
	}

	// Handle rename semantics first.
	if targetID != originalID {
		if _, exists := m.secrets[targetID]; exists {
			return Secret{}, ErrConflict
		}
		delete(m.secrets, originalID)
		entry.id = targetID
		m.secrets[targetID] = entry
		// Update placeholder index to point at the new id.
		if entry.placeholder != "" {
			m.placeholderIndex[entry.placeholder] = targetID
		}
	}

	// Regenerate placeholder when value changes.
	if entry.value != value {
		oldPlaceholder := entry.placeholder
		placeholder, err := m.uniquePlaceholder(len(value), oldPlaceholder)
		if err != nil {
			return Secret{}, err
		}
		entry.placeholder = placeholder
		entry.value = value
		if oldPlaceholder != "" {
			delete(m.placeholderIndex, oldPlaceholder)
		}
		m.placeholderIndex[placeholder] = entry.id
	} else {
		entry.value = value
	}

	return entry.snapshot(), nil
}

func (m *Manager) createNew(id, value string) (Secret, error) {
	if _, exists := m.secrets[id]; exists {
		return Secret{}, ErrConflict
	}
	placeholder, err := m.uniquePlaceholder(len(value), "")
	if err != nil {
		return Secret{}, err
	}
	entry := &secretEntry{
		id:          id,
		value:       value,
		placeholder: placeholder,
	}
	m.secrets[id] = entry
	m.placeholderIndex[placeholder] = id
	return entry.snapshot(), nil
}

func (m *Manager) uniquePlaceholder(length int, current string) (string, error) {
	if length == 0 {
		if current != "" {
			delete(m.placeholderIndex, current)
		}
		return "", nil
	}
	if length < minPlaceholderLength {
		length = minPlaceholderLength
	}

	for i := 0; i < maxPlaceholderAttempts; i++ {
		placeholder, err := randomPlaceholder(length)
		if err != nil {
			return "", err
		}
		if placeholder == current {
			continue
		}
		if _, exists := m.placeholderIndex[placeholder]; exists {
			continue
		}
		return placeholder, nil
	}
	return "", fmt.Errorf("failed to generate unique placeholder after %d attempts", maxPlaceholderAttempts)
}

func randomPlaceholder(length int) (string, error) {
	if length < 0 {
		return "", errInvalidPlaceholderCh
	}
	if length == 0 {
		return "", nil
	}
	builder := strings.Builder{}
	builder.Grow(length)
	max := big.NewInt(int64(len(placeholderAlphabet)))

	for i := 0; i < length; i++ {
		idx, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		builder.WriteByte(placeholderAlphabet[idx.Int64()])
	}
	return builder.String(), nil
}
