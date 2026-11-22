package server

import (
	"bufio"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Tokens holds the bearer tokens that may call the server over HTTP, each
// with the name of the team or client it was issued to. The name is what
// appears in the audit log and the metrics; the token itself never does.
//
// Tokens come from a single shared secret, from a file of named tokens, or
// both. The file is read again when it changes, so a token can be added or
// revoked without restarting the server.
type Tokens struct {
	shared [sha256.Size]byte
	hasOne bool
	path   string

	mu      sync.Mutex
	named   map[string][sha256.Size]byte
	modTime time.Time
	checked time.Time
}

const (
	sharedName      = "shared"
	minTokenLength  = 16
	recheckInterval = 5 * time.Second
)

var tokenName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,39}$`)

// NewTokens builds the token set. shared is a single token for everyone, and
// path is a file of named tokens; either may be empty. The file is read now,
// so that a mistake in it stops the server at start-up.
func NewTokens(shared, path string) (*Tokens, error) {
	t := &Tokens{path: path}
	if shared != "" {
		t.shared, t.hasOne = sha256.Sum256([]byte(shared)), true
	}
	if path != "" {
		if err := t.load(); err != nil {
			return nil, err
		}
	}
	return t, nil
}

// load reads the token file. Each line is a name, whitespace, and a token.
// Blank lines and lines starting with # are ignored.
func (t *Tokens) load() error {
	file, err := os.Open(t.path)
	if err != nil {
		return fmt.Errorf("token file: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("token file: %w", err)
	}
	named := map[string][sha256.Size]byte{}
	scanner := bufio.NewScanner(file)
	for number := 1; scanner.Scan(); number++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		// Errors name the line, never its contents: the file holds secrets.
		switch {
		case len(fields) != 2:
			return fmt.Errorf("token file %s line %d: expected a name and a token", t.path, number)
		case !tokenName.MatchString(fields[0]) || fields[0] == sharedName || fields[0] == anonymous:
			return fmt.Errorf("token file %s line %d: the name must be 1 to 40 letters, digits, dots, dashes or underscores, and not %q or %q", t.path, number, sharedName, anonymous)
		case len(fields[1]) < minTokenLength:
			return fmt.Errorf("token file %s line %d: the token must be at least %d characters", t.path, number, minTokenLength)
		}
		if _, duplicate := named[fields[0]]; duplicate {
			return fmt.Errorf("token file %s line %d: the name %q is used twice", t.path, number, fields[0])
		}
		named[fields[0]] = sha256.Sum256([]byte(fields[1]))
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("token file: %w", err)
	}
	t.named, t.modTime, t.checked = named, info.ModTime(), time.Now()
	return nil
}

// refresh re-reads the file when it has changed. A file that has become
// unreadable or invalid leaves the previous tokens in force, so a bad edit
// does not lock everyone out.
func (t *Tokens) refresh() {
	if t.path == "" || time.Since(t.checked) < recheckInterval {
		return
	}
	t.checked = time.Now()
	if info, err := os.Stat(t.path); err == nil && !info.ModTime().Equal(t.modTime) {
		_ = t.load()
	}
}

// Required reports whether callers must present a token.
func (t *Tokens) Required() bool {
	return t != nil && (t.hasOne || t.path != "")
}

// Lookup returns the name a token was issued to. Every stored token is
// compared, each in constant time, so the answer takes the same time
// whichever token matches or none.
func (t *Tokens) Lookup(presented string) (name string, ok bool) {
	if t == nil || presented == "" {
		return "", false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.refresh()
	hashed := sha256.Sum256([]byte(presented))
	if t.hasOne && subtle.ConstantTimeCompare(hashed[:], t.shared[:]) == 1 {
		name, ok = sharedName, true
	}
	for candidate, stored := range t.named {
		if subtle.ConstantTimeCompare(hashed[:], stored[:]) == 1 {
			name, ok = candidate, true
		}
	}
	return name, ok
}

// Names returns how many named tokens are loaded.
func (t *Tokens) Names() int {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.named)
}
