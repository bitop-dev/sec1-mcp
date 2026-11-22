// Package intel looks up security advisories for one software component
// across OSV, GitHub repository advisories, NVD, CISA's Known Exploited
// Vulnerabilities catalog and EPSS, and combines the answers.
package intel

import (
	"bytes"
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

// Endpoints are the base URLs of the services the client calls. They are
// fixed in production; tests point them at a local server. No tool input is
// ever used as a host, so a caller cannot make the server fetch an arbitrary
// address.
type Endpoints struct {
	OSV, GitHub, NVD, NVDProducts, KEV, EPSS, PyPI, NPM, GitLab string
	// Lifecycle is endoflife.date's product API. Nuclei and Metasploit are
	// the published indexes of scanner templates and exploit modules.
	Lifecycle, Nuclei, Metasploit string
}

// DefaultEndpoints returns the real services.
func DefaultEndpoints() Endpoints {
	return Endpoints{
		OSV:         "https://api.osv.dev",
		GitHub:      "https://api.github.com",
		NVD:         "https://services.nvd.nist.gov/rest/json/cves/2.0",
		NVDProducts: "https://services.nvd.nist.gov/rest/json/cpes/2.0",
		KEV:         "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
		EPSS:        "https://api.first.org/data/v1/epss",
		PyPI:        "https://pypi.org",
		NPM:         "https://registry.npmjs.org",
		GitLab:      "https://gitlab.com",
		Lifecycle:   "https://endoflife.date/api/v1/products",
		Nuclei:      "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json",
		Metasploit:  "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json",
	}
}

// How long each service's answers are reused. Advisory feeds change slowly
// next to how often an agent repeats a question, and NVD and GitHub both
// rate-limit unauthenticated callers.
const (
	ttlOSV       = 15 * time.Minute
	ttlGitHub    = 30 * time.Minute
	ttlNVD       = time.Hour
	ttlKEV       = time.Hour
	ttlEPSS      = 6 * time.Hour
	ttlLatest    = 30 * time.Minute
	ttlFeeds     = 30 * time.Minute
	ttlLifecycle = 12 * time.Hour
	ttlExploits  = 24 * time.Hour
)

const maxResponseBytes = 32 << 20

// Client fetches from the advisory services, with caching, retries and
// pacing for NVD.
type Client struct {
	HTTP      *http.Client
	Endpoints Endpoints
	Cache     *Cache
	// GitHubToken and NVDKey are optional and only raise rate limits.
	GitHubToken string
	NVDKey      string
	// NVDPause is the gap kept between NVD requests.
	NVDPause time.Duration
	// RetryDelays are the waits before the second and third attempts.
	RetryDelays []time.Duration
	// Observe, when set, is told about every lookup: which service it went
	// to, and whether it was answered from the cache, succeeded or failed.
	Observe func(source, outcome string)

	nvdMu   sync.Mutex
	nvdLast time.Time

	kevMu    sync.Mutex
	kevAt    time.Time
	kevIndex *kevIndex

	exploitMu     sync.Mutex
	exploitAt     time.Time
	exploitIndex  *exploitIndex
	exploitFailed []string
}

// NewClient returns a client for the real services. Credentials are read
// from the environment and are never logged or cached.
func NewClient(cacheDir string) *Client {
	c := &Client{
		HTTP:        &http.Client{Timeout: 30 * time.Second},
		Endpoints:   DefaultEndpoints(),
		Cache:       NewCache(cacheDir),
		GitHubToken: os.Getenv("GITHUB_TOKEN"),
		NVDKey:      os.Getenv("NVD_API_KEY"),
		NVDPause:    6500 * time.Millisecond,
		RetryDelays: []time.Duration{time.Second, 3 * time.Second},
	}
	if c.NVDKey != "" {
		c.NVDPause = 700 * time.Millisecond
	}
	return c
}

type request struct {
	method  string
	url     string
	body    any
	headers map[string]string
	ttl     time.Duration
	// paced requests wait their turn in the NVD queue.
	paced bool
}

// statusError is an HTTP response outside the 2xx range.
type statusError struct {
	Code int
	URL  string
}

func (e *statusError) Error() string {
	return fmt.Sprintf("%s returned HTTP %d", e.URL, e.Code)
}

func isNotFound(err error) bool {
	status, ok := err.(*statusError)
	return ok && status.Code == http.StatusNotFound
}

var linkNext = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

// fetch performs the request and decodes the JSON response into out. It
// returns the URL of the next page when the response carries a Link header.
func (c *Client) fetch(ctx context.Context, r request, out any) (next string, err error) {
	if r.method == "" {
		r.method = http.MethodGet
	}
	var body []byte
	if r.body != nil {
		if body, err = json.Marshal(r.body); err != nil {
			return "", err
		}
	}
	key := r.method + " " + r.url + "\n" + string(body)
	if entry, ok := c.Cache.get(key, r.ttl); ok {
		c.observe(r.url, "cached")
		return entry.Next, json.Unmarshal(entry.Body, out)
	}

	response, next, err := c.raw(ctx, r, body)
	if err != nil {
		return "", err
	}
	if err := json.Unmarshal(response, out); err != nil {
		return "", fmt.Errorf("%s: unreadable response: %w", r.url, err)
	}
	c.Cache.put(key, cacheEntry{At: time.Now(), Next: next, Body: response})
	return next, nil
}

// cachedRaw returns a URL's body as bytes, from the cache when it is fresh.
// It is for responses that are not JSON.
func (c *Client) cachedRaw(ctx context.Context, target string, ttl time.Duration) ([]byte, error) {
	key := "GET-raw " + target
	if entry, ok := c.Cache.get(key, ttl); ok {
		return entry.Body, nil
	}
	data, _, err := c.raw(ctx, request{url: target, headers: map[string]string{"Accept": "application/atom+xml, application/rss+xml, application/xml, text/xml"}}, nil)
	if err != nil {
		return nil, err
	}
	c.Cache.put(key, cacheEntry{At: time.Now(), Body: data})
	return data, nil
}

// raw performs the request with retries and returns the response body
// uncached. Callers that want caching use fetch.
func (c *Client) raw(ctx context.Context, r request, body []byte) (response []byte, next string, err error) {
	if r.method == "" {
		r.method = http.MethodGet
	}
	for attempt := 0; ; attempt++ {
		if r.paced {
			if err := c.waitForNVD(ctx); err != nil {
				return nil, "", err
			}
		}
		response, next, err = c.once(ctx, r, body)
		if err == nil {
			c.observe(r.url, "ok")
			return response, next, nil
		}
		status, isStatus := err.(*statusError)
		transient := !isStatus || status.Code == http.StatusTooManyRequests || status.Code >= 500
		if !transient || attempt >= len(c.RetryDelays) || ctx.Err() != nil {
			c.observe(r.url, "error")
			return nil, "", err
		}
		select {
		case <-ctx.Done():
			return nil, "", ctx.Err()
		case <-time.After(c.RetryDelays[attempt]):
		}
	}
}

func (c *Client) once(ctx context.Context, r request, body []byte) ([]byte, string, error) {
	httpRequest, err := http.NewRequestWithContext(ctx, r.method, r.url, bytes.NewReader(body))
	if err != nil {
		return nil, "", err
	}
	httpRequest.Header.Set("User-Agent", "stack-watch-mcp")
	httpRequest.Header.Set("Accept", "application/json")
	if body != nil {
		httpRequest.Header.Set("Content-Type", "application/json")
	}
	for name, value := range r.headers {
		httpRequest.Header.Set(name, value)
	}
	response, err := c.HTTP.Do(httpRequest)
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w", r.url, err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return nil, "", &statusError{Code: response.StatusCode, URL: r.url}
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes))
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w", r.url, err)
	}
	next := ""
	if match := linkNext.FindStringSubmatch(response.Header.Get("Link")); match != nil {
		next = match[1]
	}
	return data, next, nil
}

// observe reports a lookup to the Observe hook, naming the service by its
// host so that the number of distinct names stays small.
func (c *Client) observe(target, outcome string) {
	if c.Observe == nil {
		return
	}
	source := "unknown"
	if parsed, err := url.Parse(target); err == nil && parsed.Host != "" {
		source = parsed.Hostname()
	}
	c.Observe(source, outcome)
}

// waitForNVD blocks until this request may go to NVD. Holding the lock while
// waiting is what queues concurrent callers one behind another.
func (c *Client) waitForNVD(ctx context.Context) error {
	c.nvdMu.Lock()
	defer c.nvdMu.Unlock()
	if wait := time.Until(c.nvdLast.Add(c.NVDPause)); wait > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
	c.nvdLast = time.Now()
	return nil
}

func (c *Client) githubHeaders() map[string]string {
	headers := map[string]string{"Accept": "application/vnd.github+json"}
	if c.GitHubToken != "" {
		headers["Authorization"] = "Bearer " + c.GitHubToken
	}
	return headers
}

const (
	// maxCacheBytes bounds the in-memory cache, so a server that runs for
	// months does not grow without limit.
	maxCacheBytes = 128 << 20
	// Files in the disk cache older than this are deleted. No lookup reuses
	// an answer that old.
	diskCacheMaxAge = 48 * time.Hour
	pruneInterval   = time.Hour
)

// Cache keeps responses in memory and, when it has a directory, on disk, so
// that short-lived server processes still benefit from earlier lookups. The
// memory side holds the most recently used responses up to a fixed size.
type Cache struct {
	mu        sync.Mutex
	items     map[string]*list.Element
	recent    *list.List // most recently used at the front
	bytes     int
	maxBytes  int
	dir       string
	lastPrune time.Time
}

type cacheItem struct {
	key   string
	entry cacheEntry
}

type cacheEntry struct {
	At   time.Time `json:"at"`
	Next string    `json:"next,omitempty"`
	Body []byte    `json:"body"`
}

// NewCache returns a cache. An empty dir keeps it in memory only.
func NewCache(dir string) *Cache {
	if dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			dir = ""
		}
	}
	return &Cache{items: map[string]*list.Element{}, recent: list.New(), maxBytes: maxCacheBytes, dir: dir}
}

func (c *Cache) path(key string) string {
	sum := sha256.Sum256([]byte(key))
	return filepath.Join(c.dir, hex.EncodeToString(sum[:])+".json")
}

func (c *Cache) get(key string, ttl time.Duration) (cacheEntry, bool) {
	if c == nil || ttl <= 0 {
		return cacheEntry{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	var entry cacheEntry
	if element, ok := c.items[key]; ok {
		c.recent.MoveToFront(element)
		entry = element.Value.(*cacheItem).entry
	} else if c.dir != "" {
		data, err := os.ReadFile(c.path(key))
		if err != nil || json.Unmarshal(data, &entry) != nil {
			return cacheEntry{}, false
		}
		c.remember(key, entry)
	} else {
		return cacheEntry{}, false
	}
	if time.Since(entry.At) > ttl {
		return cacheEntry{}, false
	}
	return entry, true
}

func (c *Cache) put(key string, entry cacheEntry) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.remember(key, entry)
	if c.dir == "" {
		return
	}
	// A failed disk write only costs a later cache miss.
	if data, err := json.Marshal(entry); err == nil {
		temporary := c.path(key) + ".tmp"
		if os.WriteFile(temporary, data, 0o600) == nil {
			_ = os.Rename(temporary, c.path(key))
		}
	}
	if time.Since(c.lastPrune) > pruneInterval {
		c.lastPrune = time.Now()
		go pruneDisk(c.dir)
	}
}

// remember stores an entry in memory and evicts the least recently used
// ones until the cache fits its size again. The caller holds the lock.
func (c *Cache) remember(key string, entry cacheEntry) {
	if element, ok := c.items[key]; ok {
		c.bytes -= len(element.Value.(*cacheItem).entry.Body)
		c.recent.Remove(element)
		delete(c.items, key)
	}
	// A response bigger than the whole cache is served from disk each time.
	if len(entry.Body) > c.maxBytes {
		return
	}
	c.items[key] = c.recent.PushFront(&cacheItem{key, entry})
	c.bytes += len(entry.Body)
	for c.bytes > c.maxBytes {
		oldest := c.recent.Back()
		item := oldest.Value.(*cacheItem)
		c.bytes -= len(item.entry.Body)
		c.recent.Remove(oldest)
		delete(c.items, item.key)
	}
}

// pruneDisk deletes cache files too old for any lookup to reuse.
func pruneDisk(dir string) {
	files, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-diskCacheMaxAge)
	for _, file := range files {
		if info, err := file.Info(); err == nil && !file.IsDir() && info.ModTime().Before(cutoff) {
			_ = os.Remove(filepath.Join(dir, file.Name()))
		}
	}
}
