// Package metrics is a small registry of counters and histograms that can
// be scraped in the Prometheus text format. It exists so the server needs no
// metrics dependency for the handful of series it exposes.
package metrics

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
)

// buckets are the histogram upper bounds, in seconds. Lookups range from a
// cache hit to a batch that waits its turn for a rate-limited source.
var buckets = []float64{0.05, 0.25, 1, 2.5, 5, 10, 25, 50, 100}

// Registry holds the server's metrics. A nil *Registry is valid and records
// nothing, so callers need not check whether metrics are switched on.
type Registry struct {
	mu         sync.Mutex
	help       map[string]string
	kind       map[string]string
	counters   map[string]float64
	histograms map[string]*histogram
}

type histogram struct {
	counts []uint64 // one per bucket, cumulative on output
	sum    float64
	total  uint64
}

// New returns an empty registry.
func New() *Registry {
	return &Registry{help: map[string]string{}, kind: map[string]string{}, counters: map[string]float64{}, histograms: map[string]*histogram{}}
}

// series builds the key for one labelled series: name{k="v",...}. Labels are
// given as alternating names and values.
func series(name string, labels []string) string {
	if len(labels) == 0 {
		return name
	}
	pairs := make([]string, 0, len(labels)/2)
	for i := 0; i+1 < len(labels); i += 2 {
		value := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(labels[i+1])
		pairs = append(pairs, fmt.Sprintf(`%s="%s"`, labels[i], value))
	}
	return name + "{" + strings.Join(pairs, ",") + "}"
}

// Inc adds one to a counter.
func (r *Registry) Inc(name, help string, labels ...string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.help[name], r.kind[name] = help, "counter"
	r.counters[series(name, labels)]++
}

// Observe records one duration, in seconds, in a histogram.
func (r *Registry) Observe(name, help string, seconds float64, labels ...string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.help[name], r.kind[name] = help, "histogram"
	key := series(name, labels)
	h := r.histograms[key]
	if h == nil {
		h = &histogram{counts: make([]uint64, len(buckets))}
		r.histograms[key] = h
	}
	for i, bound := range buckets {
		if seconds <= bound {
			h.counts[i]++
			break
		}
	}
	h.sum += seconds
	h.total++
}

// Handler serves the metrics in the Prometheus text exposition format.
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_, _ = w.Write([]byte(r.text()))
	})
}

func (r *Registry) text() string {
	if r == nil {
		return ""
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	names := make([]string, 0, len(r.help))
	for name := range r.help {
		names = append(names, name)
	}
	sort.Strings(names)

	var b strings.Builder
	for _, name := range names {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", name, r.help[name], name, r.kind[name])
		if r.kind[name] == "counter" {
			for _, key := range sortedKeys(r.counters, name) {
				fmt.Fprintf(&b, "%s %g\n", key, r.counters[key])
			}
			continue
		}
		for _, key := range sortedKeys(r.histograms, name) {
			h := r.histograms[key]
			labels := strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(key, name), "{"), "}")
			with := func(extra string) string {
				if labels == "" {
					return "{" + extra + "}"
				}
				return "{" + labels + "," + extra + "}"
			}
			var cumulative uint64
			for i, bound := range buckets {
				cumulative += h.counts[i]
				fmt.Fprintf(&b, "%s_bucket%s %d\n", name, with(fmt.Sprintf(`le="%g"`, bound)), cumulative)
			}
			fmt.Fprintf(&b, "%s_bucket%s %d\n", name, with(`le="+Inf"`), h.total)
			suffix := ""
			if labels != "" {
				suffix = "{" + labels + "}"
			}
			fmt.Fprintf(&b, "%s_sum%s %g\n%s_count%s %d\n", name, suffix, h.sum, name, suffix, h.total)
		}
	}
	return b.String()
}

// sortedKeys returns the series of one metric, in a stable order.
func sortedKeys[V any](all map[string]V, name string) []string {
	var keys []string
	for key := range all {
		if key == name || strings.HasPrefix(key, name+"{") {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}
