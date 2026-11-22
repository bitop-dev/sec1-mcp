package metrics

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTextFormat(t *testing.T) {
	r := New()
	r.Inc("sec1_tool_calls_total", "Tool calls.", "tool", "check_component", "outcome", "ok")
	r.Inc("sec1_tool_calls_total", "Tool calls.", "tool", "check_component", "outcome", "ok")
	r.Inc("sec1_tool_calls_total", "Tool calls.", "tool", "get_advisory", "outcome", "error")
	r.Observe("sec1_tool_duration_seconds", "Tool call duration.", 0.2, "tool", "check_component")
	r.Observe("sec1_tool_duration_seconds", "Tool call duration.", 7, "tool", "check_component")
	r.Observe("sec1_tool_duration_seconds", "Tool call duration.", 500, "tool", "check_component")

	recorder := httptest.NewRecorder()
	r.Handler().ServeHTTP(recorder, httptest.NewRequest("GET", "/metrics", nil))
	text := recorder.Body.String()
	for _, want := range []string{
		"# TYPE sec1_tool_calls_total counter",
		`sec1_tool_calls_total{tool="check_component",outcome="ok"} 2`,
		`sec1_tool_calls_total{tool="get_advisory",outcome="error"} 1`,
		"# TYPE sec1_tool_duration_seconds histogram",
		`sec1_tool_duration_seconds_bucket{tool="check_component",le="0.25"} 1`,
		`sec1_tool_duration_seconds_bucket{tool="check_component",le="10"} 2`,
		`sec1_tool_duration_seconds_bucket{tool="check_component",le="+Inf"} 3`,
		`sec1_tool_duration_seconds_count{tool="check_component"} 3`,
		`sec1_tool_duration_seconds_sum{tool="check_component"} 507.2`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in:\n%s", want, text)
		}
	}
}

func TestLabelValuesAreEscaped(t *testing.T) {
	r := New()
	r.Inc("x_total", "X.", "client", "a\"b\nc")
	if text := r.text(); !strings.Contains(text, `x_total{client="a\"b\nc"} 1`) {
		t.Errorf("label value was not escaped:\n%s", text)
	}
}

func TestNilRegistryRecordsNothing(t *testing.T) {
	var r *Registry
	r.Inc("x_total", "X.")
	r.Observe("y_seconds", "Y.", 1)
	if r.text() != "" {
		t.Error("a nil registry should produce no output")
	}
}
