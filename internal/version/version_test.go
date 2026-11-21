package version

import "testing"

func sign(t *testing.T, a, b string) int {
	t.Helper()
	result, ok := Compare(a, b)
	if !ok {
		t.Fatalf("Compare(%q, %q) could not compare", a, b)
	}
	switch {
	case result < 0:
		return -1
	case result > 0:
		return 1
	}
	return 0
}

func TestCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.10.0", "1.9.0", 1},
		{"1.83.7", "1.83.10", -1},
		{"17.5", "17.5.0", 0},
		{"v4.3.0", "4.3.0", 0},
		{"0.32.0rc0", "0.32.0", -1},
		{"0.32.0rc1", "0.32.0rc0", 1},
		{"1.83.7-nightly", "1.83.7", -1},
		{"1.83.7-stable", "1.83.7", 0},
		{"1.83.7-stable.patch.1", "1.83.7-stable", 1},
		{"17.5.1-ee", "17.5.1", 0},
	}
	for _, c := range cases {
		if got := sign(t, c.a, c.b); got != c.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestCompareRejectsNonVersions(t *testing.T) {
	for _, text := range []string{"helm/onyx-0.9.56", "latest", ""} {
		if _, ok := Compare(text, "1.0.0"); ok {
			t.Errorf("Compare(%q, ...) should not be comparable", text)
		}
	}
}

func TestSatisfies(t *testing.T) {
	cases := []struct {
		version, constraints string
		inRange, known       bool
	}{
		{"1.83.6", "< 1.83.7", true, true},
		{"1.83.7", "< 1.83.7", false, true},
		{"0.33.0", ">= 0.32.0rc0, <= 0.34.0", true, true},
		{"0.34.1", ">= 0.32.0rc0, <= 0.34.0", false, true},
		{"2.0.0", "= 2.0.0", true, true},
		{"latest", "< 1.83.7", false, false},
		{"1.0.0", "", false, false},
	}
	for _, c := range cases {
		inRange, known := Satisfies(c.version, c.constraints)
		if inRange != c.inRange || known != c.known {
			t.Errorf("Satisfies(%q, %q) = %v, %v; want %v, %v", c.version, c.constraints, inRange, known, c.inRange, c.known)
		}
	}
}

func TestSameLine(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"1.106.6", "1.106.12", true},
		{"1.106.12", "1.108.6", false},
		{"v1.110.2", "1.110.0-rc.2", true},
		{"2", "2.0.1", false},
		{"latest", "1.0.0", false},
	}
	for _, c := range cases {
		if got := SameLine(c.a, c.b); got != c.want {
			t.Errorf("SameLine(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestHighest(t *testing.T) {
	cases := []struct {
		tags []string
		want string
	}{
		{[]string{"v1.112.0-dev.2", "v1.111.0-rc.3", "v1.110.2", "v1.109.3"}, "1.110.2"},
		{[]string{"helm/onyx-0.9.56", "cli-latest", "cli/v1.5.0", "v5.1.3", "v5.1.2"}, "5.1.3"},
		{[]string{"v19.6.1-ee", "v19.6.0-rc43-ee", "v19.5.8-ee"}, "19.6.1-ee"},
		{[]string{"nightly", "latest"}, ""},
	}
	for _, c := range cases {
		if got := Highest(c.tags); got != c.want {
			t.Errorf("Highest(%v) = %q, want %q", c.tags, got, c.want)
		}
	}
}
