// Package version compares the version strings that advisories and release
// tags use: dotted numbers with an optional pre-release or post-release
// suffix (1.83.7, v4.3.0, 0.32.0rc0, 17.5.1-ee, 1.83.7-stable.patch.1).
//
// Anything it cannot parse is reported as not comparable. Callers must then
// keep the advisory rather than drop it.
package version

import (
	"regexp"
	"strconv"
	"strings"
)

type parsed struct {
	release []int
	// stage is negative for pre-releases, 0 for a final release and positive
	// for post-releases.
	stage    int
	stageNum int
}

var (
	shape      = regexp.MustCompile(`^[vV]?(\d+(?:\.\d+)*)(.*)$`)
	separators = regexp.MustCompile(`^[-._+]+`)
	lastNumber = regexp.MustCompile(`(\d+)\D*$`)
	stages     = []struct {
		pattern *regexp.Regexp
		value   int
	}{
		{regexp.MustCompile(`^dev`), -4},
		{regexp.MustCompile(`^(alpha|a)([^a-z]|$)`), -3},
		{regexp.MustCompile(`^(beta|b)([^a-z]|$)`), -2},
		{regexp.MustCompile(`^(rc|c|pre|preview|nightly)([^a-z]|$)`), -1},
		{regexp.MustCompile(`^(post|patch)([^a-z]|$)`), 1},
	}
)

func parse(text string) (parsed, bool) {
	match := shape.FindStringSubmatch(strings.TrimSpace(text))
	if match == nil {
		return parsed{}, false
	}
	var p parsed
	for _, part := range strings.Split(match[1], ".") {
		n, err := strconv.Atoi(part)
		if err != nil {
			return parsed{}, false
		}
		p.release = append(p.release, n)
	}
	suffix := separators.ReplaceAllString(strings.ToLower(match[2]), "")
	for _, stage := range stages {
		if stage.pattern.MatchString(suffix) {
			p.stage = stage.value
			break
		}
	}
	if number := lastNumber.FindStringSubmatch(suffix); number != nil {
		p.stageNum, _ = strconv.Atoi(number[1])
	}
	return p, true
}

// Compare returns a negative number when a < b, zero when they are equal and
// a positive number when a > b. ok is false when either cannot be parsed.
func Compare(a, b string) (result int, ok bool) {
	left, leftOK := parse(a)
	right, rightOK := parse(b)
	if !leftOK || !rightOK {
		return 0, false
	}
	for i := 0; i < len(left.release) || i < len(right.release); i++ {
		var l, r int
		if i < len(left.release) {
			l = left.release[i]
		}
		if i < len(right.release) {
			r = right.release[i]
		}
		if l != r {
			return l - r, true
		}
	}
	if left.stage != right.stage {
		return left.stage - right.stage, true
	}
	return left.stageNum - right.stageNum, true
}

// SameLine reports whether a and b are on the same release line: the same
// major and minor numbers, as 1.106.6 and 1.106.12 are.
func SameLine(a, b string) bool {
	left, leftOK := parse(a)
	right, rightOK := parse(b)
	return leftOK && rightOK && len(left.release) >= 2 && len(right.release) >= 2 &&
		left.release[0] == right.release[0] && left.release[1] == right.release[1]
}

// Valid reports whether text parses as a version.
func Valid(text string) bool {
	_, ok := parse(text)
	return ok
}

// IsPreRelease reports whether text is a release candidate, nightly or other
// build that precedes a final release.
func IsPreRelease(text string) bool {
	p, ok := parse(text)
	return ok && p.stage < 0
}

// Satisfies reports whether v falls inside a range written as comma-separated
// constraints, such as ">= 0.32.0rc0, <= 0.34.0" or "< 1.106.9". known is
// false when the answer cannot be worked out.
func Satisfies(v, constraints string) (inRange bool, known bool) {
	any := false
	for _, constraint := range strings.Split(constraints, ",") {
		constraint = strings.TrimSpace(constraint)
		if constraint == "" {
			continue
		}
		any = true
		operator, bound := "=", constraint
		for _, candidate := range []string{"<=", ">=", "==", "!=", "<", ">", "="} {
			if strings.HasPrefix(constraint, candidate) {
				operator, bound = candidate, strings.TrimSpace(constraint[len(candidate):])
				break
			}
		}
		comparison, ok := Compare(v, bound)
		if !ok {
			return false, false
		}
		holds := map[string]bool{
			"<": comparison < 0, "<=": comparison <= 0,
			">": comparison > 0, ">=": comparison >= 0,
			"=": comparison == 0, "==": comparison == 0, "!=": comparison != 0,
		}[operator]
		if !holds {
			return false, true
		}
	}
	return any, any
}

// Highest returns the highest final version among tags, without a leading
// "v". Tags that are not versions and pre-releases are ignored. It returns
// "" when no tag qualifies.
func Highest(tags []string) string {
	best := ""
	for _, tag := range tags {
		if !Valid(tag) || IsPreRelease(tag) {
			continue
		}
		if best == "" {
			best = tag
			continue
		}
		if comparison, _ := Compare(tag, best); comparison > 0 {
			best = tag
		}
	}
	return strings.TrimLeft(best, "vV")
}
