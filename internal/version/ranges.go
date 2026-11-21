package version

import (
	"regexp"
	"strings"
)

// Constraint is one comparison against a version, such as ">= 9.2.0".
type Constraint struct {
	Op      string
	Version string
}

// Clause is a set of constraints that must all hold. A range is one or more
// clauses, any one of which may hold.
type Clause []Constraint

var (
	rangeOperators = []string{"<=", ">=", "==", "!=", "<", ">", "="}
	hyphenRange    = regexp.MustCompile(`([vV]?\d[0-9A-Za-z.+-]*)\s+-\s+([vV]?\d[0-9A-Za-z.+-]*)`)
	operatorGap    = regexp.MustCompile(`(<=|>=|==|!=|<|>|=)\s+`)
	wildcard       = regexp.MustCompile(`(?i)(^|\.)(x|\*|\+)(\.|$)`)
	anyDigit       = regexp.MustCompile(`\d`)
)

// ParseRange reads an affected-version range the way advisories write them.
// Project advisories are free text, so it accepts several styles:
//
//	>= 0.32.0rc0, <= 0.34.0             one clause
//	< 9.0.3, < 8.5.9                    one clause per release line
//	>=9.2.0 <9.2.10 >=9.3.0 <9.3.4      two bounded clauses
//	8.0.0 - 8.3.0                       a hyphen range
//	Grafana Enterprise 8.1.0 - 8.4.5    words are skipped
//
// ok is false when any part cannot be understood, as with "<9.x". The caller
// must then treat the range as unknown, never as empty.
func ParseRange(text string) (clauses []Clause, ok bool) {
	text = hyphenRange.ReplaceAllString(text, ">=$1 <=$2")
	text = strings.ReplaceAll(text, ",", " ")
	text = operatorGap.ReplaceAllString(text, "$1")

	var current Clause
	flush := func() {
		if len(current) > 0 {
			clauses = append(clauses, current)
			current = nil
		}
	}
	for _, token := range strings.Fields(text) {
		if token == "||" || strings.EqualFold(token, "or") {
			flush()
			continue
		}
		if !anyDigit.MatchString(token) {
			continue // a product or edition name
		}
		constraint := Constraint{Op: "=", Version: token}
		for _, operator := range rangeOperators {
			if strings.HasPrefix(token, operator) {
				constraint = Constraint{Op: operator, Version: token[len(operator):]}
				break
			}
		}
		if wildcard.MatchString(constraint.Version) || !Valid(constraint.Version) {
			return nil, false
		}
		// A second bound of the same kind starts a new clause: "< 9.0.3" and
		// "< 8.5.9" are two release lines, not one range.
		if kind := boundKind(constraint.Op); kind != 0 && current.has(kind) || current.has(exact) || (kind == exact && len(current) > 0) {
			flush()
		}
		current = append(current, constraint)
	}
	flush()
	return clauses, len(clauses) > 0
}

const (
	lower = iota + 1
	upper
	exact
)

func boundKind(operator string) int {
	switch operator {
	case ">", ">=":
		return lower
	case "<", "<=":
		return upper
	case "=", "==":
		return exact
	}
	return 0
}

func (c Clause) has(kind int) bool {
	for _, constraint := range c {
		if boundKind(constraint.Op) == kind {
			return true
		}
	}
	return false
}

// Bounded reports whether the clause pins versions down from both sides: it
// has a lower and an upper bound, or names one exact version. A bounded
// clause is a deliberate statement and is taken as written. An open-ended
// one, such as ">= 9.2.0" alone, usually means "until the fix".
func (c Clause) Bounded() bool {
	return c.has(exact) || (c.has(lower) && c.has(upper))
}

// LowerBound returns the version the clause starts at, or "" when it has no
// lower bound.
func (c Clause) LowerBound() string {
	for _, constraint := range c {
		if kind := boundKind(constraint.Op); kind == lower || kind == exact {
			return constraint.Version
		}
	}
	return ""
}

// Contains reports whether v satisfies every constraint of the clause. known
// is false when v cannot be compared.
func (c Clause) Contains(v string) (in bool, known bool) {
	for _, constraint := range c {
		comparison, ok := Compare(v, constraint.Version)
		if !ok {
			return false, false
		}
		holds := map[string]bool{
			"<": comparison < 0, "<=": comparison <= 0,
			">": comparison > 0, ">=": comparison >= 0,
			"=": comparison == 0, "==": comparison == 0, "!=": comparison != 0,
		}[constraint.Op]
		if !holds {
			return false, true
		}
	}
	return true, true
}

// List pulls the versions out of free text such as "9.3.2, 9.2.8, 8.5.16" or
// "4.0.0+". Anything that is not a version is skipped.
func List(text string) []string {
	var versions []string
	for _, token := range strings.FieldsFunc(text, func(r rune) bool { return r == ',' || r == ' ' || r == ';' }) {
		token = strings.TrimRight(strings.TrimLeft(token, "<>=!~^"), "+")
		if token != "" && !wildcard.MatchString(token) && Valid(token) {
			versions = append(versions, token)
		}
	}
	return versions
}
