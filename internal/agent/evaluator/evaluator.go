package evaluator

import (
	"fmt"
	"regexp"
	"strings"
)

func Evaluate(actual string, expect map[string]interface{}) (bool, string) {
	a := strings.TrimSpace(actual)
	if strings.HasPrefix(a, "ERROR:") {
		return false, a
	}
	// equals
	if v, ok := expect["equals"]; ok {
		exp := strings.TrimSpace(fmt.Sprintf("%v", v))
		if strings.EqualFold(a, exp) {
			return true, ""
		}
		return false, fmt.Sprintf("expected equals %q, got %q", exp, a)
	}
	// contains
	if v, ok := expect["contains"]; ok {
		exp := strings.ToLower(fmt.Sprintf("%v", v))
		if strings.Contains(strings.ToLower(a), exp) {
			return true, ""
		}
		return false, fmt.Sprintf("expected contains %q", v)
	}
	// in
	if v, ok := expect["in"]; ok {
		if arr, ok := v.([]interface{}); ok {
			for _, ev := range arr {
				if strings.EqualFold(a, strings.TrimSpace(fmt.Sprintf("%v", ev))) {
					return true, ""
				}
			}
			return false, fmt.Sprintf("expected one of %v, got %q", arr, a)
		}
	}
	// regex
	if v, ok := expect["regex"]; ok {
		pat := fmt.Sprintf("%v", v)
		re, err := regexp.Compile(pat)
		if err != nil {
			return false, "bad regex: " + err.Error()
		}
		if re.MatchString(a) {
			return true, ""
		}
		return false, fmt.Sprintf("expected match /%s/", pat)
	}
	return false, "no supported operator in expect"
}