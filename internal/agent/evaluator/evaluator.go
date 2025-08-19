package evaluator

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

func normalizeValue(val interface{}) string {
	if val == nil {
		return ""
	}
	if b, ok := val.(bool); ok {
		return map[bool]string{true: "1", false: "0"}[b]
	}
	valStr := strings.TrimSpace(fmt.Sprintf("%v", val))
	switch valStr {
	case "true", "enabled", "up", "on":
		return "1"
	case "false", "disabled", "down", "off":
		return "0"
	}
	return strings.ToLower(valStr)
}

func Evaluate(actual string, expect map[string]interface{}) bool {
	actualNorm := normalizeValue(actual)
	if strings.Contains(actualNorm, "\n") {
		actualNorm = strings.Split(actualNorm, "\n")[0]
	}

	if eq, ok := expect["equals"]; ok {
		return actualNorm == normalizeValue(eq)
	}
	if cont, ok := expect["contains"]; ok {
		return strings.Contains(actualNorm, strings.ToLower(cont.(string)))
	}
	if contAny, ok := expect["contains_any"]; ok {
		for _, item := range contAny.([]interface{}) {
			if strings.Contains(actualNorm, strings.ToLower(item.(string))) {
				return true
			}
		}
		return false
	}
	if exists, ok := expect["exists"]; ok {
		return (actualNorm != "") == exists.(bool)
	}
	if gte, ok := expect["gte"]; ok {
		re := regexp.MustCompile(`\d+`)
		m := re.FindString(actualNorm)
		if m == "" {
			return false
		}
		val, _ := strconv.Atoi(m)
		return val >= gte.(int)
	}
	return false
}