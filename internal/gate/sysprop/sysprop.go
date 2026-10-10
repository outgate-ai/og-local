// Package sysprop reads Android system properties. Elsewhere (tests, the host) it
// reads OGL_PROP_<name with dots as underscores> from the environment.
package sysprop

import (
	"os"
	"strconv"
	"strings"
)

func Get(name, def string) string {
	if v := get(name); v != "" {
		return v
	}
	return def
}

func Int(name string, def int) int {
	if n, err := strconv.Atoi(Get(name, "")); err == nil {
		return n
	}
	return def
}

func Bool(name string, def bool) bool {
	switch Get(name, "") {
	case "1", "true", "y", "yes", "on":
		return true
	case "0", "false", "n", "no", "off":
		return false
	}
	return def
}

func envName(name string) string {
	return "OGL_PROP_" + strings.ReplaceAll(name, ".", "_")
}

func fromEnv(name string) string {
	return os.Getenv(envName(name))
}
