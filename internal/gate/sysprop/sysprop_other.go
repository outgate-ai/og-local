//go:build !android || !cgo

package sysprop

func get(name string) string { return fromEnv(name) }
