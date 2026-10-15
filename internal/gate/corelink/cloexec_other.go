//go:build !linux

package corelink

// closeOnExecAll is Linux's (Android's) concern; elsewhere the helper isn't used.
func closeOnExecAll() []string { return nil }
