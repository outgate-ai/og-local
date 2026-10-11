package route

import (
	"errors"
	"net/url"
	"regexp"
	"strings"
)

// Model mirror errors: the mirror is unset or unusable (the gate's mirror_not_configured),
// or a download's path is not a plain relative file path (bad_path).
var (
	ErrNoMirror       = errors.New("no model mirror configured")
	ErrMirrorNotHTTPS = errors.New("mirror is not https")
	ErrMirrorURL      = errors.New("mirror is not a plain base URL")
	ErrBadPath        = errors.New("bad path")
)

var mirrorPathChars = regexp.MustCompile(`^[A-Za-z0-9._/@+-]+$`)

// MirrorBase checks the model mirror's base URL: absolute https (plain http only to
// an AllowHTTP host), no user info, query or fragment. A path prefix is allowed.
func (r *Router) MirrorBase(raw string) (*url.URL, error) {
	if raw == "" {
		return nil, ErrNoMirror
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Opaque != "" {
		return nil, ErrMirrorURL
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !contains(r.AllowHTTP, u.Hostname()) {
			return nil, ErrMirrorNotHTTPS
		}
	default:
		return nil, ErrMirrorNotHTTPS
	}
	if u.User != nil || strings.ContainsAny(raw, "?#") {
		return nil, ErrMirrorURL
	}
	return u, nil
}

// Mirror resolves a download's path under a base MirrorBase accepted (class mirror).
// The path is relative: no leading "/", no empty, "." or ".." segment, only
// [A-Za-z0-9._/@+-].
func Mirror(base *url.URL, path string) (*Destination, error) {
	if !mirrorPath(path) {
		return nil, ErrBadPath
	}
	u, err := url.Parse(strings.TrimRight(base.String(), "/") + "/" + path)
	if err != nil {
		return nil, ErrBadPath
	}
	return &Destination{Kind: Cloud, URL: u, Display: u.Hostname(), Class: ClassMirror}, nil
}

func mirrorPath(p string) bool {
	if p == "" || len(p) > 1024 || strings.HasPrefix(p, "/") || !mirrorPathChars.MatchString(p) {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	return true
}
