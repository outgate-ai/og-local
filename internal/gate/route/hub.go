package route

import (
	"errors"
	"net/url"
	"regexp"
	"strings"
)

// HubOrigin is Hugging Face, where model downloads come from while no mirror is configured.
const HubOrigin = "https://huggingface.co"

// ErrBadRepo: a Hugging Face download names no "owner/name" repository or no pinned
// commit (40 lowercase hex). Branches and tags are refused: they move.
var ErrBadRepo = errors.New("bad repo or revision")

var (
	hubRepo     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,95}/[A-Za-z0-9][A-Za-z0-9._-]{0,95}$`)
	hubRevision = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

// Hub resolves file path of model repository repo at commit revision under base
// (HubOrigin, or a test server): base/<repo>/resolve/<revision>/<path> (class mirror).
func Hub(base *url.URL, repo, revision, path string) (*Destination, error) {
	if !hubRepo.MatchString(repo) || !hubRevision.MatchString(revision) {
		return nil, ErrBadRepo
	}
	if !mirrorPath(path) {
		return nil, ErrBadPath
	}
	u, err := url.Parse(strings.TrimRight(base.String(), "/") + "/" + repo + "/resolve/" + revision + "/" + path)
	if err != nil {
		return nil, ErrBadPath
	}
	return &Destination{Kind: Cloud, URL: u, Display: u.Hostname(), Class: ClassMirror}, nil
}

// HubRedirect says whether a Hugging Face download may follow a redirect to u: https,
// to base's host or to Hugging Face's own domains (huggingface.co, hf.co and their
// subdomains, where the file CDNs live).
func HubRedirect(base, u *url.URL) bool {
	if u.Scheme != "https" || u.User != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if host == strings.ToLower(base.Hostname()) {
		return true
	}
	for _, d := range []string{"huggingface.co", "hf.co"} {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}
