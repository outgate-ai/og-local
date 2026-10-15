package route

import (
	"encoding/json"
	"errors"
	"net/url"
	"strings"
)

// Tenancy is an app command-queue tenancy (a participant of an Outgate app, from its .ogpkg package):
// where its app's endpoints are and the join token the gate adds to its requests. The gate alone
// holds the token; og-agentd and OGChat only know the tenancy's name.
type Tenancy struct {
	Name        string
	Participant string
	AppID       string
	AppName     string
	Hook        string
	Commands    string
	AuthHeader  string
	Token       string
	// Gen tells one tenancy from a later one of the same name (the store's, internal/gate/appq).
	Gen string
}

// TenancySource opens app tenancies by name: the gate's sealed store (internal/gate/appq). An
// unknown name is ErrUnknownRegion; any other error (storage locked, keystore unavailable) is the
// store's and passes through Resolve as it is.
type TenancySource interface {
	Get(name string) (Tenancy, error)
}

// ErrBadPackage: not an .ogpkg package with a hook endpoint and a join token.
var ErrBadPackage = errors.New("bad package")

// ParsePackage reads the parts of an .ogpkg package (ogpkg/1) the gate uses.
func ParsePackage(b []byte) (Tenancy, error) {
	var p struct {
		App struct {
			AppID     string `json:"appId"`
			Name      string `json:"name"`
			Endpoints struct {
				Hook     string `json:"hook"`
				Commands string `json:"commands"`
			} `json:"endpoints"`
		} `json:"app"`
		Client struct {
			Auth struct {
				Header string `json:"header"`
			} `json:"auth"`
		} `json:"client"`
		Join struct {
			Participant string `json:"participant"`
			Token       string `json:"token"`
		} `json:"join"`
		Issuer struct {
			AppName string `json:"appName"`
		} `json:"issuer"`
	}
	if json.Unmarshal(b, &p) != nil || p.App.Endpoints.Hook == "" || p.Join.Token == "" {
		return Tenancy{}, ErrBadPackage
	}
	if u, err := url.Parse(p.App.Endpoints.Hook); err != nil || u.Host == "" {
		return Tenancy{}, ErrBadPackage
	}
	if strings.ContainsAny(p.Join.Token, "\r\n") {
		return Tenancy{}, ErrBadPackage
	}
	header := p.Client.Auth.Header
	if header == "" {
		header = "X-Outgate-Hook-Token"
	}
	commands := p.App.Endpoints.Commands
	if commands == "" {
		commands = strings.TrimRight(p.App.Endpoints.Hook, "/") + "/commands"
	}
	name := p.App.Name
	if name == "" {
		name = p.Issuer.AppName
	}
	return Tenancy{
		Participant: p.Join.Participant, AppID: p.App.AppID, AppName: name,
		Hook: p.App.Endpoints.Hook, Commands: commands, AuthHeader: header, Token: p.Join.Token,
	}, nil
}
