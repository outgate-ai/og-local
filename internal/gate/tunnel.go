package gate

import "fmt"

// validateTunnelCallers: the tunnel daemon and its launcher share a uid, so their rules name
// both the uid and the SELinux domain that tells them apart.
func (c *Config) validateTunnelCallers() error {
	for _, r := range c.Callers {
		if (r.Class == callerTunnel || r.Class == callerTunnelLauncher) && (r.Domain == "" || r.UID == nil) {
			return fmt.Errorf("callers: a %q rule needs both domain and uid", r.Class)
		}
	}
	return nil
}
