package peer

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Packages maps app uids to package names from the system's packages.list (one line
// per package: "<name> <uid> <debuggable> <data dir> <seinfo> <gids>…"), re-read
// when the file changes. App uids are assigned at install, so they are never cached
// longer than the file is unchanged.
type Packages struct {
	Path string

	mu      sync.Mutex
	modTime time.Time
	size    int64
	byUID   map[uint32][]string
}

// DefaultPackagesList is where Android keeps it.
const DefaultPackagesList = "/data/system/packages.list"

// Names returns the packages sharing uid (usually one), in any user: packages.list
// holds user 0's uids, and a user's uid is user*100000 + the app id.
func (p *Packages) Names(uid uint32) []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.refresh()
	return p.byUID[uid%100000]
}

func (p *Packages) refresh() {
	fi, err := os.Stat(p.Path)
	if err != nil {
		p.byUID = nil
		return
	}
	if p.byUID != nil && fi.ModTime().Equal(p.modTime) && fi.Size() == p.size {
		return
	}
	f, err := os.Open(p.Path)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	byUID := map[uint32][]string{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		uid, err := strconv.ParseUint(fields[1], 10, 32)
		if err != nil {
			continue
		}
		appID := uint32(uid % 100000)
		byUID[appID] = append(byUID[appID], fields[0])
	}
	p.byUID, p.modTime, p.size = byUID, fi.ModTime(), fi.Size()
}
