package launch

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/outgate-ai/og-local/internal/detector"
	"github.com/outgate-ai/og-local/internal/models"
)

// offerDownload reacts to a detector preflight failure by offering to fetch
// the missing artifact. It reports whether a download succeeded and the
// preflight is worth retrying.
func (a *App) offerDownload(ctx context.Context, err error) bool {
	if a.Confirm == nil {
		return false
	}
	switch {
	case errors.Is(err, detector.ErrModelMissing) && a.PullModel != nil:
		m := models.Default()
		if !a.Confirm(fmt.Sprintf("The detection model %s (%s) is not downloaded.\nDownload it now? [Y/n] ", m.Name, humanSize(m.TotalSize()))) {
			return false
		}
		return a.reportPull(a.PullModel(ctx))
	case errors.Is(err, models.ErrRuntimeNotFound) && a.PullRuntime != nil:
		size := models.RuntimeDownloadSize()
		if size == 0 {
			return false
		}
		if !a.Confirm(fmt.Sprintf("The ONNX Runtime library (%s) is missing.\nDownload it now? [Y/n] ", humanSize(size))) {
			return false
		}
		return a.reportPull(a.PullRuntime(ctx))
	}
	return false
}

func (a *App) reportPull(err error) bool {
	if err != nil && a.Stdio.Err != nil {
		_, _ = fmt.Fprintf(a.Stdio.Err, "ogl: download failed: %v\n", err)
	}
	return err == nil
}

func humanSize(n int64) string {
	const mb = 1000 * 1000
	if n >= 1000*mb {
		return fmt.Sprintf("%.1f GB", float64(n)/float64(1000*mb))
	}
	return fmt.Sprintf("%d MB", (n+mb/2)/mb)
}

// confirmFrom builds a [Y/n] prompt (default yes) that only engages when the
// session is interactive; otherwise it declines so scripts keep the fail-fast
// behavior.
func confirmFrom(interactive func() bool, in io.Reader, out io.Writer) func(string) bool {
	return func(msg string) bool {
		if !interactive() {
			return false
		}
		_, _ = fmt.Fprint(out, msg)
		line, err := bufio.NewReader(in).ReadString('\n')
		if err != nil && line == "" {
			return false
		}
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "", "y", "yes":
			return true
		}
		return false
	}
}

func stdinIsTerminal() bool {
	fi, err := os.Stdin.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func progressTo(w io.Writer) models.ProgressFunc {
	return func(f models.File, done, total int64) {
		if total > 0 {
			_, _ = fmt.Fprintf(w, "\r%s %d/%d bytes", f.Path, done, total)
		} else {
			_, _ = fmt.Fprintf(w, "\r%s %d bytes", f.Path, done)
		}
	}
}
