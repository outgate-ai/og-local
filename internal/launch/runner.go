package launch

import (
	"context"
	"errors"
	"os/exec"
)

type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, argv, env []string, stdio Stdio) (int, error) {
	if len(argv) == 0 {
		return 1, errors.New("launch: empty command")
	}
	bin, err := resolveAgent(ctx, argv[0], env, exec.LookPath, runShell)
	if err != nil {
		return 1, err
	}
	cmd := exec.CommandContext(ctx, bin, argv[1:]...) //nolint:gosec // argv is the agent command the user asked ogl to run.
	cmd.Env = env
	cmd.Stdin = stdio.In
	cmd.Stdout = stdio.Out
	cmd.Stderr = stdio.Err

	err = cmd.Run()
	if err == nil {
		return 0, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode(), nil
	}
	return 1, err
}
