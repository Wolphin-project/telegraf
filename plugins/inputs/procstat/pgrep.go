package procstat

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

type Pgrep struct {
	path string
}

func NewPgrep() (*Pgrep, error) {
	path, err := exec.LookPath("pgrep")
	if err != nil {
		return nil, fmt.Errorf("Could not find pgrep binary: %s", err)
	}
	return &Pgrep{path}, nil
}

func (pg *Pgrep) PidFile(path string) ([]PID, error) {
	args := []string{"-F", path}
	return gather(pg.path, args)
}

func (pg *Pgrep) Pattern(pattern string) ([]PID, error) {
	args := []string{pattern}
	return gather(pg.path, args)
}

func (pg *Pgrep) Uid(user string) ([]PID, error) {
	args := []string{"-u", user}
	return gather(pg.path, args)
}

func (pg *Pgrep) FullPattern(pattern string) ([]PID, error) {
	args := []string{"-f", pattern}
	return gather(pg.path, args)
}

func gather(path string, args []string) ([]PID, error) {
	out, err := run(path, args)
	if err != nil {
		return nil, err
	}

	return parseOutput(out)
}

func run(path string, args []string) (string, error) {
	out, err := exec.Command(path, args...).Output()
	if err != nil {
		return "", fmt.Errorf("Error running %s: %s", path, err)
	}
	return string(out), err
}

func parseOutput(out string) ([]PID, error) {
	pids := []PID{}
	fields := strings.Fields(out)
	for _, field := range fields {
		pid, err := strconv.Atoi(field)
		if err != nil {
			return nil, err
		}
		if err == nil {
			pids = append(pids, PID(pid))
		}
	}
	return pids, nil
}
