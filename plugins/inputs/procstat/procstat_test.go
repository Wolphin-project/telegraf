package procstat

import (
	"fmt"
	"os"
	"testing"

	"github.com/influxdata/telegraf/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type TestPgrep struct {
	pids []PID
	err  error
}

func (pg *TestPgrep) PidFile(path string) ([]PID, error) {
	return pg.pids, pg.err
}

func (pg *TestPgrep) Pattern(pattern string) ([]PID, error) {
	return pg.pids, pg.err
}

func (pg *TestPgrep) Uid(user string) ([]PID, error) {
	return pg.pids, pg.err
}

func (pg *TestPgrep) FullPattern(pattern string) ([]PID, error) {
	return pg.pids, pg.err
}

func TestGatherExe(t *testing.T) {
	var acc testutil.Accumulator
	pid := PID(os.Getpid())
	pgrep := &TestPgrep{pids: []PID{pid}}

	p := Procstat{
		Exe:         "foo",
		pidGatherer: pgrep,
	}
	require.NoError(t, p.Gather(&acc))

	assert.True(t, acc.HasTag("procstat", "process_name"))
	assert.Equal(t, "foo", acc.TagValue("procstat", "exe"))
	assert.True(t, acc.HasInt32Field("procstat", "pid"))
	assert.True(t, acc.HasFloatField("procstat", "cpu_time_user"))
}

func TestGatherUser(t *testing.T) {
	var acc testutil.Accumulator
	pid := PID(os.Getpid())
	pgrep := &TestPgrep{pids: []PID{pid}}

	p := Procstat{
		User:        "ada",
		pidGatherer: pgrep,
	}
	require.NoError(t, p.Gather(&acc))

	assert.True(t, acc.HasTag("procstat", "process_name"))
	assert.Equal(t, "ada", acc.TagValue("procstat", "user"))
	assert.True(t, acc.HasInt32Field("procstat", "pid"))
	assert.True(t, acc.HasFloatField("procstat", "cpu_time_user"))
}

func TestGatherPidTag(t *testing.T) {
	var acc testutil.Accumulator
	pid := PID(os.Getpid())
	pgrep := &TestPgrep{pids: []PID{pid}}

	p := Procstat{
		PidFile:     "/foo",
		PidTag:      true,
		pidGatherer: pgrep,
	}
	require.NoError(t, p.Gather(&acc))

	assert.Equal(t, "/foo", acc.TagValue("procstat", "pidfile"))
	assert.True(t, acc.HasFloatField("procstat", "cpu_time_user"))
	assert.False(t, acc.HasFloatField("procstat", "cpu_usage"))
}

func TestGatherSecondPass(t *testing.T) {
	var acc testutil.Accumulator
	pid := PID(os.Getpid())
	pgrep := &TestPgrep{pids: []PID{pid}}

	p := Procstat{
		Pattern:     "foo",
		PidTag:      true,
		pidGatherer: pgrep,
	}
	require.NoError(t, p.Gather(&acc))
	require.NoError(t, p.Gather(&acc))

	assert.Equal(t, "foo", acc.TagValue("procstat", "pattern"))
	assert.True(t, acc.HasFloatField("procstat", "cpu_time_user"))
	assert.True(t, acc.HasFloatField("procstat", "cpu_usage"))
}

func TestGatherPIDGathererError(t *testing.T) {
	var acc testutil.Accumulator
	pgrep := &TestPgrep{err: fmt.Errorf("err")}

	p := Procstat{
		pidGatherer: pgrep,
	}
	require.Error(t, p.Gather(&acc))
}
