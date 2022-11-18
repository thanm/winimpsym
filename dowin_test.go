package main

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestBasic(t *testing.T) {
	tdir := t.TempDir()

	// Do a build of . into <tmpdir>/out.exe
	exe := filepath.Join(tdir, "out.exe")
	gotoolpath := filepath.Join(runtime.GOROOT(), "bin", "go")
	cmd := exec.Command(gotoolpath, "build", "-o", exe, ".")
	t.Logf("cmd: %+v\n", cmd)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Logf("build: %s\n", b)
		t.Fatalf("build error: %v", err)
	}

	// do a default dump run, if that doesn't succeed no point in doing more.
	op := filepath.Join("testdata", "sample.o")
	cmd = exec.Command(DefaultDumper, "-t", op)
	t.Logf("cmd: %+v\n", cmd)
	if _, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("objdump -t run failed")
	}

	// Now run executable on test obj.
	cmd = exec.Command(exe, "-i="+op, "-watch=foo,bar,_errno")
	t.Logf("cmd: %+v\n", cmd)
	var output string
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Logf("run: %s\n", b)
		t.Fatalf("run error: %v", err)
	} else {
		output = string(b)
	}

	// Check for a few critical strings.
	lines := strings.Split(output, "\n")
	drb := []string{}
	cap := false
	for _, line := range lines {
		if line == "Def/ref breakdown:" {
			cap = true
			continue
		}
		if cap {
			if line == "" {
				break
			}
			drb = append(drb, line)
		}
	}

	t.Logf("drb: %+v\n", drb)
	want0 := " \"__acrt_iob_func\":  refimp"
	if !strings.Contains(drb[0], want0) {
		t.Errorf("drb[0] got %s want %s", drb[0], want0)
	}
	wantlast := " \"_errno\":  refimp"
	cpl := drb[len(drb)-1]
	if !strings.Contains(cpl, wantlast) {
		t.Errorf("drb[last] got %s want %s", cpl, wantlast)
	}
}
