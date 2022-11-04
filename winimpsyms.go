// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
)

// Overview: given a set of object files, look for definitions and references
// to import symbols.

var inputsflag = flag.String("i", "", "Comma-separated list of input files (omit to read from stdin)")
var allsymsflag = flag.Bool("all", false, "Process all syms, not just import syms")
var watchsymsflag = flag.String("watch", "", "Comma-separated list of additional symbols to include in analysis")
var watched map[string]bool

// [ 0](sec  1)(fl 0x00)(ty   0)(scl   3) (nx 1) 0x00000000 .text
var symre = regexp.MustCompile(`^\[\s*\d+\]\(sec\s+(\-?\d+)\)\(fl\s+\S+\)\(ty\s+\S+\)\(scl\s+\d+\)\s*\(nx\s+\S+\)\s+(\S+)\s+(\S+)\s*$`)

type definfo struct {
	objidx int
	secidx int
	value  int
}

type reflist []refinfo

type refinfo struct {
	objidx  int
	secidx  int
	offsets []int
	def     bool
}

type secinfo struct {
	objidx int
	name   string
	size   int
	idx    int
}

type state struct {
	// objects
	objs []string
	// path info for objects
	paths []string
	// section table, map
	sects  []secinfo
	secmap map[string]int
	// Maps import symbol to def info.
	defs map[string]definfo
	// Maps import symbol to list of ref infos.
	refs map[string]reflist
	// list of all interesting symbols, generated in pass 1.
	all map[string]bool
	// scanner
	scanner *bufio.Scanner
	// current obj idx
	objidx int
}

func newState(objs []string) *state {
	return &state{
		objs:   objs,
		secmap: make(map[string]int),
		defs:   make(map[string]definfo),
		refs:   make(map[string]reflist),
		all:    make(map[string]bool),
	}
}

func (s *state) String() string {
	sb := &strings.Builder{}
	fmt.Fprintf(sb, "Objects:\n")
	for i := range s.objs {
		fmt.Fprintf(sb, " O%d: %s %s\n", i, s.objs[i], s.paths[i])
	}
	fmt.Fprintf(sb, "Sections:\n")
	for _, sn := range s.sects {
		fmt.Fprintf(sb, " O%d: %d %q 0x%x\n",
			sn.objidx, sn.idx, sn.name, sn.size)
	}
	if len(s.defs) != 0 {
		defs := make([]string, 0, len(s.defs))
		for k := range s.defs {
			defs = append(defs, k)
		}
		sort.Strings(defs)
		fmt.Fprintf(sb, "Defs:\n")
		for k, v := range defs {
			di := s.defs[v]
			fmt.Fprintf(sb, " %d: %q obj=%d sec=%d val=0x%x\n",
				k, v, di.objidx, di.secidx, di.value)
		}
	}
	hexlist := func(vals []int) string {
		sb := &strings.Builder{}
		sb.WriteString("[")
		sp := ""
		for _, v := range vals {
			fmt.Fprintf(sb, "%s0x%x", sp, v)
			sp = " "
		}
		sb.WriteString("]")
		return sb.String()
	}
	if len(s.refs) != 0 {
		refs := make([]string, 0, len(s.refs))
		for k := range s.refs {
			refs = append(refs, k)
		}
		sort.Strings(refs)
		fmt.Fprintf(sb, "Refs:\n")
		for _, v := range refs {
			rl := s.refs[v]
			fmt.Fprintf(sb, " %q:\n", v)
			for j, ri := range rl {
				def := " "
				if ri.def {
					def = "*"
				}
				fmt.Fprintf(sb, "  %s%d: O=%d S=%d %s\n", def,
					j, ri.objidx, ri.secidx, hexlist(ri.offsets))
			}
		}
	}
	return sb.String()
}

// pass1 looks just at the symbol table for the specified object. Here
// the idea is to build up a list of all import symbols.
func (s *state) pass1(infile string) error {
	// kick off command
	cmd := exec.Command("llvm-objdump-14", "-t", infile)
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("running llvm-objdump-14 on %s: %v", infile, err)
	}

	// process the output
	s.scanner = bufio.NewScanner(strings.NewReader(string(out)))
	for s.scanner.Scan() {
		line := s.scanner.Text()
		if line == "SYMBOL TABLE:" {
			for s.scanner.Scan() {
				line := s.scanner.Text()
				if strings.HasPrefix(line, "AUX ") {
					continue
				}
				if line == "" {
					break
				}
				m := symre.FindStringSubmatch(line)
				if len(m) == 0 {
					return fmt.Errorf("bad line %s in symtab", line)
				}
				sname := m[3]
				if !s.isInterestingSym(sname) {
					continue
				}
				s.all[sname] = true
			}
		}
	}
	return nil
}

// Expand out set of interesting symbols from __imp_X to include X as well.
func (s *state) pass2() {
	keys := make([]string, 0, len(s.all))
	for k := range s.all {
		keys = append(keys, k)
	}
	for _, k := range keys {
		if strings.HasPrefix(k, "__imp_") {
			x := k[len("__imp_"):]
			s.all[x] = true
		}
	}
}

func (s *state) pass3(infile string) error {
	// kick off command
	cmd := exec.Command("llvm-objdump-14",
		"-h", // section headers
		"-t", // symbols
		"-r", // relocations
		"--section=.text",
		"--section=.data",
		"--section=.bss",
		"--section=.rdata",
		"--section=.xdata", infile)
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("running llvm-objdump-14 on %s: %v", infile, err)
	}

	// digest output
	if err := s.digest(string(out)); err != nil {
		return err
	}

	// try to derive path info
	pi := s.pathinfo(infile)
	s.paths = append(s.paths, pi)
	return nil
}

func (s *state) pathinfo(infile string) string {
	if !strings.HasSuffix(infile, ".o") {
		return ""
	}
	txtfile := infile[:len(infile)-1] + "txt"
	if content, err := os.ReadFile(txtfile); err != nil {
		return ""
	} else {
		lines := strings.Split(string(content), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "pn: ") {
				return line[4:]
			}
		}
	}
	return ""
}

func (s *state) digest(content string) error {
	s.scanner = bufio.NewScanner(strings.NewReader(content))
	for s.scanner.Scan() {
		line := s.scanner.Text()
		if line == "Sections:" {
			if err := s.readSections(); err != nil {
				return err
			}
		}
		if line == "SYMBOL TABLE:" {
			if err := s.readSymtab(); err != nil {
				return err
			}
		}
		if strings.HasPrefix(line, "RELOCATION RECORDS FOR [") {
			if err := s.readRelocations(line); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *state) isInterestingSym(sname string) bool {
	return strings.HasPrefix(sname, "__imp") ||
		*allsymsflag || watched[sname] || s.all[sname]
}

func (s *state) readSymtab() error {
	// [ 0](sec  1)(fl 0x00)(ty   0)(scl   3) (nx 1) 0x00000000 .text
	symre := regexp.MustCompile(`^\[\s*\d+\]\(sec\s+(\-?\d+)\)\(fl\s+\S+\)\(ty\s+\S+\)\(scl\s+\d+\)\s*\(nx\s+\S+\)\s+(\S+)\s+(\S+)\s*$`)
	for s.scanner.Scan() {
		line := s.scanner.Text()
		if strings.HasPrefix(line, "AUX ") {
			continue
		}
		if line == "" {
			return nil
		}
		m := symre.FindStringSubmatch(line)
		if len(m) == 0 {
			return fmt.Errorf("bad line %s in sections table", line)
		}
		var secidx int
		if n, err := fmt.Sscanf(m[1], "%d", &secidx); n != 1 || err != nil {
			return fmt.Errorf("can't parse sec idx in line %s in symtab", line)
		}
		var value int
		if n, err := fmt.Sscanf(m[2], "0x%x", &value); n != 1 || err != nil {
			return fmt.Errorf("can't parse value in line %s in symtab", line)
		}
		sname := m[3]
		if !s.isInterestingSym(sname) {
			continue
		}
		def := false
		if secidx != 0 {
			// This is a definition.
			di := definfo{
				objidx: s.objidx,
				secidx: secidx,
				value:  value,
			}
			if _, ok := s.defs[sname]; ok {
				panic("resolve collision here")
			}
			s.defs[sname] = di
			def = true
		}
		// now add reference. Can't fill in secidx until we look
		// at relocations.
		ri := refinfo{
			objidx: s.objidx,
			secidx: secidx,
			def:    def,
		}
		sl := s.refs[sname]
		sl = append(sl, ri)
		s.refs[sname] = sl
	}
	return nil
}

func (s *state) readRelocations(rline string) error {
	// Determine section.
	secre := regexp.MustCompile(`RELOCATION RECORDS FOR \[(\S+)\]:$`)
	m := secre.FindStringSubmatch(rline)
	if len(m) == 0 {
		return fmt.Errorf("bad relocations line %s", rline)
	}
	// skip preamble
	s.scanner.Scan()
	// read the relocs
	relre := regexp.MustCompile(`^(\S+)\s+(\S+)\s+(\S+)\s*`)
	for s.scanner.Scan() {
		line := s.scanner.Text()
		if line == "" {
			return nil
		}
		m := relre.FindStringSubmatch(line)
		if len(m) == 0 {
			return fmt.Errorf("bad line %s in relocs", line)
		}
		soff := m[1]
		//styp := m[2]
		sval := m[3]
		if !s.isInterestingSym(sval) {
			continue
		}
		var off int
		if n, err := fmt.Sscanf(soff, "%x", &off); n != 1 || err != nil {
			return fmt.Errorf("can't parse offset in line %s relocs", line)
		}
		// Locate ref entry
		rl, ok := s.refs[sval]
		if !ok {
			return fmt.Errorf("can't find refs entry in %s", line)
		}
		// Walk the ref list backwards, stopping when we hit end of obj.
		rln := len(rl)
		found := false
		for i := range rl {
			ri := &rl[rln-i-1]
			if ri.objidx != s.objidx {
				break
			}
			found = true
			ri.offsets = append(ri.offsets, off)
		}
		if !found {
			return fmt.Errorf("could not find ref info for reloc %s", line)
		}
	}
	return nil
}

func (s *state) readSections() error {
	s.scanner.Scan() // advance past preamble
	secre := regexp.MustCompile(`^\s+([0-9]+)\s+(\S+)\s+(\S+)\s+.*`)
	for s.scanner.Scan() {
		line := s.scanner.Text()
		if line == "" {
			return nil
		}
		m := secre.FindStringSubmatch(line)
		if len(m) == 0 {
			return fmt.Errorf("bad line %s in sections table", line)
		}
		sidx := m[1]
		sname := m[2]
		ssz := m[3]
		var ssiz int
		var sindex int
		if n, err := fmt.Sscanf(ssz, "%x", &ssiz); n != 1 || err != nil {
			return fmt.Errorf("can't parse sec size in line %s in sections table", line)
		}
		if n, err := fmt.Sscanf(sidx, "%d", &sindex); n != 1 || err != nil {
			return fmt.Errorf("can't parse idx in line %s in sections table", line)
		}
		s.secmap[sname] = len(s.sects)
		s.sects = append(s.sects,
			secinfo{
				objidx: s.objidx,
				name:   sname,
				size:   ssiz,
				idx:    sindex,
			})
	}
	return nil
}

func usage(msg string) {
	if len(msg) > 0 {
		fmt.Fprintf(os.Stderr, "error: %s\n", msg)
	}
	fmt.Fprintf(os.Stderr, "usage: winimpsyms [flags] -i=X,Y,...,Z\n")
	flag.PrintDefaults()
	os.Exit(2)
}

func fatal(s string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, s, a...)
	fmt.Fprintf(os.Stderr, "\n")
	os.Exit(1)
}

func main() {
	flag.Parse()
	if *inputsflag == "" {
		usage("supply input files with -i option")
	}
	watched = make(map[string]bool)
	if *watchsymsflag != "" {
		for _, s := range strings.Split(*watchsymsflag, ",") {
			watched[s] = true
		}
	}
	infiles := strings.Split(*inputsflag, ",")
	s := newState(infiles)
	for k, ifile := range infiles {
		s.objidx = k
		if err := s.pass1(ifile); err != nil {
			fatal("reading %s: %v", ifile, err)
		}
	}
	s.pass2()
	for k, ifile := range infiles {
		s.objidx = k
		if err := s.pass3(ifile); err != nil {
			fatal("reading %s: %v", ifile, err)
		}
	}
	fmt.Fprintf(os.Stderr, "state: %s\n", s.String())
}
