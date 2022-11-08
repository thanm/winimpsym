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

// TODO:
// - write an objdump -tldr dumper that puts out excerpts of the disassembly

// Overview: given a set of object files, look for definitions and references
// to import symbols.

var inputsflag = flag.String("i", "", "Comma-separated list of input files (omit to read from stdin)")
var allsymsflag = flag.Bool("all", false, "Process all syms, not just import syms")
var watchsymsflag = flag.String("watch", "", "Comma-separated list of additional symbols to include in analysis")

var watched map[string]bool

// [ 0](sec  1)(fl 0x00)(ty   0)(scl   3) (nx 1) 0x00000000 .text
var symre = regexp.MustCompile(`^\[\s*\d+\]\(sec\s+(\-?\d+)\)\(fl\s+\S+\)\(ty\s+\S+\)\(scl\s+\d+\)\s*\(nx\s+\S+\)\s+(\S+)\s+(\S+)\s*$`)

const imppref = "__imp_"

type defrefmask uint32

const (
	defrefnone defrefmask = 0
	defbase    defrefmask = 1 << iota // base symbol X is defined
	refbase                           // base symbol X is referenced
	defimp                            // import symbol __imp_X is defined
	refimp                            // import symbol __imp_X is referenced
	dsameobj                          // defimp and defbase in same obj
)

func (drm defrefmask) String() string {
	res := ""
	if drm&defbase != 0 {
		res += " defbase"
	}
	if drm&refbase != 0 {
		res += " refbase"
	}
	if drm&defimp != 0 {
		res += " defimp"
	}
	if drm&refimp != 0 {
		res += " refimp"
	}
	if drm&dsameobj != 0 {
		res += " sameobj"
	}
	return res
}

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
	// def/ref disposition for symbol X
	defref map[string]defrefmask
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
		defref: make(map[string]defrefmask),
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
	dumpref := func(sname string) {
		fmt.Fprintf(sb, " %q:\n", sname)
		rl := s.refs[sname]
		for j, ri := range rl {
			def := " "
			if ri.def {
				def = "*"
			}
			fmt.Fprintf(sb, "  %s%d: O=%d S=%d %s\n", def,
				j, ri.objidx, ri.secidx, hexlist(ri.offsets))
		}
	}
	if len(s.refs) != 0 {
		refs := make([]string, 0, len(s.refs))
		for k := range s.refs {
			refs = append(refs, k)
		}
		sort.Strings(refs)
		fmt.Fprintf(sb, "Refs:\n")
		for _, v := range refs {
			// Dump symbol first followed by import symbol.
			if strings.HasPrefix(v, imppref) {
				continue
			}
			dumpref(v)
			iv := imppref + v
			if _, ok := s.refs[iv]; ok {
				dumpref(iv)
			}
		}
	}
	dr := make([]string, 0, len(s.defref))
	for k := range s.defref {
		dr = append(dr, k)
	}
	sort.Strings(dr)
	fmt.Fprintf(sb, "Def/ref breakdown:\n")
	for _, v := range dr {
		fmt.Fprintf(sb, " %q: %s\n", v, s.defref[v])
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
		if strings.HasPrefix(k, imppref) {
			x := k[len(imppref):]
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
	defs := make(map[string]struct{})
	// [ 0](sec  1)(fl 0x00)(ty   0)(scl   3) (nx 1) 0x00000000 .text
	symre := regexp.MustCompile(`^\[\s*\d+\]\(sec\s+(\-?\d+)\)\(fl\s+\S+\)\(ty\s+\S+\)\(scl\s+\d+\)\s*\(nx\s+\S+\)\s+(\S+)\s+(\S+)\s*$`)
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
			s.maskAddDef(sname)
			defs[sname] = struct{}{}
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
		if !def {
			s.maskAddRef(sname)
		}
	}
	for k := range defs {
		if strings.HasPrefix(k, imppref) {
			base := k[len(imppref):]
			if _, ok := defs[base]; ok {
				s.defref[base] = s.defref[base] | dsameobj
			}
		}
	}
	return nil
}

func (s *state) maskAddDef(sname string) {
	if strings.HasPrefix(sname, imppref) {
		x := sname[len(imppref):]
		s.defref[x] = s.defref[x] | defimp
	} else {
		s.defref[sname] = s.defref[sname] | defbase
	}
}

func (s *state) maskAddRef(sname string) {
	if strings.HasPrefix(sname, imppref) {
		x := sname[len(imppref):]
		s.defref[x] = s.defref[x] | refimp
	} else {
		s.defref[sname] = s.defref[sname] | refbase
	}
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

type objinfo struct {
	objidx int
	oname  string
}

func (s *state) collectWatchedFiles() []objinfo {
	oinds := make(map[int]bool)
	for k := range watched {
		rl := s.refs[k]
		for _, ri := range rl {
			oinds[ri.objidx] = true
		}
	}
	res := make([]objinfo, 0, len(oinds))
	for oidx := range oinds {
		res = append(res, objinfo{objidx: oidx, oname: s.objs[oidx]})
	}
	sort.Slice(res, func(i, j int) bool {
		if res[i].oname != res[j].oname {
			return res[i].oname < res[j].oname
		}
		return res[i].objidx < res[j].objidx
	})
	return res
}

func (s *state) dumpWatched() error {

	// Figure out which files we're ging to e
	ofiles := s.collectWatchedFiles()

	// Dump excerpts from each file.
	for _, of := range ofiles {
		ofile := of.oname
		cmd := exec.Command("llvm-objdump-14",
			"-l", // line numbers
			"-d", // assembly
			"-r", // relocations
			ofile)
		out, err := cmd.Output()
		if err != nil {
			return fmt.Errorf("running llvm-objdump-14 on %s: %v", ofile, err)
		}
		fmt.Printf("\nexcerpts from 'llvm-objdump-14 -ldr %s`\n", ofile)
		if err := s.emitExcerpts(string(out), of.objidx); err != nil {
			return err
		}
	}
	return nil
}

func (s *state) emitExcerpts(content string, oidx int) error {
	// 0000000000000000 <makeEvent>:
	var fnstre = regexp.MustCompile(`^\S+\s+\<(\S+)\>\:\s*$`)
	// 000000000000009b:  IMAGE_REL_AMD64_REL32	printf
	var relocre = regexp.MustCompile(`^\s+(\S+)\:\s+IMAGE_\S+\s+(\S+)\s*$`)

	fnLine := 0
	lines := strings.Split(content, "\n")
	painted := make(map[int]bool)
	oimap := make(map[int]int)
	ofmap := make(map[int]int)
	fnmap := make(map[int]int)
	for i := range lines {
		line := lines[i]
		m := fnstre.FindStringSubmatch(line)
		if len(m) != 0 {
			fnLine = i
			continue
		}
		m = relocre.FindStringSubmatch(line)
		if len(m) == 0 {
			continue
		}
		off := m[1]
		fn := m[2]
		if !watched[fn] {
			continue
		}
		var offset int
		if n, err := fmt.Sscanf(off, "%x", &offset); n != 1 || err != nil {
			return fmt.Errorf("bad offset %s", off)
		}
		ri, rerr := s.findRefInfo(fn, offset, oidx)
		if rerr != nil {
			return rerr
		}
		oimap[i] = ri.objidx
		ofmap[i] = offset
		fnmap[i] = fnLine
		painted[i] = true
	}
	for i := range lines {
		if !painted[i] {
			continue
		}
		oi := oimap[i]
		of := ofmap[i]
		fn := fnmap[i]
		fmt.Printf("\n=-= ref O%d off=0x%x:\n", oi, of)
		// func
		fmt.Printf("%d: %s\n...\n", fn, lines[fn])
		// reloc, couple of lines before and after
		for ci := i - 2; ci <= i+2; ci++ {
			if ci > 0 && ci < len(lines) {
				fmt.Printf("%d: %s\n", ci, lines[ci])
			}
		}
	}
	return nil
}

func (s *state) findRefInfo(fn string, offset, oidx int) (*refinfo, error) {
	rl := s.refs[fn]
	for k := range rl {
		ri := &rl[k]
		if ri.objidx != oidx {
			continue
		}
		for _, of := range ri.offsets {
			if of == offset {
				// Found.
				return ri, nil
			}
		}
		return nil, fmt.Errorf("could not find offset %x in refinfo for fn=%s",
			offset, fn)
	}
	return nil, fmt.Errorf("could not find refinfo for fn=%s of=%x", fn, offset)
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
			watched[imppref+s] = true
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
	fmt.Fprintf(os.Stdout, "state: %s\n", s.String())
	if len(watched) != 0 {
		if err := s.dumpWatched(); err != nil {
			fatal("dumping watched syms: %v", err)
		}
	}
}
