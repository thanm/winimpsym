
# winimpsym

This tool helps debug problems in the Go linker relating to handling
of import ("__imp_XXX"), which require some tricky handling in the 
linker's host object loader. 

The tool will scan the specified list of objects, looking for import symbols,
then for each import symbol __imp_X and its target symbol X, it will report
information on definitions (if we have a definition) and on references.
Objects are read by shelling out to an external objdump program (defaults
to llvm-objdump). A "-watch" flag can be used to seed the list of symbols
to inspect (if a symbol is on the watch list, we'll look for defs and
refs even if it has no import symbol).

In this example, three host objects (possibly derived from a Go linker
run passing the "-capturehostobjs" debugging flag) are passed in for
inspection, with a request to watch "_errno"):

```
$ go build .
./winimpsym -watch=_errno -i=obj1.o,obj2.o,obj3.o > report.txt
```

The report shows a listing of the objects:

```
state: Objects:
 O0: obj1.o
 O1: obj2.o
 O2: obj3.o
```

then a listing of their sections:

```
Sections:
 O0: 0 ".text" 0xe27
 O0: 1 ".data" 0x0
 O0: 2 ".bss" 0x0
 O0: 3 ".xdata" 0x1cc
 O1: 0 ".text" 0xb9
 O1: 1 ".data" 0x0
 O1: 2 ".bss" 0x0
 O1: 3 ".xdata" 0x18
 O1: 4 ".rdata" 0x1b
 O2: 0 ".text" 0x37
 O2: 1 ".data" 0x0
 O2: 2 ".bss" 0x0
 O2: 3 ".xdata" 0x8
 O2: 4 ".rdata" 0xd
```

Next comes a blurb describing import symbol definitions:

```
Defs:
 0: "__imp___acrt_iob_func" obj=38 sec=2 val=0x0
 1: "__imp___p__acmdln" obj=67 sec=2 val=0x0
 2: "__imp___p__commode" obj=64 sec=2 val=0x0
```

Here "obj" is the object index, section is the section index, and value is the symbol value.

The next section shows references and definitions of import symbols and their base symbols, along with the places in the object where the symbol is def/ref takes place. 

```
Defs:
 0: "__acrt_iob_func" obj=116 sec=1 val=0x0
 1: "__imp___acrt_iob_func" obj=116 sec=2 val=0x0
...
Refs:
 "__imp_CloseHandle":
   0: O=3 S=0 [0x99]
   1: O=16 S=0 [0x76]
 "__imp_CreateEventA":
   0: O=23 S=0 [0x13 0x102]
 "__imp_CreateThread":
   0: O=16 S=0 [0x56]
 "__imp__lock_file":
  *0: O=117 S=2 []
...
```

Here "O=3" means object with index 3, "S=0" means section index zero, and 0x99 represents the offset within the section targeted by the relocation against the import symbol.

The next section is a summary of how a given symbol X is referred to, via the following tags:

```
refimp   reference to import symbol 
defimp   definition of import symbol
refbase  reference to base symbol
defbase  definition of base symbol
sameobj  definition of both import symbol and base in same object
```

Example:

```
Def/ref breakdown:
 "WaitForSingleObject":  refimp
 "WideCharToMultiByte":  refimp
 "__acrt_iob_func":  defbase refbase defimp refimp sameobj
 "__initenv":  refimp
 "__p__acmdln":  defbase refbase defimp sameobj
 ...
```

A final section shows excerpts from the assembly dump for each reference:

```
excerpts from 'llvm-objdump-14 -ldr /tmp/xxx/captured-obj-10.o`

=-= ref O11 off=0xa6:
69: 0000000000000060 <cTest>:
...
97: ; C:\workdir/go/misc/cgo/test/test.go:80
98:       a4: ff 15 00 00 00 00            	callq	*(%rip)                 # 0xaa <cTest+0x4a>
99: 		00000000000000a6:  IMAGE_REL_AMD64_REL32	__imp___acrt_iob_func
100:       aa: 48 89 c1                     	movq	%rax, %rcx
101:       ad: 48 83 c4 48                  	addq	$72, %rsp

```

This provides information on the nature of the reference, e.g. the flavor of the relocation and the instruction to which it applies.
