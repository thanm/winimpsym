
# winimpsym

This tool helps debug problems in the Go linker relating to handling
of import ("__imp_XXX"), which require some tricky handling in the 
linker's host object loader. 

The tool will scan the specified list of objects, looking for import symbols,
then for each import symbol __imp_X and its target symbol X, it will report
information on definitions (if we have a definition) and on references.

Example:

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

A final section shows the references to import symbols (places in the object where the symbol is undefined):

```
Refs:
 "__imp_CloseHandle":
   0: O=3 S=0 [0x99]
   1: O=16 S=0 [0x76]
 "__imp_CreateEventA":
   0: O=23 S=0 [0x13 0x102]
 "__imp_CreateThread":
   0: O=16 S=0 [0x56]
...

```

Here "O=3" means object with index 3, "S=0" means section index zero, and 0x99 represents the offset within the section targeted by the relocation against the import symbol.
