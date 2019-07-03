### Compile Dtrace
Open VS2015 development command prompt. (amd64 or i386). 
For dynamic build,
```
nmake -f Makefile.vc [RELEASE=1]
```
For static build
```
nmake -f Makefile.vc STATIC=1 [RELEASE=1]
```
The grammar files (dt_grammar.y and dt_lex.l) where converted in freebsd 12.0. 
### Dtrace testsuite:
For a debug build for AMD64,
open x64 VS2015 development command prompt.
```
nmake -f Makefile.vc
```
Open a bash terminal.
add dtrace.exe location to PATH variable.
```
export PATH=$PATH:<pathtodtrace>
mkdir debug/amd64/test
cd debug/amd64/test
perl ../../../tests/dtrace/dtest.pl -n ../../../tests/dtrace/tst/common
```
if script cant find the dtrace executable, change the location of dtrace.exe in the perl script.