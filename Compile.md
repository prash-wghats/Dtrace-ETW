Open VS2015 development command prompt. (amd64 or i386). 
For dynamic build,
```
nmake -f Makefile.vc [RELEASE=1]
```
For static build
```
nmake -f Makefile.vc STATIC=1 [RELEASE=1]
```
