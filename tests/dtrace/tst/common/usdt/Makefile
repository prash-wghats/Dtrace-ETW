all: main livelib.so deadlib.so

main: main.o prov.o
	cc -o main main.o

main.o: main.c
	cc -c main.c


livelib.so: livelib.o prov.o
	cc -z defs -G -o livelib.so livelib.o prov.o -lc

livelib.o: livelib.c prov.h
	cc -c livelib.c

prov.o: livelib.o prov.d
	/e/Repos/Dtrace-ETW/debug/amd64/obj/../bin/dtrace.exe -G -s prov.d livelib.o

prov.h: prov.d
	/e/Repos/Dtrace-ETW/debug/amd64/obj/../bin/dtrace.exe -h -s prov.d


deadlib.so: deadlib.o
	cc -z defs -G -o deadlib.so deadlib.o -lc

deadlib.o: deadlib.c
	cc -c deadlib.c

clean:
	rm -f main.o livelib.o prov.o prov.h deadlib.o

clobber: clean
	rm -f main livelib.so deadlib.so
