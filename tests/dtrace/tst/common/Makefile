LINK.c = gcc
COMPILE.d = E:/Repos/WorkArea/cc/DTrace-0.1/debug/amd64/bin/dtrace.exe -G
DTRACE = E:/Repos/WorkArea/cc/DTrace-0.1/debug/amd64/bin/dtrace.exe
POST_PROCESS =
STRIP_STABS =

all: usdt/tst.args.exe usdt/tst.argmap.exe 
usdt/tst.args.exe: usdt/tst.args.o usdt/args.o
	$(LINK.c) -o usdt/tst.args.exe usdt/tst.args.o usdt/args.o $(LDLIBS)
usdt/args.o: usdt/args.d usdt/tst.args.o
	$(COMPILE.d) -o usdt/args.o -s usdt/args.d usdt/tst.args.o


usdt/tst.argmap.exe: usdt/tst.argmap.o usdt/argmap.o
	$(LINK.c) -o usdt/tst.argmap.exe \
	    usdt/tst.argmap.o usdt/argmap.o $(LDLIBS)
usdt/argmap.o: usdt/argmap.d usdt/tst.argmap.o
	$(COMPILE.d) -o usdt/argmap.o -s usdt/argmap.d usdt/tst.argmap.o


	
clean:
	rm usdt/tst.args.exe usdt/tst.argmap.exe  usdt/tst.argmap.o usdt/argmap.o \
		usdt/tst.args.o usdt/args.o 