
SCFLAGS = -arch x86_64 -Wall -Wno-error=incompatible-function-pointer-types -Wno-error=int-conversion -c -Os -fno-stack-protector -mno-sse -fno-unwind-tables -fno-exceptions 

all:
	clang stage1.c -o stage1.o $(SCFLAGS)
	ld stage1.o -o stage1 -dylib -lSystem -syslibroot /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk
	python3 objcopy.py stage1 stage1.bin