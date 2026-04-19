CC      = gcc
CFLAGS  = -Wall -Wextra -g -O2

# Detect OS for shared library extension
UNAME := $(shell uname)
ifeq ($(UNAME), Darwin)
    SOFLAGS = -dynamiclib
    SOEXT   = dylib
else
    SOFLAGS = -shared -fPIC
    SOEXT   = so
endif

SO = rijndael.$(SOEXT)

.PHONY: all clean test

all: aes_demo $(SO)

# Symlink rijndael.so -> rijndael.dylib on macOS so Python test works
ifeq ($(UNAME), Darwin)
all: rijndael.so
rijndael.so: $(SO)
	ln -sf $(SO) rijndael.so
endif

# Build the executable demo
aes_demo: main.c rijndael.c rijndael.h
	$(CC) $(CFLAGS) -o aes_demo main.c rijndael.c

# Build the shared object for Python ctypes testing
$(SO): rijndael.c rijndael.h
	$(CC) $(CFLAGS) $(SOFLAGS) -o $(SO) rijndael.c

# Run Python unit tests
test: $(SO)
ifeq ($(UNAME), Darwin)
	ln -sf $(SO) rijndael.so
endif
	python3 test_rijndael.py -v

clean:
	rm -f aes_demo rijndael.so rijndael.dylib *.o