CFLAGS = -g -O0

TARGETS = poc hello

all: $(TARGETS) libhello.so

poc: poc.c proc.c
hello: hello.c

$(TARGETS):
	$(CC) $(CFLAGS) -o $@ $^

libhello.so: lib.c proc.c
	$(CC) $(CFLAGS) -o $@ -shared -fPIC $^

.PHONY: clean
clean:
	rm -f $(TARGETS) libhello.so
