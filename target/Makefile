# Build the vulnerable PNG decoder.
#
#   make            -> sanitized build (AddressSanitizer + UndefinedBehaviorSanitizer)
#                      This is the build the fuzzer uses. Bugs abort loudly.
#   make release    -> optimized build with NO sanitizers.
#                      Used to demonstrate that the same bugs are SILENT without
#                      a sanitizer (memory corruption with no visible crash).
#   make clean      -> remove built binaries.
#
# CC defaults to the system compiler. On macOS `cc`/`gcc` are Apple clang, which
# supports both sanitizers. On Linux, gcc or clang both work.

CC      ?= cc
CFLAGS  ?= -g -O1 -fno-omit-frame-pointer -Wall -Wextra
SANFLAGS = -fsanitize=address,undefined -fno-sanitize-recover=all

TARGET      = naive_decoder
REL_TARGET  = naive_decoder_release

.PHONY: all release clean

all: $(TARGET)

$(TARGET): naive_decoder.c
	$(CC) $(CFLAGS) $(SANFLAGS) -o $(TARGET) naive_decoder.c

release: $(REL_TARGET)

$(REL_TARGET): naive_decoder.c
	$(CC) -O2 -Wall -o $(REL_TARGET) naive_decoder.c

clean:
	rm -f $(TARGET) $(REL_TARGET)
	rm -rf $(TARGET).dSYM $(REL_TARGET).dSYM
