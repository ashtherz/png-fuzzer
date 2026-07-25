/*
 * naive_decoder.c  --  a DELIBERATELY VULNERABLE PNG decoder.
 * ---------------------------------------------------------------------------
 * This program is a fuzzing *target*. It is written naively on purpose: it
 * trusts values that come straight out of an attacker-controlled file. Each
 * planted bug is isolated in its own function so that a sanitizer report points
 * at exactly one weakness class, which lets the harness deduplicate cleanly.
 *
 * It is NOT a real image library. Do not use it to decode real PNGs.
 *
 * Build (sanitized, the normal mode):   make
 * Build (release, to show bugs are silent without ASan):   make release
 *
 * Planted weaknesses (see PNG spec: 8-byte signature, then chunks of
 *   [length:4][type:4][data:length][crc:4]):
 *
 *   BUG 1  chunk_checksum()      CWE-125            heap over-read
 *   BUG 2  fill_row_scratch()    CWE-121 / CWE-787  fixed stack buffer overflow
 *   BUG 3  ihdr_channel_lookup() CWE-125 / CWE-129  OOB read via bad index
 *   BUG 4  ihdr_alloc_and_fill() CWE-190 -> CWE-787 integer narrowing -> heap OOB write
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

/* Read a big-endian unsigned 32-bit integer (PNG stores lengths this way). */
static uint32_t be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  | ((uint32_t)p[3]);
}

/*
 * Number of colour channels per PNG colour type.
 * Valid PNG colour types are 0,2,3,4,6 -- so only indices 0..6 are meaningful
 * and this table has exactly 7 entries. Anything past index 6 is out of bounds.
 */
static const int channel_table[7] = { 1, 0, 3, 1, 2, 0, 4 };

/*
 * BUG 3 -- CWE-125 / CWE-129 (out-of-bounds read via unvalidated index).
 * The colour-type byte comes straight from the file and is used directly as an
 * array index with no range check. A colour type of, say, 0xFF reads far past
 * the end of channel_table.
 */
__attribute__((noinline))
static int ihdr_channel_lookup(uint8_t colortype) {
    return channel_table[colortype];            /* <-- OOB read when colortype >= 7 */
}

/*
 * BUG 4 -- CWE-190 -> CWE-787 (integer narrowing leading to a heap overflow write).
 * The real width is a 32-bit field, but it is narrowed to 16 bits when the
 * pixel buffer is sized. If width has any bits set above bit 15 whose low 16
 * bits are small (e.g. 0x10000 -> 0), the allocation is far too small while the
 * write loop still uses the full 32-bit width.
 */
__attribute__((noinline))
static void ihdr_alloc_and_fill(uint32_t width, int channels,
                                const uint8_t *data, uint32_t avail) {
    uint16_t w16   = (uint16_t)width;                       /* narrowing happens here */
    size_t   nchan = channels > 0 ? (size_t)channels : 1;
    size_t   alloc = (size_t)w16 * nchan;                   /* undersized when width > 65535 */
    uint8_t *img   = (uint8_t *)malloc(alloc ? alloc : 1);

    size_t writes = width;                                  /* full 32-bit width used to write */
    if (writes > 4096) writes = 4096;                       /* cap keeps the loop fast; still overflows */
    for (size_t i = 0; i < writes; i++) {
        img[i] = data ? data[i % (avail ? avail : 1)] : 0;  /* <-- heap OOB write when writes > alloc */
    }
    free(img);
}

/*
 * BUG 2 -- CWE-121 / CWE-787 (fixed-size stack buffer overflow).
 * A file-controlled count (derived from the width and channel count) drives a
 * write loop into a fixed 64-byte stack buffer with no bounds check.
 */
__attribute__((noinline))
static void fill_row_scratch(uint32_t width, int channels) {
    uint8_t rowbuf[64];
    size_t  nchan    = channels > 0 ? (size_t)channels : 1;
    size_t  rowbytes = (size_t)width * nchan;
    if (rowbytes > 4096) rowbytes = 4096;                   /* cap keeps the loop fast; still overflows 64 */
    for (size_t i = 0; i < rowbytes; i++) {
        rowbuf[i] = (uint8_t)i;                             /* <-- stack OOB write when rowbytes > 64 */
    }
    /* touch the buffer so the compiler cannot optimise the loop away */
    volatile uint8_t sink = rowbuf[width % 64];
    (void)sink;
}

/*
 * BUG 1 -- CWE-125 (heap over-read from a trusted length).
 * The chunk's declared length is believed absolutely. If a file declares a
 * length larger than the bytes actually present, this walks off the end of the
 * heap allocation that holds the file.
 */
__attribute__((noinline))
static uint32_t chunk_checksum(const uint8_t *data, uint32_t length) {
    uint32_t sum = 0;
    for (uint32_t i = 0; i < length; i++) {
        sum += data[i];                                     /* <-- heap OOB read when length > bytes present */
    }
    return sum;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file.png>\n", argv[0]);
        return 2;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("open"); return 2; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0) { fclose(f); return 2; }

    /* The whole file lives in one heap buffer sized to exactly the file length,
     * so any read past the declared data lands in an ASan red-zone. */
    uint8_t *buf = (uint8_t *)malloc(sz ? (size_t)sz : 1);
    size_t   n   = fread(buf, 1, (size_t)sz, f);
    fclose(f);

    /* Signature is 8 bytes. We are lenient: warn but keep parsing so that
     * mutations to the signature still let us reach the chunk parser. */
    size_t pos = (n >= 8) ? 8 : n;
    if (n < 8 || memcmp(buf, "\x89PNG\r\n\x1a\n", 8) != 0) {
        fprintf(stderr, "warning: bad or missing PNG signature\n");
    }

    while (pos + 8 <= n) {
        uint32_t       length = be32(buf + pos);
        const uint8_t *type   = buf + pos + 4;
        const uint8_t *data   = buf + pos + 8;
        uint32_t       avail  = (uint32_t)(n - (pos + 8));  /* bytes physically present after the header */

        if (memcmp(type, "IHDR", 4) == 0 && avail >= 13) {
            uint32_t width     = be32(data + 0);
            uint32_t height    = be32(data + 4);
            uint8_t  bitdepth  = data[8];
            uint8_t  colortype = data[9];
            (void)height; (void)bitdepth;                   /* not modelled; kept for realism */

            int channels = ihdr_channel_lookup(colortype);          /* BUG 3 */
            ihdr_alloc_and_fill(width, channels, data, avail);      /* BUG 4 */
            fill_row_scratch(width, channels);                      /* BUG 2 */
        }

        /* BUG 1: this runs for every chunk and trusts the declared length. */
        volatile uint32_t cs = chunk_checksum(data, length);
        (void)cs;

        if (memcmp(type, "IEND", 4) == 0) break;

        /* Advance past header + declared data + CRC. Always makes progress. */
        pos += (size_t)8 + (size_t)length + 4;
    }

    free(buf);
    printf("decoded ok\n");
    return 0;
}
