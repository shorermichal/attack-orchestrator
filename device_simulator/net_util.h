#ifndef NET_UTIL_H
#define NET_UTIL_H

#include <stddef.h>

#define LINE_READER_INITIAL_CAP 256
#define LINE_READER_MAX_CAP (1 << 20)

/* Buffers raw bytes off a socket and hands back one '\n'-terminated command
 * at a time. TCP gives no guarantee that one read() call returns exactly
 * one line, so this exists to turn a byte stream back into discrete lines. */
typedef struct {
    int fd;
    char *buf;
    size_t start; /* index of first unconsumed byte */
    size_t len;   /* index one past the last buffered byte */
    size_t cap;
} line_reader_t;

void line_reader_init(line_reader_t *lr, int fd);
void line_reader_free(line_reader_t *lr);

/* Reads one line, strips the trailing '\n' (and '\r' if present), and
 * returns a pointer into an internal buffer valid until the next call.
 * Returns NULL on EOF, a socket error, or a line exceeding the max size. */
char *line_reader_next(line_reader_t *lr);

/* Writes all `n` bytes to fd, retrying on partial writes / EINTR.
 * Returns 0 on success, -1 on error. */
int write_all(int fd, const void *data, size_t n);

#endif
