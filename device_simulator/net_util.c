#define _POSIX_C_SOURCE 200809L

#include "net_util.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void line_reader_init(line_reader_t *lr, int fd) {
    lr->fd = fd;
    lr->cap = LINE_READER_INITIAL_CAP;
    lr->buf = malloc(lr->cap);
    lr->start = 0;
    lr->len = 0;
}

void line_reader_free(line_reader_t *lr) {
    free(lr->buf);
    lr->buf = NULL;
}

static char *find_newline(line_reader_t *lr) {
    for (size_t i = lr->start; i < lr->len; i++) {
        if (lr->buf[i] == '\n') return &lr->buf[i];
    }
    return NULL;
}

char *line_reader_next(line_reader_t *lr) {
    for (;;) {
        char *nl = find_newline(lr);
        if (nl) {
            *nl = '\0';
            char *line = lr->buf + lr->start;
            size_t line_len = (size_t)(nl - line);
            if (line_len > 0 && line[line_len - 1] == '\r') {
                line[line_len - 1] = '\0';
            }
            lr->start = (size_t)(nl - lr->buf) + 1;
            return line;
        }

        /* No full line buffered yet - make room and read more. */
        if (lr->start > 0) {
            memmove(lr->buf, lr->buf + lr->start, lr->len - lr->start);
            lr->len -= lr->start;
            lr->start = 0;
        }

        if (lr->len == lr->cap) {
            if (lr->cap >= LINE_READER_MAX_CAP) return NULL; /* refuse absurd lines */
            size_t new_cap = lr->cap * 2;
            char *grown = realloc(lr->buf, new_cap);
            if (!grown) return NULL;
            lr->buf = grown;
            lr->cap = new_cap;
        }

        ssize_t n = read(lr->fd, lr->buf + lr->len, lr->cap - lr->len);
        if (n == 0) return NULL; /* peer closed the connection cleanly */
        if (n < 0) {
            if (errno == EINTR) continue;
            return NULL; /* connection error - treat like a drop */
        }
        lr->len += (size_t)n;
    }
}

int write_all(int fd, const void *data, size_t n) {
    const char *p = data;
    size_t remaining = n;
    while (remaining > 0) {
        ssize_t written = write(fd, p, remaining);
        if (written < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        p += written;
        remaining -= (size_t)written;
    }
    return 0;
}
