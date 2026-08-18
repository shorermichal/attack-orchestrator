#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "net_util.h"

#define MAX_FILES 64
#define BACKLOG 8

typedef struct {
    char *path;
    char *data;
    size_t len;
} vfile_t;

typedef struct {
    const char *device_id;
    const char *model;
    const char *ios_version;
    int battery_percent;
    int jailbroken;
    int port;
    unsigned int seed;
    double drop_rate;
    const char *drop_on_stage;
    vfile_t files[MAX_FILES];
    size_t file_count;
} config_t;

static void set_default_files(config_t *cfg) {
    static const struct {
        const char *path;
        const char *data;
    } defaults[] = {
        {"/private/var/mobile/Library/SMS/sms.db", "-- simulated sms database --"},
        {"/private/var/mobile/Library/AddressBook/AddressBook.sqlitedb", "-- simulated address book --"},
        {"/private/var/mobile/Library/CallHistoryDB/CallHistory.storedata", "-- simulated call history --"},
        {"/private/var/mobile/Library/Safari/History.db", "-- simulated safari history --"},
        {"/private/var/mobile/Library/Preferences/com.apple.mobile.installation.plist", "-- simulated plist --"},
    };
    for (size_t i = 0; i < sizeof(defaults) / sizeof(defaults[0]); i++) {
        cfg->files[cfg->file_count].path = strdup(defaults[i].path);
        cfg->files[cfg->file_count].data = strdup(defaults[i].data);
        cfg->files[cfg->file_count].len = strlen(defaults[i].data);
        cfg->file_count++;
    }
}

/* arg is "path=content"; replaces an existing entry with the same path. */
static void add_file_override(config_t *cfg, const char *arg) {
    const char *eq = strchr(arg, '=');
    if (!eq) {
        fprintf(stderr, "warning: ignoring malformed --file %s (expected path=content)\n", arg);
        return;
    }
    size_t path_len = (size_t)(eq - arg);

    for (size_t i = 0; i < cfg->file_count; i++) {
        if (strncmp(cfg->files[i].path, arg, path_len) == 0 && cfg->files[i].path[path_len] == '\0') {
            free(cfg->files[i].data);
            cfg->files[i].data = strdup(eq + 1);
            cfg->files[i].len = strlen(eq + 1);
            return;
        }
    }
    if (cfg->file_count >= MAX_FILES) {
        fprintf(stderr, "warning: too many --file overrides, ignoring %s\n", arg);
        return;
    }
    cfg->files[cfg->file_count].path = strndup(arg, path_len);
    cfg->files[cfg->file_count].data = strdup(eq + 1);
    cfg->files[cfg->file_count].len = strlen(eq + 1);
    cfg->file_count++;
}

static void print_usage(const char *prog) {
    fprintf(stderr,
            "usage: %s [options]\n"
            "  --port N              TCP port to listen on (default 9999)\n"
            "  --device-id ID        reported device id (default sim-0001)\n"
            "  --model MODEL         reported model (default iPhone14,5)\n"
            "  --ios-version V       reported iOS version (default 16.1)\n"
            "  --battery N           reported battery percent (default 80)\n"
            "  --jailbroken          report the device as already jailbroken\n"
            "  --seed N              RNG seed (default: time-based)\n"
            "  --drop-rate F         probability [0,1] of dropping the connection\n"
            "                        instead of responding to a STAGE command\n"
            "  --drop-on-stage NAME  always drop the connection on a STAGE command\n"
            "                        with this exact name (deterministic, for tests)\n"
            "  --file PATH=CONTENT   add/override a readable file (repeatable)\n"
            "  -h, --help             show this help\n",
            prog);
}

static int parse_args(int argc, char **argv, config_t *cfg) {
    cfg->device_id = "sim-0001";
    cfg->model = "iPhone14,5";
    cfg->ios_version = "16.1";
    cfg->battery_percent = 80;
    cfg->jailbroken = 0;
    cfg->port = 9999;
    cfg->seed = (unsigned int)time(NULL);
    cfg->drop_rate = 0.0;
    cfg->drop_on_stage = NULL;
    cfg->file_count = 0;
    set_default_files(cfg);

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            cfg->port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--device-id") == 0 && i + 1 < argc) {
            cfg->device_id = argv[++i];
        } else if (strcmp(argv[i], "--model") == 0 && i + 1 < argc) {
            cfg->model = argv[++i];
        } else if (strcmp(argv[i], "--ios-version") == 0 && i + 1 < argc) {
            cfg->ios_version = argv[++i];
        } else if (strcmp(argv[i], "--battery") == 0 && i + 1 < argc) {
            cfg->battery_percent = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--jailbroken") == 0) {
            cfg->jailbroken = 1;
        } else if (strcmp(argv[i], "--seed") == 0 && i + 1 < argc) {
            cfg->seed = (unsigned int)strtoul(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--drop-rate") == 0 && i + 1 < argc) {
            cfg->drop_rate = atof(argv[++i]);
        } else if (strcmp(argv[i], "--drop-on-stage") == 0 && i + 1 < argc) {
            cfg->drop_on_stage = argv[++i];
        } else if (strcmp(argv[i], "--file") == 0 && i + 1 < argc) {
            add_file_override(cfg, argv[++i]);
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            exit(0);
        } else {
            fprintf(stderr, "unknown argument: %s\n", argv[i]);
            print_usage(argv[0]);
            return -1;
        }
    }
    return 0;
}

static vfile_t *find_file(config_t *cfg, const char *path) {
    for (size_t i = 0; i < cfg->file_count; i++) {
        if (strcmp(cfg->files[i].path, path) == 0) return &cfg->files[i];
    }
    return NULL;
}

/* Splits `line` in place on spaces into at most `max_tokens` tokens. The
 * final token absorbs any remaining text (spaces included), so a STAGE's
 * numeric fields split cleanly while a READ path may still contain spaces. */
static int tokenize(char *line, char **tokens, int max_tokens) {
    int count = 0;
    char *p = line;
    while (*p == ' ') p++;
    while (*p && count < max_tokens) {
        if (count == max_tokens - 1) {
            tokens[count++] = p;
            break;
        }
        tokens[count++] = p;
        while (*p && *p != ' ') p++;
        if (*p == ' ') {
            *p = '\0';
            p++;
            while (*p == ' ') p++;
        }
    }
    return count;
}

static int handle_info(int fd, config_t *cfg) {
    char resp[512];
    int n = snprintf(resp, sizeof(resp), "INFO %s %s %s %d %d\n", cfg->device_id, cfg->model,
                      cfg->ios_version, cfg->battery_percent, cfg->jailbroken ? 1 : 0);
    return write_all(fd, resp, (size_t)n);
}

/* Returns 1 if this STAGE command should be answered by silently dropping
 * the connection instead - simulating a device that dies or loses its link
 * mid-attack. */
static int should_drop(config_t *cfg, const char *stage_name) {
    if (cfg->drop_on_stage && strcmp(stage_name, cfg->drop_on_stage) == 0) return 1;
    if (cfg->drop_rate > 0.0) {
        double roll = (double)rand() / ((double)RAND_MAX + 1.0);
        if (roll < cfg->drop_rate) return 1;
    }
    return 0;
}

/* STAGE <name> <probability> <is_last:0/1>
 *
 * The server rolls the dice, not the client: on real hardware, whether an
 * exploit lands is a property of the device, not something the attacker's
 * laptop gets to decide. `is_last` tells the simulator this is the final
 * stage of the chain - only a success there unlocks READ. Any failure
 * re-locks the device, whichever stage it happens on. */
static int handle_stage(int fd, config_t *cfg, char *args, int *unlocked) {
    char *tokens[3];
    int n = tokenize(args, tokens, 3);
    if (n != 3) {
        const char *msg = "ERR bad_request\n";
        return write_all(fd, msg, strlen(msg));
    }
    const char *name = tokens[0];
    double probability = atof(tokens[1]);
    int is_last = atoi(tokens[2]) != 0;

    if (should_drop(cfg, name)) {
        return -1; /* caller closes the connection without responding */
    }

    double roll = (double)rand() / ((double)RAND_MAX + 1.0);
    int success = roll < probability;

    if (success) {
        if (is_last) *unlocked = 1;
        const char *msg = "SUCCESS\n";
        return write_all(fd, msg, strlen(msg));
    }
    *unlocked = 0;
    const char *msg = "FAILURE\n";
    return write_all(fd, msg, strlen(msg));
}

static int handle_read(int fd, config_t *cfg, char *path, int unlocked) {
    if (!unlocked) {
        const char *msg = "ERR locked\n";
        return write_all(fd, msg, strlen(msg));
    }
    vfile_t *f = find_file(cfg, path);
    if (!f) {
        const char *msg = "ERR not_found\n";
        return write_all(fd, msg, strlen(msg));
    }
    char header[64];
    int hn = snprintf(header, sizeof(header), "OK %zu\n", f->len);
    if (write_all(fd, header, (size_t)hn) != 0) return -1;
    return write_all(fd, f->data, f->len);
}

static void handle_client(int fd, config_t *cfg) {
    line_reader_t lr;
    line_reader_init(&lr, fd);
    int unlocked = 0;

    for (;;) {
        char *line = line_reader_next(&lr);
        if (!line) break; /* client disconnected or sent garbage */

        char *tokens[2];
        int n = tokenize(line, tokens, 2);
        if (n == 0) continue; /* blank line */
        const char *cmd = tokens[0];
        char *rest = (n == 2) ? tokens[1] : "";

        int rc = 0;
        if (strcmp(cmd, "INFO") == 0) {
            rc = handle_info(fd, cfg);
        } else if (strcmp(cmd, "STAGE") == 0) {
            rc = handle_stage(fd, cfg, rest, &unlocked);
        } else if (strcmp(cmd, "READ") == 0) {
            rc = handle_read(fd, cfg, rest, unlocked);
        } else if (strcmp(cmd, "QUIT") == 0) {
            break;
        } else {
            const char *msg = "ERR bad_request\n";
            rc = write_all(fd, msg, strlen(msg));
        }
        if (rc != 0) break; /* write failed, or a drop was simulated */
    }

    line_reader_free(&lr);
    close(fd);
}

int main(int argc, char **argv) {
    config_t cfg;
    if (parse_args(argc, argv, &cfg) != 0) return 1;
    srand(cfg.seed);
    signal(SIGPIPE, SIG_IGN); /* a client that vanishes shouldn't kill the server */

    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("socket");
        return 1;
    }

    int yes = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((uint16_t)cfg.port);

    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }
    if (listen(listen_fd, BACKLOG) < 0) {
        perror("listen");
        return 1;
    }

    fprintf(stderr, "device simulator listening on port %d (device_id=%s model=%s ios=%s)\n",
            cfg.port, cfg.device_id, cfg.model, cfg.ios_version);

    /* One connection handled fully at a time: the framework only ever opens
     * a single connection per attack run, so a sequential accept loop keeps
     * the state machine (the `unlocked` flag) trivially simple, at the cost
     * of not serving multiple clients concurrently. */
    for (;;) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(listen_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            continue;
        }
        handle_client(client_fd, &cfg);
    }

    close(listen_fd);
    return 0;
}
