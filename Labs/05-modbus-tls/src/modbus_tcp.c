/*
 * Мінімальний Modbus TCP клієнт/сервер із необов'язковим захистом TLS.
 *
 * Реалізує функцію 0x03 (Read Holding Registers) за специфікацією
 * Modbus Application Protocol v1.1b3 та Modbus Messaging on TCP/IP v1.0b.
 * Прапорець --tls загортає той самий обмін у TLS 1.3 (OpenSSL), не змінюючи
 * прикладну логіку: так видно різницю у трафіку до та після захисту.
 *
 *   server:  modbus_tcp --server [--tls] [--port N]
 *   client:  modbus_tcp --client [--tls] [--port N] [--addr 1 --count 4]
 */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#define DEFAULT_PORT 1502 /* 502 потребує root; 1502 поширений для тестів */
#define NREG 16           /* кількість регістрів у сервера */

/* Один канал зв'язку: звичайний сокет або сокет, загорнутий у TLS. */
typedef struct {
    int fd;
    SSL *ssl; /* NULL, якщо TLS не використовується */
} conn_t;

static void die(const char *msg) {
    fprintf(stderr, "error: %s\n", msg);
    ERR_print_errors_fp(stderr);
    exit(1);
}

static int conn_read(conn_t *c, unsigned char *buf, int n) {
    return c->ssl ? SSL_read(c->ssl, buf, n) : (int)read(c->fd, buf, n);
}
static int conn_write(conn_t *c, const unsigned char *buf, int n) {
    return c->ssl ? SSL_write(c->ssl, buf, n) : (int)write(c->fd, buf, n);
}

/* Прочитати рівно n байтів (TCP може віддавати дані частинами). */
static int read_full(conn_t *c, unsigned char *buf, int n) {
    int got = 0;
    while (got < n) {
        int r = conn_read(c, buf + got, n - got);
        if (r <= 0) return r;
        got += r;
    }
    return got;
}

/* ---- TLS ---- */
static SSL_CTX *tls_server_ctx(const char *cert, const char *key) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) die("SSL_CTX_new");
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    if (SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) != 1)
        die("load cert (запустіть gen-certs.sh)");
    if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) != 1)
        die("load key");
    return ctx;
}
static SSL_CTX *tls_client_ctx(void) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) die("SSL_CTX_new");
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    /* Автентифікація сервера за сертифікатом нашого CA. */
    if (SSL_CTX_load_verify_locations(ctx, "certs/ca.crt", NULL) != 1)
        die("load CA");
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    return ctx;
}

/* ---- Modbus ---- */

/* Відповідь сервера на один запит. Повертає 0, якщо клієнт від'єднався. */
static int serve_one(conn_t *c, unsigned short regs[]) {
    unsigned char req[260];
    if (read_full(c, req, 8) <= 0) return 0; /* MBAP(7) + код функції(1) */
    unsigned short len = (req[4] << 8) | req[5];
    int rest = len - 2; /* уже прочитано unit id + код функції */
    if (rest > 0 && read_full(c, req + 8, rest) <= 0) return 0;

    unsigned char fc = req[7];
    unsigned char resp[260];
    memcpy(resp, req, 4); /* transaction id + protocol id */
    resp[6] = req[6];     /* unit id */

    if (fc == 0x03) { /* Read Holding Registers */
        unsigned short start = (req[8] << 8) | req[9];
        unsigned short cnt = (req[10] << 8) | req[11];
        if (start + cnt > NREG || cnt == 0 || cnt > 125) {
            resp[7] = 0x83; /* exception */
            resp[8] = 0x02; /* illegal data address */
            unsigned short pl = 3;
            resp[4] = pl >> 8; resp[5] = pl & 0xff;
            return conn_write(c, resp, 9) > 0;
        }
        resp[7] = 0x03;
        resp[8] = cnt * 2; /* byte count */
        for (int i = 0; i < cnt; i++) {
            resp[9 + i * 2] = regs[start + i] >> 8;
            resp[9 + i * 2 + 1] = regs[start + i] & 0xff;
        }
        unsigned short pl = 3 + cnt * 2; /* unit + fc + bytecount + data */
        resp[4] = pl >> 8; resp[5] = pl & 0xff;
        return conn_write(c, resp, 9 + cnt * 2) > 0;
    }
    resp[7] = fc | 0x80; /* illegal function */
    resp[8] = 0x01;
    resp[4] = 0; resp[5] = 3;
    return conn_write(c, resp, 9) > 0;
}

static int run_server(int port, int use_tls, const char *cert, const char *key) {
    SSL_CTX *ctx = use_tls ? tls_server_ctx(cert, key) : NULL;
    unsigned short regs[NREG];
    for (int i = 0; i < NREG; i++) regs[i] = 1000 + i; /* показові значення */

    int ls = socket(AF_INET, SOCK_STREAM, 0);
    int on = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port),
                            .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    if (bind(ls, (struct sockaddr *)&a, sizeof a) != 0) die("bind");
    if (listen(ls, 4) != 0) die("listen");
    fprintf(stderr, "server: %s on 127.0.0.1:%d\n", use_tls ? "TLS" : "plain", port);

    int fd;
    while ((fd = accept(ls, NULL, NULL)) >= 0) {
        conn_t c = {.fd = fd, .ssl = NULL};
        if (use_tls) {
            c.ssl = SSL_new(ctx);
            SSL_set_fd(c.ssl, fd);
            if (SSL_accept(c.ssl) != 1) { SSL_free(c.ssl); close(fd); continue; }
        }
        while (serve_one(&c, regs)) {}
        if (c.ssl) { SSL_shutdown(c.ssl); SSL_free(c.ssl); }
        close(fd);
    }
    close(ls);
    if (ctx) SSL_CTX_free(ctx);
    return 0;
}

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e3 + ts.tv_nsec / 1e6;
}

static void hexdump_fd(FILE *f, const unsigned char *buf, int n) {
    for (int i = 0; i < n; i++) fprintf(f, "%02x ", buf[i]);
    fprintf(f, "\n");
}

/* Один обмін запит-відповідь; повертає 1 успіх, 0 кінець, -1 помилка. */
static int exchange(conn_t *c, unsigned short start, unsigned short cnt, int print) {
    unsigned char req[12] = {0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01,
                             0x03, start >> 8, start & 0xff, cnt >> 8, cnt & 0xff};
    if (conn_write(c, req, sizeof req) <= 0) return -1;
    unsigned char resp[9 + 255];  /* MBAP+PDU header (9) + max byte count (255) */
    if (read_full(c, resp, 9) <= 0) return -1;
    unsigned char bytecount = resp[8];
    if (bytecount == 0 || read_full(c, resp + 9, bytecount) <= 0) return -1;
    if (print) {
        printf("client: прочитано %d регістрів від адреси %u:\n", cnt, start);
        for (int i = 0; i < cnt; i++) {
            unsigned short v = (resp[9 + i * 2] << 8) | resp[9 + i * 2 + 1];
            printf("  reg[%u] = %u\n", start + i, v);
        }
    }
    return 1;
}

static int run_client(int port, int use_tls, unsigned short start, unsigned short cnt,
                      int repeat, int hold_ms) {
    SSL_CTX *ctx = use_tls ? tls_client_ctx() : NULL;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port),
                            .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    if (connect(fd, (struct sockaddr *)&a, sizeof a) != 0) die("connect");
    conn_t c = {.fd = fd, .ssl = NULL};
    if (use_tls) {
        c.ssl = SSL_new(ctx);
        SSL_set_fd(c.ssl, fd);
        if (SSL_connect(c.ssl) != 1) die("TLS handshake");
        if (SSL_get_verify_result(c.ssl) != X509_V_OK) die("cert not trusted");
        printf("client: TLS %s, сервер автентифіковано\n", SSL_get_version(c.ssl));
    }

    for (int i = 0; i < repeat; i++)
        if (exchange(&c, start, cnt, 1) < 0) die("exchange failed");

    /* Тримати з'єднання відкритим, щоб побачити дані атаки повторного
       відтворення (сніфер --replay) або нічого не отримати. */
    if (hold_ms > 0) {
        struct timeval tv = {.tv_sec = hold_ms / 1000, .tv_usec = (hold_ms % 1000) * 1000};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        unsigned char extra[512];
        int r = conn_read(&c, extra, sizeof extra);
        if (r > 0) {
            printf("client: НЕОЧІКУВАНІ дані (ознака replay, %d байт): ", r);
            hexdump_fd(stdout, extra, r);
        } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
            printf("client: додаткових даних не надійшло\n");
        } else {
            printf("client: з'єднання розірвано сервером після повторного "
                   "відтворення запису (TLS відхилив повтор)\n");
        }
    }
    if (c.ssl) { SSL_shutdown(c.ssl); SSL_free(c.ssl); }
    close(fd);
    return 0;
}

/* Вимірювання: час встановлення з'єднання (TCP або TCP+TLS) і час
   кругового обходу запиту. */
static int run_bench(int port, int use_tls, int nconn, unsigned short cnt) {
    SSL_CTX *bench_ctx = use_tls ? tls_client_ctx() : NULL;
    double t_conn = 0, t_rtt = 0;
    int ok = 0, rtts = 0;
    for (int i = 0; i < nconn; i++) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port),
                                .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
        double t0 = now_ms();
        if (connect(fd, (struct sockaddr *)&a, sizeof a) != 0) { close(fd); continue; }
        conn_t c = {.fd = fd, .ssl = NULL};
        if (use_tls) {
            c.ssl = SSL_new(bench_ctx);
            SSL_set_fd(c.ssl, fd);
            if (SSL_connect(c.ssl) != 1 ||
                SSL_get_verify_result(c.ssl) != X509_V_OK) { close(fd); continue; }
        }
        t_conn += now_ms() - t0;
        for (int k = 0; k < 20; k++) {
            double t1 = now_ms();
            if (exchange(&c, 0, cnt, 0) == 1) { t_rtt += now_ms() - t1; rtts++; }
        }
        if (c.ssl) { SSL_shutdown(c.ssl); SSL_free(c.ssl); }
        close(fd);
        ok++;
    }
    if (!ok) die("bench: жодного з'єднання");
    printf("bench: %d з'єднань, %s\n", ok, use_tls ? "TLS 1.3" : "plain TCP");
    printf("  середній час з'єднання (з рукостисканням): %.3f мс\n", t_conn / ok);
    if (rtts) printf("  середній час запит-відповідь: %.3f мс (%d запитів)\n", t_rtt / rtts, rtts);
    return 0;
}

int main(int argc, char **argv) {
    int server = 0, client = 0, tls = 0, bench = 0, port = DEFAULT_PORT;
    int repeat = 1, hold_ms = 0;
    unsigned short start = 0, cnt = 4;
    const char *cert = "certs/server.crt", *key = "certs/server.key";
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--server")) server = 1;
        else if (!strcmp(argv[i], "--client")) client = 1;
        else if (!strcmp(argv[i], "--tls")) tls = 1;
        else if (!strcmp(argv[i], "--bench")) bench = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--port")) port = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--addr")) start = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--count")) cnt = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--repeat")) repeat = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--hold")) hold_ms = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--cert")) cert = argv[++i];
        else if (!strcmp(argv[i], "--key")) key = argv[++i];
    }
    if (tls) { SSL_library_init(); SSL_load_error_strings(); }
    if (server) return run_server(port, tls, cert, key);
    if (bench > 0) return run_bench(port, tls, bench, cnt);
    if (client) return run_client(port, tls, start, cnt, repeat, hold_ms);
    fprintf(stderr, "usage: %s --server|--client [--tls] [--port N] [--bench N] "
            "[--repeat N] [--hold MS] [--cert F] [--key F]\n", argv[0]);
    return 2;
}
