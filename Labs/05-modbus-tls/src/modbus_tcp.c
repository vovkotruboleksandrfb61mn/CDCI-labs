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
static SSL_CTX *tls_server_ctx(void) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) die("SSL_CTX_new");
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    if (SSL_CTX_use_certificate_file(ctx, "certs/server.crt", SSL_FILETYPE_PEM) != 1)
        die("load cert (запустіть gen-certs.sh)");
    if (SSL_CTX_use_PrivateKey_file(ctx, "certs/server.key", SSL_FILETYPE_PEM) != 1)
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

static int run_server(int port, int use_tls) {
    SSL_CTX *ctx = use_tls ? tls_server_ctx() : NULL;
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

static int run_client(int port, int use_tls, unsigned short start, unsigned short cnt) {
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

    /* Read Holding Registers: MBAP + PDU */
    unsigned char req[12] = {0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01,
                             0x03, start >> 8, start & 0xff, cnt >> 8, cnt & 0xff};
    conn_write(&c, req, sizeof req);

    unsigned char resp[260];
    if (read_full(&c, resp, 9) <= 0) die("no response");
    unsigned char bytecount = resp[8];
    if (read_full(&c, resp + 9, bytecount - 0) < 0) die("short read");
    printf("client: прочитано %d регістрів від адреси %u:\n", cnt, start);
    for (int i = 0; i < cnt; i++) {
        unsigned short v = (resp[9 + i * 2] << 8) | resp[9 + i * 2 + 1];
        printf("  reg[%u] = %u\n", start + i, v);
    }
    if (c.ssl) { SSL_shutdown(c.ssl); SSL_free(c.ssl); }
    close(fd);
    return 0;
}

int main(int argc, char **argv) {
    int server = 0, client = 0, tls = 0, port = DEFAULT_PORT;
    unsigned short start = 0, cnt = 4;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--server")) server = 1;
        else if (!strcmp(argv[i], "--client")) client = 1;
        else if (!strcmp(argv[i], "--tls")) tls = 1;
        else if (!strcmp(argv[i], "--port")) port = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--addr")) start = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--count")) cnt = atoi(argv[++i]);
    }
    if (tls) { SSL_library_init(); SSL_load_error_strings(); }
    if (server) return run_server(port, tls);
    if (client) return run_client(port, tls, start, cnt);
    fprintf(stderr, "usage: %s --server|--client [--tls] [--port N]\n", argv[0]);
    return 2;
}
