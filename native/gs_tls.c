#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE
#endif
#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

typedef struct {
    int fd;
    SSL_CTX *ctx;
    SSL *ssl;
} gs_tls_conn_t;

#define GS_TLS_MAX_CONNS 1024

static pthread_mutex_t g_tls_mu = PTHREAD_MUTEX_INITIALIZER;
static gs_tls_conn_t *g_tls_slots[GS_TLS_MAX_CONNS];
static _Thread_local char g_tls_err[512];

static void gs_tls_set_err(const char *msg)
{
    if (msg == NULL) {
        g_tls_err[0] = '\0';
        return;
    }
    snprintf(g_tls_err, sizeof(g_tls_err), "%s", msg);
}

static void gs_tls_set_ssl_err(const char *prefix)
{
    unsigned long code = ERR_get_error();
    if (code != 0) {
        char buf[256];
        ERR_error_string_n(code, buf, sizeof(buf));
        snprintf(g_tls_err, sizeof(g_tls_err), "%s: %s", prefix, buf);
    } else {
        snprintf(g_tls_err, sizeof(g_tls_err), "%s", prefix);
    }
}

const char *gs_tls_last_error(void)
{
    return g_tls_err;
}

static int64_t gs_tls_alloc_slot(gs_tls_conn_t *c)
{
    pthread_mutex_lock(&g_tls_mu);
    for (int i = 1; i < GS_TLS_MAX_CONNS; i++) {
        if (g_tls_slots[i] == NULL) {
            g_tls_slots[i] = c;
            pthread_mutex_unlock(&g_tls_mu);
            return (int64_t)i;
        }
    }
    pthread_mutex_unlock(&g_tls_mu);
    return -1;
}

static gs_tls_conn_t *gs_tls_get_slot(int64_t handle)
{
    if (handle <= 0 || handle >= GS_TLS_MAX_CONNS) return NULL;
    pthread_mutex_lock(&g_tls_mu);
    gs_tls_conn_t *c = g_tls_slots[handle];
    pthread_mutex_unlock(&g_tls_mu);
    return c;
}

static gs_tls_conn_t *gs_tls_take_slot(int64_t handle)
{
    if (handle <= 0 || handle >= GS_TLS_MAX_CONNS) return NULL;
    pthread_mutex_lock(&g_tls_mu);
    gs_tls_conn_t *c = g_tls_slots[handle];
    g_tls_slots[handle] = NULL;
    pthread_mutex_unlock(&g_tls_mu);
    return c;
}

static int gs_tls_tcp_dial(const char *host, int32_t port, int32_t timeout_ms)
{
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *res = NULL;
    int rc = getaddrinfo(host, port_str, &hints, &res);
    if (rc != 0 || res == NULL) {
        snprintf(g_tls_err, sizeof(g_tls_err), "DNS lookup failed for %s: %s", host, gai_strerror(rc));
        return -1;
    }

    int fd = -1;
    for (struct addrinfo *p = res; p != NULL; p = p->ai_next) {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) continue;

        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
#ifdef SO_NOSIGPIPE
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif
        if (timeout_ms > 0) {
            struct timeval tv;
            tv.tv_sec = timeout_ms / 1000;
            tv.tv_usec = (timeout_ms % 1000) * 1000;
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        }

        if (connect(fd, p->ai_addr, p->ai_addrlen) == 0) {
            break;
        }
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) {
        snprintf(g_tls_err, sizeof(g_tls_err), "TCP connect failed to %s:%d (errno=%d)", host, port, errno);
    }
    return fd;
}

int64_t gs_tls_connect_ex(const char *host, int32_t port, int32_t verify, int32_t timeout_ms)
{
    if (host == NULL || host[0] == '\0' || port <= 0 || port > 65535) {
        gs_tls_set_err("invalid host or port");
        return -1;
    }
    g_tls_err[0] = '\0';

    int fd = gs_tls_tcp_dial(host, port, timeout_ms);
    if (fd < 0) return -1;

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL) {
        gs_tls_set_ssl_err("SSL_CTX_new failed");
        close(fd);
        return -1;
    }

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    if (verify != 0) {
        if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
            gs_tls_set_ssl_err("SSL_CTX_set_default_verify_paths failed");
            SSL_CTX_free(ctx);
            close(fd);
            return -1;
        }
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    } else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    }

    SSL *ssl = SSL_new(ctx);
    if (ssl == NULL) {
        gs_tls_set_ssl_err("SSL_new failed");
        SSL_CTX_free(ctx);
        close(fd);
        return -1;
    }

    SSL_set_tlsext_host_name(ssl, host);
    if (verify != 0) {
        SSL_set1_host(ssl, host);
    }
    SSL_set_fd(ssl, fd);

    if (SSL_connect(ssl) != 1) {
        gs_tls_set_ssl_err("TLS handshake failed");
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(fd);
        return -1;
    }

    gs_tls_conn_t *c = (gs_tls_conn_t *)malloc(sizeof(gs_tls_conn_t));
    if (c == NULL) {
        gs_tls_set_err("out of memory");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(fd);
        return -1;
    }
    c->fd = fd;
    c->ctx = ctx;
    c->ssl = ssl;

    int64_t handle = gs_tls_alloc_slot(c);
    if (handle < 0) {
        gs_tls_set_err("too many open TLS connections");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(fd);
        free(c);
        return -1;
    }
    return handle;
}

int32_t gs_tls_read(int64_t handle, void *buf, int32_t cap)
{
    gs_tls_conn_t *c = gs_tls_get_slot(handle);
    if (c == NULL || buf == NULL || cap <= 0) {
        gs_tls_set_err("invalid TLS handle or buffer");
        return -1;
    }
    for (;;) {
        int n = SSL_read(c->ssl, buf, cap);
        if (n > 0) return n;
        int err = SSL_get_error(c->ssl, n);
        if (err == SSL_ERROR_ZERO_RETURN) return 0;
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) continue;
        if (err == SSL_ERROR_SYSCALL && errno == EINTR) continue;
        if (err == SSL_ERROR_SYSCALL && n == 0) return 0;
        gs_tls_set_ssl_err("TLS read failed");
        return -1;
    }
}

int32_t gs_tls_peek(int64_t handle, void *buf, int32_t cap)
{
    gs_tls_conn_t *c = gs_tls_get_slot(handle);
    if (c == NULL || buf == NULL || cap <= 0) {
        gs_tls_set_err("invalid TLS handle or buffer");
        return -1;
    }
    for (;;) {
        int n = SSL_peek(c->ssl, buf, cap);
        if (n > 0) return n;
        int err = SSL_get_error(c->ssl, n);
        if (err == SSL_ERROR_ZERO_RETURN) return 0;
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) continue;
        if (err == SSL_ERROR_SYSCALL && errno == EINTR) continue;
        if (err == SSL_ERROR_SYSCALL && n == 0) return 0;
        gs_tls_set_ssl_err("TLS peek failed");
        return -1;
    }
}

int32_t gs_tls_write(int64_t handle, const void *buf, int32_t len)
{
    gs_tls_conn_t *c = gs_tls_get_slot(handle);
    if (c == NULL || (buf == NULL && len > 0) || len < 0) {
        gs_tls_set_err("invalid TLS handle or buffer");
        return -1;
    }
    int32_t total = 0;
    const uint8_t *p = (const uint8_t *)buf;
    while (total < len) {
        int n = SSL_write(c->ssl, p + total, len - total);
        if (n > 0) {
            total += n;
            continue;
        }
        int err = SSL_get_error(c->ssl, n);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) continue;
        if (err == SSL_ERROR_SYSCALL && errno == EINTR) continue;
        gs_tls_set_ssl_err("TLS write failed");
        return -1;
    }
    return total;
}

int32_t gs_tls_write_str(int64_t handle, const char *s, int32_t len)
{
    return gs_tls_write(handle, (const void *)s, len);
}

int32_t gs_tls_close(int64_t handle)
{
    gs_tls_conn_t *c = gs_tls_take_slot(handle);
    if (c == NULL) return 0;
    SSL_shutdown(c->ssl);
    SSL_free(c->ssl);
    SSL_CTX_free(c->ctx);
    close(c->fd);
    free(c);
    return 0;
}
