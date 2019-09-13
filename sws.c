/* See LICENSE file for copyright and license details. */

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <netdb.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define USAGE           "usage: sws -aprihv\n\n" \
                        "Simple Small Static Stupid Whatever Web Server.\n\n" \
                        "  -a  ip address\n" \
                        "  -p  port\n" \
                        "  -r  webroot\n" \
                        "  -i  index page\n" \
                        "  -h  help message\n" \
                        "  -v  version"
#define VERSION         "0.6.0"
#define DEFAULTPORT     "8080"
#define DEFAULTBACKLOG  10
#define DEFAULTINDEX    "index.html"
#define METHODMAX       8               /* request method max size */
#define URIMAX          8192            /* request uri max size */
#define HEADERMAX       4096            /* single request header max size */
#define MAXHEADERS      100             /* max number of request headers allowed */
#define BUFCHUNK        256             /* minimum buffer capacity increment */

#define ARRAYLEN(a)     (sizeof((a)) / sizeof((a)[0]))
#define MAX(a, b)       ((a) > (b) ? (a) : (b))

typedef struct Buffer   Buffer;
typedef struct Args     Args;
typedef struct HParser  HParser;
typedef struct HRange   HRange;
typedef struct HReq     HReq;
typedef struct HResp    HResp;
typedef struct HConn    HConn;

struct Buffer                           /* autogrowing characters buffer */
{
        size_t          cap;
        size_t          len;
        char           *data;
};

struct Args                             /* command line arguments */
{
        const char     *address;
        const char     *port;
        const char     *rootpath;
        const char     *index;
        int             help;
        int             version;
};

struct Server                           /* server informations */
{
        int             sock;           /* server listening socket */
        int             running;        /* 1 if running, 0 if stopped */
        char           *rootpath;       /* current working directory absolute path */
        const char     *index;          /* index filename for directories requests */
};

struct HParser                          /* http header parser pair stored in table */
{
        const char     *name;           /* name of header used for searching in table */
        void          (*parse)(HConn *, const char *value);     /* parser function */
};

struct HRange                           /* http range header first value */
{
        long            start;          /* range start. -1 if -nnn */
        long            end;            /* range end. -1 if nnn- */
};

struct HReq                             /* http request */
{
        time_t          timestamp;      /* request arrival timestamp */
        char            method[METHODMAX];
        char           *uri;            /* decoded request uri */
        int             keepalive;      /* connection header (1 keep-alive, 0 close) */
        time_t          ifmodsince;     /* if modified since header timestamp */
        HRange          range;
        long            contentlen;     /* request payload length. If present will be skipped */
};

struct HResp                            /* http response */
{
        int             status;         /* response http status */
        Buffer          head;           /* buffer for response line and headers */
        Buffer          content;        /* buffer for generated responses */
        FILE           *file;           /* file to send as response or NULL if sending generated response */
        size_t          sent;           /* number of bytes sent to client */
};

struct HConn                            /* http connection */
{
        FILE           *in;             /* input stream */
        FILE           *out;            /* output stream */
        HReq            req;
        HResp           resp;
        Buffer          buf;            /* common buffer used e.g. for building file paths */
};

static void             bufinit(Buffer *);
static int              bufputs(Buffer *, const char *s);
static int              bufputc(Buffer *, int c);
static int              bufvprintf(Buffer *, const char *fmt, va_list ap, va_list apcopy);
static int              bufreserve(Buffer *, size_t n);
static size_t           bufavailable(Buffer *);
static void             bufclear(Buffer *);
static void             buftruncate(Buffer *, size_t newlen);
static void             bufdeinit(Buffer *);
static void             parseargs(Args *, int argc, char *const *argv);
static void             initsrv(const Args *);
static void             setupsock(const Args *);
static void             setuprootpath(const Args *);
static void             setupsighandler(void);
static void             sighandler(int);
static void             logsrvinfo(void);
static void             ssinetntop(const struct sockaddr_storage *, char *address, char *port);
static void             run(void);
static void             handlereq(int client);
static HConn           *hopen(int client);
static void             hclear(HConn *);
static void             hclose(HConn *);
static int              hrecvreq(HConn *);
static int              hparsemethod(HConn *);
static int              hparseuri(HConn *);
static int              hparseversion(HConn *);
static int              hparseheaders(HConn *);
static HParser         *findhparser(const char *name);
static int              hparsercmp(const void *name, const void *parser);
static void             hparseconnection(HConn *, const char *value);
static void             hparsecontentlen(HConn *, const char *value);
static void             hparserange(HConn *, const char *value);
static int              hprintf(HConn *, const char *fmt, ...);
static int              haddheader(HConn *, const char *name, const char *value, ...);
static char            *percentdec(char *);
static void             loghconn(const HConn *);
static char            *strtrim(char *s);
static const char      *strstatus(int);
static void             logerr(const char *fmt, ...);
static void             vlogerr(const char *fmt, va_list ap);
static void             die(const char *reason, ...);
static void             cleanup(void);

static HParser hparsers[] =      /* keep sorted */
{
        { "connection",         hparseconnection },
        { "content-length",     hparsecontentlen },
        { "range",              hparserange      },
};

static struct Server server;            /* global server informations */

static void bufinit(Buffer *buf)
{
        buf->cap  = 0;
        buf->len  = 0;
        buf->data = NULL;
}

static int bufputs(Buffer *buf, const char *s)
{
        while (*s)
                if (bufputc(buf, *s++) == -1)
                        return -1;

        return 0;
}

static int bufputc(Buffer *buf, int c)
{
        if (bufavailable(buf) == 0 && bufreserve(buf, 1) == -1)
                return -1;

        buf->data[buf->len++] = c;
        return 0;
}

/*
 * In c89 we don't have va_copy, so we take 2 va_list started by the caller.
 * Ugly but works.
 */
static int bufvprintf(Buffer *buf, const char *fmt, va_list ap, va_list apcopy)
{
        char *p = buf->data + buf->len;
        int prilen;

        if (bufavailable(buf) == 0 && bufreserve(buf, 1) == -1)
                return -1;

        if ((prilen = vsnprintf(p, bufavailable(buf), fmt, ap)) < 0)
                return -1;

        if ((unsigned int)prilen >= bufavailable(buf)) {
                if (bufreserve(buf, prilen + 1) == -1)
                        return -1;

                if ((prilen = vsnprintf(p, bufavailable(buf), fmt, apcopy)) < 0)
                        return -1;
        }

        buf->len += prilen;
        return prilen;
}

static int bufreserve(Buffer *buf, size_t n)
{
        size_t newcap;
        char *p;

        if (bufavailable(buf) >= n)
                return 0;

        newcap = buf->cap + MAX(BUFCHUNK, (n - bufavailable(buf)));

        if ( ! (p = realloc(buf->data, newcap)))
                return -1;

        buf->cap = newcap;
        buf->data = p;
        return 0;
}

static size_t bufavailable(Buffer *buf)
{
        return buf->cap - buf->len;
}

static void bufclear(Buffer *buf)
{
        buftruncate(buf, 0);
}

static void buftruncate(Buffer *buf, size_t newlen)
{
        if (buf->len > newlen)
                buf->len = newlen;
}

static void bufdeinit(Buffer *buf)
{
        free(buf->data);
}

static void parseargs(Args *args, int argc, char *const *argv)
{
        int opt;

        while ((opt = getopt(argc, argv, "a:p:r:i:hv")) != -1) {
                switch (opt) {
                case 'a':
                        args->address = optarg;
                        break;
                case 'p':
                        args->port = optarg;
                        break;
                case 'r':
                        args->rootpath = optarg;
                        break;
                case 'i':
                        args->index = optarg;
                        break;
                case 'h':
                        args->help = 1;
                        break;
                case 'v':
                        args->version = 1;
                        break;
                }
        }
}

static void initsrv(const Args *args)
{
        setupsock(args);
        setuprootpath(args);
        setupsighandler();
        server.index = args->index ? args->index : DEFAULTINDEX;
}

static void setupsock(const Args *args)
{
        struct addrinfo hints, *info, *p;
        int err, yes = 1;

        memset(&hints, 0, sizeof(hints));
        hints.ai_family   = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags    = AI_PASSIVE;

        err = getaddrinfo(args->address, args->port ? args->port : DEFAULTPORT, &hints, &info);
        if (err)
                die("getaddrinfo: %s", gai_strerror(err));

        for (p = info; p; p = p->ai_next) {
                server.sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
                if (server.sock == -1)
                        continue;

                if (setsockopt(server.sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1) {
                        close(server.sock);
                        continue;
                }
                if (bind(server.sock, p->ai_addr, p->ai_addrlen) == -1) {
                        close(server.sock);
                        continue;
                }
                if (listen(server.sock, DEFAULTBACKLOG) == -1) {
                        close(server.sock);
                        continue;
                }
                break;
        }

        freeaddrinfo(info);

        if ( ! p)
                die("failed to bind socket");
}

static void setuprootpath(const Args *args)
{
        Buffer buf;

        if (args->rootpath && chdir(args->rootpath) != 0)
                die("chdir: %s", strerror(errno));

        bufinit(&buf);
        for (;;) {
                if (bufreserve(&buf, buf.cap + BUFCHUNK) == -1)
                        die("buf_reserve: %s", strerror(errno));

                server.rootpath = buf.data;
                if (getcwd(server.rootpath, buf.cap))
                        break;
                if (errno != ERANGE)
                        die("getcwd: %s", strerror(errno));
        }
}

static void setupsighandler(void)
{
        struct sigaction sa;

        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = sighandler;

        if (sigaction(SIGINT,  &sa, NULL) == -1
        ||  sigaction(SIGTERM, &sa, NULL) == -1
        ||  sigaction(SIGCHLD, &sa, NULL) == -1)
                die("sigaction: %s", strerror(errno));
}

static void sighandler(int sig)
{
        switch (sig) {
        case SIGINT:
        case SIGTERM:
                server.running = 0;
                break;
        case SIGCHLD:
                while (waitpid(-1, NULL, WNOHANG) > 0)
                        ;
                break;
        }
}

static void logsrvinfo(void)
{
        struct sockaddr_storage ss;
        socklen_t               sslen = sizeof(ss);
        char                    address[INET6_ADDRSTRLEN], port[6];

        memset(&ss, 0, sslen);
        if (getsockname(server.sock, (struct sockaddr *)&ss, &sslen) == -1)
                die("getsockname: %s", strerror(errno));

        ssinetntop(&ss, address, port);

        printf("serving %s at %s:%s pid is %ld\n",
               server.rootpath,
               address,
               port,
               (long)getpid());
}

static void ssinetntop(const struct sockaddr_storage *ss, char *address, char *port)
{
        if (ss->ss_family == AF_INET) {
                inet_ntop(AF_INET, &(((struct sockaddr_in *)ss)->sin_addr), address, INET_ADDRSTRLEN);
                sprintf(port, "%u", ntohs(((struct sockaddr_in *)ss)->sin_port));

        } else if (ss->ss_family == AF_INET6) {
                inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)ss)->sin6_addr), address, INET6_ADDRSTRLEN);
                sprintf(port, "%u", ntohs(((struct sockaddr_in6 *)ss)->sin6_port));

        } else
                address[0] = port[0] = '\0';
}

static void run(void)
{
        server.running = 1;
        while (server.running) {
                int client = accept(server.sock, NULL, NULL);
                if (client == -1) {
                        if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)
                                logerr("accept: %s", strerror(errno));
                        continue;
                }

                switch (fork()) {
                case 0:
                        handlereq(client);
                        return;
                case -1:
                        logerr("fork: %s", strerror(errno));
                        /* fallthrough */
                default:
                        close(client);
                }
        }
}

static void handlereq(int client)
{
        HConn *conn = hopen(client);
        if ( ! conn) {
                logerr("cannot open http connection");
                return;
        }

        if ((conn->resp.status = hrecvreq(conn)) == 200) {
                /* TODO */
        }

        loghconn(conn);
        hclose(conn);
}

static HConn *hopen(int client)
{
        HConn *conn;
        int outfd;

        if ( ! (conn = malloc(sizeof(*conn))))
                goto errconn;
        if ( ! (conn->in = fdopen(client, "r")))
                goto errin;
        if ((outfd = dup(client)) == -1)
                goto erroutfd;
        if ( ! (conn->out = fdopen(outfd, "w")))
                goto errout;

        conn->req.uri = NULL;
        conn->resp.file = NULL;
        bufinit(&conn->resp.head);
        bufinit(&conn->resp.content);
        bufinit(&conn->buf);

        hclear(conn);

        return conn;
errout:
        close(outfd);
erroutfd:
        fclose(conn->in);
errin:
        free(conn);
errconn:
        return NULL;
}

static void hclear(HConn *conn)
{
        conn->req.timestamp   = (time_t)-1;
        conn->req.method[0]   = '\0';
        conn->req.keepalive   = 0;
        conn->req.ifmodsince  = (time_t)-1;
        conn->req.range.start = -1;
        conn->req.range.end   = -1;
        conn->req.contentlen  = -1;
        conn->resp.status     = 500;
        conn->resp.sent       = 0;

        free(conn->req.uri);
        conn->req.uri = NULL;

        if (conn->resp.file)
                fclose(conn->resp.file);
        conn->resp.file = NULL;

        bufclear(&conn->resp.head);
        bufclear(&conn->resp.content);
        bufclear(&conn->buf);
}

static void hclose(HConn *conn)
{
        hclear(conn);   /* to free req.uri and close resp.file */
        bufdeinit(&conn->resp.head);
        bufdeinit(&conn->resp.content);
        bufdeinit(&conn->buf);
        fclose(conn->in);
        fclose(conn->out);
        free(conn);
}

static int hrecvreq(HConn *conn)
{
        int ret = hparsemethod(conn);

        conn->req.timestamp = time(NULL);

        /*
         * stop at first return value != 200
         */
        if (ret != 200
        ||  (ret = hparseuri(conn))     != 200
        ||  (ret = hparseversion(conn)) != 200
        ||  (ret = hparseheaders(conn)) != 200) {
        }

        return ret;
}

static int hparsemethod(HConn *conn)
{
        char   buf[METHODMAX];
        size_t len = 0;
        int    c;

        while ((c = fgetc(conn->in)) != EOF) {
                if (c == ' ' || ! isupper(c) || len == sizeof(buf) - 1)
                        break;

                buf[len++] = c;
        }
        if (len == 0 || c != ' ')
                return 400;

        memcpy(conn->req.method, buf, len);
        conn->req.method[len] = '\0';

        if (strcmp("GET", conn->req.method) != 0 && strcmp("HEAD", conn->req.method) != 0)
                return 501;

        return 200;
}

static int hparseuri(HConn *conn)
{
        Buffer *buf = &conn->buf;
        int     c;

        bufclear(buf);
        while ((c = fgetc(conn->in)) != EOF) {
                if (c == ' ')
                        break;
                if (buf->len == URIMAX - 1)
                        return 414;
                if (bufputc(buf, c) == -1)
                        return 500;
        }
        if (buf->len == 0 || c != ' ')
                return 400;
        if (bufputc(buf, '\0') == -1)
                return 500;

        percentdec(buf->data);
        if ( ! (conn->req.uri = strdup(buf->data)))
                return 500;

        return 200;
}

static int hparseversion(HConn *conn)
{
        int c;

        if (fgetc(conn->in) != 'H'
        ||  fgetc(conn->in) != 'T'
        ||  fgetc(conn->in) != 'T'
        ||  fgetc(conn->in) != 'P'
        ||  fgetc(conn->in) != '/')
                return 400;

        c = fgetc(conn->in);
        if ( ! isdigit(c))
                return 400;
        if (c != '1')
                return 505;

        if (fgetc(conn->in) != '.')
                return 400;

        c = fgetc(conn->in);
        if ( ! isdigit(c))
                return 400;
        if (c != '0' && c != '1')
                return 505;

        if (fgetc(conn->in) != '\r' || fgetc(conn->in) != '\n')
                return 400;

        return 200;
}

static int hparseheaders(HConn *conn)
{
        Buffer *buf = &conn->buf;
        int i, c;
        char *name, *value;
        HParser *parser;

        for (i = 0; i < MAXHEADERS; i++) {
                bufclear(buf);
                while ((c = fgetc(conn->in)) != EOF) {
                        if (c == '\r')
                                break;
                        if (buf->len == HEADERMAX - 1)
                                return 400;     /* TODO see if there is a specific status code */
                        if (bufputc(buf, c) == -1)
                                return 500;
                }
                if (fgetc(conn->in) != '\n')
                        return 400;
                if (buf->len == 0)
                        return 200;     /* end of headers */
                if (bufputc(buf, '\0') == -1)
                        return 500;

                name = buf->data;
                if ( ! (value = strchr(name, ':')))
                        return 400;     /* malformed header */

                *value++ = '\0';        /* null-terminate name string */

                if ((parser = findhparser(name)))
                        parser->parse(conn, strtrim(value));
        }

        return i < MAXHEADERS ? 200 : 400;
}

static HParser *findhparser(const char *name)
{
        return bsearch(name, hparsers, ARRAYLEN(hparsers), sizeof(*hparsers), hparsercmp);
}

static int hparsercmp(const void *name, const void *parser)
{
        return strcasecmp((const char *)name, ((const HParser *)parser)->name);
}

static void hparseconnection(HConn *conn, const char *value)
{
        conn->req.keepalive = strcmp(value, "keep-alive") == 0;
}

static void hparsecontentlen(HConn *conn, const char *value)
{
        long clen = atol(value);

        if (clen > 0)
                conn->req.contentlen = clen;
}

static void hparserange(HConn *conn, const char *value)
{
        char buf[32];
        const char *p = value;
        long start = -1;
        long end = -1;
        size_t i;

        if (strncmp(p, "bytes=", strlen("bytes=")) != 0)
                return;

        p += strlen("bytes=");

        for (i = 0; isdigit(*p) && i < sizeof(buf) - 1; i++, p++)
                buf[i] = *p;
        buf[i] = '\0';

        if (*p != '-')
                return;

        if (buf[0] != '\0')
                start = atol(buf);

        for (i = 0, p++; isdigit(*p) && i < sizeof(buf) - 1; i++, p++)
                buf[i] = *p;
        buf[i] = '\0';

        if (*p != '\0' && *p != '-')
                return;

        if (buf[0] != '\0')
                end = atol(buf);

        if ((start >  -1 && end == -1)
        ||  (start == -1 && end >  -1)
        ||  (start >  -1 && end >  -1 && start <= end)) {
                conn->req.range.start = start;
                conn->req.range.end = end;
        }
}

static int hprintf(HConn *conn, const char *fmt, ...)
{
        va_list ap, apcopy;
        int     ret;

        va_start(ap, fmt);
        va_start(apcopy, fmt);
        ret = bufvprintf(&conn->resp.content, fmt, ap, apcopy);
        va_end(ap);
        va_end(apcopy);

        return ret >= 0 ? 200 : 500;
}

static int haddheader(HConn *conn, const char *name, const char *value, ...)
{
        Buffer  *buf = &conn->resp.head;
        va_list  ap, apcopy;
        int      ret;

        if (bufputs(buf, name) || bufputs(buf, ": ") == -1)
                return 500;

        va_start(ap, value);
        va_start(apcopy, value);
        ret = bufvprintf(buf, value, ap, apcopy);
        va_end(ap);
        va_end(apcopy);

        if (ret < 0 || bufputs(buf, "\r\n") == -1)
                return 500;

        return 200;
}

static char *percentdec(char *s)
{
        char *e = s;    /* encoded character pointer */
        char *d = s;    /* decoded character pointer */

        for (; *e; e++, d++) {
                if (*e == '%' && isxdigit(e[1]) && isxdigit(e[2])) {
                        e++;
                        *d  = (isdigit(*e) ? (*e - '0') : (toupper(*e) - 'A' + 0x0A)) * 0x10;
                        e++;
                        *d += (isdigit(*e) ? (*e - '0') : (toupper(*e) - 'A' + 0x0A));
                } else
                        *d = *e == '+' ? ' ' : *e;
        }

        *d = '\0';
        return s;
}

static void loghconn(const HConn *conn)
{
        struct sockaddr_storage ss;
        socklen_t               sslen = sizeof(ss);
        char                    address[INET6_ADDRSTRLEN], port[6], timestamp[64];

        memset(&ss, 0, sslen);
        address[0] = port[0] = '\0';

        if (getpeername(fileno(conn->in), (struct sockaddr *)&ss, &sslen) == -1)
                logerr("getpeername: %s", strerror(errno));
        else
                ssinetntop(&ss, address, port);

        strftime(timestamp, sizeof(timestamp), "%d/%b/%Y:%H:%M:%S %Z", localtime(&conn->req.timestamp));

        printf("%s:%s [%s] \"%s %s\" %d %s %lu\n",
               address,
               port,
               timestamp,
               conn->req.method,
               conn->req.uri ? conn->req.uri : "",
               conn->resp.status,
               strstatus(conn->resp.status),
               (unsigned long)conn->resp.sent);
}

static char *strtrim(char *s)
{
        size_t len;
        char *end;

        for (; *s == ' ' || *s == '\t'; s++)
                ;

        len = strlen(s);

        if (len > 0) {
                end = s + len - 1;
                for (; end > s && (*end == ' ' || *end == '\t'); end--)
                        ;
                end[1] = '\0';
        }

        return s;
}

static const char *strstatus(int status)
{
        switch (status) {
        case 200: return "OK";
        case 206: return "Partial Content";
        case 301: return "Moved Permanently";
        case 304: return "Not Modified";
        case 400: return "Bad Request";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 408: return "Request Timeout";
        case 413: return "Payload Too Large";
        case 414: return "URI Too Long";
        case 416: return "Range Not Satisfiable";
        case 500: return "Internal Server Error";
        case 501: return "Not Implemented";
        case 505: return "HTTP Version Not Supported";
        default:  return NULL;
        }
}

static void logerr(const char *fmt, ...)
{
        va_list ap;

        va_start(ap, fmt);
        vlogerr(fmt, ap);
        va_end(ap);
}

static void vlogerr(const char *fmt, va_list ap)
{
        fprintf(stderr, "sws: ");
        vfprintf(stderr, fmt, ap);
        fprintf(stderr, "\n");
}

static void die(const char *reason, ...)
{
        va_list ap;

        va_start(ap, reason);
        vlogerr(reason, ap);
        va_end(ap);

        cleanup();
        exit(EXIT_FAILURE);
}

static void cleanup(void)
{
        close(server.sock);
        free(server.rootpath);
}

int main(int argc, char **argv)
{
        Args args;

        memset(&args, 0, sizeof(args));

        parseargs(&args, argc, argv);
        if (args.help)
                die(USAGE);
        if (args.version)
                die(VERSION);

        initsrv(&args);
        logsrvinfo();
        run();
        cleanup();

        return 0;
}
