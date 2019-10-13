/*
 * MIT License
 *
 * Copyright (c) 2019 Marco Lucidi
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
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
#include <sys/stat.h>
#include <sys/time.h>
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
#define CONNTIMEOUT     30              /* seconds a connection is allowed to remain in idle */
#define CONNMAXREQS     200             /* max number of requests allowed on a single connection */
#define METHODMAX       8               /* request method max size */
#define URIMAX          8192            /* request uri max size */
#define HEADERMAX       4096            /* single request header max size */
#define MAXHEADERS      100             /* max number of request headers allowed */
#define HDATEFMT        "%a, %d %b %Y %H:%M:%S GMT"     /* http date format for strftime */
#define BUFCHUNK        256             /* minimum buffer capacity increment */

#define ARRAYLEN(a)     (sizeof((a)) / sizeof((a)[0]))
#define MAX(a, b)       ((a) > (b) ? (a) : (b))
#define MIN(a, b)       ((a) < (b) ? (a) : (b))
#define ISASCII(c)      ((c) > 0 && (c) < 128)

typedef struct Buffer           Buffer;
typedef struct Args             Args;
typedef struct HParser          HParser;
typedef struct HRange           HRange;
typedef struct HRequest         HRequest;
typedef struct HResponse        HResponse;
typedef struct HConnection      HConnection;
typedef struct MimeType         MimeType;
typedef struct sockaddr_storage SockaddrStorage;

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
        void          (*parse)(HConnection *, const char *value);       /* parser function */
};

struct HRange                           /* http range header first value */
{
        long            start;          /* range start. -1 if -nnn */
        long            end;            /* range end. -1 if nnn- */
};

struct HRequest                         /* http request aka req */
{
        time_t          timestamp;      /* request arrival timestamp */
        char            method[METHODMAX];
        char           *uri;            /* decoded request uri */
        int             keepalive;      /* connection header (1 keep-alive, 0 close) */
        time_t          ifmodsince;     /* if modified since header timestamp */
        HRange          range;
        long            contentlen;     /* request payload length. If present will be skipped */
};

struct HResponse                        /* http response aka resp */
{
        int             status;         /* response http status */
        Buffer          headers;        /* buffer for response headers */
        Buffer          content;        /* buffer for generated responses */
        FILE           *file;           /* file to send as response or NULL if sending generated response */
        long            filesize;       /* size of resp.file taken from stat */
        size_t          sent;           /* number of payload bytes sent to client */
};

struct HConnection                      /* http connection aka conn */
{
        SockaddrStorage addr;           /* client address */
        FILE           *in;             /* input stream */
        FILE           *out;            /* output stream */
        int             reqsleft;       /* number of remaining requests allowed on this connection */
        HRequest        req;
        HResponse       resp;
        Buffer          buf;            /* common buffer used e.g. for building file paths */
};

struct MimeType                         /* mime type pair stored in table */
{
        const char     *ext;            /* file extension used for searching in table */
        const char     *mime;           /* mime type string */
};

static void             bufinit(Buffer *);
static int              bufputs(Buffer *, const char *);
static int              bufputc(Buffer *, int);
static int              bufvprintf(Buffer *, const char *, va_list ap, va_list apcopy);
static int              bufreserve(Buffer *, size_t);
static size_t           bufavailable(Buffer *);
static void             bufclear(Buffer *);
static void             buftruncate(Buffer *, size_t);
static void             bufdeinit(Buffer *);
static void             parseargs(Args *, int argc, char *const *argv);
static void             initsrv(const Args *);
static void             setuputctz(void);
static void             setupsock(const Args *);
static void             setuprootpath(const Args *);
static void             setupsighandler(void);
static void             sighandler(int);
static void             logsrvinfo(void);
static void             ssinetntop(const SockaddrStorage *, char *address, char *port);
static void             run(void);
static void             handlereq(int);
static HConnection     *hopen(int);
static int              setsocktimeout(int, time_t);
static void             hclear(HConnection *);
static void             hclose(HConnection *);
static int              isalive(HConnection *);
static int              recvreq(HConnection *);
static int              parsemethod(HConnection *);
static int              parseuri(HConnection *);
static int              parseversion(HConnection *);
static int              parseheaders(HConnection *);
static HParser         *findhparser(const char *name);
static int              hparsercmp(const void *name, const void *parser);
static void             parseconnection(HConnection *, const char *);
static void             parsecontentlen(HConnection *, const char *);
static void             parseifmodsince(HConnection *, const char *);
static void             parserange(HConnection *, const char *);
static int              buildresp(HConnection *);
static int              buildresperror(HConnection *, int errstatus);
static int              buildrespfile(HConnection *, const char *path, const struct stat *);
static int              buildrespdir(HConnection *, const char *path);
static int              scandirfilter(const struct dirent *);
static int              scandircmp(const struct dirent **, const struct dirent **);
static int              buildrespdirlist(HConnection *, const char *path, struct dirent **, int n);
static int              sendresp(HConnection *);
static int              fixhrange(HRange *, long contentlen);
static int              hprintf(HConnection *, const char *, ...);
static int              addheader(HConnection *, const char *name, const char *value, ...);
static char            *uridecode(char *);
static char            *uriencode(const char *, char *buf, size_t size);
static char            *time2hdate(time_t, char *buf, size_t size);
static time_t           hdate2time(const char *);
static const char      *parsemimetype(const char *fname, FILE *);
static int              mimetypecmp(const void *ext, const void *mimetype);
static void             logconnection(const HConnection *);
static char            *strtrim(char *);
static const char      *strstatus(int);
static void             logerror(const char *, ...);
static void             vlogerror(const char *, va_list);
static void             die(const char *, ...);
static void             cleanup(void);

static HParser hparsers[] =     /* keep sorted */
{
        { "connection",         parseconnection },
        { "content-length",     parsecontentlen },
        { "if-modified-since",  parseifmodsince },
        { "range",              parserange      },
};

static MimeType mimetypes[] =   /* keep sorted by extension */
{
        { "3g2",        "video/3gpp2" },
        { "3gp",        "video/3gpp" },
        { "7z",         "application/x-7z-compressed" },
        { "aac",        "audio/aac" },
        { "abw",        "application/x-abiword" },
        { "arc",        "application/x-freearc" },
        { "avi",        "video/avi" },
        { "bin",        "application/octet-stream" },
        { "bmp",        "image/bmp" },
        { "bz",         "application/x-bzip" },
        { "bz2",        "application/x-bzip2" },
        { "csh",        "application/x-csh" },
        { "css",        "text/css" },
        { "csv",        "text/csv" },
        { "doc",        "application/msword" },
        { "docx",       "application/vnd.openxmlformats-officedocument.wordprocessingml.document" },
        { "epub",       "application/epub+zip" },
        { "gif",        "image/gif" },
        { "gz",         "application/gzip" },
        { "htm",        "text/html" },
        { "html",       "text/html" },
        { "ico",        "image/vnd.microsoft.icon" },
        { "ics",        "text/calendar" },
        { "jar",        "application/java-archive" },
        { "jpeg",       "image/jpeg" },
        { "jpg",        "image/jpeg" },
        { "js",         "application/javascript" },
        { "json",       "application/json" },
        { "jsonld",     "application/ld+json" },
        { "mid",        "audio/midi" },
        { "midi",       "audio/midi" },
        { "mjs",        "application/javascript" },
        { "mp3",        "audio/mpeg" },
        { "mp4",        "video/mpeg" },
        { "mpeg",       "video/mpeg" },
        { "odp",        "application/vnd.oasis.opendocument.presentation" },
        { "ods",        "application/vnd.oasis.opendocument.spreadsheet" },
        { "odt",        "application/vnd.oasis.opendocument.text" },
        { "oga",        "audio/ogg" },
        { "ogv",        "video/ogg" },
        { "ogx",        "application/ogg" },
        { "otf",        "font/otf" },
        { "pdf",        "application/pdf" },
        { "php",        "application/php" },
        { "png",        "image/png" },
        { "ppt",        "application/vnd.ms-powerpoint" },
        { "pptx",       "application/vnd.openxmlformats-officedocument.presentationml.presentation" },
        { "rar",        "application/x-rar-compressed" },
        { "rtf",        "application/rtf" },
        { "sh",         "application/x-sh" },
        { "svg",        "image/svg+xml" },
        { "swf",        "application/x-shockwave-flash" },
        { "tar",        "application/x-tar" },
        { "tif",        "image/tiff" },
        { "tiff",       "image/tiff" },
        { "ts",         "video/mp2t" },
        { "ttf",        "font/ttf" },
        { "txt",        "text/plain" },
        { "vsd",        "application/vnd.visio" },
        { "wav",        "audio/wav" },
        { "weba",       "audio/webm" },
        { "webm",       "video/webm" },
        { "webp",       "image/webp" },
        { "woff",       "font/woff" },
        { "woff2",      "font/woff2" },
        { "xhtml",      "application/xhtml+xml" },
        { "xls",        "application/vnd.ms-excel" },
        { "xlsx",       "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" },
        { "xml",        "application/xml" },
        { "zip",        "application/zip" },
};

static struct Server server;            /* global server informations */

static void bufinit(Buffer *buf)
{
        buf->cap = 0;
        buf->len = 0;
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
        int prilen;

        if (bufavailable(buf) == 0 && bufreserve(buf, 1) == -1)
                return -1;

        if ((prilen = vsnprintf(buf->data + buf->len, bufavailable(buf), fmt, ap)) < 0)
                return -1;

        if ((unsigned int)prilen >= bufavailable(buf)) {
                if (bufreserve(buf, prilen + 1) == -1)
                        return -1;

                if ((prilen = vsnprintf(buf->data + buf->len, bufavailable(buf), fmt, apcopy)) < 0)
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

        if ((p = realloc(buf->data, newcap)) == NULL)
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

        memset(args, 0, sizeof(*args));
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
        setuputctz();
        setupsock(args);
        setuprootpath(args);
        setupsighandler();
        server.index = args->index ? args->index : DEFAULTINDEX;
}

static void setuputctz(void)
{
        if (setenv("TZ", "UTC", 1) == -1)
                die("setenv: %s", strerror(errno));
        tzset();
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

        if (p == NULL)
                die("failed to bind socket");
}

static void setuprootpath(const Args *args)
{
        Buffer buf;

        if (args->rootpath != NULL && chdir(args->rootpath) != 0)
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
        ||  sigaction(SIGCHLD, &sa, NULL) == -1
        ||  sigaction(SIGPIPE, &sa, NULL) == -1)
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
        case SIGPIPE:
                /*
                 * SIGPIPE is raised when a client prematurely closes the
                 * connection. The default behavior is to terminate the process,
                 * so we ignore it!
                 */
                break;
        }
}

static void logsrvinfo(void)
{
        SockaddrStorage ss;
        socklen_t sslen = sizeof(ss);
        char address[INET6_ADDRSTRLEN], port[6];

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

static void ssinetntop(const SockaddrStorage *ss, char *address, char *port)
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
        int client;

        server.running = 1;
        while (server.running) {
                if ((client = accept(server.sock, NULL, NULL)) == -1) {
                        if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)
                                logerror("accept: %s", strerror(errno));
                        continue;
                }

                switch (fork()) {
                case 0:
                        handlereq(client);
                        return;
                case -1:
                        logerror("fork: %s", strerror(errno));
                        /* fallthrough */
                default:
                        close(client);
                }
        }
}

static void handlereq(int client)
{
        HConnection *conn;

        if ((conn = hopen(client)) == NULL) {
                logerror("cannot open http connection");
                return;
        }

        do {
                hclear(conn);
                recvreq(conn);

                if ( ! isalive(conn))
                        break;          /* client disconnected, don't bother go on */

                conn->reqsleft--;
                buildresp(conn);
                sendresp(conn);
                fflush(conn->out);
                logconnection(conn);

        } while (conn->req.keepalive && conn->reqsleft > 0);

        hclose(conn);
}

static HConnection *hopen(int client)
{
        HConnection *conn;
        socklen_t addrlen = sizeof(SockaddrStorage);
        int outfd;

        if (setsocktimeout(client, CONNTIMEOUT) == -1)
                goto errtimeout;
        if ((conn = malloc(sizeof(*conn))) == NULL)
                goto errconn;
        if (getpeername(client, (struct sockaddr *)&conn->addr, &addrlen) == -1)
                goto erraddr;
        if ((conn->in = fdopen(client, "r")) == NULL)
                goto errin;
        if ((outfd = dup(client)) == -1)
                goto erroutfd;
        if ((conn->out = fdopen(outfd, "w")) == NULL)
                goto errout;

        conn->reqsleft = CONNMAXREQS;
        conn->req.uri = NULL;
        conn->resp.file = NULL;
        bufinit(&conn->resp.headers);
        bufinit(&conn->resp.content);
        bufinit(&conn->buf);

        hclear(conn);

        return conn;
errout:
        close(outfd);
erroutfd:
        fclose(conn->in);
errin:
erraddr:
        free(conn);
errconn:
errtimeout:
        return NULL;
}

static int setsocktimeout(int sock, time_t sec)
{
        struct timeval timeout;

        timeout.tv_sec  = sec;
        timeout.tv_usec = 0;

        if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0
        &&  setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0)
                return 0;

        return -1;
}

static void hclear(HConnection *conn)
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
        conn->resp.filesize   = -1;

        free(conn->req.uri);
        conn->req.uri = NULL;

        if (conn->resp.file)
                fclose(conn->resp.file);
        conn->resp.file = NULL;

        bufclear(&conn->resp.headers);
        bufclear(&conn->resp.content);
        bufclear(&conn->buf);
}

static void hclose(HConnection *conn)
{
        hclear(conn);   /* to free req.uri and close resp.file */
        bufdeinit(&conn->resp.headers);
        bufdeinit(&conn->resp.content);
        bufdeinit(&conn->buf);
        fclose(conn->in);
        fclose(conn->out);
        free(conn);
}

static int isalive(HConnection *conn)
{
        return ! feof(conn->in) && ! ferror(conn->in) && ! feof(conn->out) && ! ferror(conn->out);
}

static int recvreq(HConnection *conn)
{
        int ret = parsemethod(conn);

        conn->req.timestamp = time(NULL);

        /*
         * stop at first return value != 200
         */
        if (ret != 200
        ||  (ret = parseuri(conn))     != 200
        ||  (ret = parseversion(conn)) != 200
        ||  (ret = parseheaders(conn)) != 200) {
        }

        conn->resp.status = ret;
        return ret;
}

static int parsemethod(HConnection *conn)
{
        char buf[METHODMAX];
        size_t len = 0;
        int c;

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

static int parseuri(HConnection *conn)
{
        Buffer *buf = &conn->buf;
        int c;

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

        uridecode(buf->data);
        if ((conn->req.uri = strdup(buf->data)) == NULL)
                return 500;

        return 200;
}

static int parseversion(HConnection *conn)
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

static int parseheaders(HConnection *conn)
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
                                return 431;
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
                if ((value = strchr(name, ':')) == NULL)
                        return 400;     /* malformed header */

                *value++ = '\0';        /* null-terminate name string */

                if ((parser = findhparser(name)))
                        parser->parse(conn, strtrim(value));
        }

        return i < MAXHEADERS ? 200 : 431;
}

static HParser *findhparser(const char *name)
{
        return bsearch(name, hparsers, ARRAYLEN(hparsers), sizeof(*hparsers), hparsercmp);
}

static int hparsercmp(const void *name, const void *parser)
{
        return strcasecmp((const char *)name, ((const HParser *)parser)->name);
}

static void parseconnection(HConnection *conn, const char *value)
{
        conn->req.keepalive = strcmp(value, "keep-alive") == 0;
}

static void parsecontentlen(HConnection *conn, const char *value)
{
        long clen = atol(value);

        if (clen > 0)
                conn->req.contentlen = clen;
}

static void parseifmodsince(HConnection *conn, const char *value)
{
        conn->req.ifmodsince = hdate2time(value);
}

static void parserange(HConnection *conn, const char *value)
{
        const char *p = value;
        char buf[32];
        long start = -1, end = -1;
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

static int buildresp(HConnection *conn)
{
        struct stat finfo;
        const char *relpath;

        if (conn->resp.status != 200)
                return buildresperror(conn, conn->resp.status);

        relpath = strtrim(conn->req.uri);
        if (relpath[0] == '.' || strstr(relpath, "/."))
                return buildresperror(conn, 404);

        for (; *relpath == '/'; relpath++)
                ;
        if (*relpath == '\0')
                relpath = "./";

        if (lstat(relpath, &finfo) == -1)
                return buildresperror(conn, 404);

        if (S_ISREG(finfo.st_mode))
                return buildrespfile(conn, relpath, &finfo);
        else if (S_ISDIR(finfo.st_mode))
                return buildrespdir(conn, relpath);

        return buildresperror(conn, 403);
}

static int buildresperror(HConnection *conn, int errstatus)
{
        hprintf(conn, "<!DOCTYPE html><title>%d %s</title><h1>%d %s</h1>",
                errstatus, strstatus(errstatus), errstatus, strstatus(errstatus));

        addheader(conn, "Content-Type", "text/html");

        conn->resp.status = errstatus;
        return errstatus;
}

static int buildrespfile(HConnection *conn, const char *path, const struct stat *finfo)
{
        char hdate[32];
        FILE *f;

        if (conn->req.ifmodsince != -1 && difftime(finfo->st_mtime, conn->req.ifmodsince) <= 0.0) {
                conn->resp.status = 304;
                return 304;
        }

        if ((f = fopen(path, "r")) == NULL)
                return buildresperror(conn, 403);

        addheader(conn, "Accept-Ranges", "bytes");
        addheader(conn, "Last-Modified", "%s", time2hdate(finfo->st_mtime, hdate, sizeof(hdate)));
        addheader(conn, "Content-Type", "%s", parsemimetype(path, f));

        conn->resp.file = f;
        conn->resp.filesize = finfo->st_size;
        conn->resp.status = 200;
        return 200;
}

static int buildrespdir(HConnection *conn, const char *path)
{
        Buffer *buf = &conn->buf;
        size_t pathlen = strlen(path);
        struct stat finfo;
        struct dirent **entries;
        int n, ret;

        /*
         * redirect if directory path doesn't end with /
         */

        if (path[pathlen - 1] != '/') {
                if (bufreserve(buf, pathlen * 3 + 1) == -1)
                        return buildresperror(conn, 500);

                addheader(conn, "Location", "/%s/", uriencode(path, buf->data, buf->cap));
                return buildresperror(conn, 301);
        }

        /*
         * try index file
         */

        bufclear(buf);
        if (bufputs(buf, path) == -1
        ||  bufputs(buf, server.index) == -1
        ||  bufputc(buf, '\0') == -1)
                return buildresperror(conn, 500);

        if (lstat(buf->data, &finfo) == 0 && S_ISREG(finfo.st_mode))
                return buildrespfile(conn, buf->data, &finfo);

        /*
         * directory listing
         */

        if ((n = scandir(path, &entries, scandirfilter, scandircmp)) == -1)
                return buildresperror(conn, 404);

        ret = buildrespdirlist(conn, path, entries, n);

        while (n--)
                free(entries[n]);
        free(entries);

        return ret;
}

static int scandirfilter(const struct dirent *entry)
{
        return entry->d_name[0] != '.';
}

static int scandircmp(const struct dirent **a, const struct dirent **b)
{
        return strcasecmp((*a)->d_name, (*b)->d_name);
}

static int buildrespdirlist(HConnection *conn, const char *path, struct dirent **entries, int n)
{
        Buffer *buf = &conn->buf;
        struct stat finfo;
        char mtime[32];
        const char *title, *fname, *fmt;
        int i;

        title = strcmp(path, "./") == 0 ? "" : path;
        hprintf(conn, "<!DOCTYPE html><style>"
                      "table { border-collapse: collapse; }"
                      "td { border: 1px solid #ddd; padding: 10px; }"
                      "tr:nth-child(odd) { background-color: #f2f2f2; }"
                      "td:nth-child(3) { text-align: right }"
                      "a { text-decoration: none }"
                      "</style><title>/%s</title><h1>/%s</h1><table>\n",
                      title, title);

        for (i = 0; i < n; i++) {
                fname = entries[i]->d_name;

                bufclear(buf);
                bufputs(buf, path);
                bufputs(buf, fname);
                bufputc(buf, '\0');

                if (lstat(buf->data, &finfo) == -1)
                        continue;

                if (S_ISREG(finfo.st_mode))
                        fmt = "<tr><td><a href=\"%s\">%s</a></td><td>%s</td><td>%ld</td></tr>\n";
                else if (S_ISDIR(finfo.st_mode))
                        fmt = "<tr><td><a href=\"%s/\"><b>%s/</b></a></td><td>%s</td><td>%ld</td></tr>\n";
                else if (S_ISLNK(finfo.st_mode))
                        fmt = "<tr><td><a href=\"%s\">%s@</a></td><td>%s</td><td>%ld</td></tr>\n";
                else
                        continue;

                if (bufreserve(buf, strlen(fname) * 3 + 1) == -1)
                        continue;

                strftime(mtime, sizeof(mtime), "%Y-%m-%d %H:%M:%S %Z", localtime(&finfo.st_mtime));
                hprintf(conn, fmt, uriencode(fname, buf->data, buf->cap), fname, mtime, (long)finfo.st_size);
        }
        hprintf(conn, "</table>\n");

        addheader(conn, "Content-Type", "%s", "text/html");
        return 200;
}

static int sendresp(HConnection *conn)
{
        unsigned long contentlen, tosend, n;
        char hdate[32], *p;
        HRange *range;
        HRequest *req = &conn->req;
        HResponse *resp = &conn->resp;
        Buffer *buf = &conn->buf;

        contentlen = resp->file ? (unsigned long)resp->filesize : (unsigned long)resp->content.len;

        range = (req->range.start != -1 || req->range.end != -1) ? &req->range : NULL;
        if (resp->status == 200 && range && fixhrange(range, contentlen) == 0) {
                addheader(conn, "Content-Range", "bytes %ld-%ld/%lu", range->start, range->end, contentlen);
                contentlen = range->end - range->start;
                resp->status = 206;
        }

        if (req->keepalive && conn->reqsleft > 0) {
                addheader(conn, "Connection", "keep-alive");
                addheader(conn, "Keep-Alive", "timeout=%d, max=%d", CONNTIMEOUT, conn->reqsleft);
        } else
                addheader(conn, "Connection", "close");

        addheader(conn, "Content-Length", "%lu", contentlen);
        addheader(conn, "Date", "%s", time2hdate(time(NULL), hdate, sizeof(hdate)));
        addheader(conn, "Server", "sws " VERSION);

        /*
         * response head
         */

        fprintf(conn->out, "HTTP/1.0 %d %s\r\n", resp->status, strstatus(resp->status));
        fwrite(resp->headers.data, 1, resp->headers.len, conn->out);
        fputs("\r\n", conn->out);

        if (strcmp("HEAD", req->method) == 0)
                return resp->status;

        /*
         * error or generated response
         */

        if ((resp->status != 200 && resp->status != 206) || resp->file == NULL) {
                p = resp->status == 206 ? resp->content.data + range->start : resp->content.data;
                resp->sent = fwrite(p, 1, contentlen, conn->out);
                return resp->status;
        }

        /*
         * file response
         */

        if (resp->status == 206)
                fseek(resp->file, range->start, SEEK_SET);

        tosend = contentlen;
        resp->sent = 0;
        bufreserve(buf, MIN(tosend, BUFSIZ));
        while (tosend && ! ferror(resp->file) && ! feof(resp->file) && ! ferror(conn->out) && ! feof(conn->out)) {
                n = fread(buf->data, 1, MIN(tosend, buf->cap), resp->file);
                n = fwrite(buf->data, 1, n, conn->out);
                tosend -= n;
                resp->sent += n;
        }

        return resp->status;
}

static int fixhrange(HRange *range, long contentlen)
{
        long start = range->start;
        long end = range->end;

        if (start == -1 && end == -1)
                return 0;

        if (start != -1)
                end = end != -1 ? MIN(contentlen, end + 1) : contentlen;
        else {
                start = contentlen - end;
                end = contentlen;
        }

        if (start < 0 || start > end)
                return -1;

        range->start = start;
        range->end = end;
        return 0;
}

static int hprintf(HConnection *conn, const char *fmt, ...)
{
        va_list ap, apcopy;
        int ret;

        va_start(ap, fmt);
        va_start(apcopy, fmt);
        ret = bufvprintf(&conn->resp.content, fmt, ap, apcopy);
        va_end(ap);
        va_end(apcopy);

        return ret >= 0 ? 200 : 500;
}

static int addheader(HConnection *conn, const char *name, const char *value, ...)
{
        Buffer *buf = &conn->resp.headers;
        va_list ap, apcopy;
        int ret;

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

static char *uridecode(char *s)
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

static char *uriencode(const char *s, char *buf, size_t size)
{
        unsigned char c, tmp;
        size_t i = 0;

        while (*s && i < size - 1) {
                c = *s++;

                if ((c >= 'A' && c <= 'Z')
                ||  (c >= 'a' && c <= 'z')
                ||  (c >= '0' && c <= '9')
                ||  strchr(";,/?:@&=+$-_.!~*'()#", c))
                        buf[i++] = c;
                else {
                        buf[i++] = '%';

                        if (i == size - 1)
                                break;
                        tmp = c >> 0x04;
                        buf[i++] = (tmp < 10) ? ('0' + tmp) : ('A' + tmp - 10);

                        if (i == size - 1)
                                break;
                        tmp = c & 0x0F;
                        buf[i++] = (tmp < 10) ? ('0' + tmp) : ('A' + tmp - 10);
                }
        }

        buf[i] = '\0';
        return buf;
}

static char *time2hdate(time_t time, char *buf, size_t size)
{
        strftime(buf, size, HDATEFMT, gmtime(&time));;
        return buf;
}

static time_t hdate2time(const char *hdate)
{
        struct tm tm;
        char *ret;

        memset(&tm, 0, sizeof(tm));
        ret = strptime(hdate, HDATEFMT, &tm);
        if (ret == NULL || *ret != '\0')
                return -1;

        return mktime(&tm);
}

static const char *parsemimetype(const char *fname, FILE *f)
{
        const char *ext;
        MimeType *m;
        char buf[256];
        size_t n, i;

        ext = strrchr(fname, '.');
        if (ext && (m = bsearch(++ext, mimetypes, ARRAYLEN(mimetypes), sizeof(*mimetypes), mimetypecmp)))
                return m->mime;

        n = fread(buf, sizeof(*buf), sizeof(buf), f);
        rewind(f);
        for (i = 0; i < n; i++)
                if ( ! ISASCII(buf[i]))
                        return "application/octet-stream";

        return "text/plain";
}

static int mimetypecmp(const void *ext, const void *mimetype)
{
        return strcasecmp((const char *)ext, ((const MimeType *)mimetype)->ext);
}

static void logconnection(const HConnection *conn)
{
        char address[INET6_ADDRSTRLEN], port[6], date[64];

        address[0] = port[0] = date[0] = '\0';
        ssinetntop(&conn->addr, address, port);
        strftime(date, sizeof(date), "%d/%b/%Y:%H:%M:%S %Z", gmtime(&conn->req.timestamp));

        printf("%s [%s] \"%s %s\" %d %s %lu\n",
               address,
               date,
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
        case 414: return "URI Too Long";
        case 431: return "Request Header Fields Too Large";
        case 500: return "Internal Server Error";
        case 501: return "Not Implemented";
        case 505: return "HTTP Version Not Supported";
        default:  return NULL;
        }
}

static void logerror(const char *fmt, ...)
{
        va_list ap;

        va_start(ap, fmt);
        vlogerror(fmt, ap);
        va_end(ap);
}

static void vlogerror(const char *fmt, va_list ap)
{
        fprintf(stderr, "sws: ");
        vfprintf(stderr, fmt, ap);
        fprintf(stderr, "\n");
}

static void die(const char *reason, ...)
{
        va_list ap;

        va_start(ap, reason);
        vlogerror(reason, ap);
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
