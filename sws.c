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
#include <assert.h>
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
#include <time.h>
#include <unistd.h>

#define USAGE           "usage: sws -aprihv\n\n" \
                        "Simple Small Static Stupid Whatever Web Server\n\n" \
                        "  -a  bind address, default all interfaces\n" \
                        "  -p  port, default 8080\n" \
                        "  -r  rootpath, default current working directory\n" \
                        "  -i  index page file name, default index.html\n" \
                        "  -h  help message\n" \
                        "  -v  version\n\n" \
                        "repo: https://github.com/MarcoLucidi01/sws"
#define VERSION         "0.6.0"
#define DEFAULTADDRESS  NULL            /* to get wildcard address from getaddrinfo() if address (-a) is not specified */
#define DEFAULTPORT     "8080"
#define DEFAULTROOTPATH "."             /* current working directory */
#define DEFAULTINDEX    "index.html"
#define BACKLOG         10              /* backlog argument for listen() syscall */
#define CONNTIMEOUT     30              /* seconds a connection is allowed to remain in idle */
#define CONNMAXREQS     200             /* max number of requests allowed on a single connection */
#define METHODMAX       8               /* request method max size */
#define URIMAX          8192            /* request uri max size */
#define HEADERMAX       4096            /* single request header max size */
#define MAXHEADERS      100             /* max number of request headers allowed */
#define HDATEFMT        "%a, %d %b %Y %H:%M:%S GMT"     /* http date format for strftime */
#define DATEMAX         64              /* size for date buffers (both log and http) */
#define BUFCHUNK        256             /* minimum buffer capacity increment */

#define ARRAYLEN(a)     (sizeof((a)) / sizeof((a)[0]))
#define MAX(a, b)       ((a) > (b) ? (a) : (b))
#define MIN(a, b)       ((a) < (b) ? (a) : (b))

typedef struct Buffer           Buffer;
typedef struct Args             Args;
typedef struct Server           Server;
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

struct Server                           /* server runtime informations */
{
        int                     sock;           /* server listening socket */
        volatile sig_atomic_t   running;        /* 1 if running, 0 if stopped */
        char                   *rootpath;       /* current working directory absolute path */
        const char             *index;          /* index filename for directories requests */
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
        char            ifmodsince[DATEMAX];    /* if modified since header value */
        HRange          range;
};

struct HResponse                        /* http response aka resp */
{
        int             status;         /* response http status */
        Buffer          headers;        /* buffer for response headers */
        Buffer          content;        /* buffer for generated responses */
        FILE           *file;           /* file to send as response or NULL if sending generated response */
        long            filesize;       /* size of resp.file taken from stat */
        size_t          bsent;          /* number of payload bytes sent to client */
};

struct HConnection                      /* http connection aka conn */
{
        SockaddrStorage addr;           /* client address */
        FILE           *in;             /* input stream */
        FILE           *out;            /* output stream */
        int             reqsleft;       /* number of remaining requests allowed on this connection */
        HRequest        req;            /* current request */
        HResponse       resp;           /* current response */
        Buffer          buf;            /* common reusable buffer used e.g. for building file paths */
};

struct MimeType                         /* mime type pair stored in table */
{
        const char     *ext;            /* file extension used for searching in table */
        const char     *mime;           /* mime type string */
};

static void             parseargs(Args *, int, char *const *);
static void             initsrv(const Args *);
static void             setupsock(const Args *);
static void             setuprootpath(const Args *);
static void             setupsighandlers(void);
static void             stop(int);
static void             logsrvinfo(void);
static void             ssinetntop(const SockaddrStorage *, char *, char *);
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
static void             parseconnection(HConnection *, const char *);
static void             parseifmodsince(HConnection *, const char *);
static void             parserange(HConnection *, const char *);
static int              buildresp(HConnection *);
static int              buildresperror(HConnection *, int);
static int              buildrespfile(HConnection *, const char *, const struct stat *);
static int              buildrespdir(HConnection *, const char *);
static int              scandirfilter(const struct dirent *);
static int              scandircmp(const struct dirent **, const struct dirent **);
static int              buildrespdirlist(HConnection *, const char *, struct dirent **, int);
static int              sendresp(HConnection *);
static int              fixhrange(HRange *, long);
static int              hprintf(HConnection *, const char *, ...);
static int              addheader(HConnection *, const char *, const char *, ...);
static char            *uridecode(char *);
static char            *uriencode(const char *, char *, size_t);
static char            *time2hdate(time_t, char *);
static const char      *parsemimetype(const char *, FILE *);
static int              mimetypecmp(const void *, const void *);
static void             logconnection(const HConnection *);
static char            *strtrim(char *);
static const char      *strstatus(int);
static void             logerror(const char *, ...);
static void             vlogerror(const char *, va_list);
static void             die(const char *, ...);
static void             cleanup(void);
static void             bufinit(Buffer *);
static int              bufputs(Buffer *, const char *);
static int              bufputc(Buffer *, int);
static int              bufvprintf(Buffer *, const char *, va_list, va_list);
static int              bufreserve(Buffer *, size_t);
static size_t           bufavailable(Buffer *);
static void             bufclear(Buffer *);
static void             buftruncate(Buffer *, size_t);
static void             bufdeinit(Buffer *);

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
        { "mp4",        "video/mp4" },
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

static Server server = { -1, 0, NULL, NULL };   /* global server runtime informations */

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

static void parseargs(Args *args, int argc, char *const *argv)
{
        int opt;

        args->address   = DEFAULTADDRESS;
        args->port      = DEFAULTPORT;
        args->rootpath  = DEFAULTROOTPATH;
        args->index     = DEFAULTINDEX;
        args->help      = 0;
        args->version   = 0;

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
        setvbuf(stdout, NULL, _IOLBF, 0);       /* line buffer even when stdout is not a terminal */
        setupsock(args);
        setuprootpath(args);
        setupsighandlers();
        server.index = args->index;
}

static void setupsock(const Args *args)
{
        struct addrinfo hints, *info, *p;
        int err, yes = 1;

        memset(&hints, 0, sizeof(hints));
        hints.ai_family   = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags    = AI_PASSIVE;

        err = getaddrinfo(args->address, args->port, &hints, &info);
        if (err)
                die("getaddrinfo: %s", gai_strerror(err));

        for (p = info; p != NULL; p = p->ai_next) {
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
                if (listen(server.sock, BACKLOG) == -1) {
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

        if (chdir(args->rootpath) != 0)
                die("chdir: %s", strerror(errno));

        bufinit(&buf);
        for (;;) {
                if (bufreserve(&buf, buf.cap + BUFCHUNK) == -1)
                        die("bufreserve: %s", strerror(errno));

                server.rootpath = buf.data;
                if (getcwd(server.rootpath, buf.cap))
                        break;
                if (errno != ERANGE)
                        die("getcwd: %s", strerror(errno));
        }
}

static void setupsighandlers(void)
{
        struct sigaction sa;

        memset(&sa, 0, sizeof(sa));

        sa.sa_handler = stop;
        if (sigaction(SIGINT, &sa, NULL) == -1 || sigaction(SIGTERM, &sa, NULL) == -1)
                die("sigaction: %s", strerror(errno));

        /*
         * SIG_IGN SIGCHLD prevents zombies creation since POSIX.1 2001.
         *
         * SIGPIPE is raised when a client prematurely closes the connection.
         * Default behavior is to terminate the process, so we ignore it to
         * handle the error.
         */
        sa.sa_handler = SIG_IGN;
        if (sigaction(SIGCHLD, &sa, NULL) == -1 || sigaction(SIGPIPE, &sa, NULL) == -1)
                die("sigaction: %s", strerror(errno));
}

static void stop(int sig)
{
        (void)sig;

        server.running = 0;
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

        printf("serving %s at http://%s:%s pid is %ld\n",
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
                client = accept(server.sock, NULL, NULL);
                if (client == -1) {
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
        HConnection *conn = hopen(client);

        if (conn == NULL) {
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
                logconnection(conn);

        } while (conn->req.keepalive && conn->reqsleft > 0);

        hclose(conn);
}

static HConnection *hopen(int client)
{
        HConnection *conn = NULL;
        socklen_t addrlen = sizeof(SockaddrStorage);
        int outfd = -1;

        if (setsocktimeout(client, CONNTIMEOUT) == -1)
                goto error;

        conn = malloc(sizeof(*conn));
        if (conn == NULL)
                goto error;

        conn->in = fdopen(client, "r");
        if (conn->in == NULL)
                goto error;

        if (getpeername(client, (struct sockaddr *)&conn->addr, &addrlen) == -1)
                goto error;

        outfd = dup(client);
        if (outfd == -1)
                goto error;

        conn->out = fdopen(outfd, "w");
        if (conn->out == NULL)
                goto error;

        conn->reqsleft  = CONNMAXREQS;
        conn->req.uri   = NULL;
        conn->resp.file = NULL;

        bufinit(&conn->resp.headers);
        bufinit(&conn->resp.content);
        bufinit(&conn->buf);

        hclear(conn);
        return conn;

error:
        if (conn != NULL) {
                if (conn->in != NULL)
                        fclose(conn->in);
                free(conn);
        }
        if (outfd != -1)
                close(outfd);

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
        conn->req.timestamp     = (time_t)-1;
        conn->req.method[0]     = '\0';
        conn->req.keepalive     = 0;
        conn->req.ifmodsince[0] = '\0';
        conn->req.range.start   = -1;
        conn->req.range.end     = -1;
        conn->resp.status       = 500;
        conn->resp.bsent        = 0;
        conn->resp.filesize     = -1;

        free(conn->req.uri);
        conn->req.uri = NULL;

        if (conn->resp.file != NULL)
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

        if (ret != 200)
                goto done;

        ret = parseuri(conn);
        if (ret != 200)
                goto done;

        ret = parseversion(conn);
        if (ret != 200)
                goto done;

        ret = parseheaders(conn);

done:
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
        conn->req.uri = strdup(buf->data);
        if (conn->req.uri == NULL)
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
                value = strchr(name, ':');
                if (value == NULL)
                        return 400;     /* malformed header */

                *value++ = '\0';        /* null-terminate name string */
                value = strtrim(value);

                if (strcasecmp("connection", name) == 0)
                        parseconnection(conn, value);
                else if (strcasecmp("if-modified-since", name) == 0)
                        parseifmodsince(conn, value);
                else if (strcasecmp("range", name) == 0)
                        parserange(conn, value);
        }

        return i < MAXHEADERS ? 200 : 431;
}

static void parseconnection(HConnection *conn, const char *value)
{
        conn->req.keepalive = strcmp(value, "keep-alive") == 0;
}

static void parseifmodsince(HConnection *conn, const char *value)
{
        size_t len = MIN(strlen(value), sizeof(conn->req.ifmodsince) - 1);

        memcpy(conn->req.ifmodsince, value, len);
        conn->req.ifmodsince[len] = '\0';
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
        if (relpath[0] == '.' || strstr(relpath, "/.") != NULL)
                return buildresperror(conn, 404);

        for (; *relpath == '/'; relpath++)
                ;
        if (*relpath == '\0')
                relpath = "./";

        if (stat(relpath, &finfo) == -1)
                return buildresperror(conn, 404);

        if (S_ISREG(finfo.st_mode))
                return buildrespfile(conn, relpath, &finfo);
        else if (S_ISDIR(finfo.st_mode))
                return buildrespdir(conn, relpath);

        return buildresperror(conn, 403);
}

static int buildresperror(HConnection *conn, int errstatus)
{
        hprintf(conn, "<!DOCTYPE html><meta charset=\"utf-8\"/><title>%d %s</title><h1>%d %s</h1>",
                errstatus, strstatus(errstatus), errstatus, strstatus(errstatus));

        addheader(conn, "Content-Type", "text/html");

        conn->resp.status = errstatus;
        return errstatus;
}

static int buildrespfile(HConnection *conn, const char *path, const struct stat *finfo)
{
        char lastmod[DATEMAX];
        FILE *f;

        time2hdate(finfo->st_mtime, lastmod);
        if (strcmp(lastmod, conn->req.ifmodsince) == 0) {
                conn->resp.status = 304;
                return 304;
        }

        f = fopen(path, "r");
        if (f == NULL)
                return buildresperror(conn, 403);

        addheader(conn, "Accept-Ranges", "bytes");
        addheader(conn, "Last-Modified", "%s", lastmod);
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

        assert(buf->data != path);

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

        if (stat(buf->data, &finfo) == 0 && S_ISREG(finfo.st_mode))
                return buildrespfile(conn, buf->data, &finfo);

        /*
         * directory listing
         */
        n = scandir(path, &entries, scandirfilter, scandircmp);
        if (n == -1)
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
        char mtime[DATEMAX];
        const char *title, *fname, *fmt;
        int i;

        assert(buf->data != path);

        title = strcmp(path, "./") == 0 ? "" : path;
        hprintf(conn, "<!DOCTYPE html><meta charset=\"utf-8\"/><style>"
                      " table { border-collapse: collapse; }"
                      " td { border: 1px solid #ddd; padding: 10px; }"
                      " tr:nth-child(odd) { background-color: #f2f2f2; }"
                      " td:nth-child(3) { text-align: right }"
                      " a { text-decoration: none }"
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
        char hdate[DATEMAX], *p;
        HRange *range;
        HRequest *req = &conn->req;
        HResponse *resp = &conn->resp;
        Buffer *buf = &conn->buf;

        contentlen = resp->file ? (unsigned long)resp->filesize : (unsigned long)resp->content.len;

        range = (req->range.start != -1 || req->range.end != -1) ? &req->range : NULL;
        if (resp->status == 200 && range && fixhrange(range, contentlen) == 0) {
                addheader(conn, "Content-Range", "bytes %ld-%ld/%lu", range->start, range->end, contentlen);
                contentlen = range->end - range->start + 1;
                resp->status = 206;
        }

        if (req->keepalive && conn->reqsleft > 0) {
                addheader(conn, "Connection", "keep-alive");
                addheader(conn, "Keep-Alive", "timeout=%d, max=%d", CONNTIMEOUT, conn->reqsleft);
        } else
                addheader(conn, "Connection", "close");

        addheader(conn, "Content-Length", "%lu", contentlen);
        addheader(conn, "Date", "%s", time2hdate(time(NULL), hdate));
        addheader(conn, "Server", "sws " VERSION);

        /*
         * response head
         */
        fprintf(conn->out, "HTTP/1.0 %d %s\r\n", resp->status, strstatus(resp->status));
        fwrite(resp->headers.data, 1, resp->headers.len, conn->out);
        fputs("\r\n", conn->out);

        if (strcmp("HEAD", req->method) == 0)
                goto done;

        /*
         * error or generated response
         */
        if ((resp->status != 200 && resp->status != 206) || resp->file == NULL) {
                p = resp->status == 206 ? resp->content.data + range->start : resp->content.data;
                resp->bsent = fwrite(p, 1, contentlen, conn->out);
                goto done;
        }

        /*
         * file response
         */
        if (resp->status == 206)
                fseek(resp->file, range->start, SEEK_SET);

        tosend = contentlen;
        resp->bsent = 0;
        bufreserve(buf, MIN(tosend, BUFSIZ));
        while (tosend > 0 && isalive(conn) && ! ferror(resp->file) && ! feof(resp->file)) {
                n = fread(buf->data, 1, MIN(tosend, buf->cap), resp->file);
                n = fwrite(buf->data, 1, n, conn->out);
                tosend -= n;
                resp->bsent += n;
        }

done:
        fflush(conn->out);
        return resp->status;
}

static int fixhrange(HRange *range, long contentlen)
{
        long start = range->start;
        long end = range->end;

        if (start == -1 && end == -1)
                return 0;

        if (start != -1)
                end = end != -1 ? MIN(contentlen - 1, end) : contentlen - 1;
        else {
                start = contentlen - end;
                end = contentlen - 1;
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

        if (bufputs(buf, name) == -1 || bufputs(buf, ": ") == -1)
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

                if (isalnum(c) || strchr(";,/?:@&=+$-_.!~*'()#", c))
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

static char *time2hdate(time_t time, char *buf)
{
        strftime(buf, DATEMAX, HDATEFMT, gmtime(&time));
        return buf;
}

static const char *parsemimetype(const char *fname, FILE *f)
{
        const char *ext;
        MimeType *m;
        char buf[256];
        size_t n, i;

        ext = strrchr(fname, '.');
        if (ext != NULL) {
                ext++;
                m = bsearch(ext, mimetypes, ARRAYLEN(mimetypes), sizeof(*mimetypes), mimetypecmp);
                if (m != NULL)
                        return m->mime;
        }

        n = fread(buf, sizeof(*buf), sizeof(buf), f);
        rewind(f);
        for (i = 0; i < n; i++)
                if ( ! isprint(buf[i]) && ! isspace(buf[i]))
                        return "application/octet-stream";

        return "text/plain";
}

static int mimetypecmp(const void *ext, const void *mimetype)
{
        return strcasecmp((const char *)ext, ((const MimeType *)mimetype)->ext);
}

static void logconnection(const HConnection *conn)
{
        char address[INET6_ADDRSTRLEN], port[6], date[DATEMAX];

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
               (unsigned long)conn->resp.bsent);
}

static char *strtrim(char *s)
{
        size_t len;
        char *end;

        for (; isspace(*s); s++)
                ;

        len = strlen(s);
        if (len > 0) {
                for (end = s + len - 1; end > s && isspace(*end); end--)
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
        }

        assert(0);      /* not reached */
        return NULL;
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
        if (server.sock != -1)
                close(server.sock);
        free(server.rootpath);
}

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

        prilen = vsnprintf(buf->data + buf->len, bufavailable(buf), fmt, ap);
        if (prilen < 0)
                return -1;

        if ((unsigned int)prilen >= bufavailable(buf)) {
                if (bufreserve(buf, prilen + 1) == -1)
                        return -1;
                prilen = vsnprintf(buf->data + buf->len, bufavailable(buf), fmt, apcopy);
                if (prilen < 0)
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
        p = realloc(buf->data, newcap);
        if (p == NULL)
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
