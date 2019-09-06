/* See LICENSE file for copyright and license details. */

#include <getopt.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define HELP            "usage: sws -aprihv\n\n" \
                        "Simple Small Static Stupid Whatever Web Server.\n\n" \
                        "  -a  ip address\n" \
                        "  -p  port\n" \
                        "  -r  webroot\n" \
                        "  -i  index page\n" \
                        "  -h  help message\n" \
                        "  -v  version"

#define VERSION         "0.6.0"
#define DEFAULTINDEX    "index.html"

#define BUFCHUNK        256             /* minimum buffer capacity increment */

#define MAX(a, b)       ((a) > (b) ? (a) : (b))

typedef struct Buffer   Buffer;
typedef struct Args     Args;
typedef struct HRange   HRange;
typedef struct HReq     HReq;
typedef struct HResp    HResp;
typedef struct HConn    HConn;

struct Buffer                           /* autogrowing characters buffer */
{
        size_t          cap;
        size_t          len;
        unsigned char  *data;
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
        char            address[128];   /* printable server address (ipv4 or ipv6) */
        char            port[6];        /* printable server port (real port, not 0) */
        char           *rootpath;       /* current working directory absolute path */
        const char     *index;          /* index filename for directories requests */
};

struct HRange                           /* http range header first value */
{
        long            start;          /* range start. -1 if -nnn */
        long            end;            /* range end. -1 if nnn- */
};

struct HReq                             /* http request */
{
        time_t          timestamp;
        char            method[16];
        char           *uri;            /* decoded request uri */
        int             keepalive;      /* connection header (1 keep-alive, 0 close) */
        time_t          ifmodsince;     /* if modified since header timestamp */
        HRange          range;
};

struct HResp                            /* http response */
{
        int             status;         /* response http status */
        Buffer          head;           /* buffer for response line and headers */
        Buffer          content;        /* buffer for generated responses */
        FILE           *file;           /* file to send as response or NULL if sending generated response */
};

struct HConn                            /* http connection */
{
        FILE           *in;             /* input stream */
        FILE           *out;            /* output stream */
        HReq            req;
        HResp           resp;
        Buffer          buf;            /* common buffer used e.g. for building file paths */
};

static struct Server server;            /* global server informations */

static void     bufinit(Buffer *);
static int      bufputs(Buffer *, const char *s);
static int      bufputc(Buffer *, int c);
static int      bufreserve(Buffer *, size_t n);
static void     bufclear(Buffer *);
static void     buftruncate(Buffer *, size_t newlen);
static void     bufdeinit(Buffer *);
static void     parseargs(Args *, int argc, char **argv);
static void     srvinit(Args *);
static void     logerr(const char *fmt, ...);
static void     vlogerr(const char *fmt, va_list ap);
static void     cleanup(void);
static void     die(const char *reason, ...);

static void bufinit(Buffer *buf)
{
        buf->cap  = 0;
        buf->len  = 0;
        buf->data = NULL;
}

static int bufputs(Buffer *buf, const char *s)
{
        while (*s)
                if (bufputc(buf, *s++) == EOF)
                        return EOF;

        return 1;
}

static int bufputc(Buffer *buf, int c)
{
        if (buf->len == buf->cap && bufreserve(buf, 1) == EOF)
                return EOF;

        return buf->data[buf->len++] = (unsigned char)c;
}

static int bufreserve(Buffer *buf, size_t n)
{
        size_t available, newcap;
        unsigned char *p;

        available = buf->cap - buf->len;
        if (available >= n)
                return 1;

        newcap = buf->cap + MAX(BUFCHUNK, (n - available));

        p = realloc(buf->data, newcap);
        if ( ! p)
                return EOF;

        buf->cap = newcap;
        buf->data = p;
        return 1;
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

static void parseargs(Args *args, int argc, char **argv)
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

static void srvinit(Args *args)
{
        server.index = args->index ? args->index : DEFAULTINDEX;
}

static void cleanup(void)
{

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

int main(int argc, char **argv)
{
        Args args;

        memset(&args, 0, sizeof(args));

        parseargs(&args, argc, argv);
        if (args.help)
                die(HELP);
        if (args.version)
                die(VERSION);

        srvinit(&args);

        return 0;
}
