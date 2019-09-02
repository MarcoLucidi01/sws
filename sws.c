/* See LICENSE file for copyright and license details. */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define VERSION         "0.6.0"

#define BUFCHUNK        256             /* minimum buffer capacity increment */

#define MAX(a, b)       ((a) > (b) ? (a) : (b))

typedef struct Buffer   Buffer;
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

int main(int argc, char **argv)
{
        (void)server;
        (void)argc;
        (void)argv;
        return 0;
}
