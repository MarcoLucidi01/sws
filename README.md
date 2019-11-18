sws: Simple Small Static Stupid Whatever Web Server
===================================================

I was learning about sockets and network programming (yes, [Beej's guide](http://beej.us/guide/bgnet/))
and decided to implement a tiny HEAD GET only http server as exercise.

the idea was to mimic and maybe improve what you can do with the command:

    $ python3 -m http.server

it speaks HTTP/1.0 (more or less) and it will accept HTTP/1.1 requests, anything
else will be rejected.

features
========

- Connection keep-alive
- range requests (only one byte range is allowed)
- If-Modified-Since
- directory listing
- custom index page file (default index.html)

install / uninstall
===================

to install inside directory `/usr/local/bin/` run

    $ make install

to uninstall run

    $ make uninstall

usage
=====

to serve your current working directory at http://localhost:8080 run

    $ sws

to serve directory `/foo/bar` at http://localhost:8080 run

    $ sws -r /foo/bar

to serve directory `/foo/bar` at http://localhost:6666 using file `home.html`
as index page run

    $ sws -r /foo/bar -p 6666 -i home.html

benchmarks
==========

my machine is a i5-4300U @ 1.90GHz with 4GB of RAM running Linux 4.19 (Debian 10)

13 bytes ascii file

    $ more hello
    Hello World!
    $ sws > /dev/null

    $ wrk -c 500 -t 10 -d 10s --latency http://localhost:8080/hello
    Running 10s test @ http://localhost:8080/hello
      10 threads and 500 connections
      Thread Stats   Avg      Stdev     Max   +/- Stdev
        Latency    18.71ms  107.40ms   1.67s    96.72%
        Req/Sec     0.87k   697.31     4.26k    76.36%
      Latency Distribution
         50%    3.11ms
         75%    3.96ms
         90%    5.62ms
         99%  450.05ms
      78317 requests in 10.07s, 16.51MB read
      Socket errors: connect 0, read 0, write 0, timeout 43
    Requests/sec:    7774.18
    Transfer/sec:    1.64MB

1MB random file

    $ head -c $(( 2 ** 20 )) /dev/urandom > foo
    $ sws > /dev/null

    $ wrk -c 500 -t 10 -d 10s --latency http://localhost:8080/foo
    Running 10s test @ http://localhost:8080/foo
      10 threads and 500 connections
      Thread Stats   Avg      Stdev     Max   +/- Stdev
        Latency    62.64ms  155.25ms   1.94s    94.20%
        Req/Sec   154.08     66.77   434.00     68.91%
      Latency Distribution
         50%   27.90ms
         75%   45.25ms
         90%   86.70ms
         99%  881.81ms
      15150 requests in 10.09s, 14.80GB read
      Socket errors: connect 0, read 0, write 0, timeout 20
    Requests/sec:    1501.31
    Transfer/sec:    1.47GB

64 entries directory listing

    $ ls Music/Playlist\ Pink\ Floyd/ | wc -l
    64
    $ sws > /dev/null

    $ wrk -c 500 -t 10 -d 10s --latency http://localhost:8080/Music/Playlist%20Pink%20Floyd/
    Running 10s test @ http://localhost:8080/Music/Playlist%20Pink%20Floyd/
      10 threads and 500 connections
      Thread Stats   Avg      Stdev     Max   +/- Stdev
        Latency    34.22ms  139.70ms   1.84s    95.76%
        Req/Sec   391.74    263.27     1.42k    64.00%
      Latency Distribution
         50%   10.50ms
         75%   11.54ms
         90%   12.81ms
         99%  797.23ms
      34812 requests in 10.10s, 285.65MB read
      Socket errors: connect 0, read 0, write 0, timeout 48
    Requests/sec:    3447.72
    Transfer/sec:    28.29MB

please don't use this thing in any real world environment! I use it inside my
LAN to share files, stream videos and to play around with static websites.
