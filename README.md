sws: Simple Small Static Stupid Whatever Web Server
===================================================

I was learning about sockets and network programming (yes, [Beej's guide](http://beej.us/guide/bgnet/))
and decided to implement a tiny HEAD GET only http server as exercise.

The idea was to mimic and maybe improve what you can do with the command:

    $ python3 -m http.server

features
========

- Connection keep-alive
- range requests (only one byte range is allowed)
- If-Modified-Since
- directory listing
- custom index page file (default index.html)

install
=======

    $ make install

uninstall
=========

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


please don't use this thing in any real word environment! I use it inside my LAN
to share files, stream videos and to play around with static websites.
