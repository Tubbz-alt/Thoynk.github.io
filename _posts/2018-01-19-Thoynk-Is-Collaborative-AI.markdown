---
layout: post
title:  "Thoynk Is Collaborative AI!"
date:   2018-01-19 12:41:30 -0600
categories: Thoynk update
---
This is a trial run of Jekyll for Thoynk ... we're trying Jekyll for a lot of different reasons ... [way too many developers continue to be fanatically enthusiastic about Jekyll](https://stackshare.io/stackups/hugo-vs-jekyll-vs-pelican) and *arguments freight trains don't end well for the guy who wants to argue* ... [Jekyll plays well with Github Pages](https://github.com/blog/2277-what-s-new-in-github-pages-with-jekyll-3-3) and with things such as automatically rendering markdown documents, from an RMarkdown Notebook or other sources, [GitHub is doing a lot to support data science workflows](https://resources.github.com/webcasts/Enabling-Data-Science-with-GitHub/) ... and Jekyll has been around, so it does a lot of different little things that are very useful, such powerful support for code snippets in different languages such this gist from [Peter Hintjens CurveMQ proof of concept](https://gist.github.com/hintjens/5137685):

{% highlight c %}
#=> Remember, this is JUST an example to show highlighting functionality ...
//  Proof of concept CurveCP handshake over 0MQ.
//
//  Demonstrates a confidential, authenticated connection between
//  two 0MQ peers (two DEALER sockets in this example). See the
//  curvecp.org website for details of the security design.
//
//  This is a flat walk-through in code with minimal abstraction.
//  The next version of this code will be more packaged.
//  
//  IMPORTANT NOTE: this code has not been reviewed by security experts
//  and is for demonstration purposes only.

//  ---------------------------------------------------------------------
//  Copyright (c) 2013 iMatix Corporation <www.imatix.com>
//
//  This is free software; you can redistribute it and/or modify it under
//  the terms of the GNU Lesser General Public License as published by
//  the Free Software Foundation; either version 3 of the License, or (at
//  your option) any later version.
//
//  This software is distributed in the hope that it will be useful, but
//  WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
//  Lesser General Public License for more details.
//  ---------------------------------------------------------------------

#include <czmq.h>
#include <crypto_box.h>
#include <crypto_secretbox.h>
#include <randombytes.h>

#if crypto_box_PUBLICKEYBYTES != 32 || crypto_box_SECRETKEYBYTES != 32
#   error "NaCl not built correctly"
#endif

//  Command types
#define CMD_C_HELLO     "QvnQ5XlH"
#define CMD_S_COOKIE    "RL3aNMXK"
#define CMD_C_INITIATE  "QvnQ5XlI"
#define CMD_C_MESSAGE   "RL3aNMXM"
#define CMD_S_MESSAGE   "QvnQ5XlM"

//  Command structures
typedef struct {
    byte cn_public [32];        //  Client short-term public key C'
    byte cn_nonce [8];          //  Client short-term nonce
    byte box [80];              //  Box [64 * %x0](C'->S)
    byte padding [64];          //  Anti-amplification padding
} cmd_c_hello_t;

typedef struct {
    byte nonce [16];            //  Server long-term nonce
    byte box [144];             //  Box [S' + cookie](C'->S)
} cmd_s_cookie_t;

typedef struct {
    byte cn_public [32];        //  Client short-term public key C'
    byte cn_cookie [96];        //  Server connection cookie
    byte cn_nonce [8];          //  Client short-term nonce
    byte box [368];             //  Box [C + nonce + vouch + host](C'->S')
} cmd_c_initiate_t;

typedef struct {
    byte cn_nonce [8];          //  Server short-term nonce
    byte box [272];             //  Box [M](S'->C'), max M is 256
} cmd_s_message_t;

typedef struct {
    byte cn_public [32];        //  Client short-term public key C'
    byte cn_nonce [8];          //  Client short-term nonce
    byte box [272];             //  Box [M](C'->S'), max M is 256
} cmd_c_message_t;

typedef struct {
    byte type [8];
    union {
        cmd_c_hello_t c_hello;
        cmd_s_cookie_t s_cookie;
        cmd_c_initiate_t c_initiate;
        cmd_s_message_t s_message;
        cmd_c_message_t c_message;
    };
} cmd_t;

//  Announce public keys simple via static memory
static byte
    server_public [32],          //  Server public key
    client_public [32];          //  Client public key

static void
s_dump (byte *buffer, int size, char *prefix)
{
    printf ("\n%s: ", prefix);
    int byte_nbr;
    for (byte_nbr = 0; byte_nbr < size; byte_nbr++)
        printf ("%02X ", buffer [byte_nbr]);
    printf ("\n");
}

static void
s_server (void *args, zctx_t *ctx, void *pipe)
{
    //  Generate our long-term keys
    byte server_secret [32];
    int rc = crypto_box_keypair (server_public, server_secret);
    assert (rc == 0);

    void *server = zsocket_new (ctx, ZMQ_DEALER);
    assert (server);
    rc = zsocket_bind (server, "tcp://*:9999");
    assert (rc != -1);

    //  Short-term connection keys
    byte cn_client [32];        //  Client short-term public key
    byte cn_public [32];        //  Server short-term public key
    byte cn_secret [32];        //  Server short-term secret key
    rc = crypto_box_keypair (cn_public, cn_secret);
    assert (rc == 0);

    //  Initialize connection nonce
    int64_t cn_nonce = 0;

    //  Cookie key; we'd rotate this every minute
    byte cookie_key [32];
    randombytes (cookie_key, 32);

    //  Working variables for crypto calls
    //  Assert sizes are same for secretbox calls
#   if crypto_secretbox_NONCEBYTES != crypto_box_NONCEBYTES
#       error
#   endif
    byte nonce [crypto_box_NONCEBYTES];
    byte text [crypto_box_ZEROBYTES + 1024];
    byte box [crypto_box_ZEROBYTES + 1024];

    //  Now process commands from client
    while (true) {
        cmd_t command;
        rc = zmq_recv (server, &command, sizeof (command), 0);
        if (rc == -1)
            break;

        if (rc == 8 + sizeof (cmd_c_hello_t)
        && memcmp (command.type, CMD_C_HELLO, 8) == 0) {
            //  Check HELLO command is valid
            printf ("C:HELLO: ");
            memcpy (cn_client, command.c_hello.cn_public, 32);

            //  Open Box [64 * %x0](C'->S)
            memcpy (nonce, (byte *) "CurveCP-client-H", 16);
            memcpy (nonce + 16, command.c_hello.cn_nonce, 8);
            memset (box, 0, 16);
            memcpy (box + 16, command.c_hello.box, 80);
            rc = crypto_box_open (text, box, 96, nonce, cn_client, server_secret);
            assert (rc == 0);
            puts ("OK");

            //  Reply to every HELLO with a COOKIE
            cmd_t cookie = { CMD_S_COOKIE };

            //  Generate cookie = Box [C' + s'](t),
            memset (text, 0, 32);
            memcpy (text + 32, cn_client, 32);
            memcpy (text + 64, cn_secret, 32);

            //  Create full nonce for encryption
            byte cookie_nonce [16];
            randombytes (cookie_nonce, 16);
            assert (crypto_secretbox_NONCEBYTES == 24);
            memcpy (nonce, (byte *) "Cookie--", 8);
            memcpy (nonce + 8, cookie_nonce, 16);

            //  Encrypt using symmetric cookie key
            byte cookie_box [96];
            rc = crypto_secretbox (cookie_box, text, 96, nonce, cookie_key);
            assert (rc == 0);

            //  Put 16-byte nonce into start of encrypted text
            //  Use 16 bytes of leading zero padding for this
            assert (crypto_secretbox_BOXZEROBYTES == 16);
            memcpy (cookie_box, cookie_nonce, 16);

            //  Now create 144-byte Box [S' + cookie] (S->C')
            memset (text, 0, 32);
            memcpy (text + 32, cn_public, 32);
            memcpy (text + 64, cookie_box, 96);

            //  Create full nonce for encryption
            randombytes (cookie.s_cookie.nonce, 16);
            memcpy (nonce, (byte *) "CurveCPK", 8);
            memcpy (nonce + 8, cookie.s_cookie.nonce, 16);
            rc = crypto_box (box, text, 160, nonce, cn_client, server_secret);
            assert (rc == 0);
            memcpy (cookie.s_cookie.box, box + 16, 144);
            zmq_send (server, &cookie, 8 + sizeof (cmd_s_cookie_t), 0);
        }
        else
        if (rc == 8 + sizeof (cmd_c_initiate_t)
        && memcmp (command.type, CMD_C_INITIATE, 8) == 0) {
            //  Check INITIATE command is valid
            printf ("C:INITIATE: ");
            memcpy (cn_client, command.c_initiate.cn_public, 32);

            //  Check cookie is valid
            //  Cookie nonce is first 16 bytes of cookie
            memcpy (nonce, (byte *) "Cookie--", 8);
            memcpy (nonce + 8, command.c_initiate.cn_cookie, 16);

            //  Cookie box is next 80 bytes of cookie
            memset (box, 0, 16);
            memcpy (box + 16, command.c_initiate.cn_cookie + 16, 80);
            rc = crypto_secretbox_open (text, box, 96, nonce, cookie_key);
            assert (rc == 0);

            //  Check cookie plain text is as expected [C' + s']
            assert (memcmp (text + 32, cn_client, 32) == 0);
            assert (memcmp (text + 64, cn_secret, 32) == 0);

            //  Open Box [C + nonce + vouch + host](C'->S')
            memcpy (nonce, (byte *) "CurveCP-client-I", 16);
            memcpy (nonce + 16, command.c_initiate.cn_nonce, 8);
            memset (box, 0, 16);
            memcpy (box + 16, command.c_initiate.box, 368);
            rc = crypto_box_open (text, box, 384, nonce, cn_client, cn_secret);
            assert (rc == 0);

            //  Get & check contents of box
            assert (memcmp (text + 32, client_public, 32) == 0);
            printf ("(host=%s) ", text + 128);

            //  Open vouch Box [C'](C->S) and check contents
            memcpy (nonce, (byte *) "CurveCPV", 8);
            memcpy (nonce + 8, text + 64, 16);
            memset (box, 0, 16);
            memcpy (box + 16, text + 80, 48);
            rc = crypto_box_open (text, box, 64, nonce, client_public, server_secret);
            assert (rc == 0);
            assert (memcmp (text + 32, cn_client, 32) == 0);
            puts ("OK");
        }
        else
        if (rc == 8 + sizeof (cmd_c_message_t)
        && memcmp (command.type, CMD_C_MESSAGE, 8) == 0) {
            //  Check MESSAGE command is valid
            printf ("C:MESSAGE: ");
            memcpy (cn_client, command.c_message.cn_public, 32);

            //  Open Box [M](C'->S')
            memcpy (nonce, (byte *) "CurveCP-client-M", 16);
            memcpy (nonce + 16, command.c_message.cn_nonce, 8);
            memset (box, 0, 16);
            memcpy (box + 16, command.c_message.box, 272);
            rc = crypto_box_open (text, box, 288, nonce, cn_client, cn_secret);
            assert (rc == 0);
            printf ("(request=%s) ", text + 32);
            puts ("OK");

            //  Send MESSAGE now with "World"
            //  Create message Box [M](S'->C'), max M is 256
            memcpy (nonce, (byte *) "CurveCP-server-M", 16);
            memcpy (nonce + 16, &cn_nonce, 8);
            memset (text, 0, 256);
            memcpy (text + 32, "World", 5);
            rc = crypto_box (box, text, 288, nonce, cn_client, cn_secret);
            assert (rc == 0);

            cmd_t message = { CMD_S_MESSAGE };
            memcpy (message.s_message.cn_nonce, &cn_nonce, 8);
            memcpy (message.s_message.box, box + 16, 272);
            zmq_send (server, &message, 8 + sizeof (cmd_s_message_t), 0);
            cn_nonce++;
        }
        else
            puts ("E: invalid client command, rejected");
    }
}

static void
s_client (void *args, zctx_t *ctx, void *pipe)
{
    //  Generate our long-term keys
    byte client_secret [32];
    int rc = crypto_box_keypair (client_public, client_secret);
    assert (rc == 0);

    //  Open new connection to server
    void *client = zsocket_new (ctx, ZMQ_DEALER);
    assert (client);
    rc = zsocket_connect (client, "tcp://localhost:9999");
    assert (rc == 0);

    //  Short-term connection keys
    byte cn_server [32];        //  Server short-term public key
    byte cn_public [32];        //  Client short-term public key
    byte cn_secret [32];        //  Client short-term secret key
    rc = crypto_box_keypair (cn_public, cn_secret);
    assert (rc == 0);

    //  Initialize connection nonce
    int64_t cn_nonce = 0;

    //  Working variables for crypto calls
    byte nonce [crypto_box_NONCEBYTES];
    byte text [crypto_box_ZEROBYTES + 1024];
    byte box [crypto_box_ZEROBYTES + 1024];

    //  Create Box [64 * %x0](C'->S)
    memcpy (nonce, (byte *) "CurveCP-client-H", 16);
    memcpy (nonce + 16, &cn_nonce, 8);
    assert (crypto_box_ZEROBYTES == 32);
    memset (text, 0, 96);
    rc = crypto_box (box, text, 96, nonce, server_public, cn_secret);
    assert (rc == 0);

    //  Send HELLO command to start connection
    cmd_t hello = { CMD_C_HELLO };
    memcpy (hello.c_hello.cn_public, cn_public, 32);
    memcpy (hello.c_hello.cn_nonce, &cn_nonce, 8);
    assert (crypto_box_BOXZEROBYTES == 16);
    memcpy (hello.c_hello.box, box + 16, 80);
    zmq_send (client, &hello, 8 + sizeof (cmd_c_hello_t), 0);
    cn_nonce++;

    //  Now process commands from server
    while (true) {
        cmd_t command;
        rc = zmq_recv (client, &command, sizeof (command), 0);
        if (rc == -1)
            break;

        if (rc == 8 + sizeof (cmd_s_cookie_t)
        && memcmp (command.type, CMD_S_COOKIE, 8) == 0) {
            //  Check COOKIE command is valid
            printf ("S:COOKIE: ");

            //  Open Box [S' + cookie](C'->S)
            memcpy (nonce, (byte *) "CurveCPK", 8);
            memcpy (nonce + 8, command.s_cookie.nonce, 16);
            memset (box, 0, 16);
            memcpy (box + 16, command.s_cookie.box, 144);
            rc = crypto_box_open (text, box, 160, nonce, server_public, cn_secret);
            assert (rc == 0);
            puts ("OK");

            //  Get server cookie and short-term key
            byte cn_cookie [96];
            memcpy (cn_server, text + 32, 32);
            memcpy (cn_cookie, text + 64, 96);

            //  Create vouch = Box [C'](C->S)
            memset (text, 0, 32);
            memcpy (text + 32, cn_public, 32);
            memcpy (nonce, (byte *) "CurveCPV", 8);
            byte vouch_nonce [16];
            randombytes (vouch_nonce, 16);
            memcpy (nonce + 8, vouch_nonce, 16);
            rc = crypto_box (box, text, 64, nonce, server_public, client_secret);
            assert (rc == 0);

            //  Create Box [C + nonce + vouch + host](C'->S')
            memcpy (nonce, (byte *) "CurveCP-client-I", 16);
            memcpy (nonce + 16, &cn_nonce, 8);
            memset (text, 0, sizeof (text));
            memcpy (text + 32, client_public, 32);
            memcpy (text + 64, vouch_nonce, 16);
            memcpy (text + 80, box + 16, 48);    //  Vouch is still in box
            memcpy (text + 128, (byte *) "localhost", 9);
            rc = crypto_box (box, text, 384, nonce, cn_server, cn_secret);
            assert (rc == 0);

            //  We have server short-term key and cookie, send INITIATE
            cmd_t initiate = { CMD_C_INITIATE };
            memcpy (initiate.c_initiate.cn_public, cn_public, 32);
            memcpy (initiate.c_initiate.cn_cookie, cn_cookie, 96);
            memcpy (initiate.c_initiate.cn_nonce, &cn_nonce, 8);
            memcpy (initiate.c_initiate.box, box + 16, 368);
            zmq_send (client, &initiate, 8 + sizeof (cmd_c_initiate_t), 0);
            cn_nonce++;

            //  Send MESSAGE now with "Hello"
            //  Create message Box [M](C'->S'), max M is 256
            //  Don't bother splitting into two steps for this PoC
            memcpy (nonce, (byte *) "CurveCP-client-M", 16);
            memcpy (nonce + 16, &cn_nonce, 8);
            memset (text, 0, 256);
            memcpy (text + 32, "Hello", 5);
            rc = crypto_box (box, text, 288, nonce, cn_server, cn_secret);
            assert (rc == 0);

            cmd_t message = { CMD_C_MESSAGE };
            memcpy (message.c_message.cn_public, cn_public, 32);
            memcpy (message.c_message.cn_nonce, &cn_nonce, 8);
            memcpy (message.c_message.box, box + 16, 272);
            zmq_send (client, &message, 8 + sizeof (cmd_c_message_t), 0);
            cn_nonce++;
        }
        else
        if (rc == 8 + sizeof (cmd_s_message_t)
        && memcmp (command.type, CMD_S_MESSAGE, 8) == 0) {
            //  Check MESSAGE command is valid
            printf ("S:MESSAGE: ");

            //  Open Box Box [M](S'->C')
            memcpy (nonce, (byte *) "CurveCP-server-M", 16);
            memcpy (nonce + 16, command.s_message.cn_nonce, 8);
            memset (box, 0, 16);
            memcpy (box + 16, command.s_message.box, 272);
            rc = crypto_box_open (text, box, 288, nonce, cn_server, cn_secret);
            assert (rc == 0);
            printf ("(reply=%s) ", text + 32);
            puts ("OK");

            puts ("-> 'Hello World' test successful");
            break;
        }
        else
            puts ("E: invalid server command, rejected");
    }
    zstr_send (pipe, "Test successful");
}


//  Main loop starts server and client threads and then waits
//  for a user interrupt.

int main (void)
{
    zctx_t *ctx = zctx_new ();
    assert (ctx);

    //  One server, one client for this proof of concept
    void *server = zthread_fork (ctx, s_server, NULL);
    void *client = zthread_fork (ctx, s_client, NULL);

    //  Client runs test and tells us all is OK
    char *ready = zstr_recv (client);
    free (ready);

    zctx_destroy (&ctx);
    return 0;
}

#=> Remember ... this is JUST an example to show the highlighting of Jekyll/Github functionality ...
{% endhighlight %}
