#!/usr/bin/env python

from M2Crypto import SSL

versions = ["sslv2", "sslv23", "sslv3", "tlsv1"]
ciphers = []

for version in versions:
    try:
        ctx = SSL.Context(version, weak_crypto=True)
        conn = SSL.Connection(ctx)
        cipher_stack = conn.get_ciphers()
        for cipher in cipher_stack:
            print "%s\t%s" % (version, cipher)
    except ValueError as e:
        print e
