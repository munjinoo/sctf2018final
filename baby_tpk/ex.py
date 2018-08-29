from pwn import *
from Crypto.Cipher import CAST

aes = CAST.new('samsungctf_TPK'.ljust(16, '\x00'), CAST.MODE_OFB, 'ivishere')

r = ELF('./samsungctf')
s = r.read(0x12b78, 48)
print s.encode('hex')
print aes.decrypt(s)
