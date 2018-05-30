import ctypes

def uint32(x):
    return ctypes.c_uint32(x).value

def uint64(x):
    return ctypes.c_uint64(x).value

def mul64(a, b):
    res = uint64(uint32(a) * uint32(b))
    return (uint32(res & 0xFFFFFFFF), uint32((res & (0xFFFFFFFF << 32)) >> 32))

def compute_serial(user):
    if len(user) <= 5: return -1

    var_10 = uint32((ord(user[3]) & 0xff) ^ 0x1337 + 0x5eeded)

    for i in range(len(user)):
        ecx = uint32((ord(user[i]) & 0xff) ^ var_10)
        lower, upper = mul64(ecx, 0x88233b2b)
        edx = uint32(((uint32(ecx - upper) // 2 + upper) // 1024) * 1337)
        var_10 += uint32(uint32(ecx) - uint32(edx))

        print ("%u (%x)" % (var_10, var_10))

print (compute_serial("misuABC"))
