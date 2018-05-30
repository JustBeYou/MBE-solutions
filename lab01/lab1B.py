s1 = "Q}|u`sfg~sf{}|a3"
s2 = "Congratulations!"

new_s = ""
for i in range(len(s1)):
    new_s += chr(ord(s1[i]) ^ ord(s2[i]))
print (ord(new_s[0]))

# 0x1337d00d - 18 -> 322424827
# flag 1337_3nCRyptI0n_br0
