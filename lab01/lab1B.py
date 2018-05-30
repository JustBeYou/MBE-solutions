s1 = "Q}|u`sfg~sf{}|a3"
s2 = "Congratulations!"

new_s = ""
for i in range(len(s1)):
    new_s += chr(ord(s1[i]) ^ ord(s2[i]))
print (ord(new_s[0]))
