int hash(int arg0) {
    var_4 = arg0;
    for (var_4 = 0x0; var_4 <= 0xf; var_4 = var_4 + 0x1) {
            ecx = *(int8_t *)(var_4 + salt) & 0xff;
            ecx = (*(int8_t *)(var_4 + secretpass) & 0xff) + ecx;
            eax = *(int8_t *)(var_4 + user) & 0xff;
            eax = eax ^ ecx;
            *(int8_t *)(var_4 + var_4) = eax;
    }
    esp = esp - 0x4;
    if (eax != 0x0) {
            esp = esp + 0x4;
    }
    eax = stack[-20];
    return eax;
}
