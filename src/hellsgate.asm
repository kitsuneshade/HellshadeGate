; Hell's Gate x64


.data
    sysnum DWORD 0
.code
    BasicGate PROC
        mov sysnum, ecx
        ret
    BasicGate ENDP
    BasicExec PROC
        mov r10, rcx
        mov eax, sysnum
        sub rsp, 78h
        mov r11, [rsp + 0A0h]
        mov [rsp + 28h], r11
        mov r11, [rsp + 0A8h]
        mov [rsp + 30h], r11
        mov r11, [rsp + 0B0h]
        mov [rsp + 38h], r11
        mov r11, [rsp + 0B8h]
        mov [rsp + 40h], r11
        mov r11, [rsp + 0C0h]
        mov [rsp + 48h], r11
        mov r11, [rsp + 0C8h]
        mov [rsp + 50h], r11
        mov r11, [rsp + 0D0h]
        mov [rsp + 58h], r11
        syscall
        add rsp, 78h
        ret
    BasicExec ENDP
end
