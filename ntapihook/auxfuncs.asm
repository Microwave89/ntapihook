.code
syscallStub PROC
	mov eax, ecx
	mov r10, rdx
	mov rdx, r8
	mov r8, r9
	mov r9, qword ptr[rsp+28h]
	add rsp, 8h
	syscall
	sub rsp, 8h
	ret
syscallStub ENDP
END
