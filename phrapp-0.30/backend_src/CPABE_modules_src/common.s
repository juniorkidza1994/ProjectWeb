	.file	"common.c"
	.text
	.type	g_string_append_c_inline, @function
g_string_append_c_inline:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$40, %esp
	movl	12(%ebp), %eax
	movb	%al, -12(%ebp)
	movl	8(%ebp), %eax
	movl	4(%eax), %eax
	leal	1(%eax), %edx
	movl	8(%ebp), %eax
	movl	8(%eax), %eax
	cmpl	%eax, %edx
	jae	.L2
	movl	8(%ebp), %eax
	movl	(%eax), %edx
	movl	8(%ebp), %eax
	movl	4(%eax), %eax
	leal	(%edx,%eax), %ecx
	movzbl	-12(%ebp), %edx
	movb	%dl, (%ecx)
	leal	1(%eax), %edx
	movl	8(%ebp), %eax
	movl	%edx, 4(%eax)
	movl	8(%ebp), %eax
	movl	(%eax), %edx
	movl	8(%ebp), %eax
	movl	4(%eax), %eax
	leal	(%edx,%eax), %eax
	movb	$0, (%eax)
	jmp	.L3
.L2:
	movsbl	-12(%ebp),%eax
	movl	%eax, 8(%esp)
	movl	$-1, 4(%esp)
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	g_string_insert_c
.L3:
	movl	8(%ebp), %eax
	leave
	ret
	.size	g_string_append_c_inline, .-g_string_append_c_inline
	.type	element_length_in_bytes, @function
element_length_in_bytes:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$24, %esp
	movl	8(%ebp), %eax
	movl	(%eax), %eax
	movl	164(%eax), %eax
	testl	%eax, %eax
	jns	.L6
	movl	8(%ebp), %eax
	movl	(%eax), %eax
	movl	160(%eax), %edx
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	*%edx
	jmp	.L7
.L6:
	movl	8(%ebp), %eax
	movl	(%eax), %eax
	movl	164(%eax), %eax
.L7:
	leave
	ret
	.size	element_length_in_bytes, .-element_length_in_bytes
	.type	element_to_bytes, @function
element_to_bytes:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$24, %esp
	movl	12(%ebp), %eax
	movl	(%eax), %eax
	movl	152(%eax), %edx
	movl	12(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	*%edx
	leave
	ret
	.size	element_to_bytes, .-element_to_bytes
.globl init_aes
	.type	init_aes, @function
init_aes:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$40, %esp
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	element_length_in_bytes
	cmpl	$16, %eax
	jle	.L12
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	element_length_in_bytes
	jmp	.L13
.L12:
	movl	$17, %eax
.L13:
	movl	%eax, -12(%ebp)
	movl	-12(%ebp), %eax
	movl	%eax, (%esp)
	call	malloc
	movl	%eax, -16(%ebp)
	movl	8(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	-16(%ebp), %eax
	movl	%eax, (%esp)
	call	element_to_bytes
	cmpl	$0, 12(%ebp)
	je	.L14
	movl	-16(%ebp), %eax
	leal	1(%eax), %edx
	movl	16(%ebp), %eax
	movl	%eax, 8(%esp)
	movl	$128, 4(%esp)
	movl	%edx, (%esp)
	call	AES_set_encrypt_key
	jmp	.L15
.L14:
	movl	-16(%ebp), %eax
	leal	1(%eax), %edx
	movl	16(%ebp), %eax
	movl	%eax, 8(%esp)
	movl	$128, 4(%esp)
	movl	%edx, (%esp)
	call	AES_set_decrypt_key
.L15:
	movl	-16(%ebp), %eax
	movl	%eax, (%esp)
	call	free
	movl	$16, 8(%esp)
	movl	$0, 4(%esp)
	movl	20(%ebp), %eax
	movl	%eax, (%esp)
	call	memset
	leave
	ret
	.size	init_aes, .-init_aes
.globl aes_128_cbc_encrypt
	.type	aes_128_cbc_encrypt, @function
aes_128_cbc_encrypt:
	pushl	%ebp
	movl	%esp, %ebp
	pushl	%ebx
	subl	$340, %esp
	movl	8(%ebp), %eax
	movl	%eax, -300(%ebp)
	movl	12(%ebp), %eax
	movl	%eax, -304(%ebp)
	movl	%gs:20, %eax
	movl	%eax, -12(%ebp)
	xorl	%eax, %eax
	leal	-28(%ebp), %eax
	movl	%eax, 12(%esp)
	leal	-284(%ebp), %eax
	movl	%eax, 8(%esp)
	movl	$1, 4(%esp)
	movl	-304(%ebp), %eax
	movl	%eax, (%esp)
	call	init_aes
	movl	-300(%ebp), %eax
	movl	4(%eax), %eax
	shrl	$24, %eax
	movb	%al, -40(%ebp)
	movl	-300(%ebp), %eax
	movl	4(%eax), %eax
	andl	$16711680, %eax
	shrl	$16, %eax
	movb	%al, -39(%ebp)
	movl	-300(%ebp), %eax
	movl	4(%eax), %eax
	andl	$65280, %eax
	shrl	$8, %eax
	movb	%al, -38(%ebp)
	movl	-300(%ebp), %eax
	movl	4(%eax), %eax
	movb	%al, -37(%ebp)
	movl	$4, 8(%esp)
	leal	-40(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	-300(%ebp), %eax
	movl	%eax, (%esp)
	call	g_byte_array_prepend
	movb	$0, -29(%ebp)
	jmp	.L18
.L19:
	movl	$1, 8(%esp)
	leal	-29(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	-300(%ebp), %eax
	movl	%eax, (%esp)
	call	g_byte_array_append
.L18:
	movl	-300(%ebp), %eax
	movl	4(%eax), %eax
	andl	$15, %eax
	testl	%eax, %eax
	jne	.L19
	call	g_byte_array_new
	movl	%eax, -36(%ebp)
	movl	-300(%ebp), %eax
	movl	4(%eax), %eax
	movl	%eax, 4(%esp)
	movl	-36(%ebp), %eax
	movl	%eax, (%esp)
	call	g_byte_array_set_size
	movl	-300(%ebp), %eax
	movl	4(%eax), %ecx
	movl	-36(%ebp), %eax
	movl	(%eax), %edx
	movl	-300(%ebp), %eax
	movl	(%eax), %eax
	movl	$1, 20(%esp)
	leal	-28(%ebp), %ebx
	movl	%ebx, 16(%esp)
	leal	-284(%ebp), %ebx
	movl	%ebx, 12(%esp)
	movl	%ecx, 8(%esp)
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	AES_cbc_encrypt
	movl	-36(%ebp), %eax
	movl	-12(%ebp), %edx
	xorl	%gs:20, %edx
	je	.L21
	call	__stack_chk_fail
.L21:
	addl	$340, %esp
	popl	%ebx
	popl	%ebp
	ret
	.size	aes_128_cbc_encrypt, .-aes_128_cbc_encrypt
.globl aes_128_cbc_decrypt
	.type	aes_128_cbc_decrypt, @function
aes_128_cbc_decrypt:
	pushl	%ebp
	movl	%esp, %ebp
	pushl	%ebx
	subl	$324, %esp
	movl	8(%ebp), %eax
	movl	%eax, -284(%ebp)
	movl	12(%ebp), %eax
	movl	%eax, -288(%ebp)
	movl	%gs:20, %eax
	movl	%eax, -12(%ebp)
	xorl	%eax, %eax
	leal	-28(%ebp), %eax
	movl	%eax, 12(%esp)
	leal	-280(%ebp), %eax
	movl	%eax, 8(%esp)
	movl	$0, 4(%esp)
	movl	-288(%ebp), %eax
	movl	%eax, (%esp)
	call	init_aes
	call	g_byte_array_new
	movl	%eax, -32(%ebp)
	movl	-284(%ebp), %eax
	movl	4(%eax), %eax
	movl	%eax, 4(%esp)
	movl	-32(%ebp), %eax
	movl	%eax, (%esp)
	call	g_byte_array_set_size
	movl	-284(%ebp), %eax
	movl	4(%eax), %ecx
	movl	-32(%ebp), %eax
	movl	(%eax), %edx
	movl	-284(%ebp), %eax
	movl	(%eax), %eax
	movl	$0, 20(%esp)
	leal	-28(%ebp), %ebx
	movl	%ebx, 16(%esp)
	leal	-280(%ebp), %ebx
	movl	%ebx, 12(%esp)
	movl	%ecx, 8(%esp)
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	AES_cbc_encrypt
	movl	$0, -36(%ebp)
	movl	-32(%ebp), %eax
	movl	(%eax), %eax
	movzbl	(%eax), %eax
	movzbl	%al, %eax
	sall	$24, %eax
	movl	%eax, %edx
	orl	-36(%ebp), %edx
	movl	-32(%ebp), %eax
	movl	(%eax), %eax
	addl	$1, %eax
	movzbl	(%eax), %eax
	movzbl	%al, %eax
	sall	$16, %eax
	orl	%eax, %edx
	movl	-32(%ebp), %eax
	movl	(%eax), %eax
	addl	$2, %eax
	movzbl	(%eax), %eax
	movzbl	%al, %eax
	sall	$8, %eax
	orl	%eax, %edx
	movl	-32(%ebp), %eax
	movl	(%eax), %eax
	addl	$3, %eax
	movzbl	(%eax), %eax
	movzbl	%al, %eax
	orl	%edx, %eax
	movl	%eax, -36(%ebp)
	movl	$0, 4(%esp)
	movl	-32(%ebp), %eax
	movl	%eax, (%esp)
	call	g_byte_array_remove_index
	movl	$0, 4(%esp)
	movl	-32(%ebp), %eax
	movl	%eax, (%esp)
	call	g_byte_array_remove_index
	movl	$0, 4(%esp)
	movl	-32(%ebp), %eax
	movl	%eax, (%esp)
	call	g_byte_array_remove_index
	movl	$0, 4(%esp)
	movl	-32(%ebp), %eax
	movl	%eax, (%esp)
	call	g_byte_array_remove_index
	movl	-36(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	-32(%ebp), %eax
	movl	%eax, (%esp)
	call	g_byte_array_set_size
	movl	-32(%ebp), %eax
	movl	-12(%ebp), %edx
	xorl	%gs:20, %edx
	je	.L24
	call	__stack_chk_fail
.L24:
	addl	$324, %esp
	popl	%ebx
	popl	%ebp
	ret
	.size	aes_128_cbc_decrypt, .-aes_128_cbc_decrypt
	.section	.rodata
.LC0:
	.string	"r"
.LC1:
	.string	"can't read file: %s\n"
	.text
.globl fopen_read_or_die
	.type	fopen_read_or_die, @function
fopen_read_or_die:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$40, %esp
	movl	$.LC0, %edx
	movl	8(%ebp), %eax
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	fopen
	movl	%eax, -12(%ebp)
	cmpl	$0, -12(%ebp)
	jne	.L26
	movl	8(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	$.LC1, (%esp)
	call	die
.L26:
	movl	-12(%ebp), %eax
	leave
	ret
	.size	fopen_read_or_die, .-fopen_read_or_die
	.section	.rodata
.LC2:
	.string	"w"
.LC3:
	.string	"can't write file: %s\n"
	.text
.globl fopen_write_or_die
	.type	fopen_write_or_die, @function
fopen_write_or_die:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$40, %esp
	movl	$.LC2, %edx
	movl	8(%ebp), %eax
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	fopen
	movl	%eax, -12(%ebp)
	cmpl	$0, -12(%ebp)
	jne	.L29
	movl	8(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	$.LC3, (%esp)
	call	die
.L29:
	movl	-12(%ebp), %eax
	leave
	ret
	.size	fopen_write_or_die, .-fopen_write_or_die
.globl suck_file
	.type	suck_file, @function
suck_file:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$120, %esp
	call	g_byte_array_new
	movl	%eax, -16(%ebp)
	movl	8(%ebp), %eax
	leal	-104(%ebp), %edx
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	stat
	movl	-60(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	-16(%ebp), %eax
	movl	%eax, (%esp)
	call	g_byte_array_set_size
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	fopen_read_or_die
	movl	%eax, -12(%ebp)
	movl	-60(%ebp), %eax
	movl	%eax, %edx
	movl	-16(%ebp), %eax
	movl	(%eax), %eax
	movl	-12(%ebp), %ecx
	movl	%ecx, 12(%esp)
	movl	%edx, 8(%esp)
	movl	$1, 4(%esp)
	movl	%eax, (%esp)
	call	fread
	movl	-12(%ebp), %eax
	movl	%eax, (%esp)
	call	fclose
	movl	-16(%ebp), %eax
	leave
	ret
	.size	suck_file, .-suck_file
.globl suck_file_str
	.type	suck_file_str, @function
suck_file_str:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$40, %esp
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	suck_file
	movl	%eax, -16(%ebp)
	movb	$0, -9(%ebp)
	movl	$1, 8(%esp)
	leal	-9(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	-16(%ebp), %eax
	movl	%eax, (%esp)
	call	g_byte_array_append
	movl	-16(%ebp), %eax
	movl	(%eax), %eax
	movl	%eax, -20(%ebp)
	movl	$0, 4(%esp)
	movl	-16(%ebp), %eax
	movl	%eax, (%esp)
	call	g_byte_array_free
	movl	-20(%ebp), %eax
	leave
	ret
	.size	suck_file_str, .-suck_file_str
	.section	.rodata
.LC4:
	.string	""
	.text
.globl suck_stdin
	.type	suck_stdin, @function
suck_stdin:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$40, %esp
	movl	$.LC4, (%esp)
	call	g_string_new
	movl	%eax, -12(%ebp)
	jmp	.L36
.L37:
	movl	-20(%ebp), %eax
	movsbl	%al,%eax
	movl	%eax, 4(%esp)
	movl	-12(%ebp), %eax
	movl	%eax, (%esp)
	call	g_string_append_c_inline
.L36:
	movl	stdin, %eax
	movl	%eax, (%esp)
	call	fgetc
	movl	%eax, -20(%ebp)
	cmpl	$-1, -20(%ebp)
	jne	.L37
	movl	-12(%ebp), %eax
	movl	(%eax), %eax
	movl	%eax, -16(%ebp)
	movl	$0, 4(%esp)
	movl	-12(%ebp), %eax
	movl	%eax, (%esp)
	call	g_string_free
	movl	-16(%ebp), %eax
	leave
	ret
	.size	suck_stdin, .-suck_stdin
.globl spit_file
	.type	spit_file, @function
spit_file:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$40, %esp
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	fopen_write_or_die
	movl	%eax, -12(%ebp)
	movl	12(%ebp), %eax
	movl	4(%eax), %edx
	movl	12(%ebp), %eax
	movl	(%eax), %eax
	movl	-12(%ebp), %ecx
	movl	%ecx, 12(%esp)
	movl	%edx, 8(%esp)
	movl	$1, 4(%esp)
	movl	%eax, (%esp)
	call	fwrite
	movl	-12(%ebp), %eax
	movl	%eax, (%esp)
	call	fclose
	cmpl	$0, 16(%ebp)
	je	.L41
	movl	$1, 4(%esp)
	movl	12(%ebp), %eax
	movl	%eax, (%esp)
	call	g_byte_array_free
.L41:
	leave
	ret
	.size	spit_file, .-spit_file
.globl read_cpabe_file
	.type	read_cpabe_file, @function
read_cpabe_file:
	pushl	%ebp
	movl	%esp, %ebp
	pushl	%ebx
	subl	$36, %esp
	call	g_byte_array_new
	movl	12(%ebp), %edx
	movl	%eax, (%edx)
	call	g_byte_array_new
	movl	20(%ebp), %edx
	movl	%eax, (%edx)
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	fopen_read_or_die
	movl	%eax, -12(%ebp)
	movl	16(%ebp), %eax
	movl	$0, (%eax)
	movl	$3, -16(%ebp)
	jmp	.L43
.L44:
	movl	16(%ebp), %eax
	movl	(%eax), %ebx
	movl	-12(%ebp), %eax
	movl	%eax, (%esp)
	call	fgetc
	movl	-16(%ebp), %edx
	sall	$3, %edx
	movl	%edx, %ecx
	sall	%cl, %eax
	movl	%ebx, %edx
	orl	%eax, %edx
	movl	16(%ebp), %eax
	movl	%edx, (%eax)
	subl	$1, -16(%ebp)
.L43:
	cmpl	$0, -16(%ebp)
	jns	.L44
	movl	$0, -20(%ebp)
	movl	$3, -16(%ebp)
	jmp	.L45
.L46:
	movl	-12(%ebp), %eax
	movl	%eax, (%esp)
	call	fgetc
	movl	-16(%ebp), %edx
	sall	$3, %edx
	movl	%edx, %ecx
	sall	%cl, %eax
	orl	%eax, -20(%ebp)
	subl	$1, -16(%ebp)
.L45:
	cmpl	$0, -16(%ebp)
	jns	.L46
	movl	-20(%ebp), %edx
	movl	20(%ebp), %eax
	movl	(%eax), %eax
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	g_byte_array_set_size
	movl	-20(%ebp), %edx
	movl	20(%ebp), %eax
	movl	(%eax), %eax
	movl	(%eax), %eax
	movl	-12(%ebp), %ecx
	movl	%ecx, 12(%esp)
	movl	%edx, 8(%esp)
	movl	$1, 4(%esp)
	movl	%eax, (%esp)
	call	fread
	movl	$0, -20(%ebp)
	movl	$3, -16(%ebp)
	jmp	.L47
.L48:
	movl	-12(%ebp), %eax
	movl	%eax, (%esp)
	call	fgetc
	movl	-16(%ebp), %edx
	sall	$3, %edx
	movl	%edx, %ecx
	sall	%cl, %eax
	orl	%eax, -20(%ebp)
	subl	$1, -16(%ebp)
.L47:
	cmpl	$0, -16(%ebp)
	jns	.L48
	movl	-20(%ebp), %edx
	movl	12(%ebp), %eax
	movl	(%eax), %eax
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	g_byte_array_set_size
	movl	-20(%ebp), %edx
	movl	12(%ebp), %eax
	movl	(%eax), %eax
	movl	(%eax), %eax
	movl	-12(%ebp), %ecx
	movl	%ecx, 12(%esp)
	movl	%edx, 8(%esp)
	movl	$1, 4(%esp)
	movl	%eax, (%esp)
	call	fread
	movl	-12(%ebp), %eax
	movl	%eax, (%esp)
	call	fclose
	addl	$36, %esp
	popl	%ebx
	popl	%ebp
	ret
	.size	read_cpabe_file, .-read_cpabe_file
.globl write_cpabe_file
	.type	write_cpabe_file, @function
write_cpabe_file:
	pushl	%ebp
	movl	%esp, %ebp
	pushl	%esi
	pushl	%ebx
	subl	$32, %esp
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	fopen_write_or_die
	movl	%eax, -12(%ebp)
	movl	$3, -16(%ebp)
	jmp	.L51
.L52:
	movl	-16(%ebp), %eax
	sall	$3, %eax
	movl	$255, %edx
	movl	%edx, %ebx
	movl	%eax, %ecx
	sall	%cl, %ebx
	movl	%ebx, %eax
	movl	%eax, %edx
	andl	16(%ebp), %edx
	movl	-16(%ebp), %eax
	sall	$3, %eax
	movl	%eax, %ecx
	sarl	%cl, %edx
	movl	-12(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	%edx, (%esp)
	call	fputc
	subl	$1, -16(%ebp)
.L51:
	cmpl	$0, -16(%ebp)
	jns	.L52
	movl	$3, -16(%ebp)
	jmp	.L53
.L54:
	movl	20(%ebp), %eax
	movl	4(%eax), %edx
	movl	-16(%ebp), %eax
	sall	$3, %eax
	movl	$255, %ebx
	movl	%ebx, %esi
	movl	%eax, %ecx
	sall	%cl, %esi
	movl	%esi, %eax
	andl	%eax, %edx
	movl	-16(%ebp), %eax
	sall	$3, %eax
	movl	%edx, %ebx
	movl	%eax, %ecx
	shrl	%cl, %ebx
	movl	%ebx, %eax
	movl	-12(%ebp), %edx
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	fputc
	subl	$1, -16(%ebp)
.L53:
	cmpl	$0, -16(%ebp)
	jns	.L54
	movl	20(%ebp), %eax
	movl	4(%eax), %edx
	movl	20(%ebp), %eax
	movl	(%eax), %eax
	movl	-12(%ebp), %ecx
	movl	%ecx, 12(%esp)
	movl	%edx, 8(%esp)
	movl	$1, 4(%esp)
	movl	%eax, (%esp)
	call	fwrite
	movl	$3, -16(%ebp)
	jmp	.L55
.L56:
	movl	12(%ebp), %eax
	movl	4(%eax), %edx
	movl	-16(%ebp), %eax
	sall	$3, %eax
	movl	$255, %ebx
	movl	%ebx, %esi
	movl	%eax, %ecx
	sall	%cl, %esi
	movl	%esi, %eax
	andl	%eax, %edx
	movl	-16(%ebp), %eax
	sall	$3, %eax
	movl	%edx, %ebx
	movl	%eax, %ecx
	shrl	%cl, %ebx
	movl	%ebx, %eax
	movl	-12(%ebp), %edx
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	fputc
	subl	$1, -16(%ebp)
.L55:
	cmpl	$0, -16(%ebp)
	jns	.L56
	movl	12(%ebp), %eax
	movl	4(%eax), %edx
	movl	12(%ebp), %eax
	movl	(%eax), %eax
	movl	-12(%ebp), %ecx
	movl	%ecx, 12(%esp)
	movl	%edx, 8(%esp)
	movl	$1, 4(%esp)
	movl	%eax, (%esp)
	call	fwrite
	movl	-12(%ebp), %eax
	movl	%eax, (%esp)
	call	fclose
	addl	$32, %esp
	popl	%ebx
	popl	%esi
	popl	%ebp
	ret
	.size	write_cpabe_file, .-write_cpabe_file
.globl die
	.type	die, @function
die:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$40, %esp
	leal	12(%ebp), %eax
	movl	%eax, -12(%ebp)
	movl	-12(%ebp), %ecx
	movl	8(%ebp), %edx
	movl	stderr, %eax
	movl	%ecx, 8(%esp)
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	vfprintf
	movl	$1, (%esp)
	call	exit
	.size	die, .-die
	.ident	"GCC: (Ubuntu 4.4.3-4ubuntu5) 4.4.3"
	.section	.note.GNU-stack,"",@progbits
