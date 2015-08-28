	.file	"misc.c"
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
	.type	element_init, @function
element_init:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$24, %esp
	movl	8(%ebp), %eax
	movl	12(%ebp), %edx
	movl	%edx, (%eax)
	movl	12(%ebp), %eax
	movl	4(%eax), %edx
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	*%edx
	leave
	ret
	.size	element_init, .-element_init
	.type	element_clear, @function
element_clear:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$24, %esp
	movl	8(%ebp), %eax
	movl	(%eax), %eax
	movl	8(%eax), %edx
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	*%edx
	leave
	ret
	.size	element_clear, .-element_clear
	.type	element_length_in_bytes, @function
element_length_in_bytes:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$24, %esp
	movl	8(%ebp), %eax
	movl	(%eax), %eax
	movl	164(%eax), %eax
	testl	%eax, %eax
	jns	.L10
	movl	8(%ebp), %eax
	movl	(%eax), %eax
	movl	160(%eax), %edx
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	*%edx
	jmp	.L11
.L10:
	movl	8(%ebp), %eax
	movl	(%eax), %eax
	movl	164(%eax), %eax
.L11:
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
	.type	element_from_bytes, @function
element_from_bytes:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$24, %esp
	movl	8(%ebp), %eax
	movl	(%eax), %eax
	movl	156(%eax), %edx
	movl	12(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	*%edx
	leave
	ret
	.size	element_from_bytes, .-element_from_bytes
	.type	element_init_G1, @function
element_init_G1:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$24, %esp
	movl	12(%ebp), %eax
	movl	228(%eax), %eax
	movl	%eax, 4(%esp)
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	element_init
	leave
	ret
	.size	element_init_G1, .-element_init_G1
	.type	element_init_G2, @function
element_init_G2:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$24, %esp
	movl	12(%ebp), %eax
	movl	232(%eax), %eax
	movl	%eax, 4(%esp)
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	element_init
	leave
	ret
	.size	element_init_G2, .-element_init_G2
	.type	element_init_GT, @function
element_init_GT:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$24, %esp
	movl	12(%ebp), %eax
	addl	$236, %eax
	movl	%eax, 4(%esp)
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	element_init
	leave
	ret
	.size	element_init_GT, .-element_init_GT
	.type	element_init_Zr, @function
element_init_Zr:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$24, %esp
	movl	12(%ebp), %eax
	addl	$12, %eax
	movl	%eax, 4(%esp)
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	element_init
	leave
	ret
	.size	element_init_Zr, .-element_init_Zr
.globl serialize_uint32
	.type	serialize_uint32, @function
serialize_uint32:
	pushl	%ebp
	movl	%esp, %ebp
	pushl	%ebx
	subl	$36, %esp
	movl	$3, -16(%ebp)
	jmp	.L26
.L27:
	movl	-16(%ebp), %eax
	sall	$3, %eax
	movl	$255, %edx
	movl	%edx, %ebx
	movl	%eax, %ecx
	sall	%cl, %ebx
	movl	%ebx, %eax
	movl	%eax, %edx
	andl	12(%ebp), %edx
	movl	-16(%ebp), %eax
	sall	$3, %eax
	movl	%edx, %ebx
	movl	%eax, %ecx
	shrl	%cl, %ebx
	movl	%ebx, %eax
	movb	%al, -9(%ebp)
	movl	$1, 8(%esp)
	leal	-9(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	g_byte_array_append
	subl	$1, -16(%ebp)
.L26:
	cmpl	$0, -16(%ebp)
	jns	.L27
	addl	$36, %esp
	popl	%ebx
	popl	%ebp
	ret
	.size	serialize_uint32, .-serialize_uint32
.globl unserialize_uint32
	.type	unserialize_uint32, @function
unserialize_uint32:
	pushl	%ebp
	movl	%esp, %ebp
	pushl	%esi
	pushl	%ebx
	subl	$16, %esp
	movl	$0, -16(%ebp)
	movl	$3, -12(%ebp)
	jmp	.L30
.L31:
	movl	8(%ebp), %eax
	movl	(%eax), %ecx
	movl	12(%ebp), %eax
	movl	(%eax), %eax
	movl	%eax, %edx
	leal	(%ecx,%edx), %edx
	movzbl	(%edx), %edx
	movzbl	%dl, %ebx
	movl	-12(%ebp), %edx
	sall	$3, %edx
	movl	%ebx, %esi
	movl	%edx, %ecx
	sall	%cl, %esi
	movl	%esi, %edx
	orl	%edx, -16(%ebp)
	leal	1(%eax), %edx
	movl	12(%ebp), %eax
	movl	%edx, (%eax)
	subl	$1, -12(%ebp)
.L30:
	cmpl	$0, -12(%ebp)
	jns	.L31
	movl	-16(%ebp), %eax
	addl	$16, %esp
	popl	%ebx
	popl	%esi
	popl	%ebp
	ret
	.size	unserialize_uint32, .-unserialize_uint32
.globl serialize_element
	.type	serialize_element, @function
serialize_element:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$40, %esp
	movl	12(%ebp), %eax
	movl	%eax, (%esp)
	call	element_length_in_bytes
	movl	%eax, -12(%ebp)
	movl	-12(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	serialize_uint32
	movl	-12(%ebp), %eax
	movl	%eax, (%esp)
	call	malloc
	movl	%eax, -16(%ebp)
	movl	12(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	-16(%ebp), %eax
	movl	%eax, (%esp)
	call	element_to_bytes
	movl	-12(%ebp), %eax
	movl	%eax, 8(%esp)
	movl	-16(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	g_byte_array_append
	movl	-16(%ebp), %eax
	movl	%eax, (%esp)
	call	free
	leave
	ret
	.size	serialize_element, .-serialize_element
.globl unserialize_element
	.type	unserialize_element, @function
unserialize_element:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$40, %esp
	movl	12(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	unserialize_uint32
	movl	%eax, -12(%ebp)
	movl	-12(%ebp), %eax
	movl	%eax, (%esp)
	call	malloc
	movl	%eax, -16(%ebp)
	movl	8(%ebp), %eax
	movl	(%eax), %edx
	movl	12(%ebp), %eax
	movl	(%eax), %eax
	addl	%eax, %edx
	movl	-12(%ebp), %eax
	movl	%eax, 8(%esp)
	movl	%edx, 4(%esp)
	movl	-16(%ebp), %eax
	movl	%eax, (%esp)
	call	memcpy
	movl	12(%ebp), %eax
	movl	(%eax), %eax
	addl	-12(%ebp), %eax
	movl	%eax, %edx
	movl	12(%ebp), %eax
	movl	%edx, (%eax)
	movl	-16(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	16(%ebp), %eax
	movl	%eax, (%esp)
	call	element_from_bytes
	movl	-16(%ebp), %eax
	movl	%eax, (%esp)
	call	free
	leave
	ret
	.size	unserialize_element, .-unserialize_element
.globl serialize_string
	.type	serialize_string, @function
serialize_string:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$24, %esp
	movl	12(%ebp), %eax
	movl	%eax, (%esp)
	call	strlen
	leal	1(%eax), %edx
	movl	12(%ebp), %eax
	movl	%edx, 8(%esp)
	movl	%eax, 4(%esp)
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	g_byte_array_append
	leave
	ret
	.size	serialize_string, .-serialize_string
.globl unserialize_string
	.type	unserialize_string, @function
unserialize_string:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$40, %esp
	movl	$32, (%esp)
	call	g_string_sized_new
	movl	%eax, -16(%ebp)
.L41:
	movl	8(%ebp), %eax
	movl	(%eax), %ecx
	movl	12(%ebp), %eax
	movl	(%eax), %eax
	movl	%eax, %edx
	leal	(%ecx,%edx), %edx
	movzbl	(%edx), %edx
	movb	%dl, -9(%ebp)
	leal	1(%eax), %edx
	movl	12(%ebp), %eax
	movl	%edx, (%eax)
	cmpb	$0, -9(%ebp)
	je	.L40
	cmpb	$-1, -9(%ebp)
	je	.L40
	movsbl	-9(%ebp),%eax
	movl	%eax, 4(%esp)
	movl	-16(%ebp), %eax
	movl	%eax, (%esp)
	call	g_string_append_c_inline
	jmp	.L41
.L40:
	movl	-16(%ebp), %eax
	movl	(%eax), %eax
	movl	%eax, -20(%ebp)
	movl	$0, 4(%esp)
	movl	-16(%ebp), %eax
	movl	%eax, (%esp)
	call	g_string_free
	movl	-20(%ebp), %eax
	leave
	ret
	.size	unserialize_string, .-unserialize_string
.globl bswabe_pub_serialize
	.type	bswabe_pub_serialize, @function
bswabe_pub_serialize:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$40, %esp
	call	g_byte_array_new
	movl	%eax, -12(%ebp)
	movl	8(%ebp), %eax
	movl	(%eax), %eax
	movl	%eax, 4(%esp)
	movl	-12(%ebp), %eax
	movl	%eax, (%esp)
	call	serialize_string
	movl	8(%ebp), %eax
	addl	$512, %eax
	movl	%eax, 4(%esp)
	movl	-12(%ebp), %eax
	movl	%eax, (%esp)
	call	serialize_element
	movl	8(%ebp), %eax
	addl	$520, %eax
	movl	%eax, 4(%esp)
	movl	-12(%ebp), %eax
	movl	%eax, (%esp)
	call	serialize_element
	movl	8(%ebp), %eax
	addl	$528, %eax
	movl	%eax, 4(%esp)
	movl	-12(%ebp), %eax
	movl	%eax, (%esp)
	call	serialize_element
	movl	8(%ebp), %eax
	addl	$536, %eax
	movl	%eax, 4(%esp)
	movl	-12(%ebp), %eax
	movl	%eax, (%esp)
	call	serialize_element
	movl	-12(%ebp), %eax
	leave
	ret
	.size	bswabe_pub_serialize, .-bswabe_pub_serialize
.globl bswabe_pub_unserialize
	.type	bswabe_pub_unserialize, @function
bswabe_pub_unserialize:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$40, %esp
	movl	$544, (%esp)
	call	malloc
	movl	%eax, -12(%ebp)
	movl	$0, -16(%ebp)
	leal	-16(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	unserialize_string
	movl	-12(%ebp), %edx
	movl	%eax, (%edx)
	movl	-12(%ebp), %eax
	movl	(%eax), %eax
	movl	%eax, (%esp)
	call	strlen
	movl	-12(%ebp), %edx
	movl	(%edx), %edx
	movl	-12(%ebp), %ecx
	addl	$4, %ecx
	movl	%eax, 8(%esp)
	movl	%edx, 4(%esp)
	movl	%ecx, (%esp)
	call	pairing_init_set_buf
	movl	-12(%ebp), %eax
	leal	4(%eax), %edx
	movl	-12(%ebp), %eax
	addl	$512, %eax
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	element_init_G1
	movl	-12(%ebp), %eax
	leal	4(%eax), %edx
	movl	-12(%ebp), %eax
	addl	$520, %eax
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	element_init_G1
	movl	-12(%ebp), %eax
	leal	4(%eax), %edx
	movl	-12(%ebp), %eax
	addl	$528, %eax
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	element_init_G2
	movl	-12(%ebp), %eax
	leal	4(%eax), %edx
	movl	-12(%ebp), %eax
	addl	$536, %eax
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	element_init_GT
	movl	-12(%ebp), %eax
	addl	$512, %eax
	movl	%eax, 8(%esp)
	leal	-16(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	unserialize_element
	movl	-12(%ebp), %eax
	addl	$520, %eax
	movl	%eax, 8(%esp)
	leal	-16(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	unserialize_element
	movl	-12(%ebp), %eax
	addl	$528, %eax
	movl	%eax, 8(%esp)
	leal	-16(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	unserialize_element
	movl	-12(%ebp), %eax
	addl	$536, %eax
	movl	%eax, 8(%esp)
	leal	-16(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	unserialize_element
	cmpl	$0, 12(%ebp)
	je	.L46
	movl	$1, 4(%esp)
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	g_byte_array_free
.L46:
	movl	-12(%ebp), %eax
	leave
	ret
	.size	bswabe_pub_unserialize, .-bswabe_pub_unserialize
.globl bswabe_msk_serialize
	.type	bswabe_msk_serialize, @function
bswabe_msk_serialize:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$40, %esp
	call	g_byte_array_new
	movl	%eax, -12(%ebp)
	movl	8(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	-12(%ebp), %eax
	movl	%eax, (%esp)
	call	serialize_element
	movl	8(%ebp), %eax
	addl	$8, %eax
	movl	%eax, 4(%esp)
	movl	-12(%ebp), %eax
	movl	%eax, (%esp)
	call	serialize_element
	movl	-12(%ebp), %eax
	leave
	ret
	.size	bswabe_msk_serialize, .-bswabe_msk_serialize
.globl bswabe_msk_unserialize
	.type	bswabe_msk_unserialize, @function
bswabe_msk_unserialize:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$40, %esp
	movl	$16, (%esp)
	call	malloc
	movl	%eax, -12(%ebp)
	movl	$0, -16(%ebp)
	movl	8(%ebp), %eax
	leal	4(%eax), %edx
	movl	-12(%ebp), %eax
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	element_init_Zr
	movl	8(%ebp), %eax
	leal	4(%eax), %edx
	movl	-12(%ebp), %eax
	addl	$8, %eax
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	element_init_G2
	movl	-12(%ebp), %eax
	movl	%eax, 8(%esp)
	leal	-16(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	12(%ebp), %eax
	movl	%eax, (%esp)
	call	unserialize_element
	movl	-12(%ebp), %eax
	addl	$8, %eax
	movl	%eax, 8(%esp)
	leal	-16(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	12(%ebp), %eax
	movl	%eax, (%esp)
	call	unserialize_element
	cmpl	$0, 16(%ebp)
	je	.L51
	movl	$1, 4(%esp)
	movl	12(%ebp), %eax
	movl	%eax, (%esp)
	call	g_byte_array_free
.L51:
	movl	-12(%ebp), %eax
	leave
	ret
	.size	bswabe_msk_unserialize, .-bswabe_msk_unserialize
.globl bswabe_prv_serialize
	.type	bswabe_prv_serialize, @function
bswabe_prv_serialize:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$40, %esp
	call	g_byte_array_new
	movl	%eax, -12(%ebp)
	movl	8(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	-12(%ebp), %eax
	movl	%eax, (%esp)
	call	serialize_element
	movl	8(%ebp), %eax
	movl	8(%eax), %eax
	movl	4(%eax), %eax
	movl	%eax, 4(%esp)
	movl	-12(%ebp), %eax
	movl	%eax, (%esp)
	call	serialize_uint32
	movl	$0, -16(%ebp)
	jmp	.L54
.L55:
	movl	8(%ebp), %eax
	movl	8(%eax), %eax
	movl	(%eax), %eax
	movl	%eax, %ecx
	movl	-16(%ebp), %edx
	movl	%edx, %eax
	sall	$2, %eax
	addl	%edx, %eax
	sall	$3, %eax
	leal	(%ecx,%eax), %eax
	movl	(%eax), %eax
	movl	%eax, 4(%esp)
	movl	-12(%ebp), %eax
	movl	%eax, (%esp)
	call	serialize_string
	movl	8(%ebp), %eax
	movl	8(%eax), %eax
	movl	(%eax), %eax
	movl	%eax, %ecx
	movl	-16(%ebp), %edx
	movl	%edx, %eax
	sall	$2, %eax
	addl	%edx, %eax
	sall	$3, %eax
	leal	(%ecx,%eax), %eax
	addl	$4, %eax
	movl	%eax, 4(%esp)
	movl	-12(%ebp), %eax
	movl	%eax, (%esp)
	call	serialize_element
	movl	8(%ebp), %eax
	movl	8(%eax), %eax
	movl	(%eax), %eax
	movl	%eax, %ecx
	movl	-16(%ebp), %edx
	movl	%edx, %eax
	sall	$2, %eax
	addl	%edx, %eax
	sall	$3, %eax
	leal	(%ecx,%eax), %eax
	addl	$12, %eax
	movl	%eax, 4(%esp)
	movl	-12(%ebp), %eax
	movl	%eax, (%esp)
	call	serialize_element
	addl	$1, -16(%ebp)
.L54:
	movl	-16(%ebp), %edx
	movl	8(%ebp), %eax
	movl	8(%eax), %eax
	movl	4(%eax), %eax
	cmpl	%eax, %edx
	jb	.L55
	movl	-12(%ebp), %eax
	leave
	ret
	.size	bswabe_prv_serialize, .-bswabe_prv_serialize
.globl bswabe_prv_unserialize
	.type	bswabe_prv_unserialize, @function
bswabe_prv_unserialize:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$88, %esp
	movl	$12, (%esp)
	call	malloc
	movl	%eax, -12(%ebp)
	movl	$0, -24(%ebp)
	movl	8(%ebp), %eax
	leal	4(%eax), %edx
	movl	-12(%ebp), %eax
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	element_init_G2
	movl	-12(%ebp), %eax
	movl	%eax, 8(%esp)
	leal	-24(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	12(%ebp), %eax
	movl	%eax, (%esp)
	call	unserialize_element
	movl	$40, 8(%esp)
	movl	$1, 4(%esp)
	movl	$0, (%esp)
	call	g_array_new
	movl	-12(%ebp), %edx
	movl	%eax, 8(%edx)
	leal	-24(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	12(%ebp), %eax
	movl	%eax, (%esp)
	call	unserialize_uint32
	movl	%eax, -20(%ebp)
	movl	$0, -16(%ebp)
	jmp	.L58
.L59:
	leal	-24(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	12(%ebp), %eax
	movl	%eax, (%esp)
	call	unserialize_string
	movl	%eax, -64(%ebp)
	movl	8(%ebp), %eax
	addl	$4, %eax
	movl	%eax, 4(%esp)
	leal	-64(%ebp), %eax
	addl	$4, %eax
	movl	%eax, (%esp)
	call	element_init_G2
	movl	8(%ebp), %eax
	addl	$4, %eax
	movl	%eax, 4(%esp)
	leal	-64(%ebp), %eax
	addl	$12, %eax
	movl	%eax, (%esp)
	call	element_init_G2
	leal	-64(%ebp), %eax
	addl	$4, %eax
	movl	%eax, 8(%esp)
	leal	-24(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	12(%ebp), %eax
	movl	%eax, (%esp)
	call	unserialize_element
	leal	-64(%ebp), %eax
	addl	$12, %eax
	movl	%eax, 8(%esp)
	leal	-24(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	12(%ebp), %eax
	movl	%eax, (%esp)
	call	unserialize_element
	movl	-12(%ebp), %eax
	movl	8(%eax), %eax
	movl	$1, 8(%esp)
	leal	-64(%ebp), %edx
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	g_array_append_vals
	addl	$1, -16(%ebp)
.L58:
	movl	-16(%ebp), %eax
	cmpl	-20(%ebp), %eax
	jl	.L59
	cmpl	$0, 16(%ebp)
	je	.L60
	movl	$1, 4(%esp)
	movl	12(%ebp), %eax
	movl	%eax, (%esp)
	call	g_byte_array_free
.L60:
	movl	-12(%ebp), %eax
	leave
	ret
	.size	bswabe_prv_unserialize, .-bswabe_prv_unserialize
.globl serialize_policy
	.type	serialize_policy, @function
serialize_policy:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$40, %esp
	movl	12(%ebp), %eax
	movl	(%eax), %eax
	movl	%eax, 4(%esp)
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	serialize_uint32
	movl	12(%ebp), %eax
	movl	24(%eax), %eax
	movl	4(%eax), %eax
	movl	%eax, 4(%esp)
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	serialize_uint32
	movl	12(%ebp), %eax
	movl	24(%eax), %eax
	movl	4(%eax), %eax
	testl	%eax, %eax
	jne	.L63
	movl	12(%ebp), %eax
	movl	4(%eax), %eax
	movl	%eax, 4(%esp)
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	serialize_string
	movl	12(%ebp), %eax
	addl	$8, %eax
	movl	%eax, 4(%esp)
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	serialize_element
	movl	12(%ebp), %eax
	addl	$16, %eax
	movl	%eax, 4(%esp)
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	serialize_element
	jmp	.L67
.L63:
	movl	$0, -12(%ebp)
	jmp	.L65
.L66:
	movl	12(%ebp), %eax
	movl	24(%eax), %eax
	movl	(%eax), %eax
	movl	-12(%ebp), %edx
	sall	$2, %edx
	addl	%edx, %eax
	movl	(%eax), %eax
	movl	%eax, 4(%esp)
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	serialize_policy
	addl	$1, -12(%ebp)
.L65:
	movl	-12(%ebp), %edx
	movl	12(%ebp), %eax
	movl	24(%eax), %eax
	movl	4(%eax), %eax
	cmpl	%eax, %edx
	jb	.L66
.L67:
	leave
	ret
	.size	serialize_policy, .-serialize_policy
.globl unserialize_policy
	.type	unserialize_policy, @function
unserialize_policy:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$40, %esp
	movl	$48, (%esp)
	call	malloc
	movl	%eax, -20(%ebp)
	movl	16(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	12(%ebp), %eax
	movl	%eax, (%esp)
	call	unserialize_uint32
	movl	%eax, %edx
	movl	-20(%ebp), %eax
	movl	%edx, (%eax)
	movl	-20(%ebp), %eax
	movl	$0, 4(%eax)
	call	g_ptr_array_new
	movl	-20(%ebp), %edx
	movl	%eax, 24(%edx)
	movl	16(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	12(%ebp), %eax
	movl	%eax, (%esp)
	call	unserialize_uint32
	movl	%eax, -16(%ebp)
	cmpl	$0, -16(%ebp)
	jne	.L69
	movl	16(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	12(%ebp), %eax
	movl	%eax, (%esp)
	call	unserialize_string
	movl	-20(%ebp), %edx
	movl	%eax, 4(%edx)
	movl	8(%ebp), %eax
	leal	4(%eax), %edx
	movl	-20(%ebp), %eax
	addl	$8, %eax
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	element_init_G1
	movl	8(%ebp), %eax
	leal	4(%eax), %edx
	movl	-20(%ebp), %eax
	addl	$16, %eax
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	element_init_G1
	movl	-20(%ebp), %eax
	addl	$8, %eax
	movl	%eax, 8(%esp)
	movl	16(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	12(%ebp), %eax
	movl	%eax, (%esp)
	call	unserialize_element
	movl	-20(%ebp), %eax
	addl	$16, %eax
	movl	%eax, 8(%esp)
	movl	16(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	12(%ebp), %eax
	movl	%eax, (%esp)
	call	unserialize_element
	jmp	.L70
.L69:
	movl	$0, -12(%ebp)
	jmp	.L71
.L72:
	movl	16(%ebp), %eax
	movl	%eax, 8(%esp)
	movl	12(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	unserialize_policy
	movl	-20(%ebp), %edx
	movl	24(%edx), %edx
	movl	%eax, 4(%esp)
	movl	%edx, (%esp)
	call	g_ptr_array_add
	addl	$1, -12(%ebp)
.L71:
	movl	-12(%ebp), %eax
	cmpl	-16(%ebp), %eax
	jl	.L72
.L70:
	movl	-20(%ebp), %eax
	leave
	ret
	.size	unserialize_policy, .-unserialize_policy
.globl bswabe_cph_serialize
	.type	bswabe_cph_serialize, @function
bswabe_cph_serialize:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$40, %esp
	call	g_byte_array_new
	movl	%eax, -12(%ebp)
	movl	8(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	-12(%ebp), %eax
	movl	%eax, (%esp)
	call	serialize_element
	movl	8(%ebp), %eax
	addl	$8, %eax
	movl	%eax, 4(%esp)
	movl	-12(%ebp), %eax
	movl	%eax, (%esp)
	call	serialize_element
	movl	8(%ebp), %eax
	movl	16(%eax), %eax
	movl	%eax, 4(%esp)
	movl	-12(%ebp), %eax
	movl	%eax, (%esp)
	call	serialize_policy
	movl	-12(%ebp), %eax
	leave
	ret
	.size	bswabe_cph_serialize, .-bswabe_cph_serialize
.globl bswabe_cph_unserialize
	.type	bswabe_cph_unserialize, @function
bswabe_cph_unserialize:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$40, %esp
	movl	$20, (%esp)
	call	malloc
	movl	%eax, -12(%ebp)
	movl	$0, -16(%ebp)
	movl	8(%ebp), %eax
	leal	4(%eax), %edx
	movl	-12(%ebp), %eax
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	element_init_GT
	movl	8(%ebp), %eax
	leal	4(%eax), %edx
	movl	-12(%ebp), %eax
	addl	$8, %eax
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	element_init_G1
	movl	-12(%ebp), %eax
	movl	%eax, 8(%esp)
	leal	-16(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	12(%ebp), %eax
	movl	%eax, (%esp)
	call	unserialize_element
	movl	-12(%ebp), %eax
	addl	$8, %eax
	movl	%eax, 8(%esp)
	leal	-16(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	12(%ebp), %eax
	movl	%eax, (%esp)
	call	unserialize_element
	leal	-16(%ebp), %eax
	movl	%eax, 8(%esp)
	movl	12(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	unserialize_policy
	movl	-12(%ebp), %edx
	movl	%eax, 16(%edx)
	cmpl	$0, 16(%ebp)
	je	.L77
	movl	$1, 4(%esp)
	movl	12(%ebp), %eax
	movl	%eax, (%esp)
	call	g_byte_array_free
.L77:
	movl	-12(%ebp), %eax
	leave
	ret
	.size	bswabe_cph_unserialize, .-bswabe_cph_unserialize
.globl bswabe_pub_free
	.type	bswabe_pub_free, @function
bswabe_pub_free:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$24, %esp
	movl	8(%ebp), %eax
	addl	$512, %eax
	movl	%eax, (%esp)
	call	element_clear
	movl	8(%ebp), %eax
	addl	$520, %eax
	movl	%eax, (%esp)
	call	element_clear
	movl	8(%ebp), %eax
	addl	$528, %eax
	movl	%eax, (%esp)
	call	element_clear
	movl	8(%ebp), %eax
	addl	$536, %eax
	movl	%eax, (%esp)
	call	element_clear
	movl	8(%ebp), %eax
	addl	$4, %eax
	movl	%eax, (%esp)
	call	pairing_clear
	movl	8(%ebp), %eax
	movl	(%eax), %eax
	movl	%eax, (%esp)
	call	free
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	free
	leave
	ret
	.size	bswabe_pub_free, .-bswabe_pub_free
.globl bswabe_msk_free
	.type	bswabe_msk_free, @function
bswabe_msk_free:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$24, %esp
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	element_clear
	movl	8(%ebp), %eax
	addl	$8, %eax
	movl	%eax, (%esp)
	call	element_clear
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	free
	leave
	ret
	.size	bswabe_msk_free, .-bswabe_msk_free
.globl bswabe_prv_free
	.type	bswabe_prv_free, @function
bswabe_prv_free:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$72, %esp
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	element_clear
	movl	$0, -12(%ebp)
	jmp	.L84
.L85:
	movl	8(%ebp), %eax
	movl	8(%eax), %eax
	movl	(%eax), %eax
	movl	%eax, %ecx
	movl	-12(%ebp), %edx
	movl	%edx, %eax
	sall	$2, %eax
	addl	%edx, %eax
	sall	$3, %eax
	leal	(%ecx,%eax), %eax
	movl	(%eax), %edx
	movl	%edx, -52(%ebp)
	movl	4(%eax), %edx
	movl	%edx, -48(%ebp)
	movl	8(%eax), %edx
	movl	%edx, -44(%ebp)
	movl	12(%eax), %edx
	movl	%edx, -40(%ebp)
	movl	16(%eax), %edx
	movl	%edx, -36(%ebp)
	movl	20(%eax), %edx
	movl	%edx, -32(%ebp)
	movl	24(%eax), %edx
	movl	%edx, -28(%ebp)
	movl	28(%eax), %edx
	movl	%edx, -24(%ebp)
	movl	32(%eax), %edx
	movl	%edx, -20(%ebp)
	movl	36(%eax), %eax
	movl	%eax, -16(%ebp)
	movl	-52(%ebp), %eax
	movl	%eax, (%esp)
	call	free
	leal	-52(%ebp), %eax
	addl	$4, %eax
	movl	%eax, (%esp)
	call	element_clear
	leal	-52(%ebp), %eax
	addl	$12, %eax
	movl	%eax, (%esp)
	call	element_clear
	addl	$1, -12(%ebp)
.L84:
	movl	-12(%ebp), %edx
	movl	8(%ebp), %eax
	movl	8(%eax), %eax
	movl	4(%eax), %eax
	cmpl	%eax, %edx
	jb	.L85
	movl	8(%ebp), %eax
	movl	8(%eax), %eax
	movl	$1, 4(%esp)
	movl	%eax, (%esp)
	call	g_array_free
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	free
	leave
	ret
	.size	bswabe_prv_free, .-bswabe_prv_free
.globl bswabe_policy_free
	.type	bswabe_policy_free, @function
bswabe_policy_free:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$40, %esp
	movl	8(%ebp), %eax
	movl	4(%eax), %eax
	testl	%eax, %eax
	je	.L88
	movl	8(%ebp), %eax
	movl	4(%eax), %eax
	movl	%eax, (%esp)
	call	free
	movl	8(%ebp), %eax
	addl	$8, %eax
	movl	%eax, (%esp)
	call	element_clear
	movl	8(%ebp), %eax
	addl	$16, %eax
	movl	%eax, (%esp)
	call	element_clear
.L88:
	movl	$0, -12(%ebp)
	jmp	.L89
.L90:
	movl	8(%ebp), %eax
	movl	24(%eax), %eax
	movl	(%eax), %eax
	movl	-12(%ebp), %edx
	sall	$2, %edx
	addl	%edx, %eax
	movl	(%eax), %eax
	movl	%eax, (%esp)
	call	bswabe_policy_free
	addl	$1, -12(%ebp)
.L89:
	movl	-12(%ebp), %edx
	movl	8(%ebp), %eax
	movl	24(%eax), %eax
	movl	4(%eax), %eax
	cmpl	%eax, %edx
	jb	.L90
	movl	8(%ebp), %eax
	movl	24(%eax), %eax
	movl	$1, 4(%esp)
	movl	%eax, (%esp)
	call	g_ptr_array_free
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	free
	leave
	ret
	.size	bswabe_policy_free, .-bswabe_policy_free
.globl bswabe_cph_free
	.type	bswabe_cph_free, @function
bswabe_cph_free:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$24, %esp
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	element_clear
	movl	8(%ebp), %eax
	addl	$8, %eax
	movl	%eax, (%esp)
	call	element_clear
	movl	8(%ebp), %eax
	movl	16(%eax), %eax
	movl	%eax, (%esp)
	call	bswabe_policy_free
	leave
	ret
	.size	bswabe_cph_free, .-bswabe_cph_free
	.ident	"GCC: (Ubuntu 4.4.3-4ubuntu5) 4.4.3"
	.section	.note.GNU-stack,"",@progbits
