	.file	"core.c"
	.text
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
	.type	element_init_same_as, @function
element_init_same_as:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$24, %esp
	movl	12(%ebp), %eax
	movl	(%eax), %eax
	movl	%eax, 4(%esp)
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	element_init
	leave
	ret
	.size	element_init_same_as, .-element_init_same_as
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
	.type	element_set0, @function
element_set0:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$24, %esp
	movl	8(%ebp), %eax
	movl	(%eax), %eax
	movl	24(%eax), %edx
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	*%edx
	leave
	ret
	.size	element_set0, .-element_set0
	.type	element_set1, @function
element_set1:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$24, %esp
	movl	8(%ebp), %eax
	movl	(%eax), %eax
	movl	28(%eax), %edx
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	*%edx
	leave
	ret
	.size	element_set1, .-element_set1
	.type	element_set_si, @function
element_set_si:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$24, %esp
	movl	8(%ebp), %eax
	movl	(%eax), %eax
	movl	76(%eax), %edx
	movl	12(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	*%edx
	leave
	ret
	.size	element_set_si, .-element_set_si
	.type	element_set, @function
element_set:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$24, %esp
	movl	8(%ebp), %eax
	movl	(%eax), %eax
	movl	20(%eax), %edx
	movl	12(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	*%edx
	leave
	ret
	.size	element_set, .-element_set
	.type	element_to_mpz, @function
element_to_mpz:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$24, %esp
	movl	12(%ebp), %eax
	movl	(%eax), %eax
	movl	172(%eax), %edx
	movl	12(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	*%edx
	leave
	ret
	.size	element_to_mpz, .-element_to_mpz
	.type	element_from_hash, @function
element_from_hash:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$24, %esp
	movl	8(%ebp), %eax
	movl	(%eax), %eax
	movl	132(%eax), %edx
	movl	16(%ebp), %eax
	movl	%eax, 8(%esp)
	movl	12(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	*%edx
	leave
	ret
	.size	element_from_hash, .-element_from_hash
	.type	element_add, @function
element_add:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$24, %esp
	movl	8(%ebp), %eax
	movl	(%eax), %eax
	movl	40(%eax), %edx
	movl	16(%ebp), %eax
	movl	%eax, 8(%esp)
	movl	12(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	*%edx
	leave
	ret
	.size	element_add, .-element_add
	.type	element_mul, @function
element_mul:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$24, %esp
	movl	8(%ebp), %eax
	movl	(%eax), %eax
	movl	48(%eax), %edx
	movl	16(%ebp), %eax
	movl	%eax, 8(%esp)
	movl	12(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	*%edx
	leave
	ret
	.size	element_mul, .-element_mul
	.type	element_pow_mpz, @function
element_pow_mpz:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$24, %esp
	movl	8(%ebp), %eax
	movl	(%eax), %eax
	movl	116(%eax), %edx
	movl	16(%ebp), %eax
	movl	%eax, 8(%esp)
	movl	12(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	*%edx
	leave
	ret
	.size	element_pow_mpz, .-element_pow_mpz
	.type	element_pow_zn, @function
element_pow_zn:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$40, %esp
	leal	-20(%ebp), %eax
	movl	%eax, (%esp)
	call	__gmpz_init
	movl	16(%ebp), %eax
	movl	%eax, 4(%esp)
	leal	-20(%ebp), %eax
	movl	%eax, (%esp)
	call	element_to_mpz
	leal	-20(%ebp), %eax
	movl	%eax, 8(%esp)
	movl	12(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	element_pow_mpz
	leal	-20(%ebp), %eax
	movl	%eax, (%esp)
	call	__gmpz_clear
	leave
	ret
	.size	element_pow_zn, .-element_pow_zn
	.type	element_invert, @function
element_invert:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$24, %esp
	movl	8(%ebp), %eax
	movl	(%eax), %eax
	movl	120(%eax), %edx
	movl	12(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	*%edx
	leave
	ret
	.size	element_invert, .-element_invert
	.type	element_random, @function
element_random:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$24, %esp
	movl	8(%ebp), %eax
	movl	(%eax), %eax
	movl	128(%eax), %edx
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	*%edx
	leave
	ret
	.size	element_random, .-element_random
	.type	element_is0, @function
element_is0:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$24, %esp
	movl	8(%ebp), %eax
	movl	(%eax), %eax
	movl	140(%eax), %edx
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	*%edx
	leave
	ret
	.size	element_is0, .-element_is0
	.type	pairing_apply, @function
pairing_apply:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$24, %esp
	movl	12(%ebp), %eax
	movl	%eax, (%esp)
	call	element_is0
	testl	%eax, %eax
	je	.L34
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	element_set0
	jmp	.L37
.L34:
	movl	16(%ebp), %eax
	movl	%eax, (%esp)
	call	element_is0
	testl	%eax, %eax
	je	.L36
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	element_set0
	jmp	.L37
.L36:
	movl	20(%ebp), %eax
	movl	468(%eax), %ecx
	movl	8(%ebp), %eax
	movl	4(%eax), %eax
	movl	20(%ebp), %edx
	movl	%edx, 12(%esp)
	movl	16(%ebp), %edx
	movl	%edx, 8(%esp)
	movl	12(%ebp), %edx
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	*%ecx
.L37:
	leave
	ret
	.size	pairing_apply, .-pairing_apply
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
	.comm	last_error,256,32
.globl bswabe_error
	.type	bswabe_error, @function
bswabe_error:
	pushl	%ebp
	movl	%esp, %ebp
	movl	$last_error, %eax
	popl	%ebp
	ret
	.size	bswabe_error, .-bswabe_error
.globl raise_error
	.type	raise_error, @function
raise_error:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$40, %esp
	leal	12(%ebp), %eax
	movl	%eax, -12(%ebp)
	movl	-12(%ebp), %edx
	movl	8(%ebp), %eax
	movl	%edx, 12(%esp)
	movl	%eax, 8(%esp)
	movl	$256, 4(%esp)
	movl	$last_error, (%esp)
	call	vsnprintf
	leave
	ret
	.size	raise_error, .-raise_error
.globl element_from_string
	.type	element_from_string, @function
element_from_string:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$40, %esp
	movl	$20, (%esp)
	call	malloc
	movl	%eax, -12(%ebp)
	movl	12(%ebp), %eax
	movl	%eax, (%esp)
	call	strlen
	movl	%eax, %edx
	movl	12(%ebp), %eax
	movl	-12(%ebp), %ecx
	movl	%ecx, 8(%esp)
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	SHA1
	movl	$20, 8(%esp)
	movl	-12(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	element_from_hash
	movl	-12(%ebp), %eax
	movl	%eax, (%esp)
	call	free
	leave
	ret
	.size	element_from_string, .-element_from_string
	.section	.rodata
	.align 4
.LC0:
	.ascii	"type a\nq 87807107996633125224377819847540498158068831994142"
	.ascii	"08211028653399266475630880222957078625179422"
	.string	"662221423155858769582317459277713367317481324925129998224791\nh 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776\nr 730750818665451621361119245571504901405976559617\nexp2 159\nexp1 107\nsign1 1\nsign0 1\n"
	.text
.globl bswabe_setup
	.type	bswabe_setup, @function
bswabe_setup:
	pushl	%ebp
	movl	%esp, %ebp
	pushl	%ebx
	subl	$36, %esp
	movl	$544, (%esp)
	call	malloc
	movl	%eax, %edx
	movl	8(%ebp), %eax
	movl	%edx, (%eax)
	movl	$16, (%esp)
	call	malloc
	movl	%eax, %edx
	movl	12(%ebp), %eax
	movl	%edx, (%eax)
	movl	8(%ebp), %eax
	movl	(%eax), %ebx
	movl	$.LC0, (%esp)
	call	strdup
	movl	%eax, (%ebx)
	movl	8(%ebp), %eax
	movl	(%eax), %eax
	movl	(%eax), %eax
	movl	%eax, (%esp)
	call	strlen
	movl	8(%ebp), %edx
	movl	(%edx), %edx
	movl	(%edx), %edx
	movl	8(%ebp), %ecx
	movl	(%ecx), %ecx
	addl	$4, %ecx
	movl	%eax, 8(%esp)
	movl	%edx, 4(%esp)
	movl	%ecx, (%esp)
	call	pairing_init_set_buf
	movl	8(%ebp), %eax
	movl	(%eax), %eax
	leal	4(%eax), %edx
	movl	8(%ebp), %eax
	movl	(%eax), %eax
	addl	$512, %eax
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	element_init_G1
	movl	8(%ebp), %eax
	movl	(%eax), %eax
	leal	4(%eax), %edx
	movl	8(%ebp), %eax
	movl	(%eax), %eax
	addl	$520, %eax
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	element_init_G1
	movl	8(%ebp), %eax
	movl	(%eax), %eax
	leal	4(%eax), %edx
	movl	8(%ebp), %eax
	movl	(%eax), %eax
	addl	$528, %eax
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	element_init_G2
	movl	8(%ebp), %eax
	movl	(%eax), %eax
	leal	4(%eax), %edx
	movl	8(%ebp), %eax
	movl	(%eax), %eax
	addl	$536, %eax
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	element_init_GT
	movl	8(%ebp), %eax
	movl	(%eax), %eax
	addl	$4, %eax
	movl	%eax, 4(%esp)
	leal	-16(%ebp), %eax
	movl	%eax, (%esp)
	call	element_init_Zr
	movl	8(%ebp), %eax
	movl	(%eax), %eax
	leal	4(%eax), %edx
	movl	12(%ebp), %eax
	movl	(%eax), %eax
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	element_init_Zr
	movl	8(%ebp), %eax
	movl	(%eax), %eax
	leal	4(%eax), %edx
	movl	12(%ebp), %eax
	movl	(%eax), %eax
	addl	$8, %eax
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	element_init_G2
	leal	-16(%ebp), %eax
	movl	%eax, (%esp)
	call	element_random
	movl	12(%ebp), %eax
	movl	(%eax), %eax
	movl	%eax, (%esp)
	call	element_random
	movl	8(%ebp), %eax
	movl	(%eax), %eax
	addl	$512, %eax
	movl	%eax, (%esp)
	call	element_random
	movl	8(%ebp), %eax
	movl	(%eax), %eax
	addl	$528, %eax
	movl	%eax, (%esp)
	call	element_random
	movl	8(%ebp), %eax
	movl	(%eax), %eax
	leal	528(%eax), %ecx
	movl	12(%ebp), %eax
	movl	(%eax), %eax
	leal	8(%eax), %edx
	leal	-16(%ebp), %eax
	movl	%eax, 8(%esp)
	movl	%ecx, 4(%esp)
	movl	%edx, (%esp)
	call	element_pow_zn
	movl	12(%ebp), %eax
	movl	(%eax), %eax
	movl	8(%ebp), %edx
	movl	(%edx), %edx
	leal	512(%edx), %ecx
	movl	8(%ebp), %edx
	movl	(%edx), %edx
	addl	$520, %edx
	movl	%eax, 8(%esp)
	movl	%ecx, 4(%esp)
	movl	%edx, (%esp)
	call	element_pow_zn
	movl	8(%ebp), %eax
	movl	(%eax), %eax
	leal	4(%eax), %ebx
	movl	12(%ebp), %eax
	movl	(%eax), %eax
	leal	8(%eax), %ecx
	movl	8(%ebp), %eax
	movl	(%eax), %eax
	leal	512(%eax), %edx
	movl	8(%ebp), %eax
	movl	(%eax), %eax
	addl	$536, %eax
	movl	%ebx, 12(%esp)
	movl	%ecx, 8(%esp)
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	pairing_apply
	addl	$36, %esp
	popl	%ebx
	popl	%ebp
	ret
	.size	bswabe_setup, .-bswabe_setup
.globl bswabe_keygen
	.type	bswabe_keygen, @function
bswabe_keygen:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$120, %esp
	movl	$12, (%esp)
	call	malloc
	movl	%eax, -12(%ebp)
	movl	8(%ebp), %eax
	leal	4(%eax), %edx
	movl	-12(%ebp), %eax
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	element_init_G2
	movl	8(%ebp), %eax
	addl	$4, %eax
	movl	%eax, 4(%esp)
	leal	-20(%ebp), %eax
	movl	%eax, (%esp)
	call	element_init_G2
	movl	8(%ebp), %eax
	addl	$4, %eax
	movl	%eax, 4(%esp)
	leal	-28(%ebp), %eax
	movl	%eax, (%esp)
	call	element_init_Zr
	movl	8(%ebp), %eax
	addl	$4, %eax
	movl	%eax, 4(%esp)
	leal	-36(%ebp), %eax
	movl	%eax, (%esp)
	call	element_init_Zr
	movl	$40, 8(%esp)
	movl	$1, 4(%esp)
	movl	$0, (%esp)
	call	g_array_new
	movl	-12(%ebp), %edx
	movl	%eax, 8(%edx)
	leal	-28(%ebp), %eax
	movl	%eax, (%esp)
	call	element_random
	movl	8(%ebp), %eax
	leal	528(%eax), %edx
	leal	-28(%ebp), %eax
	movl	%eax, 8(%esp)
	movl	%edx, 4(%esp)
	leal	-20(%ebp), %eax
	movl	%eax, (%esp)
	call	element_pow_zn
	movl	12(%ebp), %eax
	leal	8(%eax), %ecx
	movl	-12(%ebp), %eax
	leal	-20(%ebp), %edx
	movl	%edx, 8(%esp)
	movl	%ecx, 4(%esp)
	movl	%eax, (%esp)
	call	element_mul
	movl	12(%ebp), %eax
	movl	%eax, 4(%esp)
	leal	-36(%ebp), %eax
	movl	%eax, (%esp)
	call	element_invert
	movl	-12(%ebp), %edx
	movl	-12(%ebp), %eax
	leal	-36(%ebp), %ecx
	movl	%ecx, 8(%esp)
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	element_pow_zn
	jmp	.L55
.L56:
	movl	16(%ebp), %eax
	movl	(%eax), %eax
	movl	%eax, -92(%ebp)
	addl	$4, 16(%ebp)
	movl	8(%ebp), %eax
	addl	$4, %eax
	movl	%eax, 4(%esp)
	leal	-92(%ebp), %eax
	addl	$4, %eax
	movl	%eax, (%esp)
	call	element_init_G2
	movl	8(%ebp), %eax
	addl	$4, %eax
	movl	%eax, 4(%esp)
	leal	-92(%ebp), %eax
	addl	$12, %eax
	movl	%eax, (%esp)
	call	element_init_G1
	movl	8(%ebp), %eax
	addl	$4, %eax
	movl	%eax, 4(%esp)
	leal	-44(%ebp), %eax
	movl	%eax, (%esp)
	call	element_init_G2
	movl	8(%ebp), %eax
	addl	$4, %eax
	movl	%eax, 4(%esp)
	leal	-52(%ebp), %eax
	movl	%eax, (%esp)
	call	element_init_Zr
	movl	-92(%ebp), %eax
	movl	%eax, 4(%esp)
	leal	-44(%ebp), %eax
	movl	%eax, (%esp)
	call	element_from_string
	leal	-52(%ebp), %eax
	movl	%eax, (%esp)
	call	element_random
	leal	-52(%ebp), %eax
	movl	%eax, 8(%esp)
	leal	-44(%ebp), %eax
	movl	%eax, 4(%esp)
	leal	-44(%ebp), %eax
	movl	%eax, (%esp)
	call	element_pow_zn
	leal	-44(%ebp), %eax
	movl	%eax, 8(%esp)
	leal	-20(%ebp), %eax
	movl	%eax, 4(%esp)
	leal	-92(%ebp), %eax
	addl	$4, %eax
	movl	%eax, (%esp)
	call	element_mul
	movl	8(%ebp), %eax
	leal	512(%eax), %edx
	leal	-52(%ebp), %eax
	movl	%eax, 8(%esp)
	movl	%edx, 4(%esp)
	leal	-92(%ebp), %eax
	addl	$12, %eax
	movl	%eax, (%esp)
	call	element_pow_zn
	leal	-44(%ebp), %eax
	movl	%eax, (%esp)
	call	element_clear
	leal	-52(%ebp), %eax
	movl	%eax, (%esp)
	call	element_clear
	movl	-12(%ebp), %eax
	movl	8(%eax), %eax
	movl	$1, 8(%esp)
	leal	-92(%ebp), %edx
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	g_array_append_vals
.L55:
	movl	16(%ebp), %eax
	movl	(%eax), %eax
	testl	%eax, %eax
	jne	.L56
	movl	-12(%ebp), %eax
	leave
	ret
	.size	bswabe_keygen, .-bswabe_keygen
.globl base_node
	.type	base_node, @function
base_node:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$40, %esp
	movl	$48, (%esp)
	call	malloc
	movl	%eax, -12(%ebp)
	movl	-12(%ebp), %eax
	movl	8(%ebp), %edx
	movl	%edx, (%eax)
	cmpl	$0, 12(%ebp)
	je	.L59
	movl	12(%ebp), %eax
	movl	%eax, (%esp)
	call	strdup
	jmp	.L60
.L59:
	movl	$0, %eax
.L60:
	movl	-12(%ebp), %edx
	movl	%eax, 4(%edx)
	call	g_ptr_array_new
	movl	-12(%ebp), %edx
	movl	%eax, 24(%edx)
	movl	-12(%ebp), %eax
	movl	$0, 28(%eax)
	movl	-12(%ebp), %eax
	leave
	ret
	.size	base_node, .-base_node
	.section	.rodata
.LC1:
	.string	" "
.LC2:
	.string	"%dof%d"
	.align 4
.LC3:
	.string	"error parsing \"%s\": trivially satisfied operator \"%s\"\n"
	.align 4
.LC4:
	.string	"error parsing \"%s\": unsatisfiable operator \"%s\"\n"
	.align 4
.LC5:
	.string	"error parsing \"%s\": identity operator \"%s\"\n"
	.align 4
.LC6:
	.string	"error parsing \"%s\": stack underflow at \"%s\"\n"
	.align 4
.LC7:
	.string	"error parsing \"%s\": extra tokens left on stack\n"
	.align 4
.LC8:
	.string	"error parsing \"%s\": empty policy\n"
	.text
.globl parse_policy_postfix
	.type	parse_policy_postfix, @function
parse_policy_postfix:
	pushl	%ebp
	movl	%esp, %ebp
	pushl	%ebx
	subl	$68, %esp
	movl	$0, 8(%esp)
	movl	$.LC1, 4(%esp)
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	g_strsplit
	movl	%eax, -12(%ebp)
	movl	-12(%ebp), %eax
	movl	%eax, -16(%ebp)
	call	g_ptr_array_new
	movl	%eax, -24(%ebp)
	jmp	.L63
.L73:
	movl	-16(%ebp), %eax
	movl	(%eax), %eax
	movl	%eax, -20(%ebp)
	addl	$4, -16(%ebp)
	movl	-20(%ebp), %eax
	movzbl	(%eax), %eax
	testb	%al, %al
	je	.L77
.L64:
	movl	$.LC2, %edx
	movl	-20(%ebp), %eax
	leal	-40(%ebp), %ecx
	movl	%ecx, 12(%esp)
	leal	-36(%ebp), %ecx
	movl	%ecx, 8(%esp)
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	__isoc99_sscanf
	cmpl	$2, %eax
	je	.L65
	movl	-20(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	$1, (%esp)
	call	base_node
	movl	%eax, 4(%esp)
	movl	-24(%ebp), %eax
	movl	%eax, (%esp)
	call	g_ptr_array_add
	jmp	.L63
.L65:
	movl	-36(%ebp), %eax
	testl	%eax, %eax
	jg	.L66
	movl	-20(%ebp), %eax
	movl	%eax, 8(%esp)
	movl	8(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	$.LC3, (%esp)
	call	raise_error
	movl	$0, %eax
	jmp	.L67
.L66:
	movl	-36(%ebp), %edx
	movl	-40(%ebp), %eax
	cmpl	%eax, %edx
	jle	.L68
	movl	-20(%ebp), %eax
	movl	%eax, 8(%esp)
	movl	8(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	$.LC4, (%esp)
	call	raise_error
	movl	$0, %eax
	jmp	.L67
.L68:
	movl	-40(%ebp), %eax
	cmpl	$1, %eax
	jne	.L69
	movl	-20(%ebp), %eax
	movl	%eax, 8(%esp)
	movl	8(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	$.LC5, (%esp)
	call	raise_error
	movl	$0, %eax
	jmp	.L67
.L69:
	movl	-40(%ebp), %eax
	movl	%eax, %edx
	movl	-24(%ebp), %eax
	movl	4(%eax), %eax
	cmpl	%eax, %edx
	jbe	.L70
	movl	-20(%ebp), %eax
	movl	%eax, 8(%esp)
	movl	8(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	$.LC6, (%esp)
	call	raise_error
	movl	$0, %eax
	jmp	.L67
.L70:
	movl	-36(%ebp), %eax
	movl	$0, 4(%esp)
	movl	%eax, (%esp)
	call	base_node
	movl	%eax, -44(%ebp)
	movl	-40(%ebp), %edx
	movl	-44(%ebp), %eax
	movl	24(%eax), %eax
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	g_ptr_array_set_size
	movl	-40(%ebp), %eax
	subl	$1, %eax
	movl	%eax, -32(%ebp)
	jmp	.L71
.L72:
	movl	-44(%ebp), %eax
	movl	24(%eax), %eax
	movl	(%eax), %eax
	movl	-32(%ebp), %edx
	sall	$2, %edx
	leal	(%eax,%edx), %ebx
	movl	-24(%ebp), %eax
	movl	4(%eax), %eax
	subl	$1, %eax
	movl	%eax, 4(%esp)
	movl	-24(%ebp), %eax
	movl	%eax, (%esp)
	call	g_ptr_array_remove_index
	movl	%eax, (%ebx)
	subl	$1, -32(%ebp)
.L71:
	cmpl	$0, -32(%ebp)
	jns	.L72
	movl	-44(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	-24(%ebp), %eax
	movl	%eax, (%esp)
	call	g_ptr_array_add
	jmp	.L63
.L77:
	nop
.L63:
	movl	-16(%ebp), %eax
	movl	(%eax), %eax
	testl	%eax, %eax
	jne	.L73
	movl	-24(%ebp), %eax
	movl	4(%eax), %eax
	cmpl	$1, %eax
	jbe	.L74
	movl	8(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	$.LC7, (%esp)
	call	raise_error
	movl	$0, %eax
	jmp	.L67
.L74:
	movl	-24(%ebp), %eax
	movl	4(%eax), %eax
	testl	%eax, %eax
	jne	.L75
	movl	8(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	$.LC8, (%esp)
	call	raise_error
	movl	$0, %eax
	jmp	.L67
.L75:
	movl	-24(%ebp), %eax
	movl	(%eax), %eax
	movl	(%eax), %eax
	movl	%eax, -28(%ebp)
	movl	-12(%ebp), %eax
	movl	%eax, (%esp)
	call	g_strfreev
	movl	$0, 4(%esp)
	movl	-24(%ebp), %eax
	movl	%eax, (%esp)
	call	g_ptr_array_free
	movl	-28(%ebp), %eax
.L67:
	addl	$68, %esp
	popl	%ebx
	popl	%ebp
	ret
	.size	parse_policy_postfix, .-parse_policy_postfix
.globl rand_poly
	.type	rand_poly, @function
rand_poly:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$40, %esp
	movl	$8, (%esp)
	call	malloc
	movl	%eax, -16(%ebp)
	movl	-16(%ebp), %eax
	movl	8(%ebp), %edx
	movl	%edx, (%eax)
	movl	8(%ebp), %eax
	addl	$1, %eax
	sall	$3, %eax
	movl	%eax, (%esp)
	call	malloc
	movl	%eax, %edx
	movl	-16(%ebp), %eax
	movl	%edx, 4(%eax)
	movl	$0, -12(%ebp)
	jmp	.L79
.L80:
	movl	-16(%ebp), %eax
	movl	4(%eax), %eax
	movl	-12(%ebp), %edx
	sall	$3, %edx
	leal	(%eax,%edx), %edx
	movl	12(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	%edx, (%esp)
	call	element_init_same_as
	addl	$1, -12(%ebp)
.L79:
	movl	-16(%ebp), %eax
	movl	(%eax), %eax
	addl	$1, %eax
	cmpl	-12(%ebp), %eax
	jg	.L80
	movl	-16(%ebp), %eax
	movl	4(%eax), %eax
	movl	12(%ebp), %edx
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	element_set
	movl	$1, -12(%ebp)
	jmp	.L81
.L82:
	movl	-16(%ebp), %eax
	movl	4(%eax), %eax
	movl	-12(%ebp), %edx
	sall	$3, %edx
	addl	%edx, %eax
	movl	%eax, (%esp)
	call	element_random
	addl	$1, -12(%ebp)
.L81:
	movl	-16(%ebp), %eax
	movl	(%eax), %eax
	addl	$1, %eax
	cmpl	-12(%ebp), %eax
	jg	.L82
	movl	-16(%ebp), %eax
	leave
	ret
	.size	rand_poly, .-rand_poly
.globl eval_poly
	.type	eval_poly, @function
eval_poly:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$56, %esp
	movl	8(%ebp), %eax
	movl	%eax, 4(%esp)
	leal	-20(%ebp), %eax
	movl	%eax, (%esp)
	call	element_init_same_as
	movl	8(%ebp), %eax
	movl	%eax, 4(%esp)
	leal	-28(%ebp), %eax
	movl	%eax, (%esp)
	call	element_init_same_as
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	element_set0
	leal	-28(%ebp), %eax
	movl	%eax, (%esp)
	call	element_set1
	movl	$0, -12(%ebp)
	jmp	.L85
.L86:
	movl	12(%ebp), %eax
	movl	4(%eax), %eax
	movl	-12(%ebp), %edx
	sall	$3, %edx
	leal	(%eax,%edx), %edx
	leal	-28(%ebp), %eax
	movl	%eax, 8(%esp)
	movl	%edx, 4(%esp)
	leal	-20(%ebp), %eax
	movl	%eax, (%esp)
	call	element_mul
	leal	-20(%ebp), %eax
	movl	%eax, 8(%esp)
	movl	8(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	element_add
	movl	16(%ebp), %eax
	movl	%eax, 8(%esp)
	leal	-28(%ebp), %eax
	movl	%eax, 4(%esp)
	leal	-28(%ebp), %eax
	movl	%eax, (%esp)
	call	element_mul
	addl	$1, -12(%ebp)
.L85:
	movl	12(%ebp), %eax
	movl	(%eax), %eax
	addl	$1, %eax
	cmpl	-12(%ebp), %eax
	jg	.L86
	leal	-20(%ebp), %eax
	movl	%eax, (%esp)
	call	element_clear
	leal	-28(%ebp), %eax
	movl	%eax, (%esp)
	call	element_clear
	leave
	ret
	.size	eval_poly, .-eval_poly
.globl fill_policy
	.type	fill_policy, @function
fill_policy:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$56, %esp
	movl	12(%ebp), %eax
	addl	$4, %eax
	movl	%eax, 4(%esp)
	leal	-20(%ebp), %eax
	movl	%eax, (%esp)
	call	element_init_Zr
	movl	12(%ebp), %eax
	addl	$4, %eax
	movl	%eax, 4(%esp)
	leal	-28(%ebp), %eax
	movl	%eax, (%esp)
	call	element_init_Zr
	movl	12(%ebp), %eax
	addl	$4, %eax
	movl	%eax, 4(%esp)
	leal	-36(%ebp), %eax
	movl	%eax, (%esp)
	call	element_init_G2
	movl	8(%ebp), %eax
	movl	(%eax), %eax
	leal	-1(%eax), %edx
	movl	16(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	%edx, (%esp)
	call	rand_poly
	movl	8(%ebp), %edx
	movl	%eax, 28(%edx)
	movl	8(%ebp), %eax
	movl	24(%eax), %eax
	movl	4(%eax), %eax
	testl	%eax, %eax
	jne	.L89
	movl	12(%ebp), %eax
	leal	4(%eax), %edx
	movl	8(%ebp), %eax
	addl	$8, %eax
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	element_init_G1
	movl	12(%ebp), %eax
	leal	4(%eax), %edx
	movl	8(%ebp), %eax
	addl	$16, %eax
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	element_init_G2
	movl	8(%ebp), %eax
	movl	4(%eax), %eax
	movl	%eax, 4(%esp)
	leal	-36(%ebp), %eax
	movl	%eax, (%esp)
	call	element_from_string
	movl	8(%ebp), %eax
	movl	28(%eax), %eax
	movl	4(%eax), %eax
	movl	12(%ebp), %edx
	leal	512(%edx), %ecx
	movl	8(%ebp), %edx
	addl	$8, %edx
	movl	%eax, 8(%esp)
	movl	%ecx, 4(%esp)
	movl	%edx, (%esp)
	call	element_pow_zn
	movl	8(%ebp), %eax
	movl	28(%eax), %eax
	movl	4(%eax), %eax
	movl	8(%ebp), %edx
	addl	$16, %edx
	movl	%eax, 8(%esp)
	leal	-36(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	%edx, (%esp)
	call	element_pow_zn
	jmp	.L90
.L89:
	movl	$0, -12(%ebp)
	jmp	.L91
.L92:
	movl	-12(%ebp), %eax
	addl	$1, %eax
	movl	%eax, 4(%esp)
	leal	-20(%ebp), %eax
	movl	%eax, (%esp)
	call	element_set_si
	movl	8(%ebp), %eax
	movl	28(%eax), %eax
	leal	-20(%ebp), %edx
	movl	%edx, 8(%esp)
	movl	%eax, 4(%esp)
	leal	-28(%ebp), %eax
	movl	%eax, (%esp)
	call	eval_poly
	movl	8(%ebp), %eax
	movl	24(%eax), %eax
	movl	(%eax), %eax
	movl	-12(%ebp), %edx
	sall	$2, %edx
	addl	%edx, %eax
	movl	(%eax), %eax
	leal	-28(%ebp), %edx
	movl	%edx, 8(%esp)
	movl	12(%ebp), %edx
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	fill_policy
	addl	$1, -12(%ebp)
.L91:
	movl	-12(%ebp), %edx
	movl	8(%ebp), %eax
	movl	24(%eax), %eax
	movl	4(%eax), %eax
	cmpl	%eax, %edx
	jb	.L92
.L90:
	leal	-20(%ebp), %eax
	movl	%eax, (%esp)
	call	element_clear
	leal	-28(%ebp), %eax
	movl	%eax, (%esp)
	call	element_clear
	leal	-36(%ebp), %eax
	movl	%eax, (%esp)
	call	element_clear
	leave
	ret
	.size	fill_policy, .-fill_policy
.globl bswabe_enc
	.type	bswabe_enc, @function
bswabe_enc:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$40, %esp
	movl	$20, (%esp)
	call	malloc
	movl	%eax, -12(%ebp)
	movl	8(%ebp), %eax
	addl	$4, %eax
	movl	%eax, 4(%esp)
	leal	-20(%ebp), %eax
	movl	%eax, (%esp)
	call	element_init_Zr
	movl	8(%ebp), %eax
	addl	$4, %eax
	movl	%eax, 4(%esp)
	movl	12(%ebp), %eax
	movl	%eax, (%esp)
	call	element_init_GT
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
	movl	16(%ebp), %eax
	movl	%eax, (%esp)
	call	parse_policy_postfix
	movl	-12(%ebp), %edx
	movl	%eax, 16(%edx)
	movl	12(%ebp), %eax
	movl	%eax, (%esp)
	call	element_random
	leal	-20(%ebp), %eax
	movl	%eax, (%esp)
	call	element_random
	movl	8(%ebp), %eax
	leal	536(%eax), %ecx
	movl	-12(%ebp), %eax
	leal	-20(%ebp), %edx
	movl	%edx, 8(%esp)
	movl	%ecx, 4(%esp)
	movl	%eax, (%esp)
	call	element_pow_zn
	movl	-12(%ebp), %edx
	movl	-12(%ebp), %eax
	movl	12(%ebp), %ecx
	movl	%ecx, 8(%esp)
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	element_mul
	movl	8(%ebp), %eax
	leal	520(%eax), %ecx
	movl	-12(%ebp), %eax
	leal	8(%eax), %edx
	leal	-20(%ebp), %eax
	movl	%eax, 8(%esp)
	movl	%ecx, 4(%esp)
	movl	%edx, (%esp)
	call	element_pow_zn
	movl	-12(%ebp), %eax
	movl	16(%eax), %eax
	leal	-20(%ebp), %edx
	movl	%edx, 8(%esp)
	movl	8(%ebp), %edx
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	fill_policy
	movl	-12(%ebp), %eax
	leave
	ret
	.size	bswabe_enc, .-bswabe_enc
.globl check_sat
	.type	check_sat, @function
check_sat:
	pushl	%ebp
	movl	%esp, %ebp
	pushl	%ebx
	subl	$36, %esp
	movl	8(%ebp), %eax
	movl	$0, 32(%eax)
	movl	8(%ebp), %eax
	movl	24(%eax), %eax
	movl	4(%eax), %eax
	testl	%eax, %eax
	jne	.L97
	movl	$0, -12(%ebp)
	jmp	.L98
.L101:
	movl	8(%ebp), %eax
	movl	4(%eax), %ecx
	movl	12(%ebp), %eax
	movl	8(%eax), %eax
	movl	(%eax), %eax
	movl	%eax, %ebx
	movl	-12(%ebp), %edx
	movl	%edx, %eax
	sall	$2, %eax
	addl	%edx, %eax
	sall	$3, %eax
	leal	(%ebx,%eax), %eax
	movl	(%eax), %eax
	movl	%ecx, 4(%esp)
	movl	%eax, (%esp)
	call	strcmp
	testl	%eax, %eax
	jne	.L99
	movl	8(%ebp), %eax
	movl	$1, 32(%eax)
	movl	8(%ebp), %eax
	movl	-12(%ebp), %edx
	movl	%edx, 40(%eax)
	nop
	jmp	.L108
.L99:
	addl	$1, -12(%ebp)
.L98:
	movl	-12(%ebp), %edx
	movl	12(%ebp), %eax
	movl	8(%eax), %eax
	movl	4(%eax), %eax
	cmpl	%eax, %edx
	jb	.L101
	jmp	.L108
.L97:
	movl	$0, -12(%ebp)
	jmp	.L103
.L104:
	movl	8(%ebp), %eax
	movl	24(%eax), %eax
	movl	(%eax), %eax
	movl	-12(%ebp), %edx
	sall	$2, %edx
	addl	%edx, %eax
	movl	(%eax), %eax
	movl	12(%ebp), %edx
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	check_sat
	addl	$1, -12(%ebp)
.L103:
	movl	-12(%ebp), %edx
	movl	8(%ebp), %eax
	movl	24(%eax), %eax
	movl	4(%eax), %eax
	cmpl	%eax, %edx
	jb	.L104
	movl	$0, -16(%ebp)
	movl	$0, -12(%ebp)
	jmp	.L105
.L107:
	movl	8(%ebp), %eax
	movl	24(%eax), %eax
	movl	(%eax), %eax
	movl	-12(%ebp), %edx
	sall	$2, %edx
	addl	%edx, %eax
	movl	(%eax), %eax
	movl	32(%eax), %eax
	testl	%eax, %eax
	je	.L106
	addl	$1, -16(%ebp)
.L106:
	addl	$1, -12(%ebp)
.L105:
	movl	-12(%ebp), %edx
	movl	8(%ebp), %eax
	movl	24(%eax), %eax
	movl	4(%eax), %eax
	cmpl	%eax, %edx
	jb	.L107
	movl	8(%ebp), %eax
	movl	(%eax), %eax
	cmpl	-16(%ebp), %eax
	jg	.L108
	movl	8(%ebp), %eax
	movl	$1, 32(%eax)
.L108:
	addl	$36, %esp
	popl	%ebx
	popl	%ebp
	ret
	.size	check_sat, .-check_sat
.globl pick_sat_naive
	.type	pick_sat_naive, @function
pick_sat_naive:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$40, %esp
	movl	8(%ebp), %eax
	movl	24(%eax), %eax
	movl	4(%eax), %eax
	testl	%eax, %eax
	je	.L116
.L110:
	movl	$4, 8(%esp)
	movl	$0, 4(%esp)
	movl	$0, (%esp)
	call	g_array_new
	movl	8(%ebp), %edx
	movl	%eax, 44(%edx)
	movl	$0, -20(%ebp)
	movl	$0, -12(%ebp)
	jmp	.L112
.L114:
	movl	8(%ebp), %eax
	movl	24(%eax), %eax
	movl	(%eax), %eax
	movl	-12(%ebp), %edx
	sall	$2, %edx
	addl	%edx, %eax
	movl	(%eax), %eax
	movl	32(%eax), %eax
	testl	%eax, %eax
	je	.L113
	movl	8(%ebp), %eax
	movl	24(%eax), %eax
	movl	(%eax), %eax
	movl	-12(%ebp), %edx
	sall	$2, %edx
	addl	%edx, %eax
	movl	(%eax), %eax
	movl	12(%ebp), %edx
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	pick_sat_naive
	addl	$1, -20(%ebp)
	movl	-12(%ebp), %eax
	addl	$1, %eax
	movl	%eax, -16(%ebp)
	movl	8(%ebp), %eax
	movl	44(%eax), %eax
	movl	$1, 8(%esp)
	leal	-16(%ebp), %edx
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	g_array_append_vals
.L113:
	addl	$1, -12(%ebp)
.L112:
	movl	-12(%ebp), %edx
	movl	8(%ebp), %eax
	movl	24(%eax), %eax
	movl	4(%eax), %eax
	cmpl	%eax, %edx
	jae	.L115
	movl	8(%ebp), %eax
	movl	(%eax), %eax
	cmpl	-20(%ebp), %eax
	jg	.L114
	jmp	.L115
.L116:
	nop
.L115:
	leave
	ret
	.size	pick_sat_naive, .-pick_sat_naive
	.comm	cur_comp_pol,4,4
.globl cmp_int
	.type	cmp_int, @function
cmp_int:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$16, %esp
	movl	cur_comp_pol, %eax
	movl	24(%eax), %eax
	movl	(%eax), %edx
	movl	8(%ebp), %eax
	movl	(%eax), %eax
	sall	$2, %eax
	leal	(%edx,%eax), %eax
	movl	(%eax), %eax
	movl	36(%eax), %eax
	movl	%eax, -4(%ebp)
	movl	cur_comp_pol, %eax
	movl	24(%eax), %eax
	movl	(%eax), %edx
	movl	12(%ebp), %eax
	movl	(%eax), %eax
	sall	$2, %eax
	leal	(%edx,%eax), %eax
	movl	(%eax), %eax
	movl	36(%eax), %eax
	movl	%eax, -8(%ebp)
	movl	-4(%ebp), %eax
	cmpl	-8(%ebp), %eax
	jl	.L118
	movl	-4(%ebp), %eax
	cmpl	-8(%ebp), %eax
	setne	%al
	movzbl	%al, %eax
	jmp	.L119
.L118:
	movl	$-1, %eax
.L119:
	leave
	ret
	.size	cmp_int, .-cmp_int
.globl pick_sat_min_leaves
	.type	pick_sat_min_leaves, @function
pick_sat_min_leaves:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$72, %esp
	movl	8(%ebp), %eax
	movl	%eax, -44(%ebp)
	movl	12(%ebp), %eax
	movl	%eax, -48(%ebp)
	movl	%gs:20, %eax
	movl	%eax, -12(%ebp)
	xorl	%eax, %eax
	movl	-44(%ebp), %eax
	movl	24(%eax), %eax
	movl	4(%eax), %eax
	testl	%eax, %eax
	jne	.L122
	movl	-44(%ebp), %eax
	movl	$1, 36(%eax)
	jmp	.L132
.L122:
	movl	$0, -16(%ebp)
	jmp	.L124
.L126:
	movl	-44(%ebp), %eax
	movl	24(%eax), %eax
	movl	(%eax), %eax
	movl	-16(%ebp), %edx
	sall	$2, %edx
	addl	%edx, %eax
	movl	(%eax), %eax
	movl	32(%eax), %eax
	testl	%eax, %eax
	je	.L125
	movl	-44(%ebp), %eax
	movl	24(%eax), %eax
	movl	(%eax), %eax
	movl	-16(%ebp), %edx
	sall	$2, %edx
	addl	%edx, %eax
	movl	(%eax), %eax
	movl	-48(%ebp), %edx
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	pick_sat_min_leaves
.L125:
	addl	$1, -16(%ebp)
.L124:
	movl	-16(%ebp), %edx
	movl	-44(%ebp), %eax
	movl	24(%eax), %eax
	movl	4(%eax), %eax
	cmpl	%eax, %edx
	jb	.L126
	movl	-44(%ebp), %eax
	movl	24(%eax), %eax
	movl	4(%eax), %eax
	sall	$2, %eax
	addl	$15, %eax
	addl	$15, %eax
	shrl	$4, %eax
	sall	$4, %eax
	subl	%eax, %esp
	leal	16(%esp), %eax
	addl	$15, %eax
	shrl	$4, %eax
	sall	$4, %eax
	movl	%eax, -28(%ebp)
	movl	$0, -16(%ebp)
	jmp	.L127
.L128:
	movl	-16(%ebp), %eax
	sall	$2, %eax
	addl	-28(%ebp), %eax
	movl	-16(%ebp), %edx
	movl	%edx, (%eax)
	addl	$1, -16(%ebp)
.L127:
	movl	-16(%ebp), %edx
	movl	-44(%ebp), %eax
	movl	24(%eax), %eax
	movl	4(%eax), %eax
	cmpl	%eax, %edx
	jb	.L128
	movl	-44(%ebp), %eax
	movl	%eax, cur_comp_pol
	movl	-44(%ebp), %eax
	movl	24(%eax), %eax
	movl	4(%eax), %eax
	movl	$cmp_int, 12(%esp)
	movl	$4, 8(%esp)
	movl	%eax, 4(%esp)
	movl	-28(%ebp), %eax
	movl	%eax, (%esp)
	call	qsort
	movl	$4, 8(%esp)
	movl	$0, 4(%esp)
	movl	$0, (%esp)
	call	g_array_new
	movl	-44(%ebp), %edx
	movl	%eax, 44(%edx)
	movl	-44(%ebp), %eax
	movl	$0, 36(%eax)
	movl	$0, -24(%ebp)
	movl	$0, -16(%ebp)
	jmp	.L129
.L131:
	movl	-44(%ebp), %eax
	movl	24(%eax), %eax
	movl	(%eax), %edx
	movl	-16(%ebp), %eax
	sall	$2, %eax
	addl	-28(%ebp), %eax
	movl	(%eax), %eax
	sall	$2, %eax
	leal	(%edx,%eax), %eax
	movl	(%eax), %eax
	movl	32(%eax), %eax
	testl	%eax, %eax
	je	.L130
	addl	$1, -24(%ebp)
	movl	-44(%ebp), %eax
	movl	36(%eax), %edx
	movl	-44(%ebp), %eax
	movl	24(%eax), %eax
	movl	(%eax), %ecx
	movl	-16(%ebp), %eax
	sall	$2, %eax
	addl	-28(%ebp), %eax
	movl	(%eax), %eax
	sall	$2, %eax
	leal	(%ecx,%eax), %eax
	movl	(%eax), %eax
	movl	36(%eax), %eax
	addl	%eax, %edx
	movl	-44(%ebp), %eax
	movl	%edx, 36(%eax)
	movl	-16(%ebp), %eax
	sall	$2, %eax
	addl	-28(%ebp), %eax
	movl	(%eax), %eax
	addl	$1, %eax
	movl	%eax, -20(%ebp)
	movl	-44(%ebp), %eax
	movl	44(%eax), %eax
	movl	$1, 8(%esp)
	leal	-20(%ebp), %edx
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	g_array_append_vals
.L130:
	addl	$1, -16(%ebp)
.L129:
	movl	-16(%ebp), %edx
	movl	-44(%ebp), %eax
	movl	24(%eax), %eax
	movl	4(%eax), %eax
	cmpl	%eax, %edx
	jae	.L132
	movl	-44(%ebp), %eax
	movl	(%eax), %eax
	cmpl	-24(%ebp), %eax
	jg	.L131
.L132:
	movl	-12(%ebp), %eax
	xorl	%gs:20, %eax
	je	.L133
	call	__stack_chk_fail
.L133:
	leave
	ret
	.size	pick_sat_min_leaves, .-pick_sat_min_leaves
.globl lagrange_coef
	.type	lagrange_coef, @function
lagrange_coef:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$40, %esp
	movl	8(%ebp), %eax
	movl	%eax, 4(%esp)
	leal	-24(%ebp), %eax
	movl	%eax, (%esp)
	call	element_init_same_as
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	element_set1
	movl	$0, -16(%ebp)
	jmp	.L135
.L138:
	movl	12(%ebp), %eax
	movl	(%eax), %eax
	movl	-16(%ebp), %edx
	sall	$2, %edx
	addl	%edx, %eax
	movl	(%eax), %eax
	movl	%eax, -12(%ebp)
	movl	-12(%ebp), %eax
	cmpl	16(%ebp), %eax
	je	.L140
.L136:
	movl	-12(%ebp), %eax
	negl	%eax
	movl	%eax, 4(%esp)
	leal	-24(%ebp), %eax
	movl	%eax, (%esp)
	call	element_set_si
	leal	-24(%ebp), %eax
	movl	%eax, 8(%esp)
	movl	8(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	element_mul
	movl	-12(%ebp), %eax
	movl	16(%ebp), %edx
	movl	%edx, %ecx
	subl	%eax, %ecx
	movl	%ecx, %eax
	movl	%eax, 4(%esp)
	leal	-24(%ebp), %eax
	movl	%eax, (%esp)
	call	element_set_si
	leal	-24(%ebp), %eax
	movl	%eax, 4(%esp)
	leal	-24(%ebp), %eax
	movl	%eax, (%esp)
	call	element_invert
	leal	-24(%ebp), %eax
	movl	%eax, 8(%esp)
	movl	8(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	element_mul
	jmp	.L137
.L140:
	nop
.L137:
	addl	$1, -16(%ebp)
.L135:
	movl	-16(%ebp), %edx
	movl	12(%ebp), %eax
	movl	4(%eax), %eax
	cmpl	%eax, %edx
	jb	.L138
	leal	-24(%ebp), %eax
	movl	%eax, (%esp)
	call	element_clear
	leave
	ret
	.size	lagrange_coef, .-lagrange_coef
.globl dec_leaf_naive
	.type	dec_leaf_naive, @function
dec_leaf_naive:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$40, %esp
	movl	16(%ebp), %eax
	movl	8(%eax), %eax
	movl	(%eax), %eax
	movl	%eax, %ecx
	movl	12(%ebp), %eax
	movl	40(%eax), %eax
	movl	%eax, %edx
	movl	%edx, %eax
	sall	$2, %eax
	addl	%edx, %eax
	sall	$3, %eax
	leal	(%ecx,%eax), %eax
	movl	%eax, -12(%ebp)
	movl	20(%ebp), %eax
	addl	$4, %eax
	movl	%eax, 4(%esp)
	leal	-20(%ebp), %eax
	movl	%eax, (%esp)
	call	element_init_GT
	movl	20(%ebp), %eax
	leal	4(%eax), %ecx
	movl	-12(%ebp), %eax
	leal	4(%eax), %edx
	movl	12(%ebp), %eax
	addl	$8, %eax
	movl	%ecx, 12(%esp)
	movl	%edx, 8(%esp)
	movl	%eax, 4(%esp)
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	pairing_apply
	movl	20(%ebp), %eax
	leal	4(%eax), %ecx
	movl	-12(%ebp), %eax
	leal	12(%eax), %edx
	movl	12(%ebp), %eax
	addl	$16, %eax
	movl	%ecx, 12(%esp)
	movl	%edx, 8(%esp)
	movl	%eax, 4(%esp)
	leal	-20(%ebp), %eax
	movl	%eax, (%esp)
	call	pairing_apply
	leal	-20(%ebp), %eax
	movl	%eax, 4(%esp)
	leal	-20(%ebp), %eax
	movl	%eax, (%esp)
	call	element_invert
	leal	-20(%ebp), %eax
	movl	%eax, 8(%esp)
	movl	8(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	element_mul
	leal	-20(%ebp), %eax
	movl	%eax, (%esp)
	call	element_clear
	leave
	ret
	.size	dec_leaf_naive, .-dec_leaf_naive
.globl dec_internal_naive
	.type	dec_internal_naive, @function
dec_internal_naive:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$56, %esp
	movl	20(%ebp), %eax
	addl	$4, %eax
	movl	%eax, 4(%esp)
	leal	-20(%ebp), %eax
	movl	%eax, (%esp)
	call	element_init_GT
	movl	20(%ebp), %eax
	addl	$4, %eax
	movl	%eax, 4(%esp)
	leal	-28(%ebp), %eax
	movl	%eax, (%esp)
	call	element_init_Zr
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	element_set1
	movl	$0, -12(%ebp)
	jmp	.L144
.L145:
	movl	12(%ebp), %eax
	movl	24(%eax), %eax
	movl	(%eax), %edx
	movl	12(%ebp), %eax
	movl	44(%eax), %eax
	movl	(%eax), %eax
	movl	-12(%ebp), %ecx
	sall	$2, %ecx
	addl	%ecx, %eax
	movl	(%eax), %eax
	subl	$1, %eax
	sall	$2, %eax
	leal	(%edx,%eax), %eax
	movl	(%eax), %eax
	movl	20(%ebp), %edx
	movl	%edx, 12(%esp)
	movl	16(%ebp), %edx
	movl	%edx, 8(%esp)
	movl	%eax, 4(%esp)
	leal	-20(%ebp), %eax
	movl	%eax, (%esp)
	call	dec_node_naive
	movl	12(%ebp), %eax
	movl	44(%eax), %eax
	movl	(%eax), %eax
	movl	-12(%ebp), %edx
	sall	$2, %edx
	addl	%edx, %eax
	movl	(%eax), %edx
	movl	12(%ebp), %eax
	movl	44(%eax), %eax
	movl	%edx, 8(%esp)
	movl	%eax, 4(%esp)
	leal	-28(%ebp), %eax
	movl	%eax, (%esp)
	call	lagrange_coef
	leal	-28(%ebp), %eax
	movl	%eax, 8(%esp)
	leal	-20(%ebp), %eax
	movl	%eax, 4(%esp)
	leal	-20(%ebp), %eax
	movl	%eax, (%esp)
	call	element_pow_zn
	leal	-20(%ebp), %eax
	movl	%eax, 8(%esp)
	movl	8(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	element_mul
	addl	$1, -12(%ebp)
.L144:
	movl	-12(%ebp), %edx
	movl	12(%ebp), %eax
	movl	44(%eax), %eax
	movl	4(%eax), %eax
	cmpl	%eax, %edx
	jb	.L145
	leal	-20(%ebp), %eax
	movl	%eax, (%esp)
	call	element_clear
	leal	-28(%ebp), %eax
	movl	%eax, (%esp)
	call	element_clear
	leave
	ret
	.size	dec_internal_naive, .-dec_internal_naive
.globl dec_node_naive
	.type	dec_node_naive, @function
dec_node_naive:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$24, %esp
	movl	12(%ebp), %eax
	movl	24(%eax), %eax
	movl	4(%eax), %eax
	testl	%eax, %eax
	jne	.L148
	movl	20(%ebp), %eax
	movl	%eax, 12(%esp)
	movl	16(%ebp), %eax
	movl	%eax, 8(%esp)
	movl	12(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	dec_leaf_naive
	jmp	.L150
.L148:
	movl	20(%ebp), %eax
	movl	%eax, 12(%esp)
	movl	16(%ebp), %eax
	movl	%eax, 8(%esp)
	movl	12(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	dec_internal_naive
.L150:
	leave
	ret
	.size	dec_node_naive, .-dec_node_naive
.globl dec_naive
	.type	dec_naive, @function
dec_naive:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$24, %esp
	movl	20(%ebp), %eax
	movl	%eax, 12(%esp)
	movl	16(%ebp), %eax
	movl	%eax, 8(%esp)
	movl	12(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	dec_node_naive
	leave
	ret
	.size	dec_naive, .-dec_naive
.globl dec_leaf_merge
	.type	dec_leaf_merge, @function
dec_leaf_merge:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$40, %esp
	movl	16(%ebp), %eax
	movl	8(%eax), %eax
	movl	(%eax), %eax
	movl	%eax, %ecx
	movl	12(%ebp), %eax
	movl	40(%eax), %eax
	movl	%eax, %edx
	movl	%edx, %eax
	sall	$2, %eax
	addl	%edx, %eax
	sall	$3, %eax
	leal	(%ecx,%eax), %eax
	movl	%eax, -12(%ebp)
	movl	-12(%ebp), %eax
	movl	20(%eax), %eax
	testl	%eax, %eax
	jne	.L154
	movl	-12(%ebp), %eax
	movl	$1, 20(%eax)
	movl	20(%ebp), %eax
	leal	4(%eax), %edx
	movl	-12(%ebp), %eax
	addl	$24, %eax
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	element_init_G1
	movl	20(%ebp), %eax
	leal	4(%eax), %edx
	movl	-12(%ebp), %eax
	addl	$32, %eax
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	element_init_G1
	movl	-12(%ebp), %eax
	addl	$24, %eax
	movl	%eax, (%esp)
	call	element_set1
	movl	-12(%ebp), %eax
	addl	$32, %eax
	movl	%eax, (%esp)
	call	element_set1
.L154:
	movl	20(%ebp), %eax
	addl	$4, %eax
	movl	%eax, 4(%esp)
	leal	-20(%ebp), %eax
	movl	%eax, (%esp)
	call	element_init_G1
	movl	12(%ebp), %eax
	leal	8(%eax), %edx
	movl	8(%ebp), %eax
	movl	%eax, 8(%esp)
	movl	%edx, 4(%esp)
	leal	-20(%ebp), %eax
	movl	%eax, (%esp)
	call	element_pow_zn
	movl	-12(%ebp), %eax
	leal	24(%eax), %ecx
	movl	-12(%ebp), %eax
	leal	24(%eax), %edx
	leal	-20(%ebp), %eax
	movl	%eax, 8(%esp)
	movl	%ecx, 4(%esp)
	movl	%edx, (%esp)
	call	element_mul
	movl	12(%ebp), %eax
	leal	16(%eax), %edx
	movl	8(%ebp), %eax
	movl	%eax, 8(%esp)
	movl	%edx, 4(%esp)
	leal	-20(%ebp), %eax
	movl	%eax, (%esp)
	call	element_pow_zn
	movl	-12(%ebp), %eax
	leal	32(%eax), %ecx
	movl	-12(%ebp), %eax
	leal	32(%eax), %edx
	leal	-20(%ebp), %eax
	movl	%eax, 8(%esp)
	movl	%ecx, 4(%esp)
	movl	%edx, (%esp)
	call	element_mul
	leal	-20(%ebp), %eax
	movl	%eax, (%esp)
	call	element_clear
	leave
	ret
	.size	dec_leaf_merge, .-dec_leaf_merge
.globl dec_internal_merge
	.type	dec_internal_merge, @function
dec_internal_merge:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$56, %esp
	movl	20(%ebp), %eax
	addl	$4, %eax
	movl	%eax, 4(%esp)
	leal	-20(%ebp), %eax
	movl	%eax, (%esp)
	call	element_init_Zr
	movl	20(%ebp), %eax
	addl	$4, %eax
	movl	%eax, 4(%esp)
	leal	-28(%ebp), %eax
	movl	%eax, (%esp)
	call	element_init_Zr
	movl	$0, -12(%ebp)
	jmp	.L157
.L158:
	movl	12(%ebp), %eax
	movl	44(%eax), %eax
	movl	(%eax), %eax
	movl	-12(%ebp), %edx
	sall	$2, %edx
	addl	%edx, %eax
	movl	(%eax), %edx
	movl	12(%ebp), %eax
	movl	44(%eax), %eax
	movl	%edx, 8(%esp)
	movl	%eax, 4(%esp)
	leal	-20(%ebp), %eax
	movl	%eax, (%esp)
	call	lagrange_coef
	leal	-20(%ebp), %eax
	movl	%eax, 8(%esp)
	movl	8(%ebp), %eax
	movl	%eax, 4(%esp)
	leal	-28(%ebp), %eax
	movl	%eax, (%esp)
	call	element_mul
	movl	12(%ebp), %eax
	movl	24(%eax), %eax
	movl	(%eax), %edx
	movl	12(%ebp), %eax
	movl	44(%eax), %eax
	movl	(%eax), %eax
	movl	-12(%ebp), %ecx
	sall	$2, %ecx
	addl	%ecx, %eax
	movl	(%eax), %eax
	subl	$1, %eax
	sall	$2, %eax
	leal	(%edx,%eax), %eax
	movl	(%eax), %eax
	movl	20(%ebp), %edx
	movl	%edx, 12(%esp)
	movl	16(%ebp), %edx
	movl	%edx, 8(%esp)
	movl	%eax, 4(%esp)
	leal	-28(%ebp), %eax
	movl	%eax, (%esp)
	call	dec_node_merge
	addl	$1, -12(%ebp)
.L157:
	movl	-12(%ebp), %edx
	movl	12(%ebp), %eax
	movl	44(%eax), %eax
	movl	4(%eax), %eax
	cmpl	%eax, %edx
	jb	.L158
	leal	-20(%ebp), %eax
	movl	%eax, (%esp)
	call	element_clear
	leal	-28(%ebp), %eax
	movl	%eax, (%esp)
	call	element_clear
	leave
	ret
	.size	dec_internal_merge, .-dec_internal_merge
.globl dec_node_merge
	.type	dec_node_merge, @function
dec_node_merge:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$24, %esp
	movl	12(%ebp), %eax
	movl	24(%eax), %eax
	movl	4(%eax), %eax
	testl	%eax, %eax
	jne	.L161
	movl	20(%ebp), %eax
	movl	%eax, 12(%esp)
	movl	16(%ebp), %eax
	movl	%eax, 8(%esp)
	movl	12(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	dec_leaf_merge
	jmp	.L163
.L161:
	movl	20(%ebp), %eax
	movl	%eax, 12(%esp)
	movl	16(%ebp), %eax
	movl	%eax, 8(%esp)
	movl	12(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	dec_internal_merge
.L163:
	leave
	ret
	.size	dec_node_merge, .-dec_node_merge
.globl dec_merge
	.type	dec_merge, @function
dec_merge:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$56, %esp
	movl	$0, -12(%ebp)
	jmp	.L165
.L166:
	movl	16(%ebp), %eax
	movl	8(%eax), %eax
	movl	(%eax), %eax
	movl	%eax, %ecx
	movl	-12(%ebp), %edx
	movl	%edx, %eax
	sall	$2, %eax
	addl	%edx, %eax
	sall	$3, %eax
	leal	(%ecx,%eax), %eax
	movl	$0, 20(%eax)
	addl	$1, -12(%ebp)
.L165:
	movl	-12(%ebp), %edx
	movl	16(%ebp), %eax
	movl	8(%eax), %eax
	movl	4(%eax), %eax
	cmpl	%eax, %edx
	jb	.L166
	movl	20(%ebp), %eax
	addl	$4, %eax
	movl	%eax, 4(%esp)
	leal	-24(%ebp), %eax
	movl	%eax, (%esp)
	call	element_init_Zr
	leal	-24(%ebp), %eax
	movl	%eax, (%esp)
	call	element_set1
	movl	20(%ebp), %eax
	movl	%eax, 12(%esp)
	movl	16(%ebp), %eax
	movl	%eax, 8(%esp)
	movl	12(%ebp), %eax
	movl	%eax, 4(%esp)
	leal	-24(%ebp), %eax
	movl	%eax, (%esp)
	call	dec_node_merge
	leal	-24(%ebp), %eax
	movl	%eax, (%esp)
	call	element_clear
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	element_set1
	movl	20(%ebp), %eax
	addl	$4, %eax
	movl	%eax, 4(%esp)
	leal	-32(%ebp), %eax
	movl	%eax, (%esp)
	call	element_init_GT
	movl	$0, -12(%ebp)
	jmp	.L167
.L169:
	movl	16(%ebp), %eax
	movl	8(%eax), %eax
	movl	(%eax), %eax
	movl	%eax, %ecx
	movl	-12(%ebp), %edx
	movl	%edx, %eax
	sall	$2, %eax
	addl	%edx, %eax
	sall	$3, %eax
	leal	(%ecx,%eax), %eax
	movl	20(%eax), %eax
	testl	%eax, %eax
	je	.L168
	movl	16(%ebp), %eax
	movl	8(%eax), %eax
	movl	(%eax), %eax
	movl	%eax, %ecx
	movl	-12(%ebp), %edx
	movl	%edx, %eax
	sall	$2, %eax
	addl	%edx, %eax
	sall	$3, %eax
	leal	(%ecx,%eax), %eax
	movl	%eax, -16(%ebp)
	movl	20(%ebp), %eax
	leal	4(%eax), %ecx
	movl	-16(%ebp), %eax
	leal	4(%eax), %edx
	movl	-16(%ebp), %eax
	addl	$24, %eax
	movl	%ecx, 12(%esp)
	movl	%edx, 8(%esp)
	movl	%eax, 4(%esp)
	leal	-32(%ebp), %eax
	movl	%eax, (%esp)
	call	pairing_apply
	leal	-32(%ebp), %eax
	movl	%eax, 8(%esp)
	movl	8(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	element_mul
	movl	20(%ebp), %eax
	leal	4(%eax), %ecx
	movl	-16(%ebp), %eax
	leal	12(%eax), %edx
	movl	-16(%ebp), %eax
	addl	$32, %eax
	movl	%ecx, 12(%esp)
	movl	%edx, 8(%esp)
	movl	%eax, 4(%esp)
	leal	-32(%ebp), %eax
	movl	%eax, (%esp)
	call	pairing_apply
	leal	-32(%ebp), %eax
	movl	%eax, 4(%esp)
	leal	-32(%ebp), %eax
	movl	%eax, (%esp)
	call	element_invert
	leal	-32(%ebp), %eax
	movl	%eax, 8(%esp)
	movl	8(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	element_mul
.L168:
	addl	$1, -12(%ebp)
.L167:
	movl	-12(%ebp), %edx
	movl	16(%ebp), %eax
	movl	8(%eax), %eax
	movl	4(%eax), %eax
	cmpl	%eax, %edx
	jb	.L169
	leal	-32(%ebp), %eax
	movl	%eax, (%esp)
	call	element_clear
	leave
	ret
	.size	dec_merge, .-dec_merge
.globl dec_leaf_flatten
	.type	dec_leaf_flatten, @function
dec_leaf_flatten:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$56, %esp
	movl	20(%ebp), %eax
	movl	8(%eax), %eax
	movl	(%eax), %eax
	movl	%eax, %ecx
	movl	16(%ebp), %eax
	movl	40(%eax), %eax
	movl	%eax, %edx
	movl	%edx, %eax
	sall	$2, %eax
	addl	%edx, %eax
	sall	$3, %eax
	leal	(%ecx,%eax), %eax
	movl	%eax, -12(%ebp)
	movl	24(%ebp), %eax
	addl	$4, %eax
	movl	%eax, 4(%esp)
	leal	-20(%ebp), %eax
	movl	%eax, (%esp)
	call	element_init_GT
	movl	24(%ebp), %eax
	addl	$4, %eax
	movl	%eax, 4(%esp)
	leal	-28(%ebp), %eax
	movl	%eax, (%esp)
	call	element_init_GT
	movl	24(%ebp), %eax
	leal	4(%eax), %ecx
	movl	-12(%ebp), %eax
	leal	4(%eax), %edx
	movl	16(%ebp), %eax
	addl	$8, %eax
	movl	%ecx, 12(%esp)
	movl	%edx, 8(%esp)
	movl	%eax, 4(%esp)
	leal	-20(%ebp), %eax
	movl	%eax, (%esp)
	call	pairing_apply
	movl	24(%ebp), %eax
	leal	4(%eax), %ecx
	movl	-12(%ebp), %eax
	leal	12(%eax), %edx
	movl	16(%ebp), %eax
	addl	$16, %eax
	movl	%ecx, 12(%esp)
	movl	%edx, 8(%esp)
	movl	%eax, 4(%esp)
	leal	-28(%ebp), %eax
	movl	%eax, (%esp)
	call	pairing_apply
	leal	-28(%ebp), %eax
	movl	%eax, 4(%esp)
	leal	-28(%ebp), %eax
	movl	%eax, (%esp)
	call	element_invert
	leal	-28(%ebp), %eax
	movl	%eax, 8(%esp)
	leal	-20(%ebp), %eax
	movl	%eax, 4(%esp)
	leal	-20(%ebp), %eax
	movl	%eax, (%esp)
	call	element_mul
	movl	12(%ebp), %eax
	movl	%eax, 8(%esp)
	leal	-20(%ebp), %eax
	movl	%eax, 4(%esp)
	leal	-20(%ebp), %eax
	movl	%eax, (%esp)
	call	element_pow_zn
	leal	-20(%ebp), %eax
	movl	%eax, 8(%esp)
	movl	8(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	element_mul
	leal	-20(%ebp), %eax
	movl	%eax, (%esp)
	call	element_clear
	leal	-28(%ebp), %eax
	movl	%eax, (%esp)
	call	element_clear
	leave
	ret
	.size	dec_leaf_flatten, .-dec_leaf_flatten
.globl dec_internal_flatten
	.type	dec_internal_flatten, @function
dec_internal_flatten:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$72, %esp
	movl	24(%ebp), %eax
	addl	$4, %eax
	movl	%eax, 4(%esp)
	leal	-20(%ebp), %eax
	movl	%eax, (%esp)
	call	element_init_Zr
	movl	24(%ebp), %eax
	addl	$4, %eax
	movl	%eax, 4(%esp)
	leal	-28(%ebp), %eax
	movl	%eax, (%esp)
	call	element_init_Zr
	movl	$0, -12(%ebp)
	jmp	.L174
.L175:
	movl	16(%ebp), %eax
	movl	44(%eax), %eax
	movl	(%eax), %eax
	movl	-12(%ebp), %edx
	sall	$2, %edx
	addl	%edx, %eax
	movl	(%eax), %edx
	movl	16(%ebp), %eax
	movl	44(%eax), %eax
	movl	%edx, 8(%esp)
	movl	%eax, 4(%esp)
	leal	-20(%ebp), %eax
	movl	%eax, (%esp)
	call	lagrange_coef
	leal	-20(%ebp), %eax
	movl	%eax, 8(%esp)
	movl	12(%ebp), %eax
	movl	%eax, 4(%esp)
	leal	-28(%ebp), %eax
	movl	%eax, (%esp)
	call	element_mul
	movl	16(%ebp), %eax
	movl	24(%eax), %eax
	movl	(%eax), %edx
	movl	16(%ebp), %eax
	movl	44(%eax), %eax
	movl	(%eax), %eax
	movl	-12(%ebp), %ecx
	sall	$2, %ecx
	addl	%ecx, %eax
	movl	(%eax), %eax
	subl	$1, %eax
	sall	$2, %eax
	leal	(%edx,%eax), %eax
	movl	(%eax), %eax
	movl	24(%ebp), %edx
	movl	%edx, 16(%esp)
	movl	20(%ebp), %edx
	movl	%edx, 12(%esp)
	movl	%eax, 8(%esp)
	leal	-28(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	dec_node_flatten
	addl	$1, -12(%ebp)
.L174:
	movl	-12(%ebp), %edx
	movl	16(%ebp), %eax
	movl	44(%eax), %eax
	movl	4(%eax), %eax
	cmpl	%eax, %edx
	jb	.L175
	leal	-20(%ebp), %eax
	movl	%eax, (%esp)
	call	element_clear
	leal	-28(%ebp), %eax
	movl	%eax, (%esp)
	call	element_clear
	leave
	ret
	.size	dec_internal_flatten, .-dec_internal_flatten
.globl dec_node_flatten
	.type	dec_node_flatten, @function
dec_node_flatten:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$40, %esp
	movl	16(%ebp), %eax
	movl	24(%eax), %eax
	movl	4(%eax), %eax
	testl	%eax, %eax
	jne	.L178
	movl	24(%ebp), %eax
	movl	%eax, 16(%esp)
	movl	20(%ebp), %eax
	movl	%eax, 12(%esp)
	movl	16(%ebp), %eax
	movl	%eax, 8(%esp)
	movl	12(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	dec_leaf_flatten
	jmp	.L180
.L178:
	movl	24(%ebp), %eax
	movl	%eax, 16(%esp)
	movl	20(%ebp), %eax
	movl	%eax, 12(%esp)
	movl	16(%ebp), %eax
	movl	%eax, 8(%esp)
	movl	12(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	dec_internal_flatten
.L180:
	leave
	ret
	.size	dec_node_flatten, .-dec_node_flatten
.globl dec_flatten
	.type	dec_flatten, @function
dec_flatten:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$56, %esp
	movl	20(%ebp), %eax
	addl	$4, %eax
	movl	%eax, 4(%esp)
	leal	-16(%ebp), %eax
	movl	%eax, (%esp)
	call	element_init_Zr
	leal	-16(%ebp), %eax
	movl	%eax, (%esp)
	call	element_set1
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	element_set1
	movl	20(%ebp), %eax
	movl	%eax, 16(%esp)
	movl	16(%ebp), %eax
	movl	%eax, 12(%esp)
	movl	12(%ebp), %eax
	movl	%eax, 8(%esp)
	leal	-16(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	dec_node_flatten
	leal	-16(%ebp), %eax
	movl	%eax, (%esp)
	call	element_clear
	leave
	ret
	.size	dec_flatten, .-dec_flatten
	.section	.rodata
	.align 4
.LC9:
	.string	"cannot decrypt, attributes in key do not satisfy policy\n"
	.text
.globl bswabe_dec
	.type	bswabe_dec, @function
bswabe_dec:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$40, %esp
	movl	8(%ebp), %eax
	addl	$4, %eax
	movl	%eax, 4(%esp)
	movl	20(%ebp), %eax
	movl	%eax, (%esp)
	call	element_init_GT
	movl	8(%ebp), %eax
	addl	$4, %eax
	movl	%eax, 4(%esp)
	leal	-16(%ebp), %eax
	movl	%eax, (%esp)
	call	element_init_GT
	movl	16(%ebp), %eax
	movl	16(%eax), %eax
	movl	12(%ebp), %edx
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	check_sat
	movl	16(%ebp), %eax
	movl	16(%eax), %eax
	movl	32(%eax), %eax
	testl	%eax, %eax
	jne	.L184
	movl	$.LC9, (%esp)
	call	raise_error
	movl	$0, %eax
	jmp	.L185
.L184:
	movl	16(%ebp), %eax
	movl	16(%eax), %eax
	movl	12(%ebp), %edx
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	pick_sat_min_leaves
	movl	16(%ebp), %eax
	movl	16(%eax), %eax
	movl	8(%ebp), %edx
	movl	%edx, 12(%esp)
	movl	12(%ebp), %edx
	movl	%edx, 8(%esp)
	movl	%eax, 4(%esp)
	leal	-16(%ebp), %eax
	movl	%eax, (%esp)
	call	dec_flatten
	movl	16(%ebp), %eax
	leal	-16(%ebp), %edx
	movl	%edx, 8(%esp)
	movl	%eax, 4(%esp)
	movl	20(%ebp), %eax
	movl	%eax, (%esp)
	call	element_mul
	movl	8(%ebp), %eax
	leal	4(%eax), %ecx
	movl	12(%ebp), %eax
	movl	16(%ebp), %edx
	addl	$8, %edx
	movl	%ecx, 12(%esp)
	movl	%eax, 8(%esp)
	movl	%edx, 4(%esp)
	leal	-16(%ebp), %eax
	movl	%eax, (%esp)
	call	pairing_apply
	leal	-16(%ebp), %eax
	movl	%eax, 4(%esp)
	leal	-16(%ebp), %eax
	movl	%eax, (%esp)
	call	element_invert
	leal	-16(%ebp), %eax
	movl	%eax, 8(%esp)
	movl	20(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	20(%ebp), %eax
	movl	%eax, (%esp)
	call	element_mul
	movl	$1, %eax
.L185:
	leave
	ret
	.size	bswabe_dec, .-bswabe_dec
	.ident	"GCC: (Ubuntu 4.4.3-4ubuntu5) 4.4.3"
	.section	.note.GNU-stack,"",@progbits
