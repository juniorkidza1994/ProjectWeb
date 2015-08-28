	.file	"setup.c"
.globl usage
	.section	.rodata
	.align 4
.LC0:
	.ascii	"Usage: cpabe-setup [OPTION ...]\n\nGenerate system parameter"
	.ascii	"s, a public key, and a master secret key\nfor use with cpabe"
	.ascii	"-keygen, cpabe-enc, and cpabe-dec.\n\nOutput will be written"
	.ascii	" to the files \"pub_key\" and \"master_key\"\nunless the --o"
	.ascii	"utput-public-key or --output-master-key options are\nused.\n"
	.ascii	"\nMandatory arguments to long options are mandatory for shor"
	.ascii	"t options too.\n\n -h, --help                    print this "
	.ascii	"message\n\n -v, --version                 print versi"
	.string	"on information\n\n -p, --output-public-key FILE  write public key to FILE\n\n -m, --output-master-key FILE  write master secret key to FILE\n\n -d, --deterministic           use deterministic \"random\" numbers\n                               (only for debugging)\n\n"
	.data
	.align 4
	.type	usage, @object
	.size	usage, 4
usage:
	.long	.LC0
.globl pub_file
	.section	.rodata
.LC1:
	.string	"pub_key"
	.data
	.align 4
	.type	pub_file, @object
	.size	pub_file, 4
pub_file:
	.long	.LC1
.globl msk_file
	.section	.rodata
.LC2:
	.string	"master_key"
	.data
	.align 4
	.type	msk_file, @object
	.size	msk_file, 4
msk_file:
	.long	.LC2
	.section	.rodata
.LC3:
	.string	"-h"
.LC4:
	.string	"--help"
.LC5:
	.string	"%s"
.LC6:
	.string	"-v"
.LC7:
	.string	"--version"
.LC8:
	.string	"-p"
.LC9:
	.string	"--output-public-key"
.LC10:
	.string	"-m"
.LC11:
	.string	"--output-master-key"
.LC12:
	.string	"-d"
.LC13:
	.string	"--deterministic"
	.text
.globl parse_args
	.type	parse_args, @function
parse_args:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$40, %esp
	movl	$1, -12(%ebp)
	jmp	.L2
.L18:
	movl	-12(%ebp), %eax
	sall	$2, %eax
	addl	12(%ebp), %eax
	movl	(%eax), %eax
	movl	$.LC3, 4(%esp)
	movl	%eax, (%esp)
	call	strcmp
	testl	%eax, %eax
	je	.L3
	movl	-12(%ebp), %eax
	sall	$2, %eax
	addl	12(%ebp), %eax
	movl	(%eax), %eax
	movl	$.LC4, 4(%esp)
	movl	%eax, (%esp)
	call	strcmp
	testl	%eax, %eax
	jne	.L4
.L3:
	movl	usage, %edx
	movl	$.LC5, %eax
	movl	%edx, 4(%esp)
	movl	%eax, (%esp)
	call	printf
	movl	$0, (%esp)
	call	exit
.L4:
	movl	-12(%ebp), %eax
	sall	$2, %eax
	addl	12(%ebp), %eax
	movl	(%eax), %eax
	movl	$.LC6, 4(%esp)
	movl	%eax, (%esp)
	call	strcmp
	testl	%eax, %eax
	je	.L5
	movl	-12(%ebp), %eax
	sall	$2, %eax
	addl	12(%ebp), %eax
	movl	(%eax), %eax
	movl	$.LC7, 4(%esp)
	movl	%eax, (%esp)
	call	strcmp
	testl	%eax, %eax
	jne	.L6
.L5:
	movl	$0, (%esp)
	call	exit
.L6:
	movl	-12(%ebp), %eax
	sall	$2, %eax
	addl	12(%ebp), %eax
	movl	(%eax), %eax
	movl	$.LC8, 4(%esp)
	movl	%eax, (%esp)
	call	strcmp
	testl	%eax, %eax
	je	.L7
	movl	-12(%ebp), %eax
	sall	$2, %eax
	addl	12(%ebp), %eax
	movl	(%eax), %eax
	movl	$.LC9, 4(%esp)
	movl	%eax, (%esp)
	call	strcmp
	testl	%eax, %eax
	jne	.L8
.L7:
	addl	$1, -12(%ebp)
	movl	-12(%ebp), %eax
	cmpl	8(%ebp), %eax
	jl	.L9
	movl	usage, %eax
	movl	%eax, (%esp)
	call	die
	jmp	.L11
.L9:
	movl	-12(%ebp), %eax
	sall	$2, %eax
	addl	12(%ebp), %eax
	movl	(%eax), %eax
	movl	%eax, pub_file
	jmp	.L11
.L8:
	movl	-12(%ebp), %eax
	sall	$2, %eax
	addl	12(%ebp), %eax
	movl	(%eax), %eax
	movl	$.LC10, 4(%esp)
	movl	%eax, (%esp)
	call	strcmp
	testl	%eax, %eax
	je	.L12
	movl	-12(%ebp), %eax
	sall	$2, %eax
	addl	12(%ebp), %eax
	movl	(%eax), %eax
	movl	$.LC11, 4(%esp)
	movl	%eax, (%esp)
	call	strcmp
	testl	%eax, %eax
	jne	.L13
.L12:
	addl	$1, -12(%ebp)
	movl	-12(%ebp), %eax
	cmpl	8(%ebp), %eax
	jl	.L14
	movl	usage, %eax
	movl	%eax, (%esp)
	call	die
	jmp	.L11
.L14:
	movl	-12(%ebp), %eax
	sall	$2, %eax
	addl	12(%ebp), %eax
	movl	(%eax), %eax
	movl	%eax, msk_file
	jmp	.L11
.L13:
	movl	-12(%ebp), %eax
	sall	$2, %eax
	addl	12(%ebp), %eax
	movl	(%eax), %eax
	movl	$.LC12, 4(%esp)
	movl	%eax, (%esp)
	call	strcmp
	testl	%eax, %eax
	je	.L16
	movl	-12(%ebp), %eax
	sall	$2, %eax
	addl	12(%ebp), %eax
	movl	(%eax), %eax
	movl	$.LC13, 4(%esp)
	movl	%eax, (%esp)
	call	strcmp
	testl	%eax, %eax
	jne	.L17
.L16:
	movl	$0, (%esp)
	call	pbc_random_set_deterministic
	jmp	.L11
.L17:
	movl	usage, %eax
	movl	%eax, (%esp)
	call	die
.L11:
	addl	$1, -12(%ebp)
.L2:
	movl	-12(%ebp), %eax
	cmpl	8(%ebp), %eax
	jl	.L18
	leave
	ret
	.size	parse_args, .-parse_args
.globl main
	.type	main, @function
main:
	pushl	%ebp
	movl	%esp, %ebp
	andl	$-16, %esp
	subl	$32, %esp
	movl	12(%ebp), %eax
	movl	%eax, 4(%esp)
	movl	8(%ebp), %eax
	movl	%eax, (%esp)
	call	parse_args
	leal	24(%esp), %eax
	movl	%eax, 4(%esp)
	leal	28(%esp), %eax
	movl	%eax, (%esp)
	call	bswabe_setup
	movl	28(%esp), %eax
	movl	%eax, (%esp)
	call	bswabe_pub_serialize
	movl	pub_file, %edx
	movl	$1, 8(%esp)
	movl	%eax, 4(%esp)
	movl	%edx, (%esp)
	call	spit_file
	movl	24(%esp), %eax
	movl	%eax, (%esp)
	call	bswabe_msk_serialize
	movl	msk_file, %edx
	movl	$1, 8(%esp)
	movl	%eax, 4(%esp)
	movl	%edx, (%esp)
	call	spit_file
	movl	$0, %eax
	leave
	ret
	.size	main, .-main
	.ident	"GCC: (Ubuntu 4.4.3-4ubuntu5) 4.4.3"
	.section	.note.GNU-stack,"",@progbits
