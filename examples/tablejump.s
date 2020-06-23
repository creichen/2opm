.text
main:
	la $a0, intro
	jal print_string
	jal read_int
	la $t0, option
	slli $v0, $v0, 3
	add $t0, $v0
	ld  $t1, 0($t0)
	jr   $t1

a:
	la $a0, t
	jal print_string
	jreturn
b:
	la $a0, 1
	jal print_int
c:
	la $a0, 2
	jal print_int
	jreturn
	
.data
option:
.word a, b, c
.asciiz
t:	"Hello"
intro:	"Enter 0, 1, or 2"
