.text
main:
	jal read_int
	move $s0, $v0
	jal read_int
	move $a0, $s0
	add $a0, $v0
	jal print_int
	jreturn

