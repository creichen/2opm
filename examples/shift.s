.text
main:
	li $v0, -1
	li $a0, 3
	srl $v0, $a0
	li $v0, -1
	li $a3, 3
	srl $v0, $a3
	li $v0, -1
	li $a0, 3
	sra $v0, $a0
	li $v0, -1
	li $a3, 3
	sra $v0, $a3
	jreturn

