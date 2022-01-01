.text
main:
    	subi $sp, 24
        sb8   $fp, -16($sp)
        sb8   $s0, -8($sp)

    	move $a1, $gp
    	addi $a1, string     ; output string buffer
    	move $t1, $a1
    	li   $s0, 0x40
        li   $a2, 0          ; length
loop:
    	lb   $t0, 0($t1)
    	beqz $t0, done_loop
        addi $a2, 1
    	ble  $t0, $s0, skip
    	andi $t0, 0x5f
skip:
    	sb   $t0, 0($t1)
    	addi $t1, 1
    	j loop
done_loop:
        li   $v0, 1	     ; syscall 1 (Linux only) is write()
        li   $a0, 0          ; stdout
        syscall

        lb8   $s0, -8($sp)
        lb8   $fp, -16($sp)
        addi $sp, 24
    	jreturn
.data
.asciiz
string:
    	"Hello, World!\n"
