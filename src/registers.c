// This is GENERATED CODE.  Do not modify by hand, or your modifications will be lost on the next re-buld!

#include "registers.h"

regname_t register_names[REGISTERS_NR] = {
	{"rax",	"$v0"},
	{"rcx",	"$a3"},
	{"rdx",	"$a2"},
	{"rbx",	"$s0"},
	{"rsp",	"$sp"},
	{"rbp",	"$fp"},
	{"rsi",	"$a1"},
	{"rdi",	"$a0"},
	{"r8",	"$a4"},
	{"r9",	"$a5"},
	{"r10",	"$t0"},
	{"r11",	"$t1"},
	{"r12",	"$s1"},
	{"r13",	"$s2"},
	{"r14",	"$s3"},
	{"r15",	"$gp"}};

int registers_callee_saved[REGISTERS_CALLEE_SAVED_NR] = {
	3, 12, 13, 14
};

int registers_temp[REGISTERS_TEMP_NR] = {
	10, 11
};

int registers_argument[REGISTERS_ARGUMENT_NR] = {
	7, 6, 2, 1, 8, 9
};

