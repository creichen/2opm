// This is GENERATED CODE.  Do not modify by hand, or your modifications will be lost on the next re-buld!


#ifndef _A2OPM_REGISTERS_H
#define _A2OPM_REGISTERS_H

// Number of supported registers
#define REGISTERS_NR		16
// Number of native machine register (may be a superset)
#define REGISTERS_NATIVE_NR	16

// Register names
#define REGISTER_V0	0
#define REGISTER_A0	7
#define REGISTER_A1	6
#define REGISTER_A2	2
#define REGISTER_A3	1
#define REGISTER_A4	8
#define REGISTER_A5	9
#define REGISTER_T0	10
#define REGISTER_T1	11
#define REGISTER_S0	3
#define REGISTER_S1	12
#define REGISTER_S2	13
#define REGISTER_S3	14
#define REGISTER_SP	4
#define REGISTER_FP	5
#define REGISTER_GP	15

#define REGISTERS_TEMP_NR		2	// Caller-saved (not including args/special registers)
#define REGISTERS_CALLEE_SAVED_NR	4	// Callee-saved
#define REGISTERS_ARGUMENT_NR		6	// Arguments

typedef struct {
	char *native; // native register name
	char *mips;   // 2OPM name
} regname_t;

extern regname_t register_names[REGISTERS_NATIVE_NR];
extern int registers_ALL[REGISTERS_NR];
extern int registers_temp[REGISTERS_TEMP_NR];
extern int registers_callee_saved[REGISTERS_CALLEE_SAVED_NR];
extern int registers_argument[REGISTERS_ARGUMENT_NR];


#endif // !defined(_A2OPM_REGISTERS_H)

