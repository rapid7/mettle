/*
 * PowerPC startup code for mettle
 * Fixes ABI compliance and stack alignment issues
 */

.section .text
.global _start
.global __start

_start:
__start:
    # PowerPC ABI setup
    # Save link register
    mflr    r0
    stwu    r1, -16(r1)
    stw     r0, 20(r1)
    
    # Set up stack frame
    addi    r1, r1, -64
    stw     r31, 60(r1)
    mr      r31, r1
    
    # Ensure 16-byte stack alignment
    clrrwi  r1, r1, 4
    
    # Set up argc/argv
    lwz     r3, 0(r1)      # argc
    addi    r4, r1, 4      # argv
    addi    r5, r4, 4      # skip argv[0]
    
    # Call main
    bl      main
    
    # Exit
    li      r0, 1
    sc
    
    # Restore and return
    lwz     r31, 60(r1)
    addi    r1, r1, 64
    lwz     r0, 20(r1)
    mtlr    r0
    addi    r1, r1, 16
    blr

# PowerPC-specific initialization
.global powerpc_init
powerpc_init:
    # Initialize TOC (Table of Contents)
    bl      .+4
    mflr    r30
    addis   r30, r30, 0
    
    # Set up GOT pointer
    lis     r2, 0
    ori     r2, r2, 0
    
    # Initialize small data area
    lis     r13, 0
    ori     r13, r13, 0
    
    # Return
    blr
EOF
