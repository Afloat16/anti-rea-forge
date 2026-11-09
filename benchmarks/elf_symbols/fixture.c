// Project-owned i386 Linux executable. No libc or 32-bit development libraries.
static __attribute__((noinline)) unsigned PRIVATE_RULE(unsigned argc) {
    return argc * 13 + 21;
}

__attribute__((noinline)) unsigned rg_public_entry(unsigned argc) {
    return PRIVATE_RULE(argc) + 5;
}

__asm__(".text\n"
        ".globl _start\n"
        ".type _start,@function\n"
        "_start:\n"
        "pushl (%esp)\n"
        "call rg_public_entry\n"
        "movl %eax,%ebx\n"
        "movl $1,%eax\n"
        "int $0x80\n"
        ".size _start,.-_start\n");
