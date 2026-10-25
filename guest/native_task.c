/* Minimal independently compiled guest executable; no libc dependencies. */
#include <stdint.h>
#include <stddef.h>
static long syscall3(long n,long a,long b,long c) {
    long r;
    __asm__ volatile("syscall":"=a"(r):"a"(n),"D"(a),"S"(b),"d"(c):"rcx","r11","memory");
    return r;
}
static void write_text(const char *s) {
    size_t n=0;
    while(s[n]) n++;
    syscall3(1,1,(long)s,(long)n);
}
static void emit_number(unsigned int n) {
    char buf[16]; int i=0;
    do {buf[i++]=(char)('0'+n%10); n/=10;} while(n);
    while(i--) syscall3(1,1,(long)&buf[i],1);
}
void _start(void) {
    write_text("OMNI_GUEST_NATIVE_PROGRAM_V1 value=");
    emit_number((unsigned int)(OMNI_LEFT + OMNI_RIGHT));
    write_text("\n");
    syscall3(60,0,0,0);
    for(;;){}
}
