#include <riscv/sbi.h>
#include <riscv/umprintf.h>

void print_msg(void) {
  char *msg = "Hello RISC-V world!\n";
  for (int i = 0; i < 20; ++i) {
    sbi_console_putchar(msg[i]);
  }
}
