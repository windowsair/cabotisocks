#ifndef _LOONGARCH64_PTRACE_H_
#define _LOONGARCH64_PTRACE_H_

struct pt_regs {
	/* Main processor registers. */
	unsigned long regs[32];

	/* Original syscall arg0. */
	unsigned long orig_a0;

	/* Special CSR registers. */
	unsigned long csr_era;
	unsigned long csr_badvaddr;
	unsigned long csr_crmd;
	unsigned long csr_prmd;
	unsigned long csr_euen;
	unsigned long csr_ecfg;
	unsigned long csr_estat;
	unsigned long __last[];
} __attribute__((__aligned__(8)));

#endif
