#include <errno.h>
#include <linux/audit.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/unistd.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <unistd.h>

#include "common.h"

static int seccomp(unsigned int operation, unsigned int flags, void *args) {
	return syscall(__NR_seccomp, operation, flags, args);
}

static int install_filter(int nr, int arch, int error) {
	int fd;
  struct sock_filter filter[] = {
      BPF_STMT(BPF_LD + BPF_W + BPF_ABS, (offsetof(struct seccomp_data, arch))),
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, arch, 0, 3),
      BPF_STMT(BPF_LD + BPF_W + BPF_ABS, (offsetof(struct seccomp_data, nr))),
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, nr, 0, 1),
      BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | (error & SECCOMP_RET_DATA)),
      BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
  };
  struct sock_fprog prog = {
      .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
      .filter = filter,
  };

  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
	  die ("  prctl");
  }

  if ((fd = seccomp(
	SECCOMP_SET_MODE_FILTER, 
	SECCOMP_FILTER_FLAG_NEW_LISTENER, 
	&prog)) < 0) {
	  die("  seccomp");
  }

  return fd;
}

int main() {
  printf("hey there!\n");
  printf("something's gonna happen!!\n");

  install_filter(__NR_write, AUDIT_ARCH_X86_64, EPERM);

  printf("it will not definitely print this here\n");
  return 0;
}

