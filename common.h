#ifndef COMMON_H
#define COMMON_H

#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>

void err(const char *format, ...);

#define die(...)						\
	do {							\
		fprintf(stderr, "%s:%i: ", __FILE__, __LINE__);	\
		err(__VA_ARGS__);				\
		exit(EXIT_FAILURE);				\
	} while (0)

#endif
