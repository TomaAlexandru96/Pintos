#ifndef THREADS_fIxED_POInT_H
#define THREADs_fIxED_POInT_H

#include <stdint.h>

/*Macros for 17.14 fixed-point number representation*/

#define P 17
#define Q 14
#define F (1 << Q)

#define int_to_fp(n) (n * F)

#define fp_to_int_round_towards_zero(x) (x / F)

#define fp_to_int_round_to_nearest(x) (x >= 0 ? ((x + (F / 2)) / F) : ((x - (F / 2)) / F))

#define add_fp(x, y) (x + y)

#define subtract_fp(x, y) (x - y)

#define add_fp_and_int(x, n) (x + (n * F))

#define subtract_int_from_fp(x, n) (x - (n * F))

#define multiply_fp(x, y) ((((int64_t) x) * y) / F)

#define multiply_fp_and_int(x, n) (x * n)

#define divide_fp(x, y) ((((int64_t) x) * F) / y)

#define divide_fp_by_int(x, n) (x / n)


#endif /* threads/fixed-point.h */