#include <linux/types.h>
struct __whatever_s {
  int j_max_transaction_buffers;
  __whatever_s* j_committing_transaction;
  int t_outstanding_credits;
};
typedef unsigned __bitwise__ gfp_t;
typedef unsigned int         tid_t;
typedef struct __whatever_s  journal_t;
