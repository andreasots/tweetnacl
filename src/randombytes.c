#include <stdio.h>
#include <stdlib.h>
#include "tweetnacl.h"

typedef unsigned char u8;
typedef unsigned long long u64;

void randombytes(u8* buf, u64 len)
{
    fprintf(stderr, "tweetnacl called `randombytes', aborting");
    abort();
}
