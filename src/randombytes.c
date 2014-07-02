#include <stdio.h>
#include <stdlib.h>
#include "tweetnacl.h"

void randombytes(u8* buf, u64 len)
{
    fprintf(stderr, "tweetnacl called `randombytes', aborting");
    abort();
}
