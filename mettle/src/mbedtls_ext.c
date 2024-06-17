#include <time.h>
#ifndef __MINGW32__
#include "mbedtls_ext.h"
#endif
#include "mtwister.h"

#ifndef __MINGW32__
int mbedtls_entropy_remove_source(mbedtls_entropy_context *ctx, mbedtls_entropy_f_source_ptr f_source){
    int idx = 0;
    int found = 0;
    for(idx = 0; idx < ctx->source_count; idx++) {
        if(ctx->source[idx].f_source == f_source) {
            found = 1;
        }
        if(found == 1 && idx + 1 < ctx->source_count) {
            ctx->source[idx].f_source   = ctx->source[idx+1].f_source;
            ctx->source[idx].p_source   = ctx->source[idx+1].p_source;
            ctx->source[idx].size       = ctx->source[idx+1].size;
            ctx->source[idx].strong     = ctx->source[idx+1].strong;
            ctx->source[idx].threshold  = ctx->source[idx+1].threshold;
        }
    }
    if(found) {
        ctx->source_count--;
        return 0;
    }
    return 1;
}

int mbedtls_mtwister_entropy_poll(void *data, unsigned char *output, size_t len, size_t *olen)
{
  MTRand r = seedRand((uint32_t)time(NULL));
  int len_left = len;
  int mem_size = 0;
  uint32_t rand_val = 0;

  while (len_left != 0)
  {
    rand_val = genRandLong(&r);
    if (len_left >= 4)
    {
      mem_size = 4;
    }
    else
    {
      mem_size = len_left;
    }
    for (int i = 0; i < mem_size; i++)
    {
      output[len - len_left + i] = ((uint8_t *)&rand_val)[i];
    }
    len_left -= mem_size;
    *olen += mem_size;
  }
  return 0;
}
#endif