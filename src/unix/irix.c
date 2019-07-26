/* Copyright libuv project contributors. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include "uv.h"
#include "internal.h"

#include <stdio.h>
#include <sys/sysinfo.h>
#include <sys/sysmp.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

uint64_t uv__hrtime(uv_clocktype_t type)
{
  uint64_t G = 1000000000;
  struct timespec t;
  if(clock_gettime(CLOCK_REALTIME, &t))
    abort();
  return (uint64_t) t.tv_sec * G + t.tv_nsec;
}

uint64_t uv_get_free_memory(void)
{
  struct rminfo realmem;
  long pagesize;
    
  if (sysmp(MP_SAGET, MPSA_RMINFO, &realmem, sizeof(realmem)) == -1) {
    perror("sysmp(MP_SAGET,MPSA_RMINFO, ...)");
    return;
  }

  pagesize = sysconf(_SC_PAGESIZE);
  return (uint64_t) realmem.freemem * pagesize;
}

uint64_t uv_get_total_memory(void)
{
  struct rminfo realmem;
  long pagesize;
    
  if (sysmp(MP_SAGET, MPSA_RMINFO, &realmem, sizeof(realmem)) == -1) {
    perror("sysmp(MP_SAGET,MPSA_RMINFO, ...)");
    return;
  }

  pagesize = sysconf(_SC_PAGESIZE);
  return (uint64_t) realmem.physmem * pagesize;
}

uint64_t uv_get_constrained_memory(void)
{
  return 0;
}

void uv_loadavg(double avg[3])
{
  int avenrun[3];
    
  static unsigned long avenrun_offset;
  sgt_cookie_t cookie;
    
    
  if ((avenrun_offset = sysmp(MP_KERNADDR, MPKA_AVENRUN)) == -1) {
    avg[0] = 0.; avg[1] = 0.; avg[2] = 0.;
    return;
  }

  SGT_COOKIE_INIT(&cookie);
  SGT_COOKIE_SET_KSYM(&cookie, "avenrun");
    
  if (sysget(SGT_KSYM, (char *)avenrun, sizeof(avenrun),
	     SGT_READ, &cookie) != sizeof(avenrun)) {
    avg[0] = 0.; avg[1] = 0.; avg[2] = 0.;
    return;
  }

  for (int i = 0; i < 3; i++) {
    avg[i] = avenrun[i];
    avg[i] /= 1024.0;
  }
}
