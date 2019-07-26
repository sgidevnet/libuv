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
#include <sys/sysget.h>
#include <sys/sysmp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* Support functions for things missing from IRIX. */

int setenv(const char *name, const char *value, int o) {
    size_t len = strlen(name) + strlen(value) + 1;
    char *s = malloc(len+1);
    int ret;

    snprintf(s, len, "%s=%s", name, value);
    ret = putenv(s);
    free(s);
    return ret;
}

char *mkdtemp(char *template) {
    mkdir(mktemp(template), 0700);
    return template;
}

size_t strnlen(const char* str, size_t maxlen) {
  char* p = memchr(str, 0, maxlen);
  if (p == NULL)
    return maxlen;
  else
    return p - str;
}

/* Actual libuv functions. */

uint64_t uv__hrtime(uv_clocktype_t type) {
  uint64_t G = 1000000000;
  struct timespec t;
  if(clock_gettime(CLOCK_REALTIME, &t))
    abort();
  return (uint64_t) t.tv_sec * G + t.tv_nsec;
}

uint64_t uv_get_free_memory(void) {
  struct rminfo realmem;
  long pagesize;
    
  if (sysmp(MP_SAGET, MPSA_RMINFO, &realmem, sizeof(realmem)) == -1) {
    return 0;
  }

  pagesize = sysconf(_SC_PAGESIZE);
  return (uint64_t) realmem.freemem * pagesize;
}

uint64_t uv_get_total_memory(void) {
  struct rminfo realmem;
  long pagesize;
    
  if (sysmp(MP_SAGET, MPSA_RMINFO, &realmem, sizeof(realmem)) == -1) {
    return 0;
  }

  pagesize = sysconf(_SC_PAGESIZE);
  return (uint64_t) realmem.physmem * pagesize;
}

uint64_t uv_get_constrained_memory(void) {
  return 0;
}

void uv_loadavg(double avg[3]) {
  int avenrun[3];
    
  static unsigned long avenrun_offset;
  sgt_cookie_t cookie;

  int i;
    
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

  for (i = 0; i < 3; i++) {
    avg[i] = avenrun[i];
    avg[i] /= 1024.0;
  }
}

int uv_cpu_info(uv_cpu_info_t** cpu_infos, int*count) {
  uv_cpu_info_t *cpu_info;
  int result, ncpus, i = 0;
  
  ncpus = sysconf(_SC_NPROC_ONLN);
  
  *cpu_infos = (uv_cpu_info_t*) uv__malloc(ncpus * sizeof(uv_cpu_info_t));
  if (!*cpu_infos) {
    return UV_ENOMEM;
  }

  cpu_info = *cpu_infos;
  while(i < ncpus) {
    cpu_info->speed = 100;
    cpu_info->model = "CPU";
    cpu_info->cpu_times.user = 0;
    cpu_info->cpu_times.sys = 0;
    cpu_info->cpu_times.idle = 100;
    cpu_info->cpu_times.irq = 0;
    cpu_info->cpu_times.nice = 0;
    cpu_info++;
    i++;
  }
  return 0;
}

void uv_free_cpu_info(uv_cpu_info_t* cpu_infos, int count) {
  int i;

  for (i = 0; i < count; ++i) {
    uv__free(cpu_infos[i].model);
  }

  uv__free(cpu_infos);
}

void uv_uptime(double* uptime) {
  *uptime = 12345;
}

int uv_resident_set_memory(size_t* rss) {
  *rss = 1024*1024;
  return 0;
}

/* Stolen verbatim from AIX.
 */
int uv_set_process_title(const char* title) {
  char* new_title;

  /* We cannot free this pointer when libuv shuts down,
   * the process may still be using it.
   */
  new_title = uv__strdup(title);
  if (new_title == NULL)
    return UV_ENOMEM;

  uv_once(&process_title_mutex_once, init_process_title_mutex_once);
  uv_mutex_lock(&process_title_mutex);

  /* If this is the first time this is set,
   * don't free and set argv[1] to NULL.
   */
  if (process_title_ptr != NULL)
    uv__free(process_title_ptr);

  process_title_ptr = new_title;

  process_argv[0] = process_title_ptr;
  if (process_argc > 1)
     process_argv[1] = NULL;

  uv_mutex_unlock(&process_title_mutex);

  return 0;
}

/* Stolen from AIX, slightly modified.
 *
 * We could use a static buffer for the path manipulations that we need outside
 * of the function, but this function could be called by multiple consumers and
 * we don't want to potentially create a race condition in the use of snprintf.
 * There is no direct way of getting the exe path in AIX - either through /procfs
 * or through some libc APIs. The below approach is to parse the argv[0]'s pattern
 * and use it in conjunction with PATH environment variable to craft one.
 */
int uv_exepath(char* buffer, size_t* size) {
  char args[PATH_MAX];
  char abspath[PATH_MAX];
  size_t abspath_size;

  if (buffer == NULL || size == NULL || *size == 0)
    return UV_EINVAL;

  /*
   * Possibilities for args:
   * i) an absolute path such as: /home/user/myprojects/nodejs/node
   * ii) a relative path such as: ./node or ../myprojects/nodejs/node
   * iii) a bare filename such as "node", after exporting PATH variable
   *     to its location.
   */

  /* Case i) and ii) absolute or relative paths */
  if (strchr(args, '/') != NULL) {
    if (realpath(args, abspath) != abspath)
      return UV__ERR(errno);

    abspath_size = strlen(abspath);

    *size -= 1;
    if (*size > abspath_size)
      *size = abspath_size;

    memcpy(buffer, abspath, *size);
    buffer[*size] = '\0';

    return 0;
  } else {
    /* Case iii). Search PATH environment variable */
    char trypath[PATH_MAX];
    char *clonedpath = NULL;
    char *token = NULL;
    char *path = getenv("PATH");

    if (path == NULL)
      return UV_EINVAL;

    clonedpath = uv__strdup(path);
    if (clonedpath == NULL)
      return UV_ENOMEM;

    token = strtok(clonedpath, ":");
    while (token != NULL) {
      snprintf(trypath, sizeof(trypath) - 1, "%s/%s", token, args);
      if (realpath(trypath, abspath) == abspath) {
        /* Check the match is executable */
        if (access(abspath, X_OK) == 0) {
          abspath_size = strlen(abspath);

          *size -= 1;
          if (*size > abspath_size)
            *size = abspath_size;

          memcpy(buffer, abspath, *size);
          buffer[*size] = '\0';

          uv__free(clonedpath);
          return 0;
        }
      }
      token = strtok(NULL, ":");
    }
    uv__free(clonedpath);

    /* Out of tokens (path entries), and no match found */
    return UV_EINVAL;
  }
}
