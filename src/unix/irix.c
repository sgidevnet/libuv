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

#include <fcntl.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/soioctl.h>
#include <procfs/procfs.h>
#include <stdio.h>
#include <string.h>
#include <stropts.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/procfs.h>
#include <sys/stat.h>
#include <sys/sysget.h>
#include <sys/sysinfo.h>
#include <sys/sysmp.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

extern char** environ;

static uv_mutex_t process_title_mutex;
static uv_once_t process_title_mutex_once = UV_ONCE_INIT;
static void* args_mem = NULL;
static char** process_argv = NULL;
static int process_argc = 0;
static char* process_title_ptr = NULL;

/* Support functions for things missing from IRIX. */

int setenv(const char *name, const char *value, int o) {
    size_t len = strlen(name) + strlen(value) + 2;
    char *s = malloc(len+1);
    int ret;

    snprintf(s, len, "%s=%s", name, value);
    ret = putenv(s);
    free(s);
    return ret;
}

int unsetenv (const char *name) {
  size_t len;
  char **ep;

  if (name == NULL || *name == '\0' || strchr (name, '=') != NULL)
    return UV_EINVAL;

  len = strlen (name);

  ep = environ;
  while (*ep != NULL)
    if (!strncmp (*ep, name, len) && (*ep)[len] == '=') {
      char **dp = ep;

      do
	dp[0] = dp[1];
      while (*dp++);
    } else { 
      ++ep;
    }

  return 0;
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

int uv_uptime(double* uptime) {
  *uptime = 12345;
  return 0;
}

int uv_resident_set_memory(size_t* rss) {
  *rss = 1024*1024;
  return 0;
}

int uv_exepath(char* buffer, size_t* size) {
  char filename[50];
  char abspath[PATH_MAX];
  char firstarg[PATH_MAX];
  size_t abspath_size;
  int fd;

  if (buffer == NULL || size == NULL || *size == 0)
    return UV_EINVAL;

  sprintf (filename, "/proc/pinfo/%d", (int) getpid ());
  fd = open (filename, O_RDONLY);
  if (0 <= fd) {
    prpsinfo_t buf;
    int ioctl_ok = 0 <= ioctl (fd, PIOCPSINFO, &buf);
    close (fd);
    if (ioctl_ok)
      {
	int offset = strchr(buf.pr_psargs, ' ') - buf.pr_psargs;
	memcpy(firstarg, buf.pr_psargs, offset);
	firstarg[offset] = '\0';

	printf("%s\n", firstarg);
	
	if(!realpath(firstarg, abspath))
	  return UV__ERR(errno);

	abspath_size = strlen(abspath);

	*size -= 1;
	if (*size > abspath_size)
	  *size = abspath_size;

	memcpy(buffer, abspath, *size);
	buffer[*size] = '\0';

	return 0;
      }
  }
  return UV__EINVAL;
}

/* Stuff below stolen from AIX.
 */
static void init_process_title_mutex_once(void) {
  uv_mutex_init(&process_title_mutex);
}

char** uv_setup_args(int argc, char** argv) {
  char** new_argv;
  size_t size;
  char* s;
  int i;

  if (argc <= 0)
    return argv;

  /* Save the original pointer to argv.
   * AIX uses argv to read the process name.
   * (Not the memory pointed to by argv[0..n] as on Linux.)
   */
  process_argv = argv;
  process_argc = argc;

  /* Calculate how much memory we need for the argv strings. */
  size = 0;
  for (i = 0; i < argc; i++)
    size += strlen(argv[i]) + 1;

  /* Add space for the argv pointers. */
  size += (argc + 1) * sizeof(char*);

  new_argv = uv__malloc(size);
  if (new_argv == NULL)
    return argv;
  args_mem = new_argv;

  /* Copy over the strings and set up the pointer table. */
  s = (char*) &new_argv[argc + 1];
  for (i = 0; i < argc; i++) {
    size = strlen(argv[i]) + 1;
    memcpy(s, argv[i], size);
    new_argv[i] = s;
    s += size;
  }
  new_argv[i] = NULL;

  return new_argv;
}

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

int uv_get_process_title(char* buffer, size_t size) {
  size_t len;
  if (buffer == NULL || size == 0)
    return UV_EINVAL;

  uv_once(&process_title_mutex_once, init_process_title_mutex_once);
  uv_mutex_lock(&process_title_mutex);

  len = strlen(process_argv[0]);
  if (size <= len) {
    uv_mutex_unlock(&process_title_mutex);
    return UV_ENOBUFS;
  }

  memcpy(buffer, process_argv[0], len);
  buffer[len] = '\0';

  uv_mutex_unlock(&process_title_mutex);

  return 0;
}



/* This may work.
 */

int uv_interface_addresses(uv_interface_address_t** addresses, int* count) {
  uv_interface_address_t* address;
  int sockfd, inet6, size = 1;
  struct ifconf ifc;
  struct ifreq *ifr, *p, flg;
  struct sockaddr_dl* sa_addr;

  *count = 0;
  *addresses = NULL;

  if (0 > (sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP))) {
    return UV__ERR(errno);
  }

  /*  if (ioctl(sockfd, SIOCGSIZIFCONF, &size) == -1) {
    uv__close(sockfd);
    return UV__ERR(errno);
    } */

  ifc.ifc_req = (struct ifreq*)uv__malloc(size);
  ifc.ifc_len = size;
  if (ioctl(sockfd, SIOCGIFCONF, &ifc) == -1) {
    uv__close(sockfd);
    return UV__ERR(errno);
  }

  /* #define ADDR_SIZE(p) MAX((p).sa_len, sizeof(p)) */
#define ADDR_SIZE(p) sizeof(p)

  /* Count all up and running ipv4/ipv6 addresses */
  ifr = ifc.ifc_req;
  while ((char*)ifr < (char*)ifc.ifc_req + ifc.ifc_len) {
    p = ifr;
    ifr = (struct ifreq*)
      ((char*)ifr + sizeof(ifr->ifr_name) + ADDR_SIZE(ifr->ifr_addr));

    if (!(p->ifr_addr.sa_family == AF_INET6 ||
          p->ifr_addr.sa_family == AF_INET))
      continue;

    memcpy(flg.ifr_name, p->ifr_name, sizeof(flg.ifr_name));
    if (ioctl(sockfd, SIOCGIFFLAGS, &flg) == -1) {
      uv__close(sockfd);
      return UV__ERR(errno);
    }

    if (!(flg.ifr_flags & IFF_UP && flg.ifr_flags & IFF_RUNNING))
      continue;

    (*count)++;
  }

  if (*count == 0) {
    uv__close(sockfd);
    return 0;
  }

  /* Alloc the return interface structs */
  *addresses = uv__malloc(*count * sizeof(uv_interface_address_t));
  if (!(*addresses)) {
    uv__close(sockfd);
    return UV_ENOMEM;
  }
  address = *addresses;

  ifr = ifc.ifc_req;
  while ((char*)ifr < (char*)ifc.ifc_req + ifc.ifc_len) {
    p = ifr;
    ifr = (struct ifreq*)
      ((char*)ifr + sizeof(ifr->ifr_name) + ADDR_SIZE(ifr->ifr_addr));

    if (!(p->ifr_addr.sa_family == AF_INET6 ||
          p->ifr_addr.sa_family == AF_INET))
      continue;

    inet6 = (p->ifr_addr.sa_family == AF_INET6);

    memcpy(flg.ifr_name, p->ifr_name, sizeof(flg.ifr_name));
    if (ioctl(sockfd, SIOCGIFFLAGS, &flg) == -1) {
      uv__close(sockfd);
      return UV_ENOSYS;
    }

    if (!(flg.ifr_flags & IFF_UP && flg.ifr_flags & IFF_RUNNING))
      continue;

    /* All conditions above must match count loop */

    address->name = uv__strdup(p->ifr_name);

    if (inet6)
      address->address.address6 = *((struct sockaddr_in6*) &p->ifr_addr);
    else
      address->address.address4 = *((struct sockaddr_in*) &p->ifr_addr);

    sa_addr = (struct sockaddr_dl*) &p->ifr_addr;
    memcpy(address->phys_addr, LLADDR(sa_addr), sizeof(address->phys_addr));

    if (ioctl(sockfd, SIOCGIFNETMASK, p) == -1) {
      uv__close(sockfd);
      return UV_ENOSYS;
    }

    if (inet6)
      address->netmask.netmask6 = *((struct sockaddr_in6*) &p->ifr_addr);
    else
      address->netmask.netmask4 = *((struct sockaddr_in*) &p->ifr_addr);

    address->is_internal = flg.ifr_flags & IFF_LOOPBACK ? 1 : 0;

    address++;
  }

#undef ADDR_SIZE

  uv__close(sockfd);
  return 0;
}


void uv_free_interface_addresses(uv_interface_address_t* addresses,
  int count) {
  int i;

  for (i = 0; i < count; ++i) {
    uv__free(addresses[i].name);
  }

  uv__free(addresses);
}

