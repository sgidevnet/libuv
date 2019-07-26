#ifndef UV_IRIX_H
#define UV_IRIX_H

/* Pulling this from the system headers seems semi-impossible without
 * breaking other things.
 */
#ifndef SCM_RIGHTS
#define SCM_RIGHTS 0x01
#endif

/* This is functionally equivalent.
 */

#define CLOCK_MONOTONIC CLOCK_SGI_CYCLE

int setenv(const char *name, const char *value, int o);
int unsetenv(const char *name);
char *mkdtemp(char *template);
size_t strnlen(const char* str, size_t maxlen);

#define UV_PLATFORM_LOOP_FIELDS                                               \
  struct pollfd* poll_fds;                                                    \
  size_t poll_fds_used;                                                       \
  size_t poll_fds_size;                                                       \
  unsigned char poll_fds_iterating;                                           \


#endif /* UV_IRIX_H */
