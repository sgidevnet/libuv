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
#define unsetenv(x) setenv(x, "", 1)
char *mkdtemp(char *template);

#endif /* UV_IRIX_H */
