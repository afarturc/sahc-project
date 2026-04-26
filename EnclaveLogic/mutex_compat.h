#ifndef SAHC_MUTEX_COMPAT_H
#define SAHC_MUTEX_COMPAT_H

/* Header-only mutex shim.
 *
 * Inside the SGX-SDK enclave the only mutex API available is
 * sgx_thread_mutex_*. Outside (Gramine LibOS, plain Linux) it's pthread.
 * The enclave logic uses sahc_mutex_t / sahc_mutex_lock / unlock and
 * doesn't care which one it gets.
 */

#ifdef SAHC_BACKEND_SGX
  #include "sgx_thread.h"
  typedef sgx_thread_mutex_t sahc_mutex_t;
  #define SAHC_MUTEX_INITIALIZER SGX_THREAD_MUTEX_INITIALIZER
  static inline void sahc_mutex_lock(sahc_mutex_t* m)   { sgx_thread_mutex_lock(m); }
  static inline void sahc_mutex_unlock(sahc_mutex_t* m) { sgx_thread_mutex_unlock(m); }
#else
  #include <pthread.h>
  typedef pthread_mutex_t sahc_mutex_t;
  #define SAHC_MUTEX_INITIALIZER PTHREAD_MUTEX_INITIALIZER
  static inline void sahc_mutex_lock(sahc_mutex_t* m)   { pthread_mutex_lock(m); }
  static inline void sahc_mutex_unlock(sahc_mutex_t* m) { pthread_mutex_unlock(m); }
#endif

#endif
