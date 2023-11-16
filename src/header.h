struct test_struct_t {
    // callback
    void (*send)(int);
    void (*recv)(void);
};

#include <infiniband/verbs.h>