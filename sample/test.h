#include <stdio.h>

struct test_struct {
    // callback
    void (*send)(int);
    void (*recv)(int);
};

static inline void test_send(struct test_struct* t,int a){
    printf("test send, t->send() %llx\n",(unsigned long long)t->send);
    t->send(a);
}

static inline void test_recv(struct test_struct* t,int a){
    printf("test recv, t->recv() %llx\n",(unsigned long long)t->recv);
    t->recv(a);
}

void create_test_struct(struct test_struct *t);
