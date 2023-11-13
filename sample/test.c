#include "test.h"
static void send1(int a){
    printf("send1 %d\n",a);
}

static void recv1(int a){
    printf("recv1 %d\n",a);
}

static void send2(int a){
    printf("send2 %d\n",a);
}

static void recv2(int a){
    printf("recv2 %d\n",a);
}

static int count = 0;

void create_test_struct(struct test_struct *t){
    count++;
    switch(count % 2){
        case 0:
            t->send = (void*)send1;
            t->recv = (void*)recv1;
            break;
        case 1:
            t->send = (void*)send2;
            t->recv = (void*)recv2;
            break;
        default:
            t->send = (void*)send1;
            t->recv = (void*)recv1;
            count = 0;
            break;
    }
}
