#include "test.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(){
    struct test_struct t;
    while(1){
        create_test_struct(&t);
        test_send(&t,1);
        test_recv(&t,1);
        create_test_struct(&t);
        test_send(&t,2);
        test_recv(&t,2);
        sleep(5);
    }
    return 0;
}

