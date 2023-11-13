#!/bin/bash 
gcc -shared -o libtest.so -fPIC test.c
strip libtest.so
gcc main.c -ltest -o main
sudo mv libtest.so /usr/lib/libtest.so