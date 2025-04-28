#include<stdio.h>
#include<stdlib.h>
#include<pthread.h>
#include<stdbool.h>

typedef struct data {
    int a,b;
    int *p;
} data;

data *g;
pthread_mutex_t lock;
bool flag = true;

int __attribute__ ((noinline)) e0(int cmd) {
    data *p = (data*)malloc(sizeof(data));
    p->a = 1;
    if (cmd > 1) {
        free(p);
        //UAF here
        printf("%d\n",p->a);
        p = (data*)malloc(sizeof(data));
        p->a = 2;
    }
    //The seq UAF is impossible because after F a new object is allocated.
    printf("%d\n",p->a);
    return 0;
}

int __attribute__ ((noinline)) e1(int cmd) {
    data *p = (data*)malloc(sizeof(data));
    p->a = 1;
    if (cmd > 1) {
        free(p);
    } else {
        g = p;
    }
    //The seq UAF is impossible because after F cannot be sequentially executed
    //with the required pto record propagation for U site.
    printf("%d\n",g->a);
    return 0;
}

int main(int argc, char **argv){
    if (pthread_mutex_init(&lock, NULL) != 0) {
        return 1;
    }
    e0(argc);
    e1(argc);
    return 0;
}
