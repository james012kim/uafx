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

int __attribute__ ((noinline)) foo(data **p) {
    data *t = malloc(sizeof(data));
    int ec = 0;
    if (!t) {
        ec = -1;
        goto exit;
    }
    if (!p) {
        ec = -2;
        goto free;
    }
    *p = t;
    printf("success!\n");
    return 0;
free:
    free(t);
exit:
    return ec;
}

int __attribute__ ((noinline)) e0(int cmd) {
    data *p;
    int ec = foo(&p);
    if (ec < 0) {
        return ec;;
    }
    //Possible False Alarm UAF here, if "ec" is not negative, it's guaranteed that p will
    //point to a valid object (not freed) according to the logic of foo().
    printf("%d\n",p->a);
    return 0;
}

int main(int argc, char **argv){
    if (pthread_mutex_init(&lock, NULL) != 0) {
        return 1;
    }
    e0(argc);
    return 0;
}
