#include<stdio.h>
#include<stdlib.h>
#include<pthread.h>
#include<stdbool.h>

typedef struct data {
    int a,b;
    int *p;
} data;

data *g;
pthread_mutex_t lock, lock1, lock2, lock3;
bool flag = true;

int e0(int cmd) {
    switch(cmd) {
    case 0:
        //allocation
        g = (data*)malloc(sizeof(data));
        break;
    case 1:
        //UAF here.
        printf("sum: %d\n", g->a + g->b);
        break;
    case 2:
        //free
        free(g);
        break;
    }
    return 0;
}

int e1() {
    //False alarm here: UAF cannot happen due to the interaction between lock and cond set/check.
    pthread_mutex_lock(&lock3);
    pthread_mutex_lock(&lock2);
    pthread_mutex_lock(&lock1);
    pthread_mutex_lock(&lock);
    printf("data: %d\n", *(g->p));
    pthread_mutex_unlock(&lock);
    pthread_mutex_unlock(&lock1);
    pthread_mutex_unlock(&lock2);
    pthread_mutex_unlock(&lock3);
    return 0;
}

int main(int argc, char **argv){
    if (pthread_mutex_init(&lock, NULL) != 0) {
        return 1;
    }
    if (pthread_mutex_init(&lock1, NULL) != 0) {
        return 1;
    }
    if (pthread_mutex_init(&lock2, NULL) != 0) {
        return 1;
    }
    if (pthread_mutex_init(&lock3, NULL) != 0) {
        return 1;
    }
    e0(argc);
    e1();
    return 0;
}
