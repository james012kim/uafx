#include<stdio.h>
#include<stdlib.h>
#include<pthread.h>

typedef struct data {
    int a,b;
    int *p;
} data;

data *g;

void *e0_work(void *p) {
    data *pg = (data*)p;
    //USE
    printf("a:%d\n",pg->b);
    return p;
}

int e0() {
    pthread_t tr;
    pthread_create(&tr, NULL, e0_work, (void*)g);
    printf("tid: %d\n",(int)tr);
    pthread_join(tr, NULL);
    //FREE
    free(g); //FP, because the USE in e0_work must happen before here, due to JOIN.
    return 0;
}

int e1() {
    pthread_t tr;
    pthread_create(&tr, NULL, e0_work, (void*)g);
    printf("tid: %d\n",(int)tr);
    //FREE
    free(g); //TP, it's possible that e0_work() can happen after free.
    pthread_join(tr, NULL);
    return 0;
}

int main(int argc, char **argv){
    g = (data*)malloc(sizeof(data));
    e0();
    e1();
    return 0;
}