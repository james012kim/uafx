#include<stdio.h>
#include<stdlib.h>

typedef struct data {
    int a,b;
    int *p;
} data;

data *g;

int foo() {
    //Possible False Alarm.
    if (g) {
        return g->a;
    }
    return 1;
}

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
        g = NULL;
        return foo();
    }
    return 0;
}

int e1() {
    //UAF here.
    //Despite the pointer nullification after free(), the UAF is still possible because
    //e1() can be concurrently executed with e0() w/o proper locking.
    if (g) {
        return *(g->p);
    }
    return 1;
}

int main(int argc, char **argv){
    e0(argc);
    e1();
    return 0;
}
