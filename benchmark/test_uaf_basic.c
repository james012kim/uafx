#include<stdio.h>
#include<stdlib.h>

typedef struct data {
    int a,b;
    int *p;
} data;

data *g;

int e0(int cmd) {
    switch(cmd) {
    case 0:
        //allocation
        g = (data*)malloc(sizeof(data));
        break;
    case 1:
        //use
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
