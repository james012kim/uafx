#include<stdio.h>
#include<stdlib.h>
#include<pthread.h>
#include<stdbool.h>

char *g0, *g1;
bool flag = false;
pthread_mutex_t lock;

void __attribute__ ((noinline)) entry0() {
    char *p = malloc(16);
    g0 = p;
    pthread_mutex_lock(&lock);
    flag = true;
    pthread_mutex_unlock(&lock);
    free(p);
}

void __attribute__ ((noinline)) entry1() {
    g1 = g0;
}

void __attribute__ ((noinline)) entry2() {
    pthread_mutex_lock(&lock);
    if (!flag) {
        printf("%c\n",*g1);
    }
    pthread_mutex_unlock(&lock);
}

void __attribute__ ((noinline)) entry3() {
    printf("%c\n",*g1);
}

int main() {
    printf("A simple multi-entry program showing the cross-entry UAFs.\n");
    return 0;
}