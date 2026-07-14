#define _GNU_SOURCE
#include <unistd.h>

int main(void) {
    // char *argv[] = {"./write", NULL};
    char *argv[] = {NULL};
    char *envp[] = {NULL};
    
    execve("./write", argv, envp);  // should run writer too
    
    _exit(1);  // only reached if execve fails
}