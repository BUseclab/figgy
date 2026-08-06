#define _GNU_SOURCE
#include <unistd.h>

int main(void) {
    char *argv[] = {"./write", NULL};  // replace with the path to your executable
    char *envp[] = {NULL};
    
    execve("/usr/bin/make", argv, envp);
    
    _exit(1);  // only reached if execve fails
}