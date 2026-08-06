#define _GNU_SOURCE
#include <unistd.h>
#include <sys/wait.h>

int main(void) {
    pid_t p = fork(); 

    if (p == 0) {
        write(STDOUT_FILENO, "child\n", 6);
        _exit(0); 
    }

    write(STDOUT_FILENO, "parent\n", 7);
    wait(NULL); 
    
    return 0;
}
