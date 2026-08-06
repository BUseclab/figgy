#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdint.h>

#define NUM_FORKS 100000  // how many times to fork; change as needed

int main(void) {
    char *const argv[] = { "/usr/bin/true", NULL };
    char *const envp[] = { NULL };

    for (int i = 0; i < NUM_FORKS; i++) {
        pid_t pid = fork();

        if (pid < 0) {
            perror("fork");
            exit(EXIT_FAILURE);
        }

        if (pid == 0) {
            // child: replace image with /usr/bin/true
            execve("/usr/bin/true", argv, envp);
            // only reached if execve fails
            perror("execve");
            _exit(127);
        }

        // parent: wait for this child before spawning the next
        int status;
        waitpid(pid, &status, 0);
    }

    return 0;
}