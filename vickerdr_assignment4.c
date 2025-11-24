
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>

#define MAX_CMD_LEN 2048
#define MAX_ARGS 512

// Global variables for signal handling and status
volatile sig_atomic_t foreground_only_mode = 0;
int last_foreground_status = 0;
int background_pids[MAX_ARGS];
int background_count = 0;

// Command structure
typedef struct {
    char *args[MAX_ARGS + 1];
    int arg_count;
    char *input_file;
    char *output_file;
    int background;
} Command;

// Function prototypes
void shell_loop(void);
Command *parse_command(char *input);
void free_command(Command *cmd);
void execute_command(Command *cmd);
void execute_builtin(Command *cmd);
void execute_external(Command *cmd);
void check_background_processes(void);
void handle_sigtstp(int sig);

// Signal handler for SIGTSTP (Ctrl-Z)
void handle_sigtstp(int sig) {
    char *enter_msg = "\nEntering foreground-only mode (& is now ignored)\n";
    char *exit_msg = "\nExiting foreground-only mode\n";

    if (foreground_only_mode == 0) {
        write(STDOUT_FILENO, enter_msg, strlen(enter_msg));
        foreground_only_mode = 1;
    } else {
        write(STDOUT_FILENO, exit_msg, strlen(exit_msg));
        foreground_only_mode = 0;
    }
}

// Main shell loop
void shell_loop(void) {
    char input[MAX_CMD_LEN];

    // Set up signal handlers
    struct sigaction sa_int = {0};
    sa_int.sa_handler = SIG_IGN;
    sigfillset(&sa_int.sa_mask);
    sa_int.sa_flags = 0;
    sigaction(SIGINT, &sa_int, NULL);

    struct sigaction sa_tstp = {0};
    sa_tstp.sa_handler = handle_sigtstp;
    sigfillset(&sa_tstp.sa_mask);
    sa_tstp.sa_flags = SA_RESTART;
    sigaction(SIGTSTP, &sa_tstp, NULL);

    while (1) {
        // Check for completed background processes
        check_background_processes();

        // Print prompt
        printf(": ");
        fflush(stdout);

        // Read input
        if (fgets(input, MAX_CMD_LEN, stdin) == NULL) {
            clearerr(stdin);
            continue;
        }

        // Remove newline
        input[strcspn(input, "\n")] = '\0';

        // Skip blank lines and comments
        if (strlen(input) == 0 || input[0] == '#') {
            continue;
        }

        // Parse and execute command
        Command *cmd = parse_command(input);
        if (cmd != NULL) {
            execute_command(cmd);
            free_command(cmd);
        }
    }
}

// Parse command line into Command structure
Command *parse_command(char *input) {
    Command *cmd = malloc(sizeof(Command));
    cmd->arg_count = 0;
    cmd->input_file = NULL;
    cmd->output_file = NULL;
    cmd->background = 0;

    char *token = strtok(input, " ");
    int redirect_next_input = 0;
    int redirect_next_output = 0;

    while (token != NULL && cmd->arg_count < MAX_ARGS) {
        if (redirect_next_input) {
            cmd->input_file = strdup(token);
            redirect_next_input = 0;
        } else if (redirect_next_output) {
            cmd->output_file = strdup(token);
            redirect_next_output = 0;
        } else if (strcmp(token, "<") == 0) {
            redirect_next_input = 1;
        } else if (strcmp(token, ">") == 0) {
            redirect_next_output = 1;
        } else if (strcmp(token, "&") == 0) {
            cmd->background = 1;
        } else {
            cmd->args[cmd->arg_count] = strdup(token);
            cmd->arg_count++;
        }
        token = strtok(NULL, " ");
    }

    cmd->args[cmd->arg_count] = NULL;

    if (cmd->arg_count == 0) {
        free_command(cmd);
        return NULL;
    }

    return cmd;
}

// Free command structure
void free_command(Command *cmd) {
    if (cmd == NULL) return;

    for (int i = 0; i < cmd->arg_count; i++) {
        free(cmd->args[i]);
    }
    if (cmd->input_file) free(cmd->input_file);
    if (cmd->output_file) free(cmd->output_file);
    free(cmd);
}

// Execute command
void execute_command(Command *cmd) {
    // Check for built-in commands
    if (strcmp(cmd->args[0], "exit") == 0) {
        // Kill all background processes
        for (int i = 0; i < background_count; i++) {
            kill(background_pids[i], SIGTERM);
        }
        exit(0);
    } else if (strcmp(cmd->args[0], "cd") == 0) {
        execute_builtin(cmd);
    } else if (strcmp(cmd->args[0], "status") == 0) {
        execute_builtin(cmd);
    } else {
        execute_external(cmd);
    }
}

// Execute built-in commands
void execute_builtin(Command *cmd) {
    if (strcmp(cmd->args[0], "cd") == 0) {
        char *path;
        if (cmd->arg_count == 1) {
            path = getenv("HOME");
        } else {
            path = cmd->args[1];
        }

        if (chdir(path) != 0) {
            perror("cd");
        }
    } else if (strcmp(cmd->args[0], "status") == 0) {
        if (WIFEXITED(last_foreground_status)) {
            printf("exit value %d\n", WEXITSTATUS(last_foreground_status));
        } else if (WIFSIGNALED(last_foreground_status)) {
            printf("terminated by signal %d\n", WTERMSIG(last_foreground_status));
        }
        fflush(stdout);
    }
}

// Execute external commands
void execute_external(Command *cmd) {
    int is_background = cmd->background && !foreground_only_mode;

    pid_t pid = fork();

    if (pid == 0) {
        // Child process

        // Set up signal handlers for child
        struct sigaction sa_int = {0};
        if (is_background) {
            sa_int.sa_handler = SIG_IGN;
        } else {
            sa_int.sa_handler = SIG_DFL;
        }
        sigaction(SIGINT, &sa_int, NULL);

        struct sigaction sa_tstp = {0};
        sa_tstp.sa_handler = SIG_IGN;
        sigaction(SIGTSTP, &sa_tstp, NULL);

        // Handle input redirection
        if (cmd->input_file != NULL) {
            int fd = open(cmd->input_file, O_RDONLY);
            if (fd == -1) {
                fprintf(stderr, "cannot open %s for input\n", cmd->input_file);
                fflush(stderr);
                exit(1);
            }
            dup2(fd, STDIN_FILENO);
            close(fd);
        } else if (is_background) {
            int fd = open("/dev/null", O_RDONLY);
            dup2(fd, STDIN_FILENO);
            close(fd);
        }

        // Handle output redirection
        if (cmd->output_file != NULL) {
            int fd = open(cmd->output_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd == -1) {
                fprintf(stderr, "cannot open %s for output\n", cmd->output_file);
                fflush(stderr);
                exit(1);
            }
            dup2(fd, STDOUT_FILENO);
            close(fd);
        } else if (is_background) {
            int fd = open("/dev/null", O_WRONLY);
            dup2(fd, STDOUT_FILENO);
            close(fd);
        }

        // Execute command
        execvp(cmd->args[0], cmd->args);

        // If exec returns, it failed
        fprintf(stderr, "%s: no such file or directory\n", cmd->args[0]);
        fflush(stderr);
        exit(1);

    } else if (pid > 0) {
        // Parent process
        if (is_background) {
            printf("background pid is %d\n", pid);
            fflush(stdout);
            background_pids[background_count++] = pid;
        } else {
            // Wait for foreground process
            int status;
            waitpid(pid, &status, 0);
            last_foreground_status = status;

            // If terminated by signal, print message
            if (WIFSIGNALED(status)) {
                printf("terminated by signal %d\n", WTERMSIG(status));
                fflush(stdout);
            }
        }
    } else {
        perror("fork");
    }
}

// Check for completed background processes
void check_background_processes(void) {
    int status;
    pid_t pid;

    // Check all background processes
    for (int i = 0; i < background_count; i++) {
        pid = waitpid(background_pids[i], &status, WNOHANG);

        if (pid > 0) {
            // Process completed
            if (WIFEXITED(status)) {
                printf("background pid %d is done: exit value %d\n",
                       pid, WEXITSTATUS(status));
            } else if (WIFSIGNALED(status)) {
                printf("background pid %d is done: terminated by signal %d\n",
                       pid, WTERMSIG(status));
            }
            fflush(stdout);

            // Remove from array
            for (int j = i; j < background_count - 1; j++) {
                background_pids[j] = background_pids[j + 1];
            }
            background_count--;
            i--;
        }
    }
}

int main(void) {
    shell_loop();
    return 0;
}
