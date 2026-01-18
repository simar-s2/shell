#define _POSIX_C_SOURCE 200809L
#include "../include/msgs.h"
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAX_COMMAND_LENGTH 256
#define MAX_TOKENS 128
#define HISTORY_SIZE 10

char *history[HISTORY_SIZE];
int history_count = 0;

static void write_string(const char *s) { write(STDOUT_FILENO, s, strlen(s)); }
static void write_error(const char *s) { write(STDERR_FILENO, s, strlen(s)); }

static void print_prompt(void) {
  char cwd[PATH_MAX];
  if (getcwd(cwd, sizeof(cwd)) == NULL) {
    perror(GETCWD_ERROR_MSG);
    return;
  }
  write_string(cwd);
  write_string("$ ");
}

static void trim_newline(char *s) {
  if (!s)
    return;
  size_t n = strlen(s);
  if (n == 0)
    return;
  if (s[n - 1] == '\n')
    s[n - 1] = '\0';
}

static int tokenize(char *line, char *argv[], int max_tokens) {
  char *saveptr = NULL;
  int argc = 0;
  for (char *tok = strtok_r(line, " \t\n", &saveptr);
       tok != NULL && argc < max_tokens - 1;
       tok = strtok_r(NULL, " \t\n", &saveptr)) {
    argv[argc++] = tok;
  }
  argv[argc] = NULL;
  return argc;
}

static void reap_zombies(void) {
  int status;
  pid_t wpid;

  while ((wpid = waitpid(-1, &status, WNOHANG)) > 0) {
    (void)wpid;
  }
  if (wpid == -1 && errno != ECHILD) {
    write_error("shell: unable to wait for child\n");
  }
}

void sigint_handler(int signum) {
  (void)signum;
  write_string("\n");
  write_string("exit: exit the shell\n");
  write_string("pwd: print current directory\n");
  write_string("cd: change current directory\n");
  write_string("help: display help information\n");
  write_string("history: display the command history\n");
  char cwd[PATH_MAX];
  if (getcwd(cwd, sizeof(cwd)) != NULL) {
    write(STDOUT_FILENO, cwd, strlen(cwd));
    write_string("$ ");
  }
}

void add_to_history(const char *cmd) {
  if (cmd == NULL || cmd[0] == '\0')
    return;
  long slot = history_count % HISTORY_SIZE;
  free(history[slot]);
  history[slot] = strdup(cmd);
  history_count++;
}

static void show_history(void) {
  int start = history_count > HISTORY_SIZE ? history_count - HISTORY_SIZE : 0;
  for (int i = history_count - 1; i >= start; --i) {
    int idx = i % HISTORY_SIZE;
    if (history[idx] != NULL) {
      char buf[20];
      sprintf(buf, "%d", i);
      write_string(buf);
      write_string("\t");
      write_string(history[idx]);
      write_string("\n");
    }
  }
}

static const char *get_history_command(int n) {
  int start = (history_count > HISTORY_SIZE) ? history_count - HISTORY_SIZE : 0;
  int end = history_count - 1;

  if (n < start || n > end) {
    return NULL;
  }

  int idx = n % HISTORY_SIZE;
  return history[idx];
}

int handle_internal(char *argv[], int argc) {

  if (strcmp(argv[0], "history") == 0) {
    if (argc > 1) {
      write_error("history: too many arguments\n");
      return 1;
    } else {
      show_history();
      return 1;
    }
  }

  if (strcmp(argv[0], "exit") == 0) {
    if (argc > 1) {
      write_error("exit: too many arguments\n");
      return 1;
    } else {
      exit(0);
    }
    return 1;
  }

  else if (strcmp(argv[0], "pwd") == 0) {
    if (argc > 1) {
      write_error("pwd: too many arguments\n");
      return 1;
    } else {
      char cwd[PATH_MAX] = {};
      if (getcwd(cwd, sizeof(cwd)) == NULL) {
        perror(GETCWD_ERROR_MSG);
      }
      write_string(cwd);
      write_string("\n");
    }
    return 1;
  }

  else if (strcmp(argv[0], "help") == 0) {
    if (argc > 2) {
      write_error("help: too many arguments\n");
      return 1;
    }

    if (argc == 1) {
      write_string("exit: exit the shell\n");
      write_string("pwd: print current directory\n");
      write_string("cd: change current directory\n");
      write_string("help: display help information\n");
      write_string("history: display the command history\n");

      return 1;
    } else {
      const char *cmd = argv[1];
      if (strcmp(cmd, "exit") == 0)
        printf("exit: exit the shell\n");
      else if (strcmp(cmd, "pwd") == 0)
        printf("pwd: display the current working directory\n");
      else if (strcmp(cmd, "cd") == 0)
        write_string("cd: change the current directory\n");
      else if (strcmp(cmd, "help") == 0)
        write_string("help: display help information on internal commands\n");
      else if (strcmp(cmd, "history") == 0)
        write_string("history: display the command history\n");
      else {
        write_string(cmd);
        write_string(": external command or application\n");
      }
      return 1;
    }
  }

  if (strcmp(argv[0], "cd") == 0) {
    static char old_pwd[PATH_MAX] = "";
    static int old_pwd_set = 0;

    if (argc > 2) {
      write_error("cd: too many arguments\n");
      return 1;
    }

    char cwd[PATH_MAX];
    char target_dir[PATH_MAX];

    if (getcwd(cwd, sizeof(cwd)) == NULL) {
      write_error("cd: unable to get current directory\n");
      return 1;
    }

    const char *path_arg = (argc == 2) ? argv[1] : NULL;

    // case cd or cd ~
    if (path_arg == NULL || strcmp(path_arg, "~") == 0) {
      struct passwd *pw = getpwuid(getuid());
      if (!pw) {
        write_error("cd: unable to change directory\n");
        return 1;
      }
      strncpy(target_dir, pw->pw_dir, sizeof(target_dir) - 1);
    }

    // case cd -
    else if (strcmp(path_arg, "-") == 0) {
      if (!old_pwd_set) {
        write_error("cd: unable to change directory\n");
        return 1;
      }
      strncpy(target_dir, old_pwd, sizeof(target_dir) - 1);
    }

    // case cd ~/
    else if (path_arg[0] == '~') {
      struct passwd *pw = getpwuid(getuid());
      if (!pw) {
        write_error("cd: unable to change directory\n");
        return 1;
      }
      if (path_arg[1] == '\0')
        strncpy(target_dir, pw->pw_dir, sizeof(target_dir) - 1);
      else if (path_arg[1] == '/')
        snprintf(target_dir, sizeof(target_dir), "%s%s", pw->pw_dir,
                 &path_arg[1]);
      else
        strncpy(target_dir, path_arg, sizeof(target_dir) - 1);
      // cd some path
    } else {
      strncpy(target_dir, path_arg, sizeof(target_dir) - 1);
    }

    target_dir[sizeof(target_dir) - 1] = '\0';

    if (chdir(target_dir) == -1) {
      write_error("cd: unable to change directory\n");
    } else {
      strncpy(old_pwd, cwd, sizeof(old_pwd) - 1);
      old_pwd[PATH_MAX - 1] = '\0';
      old_pwd_set = 1;
    }

    return 1;
  }

  return 0;
}

int main() {
  char command[MAX_COMMAND_LENGTH];
  ssize_t nread;
  char *argv[MAX_TOKENS];
  int from_history = 0;

  signal(SIGINT, sigint_handler);

  while (1) {
    print_prompt();

    nread = read(STDIN_FILENO, command, sizeof(command) - 1);
    if (nread < 0) {
      write(STDERR_FILENO, "shell: unable to read command\n", 30);
      continue;
    } else if (nread == 0) {
      write_string("\n");
      break;
    }

    command[nread] = '\0';
    trim_newline(command);

    char *p = command;
    while (*p == ' ' || *p == '\t' || *p == '\n') {
      ++p;
    }
    if (*p == '\0') {
      reap_zombies();
      continue;
    }

    if (p[0] == '!') {
      if (strcmp(p, "!!") == 0) {
        if (history_count == 0) {
          write_error("history: no command entered\n");
          continue;
        }
        int last_idx = (history_count - 1) % HISTORY_SIZE;
        write_string(history[last_idx]);
        write_string("\n");

        strncpy(command, history[last_idx], MAX_COMMAND_LENGTH - 1);
        command[MAX_COMMAND_LENGTH - 1] = '\0';
        add_to_history(history[last_idx]);
        from_history = 1;
      } else {
        if (!isdigit(p[1])) {
          write_error("history: command invalid\n");
          continue;
        }

        int n = atoi(&command[1]);
        const char *hist_cmd = get_history_command(n);
        if (!hist_cmd) {
          write_error("history: command invalid\n");
          continue;
        }

        write_string(hist_cmd);
        write_string("\n");
        strncpy(command, hist_cmd, MAX_COMMAND_LENGTH - 1);
        command[MAX_COMMAND_LENGTH - 1] = '\0';
        add_to_history(hist_cmd);
        from_history = 1;
      }
    }

    if (!from_history) {
      char raw_copy[MAX_COMMAND_LENGTH];
      strncpy(raw_copy, p, sizeof(raw_copy) - 1);
      raw_copy[sizeof(raw_copy) - 1] = '\0';
      add_to_history(raw_copy);
    } else {
      from_history = 0;
    }

    char line_copy[MAX_COMMAND_LENGTH];
    strncpy(line_copy, p, sizeof(line_copy));
    line_copy[sizeof(line_copy) - 1] = '\0';

    int argc = tokenize(line_copy, argv, MAX_TOKENS);
    if (argc == 0) {
      reap_zombies();
      continue;
    }

    int background = 0;
    if (argv > 0 && strcmp(argv[argc - 1], "&") == 0) {
      background = 1;
      argv[argc - 1] = NULL;
      argc--;
      if (argc == 0) {
        reap_zombies();
        continue;
      }
    }

    if (!handle_internal(argv, argc)) {

      pid_t pid = fork();

      if (pid == -1) {
        write_error("unable to fork\n");
        reap_zombies();
        continue;
      } else if (pid == 0) {
        if (execvp(argv[0], argv) == -1) {
          write_error("shell: unable to execute command\n");
        }
        exit(EXIT_FAILURE);
      } else {
        if (!background) {
          int status;
          if (waitpid(pid, &status, 0) == -1) {
            perror(WAIT_ERROR_MSG);
          }
        } else {
        }
        reap_zombies();
      }
    }
  }
  for (long i = 0; i < HISTORY_SIZE; ++i) {
    free(history[i]);
    history[i] = NULL;
  }
  return 0;
}
