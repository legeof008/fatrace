//
// Created by maciek on 3/26/23.
//

#ifndef FATRACE_SAMPLE_H
#define FATRACE_SAMPLE_H

#include <ctype.h>
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <mntent.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fanotify.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/sysmacros.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

const char *mask2str(uint64_t mask);
bool show_pid(pid_t pid);
void print_event(const struct fanotify_event_metadata *data,
                 const struct timeval *event_time);
void do_mark(int fan_fd, const char *dir, bool fatal);
void setup_fanotify(int fan_fd);
void help(void);
void parse_args(int argc, char **argv);
void signal_handler(int signal);
#endif // FATRACE_SAMPLE_H
