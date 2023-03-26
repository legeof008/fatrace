
#include <stdio.h>

int main(int argc, char **argv) {
  int fan_fd = -1;
  int res;
  void *buffer;
  struct fanotify_event_metadata *data;
  struct sigaction sa;
  struct timeval event_time;

  /* always ignore events from ourselves (writing log file) */
  ignored_pids[ignored_pids_len++] = getpid();

  parse_args(argc, argv);

#ifdef FAN_REPORT_FID
  fan_fd = fanotify_init(FAN_CLASS_NOTIF | FAN_REPORT_FID, O_LARGEFILE);
  if (fan_fd >= 0)
    fid_mode = 1;

  if (fan_fd < 0 && errno == EINVAL)
    debug("FAN_REPORT_FID not available");
#endif
  if (fan_fd < 0)
    fan_fd = fanotify_init(0, O_LARGEFILE);

  if (fan_fd < 0) {
    int e = errno;
    perror("Cannot initialize fanotify");
    if (e == EPERM)
      fputs("You need to run this program as root.\n", stderr);
    exit(EXIT_FAILURE);
  }

  setup_fanotify(fan_fd);

  /* allocate memory for fanotify */
  buffer = NULL;
  res = posix_memalign(&buffer, 4096, BUFSIZE);
  if (res != 0 || buffer == NULL)
    err(EXIT_FAILURE, "Failed to allocate buffer");

  /* output file? */
  if (option_output) {
    int fd = open(option_output, O_CREAT | O_WRONLY | O_EXCL, 0666);
    if (fd < 0)
      err(EXIT_FAILURE, "Failed to open output file");
    fflush(stdout);
    dup2(fd, STDOUT_FILENO);
    close(fd);
  }

  /* useful for live tailing and multiple writers */
  setlinebuf(stdout);

  /* setup signal handler to cleanly stop the program */
  sa.sa_handler = signal_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;
  if (sigaction(SIGINT, &sa, NULL) < 0)
    err(EXIT_FAILURE, "sigaction");

  /* set up --time alarm */
  if (option_timeout > 0) {
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGALRM, &sa, NULL) < 0)
      err(EXIT_FAILURE, "sigaction");
    alarm(option_timeout);
  }

  /* clear event time if timestamp is not required */
  if (!option_timestamp) {
    memset(&event_time, 0, sizeof(struct timeval));
  }

  /* read all events in a loop */
  while (running) {
    res = read(fan_fd, buffer, BUFSIZE);
    if (res == 0) {
      fprintf(stderr, "No more fanotify event (EOF)\n");
      break;
    }
    if (res < 0) {
      if (errno == EINTR)
        continue;
      err(EXIT_FAILURE, "read");
    }

    /* get event time, if requested */
    if (option_timestamp) {
      if (gettimeofday(&event_time, NULL) < 0)
        err(EXIT_FAILURE, "gettimeofday");
    }

    data = (struct fanotify_event_metadata *)buffer;
    while (FAN_EVENT_OK(data, res)) {
      if (data->vers != FANOTIFY_METADATA_VERSION)
        errx(EXIT_FAILURE, "Mismatch of fanotify metadata version");
      print_event(data, &event_time);
      data = FAN_EVENT_NEXT(data, res);
    }
  }
}
