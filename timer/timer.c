#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/time.h>
#include <signal.h>
#include <unistd.h>

#define INTERVAL 2              // number of seconds to go off

void TimerSet(int);

void TimerStop(int signum) {
  printf("Timer ran out! Stopping timer\n");
  TimerSet(INTERVAL);
}

void TimerSet(int interval) {
  printf("starting timer\n");
  struct itimerval it_val;

  it_val.it_value.tv_sec = interval;
  it_val.it_value.tv_usec = 0;
  it_val.it_interval.tv_sec = 0;
  it_val.it_interval.tv_usec = 0;

  if (signal(SIGALRM, TimerStop) == SIG_ERR) {
    perror("Unable to catch SIGALRM");
    exit(1);
  }
  if (setitimer(ITIMER_REAL, &it_val, NULL) == -1) {
    perror("error calling setitimer()");
    exit(1);
  }
}

int main(int argc, char *argv[]) {

  TimerSet(INTERVAL);

  while (1) {
    // do stuff
  }
  return 0;
}
