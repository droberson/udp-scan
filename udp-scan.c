/* udp-scan.c -- non-privileged UDP port scanner
 *  by Daniel Roberson @dmfroberson August/2017
 *
 * This is far from perfect. Reports as open if filtered however.
 *
 * TODO:
 * - use /etc/services for "fast" scan
 * - specify ports
 * - specify threads
 * - multiple hosts/cidr
 * - randomize order of ports scanned
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <strings.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define DIE(x) { perror(x); exit (EXIT_FAILURE); }

int			threadcount = 0;
int			done = 1;
pthread_mutex_t		lock = PTHREAD_MUTEX_INITIALIZER;
char			open_ports[65535];


struct scanargs {
  char			*host;
  unsigned short	port;
};


void check_udp_port(char *host, unsigned short port) {
  int			sock;
  int			result;
  int			open;
  fd_set		s;
  struct sockaddr_in	sin;
  struct timeval	timeout;


  sin.sin_family = AF_INET;
  sin.sin_port = htons(port);
  inet_pton(AF_INET, host, &sin.sin_addr.s_addr);

  sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (sock == -1)
    DIE("socket()");

  if (connect(sock, (struct sockaddr *)&sin, sizeof(struct sockaddr_in)) == 0) {
    FD_ZERO(&s);
    FD_SET(sock, &s);

    timeout.tv_sec = 5;
    timeout.tv_usec = 0;

    send(sock, NULL, 0, 0);

    result = select(sock + 1, &s, NULL, NULL, &timeout);
    switch(result) {
    case 1:
      open = 0;
      break;

    case 0: // timeout
      open = 1;
      break;

    case -1:
      DIE("select()");
    }
  }

  close(sock);

  if (open == 1)
    open_ports[port] = 1;
}


void *thread_task(void *threadargs) {
  struct scanargs	*args;

  args = threadargs;

  pthread_mutex_lock(&lock);
  threadcount++;
  pthread_mutex_unlock(&lock);

  pthread_detach(pthread_self());

  check_udp_port(args->host, args->port);

  pthread_mutex_lock(&lock);
  threadcount--;
  pthread_mutex_unlock(&lock);

  pthread_exit(NULL);
}


int main(int argc, char *argv[]) {
  pthread_t		thread;
  struct scanargs	args;

  int i;

  bzero(open_ports, sizeof(open_ports));

  if (argc < 2) {
    fprintf(stderr, "usage: %s <host>\n", argv[0]);
    return EXIT_SUCCESS;
  }

  for (i = 1; i <= 1024; i++) {
    args.host = argv[1];
    args.port = i;

    while (threadcount >= 128); // wait for threads to become available
    pthread_create(&thread, NULL, thread_task, &args);
  }

  while (threadcount); // wait for threads to finish

  /* Display results */
  for(i = 0; i < sizeof(open_ports); i++) {
    if (open_ports[i] == 1)
      printf("%d\n", i);
  }

  return EXIT_SUCCESS;
}
