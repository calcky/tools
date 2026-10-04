#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static int input;
static atomic_int done;
static uint64_t received;
static int reader_cpu;
static double now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}
static void check(int r) { if (r < 0) { perror("benchmark"); exit(1); } }
static void pin(int cpu) {
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    check(sched_setaffinity(0, sizeof(set), &set));
}
static void *reader(void *unused) {
    (void)unused;
    pin(reader_cpu);
    char buf[4096];
    for (;;) {
        ssize_t n = read(input, buf, sizeof(buf));
        if (n > 0) received += n;
        else if (!n || atomic_load(&done)) break;
        else if (errno != EAGAIN && errno != EINTR) { check(-1); }
    }
    return NULL;
}
int main(int argc, char **argv) {
    if (argc != 3) return 2;
    int file = !strcmp(argv[1], "file"), udp = !strcmp(argv[1], "udp");
    int out, pair[2];
    pthread_t thread;
    char buf[4096] = {0};
    size_t size = udp ? 1472 : sizeof(buf);
    if (file) {
        char path[] = "/tmp/fdtop-bench-XXXXXX";
        out = mkstemp(path); check(out); unlink(path);
        check(ftruncate(out, 1024 * 1024));
    } else if (!strcmp(argv[1], "pipe")) {
        check(pipe(pair)); input = pair[0]; out = pair[1];
    } else {
        int listener = socket(AF_INET, udp ? SOCK_DGRAM : SOCK_STREAM, 0);
        check(listener);
        struct sockaddr_in addr = {.sin_family=AF_INET, .sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
        check(bind(listener, (void *)&addr, sizeof(addr)));
        socklen_t len = sizeof(addr);
        check(getsockname(listener, (void *)&addr, &len));
        if (!udp) check(listen(listener, 1));
        out = socket(AF_INET, udp ? SOCK_DGRAM : SOCK_STREAM, 0); check(out);
        check(connect(out, (void *)&addr, len));
        input = udp ? listener : accept(listener, NULL, NULL); check(input);
        if (!udp) close(listener);
        struct timeval timeout = {.tv_usec=100000};
        check(setsockopt(input, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)));
    }
    if (read(STDIN_FILENO, buf, 1) != 1) return 3;
    cpu_set_t allowed;
    check(sched_getaffinity(0, sizeof(allowed), &allowed));
    int writer_cpu = -1;
    for (int cpu = 0; cpu < CPU_SETSIZE; cpu++) {
        if (!CPU_ISSET(cpu, &allowed)) continue;
        if (writer_cpu < 0) writer_cpu = reader_cpu = cpu;
        else { reader_cpu = cpu; break; }
    }
    if (!file && pthread_create(&thread, NULL, reader, NULL)) return 4;
    pin(writer_cpu);
    double start = now(), duration = atof(argv[2]);
    uint64_t sent = 0, calls = 0;
    do {
        for (int i=0; i<256; i++) {
            ssize_t n = file ? pwrite(out, buf, size, sent % (1024*1024)) : write(out, buf, size);
            check((int)n); sent += n; calls++;
            if (file) { n = pread(out, buf, size, (sent-size) % (1024*1024)); check((int)n); received += n; calls++; }
        }
    } while (now() - start < duration);
    double elapsed = now() - start;
    close(out);
    atomic_store(&done, 1);
    if (!file) { pthread_join(thread, NULL); close(input); }
    struct rusage ru;
    getrusage(RUSAGE_SELF, &ru);
    double cpu = ru.ru_utime.tv_sec + ru.ru_utime.tv_usec/1e6 + ru.ru_stime.tv_sec + ru.ru_stime.tv_usec/1e6;
    printf("{\"seconds\":%.6f,\"sent\":%lu,\"received\":%lu,\"sender_calls\":%lu,\"cpu_seconds\":%.6f}\n", elapsed, sent, received, calls, cpu);
    return 0;
}
