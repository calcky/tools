#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <mqueue.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <sys/eventfd.h>
#include <sys/timerfd.h>
#include <sys/signalfd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

static void movefd(int fd, int dest) {
    assert(fd >= 0 && fd != dest);
    assert(dup2(fd, dest) == dest);
    close(fd);
}
static void *delayed_write(void *unused) {
    (void)unused;
    usleep(800000);
    assert(write(105, "wait", 4) == 4);
    return NULL;
}
static struct sockaddr_in endpoint(int fd) {
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    assert(bind(fd, (void *)&addr, sizeof(addr)) == 0);
    socklen_t len = sizeof(addr);
    assert(getsockname(fd, (void *)&addr, &len) == 0);
    return addr;
}
int main(int argc, char **argv) {
    assert(argc == 2 || argc == 3);
    char buf[8192] = {0};
    assert(read(0, buf, 1) == 1);
    if (argc == 3) {
        for (int i=0;i<20000;i++) {
            movefd(open("/dev/null",O_WRONLY),100);
            assert(write(100,buf,1) == 1);
            close(100);
            if (i%1000 == 999) usleep(100000);
        }
        usleep(300000);
        return 0;
    }
    movefd(open("/dev/null", O_WRONLY), 100);
    assert(write(100, buf, 123) == 123);
    for (int i = 0; i < 1000; i++) assert(fcntl(100, F_GETFD) >= 0);
    char path[1024];
    snprintf(path, sizeof(path), "%s/file", argv[1]);
    movefd(open(path, O_CREAT|O_TRUNC|O_RDWR, 0600), 101);
    assert(write(101, buf, 4096) == 4096);
    assert(pread(101, buf, 128, 0) == 128);
    struct iovec vec[2] = {{buf,64},{buf,32}};
    assert(writev(101, vec, 2) == 96);
    assert(pwrite(101, buf, 64, 0) == 64);
    assert(lseek(101, 0, SEEK_SET) == 0);
    assert(readv(101, vec, 2) == 96);
    assert(dup2(101, 102) == 102);
    assert(pwrite(102, buf, 11, 0) == 11);
    close(101);
    movefd(open(path, O_RDWR), 101);
    assert(write(101, buf, 7) == 7);
    close(101);
    close(102);

    int pipefd[2];
    assert(pipe(pipefd) == 0);
    movefd(pipefd[0],104); movefd(pipefd[1],105);
    pthread_t writer;
    assert(pthread_create(&writer,NULL,delayed_write,NULL) == 0);
    assert(read(104,buf,4) == 4);
    assert(pthread_join(writer,NULL) == 0);

    int pair[2];
    assert(socketpair(AF_UNIX,SOCK_STREAM,0,pair) == 0);
    movefd(pair[0],106); movefd(pair[1],107);
    assert(send(106,buf,5,0) == 5);
    assert(recv(107,buf,5,0) == 5);
    struct iovec one = {buf,7};
    struct msghdr msg = {.msg_iov=&one,.msg_iovlen=1};
    assert(sendmsg(106,&msg,0) == 7);
    assert(recvmsg(107,&msg,0) == 7);

    movefd(socket(AF_INET,SOCK_DGRAM,0),108);
    movefd(socket(AF_INET,SOCK_DGRAM,0),109);
    struct sockaddr_in a=endpoint(108),b=endpoint(109);
    assert(connect(108,(void *)&b,sizeof(b)) == 0);
    assert(connect(109,(void *)&a,sizeof(a)) == 0);
    struct iovec chunks[2] = {{buf,3},{buf,5}};
    struct mmsghdr batch[2] = {0};
    for(int i=0;i<2;i++){batch[i].msg_hdr.msg_iov=&chunks[i];batch[i].msg_hdr.msg_iovlen=1;}
    assert(sendmmsg(108,batch,2,0) == 2);
    assert(recvmmsg(109,batch,2,0,NULL) == 2);
    assert(sendto(108,buf,6,0,(void *)&b,sizeof(b)) == 6);
    assert(recvfrom(109,buf,6,0,NULL,NULL) == 6);

    int listener=socket(AF_INET,SOCK_STREAM,0);
    a=endpoint(listener);
    assert(listen(listener,1) == 0);
    movefd(socket(AF_INET,SOCK_STREAM,0),110);
    assert(connect(110,(void *)&a,sizeof(a)) == 0);
    movefd(accept(listener,NULL,NULL),111);
    close(listener);
    assert(send(110,buf,9,0) == 9);
    assert(recv(111,buf,9,0) == 9);

    char queue[64];
    snprintf(queue,sizeof(queue),"/fdtop-fixture-%d",getpid());
    mqd_t mq=mq_open(queue,O_CREAT|O_EXCL|O_RDWR|O_NONBLOCK,0600,NULL);
    assert(mq != (mqd_t)-1);
    assert(mq_unlink(queue) == 0);
    movefd(mq,112);
    assert(mq_send(112,buf,7,0) == 0);
    assert(mq_receive(112,buf,sizeof(buf),NULL) == 7);
    assert(mq_receive(112,buf,sizeof(buf),NULL) == -1 && errno == EAGAIN);
    assert(read(199,buf,1) == -1 && errno == EBADF);

    movefd(open(path,O_RDONLY),113);
    assert(socketpair(AF_UNIX,SOCK_STREAM,0,pair) == 0);
    movefd(pair[0],114); movefd(pair[1],115);
    assert(sendfile(114,113,NULL,32) == 32);
    assert(read(115,buf,32) == 32);
    assert(pipe(pipefd) == 0);
    movefd(pipefd[0],116); movefd(pipefd[1],117);
    assert(pipe(pipefd) == 0);
    movefd(pipefd[0],118); movefd(pipefd[1],119);
    assert(write(117,buf,16) == 16);
    assert(tee(116,119,16,0) == 16);
    assert(read(118,buf,16) == 16);
    assert(splice(116,NULL,119,NULL,16,0) == 16);
    assert(read(118,buf,16) == 16);
    snprintf(path,sizeof(path),"%s/copy",argv[1]);
    movefd(open(path,O_CREAT|O_TRUNC|O_RDWR,0600),120);
    assert(copy_file_range(113,NULL,120,NULL,24,0) == 24);
    movefd(eventfd(0, EFD_NONBLOCK), 121);
    uint64_t counter = 100;
    assert(write(121, &counter, sizeof(counter)) == 8);
    assert(read(121, &counter, sizeof(counter)) == 8 && counter == 100);
    assert(read(121, &counter, sizeof(counter)) == -1 && errno == EAGAIN);
    close(121);

    movefd(timerfd_create(CLOCK_MONOTONIC, 0), 122);
    struct itimerspec timer = {.it_value = {.tv_nsec = 1000000}};
    assert(timerfd_settime(122, 0, &timer, NULL) == 0);
    assert(read(122, &counter, sizeof(counter)) == 8 && counter == 1);
    close(122);

    sigset_t signals, previous;
    sigemptyset(&signals);
    sigaddset(&signals, SIGUSR1);
    assert(pthread_sigmask(SIG_BLOCK, &signals, &previous) == 0);
    movefd(signalfd(-1, &signals, SFD_NONBLOCK), 123);
    assert(kill(getpid(), SIGUSR1) == 0);
    struct signalfd_siginfo info;
    assert(read(123, &info, sizeof(info)) == (ssize_t)sizeof(info));
    assert(info.ssi_signo == SIGUSR1);
    close(123);
    assert(pthread_sigmask(SIG_SETMASK, &previous, NULL) == 0);
    usleep(400000);
    return 0;
}
