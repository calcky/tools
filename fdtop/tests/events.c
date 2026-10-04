#define _GNU_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <mqueue.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/prctl.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <unistd.h>

static void report(const char *name,int fd) { assert(fd>=0); printf("%s %d\n",name,fd); fflush(stdout); }
int main(int argc,char **argv) {
    assert(argc==2);
    prctl(PR_SET_NAME,"fd-event-case",0,0,0);
    puts("READY"); fflush(stdout); assert(getchar()!=EOF);
    char path[256]; snprintf(path,sizeof(path),"%s/short",argv[1]);
    for(int i=0;i<3;i++) { int fd=open(path,O_CREAT|O_RDWR,0600); report("FILE",fd); close(fd); unlink(path); }
    int fd=eventfd(0,0); report("EVENTFD",fd);
    int copy=dup(fd); report("DUP",copy);
    int other=timerfd_create(CLOCK_MONOTONIC,0); report("TIMERFD",other);
    assert(dup2(fd,other)==other); report("REPLACE",other);
    assert(dup2(fd,fd)==fd);
    assert(dup2(-1,other)==-1);
    close(copy);close(other);
    assert(fcntl(fd,F_DUPFD,150)==150);report("RANGE",150);
    assert(syscall(SYS_close_range,150,150,0)==0);
    assert(dup3(fd,160,O_CLOEXEC)==160);report("CLOEXEC",160);
    int pipefd[2];assert(pipe2(pipefd,0)==0);report("PIPE",pipefd[0]);report("PIPE",pipefd[1]);close(pipefd[0]);close(pipefd[1]);
    int pair[2];assert(socketpair(AF_UNIX,SOCK_DGRAM,0,pair)==0);report("UNIX",pair[0]);report("UNIX",pair[1]);
    char data='x',control[CMSG_SPACE(sizeof(int))]={0};struct iovec io={&data,1};
    struct msghdr msg={.msg_iov=&io,.msg_iovlen=1,.msg_control=control,.msg_controllen=sizeof(control)};
    struct cmsghdr *c=CMSG_FIRSTHDR(&msg);c->cmsg_level=SOL_SOCKET;c->cmsg_type=SCM_RIGHTS;c->cmsg_len=CMSG_LEN(sizeof(int));memcpy(CMSG_DATA(c),&fd,sizeof(fd));
    assert(sendmsg(pair[0],&msg,0)==1);memset(control,0,sizeof(control));assert(recvmsg(pair[1],&msg,0)==1);
    int received;memcpy(&received,CMSG_DATA(CMSG_FIRSTHDR(&msg)),sizeof(received));report("RECEIVED",received);close(received);close(pair[0]);close(pair[1]);
    int udp=socket(AF_INET,SOCK_DGRAM,0);report("UDP",udp);struct sockaddr_in addr={.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
    assert(bind(udp,(struct sockaddr*)&addr,sizeof(addr))==0);close(udp);
    int server=socket(AF_INET,SOCK_STREAM,0);report("TCP",server);assert(bind(server,(struct sockaddr*)&addr,sizeof(addr))==0);assert(listen(server,1)==0);
    socklen_t len=sizeof(addr);assert(getsockname(server,(struct sockaddr*)&addr,&len)==0);
    int client=socket(AF_INET,SOCK_STREAM,0);report("TCP",client);assert(connect(client,(struct sockaddr*)&addr,len)==0);
    int accepted=accept(server,0,0);report("ACCEPT",accepted);close(accepted);close(client);close(server);
    int ep=epoll_create1(0);report("EPOLL",ep);close(ep);
    sigset_t mask;sigemptyset(&mask);sigaddset(&mask,SIGUSR1);assert(sigprocmask(SIG_BLOCK,&mask,0)==0);
    int sig=signalfd(-1,&mask,0);report("SIGNALFD",sig);close(sig);
    char mqname[64];snprintf(mqname,sizeof(mqname),"/fd-events-%d",getpid());struct mq_attr attr={.mq_maxmsg=2,.mq_msgsize=16};
    mqd_t mq=mq_open(mqname,O_CREAT|O_EXCL|O_RDWR,0600,&attr);report("MQ",mq);mq_close(mq);mq_unlink(mqname);
    union bpf_attr bpf={.map_type=BPF_MAP_TYPE_ARRAY,.key_size=4,.value_size=8,.max_entries=1};
    int map=syscall(SYS_bpf,BPF_MAP_CREATE,&bpf,sizeof(bpf));report("BPFMAP",map);close(map);
    int xsk=socket(44,SOCK_RAW,0);report("XSK",xsk);close(xsk);
    pid_t child=fork();assert(child>=0);if(child==0)_exit(0);assert(waitpid(child,0,0)==child);
    report("EXIT",fd);
    execl("/bin/true","true",NULL); return 2;
}
