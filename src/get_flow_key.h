#ifndef GET_FLOW_KEY_H
#define GET_FLOW_KEY_H


#include <uapi/linux/ptrace.h>
#include <linux/tcp.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/sched.h>
#include <net/inet_sock.h>

struct data_ipv4 {
    u32 pid;
    u32 tgid;
    char comm[TASK_COMM_LEN];
    u16 family;
    u16 type;
    u16 state;
    u16 protocol;
    u32 saddr;
    u32 daddr;
    u16 sport; // source-listenign port
    u16 dport;
    u16 inner_state;
    u64 ts_us;
};

struct data_ipv6 {
    u32 pid;
    u32 tgid;
    char comm[TASK_COMM_LEN];
    u16 family;
    u16 type;
    u16 state;
    u16 protocol;
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u16 sport; // source-listenign port
    u16 dport;
    u16 inner_state;
    u64 ts_us;
};

int new_ipv4_socket_entry(struct pt_regs *ctx, struct net *net, struct socket *sock);
int new_ipv4_socket_return(struct pt_regs *ctx);
int new_ipv6_socket_entry(struct pt_regs *ctx, struct net *net, struct socket *sock, int protocol, int kern);
int new_ipv6_socket_return(struct pt_regs *ctx);
int tcp_connect_entry(struct pt_regs *ctx, struct sock *sk);
int tcp_connect_return(struct pt_regs *ctx);
int connect_udp_entry(struct pt_regs *ctx, struct socket *sock, struct sockaddr *uaddr, int addr_len, int flags);
int connect_udp_return(struct pt_regs *ctx, struct socket *sock, struct sockaddr *uaddr, int addr_len, int flags);



#endif // GET_FLOW_KEY_H