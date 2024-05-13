/*
    Contains definition of structures for IPv4 and IPv6 events.
    Declare hash maps to store values of structs socket, sock and msghdr.

    Licensed under the Apache License, Version 2.0 (the "License")

    __author__ = Branislav Dubec
    __version__ = 1.0.5
*/



#ifndef DETECT_NEW_CONNECTIONS
#define DETECT_NEW_CONNECTIONS


#include <uapi/linux/ptrace.h>
#include <linux/tcp.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/sched.h>
#include <net/inet_sock.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/skbuff.h>
#include <uapi/linux/ip.h>

struct data_ipv4 {
    u32 pid;
    u32 tgid;
    char comm[TASK_COMM_LEN];
    u16 family;
    u16 type;
    u16 state; // TCP state
    u16 protocol;
    u32 saddr;
    u32 daddr;
    u16 sport; // source-listenign port
    u16 dport;
};

struct data_ipv6 {
    u32 pid;
    u32 tgid;
    char comm[TASK_COMM_LEN];
    u16 family;
    u16 type;
    u16 state; // TCP state
    u16 protocol;
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u16 sport; // source-listenign port
    u16 dport;
};

BPF_HASH(new_socket, u64, struct socket *);
BPF_HASH(new_sock, u64, struct sock *);
BPF_HASH(new_msg, u64, struct msghdr *);

BPF_PERF_OUTPUT(ipv4events);
BPF_PERF_OUTPUT(ipv6events);



#endif // DETECT_NEW_CONNECTIONS