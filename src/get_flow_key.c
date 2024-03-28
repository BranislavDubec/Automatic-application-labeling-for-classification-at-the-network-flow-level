#include "get_flow_key.h"

BPF_HASH(new_socket, u64, struct socket *);
BPF_HASH(new_sock, u64, struct sock *);

BPF_PERF_OUTPUT(ipv4events);
BPF_PERF_OUTPUT(ipv6events);

//Debug logs, written in stdout
BPF_PERF_OUTPUT(ipv4eventsdebug);
BPF_PERF_OUTPUT(ipv6eventsdebug);


// Creation of inet_socket, entry function -> before this function is called
// Updates eBPF map with pointer of current socket with its pid_tgid
int new_ipv4_socket_entry(struct pt_regs *ctx, struct net *net, struct socket *sock) {

    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    new_socket.update(&pid_tgid, &sock);
    
    return 0;
}

// Creation of inet_socket, close function -> function is done and returns
int new_ipv4_socket_return(struct pt_regs *ctx) {
    struct data_ipv4 data = {};

    int ret = PT_REGS_RC(ctx);
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();

    struct socket **socketpp;
    socketpp = new_socket.lookup(&pid_tgid);

    if (socketpp == 0) {
    bpf_trace_printk("missed_entry in ipv4 socket creation");
        return 0;   // missed entry
    }

    if (ret != 0) {
        bpf_trace_printk("error return create ipv4 socket %d", ret);
        new_socket.delete(&pid_tgid);
        return 0;
    }

    struct socket *socketp = *socketpp;
    struct sock *inett = (struct sock *)socketp->sk;

    struct inet_sock *inet = (struct inet_sock *) inett;
    data.pid = pid_tgid >> 32;
    data.tgid = pid_tgid;

    bpf_get_current_comm(data.comm, sizeof(data.comm));

        


    data.family = socketp->sk->sk_family;
    

    data.state = socketp->sk->sk_state;
    data.type = socketp->sk->sk_type;
    data.protocol = socketp->sk->sk_protocol;

    data.saddr = inet->inet_rcv_saddr;;
    data.daddr = socketp->sk->__sk_common.skc_daddr;

    data.sport  = socketp->sk->__sk_common.skc_num;

    data.dport = socketp->sk->__sk_common.skc_dport;
    data.dport = ntohs(data.dport);
    data.ts_us = ts;
    data.inner_state = 1;   

    ipv4eventsdebug.perf_submit(ctx, &data, sizeof(data));
    
    return 0;
}


// Creation of inet6_socket, entry function -> before this function is called
// Updates eBPF map with pointer of current socket with its pid_tgid
int new_ipv6_socket_entry(struct pt_regs *ctx, struct net *net, struct socket *sock, int protocol, int kern) {

    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    new_socket.update(&pid_tgid, &sock);
    
    return 0;
}

// Creation of inet_socket, close function -> function is done and returns
int new_ipv6_socket_return(struct pt_regs *ctx) {
    struct data_ipv6 data = {};

    int ret = PT_REGS_RC(ctx);
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();

    struct socket **socketpp;
    socketpp = new_socket.lookup(&pid_tgid);

    if (socketpp == 0) {
        bpf_trace_printk("missed_entry in ipv6 socket creation");
        return 0;   // missed entry
    }

    if (ret != 0) {
        bpf_trace_printk("error return create ipv6 socket %d", ret);
        new_socket.delete(&pid_tgid);
        return 0;
    }

    struct socket *socketp = *socketpp;
    struct sock *inett = (struct sock *)socketp->sk;

    struct inet_sock *inet = (struct inet_sock *) inett;
    data.pid = pid_tgid >> 32;
    data.tgid = pid_tgid;

    bpf_get_current_comm(data.comm, sizeof(data.comm));

        


    data.family = socketp->sk->sk_family;
    

    data.state = socketp->sk->sk_state;
    data.type = socketp->sk->sk_type;
    data.protocol = socketp->sk->sk_protocol;

    bpf_probe_read_kernel(&data.saddr, sizeof(data.saddr),
                           socketp->sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
    bpf_probe_read_kernel(&data.daddr, sizeof(data.daddr),
                           socketp->sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);

    data.sport  = socketp->sk->__sk_common.skc_num;

    data.dport = socketp->sk->__sk_common.skc_dport;
    data.dport = ntohs(data.dport);
    data.ts_us = ts;
    data.inner_state = 3;   

    ipv6eventsdebug.perf_submit(ctx, &data, sizeof(data));
    
    return 0;
}


int tcp_connect_entry(struct pt_regs *ctx, struct sock *sk)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    new_sock.update(&pid_tgid, &sk);
    return 0;
}

int tcp_connect_return(struct pt_regs *ctx)
{

    int ret = PT_REGS_RC(ctx);

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tgid = pid_tgid;
    u64 ts = bpf_ktime_get_ns();

    struct sock **skpp;
    skpp = new_sock.lookup(&pid_tgid);
    if (skpp == 0) {
    bpf_trace_printk("missed_entry in tcp socket connect return");
        return 0;   // missed entry
    }
    if (ret != 0) {
        // failed to send SYNC packet, may not have populated
        // socket __sk_common.{skc_rcv_saddr, ...}
        bpf_trace_printk("tcp connect return %d", ret);
        return 0;
    }

    struct sock *skp = *skpp;
    u16 lport = skp->__sk_common.skc_num;
    u16 dport = skp->__sk_common.skc_dport;
    u16 family = skp->sk_family;
    if (family == AF_INET){
        struct data_ipv4 data = {};
        bpf_get_current_comm(data.comm, sizeof(data.comm));
        data.family = family;
        data.type = skp->sk_type;
        data.state = skp->sk_state;
        data.sport = lport;
        data.dport = ntohs(dport);
        data.pid = pid;
        data.tgid = tgid;
        data.inner_state = 1000;
        data.ts_us = ts;
        data.saddr = skp->__sk_common.skc_rcv_saddr;
        data.daddr = skp->__sk_common.skc_daddr;
        ipv4events.perf_submit(ctx, &data, sizeof(data));
        return 0;
    } else {
        struct data_ipv6 data = {};
        bpf_get_current_comm(data.comm, sizeof(data.comm));
        data.family = family;
        data.type = skp->sk_type;
        data.state = skp->sk_state;
        data.sport = lport;
        data.dport = ntohs(dport);
        data.pid = pid;
        data.tgid = tgid;
        data.inner_state = 1000;
        data.ts_us = ts;
        bpf_probe_read_kernel(&data.saddr, sizeof(data.saddr),
                           &skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&data.daddr, sizeof(data.daddr),
                           &skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        ipv6events.perf_submit(ctx, &data, sizeof(data));
        return 0;
    }

}

int connect_udp_entry(struct pt_regs *ctx, struct socket *sock, struct sockaddr *uaddr,
		       int addr_len, int flags)
{

    u64 pid_tgid = bpf_get_current_pid_tgid();
    new_socket.update(&pid_tgid, &sock);
   
    return 0;
}


//distinguish btw ipv4 and ipv6
int connect_udp_return(struct pt_regs *ctx, struct socket *sock, struct sockaddr *uaddr,
		       int addr_len, int flags)
{
    

    int ret = PT_REGS_RC(ctx);
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();

    struct socket **socketpp;
    socketpp = new_socket.lookup(&pid_tgid);

    if (socketpp == 0) {
    bpf_trace_printk("missed_entry in udp send msg");
        return 0;   // missed entry
    }
    if (ret != 0) {
        bpf_trace_printk("error return connect upd ipv4 msg %d", ret);
        new_socket.delete(&pid_tgid);
        return 0;
    }

    struct socket *socketp = *socketpp;

    u32 pid = pid_tgid >> 32;
    u32 tgid = pid_tgid;

    u16 family = socketp->sk->sk_family;

    if (family == AF_INET) {
        struct data_ipv4 data = {};
        bpf_get_current_comm(data.comm, sizeof(data.comm));
        data.ts_us = ts;
        data.family = family;
        data.type = socketp->sk->sk_type;
        data.state = socketp->sk->sk_state;
        data.saddr = socketp->sk->__sk_common.skc_rcv_saddr;
        data.daddr = socketp->sk->__sk_common.skc_daddr;
        data.pid = pid;
        data.tgid = tgid;
        data.sport = socketp->sk->__sk_common.skc_num;
        data.dport = socketp->sk->__sk_common.skc_dport;
        data.dport = ntohs(data.dport);
        ipv4events.perf_submit(ctx, &data, sizeof(data));
        return 0;
    }
    else {
        struct data_ipv6 data = {};
        data.ts_us = ts;
        data.pid = pid;
        data.tgid = tgid;
        bpf_get_current_comm(data.comm, sizeof(data.comm));
        data.family = family;
        data.type = socketp->sk->sk_type;
        data.state = socketp->sk->sk_state;
        bpf_probe_read_kernel(&data.saddr, sizeof(data.saddr),
            socketp->sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&data.daddr, sizeof(data.daddr),
            socketp->sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        data.sport = socketp->sk->__sk_common.skc_num;
        data.dport = socketp->sk->__sk_common.skc_dport;
        data.dport = ntohs(data.dport);
        ipv6events.perf_submit(ctx, &data, sizeof(data));
        return 0;
    }
}