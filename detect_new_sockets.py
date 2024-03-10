
from bcc import BPF
import ctypes









# Define BPF program
bpf_program_socket = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/sched.h>
#include <net/inet_sock.h>

struct data_t {
    u32 pid;
    u32 tgid;
    char comm[TASK_COMM_LEN];
    u16 family;
    u16 type;
    u16 state;
    u16 protocol;
    u64 saddr[2];
    u64 daddr[2];
    u64 sport; // source-listenign port
    u64 dport;
    u16 inner_state;

};
BPF_HASH(currsock, u64, struct socket *);


BPF_PERF_OUTPUT(ipv4events);
BPF_PERF_OUTPUT(ipv6events);

int new_ipv4_socket_entry(struct pt_regs *ctx, struct net *net, struct socket *sock) {
    struct data_t data = {};

    u64 pid_tgid = bpf_get_current_pid_tgid();
    currsock.update(&pid_tgid, &sock);

    bpf_trace_printk("create ipv4 socket");

    data.pid = pid_tgid >> 32;
    data.tgid = pid_tgid;

    bpf_get_current_comm(data.comm, sizeof(data.comm));


    data.family = sock->sk->sk_family;
    

    data.state = sock->sk->sk_state;
    data.type = sock->sk->sk_type;
    data.protocol = sock->sk->sk_protocol;

    data.saddr[0] = sock->sk->__sk_common.skc_rcv_saddr;
    data.daddr[0] = sock->sk->__sk_common.skc_daddr;

    data.sport  = sock->sk->__sk_common.skc_num;
    data.dport = sock->sk->__sk_common.skc_dport;
    data.dport = ntohs(data.dport);
    data.inner_state = 0;
    
    ipv4events.perf_submit(ctx, &data, sizeof(data));

    
    return 0;
}
int new_ipv4_socket_return(struct pt_regs *ctx) {
    struct data_t data = {};


    int ret = PT_REGS_RC(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();

    bpf_trace_printk("return create ipv4 socket ");

    struct socket **socketpp;
    socketpp = currsock.lookup(&pid_tgid);
    if (socketpp == 0) {
    bpf_trace_printk("missed_entry ");
        return 0;   // missed entry
    }

    if (ret != 0) {
        bpf_trace_printk("error return create ipv4 socket %d", ret);
        currsock.delete(&pid_tgid);
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

    data.saddr[0] = inet->inet_rcv_saddr;;
    data.daddr[0] = socketp->sk->__sk_common.skc_daddr;

    data.sport  = socketp->sk->__sk_common.skc_num;

    data.dport =    socketp->sk->__sk_common.skc_dport;
    data.dport = ntohs(data.dport);

    data.inner_state = 1;   

    ipv4events.perf_submit(ctx, &data, sizeof(data));
    
    currsock.delete(&pid_tgid);
    return 0;
}
int new_ipv6_socket_entry(struct pt_regs *ctx, struct net *net, struct socket *sock) {


    struct data_t data = {};

    u64 pid_tgid = bpf_get_current_pid_tgid();
    currsock.update(&pid_tgid, &sock);

    bpf_trace_printk("create ipv6 socket");

    u32 pid = pid_tgid >> 32;
    u32 tgid = pid_tgid;

    data.pid = pid;
    data.tgid = tgid;
    // Check if this socket has already been logged

    data.family = sock->sk->__sk_common.skc_family;

    data.state = sock->sk->sk_state;
    data.type = sock->sk->sk_type;
    data.protocol = sock->sk->sk_protocol;
     bpf_probe_read_kernel(data.saddr, sizeof(data.saddr),
                           sock->sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
    bpf_probe_read_kernel(data.daddr, sizeof(data.daddr),
                           sock->sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);

    data.sport  = sock->sk->__sk_common.skc_num;
    data.dport = sock->sk->__sk_common.skc_dport;
    data.dport = ntohs(data.dport);
    data.inner_state = 20;

    ipv6events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int new_ipv6_socket_return(struct pt_regs *ctx) {
    struct data_t data = {};


    int ret = PT_REGS_RC(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();

    bpf_trace_printk("return create ipv6 socket ");

    struct socket **socketpp;
    socketpp = currsock.lookup(&pid_tgid);
    if (socketpp == 0) {
        bpf_trace_printk("missed_entry ");
        return 0;   // missed entry
    }

    if (ret != 0) {
        bpf_trace_printk("error return create ipv6 socket %d", ret);
        currsock.delete(&pid_tgid);
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

    bpf_probe_read_kernel(data.saddr, sizeof(data.saddr),
                           socketp->sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
    bpf_probe_read_kernel(data.daddr, sizeof(data.daddr),
                           socketp->sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);

    data.sport  = socketp->sk->__sk_common.skc_num;
    data.dport =    socketp->sk->__sk_common.skc_dport;
    data.dport = ntohs(data.dport);
    data.inner_state = 21;

    ipv6events.perf_submit(ctx, &data, sizeof(data));
    
    currsock.delete(&pid_tgid);
    return 0;
}

int bind_ipv4_socket_entry(struct pt_regs *ctx, struct socket *sock) {
    struct data_t data = {};



    u64 pid_tgid = bpf_get_current_pid_tgid();
    currsock.update(&pid_tgid, &sock);

    bpf_trace_printk("bind ipv4 socket");

    data.pid = pid_tgid >> 32;
    data.tgid = pid_tgid;

    bpf_get_current_comm(data.comm, sizeof(data.comm));

        


    data.family = sock->sk->sk_family;
    

    data.state = sock->sk->sk_state;
    data.type = sock->sk->sk_type;
    data.protocol = sock->sk->sk_protocol;

    data.saddr[0] = sock->sk->__sk_common.skc_rcv_saddr;
    data.daddr[0] = sock->sk->__sk_common.skc_daddr;

    data.sport  = sock->sk->__sk_common.skc_num;
    data.dport = sock->sk->__sk_common.skc_dport;
    data.dport = ntohs(data.dport);
    data.inner_state= 2;

    ipv4events.perf_submit(ctx, &data, sizeof(data));

    
    return 0;
}

int bind_ipv4_socket_return(struct pt_regs *ctx) {
    struct data_t data = {};


    int ret = PT_REGS_RC(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();

    bpf_trace_printk("return bind ipv4 socket ");

    struct socket **socketpp;
    socketpp = currsock.lookup(&pid_tgid);
    if (socketpp == 0) {
    bpf_trace_printk("missed_entry ");
        return 0;   // missed entry
    }

    if (ret != 0) {
        bpf_trace_printk("error bind ipv4 socket %d", ret);
        currsock.delete(&pid_tgid);
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

    data.saddr[0] = socketp->sk->__sk_common.skc_rcv_saddr;
    data.saddr[0] = inet->inet_rcv_saddr;;
    data.daddr[0] = socketp->sk->__sk_common.skc_daddr;

    data.sport  = socketp->sk->__sk_common.skc_num;

    data.dport =    socketp->sk->__sk_common.skc_dport;
    data.dport = ntohs(data.dport);
    data.inner_state = 3;

    ipv4events.perf_submit(ctx, &data, sizeof(data));

    
    currsock.delete(&pid_tgid);
    return 0;
}

int bind_ipv6_socket_entry(struct pt_regs *ctx,struct socket *sock) {


    struct data_t data = {};

    u64 pid_tgid = bpf_get_current_pid_tgid();
    currsock.update(&pid_tgid, &sock);

    bpf_trace_printk("bind ipv6 socket");

    u32 pid = pid_tgid >> 32;
    u32 tgid = pid_tgid;

    data.pid = pid;
    data.tgid = tgid;

    data.family = sock->sk->__sk_common.skc_family;

    data.state = sock->sk->sk_state;
    data.type = sock->sk->sk_type;
    data.protocol = sock->sk->sk_protocol;

    bpf_probe_read_kernel(data.saddr, sizeof(data.saddr),
                           sock->sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
    bpf_probe_read_kernel(data.daddr, sizeof(data.daddr),
                           sock->sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);


    data.sport  = sock->sk->__sk_common.skc_num;
    data.dport = sock->sk->__sk_common.skc_dport;
    data.dport = ntohs(data.dport);
    data.inner_state = 22;

    ipv6events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int bind_ipv6_socket_return(struct pt_regs *ctx) {
    struct data_t data = {};


    int ret = PT_REGS_RC(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();

    bpf_trace_printk("return bind ipv6 socket ");

    struct socket **socketpp;
    socketpp = currsock.lookup(&pid_tgid);
    if (socketpp == 0) {
        bpf_trace_printk("missed_entry ");
        return 0;   // missed entry
    }

    if (ret != 0) {
        bpf_trace_printk("error return bind ipv6 socket %d", ret);
        currsock.delete(&pid_tgid);
        return 0;
    }

    struct socket *socketp = *socketpp;

    data.pid = pid_tgid >> 32;
    data.tgid = pid_tgid;

    bpf_get_current_comm(data.comm, sizeof(data.comm));

        


    data.family = socketp->sk->sk_family;
    

    data.state = socketp->sk->sk_state;
    data.type = socketp->sk->sk_type;
    data.protocol = socketp->sk->sk_protocol;

    bpf_probe_read_kernel(data.saddr, sizeof(data.saddr),
                           socketp->sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
    bpf_probe_read_kernel(data.daddr, sizeof(data.daddr),
                           socketp->sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);

    data.sport  = socketp->sk->__sk_common.skc_num;
    data.dport =    socketp->sk->__sk_common.skc_dport;
    data.dport = ntohs(data.dport);
    data.inner_state = 23;

    ipv6events.perf_submit(ctx, &data, sizeof(data));
    
    currsock.delete(&pid_tgid);
    return 0;
}

int listen_socket_entry(struct pt_regs *ctx, struct socket *sock) {
    struct data_t data = {};


    bpf_trace_printk("listen ipv4 socket");



    u64 pid_tgid = bpf_get_current_pid_tgid();
    currsock.update(&pid_tgid, &sock);

    data.pid = pid_tgid >> 32;
    data.tgid = pid_tgid;

    bpf_get_current_comm(data.comm, sizeof(data.comm));
    

    data.family = sock->sk->sk_family;
    

    data.state = sock->sk->sk_state;
    data.type = sock->sk->sk_type;
    data.protocol = sock->sk->sk_protocol;
    data.sport  = sock->sk->__sk_common.skc_num;
    data.dport = sock->sk->__sk_common.skc_dport;
    data.dport = ntohs(data.dport);

    data.inner_state= 4;
    if (data.family == AF_INET) {
        data.saddr[0] = sock->sk->__sk_common.skc_rcv_saddr;
        data.daddr[0] = sock->sk->__sk_common.skc_daddr;
        ipv4events.perf_submit(ctx, &data, sizeof(data));

    }
    else if (data.family == AF_INET6) {
        bpf_probe_read_kernel(data.saddr, sizeof(data.saddr),
                           sock->sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(data.daddr, sizeof(data.daddr),
                           sock->sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        ipv6events.perf_submit(ctx, &data, sizeof(data));

    }
    

    return 0;
}

int listen_socket_return(struct pt_regs *ctx) {
     struct data_t data = {};


    int ret = PT_REGS_RC(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();

    bpf_trace_printk("return listen ipv4 socket");

    struct socket **socketpp;
    socketpp = currsock.lookup(&pid_tgid);
    if (socketpp == 0) {
    bpf_trace_printk("missed_entry ");
        return 0;   // missed entry
    }

    if (ret != 0) {
        bpf_trace_printk(" error listen ipv4 socket %d", ret);
        currsock.delete(&pid_tgid);
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


    data.sport  = socketp->sk->__sk_common.skc_num;
    data.dport =    socketp->sk->__sk_common.skc_dport;

    data.dport = ntohs(data.dport);

    data.inner_state = 5;

    if (data.family == AF_INET) {
        data.saddr[0] = socketp->sk->__sk_common.skc_rcv_saddr;
        data.daddr[0] = socketp->sk->__sk_common.skc_daddr;
        ipv4events.perf_submit(ctx, &data, sizeof(data));

    }
    else if (data.family == AF_INET6) {
        bpf_probe_read_kernel(data.saddr, sizeof(data.saddr),
                           socketp->sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(data.daddr, sizeof(data.daddr),
                           socketp->sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        ipv6events.perf_submit(ctx, &data, sizeof(data));
    }
    currsock.delete(&pid_tgid);
    return 0;
}

int connect_tcp_entry(struct pt_regs *ctx, struct socket *sock) {
    struct data_t data = {};


    bpf_trace_printk("connect ipv4 socket");



    u64 pid_tgid = bpf_get_current_pid_tgid();
    currsock.update(&pid_tgid, &sock);

    data.pid = pid_tgid >> 32;
    data.tgid = pid_tgid;

    bpf_get_current_comm(data.comm, sizeof(data.comm));    

    data.family = sock->sk->sk_family;
    

    data.state = sock->sk->sk_state;
    data.type = sock->sk->sk_type;
    data.protocol = sock->sk->sk_protocol;


    data.sport  = sock->sk->__sk_common.skc_num;
    data.dport = sock->sk->__sk_common.skc_dport;
    data.dport = ntohs(data.dport);

    data.inner_state= 6;

    if (data.family == AF_INET) {
        data.saddr[0] = sock->sk->__sk_common.skc_rcv_saddr;
        data.daddr[0] = sock->sk->__sk_common.skc_daddr;
        ipv4events.perf_submit(ctx, &data, sizeof(data));

    }
    else if (data.family == AF_INET6) {
        bpf_probe_read_kernel(data.saddr, sizeof(data.saddr),
                           sock->sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(data.daddr, sizeof(data.daddr),
                           sock->sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        ipv6events.perf_submit(ctx, &data, sizeof(data));

    }
    return 0;
}

int connect_tcp_return(struct pt_regs *ctx) {
     struct data_t data = {};


    int ret = PT_REGS_RC(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();

    bpf_trace_printk("return connect ipv4 socket");

    struct socket **socketpp;
    socketpp = currsock.lookup(&pid_tgid);
    if (socketpp == 0) {
    bpf_trace_printk("missed_entry ");
        return 0;   // missed entry
    }

    if (ret != 0) {
        bpf_trace_printk("error connect ipv4 socket %d", ret);
        currsock.delete(&pid_tgid);
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

    data.sport  = socketp->sk->__sk_common.skc_num;

    data.dport =    socketp->sk->__sk_common.skc_dport;
    data.dport = ntohs(data.dport);


    data.inner_state = 7;


    if (data.family == AF_INET) {
        data.saddr[0] = socketp->sk->__sk_common.skc_rcv_saddr;
        data.daddr[0] = socketp->sk->__sk_common.skc_daddr;
        ipv4events.perf_submit(ctx, &data, sizeof(data));

    }
    else if (data.family == AF_INET6) {
        bpf_probe_read_kernel(data.saddr, sizeof(data.saddr),
                           &socketp->sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(data.daddr, sizeof(data.daddr),
                           &socketp->sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        ipv6events.perf_submit(ctx, &data, sizeof(data));
    }
    currsock.delete(&pid_tgid);
    return 0;
}

int connect_udp_entry(struct pt_regs *ctx, struct socket *sock) {
    struct data_t data = {};


    bpf_trace_printk("connect ipv4 udp");



    u64 pid_tgid = bpf_get_current_pid_tgid();
    currsock.update(&pid_tgid, &sock);

    data.pid = pid_tgid >> 32;
    data.tgid = pid_tgid;

    bpf_get_current_comm(data.comm, sizeof(data.comm));

    data.family = sock->sk->sk_family;
    

    data.state = sock->sk->sk_state;
    data.type = sock->sk->sk_type;
    data.protocol = sock->sk->sk_protocol;

    data.sport  = sock->sk->__sk_common.skc_num;
    data.dport = sock->sk->__sk_common.skc_dport;
    data.dport = ntohs(data.dport);

    data.inner_state= 8;

    if (data.family == AF_INET) {
        data.saddr[0] = sock->sk->__sk_common.skc_rcv_saddr;
        data.daddr[0] = sock->sk->__sk_common.skc_daddr;
        ipv4events.perf_submit(ctx, &data, sizeof(data));

    }
    else if (data.family == AF_INET6) {
        bpf_probe_read_kernel(data.saddr, sizeof(data.saddr),
                           &sock->sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(data.daddr, sizeof(data.daddr),
                           &sock->sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        ipv6events.perf_submit(ctx, &data, sizeof(data));

    }
    return 0;
}

int connect_udp_return(struct pt_regs *ctx) {
     struct data_t data = {};


    int ret = PT_REGS_RC(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();

    bpf_trace_printk("return ipv4 udp ");

    struct socket **socketpp;
    socketpp = currsock.lookup(&pid_tgid);
    if (socketpp == 0) {
    bpf_trace_printk("missed_entry ");
        return 0;   // missed entry
    }

    if (ret != 0) {
        bpf_trace_printk("error ipv4 udp %d", ret);
        currsock.delete(&pid_tgid);
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

    data.sport  = socketp->sk->__sk_common.skc_num;

    data.dport =    socketp->sk->__sk_common.skc_dport;
    data.dport = ntohs(data.dport);

    data.inner_state = 9;

    
    if (data.family == AF_INET) {
        data.saddr[0] = socketp->sk->__sk_common.skc_rcv_saddr;
        data.daddr[0] = socketp->sk->__sk_common.skc_daddr;
        ipv4events.perf_submit(ctx, &data, sizeof(data));

    }
    else if (data.family == AF_INET6) {
        bpf_probe_read_kernel(data.saddr, sizeof(data.saddr),
                           &socketp->sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(data.daddr, sizeof(data.daddr),
                           &socketp->sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        ipv6events.perf_submit(ctx, &data, sizeof(data));
    }
    currsock.delete(&pid_tgid);
    return 0;
}

int accept_entry(struct pt_regs *ctx, struct socket *sock) {
    struct data_t data = {};


    bpf_trace_printk("accpet ipv4 entry");



    u64 pid_tgid = bpf_get_current_pid_tgid();
    currsock.update(&pid_tgid, &sock);

    data.pid = pid_tgid >> 32;
    data.tgid = pid_tgid;

    bpf_get_current_comm(data.comm, sizeof(data.comm));

    data.family = sock->sk->sk_family;
    

    data.state = sock->sk->sk_state;
    data.type = sock->sk->sk_type;
    data.protocol = sock->sk->sk_protocol;


    data.sport  = sock->sk->__sk_common.skc_num;
    data.dport = sock->sk->__sk_common.skc_dport;
    data.dport = ntohs(data.dport);

    data.inner_state= 10;

    if (data.family == AF_INET) {
        data.saddr[0] = sock->sk->__sk_common.skc_rcv_saddr;
        data.daddr[0] = sock->sk->__sk_common.skc_daddr;
        ipv4events.perf_submit(ctx, &data, sizeof(data));

    }
    else if (data.family == AF_INET6) {
        bpf_probe_read_kernel(data.saddr, sizeof(data.saddr),
                           sock->sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(data.daddr, sizeof(data.daddr),
                           sock->sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        ipv6events.perf_submit(ctx, &data, sizeof(data));

    }
    return 0;
}

int accept_return(struct pt_regs *ctx) {
     struct data_t data = {};


    int ret = PT_REGS_RC(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();

    bpf_trace_printk("return ipv4 accept");

    struct socket **socketpp;
    socketpp = currsock.lookup(&pid_tgid);
    if (socketpp == 0) {
    bpf_trace_printk("missed_entry ");
        return 0;   // missed entry
    }

    if (ret != 0) {
        bpf_trace_printk("error ipv4 accept %d", ret);
        currsock.delete(&pid_tgid);
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


    data.sport  = socketp->sk->__sk_common.skc_num;

    data.dport =    socketp->sk->__sk_common.skc_dport;
    data.dport = ntohs(data.dport);

    data.inner_state =11;


    if (data.family == AF_INET) {
        data.saddr[0] = socketp->sk->__sk_common.skc_rcv_saddr;
        data.daddr[0] = socketp->sk->__sk_common.skc_daddr;
        ipv4events.perf_submit(ctx, &data, sizeof(data));

    }
    else if (data.family == AF_INET6) {
        bpf_probe_read_kernel(data.saddr, sizeof(data.saddr),
                           &socketp->sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(data.daddr, sizeof(data.daddr),
                           &socketp->sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        ipv6events.perf_submit(ctx, &data, sizeof(data));
    }

    currsock.delete(&pid_tgid);
    return 0;
}

"""

bpf_program_tracepoint = """

TRACEPOINT_PROBE(sock, inet_sock_set_state)
{
    
    bpf_trace_printk("error return bind ipv6 socket %d", args);
    if (args->protocol != IPPROTO_TCP)
        return 0;

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    // sk is mostly used as a UUID, and for two tcp stats:
    struct sock *sk = (struct sock *)args->skaddr;

    // lport is either used in a filter here, or later
    u16 lport = args->sport;
    FILTER_LPORT

    // dport is either used in a filter here, or later
    u16 dport = args->dport;
    FILTER_DPORT

    /*
     * This tool includes PID and comm context. It's best effort, and may
     * be wrong in some situations. It currently works like this:
     * - record timestamp on any state < TCP_FIN_WAIT1
     * - cache task context on:
     *       TCP_SYN_SENT: tracing from client
     *       TCP_LAST_ACK: client-closed from server
     * - do output on TCP_CLOSE:
     *       fetch task context if cached, or use current task
     */

    // capture birth time
    if (args->newstate < TCP_FIN_WAIT1) {
        /*
         * Matching just ESTABLISHED may be sufficient, provided no code-path
         * sets ESTABLISHED without a tcp_set_state() call. Until we know
         * that for sure, match all early states to increase chances a
         * timestamp is set.
         * Note that this needs to be set before the PID filter later on,
         * since the PID isn't reliable for these early stages, so we must
         * save all timestamps and do the PID filter later when we can.
         */
        u64 ts = bpf_ktime_get_ns();
        birth.update(&sk, &ts);
    }

    // record PID & comm on SYN_SENT
    if (args->newstate == TCP_SYN_SENT || args->newstate == TCP_LAST_ACK) {
        // now we can PID filter, both here and a little later on for CLOSE
        FILTER_PID
        struct id_t me = {.pid = pid};
        bpf_get_current_comm(&me.task, sizeof(me.task));
        whoami.update(&sk, &me);
    }

    if (args->newstate != TCP_CLOSE)
        return 0;

    // calculate lifespan
    u64 *tsp, delta_us;
    tsp = birth.lookup(&sk);
    if (tsp == 0) {
        whoami.delete(&sk);     // may not exist
        return 0;               // missed create
    }
    delta_us = (bpf_ktime_get_ns() - *tsp) / 1000;
    birth.delete(&sk);

    // fetch possible cached data, and filter
    struct id_t *mep;
    mep = whoami.lookup(&sk);
    if (mep != 0)
        pid = mep->pid;
    FILTER_PID

    u16 family = args->family;
    FILTER_FAMILY

    // get throughput stats. see tcp_get_info().
    u64 rx_b = 0, tx_b = 0;
    struct tcp_sock *tp = (struct tcp_sock *)sk;
    rx_b = tp->bytes_received;
    tx_b = tp->bytes_acked;

    if (args->family == AF_INET) {
        struct ipv4_data_t data4 = {};
        data4.span_us = delta_us;
        data4.rx_b = rx_b;
        data4.tx_b = tx_b;
        data4.ts_us = bpf_ktime_get_ns() / 1000;
        __builtin_memcpy(&data4.saddr, args->saddr, sizeof(data4.saddr));
        __builtin_memcpy(&data4.daddr, args->daddr, sizeof(data4.daddr));
        // a workaround until data4 compiles with separate lport/dport
        data4.ports = dport + ((0ULL + lport) << 32);
        data4.pid = pid;

        if (mep == 0) {
            bpf_get_current_comm(&data4.task, sizeof(data4.task));
        } else {
            bpf_probe_read_kernel(&data4.task, sizeof(data4.task), (void *)mep->task);
        }
        ipv4_events.perf_submit(args, &data4, sizeof(data4));

    } else /* 6 */ {
        struct ipv6_data_t data6 = {};
        data6.span_us = delta_us;
        data6.rx_b = rx_b;
        data6.tx_b = tx_b;
        data6.ts_us = bpf_ktime_get_ns() / 1000;
        __builtin_memcpy(&data6.saddr, args->saddr_v6, sizeof(data6.saddr));
        __builtin_memcpy(&data6.daddr, args->daddr_v6, sizeof(data6.daddr));
        // a workaround until data6 compiles with separate lport/dport
        data6.ports = dport + ((0ULL + lport) << 32);
        data6.pid = pid;
        if (mep == 0) {
            bpf_get_current_comm(&data6.task, sizeof(data6.task));
        } else {
            bpf_probe_read_kernel(&data6.task, sizeof(data6.task), (void *)mep->task);
        }
        ipv6_events.perf_submit(args, &data6, sizeof(data6));
    }

    if (mep != 0)
        whoami.delete(&sk);

    return 0;
}



"""

if (BPF.tracepoint_exists("sock", "inet_sock_set_state")):
    bpf_program_socket += bpf_program_tracepoint
else


b = BPF(text=bpf_program_socket)
if b.get_kprobe_functions(b"inet_create"):
    b.attach_kprobe(event="inet_create", fn_name="new_ipv4_socket_entry")
    b.attach_kretprobe(event="inet_create", fn_name="new_ipv4_socket_return")
else:
    print("ERROR: inet_create kernel not found or traceable."
          " The kernel might be too old or the the function has been inlined.")

if b.get_kprobe_functions(b"inet6_create"):
    b.attach_kprobe(event="inet6_create", fn_name="new_ipv6_socket_entry")
    b.attach_kretprobe(event="inet6_create", fn_name="new_ipv6_socket_return")
else:
    print("ERROR: inet6_create kernel not found or traceable."
          " The kernel might be too old or the the function has been inlined.")


if(b.get_kprobe_functions(b"inet_bind")):
    b.attach_kprobe(event="inet_bind", fn_name="bind_ipv4_socket_entry")
    b.attach_kretprobe(event="inet_bind", fn_name="bind_ipv4_socket_return")
else:
    print("ERROR: inet_bind kernel not found or traceable."
          " The kernel might be too old or the the function has been inlined.")

if b.get_kprobe_functions(b"inet6_bind"):
    b.attach_kprobe(event="inet6_bind", fn_name="bind_ipv6_socket_entry")
    b.attach_kretprobe(event="inet6_bind", fn_name="bind_ipv6_socket_return")
else:
    print("ERROR: inet6_bind kernel not found or traceable."
          " The kernel might be too old or the the function has been inlined.")

if(b.get_kprobe_functions(b"inet_listen")):
    b.attach_kprobe(event="inet_listen", fn_name="listen_socket_entry")
    b.attach_kretprobe(event="inet_listen", fn_name="listen_socket_return")
else:
    print("ERROR: inet_listen kernel not found or traceable."
          " The kernel might be too old or the the function has been inlined.")

if(b.get_kprobe_functions(b"inet_stream_connect")):
    b.attach_kprobe(event="inet_stream_connect", fn_name="connect_tcp_entry")
    b.attach_kretprobe(event="inet_stream_connect", fn_name="connect_tcp_return")
else:
    print("ERROR: inet_stream_connect kernel not found or traceable."
          " The kernel might be too old or the the function has been inlined.")

if(b.get_kprobe_functions(b"inet_dgram_connect")):
    b.attach_kprobe(event="inet_dgram_connect", fn_name="connect_udp_entry")
    b.attach_kretprobe(event="inet_dgram_connect", fn_name="connect_udp_return")
else:
    print("ERROR: inet_dgram_connect kernel not found or traceable."
          " The kernel might be too old or the the function has been inlined.")
if(b.get_kprobe_functions(b"inet_accept")):
    b.attach_kprobe(event="inet_accept", fn_name="accept_entry")
    b.attach_kretprobe(event="inet_accept", fn_name="accept_return")
else:
    print("ERROR: inet_accept kernel not found or traceable."
          " The kernel might be too old or the the function has been inlined.")





type_dict = {
    1: "SOCK_STREAM",    # TCP
    2: "SOCK_DGRAM",     # UDP
    3: "SOCK_RAW",   
    4: "SOCK_RDM",
    5: "SOCK_SEQPACKET",
    6: "SOCK_DCCP",
    10: "SOCK_PACKET",
}


family_dict = {
    1: "AF_UNIX/AF_LOCAL",  
    2: "AF_INET",           # IPv4 
    10: "AF_INET6",         # IPv6 
    17: "AF_PACKET",       
}


state_dict = {

    0: "TCP_ESTABLISHED",  
    1: "TCP_SYN_SENT",     
    2: "TCP_SYN_RECV",    
    3: "TCP_FIN_WAIT1",    
    4: "TCP_FIN_WAIT2",    
    5: "TCP_TIME_WAIT",    
    6: "TCP_TIME_WAIT",
    7: "TCP_CLOSE_WAIT",
    8: "TCP_LAST_ACK",
    9: "TCP_LISTEN",
    10: "TCP_CLOSING",
    11: "TCP_NEW_SYN_RECV",
}

protocol_dict = {
    0: "IP",
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    41: "IPV6",
    92: "MTP",
    51: "AH",
    143: "ETH",
    255: "RAW",
    262: "MPTCP"
}

from socket import inet_ntop, AF_INET, AF_INET6, SOCK_STREAM, SOCK_DGRAM
from struct import pack
import netaddr




log_file_path = "logs/socket_log.txt"

with open(log_file_path, "w") as log_file:


    log_file.write("New socket connections\n")
    log_file.write("PID, TGID\n")

    def print_ipv6_event(cpu, data, size):
        event = b["ipv4events"].event(data)
        print(f"PID: {event.pid}, TGID: {event.tgid},COMM: {event.comm},FAMILY: {family_dict.get(event.family,'UNKNOWN: ' + str(event.family))},"
            f"TYPE: {type_dict.get(event.type, 'UNKNOWN: ' + str(event.type))},STATE: {state_dict.get(event.state, 'UNKNOWN: ' + str(event.state))},"
            f"PROTOCOL: {protocol_dict.get(event.protocol, 'UNKNOWN: ' + str(event.protocol))},"
            f"SADDR: {inet_ntop(AF_INET6, event.saddr)}.DADDR: {inet_ntop(AF_INET6, event.daddr)},SPORT: {event.sport},"
            f"DPORT: {event.dport}, INNER STATE: {event.inner_state}")

# Print the packed data
        log_file.write(f"{event.pid}, {event.tgid}\n")


    def print_ipv4_event(cpu, data, size):
        event = b["ipv6events"].event(data)
        print(f"PID: {event.pid}, TGID: {event.tgid},COMM: {event.comm},FAMILY: {family_dict.get(event.family,'UNKNOWN: ' + str(event.family))},"
            f"TYPE: {type_dict.get(event.type, 'UNKNOWN: ' + str(event.type))},STATE: {state_dict.get(event.state, 'UNKNOWN: ' + str(event.state))},"
            f"PROTOCOL: {protocol_dict.get(event.protocol, 'UNKNOWN: ' + str(event.protocol))},"
            f"SADDR: {inet_ntop(AF_INET, pack('I', event.saddr[0]))}.DADDR: {inet_ntop(AF_INET, pack('I', event.daddr[0]))},SPORT: {event.sport},"
            f"DPORT: {event.dport}, INNER STATE: {event.inner_state}")
    
# Print the packed data
        log_file.write(f"{event.pid}, {event.tgid}\n")


    b["ipv4events"].open_perf_buffer(print_ipv4_event)
    b["ipv6events"].open_perf_buffer(print_ipv6_event)
    print("Logging new socket connections. Press Ctrl+C to stop.")
    try:
        while True:

            b.perf_buffer_poll()
            

    except KeyboardInterrupt:
        print("Stopped logging socket connections.")
