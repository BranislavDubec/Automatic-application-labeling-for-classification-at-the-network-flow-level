
from bcc import BPF
import ctypes









# Define BPF program
bpf_program_socket = """
#include <uapi/linux/ptrace.h>
#include <linux/tcp.h>
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
    u32 saddrr;
    u32 daddrr;
    u64 saddr[2];
    u64 daddr[2];
    u64 sport; // source-listenign port
    u64 dport;
    u16 inner_state;
    u64 ts_us;
    u64 rx_b;
    u64 tx_b;
    u64 span_us;
};
BPF_HASH(currsock, u64, struct socket *);
BPF_HASH(currtcp, u64, struct sock *);
BPF_HASH(birth, struct sock * , u64);

BPF_PERF_OUTPUT(ipv4events);
BPF_PERF_OUTPUT(ipv6events);

int new_ipv4_socket_entry(struct pt_regs *ctx, struct net *net, struct socket *sock) {
    struct data_t data = {};

    u64 pid_tgid = bpf_get_current_pid_tgid();
    currsock.update(&pid_tgid, &sock);
    u64 ts = bpf_ktime_get_ns();
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
    u64 ts = bpf_ktime_get_ns();

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


    



    u64 pid_tgid = bpf_get_current_pid_tgid();
    currsock.update(&pid_tgid, &sock);

    data.pid = pid_tgid >> 32;
    data.tgid = pid_tgid;

    bpf_get_current_comm(data.comm, sizeof(data.comm));    

    data.family = sock->sk->sk_family;
    
    bpf_trace_printk("connect %d socket",data.family);
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

"""format:
    field:unsigned short common_type;   offset:0;   size:2; signed:0;
    field:unsigned char common_flags;   offset:2;   size:1; signed:0;
    field:unsigned char common_preempt_count;   offset:3;   size:1;signed:0;
    field:int common_pid;   offset:4;   size:4; signed:1;

    field:const void * skaddr;  offset:8;   size:8; signed:0;
    field:int oldstate; offset:16;  size:4; signed:1;
    field:int newstate; offset:20;  size:4; signed:1;
    field:__u16 sport;  offset:24;  size:2; signed:0;
    field:__u16 dport;  offset:26;  size:2; signed:0;
    field:__u16 family; offset:28;  size:2; signed:0;
    field:__u16 protocol;   offset:30;  size:2; signed:0;
    field:__u8 saddr[4];    offset:32;  size:4; signed:0;
    field:__u8 daddr[4];    offset:36;  size:4; signed:0;
    field:__u8 saddr_v6[16];    offset:40;  size:16;    signed:0;
    field:__u8 daddr_v6[16];    offset:56;  size:16;    signed:0;"""
bpf_program_tracepoint = """

struct id_t {
    u32 pid;
    char task [TASK_COMM_LEN];
};
BPF_HASH(whoami, struct sock *, struct id_t);
TRACEPOINT_PROBE(sock, inet_sock_set_state)
{
    
    struct data_t data = {};
    
    bpf_trace_printk("sock set state");
    if (args->protocol != IPPROTO_TCP){
        bpf_trace_printk("%d", args->protocol);
        return 0;
    }
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct sock *sk = (struct sock *)args->skaddr;


    data.sport = args->sport;
    data.dport = args->dport;
    data.pid = pid_tgid >> 32;
    u32 pid = pid_tgid >> 32;
    data.tgid = pid_tgid;
    u64 ts = bpf_ktime_get_ns();
    bpf_trace_printk("som v tracepointe a pid %d", data.pid);
    bpf_trace_printk("som v tracepointe a stav %d", args->newstate);
    
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


    if (args->newstate == TCP_SYN_SENT || args->newstate == TCP_LAST_ACK) {
        // now we can PID filter, both here and a little later on for CLOSE
        struct id_t me = {.pid = pid};
        bpf_get_current_comm(&me.task, sizeof(me.task));
        whoami.update(&sk, &me);
        bpf_trace_printk("som v tracepointe a pid %d", data.pid);

    }
    if (args->newstate != TCP_CLOSE)
        return 0;
    // calculate lifespan
    u64 *tsp, delta_us;
    tsp = birth.lookup(&sk);
    bpf_trace_printk("som v tracepointe v close a pid %d", data.pid);

    if (tsp == 0) {
        whoami.delete(&sk);
        return 0;               // missed create
    }
    delta_us = (bpf_ktime_get_ns() - *tsp) / 1000;
    birth.delete(&sk);
    data.inner_state = 100;

    struct id_t *mep;
    mep = whoami.lookup(&sk);
    if (mep != 0)
        data.pid = mep->pid;
    bpf_trace_printk("som v tracepointe v close a pid %d", data.pid);
    if (mep == 0) {
            bpf_get_current_comm(&data.comm, sizeof(data.comm));
        } else {
            bpf_probe_read_kernel(&data.comm, sizeof(data.comm), (void *)mep->task);
        }
    u64 rx_b = 0, tx_b = 0;
    struct tcp_sock *tp = (struct tcp_sock *)sk;
    rx_b = tp->bytes_received;
    tx_b = tp->bytes_acked;
    bpf_trace_printk("som v tracepointe v close a pfamily %d, %d", data.family, data.family == AF_INET);
    if (args->family == AF_INET) {
        data.span_us = delta_us;
        data.rx_b = rx_b;
        data.tx_b = tx_b;
        data.ts_us = bpf_ktime_get_ns() / 1000;
        __builtin_memcpy(data.saddr, args->saddr, sizeof(data.saddrr));
        __builtin_memcpy(data.daddr, args->daddr, sizeof(data.daddrr));
        ipv4events.perf_submit(args, &data, sizeof(data));

    } else /* 6 */ {
        data.span_us = delta_us;
        data.rx_b = rx_b;
        data.tx_b = tx_b;
        data.ts_us = bpf_ktime_get_ns() / 1000;
        __builtin_memcpy(&data.saddrr, args->saddr_v6, sizeof(data.saddrr));
        __builtin_memcpy(&data.daddrr, args->daddr_v6, sizeof(data.daddrr));

        ipv6events.perf_submit(args, &data, sizeof(data));
    }
    return 0;
}

"""


bpf_program_tcp = """

int tcp_connect_entry(struct pt_regs *ctx, struct sock *sk)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;
    currtcp.update(&pid_tgid, &sk);
    bpf_trace_printk("tcp connect entry %d", tid);

    return 0;
}

int tcp_connect_return(struct pt_regs *ctx)
{
    struct data_t data = {};
    int ret = PT_REGS_RC(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;
    bpf_trace_printk("tcp connect return %d", tid);
    struct sock **skpp;
    skpp = currtcp.lookup(&pid_tgid);
    if (skpp == 0) {
    bpf_trace_printk("tcp connect return F %d", tid);
        return 0;   // missed entry
    }
    if (ret != 0) {
        // failed to send SYNC packet, may not have populated
        // socket __sk_common.{skc_rcv_saddr, ...}
        bpf_trace_printk("tcp connect return F %d, %d", tid, ret);
        currtcp.delete(&pid_tgid);
        return 0;
    }
    struct sock *skp = *skpp;
    u16 lport = skp->__sk_common.skc_num;
    u16 dport = skp->__sk_common.skc_dport;
    data.family = skp->sk_family;
    data.sport = lport;
    data.dport = ntohs(dport);
    data.pid = pid;
    data.tgid = tid;
    data.inner_state = 1000;

    if (data.family == AF_INET) {
        data.saddr[0] = skp->__sk_common.skc_rcv_saddr;
        data.daddr[0] = skp->__sk_common.skc_daddr;
        ipv4events.perf_submit(ctx, &data, sizeof(data));

    }
    else if (data.family == AF_INET6) {
        bpf_probe_read_kernel(data.saddr, sizeof(data.saddr),
                           skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(data.daddr, sizeof(data.daddr),
                           skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        ipv6events.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;

}

"""

bpf_program_retrans = """
TRACEPOINT_PROBE(tcp, tcp_retransmit_skb)
{
    struct data_t data = {};
    
    bpf_trace_printk("retransmit tcp ");

    u64 pid_tgid = bpf_get_current_pid_tgid();


    struct tcp_skb_cb *tcb;
    u32 seq;

    const struct sock *skp = (const struct sock *)args->skaddr;
    const struct sk_buff *skb = (const struct sk_buff *)args->skbaddr;
    data.sport = args->sport;
    data.dport = args->dport;
    data.state = skp->__sk_common.skc_state;
    data.family = skp->__sk_common.skc_family;

    seq = 0;
    if (skb) {
        /* macro TCP_SKB_CB from net/tcp.h */
        tcb = ((struct tcp_skb_cb *)&((skb)->cb[0]));
        seq = tcb->seq;
    }


    if (family == AF_INET) {
        __builtin_memcpy(&data.saddr, args->saddr, sizeof(data.saddr));
        __builtin_memcpy(&data.daddr, args->daddr, sizeof(data.daddr));
        ipv4events.perf_submit(args, &data, sizeof(data));
    } else if (family == AF_INET6) {
        __builtin_memcpy(&data.saddr, args->saddr_v6, sizeof(data.saddr));
        __builtin_memcpy(&data.daddr, args->daddr_v6, sizeof(data.daddr));
        ipv6events.perf_submit(args, &data, sizeof(data));
    }
    return 0;
}
"""
if (BPF.tracepoint_exists("sock", "inet_sock_set_state")):
    bpf_program_socket += bpf_program_tracepoint
else:
    print("Error, trace sock set state does not work")

bpf_program_socket += bpf_program_tcp

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


if(b.get_kprobe_functions(b"tcp_v4_connect")):

    b.attach_kprobe(event="tcp_v4_connect", fn_name="tcp_connect_entry")

    b.attach_kretprobe(event="tcp_v4_connect", fn_name="tcp_connect_return")
else:
    print("ERROR: tcp_v4_connect kernel not found or traceable."
          " The kernel might be too old or the the function has been inlined.")

if(b.get_kprobe_functions(b"tcp_v6_connect")):

    b.attach_kprobe(event="tcp_v6_connect", fn_name="tcp_connect_entry")
    b.attach_kretprobe(event="tcp_v6_connect", fn_name="tcp_connect_return")
else:
    print("ERROR: tcp_v4_connect kernel not found or traceable."
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
        event = b["ipv6events"].event(data)
        print(f"PID: {event.pid}, TGID: {event.tgid},COMM: {event.comm},FAMILY: {family_dict.get(event.family,'UNKNOWN: ' + str(event.family))},"
            f"TYPE: {type_dict.get(event.type, 'UNKNOWN: ' + str(event.type))},STATE: {state_dict.get(event.state, 'UNKNOWN: ' + str(event.state))},"
            f"PROTOCOL: {protocol_dict.get(event.protocol, 'UNKNOWN: ' + str(event.protocol))},"
            f"SADDR: {inet_ntop(AF_INET6, event.saddr)}.DADDR: {inet_ntop(AF_INET6, event.daddr)},SPORT: {event.sport},"
            f"DPORT: {event.dport}, INNER STATE: {event.inner_state}")

# Print the packed data
        log_file.write(f"{event.pid}, {event.tgid}\n")


    def print_ipv4_event(cpu, data, size):
        event = b["ipv4events"].event(data)
        try:
            print(f"PID: {event.pid}, TGID: {event.tgid},COMM: {event.comm},FAMILY: {family_dict.get(event.family,'UNKNOWN: ' + str(event.family))},"
                f"TYPE: {type_dict.get(event.type, 'UNKNOWN: ' + str(event.type))},STATE: {state_dict.get(event.state, 'UNKNOWN: ' + str(event.state))},"
                f"PROTOCOL: {protocol_dict.get(event.protocol, 'UNKNOWN: ' + str(event.protocol))},"
                f"SADDR: {inet_ntop(AF_INET, pack('I', event.saddr[0]))}.DADDR: {inet_ntop(AF_INET, pack('I', event.daddr[0]))},SPORT: {event.sport},"
                f"DPORT: {event.dport}, INNER STATE: {event.inner_state}")
        except:
            print(f"SKAPPID: {event.pid}, TGID: {event.tgid},COMM: {event.comm},FAMILY: {family_dict.get(event.family,'UNKNOWN: ' + str(event.family))},"
                f"TYPE: {type_dict.get(event.type, 'UNKNOWN: ' + str(event.type))},STATE: {state_dict.get(event.state, 'UNKNOWN: ' + str(event.state))},"
                f"PROTOCOL: {protocol_dict.get(event.protocol, 'UNKNOWN: ' + str(event.protocol))},"
                f"SADDR: {inet_ntop(AF_INET, pack('I', event.saddrr))}.DADDR: {inet_ntop(AF_INET, pack('I', event.daddrr))},SPORT: {event.sport},"
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
