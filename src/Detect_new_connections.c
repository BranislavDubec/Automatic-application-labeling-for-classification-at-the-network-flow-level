/*
    Contains definition of functions that are connected to system calls.
    Functions ending with entry is executed before the function.
    Functions ending with return is execture after the function.

    Licensed under the Apache License, Version 2.0 (the "License")

    __author__ = Branislav Dubec
    __version__ = 1.0.5

*/

#include "Detect_new_connections.h"

/*
 Current version does not track lifetime of sockets, therefore no events are produced to user mode.
*/
// Creation of inet_socket,
// Updates eBPF map with pointer of current socket with its pid_tgid
int new_ipv4_socket_entry(struct pt_regs *ctx, struct net *net, struct socket *sock) {

    u64 pid_tgid = bpf_get_current_pid_tgid();  

    new_socket.update(&pid_tgid, &sock);
    
    return 0;
}

// Return of creation of inet_socket
int new_ipv4_socket_return(struct pt_regs *ctx) {
    struct data_ipv4 data = {};

    int ret = PT_REGS_RC(ctx);
    
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct socket **socketpp;
    socketpp = new_socket.lookup(&pid_tgid);

    if (socketpp == NULL) {
    bpf_trace_printk("missed_entry in ipv4 socket creation");
        return 0;   // missed entry
    }

    if (ret != 0) {
        bpf_trace_printk("error return create ipv4 socket %d", ret);
        new_socket.delete(&pid_tgid);
        return 0;
    }
   
    return 0;
}


// Creation of inet6_socket
// Updates eBPF map with pointer of current socket with its pid_tgid
int new_ipv6_socket_entry(struct pt_regs *ctx, struct net *net, struct socket *sock, int protocol, int kern) {

    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    new_socket.update(&pid_tgid, &sock);
    
    return 0;
}

// Return of creation of inet_socket -> function is done and returns
int new_ipv6_socket_return(struct pt_regs *ctx) {
    struct data_ipv6 data = {};

    int ret = PT_REGS_RC(ctx);
    
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct socket **socketpp;
    socketpp = new_socket.lookup(&pid_tgid);

    if (socketpp == NULL) {
        bpf_trace_printk("missed_entry in ipv6 socket creation");
        return 0;   // missed entry
    }

    if (ret != 0) {
        bpf_trace_printk("error return create ipv6 socket %d", ret);
        new_socket.delete(&pid_tgid);
        return 0;
    }    
    return 0;
}



// Beginning of tcp connection for both IPv4 and IPv6
// Updates eBPF map with pointer of current sock with its pid_tgid
int tcp_connect_entry(struct pt_regs *ctx, struct sock *sk)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    new_sock.update(&pid_tgid, &sk);
    return 0;
}

// Return of tcp connection for both IPv4 and IPv6: tcp_v4_connect, tcp_v6_connect
// Check if the return value is success.
// Get information from sock structure and send it to user mode.
int tcp_connect_return(struct pt_regs *ctx)
{

    int ret = PT_REGS_RC(ctx);

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tgid = pid_tgid;

    struct sock **skpp;
    skpp = new_sock.lookup(&pid_tgid);
    if (skpp == NULL) {
        bpf_trace_printk("Error: missed entry in tcp socket connect return.");
        return 0;   // missed entry
    }
    if (ret != 0) {
        bpf_trace_printk("Error: tcp connect return value: %d.", ret);
        new_sock.delete(&pid_tgid);
        return 0;
    }

    struct sock *skp = *skpp;
    u16 lport = skp->__sk_common.skc_num;
    u16 dport = skp->__sk_common.skc_dport;
    u16 protocol = skp->sk_protocol;
    u16 family = skp->sk_family;
    if (family == AF_INET){
        struct data_ipv4 data = {};
        bpf_get_current_comm(data.comm, sizeof(data.comm));
        data.family = family;
        data.protocol = protocol;
        data.type = skp->sk_type;
        data.state = skp->sk_state;
        data.sport = lport;
        data.dport = ntohs(dport);
        data.pid = pid;
        data.tgid = tgid;
        data.saddr = skp->__sk_common.skc_rcv_saddr;
        data.daddr = skp->__sk_common.skc_daddr;
        ipv4events.perf_submit(ctx, &data, sizeof(data));
        new_sock.delete(&pid_tgid);
        return 0;
    } else { // family is AF_INET6
        struct data_ipv6 data = {};
        bpf_get_current_comm(data.comm, sizeof(data.comm));
        data.family = family;
        data.type = skp->sk_type;
        data.state = skp->sk_state;
        data.sport = lport;
        data.dport = ntohs(dport);
        data.pid = pid;
        data.tgid = tgid;
        bpf_probe_read_kernel(&data.saddr, sizeof(data.saddr),
                           &skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&data.daddr, sizeof(data.daddr),
                           &skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        ipv6events.perf_submit(ctx, &data, sizeof(data));
        new_sock.delete(&pid_tgid);
        return 0;
    }

}

// Beginning of tcp accept function for both IPv4 and IPv6, server connection, inet_csk_accept function
// Updates eBPF map with pointer of current sock with its pid_tgid
int accept_entry(struct pt_regs *ctx, struct sock *sk, int flags, int *err)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    new_sock.update(&pid_tgid, &sk);
    return 0;
}

// Return of tcp accept function for both IPv4 and IPv6
// If unsuccessful, function returns NULL
// Get information from sock structure and send it to user mode.
int accept_return(struct pt_regs *ctx)
{


    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tgid = pid_tgid;

    

    struct sock **skpp;
    skpp = new_sock.lookup(&pid_tgid);
    if (skpp == NULL) {
        bpf_trace_printk("Error: missed entry in tcp socket accept return.");
        return 0;   // missed entry
    }
    
    struct sock *newsk = (struct sock *)PT_REGS_RC(ctx);

    if (newsk == NULL){
        bpf_trace_printk("Error: tcp connect return value NULL.");
        new_sock.delete(&pid_tgid);
        return 0;
    }
    
    

    u16 lport = newsk->__sk_common.skc_num;
    u16 dport = newsk->__sk_common.skc_dport;
    u16 protocol = newsk->sk_protocol;
    u16 family = newsk->sk_family;
    if (family == AF_INET){
        struct data_ipv4 data = {};
        bpf_get_current_comm(data.comm, sizeof(data.comm));
        data.family = family;
        data.protocol = protocol;
        data.type = newsk->sk_type;
        data.state = newsk->sk_state;
        data.sport = lport;
        data.dport = ntohs(dport);
        data.pid = pid;
        data.tgid = tgid;
        data.saddr = newsk->__sk_common.skc_rcv_saddr;
        data.daddr = newsk->__sk_common.skc_daddr;
        ipv4events.perf_submit(ctx, &data, sizeof(data));
        new_sock.delete(&pid_tgid);
        return 0;
    } else {
        struct data_ipv6 data = {};
        bpf_get_current_comm(data.comm, sizeof(data.comm));
        data.family = family;
        data.type = newsk->sk_type;
        data.state = newsk->sk_state;
        data.sport = lport;
        data.dport = ntohs(dport);
        data.pid = pid;
        data.tgid = tgid;
        bpf_probe_read_kernel(&data.saddr, sizeof(data.saddr),
                           &newsk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&data.daddr, sizeof(data.daddr),
                           &newsk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        ipv6events.perf_submit(ctx, &data, sizeof(data));
        new_sock.delete(&pid_tgid);
        return 0;
    }

}


// Beginning of tcp accept function for both IPv4 and IPv6 inet_dgram_connect function
// Updates eBPF map with pointer of current sock with its pid_tgid
int connect_udp_entry(struct pt_regs *ctx, struct socket *sock, struct sockaddr *uaddr,
		       int addr_len, int flags)
{

    u64 pid_tgid = bpf_get_current_pid_tgid();
    new_socket.update(&pid_tgid, &sock);
   
    return 0;
}


// Return of tcp accept function for both IPv4 and IPv6
// Check if the return value is successfull
// Get information from sock structure and send it to user mode.
int connect_udp_return(struct pt_regs *ctx)
{
    

    int ret = PT_REGS_RC(ctx);
    
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct socket **socketpp;
    socketpp = new_socket.lookup(&pid_tgid);

    if (socketpp == NULL) {
        bpf_trace_printk("Error: missed entry in udp connect return.");
        return 0;   // missed entry
    }
    if (ret != 0) {
        bpf_trace_printk("Error: return connect upd msg %d.", ret);
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
        new_socket.delete(&pid_tgid);
        return 0;
    }
    else {
        struct data_ipv6 data = {};
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
        new_socket.delete(&pid_tgid);
        return 0;
    }
}

// Beginning of UDP send msg, for both IPv4 and IPv6, udp_sendmsg and udpv6_sendmsg functions
// Updates eBPF maps with sock and msg -> to get destination
int udp_sendmsg_entry(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t len)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    new_sock.update(&pid_tgid, &sk);  
    new_msg.update(&pid_tgid, &msg); 
    return 0;
}

// Return of udp send msg function for both IPv4 and IPv6
// Check if the return value < 0 that means that no msg was sent
// Check if sock contains information about destination -> 
//          destination was therefore already anotated via connect_udp
// Get information from sock structure and from msg structure and send it to user mode.
int udp_sendmsg_return(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tgid = pid_tgid;

    int ret = PT_REGS_RC(ctx);


    struct sock **skpp;
    skpp = new_sock.lookup(&pid_tgid);
    if (skpp == NULL) {
        bpf_trace_printk("Error: missed entry in udp sendmsg return.");
        return 0;   // missed entry
    }
    struct msghdr **msgp;
    msgp = new_msg.lookup(&pid_tgid);
    if (msgp == NULL) {
        bpf_trace_printk("Error: missed entry in udp sendmsg return.");
        return 0;   // missed entry
    }
    if (ret < 0){
        bpf_trace_printk("Error return udp sendmsg  %d.", ret);
        new_sock.delete(&pid_tgid);
        new_msg.delete(&pid_tgid);
        return 0;
    }
    struct sock *skp = *skpp;
    
    
    u16 family = skp->sk_family;
    u16 protocol = skp->sk_protocol;
    u16 lport = skp->__sk_common.skc_num;
    struct msghdr *msg = *msgp;
    if (family == AF_INET) {//IPv4
        if (skp->__sk_common.skc_daddr != 0){ // connection is traced viac udp_connect

            bpf_trace_printk("UDP sendmsg known address %d", skp->__sk_common.skc_daddr);
            new_sock.delete(&pid_tgid);
            new_msg.delete(&pid_tgid);
            return 0;
        }
        struct sockaddr_in *usin = (struct sockaddr_in *)msg->msg_name;

        struct data_ipv4 data = {};
        bpf_get_current_comm(data.comm, sizeof(data.comm));
        data.family = family;
        data.protocol = protocol;
        data.type = skp->sk_type;
        data.state = skp->sk_state;
        data.sport = lport;
        
        data.pid = pid;
        data.tgid = tgid;
        data.saddr = skp->__sk_common.skc_rcv_saddr;

        data.daddr = usin->sin_addr.s_addr;
        u16 dport = usin->sin_port;
        data.dport = ntohs(dport);
        ipv4events.perf_submit(ctx, &data, sizeof(data));
        return 0;
    }
    else{
        struct sockaddr_in6 *usin6 = (struct sockaddr_in6 *)msg->msg_name;
        struct data_ipv6 data = {};
        bpf_probe_read_kernel(&data.saddr, sizeof(data.saddr),
                           &skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&data.daddr, sizeof(data.daddr), 
                           &skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);

        if (data.daddr != 0 || !usin6){ // connection is traced viac udp_connect

            bpf_trace_printk("UPDv6 sendmsg known address %d.", skp->__sk_common.skc_daddr);
            new_sock.delete(&pid_tgid);
            new_msg.delete(&pid_tgid);
            return 0;
        }

        bpf_get_current_comm(data.comm, sizeof(data.comm));
        data.family = family;
        data.protocol = protocol;
        data.type = skp->sk_type;
        data.state = skp->sk_state;
        data.sport = lport;
        
        data.pid = pid;
        data.tgid = tgid;
        
        data.dport = usin6->sin6_port;
        bpf_probe_read_kernel(&data.daddr, sizeof(data.daddr), 
                           &usin6->sin6_addr);

        ipv6events.perf_submit(ctx, &data, sizeof(data));
        new_sock.delete(&pid_tgid);
        new_msg.delete(&pid_tgid);
        return 0;

    }
        
}

// Beginning of UDP recv msg, for both IPv4 and IPv6, udp_recvmsg and udpv6_recvmsg functions
// Updates eBPF maps with sock and msg -> to get destination
int udp_recvmsg_entry(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, 
    size_t len,int flags, int *addr_len)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    new_sock.update(&pid_tgid, &sk);  
    new_msg.update(&pid_tgid, &msg); 
    return 0;
}

// Return of udp recv msg function for both IPv4 and IPv6
// Check if the return value < 0 that means that no msg was sent
// Check if sock contains information about destination -> 
//          destination was therefore already anotated via connect_udp
// Get information from sock structure and from msg structure and send it to user mode.
int udp_recvmsg_return(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tgid = pid_tgid;

    int ret = PT_REGS_RC(ctx);


    struct sock **skpp;
    skpp = new_sock.lookup(&pid_tgid);
    if (skpp == NULL) {
        bpf_trace_printk("Error: missed entry in udp sendmsg return.");
        return 0;   // missed entry
    }
    struct msghdr **msgp;
    msgp = new_msg.lookup(&pid_tgid);
    if (msgp == NULL) {
        bpf_trace_printk("Error: missed entry in udp sendmsg return.");
        return 0;   // missed entry
    }

    if (ret < 0){
        bpf_trace_printk("Error return recvmsg udp %d. ", ret);
        new_sock.delete(&pid_tgid);
        new_msg.delete(&pid_tgid);
        return 0;
    }

    struct sock *skp = *skpp;
    u16 family = skp->sk_family;
    u16 protocol = skp->sk_protocol;
    u16 lport = skp->__sk_common.skc_num;
    struct msghdr *msg = *msgp;

    if (family == AF_INET) {//IPv4
        if (skp->__sk_common.skc_daddr != 0){ // connection is traced viac udp_connect

            bpf_trace_printk("Udp recvmsg known address %d.", skp->__sk_common.skc_daddr);
            new_sock.delete(&pid_tgid);
            new_msg.delete(&pid_tgid);
            return 0;
        }
        struct sockaddr_in *usin = (struct sockaddr_in *)msg->msg_name;

        struct data_ipv4 data = {};
        bpf_get_current_comm(data.comm, sizeof(data.comm));
        
        data.family = family;
        data.protocol = protocol;
        data.type = skp->sk_type;
        data.state = skp->sk_state;
        data.sport = lport;
        
        data.pid = pid;
        data.tgid = tgid;
        data.saddr = skp->__sk_common.skc_rcv_saddr;

        data.daddr = usin->sin_addr.s_addr;
        u16 dport = usin->sin_port;
        data.dport = ntohs(dport);
        ipv4events.perf_submit(ctx, &data, sizeof(data));
        return 0;
    }
    else{
        struct sockaddr_in6 *usin6 = (struct sockaddr_in6 *)msg->msg_name;
        struct data_ipv6 data = {};
        bpf_probe_read_kernel(&data.saddr, sizeof(data.saddr),
                           &skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&data.daddr, sizeof(data.daddr), 
                           &skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);

        if (data.daddr != 0 || !usin6){ // connection is traced viac udp_connect

            bpf_trace_printk("UDPv6 recvmsg known address %d.", skp->__sk_common.skc_daddr);
            new_sock.delete(&pid_tgid);
            new_msg.delete(&pid_tgid);
            return 0;
        }

        bpf_get_current_comm(data.comm, sizeof(data.comm));
        data.family = family;
        data.protocol = protocol;
        data.type = skp->sk_type;
        data.state = skp->sk_state;
        data.sport = lport;
        
        data.pid = pid;
        data.tgid = tgid;
        
        data.dport = usin6->sin6_port;
        bpf_probe_read_kernel(&data.daddr, sizeof(data.daddr), 
                           &usin6->sin6_addr);

        ipv6events.perf_submit(ctx, &data, sizeof(data));
        new_sock.delete(&pid_tgid);
        new_msg.delete(&pid_tgid);
        return 0;

    }
}