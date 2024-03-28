from bcc import BPF
import ctypes
import psutil
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack


b = BPF(src_file = "get_flow_key.c")

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

    1: "TCP_ESTABLISHED",  
    2: "TCP_SYN_SENT",     
    3: "TCP_SYN_RECV",    
    4: "TCP_FIN_WAIT1",    
    5: "TCP_FIN_WAIT2",    
    6: "TCP_TIME_WAIT",    
    7: "TCP_CLOSE",
    8: "TCP_CLOSE_WAIT",
    9: "TCP_LAST_ACK",
    10: "TCP_LISTEN",
    11: "TCP_CLOSING",
    12: "TCP_NEW_SYN_RECV",
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

log_file_path = "../logs/socket_log.txt"
file_format = "{:<10} {:<10} {:<15} {:<40} {:<40} {:<12} {:<17} {:<10} {:<15}"
header = file_format.format("PID", "TGID", "COMMAND", "SOURCE ADDRESS", "DESTINATION ADDRESS", "SOURCE PORT", "DESTINATION PORT", "LABEL", "TIME")

def attach_function_to_event(event_name, entry_function, return_function):
    global b
    event_name_bytes = bytes(event_name, 'utf-8')
    if b.get_kprobe_functions(event_name_bytes):
        b.attach_kprobe(event=event_name, fn_name=entry_function)
        b.attach_kretprobe(event=event_name, fn_name=return_function)
    else:
        print(f"ERROR: {event_name} kernel not found or traceable. The kernel might be too old or the function has been inlined.")

#raise error, to catch in amin?
def get_application_name(pid):
    try:
        process = psutil.Process(pid)
        return process.name()
    except Exception as e:
        raise e


functions_to_events = {
    "inet_create": ("new_ipv4_socket_entry", "new_ipv4_socket_return"),
    "inet6_create": ("new_ipv6_socket_entry", "new_ipv6_socket_return"),
    "tcp_v4_connect": ("tcp_connect_entry", "tcp_connect_return"),
    "tcp_v6_connect": ("tcp_connect_entry", "tcp_connect_return"),
    "inet_dgram_connect": ("connect_udp_entry", "connect_udp_return")
    # "udp_sendmsg": ("udp_v4_sendmsg_entry", "udp_v4_sendmsg_return") 
}

for event, (entry_function, return_function) in functions_to_events.items():
    attach_function_to_event(event, entry_function, return_function)


with open(log_file_path, "w") as log_file:

    log_file.write(header)

    def print_ipv6_event_debug(cpu, data, size):
        event = b["ipv6eventsdebug"].event(data)
        print(f"PID: {event.pid}, TGID: {event.tgid},COMM: {event.comm},FAMILY: {family_dict.get(event.family,'UNKNOWN: ' + str(event.family))},"
            f"TYPE: {type_dict.get(event.type, 'UNKNOWN: ' + str(event.type))},STATE: {state_dict.get(event.state, 'UNKNOWN: ' + str(event.state))},"
            f"PROTOCOL: {protocol_dict.get(event.protocol, 'UNKNOWN: ' + str(event.protocol))},"
            f"SADDR: {inet_ntop(AF_INET6, event.saddr)}.DADDR: {inet_ntop(AF_INET6, event.daddr)},SPORT: {event.sport},"
            f"DPORT: {event.dport}, INNER STATE: {event.inner_state},"
            f"timestamp: {event.ts_us}")
    
    def print_ipv6_event(cpu, data, size):
        event = b["ipv6events"].event(data)
        print(f"PID: {event.pid}, TGID: {event.tgid},COMM: {event.comm},FAMILY: {family_dict.get(event.family,'UNKNOWN: ' + str(event.family))},"
            f"TYPE: {type_dict.get(event.type, 'UNKNOWN: ' + str(event.type))},STATE: {state_dict.get(event.state, 'UNKNOWN: ' + str(event.state))},"
            f"PROTOCOL: {protocol_dict.get(event.protocol, 'UNKNOWN: ' + str(event.protocol))},"
            f"SADDR: {inet_ntop(AF_INET6, event.saddr)}.DADDR: {inet_ntop(AF_INET6, event.daddr)},SPORT: {event.sport},"
            f"DPORT: {event.dport}, INNER STATE: {event.inner_state},"
            f"timestamp: {event.ts_us}")
        
        try:
            label = get_application_name(event.pid)
        except Exception as e:
            label = "No Process found"

        row = file_format.format(event.pid, event.tgid, event.comm.decode('UTF-8'), inet_ntop(AF_INET6, event.saddr), 
                                inet_ntop(AF_INET6, event.daddr), event.sport, event.dport, label, event.ts_us)
        log_file.write(row)


    def print_ipv4_event_debug(cpu, data, size):
        event = b["ipv4eventsdebug"].event(data)

        print(f"PID: {event.pid}, TGID: {event.tgid},COMM: {event.comm},FAMILY: {family_dict.get(event.family,'UNKNOWN: ' + str(event.family))},"
                f"TYPE: {type_dict.get(event.type, 'UNKNOWN: ' + str(event.type))},STATE: {state_dict.get(event.state, 'UNKNOWN: ' + str(event.state))},"
                f"PROTOCOL: {protocol_dict.get(event.protocol, 'UNKNOWN: ' + str(event.protocol))},"
                f"SADDR: {inet_ntop(AF_INET, pack('I', event.saddr))}.DADDR: {inet_ntop(AF_INET, pack('I', event.daddr))},SPORT: {event.sport},"
                f"DPORT: {event.dport}, INNER STATE: {event.inner_state},"
                f"timestamp: {event.ts_us}")

    def print_ipv4_event(cpu, data, size):
        event = b["ipv4events"].event(data)

        print(f"PID: {event.pid}, TGID: {event.tgid},COMM: {event.comm},FAMILY: {family_dict.get(event.family,'UNKNOWN: ' + str(event.family))},"
                f"TYPE: {type_dict.get(event.type, 'UNKNOWN: ' + str(event.type))},STATE: {state_dict.get(event.state, 'UNKNOWN: ' + str(event.state))},"
                f"PROTOCOL: {protocol_dict.get(event.protocol, 'UNKNOWN: ' + str(event.protocol))},"
                f"SADDR: {inet_ntop(AF_INET, pack('I', event.saddr))},DADDR: {inet_ntop(AF_INET, pack('I', event.daddr))},SPORT: {event.sport},"
                f"DPORT: {event.dport}, INNER STATE: {event.inner_state},"
                f"timestamp: {event.ts_us}")
        try:
            label = get_application_name(event.pid)
        except Exception as e:
            label = "No Process found"

        row = file_format.format(event.pid, event.tgid, event.comm.decode('UTF-8'), inet_ntop(AF_INET, pack('I', event.saddr)), 
                                inet_ntop(AF_INET, pack('I', event.daddr)), event.sport, event.dport, label, event.ts_us)
        log_file.write(row)


    
    b["ipv4events"].open_perf_buffer(print_ipv4_event)
    b["ipv6events"].open_perf_buffer(print_ipv6_event)

    b["ipv4eventsdebug"].open_perf_buffer(print_ipv4_event_debug)
    b["ipv6eventsdebug"].open_perf_buffer(print_ipv6_event_debug)
    print("Logging new socket connections. Press Ctrl+C to stop.")
    try:
        while True:
            b.perf_buffer_poll()
            

    except KeyboardInterrupt:
        print("Stopped logging socket connections.")