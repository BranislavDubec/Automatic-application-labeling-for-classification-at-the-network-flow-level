""" 
    Script that monitors system calls: inet_create, inet6_create,
    tcp_v4_connect, tcp_v6_connect, inet_dgram_connect, inet_csk_accept,
    udp_sendmsg, udpv6_sendmsg, udp_recvmsg, udpv6_recvmsg. 
    Script creates a log file in logs folder, that contains new network 
    connections, that are anotated by its aplication, or by URL address
    of request in case the connections is made by browser.


    Licensed under the Apache License, Version 2.0 (the "License")
"""

__author__ = "Branislav Dubec"
__version__ = "1.0.5"


from bcc import BPF
import psutil
import os
import threading
from concurrent.futures import ThreadPoolExecutor
import json
import csv
from struct import pack
from socket import inet_ntop, AF_INET, AF_INET6
from urllib.parse import urlparse
from collections import OrderedDict

class LimitedSizeDict(OrderedDict):
    def __init__(self, max_size=1000, file_path=""):
        super().__init__()
        self.max_size = max_size
        self.file_path = file_path

    def __setitem__(self, key, value):
        if key in self:
            self[key].append(value)
            super().move_to_end(key)
        else:
            if len(self) == self.max_size:
                key, items = self.popitem(last=False)
                for (url, line) in items:
                    with open(self.file_path, "a") as no_match_file:
                        no_match_file.write(line + "\n")
                super().__setitem__(key, [value])
                self.move_to_end(key)
            else:
                super().__setitem__(key, [value])
                self.move_to_end(key)
    
    def print_values(self):
        with open(self.file_path, "a") as no_match_file:
            for key,values in self.items():
                for value in values:
                    if type(value) is list:
                        for list_value in value:
                            try:
                                no_match_file.write(list_value[1] + "\n")
                            except:
                                no_match_file.write(str(list_value))
                    else:
                        no_match_file.write(value[1] + "\n")

    def get_pop_item(self,key):
        if key in self:
            values = self[key]
            url, line = values.pop(0)
            if not values:
                del self[key]
            else:
                self[key] = values
            return url
        return ""

### Global variables

# BPF code
b = BPF(src_file="Detect_new_connections.c")

"""
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
"""
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
    262: "MPTCP",
}

functions_to_events = {
    "inet_create": ("new_ipv4_socket_entry", "new_ipv4_socket_return"),
    "inet6_create": ("new_ipv6_socket_entry", "new_ipv6_socket_return"),
    "tcp_v4_connect": ("tcp_connect_entry", "tcp_connect_return"),
    "tcp_v6_connect": ("tcp_connect_entry", "tcp_connect_return"),
    "inet_dgram_connect": ("connect_udp_entry", "connect_udp_return"),
    "inet_csk_accept": ("accept_entry", "accept_return"),
    "udp_sendmsg": ("udp_sendmsg_entry", "udp_sendmsg_return"),
    "udpv6_sendmsg": ("udp_sendmsg_entry", "udp_sendmsg_return"),
    "udp_recvmsg": ("udp_recvmsg_entry", "udp_recvmsg_return"),
    "udpv6_recvmsg": ("udp_recvmsg_entry", "udp_recvmsg_return"),
}


filter_labels = ["systemd-resolve"]
log_file_path = "logs/socket_log.csv"
no_match_file_path = "logs/no_match.json"
pipe_path = "/tmp/firefox_url_pipe"

headers = [
    "PID",
    "TGID",
    "COMMAND",
    "SOURCE ADDRESS",
    "DESTINATION ADDRESS",
    "SOURCE PORT",
    "DESTINATION PORT",
    "LABEL",
    "PROTOCOL",
]

url_ip_browser_data = {}
browser_request_data = LimitedSizeDict(max_size = 1000, file_path="../logs/no_match.json")
known_address = {}

# lock to acquire writing privileges to output file
lock = threading.Lock()
# Thread that waits for messages in mkfifo file
# and is responsible for logging connections created
# by web browsers
def read_from_pipe():

    # set permissions
    old_umask = os.umask(0)

    if not os.path.exists(pipe_path):
        os.mkfifo(pipe_path, 0o666)

    os.umask(old_umask)

    with open(pipe_path, "r") as pipe:

        while True:
            message = pipe.readline().strip()
            if message:
                try:
                    line = json.loads(message)
                except json.JSONDecodeError as e:
                    print(f"Error decoding JSON: {e}", file=sys.stderr)
                    continue
                parseResult = urlparse(line["url"])
                url = parseResult.netloc
                ip = line["ip"]
                port = parseResult.scheme
                if port == "https" or port == "wss":
                    port = 443
                else:
                    port = 80
                hash_value = hash((ip, port))
                key = (ip, port)
                known_address.setdefault(key, set()).add(url)
                if key in url_ip_browser_data:
                    events_list = url_ip_browser_data[key]

                    first_event = events_list.pop(0)

                    if not events_list:
                        del url_ip_browser_data[key]
                    else:
                        url_ip_browser_data[key] = events_list
                    first_event["label"] = first_event["label"] + "-" + url
                    row = list(first_event.values())
                    
                    lock.acquire()
                    with open(log_file_path, "a") as log_file:
                        writer = csv.writer(log_file)
                        writer.writerow(row)
                    lock.release()
                else:
                    browser_request_data[(ip,port)] = (url,json.dumps(line))                                             
                


pipe_thread = threading.Thread(target=read_from_pipe, daemon=True)
pipe_thread.start()
thread_executor = ThreadPoolExecutor(max_workers=5)


def log_event(event):
    comm = event.comm.decode("UTF-8")
    if filter_event(comm):
        return
    try:
        src_ip = inet_ntop(AF_INET, pack("I", event.saddr))
        dst_ip = inet_ntop(AF_INET, pack("I", event.daddr))
    except ValueError as e:
        src_ip = inet_ntop(AF_INET6, event.saddr)
        dst_ip = inet_ntop(AF_INET6, event.daddr)

    try:
        label = get_application_name(event.pid)
    except Exception as e:
        label = "No Process found"
    used_protocol = protocol_dict[event.protocol]
    pid = event.pid
    tgid = event.tgid
    dport = event.dport
    sport = event.sport
    row = [pid, tgid, comm, src_ip, dst_ip, sport, dport, label, used_protocol]

    if is_new_web_request(comm, label, dst_ip):
        key = (dst_ip, dport)
        url = browser_request_data.get_pop_item(key)
        if url:
            label = label + "-" + url
            row = [pid, tgid, comm, src_ip, dst_ip, sport, dport, label, used_protocol]
            lock.acquire()
            with open(log_file_path, "a") as log_file:
                writer = csv.writer(log_file)
                writer.writerow(row)
            lock.release()
            return
        # hash_ip_port = hash((dstip,event.dport))
        row_dict = {
            "pid": pid,
            "tgid": tgid,
            "comm": comm,
            "srcip": src_ip,
            "dstip": dst_ip,
            "sport": sport,
            "dport": dport,
            "label": label,
            "protocol": used_protocol,
        }

        url_ip_browser_data.setdefault(key, []).append(row_dict)
        # url_ip_browser_data[hash_ip_port] = event
    else:
        lock.acquire()
        with open(log_file_path, "a") as log_file:
            writer = csv.writer(log_file)
            writer.writerow(row)
        lock.release()


def attach_function_to_event(event_name, entry_function, return_function):
    global b
    event_name_bytes = bytes(event_name, "utf-8")
    if b.get_kprobe_functions(event_name_bytes):
        b.attach_kprobe(event=event_name, fn_name=entry_function)
        b.attach_kretprobe(event=event_name, fn_name=return_function)
    else:
        print(
            f"ERROR: {event_name} kernel not found or traceable."
            f"The kernel might be too old or the function has been inlined."
        )


def get_application_name(pid):
    try:
        process = psutil.Process(pid)
        return process.name()
    except Exception as e:
        print(f"Not found process for PID: %d", pid)
        return ""


# Filter events, DNS Res or systemd-resolved
def filter_event(comm):
    return comm in filter_labels or comm.startswith("DNS Res")


def is_new_web_request(comm, label, dstip):
    if comm == "Socket Thread":
        if label == "firefox":  # add different browsers
            return True
    return False


def print_ipv6_event(cpu, data, size):
    event = b["ipv6events"].event(data)

    thread_executor.submit(log_event, event)


def print_ipv4_event(cpu, data, size):
    event = b["ipv4events"].event(data)

    thread_executor.submit(log_event, event)


if __name__ == "__main__":

    for event, (entry_function, return_function) in functions_to_events.items():
        attach_function_to_event(event, entry_function, return_function)

    lock.acquire()
    with open(log_file_path, "a") as log_file:
        writer = csv.writer(log_file)
        writer.writerow(headers)
    lock.release()

    b["ipv4events"].open_perf_buffer(print_ipv4_event)
    b["ipv6events"].open_perf_buffer(print_ipv6_event)

    print("Logging new socket connections. Press Ctrl+C to stop.")
    try:
        while True:
            b.perf_buffer_poll()

    except KeyboardInterrupt:
        browser_request_data.print_values()
        lock.acquire()
        with open(log_file_path, "a") as log_file:
            writer = csv.writer(log_file)
            for key, values in url_ip_browser_data.items():
                for value in values:
                    if key in known_address:
                        url_set = known_address[key]
                        if len(url_set) == 1:
                            url = next(iter(url_set))
                        #else:
                            #url = ''.join(url_set)
                    else:
                        url = ""
                    value["label"] = value["label"] + "-" + str(url)
                    
                    writer.writerow(value.values())
        lock.release()
        print("Stopped logging socket connections.")
