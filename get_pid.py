from bcc import BPF

# eBPF program
bpf_program = '''
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

BPF_HASH(connects, u32, u32);

int kprobe__sys_connect(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    connects.update(&pid, &pid);
    return 0;
}
'''

# Load eBPF program
bpf = BPF(text=bpf_program)

# Attach kprobe to sys_connect
bpf.attach_kprobe(event="sys_connect", fn_name="kprobe__sys_connect")

# Loop to print PIDs
print("Monitoring new network connections... Press Ctrl+C to exit")
try:
    while True:
        for k, v in bpf["connects"].items():
            print(f"PID: {k.value}")
        bpf["connects"].clear()
except KeyboardInterrupt:
    print("Detaching...")
    pass
