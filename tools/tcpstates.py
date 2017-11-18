#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# tcplife   Trace the lifespan of TCP sessions and summarize.
#           For Linux, uses BCC, BPF. Embedded C.
#
# USAGE: tcplifeext [-h] [-C] [-S] [-p PID] [interval [count]]
#
# This uses dynamic tracing of kernel functions, and will need to be updated
#

from __future__ import print_function
from bcc import BPF
import argparse
from socket import inet_ntop, ntohs, AF_INET, AF_INET6
from struct import pack
import ctypes as ct
from time import strftime

# arguments
examples = """examples:
    ./tcplifeext           # trace all TCP connect()s
"""
parser = argparse.ArgumentParser(
    description="Trace the lifespan of TCP sessions and summarize",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
args = parser.parse_args()
debug = 0

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#define KBUILD_MODNAME "foo"
#include <linux/tcp.h>
#include <net/sock.h>
#include <bcc/proto.h>

// separate data structs for ipv4 and ipv6
struct ipv4_data_t {
    u64 saddr;
    u64 daddr;
    u64 ports;
    u64 state;
};
BPF_PERF_OUTPUT(ipv4_events);

int kprobe__tcp_set_state(struct pt_regs *ctx, struct sock *sk, int state)
{
    // lport is either used in a filter here, or later
    u16 lport = sk->__sk_common.skc_num;
    
    // dport is either used in a filter here, or later
    u16 dport = sk->__sk_common.skc_dport;

    // get throughput stats. see tcp_get_info().
    struct tcp_sock *tp = (struct tcp_sock *)sk;

    u16 family = sk->__sk_common.skc_family;

    if (family == AF_INET) {
        struct ipv4_data_t data4 = {};
        data4.saddr = sk->__sk_common.skc_rcv_saddr;
        data4.daddr = sk->__sk_common.skc_daddr;
        data4.ports = ntohs(dport) + ((0ULL + lport) << 32);
        data4.state = state;
        ipv4_events.perf_submit(ctx, &data4, sizeof(data4));
    }

    return 0;
}
"""

if debug:
    print(bpf_text)

# event data
class Data_ipv4(ct.Structure):
    _fields_ = [
        ("saddr", ct.c_ulonglong),
        ("daddr", ct.c_ulonglong),
        ("ports", ct.c_ulonglong),
        ("state", ct.c_ulonglong)
    ]


def tcp_state(state):
    return {
        0: "invalid",
        1: "ESTABLISHED",
        2: "SYN_SENT",
        3: "SYN_RECV",
        4: "FIN_WAIT1",
        5: "FIN_WAIT2",
        6: "TIME_WAIT",
        7: "CLOSE",
        8: "CLOSE_WAIT",
        9: "LAST_ACK",
        10: "LISTEN",
        11: "CLOSING",
    }[state]

#
# Setup output formats
#
header_string = "%-15s %-5s %-15s %-5s %15s"
format_string = "%-15s %-5d %-15s %-5d %15s"

# process event
def print_ipv4_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data_ipv4)).contents
    print(format_string % (
        inet_ntop(AF_INET, pack("I", event.saddr)), event.ports >> 32,
        inet_ntop(AF_INET, pack("I", event.daddr)), event.ports & 0xffffffff,
        tcp_state(event.state)))

# initialize BPF
b = BPF(text=bpf_text)

# header
print(header_string % ("LADDR", "LPORT", "RADDR", "RPORT", "STATE"))

# read events
b["ipv4_events"].open_perf_buffer(print_ipv4_event, page_cnt=64)
while 1:
    b.kprobe_poll()
