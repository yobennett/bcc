#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# tcplifeext    Trace the lifespan of TCP sessions and summarize.
#               For Linux, uses BCC, BPF. Embedded C.
#
# USAGE: tcplifeext [-h] [-C] [-S] [-p PID] [interval [count]]
#
# This uses dynamic tracing of kernel functions, and will need to be updated
# to match kernel changes.
#
# While throughput counters are emitted, they are fetched in a low-overhead
# manner: reading members of the tcp_info struct on TCP close. ie, we do not
# trace send/receive.
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# IDEA: Julia Evans
#
# 18-Oct-2016   Brendan Gregg   Created this.

from __future__ import print_function
from bcc import BPF
import argparse
from socket import inet_ntop, ntohs, AF_INET, AF_INET6
from struct import pack
import ctypes as ct
import tempfile
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

BPF_HASH(birth, struct sock *, u64);

// separate data structs for ipv4 and ipv6
struct ipv4_data_t {
    // XXX: switch some to u32's when supported
    u64 ts_us;
    u64 pid;
    u64 saddr;
    u64 daddr;
    u64 ports;
    u64 rx_b;
    u64 tx_b;
    u64 span_us;
    char task[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(ipv4_events);

struct id_t {
    u32 pid;
    char task[TASK_COMM_LEN];
};
BPF_HASH(whoami, struct sock *, struct id_t);

int kprobe__tcp_set_state(struct pt_regs *ctx, struct sock *sk, int state)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    // lport is either used in a filter here, or later
    u16 lport = sk->__sk_common.skc_num;

    // dport is either used in a filter here, or later
    u16 dport = sk->__sk_common.skc_dport;

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
    if (state < TCP_FIN_WAIT1) {
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
    if (state == TCP_SYN_SENT || state == TCP_LAST_ACK) {
        // now we can PID filter, both here and a little later on for CLOSE
        struct id_t me = {.pid = pid};
        bpf_get_current_comm(&me.task, sizeof(me.task));
        whoami.update(&sk, &me);
    }

    if (state != TCP_CLOSE)
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

    // get throughput stats. see tcp_get_info().
    u64 rx_b = 0, tx_b = 0, sport = 0;
    struct tcp_sock *tp = (struct tcp_sock *)sk;
    rx_b = tp->bytes_received;
    tx_b = tp->bytes_acked;

    u16 family = sk->__sk_common.skc_family;

    if (family == AF_INET) {
        struct ipv4_data_t data4 = {.span_us = delta_us,
            .rx_b = rx_b, .tx_b = tx_b};
        data4.ts_us = bpf_ktime_get_ns() / 1000;
        data4.saddr = sk->__sk_common.skc_rcv_saddr;
        data4.daddr = sk->__sk_common.skc_daddr;
        // a workaround until data4 compiles with separate lport/dport
        data4.pid = pid;
        data4.ports = ntohs(dport) + ((0ULL + lport) << 32);
        if (mep == 0) {
            bpf_get_current_comm(&data4.task, sizeof(data4.task));
        } else {
            bpf_probe_read(&data4.task, sizeof(data4.task), (void *)mep->task);
        }
        ipv4_events.perf_submit(ctx, &data4, sizeof(data4));

    } else /* 6 */ {
    }

    if (mep != 0)
        whoami.delete(&sk);

    return 0;
}
"""

if debug:
    print(bpf_text)

# event data
TASK_COMM_LEN = 16      # linux/sched.h

class Data_ipv4(ct.Structure):
    _fields_ = [
        ("ts_us", ct.c_ulonglong),
        ("pid", ct.c_ulonglong),
        ("saddr", ct.c_ulonglong),
        ("daddr", ct.c_ulonglong),
        ("ports", ct.c_ulonglong),
        ("rx_b", ct.c_ulonglong),
        ("tx_b", ct.c_ulonglong),
        ("span_us", ct.c_ulonglong),
        ("task", ct.c_char * TASK_COMM_LEN)
    ]

#
# Setup output formats
#
# Don't change the default output (next 2 lines): this fits in 80 chars. I
# know it doesn't have NS or UIDs etc. I know. If you really, really, really
# need to add columns, columns that solve real actual problems, I'd start by
# adding an extended mode (-x) to included those columns.
#
format_string = "pid=%d task=%s saddr=%s sport=%d daddr=%s dport=%d tx=%d rx=%d span_us=%.2f\n"

# process event
def print_ipv4_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data_ipv4)).contents
    global start_ts
    with open(tf.name, 'a') as f:
        f.write(format_string % (event.pid, event.task.decode(),
            inet_ntop(AF_INET, pack("I", event.saddr)), event.ports >> 32,
            inet_ntop(AF_INET, pack("I", event.daddr)), event.ports & 0xffffffff,
            event.tx_b / 1024, event.rx_b / 1024, float(event.span_us) / 1000))

# initialize BPF
b = BPF(text=bpf_text)

# header
start_ts = 0
tf = tempfile.NamedTemporaryFile(delete=False) 

# read events
b["ipv4_events"].open_perf_buffer(print_ipv4_event, page_cnt=64)
while 1:
    b.kprobe_poll()
