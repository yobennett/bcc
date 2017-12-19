#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# tcpstats  Trace the lifespan of TCP sessions and summarize.
#           For Linux, uses BCC, BPF. Embedded C.
#
# USAGE: tcpstats [-h] [-C] [-S] [-p PID] [interval [count]]
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
from collections import deque
import argparse
from socket import inet_ntop, ntohs, AF_INET, AF_INET6
from struct import pack
import ctypes as ct
import tempfile
import sched
import datetime
import time
import os
import threading

# arguments
examples = """examples:
    ./tcpstats
"""
parser = argparse.ArgumentParser(
    description="Collect TCP session stats",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
args = parser.parse_args()
debug = 0

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#define KBUILD_MODNAME "foo"
#include <linux/tcp.h>
#include <net/tcp.h>
#include <net/sock.h>
#include <bcc/proto.h>

struct birth_t {
    u64 ts;
    u64 active;
};
BPF_HASH(birth, struct sock *, struct birth_t);

struct id_t {
    u32 pid;
    char task[TASK_COMM_LEN];
};
BPF_HASH(whoami, struct sock *, struct id_t);

int kretprobe__inet_csk_accept(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_RC(ctx);
    if (sk == NULL)
        return 0;
    
    bpf_trace_printk("inet_csk_accept\\n");    
    u64 ts = bpf_ktime_get_ns();
    struct birth_t b = {.ts = ts, .active = 0};
    birth.update(&sk, &b);
    return 0;
}

int trace_connect(struct pt_regs *ctx, struct sock *sk)
{
    bpf_trace_printk("connect\\n");
    u64 ts = bpf_ktime_get_ns();
    struct birth_t b = {.ts = ts, .active = 1};
    birth.update(&sk, &b);
    return 0;
};

int kprobe__tcp_set_state(struct pt_regs *ctx, struct sock *sk, int state)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    // lport is either used in a filter here, or later
    u16 lport = sk->__sk_common.skc_num;
    // dport is either used in a filter here, or later
    u16 dport = sk->__sk_common.skc_dport;

    if (state != TCP_CLOSE) {
        return 0;
    }

    // determine lifecycle span
    struct birth_t *b;
    u64 delta_us;
    b = birth.lookup(&sk);

    if (b == NULL) {
        // no birth info
        bpf_trace_printk("no birth\\n");
        return 0;

    }

    if (b->ts == 0) {
        bpf_trace_printk("no birth ts\\n");
        return 0;
    }
    birth.delete(&sk);
    bpf_trace_printk("birth at %d\\n", b->ts);
    return 0;
};

"""

if debug:
    print(bpf_text)

# event data
TASK_COMM_LEN = 16      # linux/sched.h

# initialize BPF
b = BPF(text=bpf_text)
b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect")
b.attach_kprobe(event="tcp_v6_connect", fn_name="trace_connect")


# handle events
while 1:
    b.kprobe_poll()
