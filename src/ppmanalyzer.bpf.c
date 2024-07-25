#include "ppm_helper.h"
#include "ppm_common.h"
typedef struct
{
    __u16 portId;
    __u32 pid;
    __u32 packet_count;
} port_to_pid_data;

typedef struct
{
    __u32 pid;
    char process_name[MAX_STR_LEN];
    __u32 total_packets;
} process_data;

typedef struct
{
    __u32 event_id;
    __u32 port_id;
    __u32 pid;
    __u32 packet_count;
    __u32 src_addr;
    __u32 dst_addr;
    __u32 src_port_id;
    char comm[16];
} perf_ppm_event;

static inline __u16 my_htons(__u16 hostshort)
{
    return (hostshort << 8) | (hostshort >> 8);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} ppm_perf_events SEC(".maps");

struct
{
    __uint(type,BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size,sizeof(u32));
    __uint(value_size, sizeof(process_data));
    __uint(max_entries,512);
} process_map SEC(".maps");




SEC("tracepoint/net/netif_receive_skb")
int netif_receive_skb(struct trace_event_raw_net_dev_template *ctx)
{
    struct sk_buff skb;
    struct sock sk;
    struct iphdr ip_header;
    perf_ppm_event ppm_event;
    bpf_probe_read(&skb, sizeof(skb), ctx->skbaddr);
    bpf_probe_read(&ip_header, sizeof(struct iphdr), skb.data);
    ppm_event.src_addr = ip_header.saddr;
    ppm_event.dst_addr = ip_header.daddr;
    ppm_event.pid = bpf_get_current_pid_tgid() >> 32;
    if(ip_header.protocol == IPPROTO_TCP)
    {
       struct tcphdr tcp_header;
       bpf_probe_read(&tcp_header, sizeof(struct tcphdr), skb.data + sizeof(struct iphdr));
       ppm_event.src_port_id =  my_htons(tcp_header.source);
       ppm_event.port_id = my_htons(tcp_header.dest);
    }
    else if(ip_header.protocol == IPPROTO_UDP)
    {
       struct udphdr udp_header;
       bpf_probe_read(&udp_header, sizeof(struct udphdr), skb.data + sizeof(struct iphdr));
       ppm_event.src_port_id =  my_htons(udp_header.source);
       ppm_event.port_id = my_htons(udp_header.dest);

    }
    ppm_event.event_id = EVENT_NEW_PACKET_DETECTED;
    bpf_get_current_comm(&ppm_event.comm, sizeof(ppm_event.comm));
    bpf_perf_event_output(ctx, &ppm_perf_events, BPF_F_CURRENT_CPU, &ppm_event, sizeof(ppm_event));
    return 0;
}




SEC("tracepoint/sched/sched_process_fork")
int trace_sched_process_fork(struct trace_event_raw_sched_process_fork *ctx)
{
    __u32 parent_id = ctx->parent_pid;
    __u32 child_id = ctx->child_pid;
    process_data pdata;
    pdata.total_packets = 0;
    bpf_printk("Parent pid: %d, child pid = %d", parent_id, child_id);
    perf_ppm_event ppm_event;
    ppm_event.event_id = EVENT_NEW_PROCESS_CREATED;
    ppm_event.pid = child_id;
    bpf_perf_event_output(ctx, &ppm_perf_events, BPF_F_CURRENT_CPU, &ppm_event, sizeof(ppm_event));
    return 0;
}

SEC("kprobe/tcp_v4_connect")
int kprobe_tcp_v4_connect(struct pt_regs *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct sock *sk;
    sk = (struct sock *)PT_REGS_PARM1(ctx);
    perf_ppm_event ppm_event;
    ppm_event.pid = pid;
    ppm_event.event_id = EVENT_NEW_PACKET_PORT_MAPPED;
    __u16 dport = 0;
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    ppm_event.port_id = my_htons(dport);
    bpf_perf_event_output(ctx, &ppm_perf_events, BPF_F_CURRENT_CPU, &ppm_event, sizeof(ppm_event));
    return 0;
}

SEC("kprobe/tcp_v6_connect")
int kprobe_tcp_v6_connect(struct pt_regs *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct sock *sk;
    sk = (struct sock *)PT_REGS_PARM1(ctx);
    perf_ppm_event ppm_event;
    ppm_event.pid = pid;
    ppm_event.event_id = EVENT_NEW_PACKET_PORT_MAPPED;
    __u16 dport = 0;
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    ppm_event.port_id = my_htons(dport);
    bpf_perf_event_output(ctx, &ppm_perf_events, BPF_F_CURRENT_CPU, &ppm_event, sizeof(ppm_event));
    return 0;
}

SEC("kprobe/udp_sendmsg")
int kprobe_udp_sendmsg(struct pt_regs *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct sock *sk;
    sk = (struct sock *)PT_REGS_PARM1(ctx);
    perf_ppm_event ppm_event;
    ppm_event.pid = pid;
    ppm_event.event_id = EVENT_NEW_PACKET_PORT_MAPPED;
    __u16 dport = 0;
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    ppm_event.port_id = my_htons(dport);
    bpf_perf_event_output(ctx, &ppm_perf_events, BPF_F_CURRENT_CPU, &ppm_event, sizeof(ppm_event));
    return 0;
}

SEC("kprobe/udp_recvmsg")
int kprobe_udp_recmsg(struct pt_regs *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct sock *sk;
    sk = (struct sock *)PT_REGS_PARM1(ctx);
    perf_ppm_event ppm_event;
    ppm_event.pid = pid;
    ppm_event.event_id = EVENT_NEW_PACKET_PORT_MAPPED;
    __u16 dport = 0;
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    ppm_event.port_id = my_htons(dport);
    bpf_perf_event_output(ctx, &ppm_perf_events, BPF_F_CURRENT_CPU, &ppm_event, sizeof(ppm_event));
    return 0;
}

