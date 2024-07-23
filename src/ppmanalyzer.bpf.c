#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
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
    struct sock *sk = NULL;
    struct iphdr ip_header;
    struct tcphdr tcp_header;
    perf_ppm_event ppm_event;
    //struct task_struct  *task = NULL;
    bpf_probe_read(&skb, sizeof(skb), ctx->skbaddr);
    sk = skb.sk;
    if(!sk)
        return 0; 
    //bpf_probe_read(&task,sizeof(task),&sk->sk_socket->file->private_data);
    bpf_probe_read(&ip_header, sizeof(struct iphdr), skb.data);
    bpf_probe_read(&tcp_header, sizeof(struct tcphdr), skb.data + sizeof(struct iphdr));
    __u32 src_addr = ip_header.saddr;
    __u32 dst_addr = ip_header.daddr;
    __u16 src_port = my_htons(tcp_header.source);
    __u16 dst_port = my_htons(tcp_header.dest);
    ppm_event.event_id = EVENT_NEW_PACKET_DETECTED;
    ppm_event.src_port_id = src_port;
    ppm_event.port_id = dst_port;
    ppm_event.src_addr = src_addr;
    ppm_event.dst_addr = dst_addr;
    //ppm_event.pid = task->pid;
    bpf_get_current_comm(&ppm_event.comm, sizeof(ppm_event.comm));
    bpf_perf_event_output(ctx, &ppm_perf_events, BPF_F_CURRENT_CPU, &ppm_event, sizeof(ppm_event));
    // bpf_printk("tcp_header1: %d %d \n", tcp_header.source, tcp_header.dest);
    // bpf_printk("Protocol: %x | Src Addr: %d.%d.%d.%d | Src Port: %d| Dst Addr: %d.%d.%d.%d| Dst Port: %d\n", ip_header.protocol, (src_addr) & 0xff, (src_addr >> 8) & 0xff, (src_addr >> 16) & 0xff, (src_addr >> 24) & 0xff, src_port, (dst_addr) & 0xff, (dst_addr >> 8) & 0xff, (dst_addr >> 16) & 0xff, (dst_addr >> 24) & 0xff, dst_port);
    return 0;
}

SEC("kprobe/tcp_v4_connect")
int kprobe_tcp_v4_connect(struct pt_regs *ctx)
{
    u16 family = 0;
    struct sock *sk;
    sk = (struct sock *)PT_REGS_PARM1(ctx);
    bpf_probe_read(&family, sizeof(family), &sk->__sk_common.skc_family);
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("Detect pid: %d\n", pid);
    perf_ppm_event ppm_event;
    ppm_event.event_id = EVENT_NEW_PACKET_PORT_TCP;
    ppm_event.pid = pid;
    __u16 dport = 0;
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    ppm_event.port_id = my_htons(dport);
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
    //pdata.pid = child_id;
    //bpf_get_current_comm(pdata.process_name,sizeof(pdata.process_name));
    //bpf_map_update_elem(&process_map,&child_id,&pdata,BPF_ANY);
    return 0;
}