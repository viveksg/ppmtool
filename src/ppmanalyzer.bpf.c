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
    __u8 ip_version;
    __u32 event_id;
    __u32 pid;
    __u32 packet_count;
    __u32 src_addr;
    __u32 dst_addr;
    __u16 port_id;
    __u16 src_port_id;
    char ipv6_src_addr[IPV6_ADDR_BYTE_COUNT];
    char ipv6_dst_addr[IPV6_ADDR_BYTE_COUNT];
    char comm[16];
} perf_ppm_event;

static inline __u16 my_htons(__u16 hostshort)
{
    return (hostshort << 8) | (hostshort >> 8);
}

static inline __u32 my_htnos32(__u32 hostval)
{
    return (((hostval >> 24)&0xFF) | (((hostval >> 16) & 0xFF) << 8) | (((hostval >> 8) & 0xFF)<<16) | ((hostval &0xFF) << 24)); 
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
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(process_data));
    __uint(max_entries, 512);
} process_map SEC(".maps");

SEC("tracepoint/net/netif_receive_skb")
int netif_receive_skb(struct trace_event_raw_net_dev_template *ctx)
{
    struct sk_buff skb;
    struct sock sk;
    __u8 ip_version;
    perf_ppm_event ppm_event;
    bpf_probe_read(&skb, sizeof(skb), ctx->skbaddr);
    bpf_probe_read(&ip_version, sizeof(ip_version), (void *)skb.data);
    ip_version = ip_version >> 4;
    bool send_event = false;
    ppm_event.ip_version = ip_version;
    if (ip_version == IP_VERSION_4)
    {
        send_event = true;
        struct iphdr ip_header;
        bpf_probe_read(&ip_header, sizeof(struct iphdr), skb.data);
        ppm_event.src_addr = ip_header.saddr;
        ppm_event.dst_addr = ip_header.daddr;
        ppm_event.pid = bpf_get_current_pid_tgid() >> 32;
        if (ip_header.protocol == IPPROTO_TCP)
        {
            struct tcphdr tcp_header;
            bpf_probe_read(&tcp_header, sizeof(struct tcphdr), skb.data + sizeof(struct iphdr));
            ppm_event.src_port_id = my_htons(tcp_header.source);
            ppm_event.port_id = my_htons(tcp_header.dest);
        }
        else if (ip_header.protocol == IPPROTO_UDP)
        {
            struct udphdr udp_header;
            bpf_probe_read(&udp_header, sizeof(struct udphdr), skb.data + sizeof(struct iphdr));
            ppm_event.src_port_id = my_htons(udp_header.source);
            ppm_event.port_id = my_htons(udp_header.dest);
        }
    }
    else if (ip_version == IP_VERSION_6)
    {
        struct ipv6hdr ip6_header;
        struct tcphdr tcp_header_ip6;
        struct udphdr udp_header_ip6;
        send_event = true;
        bpf_probe_read(&ip6_header, sizeof(ip6_header), skb.data);

        if (ip6_header.nexthdr == IPPROTO_TCP)
        {
            bpf_probe_read(&tcp_header_ip6, sizeof(struct tcphdr), &skb.data + sizeof(struct iphdr));
            ppm_event.src_port_id = my_htons(tcp_header_ip6.source);
            ppm_event.port_id = my_htons(tcp_header_ip6.dest);
        }
        else if (ip6_header.nexthdr == IPPROTO_UDP)
        {
            bpf_probe_read(&udp_header_ip6, sizeof(struct udphdr), &skb.data + sizeof(struct iphdr));
            ppm_event.src_port_id = my_htons(udp_header_ip6.source);
            ppm_event.port_id = my_htons(udp_header_ip6.dest);
        }
    }
    if (send_event)
    {
        ppm_event.event_id = EVENT_NEW_PACKET_DETECTED;
        bpf_get_current_comm(&ppm_event.comm, sizeof(ppm_event.comm));
        bpf_perf_event_output(ctx, &ppm_perf_events, BPF_F_CURRENT_CPU, &ppm_event, sizeof(ppm_event));
    }
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

SEC("tracepoint/net/net_dev_start_xmit")
int trace_net_dev_start_xmit(struct trace_event_raw_net_dev_template *ctx)
{
    struct sk_buff skb;
    struct ethhdr eth_header;
    bpf_probe_read_kernel(&skb,sizeof(struct sk_buff),ctx->skbaddr);
    bpf_probe_read_kernel(&eth_header,sizeof(struct ethhdr), skb.data);
    __u8 ip_version = 0;
    if (eth_header.h_proto == my_htons(ETH_P_IP))
    {
        __u16 src_port = 0;
        __u16 dst_port = 0;
        perf_ppm_event ppm_event;
        struct tcphdr tcp_header;
        struct udphdr udp_header;
        bpf_probe_read(&ip_version, sizeof(ip_version), skb.data + sizeof(struct ethhdr));
        ip_version = ip_version >> 4;
        if (ip_version == IP_VERSION_4)
        { struct iphdr ip_header;
          bpf_probe_read(&ip_header,sizeof(ip_header),skb.data+sizeof(struct ethhdr));
          ppm_event.src_addr = ip_header.saddr;
          ppm_event.dst_addr = ip_header.daddr;
            if(ip_header.protocol == IPPROTO_TCP)
            {
                bpf_probe_read(&tcp_header,sizeof(tcp_header),skb.data+sizeof(struct ethhdr)+sizeof(struct iphdr));
                src_port = my_htons(tcp_header.source);
                dst_port = my_htons(tcp_header.dest);
            }
            else if(ip_header.protocol == IPPROTO_UDP)
            {
                bpf_probe_read(&udp_header,sizeof(udp_header),skb.data+sizeof(struct ethhdr)+sizeof(struct iphdr));
                src_port = my_htons(udp_header.source);
                dst_port = my_htons(udp_header.dest);
            }
        }
        else if (ip_version == IP_VERSION_6)
        {
            struct ipv6hdr ipv6_header;
            bpf_probe_read(&ipv6_header,sizeof(ipv6_header),skb.data+sizeof(eth_header));
            if(ipv6_header.nexthdr== IPPROTO_TCP)
            {
                bpf_probe_read(&tcp_header,sizeof(tcp_header),skb.data+sizeof(struct ethhdr)+sizeof(struct ipv6hdr));
                src_port = my_htons(tcp_header.source);
                dst_port = my_htons(tcp_header.dest);
            }
            else if(ipv6_header.nexthdr == IPPROTO_UDP)
            {
                bpf_probe_read(&udp_header,sizeof(udp_header),skb.data+sizeof(struct ethhdr)+sizeof(struct ipv6hdr));
                src_port = my_htons(udp_header.source);
                dst_port = my_htons(udp_header.dest);
            }
        }
        ppm_event.src_port_id = src_port;
        ppm_event.port_id = dst_port;
        ppm_event.event_id = EVENT_NEW_PACKET_TRANSMISSION;
        bpf_perf_event_output(ctx,&ppm_perf_events,BPF_F_CURRENT_CPU,&ppm_event,sizeof(ppm_event));
    }

    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int trace_sched_process_exit(struct trace_event_raw_sched_process_template *ctx)
{
    perf_ppm_event ppm_event;
    if(!ctx)
      return 1;
    ppm_event.event_id = EVENT_PROCESS_DELETED;
    ppm_event.pid = ctx->pid;
    bpf_probe_read(ppm_event.comm,sizeof(ppm_event.comm),ctx->comm);
    bpf_perf_event_output(ctx,&ppm_perf_events,BPF_F_CURRENT_CPU,&ppm_event,sizeof(ppm_event));  
    return 0;
}