#ifndef __COMMON_PPM__
#define __COMMON_PPM__

#define EVENT_NEW_PROCESS_CREATED 201
#define EVENT_NEW_PACKET_DETECTED 202
#define EVENT_NEW_PACKET_PORT_MAPPED 203
#define EVENT_NEW_PACKET_TRANSMISSION 204
#define EVENT_PROCESS_DELETED 205
#
#define ETHERNET_PAYLOAD_NOT_FOUND 100
#define IP_PAYLOAD_NOT_FOUND 101
#define TCP_PAYLOAD_NOT_FOUND 102
#define UDP_PAYLOAD_NOT_FOUND 103
#define PROTOCOL_NOT_IP 104
#define PROTOCOL_NOT_TCP_OR_UDP 105
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif
#define AF_INET 2
#define AF_INET6 10

#define MAX_STR_LEN 512
#define MAX_CHRS MAX_STR_LEN
#define MAX_PROCESSES 1 << 16
#define TOTAL_PORTS 1 << 16
#define IPV6_ADDR_BYTE_COUNT 16
#define COMM_LENGTH

struct trace_event_raw_net_dev_template_cust {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    char device[16];
    void *skbaddr;
    unsigned int len;
    unsigned int data_len;
    int ip_summed;
    unsigned int vlan_tag;
    unsigned short protocol;
    unsigned short queue_mapping;
    unsigned char napi_id;
};
#endif