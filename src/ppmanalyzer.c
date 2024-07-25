#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <error.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <bpf/libbpf.h>
#include "ppm_common.h"
#include "ppmanalyzer.skel.h"
#define MAX_STR_LEN 512
#define MAX_CHRS MAX_STR_LEN
#define MAX_PROCESSES 1 << 16
#define TOTAL_PORTS 1 << 16
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
} perf_ppm_event_user;

typedef struct
{
    __u32 pid;
    char process_name[MAX_STR_LEN];
    __u32 total_packets;
} process_info;

__u32 port_process_map[TOTAL_PORTS];
process_info process_infos[MAX_PROCESSES];
bool port_process_map_status[TOTAL_PORTS];

int process_counter = 0;
struct ppmanalyzer_bpf *skel;
static volatile sig_atomic_t stop;

void add_new_process(__u32 pid)
{
    if (process_counter == MAX_PROCESSES)
    {
        fprintf(stderr, "Process array full cannot add new process\n");
        return;
    }
    process_infos[process_counter].total_packets = 0;
    process_infos[process_counter].pid = pid;
    char proce_file_path[MAX_STR_LEN];
    snprintf(proce_file_path, sizeof(proce_file_path), "/proc/%d/comm", pid);
    int proc_file_fd = open(proce_file_path, O_RDONLY);
    if (proc_file_fd < 0)
    {
        snprintf(process_infos[process_counter].process_name, MAX_STR_LEN, "unkown");
        return ;
    }
    ssize_t read_bytes = read(proc_file_fd, process_infos[process_counter].process_name, MAX_STR_LEN);
    if (read_bytes > 0)
        process_infos[process_counter].process_name[read_bytes - 1] = '\0';
    else
    {

        snprintf(process_infos[process_counter].process_name, MAX_STR_LEN, "unkown");
        return ;
    }

   // printf("Process Created: %d,comm %s\n",process_infos[process_counter].pid,process_infos[process_counter].process_name);
    process_counter++;
}

int get_process_index(int pid)
{
    int i = 0;
    for (i = 0; i < process_counter; i++)
    {
        if (pid == process_infos[i].pid)
        {
            return i;
        }
    }
    fprintf(stderr, "Cannot with in entry for PID:%d in process array\n", pid);
    return -1;
}

void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
    perf_ppm_event_user *event_data = data;
    int event_id = event_data->event_id;
    __u32 src_addr = event_data->src_addr;
    __u32 dest_addr = event_data->dst_addr;
    __u16 src_port = event_data->src_port_id;
    __u16 dest_port = event_data->dst_addr;
    int process_index = 0;
    //char pname[MAX_STR_LEN];
    switch (event_id)
    {
    case EVENT_NEW_PROCESS_CREATED:
        add_new_process(event_data->pid);
        break;
    case EVENT_NEW_PACKET_DETECTED:
        process_index =  get_process_index(event_data->pid);
        process_infos[process_index].total_packets = process_infos[process_index].total_packets + 1;
        if(process_index == -1 && port_process_map_status[event_data->pid])
                process_index = port_process_map[event_data->pid];
        if(process_index > -1)
            printf("Packet Detected- ProcessId: %d| Process_name: %s | Total Packets: %d", event_data->pid, process_infos[process_index].process_name,process_infos[process_index].total_packets);
        else
            printf("Process not founf for pid: %d\n",event_data->pid);
        printf(" Received Packet From: %d.%d.%d.%d:%d | ", (src_addr&0xff),(src_addr>>8)&0xff,(src_addr>>16)&0xff,(src_addr>>24)&0xff,src_port);
        printf(" Received Packet At:   %d.%d.%d.%d:%d  \n ",(dest_addr&0xff),(dest_addr>>8)&0xff,(dest_addr>>16)&0xff,(dest_addr>>24)&0xff,dest_port);
        break;
    case EVENT_NEW_PACKET_PORT_MAPPED:
        process_index = get_process_index(event_data->pid);
        port_process_map[event_data->port_id] = process_index;
        break;    
    default:
        break;
    }
}
static void handle_signal(int signo)
{
    stop = 1;
}
static int libbpf__print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

int detect_processes()
{
    DIR *proc_dir;
    struct dirent *proc_dir_entry;
    proc_dir = opendir("/proc");
    if (proc_dir == NULL)
    {
        perror("Cannot open proc dir\n");
        return 1;
    }
    while ((proc_dir_entry = readdir(proc_dir)) != NULL)
    {
        if (proc_dir_entry->d_type == DT_DIR)
        {
            int pid = atoi(proc_dir_entry->d_name);
            if (pid > 0)
            {
                char status_path[MAX_CHRS];
                char process_name[MAX_CHRS];
                snprintf(status_path, sizeof(status_path), "/proc/%s/status", proc_dir_entry->d_name);
                FILE *proc_status_file = fopen(status_path, "r");
                if (proc_status_file != NULL)
                {
                    char line[256];
                    while (fgets(line, sizeof(line), proc_status_file) != NULL)
                    {
                        if (strncmp(line, "Name:", 5) == 0)
                        {
                            sscanf(line, "Name:\t%s", process_name);
                            printf("Pid: %d| Process Name: %s\n", pid, process_name);
                            process_infos[process_counter].pid = pid;
                            process_infos[process_counter].total_packets = 0;
                            memcpy(&process_infos[process_counter].process_name, process_name, sizeof(process_name));
                            process_counter++;
                            break;
                        }
                    }
                }
            }
        }
    }
    closedir(proc_dir);
    return 0;
}

int main(int args, char **agrv)
{
    struct perf_buffer *pb;
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    int err;
    libbpf_set_print(libbpf__print_fn);
    skel = ppmanalyzer_bpf__open_and_load();
    // int nprocs = get_nproc();
    bpf_map__set_max_entries(skel->maps.ppm_perf_events, 4);
    if (!skel)
    {
        fprintf(stderr, "Failed to open ppmanalyzer BPF skeleton");
        return 1;
    }
    err = ppmanalyzer_bpf__attach(skel);
    if (err)
    {
        fprintf(stderr, "Failed to attach ppmanalyzer BPF skeleton");
        goto cleanup;
    }
    // struct perf_buffer_opts pb_opts = {};
    // pb_opts.sample_cb = handle_event;
    pb = perf_buffer__new(bpf_map__fd(skel->maps.ppm_perf_events), 8, handle_event, NULL, NULL, NULL);
    if (!pb)
    {
        fprintf(stderr, "failed to open perf buffer\n");
        ppmanalyzer_bpf__destroy(skel);
        return 1;
    }
    printf("Press Ctrl + c to stop");
    detect_processes();
    while (!stop)
    {
        err = perf_buffer__poll(pb, 1000);
        if (err < 0 && err != -EINTR)
        {
            fprintf(stderr, "Error in polling the buffer %d\n", err);
            break;
        }
    }

cleanup:
    perf_buffer__free(pb);
    ppmanalyzer_bpf__destroy(skel);
    return -err;
}