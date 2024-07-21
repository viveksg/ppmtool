#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <error.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "ppmanalyzer.skel.h"

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

static volatile sig_atomic_t stop;
void handle_event(void *ctx,int cpu, void* data,__u32 data_sz)
{   
    perf_ppm_event_user* event_data = data;
    printf("EventId: %d| port_no: %d | pid : %d | packed_count %d \n",event_data->event_id,event_data->port_id, event_data->pid, event_data->packet_count);
}
static void handle_signal(int signo)
{
    stop = 1;
}
static int libbpf__print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr,format, args);
}

void detect_processes()
{

}

int main(int args, char **agrv)
{
    struct ppmanalyzer_bpf* skel;
    struct perf_buffer *pb;
    signal(SIGINT,handle_signal);
    signal(SIGTERM,handle_signal);
    int n_cpus = 4;// get_nprocs();
    int err;
    libbpf_set_print(libbpf__print_fn);
    skel = ppmanalyzer_bpf__open_and_load();
    bpf_map__set_max_entries(skel->maps.ppm_perf_events, n_cpus);
    if(!skel)
    {
        fprintf(stderr,"Failed to open ppmanalyzer BPF skeleton");
        return 1;
    }
    err = ppmanalyzer_bpf__attach(skel);
    if(err){
        fprintf(stderr,"Failed to attach ppmanalyzer BPF skeleton");
        goto cleanup;
    }
    //struct perf_buffer_opts pb_opts = {};
    //pb_opts.sample_cb = handle_event;
    pb = perf_buffer__new(bpf_map__fd(skel->maps.ppm_perf_events),8,handle_event,NULL,NULL,NULL);
    if(!pb)
    {
        fprintf(stderr,"failed to open perf buffer\n");
        ppmanalyzer_bpf__destroy(skel);
        return 1;
    }
    printf("Press Ctrl + c to stop");
    while(!stop){
        err = perf_buffer__poll(pb,1000);
        if(err < 0 && err != -EINTR)
        {
            fprintf(stderr,"Error in polling the buffer %d\n",err);
            break;
        }
    }

 cleanup:
    ppmanalyzer_bpf__destroy(skel);
    return -err;   
}