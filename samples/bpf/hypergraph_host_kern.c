#include <linux/ptrace.h>
#include <linux/version.h>
#include <uapi/linux/bpf.h>
#include "bpf_helpers.h"

#define EXIT_REASON 18

struct kvm_data {
    u8 start;
    u8 exit_reason;
    u32 isa;
    u64 nr;
    u64 a0;
    u64 a1;
    u64 a2;
    u64 a3;
    u64 vcpu_id;
    u64 overhead;
};

struct events_table_t  {
	int key;
	u32 leaf;
	int (*perf_submit) (void *, void *, u32);
	int (*perf_submit_skb) (void *, u32, void *, u32);
	u32 data[0];
}; __attribute__((section("maps/perf_output"))) struct events_table_t events;


struct bpf_map_def SEC("maps") kvm_data_list = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct kvm_data),
	.max_entries = 32,
};

/* from /sys/kernel/debug/tracing/events/kvm/kvm_exit/format */
struct kvm_exit {
	__u64 pad;
	unsigned int exit_reason;
	unsigned long guest_rip;
	u32 isa;
	u64 info1;
	u64 info2;
};
SEC("tracepoint/kvm/kvm_exit")
int kvm_exit_handler(struct kvm_exit *args)
{
	int rc;    
    if (args->exit_reason == EXIT_REASON) {
        int cpu_id = bpf_get_smp_processor_id();
        struct kvm_data* data_ptr = bpf_map_lookup_elem(&kvm_data_list, &cpu_id);
        if(!data_ptr)
            return 0;
        
        data_ptr->start = 1;
        data_ptr->isa = args->isa;
        data_ptr->exit_reason = args->exit_reason;
        data_ptr->overhead = bpf_ktime_get_ns();
    }

	return 0;
}

/* from /sys/kernel/debug/tracing/events/kvm/kvm_hypercall/format */
struct kvm_hypercall {
	__u64 pad;
	unsigned long nr;
	unsigned long a0;
	unsigned long a1;
	unsigned long a2;
	unsigned long a3;
};
SEC("tracepoint/kvm/kvm_hypercall")
int kvm_hypercall_handler(struct kvm_hypercall *args)
{
	// u32 cpu_id = bpf_get_smp_processor_id();
	// char fmt[] = "kvm_hypercall: CPU-%d nr=%u, a0=%lu\n";
	// bpf_trace_printk(fmt, sizeof(fmt), cpu_id, args->nr, args->a0);

	int cpu_id = bpf_get_smp_processor_id();
    struct kvm_data* data_ptr = bpf_map_lookup_elem(&kvm_data_list, &cpu_id);
    if(!data_ptr)
        return 0;
    
    if(data_ptr->start <= 0)
        return 0;

    data_ptr->nr = args->nr;
    data_ptr->a0 = args->a0;
    data_ptr->a1 = args->a1;
    data_ptr->a2 = args->a2;
    data_ptr->a3 = args->a3;
    return 0;
}

/* from /sys/kernel/debug/tracing/events/kvm/kvm_entry/format */
struct kvm_entry {
	__u64 pad;
	unsigned int vcpu_id;
};
SEC("tracepoint/kvm/kvm_entry")
int kvm_entry_handler(struct kvm_entry *args)
{
	// u32 cpu_id = bpf_get_smp_processor_id();
	// char fmt[] = "kvm_entry: CPU-%d vcpu_id=%u\n";
	// bpf_trace_printk(fmt, sizeof(fmt), cpu_id, args->vcpu_id);
	int cpu_id = bpf_get_smp_processor_id();
    struct kvm_data* data_ptr = bpf_map_lookup_elem(&kvm_data_list, &cpu_id);
    if(!data_ptr)
        return 0;
    
    if(data_ptr->start <= 0)
        return 0;

    data_ptr->overhead = bpf_ktime_get_ns() - data_ptr->overhead;
    data_ptr->start = 0;
    data_ptr->vcpu_id = args->vcpu_id;

    int rc;
    struct kvm_data event = *data_ptr;

    // char fmt[] = "kvm: nr=%u, vcpu_id=%lu, overhead=%lu\n";
    // bpf_trace_printk(fmt, sizeof(fmt), data_ptr->nr, data_ptr->vcpu_id, data_ptr->overhead);

    if ((rc = events.perf_submit(args, &event, sizeof(event))) < 0){
    	char fmt[] = "perf_output failed: %d\\n";
    	bpf_trace_printk(fmt, sizeof(fmt), rc);
    }
	return 0;
}
char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;