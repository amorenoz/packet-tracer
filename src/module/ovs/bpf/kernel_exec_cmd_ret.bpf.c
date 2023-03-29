#include <common.h>
#include <ovs_common.h>

/* Hook for kretprobe:ovs_packet_cmd_execute. */
DEFINE_HOOK(
	u64 tid = bpf_get_current_pid_tgid();

	/* The execute command has finished. Remove the entry from the
	* inflight_exec_cmd map. */
	bpf_map_delete_elem(&inflight_exec_cmd, &tid);
	return 0;
)

char __license[] SEC("license") = "GPL";
