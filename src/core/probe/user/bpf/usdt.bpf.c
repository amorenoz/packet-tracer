#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/usdt.bpf.h>

#include <user_common.h>

/* We only have one hook per target. */
__attribute__ ((noinline))
int hook(struct pt_regs *ctx, struct trace_raw_event *event) {
	volatile int ret = 0;
	if (!ctx || !event)
		return 0;
	return ret;
}

SEC("usdt")
int probe_usdt(struct pt_regs *ctx)
{
    struct pt_regs ctx_fp = *ctx;
	struct common_event *e;
	struct trace_raw_event *event;

	event = get_event();
	if (!event)
		return 0;

	e = get_event_section(event, COMMON, 1, sizeof(*e));
	if (!e) {
		discard_event(event);
		return 0;
	}
	e->symbol = PT_REGS_IP(ctx);
	e->timestamp = bpf_ktime_get_ns();

    hook(&ctx_fp, event);

	send_event(event);

	return 0;
}

char __license[] SEC("license") = "GPL";
