#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/usdt.bpf.h>

#include <user_common.h>

/* Hook placeholder */
__attribute__ ((noinline))
int hook0(struct user_ctx *ctx, struct trace_raw_event *event) {
	volatile int ret = 0;
	if (!ctx || !event)
		return 0;
	return ret;
}

static __always_inline int get_args(struct user_ctx *uctx,
				     struct pt_regs *ctx)
{
	int cnt = bpf_usdt_arg_cnt(ctx);
	long tmp = 0;

#define get_arg(x)								\
	if (x < cnt) {								\
		if (bpf_usdt_arg(ctx, x, &tmp))					\
			return -1;						\
		uctx->args[x] = tmp;						\
	}									\

	get_arg(9)
	get_arg(8)
	get_arg(7)
	get_arg(6)
	get_arg(5)
	get_arg(4)
	get_arg(3)
	get_arg(2)
	get_arg(1)
	get_arg(0)
	uctx->num = cnt;

	return 0;
}

SEC("usdt")
int probe_usdt(struct pt_regs *ctx)
{
	struct common_event *e;
	struct trace_raw_event *event;
	struct user_event *u;
	struct user_ctx uctx = {};

	if (get_args(&uctx, ctx) != 0)
		return -1;

	event = get_event();
	if (!event)
		return 0;

	e = get_event_section(event, COMMON, 1, sizeof(*e));
	if (!e) {
		discard_event(event);
		return 0;
	}
	e->timestamp = bpf_ktime_get_ns();

	u = get_event_section(event, USERSPACE, 1, sizeof(*u));
	if (!u) {
		discard_event(event);
		return 0;
	}
	u->symbol = PT_REGS_IP(ctx);
	u->pid = bpf_get_current_pid_tgid();
	u->event_type = USDT;

	/* UST only supports a single hook. */
	hook0(&uctx, event);

	send_event(event);

	return 0;
}

char __license[] SEC("license") = "GPL";
