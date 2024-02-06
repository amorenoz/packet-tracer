ROOT_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
export LLC := llc
export CLANG := clang
export OBJCOPY := llvm-objcopy

CARGO := cargo
PRINT = echo

VERBOSITY := $(filter 1,$(V))

ifeq ($(VERBOSITY),)
    Q=@
    MAKE += -s
    CARGO += -q
define out_console
    $(PRINT) -e "[$(1)]\t$(2)"
endef

.SILENT:
endif

ifeq ($(NOVENDOR),)
    # This MUST be kept in sync with API_HEADERS under lib.rs in libbpf-sys
    LIBBPF_API_HEADERS := bpf.h \
                          libbpf.h \
                          btf.h \
                          bpf_helpers.h \
                          bpf_helper_defs.h \
                          bpf_tracing.h \
                          bpf_endian.h \
                          bpf_core_read.h \
                          libbpf_common.h \
                          usdt.bpf.h

    LIBBPF_SYS_LIBBPF_BASE_PATH := $(dir $(shell cargo metadata --format-version=1 | jq -r '.packages | .[] | select(.name == "libbpf-sys") | .manifest_path'))
    LIBBPF_SYS_LIBBPF_INCLUDES :=  $(wildcard $(addprefix $(LIBBPF_SYS_LIBBPF_BASE_PATH)/libbpf/src/, $(LIBBPF_API_HEADERS)))
    LIBBPF_INCLUDES := $(ROOT_DIR)/src/.out
endif

FILTER_INCLUDES := src/core/filters/packets/bpf/include \
                   src/core/filters/meta/bpf/include
# Taking errno.h from libc instead of linux headers.
# TODO: Remove when we fix proper header dependencies.
INCLUDES_ALL := $(abspath $(wildcard src/core/probe/bpf/include \
                                     src/core/probe/kernel/bpf/include \
                                     src/core/probe/user/bpf/include \
                                     src/core/events/bpf/include \
                                     src/core/tracking/bpf/include \
                                     /usr/include/x86_64-linux-gnu \
                                     $(FILTER_INCLUDES)))
INCLUDES_ALL += $(LIBBPF_INCLUDES)

OVS_INCLUDES := $(abspath src/module/ovs/bpf/include)
INCLUDES := $(addprefix -I, $(INCLUDES_ALL))

EBPF_PROBES := $(abspath src/core/probe/kernel/bpf \
                        src/core/probe/user/bpf)

GENERIC_HOOKS := $(abspath src/module/skb/bpf \
                           src/module/skb_drop/bpf \
                           src/module/skb_tracking/bpf \
                           src/module/nft/bpf \
                           src/module/ct/bpf)

OVS_HOOKS := $(abspath src/module/ovs/bpf)
OUT_NAME := HOOK

JOBS := $(patsubst -j%,%,$(filter -j%,$(MAKEFLAGS)))

ifneq ($(JOBS),)
    CARGO_JOBS := $(JOBS)
else
    CARGO_JOBS := 1
endif

all: ebpf
	$(call out_console,CARGO,building retis ...)
	$(Q)CARGO_BUILD_JOBS=$(CARGO_JOBS) \
	RETIS_PKG_VERSION=$(RELEASE_VERSION) \
	RETIS_RELEASE_NAME=$(RELEASE_NAME) \
	$(CARGO) $(CARGO_OPTS) build $(CARGO_CMD_OPTS)

ifeq ($(NOVENDOR),)
$(LIBBPF_INCLUDES): $(LIBBPF_SYS_LIBBPF_INCLUDES)
	-mkdir -p $(LIBBPF_INCLUDES)/bpf
	cp $^ $(LIBBPF_INCLUDES)/bpf/
endif

$(OVS_HOOKS): INCLUDES_EXTRA := -I$(OVS_INCLUDES)

$(EBPF_PROBES): OUT_NAME := PROBE

ebpf: $(EBPF_PROBES) $(GENERIC_HOOKS) $(OVS_HOOKS)

$(EBPF_PROBES) $(GENERIC_HOOKS) $(OVS_HOOKS): $(LIBBPF_INCLUDES)
	$(call out_console,$(OUT_NAME),building $@ ...)
	CFLAGS="$(INCLUDES) $(INCLUDES_EXTRA)" \
	$(MAKE) -r -f $(ROOT_DIR)/ebpf.mk -C $@ $(TGT)

clean-ebpf:
	$(call out_console,CLEAN,cleaning ebpf progs...)
	for i in $(EBPF_PROBES) $(GENERIC_HOOKS) $(OVS_HOOKS); do \
	    $(MAKE) -r -f $(ROOT_DIR)/ebpf.mk -C $$i clean; \
	done
	-if [ -n "$(LIBBPF_INCLUDES)" ]; then \
	    rm -rf $(LIBBPF_INCLUDES); \
	fi

clean: clean-ebpf
	$(call out_console,CLEAN,cleaning retis ...)
	$(Q)$(CARGO) clean

help:
	$(PRINT) 'all                 --  Builds the tool (both eBPF programs and retis).'
	$(PRINT) 'clean               --  Deletes all the files generated during the build process'
	$(PRINT) '	                  (eBPF and rust directory).'
	$(PRINT) 'clean-ebpf          --  Deletes all the files generated during the build process'
	$(PRINT) '	                  (eBPF only).'
	$(PRINT) 'ebpf                --  Builds only the eBPF programs.'
	$(PRINT)
	$(PRINT) 'Optional variables that can be used to override the default behavior:'
	$(PRINT) 'V                   --  If set to 1 the verbose output will be printed.'
	$(PRINT) '                        cargo verbosity is set to default.'
	$(PRINT) '                        To override `cargo` behavior please refer to $$(CARGO_OPTS)'
	$(PRINT) '                        and $$(CARGO_CMD_OPTS).'
	$(PRINT) '                        For further `cargo` customization please refer to configuration'
	$(PRINT) '                        environment variables'
	$(PRINT) '                        (https://doc.rust-lang.org/cargo/reference/environment-variables.html).'
	$(PRINT) 'CARGO_CMD_OPTS      --  Changes `cargo` subcommand default behavior (e.g. --release for `build`).'
	$(PRINT) 'CARGO_OPTS          --  Changes `cargo` default behavior (e.g. --verbose).'
	$(PRINT) 'NOVENDOR            --  Avoid to self detect and consume the vendored headers'
	$(PRINT) '                        shipped with libbpf-sys.'

.PHONY: all clean clean-ebpf ebpf $(EBPF_PROBES) $(GENERIC_HOOKS) help $(OVS_HOOKS)
