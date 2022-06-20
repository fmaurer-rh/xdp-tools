# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

TOOL_NAME := xdp-filter-prog
USER_TARGETS := xdp-filter-prog

XDP_TARGETS := xdp-filter-dispatcher

SUBDIRS := filter2prog

EXTRA_TARGETS := $(SUBDIRS)
.PHONY: $(SUBDIRS)

TEMPLATED_SOURCES := xdp-filter-dispatcher.c
USER_GEN := $(TEMPLATED_SOURCES)

LIB_DIR = ../lib

include $(LIB_DIR)/common.mk

$(TEMPLATED_SOURCES): %.c: %.c.in Makefile
	$(QUIET_M4)$(M4) $(DEFINES) $< > $@ || ( ret=$$?; rm -f $@; exit $$ret )

$(SUBDIRS):
	@echo; echo "  $@"; $(MAKE) -C $@
