# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

SUBDIRS := filter2prog

EXTRA_TARGETS := $(SUBDIRS)
.PHONY: $(SUBDIRS)

LIB_DIR = ../lib

include $(LIB_DIR)/common.mk

$(SUBDIRS):
	@echo; echo "  $@"; $(MAKE) -C $@
