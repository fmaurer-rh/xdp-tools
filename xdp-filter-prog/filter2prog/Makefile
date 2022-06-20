# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

TOOL_NAME := filter2prog

.PHONY: build

all: build

build:
	go build -o ${TOOL_NAME} filter2prog.go

clean:
	go clean
	rm ${TOOL_NAME}
