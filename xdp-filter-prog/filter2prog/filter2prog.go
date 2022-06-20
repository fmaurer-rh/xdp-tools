// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/cilium/ebpf/asm"
	"github.com/cloudflare/cbpfc"
	"github.com/miekg/pcap"
)

var outputFlag string
var dropFlag bool

const (
	outputFlagDefault = "prog.bin"
	dropFlagDefault   = false

	// From tcpdump
	maxSnaplen = 256 * 1024
)

func init() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [options] \"filter string\"\nOptions:\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.StringVar(&outputFlag, "output", outputFlagDefault, "output file name")
	flag.BoolVar(&dropFlag, "drop", dropFlagDefault, "drop matching packets")
}

func main() {
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(1)
	}

	filter := flag.Arg(0)
	h, err := pcap.OpenDead(pcap.LINKTYPE_ETHERNET, maxSnaplen)
	if err != nil {
		log.Fatalf("Failed to initialize libpcap: %s\n", err)
	}
	defer h.Close()

	cbpf_insns, err := h.Compile(filter)
	if err != nil {
		log.Fatalf("Failed to compile filter: %s\n", err)
	}

	ebpf_insns, err := cbpfc.ToEBPF(cbpf_insns, cbpfc.EBPFOpts{
		// Pass packet start and end pointers in these registers
		PacketStart: asm.R2,
		PacketEnd:   asm.R3,
		// Result of filter
		Result:      asm.R4,
		ResultLabel: "result",
		// Registers used by generated code
		Working:     [4]asm.Register{asm.R4, asm.R5, asm.R6, asm.R7},
		LabelPrefix: "filter",
	})
	if err != nil {
		log.Fatalf("Failed to convert to eBPF: %s\n", err)
	}

	prog := asm.Instructions{
		// R1 holds XDP context

		// Packet start
		asm.LoadMem(asm.R2, asm.R1, 0, asm.Word),

		// Packet end
		asm.LoadMem(asm.R3, asm.R1, 4, asm.Word),

		// Fall through to filter
	}
	prog = append(prog, ebpf_insns...)

	if dropFlag {
		prog = append(prog,
			asm.Mov.Imm(asm.R0, 2).Sym("result"), // XDP_PASS
			asm.JEq.Imm(asm.R4, 0, "return"),
			asm.Mov.Imm(asm.R0, 1), // XDP_DROP
			asm.Return().Sym("return"),
		)
	} else {
		prog = append(prog,
			asm.Mov.Imm(asm.R0, 1).Sym("result"), // XDP_DROP
			asm.JEq.Imm(asm.R4, 0, "return"),
			asm.Mov.Imm(asm.R0, 2), // XDP_PASS
			asm.Return().Sym("return"),
		)
	}

	fmt.Println(prog)

	outfile, err := os.Create(outputFlag)
	if err != nil {
		log.Fatalf("Failed to open output file: %s\n", err)
	}
	defer outfile.Close()

	out_writer := bufio.NewWriter(outfile)
	defer out_writer.Flush()

	err = prog.Marshal(out_writer, binary.LittleEndian)
	if err != nil {
		log.Fatalf("Failed to write program: %s\n", err)
	}
}
