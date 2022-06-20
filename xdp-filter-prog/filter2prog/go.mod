module github.com/xdp-project/xdp-tools/xdp-filter-prog/filter2prog

go 1.16

replace github.com/miekg/pcap => github.com/fmaurer-rh/pcap v1.0.2-0.20220811084517-2778a0cc2481

replace github.com/cloudflare/cbpfc => github.com/fmaurer-rh/cbpfc v0.0.0-20220810130145-73b910af9b6a

require (
	github.com/cilium/ebpf v0.9.0
	github.com/cloudflare/cbpfc v0.0.0-20211101135325-ce7ee68ade2c
	github.com/miekg/pcap v1.0.1
)
