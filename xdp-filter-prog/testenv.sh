#!/bin/sh

set -eufo pipefail
set -x

NETNSNAME0="netns-xdp-pf0"
NETNSNAME1="netns-xdp-pf1"

for ns in "$NETNSNAME0" "$NETNSNAME1"; do
    missing=0
    ip netns list | grep -q "$ns" || missing=1
    if [ $missing -eq 1 ]; then
        ip netns add "$ns"
    fi
done

ip link add net0 netns "$NETNSNAME0" type veth peer net0 netns "$NETNSNAME1" || true

ip netns exec $NETNSNAME0 ip address add 10.0.0.10/24 dev net0 || true
ip netns exec $NETNSNAME0 ip address add 10.0.1.10/24 dev net0 || true
ip netns exec $NETNSNAME1 ip address add 10.0.0.11/24 dev net0 || true
ip netns exec $NETNSNAME1 ip address add 10.0.1.11/24 dev net0 || true

ip netns exec $NETNSNAME0 ip link set lo up
ip netns exec $NETNSNAME0 ip link set net0 up
ip netns exec $NETNSNAME1 ip link set lo up
ip netns exec $NETNSNAME1 ip link set net0 up

missing=0
grep -q "bpffs /tmp/bpf bpf" /proc/mounts || missing=1
if [ $missing -eq 1 ]; then
    mkdir -p /tmp/bpf
    mount -t bpf bpffs /tmp/bpf
fi

echo "Run commands like this:
    sudo ip netns exec $NETNSNAME0 ...
    sudo ip netns exec $NETNSNAME1 ..."
