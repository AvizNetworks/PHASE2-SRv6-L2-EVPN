#!/bin/bash
# Manual testbed setup for bgp_srv6_l2_evpn_irb
# Creates PE1 and PE2 namespaces with IS-IS underlay + BGP L2VPN EVPN
# Run as root: sudo bash setup_manual.sh
# To tear down:  sudo bash setup_manual.sh teardown

set -e

TDIR=/tmp/frr_irb_manual

teardown() {
    echo "=== Tearing down ==="
    ip netns del pe1 2>/dev/null || true
    ip netns del pe2 2>/dev/null || true
    rm -rf $TDIR
    echo "Done."
}

if [ "$1" = "teardown" ]; then
    teardown
    exit 0
fi

# --- Clean any prior run ---
ip netns del pe1 2>/dev/null || true
ip netns del pe2 2>/dev/null || true
rm -rf $TDIR

mkdir -p $TDIR/pe1 $TDIR/pe2

echo "=== Creating namespaces ==="
ip netns add pe1
ip netns add pe2

echo "=== Wiring PE1 <-> PE2 (eth0) ==="
ip link add pe1-eth0 type veth peer name pe2-eth0
ip link set pe1-eth0 netns pe1
ip link set pe2-eth0 netns pe2
ip netns exec pe1 ip link set pe1-eth0 name eth0
ip netns exec pe2 ip link set pe2-eth0 name eth0

echo "=== PE1 base config ==="
ip netns exec pe1 ip link set lo up
ip netns exec pe1 ip addr add fd00::1/64 dev eth0
ip netns exec pe1 ip link set eth0 up
# Locator on loopback so IS-IS can redistribute it
ip netns exec pe1 ip addr add fc00:1::1/48 dev lo
# VRF-A + br100
ip netns exec pe1 ip link add VRF-A type vrf table 10
ip netns exec pe1 ip link set VRF-A up
ip netns exec pe1 ip link add br100 type bridge vlan_filtering 1
ip netns exec pe1 ip link set br100 master VRF-A
ip netns exec pe1 ip link set br100 up
ip netns exec pe1 ip addr add 10.0.1.1/24 dev br100
# Operator-owned sr6 decap/encap netdevs for EVI 100 (zebra discovers by name)
ip netns exec pe1 bridge vlan add vid 100 dev br100 self
for n in sr6-100 bum-sr6-100; do
  ip netns exec pe1 ip link add name $n type sr6 mode full segs 2001:db8:5262::1
  ip netns exec pe1 ip link set $n addrgenmode none
  ip netns exec pe1 ip link set $n master br100
  ip netns exec pe1 bridge vlan add dev $n vid 100
done
# flood only on the BUM port
ip netns exec pe1 bridge link set dev sr6-100 learning off flood off mcast_flood off bcast_flood off isolated on
ip netns exec pe1 bridge link set dev bum-sr6-100 learning off flood on mcast_flood on bcast_flood on isolated on
ip netns exec pe1 ip link set sr6-100 up
ip netns exec pe1 ip link set bum-sr6-100 up
# SRv6 sysctls
ip netns exec pe1 sysctl -qw net.ipv6.conf.all.forwarding=1
ip netns exec pe1 sysctl -qw net.ipv6.conf.all.seg6_enabled=1
ip netns exec pe1 sysctl -qw net.ipv6.conf.eth0.seg6_enabled=1

echo "=== PE2 base config ==="
ip netns exec pe2 ip link set lo up
ip netns exec pe2 ip addr add fd00::2/64 dev eth0
ip netns exec pe2 ip link set eth0 up
ip netns exec pe2 ip addr add fc00:2::1/48 dev lo
ip netns exec pe2 ip link add VRF-A type vrf table 10
ip netns exec pe2 ip link set VRF-A up
ip netns exec pe2 ip link add br100 type bridge vlan_filtering 1
ip netns exec pe2 ip link set br100 master VRF-A
ip netns exec pe2 ip link set br100 up
ip netns exec pe2 ip addr add 10.0.2.1/24 dev br100
# Operator-owned sr6 decap/encap netdevs for EVI 100 (zebra discovers by name)
ip netns exec pe2 bridge vlan add vid 100 dev br100 self
for n in sr6-100 bum-sr6-100; do
  ip netns exec pe2 ip link add name $n type sr6 mode full segs 2001:db8:5262::1
  ip netns exec pe2 ip link set $n addrgenmode none
  ip netns exec pe2 ip link set $n master br100
  ip netns exec pe2 bridge vlan add dev $n vid 100
done
# flood only on the BUM port
ip netns exec pe2 bridge link set dev sr6-100 learning off flood off mcast_flood off bcast_flood off isolated on
ip netns exec pe2 bridge link set dev bum-sr6-100 learning off flood on mcast_flood on bcast_flood on isolated on
ip netns exec pe2 ip link set sr6-100 up
ip netns exec pe2 ip link set bum-sr6-100 up
ip netns exec pe2 sysctl -qw net.ipv6.conf.all.forwarding=1
ip netns exec pe2 sysctl -qw net.ipv6.conf.all.seg6_enabled=1
ip netns exec pe2 sysctl -qw net.ipv6.conf.eth0.seg6_enabled=1

echo "=== Writing FRR configs ==="
CWD=$(dirname "$(realpath "$0")")

for pe in pe1 pe2; do
    mkdir -p $TDIR/$pe
    cp $CWD/$pe/frr.conf $TDIR/$pe/frr.conf
    # FRR run-dir sockets
    mkdir -p /var/run/frr/$pe
    chown frr:frr /var/run/frr/$pe 2>/dev/null || true
done

echo "=== Starting FRR daemons ==="
for pe in pe1 pe2; do
    RUNDIR=$TDIR/$pe
    CONF=$RUNDIR/frr.conf
    NSOPT="ip netns exec $pe"

    $NSOPT /usr/lib/frr/mgmtd  -d --config-file $CONF \
        --log file:$RUNDIR/mgmtd.log  --log-level debug \
        --vty_socket $RUNDIR/mgmtd.vty \
        --pid_file $RUNDIR/mgmtd.pid \
        --socket $RUNDIR/mgmtd.sock 2>/dev/null

    $NSOPT /usr/lib/frr/zebra  -d --config-file $CONF \
        --log file:$RUNDIR/zebra.log  --log-level debug \
        --vty_socket $RUNDIR/zebra.vty \
        --pid_file $RUNDIR/zebra.pid \
        -z $RUNDIR/zserv.sock 2>/dev/null

    sleep 1

    $NSOPT /usr/lib/frr/isisd  -d --config-file $CONF \
        --log file:$RUNDIR/isisd.log  --log-level debug \
        --vty_socket $RUNDIR/isisd.vty \
        --pid_file $RUNDIR/isisd.pid \
        -z $RUNDIR/zserv.sock 2>/dev/null

    $NSOPT /usr/lib/frr/staticd -d --config-file $CONF \
        --log file:$RUNDIR/staticd.log --log-level debug \
        --vty_socket $RUNDIR/staticd.vty \
        --pid_file $RUNDIR/staticd.pid \
        -z $RUNDIR/zserv.sock 2>/dev/null

    $NSOPT /usr/lib/frr/bgpd   -d --config-file $CONF \
        --log file:$RUNDIR/bgpd.log   --log-level debug \
        --vty_socket $RUNDIR/bgpd.vty \
        --pid_file $RUNDIR/bgpd.pid \
        -z $RUNDIR/zserv.sock 2>/dev/null

    echo "$pe: daemons started (logs in $RUNDIR/)"
done

echo ""
echo "=== Testbed is up. Use these to interact: ==="
echo ""
echo "  PE1 vtysh:  sudo ip netns exec pe1 vtysh -N pe1"
echo "  PE2 vtysh:  sudo ip netns exec pe2 vtysh -N pe2"
echo ""
echo "  Or: sudo ip netns exec pe1 vtysh --vty_socket $TDIR/pe1/bgpd.vty -d bgpd"
echo ""
echo "  Check BGP:  sudo ip netns exec pe1 vtysh --vty_socket $TDIR/pe1 -c 'show bgp l2vpn evpn summary'"
echo "  IS-IS nbr:  sudo ip netns exec pe1 vtysh --vty_socket $TDIR/pe1 -c 'show isis neighbor'"
echo "  Routes:     sudo ip netns exec pe1 ip -6 route"
echo ""
echo "  Teardown:   sudo bash $0 teardown"
