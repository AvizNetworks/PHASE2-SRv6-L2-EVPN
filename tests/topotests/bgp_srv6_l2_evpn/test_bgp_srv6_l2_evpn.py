#!/usr/bin/env python
# SPDX-License-Identifier: ISC
# Copyright (c) 2026 Aviz Networks
#
# SRv6 L2 EVPN topotest - multi-VLAN-to-EVI mapping.
#
# Two VLAN-aware bridges, each bound to its own EVI via the zebra
# 'segment-routing srv6 l2-evpn' config (no 'sid vpn export'):
#   EVI 10 <-> br10 (VLAN 10, eth1)   host1  <-> host2   (192.0.2.0/24)
#   EVI 20 <-> br20 (VLAN 20, eth3)   host1c <-> host2c  (198.51.100.0/24)
# plus one VPWS End.DX2 cross-connect on eth2 (host1b <-> host2b).
# Per-EVI End.DT2U/End.DT2M SIDs are allocated by zebra and reported to bgpd.
#
# All RIB/kernel assertions are behaviour- and locator-prefix-based (robust to
# the zebra-assigned per-EVI SID function values); only r{1,2}/evpn_summary.json
# (BGP peer state, topology-independent) is compared as exact JSON.

import os, sys, json, functools, pytest
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger
from lib.common_config import required_linux_kernel_version
from lib.checkping import check_ping

pytestmark = [pytest.mark.bgpd]

def _sr6_kernel_supported():
    """End.DT2U/DT2M forwarding needs an 'sr6' netdev not in mainline Linux;
    probe once so the dataplane tests skip (not fail) on kernels without it.

    We probe with a bare `ip link add type sr6`, which the kernel rejects
    because sr6 needs a segment list ("SRH with segment list is required").
    That rejection still proves the type is RECOGNISED, so treat it as
    supported; only an "unknown device type" (stock kernel) means unsupported.
    SR6_SUPPORTED=0/1 overrides the auto-detect if ever needed."""
    import subprocess

    env = os.environ.get("SR6_SUPPORTED")
    if env is not None:
        return env not in ("0", "", "no", "false")

    probe = "sr6probe%d" % os.getpid()
    try:
        res = subprocess.run(["ip", "link", "add", "name", probe, "type", "sr6"],
                             capture_output=True)
    except OSError:
        return False
    if res.returncode == 0:
        subprocess.run(["ip", "link", "del", probe], capture_output=True)
        return True
    err = (res.stderr or b"").decode(errors="replace").lower()
    # Type recognised but our minimal args rejected -> supported.  Only an
    # unknown/unsupported link type means the kernel lacks sr6.
    return not ("unknown" in err or "not supported" in err)

sr6_supported = _sr6_kernel_supported()
sr6_required = pytest.mark.skipif(
    not sr6_supported,
    reason="kernel lacks SRv6 sr6 netdev support (End.DT2U/DT2M dataplane)",
)

def _sr6_reprogram_supported():
    """Operator-owned sr6 model: the operator pre-creates the sr6 netdev with a
    placeholder SID and zebra rewrites it in place (RTM_SETLINK / IFLA_SR6_SRH
    changelink) with the dynamically-allocated End.DT2U/DT2M/DX2 SID.  Some sr6
    drivers accept `segs` only at create time and reject the in-place change
    with EOPNOTSUPP; without the kernel patch that adds changelink support the
    netdev keeps the placeholder SID and L2 *encap* (unicast + BUM) cannot work,
    so the forwarding tests would fail.  Probe once so those tests SKIP (not
    fail) there.  SR6_REPROGRAM=0/1 overrides the auto-detect."""
    import subprocess

    env = os.environ.get("SR6_REPROGRAM")
    if env is not None:
        return env not in ("0", "", "no", "false")
    if not sr6_supported:
        return False
    dev = "sr6repr%d" % os.getpid()
    try:
        add = subprocess.run(
            ["ip", "link", "add", "name", dev, "type", "sr6", "mode", "full",
             "segs", "2001:db8::1"], capture_output=True)
        if add.returncode != 0:
            return False
        chg = subprocess.run(
            ["ip", "link", "set", dev, "type", "sr6", "mode", "full",
             "segs", "2001:db8::2"], capture_output=True)
        return chg.returncode == 0
    except OSError:
        return False
    finally:
        subprocess.run(["ip", "link", "del", dev], capture_output=True)

sr6_reprogram_supported = _sr6_reprogram_supported()
sr6_reprogram_required = pytest.mark.skipif(
    not sr6_reprogram_supported,
    reason="sr6 driver lacks in-place segs reprogram (RTM_SETLINK IFLA_SR6_SRH); "
    "operator-owned sr6 encap needs the sr6 kernel patch",
)

# EVI id -> (bridge, member AC ifname, VLAN id) mapping applied on both PEs.
EVIS = ((10, "br10", "eth1", 10), (20, "br20", "eth3", 20))

def build_topo(tgen):
    for r in ("r1", "r2", "host1", "host2", "host1b", "host2b", "host1c", "host2c"):
        tgen.add_router(r)
    tgen.add_link(tgen.gears["r1"], tgen.gears["r2"], "eth0", "eth0")        # SRv6 core
    tgen.add_link(tgen.gears["host1"],  tgen.gears["r1"], "eth0", "eth1")    # EVI 10 AC (br10/vlan10)
    tgen.add_link(tgen.gears["host2"],  tgen.gears["r2"], "eth0", "eth1")
    tgen.add_link(tgen.gears["host1b"], tgen.gears["r1"], "eth0", "eth2")    # VPWS AC (DX2)
    tgen.add_link(tgen.gears["host2b"], tgen.gears["r2"], "eth0", "eth2")
    tgen.add_link(tgen.gears["host1c"], tgen.gears["r1"], "eth0", "eth3")    # EVI 20 AC (br20/vlan20)
    tgen.add_link(tgen.gears["host2c"], tgen.gears["r2"], "eth0", "eth3")


# Operator-owned sr6 model: zebra no longer creates/enslaves/brings up the
# sr6 (sr6) tunnel netdevs.  The operator pre-creates them, enslaves them to
# the EVI/VPWS bridge and brings them up; zebra discovers them by name prefix
# (sr6-* unicast / bum-sr6-* BUM / vpws-sr6-<inst>), programs the
# zebra-assigned End.DT2U/DT2M/DX2 SID in place, and (for a VLAN-aware EVI
# bridge) adds the EVI VLAN.  The segs below is a placeholder zebra overwrites.
_SR6_DUMMY_SID = "2001:db8:5262::1"

def _add_sr6(pe, name, br, is_bum, brport=True, vid=None):
    # Create the sr6 (sr6) netdev: `mode` is mandatory and `segs` takes a
    # comma-separated SID list; the SID here is a placeholder that zebra
    # overwrites in place with the zebra-assigned End.DT2U/DT2M/DX2 SID.  The
    # rest is exactly what zebra used to program in its interface-add hook.
    pe.run("ip link add name %s type sr6 mode full segs %s" % (name, _SR6_DUMMY_SID))
    pe.run("ip link set %s addrgenmode none" % name)
    pe.run("ip link set %s master %s" % (name, br))
    if vid:
        # VLAN-aware EVI bridge: the decapped/flooded inner frame is VLAN-tagged,
        # so the sr6 AND bum-sr6 overlay ports must be members of the EVI VLAN
        # (tagged) or the bridge won't flood BUM to them.  In the operator-owned
        # model FRR no longer adds this per-sr6 (it did in the auto-create
        # if-add hook), so the operator provisions it here.
        pe.run("bridge vlan add dev %s vid %d" % (name, vid))
    if brport:
        # EVPN split-horizon + flood policy (was dplane_sr6_brport_flags):
        # learning off; unknown-unicast/mcast/bcast flood only on the BUM port;
        # isolated on both (a frame from one overlay port is never re-flooded to
        # another - no PE-to-PE loop).
        fl = "on" if is_bum else "off"
        pe.run("bridge link set dev %s learning off flood %s mcast_flood %s "
               "bcast_flood %s isolated on" % (name, fl, fl, fl))
    pe.run("ip link set %s up" % name)


def _pe_kernel(pe):
    # SRv6 L2 EVPN: one VLAN-aware bridge per EVI, bound to the EVI purely via
    # 'segment-routing srv6 l2-evpn'.  Operator-owned model: the operator
    # pre-creates the sr6 (unicast) / bum-sr6 (BUM) decap netdevs and enslaves
    # them to the EVI bridge; zebra discovers them and programs the per-EVI SID.
    for evi, br, ac, vid in EVIS:
        pe.run("ip link add %s type bridge vlan_filtering 1" % br)
        pe.run("ip link set %s up" % br)
        pe.run("ip link set %s master %s" % (ac, br))
        pe.run("bridge vlan add dev %s vid %d self" % (br, vid))
        pe.run("bridge vlan add dev %s vid %d pvid untagged" % (ac, vid))
        pe.run("ip link set %s up" % ac)
        _add_sr6(pe, "sr6-%d" % evi, br, is_bum=False, vid=vid)
        _add_sr6(pe, "bum-sr6-%d" % evi, br, is_bum=True, vid=vid)

    # Operator-created VPWS bridge + sr6.  The VPWS instance binds the bridge
    # with `interface eth2 sid auto bridge br-vpws`; the operator provisions the
    # (empty, dedicated) bridge, enslaves the AC (eth2) and the vpws-sr6 encap
    # netdev, and zebra programs the peer SID into it.  Point-to-point, so no
    # VLAN filtering and no brport isolation.
    pe.run("ip link add br-vpws type bridge")
    pe.run("ip link set br-vpws up")
    pe.run("ip link set eth2 master br-vpws")
    pe.run("ip link set eth2 up")
    _add_sr6(pe, "vpws-sr6-V2", "br-vpws", is_bum=False, brport=False)

def setup_module(mod):
    if required_linux_kernel_version("5.14") is not True:
        pytest.skip("Kernel requirements are not met")
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()
    for rname, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, "%s/frr.conf" % rname))
    _pe_kernel(tgen.gears["r1"])
    _pe_kernel(tgen.gears["r2"])
    tgen.start_router()

    # Build the l2-evpn re-apply block (all EVIs) once.
    evi_block = "configure terminal\nsegment-routing\n srv6\n  l2-evpn\n"
    for evi, br, _ac, vid in EVIS:
        evi_block += ("   evi %d locator MAIN bridge %s\n"
                      "    service-type vlan-based\n     vlan %d\n   exit\n"
                      % (evi, br, vid))

    for r in ("r1", "r2"):
        # The SRv6 locator is already instantiated by the unified frr.conf load
        # (via mgmtd), so only (re)assert the VLAN->EVI bindings here.  Do NOT
        # re-create the locator: re-applying its prefix/format lands as a
        # runtime "encoding change", which forces a per-EVI SID reallocation
        # that tears down the DT2M/BUM (Type-3) setup without rebuilding it --
        # bum-sr6 is lost, BUM flooding dies, and inter-host pings fail.
        tgen.gears[r].vtysh_cmd(evi_block)

    # Gate on FULL convergence before any test: BGP Established AND the remote
    # SRv6 underlay /128s installed both ways.  Front-loads settling so no
    # per-test poll races on a slow (CI) run.
    last = {"reason": "not evaluated"}

    def _converged():
        try:
            s1 = json.loads(tgen.gears["r1"].vtysh_cmd("show bgp l2vpn evpn summary json"))
            s2 = json.loads(tgen.gears["r2"].vtysh_cmd("show bgp l2vpn evpn summary json"))
            st1 = s1.get("peers", {}).get("2001:db8:20::2", {}).get("state")
            st2 = s2.get("peers", {}).get("2001:db8:20::1", {}).get("state")
            if st1 != "Established" or st2 != "Established":
                last["reason"] = "BGP not Established (r1->r2=%s, r2->r1=%s)" % (st1, st2)
                return False
            # remote underlay must be installed both directions: at least one
            # /128 under the peer's locator block (per-EVI SID function values
            # are zebra-assigned, so match the locator prefix, not an exact SID)
            r1r = tgen.gears["r1"].run("ip -6 route show")
            r2r = tgen.gears["r2"].run("ip -6 route show")
            have = ("fcbb:bbbb:2:" in r1r, "fcbb:bbbb:1:" in r2r)
            if not all(have):
                last["reason"] = ("underlay missing (r1 has fcbb:bbbb:2:=%s, r2 has fcbb:bbbb:1:=%s)"
                                  % have)
                return False
            return True
        except (KeyError, ValueError, TypeError) as e:
            last["reason"] = "exception: %r" % e
            return False

    reapplied = [False]

    def _converged_or_retry():
        if _converged():
            return True
        if not reapplied[0] and "underlay missing" in last["reason"]:
            for r in ("r1", "r2"):
                tgen.gears[r].vtysh_cmd(evi_block)
            reapplied[0] = True
        return False

    _, ok = topotest.run_and_expect(_converged_or_retry, True, count=180, wait=1)
    assert ok is True, "topology did not converge (BGP + underlay) within 180s: %s" % last["reason"]


def teardown_module(mod):
    get_topogen().stop_topology()

def _expect(name, cmd, expected_file, count=30, wait=1):
    def _c(r, c, e): return topotest.json_cmp(json.loads(r.vtysh_cmd(c)), e)
    tgen = get_topogen()
    with open(os.path.join(CWD, expected_file)) as f:
        expected = json.load(f)
    func = functools.partial(_c, tgen.gears[name], cmd, expected)
    _, res = topotest.run_and_expect(func, None, count, wait)
    assert res is None, "%s: %s != %s" % (name, cmd, expected_file)

def _expect_text(router, cmd, needles, count=30, wait=1):
    """Poll a (non-JSON) vtysh command until all needle substrings appear."""
    def _missing():
        out = get_topogen().gears[router].vtysh_cmd(cmd)
        miss = [n for n in needles if n not in out]
        return miss if miss else None  # None => success (all needles present)
    _, res = topotest.run_and_expect(_missing, None, count=count, wait=wait)
    assert res is None, "%s: missing %s in '%s'" % (router, res, cmd)

# (1) BGP neighborship
def test_bgp_evpn_neighborship():
    _expect("r1", "show bgp l2vpn evpn summary json", "r1/evpn_summary.json")
    _expect("r2", "show bgp l2vpn evpn summary json", "r2/evpn_summary.json")

# (2) SID allocation: per-EVI DT2U / DT2M (both EVIs) + VPWS DX2.
#     Per-EVI SID function values are zebra-assigned, so match the endpoint
#     behaviours + locator prefix rather than exact SID addresses.
def test_srv6_sid_allocation():
    _expect_text("r1", "show bgp segment-routing srv6 evpn",
                 ["fcbb:bbbb:1:", "End.DT2U", "End.DT2M", "uDX2", "oif=eth2"])
    _expect_text("r2", "show bgp segment-routing srv6 evpn",
                 ["fcbb:bbbb:2:", "End.DT2U", "End.DT2M", "uDX2"])

# (3) underlay + steady-state per-EVI L2 decap.  The remote underlay /128s (peer
#     locator block) land in the zebra RIB; each EVI's local L2 service SIDs
#     decap in the kernel as End.DT2U onto that EVI's OWN sr6-N bridge-slave, so
#     the number of distinct unicast sr6-N l2dev devices == number of EVIs.
#     Behaviour/prefix-based, so no per-SID expected-JSON is needed.
@sr6_required
def test_underlay_and_dt2m_routes():
    def _check(r, remote):
        gear = get_topogen().gears[r]
        if remote not in gear.vtysh_cmd("show ipv6 route"):
            return "remote underlay %s not in RIB" % remote
        kern = gear.run("ip -6 route show")
        sr6 = set()
        for ln in kern.splitlines():
            toks = ln.split()
            if "l2dev" in toks:
                dev = toks[toks.index("l2dev") + 1]
                if dev.startswith("sr6-"):   # per-EVI unicast sr6 (not bum-/vpws-)
                    sr6.add(dev)
        if len(sr6) < 2:
            return ("expected >=2 per-EVI L2 (End.DT2U) sr6 decap devices, got %s:\n%s"
                    % (sorted(sr6), kern))
        return None

    for r, remote in (("r1", "fcbb:bbbb:2:"), ("r2", "fcbb:bbbb:1:")):
        _, res = topotest.run_and_expect(
            lambda rr=r, rem=remote: _check(rr, rem), None, count=20, wait=1)
        assert res is None, "%s: %s" % (r, res)

# (3b) DX2 decap, kernel only (netlink-direct, never in RIB). VPWS DX2 SID
#      value is zebra-assigned, so match the behaviour + oif in the full table.
def test_decap_dx2_kernel():
    out = get_topogen().gears["r1"].run("ip -6 route show")
    dx2 = [ln for ln in out.splitlines() if "End.DX2" in ln and "oif eth2" in ln]
    assert dx2, "DX2 decap (End.DX2 oif eth2) not in kernel:\n%s" % out

# (4) interfaces - steady-state VPWS sr6 + a per-EVI bum-sr6 for each EVI.
@sr6_required
def test_sr6_interfaces():
    r1 = get_topogen().gears["r1"]

    def _check():
        links = r1.run("ip -o link show")
        if "vpws-sr6-V2" not in links:
            return "missing vpws-sr6-V2 on r1:\n%s" % links
        # Operator-bridge model: zebra enslaves the AC (eth2) and the sr6
        # encap netdev to the operator-created br-vpws (never creates a bridge).
        for dev in ("eth2", "vpws-sr6-V2"):
            if not any(dev in ln and "master br-vpws" in ln
                       for ln in links.splitlines()):
                return "%s not enslaved to br-vpws on r1:\n%s" % (dev, links)
        n_bum = sum(1 for ln in links.splitlines() if "bum-sr6-" in ln)
        if n_bum < 2:
            return ("expected >=2 bum-sr6 (one DT2M netdev per EVI) on r1, "
                    "got %d:\n%s" % (n_bum, links))
        return None

    _, res = topotest.run_and_expect(_check, None, count=30, wait=1)
    assert res is None, res

# (5) E2E ping over each EVI - proves both VLAN->EVI bridges forward.
#     Each learns the remote MAC => triggers that EVI's unicast DT2U + sr6.
@sr6_required
@sr6_reprogram_required
def test_ping_evi10():
    check_ping("host1", "192.0.2.2", True, 20, 1)

@sr6_required
@sr6_reprogram_required
def test_ping_evi20():
    check_ping("host1c", "198.51.100.2", True, 20, 1)

# (5a) VPWS pseudowire baseline: host1b <-> host2b share 203.0.113.0/24 over the
#      End.DX2 cross-connect (sid auto).
@sr6_required
@sr6_reprogram_required
def test_ping_vpws():
    check_ping("host1b", "203.0.113.2", True, 30, 1)

# (5b) DT2U unicast decap, asserted RIGHT AFTER the pings. The unicast per-EVI
#      DT2U decap SID appears in the kernel with a per-MAC sr6 netdev (sr6-*,
#      distinct from the bum-sr6 BUM netdev).
@sr6_required
def test_decap_dt2u_after_traffic():
    r1 = get_topogen().gears["r1"]

    def _missing_dt2u():
        out = r1.run("ip -6 route show")
        dt2u = [ln for ln in out.splitlines()
                if "End.DT2U" in ln and "sr6-" in ln and "bum-sr6-" not in ln]
        return None if dt2u else (out or "<no route>")

    _, res = topotest.run_and_expect(_missing_dt2u, None, count=30, wait=1)
    assert res is None, "DT2U unicast decap not installed after traffic:\n%s" % res

# (5c) REMOTE MAC via Type-2 -- the assertion this suite was missing.  The pings
#      above pass on BUM flooding (End.DT2M) alone, so a GREEN ping does NOT
#      prove per-MAC Type-2 origination works: if zebra_evpn_map_vlan()
#      short-circuits on a vlan-aware bridge (returns NULL before the SRv6 EVI
#      lookup) the peer's host MAC is never originated as a Type-2 yet the ping
#      still succeeds, flooded.  Assert the remote host MAC is both (a) received
#      as a Type-2 in BGP and (b) programmed into this PE's bridge FDB on the
#      per-EVI unicast sr6 netdev.  Fails fast if that short-circuit returns.
@sr6_required
def test_remote_mac_type2_originated():
    tgen = get_topogen()

    def _mac(host):
        return tgen.gears[host].run(
            "cat /sys/class/net/eth0/address").strip().lower()

    # (peer PE that must learn it, its per-EVI unicast sr6 netdev, remote host,
    #  remote host IP).  host2* sit behind r2, host1* behind r1.
    remotes = (
        ("r1", "sr6-10", "host2",  "192.0.2.2"),
        ("r2", "sr6-10", "host1",  "192.0.2.1"),
        ("r1", "sr6-20", "host2c", "198.51.100.2"),
        ("r2", "sr6-20", "host1c", "198.51.100.1"),
    )

    # Nudge each host so its LOCAL PE learns the host MAC and originates a
    # Type-2.  The echo request alone triggers local learning (no reply
    # needed), so this holds even where the sr6 encap dataplane is unavailable.
    for _pe, _dev, host, ip in remotes:
        tgen.gears[host].run("ping -c2 -W1 %s" % ip)

    def _missing():
        miss = []
        for pe, dev, host, _ip in remotes:
            mac = _mac(host)
            # (a) control plane: Type-2 for the remote MAC received by the peer
            if mac not in tgen.gears[pe].vtysh_cmd("show bgp l2vpn evpn").lower():
                miss.append("%s: no Type-2 for remote %s (%s) in BGP"
                            % (pe, host, mac))
            # (b) data plane: remote MAC programmed on the per-EVI unicast sr6
            fdb = tgen.gears[pe].run("bridge fdb show dev %s" % dev)
            if mac not in fdb.lower():
                miss.append("%s: remote MAC %s (%s) not programmed on %s"
                            % (pe, host, mac, dev))
        return miss or None

    _, res = topotest.run_and_expect(_missing, None, count=30, wait=1)
    assert res is None, ("remote MAC not learned via Type-2 (possible "
                         "zebra_evpn_map_vlan vlan-aware short-circuit):\n%s"
                         % res)

# ---------------------------------------------------------------------------
# Explicit / automatic SID assignment (EVI DT2U/DT2M + VPWS DX2) and SRv6
# locator / block validation.  The locator MAIN uses the usid-f3216 format, so
# explicit functions must come from the ELIB range 0xfe00-0xfeff while dynamic
# ones come from the LIB (0xe000+); the ranges never overlap.
# ---------------------------------------------------------------------------
R1_DT2U = "fcbb:bbbb:1:fe10::"
R1_DT2M = "fcbb:bbbb:1:fe11::"
R1_DX2 = "fcbb:bbbb:1:fe20::"
R1_L = "fcbb:bbbb:1:"

def _evi_cfg(router, evi, cmds):
    """Run `cmds` (newline separated) inside 'evi <evi>' of the l2-evpn node."""
    return get_topogen().gears[router].vtysh_cmd(
        "configure terminal\nsegment-routing\n srv6\n  l2-evpn\n"
        "   evi %d\n%s\n" % (evi, cmds))

def _vpws_cfg(router, asn, cmds):
    return get_topogen().gears[router].vtysh_cmd(
        "configure terminal\nrouter bgp %d\n address-family l2vpn evpn\n"
        "  vpws-instance V2\n%s\n" % (asn, cmds))

def _running(router, section=None):
    cmd = "show running-config"
    return get_topogen().gears[router].vtysh_cmd(cmd)

def _sid_table(router):
    return get_topogen().gears[router].vtysh_cmd("show segment-routing srv6 sid")

def _expect_in(fn, needle, present=True, count=30, wait=1):
    """Poll until `needle` is (not) a substring of fn()."""
    def _c():
        out = fn()
        return None if ((needle in out) == present) else out
    _, res = topotest.run_and_expect(_c, None, count=count, wait=wait)
    assert res is None, "%s %s expected %s:\n%s" % (
        needle, "missing" if present else "still present", present, res)

def _block_explicit_used(router):
    blocks = json.loads(get_topogen().gears[router].vtysh_cmd(
        "show segment-routing srv6 block json"))["blocks"]
    for b in blocks:
        if b["prefix"].startswith("fcbb:bbbb:"):
            return b["explicitRange"]["allocated"]
    return None

# (7) EVI explicit DT2U/DT2M SID: accepted, allocated as explicit, advertised
#     to bgpd, reflected in the block usage counters, and removed again (no
#     stale local decap route) when switched back to auto.
def test_evi_explicit_sid_assignment():
    r1 = get_topogen().gears["r1"]
    base = _block_explicit_used("r1")

    _evi_cfg("r1", 10, "sid dt2u explicit %s\nsid dt2m explicit %s" % (R1_DT2U, R1_DT2M))
    run = _running("r1")
    assert "sid dt2u explicit %s" % R1_DT2U in run, run
    assert "sid dt2m explicit %s" % R1_DT2M in run, run

    _expect_in(lambda: _sid_table("r1"), R1_DT2U)
    _expect_in(lambda: _sid_table("r1"), R1_DT2M)
    _expect_in(lambda: r1.vtysh_cmd("show bgp segment-routing srv6 evpn"), R1_DT2U)
    _, res = topotest.run_and_expect(
        lambda: None if _block_explicit_used("r1") == base + 2 else _block_explicit_used("r1"),
        None, count=15, wait=1)
    assert res is None, "explicit block usage did not grow by 2 (base %s, now %s)" % (base, res)

    # back to automatic: explicit SIDs released and local decap routes gone
    _evi_cfg("r1", 10, "sid dt2u auto\nsid dt2m auto")
    _expect_in(lambda: _sid_table("r1"), R1_DT2U, present=False)
    _expect_in(lambda: _sid_table("r1"), R1_DT2M, present=False)
    _expect_in(lambda: r1.run("ip -6 route show"), R1_DT2U, present=False)
    _expect_in(lambda: r1.run("ip -6 route show"), R1_DT2M, present=False)
    assert _block_explicit_used("r1") == base
    assert "sid dt2u explicit" not in _running("r1")

# (7b) the EVI still forwards with an explicit SID (remote PE re-learns it)
@sr6_required
@sr6_reprogram_required
def test_ping_evi10_explicit_sid():
    _evi_cfg("r1", 10, "sid dt2u explicit %s\nsid dt2m explicit %s" % (R1_DT2U, R1_DT2M))
    try:
        _expect_in(lambda: get_topogen().gears["r1"].run("ip -6 route show"), R1_DT2U)
        check_ping("host1", "192.0.2.2", True, 30, 1)
    finally:
        _evi_cfg("r1", 10, "sid dt2u auto\nsid dt2m auto")
    check_ping("host1", "192.0.2.2", True, 30, 1)

# (8) EVI explicit SID validation: rejected at the CLI, config stays unchanged.
def test_evi_explicit_sid_validation():
    # outside the EVI's locator (MAIN = fcbb:bbbb:1::/48)
    out = _evi_cfg("r1", 10, "sid dt2u explicit fcbb:bbbb:2:fe10::")
    assert "sid dt2u explicit fcbb:bbbb:2:fe10::" not in _running("r1"), out
    # outside the block entirely
    out = _evi_cfg("r1", 10, "sid dt2u explicit 2001:db8:ffff:fe10::")
    assert "sid dt2u explicit 2001:db8:ffff:fe10::" not in _running("r1"), out

    # same value for DT2U and DT2M of one EVI
    _evi_cfg("r1", 10, "sid dt2u explicit %s" % R1_DT2U)
    try:
        out = _evi_cfg("r1", 10, "sid dt2m explicit %s" % R1_DT2U)
        assert "sid dt2m explicit" not in _running("r1"), out
        # same value on another EVI
        out = _evi_cfg("r1", 20, "sid dt2u explicit %s" % R1_DT2U)
        assert _running("r1").count("sid dt2u explicit %s" % R1_DT2U) == 1, out
    finally:
        _evi_cfg("r1", 10, "sid dt2u auto")
    assert "sid dt2u explicit" not in _running("r1")

# (9) existing dynamic SID: an explicit value equal to a live SID is refused
#     (the manager must not hold two SIDs on one address).
def test_evi_explicit_sid_conflicts_with_live_sid():
    r1 = get_topogen().gears["r1"]
    live = [ln.split()[0] for ln in _sid_table("r1").splitlines()
            if ln.split() and ln.split()[0].startswith(R1_L) and
            "DT2U" in ln]
    assert live, "no live End.DT2U SID to collide with:\n%s" % _sid_table("r1")
    sid = live[0]
    out = _evi_cfg("r1", 20, "sid dt2m explicit %s" % sid)
    assert "sid dt2m explicit" not in _running("r1"), out


# (10) VPWS explicit End.DX2 SID: allocated as explicit, installed in the
#      kernel, and advertised; switching back to auto removes the explicit
#      route and re-installs a dynamic one.
def test_vpws_explicit_sid():
    r1 = get_topogen().gears["r1"]
    base = _block_explicit_used("r1")

    _vpws_cfg("r1", 65001, "  interface eth2 sid explicit %s bridge br-vpws" % R1_DX2)
    assert ("interface eth2 sid explicit %s bridge br-vpws" % R1_DX2) in _running("r1")

    _expect_in(lambda: _sid_table("r1"), R1_DX2)
    _expect_in(lambda: r1.vtysh_cmd("show bgp segment-routing srv6 evpn"), R1_DX2)
    _expect_in(lambda: "\n".join(l for l in r1.run("ip -6 route show").splitlines()
                                 if R1_DX2 in l and "End.DX2" in l and "oif eth2" in l),
               R1_DX2)
    assert _block_explicit_used("r1") == base + 1

    _vpws_cfg("r1", 65001, "  interface eth2 sid auto bridge br-vpws")
    _expect_in(lambda: _sid_table("r1"), R1_DX2, present=False)
    _expect_in(lambda: r1.run("ip -6 route show"), R1_DX2, present=False)
    _expect_in(lambda: "\n".join(l for l in r1.run("ip -6 route show").splitlines()
                                 if "End.DX2" in l and "oif eth2" in l),
               "End.DX2")
    assert _block_explicit_used("r1") == base

@sr6_required
@sr6_reprogram_required
def test_ping_vpws_explicit_sid():
    # host1b/host2b share 203.0.113.0/24 over the pseudowire
    check_ping("host1b", "203.0.113.2", True, 30, 1)
    _vpws_cfg("r1", 65001, "  interface eth2 sid explicit %s bridge br-vpws" % R1_DX2)
    try:
        _expect_in(lambda: get_topogen().gears["r1"].run("ip -6 route show"), R1_DX2)
        check_ping("host1b", "203.0.113.2", True, 30, 1)
    finally:
        _vpws_cfg("r1", 65001, "  interface eth2 sid auto bridge br-vpws")
    check_ping("host1b", "203.0.113.2", True, 30, 1)

# (11) a VPWS explicit SID must not collide with an EVI SID, in either order
def test_vpws_evi_explicit_sid_cross_check():
    _evi_cfg("r1", 10, "sid dt2u explicit %s" % R1_DT2U)
    try:
        _vpws_cfg("r1", 65001, "  interface eth2 sid explicit %s bridge br-vpws" % R1_DT2U)
        # the SID table must hold R1_DT2U exactly once
        assert _sid_table("r1").count(R1_DT2U) == 1, _sid_table("r1")
    finally:
        _vpws_cfg("r1", 65001, "  interface eth2 sid auto bridge br-vpws")
        _evi_cfg("r1", 10, "sid dt2u auto")
    assert R1_DT2U not in _sid_table("r1")

# (12) locator / block validation: a locator whose prefix overlaps an existing
#      locator is rejected, MAIN stays untouched.
def test_locator_overlap_rejected():
    r1 = get_topogen().gears["r1"]
    before = _running("r1").count("prefix fcbb:bbbb:1::/48")
    assert before == 1
    # (prefix, node-len): block-len 32 + node-len must equal the prefix length
    for dup, nlen in (("fcbb:bbbb:1::/48", 16), ("fcbb:bbbb:1:1::/64", 32)):
        out = r1.vtysh_cmd(
            "configure terminal\nsegment-routing\n srv6\n  locators\n"
            "   locator DUP\n    prefix %s block-len 32 node-len %d\n" % (dup, nlen))
        assert "overlaps with locator MAIN" in out, out
        # MAIN is untouched and DUP got no prefix
        assert _running("r1").count("prefix fcbb:bbbb:1::/48") == 1, out
        assert "prefix %s" % dup not in _running("r1") or dup == "fcbb:bbbb:1::/48", out
    r1.vtysh_cmd("configure terminal\nsegment-routing\n srv6\n  locators\n"
                 "   no locator DUP\n")
    assert _running("r1").count("prefix fcbb:bbbb:1::/48") == 1

# (13) 'show segment-routing srv6 block' and the SID Scope column
def test_show_srv6_block_and_sid_scope():
    _expect_in(lambda: get_topogen().gears["r1"].vtysh_cmd(
        "show segment-routing srv6 block"), "fcbb:bbbb::/32")
    blocks = json.loads(get_topogen().gears["r1"].vtysh_cmd(
        "show segment-routing srv6 block json"))["blocks"]
    blk = [b for b in blocks if b["prefix"].startswith("fcbb:bbbb:")]
    assert blk and blk[0]["format"] == "usid-f3216", blocks
    assert blk[0]["explicitRange"]["start"] == 0xFE00 and blk[0]["explicitRange"]["end"] == 0xFEFF
    assert "Scope" in _sid_table("r1")


# (6) teardown, stays LAST: removing the VLAN->EVI bindings releases the per-EVI
#     End.DT2U / End.DT2M service SIDs (replaces the old 'no sid vpn export').
def test_evi_unbind_releases_l2_sids():
    r1 = get_topogen().gears["r1"]
    r1.vtysh_cmd("configure terminal\nsegment-routing\n srv6\n  l2-evpn\n"
                 "   no evi 10\n   no evi 20\n")

    def _not_released():
        out = r1.run("ip -6 route show")
        released = ("End.DT2U" not in out and "End.DT2M" not in out)
        return None if released else out

    _, res = topotest.run_and_expect(_not_released, None, count=30, wait=1)
    assert res is None, "per-EVI DT2U/DT2M not released after 'no evi 10/20':\n%s" % res

if __name__ == "__main__":
    sys.exit(pytest.main([os.path.basename(__file__)] + sys.argv[1:]))
