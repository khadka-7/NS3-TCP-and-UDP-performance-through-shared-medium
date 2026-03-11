**Cross‑Layer Performance Analysis of TCP over 802.11ax EDCA WLANs**

This repository contains the ns‑3.46 simulation code and sweep scripts for a systematic study of how Wi‑Fi’s Enhanced Distributed Channel Access (EDCA) QoS mechanisms affect TCP performance in an 802.11ax network. The work investigates the coexistence of latency‑sensitive UDP traffic (voice, video) with best‑effort TCP flows under controlled, repeatable conditions.

**Overview**

The primary research question is: How do EDCA access parameters (AIFSN, CWmin) and varying loads of high‑priority UDP traffic causally influence the behaviour of TCP congestion control algorithms – specifically RTT inflation, congestion window adaptation, throughput, and fairness – for BE (best‑effort) and BK (background) class flows?

Using ns‑3’s detailed 802.11ax model, we simulate a single infrastructure BSS with one access point (AP) and two stations (STAs). Four traffic flows are generated from wired servers towards the STAs:

VO‑Flood (UDP, AC_VO) to STA1

VI‑Flood (UDP, AC_VI) to STA2

BE‑TCP (TCP, AC_BE) to STA1

BK‑TCP (TCP, AC_BK) to STA2

The load of the UDP interferers is swept from 0 to 135 Mbps (VO) and 0 to 45 Mbps (VI), while the TCP flows always run greedy bulk transfers. This design isolates the impact of EDCA priority on transport‑layer metrics.

Research Objectives
Quantify the starvation threshold at which combined VO+VI load completely suppresses BE/BK throughput.

Measure RTT inflation and congestion window reduction caused by MAC queue build‑up.

Compute cross‑layer correlations (queue depth → RTT, queue depth → CWND) with lag analysis to identify causal relationships.

Compare the performance of TCP Bbr, Cubic, and NewReno under identical EDCA pressure.

Evaluate inter‑class fairness (Jain index) between BE and BK flows.

Verify that VO/VI latency SLAs (p95 ≤ 10 ms / 50 ms) are maintained.

Methodology
Topology
AP: 802.11ax, QoS enabled, FqCoDel queue disc, all four EDCA access categories active.

STA1: 10 m from AP, receives VO‑Flood + BE‑TCP.

STA2: 15 m from AP, receives VI‑Flood + BK‑TCP (asymmetric distances reflect realistic deployments).

Servers: Four wired nodes, each connected to the AP via dedicated 1000 Mbps / 5 ms point‑to‑point links (bottleneck is always the Wi‑Fi channel).

All traffic is downlink (server → AP → STA); only TCP ACKs are sent uplink.

Simulation Parameters
Parameter	Value
Wi‑Fi standard	802.11ax (5 GHz, 80 MHz)
PHY rate	150 Mbps (baseline)
Rate control	MinstrelHt (Scenario 2), Ideal (Scenarios 6/8)
Fading	Nakagami (on/off per scenario)
EDCA parameters	Default 802.11ax values (see code)
MAC queue size	500 packets
Queue discipline	FqCoDel (1000 packets)
Simulation time	200 s (application run)
Warm‑up	10 s (Wi‑Fi association, routing)
Measurement delay	30 s after app start (excludes slow‑start)
Clean window	170 s per run
Random seeds	30 per (load × variant) cell
TCP variants	Bbr, Cubic, NewReno
Traffic Models
VO‑Flood: UDP, 1400‑byte packets, CBR at load voLoad (0–135 Mbps).

VI‑Flood: UDP, 1400‑byte packets, CBR at load viLoad = voLoad / 3.

BE‑TCP: Greedy bulk transfer (always data to send).

BK‑TCP: Greedy bulk transfer.

Key Enhancements
Reservoir sampling for latency measurements to avoid buffer overflow at high packet rates.

True MAC queuing delay via WifiMacQueue Enqueue/Dequeue traces (replaces static PHY‑rate estimate).

Measurement window filtering: all metrics (throughput, RTT, latency, queue occupancy) are computed only after warmup + measureDelay to exclude transients.

Cross‑layer correlation with lag analysis (Pearson r, p‑values, peak lag).

Sweep scripts with resume mode, per‑run timeouts, and suppression of heavy per‑run output files (--sweepMode).

Scenarios
Scenario	Description	Flows	STA distances	Rate mgr / Fading
1	Baseline mixed traffic	VO+VI+BE+BK	10 m, 15 m	MinstrelHt / on
2	Load sweep (main study)	VO‑Flood, VI‑Flood, BE‑TCP, BK‑TCP	10 m, 15 m	MinstrelHt / on
6	TCP variant isolation	VO, VI, BE‑TCP	10 m, 10 m	Ideal / off
8	Control (UDP on one STA, TCP on other)	VO+VI on STA1, BE+BK on STA2	10 m, 10 m	Ideal / off
