# NS3-TCP-and-UDP-performance-through-shared-medium
A comparative analysis of performance of TCP (NewReno, Cubic and Bbr) and UDP

<img width="363" height="326" alt="image" src="https://github.com/user-attachments/assets/061d3ffb-2fea-41a4-a3d3-7ea43094c0a9" />

This experiment models coexistence of TCP and UDP traffic over a shared wireless medium to study how transport-layer protocols interact under contention. The goal is to analyze performance metrics such as throughput, latency, jitter, packet loss, and fairness when a best-effort TCP flow and a rate-controlled UDP flow compete for a single bottleneck: a Wi-Fi access point.

==== SIMULATION PARAMETERS ==== /n
--Simulation Duration: 25 seconds /n
--TCP Algorithm: 1. TcpNewReno 2. TcpCubic 3. TcpBbr /n
--Bottleneck Bandwidth: 10 Mbps /n
--Bottleneck Delay: 10 ms /n
--Buffer Size: 1000 packets /n
--UDP Rate: 6 Mbps /n

-- Executing the script /n
--- /path-to-folder-of-NS3-installation/scratch  /n
--- paste file or nano/filename.cc and paste /n
--- To execute and run: go to NS3 installed path /n
                        - ./ns3 run /path/scratch/script_name.cc /n

                        
