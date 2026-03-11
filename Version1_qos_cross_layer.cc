#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/wifi-module.h"
#include "ns3/applications-module.h"
#include "ns3/mobility-module.h"
#include "ns3/traffic-control-module.h"
#include "ns3/ipv4-global-routing-helper.h"
#include "ns3/random-variable-stream.h"
#include "ns3/seq-ts-header.h"
#include "ns3/tcp-socket-base.h"
#include "ns3/wifi-mac-header.h"
#include "ns3/flow-monitor-module.h"

#include <fstream>
#include <vector>
#include <algorithm>
#include <map>
#include <cmath>
#include <iomanip>
#include <numeric>
#include <string>
#include <iostream>
#include <atomic>
#include <mutex>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("WiFiCrossLayerQoSSim");

// FORWARD DECLARATIONS
enum TrafficClass {
    TC_VO = 0,
    TC_VI = 1,
    TC_BE = 2,
    TC_BK = 3
};

enum StationId {
    STA1 = 0,
    STA2 = 1
};

struct TrafficConfig;
class TcpTracker;
class LatencyTracker;

// MATHEMATICAL UTILITIES
class MathUtils {
public:
    static double CalculateFairnessIndex(const std::vector<double>& throughputs) {
        if (throughputs.empty()) return 1.0;
        
        double sum = 0.0, sumSquared = 0.0;
        size_t n = throughputs.size();
        
        for (const auto& t : throughputs) {
            sum += t;
            sumSquared += t * t;
        }
        
        if (sumSquared == 0) return 1.0;
        return (sum * sum) / (n * sumSquared);
    }

    static double Percentile(const std::vector<double>& sortedData, double p) {
        if (sortedData.empty()) return 0.0;
        if (p <= 0) return sortedData.front();
        if (p >= 100) return sortedData.back();
        
        double index = (p / 100.0) * (sortedData.size() - 1);
        size_t lower = static_cast<size_t>(std::floor(index));
        size_t upper = static_cast<size_t>(std::ceil(index));
        
        if (lower == upper) return sortedData[lower];
        
        double fraction = index - lower;
        return sortedData[lower] * (1.0 - fraction) + sortedData[upper] * fraction;
    }

    static double CalculateCorrelation(const std::vector<double>& x, const std::vector<double>& y) {
        if (x.size() != y.size() || x.size() < 2) return 0.0;
        
        size_t n = x.size();
        double sum_x = 0, sum_y = 0, sum_xy = 0, sum_x2 = 0, sum_y2 = 0;
        
        for (size_t i = 0; i < n; ++i) {
            sum_x += x[i];
            sum_y += y[i];
            sum_xy += x[i] * y[i];
            sum_x2 += x[i] * x[i];
            sum_y2 += y[i] * y[i];
        }
        
        double num = n * sum_xy - sum_x * sum_y;
        double den = std::sqrt((n * sum_x2 - sum_x * sum_x) * (n * sum_y2 - sum_y * sum_y));
        
        return (den > 1e-9) ? num / den : 0.0;
    }

    static std::string InterpretCorrelation(double r) {
        if (r > 0.7) return "Strong positive";
        if (r > 0.3) return "Moderate positive";
        if (r > -0.3) return "Weak/None";
        if (r > -0.7) return "Moderate negative";
        return "Strong negative";
    }
};

// TRAFFIC CONFIGURATION
struct TrafficConfig {
    std::string name;
    uint8_t dscp;
    uint8_t tos;
    AcIndex wifiAc;
    std::string acName;
    double targetLatencyMs;
    double targetThroughputMbps;
    bool isLatencySensitive;
    uint32_t defaultPacketSize;
    double defaultIntervalMs;
    StationId station;
    std::string protocol;
};

const std::map<TrafficClass, TrafficConfig> TRAFFIC_CONFIGS = {
    {TC_VO, {"VO", 46, 0xB8, AC_VO, "AC_VO", 10.0, 0.5, true, 200, 3.2, STA1, "UDP"}},
    {TC_VI, {"VI", 34, 0x88, AC_VI, "AC_VI", 50.0, 2.0, true, 1200, 4.8, STA2, "UDP"}},
    {TC_BE, {"BE", 0, 0x00, AC_BE, "AC_BE", 200.0, 5.0, false, 1000, 0.0, STA1, "TCP"}},
    {TC_BK, {"BK", 8, 0x20, AC_BK, "AC_BK", 1000.0, 5.0, false, 1000, 0.0, STA2, "TCP"}}
};

// TCP TRACKER WITH PER-STA TRACKING
class TcpTracker {
public:
    struct Stats {
        uint64_t bytesSent = 0;
        uint64_t bytesReceived = 0;
        std::vector<std::pair<double, double>> rttSamples;
        std::vector<std::pair<double, uint32_t>> cwndSamples;
        std::vector<std::pair<double, uint32_t>> ssThreshSamples;
        std::vector<std::pair<double, double>> throughputSamples;
        double maxRtt = 0;
        double minRtt = 1e9;
        uint32_t maxCwnd = 0;
        uint32_t lastCwnd = 0;
        double lastRtt = 0;
        uint64_t retransmissions = 0;
        double estimatedBDP = 0;
        double cwndToBdpRatio = 0;
        TrafficClass trafficClass = TC_BE;
        StationId station = STA1;
    };

private:
    std::map<TrafficClass, Stats> stats_;
    mutable std::mutex mutex_;
    double lastSampleTime_ = 0;
    std::map<TrafficClass, uint64_t> lastBytes_;
    static constexpr size_t MAX_SAMPLES = 50000;

public:
    void RecordBytesSent(TrafficClass tc, uint32_t bytes) {
        std::lock_guard<std::mutex> lock(mutex_);
        stats_[tc].bytesSent += bytes;
        stats_[tc].trafficClass = tc;
        stats_[tc].station = TRAFFIC_CONFIGS.at(tc).station;
    }

    void RecordBytesReceived(TrafficClass tc, uint32_t bytes) {
        std::lock_guard<std::mutex> lock(mutex_);
        stats_[tc].bytesReceived += bytes;
    }

    void RecordRtt(TrafficClass tc, double time, double rttMs) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto& s = stats_[tc];
        if (rttMs > 0 && rttMs < 10000 && s.rttSamples.size() < MAX_SAMPLES) {
            s.rttSamples.emplace_back(time, rttMs);
            s.maxRtt = std::max(s.maxRtt, rttMs);
            s.minRtt = std::min(s.minRtt, rttMs);
            s.lastRtt = rttMs;
        }
    }

    void RecordCwnd(TrafficClass tc, double time, uint32_t cwnd) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto& s = stats_[tc];
        if (s.cwndSamples.size() < MAX_SAMPLES) {
            s.cwndSamples.emplace_back(time, cwnd);
            s.maxCwnd = std::max(s.maxCwnd, cwnd);
            s.lastCwnd = cwnd;
        }
    }

    void RecordSsThresh(TrafficClass tc, double time, uint32_t ssThresh) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (stats_[tc].ssThreshSamples.size() < MAX_SAMPLES) {
            stats_[tc].ssThreshSamples.emplace_back(time, ssThresh);
        }
    }

    void RecordRetransmission(TrafficClass tc) {
        std::lock_guard<std::mutex> lock(mutex_);
        stats_[tc].retransmissions++;
    }

    void SampleThroughput(TrafficClass tc, double time, double intervalSec = 1.0) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto& s = stats_[tc];
        
        if (s.throughputSamples.size() >= MAX_SAMPLES) return;
        
        auto it = lastBytes_.find(tc);
        if (it != lastBytes_.end()) {
            uint64_t bytesInInterval = s.bytesReceived - it->second;
            double mbps = (bytesInInterval * 8.0) / (intervalSec * 1e6);
            s.throughputSamples.emplace_back(time, mbps);
        }
        
        lastBytes_[tc] = s.bytesReceived;
    }

    Stats GetStats(TrafficClass tc) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = stats_.find(tc);
        return it != stats_.end() ? it->second : Stats{};
    }

    void CalculateBDP(double duration) {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& [tc, s] : stats_) {
            if (s.rttSamples.empty() || duration <= 0) continue;
            
            double avgRtt = 0;
            for (const auto& sample : s.rttSamples) {
                avgRtt += sample.second;
            }
            avgRtt /= s.rttSamples.size();
            
            double throughputMbps = (s.bytesReceived * 8.0) / (duration * 1e6);
            s.estimatedBDP = (throughputMbps * 1e6 / 8.0) * (avgRtt / 1000.0);
            
            double avgCwnd = 0;
            if (!s.cwndSamples.empty()) {
                for (const auto& sample : s.cwndSamples) {
                    avgCwnd += sample.second;
                }
                avgCwnd /= s.cwndSamples.size();
            }
            
            s.cwndToBdpRatio = (s.estimatedBDP > 0) ? avgCwnd / s.estimatedBDP : 0;
        }
    }

    void WriteDatFiles(const std::string& prefix) const {
        std::map<TrafficClass, Stats> localCopy;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            localCopy = stats_;
        }
        
        for (auto tc : {TC_BE, TC_BK}) {
            auto it = localCopy.find(tc);
            if (it == localCopy.end()) continue;

            const auto& s = it->second;
            const auto& cfg = TRAFFIC_CONFIGS.at(tc);
            
            std::string staPrefix = (cfg.station == STA1) ? "sta1" : "sta2";
            std::string baseFile = prefix + "_" + staPrefix + "_tcp_" + cfg.name;
            
            if (!s.rttSamples.empty()) {
                std::ofstream out(baseFile + "_rtt.dat");
                if (out) {
                    out << "# Time(s) RTT(ms)\n";
                    for (const auto& sample : s.rttSamples) {
                        out << sample.first << " " << sample.second << "\n";
                    }
                    out.close();
                }
            }
            
            if (!s.cwndSamples.empty()) {
                std::ofstream out(baseFile + "_cwnd.dat");
                if (out) {
                    out << "# Time(s) CWND(bytes)\n";
                    for (const auto& sample : s.cwndSamples) {
                        out << sample.first << " " << sample.second << "\n";
                    }
                    out.close();
                }
            }

            if (!s.ssThreshSamples.empty()) {
                std::ofstream out(baseFile + "_ssthresh.dat");
                if (out) {
                    out << "# Time(s) SSThresh(bytes)\n";
                    for (const auto& sample : s.ssThreshSamples) {
                        out << sample.first << " " << sample.second << "\n";
                    }
                    out.close();
                }
            }
            
            if (!s.throughputSamples.empty()) {
                std::ofstream out(baseFile + "_throughput.dat");
                if (out) {
                    out << "# Time(s) Throughput(Mbps)\n";
                    for (const auto& sample : s.throughputSamples) {
                        out << sample.first << " " << sample.second << "\n";
                    }
                    out.close();
                }
            }
            
            std::ofstream summary(baseFile + "_summary.dat");
            if (summary) {
                summary << "# TCP Flow Summary for " << staPrefix << " (" << cfg.name << ")\n";
                summary << "# Metric Value\n";
                summary << "BytesSent " << s.bytesSent << "\n";
                summary << "BytesReceived " << s.bytesReceived << "\n";
                summary << "MinRTT_ms " << (s.minRtt < 1e9 ? s.minRtt : 0) << "\n";
                summary << "MaxRTT_ms " << s.maxRtt << "\n";
                
                if (!s.rttSamples.empty()) {
                    double avgRtt = 0;
                    for (const auto& sample : s.rttSamples) avgRtt += sample.second;
                    avgRtt /= s.rttSamples.size();
                    summary << "AvgRTT_ms " << avgRtt << "\n";
                }
                
                summary << "MaxCWND_bytes " << s.maxCwnd << "\n";
                summary << "LastCWND_bytes " << s.lastCwnd << "\n";
                
                if (!s.cwndSamples.empty()) {
                    double avgCwnd = 0;
                    for (const auto& sample : s.cwndSamples) avgCwnd += sample.second;
                    avgCwnd /= s.cwndSamples.size();
                    summary << "AvgCWND_bytes " << avgCwnd << "\n";
                }
                
                summary << "EstimatedBDP_bytes " << s.estimatedBDP << "\n";
                summary << "CWND_to_BDP_ratio " << s.cwndToBdpRatio << "\n";
                summary << "Retransmissions " << s.retransmissions << "\n";
                summary << "RTT_samples " << s.rttSamples.size() << "\n";
                summary << "CWND_samples " << s.cwndSamples.size() << "\n";
                summary.close();
            }
        }
    }

    void Print(double duration) const {
        std::cout << "\n=== TCP FLOW ANALYSIS ===\n";

        for (auto tc : {TC_BE, TC_BK}) {
            auto s = GetStats(tc);
            const auto& cfg = TRAFFIC_CONFIGS.at(tc);
            std::string staName = (cfg.station == STA1) ? "STA1" : "STA2";

            double rxMbps = (s.bytesReceived * 8.0) / (duration * 1e6);
            double txMbps = (s.bytesSent * 8.0) / (duration * 1e6);

            std::cout << "\n" << staName << " - " << cfg.name << " (" << cfg.acName << "):\n";
            std::cout << std::fixed << std::setprecision(2);
            std::cout << "  Throughput: TX=" << txMbps << " Mbps, RX=" << rxMbps << " Mbps\n";
            std::cout << "  Bytes: Sent=" << s.bytesSent << ", Rx=" << s.bytesReceived << "\n";
            
            if (!s.rttSamples.empty()) {
                double avgRtt = 0;
                for (const auto& sample : s.rttSamples) avgRtt += sample.second;
                avgRtt /= s.rttSamples.size();
                std::cout << "  RTT: Avg=" << avgRtt << " ms, Min=" 
                          << (s.minRtt < 1e9 ? s.minRtt : 0) << " ms, Max=" << s.maxRtt << " ms\n";
            }
            
            if (!s.cwndSamples.empty()) {
                double avgCwnd = 0;
                for (const auto& sample : s.cwndSamples) avgCwnd += sample.second;
                avgCwnd /= s.cwndSamples.size();
                std::cout << "  CWND: Avg=" << avgCwnd << " bytes, Max=" << s.maxCwnd << " bytes\n";
            }
            
            std::cout << "  Retransmissions: " << s.retransmissions << "\n";
        }
    }
};

// LATENCY TRACKER WITH PER-STA TRACKING
class LatencyTracker {
public:
    struct Stats {
        std::vector<double> samples;
        std::vector<std::pair<double, double>> timeSeries;
        uint64_t packetsSent = 0;
        uint64_t packetsReceived = 0;
        uint64_t bytesSent = 0;
        uint64_t bytesReceived = 0;
        double p50 = 0, p95 = 0, p99 = 0, mean = 0;
        double minVal = 1e9, maxVal = 0;
        double jitter = 0;
        double lastLatency = -1;
        double coefficientOfVariation = 0;
        double standardDeviation = 0;
        TrafficClass trafficClass = TC_BE;
        StationId station = STA1;
    };

private:
    std::map<TrafficClass, Stats> stats_;
    mutable std::mutex mutex_;
    static constexpr size_t MAX_SAMPLES = 100000;

public:
    void RecordSend(TrafficClass tc, uint32_t bytes) {
        std::lock_guard<std::mutex> lock(mutex_);
        stats_[tc].packetsSent++;
        stats_[tc].bytesSent += bytes;
        stats_[tc].trafficClass = tc;
        stats_[tc].station = TRAFFIC_CONFIGS.at(tc).station;
    }

    void RecordReceive(TrafficClass tc, double latencyMs, uint32_t bytes, double time) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto& s = stats_[tc];
        s.packetsReceived++;
        s.bytesReceived += bytes;

        if (latencyMs > 0 && latencyMs < 10000 && s.samples.size() < MAX_SAMPLES) {
            s.samples.push_back(latencyMs);
            s.timeSeries.emplace_back(time, latencyMs);
            s.minVal = std::min(s.minVal, latencyMs);
            s.maxVal = std::max(s.maxVal, latencyMs);

            if (s.lastLatency >= 0) {
                double diff = std::abs(latencyMs - s.lastLatency);
                s.jitter += (diff - s.jitter) / 16.0;
            }
            s.lastLatency = latencyMs;
        }
    }

    void Calculate() {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& [tc, s] : stats_) {
            if (s.samples.empty()) continue;

            std::vector<double> sorted = s.samples;
            std::sort(sorted.begin(), sorted.end());
            size_t n = sorted.size();

            s.mean = std::accumulate(sorted.begin(), sorted.end(), 0.0) / n;
            s.p50 = MathUtils::Percentile(sorted, 50);
            s.p95 = MathUtils::Percentile(sorted, 95);
            s.p99 = MathUtils::Percentile(sorted, 99);
            
            double variance = 0.0;
            for (const auto& sample : sorted) {
                variance += (sample - s.mean) * (sample - s.mean);
            }
            s.standardDeviation = std::sqrt(variance / n);
            s.coefficientOfVariation = (s.mean > 0) ? s.standardDeviation / s.mean : 0;
        }
    }

    Stats GetStats(TrafficClass tc) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = stats_.find(tc);
        return it != stats_.end() ? it->second : Stats{};
    }

    void WriteDatFiles(const std::string& prefix) const {
        std::map<TrafficClass, Stats> localCopy;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            localCopy = stats_;
        }
        
        for (auto tc : {TC_VO, TC_VI}) {
            auto it = localCopy.find(tc);
            if (it == localCopy.end() || it->second.samples.empty()) continue;

            const auto& s = it->second;
            const auto& cfg = TRAFFIC_CONFIGS.at(tc);
            
            std::string staPrefix = (cfg.station == STA1) ? "sta1" : "sta2";
            std::string baseFile = prefix + "_" + staPrefix + "_udp_" + cfg.name;
            
            std::vector<double> sorted = s.samples;
            std::sort(sorted.begin(), sorted.end());
            
            std::ofstream cdfOut(baseFile + "_latency_cdf.dat");
            if (cdfOut) {
                cdfOut << "# Latency(ms) CDF\n";
                for (size_t i = 0; i < sorted.size(); ++i) {
                    cdfOut << sorted[i] << " " << (double)(i + 1) / sorted.size() << "\n";
                }
                cdfOut.close();
            }
            
            std::ofstream tsOut(baseFile + "_latency_timeseries.dat");
            if (tsOut) {
                tsOut << "# Time(s) Latency(ms)\n";
                for (const auto& sample : s.timeSeries) {
                    tsOut << sample.first << " " << sample.second << "\n";
                }
                tsOut.close();
            }
            
            if (!sorted.empty() && sorted.size() > 1) {
                std::ofstream histOut(baseFile + "_latency_histogram.dat");
                if (histOut) {
                    histOut << "# LatencyBin(ms) Count\n";
                    
                    double minLat = sorted.front();
                    double maxLat = sorted.back();
                    int numBins = 100;
                    
                    double binWidth = (maxLat > minLat) ? (maxLat - minLat) / numBins : 1.0;
                    
                    if (binWidth > 0) {
                        std::vector<int> bins(numBins, 0);
                        for (double val : sorted) {
                            int bin = std::min((int)((val - minLat) / binWidth), numBins - 1);
                            if (bin >= 0 && bin < numBins) bins[bin]++;
                        }
                        
                        for (int i = 0; i < numBins; ++i) {
                            double binCenter = minLat + (i + 0.5) * binWidth;
                            histOut << binCenter << " " << bins[i] << "\n";
                        }
                    }
                    histOut.close();
                }
            }
            
            std::ofstream summary(baseFile + "_summary.dat");
            if (summary) {
                summary << "# UDP Flow Summary for " << staPrefix << " (" << cfg.name << ")\n";
                summary << "# Metric Value\n";
                summary << "PacketsSent " << s.packetsSent << "\n";
                summary << "PacketsReceived " << s.packetsReceived << "\n";
                summary << "BytesSent " << s.bytesSent << "\n";
                summary << "BytesReceived " << s.bytesReceived << "\n";
                
                double loss = s.packetsSent > 0 ? 
                             100.0 * (1.0 - (double)s.packetsReceived / s.packetsSent) : 0;
                summary << "PacketLoss_percent " << loss << "\n";
                
                summary << "Latency_Mean_ms " << s.mean << "\n";
                summary << "Latency_P50_ms " << s.p50 << "\n";
                summary << "Latency_P95_ms " << s.p95 << "\n";
                summary << "Latency_P99_ms " << s.p99 << "\n";
                summary << "Latency_Min_ms " << (s.minVal < 1e9 ? s.minVal : 0) << "\n";
                summary << "Latency_Max_ms " << s.maxVal << "\n";
                summary << "Latency_StdDev_ms " << s.standardDeviation << "\n";
                summary << "Latency_CoeffVar " << s.coefficientOfVariation << "\n";
                summary << "Jitter_EMA_ms " << s.jitter << "\n";
                summary << "Samples " << s.samples.size() << "\n";
                summary.close();
            }
        }
    }

    void Print() const {
        std::cout << "\n=== UDP FLOW LATENCY ANALYSIS ===\n";

        for (auto tc : {TC_VO, TC_VI}) {
            auto s = GetStats(tc);
            if (s.samples.empty()) continue;

            const auto& cfg = TRAFFIC_CONFIGS.at(tc);
            std::string staName = (cfg.station == STA1) ? "STA1" : "STA2";
            
            double loss = s.packetsSent > 0 ? 
                         100.0 * (1.0 - (double)s.packetsReceived / s.packetsSent) : 0;

            std::cout << "\n" << staName << " - " << cfg.name << " (" << cfg.acName << "):\n";
            std::cout << std::fixed << std::setprecision(3);
            std::cout << "  Latency - Mean: " << s.mean << " ms, P50: " << s.p50
                      << " ms, P95: " << s.p95 << " ms, P99: " << s.p99 << " ms\n";
            std::cout << "  Range: [" << s.minVal << " - " << s.maxVal << "] ms\n";
            std::cout << "  Jitter (EMA): " << s.jitter << " ms\n";
            std::cout << "  Packets: " << s.packetsReceived << "/" << s.packetsSent
                      << " (loss: " << std::setprecision(2) << loss << "%)\n";
        }
    }
};

// CROSS-LAYER ANALYZER
class CrossLayerAnalyzer {
public:
    struct TcpSample {
        double timestamp;
        TrafficClass tc;
        StationId station;
        uint32_t queueLength;
        double tcpRtt;
        uint32_t cwnd;
        double phyLossRate;
        
        TcpSample() : timestamp(0), tc(TC_BE), station(STA1), queueLength(0), 
                     tcpRtt(0), cwnd(0), phyLossRate(0) {}
    };

    struct UdpSample {
        double timestamp;
        TrafficClass tc;
        StationId station;
        uint32_t queueLength;
        double latency;
        double phyLossRate;
        
        UdpSample() : timestamp(0), tc(TC_VO), station(STA1), queueLength(0),
                     latency(0), phyLossRate(0) {}
    };

    struct TcpCorrelationResult {
        double queueRttCorrelation;
        double queueCwndCorrelation;
        double lossRttCorrelation;
        double lossCwndCorrelation;
        std::string interpretation;
        
        TcpCorrelationResult() : queueRttCorrelation(0), queueCwndCorrelation(0),
                                lossRttCorrelation(0), lossCwndCorrelation(0) {}
    };

    struct UdpCorrelationResult {
        double queueLatencyCorrelation;
        double lossLatencyCorrelation;
        std::string interpretation;
        
        UdpCorrelationResult() : queueLatencyCorrelation(0), lossLatencyCorrelation(0) {}
    };

private:
    std::map<TrafficClass, std::vector<TcpSample>> tcpSamples_;
    std::map<TrafficClass, std::vector<UdpSample>> udpSamples_;
    mutable std::mutex mutex_;
    static constexpr size_t MAX_SAMPLES_PER_TC = 10000;

    TcpCorrelationResult AnalyzeTcpTrafficClassUnlocked(TrafficClass tc) const {
        TcpCorrelationResult result;
        
        auto it = tcpSamples_.find(tc);
        if (it == tcpSamples_.end() || it->second.size() < 20) {
            return result;
        }
        
        const std::vector<TcpSample>& tcSamples = it->second;
        size_t sampleCount = std::min(tcSamples.size(), size_t(5000));
        
        std::vector<double> queueLengths, rtts, cwnds, lossRates;
        queueLengths.reserve(sampleCount);
        rtts.reserve(sampleCount);
        cwnds.reserve(sampleCount);
        lossRates.reserve(sampleCount);
        
        for (size_t i = 0; i < sampleCount; ++i) {
            const auto& sample = tcSamples[i];
            if (sample.tcpRtt > 0 && sample.cwnd > 0) {
                queueLengths.push_back(static_cast<double>(sample.queueLength));
                rtts.push_back(sample.tcpRtt);
                cwnds.push_back(static_cast<double>(sample.cwnd));
                lossRates.push_back(sample.phyLossRate);
            }
        }
        
        if (queueLengths.size() >= 10) {
            result.queueRttCorrelation = MathUtils::CalculateCorrelation(queueLengths, rtts);
            result.queueCwndCorrelation = MathUtils::CalculateCorrelation(queueLengths, cwnds);
            result.lossRttCorrelation = MathUtils::CalculateCorrelation(lossRates, rtts);
            result.lossCwndCorrelation = MathUtils::CalculateCorrelation(lossRates, cwnds);
            
            std::stringstream ss;
            if (result.queueRttCorrelation > 0.5) ss << "Queue affects RTT. ";
            if (result.lossRttCorrelation > 0.5) ss << "Loss increases RTT. ";
            if (result.queueCwndCorrelation < -0.3) ss << "Queue reduces CWND. ";
            result.interpretation = ss.str();
        }
        
        return result;
    }

    UdpCorrelationResult AnalyzeUdpTrafficClassUnlocked(TrafficClass tc) const {
        UdpCorrelationResult result;
        
        auto it = udpSamples_.find(tc);
        if (it == udpSamples_.end() || it->second.size() < 20) {
            return result;
        }
        
        const std::vector<UdpSample>& tcSamples = it->second;
        size_t sampleCount = std::min(tcSamples.size(), size_t(5000));
        
        std::vector<double> queueLengths, latencies, lossRates;
        queueLengths.reserve(sampleCount);
        latencies.reserve(sampleCount);
        lossRates.reserve(sampleCount);
        
        for (size_t i = 0; i < sampleCount; ++i) {
            const auto& sample = tcSamples[i];
            if (sample.latency > 0) {
                queueLengths.push_back(static_cast<double>(sample.queueLength));
                latencies.push_back(sample.latency);
                lossRates.push_back(sample.phyLossRate);
            }
        }
        
        if (queueLengths.size() >= 10) {
            result.queueLatencyCorrelation = MathUtils::CalculateCorrelation(queueLengths, latencies);
            result.lossLatencyCorrelation = MathUtils::CalculateCorrelation(lossRates, latencies);
            
            std::stringstream ss;
            if (result.queueLatencyCorrelation > 0.5) ss << "Queue increases latency. ";
            if (result.lossLatencyCorrelation > 0.3) ss << "Loss correlates with latency. ";
            result.interpretation = ss.str();
        }
        
        return result;
    }

public:
    void AddTcpSample(const TcpSample& s) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto& vec = tcpSamples_[s.tc];
        
        if (vec.size() < MAX_SAMPLES_PER_TC) {
            vec.push_back(s);
        } else if (vec.size() % 2 == 0) {
            vec.push_back(s);
            vec.erase(vec.begin() + vec.size() / 2);
        }
    }

    void AddUdpSample(const UdpSample& s) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto& vec = udpSamples_[s.tc];
        
        if (vec.size() < MAX_SAMPLES_PER_TC) {
            vec.push_back(s);
        } else if (vec.size() % 2 == 0) {
            vec.push_back(s);
            vec.erase(vec.begin() + vec.size() / 2);
        }
    }

    std::map<TrafficClass, TcpCorrelationResult> AnalyzeAllTcp() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::map<TrafficClass, TcpCorrelationResult> results;
        
        for (const auto& kv : tcpSamples_) {
            results[kv.first] = AnalyzeTcpTrafficClassUnlocked(kv.first);
        }
        
        return results;
    }

    std::map<TrafficClass, UdpCorrelationResult> AnalyzeAllUdp() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::map<TrafficClass, UdpCorrelationResult> results;
        
        for (const auto& kv : udpSamples_) {
            results[kv.first] = AnalyzeUdpTrafficClassUnlocked(kv.first);
        }
        
        return results;
    }

    void WriteDatFiles(const std::string& prefix) const {
        std::map<TrafficClass, std::vector<TcpSample>> tcpLocalCopy;
        std::map<TrafficClass, std::vector<UdpSample>> udpLocalCopy;
        
        {
            std::lock_guard<std::mutex> lock(mutex_);
            tcpLocalCopy = tcpSamples_;
            udpLocalCopy = udpSamples_;
        }
        
        for (const auto& kv : tcpLocalCopy) {
            auto cfgIt = TRAFFIC_CONFIGS.find(kv.first);
            if (cfgIt == TRAFFIC_CONFIGS.end()) continue;
            
            const auto& cfg = cfgIt->second;
            std::string staPrefix = (cfg.station == STA1) ? "sta1" : "sta2";
            std::string baseFile = prefix + "_" + staPrefix + "_crosslayer_tcp_" + cfg.name + ".dat";
            
            std::ofstream out(baseFile);
            if (out.is_open()) {
                out << "# Time(s) QueueLength RTT(ms) CWND(bytes) PhyLossRate\n";
                size_t writeCount = std::min(kv.second.size(), size_t(50000));
                for (size_t i = 0; i < writeCount; ++i) {
                    const auto& sample = kv.second[i];
                    out << sample.timestamp << " "
                        << sample.queueLength << " "
                        << sample.tcpRtt << " "
                        << sample.cwnd << " "
                        << sample.phyLossRate << "\n";
                }
                out.close();
            }
        }
        
        for (const auto& kv : udpLocalCopy) {
            auto cfgIt = TRAFFIC_CONFIGS.find(kv.first);
            if (cfgIt == TRAFFIC_CONFIGS.end()) continue;
            
            const auto& cfg = cfgIt->second;
            std::string staPrefix = (cfg.station == STA1) ? "sta1" : "sta2";
            std::string baseFile = prefix + "_" + staPrefix + "_crosslayer_udp_" + cfg.name + ".dat";
            
            std::ofstream out(baseFile);
            if (out.is_open()) {
                out << "# Time(s) QueueLength Latency(ms) PhyLossRate\n";
                size_t writeCount = std::min(kv.second.size(), size_t(50000));
                for (size_t i = 0; i < writeCount; ++i) {
                    const auto& sample = kv.second[i];
                    out << sample.timestamp << " "
                        << sample.queueLength << " "
                        << sample.latency << " "
                        << sample.phyLossRate << "\n";
                }
                out.close();
            }
        }
    }
};

// ENHANCED STATISTICS
struct EnhancedLayerStatistics {
    std::atomic<uint64_t> phyTxBegin{0};
    std::atomic<uint64_t> phyTxEnd{0};
    std::atomic<uint64_t> phyRxEnd{0};
    std::atomic<uint64_t> phyRxDrop{0};
    
    std::map<std::string, std::atomic<uint64_t>> phyDropReasons;
    std::mutex dropReasonMutex;
    
    std::atomic<uint64_t> macTxOk{0};
    std::atomic<uint64_t> macRx{0};
    
    std::mutex queueMutex;
    std::map<TrafficClass, std::vector<std::pair<double, uint32_t>>> acQueueSamples;
    std::map<TrafficClass, uint32_t> acMaxQueue;
    std::vector<std::pair<double, uint32_t>> tcQueueSamples;
    uint32_t tcMaxQueue = 0;
    
    static constexpr size_t MAX_QUEUE_SAMPLES = 50000;
    
    void RecordPhyDropReason(const std::string& reason) {
        std::lock_guard<std::mutex> lock(dropReasonMutex);
        phyDropReasons[reason]++;
    }
    
    void RecordAcQueue(TrafficClass tc, double time, uint32_t size) {
        std::lock_guard<std::mutex> lock(queueMutex);
        auto& samples = acQueueSamples[tc];
        if (samples.size() < MAX_QUEUE_SAMPLES) {
            samples.emplace_back(time, size);
            acMaxQueue[tc] = std::max(acMaxQueue[tc], size);
        }
    }
    
    void RecordTcQueue(double time, uint32_t size) {
        std::lock_guard<std::mutex> lock(queueMutex);
        if (tcQueueSamples.size() < MAX_QUEUE_SAMPLES) {
            tcQueueSamples.emplace_back(time, size);
            tcMaxQueue = std::max(tcMaxQueue, size);
        }
    }
    
    double GetRecentPhyLossRate() const {
        uint64_t totalRx = phyRxEnd.load();
        uint64_t drops = phyRxDrop.load();
        if (totalRx + drops == 0) return 0.0;
        return static_cast<double>(drops) / (totalRx + drops);
    }
    
    void WriteDatFiles(const std::string& prefix) const {
        std::map<TrafficClass, std::vector<std::pair<double, uint32_t>>> localAcCopy;
        std::vector<std::pair<double, uint32_t>> localTcCopy;
        
        {
            std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(queueMutex));
            localAcCopy = acQueueSamples;
            localTcCopy = tcQueueSamples;
        }
        
        for (auto tc : {TC_VO, TC_VI, TC_BE, TC_BK}) {
            auto it = localAcCopy.find(tc);
            if (it == localAcCopy.end() || it->second.empty()) continue;
            
            const auto& cfg = TRAFFIC_CONFIGS.at(tc);
            std::string staPrefix = (cfg.station == STA1) ? "sta1" : "sta2";
            std::string filename = prefix + "_" + staPrefix + "_queue_" + cfg.acName + ".dat";
            
            std::ofstream out(filename);
            if (out.is_open()) {
                out << "# Time(s) QueueSize(packets)\n";
                for (const auto& sample : it->second) {
                    out << sample.first << " " << sample.second << "\n";
                }
                out.close();
            }
        }
        
        if (!localTcCopy.empty()) {
            std::ofstream out(prefix + "_tc_queue.dat");
            if (out) {
                out << "# Time(s) QueueSize(packets)\n";
                for (const auto& sample : localTcCopy) {
                    out << sample.first << " " << sample.second << "\n";
                }
                out.close();
            }
        }
    }
};

// CUSTOM TCP RECEIVER
class QosTcpReceiver : public Application {
public:
    static TypeId GetTypeId() {
        static TypeId tid = TypeId("ns3::QosTcpReceiver")
            .SetParent<Application>()
            .SetGroupName("Applications")
            .AddConstructor<QosTcpReceiver>();
        return tid;
    }

    QosTcpReceiver() : m_socket(nullptr), m_tracker(nullptr), m_trafficClass(TC_BE) {}
    virtual ~QosTcpReceiver() { m_socket = nullptr; }

    void Setup(uint16_t port, TcpTracker* tracker, TrafficClass tc) {
        m_port = port;
        m_tracker = tracker;
        m_trafficClass = tc;
    }

protected:
    void StartApplication() override {
        if (!m_socket) {
            m_socket = Socket::CreateSocket(GetNode(), TcpSocketFactory::GetTypeId());
            m_socket->Bind(InetSocketAddress(Ipv4Address::GetAny(), m_port));
            m_socket->Listen();
            m_socket->SetAcceptCallback(
                MakeNullCallback<bool, Ptr<Socket>, const Address&>(),
                MakeCallback(&QosTcpReceiver::HandleAccept, this));
        }
    }

    void StopApplication() override {
        if (m_socket) {
            m_socket->Close();
        }
        for (auto& s : m_acceptedSockets) {
            s->Close();
        }
        m_acceptedSockets.clear();
    }

private:
    void HandleAccept(Ptr<Socket> socket, const Address& from) {
        socket->SetRecvCallback(MakeCallback(&QosTcpReceiver::HandleRead, this));
        m_acceptedSockets.push_back(socket);
    }

    void HandleRead(Ptr<Socket> socket) {
        Ptr<Packet> packet;
        Address from;
        while ((packet = socket->RecvFrom(from))) {
            if (m_tracker && packet->GetSize() > 0) {
                m_tracker->RecordBytesReceived(m_trafficClass, packet->GetSize());
            }
        }
    }

    Ptr<Socket> m_socket;
    std::vector<Ptr<Socket>> m_acceptedSockets;
    uint16_t m_port;
    TcpTracker* m_tracker;
    TrafficClass m_trafficClass;
};

NS_OBJECT_ENSURE_REGISTERED(QosTcpReceiver);

// CUSTOM UDP SENDER
class QosUdpSender : public Application {
public:
    static TypeId GetTypeId() {
        static TypeId tid = TypeId("ns3::QosUdpSender")
            .SetParent<Application>()
            .SetGroupName("Applications")
            .AddConstructor<QosUdpSender>();
        return tid;
    }

    QosUdpSender() : m_socket(nullptr), m_running(false), m_seq(0), m_tracker(nullptr) {}
    virtual ~QosUdpSender() { m_socket = nullptr; }

    void Setup(Ipv4Address destAddr, uint16_t port, uint32_t packetSize,
               Time interval, uint8_t tos, LatencyTracker* tracker, TrafficClass tc) {
        m_destAddr = destAddr;
        m_port = port;
        m_packetSize = packetSize;
        m_interval = interval;
        m_tos = tos;
        m_tracker = tracker;
        m_trafficClass = tc;
    }

protected:
    void StartApplication() override {
        m_running = true;
        m_seq = 0;

        if (!m_socket) {
            m_socket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
            m_socket->Bind();
            m_socket->Connect(InetSocketAddress(m_destAddr, m_port));
            m_socket->SetIpTos(m_tos);
        }
        
        SendPacket();
    }

    void StopApplication() override {
        m_running = false;
        if (m_sendEvent.IsPending()) {
            Simulator::Cancel(m_sendEvent);
        }
        if (m_socket) {
            m_socket->Close();
        }
    }

private:
    void SendPacket() {
        if (!m_running) return;

        SeqTsHeader seqTs;
        seqTs.SetSeq(m_seq);
        
        Ptr<Packet> packet = Create<Packet>(m_packetSize - seqTs.GetSerializedSize());
        packet->AddHeader(seqTs);
        
        m_socket->Send(packet);
        
        if (m_tracker) {
            m_tracker->RecordSend(m_trafficClass, packet->GetSize());
        }
        
        m_seq++;
        m_sendEvent = Simulator::Schedule(m_interval, &QosUdpSender::SendPacket, this);
    }

    Ptr<Socket> m_socket;
    Ipv4Address m_destAddr;
    uint16_t m_port;
    uint32_t m_packetSize;
    Time m_interval;
    uint8_t m_tos;
    bool m_running;
    uint32_t m_seq;
    EventId m_sendEvent;
    LatencyTracker* m_tracker;
    TrafficClass m_trafficClass;
};

NS_OBJECT_ENSURE_REGISTERED(QosUdpSender);

// CUSTOM UDP RECEIVER
class QosUdpReceiver : public Application {
public:
    static TypeId GetTypeId() {
        static TypeId tid = TypeId("ns3::QosUdpReceiver")
            .SetParent<Application>()
            .SetGroupName("Applications")
            .AddConstructor<QosUdpReceiver>();
        return tid;
    }

    QosUdpReceiver() : m_socket(nullptr), m_tracker(nullptr), m_trafficClass(TC_BE) {}
    virtual ~QosUdpReceiver() { m_socket = nullptr; }

    void Setup(uint16_t port, LatencyTracker* tracker, TrafficClass tc) {
        m_port = port;
        m_tracker = tracker;
        m_trafficClass = tc;
    }

protected:
    void StartApplication() override {
        if (!m_socket) {
            m_socket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
            m_socket->Bind(InetSocketAddress(Ipv4Address::GetAny(), m_port));
            m_socket->SetRecvCallback(MakeCallback(&QosUdpReceiver::HandleRead, this));
        }
    }

    void StopApplication() override {
        if (m_socket) {
            m_socket->Close();
            m_socket->SetRecvCallback(MakeNullCallback<void, Ptr<Socket>>());
        }
    }

private:
    void HandleRead(Ptr<Socket> socket) {
        Ptr<Packet> packet;
        Address from;

        while ((packet = socket->RecvFrom(from))) {
            SeqTsHeader seqTs;
            packet->RemoveHeader(seqTs);
            
            if (m_tracker) {
                double latencyMs = (Simulator::Now() - seqTs.GetTs()).GetMicroSeconds() / 1000.0;
                m_tracker->RecordReceive(m_trafficClass, latencyMs, 
                                         packet->GetSize() + seqTs.GetSerializedSize(),
                                         Simulator::Now().GetSeconds());
            }
        }
    }

    Ptr<Socket> m_socket;
    uint16_t m_port;
    LatencyTracker* m_tracker;
    TrafficClass m_trafficClass;
};

NS_OBJECT_ENSURE_REGISTERED(QosUdpReceiver);

// CUSTOM TCP SENDER
class QosTcpSender : public Application {
public:
    static TypeId GetTypeId() {
        static TypeId tid = TypeId("ns3::QosTcpSender")
            .SetParent<Application>()
            .SetGroupName("Applications")
            .AddConstructor<QosTcpSender>();
        return tid;
    }

    QosTcpSender() : m_socket(nullptr), m_connected(false), m_totBytes(0), m_tracker(nullptr), 
                     m_trafficClass(TC_BE), m_dataRate("1Mbps") {}
    virtual ~QosTcpSender() { m_socket = nullptr; }

    void Setup(Ipv4Address destAddr, uint16_t port, uint32_t sendSize,
               uint8_t tos, TcpTracker* tracker, TrafficClass tc, const std::string& dataRate) {
        m_destAddr = destAddr;
        m_port = port;
        m_sendSize = sendSize;
        m_tos = tos;
        m_tracker = tracker;
        m_trafficClass = tc;
        m_dataRate = dataRate;
    }

protected:
    void StartApplication() override {
        m_socket = Socket::CreateSocket(GetNode(), TcpSocketFactory::GetTypeId());
        m_socket->SetIpTos(m_tos);
        m_socket->Bind();
        m_socket->Connect(InetSocketAddress(m_destAddr, m_port));

        m_socket->SetConnectCallback(
            MakeCallback(&QosTcpSender::ConnectionSucceeded, this),
            MakeCallback(&QosTcpSender::ConnectionFailed, this));
        
        m_socket->TraceConnectWithoutContext("CongestionWindow",
            MakeCallback(&QosTcpSender::CwndChange, this));
        m_socket->TraceConnectWithoutContext("RTT",
            MakeCallback(&QosTcpSender::RttChange, this));
        
        Simulator::Schedule(Seconds(0.1), &QosTcpSender::StartSending, this);
    }

    void StopApplication() override {
        m_running = false;
        if (m_socket) {
            m_socket->Close();
        }
    }

private:
    void ConnectionSucceeded(Ptr<Socket> socket) {
        m_connected = true;
    }

    void ConnectionFailed(Ptr<Socket> socket) {
        m_connected = false;
    }

    void StartSending() {
        if (!m_connected) {
            Simulator::Schedule(Seconds(0.5), &QosTcpSender::StartSending, this);
            return;
        }
        
        SendData();
    }

    void SendData() {
        if (!m_connected || !m_running) return;
        
        if (m_socket->GetTxAvailable() > 0) {
            uint32_t toSend = std::min(m_sendSize, m_socket->GetTxAvailable());
            Ptr<Packet> packet = Create<Packet>(toSend);
            
            int actual = m_socket->Send(packet);
            if (actual > 0) {
                m_totBytes += actual;
                if (m_tracker) {
                    m_tracker->RecordBytesSent(m_trafficClass, actual);
                }
            }
        }
        
        DataRate rate(m_dataRate);
        double intervalMs = (m_sendSize * 8 * 1000.0) / rate.GetBitRate();
        
        Simulator::Schedule(MilliSeconds(intervalMs), &QosTcpSender::SendData, this);
    }

    void CwndChange(uint32_t oldCwnd, uint32_t newCwnd) {
        if (m_tracker) {
            m_tracker->RecordCwnd(m_trafficClass, Simulator::Now().GetSeconds(), newCwnd);
            
            if (newCwnd < oldCwnd / 2 && oldCwnd > 0) {
                m_tracker->RecordRetransmission(m_trafficClass);
            }
        }
    }

    void RttChange(Time oldRtt, Time newRtt) {
        if (m_tracker) {
            m_tracker->RecordRtt(m_trafficClass, Simulator::Now().GetSeconds(), 
                                newRtt.GetMicroSeconds() / 1000.0);
        }
    }

    Ptr<Socket> m_socket;
    Ipv4Address m_destAddr;
    uint16_t m_port;
    uint32_t m_sendSize;
    uint8_t m_tos;
    bool m_connected;
    bool m_running = true;
    uint64_t m_totBytes;
    TcpTracker* m_tracker;
    TrafficClass m_trafficClass;
    std::string m_dataRate;
};

NS_OBJECT_ENSURE_REGISTERED(QosTcpSender);

// MAIN SIMULATION CLASS
class WiFiCrossLayerQoSSim {
private:
    struct SimConfig {
        double simulationTime = 300.0;
        double warmupTime = 10.0;
        bool enableQos = true;
        
        double txPower = 20.0;
        double noiseFigure = 7.0;
        
        std::string errorRateModel = "Nist";
        
        std::string tcpVariant = "TcpBbr";
        uint32_t tcpSegmentSize = 1448;
        
        uint32_t wifiMacQueueSize = 600;
        uint32_t apQueueSize = 200;
        
        double sta1Distance = 15.0;
        double sta2Distance = 25.0;
        
        double pathLossExponent = 3.0;
        
        bool enableMobility = true;  
        double mobilitySpeed = 3;
        double mobilityDistance = 10.0;
        double mobilityBoundsX = 50.0;
        double mobilityBoundsY = 50.0;
        
        double monitorIntervalMs = 100.0;
        double crossLayerSampleIntervalMs = 500.0;
        double throughputSampleIntervalSec = 1.0;
        
        std::string outputPrefix = "qos_analysis";
        double progressInterval = 10.0;
    };

    SimConfig cfg_;
    EnhancedLayerStatistics layerStats_;
    LatencyTracker latencyTracker_;
    TcpTracker tcpTracker_;
    CrossLayerAnalyzer crossLayerAnalyzer_;

    NodeContainer wifiApNode_;
    NodeContainer wifiStaNodes_;
    NodeContainer serverNode_;

    NetDeviceContainer apDevices_;
    NetDeviceContainer staDevices_;

    Ipv4InterfaceContainer staInterfaces_;

    Ptr<WifiNetDevice> apWifiDevice_;
    Ptr<RateErrorModel> errorModel_;

    Ptr<FlowMonitor> flowMonitor_;
    FlowMonitorHelper flowHelper_;

    std::vector<Ptr<QosUdpSender>> udpSenders_;
    std::vector<Ptr<QosUdpReceiver>> udpReceivers_;
    std::vector<Ptr<QosTcpSender>> tcpSenders_;

    bool simulationRunning_ = false;

public:
    WiFiCrossLayerQoSSim() = default;

    void Configure(int argc, char* argv[]) {
        CommandLine cmd;
        
        cmd.AddValue("simTime", "Simulation time (s)", cfg_.simulationTime);
        cmd.AddValue("warmupTime", "Warmup time (s)", cfg_.warmupTime);
        cmd.AddValue("tcpVariant", "TCP variant", cfg_.tcpVariant);
        cmd.AddValue("errorRateModel", "Error rate model (Nist/Yans/Table)", cfg_.errorRateModel);
        
        // **NEW: Mobility parameters**
        cmd.AddValue("enableMobility", "Enable STA mobility (true/false)", cfg_.enableMobility);
        cmd.AddValue("mobilitySpeed", "STA mobility speed (m/s)", cfg_.mobilitySpeed);
        
        cmd.AddValue("sta1Distance", "STA1 initial distance from AP (m)", cfg_.sta1Distance);
        cmd.AddValue("sta2Distance", "STA2 initial distance from AP (m)", cfg_.sta2Distance);
        cmd.AddValue("outputPrefix", "Output file prefix", cfg_.outputPrefix);
        
        cmd.Parse(argc, argv);
        
        Config::SetDefault("ns3::TcpL4Protocol::SocketType", 
                          StringValue("ns3::" + cfg_.tcpVariant));
        Config::SetDefault("ns3::TcpSocket::SegmentSize", 
                          UintegerValue(cfg_.tcpSegmentSize));
        Config::SetDefault("ns3::TcpSocket::InitialCwnd", UintegerValue(10));
        Config::SetDefault("ns3::TcpSocket::SndBufSize", UintegerValue(256 * 1024));
        Config::SetDefault("ns3::TcpSocket::RcvBufSize", UintegerValue(256 * 1024));
        
        Config::SetDefault("ns3::WifiMacQueue::MaxSize", 
                          QueueSizeValue(QueueSize(QueueSizeUnit::PACKETS, 
                                                   cfg_.wifiMacQueueSize)));
    }

    void Run() {
        std::cout << "  QoS Cross-Layer Analysis \n";
        
        std::cout << "\n[1/5] Creating topology...\n";
        CreateTopology();
        
        std::cout << "\n[2/5] Setting up traffic flows...\n";
        SetupTraffic();
        
        std::cout << "\n[3/5] Setting up traces...\n";
        SetupTraces();
        
        std::cout << "\n[4/5] Setting up monitoring...\n";
        SetupMonitoring();
        
        PrintConfiguration();
        
        std::cout << "\n>>> Starting simulation...\n";
        
        simulationRunning_ = true;
        ScheduleProgressReport();
        
        Simulator::Stop(Seconds(cfg_.simulationTime + cfg_.warmupTime + 2.0));
        Simulator::Run();
        
        std::cout << "\n>>> Simulation completed.\n";
        simulationRunning_ = false;
        
        AnalyzeResults();
        WriteOutputs();
        
        Simulator::Destroy();
    }

private:
    void CreateTopology() {
        wifiApNode_.Create(1);
    	wifiStaNodes_.Create(2);
    	serverNode_.Create(2);

    	MobilityHelper mobility;
    
    // AP position (static at origin)
    	Ptr<ListPositionAllocator> apPosAlloc = CreateObject<ListPositionAllocator>();
    	apPosAlloc->Add(Vector(0.0, 0.0, 1.5));
    	mobility.SetPositionAllocator(apPosAlloc);
    	mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    	mobility.Install(wifiApNode_);
    
    // **FIXED: STA positions with proper bounds checking**
    	Ptr<ListPositionAllocator> staPosAlloc = CreateObject<ListPositionAllocator>();
    	staPosAlloc->Add(Vector(cfg_.sta1Distance, 0.0, 1.5));
    	staPosAlloc->Add(Vector(cfg_.sta2Distance, 0.0, 1.5));
    	mobility.SetPositionAllocator(staPosAlloc);
    
    	if (cfg_.enableMobility) {
        // Ensure bounds contain initial positions + mobility range
            double maxDist = std::max(std::abs(cfg_.sta1Distance), std::abs(cfg_.sta2Distance));
            double boundX = std::max(cfg_.mobilityBoundsX, (maxDist + cfg_.mobilityDistance) * 2.0);
            double boundY = std::max(cfg_.mobilityBoundsY, cfg_.mobilityDistance * 2.0);
        
            mobility.SetMobilityModel("ns3::RandomWalk2dMobilityModel",
                                 "Bounds", RectangleValue(Rectangle(-boundX/2, boundX/2,
                                                                    -boundY/2, boundY/2)),
                                 "Speed", StringValue("ns3::ConstantRandomVariable[Constant=" + 
                                                     std::to_string(cfg_.mobilitySpeed) + "]"),
                                 "Distance", DoubleValue(cfg_.mobilityDistance));
            std::cout << "  STA Mobility: ENABLED (RandomWalk2d @ " << cfg_.mobilitySpeed 
                  << " m/s, bounds: ±" << boundX/2 << "m x ±" << boundY/2 << "m)\n";
        } else {
            mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
            std::cout << "  STA Mobility: DISABLED (Static positions)\n";
        }
        mobility.Install(wifiStaNodes_);
    
    // Server positions (static)
    	Ptr<ListPositionAllocator> serverPosAlloc = CreateObject<ListPositionAllocator>();
    	serverPosAlloc->Add(Vector(-50.0, 0.0, 1.5));
    	serverPosAlloc->Add(Vector(-100.0, 0.0, 1.5));
    	mobility.SetPositionAllocator(serverPosAlloc);
    	mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    	mobility.Install(serverNode_);
        
        // WiFi setup for 802.11ac at 5 GHz with MinstrelHT
        WifiHelper wifi;
        wifi.SetStandard(WIFI_STANDARD_80211ac);
        wifi.SetRemoteStationManager("ns3::MinstrelHtWifiManager");
        
        YansWifiChannelHelper channel;
        channel.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");
        channel.AddPropagationLoss("ns3::LogDistancePropagationLossModel",
                                   "Exponent", DoubleValue(cfg_.pathLossExponent),
                                   "ReferenceLoss", DoubleValue(46.67));
        
        YansWifiPhyHelper phy;
        phy.SetChannel(channel.Create());
        phy.Set("ChannelSettings", StringValue("{42, 80, BAND_5GHZ, 0}"));
        phy.Set("TxPowerStart", DoubleValue(cfg_.txPower));
        phy.Set("TxPowerEnd", DoubleValue(cfg_.txPower));
        phy.Set("RxNoiseFigure", DoubleValue(cfg_.noiseFigure));
        
        if (cfg_.errorRateModel == "Nist") {
            phy.SetErrorRateModel("ns3::NistErrorRateModel");
        } else if (cfg_.errorRateModel == "Yans") {
            phy.SetErrorRateModel("ns3::YansErrorRateModel");
        } else if (cfg_.errorRateModel == "Table") {
            phy.SetErrorRateModel("ns3::TableBasedErrorRateModel");
        } else {
            phy.SetErrorRateModel("ns3::NistErrorRateModel");
        }
        
        WifiMacHelper mac;
        Ssid ssid = Ssid("qos-test");
        
        mac.SetType("ns3::ApWifiMac",
                    "Ssid", SsidValue(ssid),
                    "QosSupported", BooleanValue(cfg_.enableQos));
        apDevices_ = wifi.Install(phy, mac, wifiApNode_);
        apWifiDevice_ = DynamicCast<WifiNetDevice>(apDevices_.Get(0));
        
        mac.SetType("ns3::StaWifiMac",
                    "Ssid", SsidValue(ssid),
                    "QosSupported", BooleanValue(cfg_.enableQos),
                    "ActiveProbing", BooleanValue(false));
        staDevices_ = wifi.Install(phy, mac, wifiStaNodes_);
        
        InternetStackHelper stack;
        stack.Install(wifiApNode_);
        stack.Install(wifiStaNodes_);
        stack.Install(serverNode_);
        
        PointToPointHelper p2p;
        p2p.SetDeviceAttribute("DataRate", StringValue("1Gbps"));
        p2p.SetChannelAttribute("Delay", StringValue("2ms"));
        
        NetDeviceContainer server1ApDevices = p2p.Install(serverNode_.Get(0), wifiApNode_.Get(0));
        NetDeviceContainer server2ApDevices = p2p.Install(serverNode_.Get(1), wifiApNode_.Get(0));
        
        Ipv4AddressHelper address;
        
        address.SetBase("10.1.1.0", "255.255.255.0");
        address.Assign(server1ApDevices);
        
        address.SetBase("10.1.2.0", "255.255.255.0");
        address.Assign(server2ApDevices);
        
        address.SetBase("192.168.1.0", "255.255.255.0");
        NetDeviceContainer allWifiDevices;
        allWifiDevices.Add(apDevices_);
        allWifiDevices.Add(staDevices_);
        Ipv4InterfaceContainer wifiIfaces = address.Assign(allWifiDevices);
        
        staInterfaces_.Add(wifiIfaces.Get(1));
        staInterfaces_.Add(wifiIfaces.Get(2));
        
        TrafficControlHelper tch;
        tch.Uninstall(apDevices_);
        tch.SetRootQueueDisc("ns3::FqCoDelQueueDisc", 
                             "MaxSize", StringValue(std::to_string(cfg_.apQueueSize) + "p"),
                             "Target", StringValue("5ms"),
                             "Interval", StringValue("50ms"));
        tch.Install(apDevices_);
        
        Ipv4GlobalRoutingHelper::PopulateRoutingTables();
        flowMonitor_ = flowHelper_.InstallAll();
        
        std::cout << "  802.11ac 5GHz (80 MHz) with MinstrelHT rate control (MCS 0-9)\n";
        std::cout << "  Error Rate Model: " << cfg_.errorRateModel << "\n";
        std::cout << "  STA1: " << staInterfaces_.GetAddress(0) 
                  << " @ (" << cfg_.sta1Distance << "m, 0m)\n";
        std::cout << "  STA2: " << staInterfaces_.GetAddress(1) 
                  << " @ (" << cfg_.sta2Distance << "m, 0m)\n";
    }

    void SetupTraffic() {
        double startTime = cfg_.warmupTime;
        
        // STA1: UDP Voice
        {
            uint16_t port = 5001;
            const TrafficConfig& cfg = TRAFFIC_CONFIGS.at(TC_VO);
            
            Ptr<QosUdpReceiver> receiver = CreateObject<QosUdpReceiver>();
            receiver->Setup(port, &latencyTracker_, TC_VO);
            wifiStaNodes_.Get(0)->AddApplication(receiver);
            receiver->SetStartTime(Seconds(startTime - 0.5));
            receiver->SetStopTime(Seconds(cfg_.simulationTime + cfg_.warmupTime + 1.0));
            udpReceivers_.push_back(receiver);
            
            Ptr<QosUdpSender> sender = CreateObject<QosUdpSender>();
            Time interval = Seconds(cfg.defaultIntervalMs / 1000.0);
            sender->Setup(staInterfaces_.GetAddress(0), port, cfg.defaultPacketSize, 
                         interval, cfg.tos, &latencyTracker_, TC_VO);
            serverNode_.Get(0)->AddApplication(sender);
            sender->SetStartTime(Seconds(startTime));
            sender->SetStopTime(Seconds(cfg_.simulationTime + cfg_.warmupTime));
            udpSenders_.push_back(sender);
            
            std::cout << "  STA1 UDP VO (Voice)\n";
        }
        
        // STA1: TCP Best Effort
        {
            uint16_t port = 5002;
            const TrafficConfig& cfg = TRAFFIC_CONFIGS.at(TC_BE);
            
            Ptr<QosTcpReceiver> receiver = CreateObject<QosTcpReceiver>();
            receiver->Setup(port, &tcpTracker_, TC_BE);
            wifiStaNodes_.Get(0)->AddApplication(receiver);
            receiver->SetStartTime(Seconds(startTime - 0.5));
            receiver->SetStopTime(Seconds(cfg_.simulationTime + cfg_.warmupTime + 1.0));
            
            Ptr<QosTcpSender> sender = CreateObject<QosTcpSender>();
            sender->Setup(staInterfaces_.GetAddress(0), port, cfg_.tcpSegmentSize,
                         cfg.tos, &tcpTracker_, TC_BE, "10Mbps");
            serverNode_.Get(0)->AddApplication(sender);
            sender->SetStartTime(Seconds(startTime + 0.5));
            sender->SetStopTime(Seconds(cfg_.simulationTime + cfg_.warmupTime - 1.0));
            tcpSenders_.push_back(sender);
            
            std::cout << "  STA1 TCP BE\n";
        }
        
        // STA2: UDP Video
        {
            uint16_t port = 6001;
            const TrafficConfig& cfg = TRAFFIC_CONFIGS.at(TC_VI);
            
            Ptr<QosUdpReceiver> receiver = CreateObject<QosUdpReceiver>();
            receiver->Setup(port, &latencyTracker_, TC_VI);
            wifiStaNodes_.Get(1)->AddApplication(receiver);
            receiver->SetStartTime(Seconds(startTime - 0.5));
            receiver->SetStopTime(Seconds(cfg_.simulationTime + cfg_.warmupTime + 1.0));
            udpReceivers_.push_back(receiver);
            
            Ptr<QosUdpSender> sender = CreateObject<QosUdpSender>();
            Time interval = Seconds(cfg.defaultIntervalMs / 1000.0);
            sender->Setup(staInterfaces_.GetAddress(1), port, cfg.defaultPacketSize,
                         interval, cfg.tos, &latencyTracker_, TC_VI);
            serverNode_.Get(1)->AddApplication(sender);
            sender->SetStartTime(Seconds(startTime));
            sender->SetStopTime(Seconds(cfg_.simulationTime + cfg_.warmupTime));
            udpSenders_.push_back(sender);
            
            std::cout << "  STA2 UDP VI (Video)\n";
        }
        
        // STA2: TCP Background
        {
            uint16_t port = 6002;
            const TrafficConfig& cfg = TRAFFIC_CONFIGS.at(TC_BK);
            
            Ptr<QosTcpReceiver> receiver = CreateObject<QosTcpReceiver>();
            receiver->Setup(port, &tcpTracker_, TC_BK);
            wifiStaNodes_.Get(1)->AddApplication(receiver);
            receiver->SetStartTime(Seconds(startTime - 0.5));
            receiver->SetStopTime(Seconds(cfg_.simulationTime + cfg_.warmupTime + 1.0));
            
            Ptr<QosTcpSender> sender = CreateObject<QosTcpSender>();
            sender->Setup(staInterfaces_.GetAddress(1), port, cfg_.tcpSegmentSize,
                         cfg.tos, &tcpTracker_, TC_BK, "10Mbps");
            serverNode_.Get(1)->AddApplication(sender);
            sender->SetStartTime(Seconds(startTime + 0.5));
            sender->SetStopTime(Seconds(cfg_.simulationTime + cfg_.warmupTime - 1.0));
            tcpSenders_.push_back(sender);
            
            std::cout << "  STA2 TCP BK\n";
        }
    }

    void SetupTraces() {
        if (!apWifiDevice_) return;

        uint32_t apNodeId = wifiApNode_.Get(0)->GetId();

        std::ostringstream phyTxBeginPath, phyTxEndPath, phyRxEndPath, phyDropPath;
        phyTxBeginPath << "/NodeList/" << apNodeId << "/DeviceList/*/$ns3::WifiNetDevice/Phy/PhyTxBegin";
        phyTxEndPath << "/NodeList/" << apNodeId << "/DeviceList/*/$ns3::WifiNetDevice/Phy/PhyTxEnd";
        phyRxEndPath << "/NodeList/" << apNodeId << "/DeviceList/*/$ns3::WifiNetDevice/Phy/PhyRxEnd";
        phyDropPath << "/NodeList/" << apNodeId << "/DeviceList/*/$ns3::WifiNetDevice/Phy/PhyRxDrop";
        
        Config::Connect(phyTxBeginPath.str(), MakeCallback(&WiFiCrossLayerQoSSim::OnPhyTxBegin, this));
        Config::Connect(phyTxEndPath.str(), MakeCallback(&WiFiCrossLayerQoSSim::OnPhyTxEnd, this));
        Config::Connect(phyRxEndPath.str(), MakeCallback(&WiFiCrossLayerQoSSim::OnPhyRxEnd, this));
        Config::Connect(phyDropPath.str(), MakeCallback(&WiFiCrossLayerQoSSim::OnPhyRxDrop, this));
        
        Ptr<WifiMac> mac = apWifiDevice_->GetMac();
        if (mac) {
            mac->TraceConnectWithoutContext("MacTx", MakeCallback(&WiFiCrossLayerQoSSim::OnMacTx, this));
            mac->TraceConnectWithoutContext("MacRx", MakeCallback(&WiFiCrossLayerQoSSim::OnMacRx, this));
        }
        
        std::cout << "  PHY/MAC traces configured\n";
    }

    void OnPhyTxBegin(std::string context, Ptr<const Packet> pkt, double txPower) {
        layerStats_.phyTxBegin++;
    }

    void OnPhyTxEnd(std::string context, Ptr<const Packet> pkt) {
        layerStats_.phyTxEnd++;
    }

    void OnPhyRxEnd(std::string context, Ptr<const Packet> pkt) {
        layerStats_.phyRxEnd++;
    }

    void OnPhyRxDrop(std::string context, Ptr<const Packet> pkt, WifiPhyRxfailureReason reason) {
        layerStats_.phyRxDrop++;
        layerStats_.RecordPhyDropReason("DROP_" + std::to_string(static_cast<int>(reason)));
    }

    void OnMacTx(Ptr<const Packet> pkt) {
        layerStats_.macTxOk++;
    }

    void OnMacRx(Ptr<const Packet> pkt) {
        layerStats_.macRx++;
    }

    void SetupMonitoring() {
        Simulator::Schedule(Seconds(cfg_.warmupTime), 
                           &WiFiCrossLayerQoSSim::SampleQueues, this);
        Simulator::Schedule(Seconds(cfg_.warmupTime), 
                           &WiFiCrossLayerQoSSim::SampleCrossLayerData, this);
        Simulator::Schedule(Seconds(cfg_.warmupTime), 
                           &WiFiCrossLayerQoSSim::SampleThroughput, this);
    }

    void SampleQueues() {
        double now = Simulator::Now().GetSeconds();
        
        if (now >= cfg_.simulationTime + cfg_.warmupTime - 0.5 || !simulationRunning_) {
            return;
        }
        
        Ptr<TrafficControlLayer> tc = wifiApNode_.Get(0)->GetObject<TrafficControlLayer>();
        if (tc) {
            Ptr<QueueDisc> qdisc = tc->GetRootQueueDiscOnDevice(apDevices_.Get(0));
            if (qdisc) {
                layerStats_.RecordTcQueue(now, qdisc->GetCurrentSize().GetValue());
            }
        }
        
        if (apWifiDevice_) {
            Ptr<WifiMac> mac = apWifiDevice_->GetMac();
            if (mac) {
                for (auto ac : {AC_VO, AC_VI, AC_BE, AC_BK}) {
                    Ptr<QosTxop> txop = mac->GetQosTxop(ac);
                    if (txop) {
                        Ptr<WifiMacQueue> wmq = txop->GetWifiMacQueue();
                        if (wmq) {
                            TrafficClass tc;
                            switch (ac) {
                                case AC_VO: tc = TC_VO; break;
                                case AC_VI: tc = TC_VI; break;
                                case AC_BE: tc = TC_BE; break;
                                case AC_BK: tc = TC_BK; break;
                                default: tc = TC_BE;
                            }
                            layerStats_.RecordAcQueue(tc, now, wmq->GetNPackets());
                        }
                    }
                }
            }
        }
        
        if (now < cfg_.simulationTime + cfg_.warmupTime - cfg_.monitorIntervalMs / 1000.0) {
            Simulator::Schedule(MilliSeconds(cfg_.monitorIntervalMs), 
                               &WiFiCrossLayerQoSSim::SampleQueues, this);
        }
    }

    void SampleCrossLayerData() {
        double now = Simulator::Now().GetSeconds();
        
        if (now >= cfg_.simulationTime + cfg_.warmupTime - 0.5 || !simulationRunning_) {
            return;
        }
        
        for (auto tc : {TC_BE, TC_BK}) {
            auto tcpStats = tcpTracker_.GetStats(tc);
            
            if (!tcpStats.rttSamples.empty() && !tcpStats.cwndSamples.empty()) {
                CrossLayerAnalyzer::TcpSample sample;
                sample.timestamp = now;
                sample.tc = tc;
                sample.station = TRAFFIC_CONFIGS.at(tc).station;
                
                auto queueIt = layerStats_.acQueueSamples.find(tc);
                if (queueIt != layerStats_.acQueueSamples.end() && !queueIt->second.empty()) {
                    sample.queueLength = queueIt->second.back().second;
                }
                
                sample.tcpRtt = tcpStats.lastRtt;
                sample.cwnd = tcpStats.lastCwnd;
                sample.phyLossRate = layerStats_.GetRecentPhyLossRate();
                
                crossLayerAnalyzer_.AddTcpSample(sample);
            }
        }
        
        for (auto tc : {TC_VO, TC_VI}) {
            auto udpStats = latencyTracker_.GetStats(tc);
            
            if (!udpStats.timeSeries.empty()) {
                CrossLayerAnalyzer::UdpSample sample;
                sample.timestamp = now;
                sample.tc = tc;
                sample.station = TRAFFIC_CONFIGS.at(tc).station;
                
                auto queueIt = layerStats_.acQueueSamples.find(tc);
                if (queueIt != layerStats_.acQueueSamples.end() && !queueIt->second.empty()) {
                    sample.queueLength = queueIt->second.back().second;
                }
                
                sample.latency = udpStats.lastLatency > 0 ? udpStats.lastLatency : 0;
                sample.phyLossRate = layerStats_.GetRecentPhyLossRate();
                
                crossLayerAnalyzer_.AddUdpSample(sample);
            }
        }
        
        if (now < cfg_.simulationTime + cfg_.warmupTime - cfg_.crossLayerSampleIntervalMs / 1000.0) {
            Simulator::Schedule(MilliSeconds(cfg_.crossLayerSampleIntervalMs), 
                               &WiFiCrossLayerQoSSim::SampleCrossLayerData, this);
        }
    }

    void SampleThroughput() {
        double now = Simulator::Now().GetSeconds();
        
        if (now >= cfg_.simulationTime + cfg_.warmupTime - 0.5 || !simulationRunning_) {
            return;
        }
        
        for (auto tc : {TC_BE, TC_BK}) {
            tcpTracker_.SampleThroughput(tc, now, cfg_.throughputSampleIntervalSec);
        }
        
        if (now < cfg_.simulationTime + cfg_.warmupTime - cfg_.throughputSampleIntervalSec) {
            Simulator::Schedule(Seconds(cfg_.throughputSampleIntervalSec), 
                               &WiFiCrossLayerQoSSim::SampleThroughput, this);
        }
    }

    void ScheduleProgressReport() {
        Simulator::Schedule(Seconds(cfg_.progressInterval), 
                           &WiFiCrossLayerQoSSim::ReportProgress, this);
    }

    void ReportProgress() {
        double now = Simulator::Now().GetSeconds();
        double endTime = cfg_.simulationTime + cfg_.warmupTime;
        
        if (now >= endTime - 0.5 || !simulationRunning_) {
            return;
        }
        
        double progress = ((now - cfg_.warmupTime) / cfg_.simulationTime) * 100.0;
        if (progress < 0) progress = 0;
        if (progress > 100) progress = 100;
        
        std::cout << "  Progress: " << std::fixed << std::setprecision(1) 
                  << progress << "% (t=" << now << "s)\n";
        
        Simulator::Schedule(Seconds(cfg_.progressInterval), 
                           &WiFiCrossLayerQoSSim::ReportProgress, this);
    }

    void PrintConfiguration() {
        std::cout << "\n" << std::string(50, '-') << "\n";
        std::cout << "CONFIGURATION\n";
        std::cout << std::string(50, '-') << "\n";
        std::cout << "Duration:         " << cfg_.simulationTime << "s\n";
        std::cout << "WiFi Standard:    802.11ac (5 GHz, 80 MHz)\n";
        std::cout << "Rate Control:     MinstrelHT (MCS 0-9)\n";
        std::cout << "Error Model:      " << cfg_.errorRateModel << "\n";
        std::cout << "TCP Variant:      " << cfg_.tcpVariant << "\n";
        
        // **NEW: Conditional mobility info**
        if (cfg_.enableMobility) {
            std::cout << "STA Mobility:     RandomWalk2d (" << cfg_.mobilitySpeed << " m/s)\n";
        } else {
            std::cout << "STA Mobility:     Static (disabled)\n";
            std::cout << "STA1 Position:    (" << cfg_.sta1Distance << "m, 0m, 1.5m)\n";
            std::cout << "STA2 Position:    (" << cfg_.sta2Distance << "m, 0m, 1.5m)\n";
        }
        
        std::cout << "Output:           " << cfg_.outputPrefix << "_*.dat\n";
        std::cout << std::string(50, '-') << "\n";
    }

    void AnalyzeResults() {
        double effectiveDuration = cfg_.simulationTime;
        
        latencyTracker_.Calculate();
        tcpTracker_.CalculateBDP(effectiveDuration);
        
        std::cout << "  RESULTS SUMMARY\n";
        
        latencyTracker_.Print();
        tcpTracker_.Print(effectiveDuration);
        
        std::cout << "\nCROSS-LAYER CORRELATION\n";
        
        auto tcpCorrelations = crossLayerAnalyzer_.AnalyzeAllTcp();
        for (auto tc : {TC_BE, TC_BK}) {
            auto corr = tcpCorrelations[tc];
            const auto& cfg = TRAFFIC_CONFIGS.at(tc);
            std::string staName = (cfg.station == STA1) ? "STA1" : "STA2";
            
            std::cout << "\n" << staName << " - " << cfg.name << " (TCP):\n";
            std::cout << "  Queue-RTT: " << std::fixed << std::setprecision(3) 
                      << corr.queueRttCorrelation << " (" 
                      << MathUtils::InterpretCorrelation(corr.queueRttCorrelation) << ")\n";
            std::cout << "  Loss-CWND: " << corr.lossCwndCorrelation << " (" 
                      << MathUtils::InterpretCorrelation(corr.lossCwndCorrelation) << ")\n";
        }
        
        auto udpCorrelations = crossLayerAnalyzer_.AnalyzeAllUdp();
        for (auto tc : {TC_VO, TC_VI}) {
            auto corr = udpCorrelations[tc];
            const auto& cfg = TRAFFIC_CONFIGS.at(tc);
            std::string staName = (cfg.station == STA1) ? "STA1" : "STA2";
            
            std::cout << "\n" << staName << " - " << cfg.name << " (UDP):\n";
            std::cout << "  Queue-Latency: " << std::fixed << std::setprecision(3) 
                      << corr.queueLatencyCorrelation << " (" 
                      << MathUtils::InterpretCorrelation(corr.queueLatencyCorrelation) << ")\n";
            std::cout << "  Loss-Latency: " << corr.lossLatencyCorrelation << " (" 
                      << MathUtils::InterpretCorrelation(corr.lossLatencyCorrelation) << ")\n";
        }
        
        std::cout << "\n=== PHY STATISTICS ===\n";
        std::cout << "  TX Attempts:    " << layerStats_.phyTxBegin.load() << "\n";
        std::cout << "  TX Success:     " << layerStats_.phyTxEnd.load() << "\n";
        std::cout << "  RX Success:     " << layerStats_.phyRxEnd.load() << "\n";
        std::cout << "  RX Drops:       " << layerStats_.phyRxDrop.load() << "\n";
        
        uint64_t totalRx = layerStats_.phyRxEnd.load() + layerStats_.phyRxDrop.load();
        if (totalRx > 0) {
            double phyLoss = 100.0 * layerStats_.phyRxDrop.load() / totalRx;
            std::cout << "  PHY Loss Rate:  " << std::fixed << std::setprecision(2) 
                      << phyLoss << "%\n";
        }
    }

    void WriteOutputs() {
        std::string prefix = cfg_.outputPrefix;
        
        std::cout << "\n=== WRITING .DAT FILES ===\n";
        
        tcpTracker_.WriteDatFiles(prefix);
        std::cout << "  TCP data written (per STA)\n";
        
        latencyTracker_.WriteDatFiles(prefix);
        std::cout << "  UDP latency data written (per STA)\n";
        
        crossLayerAnalyzer_.WriteDatFiles(prefix);
        std::cout << "  Cross-layer data written (per STA, TCP+UDP)\n";
        
        layerStats_.WriteDatFiles(prefix);
        std::cout << "  Queue data written (per STA/AC)\n";
        
        std::ofstream summary(prefix + "_summary.dat");
        if (summary) {
            summary << "# WiFi QoS Cross-Layer Analysis Summary\n";
            summary << "# SimTime_s " << cfg_.simulationTime << "\n";
            summary << "# WiFiStandard 802.11ac_5GHz_80MHz\n";
            summary << "# RateControl MinstrelHT\n";
            summary << "# ErrorModel " << cfg_.errorRateModel << "\n";
            summary << "# TCPVariant " << cfg_.tcpVariant << "\n";
            
            if (cfg_.enableMobility) {
                summary << "# MobilityModel RandomWalk2d\n";
                summary << "# MobilitySpeed_ms " << cfg_.mobilitySpeed << "\n";
            } else {
                summary << "# MobilityModel Static\n";
                summary << "# STA1_Distance_m " << cfg_.sta1Distance << "\n";
                summary << "# STA2_Distance_m " << cfg_.sta2Distance << "\n";
            }
            
            summary << "# PHY_TX " << layerStats_.phyTxBegin.load() << "\n";
            summary << "# PHY_RX " << layerStats_.phyRxEnd.load() << "\n";
            summary << "# PHY_DROP " << layerStats_.phyRxDrop.load() << "\n";
            summary << "# MAC_TX " << layerStats_.macTxOk.load() << "\n";
            summary << "# MAC_RX " << layerStats_.macRx.load() << "\n";
            summary.close();
        }
        
        std::cout << "\n.dat Files Generated:\n";
        std::cout << "  STA1 UDP (VO): " << prefix << "_sta1_udp_VO_*.dat\n";
        std::cout << "  STA1 TCP (BE): " << prefix << "_sta1_tcp_BE_*.dat\n";
        std::cout << "  STA2 UDP (VI): " << prefix << "_sta2_udp_VI_*.dat\n";
        std::cout << "  STA2 TCP (BK): " << prefix << "_sta2_tcp_BK_*.dat\n";
        std::cout << "  Queues:        " << prefix << "_sta*_queue_*.dat\n";
        std::cout << "  Cross-layer:   " << prefix << "_sta*_crosslayer_*.dat\n";
        std::cout << "  Summary:       " << prefix << "_summary.dat\n";
    }
};

// MAIN
int main(int argc, char* argv[]) {
    WiFiCrossLayerQoSSim sim;
    sim.Configure(argc, argv);
    sim.Run();
    return 0;
}
