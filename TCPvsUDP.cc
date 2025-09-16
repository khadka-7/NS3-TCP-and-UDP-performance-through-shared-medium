#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/netanim-module.h"
#include "ns3/traffic-control-module.h"
#include <fstream>
#include <iostream>
#include "ns3/tcp-bbr.h"
#include <iomanip>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("EnhancedTcpUdpComparisonAnalysis");

// Global variables for throughput tracking
std::map<uint32_t, std::vector<std::pair<double, double>>> flowThroughputData;

// Callback function to track throughput over time
void ThroughputTracer(Ptr<FlowMonitor> monitor, Ptr<Ipv4FlowClassifier> classifier) {
    monitor->CheckForLostPackets();
    std::map<FlowId, FlowMonitor::FlowStats> stats = monitor->GetFlowStats();
    
    double currentTime = Simulator::Now().GetSeconds();
    
    for (auto& stat : stats) {
        FlowId flowId = stat.first;
        FlowMonitor::FlowStats flowStats = stat.second;
        
        if (flowStats.rxBytes > 0) {
            double instantThroughput = 0.0;
            if (flowStats.timeLastRxPacket.GetSeconds() > flowStats.timeFirstTxPacket.GetSeconds()) {
                instantThroughput = flowStats.rxBytes * 8.0 / 
                    (flowStats.timeLastRxPacket - flowStats.timeFirstTxPacket).GetSeconds() / 1e6;
            }
            flowThroughputData[flowId].push_back(std::make_pair(currentTime, instantThroughput));
        }
    }
    
    // Schedule next measurement
    Simulator::Schedule(Seconds(0.5), &ThroughputTracer, monitor, classifier);
}

int main(int argc, char *argv[])
{
    // ---- ENHANCED CONFIGURATION PARAMETERS ----
    double simulationDuration = 60.0;
    bool enablePacketCapture = true;
    std::string tcpCongestionControl = "TcpBbr";
    uint32_t bufferSize = 150;
    double bottleneckBandwidth = 50.0; // Mbps
    double accessLinkBandwidth = 150.0; // Mbps
    double bottleneckDelay = 20.0; // ms
    double udpDataRate = 6.0; // Mbps
    
    // Enhanced command line interface
    CommandLine cmd(__FILE__);
    cmd.AddValue("simulationDuration", "Total simulation time in seconds", simulationDuration);
    cmd.AddValue("enablePacketCapture", "Enable/disable PCAP packet tracing", enablePacketCapture);
    cmd.AddValue("tcpCongestionControl", "TCP congestion control algorithm (TcpNewReno, TcpCubic, TcpBbr)", tcpCongestionControl);
    cmd.AddValue("bufferSize", "Router buffer size in packets", bufferSize);
    cmd.AddValue("bottleneckBandwidth", "Bottleneck link bandwidth in Mbps", bottleneckBandwidth);
    cmd.AddValue("udpDataRate", "UDP application data rate in Mbps", udpDataRate);
    cmd.Parse(argc, argv);
    
    // Configure TCP congestion control algorithm
    if (tcpCongestionControl == "TcpBbr") {
        Config::SetDefault("ns3::TcpL4Protocol::SocketType", TypeIdValue(TcpBbr::GetTypeId()));
    } else if (tcpCongestionControl == "TcpCubic") {
        Config::SetDefault("ns3::TcpL4Protocol::SocketType", TypeIdValue(TcpCubic::GetTypeId()));
    } else {
        Config::SetDefault("ns3::TcpL4Protocol::SocketType", TypeIdValue(TcpNewReno::GetTypeId()));
    }
    
    // Optimize TCP parameters for better performance
    Config::SetDefault("ns3::TcpSocket::SegmentSize", UintegerValue(1448));
    Config::SetDefault("ns3::TcpSocket::SndBufSize", UintegerValue(2 << 20)); // 2MB
    Config::SetDefault("ns3::TcpSocket::RcvBufSize", UintegerValue(2 << 20)); // 2MB
    Config::SetDefault("ns3::TcpSocket::InitialCwnd", UintegerValue(10));
    Config::SetDefault("ns3::TcpSocket::DelAckCount", UintegerValue(2));
    
    // ---- NETWORK TOPOLOGY SETUP ----
    NodeContainer networkNodes;
    networkNodes.Create(4);
    
    // Assign meaningful node references
    Ptr<Node> udpTransmitter = networkNodes.Get(0);
    Ptr<Node> tcpTransmitter = networkNodes.Get(1);
    Ptr<Node> intermediateRouter = networkNodes.Get(2);
    Ptr<Node> destinationReceiver = networkNodes.Get(3);

    // ---- ENHANCED LINK CONFIGURATION ----
    PointToPointHelper highSpeedAccessLink, bottleneckLink;
    
    // High-speed access links configuration
    highSpeedAccessLink.SetDeviceAttribute("DataRate", StringValue(std::to_string(accessLinkBandwidth) + "Mbps"));
    highSpeedAccessLink.SetChannelAttribute("Delay", StringValue("2ms"));
    highSpeedAccessLink.SetQueue("ns3::DropTailQueue", "MaxSize", QueueSizeValue(QueueSize("200p")));
    
    // Bottleneck link configuration (primary congestion point)
    bottleneckLink.SetDeviceAttribute("DataRate", StringValue(std::to_string(bottleneckBandwidth) + "Mbps"));
    bottleneckLink.SetChannelAttribute("Delay", StringValue(std::to_string(bottleneckDelay) + "ms"));
    bottleneckLink.SetQueue("ns3::DropTailQueue", "MaxSize", QueueSizeValue(QueueSize(std::to_string(bufferSize) + "p")));

    // Install network devices
    NetDeviceContainer udpSenderToRouter = highSpeedAccessLink.Install(udpTransmitter, intermediateRouter);
    NetDeviceContainer tcpSenderToRouter = highSpeedAccessLink.Install(tcpTransmitter, intermediateRouter);
    NetDeviceContainer routerToReceiver = bottleneckLink.Install(intermediateRouter, destinationReceiver);

    // ---- PROTOCOL STACK INSTALLATION ----
    InternetStackHelper internetProtocolStack;
    internetProtocolStack.Install(networkNodes);
    
    // Install advanced traffic control for modern TCP variants
    TrafficControlHelper trafficController;
    trafficController.Install(udpSenderToRouter);
    trafficController.Install(tcpSenderToRouter);
    trafficController.Install(routerToReceiver);

    // ---- IP ADDRESS ASSIGNMENT ----
    Ipv4AddressHelper ipAddressHelper;

    ipAddressHelper.SetBase("192.168.1.0", "255.255.255.0");
    Ipv4InterfaceContainer udpSenderInterfaces = ipAddressHelper.Assign(udpSenderToRouter);

    ipAddressHelper.SetBase("192.168.2.0", "255.255.255.0");
    Ipv4InterfaceContainer tcpSenderInterfaces = ipAddressHelper.Assign(tcpSenderToRouter);

    ipAddressHelper.SetBase("192.168.3.0", "255.255.255.0");
    Ipv4InterfaceContainer receiverInterfaces = ipAddressHelper.Assign(routerToReceiver);

    // Populate routing tables
    Ipv4GlobalRoutingHelper::PopulateRoutingTables();

    // ---- APPLICATION LAYER CONFIGURATION ----
    
    // UDP Traffic Generation (Constant Bit Rate)
    uint16_t udpDestinationPort = 8080;
    OnOffHelper udpTrafficGenerator("ns3::UdpSocketFactory",
                                   InetSocketAddress(receiverInterfaces.GetAddress(1), udpDestinationPort));
    udpTrafficGenerator.SetAttribute("DataRate", StringValue(std::to_string(udpDataRate) + "Mbps"));
    udpTrafficGenerator.SetAttribute("PacketSize", UintegerValue(1024));
    udpTrafficGenerator.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
    udpTrafficGenerator.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));

    ApplicationContainer udpClientApplication = udpTrafficGenerator.Install(udpTransmitter);
    udpClientApplication.Start(Seconds(2.0));
    udpClientApplication.Stop(Seconds(simulationDuration - 1.0));

    // UDP Packet Sink
    PacketSinkHelper udpPacketSink("ns3::UdpSocketFactory",
                                  InetSocketAddress(Ipv4Address::GetAny(), udpDestinationPort));
    ApplicationContainer udpSinkApplication = udpPacketSink.Install(destinationReceiver);
    udpSinkApplication.Start(Seconds(1.0));
    udpSinkApplication.Stop(Seconds(simulationDuration));

    // TCP Bulk Transfer (Greedy Traffic)
    uint16_t tcpDestinationPort = 9090;
    BulkSendHelper tcpBulkSender("ns3::TcpSocketFactory",
                                InetSocketAddress(receiverInterfaces.GetAddress(1), tcpDestinationPort));
    tcpBulkSender.SetAttribute("MaxBytes", UintegerValue(0)); // Unlimited data transfer

    ApplicationContainer tcpClientApplication = tcpBulkSender.Install(tcpTransmitter);
    tcpClientApplication.Start(Seconds(3.0)); // Start after UDP to observe fairness
    tcpClientApplication.Stop(Seconds(simulationDuration - 1.0));

    // TCP Packet Sink
    PacketSinkHelper tcpPacketSink("ns3::TcpSocketFactory",
                                  InetSocketAddress(Ipv4Address::GetAny(), tcpDestinationPort));
    ApplicationContainer tcpSinkApplication = tcpPacketSink.Install(destinationReceiver);
    tcpSinkApplication.Start(Seconds(1.0));
    tcpSinkApplication.Stop(Seconds(simulationDuration));

    // ---- PACKET CAPTURE CONFIGURATION ----
    if (enablePacketCapture) {
        highSpeedAccessLink.EnablePcapAll("enhanced-tcp-udp-access-links");
        bottleneckLink.EnablePcapAll("enhanced-tcp-udp-bottleneck-link");
    }

    // ---- ENHANCED NETWORK ANIMATION ----
    AnimationInterface networkAnimation("enhanced-tcp-udp-network-animation.xml");
    
    // Improved node positioning for better visualization
    networkAnimation.SetConstantPosition(udpTransmitter, 5.0, 15.0);
    networkAnimation.SetConstantPosition(tcpTransmitter, 5.0, 35.0);
    networkAnimation.SetConstantPosition(intermediateRouter, 25.0, 25.0);
    networkAnimation.SetConstantPosition(destinationReceiver, 45.0, 25.0);
    
    // Enhanced node descriptions and visual styling
    networkAnimation.UpdateNodeDescription(udpTransmitter, "UDP Source");
    networkAnimation.UpdateNodeDescription(tcpTransmitter, "TCP Source (" + tcpCongestionControl + ")");
    networkAnimation.UpdateNodeDescription(intermediateRouter, "Bottleneck Router");
    networkAnimation.UpdateNodeDescription(destinationReceiver, "Destination");
    
    // Color-coded nodes for easy identification
    networkAnimation.UpdateNodeColor(udpTransmitter, 220, 20, 60);    // Crimson
    networkAnimation.UpdateNodeColor(tcpTransmitter, 30, 144, 255);   // Dodger Blue
    networkAnimation.UpdateNodeColor(intermediateRouter, 34, 139, 34); // Forest Green
    networkAnimation.UpdateNodeColor(destinationReceiver, 148, 0, 211); // Dark Violet
    
    // Track routing table evolution
    networkAnimation.EnableIpv4RouteTracking("enhanced-routing-evolution.xml", 
                                            Seconds(0), Seconds(8), Seconds(1.0));

    // ---- COMPREHENSIVE FLOW MONITORING ----
    FlowMonitorHelper flowMonitorHelper;
    Ptr<FlowMonitor> networkFlowMonitor = flowMonitorHelper.InstallAll();
    Ptr<Ipv4FlowClassifier> flowClassifier = DynamicCast<Ipv4FlowClassifier>(flowMonitorHelper.GetClassifier());
    
    // Start throughput tracking
    Simulator::Schedule(Seconds(1.0), &ThroughputTracer, networkFlowMonitor, flowClassifier);

    // ---- SIMULATION EXECUTION ----
    std::cout << "\n==== SIMULATION PARAMETERS ====\n";
    std::cout << "Simulation Duration: " << simulationDuration << " seconds\n";
    std::cout << "TCP Algorithm: " << tcpCongestionControl << "\n";
    std::cout << "Bottleneck Bandwidth: " << bottleneckBandwidth << " Mbps\n";
    std::cout << "Bottleneck Delay: " << bottleneckDelay << " ms\n";
    std::cout << "Buffer Size: " << bufferSize << " packets\n";
    std::cout << "UDP Rate: " << udpDataRate << " Mbps\n";
    std::cout << "Starting simulation...\n";

    Simulator::Stop(Seconds(simulationDuration));
    Simulator::Run();

    // ---- COMPREHENSIVE PERFORMANCE ANALYSIS ----
    networkFlowMonitor->CheckForLostPackets();
    std::map<FlowId, FlowMonitor::FlowStats> finalFlowStatistics = networkFlowMonitor->GetFlowStats();

    // Create detailed results file
    std::ofstream detailedResultsFile("comprehensive-performance-analysis.csv");
    detailedResultsFile << "FlowID,Protocol,SourceIP,DestinationIP,SourcePort,DestPort,"
                       << "ThroughputMbps,TransmittedBytes,ReceivedBytes,PacketLossRate,"
                       << "AverageDelayMs,JitterMs,TransmittedPackets,ReceivedPackets\n";

    double totalUdpThroughput = 0.0, totalTcpThroughput = 0.0;
    double totalUdpDelay = 0.0, totalTcpDelay = 0.0;
    double totalUdpLoss = 0.0, totalTcpLoss = 0.0;
    int udpFlowCount = 0, tcpFlowCount = 0;

    std::cout << "\n==== DETAILED FLOW ANALYSIS ====\n";
    for (auto& flowData : finalFlowStatistics) {
        Ipv4FlowClassifier::FiveTuple flowTuple = flowClassifier->FindFlow(flowData.first);
        FlowMonitor::FlowStats stats = flowData.second;
        
        // Calculate performance metrics
        double throughputMbps = 0.0;
        if (stats.timeLastRxPacket.GetSeconds() > stats.timeFirstTxPacket.GetSeconds()) {
            throughputMbps = stats.rxBytes * 8.0 / 
                (stats.timeLastRxPacket - stats.timeFirstTxPacket).GetSeconds() / 1e6;
        }
        
        double packetLossPercentage = (stats.txPackets > 0) ? 
            (stats.lostPackets * 100.0 / stats.txPackets) : 0.0;
        double averageDelayMs = (stats.rxPackets > 0) ? 
            (stats.delaySum.GetSeconds() / stats.rxPackets) * 1000 : 0;
        double jitterMs = (stats.rxPackets > 1) ? 
            (stats.jitterSum.GetSeconds() / (stats.rxPackets - 1)) * 1000 : 0;

        // Protocol identification
        std::string protocolName = (flowTuple.protocol == 6) ? "TCP" : "UDP";
        
        // Aggregate statistics by protocol
        if (protocolName == "TCP") {
            totalTcpThroughput += throughputMbps;
            totalTcpDelay += averageDelayMs;
            totalTcpLoss += packetLossPercentage;
            tcpFlowCount++;
        } else {
            totalUdpThroughput += throughputMbps;
            totalUdpDelay += averageDelayMs;
            totalUdpLoss += packetLossPercentage;
            udpFlowCount++;
        }

        // Console output
        std::cout << std::fixed << std::setprecision(2);
        std::cout << protocolName << " Flow " << flowData.first 
                  << " (" << flowTuple.sourceAddress << ":" << flowTuple.sourcePort 
                  << " → " << flowTuple.destinationAddress << ":" << flowTuple.destinationPort << ")\n";
        std::cout << "  Throughput: " << throughputMbps << " Mbps\n";
        std::cout << "  Packet Loss: " << packetLossPercentage << "%\n";
        std::cout << "  Average Delay: " << averageDelayMs << " ms\n";
        std::cout << "  Jitter: " << jitterMs << " ms\n\n";

        // CSV output
        detailedResultsFile << flowData.first << "," << protocolName << ","
                           << flowTuple.sourceAddress << "," << flowTuple.destinationAddress << ","
                           << flowTuple.sourcePort << "," << flowTuple.destinationPort << ","
                           << throughputMbps << "," << stats.txBytes << "," << stats.rxBytes << ","
                           << packetLossPercentage << "," << averageDelayMs << "," << jitterMs << ","
                           << stats.txPackets << "," << stats.rxPackets << "\n";
    }
    
    detailedResultsFile.close();

    // ---- ENHANCED VISUALIZATION SCRIPTS ----
    
    // 1. Throughput comparison bar chart
    std::ofstream throughputComparisonScript("enhanced-throughput-comparison.plt");
    throughputComparisonScript << "set terminal pngcairo size 1200,800 enhanced font 'Arial,12'\n";
    throughputComparisonScript << "set output 'protocol-throughput-comparison.png'\n";
    throughputComparisonScript << "set title 'Network Protocol Performance Comparison\\n"
                              << "{/*0.8 TCP: " << tcpCongestionControl << ", Buffer: " << bufferSize 
                              << " packets, Bottleneck: " << bottleneckBandwidth << " Mbps}' font 'Arial,14'\n";
    throughputComparisonScript << "set xlabel 'Transport Protocol' font 'Arial,12'\n";
    throughputComparisonScript << "set ylabel 'Aggregate Throughput (Mbps)' font 'Arial,12'\n";
    throughputComparisonScript << "set style fill solid 0.8 border -1\n";
    throughputComparisonScript << "set boxwidth 0.6\n";
    throughputComparisonScript << "set xtics font 'Arial,11'\n";
    throughputComparisonScript << "set ytics font 'Arial,11'\n";
    throughputComparisonScript << "set grid ytics alpha 0.3\n";
    throughputComparisonScript << "set key off\n";
    throughputComparisonScript << "plot '-' using 2:xtic(1) with boxes lc rgb '#FF6B6B' title 'UDP', \\\n";
    throughputComparisonScript << "     '-' using 2:xtic(1) with boxes lc rgb '#4ECDC4' title 'TCP'\n";
    throughputComparisonScript << "UDP " << totalUdpThroughput << "\n";
    throughputComparisonScript << "e\n";
    throughputComparisonScript << "TCP " << totalTcpThroughput << "\n";
    throughputComparisonScript << "e\n";
    throughputComparisonScript.close();

    // 2. Multi-metric comparison radar/bar chart
    std::ofstream multiMetricScript("enhanced-multi-metric-analysis.plt");
    multiMetricScript << "set terminal pngcairo size 1400,900 enhanced font 'Arial,12'\n";
    multiMetricScript << "set output 'comprehensive-performance-metrics.png'\n";
    multiMetricScript << "set multiplot layout 2,2 title 'Comprehensive TCP vs UDP Performance Analysis\\n"
                     << "{/*0.8 Simulation: " << simulationDuration << "s, " << tcpCongestionControl 
                     << ", " << bottleneckBandwidth << "Mbps bottleneck}' font 'Arial,16'\n";
    
    // Throughput subplot
    multiMetricScript << "set title 'Throughput Performance' font 'Arial,13'\n";
    multiMetricScript << "set xlabel 'Protocol'\n";
    multiMetricScript << "set ylabel 'Throughput (Mbps)'\n";
    multiMetricScript << "set style fill solid 0.7\n";
    multiMetricScript << "set boxwidth 0.5\n";
    multiMetricScript << "plot '-' using 2:xtic(1) with boxes lc rgb '#3498db'\n";
    multiMetricScript << "UDP " << totalUdpThroughput << "\n";
    multiMetricScript << "TCP " << totalTcpThroughput << "\n";
    multiMetricScript << "e\n";
    
    // Delay subplot
    multiMetricScript << "set title 'Average Packet Delay' font 'Arial,13'\n";
    multiMetricScript << "set ylabel 'Delay (ms)'\n";
    multiMetricScript << "plot '-' using 2:xtic(1) with boxes lc rgb '#e74c3c'\n";
    multiMetricScript << "UDP " << (udpFlowCount > 0 ? totalUdpDelay/udpFlowCount : 0) << "\n";
    multiMetricScript << "TCP " << (tcpFlowCount > 0 ? totalTcpDelay/tcpFlowCount : 0) << "\n";
    multiMetricScript << "e\n";
    
    // Loss rate subplot
    multiMetricScript << "set title 'Packet Loss Rate' font 'Arial,13'\n";
    multiMetricScript << "set ylabel 'Loss Rate (%)'\n";
    multiMetricScript << "plot '-' using 2:xtic(1) with boxes lc rgb '#f39c12'\n";
    multiMetricScript << "UDP " << (udpFlowCount > 0 ? totalUdpLoss/udpFlowCount : 0) << "\n";
    multiMetricScript << "TCP " << (tcpFlowCount > 0 ? totalTcpLoss/tcpFlowCount : 0) << "\n";
    multiMetricScript << "e\n";
    
    // Bandwidth utilization
    double totalThroughput = totalUdpThroughput + totalTcpThroughput;
    double utilizationPercentage = (totalThroughput / bottleneckBandwidth) * 100;
    multiMetricScript << "set title 'Bottleneck Utilization' font 'Arial,13'\n";
    multiMetricScript << "set ylabel 'Utilization (%)'\n";
    multiMetricScript << "plot '-' using 2:xtic(1) with boxes lc rgb '#2ecc71'\n";
    multiMetricScript << "Overall " << utilizationPercentage << "\n";
    multiMetricScript << "e\n";
    
    multiMetricScript << "unset multiplot\n";
    multiMetricScript.close();

    // 3. Time series throughput evolution
    std::ofstream timeSeriesScript("throughput-evolution.plt");
    timeSeriesScript << "set terminal pngcairo size 1400,700 enhanced font 'Arial,12'\n";
    timeSeriesScript << "set output 'throughput-time-evolution.png'\n";
    timeSeriesScript << "set title 'Throughput Evolution Over Time\\n"
                    << "{/*0.8 Real-time performance monitoring during " << simulationDuration 
                    << "s simulation}' font 'Arial,14'\n";
    timeSeriesScript << "set xlabel 'Simulation Time (seconds)' font 'Arial,12'\n";
    timeSeriesScript << "set ylabel 'Instantaneous Throughput (Mbps)' font 'Arial,12'\n";
    timeSeriesScript << "set grid\n";
    timeSeriesScript << "set key top right\n";
    
    // Write time series data
    std::ofstream timeSeriesData("throughput-timeseries.dat");
    timeSeriesData << "# Time UDP_Throughput TCP_Throughput\n";
    
    // Process collected time series data
    for (double t = 1.0; t <= simulationDuration; t += 0.5) {
        double udpThroughput = 0.0, tcpThroughput = 0.0;
        
        for (auto& flowData : flowThroughputData) {
            // Find closest time point
            for (auto& point : flowData.second) {
                if (abs(point.first - t) < 0.3) {
                    // Determine protocol based on flow ID (simplified)
                    if (flowData.first == 1) udpThroughput = point.second;
                    else if (flowData.first == 2) tcpThroughput = point.second;
                    break;
                }
            }
        }
        timeSeriesData << t << " " << udpThroughput << " " << tcpThroughput << "\n";
    }
    timeSeriesData.close();
    
    timeSeriesScript << "plot 'throughput-timeseries.dat' using 1:2 with lines lw 2 lc rgb '#FF6B6B' title 'UDP Throughput', \\\n";
    timeSeriesScript << "     'throughput-timeseries.dat' using 1:3 with lines lw 2 lc rgb '#4ECDC4' title 'TCP Throughput'\n";
    timeSeriesScript.close();

    // ---- COMPREHENSIVE SUMMARY REPORT ----
    std::cout << "\n========== SIMULATION SUMMARY ==========\n";
    std::cout << std::fixed << std::setprecision(2);
    std::cout << "Configuration:\n";
    std::cout << "  TCP Algorithm: " << tcpCongestionControl << "\n";
    std::cout << "  Bottleneck: " << bottleneckBandwidth << " Mbps, " << bottleneckDelay << " ms RTT\n";
    std::cout << "  Buffer Size: " << bufferSize << " packets\n";
    std::cout << "  UDP Rate: " << udpDataRate << " Mbps\n\n";
    
    std::cout << "Performance Results:\n";
    std::cout << "  UDP Total Throughput: " << totalUdpThroughput << " Mbps\n";
    std::cout << "  TCP Total Throughput: " << totalTcpThroughput << " Mbps\n";
    std::cout << "  Combined Throughput: " << totalThroughput << " Mbps\n";
    std::cout << "  Bottleneck Utilization: " << utilizationPercentage << "%\n\n";
    
    if (udpFlowCount > 0) {
        std::cout << "  UDP Average Delay: " << totalUdpDelay/udpFlowCount << " ms\n";
        std::cout << "  UDP Packet Loss: " << totalUdpLoss/udpFlowCount << "%\n";
    }
    if (tcpFlowCount > 0) {
        std::cout << "  TCP Average Delay: " << totalTcpDelay/tcpFlowCount << " ms\n";
        std::cout << "  TCP Packet Loss: " << totalTcpLoss/tcpFlowCount << "%\n";
    }
    
    double fairnessIndex = 0.0;
    if (totalThroughput > 0) {
        double sumSquares = totalUdpThroughput*totalUdpThroughput + totalTcpThroughput*totalTcpThroughput;
        fairnessIndex = (totalThroughput * totalThroughput) / (2 * sumSquares);
    }
    std::cout << "  Fairness Index: " << fairnessIndex << "\n";
    std::cout << "==========================================\n";

    // Execute visualization scripts
    std::cout << "\nGenerating visualizations...\n";
    int result1 = std::system("gnuplot enhanced-throughput-comparison.plt");
    int result2 = std::system("gnuplot enhanced-multi-metric-analysis.plt");
    int result3 = std::system("gnuplot throughput-evolution.plt");
    
    if (result1 == 0 && result2 == 0 && result3 == 0) {
        std::cout << "✓ All visualization files generated successfully!\n";
        std::cout << "  - protocol-throughput-comparison.png\n";
        std::cout << "  - comprehensive-performance-metrics.png\n";
        std::cout << "  - throughput-time-evolution.png\n";
    } else {
        std::cout << "Completed\n";
    }

    Simulator::Destroy();
    return 0;
}
