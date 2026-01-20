#include "packet_runner.h"
#include "sniffer_pipe.h"
#include "struct.h"
#include <iostream>
#include <sstream>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <cstring>
#include <vector>

PacketRunner::PacketRunner() {
}

PacketRunner::~PacketRunner() {
    stopCapture();
}

std::vector<std::string> PacketRunner::getDeviceList() {
    try {
        builderDevice::Builder builder(1);
        builder.FindDevices();
        builder.ListDevices();
        return builder.Build().getDevices();
    } catch (const std::exception& e) {
        std::cerr << "[PacketRunner] Error listing devices: " << e.what() << std::endl;
        return {};
    }
}

void PacketRunner::startCapture(PacketCallback packetCallback,
                                 LogCallback logCallback,
                                 ErrorCallback errorCallback) {
    if (m_running.load()) {
        if (errorCallback) {
            errorCallback("Capture already running");
        }
        return;
    }
    
    // Create pipes
    if (pipe(m_packetPipe) != 0) {
        if (errorCallback) {
            errorCallback("Failed to create packet pipe");
        }
        return;
    }
    
    if (pipe(m_logPipe) != 0) {
        close(m_packetPipe[0]);
        close(m_packetPipe[1]);
        if (errorCallback) {
            errorCallback("Failed to create log pipe");
        }
        return;
    }
    
    m_running.store(true);
    m_packetCount.store(0);
    
    if (logCallback) {
        logCallback("Starting packet capture on device " + std::to_string(deviceNumber));
    }
    
    // Start the capture worker thread
    m_captureThread = std::thread([this, packet_write = m_packetPipe[1], 
                                    log_write = m_logPipe[1]] {
        captureWorker(packet_write, log_write);
    });
    
    // Start the packet reader threa
    m_packetReaderThread = std::thread([this, packet_read = m_packetPipe[0], 
                                         packetCallback]() {
        tagSnapshot snapshot;
        ssize_t n;
        
        // Continuous read of struct size
        while ((n = read(packet_read, &snapshot, sizeof(tagSnapshot))) > 0) {
            if (n < sizeof(tagSnapshot)) {
                // If we read partial data, we should probably buffer it, but for pipes usually write is atomic for small sizes
                continue;
            }

            if (packetCallback) {
                std::stringstream ss;
                ss << "{"
                   << "\"id\":" << snapshot.id << ","
                   << "\"source_ip\":\"" << snapshot.source_ip << "\","
                   << "\"dest_ip\":\"" << snapshot.dest_ip << "\","
                   << "\"source_port\":" << snapshot.source_port << ","
                   << "\"dest_port\":" << snapshot.dest_port << ","
                   << "\"proto\":\"" << snapshot.proto << "\","
                   << "\"source_mac\":\"" << snapshot.source_mac << "\","
                   << "\"dest_mac\":\"" << snapshot.dest_mac << "\","
                   << "\"host_name\":\"" << snapshot.host_name << "\""
                   << "}";
                
                m_packetCount.fetch_add(1);
                packetCallback(ss.str());
            }
        }
        
        close(packet_read);
    });
    
    // Start the log reader thread (reads from log pipe, calls callback)
    m_logReaderThread = std::thread([log_read = m_logPipe[0], logCallback]() {
        char buf[4096];
        ssize_t n;
        
        while ((n = read(log_read, buf, sizeof(buf) - 1)) > 0) {
            buf[n] = '\0';
            std::string message(buf);
            
            if (logCallback) {
                logCallback(message);
            }
        }
        
        close(log_read);
    });
}

void PacketRunner::stopCapture() {
    if (!m_running.load()) {
        return;
    }
    
    m_running.store(false);
    
    // Wait for threads to finish
    if (m_captureThread.joinable()) {
        m_captureThread.join();
    }
    if (m_packetReaderThread.joinable()) {
        m_packetReaderThread.join();
    }
    if (m_logReaderThread.joinable()) {
        m_logReaderThread.join();
    }
}


static std::string getCurrentTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    std::tm tm_now;
#ifdef _WIN32
    localtime_s(&tm_now, &time_t_now);
#else
    localtime_r(&time_t_now, &tm_now);
#endif
    
    std::stringstream ss;
    ss << std::put_time(&tm_now, "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

void PacketRunner::captureWorker(int packet_fd, int log_fd) {

    sniffer_capture_and_write_pipe(deviceNumber, packet_fd, log_fd, &m_running);
    
    close(packet_fd);
    close(log_fd);
}
