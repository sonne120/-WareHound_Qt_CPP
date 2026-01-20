#include "sniffer_pipe.h"
#include "Sniffer.h"
#include "builderDevice.h"
#include "packages.h"
#include <iostream>
#include <sstream>
#include <thread>
#include <pcap.h>
#include <unistd.h>
#include <cstring>
#include <iomanip>
#include <vector>

// Platform handling
#ifdef __APPLE__
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#endif

int sniffer_get_devices(char* devices_json, int buffer_size) {
    try {
        auto device = builderDevice::Builder(0).FindDevices().ListDevices().Build();
        const std::vector<std::string>& list = device.getDevices();
        
        // Construct simple JSON array: ["Device 1", "Device 2"]
        std::stringstream ss;
        ss << "[";
        for (size_t i = 0; i < list.size(); ++i) {
            ss << "\"" << list[i] << "\"";
            if (i < list.size() - 1) ss << ",";
        }
        ss << "]";
        
        std::string json = ss.str();
        strncpy(devices_json, json.c_str(), buffer_size - 1);
        devices_json[buffer_size - 1] = '\0';
        return static_cast<int>(list.size());
    } catch (const std::exception& e) {
        strncpy(devices_json, "[]", buffer_size - 1);
        return -1;
    }
}

int sniffer_capture_and_write_pipe(
    int device_number,
    int result_fd,
    int log_fd,
    std::atomic<bool>* running
) {
    pcap_t* handle = nullptr;
    std::string errBufStr;
    
    // Open device
    try {
        std::string msg = "Connecting to device " + std::to_string(device_number) + "...\n";
        write(log_fd, msg.c_str(), msg.length());
        
        // Use the library's builderDevice to open the pcap handle
        builderDevice dev = builderDevice::Builder(device_number)
                                .FindDevices()
                                .SelectDevice()
                                .OpenSelectedDevice()
                                .Build();
        
        handle = dev.getHandler();
        
        if (!handle) {
             std::string err = "Failed to obtain pcap handle for device.\n";
             write(log_fd, err.c_str(), err.length());
             return -1;
        }
        
    } catch (const std::exception& e) {
        std::string err = "Error opening device: ";
        err += e.what();
        err += "\n";
        write(log_fd, err.c_str(), err.length());
        return -1;
    }
    
    std::string startMsg = "Capture started. Listening for packets...\n";
    write(log_fd, startMsg.c_str(), startMsg.length());
    
    struct pcap_pkthdr* header;
    const u_char* pkt_data;
    int packet_id = 0;
    

    // 2. Setup Globals for Packages (Legacy compatibility)
    _adhandle1 = handle;
    global_pipe_fd = result_fd;
    quit_flag = true;
    cv.notify_all();

    std::string runMsg = "Starting Sniffer (Modernized)...\n";
    write(log_fd, runMsg.c_str(), runMsg.length());

    // Use the new Sniffer architecture
    auto sniffer = SnifferBuilder()
        .UseHandle(handle)
        .AddSubscriber(std::make_shared<PipeWriterSubscriber>())
        .Build();

    sniffer->Start();

    // Monitor loop to handle stop signal
    while(running->load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    // Stop sequence
    if (handle) {
        pcap_breakloop(handle);
    }
    sniffer->Stop();

    std::string doneMsg = "Sniffer finished.\n";
    write(log_fd, doneMsg.c_str(), doneMsg.length());

    // handle is closed by Sniffer destructor
    // if (handle) pcap_close(handle);
    return 0;
}


