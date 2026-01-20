// macOS compatibility 
#ifdef __APPLE__
  #include <net/ethernet.h>
  #include <netinet/ip.h>
  #include <netinet/tcp.h>
  #include <arpa/inet.h>
  #ifndef ETHER_HDR_LEN
    #define ETHER_HDR_LEN 14
  #endif
  #ifndef SIZE_ETHERNET
    #define SIZE_ETHERNET ETHER_HDR_LEN
  #endif
  #ifndef IPv4_ETHERTYPE
    #define IPv4_ETHERTYPE ETHERTYPE_IP
  #endif
  #ifndef IP_HL
    #define IP_HL(ip) ((ip)->ip_hl)
  #endif
  #ifndef IP_V
    #define IP_V(ip) ((ip)->ip_v)
  #endif
  // Some code may use ip_vhl (Linux/Windows). Map it to ip_hl on macOS.
  #ifndef ip_vhl
    #define ip_vhl ip_hl
  #endif
  // Map Linux/Win field tokens to BSD/macOS names in struct tcphdr
  #ifndef sport
    #define sport th_sport
  #endif
  #ifndef dport
    #define dport th_dport
  #endif
#endif
#include "Sniffer.h"
#include "packages.h"
#include <iostream>
#include <string.h>
#include <vector>
#include <thread> 
#include <memory>
#include <ipc.h>
#include <random>
#include <functional>
#include <builderDevice.h>
#include <handleProto.h>

int mainFunc(HANDLE eventHandle, int deviceIndex) {
    // Wait for start signal
    {
        std::unique_lock<std::mutex> lock(m);
        cv.wait(lock, [] { return quit_flag.load(); });
    }

    // Get the latest device index from the global atomic variable
    int currentDeviceIndex = d1.load();
    std::cout << "[mainFunc] Starting Sniffer with device index: " << currentDeviceIndex << std::endl;

    auto sniffer = SnifferBuilder()
        .UseDevice(currentDeviceIndex) 
        .SetEventHandle(eventHandle)
        .AddSubscriber(std::make_shared<PipeWriterSubscriber>())
        .Build();

    sniffer->Start();
    
    // Wait for stop signal
    {
        std::unique_lock<std::mutex> lock(m);
        cv.wait(lock, [] { return !quit_flag.load(); });
    }

    std::cout << "[mainFunc] Stopping Sniffer..." << std::endl;
    sniffer->Stop();
    
    return 0;
}

