#pragma once
#ifndef BUILDER_DEVICE_H
#define BUILDER_DEVICE_H
#include <pcap.h>
#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <stdexcept>

extern char errbuf[PCAP_ERRBUF_SIZE];

class builderDevice {
public:
    class Builder {
    public:
        explicit Builder(int devIndex);
        ~Builder();

        Builder& FindDevices();       
        Builder& SelectDevice();     
        Builder& OpenSelectedDevice();
        Builder& ListDevices();       
        Builder& OpenFromFile(const std::string& filePath);

        builderDevice Build();

    private:
        int inum;              
        int deviceCount;        
        pcap_if_t* alldevs;     
        pcap_if_t* selectedDev;         
        pcap_t* handle;        
        std::vector<std::string> deviceList;

        friend class builderDevice;
    };

    pcap_t* getHandler() const;
    const std::vector<std::string>& getDevices() const;

private:
    builderDevice(const Builder& builder);

    int inum;
    pcap_t* adhandle;
    std::vector<std::string> list;
};

#endif
