#include "builderDevice.h"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif


builderDevice::Builder::Builder(int devIndex)
    : inum(devIndex), deviceCount(0), alldevs(nullptr),
    selectedDev(nullptr), handle(nullptr) {}

builderDevice::Builder::~Builder() {
    if (alldevs) {
        pcap_freealldevs(alldevs);
        alldevs = nullptr;
    }
}

builderDevice::Builder& builderDevice::Builder::FindDevices() {

    if (alldevs) {
        pcap_freealldevs(alldevs);
        alldevs = nullptr;
    }
#ifdef _WIN32
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, nullptr, &alldevs, errbuf) == -1) {
#else
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
#endif
        throw std::runtime_error("Failed to find devices: " + std::string(errbuf));
    }
    deviceCount = 0;
    for (selectedDev = alldevs; selectedDev; selectedDev = selectedDev->next) {
        ++deviceCount;
        std::cerr << deviceCount << ". " << selectedDev->name << "\n"
            << (selectedDev->description ? selectedDev->description : "No description available") << "\n";
    }
    return *this;
}

builderDevice::Builder& builderDevice::Builder::SelectDevice() {
    if (!alldevs) {
        FindDevices();
    }
    if (inum < 1 || inum > deviceCount) {
        throw std::out_of_range("Interface number out of range");
    }
    selectedDev = alldevs;
    for (int idx = 1; idx < inum; ++idx) {
        selectedDev = selectedDev->next;
    }
    return *this;
}

builderDevice::Builder& builderDevice::Builder::OpenSelectedDevice() {
    if (inum < 1 || inum > deviceCount) {
        throw std::logic_error("No valid device selected. Call SelectDevice() first.");
    }

#ifdef _WIN32
    handle = pcap_open(selectedDev->name,
        65536,
        PCAP_OPENFLAG_PROMISCUOUS,
        1000,
        NULL,
        errbuf);
#else
    handle = pcap_open_live(selectedDev->name,
        65536,
        1, // promiscuous mode
        1000,
        errbuf);
#endif
    if (!handle) {
        throw std::runtime_error("Failed to open device: " + std::string(errbuf));
    }
    return *this;
}

builderDevice::Builder& builderDevice::Builder::ListDevices() {
    deviceList.clear();
    if (!alldevs) {
        FindDevices();
    }
    int idx = 0;
    for (pcap_if_t* it = alldevs; it; it = it->next) {
        ++idx;
        std::string name = (it->name) ? it->name : "";
        std::string description = (it->description) ? it->description : "";
        std::string displayName;
        
        if (!description.empty() && description != name) {
            displayName = description + " (" + name + ")";
        } else if (!description.empty()) {
            displayName = description;
        } else {
            displayName = name;
        }

        // Add IP address if available
        std::string ipStr;
        for(pcap_addr_t *a = it->addresses; a; a = a->next) {
             if(a->addr && a->addr->sa_family == AF_INET) {
                 struct sockaddr_in *sa_in = (struct sockaddr_in *)a->addr;
                 char addrBuf[INET_ADDRSTRLEN];
                 if (inet_ntop(AF_INET, &(sa_in->sin_addr), addrBuf, sizeof(addrBuf))) {
                     ipStr = addrBuf;
                     break; 
                 }
             }
        }
        if (!ipStr.empty()) {
             displayName += " [" + ipStr + "]";
        }
        
        std::string desc = std::to_string(idx) + ". " + displayName;
        
        deviceList.push_back(desc);
    }
    return *this;
}

builderDevice::Builder& builderDevice::Builder::OpenFromFile(const std::string& filePath) {
    handle = pcap_open_offline(filePath.c_str(), errbuf);
    if (!handle) {
        throw std::runtime_error("Failed to open file: " + std::string(errbuf));
    }
    return *this;
}

builderDevice builderDevice::Builder::Build() {
    return builderDevice(*this);
}

pcap_t* builderDevice::getHandler() const {
    return adhandle;
}

const std::vector<std::string>& builderDevice::getDevices() const {
    return list;
}

builderDevice::builderDevice(const Builder& builder)
    : inum(builder.inum), adhandle(builder.handle), list(builder.deviceList) {}