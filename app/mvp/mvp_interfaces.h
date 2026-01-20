#ifndef MVP_INTERFACES_H
#define MVP_INTERFACES_H

#include <vector>
#include <string>
#include <functional>
#include <memory>
#include "packetdata.h"

class IPacketSnifferView {
public:
    virtual ~IPacketSnifferView() = default;
    
    // Display operations
    virtual void displayPackets(const std::vector<PacketDataPtr>& packets) = 0;
    virtual void displayPacketDetails(const PacketDataPtr& packet) = 0;
    virtual void setDeviceList(const std::vector<std::string>& devices) = 0;
    virtual void updateStatistics(int totalPackets, int displayedPackets, 
                                 uint64_t totalBytes) = 0;
    virtual void setCaptureState(bool capturing) = 0;
    virtual void showMessage(const std::string& message) = 0;
    virtual void showError(const std::string& error) = 0;
    
    std::function<void(int deviceNumber)> onStartCapture;
    std::function<void()> onStopCapture;
    std::function<void()> onClearPackets;
    std::function<void(int deviceIndex)> onDeviceChanged;
    std::function<void(const std::string& filter)> onFilterChanged;
    std::function<void(int packetIndex)> onPacketSelected;
    std::function<void(const std::string& filename)> onExportCSV;
    std::function<void(const std::string& filename)> onExportText;
    std::function<void(const std::string& path)> onSnifferPathChanged;
};

class IPacketSnifferPresenter {
public:
    virtual ~IPacketSnifferPresenter() = default;
    
    // Lifecycle
    virtual void initialize() = 0;
    virtual void shutdown() = 0;
    
    // Capture control
    virtual void startCapture(int deviceNumber) = 0;
    virtual void stopCapture() = 0;
    
    // Data operations
    virtual void clearPackets() = 0;
    virtual void applyFilter(const std::string& filter) = 0;
    virtual void selectPacket(int index) = 0;
    
    // Export
    virtual void exportToCSV(const std::string& filename) = 0;
    virtual void exportToText(const std::string& filename) = 0;
    
    // Configuration
    virtual void setDeviceIndex(int index) = 0;
    virtual void setSnifferPath(const std::string& path) = 0;
    
    // Statistics
    virtual void updateStatistics() = 0;
};

class IPacketRepository {
public:
    virtual ~IPacketRepository() = default;
    
    // CRUD operations
    virtual void add(PacketDataPtr packet) = 0;
    virtual void clear() = 0;
    virtual PacketDataPtr get(int index) const = 0;
    virtual std::vector<PacketDataPtr> getAll() const = 0;
    virtual std::vector<PacketDataPtr> getFiltered(
        const std::string& filter) const = 0;
    
    // Query operations
    virtual int count() const = 0;
    virtual int filteredCount(const std::string& filter) const = 0;
    virtual uint64_t totalBytes() const = 0;
    
    // Statistics
    virtual std::map<std::string, int> getProtocolStats() const = 0;
    virtual std::map<std::string, int> getIPStats() const = 0;
};

class ICaptureService {
public:
    virtual ~ICaptureService() = default;
    
    // Capture control
    virtual void start(int deviceNumber) = 0;
    virtual void stop() = 0;
    virtual bool isCapturing() const = 0;
    
    // Device management
    virtual std::vector<std::string> getDevices() = 0;
    virtual std::string getDeviceName(int index) const = 0;
    
    // Configuration
    virtual void setSnifferPath(const std::string& path) = 0;
    
    // Callbacks 
    std::function<void(PacketDataPtr)> onPacketCaptured;
    std::function<void()> onCaptureStarted;
    std::function<void()> onCaptureStopped;
    std::function<void(const std::string&)> onError;
};

class IPacketProcessor {
public:
    virtual ~IPacketProcessor() = default;
    
    // Process packet 
    virtual PacketDataPtr process(PacketDataPtr packet) = 0;
    
    // Get statistics
    virtual uint64_t getProcessedCount() const = 0;
    virtual uint64_t getFilteredCount() const = 0;
};

#endif // MVP_INTERFACES_H
