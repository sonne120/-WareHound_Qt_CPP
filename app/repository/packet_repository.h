#ifndef PACKET_REPOSITORY_H
#define PACKET_REPOSITORY_H

#include <vector>
#include <map>
#include <mutex>
#include <algorithm>
#include <QString>
#include "mvp_interfaces.h"
#include "packetdata.h"

class PacketRepository : public IPacketRepository {
private:
    std::vector<PacketDataPtr> m_packets;
    mutable std::mutex m_mutex;
    uint64_t m_totalBytes{0};
    
    bool matchesFilter(const PacketDataPtr& packet, const std::string& filter) const {
        if (filter.empty()) return true;
        
        QString filterLower = QString::fromStdString(filter).toLower();
        
        // Check source IP
        if (packet->srcIp.toLower().contains(filterLower)) return true;
        
        // Check destination IP
        if (packet->dstIp.toLower().contains(filterLower)) return true;
        
        // Check protocol
        if (packet->protocol.toLower().contains(filterLower)) return true;
        
        // Check info
        if (packet->info.toLower().contains(filterLower)) return true;
        
        // Check ports if present
        QString portStr = QString::number(packet->srcPort);
        if (portStr.contains(filterLower)) return true;
        
        portStr = QString::number(packet->dstPort);
        if (portStr.contains(filterLower)) return true;
        
        return false;
    }
    
public:
    PacketRepository() = default;
    ~PacketRepository() override = default;
    
    void add(PacketDataPtr packet) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_packets.push_back(packet);
        m_totalBytes += packet->length;
    }
    
    void clear() override {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_packets.clear();
        m_totalBytes = 0;
    }
    
    PacketDataPtr get(int index) const override {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (index >= 0 && index < static_cast<int>(m_packets.size())) {
            return m_packets[index];
        }
        return nullptr;
    }
    
    std::vector<PacketDataPtr> getAll() const override {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_packets;
    }
    
    std::vector<PacketDataPtr> getFiltered(const std::string& filter) const override {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        if (filter.empty()) {
            return m_packets;
        }
        
        std::vector<PacketDataPtr> filtered;
        std::copy_if(m_packets.begin(), m_packets.end(), 
                    std::back_inserter(filtered),
                    [this, &filter](const PacketDataPtr& p) {
                        return matchesFilter(p, filter);
                    });
        return filtered;
    }
    
    int count() const override {
        std::lock_guard<std::mutex> lock(m_mutex);
        return static_cast<int>(m_packets.size());
    }
    
    int filteredCount(const std::string& filter) const override {
        return static_cast<int>(getFiltered(filter).size());
    }
    
    uint64_t totalBytes() const override {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_totalBytes;
    }
    
    std::map<std::string, int> getProtocolStats() const override {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::map<std::string, int> stats;
        for (const auto& packet : m_packets) {
            stats[packet->protocol.toStdString()]++;
        }
        return stats;
    }
    
    std::map<std::string, int> getIPStats() const override {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::map<std::string, int> stats;
        for (const auto& packet : m_packets) {
            stats[packet->srcIp.toStdString()]++;
            stats[packet->dstIp.toStdString()]++;
        }
        return stats;
    }
    
    uint64_t getTotalBytes() const {
        return totalBytes();
    }
};

#endif // PACKET_REPOSITORY_H
