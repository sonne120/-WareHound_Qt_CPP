#ifndef PACKETDATA_H
#define PACKETDATA_H

#include <QString>
#include <QDateTime>
#include <QByteArray>
#include <memory>

struct PacketData {
    quint64 packetNumber;
    QDateTime timestamp;
    QString sourceIP;
    QString destIP;
    QString srcIp;  
    QString dstIp;  
    quint16 sourcePort;
    quint16 destPort;
    quint16 srcPort;
    quint16 dstPort;
    QString protocol;
    quint32 length;
    QByteArray rawData;
    QString info;
    QString hostName; // Added hostName field
    
    // Ethernet information
    QString sourceMac;
    QString destMac;
    QString srcMac;
    QString dstMac;  
    
    // TCP flags
    bool flagSYN;
    bool flagACK;
    bool flagFIN;
    bool flagRST;
    bool flagPSH;
    bool flagURG;
    
    PacketData()
        : packetNumber(0)
        , sourcePort(0)
        , destPort(0)
        , srcPort(0)
        , dstPort(0)
        , length(0)
        , flagSYN(false)
        , flagACK(false)
        , flagFIN(false)
        , flagRST(false)
        , flagPSH(false)
        , flagURG(false)
    {
        // Sync aliases
        srcIp = sourceIP;
        dstIp = destIP;
        srcPort = sourcePort;
        dstPort = destPort;
        srcMac = sourceMac;
        dstMac = destMac;
    }
};

using PacketDataPtr = std::shared_ptr<PacketData>;

#endif // PACKETDATA_H
