#include "pipe_sniffer_integrated.h"
#include <QJsonDocument>
#include <QJsonObject>
#include <QDateTime>
#include <QMutexLocker>

PipeSnifferIntegrated::PipeSnifferIntegrated(QObject* parent)
    : QObject(parent)
    , m_runner(std::make_unique<PacketRunner>())
    , m_packetNumber(0)
    , m_flushTimer(new QTimer(this))
    , m_updateIntervalMs(100) {
    
    connect(this, &PipeSnifferIntegrated::packetReceived,
            this, &PipeSnifferIntegrated::onPacketReceived,
            Qt::QueuedConnection);
    
    connect(this, &PipeSnifferIntegrated::logReceived,
            this, &PipeSnifferIntegrated::onLogReceived,
            Qt::QueuedConnection);
    
    connect(this, &PipeSnifferIntegrated::errorReceived,
            this, &PipeSnifferIntegrated::onErrorReceived,
            Qt::QueuedConnection);
    
    // Timer to flush pending packets to UI
    connect(m_flushTimer, &QTimer::timeout,
            this, &PipeSnifferIntegrated::onFlushTimer);
}

PipeSnifferIntegrated::~PipeSnifferIntegrated() {
    stopCapture();
}

bool PipeSnifferIntegrated::startCapture(int deviceNumber) {
    if (m_runner->isCapturing()) {
        emit errorOccurred("Capture already in progress");
        return false;
    }
    
    m_runner->deviceNumber = deviceNumber;
    m_packetNumber = 0;
    
    // Start capture with callbacks that emit Qt signals
    m_runner->startCapture(
      
        [this](const std::string& jsonPacket) {          
            emit packetReceived(QString::fromStdString(jsonPacket));
        },
      
        [this](const std::string& message) {
            emit logReceived(QString::fromStdString(message));
        },
     
        [this](const std::string& error) {
            emit errorReceived(QString::fromStdString(error));
        }
    );
    
    emit captureStarted();
    m_flushTimer->start(m_updateIntervalMs);
    return true;
}

void PipeSnifferIntegrated::stopCapture() {
    if (!m_runner->isCapturing()) {
        return;
    }
    
    m_flushTimer->stop();
    
    onFlushTimer();
    
    m_runner->stopCapture();
    emit captureStopped();
}

bool PipeSnifferIntegrated::isCapturing() const {
    return m_runner->isCapturing();
}

quint64 PipeSnifferIntegrated::getPacketCount() const {
    return m_runner->getPacketCount();
}

QStringList PipeSnifferIntegrated::getDeviceList() const {
    QStringList devices;
    std::vector<std::string> devList = m_runner->getDeviceList();
    for (const auto& dev : devList) {
        devices.append(QString::fromStdString(dev));
    }
    return devices;
}

void PipeSnifferIntegrated::setUpdateInterval(int ms) {
    m_updateIntervalMs = qMax(10, ms);
    if (m_flushTimer->isActive()) {
        m_flushTimer->setInterval(m_updateIntervalMs);
    }
}

int PipeSnifferIntegrated::updateInterval() const {
    return m_updateIntervalMs;
}

void PipeSnifferIntegrated::onPacketReceived(const QString& jsonPacket) {

    PacketDataPtr packet = parseJSONPacket(jsonPacket);
    if (packet) {
        m_packetNumber++;
        packet->packetNumber = m_packetNumber;
        
        QMutexLocker lock(&m_pendingMutex);
        m_pendingPackets.append(packet);
    }
}

void PipeSnifferIntegrated::onFlushTimer() {

    QVector<PacketDataPtr> toSend;
    {
        QMutexLocker lock(&m_pendingMutex);
        if (m_pendingPackets.isEmpty()) {
            return;
        }
        toSend = std::move(m_pendingPackets);
        m_pendingPackets.clear();
    }
    
    if (!toSend.isEmpty()) {
        emit packetsBatchReady(toSend);
        
        for (const auto& packet : toSend) {
            emit packetCaptured(packet);
        }
    }
}

void PipeSnifferIntegrated::onLogReceived(const QString& message) {
    emit logMessage(message);
}

void PipeSnifferIntegrated::onErrorReceived(const QString& error) {
    emit errorOccurred(error);
}

PacketDataPtr PipeSnifferIntegrated::parseJSONPacket(const QString& jsonData) {
    QJsonDocument doc = QJsonDocument::fromJson(jsonData.toUtf8());
    
    if (!doc.isObject()) {
        return nullptr;
    }
    
    QJsonObject obj = doc.object();
    
    auto packet = std::make_shared<PacketData>();
    
    packet->timestamp = QDateTime::currentDateTime();
    packet->sourceIP = obj["source_ip"].toString();
    packet->destIP = obj["dest_ip"].toString();
    packet->sourcePort = obj["source_port"].toInt();
    packet->destPort = obj["dest_port"].toInt();
    packet->protocol = obj["proto"].toString().trimmed();
    packet->sourceMac = obj["source_mac"].toString();
    packet->destMac = obj["dest_mac"].toString();
    packet->length = obj["length"].toInt(64);
    
    packet->srcIp = packet->sourceIP;
    packet->dstIp = packet->destIP;
    packet->srcPort = packet->sourcePort;
    packet->dstPort = packet->destPort;
    packet->srcMac = packet->sourceMac;
    packet->dstMac = packet->destMac;
    
    // Build info string
    QString hostName = obj["host_name"].toString();
    packet->hostName = hostName; // Store in packet data
    int id = obj["id"].toInt();
    
    if (packet->sourcePort > 0 && packet->destPort > 0) {
        packet->info = QString("Port %1 → %2 | Host: %3 | ID: %4")
                          .arg(packet->sourcePort)
                          .arg(packet->destPort)
                          .arg(hostName)
                          .arg(id);
    } else {
        packet->info = QString("Host: %1 | ID: %2")
                          .arg(hostName)
                          .arg(id);
    }
    
    if (packet->sourcePort == 80 || packet->destPort == 80) {
        packet->protocol = "HTTP";
    } else if (packet->sourcePort == 443 || packet->destPort == 443) {
        packet->protocol = "HTTPS";
    } else if (packet->sourcePort == 22 || packet->destPort == 22) {
        packet->protocol = "SSH";
    } else if (packet->sourcePort == 53 || packet->destPort == 53) {
        packet->protocol = "DNS";
    }
    
    // Generate sample raw data
    QByteArray rawData;
    // Ethernet header (14 bytes)
    rawData.append(QByteArray::fromHex("aabbccddeeff"));  // Dest MAC
    rawData.append(QByteArray::fromHex("001122334455"));  // Src MAC
    rawData.append(QByteArray::fromHex("0800"));          // EtherType (IPv4)
    
    // IP header (20 bytes)
    rawData.append(QByteArray::fromHex("45"));            // Version + IHL
    rawData.append(QByteArray::fromHex("00"));            // DSCP
    rawData.append(QByteArray::fromHex("0040"));          // Total Length
    rawData.append(QByteArray::fromHex("1234"));          // ID
    rawData.append(QByteArray::fromHex("4000"));          // Flags + Fragment
    rawData.append(QByteArray::fromHex("40"));            // TTL
    rawData.append(QByteArray::fromHex("06"));            // Protocol (TCP)
    rawData.append(QByteArray::fromHex("0000"));          // Checksum
    // Source IP
    QStringList srcParts = packet->srcIp.split('.');
    for (const QString& part : srcParts) {
        rawData.append(static_cast<char>(part.toInt()));
    }
    // Dest IP
    QStringList dstParts = packet->dstIp.split('.');
    for (const QString& part : dstParts) {
        rawData.append(static_cast<char>(part.toInt()));
    }
    
    // TCP header (20 bytes)
    rawData.append(static_cast<char>((packet->srcPort >> 8) & 0xFF));
    rawData.append(static_cast<char>(packet->srcPort & 0xFF));
    rawData.append(static_cast<char>((packet->dstPort >> 8) & 0xFF));
    rawData.append(static_cast<char>(packet->dstPort & 0xFF));
    rawData.append(QByteArray::fromHex("00000001"));      // Seq
    rawData.append(QByteArray::fromHex("00000000"));      // Ack
    rawData.append(QByteArray::fromHex("5018"));          // Data offset + flags
    rawData.append(QByteArray::fromHex("ffff"));          // Window
    rawData.append(QByteArray::fromHex("0000"));          // Checksum
    rawData.append(QByteArray::fromHex("0000"));          // Urgent
    
    rawData.append("Mock packet payload data for testing hex dump display.");
    
    packet->rawData = rawData;
    
    return packet;
}
