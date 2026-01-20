#ifndef PIPE_SNIFFER_INTEGRATED_H
#define PIPE_SNIFFER_INTEGRATED_H

#include <QObject>
#include <QTimer>
#include <QMutex>
#include <QQueue>
#include <memory>
#include <chrono>
#include "packet_runner.h"
#include "packetdata.h"

class PipeSnifferIntegrated : public QObject {
    Q_OBJECT
    
public:
    explicit PipeSnifferIntegrated(QObject* parent = nullptr);
    ~PipeSnifferIntegrated();

    bool startCapture(int deviceNumber);
    void stopCapture();
    
    bool isCapturing() const;
    quint64 getPacketCount() const;
    
    // Get available devices
    QStringList getDeviceList() const;
    
    // UI update interval in ms
    void setUpdateInterval(int ms);
    int updateInterval() const;
    
signals:
    void packetCaptured(PacketDataPtr packet);
    void packetsBatchReady(QVector<PacketDataPtr> packets);
    void captureStarted();
    void captureStopped();
    void errorOccurred(const QString& error);
    void logMessage(const QString& message);
    
    // Internal signals for thread-safe delivery
    void packetReceived(const QString& jsonPacket);
    void logReceived(const QString& message);
    void errorReceived(const QString& error);
    
private slots:
    void onPacketReceived(const QString& jsonPacket);
    void onLogReceived(const QString& message);
    void onErrorReceived(const QString& error);
    void onFlushTimer();
    
private:
    PacketDataPtr parseJSONPacket(const QString& jsonData);
    
    std::unique_ptr<PacketRunner> m_runner;
    quint64 m_packetNumber;
    
    // Batching for UI
    QTimer* m_flushTimer;
    QMutex m_pendingMutex;
    QVector<PacketDataPtr> m_pendingPackets;
    int m_updateIntervalMs;
};

#endif // PIPE_SNIFFER_INTEGRATED_H
