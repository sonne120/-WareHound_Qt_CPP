#ifndef PACKETMODEL_H
#define PACKETMODEL_H

#include <QAbstractTableModel>
#include <QVector>
#include <QTimer>
#include "packetdata.h"

class PacketModel : public QAbstractTableModel {
    Q_OBJECT
    
public:
    enum Column {
        Number = 0,
        Time,
        SourceIP,
        DestIP,
        Protocol,
        Length,
        Info,
        ColumnCount
    };
    
    explicit PacketModel(QObject* parent = nullptr);
    
    // QAbstractTableModel interface
    int rowCount(const QModelIndex& parent = QModelIndex()) const override;
    int columnCount(const QModelIndex& parent = QModelIndex()) const override;
    QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override;
    
    // Custom methods
    void addPacket(PacketDataPtr packet);
    void setPackets(const std::vector<PacketDataPtr>& packets);
    PacketDataPtr getPacket(int row) const;
    void clear();
    int packetCount() const { return m_packets.size(); }
    
    // Filter support
    void setFilter(const QString& filter);
    QString getFilter() const { return m_filter; }
    
signals:
    void packetAdded(int row);

private slots:
    void processPendingPackets();
    
private:
    QVector<PacketDataPtr> m_packets;
    QString m_filter;
    
    // Batching optimization
    QVector<PacketDataPtr> m_pendingPackets;
    QTimer* m_batchTimer;
    static const int MAX_PACKETS = 100000; // Circular buffer limit
    
    bool matchesFilter(PacketDataPtr packet) const;
};

#endif // PACKETMODEL_H
