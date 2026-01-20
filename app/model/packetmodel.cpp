#include "packetmodel.h"
#include <QColor>
#include <QFont>
#include <QTimer>

PacketModel::PacketModel(QObject* parent)
    : QAbstractTableModel(parent)
    , m_batchTimer(new QTimer(this)) {
    
    // Configure batch update timer
    connect(m_batchTimer, &QTimer::timeout, this, &PacketModel::processPendingPackets);
    m_batchTimer->start(100); 
}

int PacketModel::rowCount(const QModelIndex& parent) const {
    if (parent.isValid()) {
        return 0;
    }
    return m_packets.size();
}

int PacketModel::columnCount(const QModelIndex& parent) const {
    if (parent.isValid()) {
        return 0;
    }
    return ColumnCount;
}

QVariant PacketModel::data(const QModelIndex& index, int role) const {
    if (!index.isValid() || index.row() >= m_packets.size()) {
        return QVariant();
    }
    
    const PacketDataPtr& packet = m_packets[index.row()];
    

    if (role == Qt::DisplayRole) {
        switch (index.column()) {
            case Number:
                return QString::number(packet->packetNumber);
            case Time:
                return packet->timestamp.toString("hh:mm:ss.zzz");
            case SourceIP:
                return packet->sourceIP.isEmpty() ? "N/A" : packet->sourceIP;
            case DestIP:
                return packet->destIP.isEmpty() ? "N/A" : packet->destIP;
            case Protocol:
                return packet->protocol.isEmpty() ? "Unknown" : packet->protocol;
            case Length:
                return QString::number(packet->length);
            case Info:
                return packet->info.isEmpty() ? "No Info" : packet->info;
            default:
                return "Invalid Col";
        }
    } 
    
    return QVariant();
}

QVariant PacketModel::headerData(int section, Qt::Orientation orientation, int role) const {
    if (orientation != Qt::Horizontal || role != Qt::DisplayRole) {
        return QVariant();
    }
    
    switch (section) {
        case Number:
            return "No.";
        case Time:
            return "Time";
        case SourceIP:
            return "Source";
        case DestIP:
            return "Destination";
        case Protocol:
            return "Protocol";
        case Length:
            return "Length";
        case Info:
            return "Info";
        default:
            return QVariant();
    }
}

void PacketModel::addPacket(PacketDataPtr packet) {
    if (!matchesFilter(packet)) {
        return;
    }
    
    m_pendingPackets.append(packet);
}

void PacketModel::processPendingPackets() {
    if (m_pendingPackets.isEmpty()) {
        return;
    }

    int startRow = m_packets.size();
    int count = m_pendingPackets.size();

    beginInsertRows(QModelIndex(), startRow, startRow + count - 1);
    m_packets.append(m_pendingPackets);
    m_pendingPackets.clear();
    
    if (m_packets.size() > MAX_PACKETS) {
     // TO DO
    }
    
    endInsertRows();

    // Scroll hint
    emit packetAdded(m_packets.size() - 1);
}

void PacketModel::setPackets(const std::vector<PacketDataPtr>& packets) {

    beginResetModel();
    m_packets.clear();
    int matchCount = 0;
    for (const auto& packet : packets) {
        bool matches = matchesFilter(packet);
        if (matches) {
            m_packets.append(packet);
            matchCount++;
        }
    }
    endResetModel();

    if (!m_packets.isEmpty()) {
        emit dataChanged(index(0, 0), index(m_packets.size() - 1, ColumnCount - 1));
    }
}

PacketDataPtr PacketModel::getPacket(int row) const {
    if (row < 0 || row >= m_packets.size()) {
        return nullptr;
    }
    return m_packets[row];
}

void PacketModel::clear() {
    beginResetModel();
    m_packets.clear();
    endResetModel();
}

void PacketModel::setFilter(const QString& filter) {
    m_filter = filter.trimmed().toLower();
    
    beginResetModel();
    endResetModel();
}

bool PacketModel::matchesFilter(PacketDataPtr packet) const {
    if (m_filter.isEmpty()) {
        return true;
    }
    
    // filter matching
    QString searchIn = QString("%1 %2 %3 %4 %5 %6 %7")
                          .arg(packet->sourceIP)
                          .arg(packet->destIP)
                          .arg(packet->protocol)
                          .arg(packet->sourcePort)
                          .arg(packet->destPort)
                          .arg(packet->info)
                          .arg(packet->sourceMac)
                          .toLower();
    
    // Split filter
    QStringList terms = m_filter.split(' ', Qt::SkipEmptyParts);
    for (const QString& term : terms) {
        if (!searchIn.contains(term)) {
            return false;
        }
    }
    
    return true;
}
