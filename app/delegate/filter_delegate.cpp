#include "filter_delegate.h"
#include <QRegularExpression>

FilterDelegate::FilterDelegate(QObject* parent)
    : QObject(parent)
    , m_filterType(FilterType::Simple)
    , m_strategy(createSimpleStrategy())
{
}

void FilterDelegate::setFilterText(const QString& text) {
    QString newText = text.trimmed();
    if (m_filterText != newText) {
        m_filterText = newText;
        emit filterChanged(m_filterText);
    }
}

QString FilterDelegate::getFilterText() const {
    return m_filterText;
}

bool FilterDelegate::matches(const PacketDataPtr& packet) const {
    if (!packet) {
        return false;
    }
    
    if (!isActive()) {
        return true;
    }
    
    // Use advanced parsing 
    if (m_filterType == FilterType::Advanced) {
        return matchesAdvanced(packet);
    }
    
    // Use the current strategy
    return m_strategy(packet, m_filterText);
}

void FilterDelegate::clear() {
    setFilterText("");
}

bool FilterDelegate::isActive() const {
    return !m_filterText.isEmpty();
}

void FilterDelegate::setStrategy(FilterStrategy strategy) {
    if (strategy) {
        m_strategy = strategy;
    }
}

void FilterDelegate::setFilterType(FilterType type) {
    m_filterType = type;
    
    switch (type) {
        case FilterType::Simple:
            m_strategy = createSimpleStrategy();
            break;
        case FilterType::Protocol:
            m_strategy = createProtocolStrategy();
            break;
        case FilterType::IP:
            m_strategy = createIPStrategy();
            break;
        case FilterType::Port:
            m_strategy = createPortStrategy();
            break;
        case FilterType::HostName:
            m_strategy = createHostNameStrategy();
            break;
        case FilterType::Advanced:
            m_strategy = createAdvancedStrategy();
            break;
    }
}

FilterDelegate::FilterType FilterDelegate::getFilterType() const {
    return m_filterType;
}

FilterStrategy FilterDelegate::createSimpleStrategy() {
    return [](const PacketDataPtr& packet, const QString& filterText) -> bool {
        if (filterText.isEmpty()) {
            return true;
        }
        
        QString search = filterText.toLower();
        
        // Build searchable string from all packet fields
        QString searchIn = QString("%1 %2 %3 %4 %5 %6 %7 %8")
            .arg(packet->sourceIP)
            .arg(packet->destIP)
            .arg(packet->protocol)
            .arg(packet->sourcePort)
            .arg(packet->destPort)
            .arg(packet->info)
            .arg(packet->sourceMac)
            .arg(packet->destMac)
            .toLower();
        
       
        QStringList terms = search.split(' ', Qt::SkipEmptyParts);
        for (const QString& term : terms) {
            if (!searchIn.contains(term)) {
                return false;
            }
        }
        
        return true;
    };
}

FilterStrategy FilterDelegate::createProtocolStrategy() {
    return [](const PacketDataPtr& packet, const QString& filterText) -> bool {
        if (filterText.isEmpty()) {
            return true;
        }
        
        QString protocol = packet->protocol.toLower();
        QString search = filterText.toLower();
        
        // Support multiple protocols with OR (comma or pipe separated)
        QStringList protocols = search.split(QRegularExpression("[,|]"), Qt::SkipEmptyParts);
        for (const QString& p : protocols) {
            if (protocol.contains(p.trimmed())) {
                return true;
            }
        }
        
        return protocols.isEmpty(); 
    };
}

FilterStrategy FilterDelegate::createIPStrategy() {
    return [](const PacketDataPtr& packet, const QString& filterText) -> bool {
        if (filterText.isEmpty()) {
            return true;
        }
        
        QString search = filterText.toLower();
        QString srcIP = packet->sourceIP.toLower();
        QString dstIP = packet->destIP.toLower();
        
        // Support partial IP matching
        return srcIP.contains(search) || dstIP.contains(search);
    };
}

FilterStrategy FilterDelegate::createPortStrategy() {
    return [](const PacketDataPtr& packet, const QString& filterText) -> bool {
        if (filterText.isEmpty()) {
            return true;
        }
        
        // Extract port number from filter
        bool ok;
        int port = filterText.toInt(&ok);
        if (!ok) {
            return true; // Invalid port number, show all
        }
        
        return packet->sourcePort == port || packet->destPort == port;
    };
}

FilterStrategy FilterDelegate::createHostNameStrategy() {
    return [](const PacketDataPtr& packet, const QString& filterText) -> bool {
        if (filterText.isEmpty()) {
            return true;
        }
        
        QString search = filterText.toLower().trimmed();
        QString hostName = packet->hostName.toLower();
        
        if (search == "none" || search == "unknown" || search == "no") {
            return hostName.isEmpty() || hostName == "unknown";
        } else if (search == "has" || search == "known" || search == "yes") {
            return !hostName.isEmpty() && hostName != "unknown";
        }
        
        return hostName.contains(search);
    };
}

FilterStrategy FilterDelegate::createAdvancedStrategy() {
    return [](const PacketDataPtr& packet, const QString& filterText) -> bool {
        if (filterText.isEmpty()) {
            return true;
        }
        
        QString search = filterText.toLower();
        QString searchIn = QString("%1 %2 %3")
            .arg(packet->sourceIP)
            .arg(packet->destIP)
            .arg(packet->protocol)
            .toLower();
        
        return searchIn.contains(search);
    };
}

bool FilterDelegate::matchesAdvanced(const PacketDataPtr& packet) const {
    // Parse expressions like:
    // - "ip.src == 192.168.1.1"
    // - "tcp.port == 80"
    // - "protocol == TCP"
    // - "ip.dst contains 192.168"
    
    QString expr = m_filterText.toLower().trimmed();
    
    // Simple protocol filter: just "tcp", "udp", "icmp"
    if (expr == "tcp" || expr == "udp" || expr == "icmp" || expr == "arp" || expr == "dns" || expr == "http") {
        return packet->protocol.toLower() == expr;
    }
    
    // Parse "field operator value" expressions
    QRegularExpression re(R"((\w+(?:\.\w+)?)\s*(==|!=|contains)\s*(.+))");
    QRegularExpressionMatch match = re.match(expr);
    
    if (match.hasMatch()) {
        QString field = match.captured(1).toLower();
        QString op = match.captured(2);
        QString value = match.captured(3).trimmed();
        
        QString fieldValue;
        
        if (field == "ip.src" || field == "src" || field == "source") {
            fieldValue = packet->sourceIP.toLower();
        } else if (field == "ip.dst" || field == "dst" || field == "dest" || field == "destination") {
            fieldValue = packet->destIP.toLower();
        } else if (field == "protocol" || field == "proto") {
            fieldValue = packet->protocol.toLower();
        } else if (field == "tcp.srcport" || field == "udp.srcport" || field == "srcport") {
            fieldValue = QString::number(packet->sourcePort);
        } else if (field == "tcp.dstport" || field == "udp.dstport" || field == "dstport") {
            fieldValue = QString::number(packet->destPort);
        } else if (field == "port") {
            QString portVal = QString::number(packet->sourcePort) + " " + QString::number(packet->destPort);
            fieldValue = portVal;
        } else if (field == "info") {
            fieldValue = packet->info.toLower();
        } else if (field == "mac.src" || field == "eth.src") {
            fieldValue = packet->sourceMac.toLower();
        } else if (field == "mac.dst" || field == "eth.dst") {
            fieldValue = packet->destMac.toLower();
        } else {

            return m_strategy(packet, m_filterText);
        }
        
        // Apply operator
        if (op == "==") {
            return fieldValue == value.toLower();
        } else if (op == "!=") {
            return fieldValue != value.toLower();
        } else if (op == "contains") {
            return fieldValue.contains(value.toLower());
        }
    }
    
    // Fall back to simple matching
    return m_strategy(packet, m_filterText);
}

std::shared_ptr<IFilterDelegate> FilterDelegateFactory::create(FilterDelegate::FilterType type) {
    auto delegate = std::make_shared<FilterDelegate>();
    delegate->setFilterType(type);
    return delegate;
}
