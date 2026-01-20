#ifndef FILTER_DELEGATE_H
#define FILTER_DELEGATE_H

#include <QString>
#include <QObject>
#include <memory>
#include <functional>
#include "packetdata.h"


using FilterStrategy = std::function<bool(const PacketDataPtr& packet, const QString& filterText)>;

class IFilterDelegate {
public:
    virtual ~IFilterDelegate() = default;
    
    virtual void setFilterText(const QString& text) = 0;
    
    virtual QString getFilterText() const = 0;
    
    virtual bool matches(const PacketDataPtr& packet) const = 0;
   
    virtual void clear() = 0;
    
    virtual bool isActive() const = 0;
    
    virtual void setStrategy(FilterStrategy strategy) = 0;
};


class FilterDelegate : public QObject, public IFilterDelegate {
    Q_OBJECT
    
public:

    enum class FilterType {
        Simple,         
        Protocol,     
        IP,            
        Port,          
        HostName,       // Filter by hostname presence
        Advanced        
    };
    
    explicit FilterDelegate(QObject* parent = nullptr);
    ~FilterDelegate() override = default;
    
    // IFilterDelegate interface
    void setFilterText(const QString& text) override;
    QString getFilterText() const override;
    bool matches(const PacketDataPtr& packet) const override;
    void clear() override;
    bool isActive() const override;
    void setStrategy(FilterStrategy strategy) override;
    
    // Additional methods
    void setFilterType(FilterType type);
    FilterType getFilterType() const;
    
    // Predefined filter strategies
    static FilterStrategy createSimpleStrategy();
    static FilterStrategy createProtocolStrategy();
    static FilterStrategy createIPStrategy();
    static FilterStrategy createPortStrategy();
    static FilterStrategy createHostNameStrategy();
    static FilterStrategy createAdvancedStrategy();

signals:

    void filterChanged(const QString& filterText);
    
private:
    QString m_filterText;
    FilterType m_filterType;
    FilterStrategy m_strategy;
    
    // Parse advanced filter  "ip.src == 192.168.1.1"
    bool matchesAdvanced(const PacketDataPtr& packet) const;
};


class FilterDelegateFactory {
public:
    static std::shared_ptr<IFilterDelegate> create(FilterDelegate::FilterType type = FilterDelegate::FilterType::Simple);
};

#endif // FILTER_DELEGATE_H
