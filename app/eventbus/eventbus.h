#ifndef EVENTBUS_H
#define EVENTBUS_H

#include <functional>
#include <unordered_map>
#include <vector>
#include <queue>
#include <mutex>
#include <any>
#include <chrono>
#include <memory>


enum class EventType {
    // Capture events
    PacketCaptured,
    CaptureStarted,
    CaptureStopped,
    CaptureError,
    
    // UI events
    DeviceListUpdated,
    FilterChanged,
    PacketSelected,
    
    // System events
    StatisticsUpdated,
    ErrorOccurred
};

class Event {
private:
    EventType m_type;
    std::any m_data;
    std::chrono::system_clock::time_point m_timestamp;
    std::string m_source;
    
public:
    Event(EventType type, std::any data = {}, const std::string& source = "")
        : m_type(type), m_data(std::move(data)), m_source(source),
          m_timestamp(std::chrono::system_clock::now()) {}
    
    EventType type() const { return m_type; }
    const std::string& source() const { return m_source; }
    auto timestamp() const { return m_timestamp; }
    
    template<typename T>
    T getData() const {
        return std::any_cast<T>(m_data);
    }
    
    template<typename T>
    bool hasData() const {
        return m_data.type() == typeid(T);
    }
};

class EventBus {
public:
    using Subscriber = std::function<void(const Event&)>;
    using SubscriptionId = size_t;
    
private:
    struct SubscriptionInfo {
        SubscriptionId id;
        Subscriber callback;
    };
    
    std::unordered_map<EventType, std::vector<SubscriptionInfo>> m_subscribers;
    std::queue<Event> m_eventQueue;
    mutable std::mutex m_mutex;
    SubscriptionId m_nextId{0};
    bool m_asyncProcessing{true};
    
public:
    EventBus(bool asyncProcessing = true) 
        : m_asyncProcessing(asyncProcessing) {}
    

    SubscriptionId subscribe(EventType type, Subscriber subscriber) {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        SubscriptionId id = m_nextId++;
        m_subscribers[type].push_back({id, std::move(subscriber)});
        
        return id;
    }
    

    void unsubscribe(SubscriptionId id) {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        for (auto& [type, subs] : m_subscribers) {
            auto it = std::remove_if(subs.begin(), subs.end(),
                [id](const SubscriptionInfo& info) {
                    return info.id == id;
                });
            subs.erase(it, subs.end());
        }
    }
    

    void unsubscribeAll(EventType type) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_subscribers[type].clear();
    }
    

    void publish(const Event& event) {
        if (m_asyncProcessing) {
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                m_eventQueue.push(event);
            }

        } else {
            publishSync(event);
        }
    }
    
    void publishSync(const Event& event) {
       
        std::vector<SubscriptionInfo> subscribers;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            auto it = m_subscribers.find(event.type());
            if (it != m_subscribers.end()) {
                subscribers = it->second;
            }
        }
        
        for (const auto& sub : subscribers) {
            try {
                sub.callback(event);
            } catch (const std::exception& e) {
                (void)e;
            }
        }
    }
    

    void processEvents() {
        std::queue<Event> events;
        
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            events.swap(m_eventQueue);
        }
        
        while (!events.empty()) {
            publishSync(events.front());
            events.pop();
        }
    }
    

    size_t subscriberCount(EventType type) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_subscribers.find(type);
        return (it != m_subscribers.end()) ? it->second.size() : 0;
    }
    
 
    bool hasSubscribers(EventType type) const {
        return subscriberCount(type) > 0;
    }
    
  
    void clear() {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_subscribers.clear();
        while (!m_eventQueue.empty()) {
            m_eventQueue.pop();
        }
    }
};

#endif // EVENTBUS_H
