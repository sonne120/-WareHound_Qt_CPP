#pragma once
#ifndef SNIFFER_H
#define SNIFFER_H

#include <vector>
#include <string>
#include <memory>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <functional>
#include <iostream>

#include "struct.h"
#include "packages.h" 

class Sniffer;

// 1. Observer/Pub-Sub Pattern
class IPacketSubscriber {
public:
    virtual ~IPacketSubscriber() = default;
    virtual void OnPacketCaptured(const tagSnapshot& packet) = 0;
};

// Thread-safe Queue (Buffer)
class PacketBuffer {
public:
    PacketBuffer(size_t maxSize = 100);
    void Push(const tagSnapshot& item);
    bool Pop(tagSnapshot& item);
    bool IsFull() const;
    bool IsEmpty() const;

private:
    std::queue<tagSnapshot> queue;
    mutable std::mutex mutex;
    std::condition_variable notEmpty;
    std::condition_variable notFull;
    size_t maxSize;
};

// Packet Capturer (Producer)
class PacketCapturer {
public:
    PacketCapturer(std::shared_ptr<PacketBuffer> buffer, HANDLE eventHandle);
    ~PacketCapturer();

    void Start(pcap_t* handle, std::atomic<bool>& running, HANDLE eventHandle = nullptr);
    void Stop();

private:
    void CaptureLoop(pcap_t* handle, std::atomic<bool>& running, HANDLE eventHandle);
    void ProcessPacket(const struct pcap_pkthdr* pkthdr, const u_char* packet);

    HANDLE _eventHandles;
    std::shared_ptr<PacketBuffer> buffer;
    std::thread captureThread;
    Packages parserHelper; 
};

// Packet Dispatcher/Processor (Consumer)
class PacketDispatcher {
public:
    PacketDispatcher(std::shared_ptr<PacketBuffer> buffer);
    ~PacketDispatcher();

    void Subscribe(std::shared_ptr<IPacketSubscriber> subscriber);
    void Start(std::atomic<bool>& running);
    void Stop();

private:
    void DispatchLoop(std::atomic<bool>& running);

    std::shared_ptr<PacketBuffer> buffer;
    std::vector<std::shared_ptr<IPacketSubscriber>> subscribers;
    std::thread dispatchThread;
};

// Concrete Subscriber: Pipe Writer (for Windows IPC or POSIX generic pipe)
class PipeWriterSubscriber : public IPacketSubscriber {
public:
    PipeWriterSubscriber();
    ~PipeWriterSubscriber();
    void OnPacketCaptured(const tagSnapshot& packet) override;
};

// 2. Builder Pattern
class SnifferBuilder {
public:
    SnifferBuilder();
    
    SnifferBuilder& UseDevice(int deviceIndex);
    SnifferBuilder& UseFile(const std::string& filename);
    SnifferBuilder& AddSubscriber(std::shared_ptr<IPacketSubscriber> subscriber);
    SnifferBuilder& SetEventHandle(HANDLE handle);
    SnifferBuilder& UseHandle(pcap_t* handle);
    
    std::unique_ptr<Sniffer> Build();

private:
    int deviceIndex;
    std::string filename;
    HANDLE eventHandle;
    pcap_t* existingHandle;
    std::vector<std::shared_ptr<IPacketSubscriber>> subscribers;
};


// Main Sniffer Class (Facade)
class Sniffer {
public:
    Sniffer(pcap_t* handle, std::vector<std::shared_ptr<IPacketSubscriber>> subscribers, HANDLE eventHandle = nullptr);
    ~Sniffer();

    void Start();
    void Stop();

private:
    pcap_t* handle;
    HANDLE eventHandle;
    std::shared_ptr<PacketBuffer> buffer;
    std::unique_ptr<PacketCapturer> capturer;
    std::unique_ptr<PacketDispatcher> dispatcher;
    std::atomic<bool> running;
};

#endif // SNIFFER_H
