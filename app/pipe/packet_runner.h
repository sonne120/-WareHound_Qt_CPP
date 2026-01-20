#ifndef PACKET_RUNNER_H
#define PACKET_RUNNER_H

#include <string>
#include <cstdint>
#include <functional>
#include <atomic>
#include <thread>
#include <vector>

#ifdef _WIN32
    #include <fcntl.h>
    #include <io.h>
    // Windows pipe implementation
    inline int pipe(int fds[2]) {
        return _pipe(fds, 65536, _O_BINARY);
    }
    #define read _read
    #define write _write
    #define close _close
#else
    #include <unistd.h>
#endif

// Include sniffer library headers
#include "struct.h"
#include "builderDevice.h"
#include "ipc.h"
#include "packages.h"

class PacketRunner {
public:
    PacketRunner();
    ~PacketRunner();
    
    // Callback types
    using PacketCallback = std::function<void(const std::string& jsonPacket)>;
    using LogCallback = std::function<void(const std::string& message)>;
    using ErrorCallback = std::function<void(const std::string& error)>;
    
    // Configuration
    int deviceNumber = 1;
    
    std::vector<std::string> getDeviceList();
    
    void startCapture(PacketCallback packetCallback = nullptr,
                      LogCallback logCallback = nullptr,
                      ErrorCallback errorCallback = nullptr);
    
    void stopCapture();
    
    bool isCapturing() const { return m_running.load(); }
    
    uint64_t getPacketCount() const { return m_packetCount.load(); }
    
private:
    void captureWorker(int packet_fd, int log_fd);
    
    std::atomic<bool> m_running{false};
    std::atomic<uint64_t> m_packetCount{0};
    
    // Threads
    std::thread m_captureThread;
    std::thread m_packetReaderThread;
    std::thread m_logReaderThread;
    
    // Pipe file descriptors
    int m_packetPipe[2] = {-1, -1};  // [0] = read, [1] = write
    int m_logPipe[2] = {-1, -1};
};

#endif // PACKET_RUNNER_H
