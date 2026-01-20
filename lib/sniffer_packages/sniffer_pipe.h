#ifndef SNIFFER_PIPE_H
#define SNIFFER_PIPE_H

/**
 * sniffer_pipe.h - Pipe Output Interface (like AlgorithmApp pattern)
 * 
 * This provides the function that the Qt app calls to capture packets
 * and write them to a pipe. The app creates the pipes, spawns a thread,
 * and reads the output - exactly like AlgorithmApp's CollatzRunner.
 * 
 * Usage in Qt app:
 *   1. Create pipes: pipe(packet_fd), pipe(log_fd)
 *   2. Spawn thread calling sniffer_capture_and_write_pipe()
 *   3. Read JSON packets from packet_fd[0]
 *   4. Read log messages from log_fd[0]
 */

#include <atomic>
#include <cstdint>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Capture packets and write JSON to pipe
 * 
 * @param device_number  Network device index (1-based)
 * @param result_fd      Write end of packet pipe (JSON lines)
 * @param log_fd         Write end of log pipe
 * @param running        Atomic flag to control capture (set false to stop)
 * @return 0 on success, -1 on error
 * 
 * JSON output format per packet:
 * {
 *   "id": 1,
 *   "timestamp": "2026-01-09 12:34:56",
 *   "source_ip": "192.168.1.100",
 *   "dest_ip": "8.8.8.8",
 *   "source_port": 54321,
 *   "dest_port": 443,
 *   "proto": "TCP",
 *   "length": 1500,
 *   "source_mac": "00:11:22:33:44:55",
 *   "dest_mac": "AA:BB:CC:DD:EE:FF",
 *   "host_name": "dns.google"
 * }
 */
int sniffer_capture_and_write_pipe(
    int device_number,
    int result_fd,
    int log_fd,
    std::atomic<bool>* running
);

/**
 * Get list of available network devices
 * 
 * @param devices_json   Output buffer for JSON array of devices
 * @param buffer_size    Size of output buffer
 * @return Number of devices found, -1 on error
 */
int sniffer_get_devices(char* devices_json, int buffer_size);

#ifdef __cplusplus
}
#endif

#endif // SNIFFER_PIPE_H
