#include "ipc.h"
#include <iostream>
#include <cstring>
#include "builderDevice.h"

#ifdef _WIN32
#include <atlsafe.h>
#include <tchar.h>
#include <windows.h>
#include <thread>
#include <stop_token>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <vector>

std::atomic_bool quit_flag(false);
std::atomic<int> d1;
std::mutex m;
std::condition_variable cv;
pcap_t* _adhandle1 = nullptr;
#ifdef _WIN32
HANDLE hPipe = INVALID_HANDLE_VALUE;
#else
int global_pipe_fd = -1;
#endif

static std::jthread mainThread;
HANDLE eventHandle = NULL;

bool ConnectPipeClient() {
	const wchar_t* pipeName = L"\\\\.\\pipe\\testpipe";

	hPipe = CreateNamedPipeW(
		pipeName,
		PIPE_ACCESS_DUPLEX,
		PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
		PIPE_UNLIMITED_INSTANCES,
		4096, 4096,
		0,
		NULL
	);
	if (hPipe != INVALID_HANDLE_VALUE) {
		DWORD mode = PIPE_READMODE_MESSAGE;
		if (!SetNamedPipeHandleState(hPipe, &mode, nullptr, nullptr)) {
			std::wcerr << L"SetNamedPipeHandleState failed. GLE=" << GetLastError() << std::endl;
		}
		return true;
	}
		Sleep(500);
	
	std::wcerr << L"Failed to open pipe. GLE=" << GetLastError() << std::endl;
	return false;
}

// Exported functions
IPC_EXPORT void fnDevCPPDLL(char** data, int* sizes, int* count) {
	std::vector<std::string> listdev = builderDevice::Builder(0).ListDevices().Build().getDevices();
	*count = listdev.size();
	if (data) {
		for (int i = 0; i < *count; ++i) {
			sizes[i] = listdev[i].size();
			data[i] = new char[sizes[i] + 1];
			std::strcpy(data[i], listdev[i].c_str());
		}
	}
}

IPC_EXPORT void __stdcall fnCPPDLL(int d) {

	std::cout << "Attempt: YES " << std::endl;

	HANDLE eventHandle = NULL;
	DWORD IDThread;
	const WCHAR* name = L"Global\\sniffer";
	int attempt = 0;
	while ((eventHandle = OpenEventW(EVENT_MODIFY_STATE | SYNCHRONIZE, FALSE, name)) == NULL && attempt < 200000) {
		Sleep(1000); ++attempt;
		std::cout << "Attempt: " << attempt << std::endl;
	}

	if (ConnectPipeClient() == true) {
		std::cout << "Named pipe created" << std::endl;
		if (hPipe == INVALID_HANDLE_VALUE) {
			DWORD le = GetLastError();
			std::cout << "CreateNamedPipe failed. GLE=" << le << std::endl;
		}
		else {
			BOOL connected = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
			if (!connected) {
				DWORD le = GetLastError();
				std::cout << "ConnectNamedPipe failed. GLE=" << le << std::endl;
				CloseHandle(hPipe);
				hPipe = INVALID_HANDLE_VALUE;
			}
			else {
				std::cout << "Named pipe connected" << std::endl;
			}
		}
	}

	WaitForSingleObject(eventHandle, INFINITE);

	try {
		mainThread = std::jthread(
			[](std::stop_token st, HANDLE eventHandle) {
				while (!st.stop_requested()) {
					mainFunc(eventHandle);
				}
			},
			eventHandle
		);

		std::cout << "main thread started" << std::endl;
	}
	catch (const std::exception& e) {
		std::cout << "Failed to start main thread : "
			<< e.what() << std::endl;
	}
	catch (...) {
		std::cout << "Failed to start main thread" << std::endl;
	}
}

IPC_EXPORT void __stdcall fnPutdevCPPDLL(int dev) {
   
	d1 = dev; _adhandle1 = nullptr;
	builderDevice::Builder builder(dev);
	if (quit_flag) quit_flag = false;
	std::this_thread::sleep_for(std::chrono::milliseconds(20));
	_adhandle1 = builder.FindDevices()
		.SelectDevice()
		.OpenSelectedDevice()
		.Build()
		.getHandler();
	{
		std::unique_lock<std::mutex> lock(m);
		quit_flag = true;
	}
	cv.notify_one();
	std::this_thread::sleep_for(std::chrono::milliseconds(20));
}

IPC_EXPORT void __stdcall fnStop()
{
	if (mainThread.joinable()) {
		mainThread.request_stop();
		if (eventHandle) SetEvent(eventHandle);  
		mainThread.join();                       
	}

	if (hPipe != INVALID_HANDLE_VALUE) {
		CloseHandle(hPipe);
		hPipe = INVALID_HANDLE_VALUE;
	}
	if (eventHandle) {
		CloseHandle(eventHandle);
		eventHandle = NULL;
	}
}

#else // Unix/Linux
#include <chrono>
#include <thread>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

// Global variable definitions
std::atomic_bool quit_flag(false);
std::atomic<int> d1;
std::mutex m;
std::condition_variable cv;
pcap_t* _adhandle1 = nullptr;

// POSIX FIFO path
static const char* PIPE_PATH = "/tmp/testpipe";
int global_pipe_fd = -1;

// Initialize and open FIFO
static void init_pipe() {
	mkfifo(PIPE_PATH, 0666);
	global_pipe_fd = open(PIPE_PATH, O_WRONLY | O_NONBLOCK);
	if (global_pipe_fd == -1) std::cerr << "FIFO open error: " << strerror(errno) << std::endl;
}

// Exported functions
IPC_EXPORT void fnDevCPPDLL(char** data, int* sizes, int* count) {
	std::vector<std::string> listdev = builderDevice::Builder(0).ListDevices().Build().getDevices();
	*count = listdev.size();
	if (data) {
		for (int i = 0; i < *count; ++i) {
			sizes[i] = listdev[i].size();
			data[i] = new char[sizes[i] + 1];
			std::strcpy(data[i], listdev[i].c_str());
		}
	}
}

IPC_EXPORT void fnCPPDLL(int d) {
	std::thread t([d]() {
		init_pipe();
		mainFunc((HANDLE)0, d);
		});
	t.detach();
	std::cout << "main thread started (Linux)" << std::endl;
}

IPC_EXPORT void fnPutdevCPPDLL(int dev) {
	d1 = dev; _adhandle1 = nullptr;
	builderDevice::Builder builder(dev);
	if (quit_flag) quit_flag = false;
	std::this_thread::sleep_for(std::chrono::milliseconds(2000));
	_adhandle1 = builder.FindDevices().SelectDevice().OpenSelectedDevice().Build().getHandler();
	{
		std::unique_lock<std::mutex> lock(m);
		quit_flag = true;
	}
	cv.notify_one();
	std::this_thread::sleep_for(std::chrono::milliseconds(20));
}
#endif
