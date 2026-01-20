
if(MSVC)
    add_compile_options(/W4 /EHsc /wd4324)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
else()
    add_compile_options(-pthread -fPIC)
endif()

# Find pcap library (libpcap on macOS/Linux, Npcap/WinPcap on Windows)
if(WIN32)
    # Windows: Look for Npcap SDK (preferred) or WinPcap
    set(NPCAP_SDK_DIR "C:/npcap-sdk" CACHE PATH "Npcap SDK directory")
    set(WINPCAP_SDK_DIR "C:/WpdPack" CACHE PATH "WinPcap SDK directory")
    
    if(EXISTS "${NPCAP_SDK_DIR}/Include")
        set(PCAP_INCLUDE_DIR "${NPCAP_SDK_DIR}/Include")
        if(CMAKE_SIZEOF_VOID_P EQUAL 8)
            set(PCAP_LIBRARY "${NPCAP_SDK_DIR}/Lib/x64/wpcap.lib")
        else()
            set(PCAP_LIBRARY "${NPCAP_SDK_DIR}/Lib/wpcap.lib")
        endif()
    elseif(EXISTS "${WINPCAP_SDK_DIR}/Include")
        set(PCAP_INCLUDE_DIR "${WINPCAP_SDK_DIR}/Include")
        if(CMAKE_SIZEOF_VOID_P EQUAL 8)
            set(PCAP_LIBRARY "${WINPCAP_SDK_DIR}/Lib/x64/wpcap.lib")
        else()
            set(PCAP_LIBRARY "${WINPCAP_SDK_DIR}/Lib/wpcap.lib")
        endif()
    else()
        message(FATAL_ERROR "Npcap or WinPcap SDK not found. Install Npcap SDK to ${NPCAP_SDK_DIR} or WinPcap to ${WINPCAP_SDK_DIR}")
    endif()
else()
    # macOS/Linux: Use libpcap
    find_library(PCAP_LIBRARY pcap REQUIRED)
    set(PCAP_INCLUDE_DIR "")
endif()

# Source files
set(SNIFFER_SOURCES
    mainFunc.cpp
    ipc.cpp
    packages_globals.cpp
    builderDevice.cpp
    sniffer_pipe.cpp
    Sniffer.cpp
)

# Header files
set(SNIFFER_HEADERS
    mainFunc.h
    ipc.h
    builderDevice.h
    packages.h
    struct.h
    handleProto.h
    ether_ntoa.h
    Sniffer.h
)

# Create static library (like collatzlib in AlgorithmApp)
add_library(snifferlib STATIC
    ${SNIFFER_SOURCES}
    ${SNIFFER_HEADERS}
)

# Include directories
target_include_directories(snifferlib PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${PCAP_INCLUDE_DIR}
)

# Link pcap library
target_link_libraries(snifferlib PUBLIC
    ${PCAP_LIBRARY}
)

# Windows-specific: Link Winsock
if(WIN32)
    target_link_libraries(snifferlib PUBLIC ws2_32)
endif()

# Platform-specific optimizations
if(MSVC)
    target_compile_options(snifferlib PRIVATE /O2)
else()
    target_compile_options(snifferlib PRIVATE -O2)
    # Only use -march=native on macOS/Linux
    if(NOT WIN32)
        target_compile_options(snifferlib PRIVATE -march=native)
    endif()
endif()

