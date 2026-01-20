cmake_minimum_required(VERSION 3.16)

project(WireHound VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Qt6 setup
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# Find Qt6 (or fallback to Qt5)
find_package(Qt6 COMPONENTS Core Widgets QUIET)
if(NOT Qt6_FOUND)
    find_package(Qt5 COMPONENTS Core Widgets REQUIRED)
    set(QT_VERSION_MAJOR 5)
else()
    set(QT_VERSION_MAJOR 6)
endif()

# Pattern directories 
set(MVP_DIR ${CMAKE_CURRENT_SOURCE_DIR}/mvp)
set(REPOSITORY_DIR ${CMAKE_CURRENT_SOURCE_DIR}/repository)
set(DELEGATE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/delegate)
set(EVENTBUS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/eventbus)
set(PIPE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/pipe)
set(MODEL_DIR ${CMAKE_CURRENT_SOURCE_DIR}/model)

# Source files
set(SOURCES
    main.cpp
    mainwindow.cpp
    ${MODEL_DIR}/packetmodel.cpp
    ${PIPE_DIR}/packet_runner.cpp
    ${PIPE_DIR}/pipe_sniffer_integrated.cpp
    ${DELEGATE_DIR}/filter_delegate.cpp
)

set(HEADERS
    mainwindow.h
)

# Model headers 
set(MODEL_HEADERS
    ${MODEL_DIR}/packetdata.h
    ${MODEL_DIR}/packetmodel.h
)

# POSIX pipe communication
set(PIPE_HEADERS
    ${PIPE_DIR}/packet_runner.h
    ${PIPE_DIR}/pipe_sniffer_integrated.h
)

# MVP Pattern headers
set(MVP_HEADERS
    ${MVP_DIR}/mvp_interfaces.h
)

# Repository Pattern headers
set(REPOSITORY_HEADERS
    ${REPOSITORY_DIR}/packet_repository.h
)

# Delegate Pattern headers
set(DELEGATE_HEADERS
    ${DELEGATE_DIR}/filter_delegate.h
)

# EventBus Pattern headers
set(EVENTBUS_HEADERS
    ${EVENTBUS_DIR}/eventbus.h
)

# Create executable
add_executable(${PROJECT_NAME}
    ${SOURCES}
    ${HEADERS}
    ${MODEL_HEADERS}
    ${PIPE_HEADERS}
    ${MVP_HEADERS}
    ${REPOSITORY_HEADERS}
    ${DELEGATE_HEADERS}
    ${EVENTBUS_HEADERS}
)

# Link libraries
if(QT_VERSION_MAJOR EQUAL 6)
    target_link_libraries(${PROJECT_NAME} PRIVATE Qt6::Core Qt6::Widgets)
else()
    target_link_libraries(${PROJECT_NAME} PRIVATE Qt5::Core Qt5::Widgets)
endif()

target_link_libraries(${PROJECT_NAME} PRIVATE
    snifferlib      # Static library from lib/sniffer_packages (includes pcap)
)

# Windows-specific libraries
if(WIN32)
    target_link_libraries(${PROJECT_NAME} PRIVATE ws2_32)
endif()

# Include directories
target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${MODEL_DIR}
    ${PIPE_DIR}
    ${MVP_DIR}
    ${REPOSITORY_DIR}
    ${DELEGATE_DIR}
    ${EVENTBUS_DIR}
    ${CMAKE_SOURCE_DIR}/lib/sniffer_packages   # sniffer library headers
)

# Installation
install(TARGETS ${PROJECT_NAME}
    RUNTIME DESTINATION bin
)
