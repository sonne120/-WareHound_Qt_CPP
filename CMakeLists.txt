cmake_minimum_required(VERSION 3.16)

project(WireHound VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Platform-specific compiler options
if(MSVC)
    add_compile_options(/W4 /EHsc /wd4324)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
else()
    add_compile_options(-Wall -Wextra -pthread -fPIC)
endif()

# Find Qt6 (or fallback to Qt5)
find_package(Qt6 COMPONENTS Core Widgets QUIET)
if(NOT Qt6_FOUND)
    find_package(Qt5 COMPONENTS Core Widgets REQUIRED)
    set(QT_VERSION_MAJOR 5)
else()
    set(QT_VERSION_MAJOR 6)
endif()

# Set Qt libraries variable for subdirectories
if(QT_VERSION_MAJOR EQUAL 6)
    set(Qt_LIBS Qt6::Core Qt6::Widgets)
else()
    set(Qt_LIBS Qt5::Core Qt5::Widgets)
endif()

# Add subdirectories (like AlgorithmApp)
add_subdirectory(lib/sniffer_packages)
add_subdirectory(app)
