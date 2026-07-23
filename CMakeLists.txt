cmake_minimum_required(VERSION 3.16)
project(wifisec VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

find_package(Qt6 REQUIRED COMPONENTS Widgets Charts Network)
find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)
pkg_check_modules(NL3 REQUIRED libnl-3.0)
pkg_check_modules(NL3_GENL REQUIRED libnl-genl-3.0)
find_package(OpenSSL REQUIRED)

set(SOURCES
    src/main.cpp
    src/gui/MainWindow.cpp
    src/gui/ScannerTab.cpp
    src/gui/AttackTab.cpp
    src/gui/EvilTwinTab.cpp
    src/gui/CrackTab.cpp
    src/gui/StealthTab.cpp
    src/core/Scanner.cpp
    src/core/PacketEngine.cpp
    src/core/Attacker.cpp
    src/core/EvilTwin.cpp
    src/core/Cracker.cpp
    src/core/HandshakeCapture.cpp
    src/utils/Logger.cpp
    src/utils/MacSpoofer.cpp
    src/utils/NetUtils.cpp
)

set(HEADERS
    src/gui/MainWindow.h
    src/gui/ScannerTab.h
    src/gui/AttackTab.h
    src/gui/EvilTwinTab.h
    src/gui/CrackTab.h
    src/gui/StealthTab.h
    src/core/Scanner.h
    src/core/PacketEngine.h
    src/core/Attacker.h
    src/core/EvilTwin.h
    src/core/Cracker.h
    src/core/HandshakeCapture.h
    src/utils/Logger.h
    src/utils/MacSpoofer.h
    src/utils/NetUtils.h
    src/common/Types.h
)

add_executable(wifisec ${SOURCES} ${HEADERS})

target_include_directories(wifisec PRIVATE
    src/
    ${PCAP_INCLUDE_DIRS}
    ${NL3_INCLUDE_DIRS}
    ${NL3_GENL_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(wifisec PRIVATE
    Qt6::Widgets
    Qt6::Charts
    Qt6::Network
    ${PCAP_LIBRARIES}
    ${NL3_LIBRARIES}
    ${NL3_GENL_LIBRARIES}
    OpenSSL::SSL
    OpenSSL::Crypto
    pthread
)

target_compile_options(wifisec PRIVATE
    -O2
    -Wall
    -Wextra
    -march=native
)
