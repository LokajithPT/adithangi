cmake_minimum_required(VERSION 3.16)
project(ADITHANGI VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find libpcap
find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

# Compile scanner
add_executable(scanner scanner.cpp)
target_include_directories(scanner PRIVATE ${PCAP_INCLUDE_DIRS})
target_link_libraries(scanner PRIVATE ${PCAP_LIBRARIES})
target_compile_options(scanner PRIVATE ${PCAP_CFLAGS_OTHER})

# Compile game client  
add_executable(game_client game_client.cpp)
target_link_libraries(game_client PRIVATE pthread)

# Set output directory
set_target_properties(scanner PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

set_target_properties(game_client PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)