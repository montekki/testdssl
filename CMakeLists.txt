cmake_minimum_required( VERSION 2.6 )

set(CMAKE_C_FLAGS "-g ${CMAKE_C_FLAGS}")
include_directories(/home/theodor/myprefix/include)

file(COPY ${PROJECT_SOURCE_DIR}/test1.cap ${PROJECT_SOURCE_DIR}/test1.pem DESTINATION ${PROJECT_BINARY_DIR})
add_executable(testdssl testdssl.c)

target_link_libraries(testdssl pcap dssl z ssl crypto)
