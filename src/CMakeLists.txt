cmake_minimum_required(VERSION 3.13)
project(scatt-dispatcher C)

set(CMAKE_C_STANDARD 11)

add_definitions(-DLOG_USE_COLOR)

set(CMAKE_C_FLAGS_RELEASE  "-O2 -Wall -Wextra")

include_directories(${CMAKE_SOURCE_DIR})

set(SRC
    scatt-dispatcher.c
    tcp_connection.c
    remap_pipe.c
    log.c
    utils.c
)

add_executable(${PROJECT_NAME} ${SRC})

install(TARGETS ${PROJECT_NAME} RUNTIME DESTINATION ${CMAKE_INSTALL_PREFIX})


#add_executable(scatt-stdin-to-ip  scatt-stdin-to-ip.c  tcp_connection.c  log.c  utils.c)
