# Just a simple CMakeLists.txt file to build pmc. Not really needed, but
# I want to cross compile and I'm too lazy to figure out how to do it with
# make

cmake_minimum_required(VERSION 3.13)

project(pmc_special)

add_executable(pmc)

target_sources(pmc PRIVATE
    config.c
    msg.c
    phc.c
    pmc_common.c
    pmc.c
    print.c
    sad.c
    sk.c
    transport.c
    util.c
    hash.c
    interface.c
    tlv.c
    version.c
    raw.c
    udp.c
    udp6.c
    uds.c
)

target_compile_definitions(pmc
    PRIVATE
        -DVER=pmc2_1
        -D_GNU_SOURCE
        -DHAVE_CLOCK_ADJTIME 
        -DHAVE_POSIX_SPAWN 
        -DHAVE_ONESTEP_SYNC 
        -DHAVE_PTP_CAPS_ADJUST_PHASE 
        -DHAVE_IF_TEAM
)

target_include_directories(pmc
    PRIVATE
        ${CMAKE_CURRENT_BINARY_DIR})
