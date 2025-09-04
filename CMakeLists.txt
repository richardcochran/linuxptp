cmake_minimum_required(VERSION 3.16)
project(linuxptp C)

# ------------------------------------------------------------
# Option: USE_OPENSSL
# ------------------------------------------------------------
option(USE_OPENSSL "Enable OpenSSL support" OFF)

# ------------------------------------------------------------
# Run scripts to obtain version and compiler-derived defines
# ------------------------------------------------------------
execute_process(
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/version.sh ${CMAKE_CURRENT_SOURCE_DIR}
    OUTPUT_VARIABLE VERSION OUTPUT_STRIP_TRAILING_WHITESPACE
)
execute_process(
    COMMAND env CC=${CMAKE_C_COMPILER} ${CMAKE_CURRENT_SOURCE_DIR}/incdefs.sh
    OUTPUT_VARIABLE INCDEFS_RAW OUTPUT_STRIP_TRAILING_WHITESPACE
)

# Filter -DHAVE_OPENSSL if USE_OPENSSL=OFF
set(INCDEFS "${INCDEFS_RAW}")
if(NOT USE_OPENSSL)
    string(REPLACE "-DHAVE_OPENSSL" "" INCDEFS "${INCDEFS}")
else()
    add_compile_definitions(USE_OPENSSL)
endif()

# ------------------------------------------------------------
# Compile options / preprocessor definitions
# ------------------------------------------------------------
add_compile_definitions(VER=${VERSION})
add_compile_options(-Wall)
# Split INCDEFS into tokens (e.g. -DHAVE_XYZ ...)
separate_arguments(INCDEFS_LIST NATIVE_COMMAND "${INCDEFS}")
add_compile_options(${INCDEFS_LIST})

# ------------------------------------------------------------
# Common source group definitions
# ------------------------------------------------------------
set(FILTERS filter.c mave.c mmedian.c)
set(SERVOS
    linreg.c
    ntpshm.c
    nullf.c
    pi.c
    refclock_sock.c
    servo.c
)
set(TRANSP
    raw.c
    transport.c
    udp.c
    udp6.c
    uds.c
)
set(TS2PHC
    ts2phc.c
    lstab.c
    nmea.c
    serial.c
    sock.c
    ts2phc_generic_pps_source.c
    ts2phc_nmea_pps_source.c
    ts2phc_phc_pps_source.c
    ts2phc_pps_sink.c
    ts2phc_pps_source.c
)

# ------------------------------------------------------------
# Select security-related sources and required libraries
# ------------------------------------------------------------
set(SECURITY_SOURCES sad.c)
set(SECURITY_LIBS "")
if(INCDEFS MATCHES "-DHAVE_NETTLE")
    find_library(NETTLE_LIB nettle REQUIRED)
    list(APPEND SECURITY_SOURCES sad_nettle.c)
    set(SECURITY_LIBS ${NETTLE_LIB})
elseif(INCDEFS MATCHES "-DHAVE_GNUTLS")
    find_library(GNUTLS_LIB gnutls REQUIRED)
    list(APPEND SECURITY_SOURCES sad_gnutls.c)
    set(SECURITY_LIBS ${GNUTLS_LIB})
elseif(INCDEFS MATCHES "-DHAVE_GNUPG")
    find_library(GCRYPT_LIB gcrypt REQUIRED)
    list(APPEND SECURITY_SOURCES sad_gnupg.c)
    set(SECURITY_LIBS ${GCRYPT_LIB})
elseif(INCDEFS MATCHES "-DHAVE_OPENSSL")
    find_library(CRYPTO_LIB crypto REQUIRED)
    list(APPEND SECURITY_SOURCES sad_openssl.c)
    set(SECURITY_LIBS ${CRYPTO_LIB})
endif()

# ------------------------------------------------------------
# Common link libraries
# ------------------------------------------------------------
find_library(M_LIB m REQUIRED)
find_library(RT_LIB rt REQUIRED)
find_package(Threads REQUIRED)
set(COMMON_LIBS ${M_LIB} ${RT_LIB} Threads::Threads ${SECURITY_LIBS})

# ------------------------------------------------------------
# Generate .version
# ------------------------------------------------------------
add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/.version
    COMMAND ${CMAKE_COMMAND} -E echo ${VERSION} > ${CMAKE_CURRENT_BINARY_DIR}/.version
    DEPENDS version.sh
)
add_custom_target(version_target DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/.version)

# ------------------------------------------------------------
# Helper macro to declare executables
# ------------------------------------------------------------
set(ALL_PROGRAMS "")
function(add_ptp_executable name)
    add_executable(${name} ${ARGN})
    target_link_libraries(${name} PRIVATE ${COMMON_LIBS})
    add_dependencies(${name} version_target)
    list(APPEND ALL_PROGRAMS ${name})
    set(ALL_PROGRAMS "${ALL_PROGRAMS}" PARENT_SCOPE)
endfunction()

# ------------------------------------------------------------
# Per-executable source lists (structure only; behavior unchanged)
# ------------------------------------------------------------
add_ptp_executable(
    ptp4l
    bmc.c
    clock.c
    clockadj.c
    clockcheck.c
    config.c
    designated_fsm.c
    e2e_tc.c
    fault.c
    ${FILTERS}
    fsm.c
    hash.c
    interface.c
    monitor.c
    msg.c
    phc.c
    pmc_common.c
    port.c
    port_signaling.c
    pqueue.c
    print.c
    ptp4l.c
    p2p_tc.c
    rtnl.c
    ${SECURITY_SOURCES}
    ${SERVOS}
    sk.c
    stats.c
    tc.c
    ${TRANSP}
    telecom.c
    tlv.c
    tsproc.c
    unicast_client.c
    unicast_fsm.c
    unicast_service.c
    util.c
    version.c
)
add_ptp_executable(
    nsm
    config.c
    ${FILTERS}
    hash.c
    interface.c
    msg.c
    nsm.c
    phc.c
    print.c
    rtnl.c
    ${SECURITY_SOURCES}
    sk.c
    ${TRANSP}
    tlv.c
    tsproc.c
    util.c
    version.c
)
add_ptp_executable(
    pmc
    config.c
    hash.c
    interface.c
    msg.c
    phc.c
    pmc.c
    pmc_common.c
    print.c
    ${SECURITY_SOURCES}
    sk.c
    tlv.c
    ${TRANSP}
    util.c
    version.c
)
add_ptp_executable(
    phc2sys
    clockadj.c
    clockcheck.c
    config.c
    hash.c
    interface.c
    msg.c
    phc.c
    phc2sys.c
    pmc_agent.c
    pmc_common.c
    print.c
    ${SECURITY_SOURCES}
    ${SERVOS}
    sk.c
    stats.c
    sysoff.c
    tlv.c
    ${TRANSP}
    util.c
    version.c
)
add_ptp_executable(hwstamp_ctl hwstamp_ctl.c version.c)
add_ptp_executable(
    phc_ctl
    phc_ctl.c
    phc.c
    sk.c
    util.c
    clockadj.c
    sysoff.c
    print.c
    version.c
)
add_ptp_executable(
    timemaster
    phc.c
    print.c
    rtnl.c
    sk.c
    timemaster.c
    util.c
    version.c
)
add_ptp_executable(
    ts2phc
    config.c
    clockadj.c
    hash.c
    interface.c
    msg.c
    phc.c
    pmc_agent.c
    pmc_common.c
    print.c
    ${SECURITY_SOURCES}
    ${SERVOS}
    sk.c
    ${TS2PHC}
    tlv.c
    transport.c
    ${TRANSP}
    util.c
    version.c
)
add_ptp_executable(
    tz2alt
    config.c
    hash.c
    interface.c
    lstab.c
    msg.c
    phc.c
    pmc_common.c
    print.c
    ${SECURITY_SOURCES}
    sk.c
    tlv.c
    ${TRANSP}
    tz2alt.c
    util.c
    version.c
)

# ------------------------------------------------------------
# Installation
# ------------------------------------------------------------
include(GNUInstallDirs)
install(TARGETS ${ALL_PROGRAMS} DESTINATION ${CMAKE_INSTALL_SBINDIR})

# ------------------------------------------------------------
# Status output (optional)
# ------------------------------------------------------------
message(STATUS "linuxptp version: ${VERSION}")
message(STATUS "INCDEFS (filtered): ${INCDEFS}")
message(STATUS "Programs: ${ALL_PROGRAMS}")
