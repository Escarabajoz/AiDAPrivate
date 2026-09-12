include_guard(GLOBAL)

set(AIDA_QT6_ROOT "${DEPS_DIR}/qt/6.8.3/msvc2022_64")
set(Qt6_DIR "${AIDA_QT6_ROOT}/lib/cmake/Qt6")
list(PREPEND CMAKE_PREFIX_PATH "${AIDA_QT6_ROOT}")
if(NOT EXISTS "${Qt6_DIR}/Qt6Config.cmake")
    message(FATAL_ERROR
        "AiDA: Qt 6.8.3 (msvc2022_64) is required but ${Qt6_DIR}/Qt6Config.cmake is absent. "
        "Vendor the Qt 6.8.3 msvc2022_64 install under .deps/qt per "
        "plans/qt6_migration/16_tests_build_assets.md section 7.1.")
endif()

find_package(Qt6 6.8 REQUIRED COMPONENTS Core Gui Widgets Network Svg Test)

# Qt6::Test injects QT_TESTCASE_BUILDDIR/QT_TESTCASE_SOURCEDIR with a trailing
# path separator; on MSVC the resulting \" before the closing quote escapes it and
# corrupts the compile command line (C1083 on a garbled path). These macros only
# feed test-data lookup, which AiDA does not use, so strip them from the interface.
if(TARGET Qt6::Test)
    get_target_property(_aida_qt6_test_defs Qt6::Test INTERFACE_COMPILE_DEFINITIONS)
    if(_aida_qt6_test_defs)
        list(FILTER _aida_qt6_test_defs EXCLUDE REGEX "QT_TESTCASE_(BUILDDIR|SOURCEDIR)")
        set_target_properties(Qt6::Test PROPERTIES INTERFACE_COMPILE_DEFINITIONS "${_aida_qt6_test_defs}")
    endif()
endif()

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC OFF)

set(BUILD_STATIC ON CACHE BOOL "" FORCE)
set(BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(ADS_VERSION "4.4.1")
add_subdirectory("${DEPS_DIR}/qt-ads-src" "${CMAKE_BINARY_DIR}/.deps/qt-ads-build")

# AiDA defines functions/lambdas named `emit` (breadcrumb diagnostics, shellcode byte
# emitters, harness loggers). Qt's `emit`/`signals`/`slots` keyword macros collide with
# them in any TU that includes both Qt and those headers. The qt/ tree uses Q_EMIT /
# Q_SIGNALS / Q_SLOTS exclusively, so disable the keyword macros for AiDA targets. This
# is scoped AFTER the QADS add_subdirectory so the third-party QADS target (which uses
# the keyword macros in its own sources) is unaffected.
add_compile_definitions(QT_NO_KEYWORDS)

function(aida_qt6_stage_runtime target_name)
    if(NOT TARGET ${target_name})
        message(FATAL_ERROR "AiDA: aida_qt6_stage_runtime target does not exist: ${target_name}")
    endif()
    add_custom_command(TARGET ${target_name} POST_BUILD
        COMMAND "${AIDA_QT6_ROOT}/bin/windeployqt.exe"
            --release --force
            --dir "$<TARGET_FILE_DIR:${target_name}>" --plugindir "$<TARGET_FILE_DIR:${target_name}>"
            --no-translations --no-opengl-sw --no-system-d3d-compiler --no-system-dxc-compiler
            --no-quick-import
            -svg -network
            --skip-plugin-types qmltooling,qmllint,qmlls,designer,help,sqldrivers,tls,generic,networkinformation
            --exclude-plugins qdirect2d
            "$<TARGET_FILE:${target_name}>"
        COMMENT "Staging Qt 6.8.3 runtime beside ${target_name}..."
        VERBATIM
    )
endfunction()

function(aida_qt6_add_qtest target_name)
    add_executable(${target_name} ${ARGN})
    target_link_libraries(${target_name} PRIVATE Qt6::Test Qt6::Widgets)
    aida_use_dynamic_msvc_runtime(${target_name})
    aida_qt6_stage_runtime(${target_name})
    add_test(NAME ${target_name} COMMAND ${target_name} -platform offscreen)
endfunction()
