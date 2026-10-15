# Native build integration, not an encryption or anti-decompiler guarantee.
include_guard(GLOBAL)

if(CMAKE_VERSION VERSION_LESS 3.20)
    message(FATAL_ERROR "ReleaseGuard requires CMake 3.20 or newer.")
endif()

function(_releaseguard_validate_native_target target)
    if(NOT TARGET "${target}")
        message(FATAL_ERROR "ReleaseGuard: target '${target}' does not exist.")
    endif()
    get_target_property(_rg_alias "${target}" ALIASED_TARGET)
    get_target_property(_rg_imported "${target}" IMPORTED)
    get_target_property(_rg_type "${target}" TYPE)
    if(_rg_alias OR _rg_imported)
        message(FATAL_ERROR "ReleaseGuard: use a locally built, non-alias target.")
    endif()
    if(NOT _rg_type MATCHES "^(EXECUTABLE|SHARED_LIBRARY|MODULE_LIBRARY)$")
        message(FATAL_ERROR
            "ReleaseGuard: '${target}' must be an executable, shared library, or module library.")
    endif()
    get_property(_rg_enabled_languages GLOBAL PROPERTY ENABLED_LANGUAGES)
    set(_rg_native_languages "")
    foreach(_rg_language IN ITEMS C CXX)
        if(_rg_language IN_LIST _rg_enabled_languages)
            list(APPEND _rg_native_languages "${_rg_language}")
        endif()
    endforeach()
    if(NOT _rg_native_languages)
        message(FATAL_ERROR "ReleaseGuard: enable the C or CXX language before calling this function.")
    endif()
    if(NOT CMAKE_SIZEOF_VOID_P EQUAL 4 AND NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
        message(FATAL_ERROR "ReleaseGuard: could not determine a supported target pointer size.")
    endif()
    set(_rg_target_type "${_rg_type}" PARENT_SCOPE)
    set(_rg_target_languages "${_rg_native_languages}" PARENT_SCOPE)
endfunction()

function(_releaseguard_require_msvc)
    if(NOT WIN32 OR NOT MSVC)
        message(FATAL_ERROR "ReleaseGuard: this function supports Windows with Microsoft MSVC only.")
    endif()
    foreach(_rg_language IN LISTS _rg_target_languages)
        if(NOT CMAKE_${_rg_language}_COMPILER_ID STREQUAL "MSVC")
            message(FATAL_ERROR "ReleaseGuard: ${_rg_language} must use the Microsoft MSVC compiler.")
        endif()
    endforeach()
endfunction()

# Compatibility API: the v0.1 MSVC mitigations remain available independently.
function(releaseguard_harden target)
    if(NOT ARGC EQUAL 1)
        message(FATAL_ERROR "Usage: releaseguard_harden(target)")
    endif()
    _releaseguard_validate_native_target("${target}")
    _releaseguard_require_msvc()
    get_target_property(_rg_hardened "${target}" RELEASEGUARD_HARDENED)
    if(_rg_hardened)
        return()
    endif()
    target_compile_options("${target}" PRIVATE
        "$<$<COMPILE_LANGUAGE:C,CXX>:/GS>"
        "$<$<COMPILE_LANGUAGE:C,CXX>:/sdl>"
        "$<$<COMPILE_LANGUAGE:C,CXX>:/guard:cf>"
        "$<$<AND:$<CONFIG:Release>,$<COMPILE_LANGUAGE:C,CXX>>:/O2>"
    )
    target_link_options("${target}" PRIVATE
        /DYNAMICBASE /NXCOMPAT /guard:cf
        "$<$<CONFIG:Release>:/OPT:REF>"
        "$<$<CONFIG:Release>:/OPT:ICF>"
    )
    # Target pointer width is reliable with both Visual Studio and Ninja.
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        target_link_options("${target}" PRIVATE /HIGHENTROPYVA)
    endif()
    set_property(TARGET "${target}" PROPERTY RELEASEGUARD_HARDENED TRUE)
endfunction()

# releaseguard_protect(app POLICY path/to/policy.json [SEED 0123456789abcdef])
# Requires the releaseguard Python package in the selected Python interpreter.
function(releaseguard_protect target)
    cmake_parse_arguments(PARSE_ARGV 1 RG "" "POLICY;SEED" "")
    if(RG_UNPARSED_ARGUMENTS OR RG_KEYWORDS_MISSING_VALUES OR NOT RG_POLICY)
        message(FATAL_ERROR
            "Usage: releaseguard_protect(target POLICY path [SEED hex16])")
    endif()
    _releaseguard_validate_native_target("${target}")
    get_target_property(_rg_protected "${target}" RELEASEGUARD_PROTECTED)
    if(_rg_protected)
        message(FATAL_ERROR "ReleaseGuard: releaseguard_protect('${target}') was already configured.")
    endif()
    get_filename_component(_rg_policy "${RG_POLICY}" ABSOLUTE
        BASE_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
    if(NOT EXISTS "${_rg_policy}" OR IS_DIRECTORY "${_rg_policy}")
        message(FATAL_ERROR "ReleaseGuard: POLICY must name an existing JSON file: ${_rg_policy}")
    endif()
    if(DEFINED RG_SEED)
        string(LENGTH "${RG_SEED}" _rg_seed_length)
        if(NOT _rg_seed_length EQUAL 16 OR NOT RG_SEED MATCHES "^[0-9A-Fa-f]+$")
            message(FATAL_ERROR "ReleaseGuard: SEED must contain exactly 16 hexadecimal characters.")
        endif()
    endif()

    if(WIN32)
        _releaseguard_require_msvc()
    elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        foreach(_rg_language IN LISTS _rg_target_languages)
            if(NOT CMAKE_${_rg_language}_COMPILER_ID MATCHES "^(GNU|Clang)$")
                message(FATAL_ERROR "ReleaseGuard: Linux currently supports GNU GCC or Clang C/C++ only.")
            endif()
        endforeach()
    else()
        message(FATAL_ERROR "ReleaseGuard: protect currently supports MSVC on Windows and GCC/Clang on Linux.")
    endif()

    # Fail during configuration if the selected compiler/linker cannot do IPO.
    # CheckIPOSupported needs CMP0069 NEW, even when a parent uses older policies.
    cmake_policy(SET CMP0069 NEW)
    include(CheckIPOSupported)
    check_ipo_supported(RESULT _rg_ipo_supported OUTPUT _rg_ipo_error
        LANGUAGES ${_rg_target_languages})
    if(NOT _rg_ipo_supported)
        message(FATAL_ERROR "ReleaseGuard: Release IPO/LTO is unavailable: ${_rg_ipo_error}")
    endif()

    find_package(Python3 3.10 REQUIRED COMPONENTS Interpreter)
    set(_rg_generated_dir "${CMAKE_CURRENT_BINARY_DIR}/releaseguard-generated/${target}")
    set(_rg_init_command "${Python3_EXECUTABLE}" -m releaseguard native-init
        --out "${_rg_generated_dir}")
    if(DEFINED RG_SEED)
        list(APPEND _rg_init_command --seed "${RG_SEED}")
    endif()
    execute_process(COMMAND ${_rg_init_command}
        RESULT_VARIABLE _rg_init_result
        OUTPUT_VARIABLE _rg_init_output
        ERROR_VARIABLE _rg_init_error
        ENCODING UTF-8)
    if(NOT _rg_init_result STREQUAL "0")
        message(FATAL_ERROR
            "ReleaseGuard: native-init failed (${_rg_init_result}). Install releaseguard into '${Python3_EXECUTABLE}'.\n${_rg_init_error}\n${_rg_init_output}")
    endif()
    if(NOT EXISTS "${_rg_generated_dir}/releaseguard_build.hpp")
        message(FATAL_ERROR "ReleaseGuard: native-init did not produce releaseguard_build.hpp.")
    endif()
    target_include_directories("${target}" PRIVATE
        "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/../include"
        "${_rg_generated_dir}")
    if("CXX" IN_LIST _rg_target_languages)
        # Targets that compile C++ need the literal wrapper's C++17 semantics.
        # C-only projects keep their existing C language standard.
        target_compile_features("${target}" PRIVATE cxx_std_17)
    endif()
    set(_rg_seed_header "${_rg_generated_dir}/releaseguard_build.hpp")
    if(WIN32)
        # /FI and its path form one argument, including paths with spaces.
        target_compile_options("${target}" PRIVATE
            "$<$<COMPILE_LANGUAGE:C,CXX>:/FI${_rg_seed_header}>")
    else()
        # SHELL groups the two arguments without breaking paths with spaces.
        target_compile_options("${target}" PRIVATE
            "$<$<COMPILE_LANGUAGE:C,CXX>:SHELL:-include \"${_rg_seed_header}\">")
    endif()
    set_property(TARGET "${target}" PROPERTY INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE)

    if(WIN32)
        releaseguard_harden("${target}")
        target_compile_options("${target}" PRIVATE
            "$<$<AND:$<CONFIG:Release>,$<COMPILE_LANGUAGE:C,CXX>>:/GL>")
        # MSVC can emit POGO/COFF group records even in a Release build
        # without PDB output. Keep the gate strict and suppress those records.
        target_link_options("${target}" PRIVATE
            "$<$<CONFIG:Release>:/LTCG>"
            "$<$<CONFIG:Release>:/DEBUG:NONE>"
            "$<$<CONFIG:Release>:/INCREMENTAL:NO>"
            "$<$<CONFIG:Release>:/NOCOFFGRPINFO>")
    else()
        target_compile_options("${target}" PRIVATE
            "$<$<AND:$<CONFIG:Release>,$<COMPILE_LANGUAGE:C,CXX>>:-O2>"
            "$<$<AND:$<CONFIG:Release>,$<COMPILE_LANGUAGE:C,CXX>>:-fstack-protector-strong>")
        target_link_options("${target}" PRIVATE
            "$<$<CONFIG:Release>:-s>"
            "$<$<CONFIG:Release>:-Wl,-z,relro,-z,now,-z,noexecstack>")
        if(_rg_target_type STREQUAL "EXECUTABLE")
            target_compile_options("${target}" PRIVATE
                "$<$<AND:$<CONFIG:Release>,$<COMPILE_LANGUAGE:C,CXX>>:-fvisibility=hidden>"
                "$<$<AND:$<CONFIG:Release>,$<COMPILE_LANGUAGE:CXX>>:-fvisibility-inlines-hidden>")
        else()
            # Hiding default-visible library symbols would change existing ABI.
            message(STATUS
                "ReleaseGuard: '${target}' keeps existing library visibility; annotate and review public ABI before enabling hidden visibility manually.")
        endif()
    endif()

    # Make/Ninja relink on policy edits. Gate failures are normal build failures.
    set_property(TARGET "${target}" APPEND PROPERTY LINK_DEPENDS "${_rg_policy}")
    add_custom_command(TARGET "${target}" POST_BUILD
        COMMAND "${Python3_EXECUTABLE}" -m releaseguard gate
            "$<TARGET_FILE:${target}>" --policy "${_rg_policy}"
        COMMENT "ReleaseGuard: checking native release policy for ${target}"
        VERBATIM)
    set_property(TARGET "${target}" PROPERTY RELEASEGUARD_PROTECTED TRUE)
    set_property(TARGET "${target}" PROPERTY RELEASEGUARD_GENERATED_DIR "${_rg_generated_dir}")
endfunction()
