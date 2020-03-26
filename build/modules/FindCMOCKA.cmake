# From: https://github.com/lperkov/cmocka-hello/blob/master/build/modules/FindCMOCKA.cmake

# LIBCMOCKA_FOUND - true if library and headers were found
# LIBCMOCKA_INCLUDE_DIRS - include directories
# LIBCMOCKA_LIBRARIES - library directories

cmake_minimum_required (VERSION 3.8)

if (APPLE OR UNIX)
	find_package(PkgConfig)
	pkg_check_modules(PC_LIBCMOCKA QUIET cmocka)

	find_path(LIBCMOCKA_INCLUDE_DIR cmocka.h
		HINTS ${PC_LIBCMOCKA_INCLUDEDIR} ${PC_LIBCMOCKA_INCLUDE_DIRS})

	find_library(LIBCMOCKA_LIBRARY NAMES cmocka libcmocka
		HINTS ${PC_LIBCMOCKA_LIBDIR} ${PC_LIBCMOCKA_LIBRARY_DIRS})

	set(LIBCMOCKA_LIBRARIES ${LIBCMOCKA_LIBRARY})
	set(LIBCMOCKA_INCLUDE_DIRS ${LIBCMOCKA_INCLUDE_DIR})

	include(FindPackageHandleStandardArgs)

	find_package_handle_standard_args(LIBCMOCKA DEFAULT_MSG LIBCMOCKA_LIBRARY LIBCMOCKA_INCLUDE_DIR)

	mark_as_advanced(LIBCMOCKA_INCLUDE_DIR LIBCMOCKA_LIBRARY)
endif()