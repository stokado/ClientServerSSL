cmake_minimum_required (VERSION 3.8)

project ("ClientServerSSL")

set (CMAKE_CXX_STANDARD 11)

if (MSVC)
    # warning level 4 and all warnings as errors
    add_compile_options(/bigobj)
else()
    # lots of warnings and all warnings as errors
    add_compile_options(-Wall -Wextra -pedantic -Werror)
endif()

cmake_policy (SET CMP0074 NEW)

find_package (Boost REQUIRED)
find_package (OpenSSL REQUIRED)

add_subdirectory ("client")
add_subdirectory ("mylib")
add_subdirectory ("server")