cmake_minimum_required(VERSION 3.5)

project(qt_hello LANGUAGES C)

include_directories("../../common")

add_executable(qt_hello main.c
               ../../common/shared_functions.c)

include(GNUInstallDirs)
install(TARGETS qt_hello
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
