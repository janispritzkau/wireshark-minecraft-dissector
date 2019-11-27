project(WiresharkMinecraft)

cmake_minimum_required(VERSION 3.1)
cmake_policy(SET CMP0048 NEW)

find_package(Wireshark CONFIG REQUIRED)

if(NOT Wireshark_PLUGINS_ENABLED)
	message(FATAL_ERROR "Wireshark was compiled without support for plugins")
endif()

set(CMAKE_C_VISIBILITY_PRESET hidden)
if (CMAKE_COMPILER_IS_GNUCC)
    set(CMAKE_C_FLAGS  "-Wall -Wextra ${CMAKE_C_FLAGS}")
endif()

add_definitions(-DVERSION=\"${PROJECT_VERSION}\")

add_library(minecraft MODULE minecraft.c)
set_target_properties(minecraft PROPERTIES PREFIX "" DEFINE_SYMBOL "")
target_link_libraries(minecraft epan)

install(TARGETS minecraft
	LIBRARY DESTINATION "${Wireshark_PLUGIN_INSTALL_DIR}/epan" NAMELINK_SKIP
)
