cmake_minimum_required(VERSION 3.7)
project(PanicButton)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -m32 -static -static-libgcc -static-libstdc++ -Wl,--subsystem,console -mwindows")
include_directories(include)
set(RESOURCE_FILES
        res/panicbutton.rc
        )
set(SOURCE_FILES main.cpp winpmem.cpp)
add_executable(PanicButton ${SOURCE_FILES} ${RESOURCE_FILES})
target_link_libraries(PanicButton PowrProf)