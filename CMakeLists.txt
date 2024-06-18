cmake_minimum_required(VERSION 3.15)
# Name of the project (will be the name of the plugin)
project (addon)
set(CMAKE_CXX_STANDARD 11)
# Don't add this line if you will try_compile with boost.
set(CMAKE_CXX_STANDARD_REQUIRED ON)


find_package(Palisade)
set( CMAKE_CXX_FLAGS ${PALISADE_CXX_FLAGS} )
include_directories( ${OPENMP_INCLUDES} )
include_directories( ${PALISADE_INCLUDE} )
include_directories( ${PALISADE_INCLUDE}/third-party/include )
include_directories( ${PALISADE_INCLUDE}/core )
include_directories( ${PALISADE_INCLUDE}/pke )
include_directories( ${PALISADE_INCLUDE}/cereal )
include_directories( ${PALISADE_INCLUDE}/binfhe )
include_directories( ${PALISADE_INCLUDE}/nlohmann )
### add directories for other PALISADE modules as needed for your project
link_directories( ${PALISADE_LIBDIR} )
link_directories( ${OPENMP_LIBRARIES} )
set( CMAKE_EXE_LINKER_FLAGS ${PALISADE_EXE_LINKER_FLAGS} )
link_libraries( ${PALISADE_SHARED_LIBRARIES} )



# Essential include files to build a node addon,
# you should add this line in every CMake.js based project.
include_directories(${CMAKE_JS_INC})
# Declare the location of the source files
file(GLOB SOURCE_FILES "src/*.cpp" "src/*.h")
# This line will tell CMake that we're building a shared library
# from the above source files
# named after the project's name
add_library(${PROJECT_NAME} SHARED ${SOURCE_FILES} ${CMAKE_JS_SRC})
# This line will give our library file a .node extension without any "lib" prefix
set_target_properties(${PROJECT_NAME} PROPERTIES PREFIX "" SUFFIX ".node")
# Essential library files to link to a node addon,
# you should add this line in every CMake.js based project.
target_link_libraries(${PROJECT_NAME} ${CMAKE_JS_LIB})
# Include N-API wrappers
execute_process(COMMAND node -p "require('node-addon-api').include"
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        OUTPUT_VARIABLE NODE_ADDON_API_DIR
        OUTPUT_STRIP_TRAILING_WHITESPACE
        )
string(REPLACE "\n" "" NODE_ADDON_API_DIR ${NODE_ADDON_API_DIR})
string(REPLACE "\"" "" NODE_ADDON_API_DIR ${NODE_ADDON_API_DIR})
target_include_directories(${PROJECT_NAME} PRIVATE ${NODE_ADDON_API_DIR})
add_definitions(-DNAPI_VERSION=3)


### ADD YOUR EXECUTABLE(s) HERE
### add_executable( EXECUTABLE-NAME SOURCES )
###
### EXAMPLE:
### add_executable( test demo-simple-example.cpp )
# add_executable(chameleonhash src/chameleonhash.cpp)