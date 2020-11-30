file(GLOB HEADER_LIST CONFIGURE_DEPENDS
  "${WhispServer_SOURCE_DIR}/include/whisp-server/*.h"
  "${WhispServer_SOURCE_DIR}/include/whisp-protobuf/cpp/*.h")
file(GLOB SRC_LIST
  "*.cc"
  "${WhispServer_SOURCE_DIR}/include/whisp-protobuf/cpp/*.cc")

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

include(FindProtobuf)
find_package(Protobuf REQUIRED)
include_directories(${PROTOBUF_INCLUDE_DIR})

find_package(SQLite3)
include_directories(${SQLITE3_INCLUDE_DIRS})

add_library(whisp_lib ${SRC_LIST} ${HEADER_LIST})
target_include_directories(whisp_lib PUBLIC ../include)

add_executable(whisp-server main.cc)
target_compile_features(whisp-server PRIVATE cxx_std_17)

target_link_libraries(whisp-server
  PRIVATE whisp_lib Threads::Threads ${PROTOBUF_LIBRARY} sqlite3)
