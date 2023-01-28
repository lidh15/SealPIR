find_package(SEAL 4.1 REQUIRED)

add_library(sealpir pir.hpp pir.cpp pir_client.hpp pir_client.cpp pir_server.hpp pir_server.cpp xh.hpp xh.cpp)
target_link_libraries(sealpir SEAL::seal)

add_executable(main main.cpp)
target_link_libraries(main sealpir)

add_executable(server_xh server_xh.cpp)
target_link_libraries(server_xh sealpir)

add_executable(client_xh client_xh.cpp)
target_link_libraries(client_xh sealpir)
