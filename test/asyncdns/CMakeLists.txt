PROJECT(test_asyncdns)

cmake_minimum_required(VERSION 3.5)
  
include_directories("/usr/local/include")
include_directories(${CMAKE_CURRENT_LIST_DIR}/depend)
include_directories(${CMAKE_CURRENT_LIST_DIR}/test)
aux_source_directory(${CMAKE_CURRENT_LIST_DIR}/depend source_depend)  
aux_source_directory(${CMAKE_CURRENT_LIST_DIR}/test source_test)  

link_directories("/usr/local/lib")
link_libraries(crypto)
link_libraries(sodium)

add_compile_options(-std=c++11) 
add_compile_options(-Wall) 
add_compile_options(-O3 -DNDEBUG) 
add_compile_options(-DELPP_NO_DEFAULT_LOG_FILE)
add_compile_options(-Wno-unused-variable)

add_executable(${PROJECT_NAME} ${source_depend} ${source_test}) 


