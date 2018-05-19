#set(CMAKE_C_COMPILER "clang")      
#set(CMAKE_CXX_COMPILER "clang++")  

PROJECT(ssc++) 

cmake_minimum_required(VERSION 3.5)

include_directories(${CMAKE_CURRENT_LIST_DIR}/src)   
include_directories(${CMAKE_CURRENT_LIST_DIR}/src/crypto)   
include_directories(${CMAKE_CURRENT_LIST_DIR}/libs)   
  
aux_source_directory(${CMAKE_CURRENT_LIST_DIR}/src source_src) 
aux_source_directory(${CMAKE_CURRENT_LIST_DIR}/src/crypto source_src_crypto) 
aux_source_directory(${CMAKE_CURRENT_LIST_DIR}/libs source_libs) 

link_directories("/usr/local/lib")
link_libraries(crypto) #openssl
link_libraries(sodium) #libsodium
 
add_compile_options(-std=c++11)  
add_compile_options(-Wall) 
add_compile_options(-O3 -DNDEBUG)
add_compile_options(-DELPP_NO_DEFAULT_LOG_FILE)#for easyloggingpp no default log file
add_compile_options(-Wno-unused-variable)#when using gcc easyloggingpp bug: el::base::consts::kPerformanceLoggerId defined but not used [-Wunused-variable] 

add_executable(${PROJECT_NAME} ${source_src} ${source_src_crypto} ${source_libs}) 
 
