cmake_minimum_required(VERSION 3.10)
project(Steganography CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find necessary packages, including video I/O components
find_package(OpenCV REQUIRED COMPONENTS core imgproc imgcodecs videoio)
find_package(OpenSSL REQUIRED)

add_executable(steganography src/main.cpp)

# Link all required libraries
target_link_libraries(steganography PRIVATE
    ${OpenCV_LIBS}
    OpenSSL::SSL
    OpenSSL::Crypto
)

target_include_directories(steganography PRIVATE
    ${OpenCV_INCLUDE_DIRS}
    ${OpenSSL_INCLUDE_DIR}
)