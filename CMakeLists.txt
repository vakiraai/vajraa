# CMakeLists.txt
cmake_minimum_required(VERSION 3.12)
project(vajraa LANGUAGES C CXX)
set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Define source file directory
set(SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/native/src")
set(INC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/native/include")

# Select PAL implementation based on target platform
if(WIN32)
    set(PAL_SRC "${SRC_DIR}/pal_windows.cpp")
    message(STATUS "Selected Platform: Windows")
elseif(APPLE)
    set(PAL_SRC "${SRC_DIR}/pal_macos.cpp")
    message(STATUS "Selected Platform: macOS")
elseif(ANDROID)
    set(PAL_SRC "${SRC_DIR}/pal_android.cpp")
    message(STATUS "Selected Platform: Android")
elseif(UNIX)
    set(PAL_SRC "${SRC_DIR}/pal_linux.cpp")
    message(STATUS "Selected Platform: Linux")
else()
    set(PAL_SRC "${SRC_DIR}/pal_embedded.c")
    message(STATUS "Selected Platform: Embedded / RTOS")
endif()

# Build the main shared library including PAL, Crypto Engine, and custom ONNX operators
add_library(vajraa SHARED
    ${PAL_SRC}
    "${SRC_DIR}/crypto_engine.cpp"
    "${SRC_DIR}/secure_gemm_op.cpp"
)

# Set include directories for compile time
target_include_directories(vajraa PUBLIC
    ${INC_DIR}
)

# OS Specific Linkages and Libraries
find_package(OpenMP)
if(OpenMP_CXX_FOUND)
    target_link_libraries(vajraa PRIVATE OpenMP::OpenMP_CXX)
endif()

if(WIN32)
    # Link Crypt32 library for DPAPI functions (CryptProtectMemory)
    # Link bcrypt for CNG Cryptographic functions (BCryptDecrypt)
    target_link_libraries(vajraa PRIVATE Crypt32 bcrypt)
else()
    # Link OpenSSL crypto library for AES-GCM on POSIX systems
    find_package(OpenSSL REQUIRED)
    target_include_directories(vajraa PRIVATE ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(vajraa PRIVATE OpenSSL::Crypto)
endif()

