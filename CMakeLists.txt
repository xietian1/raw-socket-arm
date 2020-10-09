cmake_minimum_required (VERSION 2.6)

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR arm)

#set(CMAKE_SYSROOT /home/xt/volte-attack)
set(tools /home/xt/volte-attack/gcc-linaro-7.5.0)
set(CMAKE_C_COMPILER ${tools}/bin/arm-linux-gnueabihf-gcc)
#set(CMAKE_CXX_COMPILER ${tools}/bin/arm-linux-gnueabihf-g++)
SET(CMAKE_C_FLAGS "-march=armv7-a -static -DARM")
#set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)

#set(CMAKE_TRY_COMPILE_TARGET_TYPE "STATIC_LIBRARY")


#set(TOOLCHAIN_PREFIX arm-linux-gnueabihf)

# cross compilers to use for C and C++
#set(CMAKE_C_COMPILER arm-linux-gnueabihf-gcc)
#set(CMAKE_CXX_COMPILER arm-linux-gnueabihf-gcc)

# target environment on the build host system
#   set 1st to dir with the cross compiler's C/C++ headers/libs
#set(CMAKE_FIND_ROOT_PATH /usr/${TOOLCHAIN_PREFIX})

# modify default behavior of FIND_XXX() commands to
# search for headers/libs in the target environment and
# search for programs in the build host environment
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)


project (raw-socket)

include_directories(include)
#add_executable (ue_call_sim src/dev.c src/esp.c src/hmac.c src/main.c src/net.c src/replay.c src/sha1.c src/sip.c src/transport.c src/utils.c src/aes.c include/dev.h include/esp.h include/hmac.h include/net.h include/replay.h include/sha.h include/sip.h include/transport.h include/utils.h include/aes.h)
add_executable (raw-socket src/main2.c)



