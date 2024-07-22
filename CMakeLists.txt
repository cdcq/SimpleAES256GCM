cmake_minimum_required(VERSION 3.26)
project(SimpleAES256GCM C)

set(CMAKE_C_STANDARD 99)

add_executable(SimpleAES256GCM main.c
        aes.c
        aes.h
        gcm.c
        gcm.h)
