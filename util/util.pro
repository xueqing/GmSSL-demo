QT       -= core gui

TARGET = UtilityLib
TEMPLATE = lib

CONFIG += c++11

unix
{
    CONFIG(debug, debug|release) {
        DESTDIR = $$PWD/../build/debug
    } else {
        DESTDIR = $$PWD/../build/release
    }
}

HEADERS += \
    cstring.h \
    mysm4.h

SOURCES += \
    cstring.cpp \
    mysm4.cpp
