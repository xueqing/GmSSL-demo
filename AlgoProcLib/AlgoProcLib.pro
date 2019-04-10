QT       -= core gui

TARGET = AlgoProcLib
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

unix{
    target.path = /usr/lib
    INSTALLS += target
}

NO_GMSSL{
    QMAKE_CXXFLAGS += -D__NO_GMSSL__
}

INCLUDEPATH += \
    $$PWD/../util \
    $$PWD/../include

SOURCES += \
    algoproclib.cpp \
    randomgenerator.cpp \
    algoprocfactory.cpp \
    smtwoecsign.cpp \
    smtwoecverify.cpp \
    smthreehash.cpp \
    smfourecbcrypt.cpp \
    eckeygenerator.cpp \
    symmkeygenerator.cpp

HEADERS += \
    algoproclib.h \
    randomgenerator.h \
    algoprocfactory.h \
    algoproc_common.h \
    smtwoecsign.h \
    smtwoecverify.h \
    smthreehash.h \
    smfourecbcrypt.h \
    eckeygenerator.h \
    symmkeygenerator.h
