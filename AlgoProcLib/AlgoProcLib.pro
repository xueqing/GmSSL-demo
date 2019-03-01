QT       -= core gui

TARGET = AlgoProcLib
TEMPLATE = lib

CONFIG += c++11

unix
{
    CONFIG(debug, debug|release) {
        LIBS += -L$$PWD/../build/debug
        DESTDIR = $$PWD/../build/debug
    } else {
        LIBS += -L$$PWD/../build/release
        DESTDIR = $$PWD/../build/release
    }
}

unix{
    target.path = /usr/lib
    INSTALLS += target
}

INCLUDEPATH += \
    $$PWD/../include

SOURCES += \
    algoproclib.cpp \
    randomgenerator.cpp \
    algoprocfactory.cpp \
    smtwoellipticcurvesign.cpp \
    smtwoellipticcurveverify.cpp

HEADERS += \
    algoproclib.h \
    randomgenerator.h \
    algoprocfactory.h \
    algoproc_common.h \
    smtwoellipticcurvesign.h \
    smtwoellipticcurveverify.h
