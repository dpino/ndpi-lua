LIB_DIR=./lib
INCLUDE_DIR=./include
SRC=./src

all:
	gcc -L${LIB_DIR} -I${INCLUDE_DIR} -lndpi -lpcap ${SRC}/ndpiReader.c -fPIC -shared -o src/libndpilua.so

clean:
	rm -Rf src/libndpilua.so
