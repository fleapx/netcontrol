ROOT := ${shell pwd}

PUB := DEBUG
LKJSON_64 := -Wl,--whole-archive ${ROOT}/third-64/jansson/lib/libjansson.a -Wl,--no-whole-archive
ifeq (/usr/lib64/libjansson.a, $(wildcard /usr/lib64/libjansson.a))
    LKJSON_64 := -Wl,--whole-archive /usr/lib64/libjansson.a -Wl,--no-whole-archive
endif
LKJSON_32 := -Wl,--whole-archive ${ROOT}/third/jansson/lib/libjansson.a -Wl,--no-whole-archive
ifeq (/usr/lib/libjansson.a, $(wildcard /usr/lib/libjansson.a))
    LKJSON_32 := -Wl,--whole-archive /usr/lib/libjansson.a -Wl,--no-whole-archive
endif
CFLAGS := ${CFLAGS} -I${ROOT}/third-64/jansson/include -ldl -lstdc++ -lrt -lpthread -fPIC -shared -Wall -Wextra -fvisibility=hidden
CXXFLAGS := ${CXXFLAGS} -I${ROOT}/third-64/jansson/include -ldl -lstdc++ -lrt -lpthread -fPIC -Wall -Wextra -fvisibility=hidden
LDFLAGS := ${LDFLAGS} 
DYNLIB := -shared
CC := c++

service_path := /etc/init.d/taurus
	
TCP_API := -DHOOK_ACCEPT -DHOOK_ACCEPT4
UDP_API := -DHOOK_SEND -DHOOK_RECV -DHOOK_SENDTO -DHOOK_RECVFROM -DHOOK_READ -DHOOK_WRITE
EXTRA := -DHOOK_DLSYM  -DHOOK_CONNECT ${TCP_API} 
	
ifeq (${PUB}, DEBUG)
    CFLAGS := ${CFLAGS} -g -DDEBUG -UNDEBUG -Wall -fvisibility=hidden
    CXXFLAGS := ${CXXFLAGS} -g -DDEBUG -UNDEBUG -fvisibility=hidden
else # RELEASE
    CFLAGS := ${CFLAGS} -O3 -UDEBUG -DNDEBUG -fvisibility=hidden
    CXXFLAGS := ${CXXFLAGS} -O3 -UDEBUG -DNDEBUG -fvisibility=hidden
endif
$(info Compile as ${PUB})
ifeq (${PUB}, DEBUG)
    $(info without strip) 
else
    $(info with strip)
endif

all :  taurus_service taurus_lib taurus_lib_32 taurus_lib_test taurus_lib_empty

taurus_lib_out := libtaurus.so
taurus_lib_source := src/taurus_lib.cpp src/info_manager.cpp src/interprocess.cpp src/report.cpp \
	src/symbols.c src/thpool.cpp src/utils.cpp 
taurus_lib : ${taurus_lib_source}
ifeq (${PUB}, DEBUG)
	${CC} ${CXXFLAGS} ${EXTRA} ${DYNLIB} -o ${taurus_lib_out} ${taurus_lib_source} ${LDFLAGS} ${LIBS} -DLIB -m64 ${LKJSON_64}
else
	${CC} ${CXXFLAGS} ${EXTRA} ${DYNLIB} -o ${taurus_lib_out} ${taurus_lib_source} ${LDFLAGS} ${LIBS} -DLIB -m64 ${LKJSON_64}
	strip ${taurus_lib_out}
endif

taurus_lib_out_32 := libtaurus32.so
taurus_lib_32 : ${taurus_lib_source}
ifeq (${PUB}, DEBUG)
	${CC} ${CXXFLAGS} ${EXTRA} ${DYNLIB} -o ${taurus_lib_out_32} ${taurus_lib_source} ${LDFLAGS} ${LIBS} -DLIB -m32 ${LKJSON_32}
else
	${CC} ${CXXFLAGS} ${EXTRA} ${DYNLIB} -o ${taurus_lib_out_32} ${taurus_lib_source} ${LDFLAGS} ${LIBS} -DLIB -m32 ${LKJSON_32}
	strip ${taurus_lib_out_32}
endif

taurus_lib_test_out := libtaurus_test
taurus_lib_test_source := src/taurus_lib_test.cpp src/interprocess.cpp src/thpool.cpp src/utils.cpp 
taurus_lib_test : ${taurus_lib_test_source}
	${CC} ${CXXFLAGS} -o ${taurus_lib_test_out} ${taurus_lib_test_source} ${LDFLAGS} ${LIBS} -DLIB -m64 ${LKJSON_64}

taurus_lib_empty_out := libtaurus_empty.so
taurus_lib_empty_source := src/taurus_lib.cpp src/info_manager.cpp src/interprocess.cpp src/report.cpp \
	src/symbols.c src/thpool.cpp src/utils.cpp 
taurus_lib_empty : ${taurus_lib_empty_source}
	${CC} ${CXXFLAGS} ${EXTRA} ${DYNLIB} -o ${taurus_lib_empty_out} ${taurus_lib_empty_source} ${LDFLAGS} ${LIBS} -DEMPTYLIB -m64 ${LKJSON_64}

taurus_service_out := taurus_starter
taurus_service_source := src/taurus_service.cpp src/info_manager.cpp src/interprocess.cpp \
	src/report.cpp src/rule_manager.cpp src/symbols.c src/thpool.cpp src/utils.cpp 
taurus_service : ${taurus_service_source}
ifeq (${PUB}, DEBUG)
	${CC} ${CXXFLAGS} ${EXTRA} -o ${taurus_service_out} ${taurus_service_source} ${LDFLAGS} ${LIBS} -m64 ${LKJSON_64}
	
else
	${CC} ${CXXFLAGS} ${EXTRA} -o ${taurus_service_out} ${taurus_service_source} ${LDFLAGS} ${LIBS} -m64 ${LKJSON_64}
	strip ${taurus_service_out}
endif		

clean:
	chmod +x deploy.sh
	./deploy.sh undeploy
	rm -f *.o  ${taurus_lib_out}  ${taurus_service_out}  /lib64/${taurus_lib_out} /lib/${taurus_lib_out}  /usr/bin/${taurus_service_out} 

install:
	chmod +x deploy.sh
	./deploy.sh undeploy
	cp -f ${taurus_lib_out} /lib64/${taurus_lib_out}
	cp -f ${taurus_lib_out_32} /lib/${taurus_lib_out}
	cp -f ${taurus_service_out} /usr/bin/${taurus_service_out}
	chmod u+sx /lib64/${taurus_lib_out} /lib/${taurus_lib_out} # '+s' stop sudo warning
	./deploy.sh addservice
	./deploy.sh deploy
