CC = gcc
UNAME := $(shell uname)
SERVER := getpkd
CLIENT := getpk
#DEBUGFLAGS = -D DEBUG -g

ifeq ($(UNAME), OpenBSD)
	LIBSs = /usr/local/lib
	INCLUDES = /usr/local/include
	OS = BSD
	BSD_TYPE = OPENBSD
	INSTALL_DIR = /usr/local/sbin
	MANPATH = /usr/local/man
	MANOWNER = root:bin
	CCFLAGS = -D ${OS} -D ${BSD_TYPE} ${DEBUGFLAGS}
endif
ifeq ($(UNAME), Linux)
	LIBSs = /usr/lib64		# NEEDED ONLY FOR RHEL
	INCLUDES = /usr/include
	OS = LINUX
	LINUX_LIB = -lrt
	MANPATH = /usr/local/share/man
	MANOWNER = root:root
	CCFLAGS = -D ${OS} ${DEBUGFLAGS}
	INSTALL_DIR = /usr/local/sbin

        ifneq ("$(wildcard /etc/debian_version)", "")
	INSTALL_DIR = /opt/getpktools
        endif
endif

objects = config.o ldap_call.o parse_line.o uri.o errorlog.o

uri.o: uri.h
	$(CC) $(CCFLAGS) -c -I${INCLUDES} uri.c -o uri.o

errorlog.o: getpkd.h
	$(CC) $(CCFLAGS) -c errorlog.c -o errorlog.o

ldap_call.o: ldap_call.h
	$(CC) $(CCFLAGS) -pthread -c -I${INCLUDES} ldap_call.c -o ldap_call.o

parse_line.o: parse_line.h
	$(CC) $(CCFLAGS) -pthread -c -I${INCLUDES} parse_line.c -o parse_line.o

config.o: config.h
	$(CC) $(CCFLAGS) -pthread -c -I${INCLUDES} config.c -o config.o

all: $(objects)
	$(CC) $(CCFLAGS) -pthread -o $(SERVER) $(objects) -I${INCLUDES} -L${LIBSs} -L/lib64 ${LINUX_LIB} -lldap -lpthread getpkd.c
	$(CC) $(CCFLAGS) -pthread -o $(CLIENT) -I${INCLUDES} -L${LIBSs} -L/lib64 -lldap errorlog.c getpk.c
	@rm -f $(objects)

install:
	@mkdir -p ${INSTALL_DIR}
	@cp $(SERVER) ${INSTALL_DIR}/$(SERVER)
	@cp $(CLIENT) ${INSTALL_DIR}/$(CLIENT)
	@chmod 555 ${INSTALL_DIR}/$(SERVER)
	@chmod 555 ${INSTALL_DIR}/$(CLIENT)

ifeq ($(wildcard /etc/getpkd.conf),) 
	@cp getpkd.conf /etc/
endif	

	@mkdir -p ${MANPATH}/man5
	@mkdir -p ${MANPATH}/man8
	@cp man/getpkd.8 ${MANPATH}/man8/getpkd.8
	@cp man/getpk.8 ${MANPATH}/man8/getpk.8
	@cp man/getpkd.conf.5 ${MANPATH}/man5/getpkd.conf.5

	@chmod 644 ${MANPATH}/man5/getpkd.conf.5
	@chmod 644 ${MANPATH}/man8/getpk.8
	@chmod 644 ${MANPATH}/man8/getpkd.8

	@chown ${MANOWNER} ${MANPATH}/man5/getpkd.conf.5
	@chown ${MANOWNER} ${MANPATH}/man8/getpk.8
	@chown ${MANOWNER} ${MANPATH}/man8/getpkd.8

ifeq (${OS}, BSD)
	@chown root:bin ${INSTALL_DIR}/$(SERVER)
	@chown root:bin ${INSTALL_DIR}/$(CLIENT)
#	@/usr/sbin/makewhatis ${MANPATH}

else
	@chown root:root ${INSTALL_DIR}/$(SERVER)
	@chown root:root ${INSTALL_DIR}/$(CLIENT)

endif

clean:
	@rm -f $(objects)
	@rm -f $(SERVER)
	@rm -f $(CLIENT)
