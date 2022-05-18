# use "make OLDLIB=yes" to use libfreefare<=0.4.0 (2015)
# use "make SYSKEYFILE=/path/to/keyfile" to set global keyfile location (default is /usr/share/mctcli/mctcli_keys.dic)

TARGET  := mctcli
WARN    := -Wall
CFLAGS  := -O2 ${WARN} `pkg-config --cflags libfreefare`
LDFLAGS := `pkg-config --libs libfreefare` -lm
CC      := gcc

ifdef OLDLIB
CFLAGS += -DOLDFREEFARE
endif

ifdef SYSKEYFILE
CFLAGS += -DSYSKEYFILE=\"${SYSKEYFILE}\"
endif

C_SRCS    = $(wildcard *.c)
OBJ_FILES = $(C_SRCS:.c=.o)

all: ${TARGET}

%.o: %.c
	${CC} ${WARN} -c ${CFLAGS}  $< -o $@

mynfc_lav: mctcli.o
	${CC} ${WARN} ${LDFLAGS} -o $@ mctcli.o

clean:
	rm -rf *.o ${TARGET}

mrproper: clean
	rm -rf *~
