# use "make OLDLIB=-DOLDFREEFARE" to use libfreefare<=0.4.0 (2015)

TARGET  := mctcli
WARN    := -Wall
CFLAGS  := -O2 ${WARN} `pkg-config --cflags libfreefare` ${OLDLIB}
LDFLAGS := `pkg-config --libs libfreefare` -lm
CC      := gcc

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
