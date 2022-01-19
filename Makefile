TARGET  := mctcli
WARN    := -Wall
#OLDLIB	:= -DOLDFREEFARE
CFLAGS  := -O2 ${WARN} `pkg-config --cflags libnfc libfreefare` ${OLDLIB}
LDFLAGS := `pkg-config --libs libnfc libfreefare` -lm
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
