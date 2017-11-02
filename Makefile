APP_NAME=truncap
INCLUDES+=
DEFINES+=
LIBS+=-lpcap
CFLAGS+=-Wall -Wextra -Wno-unused-parameter -pedantic -std=gnu11 $(INCLUDES) $(DEFINES)
LDFLAGS+=$(LIBS)
OBJS=truncap.o

all: truncap

truncap: $(OBJS)
	$(CC) $(LDFLAGS) $(OBJS) -o truncap

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.o truncap

