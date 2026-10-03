CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c99
LDFLAGS =

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
    LDFLAGS += -lpthread
endif
ifeq ($(UNAME_S),Darwin)
    LDFLAGS += -lpthread
endif

SOURCES = main.c scanner.c
OBJECTS = $(SOURCES:.c=.o)
TARGET = nmap_c

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f $(OBJECTS) $(TARGET)

.PHONY: all clean
