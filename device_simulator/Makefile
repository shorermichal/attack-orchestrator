CC := cc
CFLAGS := -std=c11 -Wall -Wextra -O2
SRCS := main.c net_util.c
OBJS := $(SRCS:.c=.o)
TARGET := device_simulator

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS)

%.o: %.c net_util.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(TARGET)
