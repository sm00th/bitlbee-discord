CC=gcc
CFLAGS+=`pkg-config --cflags bitlbee` -fPIC -Wall -g3 -ggdb -O0
LDFLAGS+=-shared

TARGET=discord.so

$(TARGET): discord.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

install: $(TARGET)
	install -m=755 $(TARGET) /usr/lib64/bitlbee

clean:
	rm -rf $(TARGET) *.o
