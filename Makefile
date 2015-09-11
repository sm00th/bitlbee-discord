CC=gcc
CFLAGS+=`pkg-config --cflags bitlbee` -fPIC
LDFLAGS+=-shared

TARGET=discord.so

$(TARGET): discord.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

install:
	install -m=755 $(TARGET) /usr/lib64/bitlbee

clean:
	rm -rf $(TARGET) *.o
