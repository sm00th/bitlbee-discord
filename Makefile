CC=gcc
CFLAGS+=`pkg-config --cflags bitlbee` -fPIC -Wall -g3 -ggdb -O0
LDFLAGS+=-shared

TARGET=discord.so

$(TARGET): discord.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

install: $(TARGET)
	install -Dm=755 $(TARGET) "$(DESTDIR)/usr/lib64/bitlbee/$(TARGET)"

clean:
	rm -rf $(TARGET) *.o
