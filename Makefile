CC=gcc
CFLAGS+=`pkg-config --cflags bitlbee` -fPIC -Wall -g3 -ggdb -O0 -std=gnu99
LDFLAGS+=-shared
LDFLAGS+=`pkg-config --libs libwebsockets`

OBJS=discord.o discord-http.o discord-websockets.o discord-handlers.o discord-util.o
TARGET=discord.so

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

%.o: src/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

install: $(TARGET)
	install -Dm 755 $(TARGET) "$(DESTDIR)/usr/lib/bitlbee/$(TARGET)"

clean:
	rm -rf $(TARGET) *.o
