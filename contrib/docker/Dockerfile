FROM debian
MAINTAINER Daniel da Silva <mail@danieldasilva.org>

# Make & install
RUN apt-get update
RUN apt-get install bitlbee-dev bitlbee-libpurple bitlbee-plugin-otr git autoconf build-essential autoproject libtool glib2.0 glib2.0-dev -y
RUN mkdir /data
RUN cd tmp && git clone https://github.com/sm00th/bitlbee-discord.git && cd bitlbee-discord && ./autogen.sh && ./configure && make && make install

# Bitlbee config
VOLUME ["/data"]
EXPOSE 6667

ADD bitlbee.conf /etc/bitlbee/bitlbee.conf

ENTRYPOINT ["/usr/sbin/bitlbee", "-n", "-c", "/etc/bitlbee/bitlbee.conf"]
