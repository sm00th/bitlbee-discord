# Copyright 2017 Artem Savkov <artem.savkov@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

EXTRA_DIST = discord-help.txt

install-data-local:
	if [ -f $(datadir)/help.txt ]; then \
		for file in $(EXTRA_DIST); do \
			$(INSTALL) -m 644 $(srcdir)/$$file $(DESTDIR)$(datadir)/; \
		done \
	else \
		echo "Detected dir $(datadir) is not bitlbee's data dir"; \
		echo "Skipping help install"; \
	fi
