# Modify to point to your Wireshark and glib include directories
INCS = -I/usr/include/wireshark 

SRCS     = packet-minecraft.c

CC   = gcc

OBJS = $(foreach src, $(SRCS), $(src:.c=.o))

PLUGIN_NAME = packet-minecraft
PLUGIN_DIR  = $(HOME)/.wireshark/plugins
PLUGIN      = $(PLUGIN_DIR)/$(PLUGIN_NAME).so

CFLAGS = `pkg-config --cflags --libs glib-2.0` $(INCS) -DINET6 -D_U_=__attribute__\(\(unused\)\) -Wall -Wpointer-arith -g -DXTHREADS -D_REENTRANT -DXUSE_MTSAFE_API -fPIC -DPIC

$(PLUGIN) : $(OBJS)
	mkdir -p $(PLUGIN_DIR)
	$(CC) -shared $(OBJS) -o $@

%.o : %.c
	$(CC) -c $(CFLAGS) $< -o $@

clean:
	rm -f $(PLUGIN) $(OBJS)

