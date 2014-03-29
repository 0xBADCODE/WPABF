##################################
# WPABF Makefile 
# Thomas Hand <th6045@gmail.com>
##################################
LDLIBS		+= -lcrypto
CFLAGS		= -s -W -g3 -ggdb
#CFLAGS		+= -static
PROGOBJ		= wpabf.o
PROG		= wpabf
BINDIR		= /usr/local/bin

all: $(PROGOBJ) $(PROG)

wpabf: wpabf.c wpabf.h
	$(CC) $(CFLAGS) -o wpabf wpabf.c $(LDLIBS)

clean:
	@rm -f $(PROGOBJ) $(PROG)
