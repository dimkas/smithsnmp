# Makefile for Lua BitOp -- a bit operations library for Lua 5.1.
# To compile with MSVC please run: msvcbuild.bat
# To compile with MinGW please run: mingw32-make -f Makefile.mingw
# To compile with lua52: run: make LUAVER=5.2.4 macosx
# To compile with P1010: make CC=powerpc-fsl-linux-gnuspe-gcc DEFINES=-DSNMP_BIG_ENDIAN=1

# Include path where lua.h, luaconf.h and lauxlib.h reside:
LUAVER=5.1.4

INCLUDES= -I/workspace/zdc/external/lua-$(LUAVER)/src -I/usr/local/include -I/opt/local/include -I../core

# Use this if you need to compile for an old ARM ABI with swapped FPA doubles
#DEFINES= -DSWAPPED_DOUBLE

# Lua executable name. Used to find the install path and for testing.
LUA= lua

CC= gcc
SOCFLAGS= -fPIC -lz
SOCC= $(CC) -shared $(SOCFLAGS)
CFLAGS= -Wall -O2 -fomit-frame-pointer $(SOCFLAGS) $(DEFINES) $(INCLUDES) -DDISABLE_CRYPTO -DDISABLE_SHA -DDISABLE_AES -DSNMPCODEC
RM= rm -f
INSTALL= install -p
INSTALLPATH= $(LUA) installpath.lua

MODNAME= snmpcodec
MODOTHER=../core/snmp_decoder.o ../core/snmp_encoder.o ../core/mib_tree.o ../core/mib_view.o ../core/snmp_msg_in.o ../core/snmp_msg_out.o ../core/snmp_msg_proc.o zsnmp_mib.o zsnmp_trap.o
MODSO= $(MODNAME).so

all: $(MODSO)

# Alternative target for compiling on Mac OS X:
macosx:
	$(MAKE) all "SOCC=MACOSX_DEPLOYMENT_TARGET=10.3 $(CC) -dynamiclib -single_module -undefined dynamic_lookup $(SOCFLAGS)"

$(MODSO): $(MODNAME).o $(MODOTHER)
	$(SOCC) -o $@ $< $(MODOTHER)

install: $(MODSO)
	#$(INSTALL) $< `$(INSTALLPATH) $(MODNAME)`

test: $(MODSO)
	#@$(LUA) md5test.lua && echo "MD5 test OK"

clean:
	$(RM) *.o *.so *.obj *.lib *.exp *.dll *.manifest ../core/*.o ../core/*.obj ../core/*.lib

.PHONY: all macosx install test clean

