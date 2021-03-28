include $(top_srcdir)/build/modmake.rulesam
MODNAME=mod_apple_apn

mod_LTLIBRARIES = mod_apple_apn.la
mod_apple_apn_la_SOURCES  = mod_apple_apn.cpp apn_service.cpp
mod_apple_apn_la_CFLAGS   = $(AM_CFLAGS) -std=gnu++11 -I/usr/local/ssl/include/ -I/usr/local/include/
mod_apple_apn_la_LIBADD   = $(switch_builddir)/libfreeswitch.la
mod_apple_apn_la_LDFLAGS  = -avoid-version -module -no-undefined -shared -lpugixml -L/usr/local/ssl/lib -L/usr/local/lib -lcurl -lssl -lcrypto

