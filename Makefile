# Makefile for gcc compiler for toolchain 4 (SDK Headers)

PROJECTNAME:=pypcap.dylib
APPFOLDER:=$(PROJECTNAME).app
INSTALLFOLDERi:=$(PROJECTNAME).app

TOOLCHAIN:=/toolchain4
SDK:=$(TOOLCHAIN)/sys42
MINIMUMVERSION:=4.2
DEPLOYMENTTARGET:=$(MINIMUMVERSION)
IPHONEOSMINVERSION:=40000
#define __IPHONE_3_0     30000
#define __IPHONE_4_0     40000
#define __IPHONE_3_0     30000
#define __IPHONE_4_0     40000
#define __IPHONE_4_1     40100
#define __IPHONE_4_2     40200
DEBUG=DEBUGOFF

#CC:=$(TOOLCHAIN)/pre/bin/arm-apple-darwin9-gcc
CC:=clang -ccc-host-triple arm-apple-darwin9 
CPP:=$(TOOLCHAIN)/pre/bin/arm-apple-darwin9-g++
LD:=$(TOOLCHAIN)/pre/bin/arm-apple-darwin9-gcc


LDFLAGS := 
//LDFLAGS += -lobjc 
//LDFLAGS += -Obj-C
//LDFLAGS += -framework CoreFoundation 
//LDFLAGS += -framework Foundation 
//LDFLAGS += -framework UIKit 
//LDFLAGS += -framework CoreGraphics
//LDFLAGS += -framework AVFoundation
//LDFLAGS += -framework AddressBook
//LDFLAGS += -framework AddressBookUI
//LDFLAGS += -framework AudioToolbox
//LDFLAGS += -framework AudioUnit
//LDFLAGS += -framework CFNetwork
//LDFLAGS += -framework CoreAudio
//LDFLAGS += -framework CoreData
//LDFLAGS += -framework CoreFoundation 
//LDFLAGS += -framework GraphicsServices
//LDFLAGS += -framework CoreLocation
//LDFLAGS += -framework ExternalAccessory
//LDFLAGS += -framework GameKit
//LDFLAGS += -framework IOKit
//LDFLAGS += -framework MapKit
//LDFLAGS += -framework MediaPlayer
//LDFLAGS += -framework MessageUI
//LDFLAGS += -framework MobileCoreServices
//LDFLAGS += -framework OpenAL
//LDFLAGS += -framework OpenGLES
//LDFLAGS += -framework QuartzCore
//LDFLAGS += -framework Security
//LDFLAGS += -framework StoreKit
//LDFLAGS += -framework System
//LDFLAGS += -framework SystemConfiguration
//LDFLAGS += -framework CoreSurface
//LDFLAGS += -framework GraphicsServices
//LDFLAGS += -framework Celestial
//LDFLAGS += -framework WebCore
//LDFLAGS += -framework WebKit
//LDFLAGS += -framework SpringBoardUI
//LDFLAGS += -framework TelephonyUI
//LDFLAGS += -framework JavaScriptCore
//LDFLAGS += -framework PhotoLibrary

LDFLAGS += -isysroot $(SDK)
//LDFLAGS += -F"$(SDK)/System/Library/Frameworks"
//LDFLAGS += -F"$(SDK)/System/Library/PrivateFrameworks"
LDFLAGS += -L"$(TOOLCHAIN)/xklib"
LDFLAGS += -Wl,-dead_strip -all_load -miphoneos-version-min=$(MINIMUMVERSION)
//LDFLAGS += -bind_at_load
LDFLAGS += -multiply_defined suppress
LDFLAGS += -arch=armv6
//LDFLAGS += -shared 
//LDFLAGS += -march=armv6
//LDFLAGS += -mcpu=arm1176jzf-s 

LDLIBS :=
LDLIBS += -lpython2.5
LDLIBS += -lssl -lssl.0.9.8 -lcrypto -lcrypto.0.9.8
LDLIBS += -lpcreposix
LDLIBS += -lpcap

CFLAGS += -ObjC -fblocks
CFLAGS += -std=c99 #-Wall 
CFLAGS += -isysroot $(SDK)
CFLAGS += -I"$(TOOLCHAIN)/xkiphone"
CFLAGS += -I"$(TOOLCHAIN)/xkiphone/python2.5"
CFLAGS += -D__IPHONE_OS_VERSION_MIN_REQUIRED=$(IPHONEOSMINVERSION)
ifeq ($(DEBUG),DEBUGOFF)
CFLAGS += -g0 -O2
else
CFLAGS += -g
CFLAGS += -D$(DEBUG)
endif
CFLAGS += -Wno-attributes -Wno-trigraphs -Wreturn-type -Wunused-variable

ifeq ($(DEBUG),DEBUGOFF)
CPPFLAGS += -g0 -O2
else
CPPFLAGS += -g
CPPFLAGS += -D$(DEBUG)
endif
CPPFLAGS += -isysroot $(SDK)
CPPFLAGS +=  -DWITH_NEXT_FRAMEWORK=0
CPPFLAGS += -D__IPHONE_OS_VERSION_MIN_REQUIRED=$(IPHONEOSMINVERSION)
CPPFLAGS += -Wno-attributes -Wno-trigraphs -Wreturn-type -Wunused-variable
CPPFLAGS += -I"$(SDK)/usr/include/c++/4.2.1" 
CPPFLAGS += -I"$(SDK)/usr/include/c++/4.2.1/armv7-apple-darwin9" 

BUILDDIR=./build/$(MINIMUMVERSION)
SRCDIR1=.
OBJS+=$(patsubst %.m,%.o,$(wildcard $(SRCDIR1)/*.m))
OBJS+=$(patsubst %.c,%.o,$(wildcard $(SRCDIR1)/*.c))
PCH:=$(wildcard *.pch)
INFOPLIST:=$(wildcard *Info.plist)

CFLAGS += -I"$(SRCDIR1)"
CPPLAGS += -I"$(SRCDIR1)"

all:	$(PROJECTNAME)

$(PROJECTNAME):	$(OBJS)
#	export IPHONEOS_DEPLOYMENT_TARGET=$(DEPLOYMENTTARGET);$(LD) $(LDFLAGS) $(filter %.o,$^) -o $@ 
	$(CPP) -O  -shared -F"$(SDK)/System/Library/PrivateFrameworks"  -L"$(TOOLCHAIN)/xklib" -DENV_MACOSX -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -DNDEBUG -D_REENTRANT -DENV_UNIX $(LDLIBS)  $(filter %.o,$^) -o $@

%.o:	%.m
	$(CC)  -c $(CFLAGS) $< -o $@

%.o:	%.c
	$(CC)  -c $(CFLAGS) $< -o $@

%.o:	%.cpp
	$(CPP)  -c $(CPPFLAGS) $< -o $@

dist:	$(PROJECTNAME)
#	rm -rf $(BUILDDIR)
#	mkdir -p $(BUILDDIR)/$(APPFOLDER)
#	@echo "APPL????" > $(BUILDDIR)/$(APPFOLDER)/PkgInfo
#	export CODESIGN_ALLOCATE=$(TOOLCHAIN)/pre/bin/arm-apple-darwin9-codesign_allocate; $(TOOLCHAIN)/pre/bin/ldid -S $(PROJECTNAME)

install: dist
	ping -t 3 -c 1 $(IPHONE_IP)
	ssh root@$(IPHONE_IP) 'rm -fr /Applications/$(INSTALLFOLDER)'
	scp -r $(BUILDDIR)/$(APPFOLDER) root@$(IPHONE_IP):/Applications/$(INSTALLFOLDER)
	@echo "Application $(INSTALLFOLDER) installed"
	ssh mobile@$(IPHONE_IP) 'uicache'

test : dist
	scp t.py iphone:
	@scp $(PROJECTNAME) iphone:
	@cp pypcap.c iphone:
#	ssh iphone cp $(PROJECTNAME) /usr/lib/python2.5/
	@ssh root@iphone "cp /var/xuke/$(PROJECTNAME) /usr/lib/python2.5/site-packages/"
	ssh root@iphone "cd /var/xuke; python ./t.py"

uninstall:
	ping -t 3 -c 1 $(IPHONE_IP)
	ssh root@$(IPHONE_IP) 'rm -fr /Applications/$(INSTALLFOLDER)'
	@echo "Application $(INSTALLFOLDER) uninstalled"

clean:
	@rm -f $(SRCDIR1)/*.o
	@rm -rf $(BUILDDIR)
	@rm -f $(PROJECTNAME)

.PHONY: all dist install uninstall clean
