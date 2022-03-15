CC = clang

BUILDDIR = build
SRCDIR = src

LIBBPFSRC = modules/libbpf/src
LIBBPFOBJS = $(LIBBPFSRC)/staticobjs/bpf_prog_linfo.o $(LIBBPFSRC)/staticobjs/bpf.o $(LIBBPFSRC)/staticobjs/btf_dump.o
LIBBPFOBJS += $(LIBBPFSRC)/staticobjs/btf.o $(LIBBPFSRC)/staticobjs/hashmap.o $(LIBBPFSRC)/staticobjs/libbpf_errno.o
LIBBPFOBJS += $(LIBBPFSRC)/staticobjs/libbpf_probes.o $(LIBBPFSRC)/staticobjs/libbpf.o $(LIBBPFSRC)/staticobjs/netlink.o
LIBBPFOBJS += $(LIBBPFSRC)/staticobjs/nlattr.o $(LIBBPFSRC)/staticobjs/str_error.o  $(LIBBPFSRC)/staticobjs/xsk.o

LOADERSRC = loader.c
LOADEROUT = ipip_changer

XDPPROGSRC = xdp.c
XDPPROGBC = xdp.bc
XDPPROGOBJ = xdp.o

LDFLAGS += -lelf -lz
INCS = -I $(LIBBPFSRC)

all: loader xdp

libbpf:
	$(MAKE) -C $(LIBBPFSRC)

loader: libbpf $(OBJS)
	mkdir -p $(BUILDDIR)/
	$(CC) $(LDFLAGS) $(INCS) -o $(BUILDDIR)/$(LOADEROUT) $(LIBBPFOBJS) $(SRCDIR)/$(LOADERSRC)

xdp:
	mkdir -p $(BUILDDIR)/
	$(CC) $(INCS) -D__BPF__ -O2 -emit-llvm -c -o $(BUILDDIR)/$(XDPPROGBC) $(SRCDIR)/$(XDPPROGSRC)
	llc -march=bpf -filetype=obj -o $(BUILDDIR)/$(XDPPROGOBJ) $(BUILDDIR)/$(XDPPROGBC)

clean:
	$(MAKE) -C $(LIBBPFSRC) clean
	rm -f $(BUILDDIR)/*.o $(BUILDDIR)/*.bc
	rm -f $(BUILDDIR)/$(LOADEROUT)

install:
	mkdir -p /etc/ipip_changer/
	cp $(BUILDDIR)/$(XDPPROGOBJ) /etc/ipip_changer/$(XDPPROGOBJ)
	cp $(BUILDDIR)/$(LOADEROUT) /usr/bin/$(LOADEROUT)
	cp data/ipip_changer.service /etc/systemd/system/

.PHONY: libbpf all
.DEFAULT: all