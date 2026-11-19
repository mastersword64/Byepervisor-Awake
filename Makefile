#   Byepervisor Awake — PS5 HV defeat for FW 5.00–6.02
#   Based on Byepervisor Reborn by EchoStretch/PS5Dev

PS5_HOST ?= ps5
PS5_PORT ?= 9021

ifdef PS5_PAYLOAD_SDK
    include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
else
    $(error PS5_PAYLOAD_SDK is undefined)
endif

ELF := byepervisor_awake.elf

CFLAGS := -Wall -Werror -Wno-unused-function -Wno-unused-const-variable -g -I./include -lSceSystemService

all: $(ELF)

$(ELF): main.c kdlsym.c khook.c paging.c util.c
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(ELF)

send: $(ELF)
	nc -q0 10.0.0.196 $(PS5_PORT) < $(ELF)
