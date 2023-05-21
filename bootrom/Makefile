march ?= rv64imafdc
mabi ?= lp64
CC ?= riscv64-unknown-elf-gcc
OBJCOPY ?= riscv64-unknown-elf-objcopy

CFLAGS += \
	-march=$(march) -mcmodel=medany -mabi=$(mabi) \
	-nostdlib -nostartfiles -fno-common -std=gnu11 \
	-static \
	-fPIC \
	-O2 -Wall#\
	-I/home/valerio/keystone/bootrom/mbed_tls_keystone#\
	-I/home/valerio/Scrivania/libsodium-client/src/libsodium/include \
	-I/home/valerio/Scrivania/libsodium-client/src/libsodium/include/sodium #\
	-I/home/valerio/keystone/bootrom/openssl/include#\
	-I/home/valerio/Scrivania/openssl_riscv64_v2/include #\
	-Wl,--whole-archive /home/valerio/Scrivania/openssl_riscv64/lib/libcrypto.a \
	-Wl,--no-whole-archive \
	-Wl,-Bstatic -lcrypto -Wl,-Bdynamic
O ?=.

#LDFLAGS = \
	#-L/home/valerio/Scrivania/openssl_riscv64_v2/lib \
	-lssl \
	-lcrypto #\
	-lglibc #\
	-L$(KEYSTONE_SDK_DIR)/lib \
	-lc \
	-Wl,-Bstatic -lcrypto -Wl,-Bdynamic
#LDFLAGS+="-Wl,-rpath-link,/home/valerio/keystone/riscv64/sysroot/usr/lib"

#LDFLAGS += -L/home/valerio/keystone/riscv64/lib -Wl,--whole-archive -lc -Wl,--no-whole-archive


# ^ consider taking out -g -Og and putting in -O2

bootloaders=\
	$(O)/bootrom.elf \
	$(O)/bootrom.bin

.PHONY: all
all: $(bootloaders)

.PHONY: clean
clean:
	rm -f $(bootloaders)

bootrom_sources = \
	./bootloader.S \
	./bootloader.c \
	./ed25519/*.c \
	./sha3/*.c \
	./x509custom/*.c\
	./myString.c#\
	./string.c#\
	./prova.c#\
	./mbed_tls_keystone/*.c#\
	./mbed_tls_keystone/crypto_*.c#\
	./openssl/crypto/evp/kdf_meth.c \
	./openssl/crypto/evp/kdf_lib.c \
	./openssl/crypto/params.c \
	./openssl/crypto/hmac/hmac.c#\
	./openssl/crypto/hmac/hmac.c\
	./openssl/crypto/evp/evp_*.c\
	./openssl/crypto/err/err.c#\
	./openssl/crypto/evp/*.c #\
	./openssl/crypto/kdf/*.c# \
	./openssl/engines/*.c \
	./openssl/fuzz/*.c\
	./openssl/util/*.c #\
	./openssl/ssl/*.o \
	./openssl/crypto/*.o \
	./openssl/engines/*.o \
	./openssl/fuzz/*.o\
	./openssl/util/*.o #\
	./openssl/provider/*.o #\
	./libsodium-client/src/libsodium/crypto_pwhash/crypto_pwhash.c #\
	#-I./libsodium-client/src/libsodium/include

%.elf: $(bootrom_sources) bootloader.lds
	$(CC) $(CFLAGS) -I./  -L . -T bootloader.lds -o $@ $(bootrom_sources) 

%.bin: %.elf
	$(OBJCOPY) -O binary --only-section=.text $< $@;
