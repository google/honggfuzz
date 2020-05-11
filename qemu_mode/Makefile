
.PHONY: clean qemu_bin

TARGETS ?= i386-linux-user x86_64-linux-user

qemu_bin: honggfuzz-qemu/config.status
	@echo "\nRun \"cd honggfuzz-qemu/ && make\"."
	@echo "Targets: \"honggfuzz-qemu/*-linux-user/qemu-*\".\n"

honggfuzz-qemu/config.status: honggfuzz-qemu/
	@echo "=== Configuring QEMU for \"$(TARGETS)\" ==="
	@cd honggfuzz-qemu/ && \
		LIBS=-ldl ./configure --honggfuzz-path="$(PWD)/../" --disable-system --target-list="$(TARGETS)"

honggfuzz-qemu/:
	@echo "=== Cloning custom QEMU version ==="
	@git clone --depth 1 https://github.com/thebabush/honggfuzz-qemu.git -b honggfuzz

clean:
	@echo "=== Cleaning ==="
	rm -rf honggfuzz-qemu/
