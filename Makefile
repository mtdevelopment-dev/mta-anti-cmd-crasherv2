# ==============================================================================
# MTA:SA Server Shield - Linux x64 Build System
# ==============================================================================

CXX ?= g++
CXXFLAGS ?= -std=c++17 -O2 -fPIC -Wall -Wextra -pthread
LDFLAGS ?= -shared -fPIC -ldl -lpthread

TARGET_DIR = bin/x64
TARGET = $(TARGET_DIR)/mta_server_shield.so
SRCS = src/mta_server_shield.cpp

all: $(TARGET)

$(TARGET): $(SRCS)
	@mkdir -p $(TARGET_DIR)
	@echo "[*] Compiling mta_server_shield.so (Linux x64)..."
	$(CXX) $(CXXFLAGS) $(SRCS) -o $(TARGET) $(LDFLAGS)
	@strip --strip-unneeded $(TARGET) 2>/dev/null || true
	@echo "======================================================="
	@echo "  [SUCCESS] Built successfully: $(TARGET)"
	@echo "======================================================="

clean:
	rm -f $(TARGET)

.PHONY: all clean
