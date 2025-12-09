# === Compiler and flags ===
CC  := x86_64-w64-mingw32-gcc
CXX := x86_64-w64-mingw32-g++
# STRICT_CFLAGS := -Wall -Wextra -Wpointer-arith -Wpointer-sign -Wconversion -Wcast-align -O0 -g -Icommon
CFLAGS := -Wall -Wextra -O0 -g -Icommon
CXXFLAGS := -std=c++17 -Wall -Wextra -O0 -g -Icommon
LDFLAGS := -shared

# === Directory structure ===
SRC_DIRS := installer common loader
OBJ_DIR := obj
BIN_DIR := bin

# === Source file discovery ===
C_SOURCES   := $(foreach dir,$(SRC_DIRS),$(wildcard $(dir)/*.c))
CPP_SOURCES := $(foreach dir,$(SRC_DIRS),$(wildcard $(dir)/*.cpp))

# === Object file generation (mirrors directory structure) ===
C_OBJS   := $(patsubst %.c,$(OBJ_DIR)/%.o,$(C_SOURCES))
CPP_OBJS := $(patsubst %.cpp,$(OBJ_DIR)/%.o,$(CPP_SOURCES))

OBJS := $(C_OBJS) $(CPP_OBJS)

# === Output DLL ===
INSTALLER_DLL := $(BIN_DIR)/installer.dll

# === Default target ===
all: $(INSTALLER_DLL)

# === Build DLL ===
$(INSTALLER_DLL): $(OBJS) | $(BIN_DIR)
	$(CXX) $(LDFLAGS) $(OBJS) -o $@

# === Compile C source ===
$(OBJ_DIR)/%.o: %.c | prepare_dirs
	$(CC) $(CFLAGS) -c $< -o $@

# === Compile C++ source ===
$(OBJ_DIR)/%.o: %.cpp | prepare_dirs
	$(CXX) $(CXXFLAGS) -c $< -o $@

# === Directory creation ===
prepare_dirs:
	@mkdir -p $(BIN_DIR)
	@for dir in $(SRC_DIRS); do mkdir -p $(OBJ_DIR)/$$dir; done

# === Cleanup ===
clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)

.PHONY: all clean prepare_dirs

