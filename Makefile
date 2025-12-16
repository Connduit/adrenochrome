# === Compiler and flags ===
CC      := x86_64-w64-mingw32-gcc
CXX     := x86_64-w64-mingw32-g++
CFLAGS  := -Wall -Wextra -O0 -g -Icommon
CXXFLAGS:= -std=c++17 -Wall -Wextra -O0 -g -Icommon
LDFLAGS := -shared

# === Directory structure ===
SRC_DIRS := installer loader common
OBJ_DIR  := obj
BIN_DIR  := bin

# === Source discovery ===
INSTALLER_CSOURCES := $(wildcard installer/*.c)
INSTALLER_CPPSOURCES := $(wildcard installer/*.cpp)

LOADER_CSOURCES := $(wildcard loader/*.c)
LOADER_CPPSOURCES := $(wildcard loader/*.cpp)

COMMON_CSOURCES := $(wildcard common/*.c)
COMMON_CPPSOURCES := $(wildcard common/*.cpp)

# === Object lists ===
COMMON_OBJS := $(patsubst %.c,$(OBJ_DIR)/%.o,$(COMMON_CSOURCES)) \
			   $(patsubst %.cpp,$(OBJ_DIR)/%.o,$(COMMON_CPPSOURCES))

INSTALLER_OBJS := $(patsubst %.c,$(OBJ_DIR)/%.o,$(INSTALLER_CSOURCES)) \
				  $(patsubst %.cpp,$(OBJ_DIR)/%.o,$(INSTALLER_CPPSOURCES)) \
				  $(COMMON_OBJS)

LOADER_OBJS := $(patsubst %.c,$(OBJ_DIR)/%.o,$(LOADER_CSOURCES)) \
			   $(patsubst %.cpp,$(OBJ_DIR)/%.o,$(LOADER_CPPSOURCES)) \
			   $(COMMON_OBJS)

# === Output files ===
INSTALLER_DLL := $(BIN_DIR)/installer.dll
LOADER_DLL    := $(BIN_DIR)/loader.dll
# TODO: INSTALLER_EXE

# === Default target builds both DLLs ===
all: $(INSTALLER_DLL) $(LOADER_DLL)

# === Build installer.dll ===
$(INSTALLER_DLL): $(INSTALLER_OBJS)
	@mkdir -p $(BIN_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

# === Build loader.dll ===
$(LOADER_DLL): $(LOADER_OBJS)
	@mkdir -p $(BIN_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

# === Compile rules (handles subdirectories automatically) ===
$(OBJ_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/%.o: %.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# === Clean target ===
clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)

# === PHONY targets ===
.PHONY: all clean

