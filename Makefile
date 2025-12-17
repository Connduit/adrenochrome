# === Compiler and flags ===
CC      := x86_64-w64-mingw32-gcc
CXX     := x86_64-w64-mingw32-g++
CFLAGS  := -Wall -Wextra -O0 -g -Icommon
CXXFLAGS:= -std=c++17 -Wall -Wextra -O0 -g -Icommon
LDFLAGS := -shared

OBJ_DIR  := obj
BIN_DIR  := bin

# === Add include paths for each module ===
CFLAGS  += -Iinstaller/include -Iloader/include -Ibuilder/include -Icommon/include
CXXFLAGS+= -Iinstaller/include -Iloader/include -Ibuilder/include -Icommon/include

# === Source discovery ===
INSTALLER_SOURCES := $(wildcard installer/src/*.c) $(wildcard installer/src/*.cpp)
LOADER_SOURCES    := $(wildcard loader/src/*.c) $(wildcard loader/src/*.cpp)
BUILDER_SOURCES   := $(wildcard builder/src/*.c) $(wildcard builder/src/*.cpp)
COMMON_SOURCES    := $(wildcard common/src/*.c) $(wildcard common/src/*.cpp)

# === Object lists (preserve directories) ===
COMMON_OBJS    := $(patsubst %.c,$(OBJ_DIR)/%,$(COMMON_SOURCES:.c=.o))
COMMON_OBJS    := $(patsubst %.cpp,$(OBJ_DIR)/%,$(COMMON_OBJS:.cpp=.o))

INSTALLER_OBJS := $(patsubst %.c,$(OBJ_DIR)/%,$(INSTALLER_SOURCES:.c=.o))
INSTALLER_OBJS := $(patsubst %.cpp,$(OBJ_DIR)/%,$(INSTALLER_OBJS:.cpp=.o))
INSTALLER_OBJS := $(INSTALLER_OBJS) $(COMMON_OBJS)

LOADER_OBJS := $(patsubst %.c,$(OBJ_DIR)/%,$(LOADER_SOURCES:.c=.o))
LOADER_OBJS := $(patsubst %.cpp,$(OBJ_DIR)/%,$(LOADER_OBJS:.cpp=.o))
LOADER_OBJS := $(LOADER_OBJS) $(COMMON_OBJS)

BUILDER_OBJS := $(patsubst %.c,$(OBJ_DIR)/%,$(BUILDER_SOURCES:.c=.o))
BUILDER_OBJS := $(patsubst %.cpp,$(OBJ_DIR)/%,$(BUILDER_OBJS:.cpp=.o))
BUILDER_OBJS := $(BUILDER_OBJS) $(COMMON_OBJS)


# === Output files ===
INSTALLER_DLL := $(BIN_DIR)/installer.dll
LOADER_DLL    := $(BIN_DIR)/loader.dll
BUILDER_EXE   := $(BIN_DIR)/builder.exe

# === Default target ===
all: $(INSTALLER_DLL) $(LOADER_DLL) $(BUILDER_EXE)

# === Build installer.dll ===
$(INSTALLER_DLL): $(INSTALLER_OBJS)
	@mkdir -p $(BIN_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

# === Build loader.dll ===
$(LOADER_DLL): $(LOADER_OBJS)
	@mkdir -p $(BIN_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

# === Build builder.exe ===
$(BUILDER_EXE): $(BUILDER_OBJS)
	@mkdir -p $(BIN_DIR)
	$(CXX) $^ -o $@

# === Compile rules ===
$(OBJ_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/%.o: %.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# === Clean target ===
clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)

.PHONY: all clean

