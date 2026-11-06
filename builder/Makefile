# Standalone analysis tools; no runtime loader or legacy conversion objects.
CXX ?= c++
AR ?= ar
PYTHON ?= python3
CPPFLAGS += -Iinclude
CXXFLAGS ?= -O2 -Wall -Wextra
CXXFLAGS += -std=c++17
BUILD_DIR ?= build
EXEEXT ?=

ARCHIVE_LIB := $(BUILD_DIR)/libaxe_archive.a
BUILDER := $(BUILD_DIR)/builder$(EXEEXT)
EXTRACTOR := $(BUILD_DIR)/axe_extract$(EXEEXT)
OBJECTS := $(BUILD_DIR)/AxeArchive.o $(BUILD_DIR)/main.o $(BUILD_DIR)/extract_main.o

.PHONY: all test
all: $(BUILDER) $(EXTRACTOR)

$(BUILD_DIR):
	mkdir -p "$@"

$(BUILD_DIR)/AxeArchive.o: src/AxeArchive.cpp include/AxeArchive.h | $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -MMD -MP -c $< -o $@

$(BUILD_DIR)/main.o: src/main.cpp include/AxeArchive.h | $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -MMD -MP -c $< -o $@

$(BUILD_DIR)/extract_main.o: tools/extract_main.cpp include/AxeArchive.h | $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -MMD -MP -c $< -o $@

$(ARCHIVE_LIB): $(BUILD_DIR)/AxeArchive.o
	$(AR) rcs $@ $^

$(BUILDER): $(BUILD_DIR)/main.o $(ARCHIVE_LIB)
	$(CXX) $(LDFLAGS) $^ $(LDLIBS) -o $@

$(EXTRACTOR): $(BUILD_DIR)/extract_main.o $(ARCHIVE_LIB)
	$(CXX) $(LDFLAGS) $^ $(LDLIBS) -o $@

test: all
	AXE_EXTRACTOR="$(abspath $(EXTRACTOR))" $(PYTHON) tests/test_archive.py "$(abspath $(BUILDER))"

-include $(OBJECTS:.o=.d)
