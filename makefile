CC := clang

INCLUDE_DIR = include
INCLUDE_FLAG = -I$(INCLUDE_DIR)
LIBS = -lpcap
CCFLAGS = -Wall -Werror -O0 -g $(INCLUDE_FLAG)

EXE_NAME = test

SRC_DIR = src
OUT_DIR = out
OBJ_DIR = obj

SOURCES = $(wildcard $(SRC_DIR)/*.c)
OBJECTS = $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SOURCES))

$(OBJECTS): $(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CCFLAGS) $< -c -o $@

$(OUT_DIR)/$(EXE_NAME): $(OBJECTS)
	$(CC) $(CCFLAGS) $(LIBS) $^ -o $@

all: make_dirs $(OUT_DIR)/$(EXE_NAME)

run: all
	$(OUT_DIR)/$(EXE_NAME)

make_dirs:
	mkdir -p out
	mkdir -p obj

clean:
	-rm -f $(OUT_DIR)/*
	-rm -f $(OBJ_DIR)/*