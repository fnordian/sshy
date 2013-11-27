COMPILER=G++

# todo: object files into output path, processing c / c++ files in the same time (?), nested directories for source files (?)
C = c
OUTPUT_PATH = out/production/sshy/
SOURCE_PATH = src/
TEST_PATH = tests/
TESTOUTPUT_PATH = out/tests/
EXE = $(OUTPUT_PATH)testclient
LIB = $(OUTPUT_PATH)libsshy.so

TESTEXE = $(TESTOUTPUT_PATH)testrunner

OBJ = o
COPT = -O0 -fPIC  -Wl,--wrap,poll -ggdb
CCMD = gcc
OBJFLAG = -o
EXEFLAG = -o
LIBFLAG = -shared -o
INCLUDES = -I$(SOURCE_PATH)

# LIBS = -lgc
LIBS = -ldl  -lssh2
# LIBPATH = -L../gc/.libs
LIBPATH =
CPPFLAGS = $(COPT) -g $(INCLUDES) -Wall
LDFLAGS = $(LIBPATH) -g $(LIBS)  -Wl,--wrap,poll -std=gnu99 -march=i686
DEP = dep

OBJS := $(patsubst %.$(C),%.$(OBJ),$(wildcard $(SOURCE_PATH)*.$(C)))
ALLOBJS := $(patsubst %.$(C),%.$(OBJ),$(wildcard $(TEST_PATH)*.$(C))) $(OBJS)
TESTOBJS := $(filter-out $(SOURCE_PATH)$(shell basename $(EXE)).o,$(ALLOBJS))
LIBOBJS := $(filter-out  $(SOURCE_PATH)$(shell basename $(EXE)).o,$(OBJS))

%.$(OBJ):%.$(C)
	@echo Compiling $(basename $<)...
	$(CCMD) -c $(CPPFLAGS) $(CXXFLAGS) $< $(OBJFLAG)$@

all: exe lib

	
exe: $(OBJS)
	mkdir -p $(OUTPUT_PATH)
	$(CCMD) $(LDFLAGS) $^ $(LIBS) $(EXEFLAG) $(EXE)  -lpthread 

lib: $(LIBOBJS)
	mkdir -p $(OUTPUT_PATH)
	$(CCMD) $(LDFLAGS) $^ $(LIBS) $(LIBFLAG) $(LIB)
	
	
tests: $(TESTOBJS)
	echo testobjs $(TESTOBJS)
	$(CCMD) $(LDFLAGS) $^ $(LIBS) $(EXEFLAG) $(TESTEXE)
	$(TESTEXE)
	
infinitest:
	while (inotifywait  -r -e modify,create --exclude '.*-swp' .); do \
		sleep 1; \
		$(MAKE) tests; \
	done
		
clean:
	rm -rf $(SOURCE_PATH)*.$(OBJ) $(EXE) $(LIB)

rebuild: clean all

.PHONY: tests
