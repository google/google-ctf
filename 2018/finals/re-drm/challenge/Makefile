H_FILES := $(wildcard *.h)

.PHONY: all

all: ASPARAGUS solution ASPARAGUS_tampered solution_tampered

ptrace_checker.obj: ptrace_checker.cc $(H_FILES)
	g++  -O1 $< -fPIC -std=c++17 -o $@ -c -Wno-narrowing

invoker.obj: invoker.cc $(H_FILES)
	g++  -O1 $< -fPIC -std=c++17 -o $@ -c -Wno-narrowing

md5.obj: md5.cc $(H_FILES)
	g++  -O1 $< -fPIC -std=c++17 -o $@ -c -Wno-narrowing

serial_validator.obj: serial_validator.cc md5.ench $(H_FILES)
	g++  -O1 $< -fPIC -std=c++17 -o $@ -c -Wno-narrowing

checksum.obj: checksum.cc md5.ench $(H_FILES)
	g++  -O1 $< -fPIC -std=c++17 -o $@ -c -Wno-narrowing

cat_exit.obj: cat_exit.cc checksum.ench $(H_FILES)
	g++  -O1 $< -fPIC -std=c++17 -o $@ -c -Wno-narrowing

preload.obj: preload.cc $(H_FILES)
	g++  -O1 $< -fPIC -std=c++17 -o $@ -c -Wno-narrowing

xorstr_license.txth: $(H_FILES)
	cat xorstr.h | head -n 16 | python encode_str.py xorstr_license > xorstr_license.txth

%.ench: %.obj
	./encrypt_all.sh $< > $@

debug_version: main.cc serial_validator.ench ptrace_checker.ench md5.ench checksum.ench preload.ench invoker.ench cat_exit.ench xorstr_license.txth adventure.cc correct_checksum.cc
	g++  -O1 main.cc adventure.cc correct_checksum.cc -fPIC -ftemplate-depth=1000000 -std=c++17 -z execstack -Wno-narrowing -o debug_version
	strip -s debug_version

ASPARAGUS: debug_version
	cat ./debug_version | python inject_checksum.py $(shell ./debug_version) > ASPARAGUS
	chmod +x ./ASPARAGUS

ASPARAGUS_tampered: debug_version
	cat ./debug_version | python inject_checksum.py 0 > ASPARAGUS_tampered
	chmod +x ./ASPARAGUS_tampered

solution_debug_version: main.cc serial_validator.ench ptrace_checker.ench md5.ench checksum.ench preload.ench invoker.ench cat_exit.ench xorstr_license.txth adventure.cc correct_checksum.cc
	g++ -DDISABLE_DRM -O1 main.cc adventure.cc correct_checksum.cc -fPIC -ftemplate-depth=1000000 -std=c++17 -z execstack -Wno-narrowing -o solution_debug_version

solution: solution_debug_version
	cat ./solution_debug_version | python inject_checksum.py $(shell ./solution_debug_version) > solution
	chmod +x ./solution

solution_tampered: solution_debug_version
	cat ./solution_debug_version | python inject_checksum.py 0 > solution_tampered
	chmod +x ./solution_tampered

clean:
	-rm -rf *.o
	-rm -rf *.obj
	-rm -rf *.ench
	-rm -rf *.txth
	-rm debug_version
	-rm ASPARAGUS
	-rm solution
	-rm solution_debug_version
	-rm *_tampered
