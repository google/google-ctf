# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

H_FILES := $(wildcard *.h)

.PHONY: all clean

all: polymorph polymorph_static

polymorph: defenses.ench badstuff.ench polymorph.cc crypto.cc aes.cc
	$(CXX) -DLINKMODE_1=1 -g $(POLYMORPH_OPT) --std=c++17 -z execstack polymorph.cc crypto.cc aes.cc -o "polymorph"
	strip polymorph

polymorph_static_packed: defenses.ench badstuff.ench polymorph.cc crypto.cc aes.cc
	$(CXX) -DLINKMODE_1=1 -g $(POLYMORPH_OPT) --std=c++17 -z execstack polymorph.cc crypto.cc aes.cc -static -o "polymorph_static_packed"
	strip polymorph_static_packed

polymorph_static: polymorph.cc crypto.cc aes.cc defenses.obj badstuff.obj
	$(CXX) -DLINKMODE_2=1 -g $(POLYMORPH_OPT) -static --std=c++17 $^ -o "polymorph_static"
	strip polymorph_static

polymorph_dynamic: polymorph.cc crypto.cc aes.cc defenses.so badstuff.so
	$(CXX) -DLINKMODE_2=1 -g $(POLYMORPH_OPT) --std=c++17 $^ -Wl,-rpath=./  -o "polymorph_dynamic"
	strip polymorph_dynamic

polymorph_dynamic_packed: defenses.so_ench badstuff.so_ench polymorph.cc crypto.cc aes.cc
	$(CXX) -DLINKMODE_4=1 -g $(POLYMORPH_OPT) --std=c++17 polymorph.cc crypto.cc aes.cc -ldl -o "polymorph_dynamic_packed"
	strip polymorph_dynamic_packed

polymorph_object.obj: defenses.ench badstuff.ench polymorph.cc crypto.cc aes.cc
	$(CXX) -DLINKMODE_1=1 -DOBJECT_MODE=1 -g $(POLYMORPH_OPT) --std=c++17 polymorph.cc -c -o polymorph.cc.obj
	$(CXX) -DLINKMODE_1=1 -g $(POLYMORPH_OPT) --std=c++17 crypto.cc -c -o crypto.cc.obj
	$(CXX) -DLINKMODE_1=1 -g $(POLYMORPH_OPT) --std=c++17 aes.cc -c -o aes.cc.obj
	ld -relocatable polymorph.cc.obj crypto.cc.obj aes.cc.obj -o polymorph_object.obj

polymorph_static_object.obj: polymorph.cc crypto.cc aes.cc defenses.obj badstuff.obj
	$(CXX) -DLINKMODE_2=1 -DOBJECT_MODE=1 -g $(POLYMORPH_OPT) --std=c++17 polymorph.cc -c -o polymorph.cc.obj
	$(CXX) -DLINKMODE_2=1 -g $(POLYMORPH_OPT) --std=c++17 crypto.cc -c -o crypto.cc.obj
	$(CXX) -DLINKMODE_2=1 -g $(POLYMORPH_OPT) --std=c++17 aes.cc -c -o aes.cc.obj
	ld -relocatable polymorph.cc.obj crypto.cc.obj aes.cc.obj defenses.obj badstuff.obj -o polymorph_static_object.obj

polymorph_dynamic_packed_object.obj: defenses.so_ench badstuff.so_ench polymorph.cc crypto.cc aes.cc
	$(CXX) -DLINKMODE_4=1 -DOBJECT_MODE=1 -g $(POLYMORPH_OPT) --std=c++17 polymorph.cc -c -o polymorph.cc.obj
	$(CXX) -DLINKMODE_4=1 -g $(POLYMORPH_OPT) --std=c++17 crypto.cc -c -o crypto.cc.obj
	$(CXX) -DLINKMODE_4=1 -g $(POLYMORPH_OPT) --std=c++17 aes.cc -c -o aes.cc.obj
	ld -relocatable polymorph.cc.obj crypto.cc.obj aes.cc.obj -o polymorph_dynamic_packed_object.obj

polymorph_python: polymorph_object.obj
	cp ./polymorph_object.obj ~/cpython/polymorph_object.obj
	(cd ~/cpython && g++ ./polymorph_object.obj -z execstack -pthread     -Xlinker -export-dynamic -o python Programs/python.o libpython3.10.a -lcrypt -lpthread -ldl  -lutil -lm   -lm)
	objcopy -S --keep-symbols=./expected_syms_python ~/cpython/python ./polymorph_python

polymorph_static_python: polymorph_static_object.obj
	cp ./polymorph_static_object.obj ~/cpython/polymorph_object.obj
	(cd ~/cpython && g++ ./polymorph_object.obj -pthread     -Xlinker -export-dynamic -o python Programs/python.o libpython3.10.a -lcrypt -lpthread -ldl  -lutil -lm   -lm)
	objcopy -S --keep-symbols=./expected_syms_python ~/cpython/python ./polymorph_static_python

polymorph_dynamic_packed_python: polymorph_dynamic_packed_object.obj
	cp ./polymorph_dynamic_packed_object.obj ~/cpython/polymorph_object.obj
	(cd ~/cpython && g++ ./polymorph_object.obj -pthread     -Xlinker -export-dynamic -o python Programs/python.o libpython3.10.a -lcrypt -lpthread -ldl  -lutil -lm   -lm)
	objcopy -S --keep-symbols=./expected_syms_python ~/cpython/python ./polymorph_dynamic_packed_python

polymorph_zsh: polymorph_object.obj
	cp ./polymorph_object.obj ~/zsh/Src/polymorph_object.obj
	(cd ~/zsh/Src && g++ ./polymorph_object.obj -z execstack -s -rdynamic -o zsh main.o  `cat stamp-modobjs`   -ldl -lncursesw -lrt -lm  -lc)
	cp ~/zsh/Src/zsh ./polymorph_zsh
	strip --strip-debug polymorph_zsh

polymorph_static_zsh: polymorph_static_object.obj
	cp ./polymorph_static_object.obj ~/zsh/Src/polymorph_object.obj
	(cd ~/zsh/Src && g++ ./polymorph_object.obj -s -rdynamic -o zsh main.o  `cat stamp-modobjs`   -ldl -lncursesw -lrt -lm  -lc)
	cp ~/zsh/Src/zsh ./polymorph_static_zsh
	strip --strip-debug polymorph_static_zsh

polymorph_dynamic_packed_zsh: polymorph_dynamic_packed_object.obj
	cp ./polymorph_dynamic_packed_object.obj ~/zsh/Src/polymorph_object.obj
	(cd ~/zsh/Src && g++ ./polymorph_object.obj -s -rdynamic -o zsh main.o  `cat stamp-modobjs`   -ldl -lncursesw -lrt -lm  -lc)
	cp ~/zsh/Src/zsh ./polymorph_dynamic_packed_zsh
	strip --strip-debug polymorph_dynamic_packed_zsh


defenses.obj: defenses.cc $(H_FILES)
	$(CXX) -O1 $< -fPIC -std=c++17 -o $@ -c -Wno-narrowing

badstuff.obj: badstuff.cc $(H_FILES)
	$(CXX) -O1 $< -fPIC -std=c++17 -o $@ -c -Wno-narrowing

invokable.obj: invokable.cc $(H_FILES)
	$(CXX) -O1 $< -fPIC -std=c++17 -o $@ -c -Wno-narrowing

%.ench: %.obj encrypt
	./encrypt_all.sh $< > $@

%.so: %.obj
	$(CXX) $< -shared -o $@

%.so_ench: %.so encrypt
	./list_sections.sh $< | cut -c 6- | xargs -I{} -n1 ./encrypt_file.sh $< {} > $@

encrypt: encrypt.cc crypto.cc aes.cc
	$(CXX) -O1 $^ -fPIC -std=c++17 -o $@ -Wno-narrowing


clean:
	-rm -rf *.o
	-rm -rf *.obj
	-rm -rf *.ench
	-rm -rf *.so_ench
	-rm -rf *.txth
	-rm -rf *.so
	-rm -rf polymorph
	-rm -rf polymorph_*
	-rm -rf polymorph_object.obj
	-rm -rf encrypt
