#!/usr/bin/python
#
# Copyright 2018 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

keystream = iter('''Heat oil in a large saucepan over medium heat. Cook green pepper, and onion, until softened. Add the ground beef and cook until browned. Crumble over bouillon cubes, and stir in wine; continue to cook for a few minutes. Stir in chopped tomatoes, garlic, and tomato paste. Season with paprika, chili powder, cayenne pepper, basil, oregano, and parsley. Stir in salt and pepper. Bring to a boil over high heat. Reduce heat to medium low. Cover, and simmer for 90 minutes, stirring occasionally. Stir in kidney beans, and hot pepper sauce. You can add the reserved tomato juice if more liquid is needed. Continue to simmer for an additional 30 minutes. In a small bowl, whisk together the flour, corn meal, and water until smooth. Stir into chili, and cook for a further 10 minutes, or until chili has thickened up. Heat oil in a large saucepan over medium heat. Cook green pepper, and onion, until softened. Add the ground beef and cook until browned. Crumble over bouillon cubes, and stir in wine; continue to cook for a few minutes. Stir in chopped tomatoes, garlic, and tomato paste. Season with paprika, chili powder, cayenne pepper, basil, oregano, and parsley. Stir in salt and pepper. Bring to a boil over high heat. Reduce heat to medium low. Cover, and simmer for 90 minutes, stirring occasionally. Stir in kidney beans, and hot pepper sauce. You can add the reserved tomato juice if more liquid is needed. Continue to simmer for an additional 30 minutes. In a small bowl, whisk together the flour, corn meal, and water until smooth. Stir into chili, and cook for a further 10 minutes, or until chili has thickened up.''')

# Too lazy to strip strings from source and I already have this list sooo...
strings = ["/proc/self/maps",
  "r",
  "/d.dex",
  "java/lang/ClassLoader",
  "getSystemClassLoader",
  "()Ljava/lang/ClassLoader;",
  "/data/data/com.google.ctf.food/files/d.dex",
  "/data/data/com.google.ctf.food/files/odex",
  "/data/data/com.google.ctf.food/files/odex/d.dex",
  "com/google/ctf/food/S",
  "libdvm.so",
  "com/google/ctf/food/FoodActivity",
  "wb",
  "dalvik/system/DexClassLoader",
  "<init>",
  "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/ClassLoader;)V",
  "loadClass",
  "(Ljava/lang/String;)Ljava/lang/Class;",
  "<init>",
  "(Landroid/app/Activity;)V",
  "activity",
  "Landroid/app/Activity;"
]

def encrypt(string):
  res = []

  if len(string) % 2 != 0:
    string += '\0'

  for char1, char2 in zip(string[::2], string[1::2]):
    key1 = ord(keystream.next())
    key2 = ord(keystream.next())

    value1 = ord(char1) ^ key1
    value2 = ord(char2) ^ key2

    low = (value1 << 8) | key1
    high = (value2 << 8) | key2

    res.append(low | (high << 16))

  return res

data = open('cook_original.c', 'rb').read()

for string in strings:
  res = encrypt(string)
  res_str = str(res).replace('[', '').replace(']', '')
  decrypt_call = 'decrypt(%d, %s)' % (len(res), res_str)
  
  data = decrypt_call.join(data.split('"' + string + '"'))

open('cook.c', 'wb').write(data)