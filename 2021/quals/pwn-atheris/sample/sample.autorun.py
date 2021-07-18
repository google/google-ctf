import os
print("Directory contents:")
for path in os.listdir('.'):
  if path == '.' or path == '..':
    continue
  if path.endswith(".autorun.py"):
    continue
  print(path)
