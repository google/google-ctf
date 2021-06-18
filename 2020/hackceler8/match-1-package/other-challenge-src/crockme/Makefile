all:
	gdk-pixbuf-csource --raw --name=myimage_inline logo.png > logo.h
	gcc `pkg-config --cflags gtk+-3.0` -o bin main.c `pkg-config --libs gtk+-3.0`

