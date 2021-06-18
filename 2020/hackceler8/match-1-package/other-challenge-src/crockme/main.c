// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
#include <gtk/gtk.h>
#include "logo.h"

static inline int check(const char* c) __attribute__((always_inline));
static inline int check(const char* c){
	float volatile a = 1337;
	static const char flag[] = {'I', 'B', 'M', '9', 'z', 'O', 'd', 'y', 'u', '^', 'u', 'h', 'l', 'd', '^', 'H', 'm', 'm', '^', 't', 'r', 'd', '^', 'P', 'u', '|', '\0'};
	if (strlen(c) != strlen(flag)) {
		return 1;
	}
	size_t ret = 1;
	for(size_t i = 0; flag[i]; i++) {
		ret = ret * (flag[i] ^ c[i]);
		a += 0.2;
	}
	if (ret == 1) {
		return ret - 1;
	} else {
		return a;
	}
}

static void button_clicked(GtkWidget *button, gpointer data) {
	const char *password_text = gtk_entry_get_text(GTK_ENTRY((GtkWidget *)data));
	const char* title, *msg;

	if(check(password_text) == 0) {
		title = "Yup";
		msg = "Correct flag.";
	}	else {
		title = "Nope";
		msg = "Invalid flag.";
	}

	GtkWidget* dialog = gtk_dialog_new_with_buttons (title, NULL, GTK_DIALOG_DESTROY_WITH_PARENT, "OK", GTK_RESPONSE_NONE, NULL);
	GtkWidget* content_area = gtk_dialog_get_content_area (GTK_DIALOG (dialog));
	GtkWidget *label = gtk_label_new (msg);
	g_signal_connect_swapped (dialog, "response", G_CALLBACK (gtk_widget_destroy), dialog);
	gtk_container_add (GTK_CONTAINER (content_area), label);
	gtk_widget_show_all (dialog);
}

static void activate (GtkApplication* app, gpointer        user_data) {
	GtkWidget *window = gtk_application_window_new (app);
	gtk_window_set_title (GTK_WINDOW (window), "Crockme");
	gtk_window_set_position(GTK_WINDOW(window), GTK_WIN_POS_CENTER);

	GtkWidget* password_entry = gtk_entry_new();
	GtkWidget* ok_button = gtk_button_new_with_label("Check");

	g_signal_connect(G_OBJECT(ok_button), "clicked", G_CALLBACK(button_clicked), password_entry);

	GdkPixbuf* pixbuf = gdk_pixbuf_new_from_inline (-1, myimage_inline, FALSE, NULL);
	GtkWidget* logo = gtk_image_new_from_pixbuf(pixbuf);

	GtkWidget* hbox = gtk_grid_new();
	gtk_grid_attach(GTK_GRID(hbox), logo, 0, 0, 2, 1);
	gtk_grid_attach(GTK_GRID(hbox), password_entry, 0, 1, 1, 1);
	gtk_grid_attach_next_to(GTK_GRID(hbox), ok_button, password_entry, GTK_POS_RIGHT, 1, 1);
	gtk_container_add(GTK_CONTAINER(window), hbox);

	gtk_widget_show_all (window);
}

int main (int argc, char **argv) {
	GtkApplication *app = gtk_application_new ("org.gtk.crockme", G_APPLICATION_FLAGS_NONE);
	g_signal_connect (app, "activate", G_CALLBACK (activate), NULL);
	int status = g_application_run (G_APPLICATION (app), argc, argv);
	g_object_unref (app);

	return status;
}
