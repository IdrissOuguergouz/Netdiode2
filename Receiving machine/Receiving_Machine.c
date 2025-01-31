#include <gtk/gtk.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/stat.h>
#include <pthread.h>

#define RECEIVED_DIR "./received_files"

// Function to start the file server in the background
void start_file_server() {
    mkdir(RECEIVED_DIR, 0777);

    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    char buffer[1024];

    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(4444);

    bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr));
    listen(server_socket, 5);
    printf("Receiving Machine listening on port 4444...\n");

    while ((client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_len)) >= 0) {
        printf("Receiving file from %s\n", inet_ntoa(client_addr.sin_addr));

        FILE *file = fopen(RECEIVED_DIR "/received_file", "wb");
        ssize_t bytes_received;
        while ((bytes_received = recv(client_socket, buffer, sizeof(buffer), 0)) > 0) {
            fwrite(buffer, 1, bytes_received, file);
        }
        fclose(file);
        close(client_socket);
        printf("File received successfully!\n");
    }

    close(server_socket);
}

// **🟢 FIX: Added GTK `activate()` Function**
void activate(GtkApplication *app, gpointer user_data) {
    GtkWidget *window, *label;

    // Create main GTK window
    window = gtk_application_window_new(app);
    gtk_window_set_title(GTK_WINDOW(window), "Received Files");
    gtk_window_set_default_size(GTK_WINDOW(window), 400, 300);

    // Label inside the window
    label = gtk_label_new("Receiving Machine is running...");
    gtk_container_add(GTK_CONTAINER(window), label);

    gtk_widget_show_all(window);
}

int main(int argc, char **argv) {
    pthread_t server_thread;
    pthread_create(&server_thread, NULL, (void *)start_file_server, NULL);
    pthread_detach(server_thread);

    GtkApplication *app = gtk_application_new("com.example.DestinationApp", G_APPLICATION_DEFAULT_FLAGS);
    g_signal_connect(app, "activate", G_CALLBACK(activate), NULL);  // ✅ FIX: Now `activate` exists
    int status = g_application_run(G_APPLICATION(app), argc, argv);
    g_object_unref(app);
    return status;
}



