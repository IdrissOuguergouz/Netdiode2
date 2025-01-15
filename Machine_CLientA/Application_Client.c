#include <gtk/gtk.h>
#include <libssh2.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/stat.h>

#define BUFFER_SIZE 1024 // Define BUFFER_SIZE

// Structure to hold IP and Token entry widgets
typedef struct {
    GtkWidget *ip_entry;
    GtkWidget *token_entry;
} SettingsEntries;

// Global variables
static GtkWidget *window;
static GtkWidget *file_chooser_button;
static GtkWidget *destination_entry;
static GtkWidget *send_button;
static GtkWidget *status_label;
static GtkWidget *settings_window;

static char *selected_file = NULL;
static char *auth_token = NULL;
static char *transfer_server_ip = NULL;

// Function to establish a connection to the server
int open_connection(const char *ip, int port) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        return -1;
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, ip, &server_addr.sin_addr) <= 0) {
        perror("Invalid IP address");
        close(sockfd);
        return -1;
    }

    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        close(sockfd);
        return -1;
    }

    return sockfd;
}

// Function to handle the Save button click in the Settings window
static void on_save_settings(GtkWidget *button, gpointer user_data) {
    SettingsEntries *entries = (SettingsEntries *)user_data;

    if (!entries || !GTK_IS_ENTRY(entries->ip_entry) || !GTK_IS_ENTRY(entries->token_entry)) {
        gtk_label_set_text(GTK_LABEL(status_label), "Error: Invalid widget pointers.");
        return;
    }

    const char *entered_ip = gtk_entry_get_text(GTK_ENTRY(entries->ip_entry));
    const char *entered_token = gtk_entry_get_text(GTK_ENTRY(entries->token_entry));

    if (!entered_ip || strlen(entered_ip) == 0 || !entered_token || strlen(entered_token) == 0) {
        gtk_label_set_text(GTK_LABEL(status_label), "IP or token fields cannot be empty.");
        return;
    }

    if (transfer_server_ip) free(transfer_server_ip);
    if (auth_token) free(auth_token);

    transfer_server_ip = strdup(entered_ip);
    auth_token = strdup(entered_token);

    gtk_label_set_text(GTK_LABEL(status_label), "Settings saved successfully.");
    gtk_widget_destroy(settings_window);
    settings_window = NULL; // Reset pointer after destroying the settings window
    free(entries); // Free the allocated structure
}

// Function to open the Settings window
static void open_settings_window(GtkWidget *widget, gpointer data) {
    if (settings_window != NULL) {
        gtk_widget_show_all(settings_window);
        return;
    }

    settings_window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(settings_window), "Settings");
    gtk_window_set_default_size(GTK_WINDOW(settings_window), 300, 200);

    GtkWidget *settings_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_container_add(GTK_CONTAINER(settings_window), settings_box);

    GtkWidget *ip_label = gtk_label_new("Transfer Server IP:");
    gtk_box_pack_start(GTK_BOX(settings_box), ip_label, FALSE, FALSE, 0);

    GtkWidget *ip_entry = gtk_entry_new();
    gtk_box_pack_start(GTK_BOX(settings_box), ip_entry, FALSE, FALSE, 0);

    GtkWidget *token_label = gtk_label_new("Authentication Token:");
    gtk_box_pack_start(GTK_BOX(settings_box), token_label, FALSE, FALSE, 0);

    GtkWidget *token_entry = gtk_entry_new();
    gtk_box_pack_start(GTK_BOX(settings_box), token_entry, FALSE, FALSE, 0);

    GtkWidget *save_button = gtk_button_new_with_label("Save");
    gtk_box_pack_start(GTK_BOX(settings_box), save_button, FALSE, FALSE, 0);

    // Allocate structure to hold entries
    SettingsEntries *entries = malloc(sizeof(SettingsEntries));
    entries->ip_entry = ip_entry;
    entries->token_entry = token_entry;

    g_signal_connect(save_button, "clicked", G_CALLBACK(on_save_settings), entries);

    gtk_widget_show_all(settings_window);
}

// Function called when the "Send File" button is clicked
static void on_send_button_clicked(GtkButton *button, gpointer user_data) {
    const char *destination_ip = gtk_entry_get_text(GTK_ENTRY(destination_entry));

    if (!selected_file || !auth_token || !transfer_server_ip || !destination_ip) {
        gtk_label_set_text(GTK_LABEL(user_data), "Please select a file and enter all required fields.");
        return;
    }

    int port = 2222; // Match the server's port
    int sockfd = open_connection(transfer_server_ip, port);

    if (sockfd < 0) {
        gtk_label_set_text(GTK_LABEL(user_data), "Failed to connect to the server.");
        return;
    }

    // Step 1: Send authentication token
    send(sockfd, auth_token, strlen(auth_token), 0);

    // Step 2: Receive authentication response
    char response[BUFFER_SIZE];
    ssize_t response_size = recv(sockfd, response, sizeof(response) - 1, 0);
    if (response_size <= 0) {
        gtk_label_set_text(GTK_LABEL(user_data), "No response from server.");
        close(sockfd);
        return;
    }
    response[response_size] = '\0';

    if (strcmp(response, "AUTH_SUCCESS") != 0) {
        gtk_label_set_text(GTK_LABEL(user_data), "Authentication failed.");
        close(sockfd);
        return;
    }

    // Step 3: Send file
    FILE *file = fopen(selected_file, "rb");
    if (!file) {
        gtk_label_set_text(GTK_LABEL(user_data), "Error opening selected file.");
        close(sockfd);
        return;
    }

    char buffer[BUFFER_SIZE];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        send(sockfd, buffer, bytes_read, 0);
    }

    fclose(file);
    close(sockfd);
    gtk_label_set_text(GTK_LABEL(user_data), "File sent successfully!");
}

// Function to select a file
static void on_file_chooser_button_clicked(GtkButton *button, gpointer user_data) {
    GtkWidget *dialog;
    dialog = gtk_file_chooser_dialog_new("Select a file", GTK_WINDOW(window),
                                         GTK_FILE_CHOOSER_ACTION_OPEN,
                                         "_Cancel", GTK_RESPONSE_CANCEL,
                                         "_Open", GTK_RESPONSE_ACCEPT, NULL);
    if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
        selected_file = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
        gtk_button_set_label(GTK_BUTTON(button), selected_file);
    }
    gtk_widget_destroy(dialog);
}

// GUI initialization
static void activate(GtkApplication *app, gpointer user_data) {
    window = gtk_application_window_new(app);
    gtk_window_set_title(GTK_WINDOW(window), "File Transfer");
    gtk_window_set_default_size(GTK_WINDOW(window), 500, 300);

    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_container_add(GTK_CONTAINER(window), box);

    GtkWidget *settings_button = gtk_button_new_with_label("Settings");
    gtk_box_pack_start(GTK_BOX(box), settings_button, FALSE, FALSE, 0);
    g_signal_connect(settings_button, "clicked", G_CALLBACK(open_settings_window), NULL);

    GtkWidget *destination_label = gtk_label_new("Destination Machine IP:");
    gtk_box_pack_start(GTK_BOX(box), destination_label, FALSE, FALSE, 0);

    destination_entry = gtk_entry_new();
    gtk_box_pack_start(GTK_BOX(box), destination_entry, FALSE, FALSE, 0);

    file_chooser_button = gtk_button_new_with_label("Choose a File");
    gtk_box_pack_start(GTK_BOX(box), file_chooser_button, FALSE, FALSE, 0);
    g_signal_connect(file_chooser_button, "clicked", G_CALLBACK(on_file_chooser_button_clicked), NULL);

    status_label = gtk_label_new("");
    gtk_box_pack_start(GTK_BOX(box), status_label, FALSE, FALSE, 0);

    send_button = gtk_button_new_with_label("Send File");
    gtk_box_pack_start(GTK_BOX(box), send_button, FALSE, FALSE, 0);
    g_signal_connect(send_button, "clicked", G_CALLBACK(on_send_button_clicked), status_label);

    gtk_widget_show_all(window);
}

int main(int argc, char *argv[]) {
    GtkApplication *app;
    int status;

    app = gtk_application_new("com.example.FileTransfer", G_APPLICATION_DEFAULT_FLAGS);
    g_signal_connect(app, "activate", G_CALLBACK(activate), NULL);
    status = g_application_run(G_APPLICATION(app), argc, argv);
    g_object_unref(app);

    return status;
}


                                                                                                                                                                                                                    