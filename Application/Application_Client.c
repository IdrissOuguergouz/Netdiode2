#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifdef _WIN32
    // Windows-specific includes
    #include <winsock2.h>
    #include <ws2tcpip.h> // For inet_pton
    #pragma comment(lib, "ws2_32.lib") // Link Winsock library
#else
    // Linux-specific includes
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
#endif

#include <gtk/gtk.h>
#include <libssh2.h>

#define BUFFER_SIZE 1024

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

// Cross-platform socket functions
#ifdef _WIN32
    #define CLOSESOCKET closesocket
    typedef int socklen_t;
#else
    #define CLOSESOCKET close
#endif

// Function to initialize networking (Windows only)
int initialize_networking() {
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "Failed to initialize Winsock: %d\n", WSAGetLastError());
        return -1;
    }
#endif
    return 0;
}

// Function to clean up networking (Windows only)
void cleanup_networking() {
#ifdef _WIN32
    WSACleanup();
#endif
}

// Function to establish a connection to the server
int open_connection(const char *ip, int port) {
    int sockfd;
    struct sockaddr_in server_addr;

    // Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
#ifdef _WIN32
        fprintf(stderr, "Socket creation failed: %d\n", WSAGetLastError());
#else
        perror("Socket creation failed");
#endif
        return -1;
    }

    // Set up server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &server_addr.sin_addr) <= 0) {
#ifdef _WIN32
        fprintf(stderr, "Invalid IP address: %d\n", WSAGetLastError());
#else
        perror("Invalid IP address");
#endif
        CLOSESOCKET(sockfd);
        return -1;
    }

    // Connect to the server
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
#ifdef _WIN32
        fprintf(stderr, "Connection failed: %d\n", WSAGetLastError());
#else
        perror("Connection failed");
#endif
        CLOSESOCKET(sockfd);
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

static void on_settings_window_destroy(GtkWidget *widget, gpointer data) {
    settings_window = NULL; // Reset the global pointer when the window is destroyed
}

static void open_settings_window(GtkWidget *widget, gpointer data) {
    if (settings_window != NULL) {
        gtk_widget_show_all(settings_window);
        return;
    }

    settings_window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(settings_window), "Settings");
    gtk_window_set_default_size(GTK_WINDOW(settings_window), 300, 200);

    g_signal_connect(settings_window, "destroy", G_CALLBACK(on_settings_window_destroy), NULL);

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

    SettingsEntries *entries = malloc(sizeof(SettingsEntries));
    entries->ip_entry = ip_entry;
    entries->token_entry = token_entry;

    g_signal_connect(save_button, "clicked", G_CALLBACK(on_save_settings), entries);

    gtk_widget_show_all(settings_window);
}

// Function to handle file transfer
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
        CLOSESOCKET(sockfd);
        return;
    }
    response[response_size] = '\0';

    if (strcmp(response, "AUTH_SUCCESS") != 0) {
        gtk_label_set_text(GTK_LABEL(user_data), "Authentication failed.");
        CLOSESOCKET(sockfd);
        return;
    }

    // Step 3: Send file
    FILE *file = fopen(selected_file, "rb");
    if (!file) {
        gtk_label_set_text(GTK_LABEL(user_data), "Error opening selected file.");
        CLOSESOCKET(sockfd);
        return;
    }

    char buffer[BUFFER_SIZE];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        send(sockfd, buffer, bytes_read, 0);
    }

    fclose(file);
    CLOSESOCKET(sockfd);
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
    gtk_window_set_title(GTK_WINDOW(window), "File Transfer Client");
    gtk_window_set_default_size(GTK_WINDOW(window), 600, 400);

    GtkWidget *main_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_container_set_border_width(GTK_CONTAINER(main_box), 15);
    gtk_container_add(GTK_CONTAINER(window), main_box);

    // Header Section
    GtkWidget *header_label = gtk_label_new("File Transfer Client");
    gtk_widget_set_halign(header_label, GTK_ALIGN_CENTER);
    PangoAttrList *attr_list = pango_attr_list_new();
    PangoAttribute *attr = pango_attr_size_new_absolute(20 * PANGO_SCALE); // 20pt font size
    pango_attr_list_insert(attr_list, attr);
    gtk_label_set_attributes(GTK_LABEL(header_label), attr_list);
    pango_attr_list_unref(attr_list);
    gtk_box_pack_start(GTK_BOX(main_box), header_label, FALSE, FALSE, 10);

    // Settings and Destination Section
    GtkWidget *settings_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    gtk_box_pack_start(GTK_BOX(main_box), settings_box, FALSE, FALSE, 0);

    GtkWidget *settings_button = gtk_button_new_with_label("⚙️ Settings");
    gtk_box_pack_start(GTK_BOX(settings_box), settings_button, FALSE, FALSE, 0);
    g_signal_connect(settings_button, "clicked", G_CALLBACK(open_settings_window), NULL);

    GtkWidget *destination_label = gtk_label_new("Destination Machine IP:");
    gtk_box_pack_start(GTK_BOX(settings_box), destination_label, FALSE, FALSE, 0);

    destination_entry = gtk_entry_new();
    gtk_box_pack_start(GTK_BOX(settings_box), destination_entry, TRUE, TRUE, 0);

    // File Selection Section
    GtkWidget *file_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    gtk_box_pack_start(GTK_BOX(main_box), file_box, FALSE, FALSE, 0);

    GtkWidget *file_label = gtk_label_new("Selected File:");
    gtk_box_pack_start(GTK_BOX(file_box), file_label, FALSE, FALSE, 0);

    file_chooser_button = gtk_button_new_with_label("📂 Choose a File");
    gtk_box_pack_start(GTK_BOX(file_box), file_chooser_button, TRUE, TRUE, 0);
    g_signal_connect(file_chooser_button, "clicked", G_CALLBACK(on_file_chooser_button_clicked), NULL);

    // Status Section
    GtkWidget *status_frame = gtk_frame_new("Status");
    gtk_box_pack_start(GTK_BOX(main_box), status_frame, TRUE, TRUE, 10);

    GtkWidget *status_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_container_add(GTK_CONTAINER(status_frame), status_box);

    status_label = gtk_label_new("Status messages will appear here.");
    gtk_label_set_line_wrap(GTK_LABEL(status_label), TRUE);
    gtk_box_pack_start(GTK_BOX(status_box), status_label, TRUE, TRUE, 0);

    // Send Button Section
    GtkWidget *button_box = gtk_button_box_new(GTK_ORIENTATION_HORIZONTAL);
    gtk_box_pack_end(GTK_BOX(main_box), button_box, FALSE, FALSE, 0);

    send_button = gtk_button_new_with_label("🚀 Send File");
    gtk_button_set_relief(GTK_BUTTON(send_button), GTK_RELIEF_NORMAL);
    gtk_container_add(GTK_CONTAINER(button_box), send_button);
    g_signal_connect(send_button, "clicked", G_CALLBACK(on_send_button_clicked), status_label);

    // Show everything
    gtk_widget_show_all(window);
}

int main(int argc, char *argv[]) {
    if (initialize_networking() != 0) {
        fprintf(stderr, "Failed to initialize networking.\n");
        return EXIT_FAILURE;
    }

    GtkApplication *app;
    int status;

    app = gtk_application_new("com.example.FileTransfer", G_APPLICATION_DEFAULT_FLAGS);
    g_signal_connect(app, "activate", G_CALLBACK(activate), NULL);
    status = g_application_run(G_APPLICATION(app), argc, argv);
    g_object_unref(app);

    cleanup_networking();
    return status;
}

