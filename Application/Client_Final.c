#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/rand.h>
#include <gtk/gtk.h>

#ifdef _WIN32
    #include <winsock2.h>
	#include <io.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
	#define access _access
	#define F_OK 0
	#define R_OK 4
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
#endif
	

#define SERVER_PORT 2222
#define CLIENT_ID "5dac26e10b"
#define BUFFER_SIZE 8192
#define AES_KEY_SIZE 32
#define AES_IV_SIZE 16
#define SERVER_PUBLIC_KEY "server_keypublic.pem"


static GtkWidget *window;
static GtkWidget *file_chooser_button;
static GtkWidget *destination_entry;
static GtkWidget *transfer_server_entry;
static GtkWidget *send_button;
static GtkWidget *status_label;

static char *selected_file = NULL;
static char *transfer_server_ip = NULL;
static char *destination_ip = NULL;
static char *private_key_path = "private_key.pem";  // Clé privée
static char *public_key_path = "server_keypublic.pem"; // Clé public du serveur

#ifdef _WIN32
    #define CLOSESOCKET closesocket
    typedef int socklen_t;
#else
    #define CLOSESOCKET close
#endif

// Fonction pour ouvrir une connexion TCP au serveur
int open_connection(const char *host, int port) {
    WSADATA wsaData;
    SOCKET sockfd;
    struct sockaddr_in server_addr;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        perror("Erreur: WSAStartup");
        return -1;
    }

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == INVALID_SOCKET) {
        perror("Erreur: Création socket");
        WSACleanup();
        return -1;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &server_addr.sin_addr) <= 0) {
        perror("Adresse IP invalide");
        CLOSESOCKET(sockfd);
        WSACleanup();
        return -1;
    }

    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Échec connexion serveur");
        CLOSESOCKET(sockfd);
        WSACleanup();
        return -1;
    }

    return sockfd;
}

// Fonction pour encoder en base64
char *base64_encode(const unsigned char *buffer, size_t length) {
    BIO *bio, *b64;
    BUF_MEM *buffer_ptr;

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    BIO_write(bio, buffer, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &buffer_ptr);

    char *encoded = malloc(buffer_ptr->length + 1);
    memcpy(encoded, buffer_ptr->data, buffer_ptr->length);
    encoded[buffer_ptr->length] = '\0';

    BIO_free_all(bio);
    return encoded;
}

// Charger la clé privée
EVP_PKEY *load_private_key(const char *key_path) {
    FILE *key_file = fopen(key_path, "r");
    if (!key_file) {
        perror("Erreur chargement clé privée");
        return NULL;
    }
    EVP_PKEY *private_key = PEM_read_PrivateKey(key_file, NULL, NULL, NULL);
    fclose(key_file);
    return private_key;
}

// Fonction pour générer une clé AES et un IV
void generate_aes_key_iv(unsigned char *key, unsigned char *iv) {
    RAND_bytes(key, AES_KEY_SIZE);
    RAND_bytes(iv, AES_IV_SIZE);
}

// Fonction pour charger la clé publique du serveur
EVP_PKEY *load_public_key(const char *public_key_path) {
    FILE *key_file = fopen(public_key_path, "r");
    if (!key_file) {
        perror("Erreur chargement clé publique");
        return NULL;
    }
    EVP_PKEY *public_key = PEM_read_PUBKEY(key_file, NULL, NULL, NULL);
    fclose(key_file);
    return public_key;
}

// Fonction pour chiffrer avec AES-256-CBC#include <openssl/evp.h>


// Fonction pour dériver une clé avec PBKDF2-HMAC-SHA256
int derive_key_pbkdf2(const unsigned char *password, size_t password_len,
                      const unsigned char *salt, size_t salt_len,
                      unsigned char *key, size_t key_len) {
    int iterations = 10000;  // Ajustable selon le niveau de sécurité souhaité

    if (PKCS5_PBKDF2_HMAC((const char *)password, password_len, 
                          salt, salt_len, iterations, EVP_sha256(), 
                          key_len, key) != 1) {
        fprintf(stderr, "Erreur de dérivation de la clé avec PBKDF2\n");
        return -1;
    }
    return 1;
}
// Fonction pour chiffrer avec AES-256-CBC et ajouter l'en-tête "Salted__"
int encrypt_aes(const unsigned char *plaintext, size_t plaintext_len,
                unsigned char *ciphertext, unsigned char *key, unsigned char *iv) {
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    // Générer un sel aléatoire de 8 octets
    unsigned char salt[8];
    RAND_bytes(salt, sizeof(salt));

    // Ajouter l'en-tête "Salted__" suivi du sel
    memcpy(ciphertext, "Salted__", 8);
    memcpy(ciphertext + 8, salt, 8);

    // Initialiser le chiffrement avec PBKDF2 pour dériver la clé AES
    unsigned char derived_key[AES_KEY_SIZE];
    if (derive_key_pbkdf2(key, AES_KEY_SIZE, salt, sizeof(salt), derived_key, AES_KEY_SIZE) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, derived_key, iv);
    int len;
    EVP_EncryptUpdate(ctx, ciphertext + 16, &len, plaintext, plaintext_len);
    int ciphertext_len = len;

    EVP_EncryptFinal_ex(ctx, ciphertext + 16 + len, &len);
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len + 16;  // Ajouter 16 octets pour "Salted__" + sel
}

// Fonction pour chiffrer une clé AES avec RSA
char *encrypt_rsa(const unsigned char *plaintext, size_t plaintext_len, EVP_PKEY *public_key) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(public_key, NULL);
    EVP_PKEY_encrypt_init(ctx);
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING);
    size_t encrypted_len;
    EVP_PKEY_encrypt(ctx, NULL, &encrypted_len, plaintext, plaintext_len);
    unsigned char *encrypted = malloc(encrypted_len);
    EVP_PKEY_encrypt(ctx, encrypted, &encrypted_len, plaintext, plaintext_len);
    EVP_PKEY_CTX_free(ctx);
    char *encoded = base64_encode(encrypted, encrypted_len);
    free(encrypted);
    return encoded;
}
// Fonction pour signer un fichier avec EVP_DigestSign
char *sign_file(const char *filename, EVP_PKEY *private_key) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Erreur ouverture fichier");
        return NULL;
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, private_key);

    unsigned char buffer[BUFFER_SIZE];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        EVP_DigestSignUpdate(mdctx, buffer, bytes_read);
    }
    fclose(file);

    size_t sig_len = 0;
    EVP_DigestSignFinal(mdctx, NULL, &sig_len);
    unsigned char *signature = malloc(sig_len);
    EVP_DigestSignFinal(mdctx, signature, &sig_len);
    EVP_MD_CTX_free(mdctx);

    char *signature_base64 = base64_encode(signature, sig_len);
    free(signature);

    return signature_base64;
}

static void on_send_button_clicked(GtkButton *button, gpointer user_data) {
    // Récupération des champs
    transfer_server_ip = strdup(gtk_entry_get_text(GTK_ENTRY(transfer_server_entry)));
    destination_ip = strdup(gtk_entry_get_text(GTK_ENTRY(destination_entry)));

    if (!selected_file || !transfer_server_ip || !destination_ip) {
        gtk_label_set_text(GTK_LABEL(status_label), "Please fill all fields.");
        return;
    }

    // Vérifier si le fichier existe et est accessible
    if (access(selected_file, F_OK) != 0) {
        perror("Fichier introuvable");
        gtk_label_set_text(GTK_LABEL(status_label), "File not found.");
        return;
    }
    if (access(selected_file, R_OK) != 0) {
        perror("Permissions insuffisantes");
        gtk_label_set_text(GTK_LABEL(status_label), "Cannot read file.");
        return;
    }

    // Lecture du fichier et encodage en Base64
    FILE *file = fopen(selected_file, "rb");
    if (!file) {
        perror("Erreur d'ouverture du fichier");
        gtk_label_set_text(GTK_LABEL(status_label), "Failed to open file.");
        return;
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    unsigned char *file_data = malloc(file_size);
    fread(file_data, 1, file_size, file);
    fclose(file);

    char *encoded_content = base64_encode(file_data, file_size);
    free(file_data);

    // Génération de la clé AES et IV
    unsigned char aes_key[AES_KEY_SIZE], aes_iv[AES_IV_SIZE];
    generate_aes_key_iv(aes_key, aes_iv);

    // Chargement de la clé publique du serveur pour chiffrer la clé AES
    EVP_PKEY *public_key = load_public_key(public_key_path);
    if (!public_key) {
        gtk_label_set_text(GTK_LABEL(status_label), "Erreur chargement clé publique.");
        free(encoded_content);
        return;
    }

    char *encrypted_aes_key = encrypt_rsa(aes_key, AES_KEY_SIZE, public_key);
    EVP_PKEY_free(public_key);

    // Création du JSON original (avant chiffrement)
    json_t *metadata = json_object();
    const char *filename = strrchr(selected_file, '/');
    if (!filename) filename = strrchr(selected_file, '\\');
    filename = filename ? filename + 1 : selected_file;

    json_object_set_new(metadata, "filename", json_string(filename));
    json_object_set_new(metadata, "filesize", json_integer(file_size));
    json_object_set_new(metadata, "data_type", json_string("FILE"));
    json_object_set_new(metadata, "recipient", json_string(destination_ip));

    json_t *message = json_object();
    json_object_set_new(message, "metadata", metadata);
    json_object_set_new(message, "content", json_string(encoded_content));
    json_object_set_new(message, "client_id", json_string(CLIENT_ID));

    // Signature du JSON avant chiffrement
    EVP_PKEY *private_key = load_private_key(private_key_path);
    if (!private_key) {
        gtk_label_set_text(GTK_LABEL(status_label), "Erreur chargement clé privée.");
        json_decref(message);
        free(encoded_content);
        return;
    }

    char *signature_base64 = sign_file(selected_file, private_key);
    EVP_PKEY_free(private_key);

    if (signature_base64) {
        json_object_set_new(message, "signature", json_string(signature_base64));
        free(signature_base64);
    } else {
        json_object_set_new(message, "signature", json_string("Error creating signature"));
    }

    // Conversion en chaîne JSON
    char *json_str = json_dumps(message, JSON_INDENT(4));
    json_decref(message);
    free(encoded_content);

    // Chiffrement du JSON original avec AES-256-CBC + Salted__
    unsigned char ciphertext[BUFFER_SIZE];
    int enc_len = encrypt_aes((unsigned char *)json_str, strlen(json_str), ciphertext, aes_key, aes_iv);
    if (enc_len < 0) {
        gtk_label_set_text(GTK_LABEL(status_label), "Erreur chiffrement AES.");
        free(json_str);
        return;
    }

    // Encodage en Base64 du payload et de l'IV
    char *encrypted_payload_base64 = base64_encode(ciphertext, enc_len);
    char *aes_iv_base64 = base64_encode(aes_iv, AES_IV_SIZE);

    free(json_str);

    // Création du JSON final chiffré
    json_t *encrypted_message = json_object();
    json_object_set_new(encrypted_message, "aes_key", json_string(encrypted_aes_key));
    json_object_set_new(encrypted_message, "aes_iv", json_string(aes_iv_base64));
    json_object_set_new(encrypted_message, "payload", json_string(encrypted_payload_base64));

    char *final_json_str = json_dumps(encrypted_message, JSON_INDENT(4));
    json_decref(encrypted_message);
    free(encrypted_aes_key);
    free(aes_iv_base64);
    free(encrypted_payload_base64);

    // Imprimer le payload avant envoi
    printf("Payload JSON chiffré :\n%s\n", final_json_str);

    // Envoi au serveur
    int sockfd = open_connection(transfer_server_ip, SERVER_PORT);
    if (sockfd < 0) {
        gtk_label_set_text(GTK_LABEL(status_label), "Failed to connect.");
        free(final_json_str);
        return;
    }

    send(sockfd, final_json_str, strlen(final_json_str), 0);
    free(final_json_str);

    // Réception de la réponse
    char buffer[BUFFER_SIZE];
    int bytes_received = recv(sockfd, buffer, sizeof(buffer), 0);
    if (bytes_received < 0) {
        perror("Erreur lors de la réception de la réponse");
        gtk_label_set_text(GTK_LABEL(status_label), "Error receiving data");
    } else {
        buffer[bytes_received] = '\0';
        gtk_label_set_text(GTK_LABEL(status_label), "File sent successfully!");
    }

    CLOSESOCKET(sockfd);
}




// Fonction appelée lorsque l'utilisateur choisit un fichier
static void on_file_chooser_button_clicked(GtkFileChooserButton *button, gpointer user_data) {
	GtkFileChooser *chooser = GTK_FILE_CHOOSER(button);
    selected_file = gtk_file_chooser_get_filename(chooser);
    gtk_label_set_text(GTK_LABEL(status_label), "File selected.");
}

// Fonction principale
int main(int argc, char *argv[]) {
    gtk_init(&argc, &argv);

    window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), "Ghost Transfer");
	gtk_window_set_default_size(GTK_WINDOW(window), 800, 500);
    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
	gtk_container_set_border_width(GTK_CONTAINER(window),15);
    gtk_container_add(GTK_CONTAINER(window), vbox);

    file_chooser_button = gtk_file_chooser_button_new("Choose a file", GTK_FILE_CHOOSER_ACTION_OPEN);
    gtk_box_pack_start(GTK_BOX(vbox), file_chooser_button, FALSE, FALSE, 0);
    g_signal_connect(file_chooser_button, "file-set", G_CALLBACK(on_file_chooser_button_clicked), NULL);

    transfer_server_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(transfer_server_entry), "Transfer Server IP");
    gtk_box_pack_start(GTK_BOX(vbox), transfer_server_entry, FALSE, FALSE, 0);

    destination_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(destination_entry), "Recipient IP");
    gtk_box_pack_start(GTK_BOX(vbox), destination_entry, FALSE, FALSE, 0);

    send_button = gtk_button_new_with_label("Send File");
    gtk_box_pack_start(GTK_BOX(vbox), send_button, FALSE, FALSE, 0);
    g_signal_connect(send_button, "clicked", G_CALLBACK(on_send_button_clicked), NULL);

    status_label = gtk_label_new("Status: Waiting...");
    gtk_box_pack_start(GTK_BOX(vbox), status_label, FALSE, FALSE, 0);

    gtk_widget_show_all(window);
    gtk_main();

    return 0;
}
