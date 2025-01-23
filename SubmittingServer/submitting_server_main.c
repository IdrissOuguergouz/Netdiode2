#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#define BUFFER_SIZE 1024
#define TOKEN_LENGTH 256
#define MAGIC_NUMBER 0xABCD1234
#define MAX_DEST_SIZE 64
#define CONFIG_FILE "config.ini"

// Structure pour l'en-tête du fichier encapsulé
typedef struct {
    uint32_t magic;
    uint8_t version;
    time_t timestamp;
    uint64_t original_size;
    uint64_t total_size;
    char recipient[MAX_DEST_SIZE];
    char hash_algo[16];
    uint8_t hash[32]; // SHA-256
    uint8_t ecc[32];  // Données pour correction d'erreurs
} EncapsulationHeader;

// Structure pour les paramètres de configuration
typedef struct {
    int port;
    char transfer_dir[256];
} Config;

// Liste des IPs autorisées
const char *authorized_ips[] = {"192.168.56.2", NULL};

// Fonction pour vérifier si une IP est autorisée
int is_ip_authorized(const char *client_ip) {
    for (int i = 0; authorized_ips[i] != NULL; i++) {
        if (strcmp(client_ip, authorized_ips[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

// Fonction pour vérifier le token avec une clé publique
int verify_token(const char *token, const char *public_key_path) {
    FILE *pubkey_file = fopen(public_key_path, "r");
    if (!pubkey_file) {
        perror("Erreur d'ouverture de la clé publique");
        return 0;
    }

    EVP_PKEY *pubkey = PEM_read_PUBKEY(pubkey_file, NULL, NULL, NULL);
    fclose(pubkey_file);

    if (!pubkey) {
        fprintf(stderr, "Erreur de lecture de la clé publique\n");
        return 0;
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pubkey, NULL);
    if (!ctx) {
        fprintf(stderr, "Erreur de création du contexte de clé\n");
        EVP_PKEY_free(pubkey);
        return 0;
    }

    if (EVP_PKEY_verify_recover_init(ctx) <= 0) {
        fprintf(stderr, "Erreur d'initialisation de la vérification\n");
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pubkey);
        return 0;
    }

    unsigned char decrypted[TOKEN_LENGTH];
    size_t decrypted_len = sizeof(decrypted);

    if (EVP_PKEY_verify_recover(ctx, decrypted, &decrypted_len, (unsigned char *)token, TOKEN_LENGTH) <= 0) {
        fprintf(stderr, "Erreur de décryptage du token\n");
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pubkey);
        return 0;
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pubkey);

    return 1; // Si décryptage réussi, le token est valide
}

// Fonction pour calculer le hash SHA-256 d'un fichier
void compute_hash(const char *filename, uint8_t *hash) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Erreur d'ouverture du fichier");
        exit(EXIT_FAILURE);
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fprintf(stderr, "Erreur de création du contexte de hash\n");
        fclose(file);
        exit(EXIT_FAILURE);
    }

    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) <= 0) {
        fprintf(stderr, "Erreur d'initialisation du hash\n");
        EVP_MD_CTX_free(mdctx);
        fclose(file);
        exit(EXIT_FAILURE);
    }

    uint8_t buffer[1024];
    size_t bytesRead;
    while ((bytesRead = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        if (EVP_DigestUpdate(mdctx, buffer, bytesRead) <= 0) {
            fprintf(stderr, "Erreur de mise à jour du hash\n");
            EVP_MD_CTX_free(mdctx);
            fclose(file);
            exit(EXIT_FAILURE);
        }
    }

    if (EVP_DigestFinal_ex(mdctx, hash, NULL) <= 0) {
        fprintf(stderr, "Erreur de finalisation du hash\n");
        EVP_MD_CTX_free(mdctx);
        fclose(file);
        exit(EXIT_FAILURE);
    }

    EVP_MD_CTX_free(mdctx);
    fclose(file);
}

// Fonction pour encapsuler un fichier
void encapsulate_file(const char *original_file, const char *recipient, const char *output_file) {
    FILE *input = fopen(original_file, "rb");
    if (!input) {
        perror("Erreur d'ouverture du fichier original");
        exit(EXIT_FAILURE);
    }

    FILE *output = fopen(output_file, "wb");
    if (!output) {
        perror("Erreur de création du fichier encapsulé");
        fclose(input);
        exit(EXIT_FAILURE);
    }

    // Calcul du hash
    uint8_t hash[32];
    compute_hash(original_file, hash);

    // Création de l'en-tête
    EncapsulationHeader header = {
        .magic = MAGIC_NUMBER,
        .version = 1,
        .timestamp = time(NULL),
        .original_size = 0
    };
    strncpy(header.recipient, recipient, MAX_DEST_SIZE - 1);
    strncpy(header.hash_algo, "SHA-256", sizeof(header.hash_algo));
    memcpy(header.hash, hash, sizeof(hash));

    // Calcul de la taille du fichier original
    fseek(input, 0, SEEK_END);
    header.original_size = ftell(input);
    header.total_size = sizeof(header) + header.original_size;
    fseek(input, 0, SEEK_SET);

    // Génération de données de correction d'erreurs (simple exemple)
    memset(header.ecc, 0xFF, sizeof(header.ecc)); // À remplacer par un algorithme ECC réel

    // Écriture de l'en-tête
    fwrite(&header, sizeof(header), 1, output);

    // Écriture des données du fichier original
    uint8_t buffer[1024];
    size_t bytesRead;
    while ((bytesRead = fread(buffer, 1, sizeof(buffer), input)) > 0) {
        fwrite(buffer, 1, bytesRead, output);
    }

    fclose(input);
    fclose(output);

    printf("Fichier encapsulé créé : %s\n", output_file);
}

// Fonction pour gérer un client
void handle_client(int client_socket, const char *public_key_path, const char *transfer_dir) {
    char buffer[BUFFER_SIZE];
    ssize_t bytes_received;

    // Étape 1 : Vérification de l'IP
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    getpeername(client_socket, (struct sockaddr *)&client_addr, &addr_len);
    const char *client_ip = inet_ntoa(client_addr.sin_addr);

    if (!is_ip_authorized(client_ip)) {
        fprintf(stderr, "IP non autorisée : %s\n", client_ip);
        close(client_socket);
        return;
    }

    // Étape 2 : Vérification du token
    bytes_received = recv(client_socket, buffer, sizeof(buffer), 0);
    if (bytes_received <= 0 || !verify_token(buffer, public_key_path)) {
        fprintf(stderr, "Token invalide ou réception échouée\n");
        close(client_socket);
        return;
    }

    // Étape 3 : Réception des métadonnées et du fichier
    char recipient[MAX_DEST_SIZE];
    bytes_received = recv(client_socket, recipient, sizeof(recipient), 0);
    if (bytes_received <= 0) {
        fprintf(stderr, "Erreur lors de la réception du destinataire\n");
        close(client_socket);
        return;
    }

    FILE *temp_file = fopen("temp_received_file", "wb");
    if (!temp_file) {
        perror("Erreur d'ouverture du fichier temporaire");
        close(client_socket);
        return;
    }

    while ((bytes_received = recv(client_socket, buffer, sizeof(buffer), 0)) > 0) {
        fwrite(buffer, 1, bytes_received, temp_file);
    }
    fclose(temp_file);

    // Étape 4 : Encapsulation
    char output_file[BUFFER_SIZE];
    snprintf(output_file, sizeof(output_file), "%s/encapsulated_%ld.bin", transfer_dir, time(NULL));
    encapsulate_file("temp_received_file", recipient, output_file);

    // Nettoyage
    remove("temp_received_file");
    close(client_socket);
}

// Fonction pour charger la configuration
int load_config(const char *filename, Config *config) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Erreur d'ouverture du fichier de configuration");
        return 0;
    }

    char line[256];
    while (fgets(line, sizeof(line), file)) {
        if (strncmp(line, "port", 4) == 0) {
            sscanf(line, "port = %d", &config->port);
        } else if (strncmp(line, "transfer_dir", 12) == 0) {
            sscanf(line, "transfer_dir = %s", config->transfer_dir);
        }
    }

    fclose(file);
    return 1;
}

int main() {
    Config config;

    // Charger la configuration
    if (!load_config(CONFIG_FILE, &config)) {
        fprintf(stderr, "Impossible de charger la configuration\n");
        return EXIT_FAILURE;
    }

    printf("Configuration chargée :\n");
    printf("Port : %d\n", config.port);
    printf("Dossier de transfert : %s\n", config.transfer_dir);
    printf("PID du processus : %d\n", getpid());

    // Créer le dossier TRANSFER_DIR si nécessaire
    mkdir(config.transfer_dir, S_IRWXU | S_IRWXG | S_IROTH);

    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        perror("Erreur de création du socket");
        return EXIT_FAILURE;
    }

    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(config.port);

    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Erreur de liaison du socket");
        close(server_socket);
        return EXIT_FAILURE;
    }

    if (listen(server_socket, 5) < 0) {
        perror("Erreur d'écoute sur le socket");
        close(server_socket);
        return EXIT_FAILURE;
    }

    printf("Serveur en écoute sur le port %d...\n", config.port);

    while (1) {
        int client_socket = accept(server_socket, NULL, NULL);
        if (client_socket >= 0) {
            handle_client(client_socket, "public_key.pem", config.transfer_dir);
        }
    }

    close(server_socket);
    return 0;
}