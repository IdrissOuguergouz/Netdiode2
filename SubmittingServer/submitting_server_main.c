#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <cjson/cJSON.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

//TODO envisager de permettre la lecture de fichier volumineux en les découpants en plusieurs requêtes pour ne pas avoir un buffer trop grand
#define CLIENT_DATA_BUFFER_SIZE 8192
#define SIGNATURE_SIZE 1024
#define MAGIC_NUMBER 0xABCD1234
#define MAX_DEST_SIZE 64
#define CONFIG_FILE "config.ini"
#define MAX_IP_ENTRIES 1000
#define ACL "ACL.txt"

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
    char keys_path[256];
} Config;

struct in_addr acl_ips[MAX_IP_ENTRIES];  // Tableau d'IP autorisées
int acl_count = 0;  // Nombre d'IP stockées

// Fonction pour convertir une adresse CIDR en une plage d'IP et les stocker
void add_cidr_range(const char *cidr) {
    char ip[INET_ADDRSTRLEN];
    int prefix;
    struct in_addr start, end;

    sscanf(cidr, "%[^/]/%d", ip, &prefix);
    if (inet_pton(AF_INET, ip, &start) != 1) return;

    uint32_t mask = 0xFFFFFFFF << (32 - prefix);
    uint32_t ip_addr = ntohl(start.s_addr);
    uint32_t range_start = ip_addr & mask;
    uint32_t range_end = range_start | ~mask;

    for (uint32_t i = range_start; i <= range_end && acl_count < MAX_IP_ENTRIES; i++) {
        acl_ips[acl_count++].s_addr = htonl(i);
    }
}

// Fonction pour ajouter une plage d'IP
void add_ip_range(const char *range) {
    char start_ip[INET_ADDRSTRLEN], end_ip[INET_ADDRSTRLEN];
    struct in_addr start, end;

    sscanf(range, "%[^-]-%s", start_ip, end_ip);
    if (inet_pton(AF_INET, start_ip, &start) != 1 || inet_pton(AF_INET, end_ip, &end) != 1) return;

    uint32_t start_addr = ntohl(start.s_addr);
    uint32_t end_addr = ntohl(end.s_addr);

    for (uint32_t i = start_addr; i <= end_addr && acl_count < MAX_IP_ENTRIES; i++) {
        acl_ips[acl_count++].s_addr = htonl(i);
    }
}

// Fonction pour charger ACL.txt dans acl_ips[]
int load_acl(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Erreur d'ouverture du fichier ACL");
        return 0;
    }

    char line[64];
    while (fgets(line, sizeof(line), file)) {
        line[strcspn(line, "\n")] = 0;  // Supprimer le saut de ligne

        if (strchr(line, '/')) {  // CIDR
            add_cidr_range(line);
        } else if (strchr(line, '-')) {  // Plage IP
            add_ip_range(line);
        } else {  // IP unique
            if (inet_pton(AF_INET, line, &acl_ips[acl_count]) == 1 && acl_count < MAX_IP_ENTRIES) {
                acl_count++;
            }
        }
    }

    fclose(file);
    return 1;
}

// Fonction pour afficher le tableau acl_ips[]
void print_acl() {
    char ip_str[INET_ADDRSTRLEN];
    printf("ACL chargée (%d IPs) :\n", acl_count);
    for (int i = 0; i < acl_count; i++) {
        inet_ntop(AF_INET, &acl_ips[i], ip_str, sizeof(ip_str));
        printf("  - %s\n", ip_str);
    }
}

int is_ip_authorized(const char *client_ip) {
    struct in_addr client_addr;
    if (inet_pton(AF_INET, client_ip, &client_addr) != 1) {
        return 0;
    }

    for (int i = 0; i < acl_count; i++) {
        if (client_addr.s_addr == acl_ips[i].s_addr) {
            return 1;
        }
    }
    return 0;
}

// Fonction pour vérifier une signature avec une clé publique
int verify_signature(const unsigned char *message, size_t message_len,
                     const unsigned char *signature, size_t signature_len,
                     const char *public_key_path) {
    char full_public_key_path[512];
    snprintf(full_public_key_path, sizeof(full_public_key_path), "%s/public/clients/public_key.pem", public_key_path);
    FILE *pubkey_file = fopen(full_public_key_path, "r");
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

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fprintf(stderr, "Erreur de création du contexte de vérification\n");
        EVP_PKEY_free(pubkey);
        return 0;
    }

    if (EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pubkey) <= 0) {
        fprintf(stderr, "Erreur d'initialisation de la vérification\n");
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pubkey);
        return 0;
    }

    int result = EVP_DigestVerify(mdctx, signature, signature_len, message, message_len);

    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pubkey);

    if (result == 1) {
        return 1; // Signature valide
    } else if (result == 0) {
        fprintf(stderr, "Signature invalide\n");
        return 0;
    } else {
        fprintf(stderr, "Erreur lors de la vérification de la signature\n");
        return 0;
    }
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

size_t base64_decode(const char *input, size_t input_len, unsigned char *output) {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *bio = BIO_new_mem_buf(input, input_len);
    bio = BIO_push(b64, bio);

    // Désactiver le saut de ligne dans le Base64
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    const size_t output_len = BIO_read(bio, output, input_len);
    BIO_free_all(bio);

    return output_len;
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
void handle_client(int client_socket, const char *keys_path, const char *transfer_dir) {
    char buffer[CLIENT_DATA_BUFFER_SIZE];
    size_t bytes_received;

    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    getpeername(client_socket, (struct sockaddr *)&client_addr, &addr_len);
    const char *client_ip = inet_ntoa(client_addr.sin_addr);

    printf("Tentative de connexion de %s\n", client_ip);

    // Étape 1 : Vérification de l'IP
    if (is_ip_authorized(client_ip)) {
        printf("| Connexion autorisée\n");
    } else {
        fprintf(stderr, "| Connexion bloquée\n");
        const char *response = "Connexion impossible : IP non autorisée\n";
        send(client_socket, response, strlen(response), 0);
        shutdown(client_socket, SHUT_RDWR);
        close(client_socket);
        return;
    }

    // Étape 2 : Réception des données
    bytes_received = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
    if (bytes_received <= 0) {
        fprintf(stderr, "| Erreur lors de la réception des données\n");
        close(client_socket);
        return;
    } else {
        printf("| Reception de %ldB de données\n", bytes_received);
    }
    buffer[bytes_received] = '\0';

    cJSON *json = cJSON_Parse(buffer);
    if (!json) {
        fprintf(stderr, "| Erreur de parsing du JSON\n");
        const char *response = "Données au format invalide !\n";
        send(client_socket, response, strlen(response), 0);
        close(client_socket);
        return;
    } else {
        printf("| Données JSON reçues\n");
    }

    // Extraire les métadonnées
    cJSON *metadata = cJSON_GetObjectItem(json, "metadata");
    if (!metadata) {
        fprintf(stderr, "| Métadonnées manquantes\n");
        const char *response = "Données au format invalide ! (Métadonnées manquantes)\n";
        send(client_socket, response, strlen(response), 0);
        cJSON_Delete(json);
        close(client_socket);
        return;
    }

    const char *filename = cJSON_GetObjectItem(metadata, "filename")->valuestring;
    const char *filesize = cJSON_GetObjectItem(metadata, "filesize")->valuestring;
    const char *data_type = cJSON_GetObjectItem(metadata, "data_type")->valuestring;
    const char *recipient = cJSON_GetObjectItem(metadata, "recipient")->valuestring;

    // Extraire les données encodées du fichier
    const char *content_data_base64 = cJSON_GetObjectItem(json, "content")->valuestring;
    const char *signature_base64 = cJSON_GetObjectItem(json, "signature")->valuestring;
    const char *client_id = cJSON_GetObjectItem(json, "client_id")->valuestring;

    // Décodage de base64 des données fichier et de la signature
    unsigned char file_data[CLIENT_DATA_BUFFER_SIZE];
    size_t file_data_len = base64_decode(content_data_base64, strlen(content_data_base64), file_data);

    unsigned char signature[SIGNATURE_SIZE];
    base64_decode(signature_base64, strlen(signature_base64), signature);

    // Étape 3 : Vérifier la signature avec la clé publique
    if (!verify_signature(file_data, file_data_len, signature, SIGNATURE_SIZE, keys_path)) {
        fprintf(stderr, "| Échec de l'authentification du client\n");
        const char *response = "Échec de l'authentification du client (Signature invalide)\n";
        send(client_socket, response, strlen(response), 0);
        cJSON_Delete(json);
        close(client_socket);
        return;
    } else {
        printf("| Client authentifié avec succès\n");
    }

    // Étape 4 : Sauvegarder/traiter selon le type de données
    if (strcmp(data_type, "FILE") == 0) {
        char output_file[CLIENT_DATA_BUFFER_SIZE];
        snprintf(output_file, sizeof(output_file), "received_file_%ld.bin", time(NULL));

        FILE *output = fopen(output_file, "wb");
        if (!output) {
            perror("Erreur d'ecriture du fichier");
            cJSON_Delete(json);
            close(client_socket);
            return;
        }

        fwrite(file_data, 1, file_data_len, output);
        fclose(output);

        printf("Fichier sauvegardé : %s\n", output_file);
    } else if (strcmp(data_type, "MAIL") == 0) {
        printf("Traitement des mails non implémenté\n");
        // TODO : Ajouter un traitement spécifique pour les mails.
    } else {
        fprintf(stderr, "Type de données inconnu : %s\n", data_type);
    }

    cJSON_Delete(json);
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
            if (sscanf(line, "port = %d", &config->port) != 1) {
                fprintf(stderr, "Erreur : impossible de lire 'port'.\n");
            }
        } else if (strncmp(line, "transfer_dir", 12) == 0) {
            if (sscanf(line, "transfer_dir = %s", config->transfer_dir) != 1) {
                fprintf(stderr, "Erreur : impossible de lire 'transfer_dir'.\n");
            }
        } else if (strncmp(line, "keys_path", 9) == 0) {
            if (sscanf(line, "keys_path = %s", config->keys_path) != 1) {
                fprintf(stderr, "Erreur : impossible de lire 'keys_path'.\n");
            }
        }
    }

    fclose(file);
    return 1;
}

int main() {
    Config config;
    printf("Démarrage du serveur GhostTransfer...\n");
    if (!load_config(CONFIG_FILE, &config)) {

    printf("Chargement de la configuration...\n");
        fprintf(stderr, "Impossible de charger la configuration\n");
        return EXIT_FAILURE;
    } else {
        printf("Configuration chargée avec succès\n");
        printf("| Port : %d\n", config.port);
        printf("| Dossier de transfert : %s\n", config.transfer_dir);
        printf("| Localisation des clés RSA : %s\n", config.keys_path);
    }

    if (load_acl(ACL)) {
        printf("ACL chargée avec succès !\n");
        print_acl();
    } else {
        printf("Erreur de chargement de l'ACL\n");
    }

    // Vérifier et créer le dossier transfer_dir si nécessaire
    struct stat transfer_dir_stat;
    if (stat(config.transfer_dir, &transfer_dir_stat) != 0) {
        // Le dossier n'existe pas, on le crée
        if (mkdir(config.transfer_dir, S_IRWXU | S_IRWXG | S_IROTH) != 0) {
            perror("Erreur lors de la création du dossier transfer_dir");
            return EXIT_FAILURE;
        }
        printf("Dossier de transfert créé : %s\n", config.transfer_dir);
    } else if (!S_ISDIR(transfer_dir_stat.st_mode)) {
        // Si un fichier avec le même nom existe, erreur
        fprintf(stderr, "Erreur : %s existe mais n'est pas un dossier\n", config.transfer_dir);
        return EXIT_FAILURE;
    }

    // Vérifier et créer le dossier keys_path et son arborescence si nécessaire
    struct stat keys_dir_stat;
    if (stat(config.keys_path, &keys_dir_stat) != 0) {
        // Le dossier n'existe pas, on le crée
        if (mkdir(config.keys_path, S_IRWXU | S_IRGRP | S_IROTH) != 0) {
            perror("Erreur lors de la création du dossier keys_path");
            return EXIT_FAILURE;
        }
        printf("Dossier des clés créé : %s\n", config.keys_path);
    } else if (!S_ISDIR(keys_dir_stat.st_mode)) {
        // Si un fichier avec le même nom existe, erreur
        fprintf(stderr, "Erreur : %s existe mais n'est pas un dossier\n", config.keys_path);
        return EXIT_FAILURE;
    }

    // Créer le dossier private avec les permissions 700
    if (mkdir("keys/private", S_IRWXU) != 0 && errno != EEXIST) {
        perror("Erreur lors de la création du dossier private");
        return EXIT_FAILURE;
    }

    // Créer le dossier public avec les permissions 775
    if (mkdir("keys/public", S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) != 0 && errno != EEXIST) {
        perror("Erreur lors de la création du dossier public");
        return EXIT_FAILURE;
    }

    // Créer le dossier clients avec les permissions 775
    if (mkdir("keys/public/clients", S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) != 0 && errno != EEXIST) {
        perror("Erreur lors de la création du dossier clients");
        return EXIT_FAILURE;
    }

    // Créer le dossier servers avec les permissions 700
    if (mkdir("keys/public/servers", S_IRWXU) != 0 && errno != EEXIST) {
        perror("Erreur lors de la création du dossier servers");
        return EXIT_FAILURE;
    }

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
    printf("PID du processus : %d\n", getpid());

    while (1) {
        int client_socket = accept(server_socket, NULL, NULL);
        if (client_socket >= 0) {
            handle_client(client_socket, config.keys_path, config.transfer_dir);
        }
    }

    close(server_socket);
    return 0;
}
