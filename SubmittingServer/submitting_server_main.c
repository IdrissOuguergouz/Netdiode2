#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <cjson/cJSON.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "correct.h"

//TODO envisager de permettre la lecture de fichier volumineux en les découpants en plusieurs requêtes pour ne pas avoir un buffer trop grand
#define CLIENT_DATA_BUFFER_SIZE 16384
#define SIGNATURE_SIZE 1024
#define AES_KEY_SIZE 32
#define MAGIC_NUMBER 0xABCD1234
#define MAX_DEST_SIZE 64
#define CONFIG_FILE "config.ini"
#define MAX_IP_ENTRIES 1000
#define ACL "ACL.txt"
#define PARITY_SIZE 32  // Nombre d'octets de parité
#define BLOCK_SIZE 223  // Taille des données utiles dans un bloc
#define ENCODED_SIZE 255 // Taille totale après encodage (223 + 32)

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

// Fonction pour calculer le hash SHA-256 d'une chaîne de caractères
void compute_hash(const char *input, uint8_t *hash) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fprintf(stderr, "Erreur de création du contexte de hash\n");
        exit(EXIT_FAILURE);
    }

    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) <= 0) {
        fprintf(stderr, "Erreur d'initialisation du hash\n");
        EVP_MD_CTX_free(mdctx);
        exit(EXIT_FAILURE);
    }

    if (EVP_DigestUpdate(mdctx, input, strlen(input)) <= 0) {
        fprintf(stderr, "Erreur de mise à jour du hash\n");
        EVP_MD_CTX_free(mdctx);
        exit(EXIT_FAILURE);
    }

    if (EVP_DigestFinal_ex(mdctx, hash, NULL) <= 0) {
        fprintf(stderr, "Erreur de finalisation du hash\n");
        EVP_MD_CTX_free(mdctx);
        exit(EXIT_FAILURE);
    }

    EVP_MD_CTX_free(mdctx);
}

size_t base64_decode(const char *input, unsigned char *output) {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *bio = BIO_new_mem_buf(input, -1);
    bio = BIO_push(b64, bio);

    // Désactiver le saut de ligne dans le Base64
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    const size_t input_len = strlen(input);
    const size_t output_len = BIO_read(bio, output, input_len);
    BIO_free_all(bio);
    return output_len;
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

// Fonction pour extraire le salt d'un contenu chiffré OpenSSL
int extract_salt(const unsigned char *encrypted_content, unsigned char *salt) {
    const int HEADER_SIZE = 8;
    const int SALT_SIZE = 8;

    // Vérification du préfixe "Salted__"
    char header[HEADER_SIZE];

    memcpy(header, encrypted_content, HEADER_SIZE);
    
    // Vérifier que l'en-tête est "Salted__"
    if (strncmp(header, "Salted__", HEADER_SIZE) != 0) {
        fprintf(stderr, "En-tête 'Salted__' manquant\n");
        return -1;
    }
    memcpy(salt, encrypted_content + HEADER_SIZE, SALT_SIZE);

    return 0;
}

// Fonction pour dériver une clé à partir d'un mot de passe et d'un salt
int derive_key_pbkdf2(const unsigned char *password, size_t password_len,
                      const unsigned char *salt, size_t salt_len,
                      unsigned char *key, size_t key_len) {
    // Dérivation de la clé avec PBKDF2-HMAC
    int iterations = 10000;  // Nombre d'itérations, tu peux ajuster selon tes besoins

    if (PKCS5_PBKDF2_HMAC((const char *)password, password_len, salt, salt_len, iterations, EVP_sha256(), key_len, key) != 1) {
        fprintf(stderr, "Erreur de dérivation de la clé avec PBKDF2\n");
        return -1;
    }
    return 1;
}

// Fonction pour signer un contenu avec une clé privée
int sign_content(const unsigned char *content, size_t content_len, unsigned char **signature, size_t *signature_len, const char *keys_path) {
    char full_private_key_path[512];
    snprintf(full_private_key_path, sizeof(full_private_key_path), "%sprivate/server_private.pem", keys_path);
    FILE *privkey_file = fopen(full_private_key_path, "r");
    if (!privkey_file) {
        if (errno == ENOENT) {
            fprintf(stderr, "| /!\\ Fichier de clé privée manquant\n");
        } else {
            perror("Erreur d'ouverture de la clé privée");
        }
        return -1;
    }

    EVP_PKEY *privkey = PEM_read_PrivateKey(privkey_file, NULL, NULL, NULL);
    fclose(privkey_file);

    if (!privkey) {
        fprintf(stderr, "Erreur de lecture de la clé privée\n");
        return -1;
    }
    
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fprintf(stderr, "Erreur de création du contexte de signature\n");
        return -1;
    }

    if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, privkey) <= 0) {
        fprintf(stderr, "Erreur d'initialisation de la signature\n");
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    if (EVP_DigestSignUpdate(mdctx, content, content_len) <= 0) {
        fprintf(stderr, "Erreur de mise à jour de la signature\n");
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    if (EVP_DigestSignFinal(mdctx, NULL, signature_len) <= 0) {
        fprintf(stderr, "Erreur de finalisation de la signature (taille)\n");
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    *signature = (unsigned char *)malloc(*signature_len);
    if (!*signature) {
        fprintf(stderr, "Erreur d'allocation de mémoire pour la signature\n");
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    if (EVP_DigestSignFinal(mdctx, *signature, signature_len) <= 0) {
        fprintf(stderr, "Erreur de finalisation de la signature\n");
        free(*signature);
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    EVP_MD_CTX_free(mdctx);
    return 1;
}

// Fonction pour vérifier une signature avec une clé publique
int verify_signature(const unsigned char *content, size_t content_len,
                     const unsigned char *signature, size_t signature_len, 
                     const char *keys_path, const char *client_id) {

    char full_public_key_path[512];
    snprintf(full_public_key_path, sizeof(full_public_key_path), "%spublic/clients/%s_pub.pem", keys_path, client_id);
    FILE *pubkey_file = fopen(full_public_key_path, "r");
    if (!pubkey_file) {
        if (errno == ENOENT) {
            fprintf(stderr, "| /!\\ Fichier de clé publique manquant\n");
        } else {
            perror("Erreur d'ouverture de la clé publique");
        }
        return -1;
    }

    EVP_PKEY *pubkey = PEM_read_PUBKEY(pubkey_file, NULL, NULL, NULL);
    fclose(pubkey_file);

    if (!pubkey) {
        fprintf(stderr, "Erreur de lecture de la clé publique\n");
        return -1;
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fprintf(stderr, "Erreur de création du contexte de vérification\n");
        EVP_PKEY_free(pubkey);
        return -1;
    }

    EVP_PKEY_CTX *pkey_ctx;
    if (EVP_DigestVerifyInit(mdctx, &pkey_ctx, EVP_sha256(), NULL, pubkey) <= 0) {
        fprintf(stderr, "Erreur d'initialisation de la vérification\n");
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pubkey);
        return -1;
    }

    EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PADDING);
    
    if (EVP_DigestVerifyUpdate(mdctx, content, content_len) <= 0) {
        fprintf(stderr, "Erreur de mise à jour de la vérification\n");
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pubkey);
        return -1;
    }

    int result = EVP_DigestVerifyFinal(mdctx, signature, signature_len);
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pubkey);

    if (result == 1) {
        return 1; // Signature valide
    } else if (result == 0) {
        return 0;
    } else {
        return -1;
    }
}

// Fonction pour déchiffrer un contenu avec AES-256-CBC
int decrypt_aes(const unsigned char *encrypted_content, size_t encrypted_len,
                unsigned char *decrypted_content, size_t *decrypted_len,
                const unsigned char *password, const unsigned char *salt,
                const unsigned char *iv) {
    // Dérivation de la clé à partir du mot de passe et du salt
    unsigned char key[AES_KEY_SIZE];
    if (derive_key_pbkdf2(password, strlen((const char *)password), salt, sizeof(salt), key, AES_KEY_SIZE) != 1) {
        return -1;
    }

    // Création du contexte de déchiffrement
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Erreur de création du contexte de déchiffrement AES\n");
        return -1;
    }

    // Initialisation du déchiffrement AES-256-CBC
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        fprintf(stderr, "Erreur d'initialisation du déchiffrement AES\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Ignorer les 16 premiers octets qui contiennent le sel
    const unsigned char *data_to_decrypt = encrypted_content + 16;
    size_t data_len = encrypted_len - 16;

    // Déchiffrement
    int len;
    if (EVP_DecryptUpdate(ctx, decrypted_content, &len, data_to_decrypt, data_len) != 1) {
        fprintf(stderr, "Erreur lors du déchiffrement AES\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    *decrypted_len = len;

    // Finalisation du déchiffrement
    if (EVP_DecryptFinal_ex(ctx, decrypted_content + len, &len) != 1) {
        fprintf(stderr, "Erreur lors de la finalisation du déchiffrement AES\n");

        unsigned long err_code;
        while ((err_code = ERR_get_error())) {
            char err_buf[256];
            ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
            fprintf(stderr, "OpenSSL error: %s\n", err_buf);
        }

        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    *decrypted_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return 1;
}

// Fonction pour déchiffrer un contenu avec une clé privée
int decrypt_rsa(const unsigned char *encrypted_content, size_t encrypted_len,
                    unsigned char *decrypted_content, size_t *decrypted_len,
                    const char *keys_path) {

    char full_private_key_path[512];
    snprintf(full_private_key_path, sizeof(full_private_key_path), "%sprivate/server_private.pem", keys_path);
    FILE *privkey_file = fopen(full_private_key_path, "r");
    if (!privkey_file) {
        if (errno == ENOENT) {
            fprintf(stderr, "| /!\\ Fichier de clé privée manquant\n");
        } else {
            perror("Erreur d'ouverture de la clé privée");
        }
        return -1;
    }

    EVP_PKEY *privkey = PEM_read_PrivateKey(privkey_file, NULL, NULL, NULL);
    fclose(privkey_file);

    if (!privkey) {
        fprintf(stderr, "Erreur de lecture de la clé privée\n");
        return -1;
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(privkey, NULL);
    if (!ctx) {
        fprintf(stderr, "Erreur de création du contexte de déchiffrement\n");
        EVP_PKEY_free(privkey);
        return -1;
    }

    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        fprintf(stderr, "Erreur d'initialisation du déchiffrement\n");
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(privkey);
        return -1;
    }

    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING);
    
    if (EVP_PKEY_decrypt(ctx, NULL, decrypted_len, encrypted_content, encrypted_len) <= 0) {
        fprintf(stderr, "Erreur lors de la détermination de la taille du contenu déchiffré\n");
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(privkey);
        return -1;
    }

    if (EVP_PKEY_decrypt(ctx, decrypted_content, decrypted_len, encrypted_content, encrypted_len) <= 0) {
        fprintf(stderr, "Erreur lors du déchiffrement du contenu\n");
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(privkey);
        return -1;
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(privkey);
    return 1;
}

unsigned char* read_file(const char *filename, size_t *filesize) {
    printf("Filename: %s\n", filename);
    FILE *file = fopen(filename, "rb"); // "rb" pour lecture binaire
    if (!file) {
        perror("Erreur d'ouverture");
        return NULL;
    }

    // Obtenir la taille du fichier
    fseek(file, 0, SEEK_END);
    *filesize = ftell(file);  // On stocke la taille dans la variable pointée
    rewind(file);

    // Allouer la mémoire
    unsigned char *content = (unsigned char*)malloc(*filesize + 1);
    if (!content) {
        perror("Erreur d'allocation");
        fclose(file);
        return NULL;
    }

    // Lire le fichier en mémoire
    size_t read_size = fread(content, 1, *filesize, file);
    fclose(file);

    // Vérifier que toute la lecture s'est bien passée
    if (read_size != *filesize) {
        fprintf(stderr, "Erreur de lecture du fichier : attendu %zu, lu %zu\n", *filesize, read_size);
        free(content);
        return NULL;
    }

    // Ajouter un caractère de fin de chaîne (utile pour les fichiers texte)
    content[*filesize] = '\0';

    return content;
}

// Fonction pour encoder les données avec Reed-Solomon
void encode_rs(unsigned char* data, size_t size, unsigned char* encoded) {
    correct_reed_solomon *rs = correct_reed_solomon_create(0x11D, 1, 1, 16);
    if (!rs) {
        fprintf(stderr, "Erreur lors de la création de l'encodeur Reed-Solomon\n");
        exit(EXIT_FAILURE);
    }

    unsigned char block[BLOCK_SIZE] = {0}; // Initialiser à 0
    memcpy(block, data, size);

    ssize_t encoded_len = correct_reed_solomon_encode(rs, block, BLOCK_SIZE, encoded);
    if (encoded_len < 0) {
        fprintf(stderr, "Erreur d'encodage. Taille encodée: %ld\n", encoded_len);
        correct_reed_solomon_destroy(rs);
        exit(EXIT_FAILURE);
    }

    correct_reed_solomon_destroy(rs);
    return;
}

void introduce_errors(unsigned char* data, int num_errors) {
    num_errors = num_errors > PARITY_SIZE / 2 ? PARITY_SIZE / 2 : num_errors;
    for (int i = 0; i < num_errors; i++) {
        int pos = rand() % ENCODED_SIZE;
        data[pos] ^= (1 << (rand() % 8));
    }
    return;
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
        printf("| Réception de %ldB de données\n", bytes_received);
    }

    // Parse the received JSON data
    cJSON *received_json = cJSON_Parse(buffer);
    if (!received_json) {
        fprintf(stderr, "| Erreur de parsing du payload\n");
        const char *response = "Données reçues au format invalide !\n";
        send(client_socket, response, strlen(response), 0);
        close(client_socket);
        return;
    }

    // Extract the AES key and payload from the JSON
    const char *aes_key_base64 = cJSON_GetObjectItem(received_json, "aes_key")->valuestring;
    const char *aes_iv_base64 = cJSON_GetObjectItem(received_json, "aes_iv")->valuestring;
    const char *payload_base64 = cJSON_GetObjectItem(received_json, "payload")->valuestring;

    // Decode the base64 content
    unsigned char aes_key[1024];
    size_t aes_key_len = base64_decode(aes_key_base64, aes_key);

    unsigned char aes_iv[16];
    size_t aes_iv_len = base64_decode(aes_iv_base64, aes_iv);

    unsigned char encrypted_payload[CLIENT_DATA_BUFFER_SIZE];
    size_t encrypted_payload_len = base64_decode(payload_base64, encrypted_payload);
    
    unsigned char decrypted_content[CLIENT_DATA_BUFFER_SIZE];
    size_t decrypted_content_len = sizeof(decrypted_content);

    unsigned char decrypted_aes_key[256];
    size_t decrypted_aes_key_len = sizeof(decrypted_aes_key);

    unsigned char salt[8];

    // Decrypt the payload using the AES key
    if (decrypt_rsa(aes_key, aes_key_len, decrypted_aes_key, &decrypted_aes_key_len, keys_path) != 1) {
        fprintf(stderr, "| Erreur lors du déchiffrement de la clé AES\n");
        const char *response = "Erreur lors du déchiffrement du contenu\n";
        send(client_socket, response, strlen(response), 0);
        cJSON_Delete(received_json);
        close(client_socket);
        return;
    } else {
        printf("| Clé AES déchiffrée avec succès\n");
        if (extract_salt(encrypted_payload, salt) != 0) {
            fprintf(stderr, "| Erreur lors de l'extraction du sel\n");
            const char *response = "Erreur lors du déchiffrement du contenu\n";
            send(client_socket, response, strlen(response), 0);
            cJSON_Delete(received_json);
            close(client_socket);
            return;
        } else {
            printf("| Sel extrait avec succès\n");
            if (decrypt_aes(encrypted_payload, encrypted_payload_len, decrypted_content, &decrypted_content_len, decrypted_aes_key, salt, aes_iv) != 1) {
                fprintf(stderr, "| Erreur lors du déchiffrement du contenu\n");
                const char *response = "Erreur lors du déchiffrement du contenu\n";
                send(client_socket, response, strlen(response), 0);
                cJSON_Delete(received_json);
                close(client_socket);
                return;
            } else {
                printf("| Contenu déchiffré avec succès\n");
                cJSON_Delete(received_json);
            }
        }
    }

    cJSON *json = cJSON_Parse(decrypted_content);
    if (!json) {
        fprintf(stderr, "| Erreur de parsing des données\n");
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

    // Vérification et récupération des champs individuellement
    int error_flag = 0;

    cJSON *json_filename = cJSON_GetObjectItem(metadata, "filename");
    if (!json_filename || !cJSON_IsString(json_filename)) {
        fprintf(stderr, "| Erreur : Champ 'filename' manquant ou invalide\n");
        error_flag = 1;
    }

    cJSON *json_filesize = cJSON_GetObjectItem(metadata, "filesize");
    if (!json_filesize || !cJSON_IsNumber(json_filesize)) {
        fprintf(stderr, "| Erreur : Champ 'filesize' manquant ou invalide\n");
        error_flag = 1;
    }

    cJSON *json_data_type = cJSON_GetObjectItem(metadata, "data_type");
    if (!json_data_type || !cJSON_IsString(json_data_type)) {
        fprintf(stderr, "| Erreur : Champ 'data_type' manquant ou invalide\n");
        error_flag = 1;
    }

    cJSON *json_recipient = cJSON_GetObjectItem(metadata, "recipient");
    if (!json_recipient || !cJSON_IsString(json_recipient)) {
        fprintf(stderr, "| Erreur : Champ 'recipient' manquant ou invalide\n");
        error_flag = 1;
    }

    cJSON *json_content = cJSON_GetObjectItem(json, "content");
    if (!json_content || !cJSON_IsString(json_content)) {
        fprintf(stderr, "| Erreur : Champ 'content' manquant ou invalide\n");
        error_flag = 1;
    }

    cJSON *json_signature = cJSON_GetObjectItem(json, "signature");
    if (!json_signature || !cJSON_IsString(json_signature)) {
        fprintf(stderr, "| Erreur : Champ 'signature' manquant ou invalide\n");
        error_flag = 1;
    }

    cJSON *json_client_id = cJSON_GetObjectItem(json, "client_id");
    if (!json_client_id || !cJSON_IsString(json_client_id)) {
        fprintf(stderr, "| Erreur : Champ 'client_id' manquant ou invalide\n");
        error_flag = 1;
    }

    // Si une erreur a été détectée, renvoyer une réponse et fermer la connexion
    if (error_flag) {
        const char *response = "Données JSON invalides !\n";
        send(client_socket, response, strlen(response), 0);
        cJSON_Delete(json);
        close(client_socket);
        return;
    }

    // Récupération des valeurs après validation
    const char *filename = json_filename->valuestring;
    int filesize = json_filesize->valueint;
    const char *data_type = json_data_type->valuestring;
    const char *recipient = json_recipient->valuestring;
    const char *content_data_base64 = json_content->valuestring;
    const char *signature_base64 = json_signature->valuestring;
    const char *client_id = json_client_id->valuestring;

    // Affichage des valeurs récupérées
    printf("| Métadonnées récupérées avec succès :\n");
    printf("  - Filename : %s\n", filename);
    printf("  - Filesize : %d\n", filesize);
    printf("  - Data Type : %s\n", data_type);
    printf("  - Recipient : %s\n", recipient);
    printf("  - Client ID : %s\n", client_id);

    // Décodage de base64 des données fichier et de la signature
    unsigned char content_data[CLIENT_DATA_BUFFER_SIZE];
    size_t content_data_len = base64_decode(content_data_base64, content_data);

    unsigned char signature[SIGNATURE_SIZE];
    size_t signature_len = base64_decode(signature_base64, signature);

    // Étape 3 : Vérifier la signature avec la clé publique
    printf("| Authentification du client %s...\n", client_id);
    int result = verify_signature(content_data, content_data_len, signature, signature_len, keys_path, client_id);
    if (result == 1) {
        printf("| Client authentifié avec succès\n");
    } else if (result == 0) {
        fprintf(stderr, "| Échec de l'authentification du client (Signature invalide)\n");
        const char *response = "Échec de l'authentification du client (Signature invalide)\n";
        send(client_socket, response, strlen(response), 0);
        cJSON_Delete(json);
        close(client_socket);
        return;
    } else {
        fprintf(stderr, "| Erreur lors de l'authentification du client\n");
        const char *response = "Erreur lors de l'authentification du client\n";
        send(client_socket, response, strlen(response), 0);
        cJSON_Delete(json);
        close(client_socket);
        return;
    }

    // Etape 4 : Encodage des données pour la correction d'erreurs
    unsigned char data_correction[CLIENT_DATA_BUFFER_SIZE];
    memcpy(data_correction, content_data, content_data_len);
    size_t data_size = sizeof(data_correction);
    size_t num_block = ((data_size - 1) / BLOCK_SIZE) + 1;
    time_t now = time(NULL);
    char correct_path[256];
    struct stat st = {0};
    if (stat(transfer_dir, &st) == -1) {
        printf("le dossier n'existe pas\n");
    }

    snprintf(correct_path, sizeof(correct_path), "%stransfer_%ld", transfer_dir, now);
    
    FILE *encoded_file = fopen(correct_path, "wb");
    if (!encoded_file) {
        perror("Erreur ouverture fichier encodé");
        cJSON_Delete(json);
        close(client_socket);
        return;
    }

    for (int i = 0; i < num_block; i++) {
        unsigned char encoded_block_data[ENCODED_SIZE];
        size_t block_size = (i == num_block - 1 && data_size % BLOCK_SIZE != 0) ? data_size % BLOCK_SIZE : BLOCK_SIZE;
        unsigned char block_data[BLOCK_SIZE] = {0};
        memcpy(block_data, data_correction + i * BLOCK_SIZE, block_size);

        encode_rs(block_data, block_size, encoded_block_data);
        // indroduction d'erreur par block
        introduce_errors(encoded_block_data, 0);

        fwrite(encoded_block_data, ENCODED_SIZE, 1, encoded_file);
    }

    fclose(encoded_file);
    cJSON_Delete(json);

    // Étape 5 : Réponse au client
    const char *response = "Données reçues avec succès !\n";
    send(client_socket, response, strlen(response), 0);
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
        printf("ACL chargée avec succès\n");
    } else {
        printf("Erreur lors du chargement de l'ACL\n");
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
