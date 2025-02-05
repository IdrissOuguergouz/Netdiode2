#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <cjson/cJSON.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include "correct.h"
#include <sys/inotify.h>
#include <limits.h>
#include <sys/select.h>

//TODO envisager de permettre la lecture de fichier volumineux en les découpants en plusieurs requêtes pour ne pas avoir un buffer trop grand
#define SERVER_BUFFER_SIZE 16384
#define SIGNATURE_SIZE 1024
#define AES_KEY_SIZE 32
#define AES_IV_SIZE 16
#define MAGIC_NUMBER 0xABCD1234
#define MAX_DEST_SIZE 64
#define CONFIG_FILE "config.ini"
#define MAX_IP_ENTRIES 1000
#define ACL "ACL.txt"
#define PARITY_SIZE 32  // Nombre d'octets de parité
#define BLOCK_SIZE 223  // Taille des données utiles dans un bloc
#define ENCODED_SIZE 255 // Taille totale après encodage (223 + 32)
#define MAX_FILES 100
#ifndef NAME_MAX
#define NAME_MAX 255  // Défaut si NAME_MAX n'est pas défini
#endif
#define EVENT_SIZE (sizeof(struct inotify_event))
#define BUF_LEN (1024 * (EVENT_SIZE + NAME_MAX + 1))

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

// Forward declaration of read_file function
unsigned char* read_file(const char *filename, size_t *filesize) {
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

// Fonction pour envoyer un fichier au client
void send_file(int client_socket, const char *file_path) {
    int file_fd = open(file_path, O_RDONLY);
    if (file_fd < 0) {
        perror("Erreur d'ouverture du fichier à envoyer");
        return;
    }

    char buffer[SERVER_BUFFER_SIZE];
    ssize_t bytes_read;
    while ((bytes_read = read(file_fd, buffer, sizeof(buffer))) > 0) {
        if (send(client_socket, buffer, bytes_read, 0) < 0) {
            perror("Erreur d'envoi du fichier au client");
            close(file_fd);
            return;
        }
    }

    close(file_fd);
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

// Fonction pour générer une clé AES et un IV
void generate_aes_key_iv(unsigned char *key, unsigned char *iv) {
    RAND_bytes(key, AES_KEY_SIZE);
    RAND_bytes(iv, AES_IV_SIZE);
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
int encrypt_rsa(const unsigned char *plaintext, size_t plaintext_len, unsigned char *encrypted, size_t *encrypted_len, const char *keys_path, const char *client_id) {
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
    
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pubkey, NULL);
    if (!ctx) {
        fprintf(stderr, "Erreur de création du contexte de chiffrement\n");
        EVP_PKEY_free(pubkey);
        return -1;
    }

    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        fprintf(stderr, "Erreur d'initialisation du chiffrement\n");
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pubkey);
        return -1;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
        fprintf(stderr, "Erreur de configuration du padding RSA\n");
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pubkey);
        return -1;
    }

    // Déterminer la taille nécessaire pour le buffer
    size_t outlen = 0;
    if (EVP_PKEY_encrypt(ctx, NULL, &outlen, plaintext, plaintext_len) <= 0) {
        fprintf(stderr, "Erreur lors de la détermination de la taille du contenu chiffré\n");
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pubkey);
        return -1;
    }

    if (outlen > *encrypted_len) {
        fprintf(stderr, "Erreur : buffer de sortie trop petit (%zu requis, %zu fourni)\n", outlen, *encrypted_len);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pubkey);
        return -1;
    }

    // Chiffrement réel
    if (EVP_PKEY_encrypt(ctx, encrypted, &outlen, plaintext, plaintext_len) <= 0) {
        fprintf(stderr, "Erreur lors du chiffrement du contenu\n");
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pubkey);
        return -1;
    }

    *encrypted_len = outlen;  // Mettre à jour la taille du résultat

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pubkey);
    return 1;
}

// Fonction pour signer un fichier avec EVP_DigestSign
int sign_content(const unsigned char *content, size_t content_len, 
                 unsigned char *signature, size_t *sig_len, 
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

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fprintf(stderr, "Erreur de création du contexte de signature\n");
        EVP_PKEY_free(privkey);
        return -1;
    }

    if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, privkey) <= 0) {
        fprintf(stderr, "Erreur d'initialisation de la signature\n");
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(privkey);
        return -1;
    }

    if (EVP_DigestSignUpdate(mdctx, content, content_len) <= 0) {
        fprintf(stderr, "Erreur de mise à jour de la signature\n");
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(privkey);
        return -1;
    }

    // Obtenir la taille de la signature
    if (EVP_DigestSignFinal(mdctx, NULL, sig_len) <= 0) {
        fprintf(stderr, "Erreur lors de l'obtention de la taille de la signature\n");
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(privkey);
        return -1;
    }

    // Générer la signature
    if (EVP_DigestSignFinal(mdctx, signature, sig_len) <= 0) {
        fprintf(stderr, "Erreur lors de la génération de la signature\n");
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(privkey);
        return -1;
    }

    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(privkey);
    return 0; // Succès
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

// Fonction pour créer le payload chiffré à envoyer au client
int encrypt_payload(const char *payload, size_t payload_len, char *encrypted_payload, size_t encrypted_payload_len, const char *keys_path, const char *client_id) {
    // Génération de la clé AES et IV
    unsigned char aes_key[AES_KEY_SIZE], aes_iv[AES_IV_SIZE];
    generate_aes_key_iv(aes_key, aes_iv);

    printf("Clé AES générée: ");
    for (size_t i = 0; i < sizeof(aes_key); i++) {
        printf("%02x", (unsigned char)aes_key[i]);
    }
    printf("\n");
    char encrypted_aes_key[512];
    size_t encrypted_aes_key_len = sizeof(encrypted_aes_key);
    if (encrypt_rsa(aes_key, AES_KEY_SIZE, encrypted_aes_key, &encrypted_aes_key_len, keys_path, client_id) != 1) {
        fprintf(stderr, "Erreur lors du chiffrement de la clé AES avec RSA\n");
        return -1;
    }
    printf("Clé AES chiffrée avec RSA: ");
    for (size_t i = 0; i < encrypted_aes_key_len; i++) {
        printf("%02x", (unsigned char)encrypted_aes_key[i]);
    }
    printf("\n");

    // Chiffrement du JSON original avec AES-256-CBC + Salted__
    unsigned char ciphertext[SERVER_BUFFER_SIZE];
    int enc_len = encrypt_aes((unsigned char *)payload, payload_len, ciphertext, aes_key, aes_iv);
    if (enc_len < 0) {
        fprintf(stderr, "Erreur lors du chiffrement du payload\n");
        return -1;
    }

    printf("Chiffrements fonctionnels\n");

    // Encodage en Base64 du payload et de l'IV
    char encrypted_content_base64[SERVER_BUFFER_SIZE];
    char aes_iv_base64[64];
    char encrypted_aes_key_base64[1024];
    
    EVP_EncodeBlock((unsigned char *)encrypted_content_base64, ciphertext, enc_len);
    EVP_EncodeBlock((unsigned char *)aes_iv_base64, aes_iv, AES_IV_SIZE);
    EVP_EncodeBlock((unsigned char *)encrypted_aes_key_base64, encrypted_aes_key, encrypted_aes_key_len);

    printf("Clé AES chiffrée en Base64: %s\n", encrypted_aes_key_base64);
    // Création du JSON final chiffré
    cJSON *final_payload_json = cJSON_CreateObject();
    cJSON_AddStringToObject(final_payload_json, "aes_key", encrypted_aes_key_base64);
    cJSON_AddStringToObject(final_payload_json, "aes_iv", aes_iv_base64);
    cJSON_AddStringToObject(final_payload_json, "payload",encrypted_content_base64);
    
    // Sérialisation du JSON dans le buffer passé par l'appelant
    char *json_str = cJSON_PrintUnformatted(final_payload_json);
    if (!json_str) {
        fprintf(stderr, "Erreur lors de la sérialisation du JSON\n");
        cJSON_Delete(final_payload_json);
        return -1;
    }

    if (strlen(json_str) >= encrypted_payload_len) {
        fprintf(stderr, "Erreur : buffer insuffisant pour stocker le JSON chiffré\n");
        free(json_str);
        cJSON_Delete(final_payload_json);
        return -1;
    }

    strcpy(encrypted_payload, json_str);
    free(json_str);
    cJSON_Delete(final_payload_json);
    return 1;
}

// Fonction pour gérer un client
void handle_client(int client_socket, const char *keys_path, const char *transfer_dir) {
    char buffer[SERVER_BUFFER_SIZE];
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

    unsigned char encrypted_payload[SERVER_BUFFER_SIZE];
    size_t encrypted_payload_len = base64_decode(payload_base64, encrypted_payload);
    
    unsigned char decrypted_content[SERVER_BUFFER_SIZE];
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

    cJSON *decrypted_json = cJSON_Parse(decrypted_content);
    if (!decrypted_json) {
        fprintf(stderr, "| Erreur de parsing des données\n");
        const char *response = "Données au format invalide !\n";
        send(client_socket, response, strlen(response), 0);
        close(client_socket);
        return;
    } else {
        printf("| Données JSON reçues\n");
    }

    // Vérifier le but de la requête
    cJSON *request_type = cJSON_GetObjectItem(decrypted_json, "request");
    if (!request_type || !cJSON_IsString(request_type)) {
        fprintf(stderr, "| Champ 'request' manquant ou invalide\n");
        const char *response = "Champ 'request' manquant ou invalide\n";
        send(client_socket, response, strlen(response), 0);
        cJSON_Delete(decrypted_json);
        close(client_socket);
        return;
    }

    if (strcmp(request_type->valuestring, "nonce") == 0) {
        unsigned char nonce[16];
        // Handle nonce request
        printf("| Requête de nonce\n");
        const char *client_id = cJSON_GetObjectItem(decrypted_json, "client_id")->valuestring;

        // Generate a random nonce
        if (!RAND_bytes(nonce, sizeof(nonce))) {
            fprintf(stderr, "Erreur de génération du nonce\n");
            const char *response = "Erreur de génération du nonce\n";
            send(client_socket, response, strlen(response), 0);
            close(client_socket);
            cJSON_Delete(decrypted_json);
            return;
        }

        // Encode the nonce in base64
        char nonce_base64[32];
        EVP_EncodeBlock((unsigned char *)nonce_base64, nonce, sizeof(nonce));

        // Send the nonce to the client
        cJSON *response_json = cJSON_CreateObject();
        cJSON_AddStringToObject(response_json, "nonce", nonce_base64);
        const char *response = cJSON_PrintUnformatted(response_json);
        printf("response: %s\n", response);

        char encrypted_response[SERVER_BUFFER_SIZE];
        if (encrypt_payload(response, strlen(response), encrypted_response, sizeof(encrypted_response), keys_path, client_id) == 1) {
            printf("encrypted_response: %s\n", encrypted_response);
            send(client_socket, response, strlen(response), 0);
        } else {
            fprintf(stderr, "| Erreur lors du chiffrement de la réponse\n");
            const char *response = "Erreur lors du chiffrement de la réponse\n";
            send(client_socket, response, strlen(response), 0);
        }
        cJSON_Delete(response_json);
        cJSON_Delete(decrypted_json);
        close(client_socket);
        return;
    } else if (strcmp(request_type->valuestring, "file") != 0) {
        fprintf(stderr, "| Type de requête inconnu\n");
        const char *response = "Type de requête inconnu\n";
        send(client_socket, response, strlen(response), 0);
        close(client_socket);
        return;
    }

    // Extraire les données encodées du fichier
    const char *client_nonce_base64 = cJSON_GetObjectItem(decrypted_json, "nonce")->valuestring;
    const char *signature_base64 = cJSON_GetObjectItem(decrypted_json, "signature")->valuestring;
    const char *client_id = cJSON_GetObjectItem(decrypted_json, "client_id")->valuestring;

    // Décodage de base64 des données fichier et de la signature
    unsigned char client_nonce[16];
    size_t client_nonce_len = base64_decode(client_nonce_base64, client_nonce);

    unsigned char signature[SIGNATURE_SIZE];
    size_t signature_len = base64_decode(signature_base64, signature);

    // Étape 3 : Vérifier la signature du nonce avec la clé publique
    printf("| Authentification du client %s...\n", client_id);
    int result = verify_signature(client_nonce, client_nonce_len, signature, signature_len, keys_path, client_id);
    if (result == 1) {
        printf("| Client authentifié avec succès\n");
    } else if (result == 0) {
        fprintf(stderr, "| Échec de l'authentification du client (Signature invalide)\n");
        const char *response = "Échec de l'authentification du client (Signature invalide)\n";
        send(client_socket, response, strlen(response), 0);
        cJSON_Delete(decrypted_json);
        close(client_socket);
        return;
    } else {
        fprintf(stderr, "| Erreur lors de l'authentification du client\n");
        const char *response = "Erreur lors de l'authentification du client\n";
        send(client_socket, response, strlen(response), 0);
        cJSON_Delete(decrypted_json);
        close(client_socket);
        return;
    }
    cJSON_Delete(decrypted_json);

    // Étape 4 : Envoyer les fichiers au client
    DIR *dir;
    struct dirent *entry;
    char decoded_files_dir[512];
    snprintf(decoded_files_dir, sizeof(decoded_files_dir), "decoded_files");

    if ((dir = opendir(decoded_files_dir)) == NULL) {
        perror("Erreur d'ouverture du dossier decoded_files");
        const char *response = "Erreur d'ouverture du dossier decoded_files\n";
        send(client_socket, response, strlen(response), 0);
        cJSON_Delete(decrypted_json);
        close(client_socket);
        return;
    }

    cJSON *files_json = cJSON_CreateArray();
    while ((entry = readdir(dir)) != NULL) {
        struct stat entry_stat;
        char entry_path[1024];
        snprintf(entry_path, sizeof(entry_path), "%s/%s", decoded_files_dir, entry->d_name);
        if (stat(entry_path, &entry_stat) == 0 && S_ISREG(entry_stat.st_mode)) {
            // Vérifier si le fichier correspond au pattern <ip_du_client>_file
            if (strstr(entry->d_name, client_ip) == entry->d_name && strstr(entry->d_name, "_file") != NULL) {
                char file_path[1024];
                snprintf(file_path, sizeof(file_path), "%s/%s", decoded_files_dir, entry->d_name);

                // Lire le fichier et le convertir en base64
                size_t file_size;
                unsigned char *file_content = read_file(file_path, &file_size);
                if (!file_content) {
                    fprintf(stderr, "Erreur de lecture du fichier %s\n", file_path);
                    continue;
                }

                char file_base64[SERVER_BUFFER_SIZE];
                EVP_EncodeBlock((unsigned char *)file_base64, file_content, file_size);
                free(file_content);

                // Ajouter le fichier encodé en base64 au JSON
                cJSON *file_json = cJSON_CreateObject();
                cJSON_AddStringToObject(file_json, "filename", entry->d_name);
                cJSON_AddStringToObject(file_json, "content", file_base64);
                cJSON_AddItemToArray(files_json, file_json);
            }
        }
    }
    closedir(dir);

    // Créer le payload JSON
    cJSON *payload_json = cJSON_CreateObject();
    cJSON_AddItemToObject(payload_json, "files", files_json);
    char *payload_str = cJSON_PrintUnformatted(payload_json);
    cJSON_Delete(payload_json);
    printf("Payload JSON: %s\n", payload_str);

    // Envoyer le payload chiffré au client
    send(client_socket, payload_str, strlen(payload_str), 0);

    // Étape 5 : Réponse au client
    const char *response = "Demande reçue avec succès !\n";
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

void watch_directory(const char *watch_dir) {
    int fd = inotify_init();
    if (fd < 0) {
        perror("inotify_init");
        exit(1);
    }

    int wd = inotify_add_watch(fd, watch_dir, IN_MOVED_TO);
    if (wd < 0) {
        perror("inotify_add_watch");
        exit(1);
    }

    char buffer[sizeof(struct inotify_event) + NAME_MAX + 1];

    while (1) {
        ssize_t length = read(fd, buffer, sizeof(buffer));
        if (length < 0) {
            perror("read");
            break;
        }

        struct inotify_event *event = (struct inotify_event *)buffer;
        if (event->mask & IN_MOVED_TO) {  // ✅ Correction ici
            printf("%s\n", event->name);
        }
    }

    close(fd);
}

int watch_directory_nonblocking(const char *watch_dir) {
    int fd = inotify_init1(IN_NONBLOCK);
    if (fd < 0) {
        perror("inotify_init1");
        return -1;
    }

    int wd = inotify_add_watch(fd, watch_dir, IN_MOVED_TO);  // ✅ Correction ici
    if (wd < 0) {
        perror("inotify_add_watch");
        close(fd);
        return -1;
    }

    return fd;
}

int check_new_files(int inotify_fd, char *filename, size_t max_len) {
    char buffer[BUF_LEN];
    ssize_t length = read(inotify_fd, buffer, BUF_LEN);

    if (length < 0) {
        if (errno == EAGAIN) {
            return 0;
        } else {
            perror("Erreur inotify read");
            return 0;
        }
    }

    if (length == 0) {
        printf("Aucun événement détecté.\n");
        return 0;
    }

    struct inotify_event *event;
    for (char *ptr = buffer; ptr < buffer + length; ptr += sizeof(struct inotify_event) + event->len) {
        event = (struct inotify_event *)ptr;
        if ((event->mask & IN_MOVED_TO) && event->len > 0) {
            strncpy(filename, event->name, max_len - 1);
            filename[max_len - 1] = '\0';
            return 1;
        }
    }
    return 0;
}

// Fonction pour décoder les données avec Reed-Solomon
int decode_rs(unsigned char* received, unsigned char* decoded) {
    correct_reed_solomon *rs = correct_reed_solomon_create(0x11D, 1, 1, 16);
    if (!rs) {
        fprintf(stderr, "Erreur lors de la création du décodeur Reed-Solomon\n");
        exit(EXIT_FAILURE);
    }

    unsigned char block[ENCODED_SIZE] = {0};
    ssize_t decoded_len = correct_reed_solomon_decode(rs, received, ENCODED_SIZE, block);

    if (decoded_len < 0) {
        fprintf(stderr, "Erreur de décodage. Taille décodée: %ld\n", decoded_len);
        correct_reed_solomon_destroy(rs);
        exit(EXIT_FAILURE);
    }

    memcpy(decoded, block, decoded_len);  // Copier seulement les octets valides
    decoded[decoded_len] = '\0';  // Assurer la fin de la chaîne

    correct_reed_solomon_destroy(rs);
    return 0;
}

void decode(const char *fullpath_filename, char *decoded_filepath, size_t buffer_size){
    // Décodage correcteur du fichier
    size_t file_size;
    unsigned char* encoded_data = read_file(fullpath_filename, &file_size);
    if (!encoded_data) {
        perror("Erreur de lecture du fichier encodé");
        return;
    }
    
    const char *filename = strrchr(fullpath_filename, '/');
    if (filename) {
        filename++; // Skip the '/'
    } else {
        filename = fullpath_filename; // No '/' found, use the whole string
    }
    snprintf(decoded_filepath, buffer_size + 255, "decoded_files/192.168.57.2_decoded_%s", filename);
    
    FILE *decoded_file = fopen(decoded_filepath, "wb");
    if (!decoded_file) {
        perror("Erreur ouverture fichier décodé");
        return;
    }

    size_t num_block_decode = file_size / ENCODED_SIZE;

    for (int i = 0; i < num_block_decode; i++) {
        unsigned char decoded_block_data[BLOCK_SIZE + 1] = {0}; 
        unsigned char block_data[ENCODED_SIZE] = {0};
        memcpy(block_data, encoded_data + i * ENCODED_SIZE, ENCODED_SIZE);

        decode_rs(block_data, decoded_block_data);

        unsigned char block_data_decode[BLOCK_SIZE] = {0};
        memcpy(block_data_decode, decoded_block_data, BLOCK_SIZE);

        // Déterminer la taille valide des données (jusqu'au premier '\x00')
        size_t valid_size = 0;
        for (size_t j = 0; j < BLOCK_SIZE; j++) {
            if (block_data_decode[j] == '\x00') {
                break;
            }
            valid_size++;
        }

        // Écrire les données valides dans le fichier
        fwrite(block_data_decode, valid_size, 1, decoded_file);

        // Vérifier si la taille valide est différente de 223
        if (valid_size != 223) {
            printf("Bloc %d : taille valide différente de 223 (%zu). Arrêt.\n", i, valid_size);
            fclose(decoded_file);
            free(encoded_data);
            printf("Fichier décodé : %s\n", decoded_filepath);
            return; // Arrêter la fonction immédiatement
        }
    }


    fclose(decoded_file);
    free(encoded_data);
    printf("Fichier décodé : %s\n", decoded_filepath);
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

    // Créer le dossier Temp avec les permissions 700
    if (mkdir("Temp", S_IRWXU) != 0 && errno != EEXIST) {
        perror("Erreur lors de la création du dossier Temp");
        return EXIT_FAILURE;
    }

    // Créer le dossier decoded_files avec les permissions 700
    if (mkdir("decoded_files", S_IRWXU) != 0 && errno != EEXIST) {
        perror("Erreur lors de la création du dossier Temp");
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

    int inotify_fd = watch_directory_nonblocking(config.transfer_dir);
    if (inotify_fd < 0) {
        return EXIT_FAILURE;
    }

    while (1) {
        char new_filename[NAME_MAX + 1] = {0};

        // Initialiser fd_set pour select
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(inotify_fd, &readfds);
        FD_SET(server_socket, &readfds);

        // Attente de l'événement (inotify ou connexion client)
        struct timeval timeout = {0, 100000};  // Timeout de 100 ms (réglable)
        int ready_fds = select(FD_SETSIZE, &readfds, NULL, NULL, &timeout);

        if (ready_fds < 0) {
            perror("Erreur select");
            return EXIT_FAILURE;
        }

        // Vérifier si un événement inotify est prêt
        if (FD_ISSET(inotify_fd, &readfds)) {
            if (check_new_files(inotify_fd, new_filename, sizeof(new_filename))) {
                printf("Nouveau fichier créé : %s\n", new_filename);
                // Path complet du fichier
                char full_path[512];
                snprintf(full_path, sizeof(full_path), "%s/%s", config.transfer_dir, new_filename);
                char decoded_filepath[512];
                decode(full_path, decoded_filepath, sizeof(decoded_filepath));
            }
        }

        // Vérifier si une connexion client est prête
        if (FD_ISSET(server_socket, &readfds)) {
            int client_socket = accept(server_socket, NULL, NULL);
            if (client_socket >= 0) {
                handle_client(client_socket, config.keys_path, config.transfer_dir);
            }
        }
    }

    close(server_socket);
    return 0;
}
