// object.c — Content-addressable object store
//
// Every piece of data (file contents, directory listings, commits) is stored
// as an "object" named by its SHA-256 hash. Objects are stored under
// .pes/objects/XX/YYYYYY... where XX is the first two hex characters of the
// hash (directory sharding).
//
// PROVIDED functions: compute_hash, object_path, object_exists, hash_to_hex, hex_to_hash
// TODO functions:     object_write, object_read

#include "pes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/evp.h>

// ─── PROVIDED ────────────────────────────────────────────────────────────────

void hash_to_hex(const ObjectID *id, char *hex_out) {
    for (int i = 0; i < HASH_SIZE; i++) {
        sprintf(hex_out + i * 2, "%02x", id->hash[i]);
    }
    hex_out[HASH_HEX_SIZE] = '\0';
}

int hex_to_hash(const char *hex, ObjectID *id_out) {
    if (strlen(hex) < HASH_HEX_SIZE) return -1;
    for (int i = 0; i < HASH_SIZE; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return -1;
        id_out->hash[i] = (uint8_t)byte;
    }
    return 0;
}

void compute_hash(const void *data, size_t len, ObjectID *id_out) {
    unsigned int hash_len;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, id_out->hash, &hash_len);
    EVP_MD_CTX_free(ctx);
}

// Get the filesystem path where an object should be stored.
// Format: .pes/objects/XX/YYYYYYYY...
// The first 2 hex chars form the shard directory; the rest is the filename.
void object_path(const ObjectID *id, char *path_out, size_t path_size) {
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id, hex);
    snprintf(path_out, path_size, "%s/%.2s/%s", OBJECTS_DIR, hex, hex + 2);
}

int object_exists(const ObjectID *id) {
    char path[512];
    object_path(id, path, sizeof(path));
    return access(path, F_OK) == 0;
}

// ─── TODO: Implement these ──────────────────────────────────────────────────

// Write an object to the store.
//
// Object format on disk:
//   "<type> <size>\0<data>"
//   where <type> is "blob", "tree", or "commit"
//   and <size> is the decimal string of the data length
//
// Steps:
//   1. Build the full object: header ("blob 16\0") + data
//   2. Compute SHA-256 hash of the FULL object (header + data)
//   3. Check if object already exists (deduplication) — if so, just return success
//   4. Create shard directory (.pes/objects/XX/) if it doesn't exist
//   5. Write to a temporary file in the same shard directory
//   6. fsync() the temporary file to ensure data reaches disk
//   7. rename() the temp file to the final path (atomic on POSIX)
//   8. Open and fsync() the shard directory to persist the rename
//   9. Store the computed hash in *id_out

// HINTS - Useful syscalls and functions for this phase:
//   - sprintf / snprintf : formatting the header string
//   - compute_hash       : hashing the combined header + data
//   - object_exists      : checking for deduplication
//   - mkdir              : creating the shard directory (use mode 0755)
//   - open, write, close : creating and writing to the temp file
//                          (Use O_CREAT | O_WRONLY | O_TRUNC, mode 0644)
//   - fsync              : flushing the file descriptor to disk
//   - rename             : atomically moving the temp file to the final path
//

//
// Returns 0 on success, -1 on error.
const char* type_to_string(ObjectType type) {
    switch (type) {
        case OBJ_BLOB:   return "blob";
        case OBJ_TREE:   return "tree";
        case OBJ_COMMIT: return "commit";
        default:         return "unknown";
    }
}

//
// Returns 0 on success, -1 on error.
int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out) {
    // 1. Build the header
    const char *type_str;
    switch (type) {
        case OBJ_BLOB:   type_str = "blob";   break;
        case OBJ_TREE:   type_str = "tree";   break;
        case OBJ_COMMIT: type_str = "commit"; break;
        default: return -1;
    }

    char header[64];
    int header_len = sprintf(header, "%s %zu", type_str, len);
    
    // 2. Build the full object (header + null byte + data)
    size_t full_size = header_len + 1 + len;
    uint8_t *full_buf = malloc(full_size);
    if (!full_buf) return -1;

    memcpy(full_buf, header, header_len + 1);
    memcpy(full_buf + header_len + 1, data, len);

    // 3. Compute hash and check for deduplication
    compute_hash(full_buf, full_size, id_out);
    if (object_exists(id_out)) {
        free(full_buf);
        return 0;
    }

    // 4. Get final path and ensure shard directory exists
    char final_path[512];
    object_path(id_out, final_path, sizeof(final_path));
    
    char path_copy[512];
    strncpy(path_copy, final_path, sizeof(path_copy));
    char *dir_name = dirname(path_copy);
    mkdir(dir_name, 0755);

    // 5. Write to a temporary file
    char temp_path[512];
    snprintf(temp_path, sizeof(temp_path), "%s/tmp_XXXXXX", dir_name);
    int fd = mkstemp(temp_path);
    if (fd < 0) {
        free(full_buf);
        return -1;
    }

    if (write(fd, full_buf, full_size) != (ssize_t)full_size) {
        close(fd);
        unlink(temp_path);
        free(full_buf);
        return -1;
    }

    // 6. Persist to disk
    fsync(fd);
    close(fd);

    // 7. Atomic move
    if (rename(temp_path, final_path) != 0) {
        unlink(temp_path);
        free(full_buf);
        return -1;
    }

    // 8. Sync directory
    int dfd = open(dir_name, O_RDONLY);
    if (dfd >= 0) {
        fsync(dfd);
        close(dfd);
    }

    free(full_buf);
    return 0;
}

// Read an object from the store.
//
// Steps:
//   1. Build the file path from the hash using object_path()
//   2. Open and read the entire file
//   3. Parse the header to extract the type string and size
//   4. Verify integrity: recompute the SHA-256 of the file contents
//      and compare to the expected hash (from *id). Return -1 if mismatch.
//   5. Set *type_out to the parsed ObjectType
//   6. Allocate a buffer, copy the data portion (after the \0), set *data_out and *len_out
//
// HINTS - Useful syscalls and functions for this phase:
//   - object_path        : getting the target file path
//   - fopen, fread, fseek: reading the file into memory
//   - memchr             : safely finding the '\0' separating header and data
//   - strncmp            : parsing the type string ("blob", "tree", "commit")
//   - compute_hash       : re-hashing the read data for integrity verification
//   - memcmp             : comparing the computed hash against the requested hash
//   - malloc, memcpy     : allocating and returning the extracted data
//
// The caller is responsible for calling free(*data_out).
// Returns 0 on success, -1 on error (file not found, corrupt, etc.).
int object_read(const ObjectID *id, ObjectType *type_out, void **data_out, size_t *len_out) {
    // 1. Get path and open file
    char path[512];
    object_path(id, path, sizeof(path));
    
    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    // 2. Get file size and read into local buffer
    fseek(f, 0, SEEK_END);
    size_t file_size = ftell(f);
    rewind(f);

    uint8_t *full_buf = malloc(file_size);
    if (fread(full_buf, 1, file_size, f) != file_size) {
        fclose(f);
        free(full_buf);
        return -1;
    }
    fclose(f);

    // 3. Verify integrity
    ObjectID actual_id;
    compute_hash(full_buf, file_size, &actual_id);
    if (memcmp(id->hash, actual_id.hash, HASH_SIZE) != 0) {
        free(full_buf);
        return -1; // Corrupt file
    }

    // 4. Parse header
    char *header = (char *)full_buf;
    char *null_byte = memchr(full_buf, '\0', file_size);
    if (!null_byte) {
        free(full_buf);
        return -1;
    }

    // Identify type
    if (strncmp(header, "blob", 4) == 0) *type_out = OBJ_BLOB;
    else if (strncmp(header, "tree", 4) == 0) *type_out = OBJ_TREE;
    else if (strncmp(header, "commit", 6) == 0) *type_out = OBJ_COMMIT;
    else {
        free(full_buf);
        return -1;
    }

    // Extract size
    char *space = strchr(header, ' ');
    if (!space) {
        free(full_buf);
        return -1;
    }
    *len_out = strtoull(space + 1, NULL, 10);

    // 5. Copy data to return to caller
    *data_out = malloc(*len_out);
    memcpy(*data_out, null_byte + 1, *len_out);

    free(full_buf);
    return 0;
}

