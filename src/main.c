#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define PROTOCOL_ITERS 20

struct zefm_query{
  unsigned long long nonce;
  unsigned char * hash;
  unsigned long hash_size;
};

typedef struct zefm_query ZefmQuery;

EVP_MD_CTX * init_actor(char *filename, EVP_MD * algorithm);
ZefmQuery generate_query(EVP_MD_CTX * verifier, unsigned long long nonce);
unsigned char solve_query(EVP_MD_CTX * proofer, ZefmQuery query);
int hash_nonce(
  EVP_MD_CTX * ctx,
  unsigned long long nonce,
  unsigned char ** hash_out,
  unsigned long * hash_size_out
);
unsigned char * read_file(char * filename, unsigned long * out_size);
unsigned long long get_nonce();


int main(int argc, char *argv[])
{
  EVP_MD_CTX *proofer = NULL, *verifier = NULL;
  unsigned long long nonce = 0;
  ZefmQuery query;
  unsigned int query_answer = 0;
  unsigned int i;

  // Ensure arguments were provided
  if (argc < 3) {
    fprintf(stderr, "You must provide two document names as arguments\n");
    exit(-1);
  }

  // Init proofer 
  proofer = init_actor(argv[1], (EVP_MD *)EVP_sha256());
  if(proofer == NULL) {
    perror("Couldn't init proofer");
    exit(-1);
  }

  // Init verifier
  verifier = init_actor(argv[2], (EVP_MD *)EVP_sha256());
  if(verifier == NULL) {
    perror("Couldn't init verifier");
    exit(-1);
  }

  // Set seed
  srand(time(NULL));

  // Engage Protocol
  for (i = 0; i < PROTOCOL_ITERS; i++) {

    // Generate verifier query
    nonce = get_nonce();
    query = generate_query(verifier, get_nonce());
    if (query.hash == NULL) {
      perror("Error while generating query");
      exit(-1);
    }

    // Decide to send true query or false query
    query_answer = rand() % 2;
    if (query_answer == 0) query.nonce = get_nonce(); // TODO: A change to have the same nonce, must solve later
    
    // Solve query and exit on failure
    if (query_answer != solve_query(proofer, query)) break;

    // Free query hash memory
    if (query.hash != NULL) free(query.hash);
  }

  // Respond according to result
  if (i < PROTOCOL_ITERS){
    printf("file matching protocol unsuccessful: %d iterations\n", i);
  } else {
    printf("file matching protocol successful\n");
  }


  if (proofer != NULL) EVP_MD_CTX_free(proofer);
  if (verifier != NULL) EVP_MD_CTX_free(verifier);
  return 0;
}

EVP_MD_CTX * init_actor_err(unsigned char * message, EVP_MD_CTX * ctx) {
  if (message != NULL) free(message);
  if (ctx != NULL) EVP_MD_CTX_free(ctx);
  return NULL;
}

EVP_MD_CTX * init_actor(char * filename, EVP_MD * algorithm) {
  unsigned char * message = NULL;
  unsigned long message_size = 0;

  EVP_MD_CTX * ctx = NULL;

  // Read file into message buffer
  message = read_file(filename, &message_size);
  if (message == NULL) {
    perror("Couldn't place file into message buffer");
    return init_actor_err(message, ctx);
  }

  // Initialize Message Digest Context
  ctx = EVP_MD_CTX_new();
  if (ctx == NULL) {
    perror("Couldn't initialize context");
    return init_actor_err(message, ctx);
  }

  // Initialize Message Digest Context
  if(!EVP_DigestInit_ex(ctx, algorithm, NULL)) {
    perror("Couldn't initialize context");
    return init_actor_err(message, ctx);
  }

  // Update with message buffer
  if(!EVP_DigestUpdate(ctx, message, message_size)) {
    perror("Couldn't update context with file buffer");
    return init_actor_err(message, ctx);
  }

  free(message);
  return ctx;
}



ZefmQuery generate_query(EVP_MD_CTX * verifier, unsigned long long nonce){
  ZefmQuery result;
  result.nonce = nonce;
  result.hash = NULL;
  result.hash_size = 0;

  if(hash_nonce(
      verifier,
      result.nonce,
      &result.hash,
      &result.hash_size
    )
  ) {
    perror("Couldn't generate hash with nonce");
  }

  return result;
};

unsigned char solve_query(EVP_MD_CTX * proofer, ZefmQuery query) {
  unsigned char * hash = NULL;
  unsigned long hash_size;

  if(hash_nonce(
      proofer,
      query.nonce,
      &hash,
      &hash_size
    )
  ) {
    perror("Couldn't generate hash with nonce during solve");
  }

  const unsigned char res = hash_size == query.hash_size && memcmp(hash, query.hash, hash_size) == 0;
  
  if (hash != NULL) free(hash);
  return res; // TODO: better return type in case of error
}

int hash_nonce_err(EVP_MD_CTX * ctx_copy, unsigned char * outdigest){
  if (ctx_copy != NULL) EVP_MD_CTX_free(ctx_copy);
  if (outdigest != NULL) OPENSSL_free(outdigest);
  return 1;
}
int hash_nonce(
  EVP_MD_CTX * ctx,
  unsigned long long nonce,
  unsigned char ** res,
  unsigned long * hash_size
) {
  EVP_MD_CTX * ctx_copy = NULL;
  unsigned int len = 0;
  unsigned char *outdigest = NULL;


  // Copy participant digest context
  ctx_copy = EVP_MD_CTX_new();
  if (ctx_copy == NULL) {
    perror("Couldn't initialize digest context copy");
    return hash_nonce_err(ctx_copy, outdigest);
  }

  if(!EVP_MD_CTX_copy(ctx_copy, ctx)) {
    perror("Couldn't copy participant digest context");
    return hash_nonce_err(ctx_copy, outdigest);
  }

  // Update copy digest context with hash
  if(!EVP_DigestUpdate(ctx_copy, &nonce, sizeof(unsigned long long))){
    perror("Couldn't update digest context with nonce");
    return hash_nonce_err(ctx_copy, outdigest);
  }

  // Allocate output buffer
  outdigest = OPENSSL_malloc(EVP_MAX_MD_SIZE);
  if(outdigest == NULL){
    perror("Couldn't allocate memory for digest output buffer");
    return hash_nonce_err(ctx_copy, outdigest);
  }

  // Calculate digest
  if(!EVP_DigestFinal_ex(ctx_copy, outdigest, &len)) {
    perror("Couldn't calculate digest for context copy");
    return hash_nonce_err(ctx_copy, outdigest);
  }

  *res = (unsigned char*)malloc(len);
  if (*res == NULL) {
    perror("couldn't allocate enough memory for result");
    return hash_nonce_err(ctx_copy, outdigest);
  }

  memcpy(*res, outdigest, len);
  *hash_size = len;

  EVP_MD_CTX_free(ctx_copy);
  OPENSSL_free(outdigest);

  return 0;
}

unsigned char * read_file_err(FILE * file, unsigned char * buffer) {
  if (file != NULL) fclose(file);
  if (buffer != NULL) free(buffer);
  return NULL;
}

unsigned char * read_file(char *fn, unsigned long * out_size) {
  // Open the file for reading
  FILE* file = NULL;
  file = fopen(fn, "rb");
  unsigned char* buffer = NULL;
  if (file == NULL) {
    perror("Failed to open file");
    return read_file_err(file, buffer);
  }

  // Determine the size of the file
  fseek(file, 0, SEEK_END);
  long size = ftell(file);
  fseek(file, 0, SEEK_SET);

  // Allocate a buffer to hold the file contents
  buffer = malloc(size);
  if (buffer == NULL) {
    perror("Failed to allocate memory for file buffer");
    return read_file_err(file, buffer);
  }

  // Read the file into the buffer
  fread(buffer, 1, size, file);

  // Close the file
  fclose(file);

  *out_size = size;
  return buffer;
}

unsigned long long get_nonce() {
  return ((unsigned long long)rand() << 32) | rand();
}
