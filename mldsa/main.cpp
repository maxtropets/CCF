#include <chrono>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/ml_kem.h>
#include <string>
#include <vector>

void do_sign(EVP_PKEY *pkey, const char *alg, unsigned char *msg,
             size_t msg_len) {

#pragma clang optimize off
  size_t sig_len;
  unsigned char *sig = NULL;
  const OSSL_PARAM params[] = {
      OSSL_PARAM_octet_string("context-string",
                              (unsigned char *)"A context string", 16),
      OSSL_PARAM_END};
  EVP_PKEY_CTX *sctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
  EVP_SIGNATURE *sig_alg = EVP_SIGNATURE_fetch(NULL, alg, NULL);

  if (EVP_PKEY_sign_message_init(sctx, sig_alg, params) != 1) {
    std::cout << "Aaa, bad init sign" << std::endl;
  }

  /* Calculate the required size for the signature by passing a NULL buffer. */
  if (EVP_PKEY_sign(sctx, NULL, &sig_len, msg, msg_len) != 1) {
    std::cout << "Aaa, bad sign get size" << std::endl;
  }

  // Actually sign
  sig = (unsigned char *)OPENSSL_zalloc(sig_len);
  if (EVP_PKEY_sign(sctx, sig, &sig_len, msg, msg_len) != 1) {
    std::cout << "Aaa, bad sign" << std::endl;
  }

  if (EVP_PKEY_verify_message_init(sctx, sig_alg, params) != 1) {
    std::cout << "Aaa, bad init verify" << std::endl;
  }

  if (EVP_PKEY_verify(sctx, sig, sig_len, msg, msg_len) != 1) {
    std::cout << "Aaa, bad verify" << std::endl;
  }

  OPENSSL_free(sig);
  EVP_SIGNATURE_free(sig_alg);
  EVP_PKEY_CTX_free(sctx);

#pragma clang optimize on
}

void test(const char *alg, int iters, int msg_len) {
  EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, alg);
  std::vector<std::string> msgs(iters);
  for (int i = 0; i < iters; i++) {
    for (int j = 0; j < msg_len; j++) {
      msgs[i].push_back(rand() % 9 - '0');
    }
  }

  auto before = std::chrono::high_resolution_clock::now();
  for (auto i = 0; i < iters; i++) {
    do_sign(pkey, alg, (unsigned char *)msgs[i].data(), msgs[i].size());
  }
  auto after = std::chrono::high_resolution_clock::now();

  const auto exec_time =
      std::chrono::duration_cast<std::chrono::milliseconds>(after - before);

  std::cout << "Samples: " << iters << " alg " << alg
            << ", msg len: " << msg_len
            << ", avg sign+verify ms: " << 1.0 * exec_time.count() / iters
            << std::endl;
  EVP_PKEY_free(pkey);
}

int main() {
  test("ML-DSA-87", 1000, 100);
  test("ML-DSA-87", 1000, 1000);
  test("ML-DSA-87", 1000, 10000);
  test("ML-DSA-65", 1000, 100);
  test("ML-DSA-65", 1000, 1000);
  test("ML-DSA-65", 1000, 10000);
  test("ML-DSA-44", 1000, 100);
  test("ML-DSA-44", 1000, 1000);
  test("ML-DSA-44", 1000, 10000);
}
