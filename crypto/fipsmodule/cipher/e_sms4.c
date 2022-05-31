/* ====================================================================
 * Copyright (c) 2001-2011 The OpenSSL Project.  All rights reserved.
 * Copyright (c) 2020-2021 mogoweb@gmail.com.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ==================================================================== */

#include <assert.h>
#include <string.h>

#include <openssl/aead.h>
#include <openssl/cipher.h>
#include <openssl/cpu.h>
#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/nid.h>
#include <openssl/rand.h>
#include <openssl/sms4.h>

#include "internal.h"
#include "../../internal.h"
#include "../modes/internal.h"
#include "../delocate.h"

#ifndef OPENSSL_NO_SMS4

# ifdef SMS4_AVX2
void sms4_avx2_ecb_encrypt_blocks(const unsigned char *in,
  unsigned char *out, size_t blocks, const SMS4_KEY *key);
void sms4_avx2_ctr32_encrypt_blocks(const unsigned char *in,
  unsigned char *out, size_t blocks, const SMS4_KEY *key,
  const unsigned char iv[16]);
# endif

typedef struct {
  sms4_block128_f block;
  union {
    sms4_cbc128_f cbc;
    ctr128_f ctr;
  } stream;
  union {
    double align;
    SMS4_KEY ks;
  } ks;
} EVP_SMS4_KEY;

static int sms4_init_key(EVP_CIPHER_CTX *ctx, const uint8_t *key,
                        const uint8_t *iv, int enc) {
  int mode;
  EVP_SMS4_KEY *dat = (EVP_SMS4_KEY *)ctx->cipher_data;

  mode = ctx->cipher->flags & EVP_CIPH_MODE_MASK;
  if ((mode == EVP_CIPH_ECB_MODE || mode == EVP_CIPH_CBC_MODE) && !enc) {
    sms4_set_decrypt_key(&dat->ks.ks, key);
    dat->block = sms4_encrypt;
    dat->stream.cbc = NULL;
    if (mode == EVP_CIPH_CBC_MODE) {
      dat->stream.cbc = sms4_cbc_encrypt;
    }
  } else {
    sms4_set_encrypt_key(&dat->ks.ks, key);
    dat->block = sms4_encrypt;
    dat->stream.cbc = NULL;
    if (mode == EVP_CIPH_CBC_MODE) {
      dat->stream.cbc = sms4_cbc_encrypt;
    }
  }

  return 1;
}

static int sms4_cbc_cipher(EVP_CIPHER_CTX *ctx, uint8_t *out, const uint8_t *in,
                           size_t len)
{
  EVP_SMS4_KEY *dat = (EVP_SMS4_KEY *)ctx->cipher_data;

  if (dat->stream.cbc) {
    (*dat->stream.cbc)(in, out, len, &dat->ks.ks, ctx->iv, ctx->encrypt);
  } else if (ctx->encrypt) {
    CRYPTO_sms4_cbc128_encrypt(in, out, len, &dat->ks.ks, ctx->iv, dat->block);
  } else {
    CRYPTO_sms4_cbc128_decrypt(in, out, len, &dat->ks.ks, ctx->iv, dat->block);
  }

  return 1;
}

DEFINE_METHOD_FUNCTION(EVP_CIPHER, EVP_sms4_cbc) {
  memset(out, 0, sizeof(EVP_CIPHER));

  out->nid = NID_sms4_cbc;
  out->block_size = SMS4_BLOCK_SIZE;
  out->key_len = SMS4_KEY_LENGTH;
  out->iv_len = SMS4_IV_LENGTH;
  out->ctx_size = sizeof(EVP_SMS4_KEY);
  out->flags = EVP_CIPH_CBC_MODE;
  out->init = sms4_init_key;
  out->cipher = sms4_cbc_cipher;
}

#endif /* OPENSSL_NO_SMS4 */