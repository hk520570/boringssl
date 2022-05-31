/* ====================================================================
 * Copyright (c) 2014 - 2017 The GmSSL Project.  All rights reserved.
 * Copyright (c) 2020 - 2021 mogoweb@gmail.com.  All rights reserved.
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
 *    "This product includes software developed by the GmSSL Project.
 *    (http://gmssl.org/)"
 *
 * 4. The name "GmSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    guanzhi1980@gmail.com.
 *
 * 5. Products derived from this software may not be called "GmSSL"
 *    nor may "GmSSL" appear in their names without prior written
 *    permission of the GmSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the GmSSL Project
 *    (http://gmssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE GmSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE GmSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */

#include <openssl/sms4.h>
#include "../../fipsmodule/modes/internal.h"

#ifndef OPENSSL_NO_SMS4

void CRYPTO_sms4_cbc128_encrypt(const uint8_t *in, uint8_t *out, size_t len,
                                const SMS4_KEY *key, uint8_t ivec[16],
                                sms4_block128_f block) {
  size_t n;
  const uint8_t *iv = ivec;

  assert(key != NULL && ivec != NULL);
  assert(len == 0 || (in != NULL && out != NULL));

  while (len >= 16) {
    for (n = 0; n < 16; n += sizeof(size_t)) {
      store_word_le(out + n, load_word_le(in + n) ^ load_word_le(iv + n));
    }
    (*block)(out, out, key);
    iv = out;
    len -= 16;
    in += 16;
    out += 16;
  }

  while (len) {
    for (n = 0; n < 16 && n < len; ++n) {
      out[n] = in[n] ^ iv[n];
    }
    for (; n < 16; ++n) {
      out[n] = iv[n];
    }
    (*block)(out, out, key);
    iv = out;
    if (len <= 16) {
      break;
    }
    len -= 16;
    in += 16;
    out += 16;
  }

  OPENSSL_memcpy(ivec, iv, 16);
}

void CRYPTO_sms4_cbc128_decrypt(const uint8_t *in, uint8_t *out, size_t len,
                                const SMS4_KEY *key, uint8_t ivec[16],
                                sms4_block128_f block) {
  size_t n;
  union {
    size_t t[16 / sizeof(size_t)];
    uint8_t c[16];
  } tmp;

  assert(key != NULL && ivec != NULL);
  assert(len == 0 || (in != NULL && out != NULL));

  const uintptr_t inptr = (uintptr_t) in;
  const uintptr_t outptr = (uintptr_t) out;
  // If |in| and |out| alias, |in| must be ahead.
  assert(inptr >= outptr || inptr + len <= outptr);

  if ((inptr >= 32 && outptr <= inptr - 32) || inptr < outptr) {
    // If |out| is at least two blocks behind |in| or completely disjoint, there
    // is no need to decrypt to a temporary block.
    OPENSSL_STATIC_ASSERT(16 % sizeof(size_t) == 0,
                          "block cannot be evenly divided into words");
    const uint8_t *iv = ivec;
    while (len >= 16) {
      (*block)(in, out, key);
      for (n = 0; n < 16; n += sizeof(size_t)) {
        store_word_le(out + n, load_word_le(out + n) ^ load_word_le(iv + n));
      }
      iv = in;
      len -= 16;
      in += 16;
      out += 16;
    }
    OPENSSL_memcpy(ivec, iv, 16);
  } else {
    OPENSSL_STATIC_ASSERT(16 % sizeof(size_t) == 0,
                          "block cannot be evenly divided into words");

    while (len >= 16) {
      (*block)(in, tmp.c, key);
      for (n = 0; n < 16; n += sizeof(size_t)) {
        size_t c = load_word_le(in + n);
        store_word_le(out + n,
                      tmp.t[n / sizeof(size_t)] ^ load_word_le(ivec + n));
        store_word_le(ivec + n, c);
      }
      len -= 16;
      in += 16;
      out += 16;
    }
  }

  while (len) {
    uint8_t c;
    (*block)(in, tmp.c, key);
    for (n = 0; n < 16 && n < len; ++n) {
      c = in[n];
      out[n] = tmp.c[n] ^ ivec[n];
      ivec[n] = c;
    }
    if (len <= 16) {
      for (; n < 16; ++n) {
        ivec[n] = in[n];
      }
      break;
    }
    len -= 16;
    in += 16;
    out += 16;
  }
}

void sms4_cbc_encrypt(const unsigned char *in, unsigned char *out,
                      size_t len, const SMS4_KEY *key, unsigned char *iv, int enc)
{
  if (enc)
    CRYPTO_sms4_cbc128_encrypt(in, out, len, key, iv, (sms4_block128_f)sms4_encrypt);
  else
    CRYPTO_sms4_cbc128_decrypt(in, out, len, key, iv, (sms4_block128_f)sms4_encrypt);
}

#endif  /* OPENSSL_NO_SMS4 */
