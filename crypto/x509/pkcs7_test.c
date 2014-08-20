/* Copyright (c) 2014, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#include <stdio.h>
#include <stdlib.h>

#include <openssl/bytestring.h>
#include <openssl/stack.h>
#include <openssl/x509.h>


/* kPKCS7DER contains the certificate chain of mail.google.com, as saved by NSS
 * using the Chrome UI. */
static const uint8_t kPKCS7DER[] = {
    0x30, 0x80, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07,
    0x02, 0xa0, 0x80, 0x30, 0x80, 0x02, 0x01, 0x01, 0x31, 0x00, 0x30, 0x80,
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01, 0x00,
    0x00, 0xa0, 0x82, 0x0b, 0x1e, 0x30, 0x82, 0x03, 0x54, 0x30, 0x82, 0x02,
    0x3c, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x03, 0x02, 0x34, 0x56, 0x30,
    0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05,
    0x05, 0x00, 0x30, 0x42, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04,
    0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x16, 0x30, 0x14, 0x06, 0x03, 0x55,
    0x04, 0x0a, 0x13, 0x0d, 0x47, 0x65, 0x6f, 0x54, 0x72, 0x75, 0x73, 0x74,
    0x20, 0x49, 0x6e, 0x63, 0x2e, 0x31, 0x1b, 0x30, 0x19, 0x06, 0x03, 0x55,
    0x04, 0x03, 0x13, 0x12, 0x47, 0x65, 0x6f, 0x54, 0x72, 0x75, 0x73, 0x74,
    0x20, 0x47, 0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x20, 0x43, 0x41, 0x30, 0x1e,
    0x17, 0x0d, 0x30, 0x32, 0x30, 0x35, 0x32, 0x31, 0x30, 0x34, 0x30, 0x30,
    0x30, 0x30, 0x5a, 0x17, 0x0d, 0x32, 0x32, 0x30, 0x35, 0x32, 0x31, 0x30,
    0x34, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x30, 0x42, 0x31, 0x0b, 0x30, 0x09,
    0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x16, 0x30,
    0x14, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x0d, 0x47, 0x65, 0x6f, 0x54,
    0x72, 0x75, 0x73, 0x74, 0x20, 0x49, 0x6e, 0x63, 0x2e, 0x31, 0x1b, 0x30,
    0x19, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x12, 0x47, 0x65, 0x6f, 0x54,
    0x72, 0x75, 0x73, 0x74, 0x20, 0x47, 0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x20,
    0x43, 0x41, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86,
    0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01,
    0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xda,
    0xcc, 0x18, 0x63, 0x30, 0xfd, 0xf4, 0x17, 0x23, 0x1a, 0x56, 0x7e, 0x5b,
    0xdf, 0x3c, 0x6c, 0x38, 0xe4, 0x71, 0xb7, 0x78, 0x91, 0xd4, 0xbc, 0xa1,
    0xd8, 0x4c, 0xf8, 0xa8, 0x43, 0xb6, 0x03, 0xe9, 0x4d, 0x21, 0x07, 0x08,
    0x88, 0xda, 0x58, 0x2f, 0x66, 0x39, 0x29, 0xbd, 0x05, 0x78, 0x8b, 0x9d,
    0x38, 0xe8, 0x05, 0xb7, 0x6a, 0x7e, 0x71, 0xa4, 0xe6, 0xc4, 0x60, 0xa6,
    0xb0, 0xef, 0x80, 0xe4, 0x89, 0x28, 0x0f, 0x9e, 0x25, 0xd6, 0xed, 0x83,
    0xf3, 0xad, 0xa6, 0x91, 0xc7, 0x98, 0xc9, 0x42, 0x18, 0x35, 0x14, 0x9d,
    0xad, 0x98, 0x46, 0x92, 0x2e, 0x4f, 0xca, 0xf1, 0x87, 0x43, 0xc1, 0x16,
    0x95, 0x57, 0x2d, 0x50, 0xef, 0x89, 0x2d, 0x80, 0x7a, 0x57, 0xad, 0xf2,
    0xee, 0x5f, 0x6b, 0xd2, 0x00, 0x8d, 0xb9, 0x14, 0xf8, 0x14, 0x15, 0x35,
    0xd9, 0xc0, 0x46, 0xa3, 0x7b, 0x72, 0xc8, 0x91, 0xbf, 0xc9, 0x55, 0x2b,
    0xcd, 0xd0, 0x97, 0x3e, 0x9c, 0x26, 0x64, 0xcc, 0xdf, 0xce, 0x83, 0x19,
    0x71, 0xca, 0x4e, 0xe6, 0xd4, 0xd5, 0x7b, 0xa9, 0x19, 0xcd, 0x55, 0xde,
    0xc8, 0xec, 0xd2, 0x5e, 0x38, 0x53, 0xe5, 0x5c, 0x4f, 0x8c, 0x2d, 0xfe,
    0x50, 0x23, 0x36, 0xfc, 0x66, 0xe6, 0xcb, 0x8e, 0xa4, 0x39, 0x19, 0x00,
    0xb7, 0x95, 0x02, 0x39, 0x91, 0x0b, 0x0e, 0xfe, 0x38, 0x2e, 0xd1, 0x1d,
    0x05, 0x9a, 0xf6, 0x4d, 0x3e, 0x6f, 0x0f, 0x07, 0x1d, 0xaf, 0x2c, 0x1e,
    0x8f, 0x60, 0x39, 0xe2, 0xfa, 0x36, 0x53, 0x13, 0x39, 0xd4, 0x5e, 0x26,
    0x2b, 0xdb, 0x3d, 0xa8, 0x14, 0xbd, 0x32, 0xeb, 0x18, 0x03, 0x28, 0x52,
    0x04, 0x71, 0xe5, 0xab, 0x33, 0x3d, 0xe1, 0x38, 0xbb, 0x07, 0x36, 0x84,
    0x62, 0x9c, 0x79, 0xea, 0x16, 0x30, 0xf4, 0x5f, 0xc0, 0x2b, 0xe8, 0x71,
    0x6b, 0xe4, 0xf9, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x53, 0x30, 0x51,
    0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05,
    0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e,
    0x04, 0x16, 0x04, 0x14, 0xc0, 0x7a, 0x98, 0x68, 0x8d, 0x89, 0xfb, 0xab,
    0x05, 0x64, 0x0c, 0x11, 0x7d, 0xaa, 0x7d, 0x65, 0xb8, 0xca, 0xcc, 0x4e,
    0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80,
    0x14, 0xc0, 0x7a, 0x98, 0x68, 0x8d, 0x89, 0xfb, 0xab, 0x05, 0x64, 0x0c,
    0x11, 0x7d, 0xaa, 0x7d, 0x65, 0xb8, 0xca, 0xcc, 0x4e, 0x30, 0x0d, 0x06,
    0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00,
    0x03, 0x82, 0x01, 0x01, 0x00, 0x35, 0xe3, 0x29, 0x6a, 0xe5, 0x2f, 0x5d,
    0x54, 0x8e, 0x29, 0x50, 0x94, 0x9f, 0x99, 0x1a, 0x14, 0xe4, 0x8f, 0x78,
    0x2a, 0x62, 0x94, 0xa2, 0x27, 0x67, 0x9e, 0xd0, 0xcf, 0x1a, 0x5e, 0x47,
    0xe9, 0xc1, 0xb2, 0xa4, 0xcf, 0xdd, 0x41, 0x1a, 0x05, 0x4e, 0x9b, 0x4b,
    0xee, 0x4a, 0x6f, 0x55, 0x52, 0xb3, 0x24, 0xa1, 0x37, 0x0a, 0xeb, 0x64,
    0x76, 0x2a, 0x2e, 0x2c, 0xf3, 0xfd, 0x3b, 0x75, 0x90, 0xbf, 0xfa, 0x71,
    0xd8, 0xc7, 0x3d, 0x37, 0xd2, 0xb5, 0x05, 0x95, 0x62, 0xb9, 0xa6, 0xde,
    0x89, 0x3d, 0x36, 0x7b, 0x38, 0x77, 0x48, 0x97, 0xac, 0xa6, 0x20, 0x8f,
    0x2e, 0xa6, 0xc9, 0x0c, 0xc2, 0xb2, 0x99, 0x45, 0x00, 0xc7, 0xce, 0x11,
    0x51, 0x22, 0x22, 0xe0, 0xa5, 0xea, 0xb6, 0x15, 0x48, 0x09, 0x64, 0xea,
    0x5e, 0x4f, 0x74, 0xf7, 0x05, 0x3e, 0xc7, 0x8a, 0x52, 0x0c, 0xdb, 0x15,
    0xb4, 0xbd, 0x6d, 0x9b, 0xe5, 0xc6, 0xb1, 0x54, 0x68, 0xa9, 0xe3, 0x69,
    0x90, 0xb6, 0x9a, 0xa5, 0x0f, 0xb8, 0xb9, 0x3f, 0x20, 0x7d, 0xae, 0x4a,
    0xb5, 0xb8, 0x9c, 0xe4, 0x1d, 0xb6, 0xab, 0xe6, 0x94, 0xa5, 0xc1, 0xc7,
    0x83, 0xad, 0xdb, 0xf5, 0x27, 0x87, 0x0e, 0x04, 0x6c, 0xd5, 0xff, 0xdd,
    0xa0, 0x5d, 0xed, 0x87, 0x52, 0xb7, 0x2b, 0x15, 0x02, 0xae, 0x39, 0xa6,
    0x6a, 0x74, 0xe9, 0xda, 0xc4, 0xe7, 0xbc, 0x4d, 0x34, 0x1e, 0xa9, 0x5c,
    0x4d, 0x33, 0x5f, 0x92, 0x09, 0x2f, 0x88, 0x66, 0x5d, 0x77, 0x97, 0xc7,
    0x1d, 0x76, 0x13, 0xa9, 0xd5, 0xe5, 0xf1, 0x16, 0x09, 0x11, 0x35, 0xd5,
    0xac, 0xdb, 0x24, 0x71, 0x70, 0x2c, 0x98, 0x56, 0x0b, 0xd9, 0x17, 0xb4,
    0xd1, 0xe3, 0x51, 0x2b, 0x5e, 0x75, 0xe8, 0xd5, 0xd0, 0xdc, 0x4f, 0x34,
    0xed, 0xc2, 0x05, 0x66, 0x80, 0xa1, 0xcb, 0xe6, 0x33, 0x30, 0x82, 0x03,
    0xba, 0x30, 0x82, 0x02, 0xa2, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x08,
    0x3e, 0xa3, 0xe4, 0x78, 0x99, 0x38, 0x13, 0x9d, 0x30, 0x0d, 0x06, 0x09,
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00, 0x30,
    0x49, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02,
    0x55, 0x53, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13,
    0x0a, 0x47, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x20, 0x49, 0x6e, 0x63, 0x31,
    0x25, 0x30, 0x23, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x1c, 0x47, 0x6f,
    0x6f, 0x67, 0x6c, 0x65, 0x20, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65,
    0x74, 0x20, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x20,
    0x47, 0x32, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x34, 0x30, 0x37, 0x31, 0x36,
    0x31, 0x32, 0x32, 0x31, 0x34, 0x30, 0x5a, 0x17, 0x0d, 0x31, 0x34, 0x31,
    0x30, 0x31, 0x34, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x30, 0x69,
    0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55,
    0x53, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x0a,
    0x43, 0x61, 0x6c, 0x69, 0x66, 0x6f, 0x72, 0x6e, 0x69, 0x61, 0x31, 0x16,
    0x30, 0x14, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0c, 0x0d, 0x4d, 0x6f, 0x75,
    0x6e, 0x74, 0x61, 0x69, 0x6e, 0x20, 0x56, 0x69, 0x65, 0x77, 0x31, 0x13,
    0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x0a, 0x47, 0x6f, 0x6f,
    0x67, 0x6c, 0x65, 0x20, 0x49, 0x6e, 0x63, 0x31, 0x18, 0x30, 0x16, 0x06,
    0x03, 0x55, 0x04, 0x03, 0x0c, 0x0f, 0x6d, 0x61, 0x69, 0x6c, 0x2e, 0x67,
    0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x59, 0x30,
    0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
    0xb2, 0x68, 0x6e, 0x3f, 0x03, 0x9e, 0x43, 0x85, 0x16, 0xb7, 0x89, 0x0b,
    0x16, 0x2a, 0xbe, 0x26, 0x36, 0xdd, 0x68, 0x0a, 0x53, 0x4e, 0x20, 0x40,
    0xf8, 0xd1, 0xdd, 0x63, 0xcb, 0x46, 0x73, 0x09, 0x96, 0x36, 0xde, 0x2c,
    0x45, 0x71, 0x2e, 0x8a, 0x79, 0xeb, 0x40, 0x2f, 0x65, 0x83, 0x81, 0xdb,
    0x37, 0x03, 0x84, 0xa1, 0x9a, 0xd0, 0x22, 0x3b, 0x73, 0x38, 0x45, 0xd3,
    0xd5, 0x91, 0xb2, 0x52, 0xa3, 0x82, 0x01, 0x4f, 0x30, 0x82, 0x01, 0x4b,
    0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x25, 0x04, 0x16, 0x30, 0x14, 0x06,
    0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01, 0x06, 0x08, 0x2b,
    0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02, 0x30, 0x1a, 0x06, 0x03, 0x55,
    0x1d, 0x11, 0x04, 0x13, 0x30, 0x11, 0x82, 0x0f, 0x6d, 0x61, 0x69, 0x6c,
    0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x30,
    0x0b, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x04, 0x04, 0x03, 0x02, 0x07, 0x80,
    0x30, 0x68, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01,
    0x04, 0x5c, 0x30, 0x5a, 0x30, 0x2b, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05,
    0x05, 0x07, 0x30, 0x02, 0x86, 0x1f, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f,
    0x2f, 0x70, 0x6b, 0x69, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e,
    0x63, 0x6f, 0x6d, 0x2f, 0x47, 0x49, 0x41, 0x47, 0x32, 0x2e, 0x63, 0x72,
    0x74, 0x30, 0x2b, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30,
    0x01, 0x86, 0x1f, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x63, 0x6c,
    0x69, 0x65, 0x6e, 0x74, 0x73, 0x31, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
    0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x6f, 0x63, 0x73, 0x70, 0x30, 0x1d,
    0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x75, 0xc6, 0xb0,
    0x4a, 0x46, 0x61, 0x83, 0xff, 0x91, 0x46, 0x45, 0x35, 0xa7, 0x0f, 0xd0,
    0x5b, 0xe9, 0xdd, 0x94, 0x1b, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13,
    0x01, 0x01, 0xff, 0x04, 0x02, 0x30, 0x00, 0x30, 0x1f, 0x06, 0x03, 0x55,
    0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x4a, 0xdd, 0x06, 0x16,
    0x1b, 0xbc, 0xf6, 0x68, 0xb5, 0x76, 0xf5, 0x81, 0xb6, 0xbb, 0x62, 0x1a,
    0xba, 0x5a, 0x81, 0x2f, 0x30, 0x17, 0x06, 0x03, 0x55, 0x1d, 0x20, 0x04,
    0x10, 0x30, 0x0e, 0x30, 0x0c, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01,
    0xd6, 0x79, 0x02, 0x05, 0x01, 0x30, 0x30, 0x06, 0x03, 0x55, 0x1d, 0x1f,
    0x04, 0x29, 0x30, 0x27, 0x30, 0x25, 0xa0, 0x23, 0xa0, 0x21, 0x86, 0x1f,
    0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x70, 0x6b, 0x69, 0x2e, 0x67,
    0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x47, 0x49,
    0x41, 0x47, 0x32, 0x2e, 0x63, 0x72, 0x6c, 0x30, 0x0d, 0x06, 0x09, 0x2a,
    0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00, 0x03, 0x82,
    0x01, 0x01, 0x00, 0x7f, 0x41, 0xf5, 0x57, 0x18, 0x3c, 0x75, 0xf5, 0x23,
    0x66, 0xc3, 0xf0, 0xf2, 0x3e, 0x70, 0x34, 0x56, 0xca, 0x78, 0xec, 0xc7,
    0x81, 0x58, 0x0d, 0xdf, 0xf0, 0xfd, 0x86, 0xe6, 0xe6, 0x50, 0x3d, 0xf6,
    0x09, 0x9a, 0x4d, 0xca, 0x60, 0x37, 0x9a, 0xd4, 0xca, 0x51, 0x7c, 0xf0,
    0x66, 0x23, 0xea, 0x5e, 0x6a, 0x6f, 0x7b, 0xa6, 0x7a, 0x38, 0x97, 0x42,
    0x58, 0x1a, 0x1b, 0x42, 0xae, 0x28, 0xde, 0x18, 0x7f, 0xcc, 0x76, 0x18,
    0x58, 0x05, 0xbf, 0xea, 0xef, 0x14, 0xad, 0x34, 0xe5, 0x5f, 0x25, 0xab,
    0xa1, 0x5f, 0x78, 0x5b, 0x6f, 0xe6, 0x69, 0xd8, 0x74, 0x8c, 0x19, 0x59,
    0xb0, 0x1a, 0xfb, 0x8e, 0xdf, 0x61, 0xac, 0xeb, 0x2b, 0x0a, 0x1c, 0xab,
    0x30, 0x0d, 0x64, 0x25, 0x78, 0xdf, 0x81, 0x71, 0xe3, 0xbd, 0xde, 0x9c,
    0x3f, 0xdd, 0xe9, 0xf8, 0xb6, 0x98, 0x2d, 0x13, 0xa3, 0x7b, 0x14, 0x6f,
    0xe3, 0x8b, 0xfc, 0x4e, 0x31, 0x26, 0xba, 0x10, 0xb4, 0x12, 0xe9, 0xc9,
    0x49, 0x60, 0xf0, 0xaa, 0x1f, 0x44, 0x68, 0x19, 0xd2, 0xb3, 0xc8, 0x46,
    0x22, 0x6b, 0xe1, 0x21, 0x77, 0xfd, 0x72, 0x33, 0x13, 0x21, 0x27, 0x81,
    0xe4, 0x7a, 0xc9, 0xe4, 0x1c, 0x05, 0x04, 0x73, 0x13, 0xda, 0x47, 0xfe,
    0x59, 0x41, 0x9c, 0x11, 0xc5, 0xf6, 0xb5, 0xd0, 0x01, 0xcb, 0x40, 0x19,
    0xf5, 0xfe, 0xb3, 0x3c, 0x1f, 0x61, 0x8f, 0x4d, 0xdb, 0x81, 0x2a, 0x8a,
    0xed, 0xb8, 0x53, 0xc7, 0x19, 0x6b, 0xfa, 0x8b, 0xfc, 0xe3, 0x2e, 0x12,
    0x4e, 0xbd, 0xc5, 0x44, 0x9d, 0x1c, 0x7f, 0x3b, 0x09, 0x51, 0xd7, 0x0a,
    0x0f, 0x22, 0x0a, 0xfd, 0x8c, 0x90, 0x14, 0xed, 0x10, 0xcb, 0x50, 0xcf,
    0xa5, 0x45, 0xce, 0xb0, 0x21, 0x28, 0xcb, 0xd6, 0xf5, 0x6e, 0xb2, 0x3e,
    0xfa, 0x35, 0x0c, 0x3d, 0x09, 0x0d, 0x81, 0x30, 0x82, 0x04, 0x04, 0x30,
    0x82, 0x02, 0xec, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x03, 0x02, 0x3a,
    0x69, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
    0x01, 0x05, 0x05, 0x00, 0x30, 0x42, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03,
    0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x16, 0x30, 0x14, 0x06,
    0x03, 0x55, 0x04, 0x0a, 0x13, 0x0d, 0x47, 0x65, 0x6f, 0x54, 0x72, 0x75,
    0x73, 0x74, 0x20, 0x49, 0x6e, 0x63, 0x2e, 0x31, 0x1b, 0x30, 0x19, 0x06,
    0x03, 0x55, 0x04, 0x03, 0x13, 0x12, 0x47, 0x65, 0x6f, 0x54, 0x72, 0x75,
    0x73, 0x74, 0x20, 0x47, 0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x20, 0x43, 0x41,
    0x30, 0x1e, 0x17, 0x0d, 0x31, 0x33, 0x30, 0x34, 0x30, 0x35, 0x31, 0x35,
    0x31, 0x35, 0x35, 0x35, 0x5a, 0x17, 0x0d, 0x31, 0x35, 0x30, 0x34, 0x30,
    0x34, 0x31, 0x35, 0x31, 0x35, 0x35, 0x35, 0x5a, 0x30, 0x49, 0x31, 0x0b,
    0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31,
    0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x0a, 0x47, 0x6f,
    0x6f, 0x67, 0x6c, 0x65, 0x20, 0x49, 0x6e, 0x63, 0x31, 0x25, 0x30, 0x23,
    0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x1c, 0x47, 0x6f, 0x6f, 0x67, 0x6c,
    0x65, 0x20, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x20, 0x41,
    0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x20, 0x47, 0x32, 0x30,
    0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
    0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30,
    0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0x9c, 0x2a, 0x04, 0x77,
    0x5c, 0xd8, 0x50, 0x91, 0x3a, 0x06, 0xa3, 0x82, 0xe0, 0xd8, 0x50, 0x48,
    0xbc, 0x89, 0x3f, 0xf1, 0x19, 0x70, 0x1a, 0x88, 0x46, 0x7e, 0xe0, 0x8f,
    0xc5, 0xf1, 0x89, 0xce, 0x21, 0xee, 0x5a, 0xfe, 0x61, 0x0d, 0xb7, 0x32,
    0x44, 0x89, 0xa0, 0x74, 0x0b, 0x53, 0x4f, 0x55, 0xa4, 0xce, 0x82, 0x62,
    0x95, 0xee, 0xeb, 0x59, 0x5f, 0xc6, 0xe1, 0x05, 0x80, 0x12, 0xc4, 0x5e,
    0x94, 0x3f, 0xbc, 0x5b, 0x48, 0x38, 0xf4, 0x53, 0xf7, 0x24, 0xe6, 0xfb,
    0x91, 0xe9, 0x15, 0xc4, 0xcf, 0xf4, 0x53, 0x0d, 0xf4, 0x4a, 0xfc, 0x9f,
    0x54, 0xde, 0x7d, 0xbe, 0xa0, 0x6b, 0x6f, 0x87, 0xc0, 0xd0, 0x50, 0x1f,
    0x28, 0x30, 0x03, 0x40, 0xda, 0x08, 0x73, 0x51, 0x6c, 0x7f, 0xff, 0x3a,
    0x3c, 0xa7, 0x37, 0x06, 0x8e, 0xbd, 0x4b, 0x11, 0x04, 0xeb, 0x7d, 0x24,
    0xde, 0xe6, 0xf9, 0xfc, 0x31, 0x71, 0xfb, 0x94, 0xd5, 0x60, 0xf3, 0x2e,
    0x4a, 0xaf, 0x42, 0xd2, 0xcb, 0xea, 0xc4, 0x6a, 0x1a, 0xb2, 0xcc, 0x53,
    0xdd, 0x15, 0x4b, 0x8b, 0x1f, 0xc8, 0x19, 0x61, 0x1f, 0xcd, 0x9d, 0xa8,
    0x3e, 0x63, 0x2b, 0x84, 0x35, 0x69, 0x65, 0x84, 0xc8, 0x19, 0xc5, 0x46,
    0x22, 0xf8, 0x53, 0x95, 0xbe, 0xe3, 0x80, 0x4a, 0x10, 0xc6, 0x2a, 0xec,
    0xba, 0x97, 0x20, 0x11, 0xc7, 0x39, 0x99, 0x10, 0x04, 0xa0, 0xf0, 0x61,
    0x7a, 0x95, 0x25, 0x8c, 0x4e, 0x52, 0x75, 0xe2, 0xb6, 0xed, 0x08, 0xca,
    0x14, 0xfc, 0xce, 0x22, 0x6a, 0xb3, 0x4e, 0xcf, 0x46, 0x03, 0x97, 0x97,
    0x03, 0x7e, 0xc0, 0xb1, 0xde, 0x7b, 0xaf, 0x45, 0x33, 0xcf, 0xba, 0x3e,
    0x71, 0xb7, 0xde, 0xf4, 0x25, 0x25, 0xc2, 0x0d, 0x35, 0x89, 0x9d, 0x9d,
    0xfb, 0x0e, 0x11, 0x79, 0x89, 0x1e, 0x37, 0xc5, 0xaf, 0x8e, 0x72, 0x69,
    0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x81, 0xfb, 0x30, 0x81, 0xf8, 0x30,
    0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14,
    0xc0, 0x7a, 0x98, 0x68, 0x8d, 0x89, 0xfb, 0xab, 0x05, 0x64, 0x0c, 0x11,
    0x7d, 0xaa, 0x7d, 0x65, 0xb8, 0xca, 0xcc, 0x4e, 0x30, 0x1d, 0x06, 0x03,
    0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x4a, 0xdd, 0x06, 0x16, 0x1b,
    0xbc, 0xf6, 0x68, 0xb5, 0x76, 0xf5, 0x81, 0xb6, 0xbb, 0x62, 0x1a, 0xba,
    0x5a, 0x81, 0x2f, 0x30, 0x12, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01,
    0xff, 0x04, 0x08, 0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x00, 0x30,
    0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03,
    0x02, 0x01, 0x06, 0x30, 0x3a, 0x06, 0x03, 0x55, 0x1d, 0x1f, 0x04, 0x33,
    0x30, 0x31, 0x30, 0x2f, 0xa0, 0x2d, 0xa0, 0x2b, 0x86, 0x29, 0x68, 0x74,
    0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x63, 0x72, 0x6c, 0x2e, 0x67, 0x65, 0x6f,
    0x74, 0x72, 0x75, 0x73, 0x74, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x63, 0x72,
    0x6c, 0x73, 0x2f, 0x67, 0x74, 0x67, 0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x2e,
    0x63, 0x72, 0x6c, 0x30, 0x3d, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05,
    0x07, 0x01, 0x01, 0x04, 0x31, 0x30, 0x2f, 0x30, 0x2d, 0x06, 0x08, 0x2b,
    0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x86, 0x21, 0x68, 0x74, 0x74,
    0x70, 0x3a, 0x2f, 0x2f, 0x67, 0x74, 0x67, 0x6c, 0x6f, 0x62, 0x61, 0x6c,
    0x2d, 0x6f, 0x63, 0x73, 0x70, 0x2e, 0x67, 0x65, 0x6f, 0x74, 0x72, 0x75,
    0x73, 0x74, 0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x17, 0x06, 0x03, 0x55, 0x1d,
    0x20, 0x04, 0x10, 0x30, 0x0e, 0x30, 0x0c, 0x06, 0x0a, 0x2b, 0x06, 0x01,
    0x04, 0x01, 0xd6, 0x79, 0x02, 0x05, 0x01, 0x30, 0x0d, 0x06, 0x09, 0x2a,
    0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00, 0x03, 0x82,
    0x01, 0x01, 0x00, 0x36, 0xd7, 0x06, 0x80, 0x11, 0x27, 0xad, 0x2a, 0x14,
    0x9b, 0x38, 0x77, 0xb3, 0x23, 0xa0, 0x75, 0x58, 0xbb, 0xb1, 0x7e, 0x83,
    0x42, 0xba, 0x72, 0xda, 0x1e, 0xd8, 0x8e, 0x36, 0x06, 0x97, 0xe0, 0xf0,
    0x95, 0x3b, 0x37, 0xfd, 0x1b, 0x42, 0x58, 0xfe, 0x22, 0xc8, 0x6b, 0xbd,
    0x38, 0x5e, 0xd1, 0x3b, 0x25, 0x6e, 0x12, 0xeb, 0x5e, 0x67, 0x76, 0x46,
    0x40, 0x90, 0xda, 0x14, 0xc8, 0x78, 0x0d, 0xed, 0x95, 0x66, 0xda, 0x8e,
    0x86, 0x6f, 0x80, 0xa1, 0xba, 0x56, 0x32, 0x95, 0x86, 0xdc, 0xdc, 0x6a,
    0xca, 0x04, 0x8c, 0x5b, 0x7f, 0xf6, 0xbf, 0xcc, 0x6f, 0x85, 0x03, 0x58,
    0xc3, 0x68, 0x51, 0x13, 0xcd, 0xfd, 0xc8, 0xf7, 0x79, 0x3d, 0x99, 0x35,
    0xf0, 0x56, 0xa3, 0xbd, 0xe0, 0x59, 0xed, 0x4f, 0x44, 0x09, 0xa3, 0x9e,
    0x38, 0x7a, 0xf6, 0x46, 0xd1, 0x1d, 0x12, 0x9d, 0x4f, 0xbe, 0xd0, 0x40,
    0xfc, 0x55, 0xfe, 0x06, 0x5e, 0x3c, 0xda, 0x1c, 0x56, 0xbd, 0x96, 0x51,
    0x7b, 0x6f, 0x57, 0x2a, 0xdb, 0xa2, 0xaa, 0x96, 0xdc, 0x8c, 0x74, 0xc2,
    0x95, 0xbe, 0xf0, 0x6e, 0x95, 0x13, 0xff, 0x17, 0xf0, 0x3c, 0xac, 0xb2,
    0x10, 0x8d, 0xcc, 0x73, 0xfb, 0xe8, 0x8f, 0x02, 0xc6, 0xf0, 0xfb, 0x33,
    0xb3, 0x95, 0x3b, 0xe3, 0xc2, 0xcb, 0x68, 0x58, 0x73, 0xdb, 0xa8, 0x24,
    0x62, 0x3b, 0x06, 0x35, 0x9d, 0x0d, 0xa9, 0x33, 0xbd, 0x78, 0x03, 0x90,
    0x2e, 0x4c, 0x78, 0x5d, 0x50, 0x3a, 0x81, 0xd4, 0xee, 0xa0, 0xc8, 0x70,
    0x38, 0xdc, 0xb2, 0xf9, 0x67, 0xfa, 0x87, 0x40, 0x5d, 0x61, 0xc0, 0x51,
    0x8f, 0x6b, 0x83, 0x6b, 0xcd, 0x05, 0x3a, 0xca, 0xe1, 0xa7, 0x05, 0x78,
    0xfc, 0xca, 0xda, 0x94, 0xd0, 0x2c, 0x08, 0x3d, 0x7e, 0x16, 0x79, 0xc8,
    0xa0, 0x50, 0x20, 0x24, 0x54, 0x33, 0x71, 0x31, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00,
};

static int test_reparse(void) {
  CBS pkcs7;
  CBB cbb;
  STACK_OF(X509) *certs = sk_X509_new_null();
  STACK_OF(X509) *certs2 = sk_X509_new_null();
  uint8_t *result_data, *result2_data;
  size_t result_len, result2_len, i;

  CBS_init(&pkcs7, kPKCS7DER, sizeof(kPKCS7DER));
  if (!PKCS7_get_certificates(certs, &pkcs7)) {
    fprintf(stderr, "PKCS7_get_certificates failed.\n");
    return 0;
  }

  CBB_init(&cbb, sizeof(kPKCS7DER));
  if (!PKCS7_bundle_certificates(&cbb, certs) ||
      !CBB_finish(&cbb, &result_data, &result_len)) {
    fprintf(stderr, "PKCS7_bundle_certificates failed.\n");
    return 0;
  }

  CBS_init(&pkcs7, result_data, result_len);
  if (!PKCS7_get_certificates(certs2, &pkcs7)) {
    fprintf(stderr, "PKCS7_get_certificates reparse failed.\n");
    return 0;
  }

  if (sk_X509_num(certs) != sk_X509_num(certs2)) {
    fprintf(stderr, "Number of certs in results differ.\n");
    return 0;
  }

  for (i = 0; i < sk_X509_num(certs); i++) {
    X509 *a = sk_X509_value(certs, i);
    X509 *b = sk_X509_value(certs2, i);

    if (X509_cmp(a, b) != 0) {
      fprintf(stderr, "Certificate %u differs.\n", (unsigned) i);
      return 0;
    }
  }

  CBB_init(&cbb, sizeof(kPKCS7DER));
  if (!PKCS7_bundle_certificates(&cbb, certs2) ||
      !CBB_finish(&cbb, &result2_data, &result2_len)) {
    fprintf(stderr,
            "PKCS7_bundle_certificates failed the second time.\n");
    return 0;
  }

  if (result_len != result2_len ||
      memcmp(result_data, result2_data, result_len) != 0) {
    fprintf(stderr, "Serialisation is not stable.\n");
    return 0;
  }

  OPENSSL_free(result_data);
  OPENSSL_free(result2_data);
  sk_X509_pop_free(certs, X509_free);
  sk_X509_pop_free(certs2, X509_free);

  return 1;
}

int main(void) {
  if (!test_reparse()) {
    return 1;
  }

  printf("PASS\n");
  return 0;
}

