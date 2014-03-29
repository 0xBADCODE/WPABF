/* 
 * Copyright (c) 2013 Thomas Hand <th6045@gmail.com>
 *
 * With exception of:
 * PBKDF2 & HMAC algorithms - Copyright (c) OpenSSL project
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
 
#define PROG_NAME       "WPABF"
#define PROG_VERSION    "1.1"
#define PROG_DATE       "November, 2013"

#define PMK_SIZE		32
#define PMK_ITERATION	4096
#define PTK_SIZE		20

#define BUFFER_SIZE	4096
#define EAPOL_SIZE	99
#define PKE_SIZE	100
#define N_THREADS	4

#define FLAGS		1
#define SHOWPMK		0
#define SHOWPTK		0
#define SHOWHMAC	0
#define SHOWPROBE	1
#define SHOWEAPOL	1
#define SHOWPACKETS	1
#define SHOWFIELDS	1

void *error_checked_malloc(unsigned int size);
void hexdump(unsigned char *data, unsigned int size);
void crack(char *clientssid, char *bssid, char *anonce, char *snonce, char *mic, char *essid, 
			char *eapol, unsigned int eapolsize, char *dictfile, char* savefile, unsigned int TKIPFLAG);
char grab_frame(char *pcapfile, char *essid, char *dictfile, char *savefile);
