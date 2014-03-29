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
 
 /*TODO
 * add multicore threading
 */
  
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <time.h>
#include <openssl/evp.h>

#include "wpabf.h"

unsigned int verbosity = 0;

void usage()
{
	printf("\nUsage: %s [options]\n", PROG_NAME);
	printf( "\n\t-d \tdictionary file\n"
			"\t-f \tpacket capture file\n"
			"\t-e \textended SSID\n"
			"\t-b \tbasic SSID\n"
			"\t-c \tclient SSID\n"
			"\t-a \tanonce\n"
			"\t-s \tsnonce\n"
			"\t-m \tmessage integrity check (MIC)\n"
			"\t-w \twrite passphrase to file\n"
			"\t-h \thelp!\n"
			"\t-v \tverbosity\n"
			"\t-V \tprint program version\n\n");
	printf("\tOnly options [dfe] are required\n\n");
	exit(-1);
}

void version()
{
	printf("\n%s, ver. %s (%s)\n\n", PROG_NAME, PROG_VERSION, PROG_DATE);
	exit(0);
}

void greeting()
{
	printf("\033[2J");
	printf("Welcome to WPABF %s, the Wi-Fi Protected Access Bruteforce recovery tool.\n\t\t\tCopyright (c) 2013 Thomas Hand <th6045@gmail.com>\n", PROG_VERSION);
}

int main(int argc, char **argv)
{	
	greeting();
	
	char *anonce, *snonce, *mic, *bssid, *clientssid, essid[32];
	char *pcapfile = NULL, *dictfile = NULL, *savefile = NULL;
	int x, aflag = 0, bflag = 0, cflag = 0, dflag = 0, eflag = 0, fflag = 0, mflag = 0, sflag = 0;

	opterr = 0;
	memset(essid, 0, 32);

	while ((x = getopt(argc, argv, "a:b:c:d:e:f:m:s:w:hvV")) != -1)
		switch (x)
		{
			case 'a':
			if(aflag)
				printf("Warning: -a is set multiple times\n");
			aflag = 1;
			anonce = optarg;
			break;

			case 'b':
			if(bflag)
				printf("Warning: -b is set multiple times\n");
			bflag = 1;
			bssid = optarg;
			break;

			case 'c':
			if(cflag)
				printf("Warning: -c is set multiple times\n");
			cflag = 1;
			clientssid = optarg;
			break;

			case 'd':
			if(dflag)
				printf("Warning: -d is set multiple times\n");
			dflag = 1;
			dictfile = optarg;
			break;

			case 'e':
			if(eflag)
				printf("Warning: -e is set multiple times\n");
			eflag = 1;
			memcpy(essid, optarg, strlen(optarg));
			break;

			case 'f':
			if(fflag)
				printf("Warning: -f is set multiple times\n");
			fflag = 1;
			pcapfile = optarg;
			break;

			case 'm':
			if(mflag)
				printf("Warning: -m is set multiple times\n");
			mflag = 1;
			mic = optarg;
			break;

			case 's':
			if(sflag)
				printf("Warning: -s is set multiple times\n");
			sflag = 1;
			snonce = optarg;
			break;

			case 'w':
			savefile = optarg;
			break;

			case 'h':
			usage();
			break;
			
			case 'v':
			verbosity++;
			break;

			case 'V':
			version();
			break;

			case '?':
			usage();

			default:
				usage();
		}
	
	if(FLAGS || verbosity >= 2)
		printf("\nFLAGS[%d%d%d%d%d%d%d%d%d]\n", aflag, bflag, cflag, dflag, eflag, fflag, mflag, sflag, verbosity);

	if(!fflag) {
		if(!eflag) {
			fprintf(stderr, "%s: missing -e option\n", PROG_NAME);
			usage();
		} else if(!dflag) {
			fprintf(stderr, "%s: missing -d option\n", PROG_NAME);
			usage();
		} else if(!aflag) {
			fprintf(stderr, "%s: missing -a option\n", PROG_NAME);
			usage();
		} else if(!sflag) {
			fprintf(stderr, "%s: missing -s option\n", PROG_NAME);
			usage();
		} else if(!bflag) {
			fprintf(stderr, "%s: missing -b option\n", PROG_NAME);
			usage();
		} else if(!cflag) {
			fprintf(stderr, "%s: missing -c option\n", PROG_NAME);
			usage();
		} else if(!mflag) {
			fprintf(stderr, "%s: missing -m option\n", PROG_NAME);
			usage();
		} else 
			printf ("\nExtended SSID: \t%s\nBasic SSID: \t%s\nClient SSID:\t%s\nanonce: \t%s\nsnonce: \t%s\nMessage IC: \t%s\n", 
							essid, bssid, clientssid, anonce, snonce, mic);
							
		crack(clientssid, bssid, anonce, snonce, mic, essid, NULL, 0, dictfile, savefile, 1);
	} else {
		if(!dflag) {
			fprintf(stderr, "%s: missing -d option\n", PROG_NAME);
			usage();
		} else if(!eflag)
			fprintf(stderr, "%s: missing -e option, will scrape capture file for ESSID\n", PROG_NAME);
		grab_frame(pcapfile, essid, dictfile, savefile); /* need eapol frame 1 and 2. */
	}
	return 0;
}

char grab_frame(char *pcapfile, char *essid, char *dictfile, char *savefile)
{
	printf("\nScraping EAPOL packets...\n");
	
	time_t tm;
	unsigned int i, bytes, line = 1, age, offset1, offset2, datasize, TKIPFLAG = 0;
	unsigned char buf[BUFFER_SIZE], IEEEframe[48], eapol[256], probe[60], clientssid[6], bssid[6], anonce[32], snonce[32], mic[16];
	
	memset(&buf, 0, BUFFER_SIZE);
	memset(&probe, 0, 60);
	memset(&IEEEframe, 0, 48);
	memset(&eapol, 0, 256);
	memset(&clientssid, 0, 6);
	memset(&bssid, 0, 6);
	memset(&anonce, 0, 32);
	memset(&snonce, 0, 32);
	memset(&mic, 0, 16);
	
	FILE *pcap = fopen (pcapfile, "rb");
	if(pcap != NULL)
	{
		bytes = fread(&buf, 1, BUFFER_SIZE, pcap); /* load capture file into memory */
		printf("Bytes read: %d", bytes);
		
		/* grab probe request data */
		for(i=0; i < BUFFER_SIZE; i++)
		{
			if(buf[i] == 0x40 && buf[i+24] == 0x00)
			{
				memcpy(probe, buf + i, 60);
				break;
			}
		}
		
		/* grep for identifying data fields */
		for(i=0; i < BUFFER_SIZE; i++)
		{
			if(buf[i] == 0x8e && buf[i-1] == 0x88) /* identify eapol packet offset1 */
			{
				offset1 = i+1;
				break;
			}
		}
		for(i=offset1; i < BUFFER_SIZE; i++)
		{			
			if(buf[i] == 0x8e && buf[i-1] == 0x88) /* identify eapol packet offset2 */
			{
				offset2 = i+1;
				break;
			}
		}

		/* Scrape header fields */
		if(buf[0] == 0xd4 && buf[1] == 0xc3 && buf[2] == 0xb2 && buf[3] == 0xa1)
			printf(" - Valid pcap file type (ver. %d.%d)\n", buf[4], buf[6]);
		else {
			printf(" - Could not read pcap file type\n");
			exit(1);
		}
			
		/* check IEEE802.11 packet */
		if(buf[20] != 0x69)
		{
			printf("Could not find IEEE802.11 link-layer header");
			exit(1);
		}
		else
			printf("Found IEEE802.11 link-layer header");
		memcpy(IEEEframe, buf + offset2 - 48, 48);
		//hexdump(IEEEframe, 48); // debug
			
		/* extract EAPOL frame 2 add WPA data */
		memcpy(eapol, buf + offset2, EAPOL_SIZE);
		datasize = eapol[98];
		memcpy(eapol + EAPOL_SIZE, buf + offset2 + EAPOL_SIZE, datasize);
		
		/* check EAPOL-key frame 88 8e and 03 */
		if(IEEEframe[46] == 0x88 && IEEEframe[47] == 0x8e && eapol[1] == 0x03)
			printf(" :: EAPOL-key frame (ver. %d)", eapol[0]);
		else {
			printf("\nCould not find EAPOL-key frame\n\n");
			exit(1);
		}

		/* check TKIP or CCMP */
		if(eapol[4] == 0xfe)
		{
			TKIPFLAG = 1;
			printf(" Type: TKIP\n");
		}
		else if(eapol[4] == 0x02)
		{
			TKIPFLAG = 0;
			printf(" Type: CCMP\n");
		}
		else {
			printf("\nCould not identify TKIP or CCMP type\n\n");
			exit(1);
		}
			
		/* set essid from probe request */
		if(strlen(probe) > 0){
			memcpy(essid, probe + 26, probe[25]);
			printf("Grabbing ESSID from probe request: %s\n", essid);
		} else if(strlen(essid) == 0){
			fprintf(stderr, "%s: Could not grab essid from probe packet, please use -e option\n", PROG_NAME);
			exit(1);
		}
				
		memcpy(bssid, IEEEframe + 20, 6);
		memcpy(clientssid, IEEEframe + 26, 6);
		memcpy(anonce, buf + offset1 + 17, 32);
		memcpy(snonce, eapol + 17, 32);
		memcpy(mic, eapol + 81, 16);
		
		/* get timestamp */
		tm = (IEEEframe[3] << 24) | (IEEEframe[2] << 16) | (IEEEframe[1] << 8) | IEEEframe[0];
		age = (int)time(NULL) - (int)tm;
		printf("Packets captured on %.*s (%.1f days old)\n", (int)strlen(ctime(&tm))-1, ctime(&tm), age/(3600*24.0));

		
		if(SHOWPROBE || verbosity >= 1)
		{
			printf("\nPROBE REQUEST");
			hexdump(probe, 60);
		}
				
		if(SHOWEAPOL || verbosity >= 1)
		{
			printf("\n\nEAPOL #2 | OFFSET: %d", offset2);
			hexdump(eapol, EAPOL_SIZE + datasize);
		}

		/* print packet dump */
		if(SHOWPACKETS || verbosity >= 1) {
			printf("\n\n\tPACKET DUMP\nOffset\t");
			for(i=0; i < bytes; i++)
			{
				printf("%02x ", buf[i]);
				if((i+1) % 4 == 0)
					printf(" ");
				if((i+1) % 16 == 0)
					printf("\n%04d :\t", line++ * 16);
			}
		}
		
		/* reset eapol packet */
		memset(eapol + 9, 0, 8); /* set replay counter to zero */
		memset(eapol + 81, 0, 16); /* set mic to zero */
		
		/* print scraped data fields */
		if(SHOWFIELDS || verbosity >= 1) {
			printf("\n\nBasic SSID: \t"); hexdump(bssid, 6);
			printf("\n\nClient SSID: \t"); hexdump(clientssid, 6);
			printf("\n\naNonce: \t"); hexdump(anonce, 32);
			printf("\n\nsNonce: \t"); hexdump(snonce, 32);
			printf("\n\nMessage IC: \t"); hexdump(mic, 16);
			printf("\n");
		}
		fclose(pcap);
	} else {
		perror("Error while opening the packet capture file");
		exit(-1);
	}
	crack(clientssid, bssid, anonce, snonce, mic, essid, eapol, EAPOL_SIZE + datasize, dictfile, savefile, TKIPFLAG);
	return 0;
}

void crack(char *clientssid, char *bssid, char *anonce, char *snonce, char *mic, char *essid, 
			char *eapol, unsigned int eapolsize, char *dictfile, char* savefile, unsigned int TKIPFLAG)
{
	printf("\n\nStarting cracking process, please wait...\n");

	double tm;
	unsigned int rej = 0, num = 0;
	unsigned char *pmk, *ptk, passphrase[64], pke[PKE_SIZE], kckmic[16];
	FILE *dict = NULL, *save = NULL;
	clock_t cstart = clock();
	clock_t cend = 0;
	
	if(*dictfile == '-') {
		/* Feed in passphrases from stdin */
		dict = stdin;
	} else {
		/* Feed in passphrases line by line */
		dict = fopen (dictfile, "r");
	}
	if(dict != NULL)
	{
		/* Pre-computed PKE */
		memset(&pke, 0, PKE_SIZE);
		memcpy(pke, "Pairwise key expansion", 23);
		if(memcmp(bssid, clientssid, 6) < 0)
		{
			memcpy(pke + 23, bssid, 6);
			memcpy(pke + 23 + 6, clientssid,6);
		} else {
			memcpy(pke + 23, clientssid, 6);
			memcpy(pke + 23 + 6, bssid, 6);
		}

		if(memcmp(anonce, snonce, 32) < 0)
		{
			memcpy(pke + 23 + 12, anonce, 32);
			memcpy(pke + 23 + 12 + 32, snonce, 32);
		} else {
			memcpy(pke + 23 + 12, snonce, 32);
			memcpy(pke + 23 + 12 + 32, anonce, 32);
		}
		//hexdump(pke, PKE_SIZE); //debug

		memset(&passphrase, 0, 63 + 1);
		while(fgets(passphrase, 63 + 1, dict) != NULL) /* read a line */
		{
			/* check passphrase complies with IEEE 802.11i */
			if(strlen(passphrase) < 8 + 1 || strlen(passphrase) > 63 + 1)
			{
				rej++;				
				continue;
			} else
				num++;
			
			/* Calculate PMK */
			pmk = (unsigned char *) error_checked_malloc(sizeof(unsigned char) * PMK_SIZE);
			if(PKCS5_PBKDF2_HMAC_SHA1(passphrase, strlen(passphrase)-1, essid, 
						strlen(essid), PMK_ITERATION, PMK_SIZE, pmk) != 0) /* ignore LF or NULL with strlen(passphrase)-1 */
			{
				if(SHOWPMK || verbosity >= 2)
				{
					printf("\nPMK(#%04d)", num);
					hexdump(pmk, PMK_SIZE);
					printf("\n");
				}
			} else
				fprintf(stderr, "%s: PKCS5_PBKDF2_HMAC_SHA1 failed on PMK\n", PROG_NAME);

			/* Calculate PTK */
			/* PTK = PRF-X(PMK, "Pairwise key expansion", Min(AA, SA) || Max(AA, SA) || Min(ANonce, SNonce) || Max(ANonce, SNonce)) */
			
			// debug PTK // taken from 802.11i IEEE standard
			/**************************
			printf("\nDEBUG PTK");
			char *name = "Jefe";
			char *prefix = "prefix";
			char *moredata = "what do ya want for nothing?";
			char somedata[36];
			memset(somedata, 0, 36);
			memcpy(somedata, prefix, 7);
			memcpy(somedata + 7, moredata, 29);
			//hexdump(somedata, 36);
			char dptk[PTK_SIZE];
			HMAC(EVP_sha1(), name, 4, somedata, 36, dptk, NULL);
			hexdump(dptk, PTK_SIZE-4);
			// PTK[0:16] = KCK = 0x51f4de5b33f249adf81aeb713a3c20f4
			
			**************************/
			
			ptk = (unsigned char *) error_checked_malloc(sizeof(unsigned char) * PTK_SIZE);
			if(HMAC(EVP_sha1(), pmk, PMK_SIZE, pke, PKE_SIZE, ptk, NULL) != 0)
			{
				if(SHOWPTK || verbosity >= 2)
					{
						printf("\nPTK(#%04d)", num);
						hexdump(ptk, PTK_SIZE-4);
						printf("\n");
					}
			} else
				fprintf(stderr, "%s: HMAC_SHA1 failed on PTK\n", PROG_NAME);

			/* Calculate MIC | PRF-384 CCMP or PRF-512 TKIP */
			if(TKIPFLAG)
				HMAC(EVP_md5(), ptk, PTK_SIZE-4, eapol, eapolsize, kckmic, NULL);
			else
				HMAC(EVP_sha1(), ptk, PTK_SIZE-4, eapol, eapolsize, kckmic, NULL);
			
			if(SHOWHMAC || verbosity >= 2)
			{
				printf("\nEAPOL HMAC");
				hexdump(kckmic, 16);
				printf("\n");
			}
			
			if(memcmp(kckmic, mic, 16) == 0) /* do comparison */
			{
				fclose(dict);
				cend = clock();
				tm = ((double)cend - (double)cstart)* 1.0e-6;
				printf("\n\nMaster Key"); hexdump(pmk, PMK_SIZE);
				printf("\n\nKey Confirmation Key"); hexdump(ptk, PTK_SIZE-4);
				printf("\n\nFound match: Passphrase is [%.*s]\nPairwise Master Keys calculated: %d in %.3f seconds (%.2f k/s)\nPassphrases rejected: %d\n\n", 
							(int)strlen(passphrase)-1, passphrase, num, tm, num/tm, rej);

				if(savefile != NULL)
				{ 
					save = fopen(savefile,"a+"); /* apend/create */
					if(save != NULL)
						fprintf(save,"%s:%s\n",essid, passphrase); 
					fclose(save);  
				}
				exit(1);
			}
			free(pmk); free(ptk);
			if(verbosity < 2 && !SHOWPMK && !SHOWPTK && !SHOWHMAC && num % 16) /* total hack */
				printf("\b\b\b\b\b\b\b\b        \b\b\b\b\b\b\b\b%08d", num);
		}
	fclose(dict);
	cend = clock();
	tm = ((double)cend - (double)cstart)* 1.0e-6;
	printf("\n\nPassphrase not in dictionary file\nPairwise Master Keys calculated: %d in %.3f seconds (%.2f k/s)\nPassphrases rejected: %d\n\n",
					num, tm, num/tm, rej);
	} else {
		perror("Error while opening the dictionary file"); /* why didn't the file open? */
	}
}

void *error_checked_malloc(unsigned int size)
{
	int *ptr;
	ptr = malloc(size);
	if (ptr == NULL) {
		fprintf(stderr, "%s: Memory could not be allocated on the heap.\n", PROG_NAME);
		exit(-1);
	}
	return ptr;
}

void hexdump(unsigned char *data, unsigned int size)
{
	unsigned int i;
	printf("\n");
	for(i = 0; i < size; i++)
	{
		printf("%02x", data[i]);
		if(size >= 16 && (i+1) % 2  == 0)
			printf(" ");
		if(size >= 32 && (i+1) % 16  == 0)
			printf("\n");
		if(size == 20 && (i+1) % 10  == 0)
			printf("\n");
	}
	printf("(%d bytes)", size);
}

/*
Have to grab essid from probe request/responce

PCAP Header    |  MAC Header  Ethernet Type  Version  Packet Type  Packet Body Length  Packet Body  Frame Check Sequence
40 bytes       |  12 bytes    2 bytes        1 byte   1 byte       2 bytes             variable     4 bytes

00000000  d4 c3 b2 a1 02 00 04 00  00 00 00 00 00 00 00 00  magic number 4, versions 4, timeoffset 4, accuracy 4
00000010  ff ff 00 00 69 00 00 00  33 88 72 52 51 1c 07 00  snapshot length 4, link layer header type 4, timestamp 4, microseconds 4
00000020  83 00 00 00 83 00 00 00  08 02 3a 01 d0 df c7 09  packet size (bytes) 4, wire size (bytes) 4, type/flags 4, dest MAC addr 6,
00000030  94 14 bb bb bb bb bb bb  bb bb bb bb bb bb 60 0f  BSSID 6, src MAC addr 6, sequence # 2, 
00000040  aa aa 03 00 00 00 88 8e  01 03 00 5f fe 00 89 00  logical-link control (03 EAPOL-key frame, 88 8e ETHERNET TYPE - EAPOL) 8, WPA decriptor 17, 
00000050  20 00 00 00 00 00 00 00  00 9f 65 87 95 6b d3 99  replay counter 8, anonce 32,
00000060  10 f8 00 fd b3 9c 72 cd  25 f8 5b 13 ba 37 5e 3f
00000070  e6 94 42 8c a0 12 b2 2a  b2 00 00 00 00 00 00 00  WPA key data NULLs 21,
00000080  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
*
000000a0  00 00 00 00 00 00 00 00  00 00 00 33 88 72 52 7c  timestamp 4, microseconds 4
000000b0  63 07 00 9b 00 00 00 9b  00 00 00 08 09 3a 01 bb  packet size (bytes) 4, wire size (bytes) 4, type/flags 4,
000000c0  bb bb bb bb bb d0 df c7  09 94 14 bb bb bb bb bb  BSSID 4, dest MAC addr 6, src MAC addr 6, 
000000d0  bb 30 01 aa aa 03 00 00  00 88 8e 01 03 00 77 fe  logical-link control (last 2 bytes TYPE) 8, WPA decriptor 17,
000000e0  01 09 00 20 00 00 00 00  00 00 00 00 3f d8 06 73  replay counter 8, snonce 32,
000000f0  fe 1a 99 e9 e6 d6 61 da  1b 6c 68 36 50 09 92 b1
00000100  b2 16 69 4d 1f 85 b4 0c  c2 ad b4 f4 00 00 00 00  WPA key data NULLs 32, 
00000110  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
00000120  00 00 00 00 00 00 00 00  00 00 00 00 a7 07 9b a4  MIC 16,
00000130  06 5b e2 60 fb ee 0d 59  44 f1 e1 2c 00 18 dd 16
00000140  00 50 f2 01 01 00 00 50  f2 02 01 00 00 50 f2 02
00000150  01 00 00 50 f2 02

**************************************************************

Master Key:    C2 03 D9 6C BF 01 8F 89 D7 C9 1D 79 CB CD 56 AD
               80 48 D0 23 74 42 25 80 B9 0C 52 7B 9B B2 36 F9

Transient Key: 77 6B 01 4D 78 4A BD 35 3A 9A CE 2D 58 F5 54 69 
               E2 B7 D3 A5 45 53 EC AC 34 E3 A1 07 B8 CA 08 F2 
               7E EE D7 98 45 59 C0 52 08 4E 76 4F 5D 48 A0 33 
               66 37 2C 2F DC 89 68 89 38 47 B3 A3 95 E0 4C 48 

EAPOL HMAC:    DA 8B 6F 5A C3 6D D1 65 6F FC ED 5B BB 31 2E 74
*/