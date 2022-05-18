#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <nfc/nfc.h>
#include <freefare.h>

#define RESET   "\033[0m"
#define BLACK   "\033[30m"      /* Black */
#define RED     "\033[31m"      /* Red */
#define GREEN   "\033[32m"      /* Green */
#define YELLOW  "\033[33m"      /* Yellow */
#define BLUE    "\033[34m"      /* Blue */
#define MAGENTA "\033[35m"      /* Magenta */
#define CYAN    "\033[36m"      /* Cyan */
#define WHITE   "\033[37m"      /* White */
#define BOLDBLACK   "\033[1m\033[30m"      /* Bold Black */
#define BOLDRED     "\033[1m\033[31m"      /* Bold Red */
#define BOLDGREEN   "\033[1m\033[32m"      /* Bold Green */
#define BOLDYELLOW  "\033[1m\033[33m"      /* Bold Yellow */
#define BOLDBLUE    "\033[1m\033[34m"      /* Bold Blue */
#define BOLDMAGENTA "\033[1m\033[35m"      /* Bold Magenta */
#define BOLDCYAN    "\033[1m\033[36m"      /* Bold Cyan */
#define BOLDWHITE   "\033[1m\033[37m"      /* Bold White */

#define KEYFILENAME "mctcli_keys.dic"

#ifndef SYSKEYFILE
#define SYSKEYFILE "/usr/share/mctcli/" KEYFILENAME
#endif

// if we are using non-github libfreefare
#ifdef OLDFREEFARE  // v0.4.0 (2015)
#define MIFARE_CLASSIC_1K CLASSIC_1K
#define MIFARE_CLASSIC_4K CLASSIC_4K
#define FreefareTag MifareTag
#endif


// keylist from file
MifareClassicKey *keylist = NULL;
int nbrkeys;

// last good keys in cache
MifareClassicKey **goodkeys;
int nbrgoodkeys;

nfc_context *context;
nfc_device *pnd = NULL;

struct keymap {
	MifareClassicKey *keyA;	// pointer to key A in keylist
	MifareClassicKey *keyB; // pointer to key B in keylist
	uint16_t readA; 		// bitmap of sectors read by this key A in the bloc
	uint16_t readB; 		// bitmap of sectors read by this key B in the bloc
	uint16_t writeA;		// TODO
	uint16_t writeB;		// TODO
};

int bcd2bin(uint8_t val) {
	return( (((val & 0xf0) >> 4)*10) + (val & 0x0f) );
}

static void sighandler(int sig)
{
	printf("Caught signal %d\n", sig);
	if(pnd != NULL) {
		nfc_abort_command(pnd);
		nfc_close(pnd);
	}
	nfc_exit(context);
	exit(EXIT_FAILURE);
}

void printhelp(char *binname)
{
	printf("Mifare Classic Tool CLI v0.0.1\n");
	printf("Copyright (c) 2019 - Denis Bodor\n\n");
	printf("Usage : %s [OPTIONS]\n", binname);
	printf(" -k file         read keys from file (default: keys.txt)\n");
	printf(" -l              display keylist\n");
	printf(" -L              list available readers/devices\n");
	printf(" -d connstring   use this device (default: use the first available device)\n");
	printf(" -m              just map and display keymap\n");
	printf(" -r              read tag and display data\n");
	printf(" -h              show this help\n");
}

void addgoodkey(MifareClassicKey *key)
{
	// search before add
	for(int i=0; i<nbrgoodkeys; i++) {
		if(goodkeys[i] == key)
			return;
	}

	// realloc and add the ney key to cache
	if((goodkeys = realloc(goodkeys, nbrgoodkeys * sizeof(MifareClassicKey *))) == NULL) {
		fprintf(stderr, "malloc list error: %s\n", strerror(errno));
	}
	nbrgoodkeys++;
	goodkeys[nbrgoodkeys-1] = key;
}

int maptag(FreefareTag *tags, struct keymap *myKM, int nbrsect)
{
	int i, j, k, c;
	int count = 0;

	for(i=0; i < nbrsect; i++) {
		// try cached keys first
		for(c=0; c < nbrgoodkeys;  c++) {
			if(goodkeys[c] != NULL && myKM[i].keyA == NULL) {
				if(mifare_classic_connect(tags[0]) == OPERATION_OK &&
						mifare_classic_authenticate(tags[0], mifare_classic_sector_last_block(i), *goodkeys[c], MFC_KEY_A) == OPERATION_OK) {
					myKM[i].keyA = goodkeys[c];
					count++;
					for(k=mifare_classic_sector_first_block(i); k <= mifare_classic_sector_last_block(i); k++) {
						if(mifare_classic_get_data_block_permission(tags[0], k, MCAB_R, MFC_KEY_A)) {
							myKM[i].readA |= (1 << (k-mifare_classic_sector_first_block(i)));
						}
						// is keyB readable ? If so, keyB cannot be used for auth
						if(!mifare_classic_get_trailer_block_permission(tags[0], mifare_classic_sector_last_block(i), MCAB_READ_KEYB, MFC_KEY_A)) {
							if(mifare_classic_get_data_block_permission(tags[0], k, MCAB_R, MFC_KEY_B)) {
								myKM[i].readB |= (1 << (k-mifare_classic_sector_first_block(i)));
							}
						}
					}
				}
				mifare_classic_disconnect(tags[0]);
			}

			if(goodkeys[c] != NULL && myKM[i].keyB == NULL) {
				if(mifare_classic_connect(tags[0]) == OPERATION_OK &&
						mifare_classic_authenticate(tags[0], mifare_classic_sector_last_block(i), *goodkeys[c], MFC_KEY_B) == OPERATION_OK) {
					myKM[i].keyB = goodkeys[c];
					count++;
				}
				mifare_classic_disconnect(tags[0]);
			}

			printf("Mapping... Sector:%2d/%d   Key:%3d/%d  %s  \r", i+1, nbrsect, c+1, nbrgoodkeys, (myKM[i].keyA && myKM[i].keyB) ? "Got it!" : "       ");
			fflush(stdout);
			if(myKM[i].keyA && myKM[i].keyB) break;
		}

		// No need to try keylist if we are done
		if(myKM[i].keyA && myKM[i].keyB) continue;

		// then use full keylist
		for(j=0; j < nbrkeys; j++) {
			if(myKM[i].keyA == NULL) {
				if(mifare_classic_connect(tags[0]) == OPERATION_OK &&
						mifare_classic_authenticate(tags[0], mifare_classic_sector_last_block(i), keylist[j], MFC_KEY_A) == OPERATION_OK) {
					myKM[i].keyA = keylist+j;
					addgoodkey(myKM[i].keyA);
					count++;
					for(k=mifare_classic_sector_first_block(i); k <= mifare_classic_sector_last_block(i); k++) {
						if(mifare_classic_get_data_block_permission(tags[0], k, MCAB_R, MFC_KEY_A)) {
							myKM[i].readA |= (1 << (k-mifare_classic_sector_first_block(i)));
						}
						// is keyB readable ? If so, keyB cannot be used for auth
						if(!mifare_classic_get_trailer_block_permission(tags[0], mifare_classic_sector_last_block(i), MCAB_READ_KEYB, MFC_KEY_A)) {
							if(mifare_classic_get_data_block_permission(tags[0], k, MCAB_R, MFC_KEY_B)) {
								myKM[i].readB |= (1 << (k-mifare_classic_sector_first_block(i)));
							}
						}
					}
				}
				mifare_classic_disconnect(tags[0]);
			}

			if(myKM[i].keyB == NULL) {
				if(mifare_classic_connect(tags[0]) == OPERATION_OK &&
						mifare_classic_authenticate(tags[0], mifare_classic_sector_last_block(i), keylist[j], MFC_KEY_B) == OPERATION_OK) {
					myKM[i].keyB = keylist+j;
					addgoodkey(myKM[i].keyB);
					count++;
				}
				mifare_classic_disconnect(tags[0]);
			}

			printf("Mapping... Sector:%2d/%d   Key:%3d/%d  %s  \r", i+1, nbrsect, j+1, nbrkeys, (myKM[i].keyA && myKM[i].keyB) ? "Got it!" : "       ");
			fflush(stdout);
			if(myKM[i].keyA && myKM[i].keyB) break;
		}
	}
	printf("\n");

	if(count != nbrsect*2)
		return(-1);

	return(0);
}

void printmapping(struct keymap *myKM, int nbrsect)
{
	// struct keymap myKM[40]
	int countkeys = 0;
	int i;

	printf("        key A         key B         ReadA    ReadB\n");
	for(i=0; i<nbrsect; i++) {
		MifareClassicKey *tmpkeyA = myKM[i].keyA;
		MifareClassicKey *tmpkeyB = myKM[i].keyB;

		printf("%02d:  ", i);
		if(tmpkeyA != NULL)
			printf("%02x%02x%02x%02x%02x%02x", (*tmpkeyA)[0],(*tmpkeyA)[1],(*tmpkeyA)[2],(*tmpkeyA)[3],(*tmpkeyA)[4],(*tmpkeyA)[5]);
		else
			printf("------------");
		if(tmpkeyB != NULL)
			printf("  %02x%02x%02x%02x%02x%02x", (*tmpkeyB)[0],(*tmpkeyB)[1],(*tmpkeyB)[2],(*tmpkeyB)[3],(*tmpkeyB)[4],(*tmpkeyB)[5]);
		else
			printf("  ------------");
		printf("     %04X", myKM[i].readA);
		printf("     %04X", myKM[i].readB);
		printf("\n");
	}

	for(i=0; i<nbrsect; i++) {
		countkeys += myKM[i].keyA == NULL ? 0 : 1;
		countkeys += myKM[i].keyB == NULL ? 0 : 1;
	}
	if(countkeys == nbrsect*2)
		printf("Found all keys\n");
	else
		printf(BOLDRED"Keymap incomplete: "RESET"%d/%d\n", countkeys, (nbrsect*2));
}

int readtag(FreefareTag *tags, struct keymap *myKM, int nbrsect, unsigned char *dest, int nbrblck)
{
	int i, k;
	int ret = 0;
	MifareClassicKey *tmpkeyA;
	MifareClassicKey *tmpkeyB;
	MifareClassicBlock data;

	for(i=0; i<nbrsect; i++) {
		tmpkeyA = myKM[i].keyA;
		tmpkeyB = myKM[i].keyB;
		// read sector block by block, check if we have keys
		for(k=mifare_classic_sector_first_block(i); k <= mifare_classic_sector_last_block(i); k++) {
			if(myKM[i].readB & (1 << (k-mifare_classic_sector_first_block(i))) && tmpkeyB != NULL) {
					if((mifare_classic_connect(tags[0]) == OPERATION_OK) &&
							(mifare_classic_authenticate(tags[0],
														 k,
														 *tmpkeyB,
														 MFC_KEY_B) == OPERATION_OK)) {
						if(mifare_classic_read(tags[0], k, &data) == OPERATION_OK) {
							// copy the key in dump
							if(k == mifare_classic_sector_last_block(i)) {
								if(tmpkeyA != NULL)
									memcpy(&data[0], tmpkeyA, sizeof(MifareClassicKey));
								if(tmpkeyB != NULL)
									memcpy(&data[10], tmpkeyB, sizeof(MifareClassicKey));
							}
							memcpy(dest+(16*k), &data, 16);
						} else {
							fprintf(stderr, "read error: %s\n", freefare_strerror(tags[0]));
							ret++;
						}
						mifare_classic_disconnect(tags[0]);
					} else {
						fprintf(stderr, "Auth error !\n");
						mifare_classic_disconnect(tags[0]);
						ret++;
					}
			} else if(myKM[i].readA & (1 << (k-mifare_classic_sector_first_block(i))) && tmpkeyA != NULL){
					if((mifare_classic_connect(tags[0]) == OPERATION_OK) &&
							(mifare_classic_authenticate(tags[0],
														 k,
														 *tmpkeyA,
														 MFC_KEY_A) == OPERATION_OK)) {
						if(mifare_classic_read(tags[0], k, &data) == OPERATION_OK) {
							// copy the key in dump
							if(k == mifare_classic_sector_last_block(i)) {
								if(tmpkeyA != NULL)
									memcpy(&data[0], tmpkeyA, sizeof(MifareClassicKey));
								if(tmpkeyB != NULL)
									memcpy(&data[10], tmpkeyB, sizeof(MifareClassicKey));
							}
							memcpy(dest+(16*k), &data, 16);
						} else {
							fprintf(stderr, "read error: %s\n", freefare_strerror(tags[0]));
							ret++;
						}
						mifare_classic_disconnect(tags[0]);
					} else {
						fprintf(stderr, "Auth error !\n");
						mifare_classic_disconnect(tags[0]);
						ret++;
					}
			} else {
				// key missing for this block
				ret++;
			}
			printf("Reading: %d/%d\r", k+1, nbrblck);
			fflush(stdout);
		}
	}
	printf("\n");
	return(ret);
}

int printmfdata(int nbrsect, unsigned char *src)
{
	int i, j, k;
	for(i=0; i<nbrsect; i++) {
		printf("+Sector: %d\n", i);
		for(k=mifare_classic_sector_first_block(i); k <= mifare_classic_sector_last_block(i); k++) {
			if(k==0) printf(MAGENTA); // sector 0 is special
			for(j=0; j<16; j++) {
				if(k==mifare_classic_sector_last_block(i)) { // last sector of a block is special
					if(j==0) printf(BOLDGREEN);
					if(j==6) printf(YELLOW);
					if(j==10) printf(GREEN);
				}
				printf("%02X", src[(k*16)+j]);
			}
			printf(RESET "\n");
		}
	}
	return(0);
}

int loadkeys(const char *filename)
{
	FILE *fp;
	char *strline = NULL;
	int line = 0;
	size_t len = 0;
	ssize_t read;
	int count = 0;

	MifareClassicKey tmpkey;

	fp = fopen(filename, "rt");
	if(fp == NULL)
		return(0);

	while((read = getline(&strline, &len, fp)) != -1) {
		// ignore empty line or starting with '#'
		if(strline[0] == '#' || strline[0] == '\n') continue;
		if(sscanf(strline, "%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx", &tmpkey[0], &tmpkey[1], &tmpkey[2], &tmpkey[3], &tmpkey[4], &tmpkey[5]) == 6) {
			if((keylist=(MifareClassicKey *)realloc(keylist, (count+1)*sizeof(MifareClassicKey))) == NULL) {
				fprintf(stderr, "malloc list error: %s\n", strerror(errno));
			}
			memcpy(keylist[count], &tmpkey, sizeof(MifareClassicKey));
			count++;
		} else {
			fprintf(stderr, "Bad line syntax at line %d\n", line);
		}
		line++;
	}

	fclose(fp);
	if(strline)
		free(strline);

	if(count)
		printf("%d key(s) loaded from %s\n", count, filename);

	return(count);
}

void printkey()
{
	printf("Key list:\n");
	for(int i=0; i<nbrkeys; i++) {
		printf("%5d: %02X %02X %02X %02X %02X %02X\n", i, keylist[i][0], keylist[i][1], keylist[i][2], keylist[i][3], keylist[i][4], keylist[i][5]);
	}
}

int main(int argc, char** argv)
{
	FreefareTag *tags = NULL;
	size_t device_count;
	nfc_connstring devices[8];
	unsigned char *mfdata = NULL;

	int nbrsect;
	int nbrblck;

	int retopt;
	int opt = 0;

	int optlistk = 0;
	int optmap = 0;
	int optdispmap = 0;
	int optread = 0;
	int optdispdata = 0;
	int optlistdev = 0;
	char *optconnstring = NULL;

	char *rfilename = NULL;

	char *home = NULL;
	char *fullpath = NULL;
	int keyfilepathsz;

	// we don't store keys, but pointers to key in keyslist
	struct keymap myKM[40] = {{ NULL, NULL, 0, 0, 0, 0 }};

	while((retopt = getopt(argc, argv, "k:d:lmrLh")) != -1) {
		switch (retopt) {
			case 'k':
				rfilename = strdup(optarg);
				opt++;
				break;
			case 'l':
				optlistk = 1;
				opt++;
				break;
			case 'm':
				optmap = 1;
				optdispmap = 1;
				opt++;
				break;
			case 'r':
				optmap = 1;
				optread = 1;
				optdispdata = 1;
				opt++;
				break;
			case 'L':
				optlistdev = 1;
				opt++;
				break;
			case 'd':
				optconnstring = strdup(optarg);
				break;
			case 'h':
				printhelp(argv[0]);
				return(EXIT_SUCCESS);
			default:
				printhelp(argv[0]);
				return(EXIT_FAILURE);
		}
	}

	if(!opt) {
		printhelp(argv[0]);
		return(EXIT_FAILURE);
	}

	if(signal(SIGINT, &sighandler) == SIG_ERR) {
		fprintf(stderr, "Can't catch SIGINT\n");
		return(EXIT_FAILURE);
	}
	if(signal(SIGTERM, &sighandler) == SIG_ERR) {
		fprintf(stderr, "Can't catch SIGTERM\n");
		return(EXIT_FAILURE);
	}

	if(rfilename) {
		if((nbrkeys = loadkeys(rfilename)) < 1) {
			fprintf(stderr, "No key to use. Exiting.\n");
			exit(EXIT_FAILURE);
		}
	} else if(!optlistdev) {
		// get home directory
		if((home=getenv("HOME")) == NULL) {
			fprintf(stderr, "Unable to get $HOME\n");
			exit(EXIT_FAILURE);
		}
		// compose path
		keyfilepathsz = strlen(home)+1+strlen(KEYFILENAME)+1;
		if((fullpath=(char *) malloc(keyfilepathsz)) == NULL) {
			fprintf(stderr, "Memory allocation error: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
		if(snprintf(fullpath, keyfilepathsz, "%s/%s", home, KEYFILENAME) != keyfilepathsz-1) {
			fprintf(stderr, "Keyfile path error\n");
			exit(EXIT_FAILURE);
		}
		// try ~/mctcli_keys.dic
		if((nbrkeys = loadkeys(fullpath)) < 1 ) {
			if(fullpath) free (fullpath);
			// try ./mctcli_keys.dic
			if((nbrkeys = loadkeys("./" KEYFILENAME)) < 1) {
				// try ${PREFIX}/usr/share/mctcli/mctcli_keys.dic
				if((nbrkeys = loadkeys(SYSKEYFILE)) < 1) {
					fprintf(stderr, "No keyfile to load. Exiting.\n");
					exit(EXIT_FAILURE);
				}
			}
		}
	}
	if(optlistk && !optlistdev)
		printkey();

	if(!optread && !optmap && !optlistdev)
		exit(EXIT_SUCCESS);

	// Initialize libnfc and set the nfc_context
	nfc_init(&context);
	if(context == NULL) {
		fprintf(stderr, "Unable to init libnfc\n");
		exit(EXIT_FAILURE);
	}

	// FIXME put this in a displaydevices() function
	if(optlistdev) {
		// Scan readers/devices
		device_count = nfc_list_devices(context, devices, sizeof(devices)/sizeof(*devices));
		if(device_count <= 0) {
			fprintf(stderr, "No NFC device found");
			nfc_exit(context);
			exit(EXIT_FAILURE);
		}

		printf("Available readers/devices:\n");
		for(size_t d = 0; d < device_count; d++) {
			printf("  %lu: ", d);
			if(!(pnd = nfc_open (context, devices[d]))) {
				printf("nfc_open() failed\n");
			} else {
				printf("%s (%s)\n", nfc_device_get_name(pnd), nfc_device_get_connstring(pnd));
				nfc_close(pnd);
			}
		}
		nfc_exit(context);
		return(EXIT_SUCCESS);
	}

	if(optconnstring)
		// Open, using specified NFC device
		pnd = nfc_open(context, optconnstring);
	else
		// Open, using the first available NFC device
		pnd = nfc_open(context, NULL);

	if(pnd == NULL) {
		fprintf(stderr, "Error: %s\n", "Unable to open NFC device.");
		nfc_exit(context);
		exit(EXIT_FAILURE);
	}

	printf("NFC reader: %s opened\n", nfc_device_get_name(pnd));

	tags = freefare_get_tags(pnd);

	if(!tags[0] || !tags) {
		fprintf(stderr, "no valid tag found !\n");
		nfc_close(pnd);
		nfc_exit(context);
		exit(EXIT_FAILURE);
	}

	switch(freefare_get_tag_type(tags[0])) {
		case MIFARE_CLASSIC_1K:
			printf("%u : Mifare 1k (S50) with UID: %s\n", 0, freefare_get_tag_uid(tags[0]));
			nbrsect = 16;  // 16 sectors * 4 bloks
			nbrblck= 4*16;
			break;
		case MIFARE_CLASSIC_4K:
			printf("%u : Mifare 4k (S70) with UID: %s\n", 0, freefare_get_tag_uid(tags[0]));
			nbrsect = 40;  // 32 sectors * 4 blocks + 8 sector * 16 blocks
			nbrblck = (4*32)+(8*16);
			break;
		default:
			fprintf(stderr, "no Mifare 1k (S50) or 4k (S70) tag found !\n");
			nfc_close(pnd);
			nfc_exit(context);
			exit(EXIT_FAILURE);
	}

	if((mfdata = (unsigned char *)malloc(nbrblck*16 * sizeof(unsigned char))) == NULL) {
		fprintf(stderr, "malloc list error: %s\n", strerror(errno));
		nfc_close(pnd);
		nfc_exit(context);
		exit(EXIT_FAILURE);
	}
	bzero(mfdata, nbrblck*16);

	if(optmap)
		if(maptag(tags, myKM, nbrsect) != 0)
			printf(BOLDRED"Warning: missing keys !"RESET"\n");

	if(optdispmap)
		printmapping(myKM, nbrsect);

	if(optread)
		if(readtag(tags, myKM, nbrsect, mfdata, nbrblck) != 0)
			printf(BOLDRED"Warning: missing blocks !"RESET"\n");

	if(optdispdata)
		printmfdata(nbrsect, mfdata);

	free(mfdata);

	freefare_free_tags(tags);
	// Close NFC device
	nfc_close(pnd);
	// Release the context
	nfc_exit(context);

	if(goodkeys)
		free(goodkeys);

	if(keylist)
		free(keylist);

	exit(EXIT_SUCCESS);
}
