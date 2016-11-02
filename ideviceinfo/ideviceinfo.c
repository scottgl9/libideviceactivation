/*
 * ideviceinfo.c
 * Simple utility to show information about an attached device
 *
 * Copyright (c) 2009 Martin Szulecki All Rights Reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>
#include "common/utils.h"

#define FORMAT_KEY_VALUE 1
#define FORMAT_XML 2

#include <openssl/x509v3.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

void load_private_key(char *filename, char *data, size_t len) {
   EVP_MD_CTX* ctx = NULL;
   EVP_PKEY *privkey;
   FILE *fp;
   RSA *rsakey;
   const EVP_MD* md = EVP_get_digestbyname("SHA256");

   OpenSSL_add_all_algorithms();
   privkey = EVP_PKEY_new();

   fp = fopen (filename, "r");

   if (!PEM_read_PrivateKey( fp, &privkey, NULL, NULL)) {
      printf("%s Failed to load %s\n", __FUNCTION__, filename);
      return;
   }

   fclose(fp);

   ctx = EVP_MD_CTX_create();
   EVP_DigestSignInit(ctx, NULL, md, NULL, privkey);
   EVP_DigestSignUpdate(ctx, data, len);
   size_t req = 0;
   EVP_DigestSignFinal(ctx, NULL, &req);

    if(ctx) {
        EVP_MD_CTX_destroy(ctx);
        ctx = NULL;
    }
}

static const char *domains[] = {
	//"com.apple.disk_usage",
	//"com.apple.disk_usage.factory",
	//"com.apple.mobile.battery",
	"com.apple.mobile.debug",
	//"com.apple.iqagent",
	//"com.apple.purplebuddy",
	"com.apple.PurpleBuddy",
	//"com.apple.mobile.chaperone",
	"com.apple.mobile.third_party_termination",
	"com.apple.mobile.lockdownd",
	"com.apple.mobile.lockdown_cache",
	//"com.apple.xcode.developerdomain",
	//"com.apple.international",
	"com.apple.mobile.data_sync",
	"com.apple.mobile.backup",
	//"com.apple.mobile.nikita",
	"com.apple.mobile.restriction",
	"com.apple.mobile.sync_data_class",
	"com.apple.mobile.software_behavior",
	"com.apple.mobile.iTunes.SQLMusicLibraryPostProcessCommands",
	"com.apple.mobile.iTunes.accessories",
	// shows deleted applications
	//"com.apple.iTunes",
	// bunch of itunes info, including MinITunesVersion, and FairPlayCertificate
	"com.apple.mobile.iTunes",
	NULL
};

/* aaaack but it's fast and const should make it shared text page. */
static const unsigned char pr2six[256] =
{
    /* ASCII table */
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
    64,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
    64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64
};

int Base64decode_len(const char *bufcoded)
{
    int nbytesdecoded;
    register const unsigned char *bufin;
    register int nprbytes;

    bufin = (const unsigned char *) bufcoded;
    while (pr2six[*(bufin++)] <= 63);

    nprbytes = (bufin - (const unsigned char *) bufcoded) - 1;
    nbytesdecoded = ((nprbytes + 3) / 4) * 3;

    return nbytesdecoded + 1;
}

int Base64decode(char *bufplain, const char *bufcoded)
{
    int nbytesdecoded;
    register const unsigned char *bufin;
    register unsigned char *bufout;
    register int nprbytes;

    bufin = (const unsigned char *) bufcoded;
    while (pr2six[*(bufin++)] <= 63);
    nprbytes = (bufin - (const unsigned char *) bufcoded) - 1;
    nbytesdecoded = ((nprbytes + 3) / 4) * 3;

    bufout = (unsigned char *) bufplain;
    bufin = (const unsigned char *) bufcoded;

    while (nprbytes > 4) {
    *(bufout++) =
        (unsigned char) (pr2six[*bufin] << 2 | pr2six[bufin[1]] >> 4);
    *(bufout++) =
        (unsigned char) (pr2six[bufin[1]] << 4 | pr2six[bufin[2]] >> 2);
    *(bufout++) =
        (unsigned char) (pr2six[bufin[2]] << 6 | pr2six[bufin[3]]);
    bufin += 4;
    nprbytes -= 4;
    }

    /* Note: (nprbytes == 1) would be an error, so just ingore that case */
    if (nprbytes > 1) {
    *(bufout++) =
        (unsigned char) (pr2six[*bufin] << 2 | pr2six[bufin[1]] >> 4);
    }
    if (nprbytes > 2) {
    *(bufout++) =
        (unsigned char) (pr2six[bufin[1]] << 4 | pr2six[bufin[2]] >> 2);
    }
    if (nprbytes > 3) {
    *(bufout++) =
        (unsigned char) (pr2six[bufin[2]] << 6 | pr2six[bufin[3]]);
    }

    *(bufout++) = '\0';
    nbytesdecoded -= (4 - nprbytes) & 3;
    return nbytesdecoded;
}

static int is_domain_known(char *domain)
{
	int i = 0;
	while (domains[i] != NULL) {
		if (strstr(domain, domains[i++])) {
			return 1;
		}
	}
	return 0;
}

static void print_usage(int argc, char **argv)
{
	int i = 0;
	char *name = NULL;

	name = strrchr(argv[0], '/');
	printf("Usage: %s [OPTIONS]\n", (name ? name + 1: argv[0]));
	printf("Show information about a connected device.\n\n");
	printf("  -d, --debug\t\tenable communication debugging\n");
	printf("  -s, --simple\t\tuse a simple connection to avoid auto-pairing with the device\n");
	printf("  -u, --udid UDID\ttarget specific device by its 40-digit device UDID\n");
	printf("  -q, --domain NAME\tset domain of query to NAME. Default: None\n");
	printf("  -k, --key NAME\tonly query key specified by NAME. Default: All keys.\n");
	printf("  -x, --xml\t\toutput information as xml plist instead of key/value pairs\n");
	printf("  -h, --help\t\tprints usage information\n");
	printf("\n");
	printf("  Known domains are:\n\n");
	while (domains[i] != NULL) {
		printf("  %s\n", domains[i++]);
	}
	printf("\n");
	//printf("Homepage: <" PACKAGE_URL ">\n");
}

void write_xml_file(char *filename, char *xml, uint32_t len) {
	FILE *f = fopen(filename, "wb");
	fwrite(xml, 1, len, f);
	fclose(f);
}

int main(int argc, char *argv[])
{
	lockdownd_client_t client = NULL;
	lockdownd_error_t ldret = LOCKDOWN_E_UNKNOWN_ERROR;
	idevice_t device = NULL;
	idevice_error_t ret = IDEVICE_E_UNKNOWN_ERROR;
	int i;
	int simple = 0;
	int format = FORMAT_XML; // xml format by default
	const char* udid = NULL;
	char *domain = NULL;
	char *key = NULL;
	char *xml_doc = NULL;
	char *str = NULL;
	uint32_t xml_length;
	uint64_t len;
	plist_t node = NULL;

	/* parse cmdline args */
	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-d") || !strcmp(argv[i], "--debug")) {
			idevice_set_debug_level(1);
			continue;
		}
		else if (!strcmp(argv[i], "-u") || !strcmp(argv[i], "--udid")) {
			i++;
			if (!argv[i] || (strlen(argv[i]) != 40)) {
				print_usage(argc, argv);
				return 0;
			}
			udid = argv[i];
			continue;
		}
		else if (!strcmp(argv[i], "-q") || !strcmp(argv[i], "--domain")) {
			i++;
			if (!argv[i] || (strlen(argv[i]) < 4)) {
				print_usage(argc, argv);
				return 0;
			}
			if (!is_domain_known(argv[i])) {
				fprintf(stderr, "WARNING: Sending query with unknown domain \"%s\".\n", argv[i]);
			}
			domain = strdup(argv[i]);
			continue;
		}
		else if (!strcmp(argv[i], "-k") || !strcmp(argv[i], "--key")) {
			i++;
			if (!argv[i] || (strlen(argv[i]) <= 1)) {
				print_usage(argc, argv);
				return 0;
			}
			key = strdup(argv[i]);
			continue;
		}
		else if (!strcmp(argv[i], "-s") || !strcmp(argv[i], "--simple")) {
			simple = 1;
			continue;
		}
		else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
			print_usage(argc, argv);
			return 0;
		}
		else {
			print_usage(argc, argv);
			return 0;
		}
	}

	ret = idevice_new(&device, udid);
	if (ret != IDEVICE_E_SUCCESS) {
		if (udid) {
			printf("No device found with udid %s, is it plugged in?\n", udid);
		} else {
			printf("No device found, is it plugged in?\n");
		}
		return -1;
	}

	if (LOCKDOWN_E_SUCCESS != (ldret = simple ?
			lockdownd_client_new(device, &client, "ideviceinfo"):
			lockdownd_client_new_with_handshake(device, &client, "ideviceinfo"))) {
		fprintf(stderr, "ERROR: Could not connect to lockdownd, error code %d\n", ldret);
		idevice_free(device);
		return -1;
	}

	/* run query and output information */
	if(lockdownd_get_value(client, domain, key, &node) == LOCKDOWN_E_SUCCESS) {
		
		if (node) {
			plist_to_xml(node, &xml_doc, &xml_length);
			printf("%s", xml_doc);
			free(xml_doc);
			xml_doc = NULL;
			plist_free(node);
			node = NULL;
		}
	}
/*
	for(int i=0; i<sizeof(domains)>>2; i++) {
		if (domains[i] == NULL) break;
		if(lockdownd_get_value(client, domains[i], key, &node) == LOCKDOWN_E_SUCCESS && node) {
			printf("Domain %s:\n", domains[i]);
			plist_to_xml(node, &xml_doc, &xml_length);
			printf("%s", xml_doc);
			free(xml_doc);
			xml_doc = NULL;
			plist_free(node);
			node = NULL;
		}
	}
*/
	if(lockdownd_get_value(client, "com.apple.mobile.iTunes", key, &node) == LOCKDOWN_E_SUCCESS && node) {
		// important fields: FairPlayCertificate, FairPlayGUID, FairPlayID, MinITunesVersion
		char *tmp_value=NULL;
		plist_t item = plist_dict_get_item(node, "FairPlayCertificate");
		if (!item) printf("Failed to get FairPlayCertificate\n");
		plist_to_xml(item, &xml_doc, &xml_length);
		write_xml_file("FairPlayCertificate.crt", xml_doc, xml_length);
		//plist_free(item);
		item = plist_dict_get_item(node, "FairPlayGUID");
		//plist_get_string_val(item, &tmp_value);	
		//printf("FairPlayGUID = %s\n", tmp_value);
		plist_free(node);
		node = NULL;
	}

	if ((lockdownd_get_value(client, NULL, "ActivationInfo", &node) != LOCKDOWN_E_SUCCESS) || !node || (plist_get_node_type(node) != PLIST_DICT)) {
		fprintf(stderr, "%s: Unable to get ActivationInfo from lockdownd\n", __func__);
	} else {
		char *tmp_value=NULL;
		plist_t subitem;
		plist_t item = plist_dict_get_item(node, "ActivationInfoXML");
		if (!item) printf("Failed to get ActivationInfoXML\n");

                subitem = plist_dict_get_item(node, "FairPlayCertChain");
                if (!subitem) printf("Failed to get FairPlayCertChain\n");
		plist_get_data_val(subitem, &xml_doc, &len);
		write_xml_file("FairPlayCertChain.crt", xml_doc, (uint32_t)len);

		plist_get_data_val(item, &xml_doc, &len);
		item = NULL;

		// load ActivationInfoXML as plist
		plist_from_xml(xml_doc, len, &item);

		subitem = plist_dict_get_item(item, "FMiPAccountExists");
		if (!subitem) printf("Failed to get FMiPAccountExists\n");

		if (plist_get_node_type(subitem) == PLIST_BOOLEAN) {
			plist_set_bool_val(subitem, 255);
		} else {
			printf("FMiPAccountExists not boolean!\n");
		}

		subitem = plist_dict_get_item(item, "ActivationState");
		if (!subitem) printf("Failed to get ActivationState\n");

		if (plist_get_node_type(subitem) == PLIST_STRING) {
			plist_set_string_val(subitem, "Activated");
		} else {
			printf("ActivationState not string!\n");
		}

		plist_to_xml(item, &xml_doc, (uint32_t*)&len);
		write_xml_file("ActivationInfoXML.xml", xml_doc, (uint32_t)len);

		// get DeviceCertRequest
		subitem = plist_dict_get_item(item, "DeviceCertRequest");
                if (!subitem) printf("Failed to get DeviceCertRequest\n");
		plist_get_data_val(subitem, &xml_doc, &len);
		write_xml_file("DeviceCertRequest.cer", xml_doc, (uint32_t)len);

		//load_private_key("certs/signature_private.key");

		plist_free(node);
	}
	if (domain != NULL)
		free(domain);
	lockdownd_client_free(client);
	idevice_free(device);

	return 0;
}

