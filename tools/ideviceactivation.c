/*
 * ideviceactivation.c
 * A command line tool to handle the activation process
 *
 * Copyright (c) 2011-2015 Mirell Development, All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <plist/plist.h>
#include <libimobiledevice/lockdown.h>
#include <libimobiledevice/libimobiledevice.h>
#include <libideviceactivation.h>

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

static void print_usage(int argc, char **argv)
{
	char *name = NULL;
	
	name = strrchr(argv[0], '/');
	printf("Usage: %s COMMAND [OPTIONS]\n", (name ? name + 1: argv[0]));
	printf("Activate or deactivate a device.\n\n");
	printf("Where COMMAND is one of:\n");
	printf("  activate\t\tattempt to activate the device\n");
	printf("  deactivate\t\tdeactivate the device\n");
	printf("\nThe following OPTIONS are accepted:\n");
	printf("  -d, --debug\t\tenable communication debugging\n");
	printf("  -u, --udid UDID\ttarget specific device by its 40-digit device UDID\n");
	printf("  -s, --service URL\tuse activation webservice at URL instead of default\n");
	printf("  -v, --version\t\tprint version information and exit\n");
	printf("  -h, --help\t\tprints usage information\n");
	printf("\n");
	printf("Homepage: <http://libimobiledevice.org>\n");
}

int main(int argc, char *argv[])
{
	idevice_t device = NULL;
	idevice_error_t ret = IDEVICE_E_UNKNOWN_ERROR;
	lockdownd_client_t lockdown = NULL;
	idevice_activation_request_t request = NULL;
	idevice_activation_response_t response = NULL;
	const char* response_title = NULL;
	const char* response_description = NULL;
	char* field_key = NULL;
	char* field_label = NULL;
	char input[1024];
	plist_t fields = NULL;
	plist_dict_iter iter = NULL;
	plist_t record = NULL;
	char *udid = NULL;
	char *signing_service_url = NULL;
	char *response_buf = NULL;
	size_t response_size;
	char *activation_info = NULL, *activation_info_xml=NULL;
	char *activation_info_decoded=NULL;
	int i;
	int result = EXIT_FAILURE;

	typedef enum {
		OP_NONE = 0, OP_ACTIVATE, OP_DEACTIVATE
	} op_t;
	op_t op = OP_NONE;

	//idevice_set_debug_level(1);
	//idevice_activation_set_debug_level(1);

	/* parse cmdline args */
	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-d") || !strcmp(argv[i], "--debug")) {
			idevice_set_debug_level(1);
			idevice_activation_set_debug_level(1);
			continue;
		}
		else if (!strcmp(argv[i], "-u") || !strcmp(argv[i], "--udid")) {
			i++;
			if (!argv[i] || (strlen(argv[i]) != 40)) {
				print_usage(argc, argv);
				return EXIT_FAILURE;
			}
			udid = argv[i];
			continue;
		}
		else if (!strcmp(argv[i], "-s") || !strcmp(argv[i], "--service")) {
			i++;
			if (!argv[i]) {
				print_usage(argc, argv);
				return EXIT_FAILURE;
			}
			signing_service_url = argv[i];
			continue;
		}
		else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
			print_usage(argc, argv);
			return EXIT_SUCCESS;
		}
		else if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--version")) {
			printf("ideviceactivation %s\n", PACKAGE_VERSION);
			return EXIT_SUCCESS;
		}
		else if (!strcmp(argv[i], "activate")) {
			op = OP_ACTIVATE;
			continue;
		}
		else if (!strcmp(argv[i], "deactivate")) {
			op = OP_DEACTIVATE;
			continue;
		}
		else {
			print_usage(argc, argv);
			return EXIT_SUCCESS;
		}
	}

	if (op == OP_NONE) {
		print_usage(argc, argv);
		return EXIT_FAILURE;
	}

	if (udid) {
		ret = idevice_new(&device, udid);
		if (ret != IDEVICE_E_SUCCESS) {
			printf("No device found with UDID %s, is it plugged in?\n", udid);
			return EXIT_FAILURE;
		}
	}
	else
	{
		ret = idevice_new(&device, NULL);
		if (ret != IDEVICE_E_SUCCESS) {
			printf("No device found, is it plugged in?\n");
			return EXIT_FAILURE;
		}
	}

	if (LOCKDOWN_E_SUCCESS != lockdownd_client_new_with_handshake(device, &lockdown, "ideviceactivation")) {
		result = EXIT_FAILURE;
		goto cleanup;
	}

	switch (op) {
		case OP_DEACTIVATE:
/*
			// deactivate device using lockdown
			if (LOCKDOWN_E_SUCCESS != lockdownd_deactivate(lockdown)) {
				fprintf(stderr, "Failed to deactivate device.\n");
				result = EXIT_FAILURE;
				goto cleanup;
			}

			result = EXIT_SUCCESS;
			printf("Successfully deactivated device.\n");
*/
			break;
		case OP_ACTIVATE:
		default:
			// create activation request
			if (idevice_activation_request_new_from_lockdownd(
				IDEVICE_ACTIVATION_CLIENT_MOBILE_ACTIVATION, lockdown, &request) != IDEVICE_ACTIVATION_E_SUCCESS) {
				fprintf(stderr, "Failed to create activation request.\n");
				result = EXIT_FAILURE;
				goto cleanup;
			}

			if (request && signing_service_url) {
				idevice_activation_request_set_url(request, signing_service_url);
			}

			while(1) {
				if (idevice_activation_send_request(request, &response) != IDEVICE_ACTIVATION_E_SUCCESS) {
					fprintf(stderr, "Failed to send request or retrieve response.\n");
					// Here response might have some content that could't be correctly interpreted (parsed)
					// by the library. Printing out the content could help to identify the cause of the error.
					result = EXIT_FAILURE;
					goto cleanup;
				}

				if (idevice_activation_response_is_activation_acknowledged(response)) {
					printf("Activation server reports that device is already activated.\n");
					result = EXIT_SUCCESS;
					goto cleanup;
				}

				if (idevice_activation_response_has_errors(response)) {
					fprintf(stderr, "Activation server reports errors.\n");

					idevice_activation_response_get_title(response, &response_title);
					if (response_title) {
						fprintf(stderr, "\t%s\n", response_title);
					}

					idevice_activation_response_get_description(response, &response_description);
					if (response_description) {
						fprintf(stderr, "\t%s\n", response_description);
					}
					result = EXIT_FAILURE;
					goto cleanup;
				}

				idevice_activation_response_get_activation_record(response, &record);
				//idevice_activation_response_to_buffer(response, &response_buf, &response_size);
				if (record) {
				/*
					// activate device using lockdown
					if (LOCKDOWN_E_SUCCESS != lockdownd_activate(lockdown, record)) {
						fprintf(stderr, "Failed to activate device with record.\n");
						result = EXIT_FAILURE;
						goto cleanup;
					}

					// set ActivationStateAcknowledged if we succeeded
					if (LOCKDOWN_E_SUCCESS != lockdownd_set_value(lockdown, NULL, "ActivationStateAcknowledged", plist_new_bool(1))) {
						fprintf(stderr, "Failed to set ActivationStateAcknowledged on device.\n");
						result = EXIT_FAILURE;
						goto cleanup;
					}
				*/
					break;
				} else {
					/*
					idevice_activation_response_get_title(response, &response_title);
					if (response_title) {
						fprintf(stderr, "Server reports:\n%s\n", response_title);
					}

					idevice_activation_response_get_description(response, &response_description);
					if (response_description) {
						fprintf(stderr, "Server reports:\n%s\n", response_description);
					}
					*/

					idevice_activation_request_get_field(request, "activation-info", &activation_info_xml);
					fprintf(stderr, "%s\n", activation_info_xml);

					idevice_activation_response_get_fields(response, &fields);
					if (!fields || plist_dict_get_size(fields) == 0) {
						// we have no activation record, no reported erros, no acknowledgment and no fields to send
						fprintf(stderr, "Unknown error.\n");
						result = EXIT_FAILURE;
						goto cleanup;
					}

					plist_dict_new_iter(fields, &iter);
					if (!iter) {
						fprintf(stderr, "Unknown error.\n");
						result = EXIT_FAILURE;
						goto cleanup;
					}

					idevice_activation_request_free(request);
					request = NULL;
					if (idevice_activation_request_new(
						IDEVICE_ACTIVATION_CLIENT_MOBILE_ACTIVATION, &request) != IDEVICE_ACTIVATION_E_SUCCESS) {
						fprintf(stderr, "Could not create new request.\n");
						result = EXIT_FAILURE;
						goto cleanup;
					}

					idevice_activation_response_get_field(response, "activation-info-base64", &activation_info);
					//activation_info_decoded = malloc(Base64decode_len(activation_info));
					//Base64decode(activation_info_decoded, activation_info);	
					//fprintf(stderr, "%s\n", activation_info_decoded);

					idevice_activation_request_set_fields_from_response(request, response);
					/*
					do {
						field_key = NULL;
						plist_dict_next_item(fields, iter, &field_key, NULL);
						if (field_key) {
							idevice_activation_response_get_label(response, field_key, &field_label);
							printf("input %s: ", field_label ? field_label : field_key);
							//fflush(stdin);
							//scanf("%1023s", input);
							idevice_activation_request_set_field(request, field_key, input);
							if (field_label) {
								free(field_label);
								field_label = NULL;
							}
						}
					} while(field_key);
					*/
					free(iter);
					iter = NULL;
					idevice_activation_response_free(response);
					response = NULL;


					break;
				}

			}

			result = EXIT_SUCCESS;
			//printf("Successfully activated device.\n");
			break;
	}

cleanup:
	if (request)
		idevice_activation_request_free(request);

	if (response)
		idevice_activation_response_free(response);

	if (fields)
		plist_free(fields);

	if (field_label)
		free(field_label);

	if (iter)
		free(iter);

	if (record)
		plist_free(record);

	if (lockdown)
		lockdownd_client_free(lockdown);

	if (device)
		idevice_free(device);

	return result;
}
