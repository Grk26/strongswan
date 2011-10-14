/*
 * Copyright (C) 2011 Sansar Choinyambuu
 * HSR Hochschule fuer Technik Rapperswil
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#define _GNU_SOURCE

#include <stdio.h>

#include "imc_attestation_process.h"

#include <ietf/ietf_attr_pa_tnc_error.h>
#include <pts/pts.h>

#include <tcg/tcg_pts_attr_proto_caps.h>
#include <tcg/tcg_pts_attr_meas_algo.h>
#include <tcg/tcg_pts_attr_dh_nonce_params_req.h>
#include <tcg/tcg_pts_attr_dh_nonce_params_resp.h>
#include <tcg/tcg_pts_attr_dh_nonce_finish.h>
#include <tcg/tcg_pts_attr_get_tpm_version_info.h>
#include <tcg/tcg_pts_attr_tpm_version_info.h>
#include <tcg/tcg_pts_attr_get_aik.h>
#include <tcg/tcg_pts_attr_aik.h>
#include <tcg/tcg_pts_attr_req_funct_comp_evid.h>
#include <tcg/tcg_pts_attr_gen_attest_evid.h>
#include <tcg/tcg_pts_attr_simple_comp_evid.h>
#include <tcg/tcg_pts_attr_simple_evid_final.h>
#include <tcg/tcg_pts_attr_req_file_meas.h>
#include <tcg/tcg_pts_attr_file_meas.h>
#include <tcg/tcg_pts_attr_req_file_meta.h>
#include <tcg/tcg_pts_attr_unix_file_meta.h>

#include <debug.h>

#define DEFAULT_NONCE_LEN		20
#define EXTEND_PCR				16

bool imc_attestation_process(pa_tnc_attr_t *attr, linked_list_t *attr_list,
							 imc_attestation_state_t *attestation_state,
							 pts_meas_algorithms_t supported_algorithms,
							 pts_dh_group_t supported_dh_groups,
							 linked_list_t *evidences)
{
	chunk_t attr_info;
	pts_t *pts;
	pts_error_code_t pts_error;
	bool valid_path;

	pts = attestation_state->get_pts(attestation_state);
	switch (attr->get_type(attr))
	{
		case TCG_PTS_REQ_PROTO_CAPS:
		{
			tcg_pts_attr_proto_caps_t *attr_cast;
			pts_proto_caps_flag_t imc_caps, imv_caps;

			attr_cast = (tcg_pts_attr_proto_caps_t*)attr;
			imv_caps = attr_cast->get_flags(attr_cast);
			imc_caps = pts->get_proto_caps(pts);
			pts->set_proto_caps(pts, imc_caps & imv_caps);

			/* Send PTS Protocol Capabilities attribute */
			attr = tcg_pts_attr_proto_caps_create(imc_caps & imv_caps, FALSE);
			attr_list->insert_last(attr_list, attr);
			break;
		}
		case TCG_PTS_MEAS_ALGO:
		{
			tcg_pts_attr_meas_algo_t *attr_cast;
			pts_meas_algorithms_t offered_algorithms, selected_algorithm;

			attr_cast = (tcg_pts_attr_meas_algo_t*)attr;
			offered_algorithms = attr_cast->get_algorithms(attr_cast);
			selected_algorithm = pts_meas_algo_select(supported_algorithms,
													  offered_algorithms);
			if (selected_algorithm == PTS_MEAS_ALGO_NONE)
			{
				attr = pts_hash_alg_error_create(supported_algorithms);
				attr_list->insert_last(attr_list, attr);
				break;
			}

			/* Send Measurement Algorithm Selection attribute */
			pts->set_meas_algorithm(pts, selected_algorithm);
			attr = tcg_pts_attr_meas_algo_create(selected_algorithm, TRUE);
			attr_list->insert_last(attr_list, attr);
			break;
		}
		case TCG_PTS_DH_NONCE_PARAMS_REQ:
		{
			tcg_pts_attr_dh_nonce_params_req_t *attr_cast;
			pts_dh_group_t offered_dh_groups, selected_dh_group;
			chunk_t responder_value, responder_nonce;
			int nonce_len, min_nonce_len;

			nonce_len = lib->settings->get_int(lib->settings,
								"libimcv.plugins.imc-attestation.nonce_len",
								 DEFAULT_NONCE_LEN);

			attr_cast = (tcg_pts_attr_dh_nonce_params_req_t*)attr;
			min_nonce_len = attr_cast->get_min_nonce_len(attr_cast);
			if (nonce_len < PTS_MIN_NONCE_LEN ||
				(min_nonce_len > 0 && nonce_len < min_nonce_len))
			{
				attr = pts_dh_nonce_error_create(nonce_len, PTS_MAX_NONCE_LEN);
				attr_list->insert_last(attr_list, attr);
				break;
			}

			offered_dh_groups = attr_cast->get_dh_groups(attr_cast);
			selected_dh_group = pts_dh_group_select(supported_dh_groups,
													offered_dh_groups);
			if (selected_dh_group == PTS_DH_GROUP_NONE)
			{
				attr = pts_dh_group_error_create(supported_dh_groups);
				attr_list->insert_last(attr_list, attr);
				break;
			}

			/* Create own DH factor and nonce */
			if (!pts->create_dh_nonce(pts, selected_dh_group, nonce_len))
			{
				return FALSE;
			}
			pts->get_my_public_value(pts, &responder_value, &responder_nonce);

			/* Send DH Nonce Parameters Response attribute */
			attr = tcg_pts_attr_dh_nonce_params_resp_create(selected_dh_group,
					 supported_algorithms, responder_nonce, responder_value);
			attr_list->insert_last(attr_list, attr);
			break;
		}
		case TCG_PTS_DH_NONCE_FINISH:
		{
			tcg_pts_attr_dh_nonce_finish_t *attr_cast;
			pts_meas_algorithms_t selected_algorithm;
			chunk_t initiator_nonce, initiator_value;
			int nonce_len;

			attr_cast = (tcg_pts_attr_dh_nonce_finish_t*)attr;
			selected_algorithm = attr_cast->get_hash_algo(attr_cast);
			if (!(selected_algorithm & supported_algorithms))
			{
				DBG1(DBG_IMC, "PTS-IMV selected unsupported DH hash algorithm");
				return FALSE;
			}
			pts->set_dh_hash_algorithm(pts, selected_algorithm);

			initiator_value = attr_cast->get_initiator_value(attr_cast);
			initiator_nonce = attr_cast->get_initiator_nonce(attr_cast);

			nonce_len = lib->settings->get_int(lib->settings,
								"libimcv.plugins.imc-attestation.nonce_len",
								 DEFAULT_NONCE_LEN);
			if (nonce_len != initiator_nonce.len)
			{
				DBG1(DBG_IMC, "initiator and responder DH nonces "
							  "have differing lengths");
				return FALSE;
			}
					
			pts->set_peer_public_value(pts, initiator_value, initiator_nonce);
			if (!pts->calculate_secret(pts))
			{
				return FALSE;
			}
			break;
		}
		case TCG_PTS_GET_TPM_VERSION_INFO:
		{
			chunk_t tpm_version_info, attr_info;

			if (!pts->get_tpm_version_info(pts, &tpm_version_info))
			{
				attr_info = attr->get_value(attr);
				attr = ietf_attr_pa_tnc_error_create(PEN_TCG,
							TCG_PTS_TPM_VERS_NOT_SUPPORTED, attr_info);
				attr_list->insert_last(attr_list, attr);
				break;
			}

			/* Send TPM Version Info attribute */
			attr = tcg_pts_attr_tpm_version_info_create(tpm_version_info);
			attr_list->insert_last(attr_list, attr);
			break;
		}
		case TCG_PTS_GET_AIK:
		{
			certificate_t *aik;

			aik = pts->get_aik(pts);
			if (!aik)
			{
				DBG1(DBG_IMC, "no AIK certificate or public key available");
				break;
			}

			/* Send AIK attribute */
			attr = tcg_pts_attr_aik_create(aik);
			attr_list->insert_last(attr_list, attr);
			break;
		}
		case TCG_PTS_REQ_FUNCT_COMP_EVID:
		{
			tcg_pts_attr_req_funct_comp_evid_t *attr_cast;
			pts_proto_caps_flag_t negotiated_caps;
			pts_attr_req_funct_comp_evid_flag_t flags;
			u_int32_t sub_comp_depth;
			u_int32_t comp_name_vendor_id;
			u_int8_t family;
			pts_qualifier_t qualifier;
			pts_funct_comp_name_t name;

			attr_info = attr->get_value(attr);
			attr_cast = (tcg_pts_attr_req_funct_comp_evid_t*)attr;
			negotiated_caps = pts->get_proto_caps(pts);
			flags = attr_cast->get_flags(attr_cast);

			if (flags & PTS_REQ_FUNC_COMP_FLAG_TTC)
			{
				attr = ietf_attr_pa_tnc_error_create(PEN_TCG,
								TCG_PTS_UNABLE_DET_TTC, attr_info);
				attr_list->insert_last(attr_list, attr);
				break;
			}
			if (flags & PTS_REQ_FUNC_COMP_FLAG_VER &&
				!(negotiated_caps & PTS_PROTO_CAPS_V))
			{
				attr = ietf_attr_pa_tnc_error_create(PEN_TCG,
								TCG_PTS_UNABLE_LOCAL_VAL, attr_info);
				attr_list->insert_last(attr_list, attr);
				break;
			}
			if (flags & PTS_REQ_FUNC_COMP_FLAG_CURR &&
				!(negotiated_caps & PTS_PROTO_CAPS_C))
			{
				attr = ietf_attr_pa_tnc_error_create(PEN_TCG,
								TCG_PTS_UNABLE_CUR_EVID, attr_info);
				attr_list->insert_last(attr_list, attr);
				break;
			}
			if (flags & PTS_REQ_FUNC_COMP_FLAG_PCR &&
				!(negotiated_caps & PTS_PROTO_CAPS_T))
			{
				attr = ietf_attr_pa_tnc_error_create(PEN_TCG,
								TCG_PTS_UNABLE_DET_PCR, attr_info);
				attr_list->insert_last(attr_list, attr);
				break;
			}

			sub_comp_depth = attr_cast->get_sub_component_depth(attr_cast);
			/* TODO: Implement checking of components with its sub-components */
			if (sub_comp_depth != 0)
			{
				DBG1(DBG_IMC, "current version of Attestation IMC does not support"
							  "sub component measurement deeper than zero. "
							   "Measuring top level component only.");
			}

			comp_name_vendor_id = attr_cast->get_comp_funct_name_vendor_id(attr_cast);
			if (comp_name_vendor_id != PEN_TCG)
			{
				DBG1(DBG_IMC, "current version of Attestation IMC supports"
							  "only functional component namings by TCG ");
				break;
			}

			family = attr_cast->get_family(attr_cast);
			if (family)
			{
				attr = ietf_attr_pa_tnc_error_create(PEN_TCG,
								TCG_PTS_INVALID_NAME_FAM, attr_info);
				attr_list->insert_last(attr_list, attr);
				break;
			}

			qualifier = attr_cast->get_qualifier(attr_cast);

			/* Check if Unknown or Wildcard was set for qualifier */
			if (qualifier.kernel && qualifier.sub_component &&
			   (qualifier.type & PTS_FUNC_COMP_TYPE_ALL))
			{
				DBG2(DBG_IMC, "wildcard was set for the qualifier of functional"
					" component. Identifying the component with name binary enumeration");
			}
			else if (!qualifier.kernel && !qualifier.sub_component &&
					(qualifier.type & PTS_FUNC_COMP_TYPE_UNKNOWN))
			{
				DBG2(DBG_IMC, "unknown was set for the qualifier of functional"
					" component. Identifying the component with name binary enumeration");
			}
			else
			{
				/* TODO: Implement what todo with received qualifier */
			}

			name = attr_cast->get_comp_funct_name(attr_cast);
			switch (name)
			{
				case PTS_FUNC_COMP_NAME_BIOS:
				{
					tcg_pts_attr_simple_comp_evid_params_t params;
					pts_qualifier_t qualifier;
					time_t measurement_time_t;
					struct tm *time_now;
					char *utc_time;
					hasher_t *hasher;
					u_char hash_output[HASH_SIZE_SHA384];
					hash_algorithm_t hash_alg;

					/* TODO: Implement BIOS measurement */
					DBG1(DBG_IMC, "experimental implementation:"
								 " Extend TPM with etc/tnc_config file");
					params.pcr_info_included = TRUE;
					params.flags = PTS_SIMPLE_COMP_EVID_FLAG_NO_VALID;
					params.depth = 0;
					params.vendor_id = PEN_TCG;
							
					qualifier.kernel = FALSE;
					qualifier.sub_component = FALSE;
					qualifier.type = PTS_FUNC_COMP_TYPE_TNC;
					params.qualifier = qualifier;
							
					params.name = PTS_FUNC_COMP_NAME_BIOS;
					params.extended_pcr = EXTEND_PCR;
					params.hash_algorithm = pts->get_meas_algorithm(pts);

					if (!params.pcr_info_included)
					{
						params.transformation = PTS_PCR_TRANSFORM_NO;
					}
					else if (pts->get_meas_algorithm(pts) & PTS_MEAS_ALGO_SHA1)
					{
						params.transformation = PTS_PCR_TRANSFORM_MATCH;
					}
					else if (pts->get_meas_algorithm(pts) & PTS_MEAS_ALGO_SHA256)
					{
						params.transformation = PTS_PCR_TRANSFORM_LONG;
					}
							
					/* Create a hasher */
					hash_alg = pts_meas_algo_to_hash(pts->get_meas_algorithm(pts));
					hasher = lib->crypto->create_hasher(lib->crypto, hash_alg);
					if (!hasher)
					{
						DBG1(DBG_IMC, "  hasher %N not available",
							 hash_algorithm_names, hash_alg);
						return FALSE;
					}

					if (!pts->hash_file(pts, hasher, "/etc/tnc_config", hash_output))
					{
						hasher->destroy(hasher);
						return FALSE;
					}
						
					measurement_time_t = time(NULL);
					if (!measurement_time_t)
					{
						params.measurement_time = chunk_create("0000-00-00T00:00:00Z", 20);
					}
					else
					{
						time_now = localtime(&measurement_time_t);
						if (asprintf(&utc_time, "%d-%2.2d-%2.2dT%2.2d:%2.2d:%2.2dZ",
												time_now->tm_year + 1900,
												time_now->tm_mon + 1,
												time_now->tm_mday,
												time_now->tm_hour,
												time_now->tm_min,
												time_now->tm_sec) < 0)
						{
							DBG1(DBG_IMC, "could not format local time to UTC");
							hasher->destroy(hasher);
							return FALSE;
						}
						params.measurement_time = chunk_create(utc_time, 20);
						params.measurement_time = chunk_clone(params.measurement_time);
						free(utc_time);
						
					}
						
					params.measurement = chunk_create(hash_output, hasher->get_hash_size(hasher));
					hasher->destroy(hasher);
							
					params.policy_uri = chunk_empty;
					if (!pts->read_pcr(pts, EXTEND_PCR, &params.pcr_before))
					{
						DBG1(DBG_IMC, "error occured while reading PCR: %d", EXTEND_PCR);
						return FALSE;
					}
							
					if (!pts->extend_pcr(pts, EXTEND_PCR,
						params.measurement, &params.pcr_after))
					{
						DBG1(DBG_IMC, "error occured while extending PCR: %d", EXTEND_PCR);
						return FALSE;
					}

					/* Buffer Simple Component Evidence attribute */
					attr = tcg_pts_attr_simple_comp_evid_create(params);
					evidences->insert_last(evidences, attr);
						
					break;
				}
				case PTS_FUNC_COMP_NAME_IGNORE:
				case PTS_FUNC_COMP_NAME_CRTM:
				case PTS_FUNC_COMP_NAME_PLATFORM_EXT:
				case PTS_FUNC_COMP_NAME_BOARD:
				case PTS_FUNC_COMP_NAME_INIT_LOADER:
				case PTS_FUNC_COMP_NAME_OPT_ROMS:
				default:
				{
					DBG1(DBG_IMC, "unsupported Functional Component Name");
					break;
				}
			}
			break;
		}
		case TCG_PTS_GEN_ATTEST_EVID:
		{
			enumerator_t *e;
			pts_simple_evid_final_flag_t flags;
			chunk_t pcr_composite, quote_signature;
			u_int32_t num_of_evidences, i = 0;
			u_int32_t *pcrs;

			/* Send buffered Simple Component Evidences */
			num_of_evidences = evidences->get_count(evidences);
			pcrs = (u_int32_t*)malloc(sizeof(u_int32_t)*num_of_evidences);
			
			e = evidences->create_enumerator(evidences);
			while (e->enumerate(e, &attr))
			{
				tcg_pts_attr_simple_comp_evid_t *attr_cast;
				u_int32_t extended_pcr;
						
				attr_cast = (tcg_pts_attr_simple_comp_evid_t*)attr;
				extended_pcr = attr_cast->get_extended_pcr(attr_cast);

				/* Add extended PCR number to PCR list to quote */
				/* Duplicated PCR numbers have no influence */
				pcrs[i] = extended_pcr;
				i++;
				/* Send Simple Compoenent Evidence */
				attr_list->insert_last(attr_list, attr);
			}
			
			/* Quote */
			if (!pts->quote_tpm(pts, pcrs, num_of_evidences, &pcr_composite, &quote_signature))
			{
				DBG1(DBG_IMC, "error occured during TPM quote operation");
				DESTROY_IF(e);
				DESTROY_IF(evidences);
				return FALSE;
			}
	
			/* Send Simple Evidence Final attribute */
			flags = PTS_SIMPLE_EVID_FINAL_FLAG_TPM_QUOTE_INFO;
			
			attr = tcg_pts_attr_simple_evid_final_create(FALSE, flags, 0,
								pcr_composite, quote_signature, chunk_empty);
			attr_list->insert_last(attr_list, attr);
					
			DESTROY_IF(e);
			DESTROY_IF(evidences);
					
			break;
		}
		case TCG_PTS_REQ_FILE_META:
		{
			tcg_pts_attr_req_file_meta_t *attr_cast;
			char *pathname;
			bool is_directory;
			u_int8_t delimiter;
			pts_file_meta_t *metadata;

			attr_info = attr->get_value(attr);
			attr_cast = (tcg_pts_attr_req_file_meta_t*)attr;
			is_directory = attr_cast->get_directory_flag(attr_cast);
			delimiter = attr_cast->get_delimiter(attr_cast);
			pathname = attr_cast->get_pathname(attr_cast);

			valid_path = pts->is_path_valid(pts, pathname, &pts_error);
			if (valid_path && pts_error)
			{
				attr = ietf_attr_pa_tnc_error_create(PEN_TCG,
										pts_error, attr_info);
				attr_list->insert_last(attr_list, attr);
				break;
			}
			else if (!valid_path)
			{
				break;
			}
			if (delimiter != SOLIDUS_UTF && delimiter != REVERSE_SOLIDUS_UTF)
			{
				attr = ietf_attr_pa_tnc_error_create(PEN_TCG,
										TCG_PTS_INVALID_DELIMITER, attr_info);
				attr_list->insert_last(attr_list, attr);
				break;
			}
			/* Get File Metadata and send them to PTS-IMV */
			DBG2(DBG_IMC, "metadata request for %s '%s'",
					is_directory ? "directory" : "file",
					pathname);
			metadata = pts->get_metadata(pts, pathname, is_directory);

			if (!metadata)
			{
				/* TODO handle error codes from measurements */
				return FALSE;
			}
			attr = tcg_pts_attr_unix_file_meta_create(metadata);
			attr->set_noskip_flag(attr, TRUE);
			attr_list->insert_last(attr_list, attr);

			break;
		}
		case TCG_PTS_REQ_FILE_MEAS:
		{
			tcg_pts_attr_req_file_meas_t *attr_cast;
			char *pathname;
			u_int16_t request_id;
			bool is_directory;
			u_int32_t delimiter;
			pts_file_meas_t *measurements;

			attr_info = attr->get_value(attr);
			attr_cast = (tcg_pts_attr_req_file_meas_t*)attr;
			is_directory = attr_cast->get_directory_flag(attr_cast);
			request_id = attr_cast->get_request_id(attr_cast);
			delimiter = attr_cast->get_delimiter(attr_cast);
			pathname = attr_cast->get_pathname(attr_cast);
			valid_path = pts->is_path_valid(pts, pathname, &pts_error);

			if (valid_path && pts_error)
			{
				attr = ietf_attr_pa_tnc_error_create(PEN_TCG,
										pts_error, attr_info);
				attr_list->insert_last(attr_list, attr);
				break;
			}
			else if (!valid_path)
			{
				break;
			}

			if (delimiter != SOLIDUS_UTF && delimiter != REVERSE_SOLIDUS_UTF)
			{
				attr = ietf_attr_pa_tnc_error_create(PEN_TCG,
										TCG_PTS_INVALID_DELIMITER, attr_info);
				attr_list->insert_last(attr_list, attr);
				break;
			}

			/* Do PTS File Measurements and send them to PTS-IMV */
			DBG2(DBG_IMC, "measurement request %d for %s '%s'",
				 request_id, is_directory ? "directory" : "file",
				 pathname);
			measurements = pts->do_measurements(pts, request_id,
									pathname, is_directory);
			if (!measurements)
			{
				/* TODO handle error codes from measurements */
				return FALSE;
			}
			attr = tcg_pts_attr_file_meas_create(measurements);
			attr->set_noskip_flag(attr, TRUE);
			attr_list->insert_last(attr_list, attr);
			break;
		}
		/* TODO: Not implemented yet */
		case TCG_PTS_REQ_INTEG_MEAS_LOG:
		/* Attributes using XML */
		case TCG_PTS_REQ_TEMPL_REF_MANI_SET_META:
		case TCG_PTS_UPDATE_TEMPL_REF_MANI:
		/* On Windows only*/
		case TCG_PTS_REQ_REGISTRY_VALUE:
		/* Received on IMV side only*/
		case TCG_PTS_PROTO_CAPS:
		case TCG_PTS_DH_NONCE_PARAMS_RESP:
		case TCG_PTS_MEAS_ALGO_SELECTION:
		case TCG_PTS_TPM_VERSION_INFO:
		case TCG_PTS_TEMPL_REF_MANI_SET_META:
		case TCG_PTS_AIK:
		case TCG_PTS_SIMPLE_COMP_EVID:
		case TCG_PTS_SIMPLE_EVID_FINAL:
		case TCG_PTS_VERIFICATION_RESULT:
		case TCG_PTS_INTEG_REPORT:
		case TCG_PTS_UNIX_FILE_META:
		case TCG_PTS_FILE_MEAS:
		case TCG_PTS_INTEG_MEAS_LOG:
		default:
			DBG1(DBG_IMC, "received unsupported attribute '%N'",
				tcg_attr_names, attr->get_type(attr));
			break;
	}
	return TRUE;
}
