/**
 * @file tlv.c
 * @note Copyright (C) 2012 Richard Cochran <richardcochran@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#include <arpa/inet.h>

#include "tlv.h"

void tlv_post_recv(struct TLV *tlv)
{
	struct management_tlv *mgt;
	struct management_error_status *mes;

	switch (tlv->type) {
	case TLV_MANAGEMENT:
		mgt = (struct management_tlv *) tlv;
		mgt->id = ntohs(mgt->id);
		break;
	case TLV_MANAGEMENT_ERROR_STATUS:
		mes = (struct management_error_status *) tlv;
		mes->error = ntohs(mes->error);
		mes->id = ntohs(mes->id);
		break;
	case TLV_ORGANIZATION_EXTENSION:
	case TLV_REQUEST_UNICAST_TRANSMISSION:
	case TLV_GRANT_UNICAST_TRANSMISSION:
	case TLV_CANCEL_UNICAST_TRANSMISSION:
	case TLV_ACKNOWLEDGE_CANCEL_UNICAST_TRANSMISSION:
	case TLV_PATH_TRACE:
	case TLV_ALTERNATE_TIME_OFFSET_INDICATOR:
	case TLV_AUTHENTICATION:
	case TLV_AUTHENTICATION_CHALLENGE:
	case TLV_SECURITY_ASSOCIATION_UPDATE:
	case TLV_CUM_FREQ_SCALE_FACTOR_OFFSET:
	default:
		break;
	}
}

void tlv_pre_send(struct TLV *tlv)
{
	struct management_tlv *mgt;
	struct management_error_status *mes;

	switch (tlv->type) {
	case TLV_MANAGEMENT:
		mgt = (struct management_tlv *) tlv;
		mgt->id = htons(mgt->id);
		break;
	case TLV_MANAGEMENT_ERROR_STATUS:
		mes = (struct management_error_status *) tlv;
		mes->error = htons(mes->error);
		mes->id = htons(mes->id);
		break;
	case TLV_ORGANIZATION_EXTENSION:
	case TLV_REQUEST_UNICAST_TRANSMISSION:
	case TLV_GRANT_UNICAST_TRANSMISSION:
	case TLV_CANCEL_UNICAST_TRANSMISSION:
	case TLV_ACKNOWLEDGE_CANCEL_UNICAST_TRANSMISSION:
	case TLV_PATH_TRACE:
	case TLV_ALTERNATE_TIME_OFFSET_INDICATOR:
	case TLV_AUTHENTICATION:
	case TLV_AUTHENTICATION_CHALLENGE:
	case TLV_SECURITY_ASSOCIATION_UPDATE:
	case TLV_CUM_FREQ_SCALE_FACTOR_OFFSET:
	default:
		break;
	}
}
