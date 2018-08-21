/**
 * @file snmp4lptp_mib.h
 * @brief Common header file for all supported mibs in linuxptp
 * @note Copyright (C) 2018 Anders Selhammer <anders.selhammer@est.tech>
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
#ifndef HAVE_SNMP4LPTP_MIB_H
#define HAVE_SNMP4LPTP_MIB_H

#include "msg.h"

/*
 * function declarations
 */
struct ptp_message* snmp4lptp_run_pmc(char *cmd);

#endif /* HAVE_SNMP4LPTP_MIB_H */
