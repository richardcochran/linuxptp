/**
 * @file interface.h
 * @brief Implements network interface data structures.
 * @note Copyright (C) 2020 Richard Cochran <richardcochran@gmail.com>
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#ifndef HAVE_INTERFACE_H
#define HAVE_INTERFACE_H

#include <stdbool.h>
#include <sys/queue.h>
#include "sk.h"

#define MAX_IFNAME_SIZE 108 /* = UNIX_PATH_MAX */

#if (IF_NAMESIZE > MAX_IFNAME_SIZE)
#error if_namesize larger than expected.
#endif

/** Opaque type */
struct interface;

/**
 * Creates an instance of an interface.
 * @param name  The device which indentifies this interface.
 * @return      A pointer to an interface instance on success, NULL otherwise.
 */
struct interface *interface_create(const char *name);

/**
 * Destroys an instance of an interface.
 * @param iface  A pointer obtained via interface_create().
 */
void interface_destroy(struct interface *iface);

/**
 * Ensures that an interface has a proper time stamping label.
 * @param iface  The interface of interest.
 */
void interface_ensure_tslabel(struct interface *iface);

/**
 * Populate the time stamping information of a given interface.
 * @param iface  The interface of interest.
 * @return       zero on success, negative on failure.
 */
int interface_get_tsinfo(struct interface *iface);

/**
 * Obtain the time stamping label of a network interface.  This can be
 * different from the name of the interface when bonding is in effect.
 *
 * @param iface  The interface of interest.
 * @return       The time stamping device name of the network interface.
 */
const char *interface_label(struct interface *iface);

/**
 * Obtains the name of a network interface.
 * @param iface  The interface of interest.
 * @return       The device name of the network interface.
 */
const char *interface_name(struct interface *iface);

/**
 * Obtains the index of a PTP Hardware Clock device from a network interface.
 * @param iface  The interface of interest.
 * @return       The PHC index of the interface.
 */
int interface_phc_index(struct interface *iface);

/**
 * Set the time stamping label of a given interface.
 * @param iface  The interface of interest.
 * @param name   The desired label for the interface.
 */
void interface_set_label(struct interface *iface, const char *label);

/**
 * Tests whether an interface's time stamping information is valid or not.
 * @param iface  The interface of interest.
 * @return       True if the time stamping information is valid, false otherwise.
 */
bool interface_tsinfo_valid(struct interface *iface);

/**
 * Tests whether an interface supports a set of given time stamping modes.
 * @param iface  The interface of interest.
 * @param modes  Bit mask of SOF_TIMESTAMPING_ flags.
 * @return       True if the time stamping modes are supported, false otherwise.
 */
bool interface_tsmodes_supported(struct interface *iface, int modes);

#endif
