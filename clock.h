/**
 * @file clock.h
 * @brief Implements a PTP clock.
 * @note Copyright (C) 2011 Richard Cochran <richardcochran@gmail.com>
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
#ifndef HAVE_CLOCK_H
#define HAVE_CLOCK_H

#include "dm.h"
#include "ds.h"
#include "config.h"
#include "monitor.h"
#include "notification.h"
#include "servo.h"
#include "tlv.h"
#include "tmv.h"
#include "transport.h"

struct ptp_message; /*forward declaration*/

/** Opaque type. */
struct clock;

enum clock_type {
	CLOCK_TYPE_ORDINARY   = 0x8000,
	CLOCK_TYPE_BOUNDARY   = 0x4000,
	CLOCK_TYPE_P2P        = 0x2000,
	CLOCK_TYPE_E2E        = 0x1000,
	CLOCK_TYPE_MANAGEMENT = 0x0800,
};

/**
 * Obtains a reference to the best foreign master of a clock.
 * @param c  The clock instance.
 * @return   A pointer to the data set of the foreign master,
 *           or NULL if none has been yet discovered.
 */
struct dataset *clock_best_foreign(struct clock *c);

/**
 * Obtains a reference to the port with the best foreign master.
 * @param c  The clock instance.
 * @return   A pointer to the port with the best foreign master,
 *           or NULL if none has been yet discovered.
 */
struct port *clock_best_port(struct clock *c);

/**
 * Obtain the clockClass attribute from a clock.
 * @param c  The clock instance.
 * @return   The value of the clock's class.
 */
UInteger8 clock_class(struct clock *c);

/**
 * Obtains a reference to the configuration database.
 * @param c  The clock instance.
 * @return   A pointer to the configuration, without fail.
 */
struct config *clock_config(struct clock *c);

/**
 * Obtains a reference to the current dataset.
 * @param c  The clock instance.
 * @return   A pointer to the current dataset, without fail.
 */
struct currentDS *clock_current_dataset(struct clock *c);

/**
 * Obtains the clock's data set comparison function.
 * @param c  The clock instance.
 * @return   A pointer to the data set comparison function, without fail.
 */
int (*clock_dscmp(struct clock *c))(struct dataset *a, struct dataset *b);

/**
 * Obtains the required time stamping mode.
 * @param c  The clock instance.
 * @return   The value of required time stamping mode, which is a bit mask
 *           of SOF_TIMESTAMPING_ flags.
 */
int clock_required_modes(struct clock *c);

/**
 * Create a clock instance. There can only be one clock in any system,
 * so subsequent calls will destroy the previous clock instance.
 *
 * @param type         Specifies which type of clock to create.
 * @param config       Pointer to the configuration database.
 * @param phc_device   PTP hardware clock device to use. Pass NULL for automatic
 *                     selection based on the network interface.
 * @return             A pointer to the single global clock instance.
 */
struct clock *clock_create(enum clock_type type, struct config *config,
			   const char *phc_device);

/**
 * Obtains a clock's default data set.
 * @param c  The clock instance.
 * @return   A pointer to the data set of the clock.
 */
struct dataset *clock_default_ds(struct clock *c);

/**
 * Free all of the resources associated with a clock.
 * @param c  The clock instance.
 */
void clock_destroy(struct clock *c);

/**
 * Obtain the domain number from a clock's default data set.
 * @param c  The clock instance.
 * @return   The PTP domain number.
 */
UInteger8 clock_domain_number(struct clock *c);

/**
 * Obtains a reference to the first port in the clock's list.
 * @param c  The clock instance.
 * @return   A pointer to a port, or NULL if no ports are present.
 */
struct port *clock_first_port(struct clock *c);

/**
 * Provide the follow_up info TLV from a slave port.
 * @param c  The clock instance.
 * @param f  Pointer to the TLV.
 */
void clock_follow_up_info(struct clock *c, struct follow_up_info_tlv *f);

/**
 * Determine if a clock is free running or not.
 * @param c  The clock instance.
 * @return   One if the clock is free running or zero otherwise.
 */
int clock_free_running(struct clock *c);

/**
 * Obtain the gmCapable flag from a clock's default data set.
 * This function is specific to the 802.1AS standard.
 * @param c  The clock instance.
 * @return One if the clock is capable of becoming grand master, zero otherwise.
 */
int clock_gm_capable(struct clock *c);

/**
 * Obtain a clock's identity from its default data set.
 * @param c  The clock instance.
 * @return   The clock's identity.
 */
struct ClockIdentity clock_identity(struct clock *c);

/**
 * Informs clock that a file descriptor of one of its ports changed. The
 * clock will rebuild its array of file descriptors to poll.
 * @param c    The clock instance.
 */
void clock_fda_changed(struct clock *c);

/**
 * Obtains the time of the latest synchronization.
 * @param c    The clock instance.
 * @return     The local time stamp of the last received Sync message.
 */
tmv_t clock_ingress_time(struct clock *c);

/**
 * Manage the clock according to a given message.
 * @param c    The clock instance.
 * @param p    The port on which the message arrived.
 * @param msg  A management message.
 * @return     One if the management action caused a change that
 *             implies a state decision event, zero otherwise.
 */
int clock_manage(struct clock *c, struct port *p, struct ptp_message *msg);

/**
 * Send notification about an event to all subscribers.
 * @param c      The clock instance.
 * @param msg    The PTP message to send, in network byte order.
 * @param event  The event that occured.
 */
void clock_send_notification(struct clock *c, struct ptp_message *msg,
			     enum notification event);

/**
 * Construct and send notification to subscribers about an event that
 * occured on the clock.
 * @param c      The clock instance.
 * @param event  The identification of the event.
 */
void clock_notify_event(struct clock *c, enum notification event);

/**
 * Obtain a clock's parent data set.
 * @param c  The clock instance.
 * @return   A pointer to the parent data set of the clock.
 */
struct parent_ds *clock_parent_ds(struct clock *c);

/**
 * Obtain the parent port identity from a clock's parent data set.
 * @param c  The clock instance.
 * @return   The parent port identity.
 */
struct PortIdentity clock_parent_identity(struct clock *c);

/**
 * Provide a data point to estimate the path delay.
 * @param c           The clock instance.
 * @param req         The transmission time of the delay request message.
 * @param rx          The reception time of the delay request message,
 *                    as reported in the delay response message, including
 *                    correction.
 */
void clock_path_delay(struct clock *c, tmv_t req, tmv_t rx);

/**
 * Provide the estimated peer delay from a slave port.
 * @param c           The clock instance.
 * @param ppd         The peer delay as measured on a slave port.
 * @param req         The transmission time of the pdelay request message.
 * @param rx          The reception time of the pdelay request message.
 * @param nrr         The neighbor rate ratio as measured on a slave port.
 */
void clock_peer_delay(struct clock *c, tmv_t ppd, tmv_t req, tmv_t rx,
		      double nrr);

/**
 * Set clock sde
 * @param c     A pointer to a clock instance obtained with clock_create().
 * @param sde   Pass one (1) if need a decision event and zero if not.
 */
void clock_set_sde(struct clock *c, int sde);

/**
 * Poll for events and dispatch them.
 * @param c A pointer to a clock instance obtained with clock_create().
 * @return  Zero on success, non-zero otherwise.
 */
int clock_poll(struct clock *c);

/**
 * Obtain the servo struct.
 * @param c The clock instance.
 * @return  A pointer to the clock's servo.
 */
struct servo *clock_servo(struct clock *c);

/**
 * Obtain the current state of clock's servo.
 * @param c The clock instance.
 * @return  The current state of the clock's servo.
 */
enum servo_state clock_servo_state(struct clock *c);

/**
 * Obtain the slave monitor instance from a clock.
 * @param c The clock instance.
 * @return  The slave monitor associated with the clock.
 */
struct monitor *clock_slave_monitor(struct clock *c);

/**
 * Obtain the slave-only flag from a clock's default data set.
 * @param c  The clock instance.
 * @return   The value of the clock's slave-only flag.
 */
int clock_slave_only(struct clock *c);

/**
 * Obtain the max steps removed field from a clock's default data set.
 * @param c  The clock instance.
 * @return   The value of the clock's max steps removed field.
 */
UInteger8 clock_max_steps_removed(struct clock *c);

/**
 * Obtain the clock class threshold field from a clock's default data set.
 * @param c  The clock instance.
 * @return   Configured clock class threshold value.
 */
UInteger8 clock_get_clock_class_threshold(struct clock *c);

/**
 * Obtain the steps removed field from a clock's current data set.
 * @param c  The clock instance.
 * @return   The value of the clock's steps removed field.
 */
UInteger16 clock_steps_removed(struct clock *c);

/**
 * Obtain the Time Stamp Processor instance from a clock.
 * @param c The clock instance.
 * @return  The Time Stamp Processor associated with the clock.
 */
struct tsproc *clock_get_tsproc(struct clock *c);

/**
 * Switch to a new PTP Hardware Clock, for use with the "jbod" mode.
 * @param c          The clock instance.
 * @param phc_index  The index of the PHC device to use.
 * @return           Zero on success, non-zero otherwise.
 */
int clock_switch_phc(struct clock *c, int phc_index);

/**
 * Provide a data point to synchronize the clock.
 * @param c            The clock instance to synchronize.
 * @param ingress      The ingress time stamp on the sync message.
 * @param origin       The reported transmission time of the sync message,
                       including any corrections.
 * @param correction1  The correction field of the sync message.
 * @param correction2  The correction field of the follow up message.
 *                     Pass zero in the case of one step operation.
 * @return             The state of the clock's servo.
 */
enum servo_state clock_synchronize(struct clock *c, tmv_t ingress,
				   tmv_t origin);

/**
 * Inform a slaved clock about the master's sync interval.
 * @param c  The clock instance.
 * @param n  The logarithm base two of the sync interval.
 */
void clock_sync_interval(struct clock *c, int n);

/**
 * Update the clock leap bits and UTC offset after a leap second
 * if operating as a grandmaster.
 * @param c  The clock instance.
 */
void clock_update_leap_status(struct clock *c);

/**
 * Obtain a clock's time properties data set.
 * @param c  The clock instance.
 * @return   A copy of the clock's time properties data set.
 */
struct timePropertiesDS clock_time_properties(struct clock *c);

/**
 * Update a clock's time properties data set.
 * @param c   The clock instance.
 * @param tds The new time properties data set for the clock.
 */
void clock_update_time_properties(struct clock *c, struct timePropertiesDS tds);

/**
 * Obtain a clock's description.
 * @param c  The clock instance.
 * @return   A pointer to the clock_description of the clock.
 */
struct clock_description *clock_description(struct clock *c);

/**
 * Obtain the type of a clock.
 * @param c  The clock instance.
 * @return   One of the @ref clock_type enumeration values.
 */
enum clock_type clock_type(struct clock *c);

/**
 * Perform a sanity check on a time stamp made by a clock.
 * @param c  The clock instance.
 * @param ts The time stamp.
 */
void clock_check_ts(struct clock *c, uint64_t ts);

/**
 * Obtain ratio between master's frequency and current clock frequency.
 * @param c  The clock instance.
 * @return   The rate ratio, 1.0 is returned when not known.
 */
double clock_rate_ratio(struct clock *c);

#endif
