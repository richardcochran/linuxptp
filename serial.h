/**
 * @file serial.h
 * @note Copyright (C) 2020 Richard Cochran <richardcochran@gmail.com>
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#ifndef HAVE_SERIAL_H
#define HAVE_SERIAL_H

/**
 * Opens a serial port device.
 * @param name		Serial port device to open.
 * @param bps		Baud rate in bits per second.
 * @param icrnl		Pass 1 to map CR to NL on input, zero otherwise.
 * @param hwfc		Pass 1 to enable hardware flow control, zero otherwise.
 * @return		An open file descriptor on success, -1 otherwise.
 */
int serial_open(const char *name, int bps, int icrnl, int hwfc);

#endif
