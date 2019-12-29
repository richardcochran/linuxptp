/**
 * @file serial.c
 * @note Copyright (C) 2020 Richard Cochran <richardcochran@gmail.com>
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <termios.h>

#include "print.h"
#include "serial.h"

#define CANONICAL 1

static int open_serial_baud(const char *name, tcflag_t baud, int icrnl, int hwfc)
{
	struct termios nterm;
	int fd;

	fd = open(name, O_RDWR | O_NOCTTY);
	if (fd < 0) {
		pr_err("cannot open %s : %m", name);
		return fd;
	}
	memset(&nterm, 0, sizeof(nterm));

	/* Input Modes */
	nterm.c_iflag = IGNPAR; /* Ignore framing errors and parity errors */
	if (icrnl) {
		/* Translate carriage return to newline on input */
		nterm.c_iflag |= ICRNL;
	}

	/* Output Modes */
	nterm.c_oflag = 0;

	/* Control Modes */
	nterm.c_cflag = baud;
	nterm.c_cflag |= CS8;    /* Character size */
	nterm.c_cflag |= CLOCAL; /* Ignore modem control lines */
	nterm.c_cflag |= CREAD;  /* Enable receiver */
	if (hwfc) {
		/* Enable RTS/CTS (hardware) flow control */
		nterm.c_cflag |= CRTSCTS;
	}

	/* Local Modes */
	if (CANONICAL) {
		nterm.c_lflag = ICANON; /* Enable canonical mode */
	}

	nterm.c_cc[VTIME] = 10;   /* timeout is 10 deciseconds */
	nterm.c_cc[VMIN] = 1;     /* blocking read until N chars received */
	tcflush(fd, TCIFLUSH);
	tcsetattr(fd, TCSANOW, &nterm);
	return fd;
}

int serial_open(const char *name, int bps, int icrnl, int hwfc)
{
	tcflag_t baud;

	switch (bps) {
	case 1200:
		baud = B1200;
		break;
	case 1800:
		baud = B1800;
		break;
	case 2400:
		baud = B2400;
		break;
	case 4800:
		baud = B4800;
		break;
	case 9600:
		baud = B9600;
		break;
	case 19200:
		baud = B19200;
		break;
	case 38400:
		baud = B38400;
		break;
	case 57600:
		baud = B57600;
		break;
	case 115200:
		baud = B115200;
		break;
	default:
		return -1;
	}
	return open_serial_baud(name, baud, icrnl, hwfc);
}
