/*
 * @file phc_ctl.c
 * @brief Utility program to directly control and debug a PHC device.
 * @note Copyright (C) 2014 Jacob Keller <jacob.keller@gmail.com>
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
#include <errno.h>
#include <fcntl.h>
#include <float.h>
#include <signal.h>
#include <inttypes.h>
#include <limits.h>
#include <net/if.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <math.h>

#include <linux/pps.h>
#include <linux/ptp_clock.h>

#include "clockadj.h"
#include "missing.h"
#include "phc.h"
#include "print.h"
#include "sk.h"
#include "sysoff.h"
#include "util.h"
#include "version.h"

#define NSEC2SEC 1000000000.0

/* trap the alarm signal so that pause() will wake up on receipt */
static void handle_alarm(int s)
{
	return;
}

static void double_to_timespec(double d, struct timespec *ts)
{
	double fraction, whole;

	fraction = modf(d, &whole);

	/* cast the whole value to a time_t to store as seconds */
	ts->tv_sec = (time_t)whole;
	/* tv_nsec is a long, so we multiply the nanoseconds per second double
	 * value by our fractional component. This results in a correct
	 * timespec from the double representing seconds.
	 */
	ts->tv_nsec = (long)(NSEC2SEC * fraction);
}

static int install_handler(int signum, void(*handler)(int))
{
	struct sigaction action;
	sigset_t mask;

	/* Unblock the signal */
	sigemptyset(&mask);
	sigaddset(&mask, signum);
	sigprocmask(SIG_UNBLOCK, &mask, NULL);

	/* Install the signal handler */
	action.sa_handler = handler;
	action.sa_flags = 0;
	sigemptyset(&action.sa_mask);
	sigaction(signum, &action, NULL);

	return 0;
}

static int64_t calculate_offset(struct timespec *ts1,
				      struct timespec *rt,
				      struct timespec *ts2)
{
	int64_t interval;
	int64_t offset;

#define NSEC_PER_SEC 1000000000ULL
	/* calculate interval between clock realtime */
	interval = (ts2->tv_sec - ts1->tv_sec) * NSEC_PER_SEC;
	interval += ts2->tv_nsec - ts1->tv_nsec;

	/* assume PHC read occured half way between CLOCK_REALTIME reads */

	offset = (rt->tv_sec - ts1->tv_sec) * NSEC_PER_SEC;
	offset += (rt->tv_nsec - ts1->tv_nsec) - (interval / 2);

	return offset;
}

static void usage(const char *progname)
{
	fprintf(stderr,
		"\n"
		"usage: %s [options] <device> -- [command]\n\n"
		" device         ethernet or ptp clock device"
		"\n"
		" options\n"
		" -l [num]       set the logging level to 'num'\n"
		" -q             do not print messages to the syslog\n"
		" -Q             do not print messages to stdout\n"
		" -v             prints the software version and exits\n"
		" -h             prints this message and exits\n"
		"\n"
		" commands\n"
		" specify commands with arguments. Can specify multiple\n"
		" commands to be executed in order. Seconds are read as\n"
		" double precision floating point values.\n"
		"  set  [seconds]  set PHC time (defaults to time on CLOCK_REALTIME)\n"
		"  get             get PHC time\n"
		"  adj  <seconds>  adjust PHC time by offset\n"
		"  freq [ppb]      adjust PHC frequency (default returns current offset)\n"
		"  cmp             compare PHC offset to CLOCK_REALTIME\n"
		"  caps            display device capabilities (default if no command given)\n"
		"  wait <seconds>  pause between commands\n"
		"\n",
		progname);
}

typedef int (*cmd_func_t)(clockid_t, int, char *[]);
struct cmd_t {
	const char *name;
	const cmd_func_t function;
};

static cmd_func_t get_command_function(const char *name);
static inline int name_is_a_command(const char *name);

static int do_set(clockid_t clkid, int cmdc, char *cmdv[])
{
	struct timespec ts;
	double time_arg = 0;
	int args_to_eat = 0;

	enum parser_result r;

	memset(&ts, 0, sizeof(ts));

	/* if we have no more arguments, or the next argument is the ";"
	 * separator, then we run set as default parameter mode */
	if (cmdc < 1 || name_is_a_command(cmdv[0])) {
		clock_gettime(CLOCK_REALTIME, &ts);

		/* since we aren't using the options, we can simply ensure
		 * that we don't eat any arguments
		 */
		args_to_eat = 0;
	} else {
		/* parse the double */
		r = get_ranged_double(cmdv[0], &time_arg, 0.0, DBL_MAX);
		switch (r) {
		case PARSED_OK:
			break;
		case MALFORMED:
			pr_err("set: '%s' is not a valid double", cmdv[0]);
			return -2;
		case OUT_OF_RANGE:
			pr_err("set: '%s' is out of range", cmdv[0]);
			return -2;
		default:
			pr_err("set: couldn't process '%s'", cmdv[0]);
			return -2;
		}

		double_to_timespec(time_arg, &ts);

		/* in order for processing to work, we need to ensure the
		 * run_cmds loop eats the optional set argument
		 */
		args_to_eat = 1;
	}

	if (clock_settime(clkid, &ts)) {
		pr_err("set: failed to set clock time: %s",
			strerror(errno));
		return -1;
	} else {
		pr_notice("set clock time to %ld.%09ld or %s",
			ts.tv_sec, ts.tv_nsec, ctime(&ts.tv_sec));
	}

	return args_to_eat;
}

static int do_get(clockid_t clkid, int cmdc, char *cmdv[])
{
	struct timespec ts;

	memset(&ts, 0, sizeof(ts));
	if (clock_gettime(clkid, &ts)) {
		pr_err("get: failed to get clock time: %s",
			strerror(errno));

		return -1;
	} else {
		pr_notice("clock time is %ld.%09lu or %s",
			ts.tv_sec, ts.tv_nsec, ctime(&ts.tv_sec));
	}

	/* get operation does not require any arguments */
	return 0;
}

static int do_adj(clockid_t clkid, int cmdc, char *cmdv[])
{
	double time_arg;
	int64_t nsecs;
	enum parser_result r;

	if (cmdc < 1 || name_is_a_command(cmdv[0])) {
		pr_err("adj: missing required time argument");
		return -2;
	}

	/* parse the double time offset argument */
	r = get_ranged_double(cmdv[0], &time_arg, -DBL_MAX, DBL_MAX);
	switch (r) {
	case PARSED_OK:
		break;
	case MALFORMED:
		pr_err("adj: '%s' is not a valid double", cmdv[0]);
		return -2;
	case OUT_OF_RANGE:
		pr_err("adj: '%s' is out of range.", cmdv[0]);
		return -2;
	default:
		pr_err("adj: couldn't process '%s'", cmdv[0]);
		return -2;
	}

	nsecs = (int64_t)(NSEC2SEC * time_arg);

	clockadj_init(clkid);
	clockadj_step(clkid, nsecs);

	pr_notice("adjusted clock by %lf seconds", time_arg);

	/* adjustment always consumes one argument */
	return 1;
}

static int do_freq(clockid_t clkid, int cmdc, char *cmdv[])
{
	double ppb;
	enum parser_result r;

	clockadj_init(clkid);

	if (cmdc < 1 || name_is_a_command(cmdv[0])) {
		ppb = clockadj_get_freq(clkid);
		pr_err("clock frequency offset is %lfppb", ppb);

		/* no argument was used */
		return 0;
	}

	/* parse the double ppb argument */
	r = get_ranged_double(cmdv[0], &ppb, -NSEC2SEC, NSEC2SEC);
	switch (r) {
	case PARSED_OK:
		break;
	case MALFORMED:
		pr_err("freq: '%s' is not a valid double", cmdv[0]);
		return -2;
	case OUT_OF_RANGE:
		pr_err("freq: '%s' is out of range.", cmdv[0]);
		return -2;
	default:
		pr_err("freq: couldn't process '%s'", cmdv[0]);
		return -2;
	}

	clockadj_set_freq(clkid, ppb);
	pr_err("adjusted clock frequency offset to %lfppb", ppb);

	/* consumed one argument to determine the frequency adjustment value */
	return 1;
}

static int do_caps(clockid_t clkid, int cmdc, char *cmdv[])
{
	struct ptp_clock_caps caps;

	if (clkid == CLOCK_REALTIME) {
		pr_warning("CLOCK_REALTIME is not a PHC device.");
		return 0;
	}

	if (ioctl(CLOCKID_TO_FD(clkid), PTP_CLOCK_GETCAPS, &caps)) {
		pr_err("get capabilities failed: %s",
			strerror(errno));
		return -1;
	}

	pr_notice("\n"
		"capabilities:\n"
		"  %d maximum frequency adjustment (ppb)\n"
		"  %d programable alarms\n"
		"  %d external time stamp channels\n"
		"  %d programmable periodic signals\n"
		"  %s pulse per second support",
		caps.max_adj,
		caps.n_alarm,
		caps.n_ext_ts,
		caps.n_per_out,
		caps.pps ? "has" : "doesn't have");
	return 0;
}

static int do_cmp(clockid_t clkid, int cmdc, char *cmdv[])
{
	struct timespec ts, rta, rtb;
	int64_t sys_offset, delay = 0, offset;
	uint64_t sys_ts;
	int method;

	method = sysoff_probe(CLOCKID_TO_FD(clkid), 9);

	if (method >= 0 && sysoff_measure(CLOCKID_TO_FD(clkid), method, 9,
					  &sys_offset, &sys_ts, &delay) >= 0) {
		pr_notice( "offset from CLOCK_REALTIME is %"PRId64"ns\n",
			sys_offset);
		return 0;
	}

	memset(&ts, 0, sizeof(ts));
	memset(&ts, 0, sizeof(rta));
	memset(&ts, 0, sizeof(rtb));
	if (clock_gettime(CLOCK_REALTIME, &rta) ||
	    clock_gettime(clkid, &ts) ||
	    clock_gettime(CLOCK_REALTIME, &rtb)) {
		pr_err("cmp: failed clock reads: %s\n",
			strerror(errno));
		return -1;
	}

	offset = calculate_offset(&rta, &ts, &rtb);
	pr_notice( "offset from CLOCK_REALTIME is approximately %"PRId64"ns\n",
		offset);

	return 0;
}

static int do_wait(clockid_t clkid, int cmdc, char *cmdv[])
{
	double time_arg;
	struct timespec ts;
	struct itimerval timer;
	enum parser_result r;

	if (cmdc < 1 || name_is_a_command(cmdv[0])) {
		pr_err("wait: requires sleep duration argument\n");
		return -2;
	}

	memset(&timer, 0, sizeof(timer));

	/* parse the double time offset argument */
	r = get_ranged_double(cmdv[0], &time_arg, 0.0, DBL_MAX);
	switch (r) {
	case PARSED_OK:
		break;
	case MALFORMED:
		pr_err("wait: '%s' is not a valid double", cmdv[0]);
		return -2;
	case OUT_OF_RANGE:
		pr_err("wait: '%s' is out of range.", cmdv[0]);
		return -2;
	default:
		pr_err("wait: couldn't process '%s'", cmdv[0]);
		return -2;
	}

	double_to_timespec(time_arg, &ts);
	timer.it_value.tv_sec = ts.tv_sec;
	timer.it_value.tv_usec = ts.tv_nsec / 1000;
	setitimer(ITIMER_REAL, &timer, NULL);
	pause();

	/* the SIGALRM is already trapped during initialization, so we will
	 * wake up here once the alarm is handled.
	 */
	pr_notice( "process slept for %lf seconds\n", time_arg);

	return 1;
}

static const struct cmd_t all_commands[] = {
	{ "set", &do_set },
	{ "get", &do_get },
	{ "adj", &do_adj },
	{ "freq", &do_freq },
	{ "cmp", &do_cmp },
	{ "caps", &do_caps },
	{ "wait", &do_wait },
	{ 0, 0 }
};

static cmd_func_t get_command_function(const char *name)
{
	int i;
	cmd_func_t cmd = NULL;

	for (i = 0; all_commands[i].name != NULL; i++) {
		if (!strncmp(name,
			     all_commands[i].name,
			     strlen(all_commands[i].name)))
			cmd = all_commands[i].function;
	}

	return cmd;
}

static inline int name_is_a_command(const char *name)
{
	return get_command_function(name) != NULL;
}

static int run_cmds(clockid_t clkid, int cmdc, char *cmdv[])
{
	int i = 0, result = 0;
	cmd_func_t action = NULL;

	while (i < cmdc) {
		char *arg = cmdv[i];

		/* increment now to remove the command argument */
		i++;

		action = get_command_function(arg);
		if (action)
			result = action(clkid, cmdc - i, &cmdv[i]);
		else
			pr_err("unknown command %s.", arg);

		/* result is how many arguments were used up by the command,
		 * not including the ";". We will increment the loop counter
		 * to avoid processing the arguments as commands.
		 */
		if (result < 0)
			return result;
		else
			i += result;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	int c, cmdc, junk, print_level = LOG_INFO, result;
	char **cmdv, *default_cmdv[] = { "caps" };
	int use_syslog = 1, verbose = 1;
	const char *progname;
	clockid_t clkid;

	install_handler(SIGALRM, handle_alarm);

	/* Process the command line arguments. */
	progname = strrchr(argv[0], '/');
	progname = progname ? 1+progname : argv[0];
	while (EOF != (c = getopt(argc, argv,
				  "l:qQvh"))) {
		switch (c) {
		case 'l':
			if (get_arg_val_i(c, optarg, &print_level,
					  PRINT_LEVEL_MIN, PRINT_LEVEL_MAX))
				return -1;
			break;
		case 'q':
			use_syslog = 0;
			break;
		case 'Q':
			verbose = 0;
			break;
		case 'v':
			version_show(stdout);
			return 0;
		case 'h':
			usage(progname);
			return 0;
		default:
			usage(progname);
			return -1;
		}
	}

	print_set_progname(progname);
	print_set_verbose(verbose);
	print_set_syslog(use_syslog);
	print_set_level(print_level);

	if ((argc - optind) < 1) {
		usage(progname);
		return -1;
	}

	if ((argc - optind) == 1) {
		cmdv = default_cmdv;
		cmdc = 1;
	} else {
		cmdv = &argv[optind+1];
		cmdc = argc - optind - 1;
	}

	clkid = posix_clock_open(argv[optind], &junk);
	if (clkid == CLOCK_INVALID)
		return -1;

	/* pass the remaining arguments to the run_cmds loop */
	result = run_cmds(clkid, cmdc, cmdv);
	posix_clock_close(clkid);
	if (result < -1) {
		/* show usage when command fails */
		usage(progname);
		return result;
	}

	return 0;
}
