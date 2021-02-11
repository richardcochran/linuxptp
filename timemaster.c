/**
 * @file timemaster.c
 * @brief Program to run NTP with PTP as reference clocks.
 * @note Copyright (C) 2014 Miroslav Lichvar <mlichvar@redhat.com>
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

#include <ctype.h>
#include <errno.h>
#include <libgen.h>
#include <limits.h>
#include <time.h>
#include <linux/net_tstamp.h>
#include <net/if.h>
#include <signal.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "print.h"
#include "rtnl.h"
#include "sk.h"
#include "util.h"
#include "version.h"

#define DEFAULT_RUNDIR "/var/run/timemaster"

#define DEFAULT_FIRST_SHM_SEGMENT 0
#define DEFAULT_RESTART_PROCESSES 1

#define DEFAULT_NTP_PROGRAM CHRONYD
#define DEFAULT_NTP_MINPOLL 6
#define DEFAULT_NTP_MAXPOLL 10
#define DEFAULT_PTP_DELAY 1e-4
#define DEFAULT_PTP_NTP_POLL 2
#define DEFAULT_PTP_PHC2SYS_POLL 0

#define DEFAULT_CHRONYD_SETTINGS \
	"makestep 1 3"
#define DEFAULT_NTPD_SETTINGS \
	"restrict default nomodify notrap nopeer noquery", \
	"restrict 127.0.0.1", \
	"restrict ::1"
#define DEFAULT_PTP4L_OPTIONS "-l", "5"
#define DEFAULT_PHC2SYS_OPTIONS "-l", "5"

enum source_type {
	NTP_SERVER,
	PTP_DOMAIN,
};

enum ntp_program {
	CHRONYD,
	NTPD,
};

struct ntp_server {
	char *address;
	int minpoll;
	int maxpoll;
	int iburst;
	char *ntp_options;
};

struct ptp_domain {
	int domain;
	int ntp_poll;
	int phc2sys_poll;
	double delay;
	char **interfaces;
	char **ptp4l_settings;
	char *ntp_options;
};

struct source {
	enum source_type type;
	union {
		struct ntp_server ntp;
		struct ptp_domain ptp;
	};
};

struct program_config {
	char *path;
	char **options;
	char **settings;
};

struct timemaster_config {
	struct source **sources;
	enum ntp_program ntp_program;
	char *rundir;
	int first_shm_segment;
	int restart_processes;
	struct program_config chronyd;
	struct program_config ntpd;
	struct program_config phc2sys;
	struct program_config ptp4l;
};

struct config_file {
	char *path;
	char *content;
};

struct script {
	struct config_file **configs;
	char ***commands;
	int **command_groups;
	int restart_groups;
	int no_restart_group;
};

static void free_parray(void **a)
{
	void **p;

	for (p = a; *p; p++)
		free(*p);
	free(a);
}

static void extend_string_array(char ***a, char **strings)
{
	char **s;

	for (s = strings; *s; s++)
		parray_append((void ***)a, xstrdup(*s));
}

static void extend_config_string(char **s, char **lines)
{
	for (; *lines; lines++)
		string_appendf(s, "%s\n", *lines);
}

static int parse_bool(char *s, int *b)
{
	if (get_ranged_int(s, b, 0, 1) != PARSED_OK)
		return 1;

	return 0;
}

static int parse_int(char *s, int *i)
{
	if (get_ranged_int(s, i, INT_MIN, INT_MAX) != PARSED_OK)
		return 1;

	return 0;
}

static int parse_double(char *s, double *d)
{
	if (get_ranged_double(s, d, INT_MIN, INT_MAX) != PARSED_OK)
		return 1;

	return 0;
}

static char *parse_word(char *s)
{
	while (*s && !isspace(*s))
		s++;
	while (*s && isspace(*s))
		*(s++) = '\0';
	return s;
}

static void parse_words(char *s, char ***a)
{
	char *w;

	if (**a) {
		free_parray((void **)(*a));
		*a = (char **)parray_new();
	}
	while (*s) {
		w = s;
		s = parse_word(s);
		parray_append((void ***)a, xstrdup(w));
	}
}

static void replace_string(char *s, char **str)
{
	if (*str)
		free(*str);
	*str = xstrdup(s);
}

static char *parse_section_name(char *s)
{
	char *s1, *s2;

	s1 = s + 1;
	for (s2 = s1; *s2 && *s2 != ']'; s2++)
		;
	*s2 = '\0';

	return xstrdup(s1);
}

static void parse_setting(char *s, char **name, char **value)
{
	*name = s;
	for (*value = s; **value && !isspace(**value); (*value)++)
		;
	for (; **value && !isspace(**value); (*value)++)
		;
	for (; **value && isspace(**value); (*value)++)
		**value = '\0';
}

static void source_destroy(struct source *source)
{
	switch (source->type) {
	case NTP_SERVER:
		free(source->ntp.address);
		free(source->ntp.ntp_options);
		break;
	case PTP_DOMAIN:
		free_parray((void **)source->ptp.interfaces);
		free_parray((void **)source->ptp.ptp4l_settings);
		free(source->ptp.ntp_options);
		break;
	}
	free(source);
}

static struct source *source_ntp_parse(char *parameter, char **settings)
{
	char *name, *value;
	struct source *source;
	int r = 0;

	if (!*parameter) {
		pr_err("missing address for ntp_server");
		return NULL;
	}

	source = xmalloc(sizeof(*source));
	source->type = NTP_SERVER;
	source->ntp.address = xstrdup(parameter);
	source->ntp.minpoll = DEFAULT_NTP_MINPOLL;
	source->ntp.maxpoll = DEFAULT_NTP_MAXPOLL;
	source->ntp.iburst = 0;
	source->ntp.ntp_options = xstrdup("");

	for (; *settings; settings++) {
		parse_setting(*settings, &name, &value);
		if (!strcasecmp(name, "minpoll")) {
			r = parse_int(value, &source->ntp.minpoll);
		} else if (!strcasecmp(name, "maxpoll")) {
			r = parse_int(value, &source->ntp.maxpoll);
		} else if (!strcasecmp(name, "iburst")) {
			r = parse_bool(value, &source->ntp.iburst);
		} else if (!strcasecmp(name, "ntp_options")) {
			replace_string(value, &source->ntp.ntp_options);
		} else {
			pr_err("unknown ntp_server setting %s", name);
			goto failed;
		}
		if (r) {
			pr_err("invalid value %s for %s", value, name);
			goto failed;
		}
	}

	return source;
failed:
	source_destroy(source);
	return NULL;
}

static struct source *source_ptp_parse(char *parameter, char **settings)
{
	char *name, *value;
	struct source *source;
	int r = 0;

	source = xmalloc(sizeof(*source));
	source->type = PTP_DOMAIN;
	source->ptp.delay = DEFAULT_PTP_DELAY;
	source->ptp.ntp_poll = DEFAULT_PTP_NTP_POLL;
	source->ptp.phc2sys_poll = DEFAULT_PTP_PHC2SYS_POLL;
	source->ptp.interfaces = (char **)parray_new();
	source->ptp.ptp4l_settings = (char **)parray_new();
	source->ptp.ntp_options = xstrdup("");

	if (parse_int(parameter, &source->ptp.domain)) {
		pr_err("invalid ptp_domain number %s", parameter);
		goto failed;
	}

	for (; *settings; settings++) {
		parse_setting(*settings, &name, &value);
		if (!strcasecmp(name, "delay")) {
			r = parse_double(value, &source->ptp.delay);
		} else if (!strcasecmp(name, "ntp_poll")) {
			r = parse_int(value, &source->ptp.ntp_poll);
		} else if (!strcasecmp(name, "phc2sys_poll")) {
			r = parse_int(value, &source->ptp.phc2sys_poll);
		} else if (!strcasecmp(name, "ptp4l_option")) {
			parray_append((void ***)&source->ptp.ptp4l_settings,
				      xstrdup(value));
		} else if (!strcasecmp(name, "ntp_options")) {
			replace_string(value, &source->ptp.ntp_options);
		} else if (!strcasecmp(name, "interfaces")) {
			parse_words(value, &source->ptp.interfaces);
		} else {
			pr_err("unknown ptp_domain setting %s", name);
			goto failed;
		}

		if (r) {
			pr_err("invalid value %s for %s", value, name);
			goto failed;
		}
	}

	if (!*source->ptp.interfaces) {
		pr_err("no interfaces specified for ptp_domain %d",
		       source->ptp.domain);
		goto failed;
	}

	return source;
failed:
	source_destroy(source);
	return NULL;
}

static int parse_program_settings(char **settings,
				  struct program_config *config)
{
	char *name, *value;

	for (; *settings; settings++) {
		parse_setting(*settings, &name, &value);
		if (!strcasecmp(name, "path")) {
			replace_string(value, &config->path);
		} else if (!strcasecmp(name, "options")) {
			parse_words(value, &config->options);
		} else {
			pr_err("unknown program setting %s", name);
			return 1;
		}
	}

	return 0;
}

static int parse_timemaster_settings(char **settings,
				     struct timemaster_config *config)
{
	char *name, *value;
	int r = 0;

	for (; *settings; settings++) {
		parse_setting(*settings, &name, &value);
		if (!strcasecmp(name, "ntp_program")) {
			if (!strcasecmp(value, "chronyd")) {
				config->ntp_program = CHRONYD;
			} else if (!strcasecmp(value, "ntpd")) {
				config->ntp_program = NTPD;
			} else {
				pr_err("unknown ntp program %s", value);
				return 1;
			}
		} else if (!strcasecmp(name, "rundir")) {
			replace_string(value, &config->rundir);
		} else if (!strcasecmp(name, "first_shm_segment")) {
			r = parse_int(value, &config->first_shm_segment);
		} else if (!strcasecmp(name, "restart_processes")) {
			r = parse_int(value, &config->restart_processes);
		} else {
			pr_err("unknown timemaster setting %s", name);
			return 1;
		}
		if (r) {
			pr_err("invalid value %s for %s", value, name);
			return 1;
		}
	}

	return 0;
}

static char **parse_raw_settings(char **settings)
{
	char **setting, *s, **parsed_settings;

	parsed_settings = (char **)parray_new();

	for (setting = settings; *setting; setting++) {
		s = *setting;
		/* Unescape lines beginning with '>' */
		if (s[0] == '>')
			s++;
		parray_append((void ***)&parsed_settings, xstrdup(s));
	}

	return parsed_settings;
}

static int parse_section(char **settings, char *name,
			 struct timemaster_config *config)
{
	struct source *source = NULL;
	char ***settings_dst = NULL;
	char *parameter = parse_word(name);

	if (!strcasecmp(name, "ntp_server")) {
		source = source_ntp_parse(parameter, settings);
		if (!source)
			return 1;
	} else if (!strcasecmp(name, "ptp_domain")) {
		source = source_ptp_parse(parameter, settings);
		if (!source)
			return 1;
	} else if (!strcasecmp(name, "chrony.conf")) {
		settings_dst = &config->chronyd.settings;
	} else if (!strcasecmp(name, "ntp.conf")) {
		settings_dst = &config->ntpd.settings;
	} else if (!strcasecmp(name, "ptp4l.conf")) {
		settings_dst = &config->ptp4l.settings;
	} else if (!strcasecmp(name, "chronyd")) {
		if (parse_program_settings(settings, &config->chronyd))
			return 1;
	} else if (!strcasecmp(name, "ntpd")) {
		if (parse_program_settings(settings, &config->ntpd))
			return 1;
	} else if (!strcasecmp(name, "phc2sys")) {
		if (parse_program_settings(settings, &config->phc2sys))
			return 1;
	} else if (!strcasecmp(name, "ptp4l")) {
		if (parse_program_settings(settings, &config->ptp4l))
			return 1;
	} else if (!strcasecmp(name, "timemaster")) {
		if (parse_timemaster_settings(settings, config))
			return 1;
	} else {
		pr_err("unknown section %s", name);
		return 1;
	}

	if (source)
		parray_append((void ***)&config->sources, source);

	if (settings_dst) {
		free_parray((void **)*settings_dst);
		*settings_dst = parse_raw_settings(settings);
	}

	return 0;
}

static void init_program_config(struct program_config *config,
				const char *name, ...)
{
	const char *s;
	va_list ap;

	config->path = xstrdup(name);
	config->settings = (char **)parray_new();
	config->options = (char **)parray_new();

	va_start(ap, name);

	/* add default options and settings */
	while ((s = va_arg(ap, const char *)))
		parray_append((void ***)&config->options, xstrdup(s));
	while ((s = va_arg(ap, const char *)))
		parray_append((void ***)&config->settings, xstrdup(s));

	va_end(ap);
}

static void free_program_config(struct program_config *config)
{
	free(config->path);
	free_parray((void **)config->settings);
	free_parray((void **)config->options);
}

static void config_destroy(struct timemaster_config *config)
{
	struct source **sources;

	for (sources = config->sources; *sources; sources++)
		source_destroy(*sources);
	free(config->sources);

	free_program_config(&config->chronyd);
	free_program_config(&config->ntpd);
	free_program_config(&config->phc2sys);
	free_program_config(&config->ptp4l);

	free(config->rundir);
	free(config);
}

static struct timemaster_config *config_parse(char *path)
{
	struct timemaster_config *config = xcalloc(1, sizeof(*config));
	FILE *f;
	char buf[4096], *line, *section_name = NULL;
	char **section_lines = NULL;
	int ret = 0;

	config->sources = (struct source **)parray_new();
	config->ntp_program = DEFAULT_NTP_PROGRAM;
	config->rundir = xstrdup(DEFAULT_RUNDIR);
	config->first_shm_segment = DEFAULT_FIRST_SHM_SEGMENT;
	config->restart_processes = DEFAULT_RESTART_PROCESSES;

	init_program_config(&config->chronyd, "chronyd",
			    NULL, DEFAULT_CHRONYD_SETTINGS, NULL);
	init_program_config(&config->ntpd, "ntpd",
			    NULL, DEFAULT_NTPD_SETTINGS, NULL);
	init_program_config(&config->phc2sys, "phc2sys",
			    DEFAULT_PHC2SYS_OPTIONS, NULL, NULL);
	init_program_config(&config->ptp4l, "ptp4l",
			    DEFAULT_PTP4L_OPTIONS, NULL, NULL);

	f = fopen(path, "r");
	if (!f) {
		pr_err("failed to open %s: %m", path);
		free(config);
		return NULL;
	}

	while (fgets(buf, sizeof(buf), f)) {
		/* remove trailing and leading whitespace */
		for (line = buf + strlen(buf) - 1;
		     line >= buf && isspace(*line); line--)
			*line = '\0';
		for (line = buf; *line && isspace(*line); line++)
			;
		/* skip comments and empty lines */
		if (!*line || *line == '#')
			continue;

		if (*line == '[') {
			/* parse previous section before starting another */
			if (section_name) {
				if (parse_section(section_lines, section_name,
						  config)) {
					ret = 1;
					break;
				}
				free_parray((void **)section_lines);
				free(section_name);
			}
			section_name = parse_section_name(line);
			section_lines = (char **)parray_new();
			continue;
		}

		if (!section_lines) {
			pr_err("settings outside section");
			ret = 1;
			break;
		}

		parray_append((void ***)&section_lines, xstrdup(line));
	}

	if (!ret && section_name &&
	    parse_section(section_lines, section_name, config)) {
		ret = 1;
	}

	fclose(f);

	if (section_name)
		free(section_name);
	if (section_lines)
		free_parray((void **)section_lines);

	if (ret) {
		config_destroy(config);
		return NULL;
	}

	return config;
}

static char **get_ptp4l_command(struct program_config *config,
				struct config_file *file, char **interfaces,
				int hw_ts)
{
	char **command = (char **)parray_new();

	parray_append((void ***)&command, xstrdup(config->path));
	extend_string_array(&command, config->options);
	parray_extend((void ***)&command,
		      xstrdup("-f"), xstrdup(file->path),
		      xstrdup(hw_ts ? "-H" : "-S"), NULL);

	for (; *interfaces; interfaces++)
		parray_extend((void ***)&command,
			      xstrdup("-i"), xstrdup(*interfaces), NULL);

	return command;
}

static char **get_phc2sys_command(struct program_config *config, int domain,
				  int poll, int shm_segment, char *uds_path,
				  char *message_tag)
{
	char **command = (char **)parray_new();

	parray_append((void ***)&command, xstrdup(config->path));
	extend_string_array(&command, config->options);
	parray_extend((void ***)&command,
		      xstrdup("-a"), xstrdup("-r"),
		      xstrdup("-R"), string_newf("%.2f", poll > 0 ?
						1.0 / (1 << poll) : 1 << -poll),
		      xstrdup("-z"), xstrdup(uds_path),
		      xstrdup("-t"), xstrdup(message_tag),
		      xstrdup("-n"), string_newf("%d", domain),
		      xstrdup("-E"), xstrdup("ntpshm"),
		      xstrdup("-M"), string_newf("%d", shm_segment), NULL);

	return command;
}

static char *get_refid(char *prefix, unsigned int number)
{
	if (number < 10)
		return string_newf("%.3s%u", prefix, number);
	else if (number < 100)
		return string_newf("%.2s%u", prefix, number);
	else if (number < 1000)
		return string_newf("%.1s%u", prefix, number);
	return NULL;
};

static void add_command(char **command, int command_group,
			struct script *script)
{
	int *group;

	parray_append((void ***)&script->commands, command);

	group = xmalloc(sizeof(int));
	*group = command_group;
	parray_append((void ***)&script->command_groups, group);
}

static void add_shm_source(int shm_segment, int poll, int dpoll, double delay,
			   char *ntp_options, char *prefix,
			   struct timemaster_config *config, char **ntp_config)
{
	char *refid = get_refid(prefix, shm_segment);

	switch (config->ntp_program) {
	case CHRONYD:
		string_appendf(ntp_config,
			       "refclock SHM %d poll %d dpoll %d "
			       "refid %s precision 1.0e-9 delay %.1e %s\n",
			       shm_segment, poll, dpoll, refid, delay,
			       ntp_options);
		break;
	case NTPD:
		string_appendf(ntp_config,
			       "server 127.127.28.%d minpoll %d maxpoll %d "
			       "mode 1 %s\n"
			       "fudge 127.127.28.%d refid %s\n",
			       shm_segment, poll, poll, ntp_options,
			       shm_segment, refid);
		break;
	}

	free(refid);
}

static int add_ntp_source(struct ntp_server *source, char **ntp_config)
{
	pr_debug("adding NTP server %s", source->address);

	string_appendf(ntp_config, "server %s minpoll %d maxpoll %d %s %s\n",
		       source->address, source->minpoll, source->maxpoll,
		       source->iburst ? "iburst" : "", source->ntp_options);
	return 0;
}

static int add_ptp_source(struct ptp_domain *source,
			  struct timemaster_config *config, int *shm_segment,
			  int *command_group, int ***allocated_phcs,
			  char **ntp_config, struct script *script)
{
	struct config_file *config_file;
	char **command, *uds_path, *uds_path2, **interfaces, *message_tag;
	char ts_interface[IF_NAMESIZE];
	int i, j, num_interfaces, *phc, *phcs, hw_ts, sw_ts;
	struct sk_ts_info ts_info;

	pr_debug("adding PTP domain %d", source->domain);

	hw_ts = SOF_TIMESTAMPING_TX_HARDWARE | SOF_TIMESTAMPING_RX_HARDWARE |
		SOF_TIMESTAMPING_RAW_HARDWARE;
	sw_ts = SOF_TIMESTAMPING_TX_SOFTWARE | SOF_TIMESTAMPING_RX_SOFTWARE |
		SOF_TIMESTAMPING_SOFTWARE;

	for (num_interfaces = 0;
	     source->interfaces[num_interfaces]; num_interfaces++)
		;

	if (!num_interfaces)
		return 0;

	/* get PHCs used by specified interfaces */
	phcs = xmalloc(num_interfaces * sizeof(int));
	for (i = 0; i < num_interfaces; i++) {
		phcs[i] = -1;

		/*
		 * if it is a bonded interface, use the name of the active
		 * slave interface (which will be timestamping packets)
		 */
		if (!rtnl_get_ts_device(source->interfaces[i], ts_interface)) {
			pr_debug("slave interface of %s: %s",
				 source->interfaces[i], ts_interface);
		} else {
			snprintf(ts_interface, sizeof(ts_interface), "%s",
				 source->interfaces[i]);
		}

		/* check if the interface has a usable PHC */
		if (sk_get_ts_info(ts_interface, &ts_info)) {
			pr_err("failed to get time stamping info for %s",
			       ts_interface);
			free(phcs);
			return 1;
		}

		if (((ts_info.so_timestamping & hw_ts) != hw_ts)) {
			pr_debug("interface %s: no PHC", ts_interface);
			if ((ts_info.so_timestamping & sw_ts) != sw_ts) {
				pr_err("time stamping not supported on %s",
				       ts_interface);
				free(phcs);
				return 1;
			}
			continue;
		}

		pr_debug("interface %s: PHC %d", ts_interface,
			 ts_info.phc_index);

		/* and the PHC isn't already used in another source */
		for (j = 0; (*allocated_phcs)[j]; j++) {
			if (*(*allocated_phcs)[j] == ts_info.phc_index) {
				pr_debug("PHC %d already allocated",
					 ts_info.phc_index);
				break;
			}
		}
		if (!(*allocated_phcs)[j])
			phcs[i] = ts_info.phc_index;
	}

	for (i = 0; i < num_interfaces; i++) {
		/* skip if already used by ptp4l in this domain */
		if (phcs[i] == -2)
			continue;

		interfaces = (char **)parray_new();
		parray_append((void ***)&interfaces, source->interfaces[i]);

		/* merge all interfaces sharing PHC to one ptp4l command */
		if (phcs[i] >= 0) {
			for (j = i + 1; j < num_interfaces; j++) {
				if (phcs[i] == phcs[j]) {
					parray_append((void ***)&interfaces,
						      source->interfaces[j]);
					/* mark the interface as used */
					phcs[j] = -2;
				}
			}

			/* don't use this PHC in other sources */
			phc = xmalloc(sizeof(int));
			*phc = phcs[i];
			parray_append((void ***)allocated_phcs, phc);
		}

		uds_path = string_newf("%s/ptp4l.%d.socket",
				       config->rundir, *shm_segment);
		uds_path2 = string_newf("%s/ptp4lro.%d.socket",
					config->rundir, *shm_segment);

		message_tag = string_newf("[%d", source->domain);
		for (j = 0; interfaces[j]; j++)
			string_appendf(&message_tag, "%s%s", j ? "+" : ":",
				       interfaces[j]);
		string_appendf(&message_tag, "]");

		config_file = xmalloc(sizeof(*config_file));
		config_file->path = string_newf("%s/ptp4l.%d.conf",
						config->rundir, *shm_segment);

		config_file->content = xstrdup("[global]\n");
		if (*config->ptp4l.settings) {
			extend_config_string(&config_file->content,
					     config->ptp4l.settings);
			string_appendf(&config_file->content, "\n[global]\n");
		}
		extend_config_string(&config_file->content,
				     source->ptp4l_settings);
		string_appendf(&config_file->content,
			       "clientOnly 1\n"
			       "domainNumber %d\n"
			       "uds_address %s\n"
			       "uds_ro_address %s\n"
			       "message_tag %s\n",
			       source->domain, uds_path, uds_path2,
			       message_tag);

		if (phcs[i] >= 0) {
			/* HW time stamping */
			command = get_ptp4l_command(&config->ptp4l, config_file,
						    interfaces, 1);
			add_command(command, *command_group, script);

			command = get_phc2sys_command(&config->phc2sys,
						      source->domain,
						      source->phc2sys_poll,
						      *shm_segment, uds_path,
						      message_tag);
			add_command(command, (*command_group)++, script);
		} else {
			/* SW time stamping */
			command = get_ptp4l_command(&config->ptp4l, config_file,
						    interfaces, 0);
			add_command(command, (*command_group)++, script);

			string_appendf(&config_file->content,
				       "clock_servo ntpshm\n"
				       "ntpshm_segment %d\n", *shm_segment);
		}

		parray_append((void ***)&script->configs, config_file);

		add_shm_source(*shm_segment, source->ntp_poll,
			       source->phc2sys_poll, source->delay,
			       source->ntp_options, "PTP", config, ntp_config);

		(*shm_segment)++;

		free(message_tag);
		free(uds_path);
		free(uds_path2);
		free(interfaces);
	}

	free(phcs);

	return 0;
}

static char **get_chronyd_command(struct program_config *config,
				  struct config_file *file)
{
	char **command = (char **)parray_new();

	parray_append((void ***)&command, xstrdup(config->path));
	extend_string_array(&command, config->options);
	parray_extend((void ***)&command, xstrdup("-n"),
		      xstrdup("-f"), xstrdup(file->path), NULL);

	return command;
}

static char **get_ntpd_command(struct program_config *config,
			       struct config_file *file)
{
	char **command = (char **)parray_new();

	parray_append((void ***)&command, xstrdup(config->path));
	extend_string_array(&command, config->options);
	parray_extend((void ***)&command, xstrdup("-n"),
		      xstrdup("-c"), xstrdup(file->path), NULL);

	return command;
}

static struct config_file *add_ntp_program(struct timemaster_config *config,
					   struct script *script,
					   int command_group)
{
	struct config_file *ntp_config = xmalloc(sizeof(*ntp_config));
	char **command = NULL;

	ntp_config->content = xstrdup("");

	switch (config->ntp_program) {
	case CHRONYD:
		extend_config_string(&ntp_config->content,
				     config->chronyd.settings);
		ntp_config->path = string_newf("%s/chrony.conf",
					       config->rundir);
		command = get_chronyd_command(&config->chronyd, ntp_config);
		break;
	case NTPD:
		extend_config_string(&ntp_config->content,
				     config->ntpd.settings);
		ntp_config->path = string_newf("%s/ntp.conf", config->rundir);
		command = get_ntpd_command(&config->ntpd, ntp_config);
		break;
	}

	parray_append((void ***)&script->configs, ntp_config);
	add_command(command, command_group, script);

	return ntp_config;
}

static void script_destroy(struct script *script)
{
	char ***commands, **command;
	int **groups;
	struct config_file *config, **configs;

	for (configs = script->configs; *configs; configs++) {
		config = *configs;
		free(config->path);
		free(config->content);
		free(config);
	}
	free(script->configs);

	for (commands = script->commands; *commands; commands++) {
		for (command = *commands; *command; command++)
			free(*command);
		free(*commands);
	}
	free(script->commands);

	for (groups = script->command_groups; *groups; groups++)
		free(*groups);
	free(script->command_groups);

	free(script);
}

static struct script *script_create(struct timemaster_config *config)
{
	struct script *script = xmalloc(sizeof(*script));
	struct source *source, **sources;
	struct config_file *ntp_config = NULL;
	int **allocated_phcs = (int **)parray_new();
	int ret = 0, shm_segment, command_group = 0;

	script->configs = (struct config_file **)parray_new();
	script->commands = (char ***)parray_new();
	script->command_groups = (int **)parray_new();
	script->no_restart_group = command_group;
	script->restart_groups = config->restart_processes;

	ntp_config = add_ntp_program(config, script, command_group++);
	shm_segment = config->first_shm_segment;

	for (sources = config->sources; (source = *sources); sources++) {
		switch (source->type) {
		case NTP_SERVER:
			if (add_ntp_source(&source->ntp, &ntp_config->content))
				ret = 1;
			break;
		case PTP_DOMAIN:
			if (add_ptp_source(&source->ptp, config, &shm_segment,
					   &command_group, &allocated_phcs,
					   &ntp_config->content, script))
				ret = 1;
			break;
		}
	}

	free_parray((void **)allocated_phcs);

	if (ret) {
		script_destroy(script);
		return NULL;
	}

	return script;
}

static pid_t start_program(char **command, sigset_t *mask)
{
	char **arg, *s;
	pid_t pid;

#ifdef HAVE_POSIX_SPAWN
	posix_spawnattr_t attr;

	if (posix_spawnattr_init(&attr)) {
		pr_err("failed to init spawn attributes: %m");
		return 0;
	}

	if (posix_spawnattr_setsigmask(&attr, mask) ||
	    posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSIGMASK) ||
	    posix_spawnp(&pid, command[0], NULL, &attr, command, environ)) {
		pr_err("failed to spawn %s: %m", command[0]);
		posix_spawnattr_destroy(&attr);
		return 0;
	}

	posix_spawnattr_destroy(&attr);
#else
	pid = fork();

	if (pid < 0) {
		pr_err("fork() failed: %m");
		return 0;
	}

	if (!pid) {
		/* restore the signal mask */
		if (sigprocmask(SIG_SETMASK, mask, NULL) < 0) {
			pr_err("sigprocmask() failed: %m");
			exit(100);
		}

		execvp(command[0], (char **)command);

		pr_err("failed to execute %s: %m", command[0]);

		exit(101);
	}
#endif

	for (s = xstrdup(""), arg = command; *arg; arg++)
		string_appendf(&s, "%s ", *arg);

	pr_info("process %d started: %s", pid, s);

	free(s);

	return pid;
}

static int create_config_files(struct config_file **configs)
{
	struct config_file *config;
	FILE *file;
	char *tmp, *dir;
	struct stat st;

	for (; (config = *configs); configs++) {
		tmp = xstrdup(config->path);
		dir = dirname(tmp);
		if (stat(dir, &st) < 0 && errno == ENOENT &&
		    mkdir(dir, 0755) < 0) {
			pr_err("failed to create %s: %m", dir);
			free(tmp);
			return 1;
		}
		free(tmp);

		pr_debug("creating %s", config->path);

		file = fopen(config->path, "w");
		if (!file) {
			pr_err("failed to open %s: %m", config->path);
			return 1;
		}

		if (fwrite(config->content,
			   strlen(config->content), 1, file) != 1) {
			pr_err("failed to write to %s", config->path);
			fclose(file);
			return 1;
		}

		fclose(file);
	}

	return 0;
}

static int remove_config_files(struct config_file **configs)
{
	struct config_file *config;

	for (; (config = *configs); configs++) {
		pr_debug("removing %s", config->path);

		if (unlink(config->path))
			pr_err("failed to remove %s: %m", config->path);
	}

	return 0;
}

static int script_run(struct script *script)
{
	struct timespec ts_start, ts_now;
	sigset_t mask, old_mask;
	siginfo_t info;
	pid_t pid, *pids;
	int i, group, num_commands, status, quit = 0, ret = 0;

	for (num_commands = 0; script->commands[num_commands]; num_commands++)
		;

	if (!num_commands) {
		/* nothing to do */
		return 0;
	}

	if (create_config_files(script->configs))
		return 1;

	sigemptyset(&mask);
	sigaddset(&mask, SIGCHLD);
	sigaddset(&mask, SIGTERM);
	sigaddset(&mask, SIGQUIT);
	sigaddset(&mask, SIGINT);

	/* block the signals */
	if (sigprocmask(SIG_BLOCK, &mask, &old_mask) < 0) {
		pr_err("sigprocmask() failed: %m");
		return 1;
	}

	pids = xcalloc(num_commands, sizeof(*pids));

	for (i = 0; i < num_commands; i++) {
		pids[i] = start_program(script->commands[i], &old_mask);
		if (!pids[i]) {
			kill(getpid(), SIGTERM);
			break;
		}
	}

	clock_gettime(CLOCK_MONOTONIC, &ts_start);

	/* process the blocked signals */
	while (1) {
		if (sigwaitinfo(&mask, &info) < 0) {
			if (errno == EINTR)
				continue;
			pr_err("sigwaitinfo() failed: %m");
			break;
		}

		clock_gettime(CLOCK_MONOTONIC, &ts_now);

		if (info.si_signo != SIGCHLD) {
			if (quit)
				continue;

			quit = 1;
			pr_debug("exiting on signal %d", info.si_signo);

			/* terminate remaining processes */
			for (i = 0; i < num_commands; i++) {
				if (pids[i] > 0) {
					pr_debug("killing process %d", pids[i]);
					kill(pids[i], SIGTERM);
				}
			}

			continue;
		}

		/* wait for all terminated processes */
		while (1) {
			pid = waitpid(-1, &status, WNOHANG);
			if (pid <= 0)
				break;

			if (!WIFEXITED(status)) {
				pr_info("process %d terminated abnormally",
					pid);
			} else {
				pr_info("process %d terminated with status %d",
					pid, WEXITSTATUS(status));
			}

			for (i = 0; i < num_commands; i++) {
				if (pids[i] == pid)
					pids[i] = 0;
			}
		}

		/* wait for all processes to terminate when exiting */
		if (quit) {
			for (i = 0; i < num_commands; i++) {
				if (pids[i])
					break;
			}
			if (i == num_commands)
				break;

			pr_debug("waiting for other processes to terminate");
			continue;
		}

		/*
		 * terminate (and then restart if allowed) all processes in
		 * groups that have a terminated process
		 */
		for (group = 0; group < num_commands; group++) {
			int terminated = 0, running = 0;

			for (i = 0; i < num_commands; i++) {
				if (*(script->command_groups[i]) != group)
					continue;
				if (pids[i])
					running++;
				else
					terminated++;
			}

			if (!terminated)
				continue;

			/*
			 * exit with a non-zero status if the group should not
			 * be restarted (i.e. chronyd/ntpd), timemaster is
			 * running only for a short time (and it is likely a
			 * configuration error), or restarting is disabled
			 * completely
			 */
			if (group == script->no_restart_group ||
			    ts_now.tv_sec - ts_start.tv_sec <= 1 ||
			    !script->restart_groups) {
				kill(getpid(), SIGTERM);
				ret = 1;
				break;
			}

			for (i = 0; i < num_commands; i++) {
				if (*(script->command_groups[i]) != group)
					continue;

				/* terminate all processes in the group first */
				if (running && pids[i]) {
					pr_debug("killing process %d", pids[i]);
					kill(pids[i], SIGTERM);
				} else if (!running && !pids[i]) {
					pids[i] = start_program(script->commands[i],
								&old_mask);
					if (!pids[i])
						kill(getpid(), SIGTERM);

					/* limit restarting rate */
					sleep(1);
				}
			}
		}
	}

	free(pids);

	if (remove_config_files(script->configs))
		return 1;

	return ret;
}

static void script_print(struct script *script)
{
	char ***commands, **command;
	int **groups;
	struct config_file *config, **configs;

	for (configs = script->configs; *configs; configs++) {
		config = *configs;
		fprintf(stderr, "%s:\n\n%s\n", config->path, config->content);
	}

	fprintf(stderr, "commands:\n\n");
	for (commands = script->commands, groups = script->command_groups;
	     *commands; commands++, groups++) {
		fprintf(stderr, "[%d] ", **groups);
		for (command = *commands; *command; command++)
			fprintf(stderr, "%s ", *command);
		fprintf(stderr, "\n");
	}
}

static void usage(char *progname)
{
	fprintf(stderr,
		"\nusage: %s [options] -f file\n\n"
		" -f file      specify path to configuration file\n"
		" -n           only print generated files and commands\n"
		" -l level     set logging level (6)\n"
		" -m           print messages to stdout\n"
		" -q           do not print messages to syslog\n"
		" -v           print version and exit\n"
		" -h           print this message and exit\n",
		progname);
}

int main(int argc, char **argv)
{
	struct timemaster_config *config;
	struct script *script;
	char *progname, *config_path = NULL;
	int c, ret = 0, log_stdout = 0, log_syslog = 1, dry_run = 0;

	progname = strrchr(argv[0], '/');
	progname = progname ? progname + 1 : argv[0];

	print_set_progname(progname);
	print_set_verbose(1);
	print_set_syslog(0);

	while (EOF != (c = getopt(argc, argv, "f:nl:mqvh"))) {
		switch (c) {
		case 'f':
			config_path = optarg;
			break;
		case 'n':
			dry_run = 1;
			break;
		case 'l':
			print_set_level(atoi(optarg));
			break;
		case 'm':
			log_stdout = 1;
			break;
		case 'q':
			log_syslog = 0;
			break;
		case 'v':
			version_show(stdout);
			return 0;
		case 'h':
			usage(progname);
			return 0;
		default:
			usage(progname);
			return 1;
		}
	}

	if (!config_path) {
		pr_err("no configuration file specified");
		return 1;
	}

	config = config_parse(config_path);
	if (!config)
		return 1;

	script = script_create(config);
	config_destroy(config);
	if (!script)
		return 1;

	print_set_verbose(log_stdout);
	print_set_syslog(log_syslog);

	if (dry_run)
		script_print(script);
	else
		ret = script_run(script);

	script_destroy(script);

	if (!dry_run)
		pr_info("exiting");

	return ret;
}
