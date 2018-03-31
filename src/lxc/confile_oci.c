/*
 * lxc: linux Container library
 * (C) Copyright IBM Corp. 2007, 2008
 *
 * Authors:
 * Daniel Lezcano <daniel.lezcano at free.fr>
 * Serge Hallyn <serge@hallyn.com>
 * Christian Brauner <christian.brauner@ubuntu.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#define _GNU_SOURCE

#define _GNU_SOURCE
#define __STDC_FORMAT_MACROS
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>

#include <jansson.h>

#include "conf.h"
#include "config.h"
#include "confile.h"
#include "log.h"
#include "parse.h"
#include "utils.h"

lxc_log_define(lxc_confile_oci, lxc);

static char *file_to_buf(const char *file, size_t *length)
{
	int fd;
	char *buf;
	struct stat st;
	int ret = 0;

	fd = open(file, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return NULL;

	ret = fstat(fd, &st);
	if (ret < 0) {
		close(fd);
		return NULL;
	}

	if (st.st_size == 0) {
		close(fd);
		return NULL;
	}

	buf = lxc_strmmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (buf == MAP_FAILED) {
		close(fd);
		return NULL;
	}

	*length = st.st_size;
	return buf;
}

int oci_config_read(const char *file, struct lxc_conf *conf)
{
	size_t length;
	char *buf;
	const char *key;
	json_t *root, *value;
	json_error_t error;
	int fret = -1;

	buf = file_to_buf(file, &length);
	if (!buf)
		return 1;

	root = json_loadb(buf, length, 0, &error);
	if (!root) {
		ERROR("Failed to load config file");
		return -1;
	}

	if (json_typeof(root) != JSON_OBJECT)
		return -EINVAL;

	json_object_foreach(root, key, value) {
		int ret;

		if (strcmp(key, "annotations") == 0) {
			/* noop */
		} else if (strcmp(key, "hostname") == 0) {
			if (json_typeof(value) != JSON_STRING)
				return -EINVAL;

			ret = set_config_uts_name("lxc.uts.name",
						  json_string_value(value),
						  conf, NULL);
			if (ret < 0)
				goto on_error;
		} else if (strcmp(key, "hooks") == 0) {
			if (json_typeof(value) != JSON_OBJECT)
				return -EINVAL;

		} else if (strcmp(key, "linux") == 0) {
			if (json_typeof(value) != JSON_OBJECT)
				return -EINVAL;

		} else if (strcmp(key, "mounts") == 0) {
			if (json_typeof(value) != JSON_ARRAY)
				return -EINVAL;

		} else if (strcmp(key, "process") == 0) {
			if (json_typeof(value) != JSON_OBJECT)
				return -EINVAL;

		} else if (strcmp(key, "root") == 0) {
			if (json_typeof(value) != JSON_OBJECT)
				return -EINVAL;

		} else if (strcmp(key, "ociVersion") == 0) {
			if (json_typeof(value) != JSON_STRING)
				return -EINVAL;

		} else if (strcmp(key, "platform") == 0) {
			if (json_typeof(value) != JSON_OBJECT)
				return -EINVAL;

		} else {
			INFO("Ignoring \"%s\"", key);
		}
	}

	fret = 0;

on_error:
	/* free shit */
	return fret;
}
