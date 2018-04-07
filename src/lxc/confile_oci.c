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
#include "confile_utils.h"
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

static int lxc_oci_add_hook(json_t *elem, struct lxc_conf *conf, int type)
{
	int ret;
	const char *key;
	json_t *val;
	char *args = NULL, *env = NULL, *hook = NULL, *path = NULL;

	if (json_is_object(elem) == 0)
		return -1;

	json_object_foreach(elem, key, val) {
		size_t i;
		json_t *it;

		if (strcmp(key, "args") == 0) {
			if (json_is_array(val) == 0)
				goto on_error;

			json_array_foreach(val, i, it) {
				if (json_is_string(it) == 0)
					goto on_error;

				if (!args)
					args = must_append_string((char *)json_string_value(it), NULL);
				else
					args = must_append_string(args, " ", json_string_value(it), NULL);
			}
		} else if (strcmp(key, "env") == 0) {
			if (json_is_array(val) == 0)
				goto on_error;

			json_array_foreach(val, i, it) {
				if (json_is_string(it) == 0)
					goto on_error;

				if (!env)
					env = must_append_string((char *)json_string_value(it), NULL);
				else
					env = must_append_string(env, " ", json_string_value(it), NULL);
			}
		} else if (strcmp(key, "path") == 0) {
			if (json_is_string(val) == 0)
				goto on_error;

			if (!path)
				path = must_append_string((char *)json_string_value(val), NULL);
			else
				path = must_append_string(path, " ", json_string_value(val), NULL);
		} else if (strcmp(key, "timeout") == 0) {
			WARN("The \"timeout\" property is not implemented");
			continue;
		} else {
			continue;
		}
	}

	if (!path)
		return 0;

	if (env)
		hook = must_append_string(env, " ", path, " ", args, NULL);
	else
		hook = must_append_string(path, args ? " " : NULL, args, NULL);

	ret = add_hook(conf, type, hook);
	if (ret == 0)
		return 0;

on_error:
	free(args);
	free(env);
	free(hook);
	free(path);
	return -1;
}

static int lxc_oci_hook(json_t *elem, struct lxc_conf *conf, int type)
{
	size_t i;
	json_t *val;

	if (json_is_array(elem) == 0)
		return -1;

	json_array_foreach(elem, i, val) {
		int ret;

		ret = lxc_oci_add_hook(val, conf, type);
		if (ret < 0)
			return ret;
	}

	return 0;
}

static int lxc_oci_hooks(json_t *elem, struct lxc_conf *conf)
{
	int ret;
	const char *key;
	json_t *val;

	if (json_typeof(elem) != JSON_OBJECT)
		return -EINVAL;

	json_object_foreach(elem, key, val) {
		enum lxchooks type;

		if (strcmp(key, "prestart") == 0)
			type = LXCHOOK_PRESTART;
		else if (strcmp(key, "poststart") == 0)
			/* It's probably our post-start. Anyway, we're
			 * technically correct since go has not concept of the
			 * fork() + exec() model.
			 */
			type = LXCHOOK_START;
		else if (strcmp(key, "poststop") == 0)
			type = LXCHOOK_POSTSTOP;
		else
			/* ignore */
			continue;

		ret = lxc_oci_hook(val, conf, type);
		if (ret < 0)
			return ret;
	}

	return 0;
}

static int lxc_oci_linux_cgroups_path(json_t *elem, struct lxc_conf *conf)
{
	WARN("The \"cgroupsPath\" property is not implemented");
	return 0;
}

static int lxc_oci_linux_devices(json_t *elem, struct lxc_conf *conf)
{
	WARN("The \"devices\" property is not implemented");
	return 0;
}

static int lxc_oci_linux_gidmap(json_t *elem, struct lxc_conf *conf)
{
	WARN("The \"gidMappings\" property is not implemented");
	return 0;
}

static int lxc_oci_linux_uidmap(json_t *elem, struct lxc_conf *conf)
{
	WARN("The \"uidMappings\" property is not implemented");
	return 0;
}

static int lxc_oci_linux_sysctl(json_t *elem, struct lxc_conf *conf)
{
	WARN("The \"sysctl\" property is not implemented");
	return 0;
}

static int lxc_oci_linux(json_t *elem, struct lxc_conf *conf)
{
	const char *key;
	json_t *val;

	if (json_typeof(elem) != JSON_OBJECT)
		return -EINVAL;

	json_object_foreach(elem, key, val) {
		int ret = 0;

		if (strcmp(key, "cgroupsPath") == 0)
			ret = lxc_oci_linux_cgroups_path(val, conf);
		else if (strcmp(key, "devices") == 0)
			ret = lxc_oci_linux_devices(val, conf);
		else if (strcmp(key, "gidMappings") == 0)
			ret = lxc_oci_linux_gidmap(val, conf);
		else if (strcmp(key, "sysctl") == 0)
			ret = lxc_oci_linux_sysctl(val, conf);
		else if (strcmp(key, "uidMappings") == 0)
			ret = lxc_oci_linux_uidmap(val, conf);
		else
			INFO("Ignoring \"%s\" property", key);
		if (ret < 0)
			return ret;
	}

	return 0;
}

static int lxc_oci_process(json_t *elem, struct lxc_conf *conf)
{
	const char *key;
	json_t *val;

	if (json_typeof(elem) != JSON_OBJECT)
		return -EINVAL;

	json_object_foreach(elem, key, val) {
		int ret = 0;

		if (strcmp(key, "args") == 0) {
		} else if (strcmp(key, "apparmorProfile") == 0) {
			if (json_is_string(val) == 0)
				return -1;

			ret = set_config_apparmor_profile("lxc.apparmor.profile",
							  json_string_value(val),
							  conf, NULL);
		} else if (strcmp(key, "capabilities") == 0) {
			if (json_is_object(val) == 0)
				return -1;

			WARN("The \"capabilities\" property is not implemented");
		} else if (strcmp(key, "cwd") == 0) {
			if (json_is_string(val) == 0)
				return -1;

			ret = set_config_init_cwd("lxc.init.cwd",
						  json_string_value(val), conf,
						  NULL);
		} else if (strcmp(key, "consoleSize") == 0) {
			if (json_is_object(val) == 0)
				return -1;

			WARN("The \"consoleSize\" property is not implemented");
		} else if (strcmp(key, "env") == 0) {
			WARN("The \"env\" property is not implemented");
		} else if (strcmp(key, "noNewPrivileges") == 0) {
			char *s = "0";

			if (json_is_boolean(val) == 0)
				return -1;

			if (json_boolean_value(val) == 1)
				s = "1";
			ret = set_config_no_new_privs("lxc.no_new_privs", s,
						      conf, NULL);
		} else if (strcmp(key, "oomScoreAdj") == 0) {
			if (json_is_integer(val) == 0)
				return -1;

			WARN("The \"oomScoreAdj\" property is not implemented");
		} else if (strcmp(key, "rlimits") == 0) {
			if (json_is_array(val) == 0)
				return -1;

			WARN("The \"rlimits\" property is not implemented");
		} else if (strcmp(key, "selinuxLabel") == 0) {
			if (json_is_string(val) == 0)
				return -1;

			ret = set_config_selinux_context("lxc.selinux.context",
							 json_string_value(val),
							 conf, NULL);
		} else if (strcmp(key, "terminal") == 0) {
			if (json_is_boolean(val) == 0)
				return -1;

			/* TODO: Seems like this is used to indicate daemonized
			 * mode. If this is the case then we need to find a
			 * simple way of setting c->daemonize in struct
			 * lxc_container.  No big deal just a todo.
			 */
			WARN("The \"terminal\" property is not implemented");
		} else {
			INFO("Ignoring \"%s\" property", key);
		}
		if (ret < 0)
			return ret;
	}

	return 0;
}

static int lxc_oci_config(json_t *root, struct lxc_conf *conf)
{
	const char *key;
	json_t *value;

	if (json_typeof(root) != JSON_OBJECT)
		return -EINVAL;

	json_object_foreach(root, key, value) {
		int ret;

		if (strcmp(key, "annotations") == 0) {
			WARN("The \"annotations\" property is not implemented");
		} else if (strcmp(key, "hostname") == 0) {
			if (json_typeof(value) != JSON_STRING)
				return -EINVAL;

			ret = set_config_uts_name("lxc.uts.name",
						  json_string_value(value),
						  conf, NULL);
			if (ret < 0)
				return ret;
		} else if (strcmp(key, "hooks") == 0) {
			ret = lxc_oci_hooks(value, conf);
			if (ret < 0)
				return ret;
		} else if (strcmp(key, "linux") == 0) {
			if (json_typeof(value) != JSON_OBJECT)
				return -EINVAL;

			ret = lxc_oci_linux(value, conf);
			if (ret < 0)
				return ret;
		} else if (strcmp(key, "mounts") == 0) {
			if (json_typeof(value) != JSON_ARRAY)
				return -EINVAL;

			WARN("The \"mounts\" property is not implemented");
		} else if (strcmp(key, "process") == 0) {
			if (json_typeof(value) != JSON_OBJECT)
				return -EINVAL;

			ret = lxc_oci_process(value, conf);
			if (ret < 0)
				return ret;
		} else if (strcmp(key, "root") == 0) {
			if (json_typeof(value) != JSON_OBJECT)
				return ret;

			WARN("The \"root\" property is not implemented");
		} else if (strcmp(key, "ociVersion") == 0) {
			if (json_typeof(value) != JSON_STRING)
				return -EINVAL;

			/* For now, just check that the version string is not
			 * empty.
			 */
			if (!json_string_value(value))
				return -EINVAL;
		} else if (strcmp(key, "platform") == 0) {
			if (json_typeof(value) != JSON_OBJECT)
				return -EINVAL;

			WARN("The \"platform\" property is not implemented");
		} else {
			INFO("Ignoring \"%s\"", key);
		}
	}

	return 0;
}

int lxc_oci_config_read(const char *file, struct lxc_conf *conf)
{
	size_t length;
	char *buf;
	json_t *root;
	json_error_t error;
	int ret = -1;

	buf = file_to_buf(file, &length);
	if (!buf)
		return -1;

	root = json_loadb(buf, length, 0, &error);
	if (!root) {
		ERROR("Failed to load config file");
		return -1;
	}

	ret = lxc_oci_config(root, conf);
	if (ret == -EINVAL)
		ERROR("Invalid OCI config file");

	json_decref(root);
	return ret;
}
