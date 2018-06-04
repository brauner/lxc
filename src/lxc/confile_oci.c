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

static char *json_array_join(json_t *array, const char *sep)
{
	size_t i;
	json_t *it;
	size_t len = 0;
	char *result = NULL;

	if (!json_is_array(array))
		goto on_error;

	if (json_array_size(array) == 0)
		return strdup("");

	json_array_foreach(array, i, it) {
		if (!json_is_string(it))
			goto on_error;

		len += strlen(json_string_value(it));
	}
	len += strlen(sep) * (json_array_size(array) - 1) + 1;

	result = malloc(len);
	if (!result)
		goto on_error;

	*result = '\0';
	json_array_foreach(array, i, it) {
		if (!json_is_string(it))
			goto on_error;

		if (i != 0)
			strcat(result, sep);
		strcat(result, json_string_value(it));
	}

	return result;

on_error:
	free(result);
	return NULL;
}

static int lxc_oci_add_hook(json_t *elem, struct lxc_conf *conf, int type)
{
	int ret = -1;
	const char *key;
	json_t *val;
	char *args = NULL, *env = NULL, *hook = NULL;
	const char *path = NULL; // ownership: jansson

	if (!json_is_object(elem))
		return -EINVAL;

	json_object_foreach(elem, key, val) {
		if (strcmp(key, "args") == 0) {
			args = json_array_join(val, " ");
			if (!args)
				goto on_error;
		} else if (strcmp(key, "env") == 0) {
			env = json_array_join(val, " ");
			if (!env)
				goto on_error;
		} else if (strcmp(key, "path") == 0) {
			if (!json_is_string(val)) {
				ret = -EINVAL;
				goto on_error;
			}

			path = json_string_value(val);
		} else if (strcmp(key, "timeout") == 0) {
			WARN("The \"timeout\" property is not implemented");
		} else {
			INFO("Ignoring \"%s\" property", key);
		}
	}

	if (!path || path[0] != '/') {
		ret = -EINVAL;
		goto on_error;
	}

	// FIXME: create a LXC -> OCI translation hook.
	ret = asprintf(&hook, "env --ignore-environment %s %s %s", env ? env : "", path, args ? args : "");
	if (ret < 0) {
		hook = NULL;
		goto on_error;
	}

	ret = add_hook(conf, type, hook);
	hook = NULL; // ownership was transferred to "conf"

on_error:
	free(args);
	free(env);
	free(hook);
	return ret;
}

static int lxc_oci_hook(json_t *elem, struct lxc_conf *conf, int type)
{
	size_t i;
	json_t *val;

	if (!json_is_array(elem))
		return -EINVAL;

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

	if (!json_is_object(elem))
		return -EINVAL;

	ret = set_config_hooks_version("lxc.hook.version", "1", conf, NULL);
	if (ret < 0)
		return ret;

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

static int lxc_oci_linux_idmap(json_t *elem, struct lxc_conf *conf, char type)
{
	json_t *val;
	json_int_t nsid, hostid, range;
	char *idmap;
	int ret;

	if (!json_is_object(elem))
		return -EINVAL;

	val = json_object_get(elem, "containerID");
	if (!json_is_integer(val))
		return -EINVAL;
	nsid = json_integer_value(val);

	val = json_object_get(elem, "hostID");
	if (!json_is_integer(val))
		return -EINVAL;
	hostid = json_integer_value(val);

	val = json_object_get(elem, "size");
	if (!json_is_integer(val))
		return -EINVAL;
	range = json_integer_value(val);

	ret = asprintf(&idmap, "%c %"JSON_INTEGER_FORMAT" %"JSON_INTEGER_FORMAT" %"JSON_INTEGER_FORMAT,
		       type, nsid, hostid, range);
	if (ret < 0)
		return ret;

	ret = set_config_idmaps("lxc.idmap", idmap, conf, NULL);
	free(idmap);
	if (ret < 0)
		return ret;

	return 0;
}

static int lxc_oci_linux_idmaps(json_t *elem, struct lxc_conf *conf, char type)
{
	size_t i;
	json_t *it;

	if (!json_is_array(elem))
		return -EINVAL;

	json_array_foreach(elem, i, it) {
		int ret;
		if (!json_is_object(it))
			return -EINVAL;

		ret = lxc_oci_linux_idmap(it, conf, type);
		if (ret < 0)
			return ret;
	}

	return 0;
}

static int lxc_oci_linux_sysctl(json_t *elem, struct lxc_conf *conf)
{
	const char *key;
	json_t *val;

	json_object_foreach(elem, key, val) {
		int ret;
		char *param;

		if (!json_is_string(val))
			return -EINVAL;

		ret = asprintf(&param, "lxc.sysctl.%s", key);
		if (ret < 0)
			return -EINVAL;

		ret = set_config_sysctl(param, json_string_value(val), conf, NULL);
		free(param);
		if (ret < 0)
			return -EINVAL;
	}

	return 0;
}

static int lxc_oci_linux_namespaces(json_t *elem, struct lxc_conf *conf)
{
	size_t i;
	json_t *it;

	if (!json_is_array(elem))
		return -EINVAL;

	json_array_foreach(elem, i, it) {
		int ret;
		const char *type;
		json_t *val;
		if (!json_is_object(it))
			return -EINVAL;

		val = json_object_get(it, "type");
		if (!json_is_string(val))
			return -EINVAL;

		type = json_string_value(val);
		if (strcmp(type, "mount") == 0)
			type = "mnt";
		else if (strcmp(type, "network") == 0)
			type = "net";
		ret = set_config_namespace_clone("lxc.namespace.clone", type, conf, NULL);
		if (ret < 0)
			return ret;

		val = json_object_get(it, "path");
		if (!val)
			continue;
		if (!json_is_string(val))
			return -EINVAL;
		WARN("The namespaces \"path\" property is not implemented");
	}

	return 0;
}

// https://github.com/opencontainers/runtime-spec/blob/v1.0.1/config-linux.md#default-devices
// FIXME: use an absolute path for the destination (https://github.com/lxc/lxc/issues/2276)
static const char * const default_devices[] = {
	"/dev/null dev/null none bind,nosuid,noexec,create=file 0 0",
	"/dev/zero dev/zero none bind,nosuid,noexec,create=file 0 0",
	"/dev/full dev/full none bind,nosuid,noexec,create=file 0 0",
	"/dev/random dev/random none bind,nosuid,noexec,create=file 0 0",
	"/dev/urandom dev/urandom none bind,nosuid,noexec,create=file 0 0",
	"/dev/tty dev/tty none bind,nosuid,noexec,create=file 0 0",
};

static int lxc_oci_linux_default_devices(struct lxc_conf *conf) {
	int i;
	int ret = -1;

	ret = set_config_autodev("lxc.autodev", "0", conf, NULL);
	if (ret < 0)
		return ret;

	// For /dev/ptmx
	ret = set_config_pty_max("lxc.pty.max", "1", conf, NULL);
	if (ret < 0)
		return ret;

	for (i = 0; i < sizeof(default_devices) / sizeof(default_devices[0]); ++i) {
		ret = set_config_mount("lxc.mount.entry", default_devices[i], conf, NULL);
		if (ret < 0)
			return ret;
	}

	return 0;
}

static int lxc_oci_linux_masked_paths(json_t *elem, struct lxc_conf *conf)
{
	size_t i;
	json_t *it;

	if (!json_is_array(elem))
		return -EINVAL;

	json_array_foreach(elem, i, it) {
		int ret;
		char *entry = NULL;
		const char *path = NULL;

		if (!json_is_string(it))
			return -EINVAL;

		path = json_string_value(it);
		if (path[0] != '/' || path[1] == '\0')
			return -EINVAL;

		// There is no nice way to do this with LXC today.
		// 1. Add an optional bind mount of /dev/null, in case the
		//    target is a file. This will fail if the target is a
		//    directory.
		// 2. Add an optional read-only tmpfs mount, in case the target
		//    is a directory. This will fail if the target is a file.
		// Unfortunately, since both mounts are optional, we can't
		// guarantee that one of these mounts will succeed.
		ret = asprintf(&entry, "/dev/null %s none bind,nosuid,optional 0 0", path + 1);
		if (ret < 0)
			return ret;
		ret = set_config_mount("lxc.mount.entry", entry, conf, NULL);
		free(entry);
		if (ret < 0)
			return ret;

		ret = asprintf(&entry, "tmpfs %s tmpfs ro,optional 0 0", path + 1);
		if (ret < 0)
			return ret;
		ret = set_config_mount("lxc.mount.entry", entry, conf, NULL);
		free(entry);
		if (ret < 0)
			return ret;
	}

	return 0;
}

static int lxc_oci_linux_readonly_paths(json_t *elem, struct lxc_conf *conf)
{
	size_t i;
	json_t *it;

	if (!json_is_array(elem))
		return -EINVAL;

	json_array_foreach(elem, i, it) {
		int ret;
		char *entry = NULL;
		const char *path = NULL;

		if (!json_is_string(it))
			return -EINVAL;

		path = json_string_value(it);
		if (path[0] != '/' || path[1] == '\0')
			return -EINVAL;

		ret = asprintf(&entry, "%s %s none rbind,ro,relative 0 0", path + 1, path + 1);
		if (ret < 0)
			return ret;
		ret = set_config_mount("lxc.mount.entry", entry, conf, NULL);
		free(entry);
		if (ret < 0)
			return ret;
	}

	return 0;
}

static int lxc_oci_linux(json_t *root, struct lxc_conf *conf)
{
	int ret;
	const char *key;
	json_t *elem, *val;

	elem = json_object_get(root, "linux");
	if (!json_is_object(elem))
		return -EINVAL;

	ret = lxc_oci_linux_default_devices(conf);
	if (ret < 0)
		return ret;

	json_object_foreach(elem, key, val) {
		if (strcmp(key, "cgroupsPath") == 0)
			ret = lxc_oci_linux_cgroups_path(val, conf);
		else if (strcmp(key, "devices") == 0)
			ret = lxc_oci_linux_devices(val, conf);
		else if (strcmp(key, "gidMappings") == 0)
			ret = lxc_oci_linux_idmaps(val, conf, 'g');
		else if (strcmp(key, "maskedPaths") == 0)
			ret = lxc_oci_linux_masked_paths(val, conf);
		else if (strcmp(key, "namespaces") == 0)
			ret = lxc_oci_linux_namespaces(val, conf);
		else if (strcmp(key, "readonlyPaths") == 0)
			ret = lxc_oci_linux_readonly_paths(val, conf);
		else if (strcmp(key, "sysctl") == 0)
			ret = lxc_oci_linux_sysctl(val, conf);
		else if (strcmp(key, "uidMappings") == 0)
			ret = lxc_oci_linux_idmaps(val, conf, 'u');
		else
			INFO("Ignoring \"%s\" property", key);
		if (ret < 0)
			return ret;
	}

	return 0;
}

static int lxc_oci_process_env(json_t *elem, struct lxc_conf *conf)
{
	size_t i;
	json_t *it;

	if (!json_is_array(elem))
		return -EINVAL;

	json_array_foreach(elem, i, it) {
		int ret;

		if (!json_is_string(it))
			return -EINVAL;

		ret = set_config_environment("lxc.environment", json_string_value(it), conf, NULL);
		if (ret < 0)
			return ret;
	}

	return 0;
}

static int lxc_oci_process(json_t *elem, struct lxc_conf *conf)
{
	const char *key;
	json_t *val;

	if (!json_is_object(elem))
		return -EINVAL;

	json_object_foreach(elem, key, val) {
		int ret = 0;

		if (strcmp(key, "args") == 0) {
			char *args;

			args = json_array_join(val, " ");
			if (!args)
				return -EINVAL;
			ret = set_config_execute_cmd("lxc.execute.cmd",
						     args, conf, NULL);
			free(args);
		} else if (strcmp(key, "apparmorProfile") == 0) {
			if (!json_is_string(val))
				return -EINVAL;

			ret = set_config_apparmor_profile("lxc.apparmor.profile",
							  json_string_value(val),
							  conf, NULL);
		} else if (strcmp(key, "capabilities") == 0) {
			if (!json_is_object(val))
				return -EINVAL;

			WARN("The \"capabilities\" property is not implemented");
		} else if (strcmp(key, "cwd") == 0) {
			if (!json_is_string(val))
				return -EINVAL;

			ret = set_config_init_cwd("lxc.init.cwd",
						  json_string_value(val), conf,
						  NULL);
		} else if (strcmp(key, "consoleSize") == 0) {
			if (!json_is_object(val))
				return -EINVAL;

			WARN("The \"consoleSize\" property is not implemented");
		} else if (strcmp(key, "env") == 0) {
			ret = lxc_oci_process_env(val, conf);
		} else if (strcmp(key, "noNewPrivileges") == 0) {
			char *s = "0";

			if (!json_is_boolean(val))
				return -EINVAL;

			if (json_is_true(val))
				s = "1";
			ret = set_config_no_new_privs("lxc.no_new_privs", s,
						      conf, NULL);
		} else if (strcmp(key, "oomScoreAdj") == 0) {
			if (!json_is_integer(val))
				return -EINVAL;

			WARN("The \"oomScoreAdj\" property is not implemented");
		} else if (strcmp(key, "rlimits") == 0) {
			if (!json_is_array(val))
				return -EINVAL;

			WARN("The \"rlimits\" property is not implemented");
		} else if (strcmp(key, "selinuxLabel") == 0) {
			if (!json_is_string(val))
				return -EINVAL;

			ret = set_config_selinux_context("lxc.selinux.context",
							 json_string_value(val),
							 conf, NULL);
		} else if (strcmp(key, "terminal") == 0) {
			if (!json_is_boolean(val))
				return -EINVAL;

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

static int lxc_oci_root(json_t *elem, struct lxc_conf *conf)
{
	const char *key;
	json_t *val;

	if (json_is_object(elem) == 0)
		return -EINVAL;

	json_object_foreach(elem, key, val) {
		int ret = 0;
		if (strcmp(key, "path") == 0) {
			if (!json_is_string(val))
				return -EINVAL;

			ret = set_config_rootfs_path("lxc.rootfs.path",
						     json_string_value(val), conf,
						     NULL);
		} else if (strcmp(key, "readonly") == 0) {
			if (!json_is_boolean(val))
				return -EINVAL;

			ret = set_config_rootfs_options("lxc.rootfs.options",
							json_is_true(val) ? "ro" : "rw", conf,
							NULL);
		} else {
			INFO("Ignoring \"%s\" property", key);
		}
		if (ret < 0)
			return -EINVAL;
	}

	return 0;
}

static int lxc_oci_mount(json_t *elem, struct lxc_conf *conf)
{
	int ret = -1;
	const char *key;
	json_t *val;
	const char *dst = NULL, *src = NULL, *type = NULL; // ownership: jansson
	char *options = NULL, *entry = NULL;

	if (!json_is_object(elem))
		return -EINVAL;

	json_object_foreach(elem, key, val) {
		if (strcmp(key, "destination") == 0) {
			if (!json_is_string(val))
				goto on_error;

			dst = json_string_value(val);
		} else if (strcmp(key, "type") == 0) {
			if (!json_is_string(val))
				goto on_error;

			type = json_string_value(val);
		} else if (strcmp(key, "source") == 0) {
			if (!json_is_string(val))
				goto on_error;

			src = json_string_value(val);
		} else if (strcmp(key, "options") == 0) {
			options = json_array_join(val, ",");
			if (!options)
				goto on_error;
		} else {
			INFO("Ignoring \"%s\" property", key);
		}
	}

	// Reject relative paths and "/"
	if (!dst || dst[0] != '/' || dst[1] == '\0') {
		ret = -EINVAL;
		goto on_error;
	}

	if (!type)
		type = "none";

	if (!options || options[0] == '\0')
		options = strdup("defaults");

	// The destination needs to be relative since the rootfs might not be known yet
	// https://github.com/lxc/lxc/issues/2276
	ret = asprintf(&entry, "%s %s %s %s,create=dir 0 0", src, dst + 1, type, options);
	if (ret < 0) {
		entry = NULL;
		goto on_error;
	}

	ret = set_config_mount("lxc.mount.entry", entry, conf, NULL);

on_error:
	free(options);
	free(entry);
	return ret;
}

static int lxc_oci_mounts(json_t *elem, struct lxc_conf *conf)
{
	size_t i;
	json_t *it;

	if (!json_is_array(elem))
		return -EINVAL;

	json_array_foreach(elem, i, it) {
		int ret;

		ret = lxc_oci_mount(it, conf);
		if (ret < 0)
			return ret;
	}

	return 0;
}

static int lxc_oci_config(json_t *root, struct lxc_conf *conf)
{
	int ret;
	const char *key;
	json_t *value;

	if (!json_is_object(root))
		return -EINVAL;

	json_object_foreach(root, key, value) {
		if (strcmp(key, "annotations") == 0) {
			WARN("The \"annotations\" property is not implemented");
		} else if (strcmp(key, "hostname") == 0) {
			if (!json_is_string(value))
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
		} else if (strcmp(key, "mounts") == 0) {
			if (!json_is_array(value))
				return -EINVAL;

			ret = lxc_oci_mounts(value, conf);
			if (ret < 0)
				return ret;
		} else if (strcmp(key, "process") == 0) {
			if (!json_is_object(value))
				return -EINVAL;

			ret = lxc_oci_process(value, conf);
			if (ret < 0)
				return ret;
		} else if (strcmp(key, "root") == 0) {
			if (!json_is_object(value))
				return ret;

			ret = lxc_oci_root(value, conf);
			if (ret < 0)
				return ret;
		} else if (strcmp(key, "ociVersion") == 0) {
			if (!json_is_string(value))
				return -EINVAL;

			/* For now, just check that the version string is not
			 * empty.
			 */
			if (!json_string_value(value))
				return -EINVAL;
		} else if (strcmp(key, "platform") == 0) {
			if (!json_is_object(value))
				return -EINVAL;

			WARN("The \"platform\" property is not implemented");
		} else {
			INFO("Ignoring \"%s\"", key);
		}
	}

	ret = lxc_oci_linux(root, conf);
	if (ret < 0)
		return ret;

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
