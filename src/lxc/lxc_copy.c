/*
 *
 * Copyright © 2015 Christian Brauner <christianvanbrauner@gmail.com>.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
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

#define _GNU_SOURCE
#include <unistd.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <sys/types.h>
#include <stdint.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>

#include <lxc/lxccontainer.h>

#include "attach.h"
#include "log.h"
#include "confile.h"
#include "arguments.h"
#include "lxc.h"
#include "conf.h"
#include "state.h"
#include "utils.h"
#include "bdev.h"

#define DOUBLE_INFO(...) {           \
		printf(__VA_ARGS__); \
		INFO(__VA_ARGS__);   \
	}

lxc_log_define(lxc_copy_ui, lxc);

static int my_parser(struct lxc_arguments *args, int c, char *arg);

static const struct option my_longopts[] = {
	{ "newname", required_argument, 0, 'N'},
	{ "newpath", required_argument, 0, 'p'},
	{ "rename", no_argument, 0, 'R'},
	{ "snapshot", no_argument, 0, 's'},
	{ "daemonize", no_argument, 0, 'd'},
	{ "ephemeral", no_argument, 0, 'e'},
	{ "mount", required_argument, 0, 'm'},
	{ "backingstore", required_argument, 0, 'B'},
	{ "fssize", required_argument, 0, 'L'},
	{ "keepdata", no_argument, 0, 'D'},
	{ "keepname", no_argument, 0, 'K'},
	{ "keepmac", no_argument, 0, 'M'},
	LXC_COMMON_OPTIONS
};

/* mount keys */
#define BIND 0
#define OVERLAY 1
#define AUFS 2
static char *const keys[] = {
	[BIND]    = "bind",
	[OVERLAY] = "overlay",
	[AUFS]    = "aufs",
	NULL
};

static struct lxc_arguments my_args = {
	.progname = "lxc-copy",
	.help = "\
--name=NAME [-P lxcpath] -N newname [-p newpath] [-B backingstorage] [-s] [-K] [-M] [-L size [unit]]\n\
--name=NAME [-P lxcpath] [-N newname] [-p newpath] [-B backingstorage] -e [-d] [-D] [-K] [-M] [-m {bind,aufs,overlay}=/src:/dest]\n\
--name=NAME [-P lxcpath] -N newname -R\n\
\n\
lxc-copy clone a container\n\
\n\
Options :\n\
  -n, --name=NAME           NAME of the container\n\
  -N, --newname=NEWNAME     NEWNAME for the restored container\n\
  -p, --newpath=NEWPATH     NEWPATH for the container to be stored\n\
  -R, --rename		    rename container\n\
  -s, --snapshot	    create snapshot instead of clone\n\
  -d, --daemonize	    start container in background\n\
  -e, --ephemeral	    start ephemeral container\n\
  -m, --mount	            directory to mount into container, either \n\
			    {bind,aufs,overlay}=/src-path or {bind,aufs,overlay}=/src-path:/dst-path\n\
  -B, --backingstorage=TYPE backingstorage type for the container\n\
  -L, --fssize		    size of the new block device for block device containers\n\
  -D, --keedata	            pass together with -e start a persistent snapshot \n\
  -K, --keepname	    keep the hostname of the original container\n\
  -M, --keepmac		    keep the MAC address of the original container\n",
	.options = my_longopts,
	.parser = my_parser,
	.task = CLONE,
};

static int mntindex = 0;

static char *construct_path(char *path, bool as_prefix);
static int create_mntlist(struct lxc_arguments *args, char *mntparameters,
			  char *mnttype);
static int do_clone(struct lxc_container *c, char *newname, char *newpath,
		    int flags, char *bdevtype, uint64_t fssize, enum task task,
		    char **args);
static int do_clone_ephemeral(struct lxc_container *c, char *newname,
			      char *newpath, int flags, char *bdevtype,
			      uint64_t fssize, char **args);
static int do_clone_rename(struct lxc_container *c, char *newname);
static int do_clone_task(struct lxc_container *c, enum task task, int flags,
			 char **args);
static char *generate_random_name(const char *name, const char *path);
static uint64_t get_fssize(char *s);
static int mkdir_userns_wrapper(void *arg);
static int mkdir_wrapper(struct lxc_container *c, char *arg);
static int parse_mntsubopts(struct lxc_arguments *args, char *subopts,
			    char *const *keys, char *mntparameters);
static int set_bind_mount(struct lxc_container *c, char *mntstring);
static int set_union_mount(struct lxc_container *c, char *newpath,
			   char *mntstring, int index, char *uniontype);

int main(int argc, char *argv[])
{
	struct lxc_container *c;
	int flags = 0;
	int ret;

	if (lxc_arguments_parse(&my_args, argc, argv))
		exit(EXIT_FAILURE);

	if (!my_args.log_file)
		my_args.log_file = "none";

	if (lxc_log_init(my_args.name, my_args.log_file, my_args.log_priority,
			 my_args.progname, my_args.quiet, my_args.lxcpath[0]))
		exit(EXIT_FAILURE);
	lxc_log_options_no_override();

	if (geteuid()) {
		if (access(my_args.lxcpath[0], O_RDWR) < 0) {
			fprintf(stderr, "You lack access to %s\n",
				my_args.lxcpath[0]);
			exit(EXIT_FAILURE);
		}
	}

	if (!my_args.newname && !(my_args.task == DESTROY)) {
		printf("Error: You must provide a NEWNAME for the clone.\n");
		exit(EXIT_FAILURE);
	}

	if (my_args.task == SNAP || my_args.task == DESTROY)
		flags |= LXC_CLONE_SNAPSHOT;
	if (my_args.keepname)
		flags |= LXC_CLONE_KEEPNAME;
	if (my_args.keepmac)
		flags |= LXC_CLONE_KEEPMACADDR;

	c = lxc_container_new(my_args.name, my_args.lxcpath[0]);
	if (!c)
		exit(EXIT_FAILURE);

	if (!c->may_control(c)) {
		fprintf(stderr, "Insufficent privileges to control %s\n",
			c->name);
		lxc_container_put(c);
		exit(EXIT_FAILURE);
	}

	if (!c->is_defined(c)) {
		fprintf(stderr, "Error: container %s is not defined\n",
			c->name);
		lxc_container_put(c);
		exit(EXIT_FAILURE);
	}

	ret = do_clone_task(c, my_args.task, flags, &argv[optind]);

	lxc_container_put(c);

	if (ret == 0)
		exit(EXIT_SUCCESS);
	exit(EXIT_FAILURE);
}

static int my_parser(struct lxc_arguments *args, int c, char *arg)
{
	char *subopts = NULL;
	char *mntparameters = NULL;
	switch (c) {
	case 'N':
		args->newname = arg;
		break;
	case 'p':
		args->newpath = arg;
		break;
	case 'R':
		args->task = RENAME;
		break;
	case 's':
		args->task = SNAP;
		break;
	case 'd':
		args->daemonize = 1;
		break;
	case 'e':
		args->task = DESTROY;
		break;
	case 'm':
		subopts = optarg;
		if (parse_mntsubopts(args, subopts, keys, mntparameters) < 0)
			return -1;
		break;
	case 'B':
		args->bdevtype = arg;
		break;
	case 'L':
		args->fssize = get_fssize(optarg);
		break;
	case 'D':
		args->keepdata = 1;
		break;
	case 'K':
		args->keepname = 1;
		break;
	case 'M':
		args->keepmac = 1;
		break;
	}

	return 0;
}

static int do_clone(struct lxc_container *c, char *newname, char *newpath,
		    int flags, char *bdevtype, uint64_t fssize, enum task task,
		    char **args)
{
	struct lxc_container *clone;

	clone = c->clone(c, newname, newpath, flags, bdevtype, NULL, fssize,
			 args);
	if (!clone) {
		fprintf(stderr, "clone failed\n");
		return -1;
	}

	DOUBLE_INFO("Created container %s as %s of %s\n", newname,
		    task ? "snapshot" : "copy", c->name);

	lxc_container_put(clone);

	return 0;
}

static int do_clone_ephemeral(struct lxc_container *c, char *newname,
			      char *newpath, int flags, char *bdevtype,
			      uint64_t fssize, char **args)
{
	int i;
	int index = 0;
	int ret = 0;
	struct lxc_container *clone;
	char *randname = NULL;
	lxc_attach_options_t attach_options = LXC_ATTACH_OPTIONS_DEFAULT;
	attach_options.env_policy = LXC_ATTACH_CLEAR_ENV;

	if (!newname) {
		randname = generate_random_name(c->name, newpath ? newpath : my_args.lxcpath[0]);
		if (randname)
			clone = c->clone(c, randname, newpath, flags, bdevtype,
					 NULL, fssize, args);
		else
			return -1;
	} else {
		clone = c->clone(c, newname, newpath, flags, bdevtype, NULL,
				 fssize, args);
	}

	if (!clone) {
		fprintf(stderr, "Creating clone of %s failed\n", c->name);
		return -1;
	}

	if (!my_args.keepdata) {
		if (!clone->set_config_item(clone, "lxc.ephemeral", "1")) {
			clone->destroy(clone);
			lxc_container_put(clone);
			fprintf(stderr, "Error setting config item\n");
			return -1;
		}

		if (!clone->save_config(clone, NULL)) {
			clone->destroy(clone);
			lxc_container_put(clone);
			fprintf(stderr, "Error saving config item\n");
			return -1;
		}
	}

	for (i = 0; i < mntindex; i++) {
		if (strncmp(my_args.mnttype[i], "bind", 4) == 0) {
			if (set_bind_mount(clone, my_args.mntlist[i]) < 0) {
				clone->destroy(clone);
				lxc_container_put(clone);
				return -1;
			}
		} else {
			if (set_union_mount(clone, newpath, my_args.mntlist[i],
					    index, my_args.mnttype[i]) < 0) {
				clone->destroy(clone);
				lxc_container_put(clone);
				return -1;
			}
			index++;
		}
		if (!clone->save_config(clone, NULL)) {
			clone->destroy(clone);
			lxc_container_put(clone);
			fprintf(stderr, "Error saving config item\n");
			return -1;
		}
	}

	DOUBLE_INFO("Created %s as %s of %s\n", newname ? newname : randname,
		    my_args.keepdata ? "clone" : "ephemeral clone", c->name);

	if (!my_args.daemonize && my_args.argc) {
		clone->want_daemonize(clone, true);
		my_args.daemonize = 1;
	} else if (!my_args.daemonize) {
		clone->want_daemonize(clone, false);
	}

	if (!clone->start(clone, 0, NULL)) {
		if (!(clone->lxc_conf->ephemeral == 1))
			clone->destroy(clone);
		lxc_container_put(clone);
		fprintf(stderr, "Error starting container\n");
		return -1;
	}

	if (my_args.daemonize && my_args.argc) {
		ret = clone->attach_run_wait(clone, &attach_options,
					     my_args.argv[0],
					     (const char *const *)my_args.argv);
		if (ret < 0) {
			lxc_container_put(clone);
			return -1;
		} else {
			clone->shutdown(clone, true);
		}
	}

	lxc_container_put(clone);

	return 0;
}

static int do_clone_rename(struct lxc_container *c, char *newname)
{
	if (!c->rename(c, newname)) {
		ERROR("Error: Renaming container %s to %s failed\n", c->name, newname);
		return -1;
	}

	INFO("Renamed container %s to %s\n", c->name, newname);

	return 0;
}

static int do_clone_task(struct lxc_container *c, enum task task, int flags,
			 char **args)
{
	int ret = 0;

	switch (task) {
	case DESTROY:
		ret = do_clone_ephemeral(c, my_args.newname, my_args.newpath,
					 flags, my_args.bdevtype,
					 my_args.fssize, args);
		break;
	case RENAME:
		ret = do_clone_rename(c, my_args.newname);
		break;
	default:
		ret = do_clone(c, my_args.newname, my_args.newpath, flags,
			       my_args.bdevtype, my_args.fssize, my_args.task,
			       args);
		break;
	}

	return ret;
}

static char *construct_path(char *path, bool as_prefix)
{
	char **components = NULL;
	char *cleanpath = NULL;

	components = lxc_normalize_path(path);
	if (!components)
		return NULL;

	cleanpath = lxc_string_join("/", (const char **)components, as_prefix);
	lxc_free_array((void **)components, free);

	return cleanpath;
}

static int create_mntlist(struct lxc_arguments *args, char *mntparameters,
			  char *mnttype)
{
	char **tmpchar1;
	char **tmpchar2;
	tmpchar1 = realloc(args->mntlist, (mntindex + 1) * sizeof(args->mntlist[0]));
	if (!tmpchar1)
		return -1;
	args->mntlist = tmpchar1;
	args->mntlist[mntindex] = mntparameters;
	tmpchar2 = realloc(args->mnttype, (mntindex + 1) * sizeof(args->mnttype[0]));
	if (!tmpchar2)
		return -1;
	args->mnttype = tmpchar2;
	args->mnttype[mntindex] = mnttype;
	mntindex++;

	return 0;
}

static char *generate_random_name(const char *name, const char *path)
{
	char testpath[MAXPATHLEN];
	static char randname[MAXPATHLEN];
	int ret;
	int suffix;
	unsigned int seed;

	do {
#ifndef HAVE_RAND_R
		seed = randseed(true);
#endif

#ifdef HAVE_RAND_R
		seed = randseed(false);
		suffix = rand_r(&seed);
#else
		suffix = rand();
#endif

		ret = snprintf(randname, MAXPATHLEN, "%s_%08x", name, suffix);
		if (ret < 0 || ret >= MAXPATHLEN) {
			ERROR("Generating a random name for the clone of %s " "failed", name);
			return NULL;
		}

		ret = snprintf(testpath, MAXPATHLEN, "%s/%s", path, randname);
		if (ret < 0 || ret >= MAXPATHLEN) {
			ERROR("Generating a random name for the clone of %s " "failed", name);
			return NULL;
		}
	} while (dir_exists(testpath));

	return randname;
}

/* we pass fssize in bytes */
static uint64_t get_fssize(char *s)
{
	uint64_t ret;
	char *end;

	ret = strtoull(s, &end, 0);
	if (end == s) {
		fprintf(stderr, "Invalid blockdev size '%s', using default size\n", s);
		return 0;
	}
	while (isblank(*end))
		end++;
	if (*end == '\0') {
		ret *= 1024ULL * 1024ULL; // MB by default
	} else if (*end == 'b' || *end == 'B') {
		ret *= 1ULL;
	} else if (*end == 'k' || *end == 'K') {
		ret *= 1024ULL;
	} else if (*end == 'm' || *end == 'M') {
		ret *= 1024ULL * 1024ULL;
	} else if (*end == 'g' || *end == 'G') {
		ret *= 1024ULL * 1024ULL * 1024ULL;
	} else if (*end == 't' || *end == 'T') {
		ret *= 1024ULL * 1024ULL * 1024ULL * 1024ULL;
	} else {
		fprintf(stderr, "Invalid blockdev unit size '%c' in '%s', " "using default size\n", *end, s);
		return 0;
	}

	return ret;
}

static int mkdir_userns_wrapper(void *arg)
{
	const char *dir = (const char *)arg;
	return mkdir_p(dir, 0755);
}

static int mkdir_wrapper(struct lxc_container *c, char *arg)
{
	if (am_unpriv()) {
		if (userns_exec_1(c->lxc_conf, mkdir_userns_wrapper, (void *)arg) < 0)
			return -1;
		if (chown_mapped_root(arg, c->lxc_conf) < 0)
			return -1;
	} else {
		if (mkdir_p(arg, 0755) < 0)
			return -1;
	}
	return 0;
}

static int parse_mntsubopts(struct lxc_arguments *args, char *subopts,
			    char *const *keys, char *mntparameters)
{
	while (*subopts != '\0') {
		switch (getsubopt(&subopts, keys, &mntparameters)) {
		case BIND:
			if (create_mntlist(args, mntparameters, "bind") < 0)
				return -1;
			break;
		case OVERLAY:
			if (create_mntlist(args, mntparameters, "overlay") < 0)
				return -1;
			break;
		case AUFS:
			if (create_mntlist(args, mntparameters, "aufs") < 0)
				return -1;
			break;
		default:
			break;
		}
	}
	return 0;
}

static int set_bind_mount(struct lxc_container *c, char *mntstring)
{
	int len = 0;
	int ret = 0;
	char *mntentry = NULL;
	char *options = NULL;
	char *src = NULL;
	char *dest = NULL;
	char **mntarray = NULL;

	mntarray = lxc_string_split(mntstring, ':');
	if (!mntarray)
		goto err;

	src = construct_path(mntarray[0], true);
	if (!src)
		goto err;

	len = lxc_array_len((void **)mntarray);
	if (len == 1) { /* bind=src */
		dest = construct_path(mntarray[0], false);
	} else if (len == 2) { /* bind=src:option or bind=src:dest */
		if (strncmp(mntarray[1], "rw", strlen(mntarray[1])) == 0)
			options = "rw";

		if (strncmp(mntarray[1], "ro", strlen(mntarray[1])) == 0)
			options = "ro";

		if (options)
			dest = construct_path(mntarray[0], false);
		else
			dest = construct_path(mntarray[1], false);
	} else if (len == 3) { /* bind=src:dest:option */
			dest = construct_path(mntarray[1], false);
			options = mntarray[2];
	} else {
		INFO("Excess elements in mount specification");
		goto err;
	}
	if (!dest)
		goto err;

	if (!options)
		options = "rw";

	len = strlen(src) + strlen(dest) + strlen(options) +
	      strlen("  none bind,optional,, 0 0") +
	      strlen(is_dir(src) ? "create=dir" : "create=file") + 1;
	mntentry = malloc(len);
	if (!mntentry)
		goto err;

	ret = snprintf(mntentry, MAXPATHLEN,
		       "%s %s none bind,optional,%s,%s 0 0", src, dest, options,
		       is_dir(src) ? "create=dir" : "create=file");
	if (ret < 0 || ret >= MAXPATHLEN)
		goto err;

	if (!c->set_config_item(c, "lxc.mount.entry", mntentry)) {
		fprintf(stderr, "Error setting config item\n");
		goto err;
	}

	free(src);
	free(dest);
	free(mntentry);
	lxc_free_array((void **)mntarray, free);
	return 0;

err:
	free(src);
	free(dest);
	free(mntentry);
	lxc_free_array((void **)mntarray, free);
	return -1;
}

static int set_union_mount(struct lxc_container *c, char *newpath,
			   char *mntstring, int index, char *uniontype)
{
	int len = 0;
	int ret = 0;
	char *mntentry = NULL;
	char *src = NULL;
	char *dest = NULL;
	const char *xinopath = "/dev/shm/aufs.xino";
	char **mntarray = NULL;
	char tmpfs[MAXPATHLEN];
	char upperdir[MAXPATHLEN];
	char workdir[MAXPATHLEN];

	mntarray = lxc_string_split(mntstring, ':');
	if (!mntarray)
		goto err;

	src = construct_path(mntarray[0], true);
	if (!src)
		goto err;

	len = lxc_array_len((void **)mntarray);
	if (len == 1) { /* aufs=src or overlay=src */
		dest = construct_path(mntarray[0], false);
	} else if (len == 2) { /* aufs=src:dest or overlay=src:dest */
		dest = construct_path(mntarray[1], false);
	} else {
		INFO("Excess elements in mount specification");
		goto err;
	}
	if (!dest)
		goto err;

	/* Create tmpfs folder under which we create the delta and workdir
	 * directories */
	ret = snprintf(tmpfs, MAXPATHLEN, "%s/%s/tmpfs",
		       newpath ? newpath : my_args.lxcpath[0], c->name);
	if (ret < 0 || ret >= MAXPATHLEN)
		goto err;

	if (mkdir_wrapper(c, tmpfs) < 0)
		goto err;

	/* Create upperdir for both aufs and overlay */
	ret = snprintf(upperdir, MAXPATHLEN, "%s/%s/tmpfs/delta%d",
		       newpath ? newpath : my_args.lxcpath[0], c->name, index);
	if (ret < 0 || ret >= MAXPATHLEN)
		goto err;

	if (mkdir_wrapper(c, upperdir) < 0)
		goto err;

	if (strncmp(uniontype, "overlay", 7) == 0) {
		/* Create workdir */
		ret = snprintf(workdir, MAXPATHLEN, "%s/%s/tmpfs/workdir%d",
			       newpath ? newpath : my_args.lxcpath[0], c->name, index);
		if (ret < 0 || ret >= MAXPATHLEN)
			goto err;

		if (mkdir_wrapper(c, workdir) < 0)
			goto err;

		len = 2 * strlen(src) + strlen(dest) + strlen(upperdir) +
		      strlen(workdir) +
		      strlen("  overlay lowerdir=,upperdir=,workdir=,create=dir") + 1;
		mntentry = malloc(len);
		if (!mntentry)
			goto err;

		ret = snprintf(mntentry, len, "%s %s overlay lowerdir=%s,upperdir=%s,workdir=%s,create=dir",
			       src, dest, src, upperdir, workdir);
		if (ret < 0 || ret >= len)
			goto err;
	} else if (strncmp(uniontype, "aufs", 4) == 0) {
		len = 2 * strlen(src) + strlen(dest) + strlen(upperdir) +
		      strlen(xinopath) +
		      strlen("  aufs br==rw:=ro,xino=,create=dir") + 1;

		mntentry = malloc(len);
		if (!mntentry)
			goto err;

		ret = snprintf(mntentry, len, "%s %s aufs br=%s=rw:%s=ro,xino=%s,create=dir",
			       src, dest, upperdir, src, xinopath);
		if (ret < 0 || ret >= len)
			goto err;
	}

	if (!c->set_config_item(c, "lxc.mount.entry", mntentry)) {
		fprintf(stderr, "Error setting config item\n");
		goto err;
	}

	free(src);
	free(dest);
	free(mntentry);
	lxc_free_array((void **)mntarray, free);
	return 0;

err:
	free(src);
	free(dest);
	free(mntentry);
	lxc_free_array((void **)mntarray, free);
	return -1;
}

