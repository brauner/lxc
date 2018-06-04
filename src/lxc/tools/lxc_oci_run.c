/*
 *
 * Copyright © 2013 Serge Hallyn <serge.hallyn@ubuntu.com>.
 * Copyright © 2013 Canonical Ltd.
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

#include <ctype.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#include <lxc/lxccontainer.h>

#include "arguments.h"
#include "tool_utils.h"

int main(int argc, char *argv[])
{
	struct lxc_container *c;
	struct lxc_log log;
	bool bret;

	char* lxcpath = NULL;
	char* name = "test-oci";

	log.name = name;
	log.file = "/dev/stderr";
	log.level = "DEBUG";
	log.prefix = "lxc-oci-run";
	log.quiet = false;
	log.lxcpath = lxcpath;

	if (lxc_log_init(&log))
		exit(EXIT_FAILURE);

	c = lxc_container_new(name, lxcpath);
	if (!c) {
		fprintf(stderr, "Failed to create lxc container.\n");
		exit(EXIT_FAILURE);
	}
	c->clear_config(c);
	c->load_config(c, "config.json");

	c->daemonize = false;
	bret = c->start(c, 1, NULL);
	if (!bret) {
		fprintf(stderr, "Failed run an application inside container\n");
		lxc_container_put(c);
		exit(EXIT_FAILURE);
	}

	lxc_container_put(c);
	exit(EXIT_SUCCESS);
}
