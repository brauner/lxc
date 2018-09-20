/*
 * lxc: linux Container library
 *
 * (C) Copyright IBM Corp. 2007, 2008
 *
 * Authors:
 * Daniel Lezcano <daniel.lezcano at free.fr>
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

#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

#include "cgroup.h"
#include "conf.h"
#include "initutils.h"
#include "log.h"
#include "start.h"
#include "../../tests/lxctest.h"

lxc_log_define(cgroup, lxc);

extern struct cgroup_ops *cgfsng_ops_init(void);

struct cgroup_ops *cgroup_init(struct lxc_handler *handler)
{
	struct cgroup_ops *cgroup_ops;

	lxc_error("%s\n", "Initializing cgroup driver");
	cgroup_ops = cgfsng_ops_init();
	if (!cgroup_ops) {
		lxc_error("%s\n", "Failed to initialize cgroup driver");
		return NULL;
	}
	lxc_error("%s\n", "Initialized cgroup driver");

	lxc_error("%s\n", "Initializing cgroup data");
	if (!cgroup_ops->data_init(cgroup_ops)) {
		lxc_error("%s\n", "Failed to initialize cgroup data");
		return NULL;
	}
	lxc_error("%s\n", "Initialized cgroup data");

	if (cgroup_ops->cgroup_layout == CGROUP_LAYOUT_LEGACY)
		lxc_error("%s\n", "Running with legacy cgroup layout");
	else if (cgroup_ops->cgroup_layout == CGROUP_LAYOUT_HYBRID)
		lxc_error("%s\n", "Running with hybrid cgroup layout");
	else if (cgroup_ops->cgroup_layout == CGROUP_LAYOUT_UNIFIED)
		lxc_error("%s\n", "Running with unified cgroup layout");
	else
		lxc_error("%s\n", "Running with unknown cgroup layout");

	return cgroup_ops;
}

void cgroup_exit(struct cgroup_ops *ops)
{
	char **cur;
	struct hierarchy **it;

	lxc_error("%s\n", "Freeing cgroups");
	if (!ops) {
		lxc_error("%s\n", "No cgroups to free");
		return;
	}
	lxc_error("%s\n", "Freed cgroups");

	lxc_error("%s\n", "Freeing cgroup_use");
	for (cur = ops->cgroup_use; cur && *cur; cur++)
		free(*cur);
	lxc_error("%s\n", "Freed cgroup_use");

	lxc_error("%s\n", "Freeing cgroup_pattern");
	free(ops->cgroup_pattern);
	lxc_error("%s\n", "Freed cgroup_pattern");

	lxc_error("%s\n", "Freeing container_cgroup");
	free(ops->container_cgroup);
	lxc_error("%s\n", "Freed container_cgroup");

	lxc_error("%s\n", "Freeing hierarchies");
	for (it = ops->hierarchies; it && *it; it++) {
		char **ctrlr;

		lxc_error("%s\n", "Freeing controllers");
		for (ctrlr = (*it)->controllers; ctrlr && *ctrlr; ctrlr++)
			free(*ctrlr);
		lxc_error("%s\n", "Freed controllers");

		lxc_error("%s\n", "Freeing controllers pointer");
		free((*it)->controllers);
		lxc_error("%s\n", "Freed controllers pointer");

		lxc_error("%s\n", "Freeing mountpoint");
		free((*it)->mountpoint);
		lxc_error("%s\n", "Freed mountpoint");

		lxc_error("%s\n", "Freeing base_cgroup");
		free((*it)->base_cgroup);
		lxc_error("%s\n", "Freed base_cgroup");

		lxc_error("%s\n", "Freeing fullcgpath");
		free((*it)->fullcgpath);
		lxc_error("%s\n", "Freed fullcgpath");

		lxc_error("%s\n", "Freeing hierarchy pointer");
		free(*it);
		lxc_error("%s\n", "Freed hierarchy pointer");
	}
	lxc_error("%s\n", "Freed hierarchies");

	lxc_error("%s\n", "Freeing hierarchies pointer");
	free(ops->hierarchies);
	lxc_error("%s\n", "Freed hierarchies pointer");

	return;
}

#define INIT_SCOPE "/init.scope"
void prune_init_scope(char *cg)
{
	char *point;

	if (!cg)
		return;

	point = cg + strlen(cg) - strlen(INIT_SCOPE);
	if (point < cg)
		return;

	if (strcmp(point, INIT_SCOPE) == 0) {
		if (point == cg)
			*(point + 1) = '\0';
		else
			*point = '\0';
	}
}
