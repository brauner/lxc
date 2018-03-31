/* liblxcapi
 *
 * Copyright © 2018 Christian Brauner <christian.brauner@ubuntu.com>.
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

#ifndef __LXC_CONFILE_OCI_H
#define __LXC_CONFILE_OCI_H

#include <stdio.h>

struct lxc_conf;

extern int oci_config_read(const char *file, struct lxc_conf *conf);

#endif /* __LXC_CONFILE_OCI_H */
