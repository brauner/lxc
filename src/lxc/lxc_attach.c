/*
 * lxc: linux Container library
 *
 * (C) Copyright IBM Corp. 2007, 2010
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

#define _GNU_SOURCE
#include <assert.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <stdlib.h>
#include <termios.h>
#include <unistd.h>

#include <lxc/lxccontainer.h>

#include "attach.h"
#include "arguments.h"
# include "commands.h"
#include "conf.h"
#include "config.h"
#include "confile.h"
#include "console.h"
#include "mainloop.h"
#include "namespace.h"
#include "caps.h"
#include "log.h"
#include "utils.h"

lxc_log_define(lxc_attach_ui, lxc);

static const struct option my_longopts[] = {
	{"elevated-privileges", optional_argument, 0, 'e'},
	{"arch", required_argument, 0, 'a'},
	{"namespaces", required_argument, 0, 's'},
	{"remount-sys-proc", no_argument, 0, 'R'},
	/* TODO: decide upon short option names */
	{"clear-env", no_argument, 0, 500},
	{"keep-env", no_argument, 0, 501},
	{"keep-var", required_argument, 0, 502},
	{"set-var", required_argument, 0, 'v'},
	LXC_COMMON_OPTIONS
};

static int elevated_privileges = 0;
static signed long new_personality = -1;
static int namespace_flags = -1;
static int remount_sys_proc = 0;
static lxc_attach_env_policy_t env_policy = LXC_ATTACH_KEEP_ENV;
static char **extra_env = NULL;
static ssize_t extra_env_size = 0;
static char **extra_keep = NULL;
static ssize_t extra_keep_size = 0;

static int add_to_simple_array(char ***array, ssize_t *capacity, char *value)
{
	ssize_t count = 0;

	assert(array);

	if (*array)
		for (; (*array)[count]; count++);

	/* we have to reallocate */
	if (count >= *capacity - 1) {
		ssize_t new_capacity = ((count + 1) / 32 + 1) * 32;
		char **new_array = realloc((void*)*array, sizeof(char *) * new_capacity);
		if (!new_array)
			return -1;
		memset(&new_array[count], 0, sizeof(char*)*(new_capacity - count));
		*array = new_array;
		*capacity = new_capacity;
	}

	assert(*array);

	(*array)[count] = value;
	return 0;
}

static int my_parser(struct lxc_arguments* args, int c, char* arg)
{
	int ret;

	switch (c) {
	case 'e':
		ret = lxc_fill_elevated_privileges(arg, &elevated_privileges);
		if (ret)
			return -1;
		break;
	case 'R': remount_sys_proc = 1; break;
	case 'a':
		new_personality = lxc_config_parse_arch(arg);
		if (new_personality < 0) {
			lxc_error(args, "invalid architecture specified: %s", arg);
			return -1;
		}
		break;
	case 's':
		namespace_flags = 0;
		ret = lxc_fill_namespace_flags(arg, &namespace_flags);
		if (ret)
			return -1;
		/* -s implies -e */
		lxc_fill_elevated_privileges(NULL, &elevated_privileges);
		break;
	case 500: /* clear-env */
		env_policy = LXC_ATTACH_CLEAR_ENV;
		break;
	case 501: /* keep-env */
		env_policy = LXC_ATTACH_KEEP_ENV;
		break;
	case 502: /* keep-var */
		ret = add_to_simple_array(&extra_keep, &extra_keep_size, arg);
		if (ret < 0) {
			lxc_error(args, "memory allocation error");
			return -1;
		}
		break;
	case 'v':
		ret = add_to_simple_array(&extra_env, &extra_env_size, arg);
		if (ret < 0) {
			lxc_error(args, "memory allocation error");
			return -1;
		}
		break;
	}

	return 0;
}

static struct lxc_arguments my_args = {
	.progname = "lxc-attach",
	.help     = "\
--name=NAME [-- COMMAND]\n\
\n\
Execute the specified COMMAND - enter the container NAME\n\
\n\
Options :\n\
  -n, --name=NAME   NAME of the container\n\
  -e, --elevated-privileges=PRIVILEGES\n\
                    Use elevated privileges instead of those of the\n\
                    container. If you don't specify privileges to be\n\
                    elevated as OR'd list: CAP, CGROUP and LSM (capabilities,\n\
                    cgroup and restrictions, respectively) then all of them\n\
                    will be elevated.\n\
                    WARNING: This may leak privileges into the container.\n\
                    Use with care.\n\
  -a, --arch=ARCH   Use ARCH for program instead of container's own\n\
                    architecture.\n\
  -s, --namespaces=FLAGS\n\
                    Don't attach to all the namespaces of the container\n\
                    but just to the following OR'd list of flags:\n\
                    MOUNT, PID, UTSNAME, IPC, USER or NETWORK.\n\
                    WARNING: Using -s implies -e with all privileges\n\
                    elevated, it may therefore leak privileges into the\n\
                    container. Use with care.\n\
  -R, --remount-sys-proc\n\
                    Remount /sys and /proc if not attaching to the\n\
                    mount namespace when using -s in order to properly\n\
                    reflect the correct namespace context. See the\n\
                    lxc-attach(1) manual page for details.\n\
      --clear-env   Clear all environment variables before attaching.\n\
                    The attached shell/program will start with only\n\
                    container=lxc set.\n\
      --keep-env    Keep all current environment variables. This\n\
                    is the current default behaviour, but is likely to\n\
                    change in the future.\n\
  -v, --set-var     Set an additional variable that is seen by the\n\
                    attached program in the container. May be specified\n\
                    multiple times.\n\
      --keep-var    Keep an additional environment variable. Only\n\
                    applicable if --clear-env is specified. May be used\n\
                    multiple times.\n",
	.options  = my_longopts,
	.parser   = my_parser,
	.checker  = NULL,
};

struct wrapargs {
	int master;
	int slave;
	lxc_attach_command_t *cmd;
};

static int attach_callback(void *p)
{
	struct wrapargs *args = p;

	close(args->master);
	setsid();
	ioctl(args->slave, TIOCSCTTY, NULL);
	dup2(args->slave, 0);
	dup2(args->slave, 1);
	dup2(args->slave, 2);

	if (args->cmd && args->cmd->program)
		execvp(args->cmd->program, args->cmd->argv);
	else
		lxc_attach_run_shell(NULL);

	return -1;
}

/*
 * Disclaimer: This is a total draft (e.g. the current sigwinch handler taken
 * from console.{c,h} is not working yet.).
 *
 * This solution opens a pty (master & slave) on the host and passes the fds
 * (master & slave) to the container. We then pass attach_callback() to
 * lxc_attach(), close the master fd and call lxc_attach_run_shell() in
 * attach_callback() to run a shell on the slave side in the container. The
 * disadvantage is that for unprivileged containers the shell we are calling
 * lxc-attach from must be in the unprivileged users cgroup because we need to
 * be allowed to move the pid of the attached shell to the containers cgroup.
 */
static int lxc_get_pty(struct lxc_container *c, lxc_attach_options_t *att,
		int *pid)
{
	int ret, masterfd;
	struct lxc_epoll_descr descr;
	struct termios oldtios;
	struct lxc_tty_state *ts;
	struct wrapargs args;
	struct lxc_attach_command_t cmd;

	if (!isatty(STDIN_FILENO)) {
		ERROR("stdin is not a tty");
		return -1;
	}

	ret = setup_tios(STDIN_FILENO, &oldtios);
	if (ret) {
		ERROR("failed to setup tios");
		return -1;
	}

	/* Create pty on the host. lxc_console_create() will do this for us.
	 *
	 * It is similiar to how we setup a console on container start with
	 * lxc-start -n CONTAINER -F
	 * Comparison with lxc-console: When we use lxc-console to get a console
	 * in the container it will allocate one of the ttys we set up in the
	 * container on startup. This is done by run lxc_cmd_console() here
	 * instead of lxc_console_create(). */
	if (lxc_console_create(c->lxc_conf) < 0)
		goto err1;

	/* Shift tty to container. */
	ttys_shift_ids(c->lxc_conf);

	masterfd = c->lxc_conf->console.master;

	ret = setsid();
	if (ret)
		INFO("already group leader");

	/* Not correctly implemented yet. */
	ts = lxc_console_sigwinch_init(STDIN_FILENO, masterfd);
	if (!ts) {
		ret = -1;
		goto err2;
	}
	ts->escape = -1;
	ts->winch_proxy = c->name;
	ts->winch_proxy_lxcpath = c->config_path;

	lxc_console_winsz(STDIN_FILENO, masterfd);
	lxc_cmd_console_winch(ts->winch_proxy, ts->winch_proxy_lxcpath);

	/* Passing master and slave fd to attach_callback(). We run a shell
	 * under the slave. */
	args.master = masterfd;
	args.slave = c->lxc_conf->console.slave;
	args.cmd = NULL;
	if (my_args.argc > 0) {
		cmd.program = my_args.argv[0];
		cmd.argv = (char**)my_args.argv;
		args.cmd = &cmd;
	}
	c->attach(c, attach_callback, &args, att, pid);
	close(c->lxc_conf->console.slave); /* Close slave side. */

	/* Setting up the epoll-mainloop. */
	ret = lxc_mainloop_open(&descr);
	if (ret) {
		ERROR("failed to create mainloop");
		goto err3;
	}

	ret = lxc_mainloop_add_handler(&descr, ts->sigfd,
			lxc_console_cb_sigwinch_fd, ts); /* Ignore the sigwinch handler for now. */
	if (ret) {
		ERROR("failed to add handler for SIGWINCH fd");
		goto err4;
	}

	ret = lxc_mainloop_add_handler(&descr, ts->stdinfd,
			lxc_console_cb_tty_stdin, ts);
	if (ret) {
		ERROR("failed to add handler for stdinfd");
		goto err4;
	}

	ret = lxc_mainloop_add_handler(&descr, ts->masterfd,
			lxc_console_cb_tty_master, ts);
	if (ret) {
		ERROR("failed to add handler for masterfd");
		goto err4;
	}

	ret = lxc_mainloop(&descr, -1);
	if (ret) {
		ERROR("mainloop returned an error");
		goto err4;
	}

	ret = 0;

err4:
	lxc_mainloop_close(&descr);
err3:
	lxc_console_sigwinch_fini(ts);
err2:
	close(masterfd);
err1:
	tcsetattr(STDIN_FILENO, TCSAFLUSH, &oldtios);

	return ret;
}

int main(int argc, char *argv[])
{
	int ret;
	pid_t pid;
	lxc_attach_options_t attach_options = LXC_ATTACH_OPTIONS_DEFAULT;

	ret = lxc_caps_init();
	if (ret)
		return 1;

	ret = lxc_arguments_parse(&my_args, argc, argv);
	if (ret)
		return 1;

	if (!my_args.log_file)
		my_args.log_file = "none";

	ret = lxc_log_init(my_args.name, my_args.log_file, my_args.log_priority,
			   my_args.progname, my_args.quiet, my_args.lxcpath[0]);
	if (ret)
		return 1;
	lxc_log_options_no_override();

	if (remount_sys_proc)
		attach_options.attach_flags |= LXC_ATTACH_REMOUNT_PROC_SYS;
	if (elevated_privileges)
		attach_options.attach_flags &= ~(elevated_privileges);
	attach_options.namespaces = namespace_flags;
	attach_options.personality = new_personality;
	attach_options.env_policy = env_policy;
	attach_options.extra_env_vars = extra_env;
	attach_options.extra_keep_env = extra_keep;

	struct lxc_container *c;
	c = lxc_container_new(my_args.name, my_args.lxcpath[0]);
	if (!c)
		goto out;

	lxc_get_pty(c, &attach_options, &pid);

	lxc_container_put(c);

	if (ret < 0)
		return 1;

	ret = lxc_wait_for_pid_status(pid);
	if (ret < 0)
		return 1;

	if (WIFEXITED(ret))
		return WEXITSTATUS(ret);

out:
	return 1;
}
