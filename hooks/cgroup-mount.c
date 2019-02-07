#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <unistd.h>

/* filesystem magic values */
#ifndef CGROUP_SUPER_MAGIC
#define CGROUP_SUPER_MAGIC 0x27e0eb
#endif

#ifndef CGROUP2_SUPER_MAGIC
#define CGROUP2_SUPER_MAGIC 0x63677270
#endif

#define debug_stream(stream, format, ...)                                  \
	do {                                                               \
		fprintf(stream, "%s: %d: %s: " format, __FILE__, __LINE__, \
			__func__, __VA_ARGS__);                            \
	} while (false)

#define error(format, ...) debug_stream(stderr, format, __VA_ARGS__)

typedef __typeof__(((struct statfs *)NULL)->f_type) fs_type_magic;
static bool is_fs_type(const struct statfs *fs, fs_type_magic magic_val)
{
	return (fs->f_type == (fs_type_magic)magic_val);
}

static bool has_fs_type(const char *path, fs_type_magic magic_val)
{
	int ret;
	struct statfs sb;

	ret = statfs(path, &sb);
	if (ret < 0)
		return false;

	return is_fs_type(&sb, magic_val);
}

int main(int argc, char *argv[])
{
	int ret;

	ret = unshare(CLONE_NEWNS);
	if (ret) {
		error("%s - Failed to unshare mount namespace", strerror(errno));
		exit(EXIT_FAILURE);
	}

	int fd = open("/proc/self/ns/mount", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		exit(EXIT_FAILURE);

	ret = mount(NULL, "/", NULL, MS_SLAVE|MS_REC, NULL);
	if (ret) {
		error("%s - Failed to remount \"/\" as slave", strerror(errno));
		exit(EXIT_FAILURE);
	}

	ret = mkdir("/sys/fs/cgroup", 0755);
	if (ret && errno != EEXIST) {
		error("%s - Failed to create \"/sys/fs/cgroup\" mountpoint",
		      strerror(errno));
		exit(EXIT_FAILURE);
	}

	ret = mount("tmpfs", "/sys/fs/cgroup", "tmpfs",
		    MS_NOSUID | MS_NODEV | MS_NOEXEC, "mode=755");
	if (ret) {
		error("%s - Failed to mount tmpfs at \"/sys/fs/cgroup\"",
		      strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (!has_fs_type("/sys/fs/cgroup/systemd", CGROUP_SUPER_MAGIC)) {
		ret = mkdir("/sys/fs/cgroup/systemd", 0755);
		if (ret && errno != EEXIST) {
			error("%s - Failed to create \"/sys/fs/cgroup/systemd\" mountpoint",
			      strerror(errno));
			exit(EXIT_FAILURE);
		}
		ret = mount("cgroup", "/sys/fs/cgroup/systemd", "cgroup",
			    MS_NOSUID | MS_NODEV | MS_NOEXEC,
			    "none,name=systemd,xattr");
		if (ret) {
			error("%s - Failed to mount name=systemd controller at \"/sys/fs/cgroup/systemd\"",
			      strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

	if (!has_fs_type("/sys/fs/cgroup/unified", CGROUP2_SUPER_MAGIC)) {
		ret = mkdir("/sys/fs/cgroup/unified", 0755);
		if (ret && errno != EEXIST) {
			error("%s - Failed to create \"/sys/fs/cgroup/unified\" mountpoint",
					strerror(errno));
			exit(EXIT_FAILURE);
		}

		ret = mount("cgroup2", "/sys/fs/cgroup/unified", "cgroup2",
			    MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL);
		if (ret) {
			error("%s - Failed to mount cgroup2 at \"/sys/fs/cgroup/unified\"",
					strerror(errno));
			(void)rmdir("/sys/fs/cgroup/unified");
		}
	}

	exit(EXIT_SUCCESS);
}
