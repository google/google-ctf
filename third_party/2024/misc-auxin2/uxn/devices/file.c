#define _XOPEN_SOURCE 500
#include <stdio.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef _WIN32
#include <libiberty/libiberty.h>
#define realpath(s, dummy) lrealpath(s)
#define DIR_SEP_CHAR '\\'
#define DIR_SEP_STR "\\"
#define pathcmp(path1, path2, length) strncasecmp(path1, path2, length) /* strncasecmp provided by libiberty */
#define notdriveroot(file_name) (file_name[0] != DIR_SEP_CHAR && ((strlen(file_name) > 2 && file_name[1] != ':') || strlen(file_name) <= 2))
#else
#define DIR_SEP_CHAR '/'
#define DIR_SEP_STR "/"
#define pathcmp(path1, path2, length) strncmp(path1, path2, length)
#define notdriveroot(file_name) (file_name[0] != DIR_SEP_CHAR)
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#include "../uxn.h"
#include "file.h"

/*
Copyright (c) 2021-2023 Devine Lu Linvega, Andrew Alderwick

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE.
*/

typedef struct {
	FILE *f;
	DIR *dir;
	char current_filename[4096];
	struct dirent *de;
	enum { IDLE,
		FILE_READ,
		FILE_WRITE,
		DIR_READ } state;
	int outside_sandbox;
} UxnFile;

static UxnFile uxn_file[POLYFILEY];

static char
inthex(int n)
{
	n &= 0xf;
	return n < 10 ? '0' + n : 'a' + (n - 10);
}

static void
reset(UxnFile *c)
{
	if(c->f != NULL)
		fclose(c->f), c->f = NULL;
	if(c->dir != NULL)
		closedir(c->dir), c->dir = NULL;
	c->de = NULL;
	c->state = IDLE;
	c->outside_sandbox = 0;
}

static Uint16
put_line(char *p, Uint16 len, const char *pathname, const char *basename, int fail_nonzero)
{
	struct stat st;
	if(len < strlen(basename) + 8)
		return 0;
	if(stat(pathname, &st))
		return fail_nonzero ? snprintf(p, len, "!!!! %s\n", basename) : 0;
	else if(S_ISDIR(st.st_mode))
		return snprintf(p, len, "---- %s/\n", basename);
	else if(st.st_size < 0x10000)
		return snprintf(p, len, "%04x %s\n", (unsigned int)st.st_size, basename);
	else
		return snprintf(p, len, "???? %s\n", basename);
}

static Uint16
file_read_dir(UxnFile *c, char *dest, Uint16 len)
{
	static char pathname[4352];
	char *p = dest;
	if(c->de == NULL) c->de = readdir(c->dir);
	for(; c->de != NULL; c->de = readdir(c->dir)) {
		Uint16 n;
		if(c->de->d_name[0] == '.' && c->de->d_name[1] == '\0')
			continue;
		if(strcmp(c->de->d_name, "..") == 0) {
			/* hide "sandbox/.." */
			char cwd[PATH_MAX] = {'\0'}, *t;
			/* Note there's [currently] no way of chdir()ing from uxn, so $PWD
			 * is always the sandbox top level. */
			getcwd(cwd, sizeof(cwd));
			/* We already checked that c->current_filename exists so don't need a wrapper. */
			t = realpath(c->current_filename, NULL);
			if(strcmp(cwd, t) == 0) {
				free(t);
				continue;
			}
			free(t);
		}
		if(strlen(c->current_filename) + 1 + strlen(c->de->d_name) < sizeof(pathname))
			snprintf(pathname, sizeof(pathname), "%s/%s", c->current_filename, c->de->d_name);
		else
			pathname[0] = '\0';
		n = put_line(p, len, pathname, c->de->d_name, 1);
		if(!n) break;
		p += n;
		len -= n;
	}
	return p - dest;
}

static char *
retry_realpath(const char *file_name)
{
	char *r, p[PATH_MAX] = {'\0'}, *x;
	int fnlen;
	if(file_name == NULL) {
		errno = EINVAL;
		return NULL;
	} else if((fnlen = strlen(file_name)) >= PATH_MAX) {
		errno = ENAMETOOLONG;
		return NULL;
	}
	if(notdriveroot(file_name)) {
		/* TODO: use a macro instead of '/' for absolute path first character so that other systems can work */
		/* if a relative path, prepend cwd */
		getcwd(p, sizeof(p));
		if(strlen(p) + strlen(DIR_SEP_STR) + fnlen >= PATH_MAX) {
			errno = ENAMETOOLONG;
			return NULL;
		}
		strcat(p, DIR_SEP_STR); /* TODO: use a macro instead of '/' for the path delimiter */
	}
	strcat(p, file_name);
	while((r = realpath(p, NULL)) == NULL) {
		if(errno != ENOENT)
			return NULL;
		x = strrchr(p, DIR_SEP_CHAR); /* TODO: path delimiter macro */
		if(x)
			*x = '\0';
		else
			return NULL;
	}
	return r;
}

static void
file_check_sandbox(UxnFile *c)
{
	char *x, *rp, cwd[PATH_MAX] = {'\0'};
	x = getcwd(cwd, sizeof(cwd));
	rp = retry_realpath(c->current_filename);
	if(rp == NULL || (x && pathcmp(cwd, rp, strlen(cwd)) != 0)) {
		c->outside_sandbox = 1;
		fprintf(stderr, "file warning: blocked attempt to access %s outside of sandbox\n", c->current_filename);
	}
	free(rp);
}

static Uint16
file_init(UxnFile *c, char *filename, size_t max_len, int override_sandbox)
{
	char *p = c->current_filename;
	size_t len = sizeof(c->current_filename);
	reset(c);
	if(len > max_len) len = max_len;
	while(len) {
		if((*p++ = *filename++) == '\0') {
			if(!override_sandbox) /* override sandbox for loading roms */
				file_check_sandbox(c);
			return 0;
		}
		len--;
	}
	c->current_filename[0] = '\0';
	return 0;
}

static Uint16
file_read(UxnFile *c, void *dest, int len)
{
	if(c->outside_sandbox) return 0;
	if(c->state != FILE_READ && c->state != DIR_READ) {
		reset(c);
		if((c->dir = opendir(c->current_filename)) != NULL)
			c->state = DIR_READ;
		else if((c->f = fopen(c->current_filename, "rb")) != NULL)
			c->state = FILE_READ;
	}
	if(c->state == FILE_READ)
		return fread(dest, 1, len, c->f);
	if(c->state == DIR_READ)
		return file_read_dir(c, dest, len);
	return 0;
}

static Uint16
file_write(UxnFile *c, void *src, Uint16 len, Uint8 flags)
{
	Uint16 ret = 0;
	if(c->outside_sandbox) return 0;
	if(c->state != FILE_WRITE) {
		reset(c);
		if((c->f = fopen(c->current_filename, (flags & 0x01) ? "ab" : "wb")) != NULL)
			c->state = FILE_WRITE;
	}
	if(c->state == FILE_WRITE) {
		if((ret = fwrite(src, 1, len, c->f)) > 0 && fflush(c->f) != 0)
			ret = 0;
	}
	return ret;
}

static Uint16
file_stat(UxnFile *c, char *p, Uint16 len)
{
	unsigned int i, size;
	struct stat st;
	if(c->outside_sandbox || !len)
		return 0;
	if(stat(c->current_filename, &st))
		for(i = 0; i < len; i++)
			p[i] = '!';
	else if(S_ISDIR(st.st_mode))
		for(i = 0; i < len; i++)
			p[i] = '-';
	else if(st.st_size >= 1 << (len << 2))
		for(i = 0; i < len; i++)
			p[i] = '?';
	else
		for(i = 0, size = st.st_size; i < len; i++)
			p[i] = inthex(size >> ((len - i - 1) << 2));
	return len;
}

static Uint16
file_delete(UxnFile *c)
{
	return c->outside_sandbox ? 0 : unlink(c->current_filename);
}

/* file registers */

static Uint16 rL;

/* IO */

void
file_deo(Uint8 id, Uint8 *ram, Uint8 *d, Uint8 port)
{
	UxnFile *c = &uxn_file[id];
	Uint16 addr, res;
	switch(port) {
	case 0x5:
		addr = (d[0x4] << 8) | d[0x5];
		if(rL > 0x10000 - addr) rL = 0x10000 - addr;
		res = file_stat(c, (char *)&ram[addr], rL > 0x10 ? 0x10 : rL);
		d[0x2] = res >> 8, d[0x3] = res;
		return;
	case 0x6:
		res = file_delete(c);
		d[0x2] = res >> 8, d[0x3] = res;
		return;
	case 0x9:
		addr = (d[0x8] << 8) | d[0x9];
		res = file_init(c, (char *)&ram[addr], 0x10000 - addr, 0);
		d[0x2] = res >> 8, d[0x3] = res;
		return;
	case 0xa:
	case 0xb:
		rL = (d[0xa] << 8) | d[0xb];
		return;
	case 0xd:
		addr = (d[0xc] << 8) | d[0xd];
		if(rL > 0x10000 - addr) rL = 0x10000 - addr;
		res = file_read(c, &ram[addr], rL);
		d[0x2] = res >> 8, d[0x3] = res;
		return;
	case 0xf:
		addr = (d[0xe] << 8) | d[0xf];
		if(rL > 0x10000 - addr) rL = 0x10000 - addr;
		res = file_write(c, &ram[addr], rL, d[0x7]);
		d[0x2] = res >> 8, d[0x3] = res;
		return;
	}
}
