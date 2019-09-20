/*-
 * Copyright (c) 2018 UPLEX Nils Goroll Systemoptimierung
 * All rights reserved
 *
 * Author: Geoffrey Simmons <geoffrey.simmons@uplex.de>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* for strdup() */
#define _POSIX_C_SOURCE 200809L

#include "config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

#include "cache/cache.h"
#include "vcl.h"

#include "vcc_if.h"

#define VFAIL(ctx, fmt, ...) \
        VRT_fail((ctx), "vmod file failure: " fmt, __VA_ARGS__)

struct file_info {
	unsigned	magic;
#define FILE_INFO_MAGIC 0x46ebec3d
	struct timespec	mtime;
	dev_t		dev;
	ino_t		ino;
};

struct VPFX(file_reader) {
	unsigned		magic;
#define FILE_READER_MAGIC 0x08d18e5b
	struct file_info	*info;
	char			*vcl_name;
	char			*path;
	char			*addr;
	size_t			len;
	VCL_DURATION		ttl;
	VCL_TIME		t_expire;
};

static inline int
do_stat(VRT_CTX, struct VPFX(file_reader) *rdr, struct stat *st,
	const char *method)
{
	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(rdr, FILE_READER_MAGIC);
	AN(st);
	
	errno = 0;
	if (stat(rdr->path, st) != 0) {
		VFAIL(ctx, "%s.%s(): cannot read info about %s: %s",
		      rdr->vcl_name, method,  rdr->path, vstrerror(errno));
		return (-1);
	}

	if (!S_ISREG(st->st_mode)) {
		VFAIL(ctx, "%s.%s(): %s is not a regular file", rdr->vcl_name,
		      method, rdr->path);
		return (-1);
	}
	return (0);
}

static int
update_map(VRT_CTX, struct VPFX(file_reader) *rdr, struct stat *st,
	   const char *method)
{
	struct file_info *info;
	int fd;
	void *addr;

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(rdr, FILE_READER_MAGIC);
	CHECK_OBJ_NOTNULL(rdr->info, FILE_INFO_MAGIC);
	AN(st);
	info = rdr->info;

	errno = 0;
	if ((fd = open(rdr->path, O_RDWR)) < 0) {
		VFAIL(ctx, "%s.%s(): cannot open %s: %s", rdr->vcl_name, method,
		      rdr->path, vstrerror(errno));
		return (-1);
	}

	errno = 0;
	if ((addr = mmap(NULL, st->st_size + 1, PROT_READ|PROT_WRITE,
			 MAP_PRIVATE, fd, 0)) == MAP_FAILED) {
		VFAIL(ctx, "%s.%s(): could not map %s: %s", rdr->vcl_name,
		      method, rdr->path, vstrerror(errno));
		closefd(&fd);
		return (-1);
	}
	closefd(&fd);

	/*
	 * Add a terminating null byte, so that the mapped file can be
	 * used as a VCL_STRING or a C string.
	 */
	*((char *)(addr + st->st_size)) = '\0';

	info->mtime.tv_sec = st->st_mtim.tv_sec;
	info->mtime.tv_nsec = st->st_mtim.tv_nsec;
	info->dev = st->st_dev;
	info->ino = st->st_ino;

	rdr->addr = addr;
	rdr->len = st->st_size + 1;
	return (0);
}

VCL_VOID
vmod_reader__init(VRT_CTX, struct VPFX(file_reader) **rdrp,
		  const char *vcl_name, struct vmod_priv *priv,
		  VCL_STRING name, VCL_DURATION ttl)
{
	struct VPFX(file_reader) *rdr;
	struct file_info *info;
	struct stat st;

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	AN(rdrp);
	AZ(*rdrp);
	AN(vcl_name);
	AN(priv);

	if (name == NULL) {
		VFAIL(ctx, "new %s: name is NULL", vcl_name);
		return;
	}
	if (ttl <= 0) {
		VFAIL(ctx, "new %s: ttl %.03f must be > 0", vcl_name, ttl);
		return;
	}

	errno = 0;
	ALLOC_OBJ(info, FILE_INFO_MAGIC);
	if (info == NULL) {
		VFAIL(ctx, "new %s: allocating space for file info: %s",
		      vcl_name, vstrerror(errno));
		return;
	}

	errno = 0;
	ALLOC_OBJ(rdr, FILE_READER_MAGIC);
	if (rdr == NULL) {
		VFAIL(ctx, "new %s: allocating space for object: %s",
		      vcl_name, vstrerror(errno));
		return;
	}

	rdr->info = info;
	rdr->vcl_name = strdup(vcl_name);
	rdr->path = strdup(name);
	rdr->ttl = ttl;
	rdr->t_expire = ctx->now + ttl;

	if (do_stat(ctx, rdr, &st, "new") != 0)
		return;
	if (update_map(ctx, rdr, &st, "new") != 0)
		return;

	*rdrp = rdr;
}

VCL_VOID
vmod_reader__fini(struct VPFX(file_reader) **rdrp)
{
	struct VPFX(file_reader) *rdr;

	if (rdrp == NULL)
		return;
	TAKE_OBJ_NOTNULL(rdr, rdrp, FILE_READER_MAGIC);

	errno = 0;
	if (munmap(rdr->addr, rdr->len) != 0)
		VSL(SLT_Error, 0, "unmap failed in %s finalization: %s",
		    rdr->vcl_name, vstrerror(errno));

	if (rdr->info != NULL) {
		CHECK_OBJ(rdr->info, FILE_INFO_MAGIC);
		FREE_OBJ(rdr->info);
	}
	if (rdr->vcl_name != NULL)
		free(rdr->vcl_name);
	if (rdr->path != NULL)
		free(rdr->path);
	FREE_OBJ(rdr);
}

VCL_STRING
vmod_reader_get(VRT_CTX, struct VPFX(file_reader) *rdr)
{
	struct file_info *info;
	struct stat st;
	double intervals, whole, frac;

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(rdr, FILE_READER_MAGIC);
	CHECK_OBJ_NOTNULL(rdr->info, FILE_INFO_MAGIC);
	AN(rdr->addr);
	info = rdr->info;

	if (ctx->now <= rdr->t_expire)
		return (rdr->addr);

	if (do_stat(ctx, rdr, &st, "get") != 0)
		return (NULL);

	if (info->mtime.tv_sec == st.st_mtim.tv_sec
	    && info->mtime.tv_nsec == st.st_mtim.tv_nsec
	    && info->dev == st.st_dev && info->ino == st.st_ino)
		return (rdr->addr);

	if (update_map(ctx, rdr, &st, "get") != 0)
		return (NULL);

	intervals = (ctx->now - rdr->t_expire) / rdr->ttl;
	frac = modf(intervals, &whole);
	rdr->t_expire = ctx->now + (rdr->ttl * (1. - frac));
	return (rdr->addr);
}

VCL_STRING
vmod_version(VRT_CTX)
{
	(void) ctx;
	return VERSION;
}

/* Event function */

int
VPFX(event)(VRT_CTX, struct vmod_priv *priv, enum vcl_event_e e)
{
	ASSERT_CLI();
	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	AN(priv);

	switch (e) {
	case VCL_EVENT_LOAD:
	case VCL_EVENT_DISCARD:
	case VCL_EVENT_WARM:
	case VCL_EVENT_COLD:
		return (0);
	default:
		WRONG("illegal event enum");
	}
	NEEDLESS(return (0));
}
