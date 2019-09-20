/*-
 * Copyright (c) 2019 UPLEX Nils Goroll Systemoptimierung
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

/* for strdup() and timer_* */
#define _POSIX_C_SOURCE 200809L

#include "config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <stdio.h>

#include "cache/cache.h"
#include "vcl.h"
#include "vtim.h"

#include "vcc_if.h"

#define FAIL(ctx, msg)					\
        VRT_fail((ctx), "vmod file failure: " msg)

#define VFAIL(ctx, fmt, ...)					\
        VRT_fail((ctx), "vmod file failure: " fmt, __VA_ARGS__)

#define VERRMSG(rdr, fmt, ...)						\
	snprintf((rdr)->errbuf, (rdr)->errlen, "vmod file failure: " fmt, \
		 __VA_ARGS__)

#define INIT_SLEEP_INTERVAL 0.001
#define ERRMSG_LEN 128
#define NO_ERR ("No error")

struct file_info {
	unsigned	magic;
#define FILE_INFO_MAGIC 0x46ebec3d
	struct timespec	mtime;
	char		*path;
	size_t		len;
	dev_t		dev;
	ino_t		ino;
};

#define RDR_INITIALIZED	(1 << 0)
#define RDR_ERROR	(1 << 1)
#define RDR_MAPPED	(1 << 2)
#define RDR_TIMER_INIT	(1 << 3)

struct VPFX(file_reader) {
	unsigned		magic;
#define FILE_READER_MAGIC 0x08d18e5b
	timer_t			timerid;
	struct file_info	*info;
	char			*vcl_name;
	char			*addr;
	char			*errbuf;
	size_t			errlen;
	int			flags;
};

static void
check(union sigval val)
{
	struct VPFX(file_reader) *rdr;
	struct file_info *info;
	struct stat st;
	int fd;
	void *addr;

	CAST_OBJ_NOTNULL(rdr, val.sival_ptr, FILE_READER_MAGIC);
	CHECK_OBJ_NOTNULL(rdr->info, FILE_INFO_MAGIC);
	info = rdr->info;
	AN(rdr->vcl_name);
	AN(rdr->errbuf);
	AN(info->path);

	errno = 0;
	if (stat(info->path, &st) != 0) {
		VERRMSG(rdr, "%s: cannot read info about %s: %s", rdr->vcl_name,
			info->path, vstrerror(errno));
		VSL(SLT_Error, 0, rdr->errbuf);
		rdr->flags |= RDR_ERROR;
		return;
	}

	if (!S_ISREG(st.st_mode)) {
		VERRMSG(rdr, "%s: %s is not a regular file", rdr->vcl_name,
			info->path);
		VSL(SLT_Error, 0, rdr->errbuf);
		rdr->flags |= RDR_ERROR;
		return;
	}

	if ((rdr->flags & (RDR_INITIALIZED | RDR_MAPPED))
	    && info->mtime.tv_sec == st.st_mtim.tv_sec
	    && info->mtime.tv_nsec == st.st_mtim.tv_nsec
	    && info->dev == st.st_dev && info->ino == st.st_ino) {
		AN(rdr->addr);
		return;
	}

	if (rdr->flags & RDR_MAPPED) {
		AN(rdr->addr);
		if (munmap(rdr->addr, info->len) != 0) {
			VERRMSG(rdr, "%s: unmap failed: %s", rdr->vcl_name,
				vstrerror(errno));
			VSL(SLT_Error, 0, rdr->errbuf);
			rdr->flags |= RDR_ERROR;
			return;
		}
	}
	rdr->flags &= ~RDR_MAPPED;

	errno = 0;
	if ((fd = open(info->path, O_RDWR)) < 0) {
		VERRMSG(rdr, "%s: cannot open %s: %s", rdr->vcl_name,
			info->path, vstrerror(errno));
		VSL(SLT_Error, 0, rdr->errbuf);
		rdr->flags |= RDR_ERROR;
		return;
	}

	errno = 0;
	if ((addr = mmap(NULL, st.st_size + 1, PROT_READ|PROT_WRITE,
			 MAP_PRIVATE, fd, 0)) == MAP_FAILED) {
		VERRMSG(rdr, "%s: could not map %s: %s", rdr->vcl_name,
			info->path, vstrerror(errno));
		VSL(SLT_Error, 0, rdr->errbuf);
		rdr->flags |= RDR_ERROR;
		closefd(&fd);
		return;
	}
	closefd(&fd);
	AN(addr);
	rdr->flags |= RDR_MAPPED;

	/*
	 * Add a terminating null byte, so that the mapped file can be
	 * used as a VCL_STRING or a C string.
	 */
	*((char *)(addr + st.st_size)) = '\0';

	info->mtime.tv_sec = st.st_mtim.tv_sec;
	info->mtime.tv_nsec = st.st_mtim.tv_nsec;
	info->dev = st.st_dev;
	info->ino = st.st_ino;
	info->len = st.st_size + 1;

	rdr->addr = addr;
	rdr->flags &= ~RDR_ERROR;
	strcpy(rdr->errbuf, NO_ERR);
	rdr->flags |= RDR_INITIALIZED;
	return;
}

VCL_VOID
vmod_reader__init(VRT_CTX, struct VPFX(file_reader) **rdrp,
		  const char *vcl_name, struct vmod_priv *priv,
		  VCL_STRING name, VCL_DURATION ttl)
{
	struct VPFX(file_reader) *rdr;
	struct file_info *info;
	struct sigevent sigev;
	timer_t timerid;
	struct itimerspec timerspec;

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	AN(rdrp);
	AZ(*rdrp);
	AN(vcl_name);
	AN(priv);

	if (name == NULL) {
		VFAIL(ctx, "new %s: name is NULL", vcl_name);
		return;
	}
	if (*name == '\0') {
		VFAIL(ctx, "new %s: name is empty", vcl_name);
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

	rdr->errlen = ERRMSG_LEN + strlen(name) + strlen(vcl_name);
	errno = 0;
	rdr->errbuf = malloc(rdr->errlen);
	if (rdr->errbuf == NULL) {
		VFAIL(ctx, "new %s: allocating error message buffer: %s",
		      vcl_name, vstrerror(errno));
		return;
	}

	rdr->info = info;
	rdr->vcl_name = strdup(vcl_name);
	info->path = strdup(name);

	memset(&sigev, 0, sizeof(sigev));
	sigev.sigev_notify = SIGEV_THREAD;
	sigev.sigev_notify_function = check;
	sigev.sigev_value.sival_ptr = rdr;

	errno = 0;
	if (timer_create(CLOCK_MONOTONIC, &sigev, &timerid) != 0) {
		VFAIL(ctx, "new %s: cannot create update timer: %s", vcl_name,
		      vstrerror(errno));
		return;
	}
	rdr->timerid = timerid;

	timerspec.it_value.tv_sec = 0;
	timerspec.it_value.tv_nsec = 1;
	timerspec.it_interval.tv_sec = (time_t)ttl;
	assert(ttl - timerspec.it_interval.tv_sec < 1.);
	timerspec.it_interval.tv_nsec
		= (long)(1e9 * (ttl - timerspec.it_interval.tv_sec));

	errno = 0;
	if (timer_settime(timerid, 0, &timerspec, NULL) != 0) {
		VFAIL(ctx, "new %s: cannot start update timer: %s", vcl_name,
		      vstrerror(errno));
		return;
	}
	rdr->flags |= RDR_TIMER_INIT;


	AZ(rdr->addr);
	AZ(rdr->info->mtime.tv_sec);
	AZ(rdr->info->mtime.tv_nsec);
	AZ(rdr->flags & (RDR_INITIALIZED | RDR_ERROR));
	do {
		VTIM_sleep(INIT_SLEEP_INTERVAL);
	} while ((rdr->flags & (RDR_INITIALIZED | RDR_ERROR)) == 0);

	if (rdr->flags & RDR_ERROR) {
		AN(strcmp(rdr->errbuf, NO_ERR));
		VFAIL(ctx, "new %s: %s", vcl_name, rdr->errbuf);
		return;
	}

	AN(rdr->flags & RDR_MAPPED);
	AN(rdr->addr);
	AN(rdr->info->mtime.tv_sec);
	AN(rdr->info->mtime.tv_nsec);

	*rdrp = rdr;
}

VCL_VOID
vmod_reader__fini(struct VPFX(file_reader) **rdrp)
{
	struct VPFX(file_reader) *rdr;

	if (rdrp == NULL)
		return;
	TAKE_OBJ_NOTNULL(rdr, rdrp, FILE_READER_MAGIC);

	if (rdr->flags & RDR_TIMER_INIT) {
		AN(rdr->vcl_name);

		errno = 0;
		if (timer_delete(rdr->timerid) != 0)
			VSL(SLT_Error, 0, "vmod file %s finalization: "
			    "cannot delete timer: %s", rdr->vcl_name,
			    vstrerror(errno));
	}

	if (rdr->flags & RDR_MAPPED) {
		CHECK_OBJ_NOTNULL(rdr->info, FILE_INFO_MAGIC);
		AN(rdr->addr);
		AN(rdr->vcl_name);

		errno = 0;
		if (munmap(rdr->addr, rdr->info->len) != 0)
			VSL(SLT_Error, 0, "vmod file %s finalization: "
			    "unmap failed: %s", rdr->vcl_name,
			    vstrerror(errno));
	}

	if (rdr->info != NULL) {
		CHECK_OBJ(rdr->info, FILE_INFO_MAGIC);
		if (rdr->info->path != NULL)
			free(rdr->info->path);
		FREE_OBJ(rdr->info);
	}
	if (rdr->vcl_name != NULL)
		free(rdr->vcl_name);
	if (rdr->errbuf != NULL)
		free(rdr->errbuf);
	FREE_OBJ(rdr);
}

VCL_STRING
vmod_reader_get(VRT_CTX, struct VPFX(file_reader) *rdr)
{
	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(rdr, FILE_READER_MAGIC);

	if ((rdr->flags & RDR_ERROR) == 0) {
		AN(rdr->addr);
		AN(rdr->flags & RDR_MAPPED);
		return (rdr->addr);
	}

	AN(strcmp(rdr->errbuf, NO_ERR));
	VFAIL(ctx, "%s.get(): %s", rdr->vcl_name, rdr->errbuf);
	return (NULL);
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
