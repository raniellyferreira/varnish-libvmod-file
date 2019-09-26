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
#include "vsb.h"

#include "vcc_if.h"

#define VFAIL(ctx, fmt, ...)					\
        VRT_fail((ctx), "vmod file failure: " fmt, __VA_ARGS__)

#define VERRMSG(rdr, fmt, ...)						\
	snprintf((rdr)->errbuf, (rdr)->errlen, "vmod file failure: " fmt, \
		 __VA_ARGS__)

/* Other VMODs may check the result of .blob() for this value, see vrt.h */
#define VMOD_FILE_BLOB_MAGIC 0x069392c4

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
	VCL_BOOL	log_checks;
};

#define RDR_INITIALIZED	(1 << 0)
#define RDR_ERROR	(1 << 1)
#define RDR_MAPPED	(1 << 2)
#define RDR_TIMER_INIT	(1 << 3)
#define RDR_DELETED	(1 << 4)

struct VPFX(file_reader) {
	unsigned		magic;
#define FILE_READER_MAGIC 0x08d18e5b
	pthread_rwlock_t	lock;
	struct file_info	*info;
	char			*addr;
	char			*vcl_name;
	char			*obj_name;
	char			*errbuf;
	size_t			errlen;
	timer_t			timerid;
	int			flags;
};

struct timer_entry {
	unsigned		magic;
#define TIMER_ENTRY_MAGIC 0xa0059ebd
	VSLIST_ENTRY(timer_entry) list;
	timer_t			timerid;
};

VSLIST_HEAD(timer_head, timer_entry);

static void
check(union sigval val)
{
	struct VPFX(file_reader) *rdr;
	struct file_info *info;
	struct stat st;
	int fd = -1;
	void *addr;
	char timbuf[VTIM_FORMAT_SIZE];
	int err;

	CAST_OBJ_NOTNULL(rdr, val.sival_ptr, FILE_READER_MAGIC);
	CHECK_OBJ_NOTNULL(rdr->info, FILE_INFO_MAGIC);
	info = rdr->info;
	AN(rdr->vcl_name);
	AN(rdr->obj_name);
	AN(rdr->errbuf);
	AN(info->path);

	if (info->log_checks) {
		VTIM_format(VTIM_real(), timbuf);
		VSL(SLT_Debug, 0,
		    "vmod file: %s.%s: check for %s running at %s",
		    rdr->vcl_name, rdr->obj_name, info->path, timbuf);
	}

	AZ(pthread_rwlock_wrlock(&rdr->lock));

	errno = 0;
	if ((fd = open(info->path, O_RDONLY)) < 0) {
		if (errno == ENOENT && (rdr->flags & RDR_MAPPED) != 0) {
			rdr->flags |= RDR_DELETED;
			VSL(SLT_Debug, 0, "vmod file: %s.%s: %s is deleted but "
			    "already mapped", rdr->vcl_name, rdr->obj_name,
			    info->path);
			goto out;
		}
		VERRMSG(rdr, "%s.%s: cannot open %s: %s", rdr->vcl_name,
			rdr->obj_name, info->path, vstrerror(errno));
		VSL(SLT_Error, 0, rdr->errbuf);
		rdr->flags |= RDR_ERROR;
		goto out;
	}
	rdr->flags &= ~RDR_DELETED;

	errno = 0;
	if (fstat(fd, &st) != 0) {
		VERRMSG(rdr, "%s.%s: cannot read info about %s: %s",
			rdr->vcl_name, rdr->obj_name, info->path,
			vstrerror(errno));
		VSL(SLT_Error, 0, rdr->errbuf);
		rdr->flags |= RDR_ERROR;
		goto out;
	}

	if (!S_ISREG(st.st_mode)) {
		VERRMSG(rdr, "%s.%s: %s is not a regular file", rdr->vcl_name,
			rdr->obj_name, info->path);
		VSL(SLT_Error, 0, rdr->errbuf);
		rdr->flags |= RDR_ERROR;
		goto out;
	}

	if ((rdr->flags & (RDR_INITIALIZED | RDR_MAPPED))
	    && info->mtime.tv_sec == st.st_mtim.tv_sec
	    && info->mtime.tv_nsec == st.st_mtim.tv_nsec
	    && info->dev == st.st_dev && info->ino == st.st_ino) {
		AN(rdr->addr);
		goto out;
	}

	if (info->log_checks) {
		VTIM_format(VTIM_real(), timbuf);
		VSL(SLT_Debug, 0, "vmod file: %s.%s: updating %s at %s",
		    rdr->vcl_name, rdr->obj_name, info->path, timbuf);
	}

	if (rdr->flags & RDR_MAPPED) {
		AN(rdr->addr);
		if (munmap(rdr->addr, info->len) != 0) {
			VERRMSG(rdr, "%s.%s: unmap failed: %s", rdr->vcl_name,
				rdr->obj_name, vstrerror(errno));
			VSL(SLT_Error, 0, rdr->errbuf);
			rdr->flags |= RDR_ERROR;
			goto out;
		}
	}
	rdr->flags &= ~RDR_MAPPED;

	/*
	 * By mapping the length st_size + 1, and due to the fact that
	 * mmap(2) fills the region of the mapped page past the length of
	 * the file with 0's, we ensure that there is a terminating null
	 * byte in the mapping after the file contents. So that the mapped
	 * address can be used as a VCL_STRING or a C string, without
	 * having to make copies.
	 */
	errno = 0;
	if ((addr = mmap(NULL, st.st_size + 1, PROT_READ, MAP_PRIVATE, fd, 0))
	    == MAP_FAILED) {
		VERRMSG(rdr, "%s.%s: could not map %s: %s", rdr->vcl_name,
			rdr->obj_name, info->path, vstrerror(errno));
		VSL(SLT_Error, 0, rdr->errbuf);
		rdr->flags |= RDR_ERROR;
		goto out;
	}
	AN(addr);
	rdr->flags |= RDR_MAPPED;

	if ((err = posix_madvise(addr, st.st_size + 1, POSIX_MADV_SEQUENTIAL))
	    != 0) {
		VERRMSG(rdr, "%s.%s: madvise(SEQUENTIAL): %s", rdr->vcl_name,
			rdr->obj_name, vstrerror(err));
		VSL(SLT_Error, 0, rdr->errbuf);
		rdr->flags |= RDR_ERROR;
		goto out;
	}
	if ((err = posix_madvise(addr, st.st_size + 1, POSIX_MADV_WILLNEED))
	    != 0) {
		VERRMSG(rdr, "%s.%s: madvise(WILLNEED): %s", rdr->vcl_name,
			rdr->obj_name, vstrerror(err));
		VSL(SLT_Error, 0, rdr->errbuf);
		rdr->flags |= RDR_ERROR;
		goto out;
	}

	info->mtime.tv_sec = st.st_mtim.tv_sec;
	info->mtime.tv_nsec = st.st_mtim.tv_nsec;
	info->dev = st.st_dev;
	info->ino = st.st_ino;
	info->len = st.st_size + 1;

	rdr->addr = addr;
	rdr->flags &= ~RDR_ERROR;
	strcpy(rdr->errbuf, NO_ERR);
	rdr->flags |= RDR_INITIALIZED;

 out:
	AZ(pthread_rwlock_unlock(&rdr->lock));

	if (fd != -1)
		closefd(&fd);

	if ((rdr->flags & RDR_ERROR) == 0 && info->log_checks) {
		VTIM_format(VTIM_real(), timbuf);
		VSL(SLT_Debug, 0, "vmod file: %s.%s: check for %s "
		    "finished successfully at %s", rdr->vcl_name,
		    rdr->obj_name, info->path, timbuf);
	}
	return;
}

static struct timer_head *
init_priv_vcl(struct vmod_priv *priv)
{
	struct timer_head *th;

	AN(priv);
	if (priv->priv == NULL) {
		th = malloc(sizeof(*th));
		AN(th);
		priv->priv = th;
		VSLIST_INIT(th);
	}
	else
		th = priv->priv;
	return (th);
}

VCL_VOID
vmod_reader__init(VRT_CTX, struct VPFX(file_reader) **rdrp,
		  const char *vcl_name, struct vmod_priv *priv,
		  VCL_STRING name, VCL_STRING path, VCL_DURATION ttl,
		  VCL_BOOL log_checks)
{
	struct VPFX(file_reader) *rdr;
	struct file_info *info;
	struct sigevent sigev;
	timer_t timerid;
	struct itimerspec timerspec;
	struct timer_head *th;
	struct timer_entry *tent;

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	AN(rdrp);
	AZ(*rdrp);
	AN(vcl_name);
	AN(priv);

	if (name == NULL || *name == '\0') {
		VFAIL(ctx, "new %s: name is empty", vcl_name);
		return;
	}
	if (ttl < 0) {
		VFAIL(ctx, "new %s: ttl %.03f must be >= 0s", vcl_name, ttl);
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
	rdr->obj_name = strdup(vcl_name);
	rdr->vcl_name = strdup(VCL_Name(ctx->vcl));
	info->log_checks = log_checks;

	if (*name == '/')
		info->path = strdup(name);
	else {
		struct vsb *search;
		char *end, delim = ':';
		int fd = -1;

		AZ(info->path);
		if (path == NULL || *path == '\0') {
			VFAIL(ctx, "new %s: path is empty", vcl_name);
			return;
		}
		search = VSB_new_auto();
		for (const char *start = path; delim == ':'; VSB_clear(search),
			     start = end + 1) {
			end = strchr(start, delim);
			if (end == NULL) {
				delim = '\0';
				end = strchr(start, delim);
			}

			VSB_bcat(search, start, end - start);
			if (*(end - 1) != '/')
				VSB_putc(search, '/');
			VSB_cat(search, name);
			VSB_finish(search);
			if ((fd = open(VSB_data(search), O_RDONLY)) < 0)
				continue;

			info->path = malloc(VSB_len(search) + 1);
			if (info->path == NULL) {
				VSB_destroy(&search);
				closefd(&fd);
				VFAIL(ctx, "new %s: allocating path", vcl_name);
				return;
			}
			strcpy(info->path, VSB_data(search));
			break;
		}
		VSB_destroy(&search);
		if (fd != -1)
			closefd(&fd);
		if (info->path == NULL) {
			VFAIL(ctx, "new %s: %s not found or not readable on "
			      "path %s", vcl_name, name, path);
			return;
		}
	}

	errno = 0;
	if (pthread_rwlock_init(&rdr->lock, NULL) != 0) {
		VFAIL(ctx, "new %s: initializing lock: %s", vcl_name,
		      vstrerror(errno));
		return;
	}

	rdr->errlen = ERRMSG_LEN + strlen(name) + strlen(vcl_name)
		+ strlen(VCL_Name(ctx->vcl));
	errno = 0;
	rdr->errbuf = malloc(rdr->errlen);
	if (rdr->errbuf == NULL) {
		VFAIL(ctx, "new %s: allocating error message buffer: %s",
		      vcl_name, vstrerror(errno));
		return;
	}

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

	th = init_priv_vcl(priv);
	AN(th);
	errno = 0;
	ALLOC_OBJ(tent, TIMER_ENTRY_MAGIC);
	if (tent == NULL) {
		VFAIL(ctx, "new %s: allocating timer list entry: %s", vcl_name,
		      vstrerror(errno));
		return;
	}
	tent->timerid = timerid;
	VSLIST_INSERT_HEAD(th, tent, list);

	AZ(rdr->addr);
	AZ(rdr->info->mtime.tv_sec);
	AZ(rdr->info->mtime.tv_nsec);
	AZ(rdr->flags & (RDR_INITIALIZED | RDR_ERROR | RDR_DELETED));
	do {
		VTIM_sleep(INIT_SLEEP_INTERVAL);
	} while ((rdr->flags & (RDR_INITIALIZED | RDR_ERROR)) == 0);

	if (rdr->flags & RDR_ERROR) {
		AN(strcmp(rdr->errbuf, NO_ERR));
		VFAIL(ctx, "new %s: %s", vcl_name, rdr->errbuf);
		return;
	}

	AN(rdr->flags & RDR_MAPPED);
	AZ(rdr->flags & RDR_DELETED);
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
		AN(rdr->obj_name);

		errno = 0;
		if (timer_delete(rdr->timerid) != 0)
			VSL(SLT_Error, 0, "vmod file %s.%s finalization: "
			    "cannot delete timer: %s", rdr->vcl_name,
			    rdr->obj_name, vstrerror(errno));
	}

	if (rdr->flags & RDR_MAPPED) {
		CHECK_OBJ_NOTNULL(rdr->info, FILE_INFO_MAGIC);
		AN(rdr->addr);
		AN(rdr->obj_name);

		errno = 0;
		if (munmap(rdr->addr, rdr->info->len) != 0)
			VSL(SLT_Error, 0, "vmod file %s.%s finalization: "
			    "unmap failed: %s", rdr->vcl_name, rdr->obj_name,
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
	if (rdr->obj_name != NULL)
		free(rdr->obj_name);
	if (rdr->errbuf != NULL)
		free(rdr->errbuf);
	FREE_OBJ(rdr);
}

#define ERRCHK(ctx, rdr, method, ret) do {				\
		if ((rdr)->flags & RDR_ERROR) {				\
			AN(strcmp((rdr)->errbuf, NO_ERR));		\
			VRT_fail((ctx), "%s." method "(): %s",		\
				 (rdr)->obj_name, (rdr)->errbuf);	\
			AZ(pthread_rwlock_unlock(&(rdr)->lock));	\
			return ret;					\
		}							\
	} while (0)

VCL_STRING
vmod_reader_get(VRT_CTX, struct VPFX(file_reader) *rdr)
{
	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(rdr, FILE_READER_MAGIC);

	AZ(pthread_rwlock_rdlock(&rdr->lock));
	ERRCHK(ctx, rdr, "get", NULL);

	AN(rdr->flags & RDR_MAPPED);
	AN(rdr->addr);

	AZ(pthread_rwlock_unlock(&rdr->lock));
	return (rdr->addr);
}

VCL_VOID
vmod_reader_synth(VRT_CTX, struct VPFX(file_reader) *rdr)
{
	const char *p[0];
	struct strands strands = { 1, p };

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(rdr, FILE_READER_MAGIC);

	if ((ctx->method & VCL_MET_SYNTH) == 0) {
		VRT_fail(ctx, "%s.synth() may only be called in vcl_synth",
			 rdr->obj_name);
		return;
	}

	AZ(pthread_rwlock_rdlock(&rdr->lock));
	ERRCHK(ctx, rdr, "synth", );

	AN(rdr->flags & RDR_MAPPED);
	AN(rdr->addr);
	strands.p[0] = rdr->addr;
	VRT_synth_page(ctx, &strands);

	AZ(pthread_rwlock_unlock(&rdr->lock));
	return;
}

VCL_BLOB
vmod_reader_blob(VRT_CTX, struct VPFX(file_reader) *rdr)
{
	struct vrt_blob *blob;

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(rdr, FILE_READER_MAGIC);
	CHECK_OBJ_NOTNULL(rdr->info, FILE_INFO_MAGIC);

	if (WS_ReserveSize(ctx->ws, sizeof(*blob)) == 0) {
		VRT_fail(ctx, "%s.blob(): cannot reserve workspace",
			 rdr->obj_name);
		return (NULL);
	}
	blob = (struct vrt_blob *)WS_Front(ctx->ws);
	blob->type = VMOD_FILE_BLOB_MAGIC;

	AZ(pthread_rwlock_rdlock(&rdr->lock));
	if (rdr->flags & RDR_ERROR) {
		AN(strcmp(rdr->errbuf, NO_ERR));
		VRT_fail(ctx, "%s.blob(): %s", rdr->obj_name, rdr->errbuf);
		AZ(pthread_rwlock_unlock(&rdr->lock));
		WS_Release(ctx->ws, 0);
		return (NULL);
	}

	blob->blob = rdr->addr;
	blob->len = rdr->info->len - 1;
	AZ(pthread_rwlock_unlock(&rdr->lock));

	WS_Release(ctx->ws, sizeof(*blob));
	return (blob);
}

VCL_BOOL
vmod_reader_error(VRT_CTX, struct VPFX(file_reader) *rdr)
{
	CHECK_OBJ_NOTNULL(rdr, FILE_READER_MAGIC);
	(void)ctx;

	return (rdr->flags & RDR_ERROR);
}

VCL_STRING
vmod_reader_errmsg(VRT_CTX, struct VPFX(file_reader) *rdr)
{
	CHECK_OBJ_NOTNULL(rdr, FILE_READER_MAGIC);
	(void)ctx;

	AN(rdr->errbuf);
	return (rdr->errbuf);
}

VCL_BOOL
vmod_reader_deleted(VRT_CTX, struct VPFX(file_reader) *rdr)
{
	CHECK_OBJ_NOTNULL(rdr, FILE_READER_MAGIC);
	(void)ctx;

	return (rdr->flags & RDR_DELETED);
}

VCL_BYTES
vmod_reader_size(VRT_CTX, struct VPFX(file_reader) *rdr)
{
	VCL_BYTES sz;

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(rdr, FILE_READER_MAGIC);
	CHECK_OBJ_NOTNULL(rdr->info, FILE_INFO_MAGIC);

	AZ(pthread_rwlock_rdlock(&rdr->lock));
	ERRCHK(ctx, rdr, "size", 0);
	sz = rdr->info->len - 1;
	AZ(pthread_rwlock_unlock(&rdr->lock));

	return (sz);
}

VCL_TIME
vmod_reader_mtime(VRT_CTX, struct VPFX(file_reader) *rdr)
{
	time_t secs;
	long nsecs;

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(rdr, FILE_READER_MAGIC);
	CHECK_OBJ_NOTNULL(rdr->info, FILE_INFO_MAGIC);

	AZ(pthread_rwlock_rdlock(&rdr->lock));
	ERRCHK(ctx, rdr, "mtime", 0.);
	secs = rdr->info->mtime.tv_sec;
	nsecs = rdr->info->mtime.tv_nsec;
	AZ(pthread_rwlock_unlock(&rdr->lock));

	return (secs + nsecs * 1e-9);
}

VCL_DURATION
vmod_reader_next_check(VRT_CTX, struct VPFX(file_reader) *rdr)
{
	struct itimerspec t;

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(rdr, FILE_READER_MAGIC);

	errno = 0;
	if (timer_gettime(rdr->timerid, &t) != 0) {
		VRT_fail(ctx, "%s.next_check(): timer read failed: %s",
			rdr->obj_name, vstrerror(errno));
		return (0.);
	}
	return (t.it_value.tv_sec + 1e-9 * t.it_value.tv_nsec);
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
	struct timer_head *th;
	struct timer_entry *ent;
	struct itimerspec timer;

	ASSERT_CLI();
	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	AN(priv);

	th = init_priv_vcl(priv);
	AN(th);

	switch (e) {
	case VCL_EVENT_DISCARD:
		while (!VSLIST_EMPTY(th)) {
			/* object .fini deletes the timers */
			ent = VSLIST_FIRST(th);
			CHECK_OBJ_NOTNULL(ent, TIMER_ENTRY_MAGIC);
			VSLIST_REMOVE_HEAD(th, list);
			FREE_OBJ(ent);
		}
		free(th);
		return (0);
	case VCL_EVENT_WARM:
		VSLIST_FOREACH(ent, th, list) {
			CHECK_OBJ_NOTNULL(ent, TIMER_ENTRY_MAGIC);
			errno = 0;
			if (timer_gettime(ent->timerid, &timer) != 0) {
				VSB_printf(ctx->msg,
					   "vmod file: reading timer: %s",
					   vstrerror(errno));
				return (-1);
			}
			timer.it_value.tv_sec = 0;
			timer.it_value.tv_nsec = 1;
			if (timer_settime(ent->timerid, 0, &timer, NULL) != 0) {
				VSB_printf(ctx->msg,
					   "vmod file: restarting timer: %s",
					   vstrerror(errno));
				return (-1);
			}
		}
		return (0);
	case VCL_EVENT_COLD:
		VSLIST_FOREACH(ent, th, list) {
			CHECK_OBJ_NOTNULL(ent, TIMER_ENTRY_MAGIC);
			errno = 0;
			if (timer_gettime(ent->timerid, &timer) != 0) {
				VSL(SLT_Error, 0,
				    "vmod file: reading timer: %s",
				    vstrerror(errno));
				continue;
			}
			timer.it_value.tv_sec = 0;
			timer.it_value.tv_nsec = 0;
			if (timer_settime(ent->timerid, 0, &timer, NULL) != 0) {
				VSL(SLT_Debug, 0,
				    "vmod file: suspending timer: %s",
				    vstrerror(errno));
				continue;
			}
		}
		return (0);
	case VCL_EVENT_LOAD:
		return (0);
	default:
		WRONG("illegal event enum");
	}
	NEEDLESS(return (0));
}
