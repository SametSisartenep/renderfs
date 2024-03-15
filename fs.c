#include <u.h>
#include <libc.h>
#include <auth.h>
#include <thread.h>
#include <draw.h>
#include <memdraw.h>
#include <fcall.h>
#include <9p.h>

typedef struct Dirtab Dirtab;

struct Dirtab
{
	char *name;
	uchar type;
	uint qidpath;
	uint perm;
};

enum {
	Qroot,
	Qctl,
	Qframe,
};

char Ebotch[] = "9P protocol botch";
char Enotfound[] = "file not found";
char Enotdir[] = "not a directory";
char Eperm[] = "permission denied";

Dirtab dirtab[] = {
	"/",		QTDIR,	Qroot,	0555|DMDIR,
	"ctl",		QTFILE,	Qctl,	0600,
	"frame",	QTFILE,	Qframe,	0444,
};
char *jefe = "Pablo R. Picasso";
Memimage *fb;

static int
mode2perm(int m)
{
	static int perms[4] = {4, 2, 6, 1};

	return perms[m&OMASK];
}

static void
fillstat(Dir *dir, Dirtab *d)
{
	dir->name = estrdup9p(d->name);
	dir->uid = estrdup9p(jefe);
	dir->gid = estrdup9p(jefe);
	dir->mode = d->perm;
	dir->length = 0;
	dir->qid = (Qid){d->qidpath, 0, d->type};
	dir->atime = time(0);
	dir->mtime = time(0);
	dir->muid = estrdup9p("");
}

static int
dirgen(int n, Dir *dir, void*)
{
	if(++n >= nelem(dirtab))
		return -1;
	fillstat(dir, &dirtab[n]);
	return 0;
}

static int
readimg(Memimage *i, char *t, Rectangle r, int offset, int n)
{
	int ww, oo, y, m;
	uchar *tt;

	ww = bytesperline(r, i->depth);
	r.min.y += offset/ww;
	if(r.min.y >= r.max.y)
		return 0;

	y = r.min.y + (n + ww-1)/ww;
	if(y < r.max.y)
		r.max.y = y;

	m = ww * Dy(r);
	oo = offset % ww;
	if(oo == 0 && n >= m)
		return unloadmemimage(i, r, (uchar*)t, n);

	if((tt = malloc(m)) == nil)
		return -1;

	m = unloadmemimage(i, r, tt, m) - oo;
	if(m > 0){
		if(n < m) m = n;
		memmove(t, tt + oo, m);
	}

	free(tt);
	return m;
}

void
fsattach(Req *r)
{
	if(r->ifcall.aname && r->ifcall.aname[0]){
		respond(r, "invalid attach specifier");
		return;
	}

	r->ofcall.qid = (Qid){Qroot, 0, QTDIR};
	r->fid->qid = r->ofcall.qid;
	r->fid->aux = nil;
	respond(r, nil);
}

void
fsopen(Req *r)
{
	int i, perm, want;

	for(i = 0; i < nelem(dirtab); i++)
		if(r->fid->qid.path == dirtab[i].qidpath)
			break;

	if(i < nelem(dirtab)){
		if(strcmp(r->fid->uid, jefe) == 0)
			perm = dirtab[i].perm>>6;
		else
			perm = dirtab[i].perm;
	}else{
		respond(r, Ebotch);
		return;
	};

	if((r->ifcall.mode & (OTRUNC|OCEXEC|ORCLOSE)) != 0)
		goto deny;
	want = mode2perm(r->ifcall.mode);
	if((want & perm) != want){
deny:
		respond(r, Eperm);
		return;
	}
	respond(r, nil);
}

void
fsread(Req *r)
{
	Memimage *i;
	char buf[128], cbuf[30], *t;
	ulong off, cnt;
	int n;

	off = r->ifcall.offset;
	cnt = r->ifcall.count;

	switch(r->fid->qid.path){
	default:
		respond(r, "bug in fsread");
		break;
	case Qroot:
		dirread9p(r, dirgen, nil);
		respond(r, nil);
		break;
	case Qctl:
		respond(r, nil);
		break;
	case Qframe:
		i = fb;
		if(off < 5*12){
			n = snprint(buf, sizeof buf, "%11s %11d %11d %11d %11d ",
				chantostr(cbuf, i->chan),
				i->r.min.x, i->r.min.y, i->r.max.x, i->r.max.y);
			t = estrdup9p(buf);

			if(off > n){
				off = n;
				cnt = 0;
			}

			if(off+cnt > n)
				cnt = n-off;

			r->ofcall.data = t+off;
			r->ofcall.count = cnt;
			respond(r, nil);
			free(t);
			break;
		}

		off -= 5*12;
		n = -1;
		t = malloc(cnt);
		if(t != nil){
			r->ofcall.data = t;
			n = readimg(i, t, i->r, off, cnt);
		}

		if(n < 0){
			buf[0] = 0;
			errstr(buf, sizeof buf);
			respond(r, buf);
		}else{
			r->ofcall.count = n;
			respond(r, nil);
		}
		free(t);
		break;
	}
}

void
fswrite(Req *r)
{
	char *msg, *f[10];
	ulong cnt, nf;
	int i;

	cnt = r->ifcall.count;

	switch(r->fid->qid.path){
	default:
		respond(r, "bug in fswrite");
		break;
	case Qctl:
		msg = emalloc9p(cnt+1);
		memmove(msg, r->ifcall.data, cnt);
		msg[cnt] = 0;
		nf = tokenize(msg, f, nelem(f));
		for(i = 0; i < nf; i++)
			fprint(2, "%s[%d]%s%s", i == 0? "": " ", i, f[i], i == nf-1? "\n": "");
		free(msg);
		r->ofcall.count = cnt;
		respond(r, nil);
		break;
	}
}

void
fsstat(Req *r)
{
	int i;

	for(i = 0; i < nelem(dirtab); i++)
		if(r->fid->qid.path == dirtab[i].qidpath){
			fillstat(&r->d, &dirtab[i]);
			respond(r, nil);
			return;
		}
	respond(r, Enotfound);	
}

char *
fswalk1(Fid *f, char *name, Qid *qid)
{
	int i;

	switch(f->qid.path){
	case Qroot:
		if(strcmp(name, "..") == 0){
			*qid = f->qid;
			return nil;
		}
		for(i = 1; i < nelem(dirtab); i++)
			if(strcmp(name, dirtab[i].name) == 0){
				*qid = (Qid){dirtab[i].qidpath, 0, 0};
				f->qid = *qid;
				return nil;
			}
		return Enotfound;
	default:
		return Enotdir;
	}
}

char *
fsclone(Fid *old, Fid *new)
{
	USED(old, new);
	return nil;
}

Srv fs = {
	.attach	= fsattach,
	.open	= fsopen,
	.read	= fsread,
	.write	= fswrite,
	.stat	= fsstat,
	.walk1	= fswalk1,
	.clone	= fsclone,
};

void
usage(void)
{
	fprint(2, "usage: %s [-D] [-s srvname] [-m mtpt]\n", argv0);
	exits("usage");
}

void
threadmain(int argc, char *argv[])
{
	char *srvname, *mtpt;
	int fd;

	srvname = "render";
	mtpt = "/mnt/render";
	ARGBEGIN{
	case 'D':
		chatty9p++;
		break;
	case 's':
		srvname = EARGF(usage());
		break;
	case 'm':
		mtpt = EARGF(usage());
		break;
	default: usage();
	}ARGEND
	if(argc != 0)
		usage();

	jefe = getuser();

	fd = open("/dev/window", OREAD);
	if(fd < 0)
		sysfatal("open: %r");
	fb = readmemimage(fd);
	if(fb == nil)
		sysfatal("readmemimage: %r");
	close(fd);

	threadpostmountsrv(&fs, srvname, mtpt, MREPL|MCREATE);
	exits(nil);
}
