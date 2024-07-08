#include <sys/types.h>
#include <sys/systm.h>
#include <sys/param.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/conf.h>
#include <sys/uio.h>
#include <sys/malloc.h>
#include <sys/ioccom.h>

static d_open_t pwn_open;
static d_close_t pwn_close;
static d_ioctl_t pwn_ioctl;

static struct cdevsw pwn_cdevsw = {
	.d_version = D_VERSION,
	.d_open = pwn_open,
	.d_close = pwn_close,
	.d_ioctl = pwn_ioctl,
	.d_name = "pwn",
};

static struct cdev *pwn_dev;

static int pwn_loader(struct module *m __unused, int what, void *arg __unused) {
	int error = 0;

	switch (what) {
	case MOD_LOAD:
		error = make_dev_p(MAKEDEV_CHECKNAME | MAKEDEV_WAITOK,
		    &pwn_dev,
		    &pwn_cdevsw,
		    0,
		    UID_ROOT,
		    GID_WHEEL,
		    0666,
		    "pwn");
		if (error != 0)
			break;

		printf("PWN device loaded.\n");
		break;
	case MOD_UNLOAD:
		destroy_dev(pwn_dev);
		printf("PWN  device unloaded.\n");
		break;
	default:
		error = EOPNOTSUPP;
		break;
	}
	return (error);
}

static int pwn_open(struct cdev *dev __unused, int oflags __unused, int devtype __unused, struct thread *td __unused) {
	return (0);
}

static int pwn_close(struct cdev *dev __unused, int fflag __unused, int devtype __unused, struct thread *td __unused) {
	return (0);
}

struct pwndata {
	char data[128];
};

#define	PWN_IOC_ALLOC _IO('v', 0x00)
#define	PWN_IOC_FREE _IO('v', 0x01)
#define	PWN_IOC_EDIT _IOWR('v', 0x02, struct pwndata)

static bool allocdone = false;
static bool freedone = false;
static bool editdone = false;
static void *pwnbuf = NULL;

static int pwn_ioctl(struct cdev *dev, u_long cmd, caddr_t data, int fflag, struct thread *td) {
	switch (cmd) {
		case PWN_IOC_ALLOC:
			if (!allocdone)
				pwnbuf = malloc(128, M_DEVBUF, M_WAITOK | M_ZERO);
			allocdone = true;
			break;
		case PWN_IOC_FREE:
			if (!freedone && allocdone)
				free(pwnbuf, M_DEVBUF);
			freedone = true;
			break;
		case PWN_IOC_EDIT:
			if (!editdone && allocdone)
				memcpy(pwnbuf, data, 128);
			editdone = true;
			break;
		default:
			return (-1);
	}
	return (0);
}

DEV_MODULE(pwn, pwn_loader, NULL);