/*
 * vmci-backdoor-shim.so — LD_PRELOAD library for vcsim container-backed VMs.
 *
 * Strategy
 * ────────
 * libvmtools.so.0 contains functions that execute the VMware x86 backdoor
 * I/O-port instruction (port 0x5658, opcode `in eax, dx`).  That instruction
 * is privileged; in an unprivileged container the CPU raises SIGILL, killing
 * vmtoolsd before it can reach the AF_VSOCK transport.
 *
 * We prevent this at two levels:
 *
 *  1. Symbol overrides (primary)
 *     Three high-level VmCheck_* functions are intercepted.  These are the
 *     main hypervisor-detection entry points used by vmtoolsd.
 *
 *  2. Backdoor_InOut / Backdoor_HbOut / Backdoor_HbIn overrides (secondary)
 *     The low-level backdoor functions are exported symbols in libvmtools.so.0.
 *     Overriding them prevents ANY remaining call to `in eax, dx` from
 *     reaching the CPU.  We return safe values:
 *       - GETVERSION (0x0A): return VMware magic so callers know we're VMware.
 *       - MESSAGE   (0x1E): return failure (cx=0) so vmtoolsd falls through to
 *                           the vsock channel instead of trying backdoor GuestRPC.
 *       - Everything else: return VMware magic in bx, zeros elsewhere.
 *
 *  3. SIGILL safety net (tertiary)
 *     libvmtools.so.0 installs its own SIGILL handler in its constructor
 *     (it runs after ours and would override us).  We work around this by
 *     overriding sigaction() itself: any attempt to install a SIGILL handler
 *     that is NOT our handler is silently dropped.  This keeps our handler in
 *     place even if libvmtools tries to replace it.
 *
 * Build (linux/amd64 only):
 *   gcc -shared -fPIC -O2 -o vmci-backdoor-shim.so shim.c -ldl -lc
 *
 * Inject:
 *   LD_PRELOAD=/path/to/vmci-backdoor-shim.so vmtoolsd --cmd "..."
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <ucontext.h>

/* ── VMCISock overrides ────────────────────────────────────────────────────
 *
 * VMCISock_GetAFValue() probes for AF_VSOCK availability by:
 *  1. Opening /dev/vmci_sockets and calling ioctl(VMCI_SOCKETS_GET_AF_VALUE)
 *  2. Falling back to socket(AF_VSOCK, SOCK_DGRAM, 0) if /dev/vmci_sockets
 *     is absent.
 *
 * In containers, /dev/vmci_sockets does not exist.  Depending on the build,
 * some photon vmtoolsd builds omit step 2 and return -1, causing vmtoolsd to
 * skip vsock entirely and fall back to the backdoor channel — which then
 * fails because `in eax, dx` is not available.
 *
 * Overriding these functions guarantees vmtoolsd gets AF_VSOCK = 40 and
 * proceeds to socket(AF_VSOCK, SOCK_STREAM, 0) + connect(), which our
 * seccomp intercept routes to the vcsim GuestRPC server.
 *
 * When outFd is non-NULL (VMCISock_GetAFValueFd), callers may use the fd for
 * follow-up ioctls.  We create a throwaway AF_UNIX SOCK_DGRAM socket; any
 * AF_VSOCK-specific ioctls on it will fail with ENOTTY/EINVAL which vmtools
 * handles gracefully — the important contract is that the returned AF value
 * is 40.
 */

#include <sys/socket.h>  /* socket(), AF_UNIX */
#include <unistd.h>      /* close() */

/* AF_VSOCK = 40 on Linux. */
#define AF_VSOCK_VALUE 40

int VMCISock_GetAFValue(void)
{
    return AF_VSOCK_VALUE;
}

int VMCISock_GetAFValueFd(int *outFd)
{
    if (outFd) {
        /*
         * Return a valid but inert fd so callers that store it and later
         * call close() don't get EBADF.  AF_UNIX SOCK_DGRAM is cheap and
         * needs no privileges.
         */
        int dummy = socket(AF_UNIX, SOCK_DGRAM, 0);
        *outFd = dummy; /* may be -1 if socket() fails; callers must check */
    }
    return AF_VSOCK_VALUE;
}

/*
 * VMCISock_GetLocalCID() returns the local VMCI Context ID of the guest VM.
 * simpleSocket.c uses it to fill in the source sockaddr_vm.svm_cid for bind().
 * We return VMADDR_CID_ANY (0xFFFFFFFF) which the kernel uses as "any local
 * CID".  Since our seccomp intercept handles bind() for tracked sockets, the
 * actual value never reaches the kernel; this just prevents a blocking ioctl
 * on /dev/vmci_sockets that would hang or crash.
 */
unsigned int VMCISock_GetLocalCID(void)
{
    /* VMADDR_CID_ANY = (unsigned int)-1 = 0xFFFFFFFF */
    return (unsigned int)-1;
}

/*
 * VMCISock_ReleaseAFValueFd() closes the fd returned by VMCISock_GetAFValueFd.
 * simpleSocket.c calls this after connect() to release the /dev/vmci_sockets fd.
 */
void VMCISock_ReleaseAFValueFd(int fd)
{
    if (fd >= 0)
        close(fd);
}

/* ── Backdoor protocol types ───────────────────────────────────────────────
 * Mirrors Backdoor_proto from open-vm-tools lib/include/backdoor.h.
 * The union approach ensures sizeof = 24 bytes (6 × uint32_t).
 */
typedef union {
    struct {
        uint32_t ax, bx, cx, dx, si, di;
    } in;
    struct {
        uint32_t ax, bx, cx, dx, si, di;
    } out;
} Backdoor_proto;

/* High-bandwidth variant (used for large RPC payloads).
 * Same layout but with 64-bit si/di for the pointer fields. */
typedef union {
    struct {
        uint32_t ax, bx, cx, dx;
        uint64_t si, di;
    } in;
    struct {
        uint32_t ax, bx, cx, dx;
        uint64_t si, di;
    } out;
} Backdoor_proto_hb;

#define BDOOR_CMD_GETVERSION  0x0Au
#define BDOOR_CMD_GETHWVER    0x11u
#define BDOOR_CMD_MESSAGE     0x1Eu   /* GuestRPC via backdoor: we want vsock */
#define VMWARE_MAGIC          0x564D5868u   /* 'VMxi' */

/* ── Level 1: VmCheck_* overrides ─────────────────────────────────────────
 *
 * Signatures from open-vm-tools lib/include/vmcheck.h:
 *   Bool VmCheck_IsVirtualWorld(void);
 *   Bool VmCheck_GetVersion(unsigned *version, unsigned *type);
 *   Bool VmCheck_GetHWVersion(unsigned *hwVersion);
 */

int VmCheck_IsVirtualWorld(void)
{
    return 1; /* TRUE: we are inside a virtual machine */
}

int VmCheck_GetVersion(unsigned int *version, unsigned int *type)
{
    if (version) *version = 6;  /* ESXi 6.x protocol */
    if (type)    *type    = 1;  /* VMCHECK_VIRTUAL_ESX */
    return 1; /* TRUE */
}

int VmCheck_GetHWVersion(unsigned int *hwVersion)
{
    if (hwVersion) *hwVersion = 13; /* HW version 13 = ESXi 6.5+ */
    return 1; /* TRUE */
}

/* ── Level 2: Backdoor_InOut / Backdoor_HbOut / Backdoor_HbIn overrides ──
 *
 * These functions are exported by libvmtools.so.0 and contain the
 * `in eax, dx` opcode.  By overriding them here we prevent the instruction
 * from ever reaching the CPU.
 */

void Backdoor_InOut(Backdoor_proto *bp)
{
    uint32_t cmd = bp->in.cx;

    /* Clear output registers to prevent garbage being interpreted as pointers */
    bp->out.ax = 0;
    bp->out.bx = 0;
    bp->out.cx = 0;
    bp->out.dx = 0;
    bp->out.si = 0;
    bp->out.di = 0;

    switch (cmd) {
    case BDOOR_CMD_GETVERSION:
        bp->out.ax = 6;           /* protocol version */
        bp->out.bx = VMWARE_MAGIC;/* identifies as VMware to callers */
        bp->out.cx = 3;           /* RPC protocol version */
        break;

    case BDOOR_CMD_GETHWVER:
        bp->out.ax = 13;          /* HW version 13 */
        break;

    case BDOOR_CMD_MESSAGE:
        /* Return failure (cx=0, bx=0) so vmtoolsd abandons the backdoor
         * GuestRPC channel and falls through to vsock transport. */
        break;

    default:
        /* Safe default: identify as VMware but zero everything else.
         * Non-zero bx prevents "not VMware" early exits; zero ax/cx/dx
         * prevents NULL-pointer dereferences in most callers. */
        bp->out.bx = VMWARE_MAGIC;
        break;
    }
}

void Backdoor_HbOut(Backdoor_proto_hb *bp)
{
    /* High-bandwidth out: used for large RPC payloads via backdoor.
     * Return failure so vmtoolsd uses vsock instead. */
    bp->out.ax = 0;
    bp->out.bx = 0;
    bp->out.cx = 0;
    bp->out.dx = 0;
    bp->out.si = 0;
    bp->out.di = 0;
}

void Backdoor_HbIn(Backdoor_proto_hb *bp)
{
    /* High-bandwidth in: symmetric with HbOut. */
    bp->out.ax = 0;
    bp->out.bx = 0;
    bp->out.cx = 0;
    bp->out.dx = 0;
    bp->out.si = 0;
    bp->out.di = 0;
}

/* ── Level 3: SIGILL safety net ───────────────────────────────────────────
 *
 * If any code path we missed still executes `in eax, dx` we catch SIGILL,
 * advance RIP past it, return a safe value, and continue.
 *
 * libvmtools.so.0 installs its own SIGILL handler in its constructor.
 * We prevent it from overriding ours by wrapping sigaction(): calls that
 * target SIGILL and install a handler OTHER than ours are silently ignored.
 */

#ifdef __x86_64__

#define BDOOR_PORT 0x5658u

static volatile sig_atomic_t g_our_sigill_installed = 0;

static void vmci_sigill_handler(int sig, siginfo_t *si, void *uctx)
{
    ucontext_t *uc = (ucontext_t *)uctx;
    uint8_t    *rip = (uint8_t *)(uintptr_t)uc->uc_mcontext.gregs[REG_RIP];
    uint16_t    dx  = (uint16_t)(uc->uc_mcontext.gregs[REG_RDX] & 0xFFFF);

    if (*rip == 0xED && dx == BDOOR_PORT) {
        /* `in eax, dx` on the VMware backdoor port.
         * Return VMware magic in EBX so callers recognise us as VMware,
         * but zero EAX to prevent any value being misused as a pointer. */
        uc->uc_mcontext.gregs[REG_RBX] = VMWARE_MAGIC;
        uc->uc_mcontext.gregs[REG_RAX] = 0;
        uc->uc_mcontext.gregs[REG_RIP] += 1; /* skip the 1-byte opcode */
        return;
    }

    /* Not a backdoor probe — re-raise with default disposition */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_DFL;
    /* Use real sigaction to avoid our wrapper intercepting this */
    typedef int (*real_sigaction_t)(int, const struct sigaction *, struct sigaction *);
    real_sigaction_t real_sa = (real_sigaction_t)dlsym(RTLD_NEXT, "sigaction");
    if (real_sa)
        real_sa(SIGILL, &sa, NULL);
    raise(SIGILL);
}

static void install_our_sigill_handler(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = vmci_sigill_handler;
    sa.sa_flags     = SA_SIGINFO | SA_NODEFER;
    sigemptyset(&sa.sa_mask);

    typedef int (*real_sigaction_t)(int, const struct sigaction *, struct sigaction *);
    real_sigaction_t real_sa = (real_sigaction_t)dlsym(RTLD_NEXT, "sigaction");
    if (real_sa) {
        real_sa(SIGILL, &sa, NULL);
        g_our_sigill_installed = 1;
    }
}

/* Override sigaction() to prevent libvmtools (or any library) from
 * replacing our SIGILL handler once it's installed. */
int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact)
{
    typedef int (*real_sigaction_t)(int, const struct sigaction *, struct sigaction *);
    static real_sigaction_t real_sa;
    if (!real_sa)
        real_sa = (real_sigaction_t)dlsym(RTLD_NEXT, "sigaction");

    if (signum == SIGILL && act != NULL && g_our_sigill_installed) {
        /* Block any attempt to override our SIGILL handler.
         * If the caller wants to query the current handler (oldact != NULL,
         * act == NULL), let that through normally. */
        if (oldact)
            real_sa(SIGILL, NULL, oldact);
        return 0;
    }

    return real_sa(signum, act, oldact);
}

__attribute__((constructor))
static void shim_init(void)
{
    install_our_sigill_handler();
}

#endif /* __x86_64__ */
