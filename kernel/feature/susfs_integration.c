// SPDX-License-Identifier: GPL-2.0-only
/*
 * SuSFS glue for this KernelSU (NidhiKernel downstream).
 *
 * The kernel tree carries SuSFS itself and routes its commands and init
 * on its own (fs/susfs.c, kernel/reboot.c). What only KernelSU can know
 * lives here, mirroring what BakaSU / KernelSU-Next provide:
 *
 *  - the ksu and priv_app SIDs (fs/susfs.c, security/selinux/avc.c),
 *  - susfs_is_current_ksu_domain() (fs/susfs.c, fs/namespace.c),
 *  - marking zygote children that must not see root as "umounted" and
 *    "no su" in their thread flags, which every SuSFS hiding check keys on,
 *  - starting the /sdcard decryption monitor at boot-completed.
 *
 * ksu_cred and setup_selinux(), which fs/susfs.c also uses, are already
 * global in this tree.
 */

#ifdef CONFIG_KSU_SUSFS

#include <linux/susfs.h>
#include <linux/susfs_def.h>

#define KSU_SUSFS_PRIV_APP_CONTEXT "u:r:priv_app:s0:c512,c768"
#define KSU_SUSFS_ZYGOTE_NEXT_CONTEXT "u:r:zygote_next:s0"

u32 susfs_ksu_sid __read_mostly = 0;
u32 susfs_priv_app_sid __read_mostly = 0;
static u32 susfs_zygote_next_sid __read_mostly = 0;

extern struct work_struct susfs_extra_works;

static u32 ksu_susfs_lookup_sid(const char *ctx)
{
	u32 sid = 0;

	if (security_secctx_to_secid(ctx, strlen(ctx), &sid))
		return 0;
	return sid;
}

/* Called right after cache_sid(), once KernelSU's rules are in the policy. */
static void ksu_susfs_cache_sid(void)
{
	susfs_ksu_sid = ksu_susfs_lookup_sid(KERNEL_SU_CONTEXT);
	susfs_priv_app_sid = ksu_susfs_lookup_sid(KSU_SUSFS_PRIV_APP_CONTEXT);
	/* only exists when ZygiskNext's policy is loaded */
	susfs_zygote_next_sid = ksu_susfs_lookup_sid(KSU_SUSFS_ZYGOTE_NEXT_CONTEXT);
	pr_info("susfs: ksu sid: %u, priv_app sid: %u, zygote_next sid: %u\n",
		susfs_ksu_sid, susfs_priv_app_sid, susfs_zygote_next_sid);
}

bool susfs_is_current_ksu_domain(void)
{
	return is_ksu_domain();
}

static __always_inline bool ksu_susfs_is_zygote_next(const struct cred *cred)
{
	const struct task_security_struct *tsec;

	if (!susfs_zygote_next_sid || !cred)
		return false;
	tsec = selinux_cred(cred);
	return tsec && tsec->sid == susfs_zygote_next_sid;
}

static __always_inline void ksu_susfs_queue_extra_works(void)
{
	if (!work_pending(&susfs_extra_works))
		schedule_work(&susfs_extra_works);
}

/*
 * Root -> new_uid transition of a process that KernelSU does not allow
 * root. Same decisions as BakaSU's setuid hook with SuSFS:
 *  - zygote children: apps, webview zygote and isolated processes that
 *    should be umounted are marked umounted (SuSFS hides from them);
 *  - ZygiskNext's zygote_next children additionally get the zygote_next
 *    and no_su marks, and every other child of it gets no_su.
 * The marks are set regardless of KernelSU's own umount switch and of
 * whether any module is mounted, as SuSFS hiding does not depend on them.
 */
static void ksu_susfs_handle_setresuid(const struct cred *old, uid_t new_uid)
{
	bool umount = is_isolated_process(new_uid) ||
		      ((is_appuid(new_uid) || new_uid == WEBVIEW_ZYGOTE_UID) &&
		       ksu_uid_should_umount(new_uid));

	if (unlikely(ksu_susfs_is_zygote_next(old))) {
		susfs_set_current_proc_no_su();
		if (umount) {
			susfs_set_current_proc_umounted();
			susfs_set_current_proc_umounted_for_zygote_next();
			ksu_susfs_queue_extra_works();
		}
		return;
	}

	if (!umount || !is_zygote(old))
		return;

	susfs_set_current_proc_umounted();
	ksu_susfs_queue_extra_works();
}

static void ksu_susfs_on_boot_completed(void)
{
	susfs_start_sdcard_monitor_fn();
}

// App uids change on reinstall: resolve the package-name filters again
static void ksu_susfs_on_packages_changed(void)
{
#ifdef CONFIG_KSU_SUSFS_PRIORITY_UID_FILTER
	susfs_parse_priority_app_strings();
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_PATH
	susfs_parse_sus_path_app_strings();
#endif
}

#else /* !CONFIG_KSU_SUSFS */

static inline void ksu_susfs_cache_sid(void) { }
static inline void ksu_susfs_handle_setresuid(const struct cred *old, uid_t new_uid) { }
static inline void ksu_susfs_on_boot_completed(void) { }
static inline void ksu_susfs_on_packages_changed(void) { }

#endif /* CONFIG_KSU_SUSFS */
