// SPDX-License-Identifier: Apache-2.0 or MIT
//

pub const SYSCALLS: &[(&str, i32)] = &[
    ("_llseek", -10026),
    ("_newselect", -10032),
    ("_sysctl", -10080),
    ("accept", 202),
    ("accept4", 242),
    ("access", -10147),
    ("acct", 89),
    ("add_key", 217),
    ("adjtimex", 171),
    ("afs_syscall", -10091),
    ("alarm", -10148),
    ("arch_prctl", -10001),
    ("arm_fadvise64_64", -10083),
    ("arm_sync_file_range", -10084),
    ("atomic_barrier", -10247),
    ("atomic_cmpxchg_32", -10248),
    ("bdflush", -10002),
    ("bind", 200),
    ("bpf", 280),
    ("break", -10003),
    ("breakpoint", -10182),
    ("brk", 214),
    ("cachectl", -10103),
    ("cacheflush", -10104),
    ("cachestat", 451),
    ("capget", 90),
    ("capset", 91),
    ("chdir", 49),
    ("chmod", -10149),
    ("chown", -10150),
    ("chown32", -10004),
    ("chroot", 51),
    ("clock_adjtime", 266),
    ("clock_adjtime64", -10212),
    ("clock_getres", 114),
    ("clock_getres_time64", -10213),
    ("clock_gettime", 113),
    ("clock_gettime64", -10214),
    ("clock_nanosleep", 115),
    ("clock_nanosleep_time64", -10215),
    ("clock_settime", 112),
    ("clock_settime64", -10216),
    ("clone", 220),
    ("clone3", 435),
    ("close", 57),
    ("close_range", 436),
    ("connect", 203),
    ("copy_file_range", 285),
    ("creat", -10151),
    ("create_module", -10074),
    ("delete_module", 106),
    ("dup", 23),
    ("dup2", -10152),
    ("dup3", 24),
    ("epoll_create", -10153),
    ("epoll_create1", 20),
    ("epoll_ctl", 21),
    ("epoll_ctl_old", -10005),
    ("epoll_pwait", 22),
    ("epoll_pwait2", 441),
    ("epoll_wait", -10154),
    ("epoll_wait_old", -10006),
    ("eventfd", -10155),
    ("eventfd2", 19),
    ("execve", 221),
    ("execveat", 281),
    ("exit", 93),
    ("exit_group", 94),
    ("faccessat", 48),
    ("faccessat2", 439),
    ("fadvise64", 223),
    ("fadvise64_64", -10007),
    ("fallocate", 47),
    ("fanotify_init", 262),
    ("fanotify_mark", 263),
    ("fchdir", 50),
    ("fchmod", 52),
    ("fchmodat", 53),
    ("fchmodat2", 452),
    ("fchown", 55),
    ("fchown32", -10008),
    ("fchownat", 54),
    ("fcntl", 25),
    ("fcntl64", -10009),
    ("fdatasync", 83),
    ("fgetxattr", 10),
    ("finit_module", 273),
    ("flistxattr", 13),
    ("flock", 32),
    ("fork", -10156),
    ("fremovexattr", 16),
    ("fsconfig", 431),
    ("fsetxattr", 7),
    ("fsmount", 432),
    ("fsopen", 430),
    ("fspick", 433),
    ("fstat", 80),
    ("fstat64", -10010),
    ("fstatat64", -10011),
    ("fstatfs", 44),
    ("fstatfs64", -10012),
    ("fsync", 82),
    ("ftime", -10013),
    ("ftruncate", 46),
    ("ftruncate64", -10014),
    ("futex", 98),
    ("futex_requeue", 456),
    ("futex_time64", -10222),
    ("futex_wait", 455),
    ("futex_waitv", 449),
    ("futex_wake", 454),
    ("futimesat", -10157),
    ("get_kernel_syms", -10075),
    ("get_mempolicy", 236),
    ("get_robust_list", 100),
    ("get_thread_area", -10076),
    ("get_tls", -10204),
    ("getcpu", 168),
    ("getcwd", 17),
    ("getdents", -10158),
    ("getdents64", 61),
    ("getegid", 177),
    ("getegid32", -10015),
    ("geteuid", 175),
    ("geteuid32", -10016),
    ("getgid", 176),
    ("getgid32", -10017),
    ("getgroups", 158),
    ("getgroups32", -10018),
    ("getitimer", 102),
    ("getpagesize", -10249),
    ("getpeername", 205),
    ("getpgid", 155),
    ("getpgrp", -10159),
    ("getpid", 172),
    ("getpmsg", -10093),
    ("getppid", 173),
    ("getpriority", 141),
    ("getrandom", 278),
    ("getresgid", 150),
    ("getresgid32", -10019),
    ("getresuid", 148),
    ("getresuid32", -10020),
    ("getrlimit", 163),
    ("getrusage", 165),
    ("getsid", 156),
    ("getsockname", 204),
    ("getsockopt", 209),
    ("gettid", 178),
    ("gettimeofday", 169),
    ("getuid", 174),
    ("getuid32", -10021),
    ("getxattr", 8),
    ("getxattrat", 464),
    ("gtty", -10022),
    ("idle", -10023),
    ("init_module", 105),
    ("inotify_add_watch", 27),
    ("inotify_init", -10160),
    ("inotify_init1", 26),
    ("inotify_rm_watch", 28),
    ("io_cancel", 3),
    ("io_destroy", 1),
    ("io_getevents", 4),
    ("io_pgetevents", 292),
    ("io_pgetevents_time64", -10223),
    ("io_setup", 0),
    ("io_submit", 2),
    ("io_uring_enter", 426),
    ("io_uring_register", 427),
    ("io_uring_setup", 425),
    ("ioctl", 29),
    ("ioperm", -10094),
    ("iopl", -10095),
    ("ioprio_get", 31),
    ("ioprio_set", 30),
    ("ipc", -10024),
    ("kcmp", 272),
    ("kexec_file_load", 294),
    ("kexec_load", 104),
    ("keyctl", 219),
    ("kill", 129),
    ("landlock_add_rule", 445),
    ("landlock_create_ruleset", 444),
    ("landlock_restrict_self", 446),
    ("lchown", -10161),
    ("lchown32", -10025),
    ("lgetxattr", 9),
    ("link", -10162),
    ("linkat", 37),
    ("listen", 201),
    ("listmount", 458),
    ("listxattr", 11),
    ("listxattrat", 465),
    ("llistxattr", 12),
    ("lock", -10027),
    ("lookup_dcookie", 18),
    ("lremovexattr", 15),
    ("lseek", 62),
    ("lsetxattr", 6),
    ("lsm_get_self_attr", 459),
    ("lsm_list_modules", 461),
    ("lsm_set_self_attr", 460),
    ("lstat", -10163),
    ("lstat64", -10028),
    ("madvise", 233),
    ("map_shadow_stack", 453),
    ("mbind", 235),
    ("membarrier", 283),
    ("memfd_create", 279),
    ("memfd_secret", 447),
    ("migrate_pages", 238),
    ("mincore", 232),
    ("mkdir", -10164),
    ("mkdirat", 34),
    ("mknod", -10165),
    ("mknodat", 33),
    ("mlock", 228),
    ("mlock2", 284),
    ("mlockall", 230),
    ("mmap", 222),
    ("mmap2", -10029),
    ("modify_ldt", -10098),
    ("mount", 40),
    ("mount_setattr", 442),
    ("move_mount", 429),
    ("move_pages", 239),
    ("mprotect", 226),
    ("mpx", -10030),
    ("mq_getsetattr", 185),
    ("mq_notify", 184),
    ("mq_open", 180),
    ("mq_timedreceive", 183),
    ("mq_timedreceive_time64", -10225),
    ("mq_timedsend", 182),
    ("mq_timedsend_time64", -10226),
    ("mq_unlink", 181),
    ("mremap", 216),
    ("mseal", 462),
    ("msgctl", 187),
    ("msgget", 186),
    ("msgrcv", 188),
    ("msgsnd", 189),
    ("msync", 227),
    ("multiplexer", -10186),
    ("munlock", 229),
    ("munlockall", 231),
    ("munmap", 215),
    ("name_to_handle_at", 264),
    ("nanosleep", 101),
    ("newfstatat", 79),
    ("nfsservctl", 42),
    ("nice", -10033),
    ("oldfstat", -10034),
    ("oldlstat", -10035),
    ("oldolduname", -10036),
    ("oldstat", -10037),
    ("olduname", -10038),
    ("open", -10166),
    ("open_by_handle_at", 265),
    ("open_tree", 428),
    ("openat", 56),
    ("openat2", 437),
    ("pause", -10167),
    ("pciconfig_iobase", -10086),
    ("pciconfig_read", -10087),
    ("pciconfig_write", -10088),
    ("perf_event_open", 241),
    ("personality", 92),
    ("pidfd_getfd", 438),
    ("pidfd_open", 434),
    ("pidfd_send_signal", 424),
    ("pipe", -10168),
    ("pipe2", 59),
    ("pivot_root", 41),
    ("pkey_alloc", 289),
    ("pkey_free", 290),
    ("pkey_mprotect", 288),
    ("poll", -10169),
    ("ppoll", 73),
    ("ppoll_time64", -10230),
    ("prctl", 167),
    ("pread64", 67),
    ("preadv", 69),
    ("preadv2", 286),
    ("prlimit64", 261),
    ("process_madvise", 440),
    ("process_mrelease", 448),
    ("process_vm_readv", 270),
    ("process_vm_writev", 271),
    ("prof", -10039),
    ("profil", -10040),
    ("pselect6", 72),
    ("pselect6_time64", -10231),
    ("ptrace", 117),
    ("putpmsg", -10099),
    ("pwrite64", 68),
    ("pwritev", 70),
    ("pwritev2", 287),
    ("query_module", -10078),
    ("quotactl", 60),
    ("quotactl_fd", 443),
    ("read", 63),
    ("readahead", 213),
    ("readdir", -10041),
    ("readlink", -10170),
    ("readlinkat", 78),
    ("readv", 65),
    ("reboot", 142),
    ("recv", -110),
    ("recvfrom", 207),
    ("recvmmsg", 243),
    ("recvmmsg_time64", -10232),
    ("recvmsg", 212),
    ("remap_file_pages", 234),
    ("removexattr", 14),
    ("removexattrat", 466),
    ("rename", -10171),
    ("renameat", -10242),
    ("renameat2", 276),
    ("request_key", 218),
    ("restart_syscall", 128),
    ("riscv_flush_icache", 259),
    ("riscv_hwprobe", 258),
    ("rmdir", -10172),
    ("rseq", 293),
    ("rt_sigaction", 134),
    ("rt_sigpending", 136),
    ("rt_sigprocmask", 135),
    ("rt_sigqueueinfo", 138),
    ("rt_sigreturn", 139),
    ("rt_sigsuspend", 133),
    ("rt_sigtimedwait", 137),
    ("rt_sigtimedwait_time64", -10233),
    ("rt_tgsigqueueinfo", 240),
    ("rtas", -10187),
    ("s390_guarded_storage", -10205),
    ("s390_pci_mmio_read", -10197),
    ("s390_pci_mmio_write", -10198),
    ("s390_runtime_instr", -10196),
    ("s390_sthyi", -10206),
    ("sched_get_priority_max", 125),
    ("sched_get_priority_min", 126),
    ("sched_getaffinity", 123),
    ("sched_getattr", 275),
    ("sched_getparam", 121),
    ("sched_getscheduler", 120),
    ("sched_rr_get_interval", 127),
    ("sched_rr_get_interval_time64", -10234),
    ("sched_setaffinity", 122),
    ("sched_setattr", 274),
    ("sched_setparam", 118),
    ("sched_setscheduler", 119),
    ("sched_yield", 124),
    ("seccomp", 277),
    ("security", -10042),
    ("select", -10101),
    ("semctl", 191),
    ("semget", 190),
    ("semop", 193),
    ("semtimedop", 192),
    ("semtimedop_time64", -10235),
    ("send", -109),
    ("sendfile", 71),
    ("sendfile64", -10043),
    ("sendmmsg", 269),
    ("sendmsg", 211),
    ("sendto", 206),
    ("set_mempolicy", 237),
    ("set_mempolicy_home_node", 450),
    ("set_robust_list", 99),
    ("set_thread_area", -10079),
    ("set_tid_address", 96),
    ("set_tls", -10183),
    ("setdomainname", 162),
    ("setfsgid", 152),
    ("setfsgid32", -10044),
    ("setfsuid", 151),
    ("setfsuid32", -10045),
    ("setgid", 144),
    ("setgid32", -10046),
    ("setgroups", 159),
    ("setgroups32", -10047),
    ("sethostname", 161),
    ("setitimer", 103),
    ("setns", 268),
    ("setpgid", 154),
    ("setpriority", 140),
    ("setregid", 143),
    ("setregid32", -10048),
    ("setresgid", 149),
    ("setresgid32", -10049),
    ("setresuid", 147),
    ("setresuid32", -10050),
    ("setreuid", 145),
    ("setreuid32", -10051),
    ("setrlimit", 164),
    ("setsid", 157),
    ("setsockopt", 208),
    ("settimeofday", 170),
    ("setuid", 146),
    ("setuid32", -10052),
    ("setxattr", 5),
    ("setxattrat", 463),
    ("sgetmask", -10053),
    ("shmat", 196),
    ("shmctl", 195),
    ("shmdt", 197),
    ("shmget", 194),
    ("shutdown", 210),
    ("sigaction", -10054),
    ("sigaltstack", 132),
    ("signal", -10055),
    ("signalfd", -10173),
    ("signalfd4", 74),
    ("sigpending", -10056),
    ("sigprocmask", -10057),
    ("sigreturn", -10058),
    ("sigsuspend", -10059),
    ("socket", 198),
    ("socketcall", -10060),
    ("socketpair", 199),
    ("splice", 76),
    ("spu_create", -10188),
    ("spu_run", -10189),
    ("ssetmask", -10061),
    ("stat", -10174),
    ("stat64", -10062),
    ("statfs", 43),
    ("statfs64", -10063),
    ("statmount", 457),
    ("statx", 291),
    ("stime", -10064),
    ("stty", -10065),
    ("subpage_prot", -10207),
    ("swapcontext", -10190),
    ("swapoff", 225),
    ("swapon", 224),
    ("switch_endian", -10191),
    ("symlink", -10175),
    ("symlinkat", 36),
    ("sync", 81),
    ("sync_file_range", 84),
    ("sync_file_range2", -10089),
    ("syncfs", 267),
    ("sys_debug_setcontext", -10191),
    ("syscall", -10090),
    ("sysfs", -10145),
    ("sysinfo", 179),
    ("syslog", 116),
    ("sysmips", -10106),
    ("tee", 77),
    ("tgkill", 131),
    ("time", -10108),
    ("timer_create", 107),
    ("timer_delete", 111),
    ("timer_getoverrun", 109),
    ("timer_gettime", 108),
    ("timer_gettime64", -10236),
    ("timer_settime", 110),
    ("timer_settime64", -10237),
    ("timerfd", -10107),
    ("timerfd_create", 85),
    ("timerfd_gettime", 87),
    ("timerfd_gettime64", -10238),
    ("timerfd_settime", 86),
    ("timerfd_settime64", -10239),
    ("times", 153),
    ("tkill", 130),
    ("truncate", 45),
    ("truncate64", -10066),
    ("tuxcall", -10067),
    ("ugetrlimit", -10068),
    ("ulimit", -10069),
    ("umask", 166),
    ("umount", -10070),
    ("umount2", 39),
    ("uname", 160),
    ("unlink", -10176),
    ("unlinkat", 35),
    ("unshare", 97),
    ("uretprobe", -10251),
    ("uselib", -10081),
    ("userfaultfd", 282),
    ("usr26", -10184),
    ("usr32", -10185),
    ("ustat", -10177),
    ("utime", -10178),
    ("utimensat", 88),
    ("utimensat_time64", -10240),
    ("utimes", -10179),
    ("vfork", -10102),
    ("vhangup", 58),
    ("vm86", -10071),
    ("vm86old", -10072),
    ("vmsplice", 75),
    ("vserver", -10082),
    ("wait4", 260),
    ("waitid", 95),
    ("waitpid", -10073),
    ("write", 64),
    ("writev", 66),
];
