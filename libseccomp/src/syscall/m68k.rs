// SPDX-License-Identifier: Apache-2.0 or MIT
//

pub const SYSCALLS: &[(&str, i32)] = &[
    ("_llseek", 140),
    ("_newselect", 142),
    ("_sysctl", 149),
    ("accept", -105),
    ("accept4", -118),
    ("access", 33),
    ("acct", 51),
    ("add_key", 279),
    ("adjtimex", 124),
    ("afs_syscall", -10091),
    ("alarm", 27),
    ("arch_prctl", -10001),
    ("arm_fadvise64_64", -10083),
    ("arm_sync_file_range", -10084),
    ("atomic_barrier", 336),
    ("atomic_cmpxchg_32", 335),
    ("bdflush", 134),
    ("bind", -102),
    ("bpf", 354),
    ("break", -10003),
    ("breakpoint", -10182),
    ("brk", 45),
    ("cachectl", -10103),
    ("cacheflush", 123),
    ("cachestat", 451),
    ("capget", 184),
    ("capset", 185),
    ("chdir", 12),
    ("chmod", 15),
    ("chown", 16),
    ("chown32", 198),
    ("chroot", 61),
    ("clock_adjtime", 342),
    ("clock_adjtime64", 405),
    ("clock_getres", 261),
    ("clock_getres_time64", 406),
    ("clock_gettime", 260),
    ("clock_gettime64", 403),
    ("clock_nanosleep", 262),
    ("clock_nanosleep_time64", 407),
    ("clock_settime", 259),
    ("clock_settime64", 404),
    ("clone", 120),
    ("clone3", 435),
    ("close", 6),
    ("close_range", 436),
    ("connect", -103),
    ("copy_file_range", 376),
    ("creat", 8),
    ("create_module", 127),
    ("delete_module", 129),
    ("dup", 41),
    ("dup2", 63),
    ("dup3", 326),
    ("epoll_create", 249),
    ("epoll_create1", 325),
    ("epoll_ctl", 250),
    ("epoll_ctl_old", -10005),
    ("epoll_pwait", 315),
    ("epoll_pwait2", 441),
    ("epoll_wait", 251),
    ("epoll_wait_old", -10006),
    ("eventfd", 319),
    ("eventfd2", 324),
    ("execve", 11),
    ("execveat", 355),
    ("exit", 1),
    ("exit_group", 247),
    ("faccessat", 300),
    ("faccessat2", 439),
    ("fadvise64", 246),
    ("fadvise64_64", 267),
    ("fallocate", 320),
    ("fanotify_init", 337),
    ("fanotify_mark", 338),
    ("fchdir", 133),
    ("fchmod", 94),
    ("fchmodat", 299),
    ("fchmodat2", 452),
    ("fchown", 95),
    ("fchown32", 207),
    ("fchownat", 291),
    ("fcntl", 55),
    ("fcntl64", 239),
    ("fdatasync", 148),
    ("fgetxattr", 228),
    ("finit_module", 348),
    ("flistxattr", 231),
    ("flock", 143),
    ("fork", 2),
    ("fremovexattr", 234),
    ("fsconfig", 431),
    ("fsetxattr", 225),
    ("fsmount", 432),
    ("fsopen", 430),
    ("fspick", 433),
    ("fstat", 108),
    ("fstat64", 197),
    ("fstatat64", 293),
    ("fstatfs", 100),
    ("fstatfs64", 264),
    ("fsync", 118),
    ("ftime", -10013),
    ("ftruncate", 93),
    ("ftruncate64", 194),
    ("futex", 235),
    ("futex_requeue", 456),
    ("futex_time64", 422),
    ("futex_wait", 455),
    ("futex_waitv", 449),
    ("futex_wake", 454),
    ("futimesat", 292),
    ("get_kernel_syms", 130),
    ("get_mempolicy", 269),
    ("get_robust_list", 305),
    ("get_thread_area", 333),
    ("get_tls", -10204),
    ("getcpu", 314),
    ("getcwd", 183),
    ("getdents", 141),
    ("getdents64", 220),
    ("getegid", 50),
    ("getegid32", 202),
    ("geteuid", 49),
    ("geteuid32", 201),
    ("getgid", 47),
    ("getgid32", 200),
    ("getgroups", 80),
    ("getgroups32", 205),
    ("getitimer", 105),
    ("getpagesize", 166),
    ("getpeername", -107),
    ("getpgid", 132),
    ("getpgrp", 65),
    ("getpid", 20),
    ("getpmsg", 188),
    ("getppid", 64),
    ("getpriority", 96),
    ("getrandom", 352),
    ("getresgid", 171),
    ("getresgid32", 211),
    ("getresuid", 165),
    ("getresuid32", 209),
    ("getrlimit", 76),
    ("getrusage", 77),
    ("getsid", 147),
    ("getsockname", -106),
    ("getsockopt", -115),
    ("gettid", 221),
    ("gettimeofday", 78),
    ("getuid", 24),
    ("getuid32", 199),
    ("getxattr", 226),
    ("getxattrat", 464),
    ("gtty", -10022),
    ("idle", -10023),
    ("init_module", 128),
    ("inotify_add_watch", 285),
    ("inotify_init", 284),
    ("inotify_init1", 328),
    ("inotify_rm_watch", 286),
    ("io_cancel", 245),
    ("io_destroy", 242),
    ("io_getevents", 243),
    ("io_pgetevents", -10209),
    ("io_pgetevents_time64", 416),
    ("io_setup", 241),
    ("io_submit", 244),
    ("io_uring_enter", 426),
    ("io_uring_register", 427),
    ("io_uring_setup", 425),
    ("ioctl", 54),
    ("ioperm", -10094),
    ("iopl", -10095),
    ("ioprio_get", 283),
    ("ioprio_set", 282),
    ("ipc", 117),
    ("kcmp", 347),
    ("kexec_file_load", -10111),
    ("kexec_load", 313),
    ("keyctl", 281),
    ("kill", 37),
    ("landlock_add_rule", 445),
    ("landlock_create_ruleset", 444),
    ("landlock_restrict_self", 446),
    ("lchown", 182),
    ("lchown32", 212),
    ("lgetxattr", 227),
    ("link", 9),
    ("linkat", 296),
    ("listen", -104),
    ("listmount", 458),
    ("listxattr", 229),
    ("listxattrat", 465),
    ("llistxattr", 230),
    ("lock", -10027),
    ("lookup_dcookie", 248),
    ("lremovexattr", 233),
    ("lseek", 19),
    ("lsetxattr", 224),
    ("lsm_get_self_attr", 459),
    ("lsm_list_modules", 461),
    ("lsm_set_self_attr", 460),
    ("lstat", 107),
    ("lstat64", 196),
    ("madvise", 238),
    ("map_shadow_stack", 453),
    ("mbind", 268),
    ("membarrier", 374),
    ("memfd_create", 353),
    ("memfd_secret", -10244),
    ("migrate_pages", 287),
    ("mincore", 237),
    ("mkdir", 39),
    ("mkdirat", 289),
    ("mknod", 14),
    ("mknodat", 290),
    ("mlock", 150),
    ("mlock2", 375),
    ("mlockall", 152),
    ("mmap", 90),
    ("mmap2", 192),
    ("modify_ldt", -10098),
    ("mount", 21),
    ("mount_setattr", 442),
    ("move_mount", 429),
    ("move_pages", 310),
    ("mprotect", 125),
    ("mpx", -10030),
    ("mq_getsetattr", 276),
    ("mq_notify", 275),
    ("mq_open", 271),
    ("mq_timedreceive", 274),
    ("mq_timedreceive_time64", 419),
    ("mq_timedsend", 273),
    ("mq_timedsend_time64", 418),
    ("mq_unlink", 272),
    ("mremap", 163),
    ("mseal", 462),
    ("msgctl", -214),
    ("msgget", -213),
    ("msgrcv", -212),
    ("msgsnd", -211),
    ("msync", 144),
    ("multiplexer", -10186),
    ("munlock", 151),
    ("munlockall", 153),
    ("munmap", 91),
    ("name_to_handle_at", 340),
    ("nanosleep", 162),
    ("newfstatat", -10031),
    ("nfsservctl", 169),
    ("nice", 34),
    ("oldfstat", 28),
    ("oldlstat", 84),
    ("oldolduname", -10036),
    ("oldstat", 18),
    ("olduname", -10038),
    ("open", 5),
    ("open_by_handle_at", 341),
    ("open_tree", 428),
    ("openat", 288),
    ("openat2", 437),
    ("pause", 29),
    ("pciconfig_iobase", -10086),
    ("pciconfig_read", -10087),
    ("pciconfig_write", -10088),
    ("perf_event_open", 332),
    ("personality", 136),
    ("pidfd_getfd", 438),
    ("pidfd_open", 434),
    ("pidfd_send_signal", 424),
    ("pipe", 42),
    ("pipe2", 327),
    ("pivot_root", 217),
    ("pkey_alloc", 382),
    ("pkey_free", 383),
    ("pkey_mprotect", 381),
    ("poll", 168),
    ("ppoll", 302),
    ("ppoll_time64", 414),
    ("prctl", 172),
    ("pread64", 180),
    ("preadv", 329),
    ("preadv2", 377),
    ("prlimit64", 339),
    ("process_madvise", 440),
    ("process_mrelease", 448),
    ("process_vm_readv", 345),
    ("process_vm_writev", 346),
    ("prof", -10039),
    ("profil", -10040),
    ("pselect6", 301),
    ("pselect6_time64", 413),
    ("ptrace", 26),
    ("putpmsg", 189),
    ("pwrite64", 181),
    ("pwritev", 330),
    ("pwritev2", 378),
    ("query_module", 167),
    ("quotactl", 131),
    ("quotactl_fd", 443),
    ("read", 3),
    ("readahead", 240),
    ("readdir", 89),
    ("readlink", 85),
    ("readlinkat", 298),
    ("readv", 145),
    ("reboot", 88),
    ("recv", -110),
    ("recvfrom", -112),
    ("recvmmsg", -119),
    ("recvmmsg_time64", 417),
    ("recvmsg", -117),
    ("remap_file_pages", 252),
    ("removexattr", 232),
    ("removexattrat", 466),
    ("rename", 38),
    ("renameat", 295),
    ("renameat2", 351),
    ("request_key", 280),
    ("restart_syscall", 0),
    ("riscv_flush_icache", -10243),
    ("riscv_hwprobe", -10250),
    ("rmdir", 40),
    ("rseq", 384),
    ("rt_sigaction", 174),
    ("rt_sigpending", 176),
    ("rt_sigprocmask", 175),
    ("rt_sigqueueinfo", 178),
    ("rt_sigreturn", 173),
    ("rt_sigsuspend", 179),
    ("rt_sigtimedwait", 177),
    ("rt_sigtimedwait_time64", 421),
    ("rt_tgsigqueueinfo", 331),
    ("rtas", -10187),
    ("s390_guarded_storage", -10205),
    ("s390_pci_mmio_read", -10197),
    ("s390_pci_mmio_write", -10198),
    ("s390_runtime_instr", -10196),
    ("s390_sthyi", -10206),
    ("sched_get_priority_max", 159),
    ("sched_get_priority_min", 160),
    ("sched_getaffinity", 312),
    ("sched_getattr", 350),
    ("sched_getparam", 155),
    ("sched_getscheduler", 157),
    ("sched_rr_get_interval", 161),
    ("sched_rr_get_interval_time64", 423),
    ("sched_setaffinity", 311),
    ("sched_setattr", 349),
    ("sched_setparam", 154),
    ("sched_setscheduler", 156),
    ("sched_yield", 158),
    ("seccomp", 380),
    ("security", -10042),
    ("select", 82),
    ("semctl", -203),
    ("semget", -202),
    ("semop", -201),
    ("semtimedop", -204),
    ("semtimedop_time64", 420),
    ("send", -109),
    ("sendfile", 187),
    ("sendfile64", 236),
    ("sendmmsg", -120),
    ("sendmsg", -116),
    ("sendto", -111),
    ("set_mempolicy", 270),
    ("set_mempolicy_home_node", 450),
    ("set_robust_list", 304),
    ("set_thread_area", 334),
    ("set_tid_address", 253),
    ("set_tls", -10183),
    ("setdomainname", 121),
    ("setfsgid", 139),
    ("setfsgid32", 216),
    ("setfsuid", 138),
    ("setfsuid32", 215),
    ("setgid", 46),
    ("setgid32", 214),
    ("setgroups", 81),
    ("setgroups32", 206),
    ("sethostname", 74),
    ("setitimer", 104),
    ("setns", 344),
    ("setpgid", 57),
    ("setpriority", 97),
    ("setregid", 71),
    ("setregid32", 204),
    ("setresgid", 170),
    ("setresgid32", 210),
    ("setresuid", 164),
    ("setresuid32", 208),
    ("setreuid", 70),
    ("setreuid32", 203),
    ("setrlimit", 75),
    ("setsid", 66),
    ("setsockopt", -114),
    ("settimeofday", 79),
    ("setuid", 23),
    ("setuid32", 213),
    ("setxattr", 223),
    ("setxattrat", 463),
    ("sgetmask", 68),
    ("shmat", -221),
    ("shmctl", -224),
    ("shmdt", -222),
    ("shmget", -223),
    ("shutdown", -113),
    ("sigaction", 67),
    ("sigaltstack", 186),
    ("signal", 48),
    ("signalfd", 317),
    ("signalfd4", 323),
    ("sigpending", 73),
    ("sigprocmask", 126),
    ("sigreturn", 119),
    ("sigsuspend", 72),
    ("socket", -101),
    ("socketcall", 102),
    ("socketpair", -108),
    ("splice", 306),
    ("spu_create", -10188),
    ("spu_run", -10189),
    ("ssetmask", 69),
    ("stat", 106),
    ("stat64", 195),
    ("statfs", 99),
    ("statfs64", 263),
    ("statmount", 457),
    ("statx", 379),
    ("stime", 25),
    ("stty", -10065),
    ("subpage_prot", -10207),
    ("swapcontext", -10190),
    ("swapoff", 115),
    ("swapon", 87),
    ("switch_endian", -10191),
    ("symlink", 83),
    ("symlinkat", 297),
    ("sync", 36),
    ("sync_file_range", 307),
    ("sync_file_range2", -10089),
    ("syncfs", 343),
    ("sys_debug_setcontext", -10191),
    ("syscall", -10090),
    ("sysfs", 135),
    ("sysinfo", 116),
    ("syslog", 103),
    ("sysmips", -10106),
    ("tee", 308),
    ("tgkill", 265),
    ("time", 13),
    ("timer_create", 254),
    ("timer_delete", 258),
    ("timer_getoverrun", 257),
    ("timer_gettime", 256),
    ("timer_gettime64", 408),
    ("timer_settime", 255),
    ("timer_settime64", 409),
    ("timerfd", -10107),
    ("timerfd_create", 318),
    ("timerfd_gettime", 322),
    ("timerfd_gettime64", 410),
    ("timerfd_settime", 321),
    ("timerfd_settime64", 411),
    ("times", 43),
    ("tkill", 222),
    ("truncate", 92),
    ("truncate64", 193),
    ("tuxcall", -10067),
    ("ugetrlimit", 191),
    ("ulimit", -10069),
    ("umask", 60),
    ("umount", 22),
    ("umount2", 52),
    ("uname", 122),
    ("unlink", 10),
    ("unlinkat", 294),
    ("unshare", 303),
    ("uretprobe", -10251),
    ("uselib", 86),
    ("userfaultfd", 373),
    ("usr26", -10184),
    ("usr32", -10185),
    ("ustat", 62),
    ("utime", 30),
    ("utimensat", 316),
    ("utimensat_time64", 412),
    ("utimes", 266),
    ("vfork", 190),
    ("vhangup", 111),
    ("vm86", -10071),
    ("vm86old", -10072),
    ("vmsplice", 309),
    ("vserver", -10082),
    ("wait4", 114),
    ("waitid", 277),
    ("waitpid", 7),
    ("write", 4),
    ("writev", 146),
];
