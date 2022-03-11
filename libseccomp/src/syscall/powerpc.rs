pub const SYSCALLS: &[(&str, i32)] = &[
    ("_llseek", 140),
    ("_newselect", 142),
    ("_sysctl", 149),
    ("accept", -105),
    ("accept4", -118),
    ("access", 33),
    ("acct", 51),
    ("add_key", 269),
    ("adjtimex", 124),
    ("afs_syscall", 137),
    ("alarm", 27),
    ("arch_prctl", -10001),
    ("arm_fadvise64_64", -10083),
    ("arm_sync_file_range", -10084),
    ("bdflush", 134),
    ("bind", -102),
    ("bpf", 361),
    ("break", 17),
    ("breakpoint", -10182),
    ("brk", 45),
    ("cachectl", -10103),
    ("cacheflush", -10104),
    ("capget", 183),
    ("capset", 184),
    ("chdir", 12),
    ("chmod", 15),
    ("chown", 181),
    ("chown32", -10004),
    ("chroot", 61),
    ("clock_adjtime", 347),
    ("clock_adjtime64", 405),
    ("clock_getres", 247),
    ("clock_getres_time64", 406),
    ("clock_gettime", 246),
    ("clock_gettime64", 403),
    ("clock_nanosleep", 248),
    ("clock_nanosleep_time64", 407),
    ("clock_settime", 245),
    ("clock_settime64", 404),
    ("clone", 120),
    ("clone3", 435),
    ("close", 6),
    ("close_range", 436),
    ("connect", -103),
    ("copy_file_range", 379),
    ("creat", 8),
    ("create_module", 127),
    ("delete_module", 129),
    ("dup", 41),
    ("dup2", 63),
    ("dup3", 316),
    ("epoll_create", 236),
    ("epoll_create1", 315),
    ("epoll_ctl", 237),
    ("epoll_ctl_old", -10005),
    ("epoll_pwait", 303),
    ("epoll_pwait2", 441),
    ("epoll_wait", 238),
    ("epoll_wait_old", -10006),
    ("eventfd", 307),
    ("eventfd2", 314),
    ("execve", 11),
    ("execveat", 362),
    ("exit", 1),
    ("exit_group", 234),
    ("faccessat", 298),
    ("faccessat2", 439),
    ("fadvise64", 233),
    ("fadvise64_64", 254),
    ("fallocate", 309),
    ("fanotify_init", 323),
    ("fanotify_mark", 324),
    ("fchdir", 133),
    ("fchmod", 94),
    ("fchmodat", 297),
    ("fchown", 95),
    ("fchown32", -10008),
    ("fchownat", 289),
    ("fcntl", 55),
    ("fcntl64", 204),
    ("fdatasync", 148),
    ("fgetxattr", 214),
    ("finit_module", 353),
    ("flistxattr", 217),
    ("flock", 143),
    ("fork", 2),
    ("fremovexattr", 220),
    ("fsconfig", 431),
    ("fsetxattr", 211),
    ("fsmount", 432),
    ("fsopen", 430),
    ("fspick", 433),
    ("fstat", 108),
    ("fstat64", 197),
    ("fstatat64", 291),
    ("fstatfs", 100),
    ("fstatfs64", 253),
    ("fsync", 118),
    ("ftime", 35),
    ("ftruncate", 93),
    ("ftruncate64", 194),
    ("futex", 221),
    ("futex_time64", 422),
    ("futimesat", 290),
    ("get_kernel_syms", 130),
    ("get_mempolicy", 260),
    ("get_robust_list", 299),
    ("get_thread_area", -10076),
    ("get_tls", -10204),
    ("getcpu", 302),
    ("getcwd", 182),
    ("getdents", 141),
    ("getdents64", 202),
    ("getegid", 50),
    ("getegid32", -10015),
    ("geteuid", 49),
    ("geteuid32", -10016),
    ("getgid", 47),
    ("getgid32", -10017),
    ("getgroups", 80),
    ("getgroups32", -10018),
    ("getitimer", 105),
    ("getpeername", -107),
    ("getpgid", 132),
    ("getpgrp", 65),
    ("getpid", 20),
    ("getpmsg", 187),
    ("getppid", 64),
    ("getpriority", 96),
    ("getrandom", 359),
    ("getresgid", 170),
    ("getresgid32", -10019),
    ("getresuid", 165),
    ("getresuid32", -10020),
    ("getrlimit", 76),
    ("getrusage", 77),
    ("getsid", 147),
    ("getsockname", -106),
    ("getsockopt", -115),
    ("gettid", 207),
    ("gettimeofday", 78),
    ("getuid", 24),
    ("getuid32", -10021),
    ("getxattr", 212),
    ("gtty", 32),
    ("idle", 112),
    ("init_module", 128),
    ("inotify_add_watch", 276),
    ("inotify_init", 275),
    ("inotify_init1", 318),
    ("inotify_rm_watch", 277),
    ("io_cancel", 231),
    ("io_destroy", 228),
    ("io_getevents", 229),
    ("io_pgetevents", 388),
    ("io_pgetevents_time64", 416),
    ("io_setup", 227),
    ("io_submit", 230),
    ("io_uring_enter", 426),
    ("io_uring_register", 427),
    ("io_uring_setup", 425),
    ("ioctl", 54),
    ("ioperm", 101),
    ("iopl", 110),
    ("ioprio_get", 274),
    ("ioprio_set", 273),
    ("ipc", 117),
    ("kcmp", 354),
    ("kexec_file_load", 382),
    ("kexec_load", 268),
    ("keyctl", 271),
    ("kill", 37),
    ("landlock_add_rule", 445),
    ("landlock_create_ruleset", 444),
    ("landlock_restrict_self", 446),
    ("lchown", 16),
    ("lchown32", -10025),
    ("lgetxattr", 213),
    ("link", 9),
    ("linkat", 294),
    ("listen", -104),
    ("listxattr", 215),
    ("llistxattr", 216),
    ("lock", 53),
    ("lookup_dcookie", 235),
    ("lremovexattr", 219),
    ("lseek", 19),
    ("lsetxattr", 210),
    ("lstat", 107),
    ("lstat64", 196),
    ("madvise", 205),
    ("mbind", 259),
    ("membarrier", 365),
    ("memfd_create", 360),
    ("memfd_secret", -10244),
    ("migrate_pages", 258),
    ("mincore", 206),
    ("mkdir", 39),
    ("mkdirat", 287),
    ("mknod", 14),
    ("mknodat", 288),
    ("mlock", 150),
    ("mlock2", 378),
    ("mlockall", 152),
    ("mmap", 90),
    ("mmap2", 192),
    ("modify_ldt", 123),
    ("mount", 21),
    ("mount_setattr", 442),
    ("move_mount", 429),
    ("move_pages", 301),
    ("mprotect", 125),
    ("mpx", 56),
    ("mq_getsetattr", 267),
    ("mq_notify", 266),
    ("mq_open", 262),
    ("mq_timedreceive", 265),
    ("mq_timedreceive_time64", 419),
    ("mq_timedsend", 264),
    ("mq_timedsend_time64", 418),
    ("mq_unlink", 263),
    ("mremap", 163),
    ("msgctl", -214),
    ("msgget", -213),
    ("msgrcv", -212),
    ("msgsnd", -211),
    ("msync", 144),
    ("multiplexer", 201),
    ("munlock", 151),
    ("munlockall", 153),
    ("munmap", 91),
    ("name_to_handle_at", 345),
    ("nanosleep", 162),
    ("newfstatat", -10031),
    ("nfsservctl", 168),
    ("nice", 34),
    ("oldfstat", 28),
    ("oldlstat", 84),
    ("oldolduname", 59),
    ("oldstat", 18),
    ("olduname", 109),
    ("open", 5),
    ("open_by_handle_at", 346),
    ("open_tree", 428),
    ("openat", 286),
    ("openat2", 437),
    ("pause", 29),
    ("pciconfig_iobase", 200),
    ("pciconfig_read", 198),
    ("pciconfig_write", 199),
    ("perf_event_open", 319),
    ("personality", 136),
    ("pidfd_getfd", 438),
    ("pidfd_open", 434),
    ("pidfd_send_signal", 424),
    ("pipe", 42),
    ("pipe2", 317),
    ("pivot_root", 203),
    ("pkey_alloc", 384),
    ("pkey_free", 385),
    ("pkey_mprotect", 386),
    ("poll", 167),
    ("ppoll", 281),
    ("ppoll_time64", 414),
    ("prctl", 171),
    ("pread64", 179),
    ("preadv", 320),
    ("preadv2", 380),
    ("prlimit64", 325),
    ("process_madvise", 440),
    ("process_mrelease", 448),
    ("process_vm_readv", 351),
    ("process_vm_writev", 352),
    ("prof", 44),
    ("profil", 98),
    ("pselect6", 280),
    ("pselect6_time64", 413),
    ("ptrace", 26),
    ("putpmsg", 188),
    ("pwrite64", 180),
    ("pwritev", 321),
    ("pwritev2", 381),
    ("query_module", 166),
    ("quotactl", 131),
    ("quotactl_fd", 443),
    ("read", 3),
    ("readahead", 191),
    ("readdir", 89),
    ("readlink", 85),
    ("readlinkat", 296),
    ("readv", 145),
    ("reboot", 88),
    ("recv", -110),
    ("recvfrom", -112),
    ("recvmmsg", -119),
    ("recvmmsg_time64", 417),
    ("recvmsg", -117),
    ("remap_file_pages", 239),
    ("removexattr", 218),
    ("rename", 38),
    ("renameat", 293),
    ("renameat2", 357),
    ("request_key", 270),
    ("restart_syscall", 0),
    ("riscv_flush_icache", -10243),
    ("rmdir", 40),
    ("rseq", 387),
    ("rt_sigaction", 173),
    ("rt_sigpending", 175),
    ("rt_sigprocmask", 174),
    ("rt_sigqueueinfo", 177),
    ("rt_sigreturn", 172),
    ("rt_sigsuspend", 178),
    ("rt_sigtimedwait", 176),
    ("rt_sigtimedwait_time64", 421),
    ("rt_tgsigqueueinfo", 322),
    ("rtas", 255),
    ("s390_guarded_storage", -10205),
    ("s390_pci_mmio_read", -10197),
    ("s390_pci_mmio_write", -10198),
    ("s390_runtime_instr", -10196),
    ("s390_sthyi", -10206),
    ("sched_get_priority_max", 159),
    ("sched_get_priority_min", 160),
    ("sched_getaffinity", 223),
    ("sched_getattr", 356),
    ("sched_getparam", 155),
    ("sched_getscheduler", 157),
    ("sched_rr_get_interval", 161),
    ("sched_rr_get_interval_time64", 423),
    ("sched_setaffinity", 222),
    ("sched_setattr", 355),
    ("sched_setparam", 154),
    ("sched_setscheduler", 156),
    ("sched_yield", 158),
    ("seccomp", 358),
    ("security", -10042),
    ("select", 82),
    ("semctl", -203),
    ("semget", -202),
    ("semop", -201),
    ("semtimedop", -204),
    ("semtimedop_time64", 420),
    ("send", -109),
    ("sendfile", 186),
    ("sendfile64", 226),
    ("sendmmsg", -120),
    ("sendmsg", -116),
    ("sendto", -111),
    ("set_mempolicy", 261),
    ("set_robust_list", 300),
    ("set_thread_area", -10079),
    ("set_tid_address", 232),
    ("set_tls", -10183),
    ("setdomainname", 121),
    ("setfsgid", 139),
    ("setfsgid32", -10044),
    ("setfsuid", 138),
    ("setfsuid32", -10045),
    ("setgid", 46),
    ("setgid32", -10046),
    ("setgroups", 81),
    ("setgroups32", -10047),
    ("sethostname", 74),
    ("setitimer", 104),
    ("setns", 350),
    ("setpgid", 57),
    ("setpriority", 97),
    ("setregid", 71),
    ("setregid32", -10048),
    ("setresgid", 169),
    ("setresgid32", -10049),
    ("setresuid", 164),
    ("setresuid32", -10050),
    ("setreuid", 70),
    ("setreuid32", -10051),
    ("setrlimit", 75),
    ("setsid", 66),
    ("setsockopt", -114),
    ("settimeofday", 79),
    ("setuid", 23),
    ("setuid32", -10052),
    ("setxattr", 209),
    ("sgetmask", 68),
    ("shmat", -221),
    ("shmctl", -224),
    ("shmdt", -222),
    ("shmget", -223),
    ("shutdown", -113),
    ("sigaction", 67),
    ("sigaltstack", 185),
    ("signal", 48),
    ("signalfd", 305),
    ("signalfd4", 313),
    ("sigpending", 73),
    ("sigprocmask", 126),
    ("sigreturn", 119),
    ("sigsuspend", 72),
    ("socket", -101),
    ("socketcall", 102),
    ("socketpair", -108),
    ("splice", 283),
    ("spu_create", 279),
    ("spu_run", 278),
    ("ssetmask", 69),
    ("stat", 106),
    ("stat64", 195),
    ("statfs", 99),
    ("statfs64", 252),
    ("statx", 383),
    ("stime", 25),
    ("stty", 31),
    ("subpage_prot", 310),
    ("swapcontext", 249),
    ("swapoff", 115),
    ("swapon", 87),
    ("switch_endian", 363),
    ("symlink", 83),
    ("symlinkat", 295),
    ("sync", 36),
    ("sync_file_range", -10100),
    ("sync_file_range2", 308),
    ("syncfs", 348),
    ("sys_debug_setcontext", 256),
    ("syscall", -10090),
    ("sysfs", 135),
    ("sysinfo", 116),
    ("syslog", 103),
    ("sysmips", -10106),
    ("tee", 284),
    ("tgkill", 250),
    ("time", 13),
    ("timer_create", 240),
    ("timer_delete", 244),
    ("timer_getoverrun", 243),
    ("timer_gettime", 242),
    ("timer_gettime64", 408),
    ("timer_settime", 241),
    ("timer_settime64", 409),
    ("timerfd", -10107),
    ("timerfd_create", 306),
    ("timerfd_gettime", 312),
    ("timerfd_gettime64", 410),
    ("timerfd_settime", 311),
    ("timerfd_settime64", 411),
    ("times", 43),
    ("tkill", 208),
    ("truncate", 92),
    ("truncate64", 193),
    ("tuxcall", 225),
    ("ugetrlimit", 190),
    ("ulimit", 58),
    ("umask", 60),
    ("umount", 22),
    ("umount2", 52),
    ("uname", 122),
    ("unlink", 10),
    ("unlinkat", 292),
    ("unshare", 282),
    ("uselib", 86),
    ("userfaultfd", 364),
    ("usr26", -10184),
    ("usr32", -10185),
    ("ustat", 62),
    ("utime", 30),
    ("utimensat", 304),
    ("utimensat_time64", 412),
    ("utimes", 251),
    ("vfork", 189),
    ("vhangup", 111),
    ("vm86", 113),
    ("vm86old", -10072),
    ("vmsplice", 285),
    ("vserver", -10082),
    ("wait4", 114),
    ("waitid", 272),
    ("waitpid", 7),
    ("write", 4),
    ("writev", 146),
];
