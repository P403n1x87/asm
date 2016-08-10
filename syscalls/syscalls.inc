; syscalls.inc
;
; A simple x86_64 Hello World application that shows how import symbols
; from an external file.
;
; Copyright (C) 2016 Gabriele N. Tornetta <phoenix1987@gmail.com>. All
; rights reserved.
;
; This program is free software: you can redistribute it and/or modify
; it under the terms of the GNU General Public License as published by
; the Free Software Foundation, either version 3 of the License, or
; (at your option) any later version.
;
; This program is distributed in the hope that it will be useful,
; but WITHOUT ANY WARRANTY; without even the implied warranty of
; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
; GNU General Public License for more details.
;
; You should have received a copy of the GNU General Public License
; along with this program.  If not, see <http://www.gnu.org/licenses/>.
;
;
; SYSTEM CALL              equ %rax ; %rdi                              %rsi                                  %rdx                                 %r10                           %r8                                  %r9
;

SYS_READ                   equ 0    ; unsigned int fd                   char *buf                             size_t count
SYS_WRITE                  equ 1    ; unsigned int fd                   const char *buf                       size_t count
SYS_OPEN                   equ 2    ; const char *filename              int flags                             int mode
SYS_CLOSE                  equ 3    ; unsigned int fd
SYS_STAT                   equ 4    ; const char *filename              struct stat *statbuf
SYS_FSTAT                  equ 5    ; unsigned int fd                   struct stat *statbuf
SYS_LSTAT                  equ 6    ; fconst char *filename             struct stat *statbuf
SYS_POLL                   equ 7    ; struct poll_fd *ufds              unsigned int nfds                     long timeout_msecs
SYS_LSEEK                  equ 8    ; unsigned int fd                   off_t offset                          unsigned int origin
SYS_MMAP                   equ 9    ; unsigned long addr                unsigned long len                     unsigned long prot                   unsigned long flags            unsigned long fd                     unsigned long off
SYS_MPROTECT               equ 10   ; unsigned long start               size_t len                            unsigned long prot
SYS_MUNMAP                 equ 11   ; unsigned long addr                size_t len
SYS_BRK                    equ 12   ; unsigned long brk
SYS_RT_SIGACTION           equ 13   ; int sig                           const struct sigaction *act           struct sigaction *oact               size_t sigsetsize
SYS_RT_SIGPROCMASK         equ 14   ; int how                           sigset_t *nset                        sigset_t *oset                       size_t sigsetsize
SYS_RT_SIGRETURN           equ 15   ; unsigned long __unused
SYS_IOCTL                  equ 16   ; unsigned int fd                   unsigned int cmd                      unsigned long arg
SYS_PREAD64                equ 17   ; unsigned long fd                  char *buf                             size_t count                         loff_t pos
SYS_PWRITE64               equ 18   ; unsigned int fd                   const char *buf                       size_t count                         loff_t pos
SYS_READV                  equ 19   ; unsigned long fd                  const struct iovec *vec               unsigned long vlen
SYS_WRITEV                 equ 20   ; unsigned long fd                  const struct iovec *vec               unsigned long vlen
SYS_ACCESS                 equ 21   ; const char *filename              int mode
SYS_PIPE                   equ 22   ; int *filedes
SYS_SELECT                 equ 23   ; int n                             fd_set *inp                           fd_set *outp                         fd_set*exp                     struct timeval *tvp
SYS_SCHED_YIELD            equ 24   ;
SYS_MREMAP                 equ 25   ; unsigned long addr                unsigned long old_len                 unsigned long new_len                unsigned long flags            unsigned long new_addr
SYS_MSYNC                  equ 26   ; unsigned long start               size_t len                            int flags
SYS_MINCORE                equ 27   ; unsigned long start               size_t len                            unsigned char *vec
SYS_MADVISE                equ 28   ; unsigned long start               size_t len_in                         int behavior
SYS_SHMGET                 equ 29   ; key_t key                         size_t size                           int shmflg
SYS_SHMAT                  equ 30   ; int shmid                         char *shmaddr                         int shmflg
SYS_SHMCTL                 equ 31   ; int shmid                         int cmd                               struct shmid_ds *buf
SYS_DUP                    equ 32   ; unsigned int fildes
SYS_DUP2                   equ 33   ; unsigned int oldfd                unsigned int newfd
SYS_PAUSE                  equ 34   ;
SYS_NANOSLEEP              equ 35   ; struct timespec *rqtp             struct timespec *rmtp
SYS_GETITIMER              equ 36   ; int which                         struct itimerval *value
SYS_ALARM                  equ 37   ; unsigned int seconds
SYS_SETITIMER              equ 38   ; int which                         struct itimerval *value               struct itimerval *ovalue
SYS_GETPID                 equ 39   ;
SYS_SENDFILE               equ 40   ; int out_fd                        int in_fd                             off_t *offset                        size_t count
SYS_SOCKET                 equ 41   ; int family                        int type                              int protocol
SYS_CONNECT                equ 42   ; int fd                            struct sockaddr *uservaddr            int addrlen
SYS_ACCEPT                 equ 43   ; int fd                            struct sockaddr *upeer_sockaddr       int *upeer_addrlen
SYS_SENDTO                 equ 44   ; int fd                            void *buff                            size_t len                           unsigned flags                 struct sockaddr *addr                int addr_len
SYS_RECVFROM               equ 45   ; int fd                            void *ubuf                            size_t size                          unsigned flags                 struct sockaddr *addr                int *addr_len
SYS_SENDMSG                equ 46   ; int fd                            struct msghdr *msg                    unsigned flags
SYS_RECVMSG                equ 47   ; int fd                            struct msghdr *msg                    unsigned int flags
SYS_SHUTDOWN               equ 48   ; int fd                            int how
SYS_BIND                   equ 49   ; int fd                            struct sokaddr *umyaddr               int addrlen
SYS_LISTEN                 equ 50   ; int fd                            int backlog
SYS_GETSOCKNAME            equ 51   ; int fd                            struct sockaddr *usockaddr            int *usockaddr_len
SYS_GETPEERNAME            equ 52   ; int fd                            struct sockaddr *usockaddr            int *usockaddr_len
SYS_SOCKETPAIR             equ 53   ; int family                        int type                              int protocol                         int *usockvec
SYS_SETSOCKOPT             equ 54   ; int fd                            int level                             int optname                          char *optval                   int optlen
SYS_GETSOCKOPT             equ 55   ; int fd                            int level                             int optname                          char *optval                   int *optlen
SYS_CLONE                  equ 56   ; unsigned long clone_flags         unsigned long newsp                   void *parent_tid                     void *child_tid
SYS_FORK                   equ 57   ;
SYS_VFORK                  equ 58   ;
SYS_EXECVE                 equ 59   ; const char *filename              const char *const argv[]              const char *const envp[]
SYS_EXIT                   equ 60   ; int error_code
SYS_WAIT4                  equ 61   ; pid_t upid                        int *stat_addr                        int options                          struct rusage *ru
SYS_KILL                   equ 62   ; pid_t pid                         int sig
SYS_UNAME                  equ 63   ; struct old_utsname *name
SYS_SEMGET                 equ 64   ; key_t key                         int nsems                             int semflg
SYS_SEMOP                  equ 65   ; int semid                         struct sembuf *tsops                  unsigned nsops
SYS_SEMCTL                 equ 66   ; int semid                         int semnum                            int cmd                              union semun arg
SYS_SHMDT                  equ 67   ; char *shmaddr
SYS_MSGGET                 equ 68   ; key_t key                         int msgflg
SYS_MSGSND                 equ 69   ; int msqid                         struct msgbuf *msgp                   size_t msgsz                         int msgflg
SYS_MSGRCV                 equ 70   ; int msqid                         struct msgbuf *msgp                   size_t msgsz                         long msgtyp                    int msgflg
SYS_MSGCTL                 equ 71   ; int msqid                         int cmd                               struct msqid_ds *buf
SYS_FCNTL                  equ 72   ; unsigned int fd                   unsigned int cmd                      unsigned long arg
SYS_FLOCK                  equ 73   ; unsigned int fd                   unsigned int cmd
SYS_FSYNC                  equ 74   ; unsigned int fd
SYS_FDATASYNC              equ 75   ; unsigned int fd
SYS_TRUNCATE               equ 76   ; const char *path                  long length
SYS_FTRUNCATE              equ 77   ; unsigned int fd                   unsigned long length
SYS_GETDENTS               equ 78   ; unsigned int fd                   struct linux_dirent *dirent           unsigned int count
SYS_GETCWD                 equ 79   ; char *buf                         unsigned long size
SYS_CHDIR                  equ 80   ; const char *filename
SYS_FCHDIR                 equ 81   ; unsigned int fd
SYS_RENAME                 equ 82   ; const char *oldname               const char *newname
SYS_MKDIR                  equ 83   ; const char *pathname              int mode
SYS_RMDIR                  equ 84   ; const char *pathname
SYS_CREAT                  equ 85   ; const char *pathname              int mode
SYS_LINK                   equ 86   ; const char *oldname               const char *newname
SYS_UNLINK                 equ 87   ; const char *pathname
SYS_SYMLINK                equ 88   ; const char *oldname               const char *newname
SYS_READLINK               equ 89   ; const char *path                  char *buf                             int bufsiz
SYS_CHMOD                  equ 90   ; const char *filename              mode_t mode
SYS_FCHMOD                 equ 91   ; unsigned int fd                   mode_t mode
SYS_CHOWN                  equ 92   ; const char *filename              uid_t user                            git_t group
SYS_FCHOWN                 equ 93   ; unsigned int fd                   uid_t user                            git_t group
SYS_LCHOWN                 equ 94   ; const char *filename              uid_t user                            git_t group
SYS_UMASK                  equ 95   ; int mask
SYS_GETTIMEOFDAY           equ 96   ; struct timeval *tv                struct timezone *tz
SYS_GETRLIMIT              equ 97   ; unsigned int resource             struct rlimit *rlim
SYS_GETRUSAGE              equ 98   ; int who                           struct rusage *ru
SYS_SYSINFO                equ 99   ; struct sysinfo *info
SYS_TIMES                  equ 100  ; struct sysinfo *info
SYS_PTRACE                 equ 101  ; long request                      long pid                              unsigned long addr                   unsigned long data
SYS_GETUID                 equ 102  ;
SYS_SYSLOG                 equ 103  ; int type                          char *buf                             int len
SYS_GETGID                 equ 104  ;
SYS_SETUID                 equ 105  ; uid_t uid
SYS_SETGID                 equ 106  ; git_t gid
SYS_GETEUID                equ 107  ;
SYS_GETEGID                equ 108  ;
SYS_SETPGID                equ 109  ; pid_t pid                         pid_t pgid
SYS_GETPPID                equ 110  ;
SYS_GETPGRP                equ 111  ;
SYS_SETSID                 equ 112  ;
SYS_SETREUID               equ 113  ; uid_t ruid                        uid_t euid
SYS_SETREGID               equ 114  ; git_t rgid                        gid_t egid
SYS_GETGROUPS              equ 115  ; int gidsetsize                    gid_t *grouplist
SYS_SETGROUPS              equ 116  ; int gidsetsize                    gid_t *grouplist
SYS_SETRESUID              equ 117  ; uid_t *ruid                       uid_t *euid                           uid_t *suid
SYS_GETRESUID              equ 118  ; uid_t *ruid                       uid_t *euid                           uid_t *suid
SYS_SETRESGID              equ 119  ; gid_t rgid                        gid_t egid                            gid_t sgid
SYS_GETRESGID              equ 120  ; git_t *rgid                       git_t *egid                           git_t *sgid
SYS_GETPGID                equ 121  ; pid_t pid
SYS_SETFSUID               equ 122  ; uid_t uid
SYS_SETFSGID               equ 123  ; gid_t gid
SYS_GETSID                 equ 124  ; pid_t pid
SYS_CAPGET                 equ 125  ; cap_user_header_t header          cap_user_data_t dataptr
SYS_CAPSET                 equ 126  ; cap_user_header_t header          const cap_user_data_t data
SYS_RT_SIGPENDING          equ 127  ; sigset_t *set                     size_t sigsetsize
SYS_RT_SIGTIMEDWAIT        equ 128  ; const sigset_t *uthese            siginfo_t *uinfo                      const struct timespec *uts           size_t sigsetsize
SYS_RT_SIGQUEUEINFO        equ 129  ; pid_t pid                         int sig                               siginfo_t *uinfo
SYS_RT_SIGSUSPEND          equ 130  ; sigset_t *unewset                 size_t sigsetsize
SYS_SIGALTSTACK            equ 131  ; const stack_t *uss                stack_t *uoss
SYS_UTIME                  equ 132  ; char *filename                    struct utimbuf *times
SYS_MKNOD                  equ 133  ; const char *filename              int mode                              unsigned dev
SYS_USELIB                 equ 134  ; NOT IMPLEMENTED
SYS_PERSONALITY            equ 135  ; unsigned int personality
SYS_USTAT                  equ 136  ; unsigned dev                      struct ustat *ubuf
SYS_STATFS                 equ 137  ; const char *pathname              struct statfs *buf
SYS_FSTATFS                equ 138  ; unsigned int fd                   struct statfs *buf
SYS_SYSFS                  equ 139  ; int option                        unsigned long arg1                    unsigned long arg2
SYS_GETPRIORITY            equ 140  ; int which                         int who
SYS_SETPRIORITY            equ 141  ; int which                         int who                               int niceval
SYS_SCHED_SETPARAM         equ 142  ; pid_t pid                         struct sched_param *param
SYS_SCHED_GETPARAM         equ 143  ; pid_t pid                         struct sched_param *param
SYS_SCHED_SETSCHEDULER     equ 144  ; pid_t pid                         int policy                            struct sched_param *param
SYS_SCHED_GETSCHEDULER     equ 145  ; pid_t pid
SYS_SCHED_GET_PRIORITY_MAX equ 146  ; int policy
SYS_SCHED_GET_PRIORITY_MIN equ 147  ; int policy
SYS_SCHED_RR_GET_INTERVAL  equ 148  ; pid_t pid                         struct timespec *interval
SYS_MLOCK                  equ 149  ; unsigned long start               size_t len
SYS_MUNLOCK                equ 150  ; unsigned long start               size_t len
SYS_MLOCKALL               equ 151  ; int flags
SYS_MUNLOCKALL             equ 152  ;
SYS_VHANGUP                equ 153  ;
SYS_MODIFY_LDT             equ 154  ; int func                          void *ptr                             unsigned long bytecount
SYS_PIVOT_ROOT             equ 155  ; const char *new_root              const char *put_old
SYS__SYSCTL                equ 156  ; struct __sysctl_args *args
SYS_PRCTL                  equ 157  ; int option                        unsigned long arg2                    unsigned long arg3                   unsigned long arg4                                                  unsigned long arg5
SYS_ARCH_PRCTL             equ 158  ; struct task_struct *task          int code                              unsigned long *addr
SYS_ADJTIMEX               equ 159  ; struct timex *txc_p
SYS_SETRLIMIT              equ 160  ; unsigned int resource             struct rlimit *rlim
SYS_CHROOT                 equ 161  ; const char *filename
SYS_SYNC                   equ 162  ;
SYS_ACCT                   equ 163  ; const char *name
SYS_SETTIMEOFDAY           equ 164  ; struct timeval *tv                struct timezone *tz
SYS_MOUNT                  equ 165  ; char *dev_name                    char *dir_name                        char *type                           unsigned long flags            void *data
SYS_UMOUNT2                equ 166  ; const char *target                int flags
SYS_SWAPON                 equ 167  ; const char *specialfile           int swap_flags
SYS_SWAPOFF                equ 168  ; const char *specialfile
SYS_REBOOT                 equ 169  ; int magic1                        int magic2                            unsigned int cmd                     void *arg
SYS_SETHOSTNAME            equ 170  ; char *name                        int len
SYS_SETDOMAINNAME          equ 171  ; char *name                        int len
SYS_IOPL                   equ 172  ; unsigned int level                struct pt_regs *regs
SYS_IOPERM                 equ 173  ; unsigned long from                unsigned long num                     int turn_on
SYS_CREATE_MODULE          equ 174  ; REMOVED IN Linux 2.6
SYS_INIT_MODULE            equ 175  ; void *umod                        unsigned long len                     const char *uargs
SYS_DELETE_MODULE          equ 176  ; const chat *name_user             unsigned int flags
SYS_GET_KERNEL_SYMS        equ 177  ; REMOVED IN Linux 2.6
SYS_QUERY_MODULE           equ 178  ; REMOVED IN Linux 2.6
SYS_QUOTACTL               equ 179  ; unsigned int cmd                  const char *special                   qid_t id                             void *addr
SYS_NFSSERVCTL             equ 180  ; NOT IMPLEMENTED
SYS_GETPMSG                equ 181  ; NOT IMPLEMENTED
SYS_PUTPMSG                equ 182  ; NOT IMPLEMENTED
SYS_AFS_SYSCALL            equ 183  ; NOT IMPLEMENTED
SYS_TUXCALL                equ 184  ; NOT IMPLEMENTED
SYS_SECURITY               equ 185  ; NOT IMPLEMENTED
SYS_GETTID                 equ 186  ;
SYS_READAHEAD              equ 187  ; int fd                            loff_t offset                         size_t count
SYS_SETXATTR               equ 188  ; const char *pathname              const char *name                      const void *value                    size_t size                    int flags
SYS_LSETXATTR              equ 189  ; const char *pathname              const char *name                      const void *value                    size_t size                    int flags
SYS_FSETXATTR              equ 190  ; int fd                            const char *name                      const void *value                    size_t size                    int flags
SYS_GETXATTR               equ 191  ; const char *pathname              const char *name                      void *value                          size_t size
SYS_LGETXATTR              equ 192  ; const char *pathname              const char *name                      void *value                          size_t size
SYS_FGETXATTR              equ 193  ; int fd                            const har *name                       void *value                          size_t size
SYS_LISTXATTR              equ 194  ; const char *pathname              char *list                            size_t size
SYS_LLISTXATTR             equ 195  ; const char *pathname              char *list                            size_t size
SYS_FLISTXATTR             equ 196  ; int fd                            char *list                            size_t size
SYS_REMOVEXATTR            equ 197  ; const char *pathname              const char *name
SYS_LREMOVEXATTR           equ 198  ; const char *pathname              const char *name
SYS_FREMOVEXATTR           equ 199  ; int fd                            const char *name
SYS_TKILL                  equ 200  ; pid_t pid                         ing sig
SYS_TIME                   equ 201  ; time_t *tloc
SYS_FUTEX                  equ 202  ; u32 *uaddr                        int op                                u32 val                              struct timespec *utime         u32 *uaddr2                          u32 val3
SYS_SCHED_SETAFFINITY      equ 203  ; pid_t pid                         unsigned int len                      unsigned long *user_mask_ptr
SYS_SCHED_GETAFFINITY      equ 204  ; pid_t pid                         unsigned int len                      unsigned long *user_mask_ptr
SYS_SET_THREAD_AREA        equ 205  ; NOT IMPLEMENTED. Use arch_prctl
SYS_IO_SETUP               equ 206  ; unsigned nr_events                aio_context_t *ctxp
SYS_IO_DESTROY             equ 207  ; aio_context_t ctx
SYS_IO_GETEVENTS           equ 208  ; aio_context_t ctx_id              long min_nr                           long nr                              struct io_event *events
SYS_IO_SUBMIT              equ 209  ; aio_context_t ctx_id              long nr                               struct iocb **iocbpp
SYS_IO_CANCEL              equ 210  ; aio_context_t ctx_id              struct iocb *iocb                     struct io_event *result
SYS_GET_THREAD_AREA        equ 211  ; NOT IMPLEMENTED. Use arch_prctl
SYS_LOOKUP_DCOOKIE         equ 212  ; u64 cookie64                      long buf                              long len
SYS_EPOLL_CREATE           equ 213  ; int size
SYS_EPOLL_CTL_OLD          equ 214  ; NOT IMPLEMENTED
SYS_EPOLL_WAIT_OLD         equ 215  ; NOT IMPLEMENTED
SYS_REMAP_FILE_PAGES       equ 216  ; unsigned long start               unsigned long size                    unsigned long prot                   unsigned long pgoff            unsigned long flags
SYS_GETDENTS64             equ 217  ; unsigned int fd                   struct linux_dirent64 *dirent         unsigned int count
SYS_SET_TID_ADDRESS        equ 218  ; int *tidptr
SYS_RESTART_SYSCALL        equ 219  ;
SYS_SEMTIMEDOP             equ 220  ; int semid                         struct sembuf *tsops                  unsigned nsops                       const struct timespec *timeout
SYS_FADVISE64              equ 221  ; int fd                            loff_t offset                         size_t len                           int advice
SYS_TIMER_CREATE           equ 222  ; const clockid_t which_clock       struct sigevent *timer_event_spec     timer_t *created_timer_id
SYS_TIMER_SETTIME          equ 223  ; timer_t timer_id                  int flags                             const struct itimerspec *new_setting struct itimerspec *old_setting
SYS_TIMER_GETTIME          equ 224  ; timer_t timer_id                  struct itimerspec *setting
SYS_TIMER_GETOVERRUN       equ 225  ; timer_t timer_id
SYS_TIMER_DELETE           equ 226  ; timer_t timer_id
SYS_CLOCK_SETTIME          equ 227  ; const clockid_t which_clock       const struct timespec *tp
SYS_CLOCK_GETTIME          equ 228  ; const clockid_t which_clock       struct timespec *tp
SYS_CLOCK_GETRES           equ 229  ; const clockid_t which_clock       struct timespec *tp
SYS_CLOCK_NANOSLEEP        equ 230  ; const clockid_t which_clock       int flags                             const struct timespec *rqtp          struct timespec *rmtp
SYS_EXIT_GROUP             equ 231  ; int error_code
SYS_EPOLL_WAIT             equ 232  ; int epfd                          struct epoll_event *events            int maxevents                        int timeout
SYS_EPOLL_CTL              equ 233  ; int epfd                          int op                                int fd                               struct epoll_event *event
SYS_TGKILL                 equ 234  ; pid_t tgid                        pid_t pid                             int sig
SYS_UTIMES                 equ 235  ; char *filename                    struct timeval *utimes
SYS_VSERVER                equ 236  ; NOT IMPLEMENTED
SYS_MBIND                  equ 237  ; unsigned long start               unsigned long len                     unsigned long mode                   unsigned long *nmask           unsigned long maxnode                unsigned flags
SYS_SET_MEMPOLICY          equ 238  ; int mode                          unsigned long *nmask                  unsigned long maxnode
SYS_GET_MEMPOLICY          equ 239  ; int *policy                       unsigned long *nmask                  unsigned long maxnode                unsigned long addr             unsigned long flags
SYS_MQ_OPEN                equ 240  ; const char *u_name                int oflag                             mode_t mode                          struct mq_attr *u_attr
SYS_MQ_UNLINK              equ 241  ; const char *u_name
SYS_MQ_TIMEDSEND           equ 242  ; mqd_t mqdes                       const char *u_msg_ptr                 size_t msg_len                       unsigned int msg_prio          const stuct timespec *u_abs_timeout
SYS_MQ_TIMEDRECEIVE        equ 243  ; mqd_t mqdes                       char *u_msg_ptr                       size_t msg_len                       unsigned int *u_msg_prio       const struct timespec *u_abs_timeout
SYS_MQ_NOTIFY              equ 244  ; mqd_t mqdes                       const struct sigevent *u_notification
SYS_MQ_GETSETATTR          equ 245  ; mqd_t mqdes                       const struct mq_attr *u_mqstat        struct mq_attr *u_omqstat
SYS_KEXEC_LOAD             equ 246  ; unsigned long entry               unsigned long nr_segments             struct kexec_segment *segments       unsigned long flags
SYS_WAITID                 equ 247  ; int which                         pid_t upid                            struct siginfo *infop                int options                    struct rusage *ru
SYS_ADD_KEY                equ 248  ; const char *_type                 const char *_description              const void *_payload                 size_t plen
SYS_REQUEST_KEY            equ 249  ; const char *_type                 const char *_description              const char *_callout_info            key_serial_t destringid
SYS_KEYCTL                 equ 250  ; int option                        unsigned long arg2                    unsigned long arg3                   unsigned long arg4             unsigned long arg5
SYS_IOPRIO_SET             equ 251  ; int which                         int who                               int ioprio
SYS_IOPRIO_GET             equ 252  ; int which                         int who
SYS_INOTIFY_INIT           equ 253  ;
SYS_INOTIFY_ADD_WATCH      equ 254  ; int fd                            const char *pathname                  u32 mask
SYS_INOTIFY_RM_WATCH       equ 255  ; int fd                            __s32 wd
SYS_MIGRATE_PAGES          equ 256  ; pid_t pid                         unsigned long maxnode                 const unsigned long *old_nodes       const unsigned long *new_nodes
SYS_OPENAT                 equ 257  ; int dfd                           const char *filename                  int flags                            int mode
SYS_MKDIRAT                equ 258  ; int dfd                           const char *pathname                  int mode
SYS_MKNODAT                equ 259  ; int dfd                           const char *filename                  int mode                             unsigned dev
SYS_FCHOWNAT               equ 260  ; int dfd                           const char *filename                  uid_t user                           gid_t group                    int flag
SYS_FUTIMESAT              equ 261  ; int dfd                           const char *filename                  struct timeval *utimes
SYS_NEWFSTATAT             equ 262  ; int dfd                           const char *filename                  struct stat *statbuf                 int flag
SYS_UNLINKAT               equ 263  ; int dfd                           const char *pathname                  int flag
SYS_RENAMEAT               equ 264  ; int oldfd                         const char *oldname                   int newfd                            const char *newname
SYS_LINKAT                 equ 265  ; int oldfd                         const char *oldname                   int newfd                            const char *newname            int flags
SYS_SYMLINKAT              equ 266  ; const char *oldname               int newfd                             const char *newname
SYS_READLINKAT             equ 267  ; int dfd                           const char *pathname                  char *buf                            int bufsiz
SYS_FCHMODAT               equ 268  ; int dfd                           const char *filename                  mode_t mode
SYS_FACCESSAT              equ 269  ; int dfd                           const char *filename                  int mode
SYS_PSELECT6               equ 270  ; int n                             fd_set *inp                           fd_set *outp                         fd_set *exp                    struct timespec *tsp                 void *sig
SYS_PPOLL                  equ 271  ; struct pollfd *ufds               unsigned int nfds                     struct timespec *tsp                 const sigset_t *sigmask        size_t sigsetsize
SYS_UNSHARE                equ 272  ; unsigned long unshare_flags
SYS_SET_ROBUST_LIST        equ 273  ; struct robust_list_head *head     size_t len
SYS_GET_ROBUST_LIST        equ 274  ; int pid                           struct robust_list_head **head_ptr    size_t *len_ptr
SYS_SPLICE                 equ 275  ; int fd_in                         loff_t *off_in                        int fd_out                           loff_t *off_out                size_t len                           unsigned int flags
SYS_TEE                    equ 276  ; int fdin                          int fdout                             size_t len                           unsigned int flags
SYS_SYNC_FILE_RANGE        equ 277  ; long fd                           loff_t offset                         loff_t bytes                         long flags
SYS_VMSPLICE               equ 278  ; int fd                            const struct iovec *iov               unsigned long nr_segs                unsigned int flags
SYS_MOVE_PAGES             equ 279  ; pid_t pid                         unsigned long nr_pages                const void **pages                   const int *nodes               int *status                          int flags
SYS_UTIMENSAT              equ 280  ; int dfd                           const char *filename                  struct timespec *utimes              int flags
SYS_EPOLL_PWAIT            equ 281  ; int epfd                          struct epoll_event *events            int maxevents                        int timeout                    const sigset_t *sigmask              size_t sigsetsize
SYS_SIGNALFD               equ 282  ; int ufd                           sigset_t *user_mask                   size_t sizemask
SYS_TIMERFD_CREATE         equ 283  ; int clockid                       int flags
SYS_EVENTFD                equ 284  ; unsigned int count
SYS_FALLOCATE              equ 285  ; long fd                           long mode                             loff_t offset                        loff_t len
SYS_TIMERFD_SETTIME        equ 286  ; int ufd                           int flags                             const struct itimerspec *utmr        struct itimerspec *otmr
SYS_TIMERFD_GETTIME        equ 287  ; int ufd                           struct itimerspec *otmr
SYS_ACCEPT4                equ 288  ; int fd                            struct sockaddr *upeer_sockaddr       int *upeer_addrlen                   int flags
SYS_SIGNALFD4              equ 289  ; int ufd                           sigset_t *user_mask                   size_t sizemask                      int flags
SYS_EVENTFD2               equ 290  ; unsigned int count                int flags
SYS_EPOLL_CREATE1          equ 291  ; int flags
SYS_DUP3                   equ 292  ; unsigned int oldfd                unsigned int newfd                    int flags
SYS_PIPE2                  equ 293  ; int *filedes                      int flags
SYS_INOTIFY_INIT1          equ 294  ; int flags
SYS_PREADV                 equ 295  ; unsigned long fd                  const struct iovec *vec               unsigned long vlen                   unsigned long pos_l            unsigned long pos_h
SYS_PWRITEV                equ 296  ; unsigned long fd                  const struct iovec *vec               unsigned long vlen                   unsigned long pos_l            unsigned long pos_h
SYS_RT_TGSIGQUEUEINFO      equ 297  ; pid_t tgid                        pid_t pid                             int sig                              siginfo_t *uinfo
SYS_PERF_EVENT_OPEN        equ 298  ; struct perf_event_attr *attr_uptr pid_t pid                             int cpu                              int group_fd                   unsigned long flags
SYS_RECVMMSG               equ 299  ; int fd                            struct msghdr *mmsg                   unsigned int vlen                    unsigned int flags             struct timespec *timeout
SYS_FANOTIFY_INIT          equ 300  ; unsigned int flags                unsigned int event_f_flags
SYS_FANOTIFY_MARK          equ 301  ; long fanotify_fd                  long flags                            __u64 mask                           long dfd                       long pathname
SYS_PRLIMIT64              equ 302  ; pid_t pid                         unsigned int resource                 const struct rlimit64 *new_rlim      struct rlimit64 *old_rlim
SYS_NAME_TO_HANDLE_AT      equ 303  ; int dfd                           const char *name                      struct file_handle *handle           int *mnt_id                    int flag
SYS_OPEN_BY_HANDLE_AT      equ 304  ; int dfd                           const char *name                      struct file_handle *handle           int *mnt_id                    int flags
SYS_CLOCK_ADJTIME          equ 305  ; clockid_t which_clock             struct timex *tx
SYS_SYNCFS                 equ 306  ; int fd
SYS_SENDMMSG               equ 307  ; int fd                            struct mmsghdr *mmsg                  unsigned int vlen                    unsigned int flags
SYS_SETNS                  equ 308  ; int fd                            int nstype
SYS_GETCPU                 equ 309  ; unsigned *cpup                    unsigned *nodep                       struct getcpu_cache *unused
SYS_PROCESS_VM_READV       equ 310  ; pid_t pid                         const struct iovec *lvec              unsigned long liovcnt                const struct iovec *rvec       unsigned long riovcnt                unsigned long flags
SYS_PROCESS_VM_WRITEV      equ 311  ; pid_t pid                         const struct iovec *lvec              unsigned long liovcnt                const struct iovcc *rvec       unsigned long riovcnt                unsigned long flags
