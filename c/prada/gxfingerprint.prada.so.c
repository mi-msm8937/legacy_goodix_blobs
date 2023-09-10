typedef unsigned char   undefined;

typedef unsigned char    byte;
typedef unsigned char    dwfenc;
typedef unsigned int    dword;
typedef long long    longlong;
typedef unsigned long    qword;
typedef unsigned char    uchar;
typedef unsigned int    uint;
typedef unsigned long    ulong;
typedef unsigned long long    ulonglong;
typedef unsigned char    undefined1;
typedef unsigned short    undefined2;
typedef unsigned int    undefined4;
typedef unsigned long    undefined8;
typedef unsigned short    ushort;
typedef unsigned short    word;
typedef struct eh_frame_hdr eh_frame_hdr, *Peh_frame_hdr;

struct eh_frame_hdr {
    byte eh_frame_hdr_version; // Exception Handler Frame Header Version
    dwfenc eh_frame_pointer_encoding; // Exception Handler Frame Pointer Encoding
    dwfenc eh_frame_desc_entry_count_encoding; // Encoding of # of Exception Handler FDEs
    dwfenc eh_frame_table_encoding; // Exception Handler Table Encoding
};

typedef struct fde_table_entry fde_table_entry, *Pfde_table_entry;

struct fde_table_entry {
    dword initial_loc; // Initial Location
    dword data_loc; // Data location
};

typedef ushort sa_family_t;

typedef void _IO_lock_t;

typedef struct _IO_marker _IO_marker, *P_IO_marker;

typedef struct _IO_FILE _IO_FILE, *P_IO_FILE;

typedef long __off_t;

typedef long __off64_t;

typedef ulong size_t;

struct _IO_FILE {
    int _flags;
    char * _IO_read_ptr;
    char * _IO_read_end;
    char * _IO_read_base;
    char * _IO_write_base;
    char * _IO_write_ptr;
    char * _IO_write_end;
    char * _IO_buf_base;
    char * _IO_buf_end;
    char * _IO_save_base;
    char * _IO_backup_base;
    char * _IO_save_end;
    struct _IO_marker * _markers;
    struct _IO_FILE * _chain;
    int _fileno;
    int _flags2;
    __off_t _old_offset;
    ushort _cur_column;
    char _vtable_offset;
    char _shortbuf[1];
    _IO_lock_t * _lock;
    __off64_t _offset;
    void * __pad1;
    void * __pad2;
    void * __pad3;
    void * __pad4;
    size_t __pad5;
    int _mode;
    char _unused2[20];
};

struct _IO_marker {
    struct _IO_marker * _next;
    struct _IO_FILE * _sbuf;
    int _pos;
};

typedef struct stat stat, *Pstat;

typedef ulong __dev_t;

typedef ulong __ino_t;

typedef ulong __nlink_t;

typedef uint __mode_t;

typedef uint __uid_t;

typedef uint __gid_t;

typedef long __blksize_t;

typedef long __blkcnt_t;

typedef struct timespec timespec, *Ptimespec;

typedef long __time_t;

struct timespec {
    __time_t tv_sec;
    long tv_nsec;
};

struct stat {
    __dev_t st_dev;
    __ino_t st_ino;
    __nlink_t st_nlink;
    __mode_t st_mode;
    __uid_t st_uid;
    __gid_t st_gid;
    int __pad0;
    __dev_t st_rdev;
    __off_t st_size;
    __blksize_t st_blksize;
    __blkcnt_t st_blocks;
    struct timespec st_atim;
    struct timespec st_mtim;
    struct timespec st_ctim;
    long __unused[3];
};

typedef struct timezone timezone, *Ptimezone;

struct timezone {
    int tz_minuteswest;
    int tz_dsttime;
};

typedef struct itimerspec itimerspec, *Pitimerspec;

struct itimerspec {
    struct timespec it_interval;
    struct timespec it_value;
};

typedef __time_t time_t;

typedef struct sigevent sigevent, *Psigevent;

typedef union sigval sigval, *Psigval;

typedef union sigval sigval_t;

typedef union _union_1250 _union_1250, *P_union_1250;

typedef int __pid_t;

typedef struct _struct_1251 _struct_1251, *P_struct_1251;

union sigval {
    int sival_int;
    void * sival_ptr;
};

struct _struct_1251 {
    void (* _function)(sigval_t);
    void * _attribute;
};

union _union_1250 {
    int _pad[12];
    __pid_t _tid;
    struct _struct_1251 _sigev_thread;
};

struct sigevent {
    sigval_t sigev_value;
    int sigev_signo;
    int sigev_notify;
    union _union_1250 _sigev_un;
};

typedef int __clockid_t;

typedef __clockid_t clockid_t;

typedef struct timeval timeval, *Ptimeval;

typedef long __suseconds_t;

struct timeval {
    __time_t tv_sec;
    __suseconds_t tv_usec;
};

typedef struct timezone * __timezone_ptr_t;

typedef void * __timer_t;

typedef __timer_t timer_t;

typedef struct tm tm, *Ptm;

struct tm {
    int tm_sec;
    int tm_min;
    int tm_hour;
    int tm_mday;
    int tm_mon;
    int tm_year;
    int tm_wday;
    int tm_yday;
    int tm_isdst;
    long tm_gmtoff;
    char * tm_zone;
};

typedef union _union_1457 _union_1457, *P_union_1457;

typedef struct siginfo siginfo, *Psiginfo;

typedef struct siginfo siginfo_t;

typedef void (* __sighandler_t)(int);

typedef union _union_1441 _union_1441, *P_union_1441;

typedef struct _struct_1442 _struct_1442, *P_struct_1442;

typedef struct _struct_1443 _struct_1443, *P_struct_1443;

typedef struct _struct_1444 _struct_1444, *P_struct_1444;

typedef struct _struct_1445 _struct_1445, *P_struct_1445;

typedef struct _struct_1446 _struct_1446, *P_struct_1446;

typedef struct _struct_1447 _struct_1447, *P_struct_1447;

typedef long __clock_t;

struct _struct_1445 {
    __pid_t si_pid;
    __uid_t si_uid;
    int si_status;
    __clock_t si_utime;
    __clock_t si_stime;
};

struct _struct_1444 {
    __pid_t si_pid;
    __uid_t si_uid;
    sigval_t si_sigval;
};

struct _struct_1443 {
    int si_tid;
    int si_overrun;
    sigval_t si_sigval;
};

struct _struct_1446 {
    void * si_addr;
};

struct _struct_1442 {
    __pid_t si_pid;
    __uid_t si_uid;
};

struct _struct_1447 {
    long si_band;
    int si_fd;
};

union _union_1441 {
    int _pad[28];
    struct _struct_1442 _kill;
    struct _struct_1443 _timer;
    struct _struct_1444 _rt;
    struct _struct_1445 _sigchld;
    struct _struct_1446 _sigfault;
    struct _struct_1447 _sigpoll;
};

union _union_1457 {
    __sighandler_t sa_handler;
    void (* sa_sigaction)(int, siginfo_t *, void *);
};

struct siginfo {
    int si_signo;
    int si_errno;
    int si_code;
    union _union_1441 _sifields;
};

typedef struct sigaction sigaction, *Psigaction;

typedef struct __sigset_t __sigset_t, *P__sigset_t;

struct __sigset_t {
    ulong __val[16];
};

struct sigaction {
    union _union_1457 __sigaction_handler;
    struct __sigset_t sa_mask;
    int sa_flags;
    void (* sa_restorer)(void);
};

typedef union sem_t sem_t, *Psem_t;

union sem_t {
    char __size[32];
    long __align;
};

typedef struct _IO_FILE FILE;

typedef struct sockaddr sockaddr, *Psockaddr;

struct sockaddr {
    sa_family_t sa_family;
    char sa_data[14];
};

typedef struct msghdr msghdr, *Pmsghdr;

typedef uint __socklen_t;

typedef __socklen_t socklen_t;

typedef struct iovec iovec, *Piovec;

struct msghdr {
    void * msg_name;
    socklen_t msg_namelen;
    struct iovec * msg_iov;
    size_t msg_iovlen;
    void * msg_control;
    size_t msg_controllen;
    int msg_flags;
};

struct iovec {
    void * iov_base;
    size_t iov_len;
};

typedef long __ssize_t;

typedef __ssize_t ssize_t;

typedef uint __useconds_t;

typedef union pthread_mutex_t pthread_mutex_t, *Ppthread_mutex_t;

typedef struct __pthread_mutex_s __pthread_mutex_s, *P__pthread_mutex_s;

typedef struct __pthread_internal_list __pthread_internal_list, *P__pthread_internal_list;

typedef struct __pthread_internal_list __pthread_list_t;

struct __pthread_internal_list {
    struct __pthread_internal_list * __prev;
    struct __pthread_internal_list * __next;
};

struct __pthread_mutex_s {
    int __lock;
    uint __count;
    int __owner;
    uint __nusers;
    int __kind;
    int __spins;
    __pthread_list_t __list;
};

union pthread_mutex_t {
    struct __pthread_mutex_s __data;
    char __size[40];
    long __align;
};

typedef union pthread_mutexattr_t pthread_mutexattr_t, *Ppthread_mutexattr_t;

union pthread_mutexattr_t {
    char __size[4];
    int __align;
};

typedef union pthread_cond_t pthread_cond_t, *Ppthread_cond_t;

typedef struct _struct_16 _struct_16, *P_struct_16;

struct _struct_16 {
    int __lock;
    uint __futex;
    ulonglong __total_seq;
    ulonglong __wakeup_seq;
    ulonglong __woken_seq;
    void * __mutex;
    uint __nwaiters;
    uint __broadcast_seq;
};

union pthread_cond_t {
    struct _struct_16 __data;
    char __size[48];
    longlong __align;
};

typedef ulong pthread_t;

typedef union pthread_attr_t pthread_attr_t, *Ppthread_attr_t;

union pthread_attr_t {
    char __size[56];
    long __align;
};

typedef struct __dirstream __dirstream, *P__dirstream;

struct __dirstream {
};

typedef struct __dirstream DIR;

typedef struct dirent dirent, *Pdirent;

struct dirent {
    __ino_t d_ino;
    __off_t d_off;
    ushort d_reclen;
    uchar d_type;
    char d_name[256];
};

typedef struct Elf64_Rela Elf64_Rela, *PElf64_Rela;

struct Elf64_Rela {
    qword r_offset; // location to apply the relocation action
    qword r_info; // the symbol table index and the type of relocation
    qword r_addend; // a constant addend used to compute the relocatable field value
};

typedef struct Elf64_Dyn_AARCH64 Elf64_Dyn_AARCH64, *PElf64_Dyn_AARCH64;

typedef enum Elf64_DynTag_AARCH64 {
    DT_NULL=0,
    DT_NEEDED=1,
    DT_PLTRELSZ=2,
    DT_PLTGOT=3,
    DT_HASH=4,
    DT_STRTAB=5,
    DT_SYMTAB=6,
    DT_RELA=7,
    DT_RELASZ=8,
    DT_RELAENT=9,
    DT_STRSZ=10,
    DT_SYMENT=11,
    DT_INIT=12,
    DT_FINI=13,
    DT_SONAME=14,
    DT_RPATH=15,
    DT_SYMBOLIC=16,
    DT_REL=17,
    DT_RELSZ=18,
    DT_RELENT=19,
    DT_PLTREL=20,
    DT_DEBUG=21,
    DT_TEXTREL=22,
    DT_JMPREL=23,
    DT_BIND_NOW=24,
    DT_INIT_ARRAY=25,
    DT_FINI_ARRAY=26,
    DT_INIT_ARRAYSZ=27,
    DT_FINI_ARRAYSZ=28,
    DT_RUNPATH=29,
    DT_FLAGS=30,
    DT_PREINIT_ARRAY=32,
    DT_PREINIT_ARRAYSZ=33,
    DT_RELRSZ=35,
    DT_RELR=36,
    DT_RELRENT=37,
    DT_ANDROID_REL=1610612751,
    DT_ANDROID_RELSZ=1610612752,
    DT_ANDROID_RELA=1610612753,
    DT_ANDROID_RELASZ=1610612754,
    DT_ANDROID_RELR=1879040000,
    DT_ANDROID_RELRSZ=1879040001,
    DT_ANDROID_RELRENT=1879040003,
    DT_GNU_PRELINKED=1879047669,
    DT_GNU_CONFLICTSZ=1879047670,
    DT_GNU_LIBLISTSZ=1879047671,
    DT_CHECKSUM=1879047672,
    DT_PLTPADSZ=1879047673,
    DT_MOVEENT=1879047674,
    DT_MOVESZ=1879047675,
    DT_FEATURE_1=1879047676,
    DT_POSFLAG_1=1879047677,
    DT_SYMINSZ=1879047678,
    DT_SYMINENT=1879047679,
    DT_GNU_XHASH=1879047924,
    DT_GNU_HASH=1879047925,
    DT_TLSDESC_PLT=1879047926,
    DT_TLSDESC_GOT=1879047927,
    DT_GNU_CONFLICT=1879047928,
    DT_GNU_LIBLIST=1879047929,
    DT_CONFIG=1879047930,
    DT_DEPAUDIT=1879047931,
    DT_AUDIT=1879047932,
    DT_PLTPAD=1879047933,
    DT_MOVETAB=1879047934,
    DT_SYMINFO=1879047935,
    DT_VERSYM=1879048176,
    DT_RELACOUNT=1879048185,
    DT_RELCOUNT=1879048186,
    DT_FLAGS_1=1879048187,
    DT_VERDEF=1879048188,
    DT_VERDEFNUM=1879048189,
    DT_VERNEED=1879048190,
    DT_VERNEEDNUM=1879048191,
    DT_AUXILIARY=2147483645,
    DT_FILTER=2147483647
} Elf64_DynTag_AARCH64;

struct Elf64_Dyn_AARCH64 {
    enum Elf64_DynTag_AARCH64 d_tag;
    qword d_val;
};

typedef struct Elf64_Phdr Elf64_Phdr, *PElf64_Phdr;

typedef enum Elf_ProgramHeaderType_AARCH64 {
    PT_NULL=0,
    PT_LOAD=1,
    PT_DYNAMIC=2,
    PT_INTERP=3,
    PT_NOTE=4,
    PT_SHLIB=5,
    PT_PHDR=6,
    PT_TLS=7,
    PT_GNU_EH_FRAME=1685382480,
    PT_GNU_STACK=1685382481,
    PT_GNU_RELRO=1685382482,
    PT_AARCH64_ARCHEXT=1879048192
} Elf_ProgramHeaderType_AARCH64;

struct Elf64_Phdr {
    enum Elf_ProgramHeaderType_AARCH64 p_type;
    dword p_flags;
    qword p_offset;
    qword p_vaddr;
    qword p_paddr;
    qword p_filesz;
    qword p_memsz;
    qword p_align;
};

typedef struct Elf64_Shdr Elf64_Shdr, *PElf64_Shdr;

typedef enum Elf_SectionHeaderType_AARCH64 {
    SHT_NULL=0,
    SHT_PROGBITS=1,
    SHT_SYMTAB=2,
    SHT_STRTAB=3,
    SHT_RELA=4,
    SHT_HASH=5,
    SHT_DYNAMIC=6,
    SHT_NOTE=7,
    SHT_NOBITS=8,
    SHT_REL=9,
    SHT_SHLIB=10,
    SHT_DYNSYM=11,
    SHT_INIT_ARRAY=14,
    SHT_FINI_ARRAY=15,
    SHT_PREINIT_ARRAY=16,
    SHT_GROUP=17,
    SHT_SYMTAB_SHNDX=18,
    SHT_ANDROID_REL=1610612737,
    SHT_ANDROID_RELA=1610612738,
    SHT_GNU_ATTRIBUTES=1879048181,
    SHT_GNU_HASH=1879048182,
    SHT_GNU_LIBLIST=1879048183,
    SHT_CHECKSUM=1879048184,
    SHT_SUNW_move=1879048186,
    SHT_SUNW_COMDAT=1879048187,
    SHT_SUNW_syminfo=1879048188,
    SHT_GNU_verdef=1879048189,
    SHT_GNU_verneed=1879048190,
    SHT_GNU_versym=1879048191,
    SHT_AARCH64_ATTRIBUTES=1879048195
} Elf_SectionHeaderType_AARCH64;

struct Elf64_Shdr {
    dword sh_name;
    enum Elf_SectionHeaderType_AARCH64 sh_type;
    qword sh_flags;
    qword sh_addr;
    qword sh_offset;
    qword sh_size;
    dword sh_link;
    dword sh_info;
    qword sh_addralign;
    qword sh_entsize;
};

typedef struct GnuBuildId GnuBuildId, *PGnuBuildId;

struct GnuBuildId {
    dword namesz; // Length of name field
    dword descsz; // Length of description field
    dword type; // Vendor specific type
    char name[4]; // Vendor name
    byte hash[20];
};

typedef struct Elf64_Ehdr Elf64_Ehdr, *PElf64_Ehdr;

struct Elf64_Ehdr {
    byte e_ident_magic_num;
    char e_ident_magic_str[3];
    byte e_ident_class;
    byte e_ident_data;
    byte e_ident_version;
    byte e_ident_osabi;
    byte e_ident_abiversion;
    byte e_ident_pad[7];
    word e_type;
    word e_machine;
    dword e_version;
    qword e_entry;
    qword e_phoff;
    qword e_shoff;
    dword e_flags;
    word e_ehsize;
    word e_phentsize;
    word e_phnum;
    word e_shentsize;
    word e_shnum;
    word e_shstrndx;
};

typedef struct Elf64_Sym Elf64_Sym, *PElf64_Sym;

struct Elf64_Sym {
    dword st_name;
    byte st_info;
    byte st_other;
    word st_shndx;
    qword st_value;
    qword st_size;
};




void FUN_00104380(void)

{
  (*(code *)(undefined *)0x0)();
  return;
}



void systemTime(void)

{
  systemTime();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int sem_wait(sem_t *__sem)

{
  int iVar1;
  
  iVar1 = sem_wait(__sem);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int pthread_mutex_destroy(pthread_mutex_t *__mutex)

{
  int iVar1;
  
  iVar1 = pthread_mutex_destroy(__mutex);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int pthread_create(pthread_t *__newthread,pthread_attr_t *__attr,__start_routine *__start_routine,
                  void *__arg)

{
  int iVar1;
  
  iVar1 = pthread_create(__newthread,__attr,__start_routine,__arg);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int pthread_join(pthread_t __th,void **__thread_return)

{
  int iVar1;
  
  iVar1 = pthread_join(__th,__thread_return);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int open(char *__file,int __oflag,...)

{
  int iVar1;
  
  iVar1 = open(__file,__oflag);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int sem_post(sem_t *__sem)

{
  int iVar1;
  
  iVar1 = sem_post(__sem);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int pthread_mutex_trylock(pthread_mutex_t *__mutex)

{
  int iVar1;
  
  iVar1 = pthread_mutex_trylock(__mutex);
  return iVar1;
}



void __cxa_finalize(void)

{
  __cxa_finalize();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

long ftell(FILE *__stream)

{
  long lVar1;
  
  lVar1 = ftell(__stream);
  return lVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int mkdir(char *__path,__mode_t __mode)

{
  int iVar1;
  
  iVar1 = mkdir(__path,__mode);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

size_t fread(void *__ptr,size_t __size,size_t __n,FILE *__stream)

{
  size_t sVar1;
  
  sVar1 = fread(__ptr,__size,__n,__stream);
  return sVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

char * stpcpy(char *__dest,char *__src)

{
  char *pcVar1;
  
  pcVar1 = stpcpy(__dest,__src);
  return pcVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int timer_create(clockid_t __clock_id,sigevent *__evp,timer_t *__timerid)

{
  int iVar1;
  
  iVar1 = timer_create(__clock_id,__evp,__timerid);
  return iVar1;
}



void QSEECom_send_cmd(void)

{
  QSEECom_send_cmd();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int pthread_mutex_init(pthread_mutex_t *__mutex,pthread_mutexattr_t *__mutexattr)

{
  int iVar1;
  
  iVar1 = pthread_mutex_init(__mutex,__mutexattr);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int bind(int __fd,sockaddr *__addr,socklen_t __len)

{
  int iVar1;
  
  iVar1 = bind(__fd,__addr,__len);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

char * strerror(int __errnum)

{
  char *pcVar1;
  
  pcVar1 = strerror(__errnum);
  return pcVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int lstat(char *__file,stat *__buf)

{
  int iVar1;
  
  iVar1 = lstat(__file,__buf);
  return iVar1;
}



void __errno(void)

{
  __errno();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int sem_timedwait(sem_t *__sem,timespec *__abstime)

{
  int iVar1;
  
  iVar1 = sem_timedwait(__sem,__abstime);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int chdir(char *__path)

{
  int iVar1;
  
  iVar1 = chdir(__path);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

__pid_t getpid(void)

{
  __pid_t _Var1;
  
  _Var1 = getpid();
  return _Var1;
}



void QSEECom_start_app(void)

{
  QSEECom_start_app();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int access(char *__name,int __type)

{
  int iVar1;
  
  iVar1 = access(__name,__type);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int timer_delete(timer_t __timerid)

{
  int iVar1;
  
  iVar1 = timer_delete(__timerid);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

time_t time(time_t *__timer)

{
  time_t tVar1;
  
  tVar1 = time(__timer);
  return tVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int fclose(FILE *__stream)

{
  int iVar1;
  
  iVar1 = fclose(__stream);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int fflush(FILE *__stream)

{
  int iVar1;
  
  iVar1 = fflush(__stream);
  return iVar1;
}



void __stack_chk_fail(void)

{
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int pthread_attr_init(pthread_attr_t *__attr)

{
  int iVar1;
  
  iVar1 = pthread_attr_init(__attr);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int gettimeofday(timeval *__tv,__timezone_ptr_t __tz)

{
  int iVar1;
  
  iVar1 = gettimeofday(__tv,__tz);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int timer_settime(timer_t __timerid,int __flags,itimerspec *__value,itimerspec *__ovalue)

{
  int iVar1;
  
  iVar1 = timer_settime(__timerid,__flags,__value,__ovalue);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int pthread_cond_wait(pthread_cond_t *__cond,pthread_mutex_t *__mutex)

{
  int iVar1;
  
  iVar1 = pthread_cond_wait(__cond,__mutex);
  return iVar1;
}



void QSEECom_shutdown_app(void)

{
  QSEECom_shutdown_app();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int ioctl(int __fd,ulong __request,...)

{
  int iVar1;
  
  iVar1 = ioctl(__fd,__request);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

DIR * opendir(char *__name)

{
  DIR *pDVar1;
  
  pDVar1 = opendir(__name);
  return pDVar1;
}



void __android_log_print(void)

{
  __android_log_print();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int pthread_attr_destroy(pthread_attr_t *__attr)

{
  int iVar1;
  
  iVar1 = pthread_attr_destroy(__attr);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int sem_trywait(sem_t *__sem)

{
  int iVar1;
  
  iVar1 = sem_trywait(__sem);
  return iVar1;
}



void QSEECom_app_load_query(void)

{
  QSEECom_app_load_query();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int pthread_attr_setstacksize(pthread_attr_t *__attr,size_t __stacksize)

{
  int iVar1;
  
  iVar1 = pthread_attr_setstacksize(__attr,__stacksize);
  return iVar1;
}



void property_get_bool(void)

{
  property_get_bool();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int sprintf(char *__s,char *__format,...)

{
  int iVar1;
  
  iVar1 = sprintf(__s,__format);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

ssize_t recvmsg(int __fd,msghdr *__message,int __flags)

{
  ssize_t sVar1;
  
  sVar1 = recvmsg(__fd,__message,__flags);
  return sVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int sigaction(int __sig,sigaction *__act,sigaction *__oact)

{
  int iVar1;
  
  iVar1 = sigaction(__sig,__act,__oact);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int pthread_mutex_lock(pthread_mutex_t *__mutex)

{
  int iVar1;
  
  iVar1 = pthread_mutex_lock(__mutex);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void * mmap(void *__addr,size_t __len,int __prot,int __flags,int __fd,__off_t __offset)

{
  void *pvVar1;
  
  pvVar1 = mmap(__addr,__len,__prot,__flags,__fd,__offset);
  return pvVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int sem_init(sem_t *__sem,int __pshared,uint __value)

{
  int iVar1;
  
  iVar1 = sem_init(__sem,__pshared,__value);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

ssize_t sendmsg(int __fd,msghdr *__message,int __flags)

{
  ssize_t sVar1;
  
  sVar1 = sendmsg(__fd,__message,__flags);
  return sVar1;
}



void Navigation(void)

{
  Navigation();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

char * strstr(char *__haystack,char *__needle)

{
  char *pcVar1;
  
  pcVar1 = strstr(__haystack,__needle);
  return pcVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int usleep(__useconds_t __useconds)

{
  int iVar1;
  
  iVar1 = usleep(__useconds);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

dirent * readdir(DIR *__dirp)

{
  dirent *pdVar1;
  
  pdVar1 = readdir(__dirp);
  return pdVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

size_t strlen(char *__s)

{
  size_t sVar1;
  
  sVar1 = strlen(__s);
  return sVar1;
}



void QSEECom_send_modified_cmd(void)

{
  QSEECom_send_modified_cmd();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int close(int __fd)

{
  int iVar1;
  
  iVar1 = close(__fd);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int remove(char *__filename)

{
  int iVar1;
  
  iVar1 = remove(__filename);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int sem_getvalue(sem_t *__sem,int *__sval)

{
  int iVar1;
  
  iVar1 = sem_getvalue(__sem,__sval);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

tm * localtime(time_t *__timer)

{
  tm *ptVar1;
  
  ptVar1 = localtime(__timer);
  return ptVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int munmap(void *__addr,size_t __len)

{
  int iVar1;
  
  iVar1 = munmap(__addr,__len);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void * malloc(size_t __size)

{
  void *pvVar1;
  
  pvVar1 = malloc(__size);
  return pvVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void * memcpy(void *__dest,void *__src,size_t __n)

{
  void *pvVar1;
  
  pvVar1 = memcpy(__dest,__src,__n);
  return pvVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void * memset(void *__s,int __c,size_t __n)

{
  void *pvVar1;
  
  pvVar1 = memset(__s,__c,__n);
  return pvVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

FILE * fopen(char *__filename,char *__modes)

{
  FILE *pFVar1;
  
  pFVar1 = fopen(__filename,__modes);
  return pFVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int socket(int __domain,int __type,int __protocol)

{
  int iVar1;
  
  iVar1 = socket(__domain,__type,__protocol);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

size_t fwrite(void *__ptr,size_t __size,size_t __n,FILE *__s)

{
  size_t sVar1;
  
  sVar1 = fwrite(__ptr,__size,__n,__s);
  return sVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int fcntl(int __fd,int __cmd,...)

{
  int iVar1;
  
  iVar1 = fcntl(__fd,__cmd);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void free(void *__ptr)

{
  free(__ptr);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void pthread_exit(void *__retval)

{
                    // WARNING: Subroutine does not return
  pthread_exit(__retval);
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int pthread_cond_signal(pthread_cond_t *__cond)

{
  int iVar1;
  
  iVar1 = pthread_cond_signal(__cond);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int pthread_mutex_unlock(pthread_mutex_t *__mutex)

{
  int iVar1;
  
  iVar1 = pthread_mutex_unlock(__mutex);
  return iVar1;
}



void __cxa_atexit(void)

{
  __cxa_atexit();
  return;
}



void QSEECom_set_bandwidth(void)

{
  QSEECom_set_bandwidth();
  return;
}



void entry(void)

{
  __cxa_finalize(&DAT_00128000);
  return;
}



void FUN_0010484c(code *param_1)

{
  if (param_1 != (code *)0x0) {
    (*param_1)();
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void gf_handler_register(ulong param_1)

{
  int iVar1;
  uint uVar2;
  undefined8 uVar3;
  _union_1457 local_28;
  ulong local_20;
  ulong local_18;
  ulong uStack_10;
  ulong local_8;
  
  local_8 = ___stack_chk_guard;
  if (param_1 == 0) {
    __android_log_print(6,"FingerGoodix","Func to register is NULL.\n");
    uVar3 = 0xffffff7b;
  }
  else {
    local_28.sa_handler = (__sighandler_t)0x0;
    local_18 = 0;
    uStack_10 = 0;
    local_20 = param_1;
    sigaction(0x1d,(sigaction *)&stack0xffffffffffffffd8,(sigaction *)0x0);
    iVar1 = DAT_001281e0;
    uVar2 = getpid();
    fcntl(iVar1,8,(ulong)uVar2);
    iVar1 = DAT_001281e0;
    uVar2 = fcntl(DAT_001281e0,3);
    fcntl(iVar1,4,(ulong)(uVar2 | 0x2000));
    uVar3 = 0;
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar3);
}



int gf_handler_unregister(void)

{
  uint uVar1;
  int iVar2;
  
  iVar2 = DAT_001281e0;
  uVar1 = getpid();
  fcntl(iVar2,8,(ulong)uVar1);
  iVar2 = DAT_001281e0;
  uVar1 = fcntl(DAT_001281e0,3);
  iVar2 = fcntl(iVar2,4,(ulong)(uVar1 & 0xffffdfff));
  return iVar2;
}



undefined8 gf_enable_irq(void)

{
  int iVar1;
  undefined8 uVar2;
  
  __android_log_print(3,"FingerGoodix","gf_enable_irq");
  if (DAT_001281e0 == 0) {
    __android_log_print(6,"FingerGoodix","g_device_handle is NULL to do IOCTL Ops.\n");
    uVar2 = 0xffffff7f;
  }
  else {
    iVar1 = ioctl(DAT_001281e0,0x4701);
    if (iVar1 < 0) {
      __android_log_print(6,"FingerGoodix","Failed to do GF_IOC_ENABLE_IRQ.\n");
      uVar2 = 0xffffffff;
    }
    else {
      uVar2 = 0;
      gIRQFlag = 1;
    }
  }
  return uVar2;
}



undefined8 gf_disable_irq(void)

{
  int iVar1;
  undefined8 uVar2;
  
  __android_log_print(3,"FingerGoodix","gf_disable_irq");
  if (DAT_001281e0 == 0) {
    __android_log_print(6,"FingerGoodix","g_device_handle is NULL to do IOCTL Ops.\n");
    uVar2 = 0xffffff7f;
  }
  else {
    iVar1 = ioctl(DAT_001281e0,0x4700);
    if (iVar1 < 0) {
      __android_log_print(6,"FingerGoodix","Failed to do GF_IOC_DISABLE_IRQ.\n");
      uVar2 = 0xffffffff;
    }
    else {
      uVar2 = 0;
      gIRQFlag = 0;
    }
  }
  return uVar2;
}



undefined8 gf_hw_reset(void)

{
  int iVar1;
  undefined8 uVar2;
  
  if (DAT_001281e0 == 0) {
    __android_log_print(6,"FingerGoodix","g_device_handle is NULL to do IOCTL Ops.\n");
    uVar2 = 0xffffff7f;
  }
  else {
    iVar1 = ioctl(DAT_001281e0,0x4703);
    uVar2 = 0;
    if (iVar1 < 0) {
      __android_log_print(6,"FingerGoodix","Failed to do GF_IOC_RESET.\n");
      uVar2 = 0xffffffff;
    }
  }
  return uVar2;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00104b38(void)

{
  int iVar1;
  char cVar2;
  undefined4 uVar3;
  int iVar4;
  char local_9;
  long local_8;
  
  cVar2 = '\0';
  local_8 = ___stack_chk_guard;
  local_9 = '\0';
  iVar4 = 1;
  while( true ) {
    iVar1 = gf_hw_reset();
    if (iVar1 != 0) {
      uVar3 = 0xffffffff;
      __android_log_print(6,"FingerGoodix","Failed to reset sensor.\n");
      gf_enable_irq();
      goto LAB_00104bc8;
    }
    fnCa_FWUpdatePre(&local_9);
    if (local_9 != '\0') break;
    cVar2 = cVar2 + '\x01';
    __android_log_print(3,"FingerGoodix","Try to hold CPU. retry = %d\n",iVar4);
    iVar4 = iVar4 + 1;
    if (cVar2 == '\x05') {
      uVar3 = 0xffffffff;
      __android_log_print(3,"FingerGoodix","Failed to hold CPU in 5 times.\n");
LAB_00104bc8:
      if (local_8 == ___stack_chk_guard) {
        return;
      }
                    // WARNING: Subroutine does not return
      __stack_chk_fail(uVar3);
    }
  }
  __android_log_print(3,"FingerGoodix","Success to hold CPU. retry = %d\n",cVar2);
  fnCa_FWUpdate(&local_9);
  gf_hw_reset();
  fnCa_DownloadCFG(&local_9);
  uVar3 = 0;
  goto LAB_00104bc8;
}



undefined8 gf_cool_boot(void)

{
  int iVar1;
  undefined8 uVar2;
  
  if (DAT_001281e0 == 0) {
    __android_log_print(6,"FingerGoodix","g_device_handle is NULL to do IOCTL Ops.\n");
    uVar2 = 0xffffff7f;
  }
  else {
    iVar1 = ioctl(DAT_001281e0,0x4704);
    uVar2 = 0;
    if (iVar1 < 0) {
      __android_log_print(6,"FingerGoodix","Failed to do GF_IOC_COOL_BOOT.\n");
      uVar2 = 0xffffffff;
    }
  }
  return uVar2;
}



undefined8 gf_set_speed(uint param_1)

{
  int iVar1;
  undefined8 uVar2;
  uint local_4;
  
  local_4 = param_1;
  if (DAT_001281e0 == 0) {
    __android_log_print(6,"FingerGoodix","g_device_handle is NULL to do IOCTL Ops.\n");
    uVar2 = 0xffffff7f;
  }
  else if (param_1 < 0xb71b01) {
    if (param_1 == DAT_001281e4) {
      __android_log_print(3,"FingerGoodix","Already in speed. [%d]\n");
      return 0;
    }
    DAT_001281e4 = param_1;
    iVar1 = ioctl(DAT_001281e0,0x40044702,&local_4);
    uVar2 = 0;
    if (iVar1 < 0) {
      __android_log_print(6,"FingerGoodix","Failed to do GF_IOC_SETSPEED. speed = %d\n",local_4);
      uVar2 = 0xffffffff;
    }
  }
  else {
    __android_log_print(6,"FingerGoodix","Wrong speed[%d]. The max speed GF supported is %d\n",
                        param_1,12000000);
    uVar2 = 0xffffffff;
  }
  return uVar2;
}



int gf_ready_spiclk(void)

{
  int iVar1;
  
  __android_log_print(3,"FingerGoodix","gf_ready_spiclk. g_spi_clk = %d\n",DAT_001281e8);
  iVar1 = DAT_001281e8;
  if (DAT_001281e8 == 0) {
    DAT_001281e8 = 1;
    if (DAT_001281e0 == 0) {
      __android_log_print(6,"FingerGoodix","g_device_handle is NULL to do IOCTL Ops.\n");
      iVar1 = -0x81;
    }
    else {
      iVar1 = ioctl(DAT_001281e0,0x4706);
      if (iVar1 < 0) {
        __android_log_print(6,"FingerGoodix","Failed to do GF_IOC_CLK_READY.\n");
        iVar1 = -1;
      }
      else {
        iVar1 = 0;
      }
    }
  }
  return iVar1;
}



int gf_unready_spiclk(void)

{
  int iVar1;
  
  __android_log_print(3,"FingerGoodix","gf_unready_spiclk. g_spi_clk = %d\n",DAT_001281e8);
  iVar1 = DAT_001281e8;
  if (DAT_001281e8 != 0) {
    DAT_001281e8 = 0;
    if (DAT_001281e0 == 0) {
      __android_log_print(6,"FingerGoodix","g_device_handle is NULL to do IOCTL Ops.\n");
      iVar1 = -0x81;
    }
    else {
      iVar1 = ioctl(DAT_001281e0,0x4707);
      if (iVar1 < 0) {
        __android_log_print(6,"FingerGoodix","Failed to do GF_IOC_CLK_UNREADY.\n");
        iVar1 = -1;
      }
      else {
        iVar1 = 0;
      }
    }
  }
  return iVar1;
}



undefined8 gf_power_on(void)

{
  int iVar1;
  undefined8 uVar2;
  
  __android_log_print(3,"FingerGoodix","gf_power_on");
  if (DAT_001281e0 == 0) {
    __android_log_print(6,"FingerGoodix","g_device_handle is NULL to do IOCTL Ops.\n");
    uVar2 = 0xffffff7f;
  }
  else {
    iVar1 = ioctl(DAT_001281e0,0x4709);
    uVar2 = 0;
    if (iVar1 < 0) {
      __android_log_print(6,"FingerGoodix","Failed to do GF_IOC_POWER_ON.\n");
      uVar2 = 0xffffffff;
    }
  }
  return uVar2;
}



undefined8 gf_power_off(void)

{
  int iVar1;
  undefined8 uVar2;
  
  __android_log_print(3,"FingerGoodix","gf_power_off");
  if (DAT_001281e0 == 0) {
    __android_log_print(6,"FingerGoodix","g_device_handle is NULL to do IOCTL Ops.\n");
    uVar2 = 0xffffff7f;
  }
  else {
    iVar1 = ioctl(DAT_001281e0,0x470a);
    uVar2 = 0;
    if (iVar1 < 0) {
      __android_log_print(6,"FingerGoodix","Failed to do GF_IOC_POWER_OFF.\n");
      uVar2 = 0xffffffff;
    }
  }
  return uVar2;
}



undefined8 gf_read_pm_fb(undefined8 param_1)

{
  int iVar1;
  undefined8 uVar2;
  
  if (DAT_001281e0 == 0) {
    __android_log_print(6,"FingerGoodix","g_device_handle is NULL to do IOCTL Ops.\n");
    uVar2 = 0xffffff7f;
  }
  else {
    iVar1 = ioctl(DAT_001281e0,0x4708,param_1);
    uVar2 = 0;
    if (iVar1 < 0) {
      __android_log_print(6,"FingerGoodix","Failed to get pm_fb \n");
      uVar2 = 0xffffffff;
    }
  }
  return uVar2;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void gf_send_key(undefined4 param_1,undefined4 param_2)

{
  int iVar1;
  undefined8 uVar2;
  undefined8 local_10;
  long local_8;
  
  local_10 = 0;
  local_8 = ___stack_chk_guard;
  if (DAT_001281e0 == 0) {
    __android_log_print(6,"FingerGoodix","g_device_handle is NULL to do IOCTL Ops.\n");
    uVar2 = 0xffffff7f;
  }
  else {
    local_10 = CONCAT44(param_2,param_1);
    iVar1 = ioctl(DAT_001281e0,0x40084705,&local_10);
    uVar2 = 0;
    if (iVar1 < 0) {
      __android_log_print(6,"FingerGoodix","Failed to send key[%d], value:%d\n",param_1,param_2);
      uVar2 = 0xffffffff;
    }
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar2);
}



undefined4 gf_fw_update(void)

{
  int iVar1;
  undefined4 uVar2;
  
  iVar1 = gf_disable_irq();
  if (iVar1 == 0) {
    uVar2 = FUN_00104b38();
    gf_enable_irq();
  }
  else {
    __android_log_print(6,"FingerGoodix","Failed to disable_irq.\n");
    uVar2 = 0xffffff7f;
  }
  return uVar2;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void gf_esd_check(void)

{
  int iVar1;
  undefined4 uVar2;
  char local_9;
  long local_8;
  
  uVar2 = 0;
  local_9 = -1;
  local_8 = ___stack_chk_guard;
  fnCa_ESDCheck(&local_9);
  if (local_9 == '\0') {
    __android_log_print(3,"FingerGoodix","ESD Check Failed.\n");
    iVar1 = gf_disable_irq();
    if (iVar1 == 0) {
      gf_set_speed(1000000);
      __android_log_print(3,"FingerGoodix","Do reset.\n");
      iVar1 = gf_hw_reset();
      if (iVar1 == 0) {
        fnCa_ESDCheck(&local_9);
        if (local_9 == '\0') {
          __android_log_print(3,"FingerGoodix","Sensor can\'t recover from abnormal by HW reset\n");
          iVar1 = gf_cool_boot();
          if (iVar1 == 0) {
            fnCa_ESDCheck(&local_9);
            uVar2 = 0;
            if (local_9 == '\0') {
              __android_log_print(3,"FingerGoodix","Do update.\n");
              FUN_00104b38();
              gf_enable_irq();
            }
            else {
              __android_log_print(3,"FingerGoodix","ESD Check passed after Re-Power.");
              gf_enable_irq();
            }
          }
          else {
            uVar2 = 0xffffffff;
            __android_log_print(3,"FingerGoodix","Failed to repower sensor.\n");
            gf_enable_irq();
          }
        }
        else {
          __android_log_print(3,"FingerGoodix","ESD Check passed after HW reset.");
          gf_enable_irq();
          uVar2 = 0;
        }
      }
      else {
        uVar2 = 0xffffffff;
        __android_log_print(6,"FingerGoodix","Failed to reset sensor.\n");
        gf_enable_irq();
      }
    }
    else {
      uVar2 = 0xffffffff;
      __android_log_print(6,"FingerGoodix","Failed to disable_irq.\n");
    }
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar2);
}



int gf_delete_esd_timer(void)

{
  int iVar1;
  
  __android_log_print(3,"FingerGoodix","delete timer \n");
  pthread_mutex_lock((pthread_mutex_t *)&DAT_001281f0);
  if ((timerid != (timer_t)0x0) && (iVar1 = timer_delete(timerid), iVar1 == 0)) {
    __android_log_print(3,"FingerGoodix","delete timer success\n");
    timerid = (timer_t)0x0;
    iVar1 = pthread_mutex_unlock((pthread_mutex_t *)&DAT_001281f0);
    return iVar1;
  }
  timerid = (timer_t)0x0;
  iVar1 = pthread_mutex_unlock((pthread_mutex_t *)&DAT_001281f0);
  return iVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void gf_create_esd_timer(void)

{
  int iVar1;
  undefined4 uVar2;
  undefined local_48 [64];
  long local_8;
  
  local_48._0_8_ = (void *)0x0;
  local_48._8_4_ = 0;
  local_48._12_4_ = 0;
  local_48._16_8_ = (_func_5017 *)0x0;
  local_48._24_8_ = (void *)0x0;
  local_48._32_8_ = 0;
  local_48._40_8_ = 0;
  local_8 = ___stack_chk_guard;
  local_48._48_8_ = 0;
  local_48._56_8_ = 0;
  if (timerid == 0) {
    local_48._0_8_ = (sigval_t)0xff;
    local_48._8_4_ = 0;
    local_48._12_4_ = 2;
    local_48._16_8_ = loop_thread;
    iVar1 = timer_create(0,(sigevent *)local_48,(timer_t *)&timerid);
    if (iVar1 == -1) {
      __android_log_print(6,"FingerGoodix","fail to timer_create");
      uVar2 = 0xffffffff;
    }
    else {
      uVar2 = 0;
    }
  }
  else {
    uVar2 = 0xffffffff;
    __android_log_print(3,"FingerGoodix","timer has been create \n");
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar2);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void gf_active_esd_timer(void)

{
  int iVar1;
  itimerspec local_28;
  long local_8;
  
  local_28.it_interval.tv_sec = 2;
  local_28.it_interval.tv_nsec = 0;
  local_8 = ___stack_chk_guard;
  local_28.it_value.tv_sec = 2;
  local_28.it_value.tv_nsec = 0;
  iVar1 = timer_settime(timerid,0,&local_28,(itimerspec *)0x0);
  if (iVar1 == -1) {
    __android_log_print(6,"FingerGoodix","fail to timer_settime");
    timer_delete(timerid);
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void gf_init_esd_timer(void)

{
  int iVar1;
  itimerspec local_68;
  undefined local_48 [64];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","init and start timer \n");
  local_68.it_interval.tv_sec = 2;
  local_68.it_interval.tv_nsec = 0;
  local_68.it_value.tv_sec = 2;
  local_68.it_value.tv_nsec = 0;
  local_48._0_8_ = (void *)0x0;
  local_48._8_4_ = 0;
  local_48._12_4_ = 0;
  local_48._16_8_ = (_func_5017 *)0x0;
  local_48._24_8_ = (void *)0x0;
  local_48._32_8_ = 0;
  local_48._40_8_ = 0;
  local_48._48_8_ = 0;
  local_48._56_8_ = 0;
  pthread_mutex_lock((pthread_mutex_t *)&DAT_001281f0);
  if (timerid == (timer_t)0x0) {
    local_48._12_4_ = 2;
    local_48._0_4_ = 0xff;
    local_48._16_8_ = loop_thread;
    iVar1 = timer_create(0,(sigevent *)local_48,&timerid);
    if (iVar1 == -1) {
      __android_log_print(6,"FingerGoodix","fail to timer_create");
    }
    else {
      iVar1 = timer_settime(timerid,0,&local_68,(itimerspec *)0x0);
      if (iVar1 == -1) {
        __android_log_print(6,"FingerGoodix","fail to timer_settime");
        timer_delete(timerid);
      }
      else {
        pthread_mutex_unlock((pthread_mutex_t *)&DAT_001281f0);
        __android_log_print(3,"FingerGoodix","init and start timer success \n");
      }
    }
  }
  else {
    __android_log_print(3,"FingerGoodix","timer has been create \n");
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



int gf_esd_mutex_lock(void)

{
  int iVar1;
  
  iVar1 = pthread_mutex_lock((pthread_mutex_t *)&DAT_00128218);
  return iVar1;
}



int gf_esd_mutex_unlock(void)

{
  int iVar1;
  
  iVar1 = pthread_mutex_unlock((pthread_mutex_t *)&DAT_00128218);
  return iVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void loop_thread(void)

{
  int iVar1;
  uint uVar2;
  ulong uVar3;
  uint uVar4;
  char local_9;
  long local_8;
  
  local_9 = '\0';
  local_8 = ___stack_chk_guard;
  mutex_get_lock();
  iVar1 = pthread_mutex_trylock((pthread_mutex_t *)&DAT_00128218);
  if (iVar1 == 0) {
    if ((DAT_001281e4 == 4800000) && (1 < g_mode - 2U)) {
      uVar4 = 1;
      do {
        fnCa_FWIsUpdate(&local_9);
        if (local_9 == '\0') {
          gf_esd_check();
          gf_esd_mutex_unlock();
          goto LAB_001057a0;
        }
        if ((uVar4 & 0xff) == 3) {
          DAT_00128240 = DAT_00128240 + 1;
          __android_log_print(3,"FingerGoodix","Do update. esd check failed count %d \n");
          gf_fw_update();
          uVar3 = gf_esd_check();
        }
        else {
          __android_log_print(3,"FingerGoodix","%s %d count %d \n","loop_thread",0x1d1,uVar4);
          uVar2 = usleep(100000);
          uVar3 = (ulong)uVar2;
        }
        uVar4 = uVar4 + 1;
      } while (uVar4 != 4);
      gf_esd_mutex_unlock(uVar3);
    }
    else {
      __android_log_print(3,"FingerGoodix","ESD doesn\'t do in HIGH speed or in FF.\n");
      gf_esd_mutex_unlock();
    }
  }
LAB_001057a0:
  mutex_get_unlock();
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



undefined8 gf_enable_gpio(void)

{
  int iVar1;
  undefined8 uVar2;
  
  __android_log_print(3,"FingerGoodix","gf_enable_gpio");
  if (DAT_001281e0 < 0) {
    __android_log_print(6,"FingerGoodix","g_device_handle is NULL to do IOCTL Ops.\n");
    uVar2 = 0xffffff7f;
  }
  else {
    iVar1 = ioctl(DAT_001281e0,0x470b);
    uVar2 = 0;
    if (iVar1 < 0) {
      __android_log_print(6,"FingerGoodix","Failed to do GF_IOC_ENABLE_GPIO.\n");
      uVar2 = 0xffffffff;
    }
  }
  return uVar2;
}



undefined8 gf_open(void)

{
  int iVar1;
  undefined8 uVar2;
  
  __android_log_print(6,"FingerGoodix","start open %s.\n","/dev/goodix_fp");
  if (DAT_001281e0 == 0) {
    DAT_001281e0 = open("/dev/goodix_fp",2);
    if (DAT_001281e0 < 0) {
      __android_log_print(6,"FingerGoodix","open %s failed.\n","/dev/goodix_fp");
      uVar2 = 0xffffff7f;
    }
    else {
      iVar1 = gf_enable_gpio();
      if (iVar1 < 0) {
        __android_log_print(6,"FingerGoodix","Failed to do GF_IOC_ENABLE_GPIO.\n");
        uVar2 = 0xffffff7f;
      }
      else {
        __android_log_print(3,"FingerGoodix","Open device[%s] success. Handle = %d\n",
                            "/dev/goodix_fp",DAT_001281e0);
        uVar2 = 0;
      }
    }
  }
  else {
    __android_log_print(6,"FingerGoodix","Device has been opened. handle = %d\n");
    uVar2 = 0xffffff70;
  }
  return uVar2;
}



undefined8 gf_release_gpio(void)

{
  int iVar1;
  undefined8 uVar2;
  
  __android_log_print(3,"FingerGoodix","%s,gf_release_gpio","gf_release_gpio");
  if (DAT_001281e0 < 0) {
    __android_log_print(6,"FingerGoodix","g_device_handle is NULL to do IOCTL Ops.\n");
    uVar2 = 0xffffff7f;
  }
  else {
    __android_log_print(3,"FingerGoodix","%s,gf_release_gpio by ioctl","gf_release_gpio");
    iVar1 = ioctl(DAT_001281e0,0x470c);
    uVar2 = 0;
    if (iVar1 < 0) {
      __android_log_print(6,"FingerGoodix","Failed to do GF_IOC_RELEASE_GPIO.\n");
      uVar2 = 0xffffffff;
    }
  }
  return uVar2;
}



void gf_close(void)

{
  int iVar1;
  
  if (DAT_001281e0 == 0) {
    __android_log_print(3,"FingerGoodix","No device to be closed.\n");
    return;
  }
  __android_log_print(3,"FingerGoodix","Close device. Handle = %d\n");
  gf_release_gpio();
  __android_log_print(3,"FingerGoodix","%s,Close device,gf_release_gpio","gf_close");
  iVar1 = close(DAT_001281e0);
  __android_log_print(3,"FingerGoodix","Close device. Handle = %d\n, ret = %d",DAT_001281e0,iVar1);
  DAT_001281e0 = 0;
  return;
}



void FUN_00105b80(undefined4 param_1)

{
  switch(param_1) {
  case 1:
    __android_log_print(3,"FingerGoodix","NAV:KEY_LEFT\n",param_1);
    gf_send_key(0x69,1);
    gf_send_key(0x69,0);
    return;
  case 2:
    __android_log_print(3,"FingerGoodix","NAV:KEY_RIGHT",param_1);
    gf_send_key(0x6a,1);
    gf_send_key(0x6a,0);
    return;
  case 3:
    __android_log_print(3,"FingerGoodix","NAV:KEY_UP\n",param_1);
    gf_send_key(0x67,1);
    gf_send_key(0x67,0);
    return;
  case 4:
    __android_log_print(3,"FingerGoodix","NAV:KEY_DOWN\n",param_1);
    gf_send_key(0x6c,1);
    gf_send_key(0x6c,0);
    return;
  case 5:
    __android_log_print(3,"FingerGoodix","NAV:KEY_CLICK\n",param_1);
    gf_send_key(0xbd,1);
    gf_send_key(0xbd,0);
    return;
  case 6:
    __android_log_print(3,"FingerGoodix","NAV:KEY_LIGHT\n",param_1);
    return;
  default:
    __android_log_print(3,"FingerGoodix","NAV: nav:%d\n",param_1);
    return;
  case 8:
    __android_log_print(3,"FingerGoodix","NAV:Complete.\n",param_1);
    return;
  case 9:
    __android_log_print(3,"FingerGoodix","NAV:NAV_DOUBLE\n",param_1);
    gf_send_key(0xbe,1);
    gf_send_key(0xbe,0);
    return;
  case 10:
    __android_log_print(3,"FingerGoodix","NAV:NAV_LONG\n",param_1);
    gf_send_key(0xbf,1);
    gf_send_key(0xbf,0);
    return;
  }
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void NavThread(void)

{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  undefined2 local_e;
  int local_c;
  undefined8 local_8;
  
  local_c = 0;
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","NavThread Enter:\n");
  if (DAT_00128250 == 0) {
    do {
      pthread_mutex_lock((pthread_mutex_t *)&DAT_00128258);
      while ((DAT_001282b4 != 2 || (DAT_00128250 != 0))) {
        pthread_cond_wait((pthread_cond_t *)&DAT_00128280,(pthread_mutex_t *)&DAT_00128258);
      }
      local_c = 0;
      pthread_mutex_lock((pthread_mutex_t *)&DAT_001282dc);
      iVar3 = DAT_001282c8;
      pthread_mutex_unlock((pthread_mutex_t *)&DAT_001282dc);
      if (iVar3 < 0) goto LAB_00105ee4;
      while (iVar3 != 0) {
        while( true ) {
          Navigation(DAT_001282d0 + (DAT_001282c4 << 0xb),&local_c,DAT_001282b8,0x10,0x40,0xc,0x14,4
                     ,0);
          pthread_mutex_lock((pthread_mutex_t *)&DAT_001282dc);
          if (DAT_001282c8 < 1) {
            __android_log_print(3,"FingerGoodix","No Frame in Buf.\n");
            pthread_mutex_unlock((pthread_mutex_t *)&DAT_001282dc);
          }
          else {
            DAT_001282c8 = DAT_001282c8 + -1;
            DAT_001282c4 = (DAT_001282c4 + 0x21) % 0x20;
            pthread_mutex_unlock((pthread_mutex_t *)&DAT_001282dc);
          }
          if (local_c != 0) {
            DAT_001282b4 = 3;
            FUN_00105b80();
            iVar2 = local_c;
            pthread_mutex_lock((pthread_mutex_t *)&DAT_001282dc);
            uVar1 = DAT_001282d8;
            pthread_mutex_unlock((pthread_mutex_t *)&DAT_001282dc);
            __android_log_print(3,"FingerGoodix","Algorithm:Result:%d, iFrameNum:%d, Flag:%d\n",
                                iVar2,iVar3,uVar1);
            fnCa_GetStatus(&local_e);
            fnCa_CleanStatus(local_e);
            fnCa_Cfg_FdtDown_Up(0);
            goto LAB_00105f04;
          }
          if (iVar3 < 1) goto LAB_00105f04;
          pthread_mutex_lock((pthread_mutex_t *)&DAT_001282dc);
          iVar3 = DAT_001282c8;
          pthread_mutex_unlock((pthread_mutex_t *)&DAT_001282dc);
          if (-1 < iVar3) break;
LAB_00105ee4:
          __android_log_print(3,"FingerGoodix","Fatal Error. iFrameNumCur:%d\n",iVar3);
        }
      }
      usleep(2000);
LAB_00105f04:
      pthread_mutex_unlock((pthread_mutex_t *)&DAT_00128258);
    } while (DAT_00128250 == 0);
  }
                    // WARNING: Subroutine does not return
  pthread_exit((void *)0x0);
}



void gx_setNav_state(void)

{
  DAT_001282b4 = 0;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void GF_Navigation(int param_1,ushort param_2)

{
  char *pcVar1;
  ushort local_a;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","Signal in NAV\n");
  __android_log_print(3,"FingerGoodix","NAV:g_state = %d, status = 0x%x, gNav.eState:%d \n",param_1,
                      param_2,DAT_001282b4);
  if (param_1 == 1) {
    if (DAT_001282b4 == 0) {
      LongPressFlag = 0;
      DoubleClickTimeOutFlag = 0;
      gf_delete_timer(&gx_doubleclicktimerid);
      gf_doubleclick_init_timer(&gx_doubleclicktimerid,400000000,gx_double_click);
      gf_delete_timer(&gx_longpresstimerid);
      gf_longpress_init_timer(&gx_longpresstimerid,1,gx_long_press);
    }
    switch(DAT_001282b4) {
    case 0:
      goto LAB_001062c8;
    case 1:
    case 2:
      __android_log_print(3,"FingerGoodix",
                          "##################### %s, g_state=%d ,LongPressFlag = %d \n",
                          "NAV_DoNavInTA",1,LongPressFlag);
      break;
    case 3:
      fnCa_CleanStatus(param_2);
      local_a = param_2;
      __android_log_print(3,"FingerGoodix","%s Enter.\n","NAV_End");
      __android_log_print(3,"FingerGoodix","UnTouch.\n");
      DAT_001282b4 = 0;
      fnCa_GetStatus(&local_a);
      fnCa_CleanStatus(local_a);
      fnCa_Cfg_FdtDown_Up(0);
      goto LAB_00106070;
    default:
      goto switchD_001061e4_caseD_4;
    }
LAB_00106590:
    fnCa_Nav(&navResult);
    __android_log_print(3,"FingerGoodix","##############1111111 !! \n");
    __android_log_print(3,"FingerGoodix","############ navResult %d \n",navResult);
    __android_log_print(3,"FingerGoodix","##############3333333 !! \n");
    DAT_001282b4 = 2;
    fnCa_Cfg_FdtDown_Up(0);
    gf_enable_irq();
  }
  else {
    if (param_1 != 3) {
      switch(DAT_001282b4) {
      case 0:
        goto LAB_001062c8;
      case 1:
      case 2:
        __android_log_print(3,"FingerGoodix",
                            "##################### %s, g_state=%d ,LongPressFlag = %d \n",
                            "NAV_DoNavInTA",param_1,LongPressFlag);
        break;
      case 3:
        goto switchD_00106140_caseD_3;
      default:
        goto switchD_001061e4_caseD_4;
      }
LAB_00106330:
      __android_log_print(3,"FingerGoodix","@@@@@gNav.eState = NAV_STATE_IDLE \n");
      DAT_001282b4 = 0;
      gf_enable_irq();
      goto LAB_00106070;
    }
    if (DoubleClickCount == 2) {
      __android_log_print(3,"FingerGoodix",
                          "@@@&&&@@@*****DoubleClickCount == 2, delete gx_doubleclicktimerid \n");
      gf_delete_timer(&gx_doubleclicktimerid);
      DoubleClickTimeOutFlag = 1;
    }
    gf_delete_timer(&gx_longpresstimerid);
    switch(DAT_001282b4) {
    case 0:
LAB_001062c8:
      fnCa_CleanStatus(param_2);
      gf_disable_irq();
      if ((param_2 >> 1 & 1) == 0) {
        __android_log_print(3,"FingerGoodix","Should not come here. status:0x%x, state:%d\n",param_2
                            ,DAT_001282b4);
      }
      else {
        __android_log_print(3,"FingerGoodix","Touch\n");
        DAT_001282b4 = 2;
        fnCa_SetMode(0x13);
      }
      __android_log_print(3,"FingerGoodix",
                          "##################### %s, g_state=%d ,LongPressFlag = %d \n",
                          "NAV_DoNavInTA",param_1,LongPressFlag);
      if (param_1 == 1) goto LAB_00106590;
      if (param_1 != 3) goto LAB_00106330;
      break;
    case 1:
    case 2:
      __android_log_print(3,"FingerGoodix",
                          "##################### %s, g_state=%d ,LongPressFlag = %d \n",
                          "NAV_DoNavInTA",3,LongPressFlag);
      break;
    case 3:
switchD_00106140_caseD_3:
      fnCa_CleanStatus(param_2);
      local_a = param_2;
      __android_log_print(3,"FingerGoodix","%s Enter.\n","NAV_End");
      if (param_1 == 3) {
        __android_log_print(3,"FingerGoodix","UnTouch.\n");
        DAT_001282b4 = 0;
        fnCa_GetStatus(&local_a);
        fnCa_CleanStatus(local_a);
        fnCa_Cfg_FdtDown_Up(1);
      }
      else {
        DAT_001282b4 = 0;
        __android_log_print(3,"FingerGoodix","Should not come here. status:0x%x, state:%d\n",local_a
                            ,0);
      }
      goto LAB_00106070;
    default:
switchD_001061e4_caseD_4:
      __android_log_print(3,"FingerGoodix","unexpect state. status:0x%x, state:%d\n",param_2);
      goto LAB_00106070;
    }
    __android_log_print(3,"FingerGoodix","############ navResult %d ,DoubleClickTimeOutFlag %d \n",
                        navResult,DoubleClickTimeOutFlag);
    if (navResult < 7) {
      if (navResult == 5) {
        __android_log_print(3,"FingerGoodix","@@@@@########@@@@ NAV_CLICK == navResult \n");
        DoubleClickCount = DoubleClickCount + 1;
        DoubleClickFlag = 1;
      }
      else {
        __android_log_print(3,"FingerGoodix",&DAT_001106e0);
        FUN_00105b80(navResult);
        DoubleClickCount = 0;
        DoubleClickFlag = 0;
        gf_delete_timer(&gx_doubleclicktimerid);
        gf_delete_timer(&gx_longpresstimerid);
      }
      DAT_001282b4 = 0;
      __android_log_print(3,"FingerGoodix","############################## \n");
      fnCa_Cfg_FdtDown_Up(1);
      gf_enable_irq();
    }
    else {
      __android_log_print(3,"FingerGoodix","############################## \n");
      gf_hw_reset();
      fnCa_Cfg_FdtDown_Up(0);
      navResult = 0;
      DAT_001282b4 = 3;
      gf_enable_irq();
    }
    gf_enable_irq();
  }
LAB_00106070:
  __android_log_print(3,"FingerGoodix",
                      "::::::::DoubleClickTimeOutFlag = %d,  DoubleClickFlag=%d, DoubleClickCount=%d ,LongPressFlag = %d\n"
                      ,DoubleClickTimeOutFlag,DoubleClickFlag,DoubleClickCount,LongPressFlag);
  if ((DoubleClickTimeOutFlag == 1) && (DoubleClickFlag == 1)) {
    if (DoubleClickCount == 2) {
      pcVar1 = "###### double click !! \n";
      navResult = 9;
    }
    else {
      pcVar1 = "###### click !! \n";
      navResult = 5;
    }
    __android_log_print(3,"FingerGoodix",pcVar1);
    FUN_00105b80(navResult);
    DoubleClickTimeOutFlag = 0;
    DoubleClickCount = 0;
    DoubleClickFlag = 0;
    DAT_001282b4 = 0;
  }
  if (LongPressFlag == 1) {
    navResult = 10;
    __android_log_print(3,"FingerGoodix","###### long press !! \n");
    FUN_00105b80(navResult);
    LongPressFlag = 0;
    DoubleClickCount = 0;
    DoubleClickFlag = 0;
    DAT_001282b4 = 3;
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



void gx_double_click(void)

{
  gf_delete_timer(&gx_doubleclicktimerid);
  __android_log_print(3,"FingerGoodix","@@@@@@@gx_doubleclicktimerid timeout ~!!! \n");
  DoubleClickTimeOutFlag = 1;
  GF_Navigation(0,0);
  return;
}



void gx_long_press(void)

{
  gf_delete_timer(&gx_longpresstimerid);
  __android_log_print(3,"FingerGoodix","@@@@@@@gx_longpresstimerid timeout ~!!! \n");
  LongPressFlag = 1;
  GF_Navigation(0,0);
  return;
}



void GX_NavUpdateBase(void)

{
  fnCa_NavGetBase(DAT_001282b8,0x800);
  return;
}



undefined8 GF_NavOpen(void)

{
  int iVar1;
  
  DAT_001282b8 = malloc(0x800);
  if (DAT_001282b8 != (void *)0x0) {
    DAT_001282b0 = 0;
    DAT_001282b4 = 0;
    DAT_001282c0 = 0;
    DAT_001282c4 = 0;
    DAT_001282c8 = 0;
    pthread_mutex_init((pthread_mutex_t *)&DAT_001282dc,(pthread_mutexattr_t *)0x0);
    DAT_001282d0 = malloc(0x10000);
    if (DAT_001282d0 != (void *)0x0) {
      iVar1 = pthread_attr_init((pthread_attr_t *)&DAT_00128310);
      if (iVar1 != 0) {
        __android_log_print(3,"FingerGoodix","Failed in pthread_attr_init. ret = %d\n",iVar1);
        return 0;
      }
      iVar1 = pthread_attr_setstacksize((pthread_attr_t *)&DAT_00128310,0x40000);
      if (iVar1 == 0) {
        iVar1 = pthread_create(&DAT_00128308,(pthread_attr_t *)&DAT_00128310,NavThread,(void *)0x0);
        if (iVar1 == 0) {
          return 0;
        }
        __android_log_print(3,"FingerGoodix","Failed in pthread_create. ret = %d\n",iVar1);
        return 0;
      }
      __android_log_print(3,"FingerGoodix","Failed in pthread_attr_setstacksize. ret = %d\n",iVar1);
      return 0;
    }
  }
  __android_log_print(3,"FingerGoodix","Failed to alloc memory for base.\n");
  return 0xffffffff;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void GF_NavClose(void)

{
  int iVar1;
  void *pvStack_10;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  if (DAT_00128308 == 0) {
    __android_log_print(3,"FingerGoodix","NavThread doesn\'t run.\n");
  }
  else {
    pthread_mutex_lock((pthread_mutex_t *)&DAT_00128258);
    DAT_00128250 = 1;
    pthread_cond_signal((pthread_cond_t *)&DAT_00128280);
    pthread_mutex_unlock((pthread_mutex_t *)&DAT_00128258);
    iVar1 = pthread_attr_destroy((pthread_attr_t *)&DAT_00128310);
    if (iVar1 == 0) {
      iVar1 = pthread_join(DAT_00128308,&pvStack_10);
    }
    else {
      __android_log_print(3,"FingerGoodix","Failed in pthread_attr_destory. ret = %d\n",iVar1);
      iVar1 = pthread_join(DAT_00128308,&pvStack_10);
    }
    if (iVar1 == 0) {
      __android_log_print(3,"FingerGoodix","NavThread exit code :\n");
    }
    else {
      __android_log_print(3,"FingerGoodix","Failed in  pthread_join.\n");
    }
  }
  pthread_mutex_destroy((pthread_mutex_t *)&DAT_001282dc);
  if (DAT_001282b8 != (void *)0x0) {
    free(DAT_001282b8);
  }
  if (DAT_001282d0 != (void *)0x0) {
    free(DAT_001282d0);
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



void set_fp_enabled(undefined4 param_1)

{
  DAT_0012800c = param_1;
  return;
}



int mutex_get_lock(void)

{
  int iVar1;
  
  iVar1 = pthread_mutex_lock((pthread_mutex_t *)&DAT_00128370);
  return iVar1;
}



int mutex_get_unlock(void)

{
  int iVar1;
  
  iVar1 = pthread_mutex_unlock((pthread_mutex_t *)&DAT_00128370);
  return iVar1;
}



int gf_delete_timer(timer_t *param_1)

{
  int iVar1;
  
  __android_log_print(3,"FingerGoodix","delete timer \n");
  pthread_mutex_lock((pthread_mutex_t *)&DAT_00128398);
  if ((*param_1 != (timer_t)0x0) && (iVar1 = timer_delete(*param_1), iVar1 == 0)) {
    __android_log_print(3,"FingerGoodix","delete timer success\n");
    *param_1 = (timer_t)0x0;
    iVar1 = pthread_mutex_unlock((pthread_mutex_t *)&DAT_00128398);
    return iVar1;
  }
  *param_1 = (timer_t)0x0;
  iVar1 = pthread_mutex_unlock((pthread_mutex_t *)&DAT_00128398);
  return iVar1;
}



void gx_loop_thread(void)

{
  int iVar1;
  char cVar2;
  
  __android_log_print(3,"FingerGoodix","====LOOP_THREAD=====");
  gf_delete_timer(&gx_timerid);
  mutex_get_lock();
  __android_log_print(3,"FingerGoodix","TouchByFinger\n");
  gf_hw_reset();
  gf_ready_spiclk();
  cVar2 = fnCa_MFKeyFDT_isTouchedByFinger();
  if (cVar2 == '\0') {
    __android_log_print(3,"FingerGoodix","===> Touch caused by Temperature.");
    fnCa_preprossor_init();
    iVar1 = g_mode;
    if (g_mode == 1) {
      __android_log_print(3,"FingerGoodix","DETECT FDT DOWN.");
      g_state = iVar1;
      gf_hw_reset();
      fnCa_Cfg_FdtDown_Up(1);
    }
  }
  else {
    __android_log_print(3,"FingerGoodix","===> Touch By Finger. touch_by_finger:%d\n",cVar2);
    g_state = 3;
    gf_hw_reset();
    fnCa_Cfg_FdtDown_Up(0);
  }
  __android_log_print(3,"FingerGoodix","Timer thread: g_mode : %d. Touch_by_Finger:%d\n",g_mode,
                      cVar2);
  if (g_mode - 2U < 2) {
    gf_unready_spiclk();
    mutex_get_unlock();
    return;
  }
  mutex_get_unlock();
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void gf_create_timer(timer_t *param_1,_func_5017 *param_2)

{
  int iVar1;
  undefined4 uVar2;
  sigevent local_48;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  local_48.sigev_value.sival_ptr = (void *)0x0;
  local_48.sigev_signo = 0;
  local_48.sigev_notify = 0;
  local_48._sigev_un._sigev_thread._function = (_func_5017 *)0x0;
  local_48._sigev_un._sigev_thread._attribute = (void *)0x0;
  local_48._sigev_un._16_8_ = 0;
  local_48._sigev_un._24_8_ = 0;
  local_48._sigev_un._32_8_ = 0;
  local_48._sigev_un._40_8_ = 0;
  __android_log_print(3,"FingerGoodix","Create Timer.\n");
  if (*param_1 == (timer_t)0x0) {
    local_48.sigev_value.sival_int = 0xff;
    local_48.sigev_notify = 2;
    local_48._sigev_un._sigev_thread._function = param_2;
    iVar1 = timer_create(0,&local_48,param_1);
    if (iVar1 == -1) {
      __android_log_print(3,"FingerGoodix","fail to timer_create");
      uVar2 = 0xffffffff;
    }
    else {
      uVar2 = 0;
    }
  }
  else {
    uVar2 = 0xffffffff;
    __android_log_print(3,"FingerGoodix","timer has been create \n");
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar2);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void gf_active_timer(timer_t *param_1)

{
  int iVar1;
  itimerspec local_28;
  long local_8;
  
  local_28.it_interval.tv_sec = 2;
  local_28.it_interval.tv_nsec = 0;
  local_28.it_value.tv_sec = 2;
  local_8 = ___stack_chk_guard;
  local_28.it_value.tv_nsec = 0;
  iVar1 = timer_settime(*param_1,0,&local_28,(itimerspec *)0x0);
  if (iVar1 == -1) {
    __android_log_print(3,"FingerGoodix","fail to timer_settime");
    timer_delete(*param_1);
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void gf_doubleclick_init_timer(timer_t *param_1,int param_2,_func_5017 *param_3)

{
  int iVar1;
  itimerspec local_68;
  sigevent local_48;
  long local_8;
  
  local_68.it_value.tv_nsec = (long)param_2;
  local_8 = ___stack_chk_guard;
  local_48.sigev_value.sival_ptr = (void *)0x0;
  local_48.sigev_signo = 0;
  local_48.sigev_notify = 0;
  local_48._sigev_un._sigev_thread._function = (_func_5017 *)0x0;
  local_48._sigev_un._sigev_thread._attribute = (void *)0x0;
  local_68.it_interval.tv_sec = 0;
  local_48._sigev_un._16_8_ = 0;
  local_48._sigev_un._24_8_ = 0;
  local_68.it_interval.tv_nsec = 0;
  local_48._sigev_un._32_8_ = 0;
  local_48._sigev_un._40_8_ = 0;
  local_68.it_value.tv_sec = 0;
  __android_log_print(3,"FingerGoodix","init and start timer \n");
  pthread_mutex_lock((pthread_mutex_t *)&DAT_00128398);
  if (*param_1 == (timer_t)0x0) {
    local_48.sigev_value.sival_int = 0xff;
    local_48.sigev_notify = 2;
    local_48._sigev_un._sigev_thread._function = param_3;
    iVar1 = timer_create(0,&local_48,param_1);
    if (iVar1 == -1) {
      __android_log_print(3,"FingerGoodix","fail to timer_create");
      pthread_mutex_unlock((pthread_mutex_t *)&DAT_00128398);
    }
    else {
      iVar1 = timer_settime(*param_1,0,&local_68,(itimerspec *)0x0);
      if (iVar1 == -1) {
        __android_log_print(3,"FingerGoodix","fail to timer_settime");
        timer_delete(*param_1);
        pthread_mutex_unlock((pthread_mutex_t *)&DAT_00128398);
      }
      else {
        pthread_mutex_unlock((pthread_mutex_t *)&DAT_00128398);
        __android_log_print(3,"FingerGoodix","init and start timer success \n");
      }
    }
  }
  else {
    __android_log_print(3,"FingerGoodix","timer has been create \n");
    pthread_mutex_unlock((pthread_mutex_t *)&DAT_00128398);
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void gf_longpress_init_timer(timer_t *param_1,int param_2,_func_5017 *param_3)

{
  int iVar1;
  itimerspec local_68;
  sigevent local_48;
  long local_8;
  
  local_68.it_value.tv_sec = (__time_t)param_2;
  local_8 = ___stack_chk_guard;
  local_48.sigev_value.sival_ptr = (void *)0x0;
  local_48.sigev_signo = 0;
  local_48.sigev_notify = 0;
  local_48._sigev_un._sigev_thread._function = (_func_5017 *)0x0;
  local_48._sigev_un._sigev_thread._attribute = (void *)0x0;
  local_68.it_interval.tv_sec = 0;
  local_48._sigev_un._16_8_ = 0;
  local_48._sigev_un._24_8_ = 0;
  local_68.it_interval.tv_nsec = 0;
  local_48._sigev_un._32_8_ = 0;
  local_48._sigev_un._40_8_ = 0;
  local_68.it_value.tv_nsec = 0;
  __android_log_print(3,"FingerGoodix","init and start timer \n");
  pthread_mutex_lock((pthread_mutex_t *)&DAT_00128398);
  if (*param_1 == (timer_t)0x0) {
    local_48.sigev_value.sival_int = 0xff;
    local_48.sigev_notify = 2;
    local_48._sigev_un._sigev_thread._function = param_3;
    iVar1 = timer_create(0,&local_48,param_1);
    if (iVar1 == -1) {
      __android_log_print(3,"FingerGoodix","fail to timer_create");
      pthread_mutex_unlock((pthread_mutex_t *)&DAT_00128398);
    }
    else {
      iVar1 = timer_settime(*param_1,0,&local_68,(itimerspec *)0x0);
      if (iVar1 == -1) {
        __android_log_print(3,"FingerGoodix","fail to timer_settime");
        timer_delete(*param_1);
        pthread_mutex_unlock((pthread_mutex_t *)&DAT_00128398);
      }
      else {
        pthread_mutex_unlock((pthread_mutex_t *)&DAT_00128398);
        __android_log_print(3,"FingerGoodix","init and start timer success \n");
      }
    }
  }
  else {
    __android_log_print(3,"FingerGoodix","timer has been create \n");
    pthread_mutex_unlock((pthread_mutex_t *)&DAT_00128398);
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void gf_init_timer(timer_t *param_1,int param_2,_func_5017 *param_3)

{
  int iVar1;
  itimerspec local_68;
  sigevent local_48;
  long local_8;
  
  local_68.it_interval.tv_sec = (__time_t)param_2;
  local_8 = ___stack_chk_guard;
  local_48.sigev_value.sival_ptr = (void *)0x0;
  local_48.sigev_signo = 0;
  local_48.sigev_notify = 0;
  local_48._sigev_un._sigev_thread._function = (_func_5017 *)0x0;
  local_48._sigev_un._sigev_thread._attribute = (void *)0x0;
  local_48._sigev_un._16_8_ = 0;
  local_48._sigev_un._24_8_ = 0;
  local_68.it_interval.tv_nsec = 0;
  local_48._sigev_un._32_8_ = 0;
  local_48._sigev_un._40_8_ = 0;
  local_68.it_value.tv_nsec = 0;
  local_68.it_value.tv_sec = local_68.it_interval.tv_sec;
  __android_log_print(3,"FingerGoodix","init and start timer \n");
  pthread_mutex_lock((pthread_mutex_t *)&DAT_00128398);
  if (*param_1 == (timer_t)0x0) {
    local_48.sigev_value.sival_int = 0xff;
    local_48.sigev_notify = 2;
    local_48._sigev_un._sigev_thread._function = param_3;
    iVar1 = timer_create(0,&local_48,param_1);
    if (iVar1 == -1) {
      __android_log_print(3,"FingerGoodix","fail to timer_create");
      pthread_mutex_unlock((pthread_mutex_t *)&DAT_00128398);
    }
    else {
      iVar1 = timer_settime(*param_1,0,&local_68,(itimerspec *)0x0);
      if (iVar1 == -1) {
        __android_log_print(3,"FingerGoodix","fail to timer_settime");
        timer_delete(*param_1);
        pthread_mutex_unlock((pthread_mutex_t *)&DAT_00128398);
      }
      else {
        pthread_mutex_unlock((pthread_mutex_t *)&DAT_00128398);
        __android_log_print(3,"FingerGoodix","init and start timer success \n");
      }
    }
  }
  else {
    __android_log_print(3,"FingerGoodix","timer has been create \n");
    pthread_mutex_unlock((pthread_mutex_t *)&DAT_00128398);
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



ulong sig_in_image(ulong param_1)

{
  uint uVar1;
  ulong uVar2;
  
  uVar2 = param_1 & 0xffff;
  if (((uint)uVar2 >> 1 & 1) != 0) {
    param_1 = fnCa_CleanStatus(uVar2);
    if (g_state == 1) {
      __android_log_print(3,"FingerGoodix","IMAGE:key touch_status = 0x%x, g_state = %d \n",uVar2,1)
      ;
      g_state = 2;
      uVar1 = sem_post((sem_t *)g_down_sem);
      return (ulong)uVar1;
    }
    if (g_state == 3) {
      __android_log_print(3,"FingerGoodix","IMAGE:key touch_status = 0x%x, g_state = %d \n",uVar2,3)
      ;
      fnCa_UpdateFDTDownUp(0);
      uVar1 = sem_post((sem_t *)g_up_sem);
      return (ulong)uVar1;
    }
  }
  return param_1;
}



void sig_in_key(ushort param_1)

{
  if ((param_1 >> 1 & 1) == 0) {
    __android_log_print(3,"FingerGoodix","Invalid status:0x%x in mode[%d]\n",param_1,g_mode);
    return;
  }
  fnCa_CleanStatus(param_1);
  if (g_state != 1) {
    if (g_state != 3) {
      return;
    }
    __android_log_print(3,"FingerGoodix","KEY:key up touch_status = 0x%x, g_state = %d \n",param_1,3
                       );
    gf_send_key(0xd4,0);
    (*event_notify)(0x7d1,0,0);
    g_state = 1;
    gf_delete_timer(&gx_timerid);
    fnCa_UpdateFDTDownUp(0);
    gf_hw_reset();
    fnCa_Cfg_FdtDown_Up(1);
    return;
  }
  __android_log_print(3,"FingerGoodix","KEY:key down touch_status = 0x%x, g_state = %d \n",param_1,1
                     );
  gf_send_key(0xd4,1);
  (*event_notify)(0x7d2,0,0);
  g_state = 3;
  gf_hw_reset();
  fnCa_Cfg_FdtDown_Up(0);
  gf_init_timer(&gx_timerid,5,gx_loop_thread);
  return;
}



void sig_in_sleep(void)

{
  __android_log_print(3,"FingerGoodix","Should not happen. Somthing wrong.\n");
  return;
}



ulong sig_in_ff(ushort param_1)

{
  uint uVar1;
  ulong uVar2;
  
  if ((param_1 >> 1 & 1) == 0) {
    uVar2 = __android_log_print(3,"FingerGoodix","Invalid status:0x%x in mode[%d]\n",param_1,g_mode)
    ;
    return uVar2;
  }
  uVar2 = fnCa_CleanStatus(param_1);
  if (g_state != 1) {
    if (g_state != 3) {
      return uVar2;
    }
    __android_log_print(3,"FingerGoodix","FF:key touch_status = 0x%x, g_state = %d, wait up",param_1
                        ,3);
    fnCa_UpdateFDTDownUp(0);
    uVar1 = sem_post((sem_t *)g_up_sem);
    return (ulong)uVar1;
  }
  DAT_001283c0 = g_state;
  __android_log_print(3,"FingerGoodix","FF:key touch_status = 0x%x, g_state = %d, wait down",param_1
                      ,1);
  g_state = 2;
  uVar1 = sem_post((sem_t *)g_down_sem);
  return (ulong)uVar1;
}



void sig_in_nav(short param_1)

{
  if ((param_1 != 0x200) && (param_1 != 2)) {
    __android_log_print(3,"FingerGoodix",
                        "In sig_in_nav should not came here. cur_mode:%d,cur_state:%d",g_mode,
                        g_state);
    return;
  }
  if (g_state == 1) {
    GF_Navigation();
    g_state = 3;
  }
  else if (g_state == 3) {
    GF_Navigation();
    g_state = 1;
  }
  return;
}



void sig_in_debug(void)

{
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void gf_netlink_event(char param_1)

{
  ushort local_a;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  mutex_get_lock();
  __android_log_print(3,"FingerGoodix","gf_netlink_event, event:%d \n",param_1);
  if (param_1 == '\0') {
    if (g_mode == 2) {
      __android_log_print(6,"FingerGoodix","INT in Sleep mode.\n");
      mutex_get_unlock();
      goto LAB_0010783c;
    }
    __android_log_print(3,"FingerGoodix","g_mode = %d\n");
    gf_ready_spiclk();
    __android_log_print(3,"FingerGoodix","fnCa_GetStatus() \n");
    fnCa_GetStatus(&local_a);
    __android_log_print(3,"FingerGoodix","%s %d status 0x%x g_mode %d g_state %d \n",
                        "gf_netlink_event",0x1b4,local_a,g_mode,g_state);
    if ((local_a >> 8 & 1) == 0) {
      if (((local_a >> 7 & 1) != 0) && (local_a != 0x82)) {
        fnCa_CleanStatus();
        __android_log_print(3,"FingerGoodix","Found REVERSE INT \n");
        if (DAT_001283c4 == 1) {
          fnCa_preprossor_init();
        }
        else {
          __android_log_print(3,"FingerGoodix",
                              "#################### recv reverse int ,so update fdt base \n");
          fnCa_UpdateFDTDownUp(0);
        }
        gf_hw_reset();
        fnCa_Cfg_FdtDown_Up(1);
        DAT_001283c4 = 0;
        mutex_get_unlock();
        goto LAB_0010783c;
      }
      if (((local_a & 0xff7f) == 2 || local_a == 8) || ((local_a - 0x80 & 0xff7f) == 0)) {
        if (g_mode == 2) {
          sig_in_sleep();
        }
        else if (g_mode < 3) {
          if (g_mode == 0) {
            if (g_state != 0) {
              sig_in_image();
            }
          }
          else if (g_mode == 1) {
            sig_in_key();
          }
          else {
LAB_00107890:
            __android_log_print(6,"FingerGoodix","Bad mode:%d\n");
          }
        }
        else if (g_mode == 0x10) {
          sig_in_nav();
        }
        else if (g_mode == 0x56) {
          sig_in_debug();
        }
        else {
          if (g_mode != 3) goto LAB_00107890;
          sig_in_ff();
        }
      }
      else {
        __android_log_print(3,"FingerGoodix","#### Invalid int. g_mode = %d\n",g_mode);
        if ((g_mode == 3) && (g_state != 2)) {
          gf_unready_spiclk();
        }
      }
    }
    else {
      fnCa_CleanStatus();
      __android_log_print(3,"FingerGoodix","Found RESET INT \n");
      fnCa_ResetChip();
      if (g_mode < 2) {
        if (g_state == 1) {
          gf_hw_reset();
          fnCa_Cfg_FdtDown_Up(1);
          DAT_001283c4 = 0;
        }
        else if (g_state == 3) {
          gf_hw_reset();
          fnCa_Cfg_FdtDown_Up(0);
        }
      }
      else {
        __android_log_print(3,"FingerGoodix","CHIP RESET INT set to previos mode again. mode is %d")
        ;
        fnCa_SetMode(g_mode);
      }
    }
  }
  else {
    __android_log_print(3,"FingerGoodix","no found command \n");
  }
  mutex_get_unlock();
LAB_0010783c:
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



undefined8 device_disable(void)

{
  g_state = 0;
  GF_NavClose();
  deinit_netlink();
  gf_close();
  DAT_001283c8 = 1;
  event_notify = 0;
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void device_waitForFinger(int param_1)

{
  int iVar1;
  int iVar2;
  int *piVar3;
  undefined8 uVar4;
  int local_2c;
  timespec local_28;
  timeval local_18;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  local_2c = 0;
  g_state = 1;
  __android_log_print(3,"FingerGoodix","===> Waiting Finger Down.\n");
  mutex_get_lock();
  sem_getvalue((sem_t *)g_down_sem,&local_2c);
  iVar1 = local_2c;
  if (local_2c != 0) {
    iVar1 = sem_trywait((sem_t *)g_down_sem);
    g_state = 1;
  }
  gf_ready_spiclk(iVar1);
  gf_hw_reset();
  __android_log_print(3,"FingerGoodix","%s FDT DOWN. Sem_value: %d\n","device_waitForFinger",
                      local_2c);
  fnCa_Cfg_FdtDown_Up(1);
  DAT_001283c4 = 0;
  if (g_mode == 3) {
    gf_unready_spiclk();
  }
  iVar1 = gf_enable_irq();
  if (iVar1 < 0) {
    uVar4 = 0xffffffff;
    __android_log_print(3,"FingerGoodix","Failed to set para in gf_enable_irq.\n");
    mutex_get_unlock();
  }
  else {
    mutex_get_unlock();
    iVar1 = param_1;
    do {
      gettimeofday(&local_18,(__timezone_ptr_t)0x0);
      local_28.tv_nsec = local_18.tv_usec * 1000 + 50000000;
      local_28.tv_sec = local_18.tv_sec + local_28.tv_nsec / 1000000000;
      local_28.tv_nsec = local_28.tv_nsec % 1000000000;
      iVar2 = sem_timedwait((sem_t *)g_down_sem,&local_28);
      __android_log_print(3,"FingerGoodix","wang-->1");
      if (iVar2 == -1) {
        piVar3 = (int *)__errno();
        if (*piVar3 == 0x6e) {
          __android_log_print(3,"FingerGoodix","wang-->2:%d,%d",DAT_001283c8,DAT_001283c9);
          if ((DAT_001283c8 == '\x01') || (DAT_001283c9 == '\x01')) {
            __android_log_print(3,"FingerGoodix","Wait for finger down canceled.");
            g_state = 0;
            iVar1 = gf_enable_irq();
            if (iVar1 < 0) {
              __android_log_print(3,"FingerGoodix","Failed to set para in gf_enable_irq.\n");
            }
            uVar4 = 1;
            __android_log_print(3,"FingerGoodix","wang-->3");
            goto LAB_00107bec;
          }
        }
        else if (*piVar3 == 4) {
          __android_log_print(3,"FingerGoodix","sem_timedwait() EINTR \n");
        }
        else {
          __android_log_print(3,"FingerGoodix","errno = %d \n",*piVar3);
        }
      }
      else {
        if (iVar2 == 0) {
          __android_log_print(3,"FingerGoodix","sem_timedwait() succeeded\n");
          iVar1 = gf_disable_irq();
          if (iVar1 < 0) {
            uVar4 = 0xffffffff;
            __android_log_print(3,"FingerGoodix","Failed to set para in waitForFinger.\n");
          }
          else {
            uVar4 = 0;
            __android_log_print(3,"FingerGoodix","got down status 0x%x=================\n",0);
            gf_ready_spiclk();
            (*event_notify)(1,0,0);
          }
          goto LAB_00107bec;
        }
        __android_log_print(3,"FingerGoodix","Unknown return value.\n");
      }
    } while ((param_1 < 1) || (iVar1 = iVar1 + -0x32, 0 < iVar1));
    uVar4 = 0x83;
    __android_log_print(3,"FingerGoodix","wait finger down time out.\n");
    g_state = 0;
    iVar1 = gf_enable_irq();
    if (iVar1 < 0) {
      __android_log_print(3,"FingerGoodix","Failed to set para in gf_enable_irq.\n");
    }
  }
LAB_00107bec:
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar4);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// WARNING: Restarted to delay deadcode elimination for space: ram

void device_waitForFingerUp(int param_1)

{
  int iVar1;
  int iVar2;
  undefined4 *puVar3;
  undefined8 uVar4;
  int *piVar5;
  int local_2c;
  timespec local_28;
  timeval local_18;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  local_2c = 0;
  __android_log_print(3,"FingerGoodix","===> Wait Finger Up. g_up_ignore = %d\n",DAT_001283c0);
  g_state = 3;
  mutex_get_lock();
  sem_getvalue((sem_t *)g_up_sem,&local_2c);
  if (local_2c != 0) {
    sem_trywait((sem_t *)g_up_sem);
  }
  __android_log_print(3,"FingerGoodix","%s UP \n","device_waitForFingerUp");
  gf_ready_spiclk();
  gf_hw_reset();
  fnCa_Cfg_FdtDown_Up(0);
  iVar1 = gf_enable_irq();
  if (iVar1 < 0) {
    __android_log_print(3,"FingerGoodix","Failed to set para in waitForFinger.\n");
    mutex_get_unlock();
    uVar4 = 0xffffffff;
  }
  else {
    mutex_get_unlock();
    __android_log_print(3,"FingerGoodix","%s %d \n","device_waitForFingerUp",0x43b);
    iVar1 = param_1;
    do {
      gettimeofday(&local_18,(__timezone_ptr_t)0x0);
      local_28.tv_nsec = local_18.tv_usec * 1000 + 50000000;
      local_28.tv_sec = local_18.tv_sec + local_28.tv_nsec / 1000000000;
      local_28.tv_nsec = local_28.tv_nsec % 1000000000;
      iVar2 = sem_timedwait((sem_t *)g_up_sem,&local_28);
      if (iVar2 == -1) {
        piVar5 = (int *)__errno();
        if (*piVar5 == 0x6e) {
          __android_log_print(3,"FingerGoodix","wang-->66:%d,%d",DAT_001283c8,DAT_001283c9);
          if ((DAT_001283c8 == '\x01') || (DAT_001283c9 == '\x01')) {
            __android_log_print(3,"FingerGoodix","Wait for finger up canceled.");
            g_state = 0;
            iVar1 = gf_enable_irq();
            if (iVar1 < 0) {
              __android_log_print(3,"FingerGoodix","Failed to set para in gf_enable_irq.\n");
            }
            __android_log_print(3,"FingerGoodix","wang-->77:%d,%d",DAT_001283c8,DAT_001283c9);
            uVar4 = 2;
            goto LAB_00107fb8;
          }
        }
        else if (*piVar5 == 4) {
          __android_log_print(3,"FingerGoodix","sem_timedwait() EINTR \n");
        }
        else {
          __android_log_print(3,"FingerGoodix","errno = %d \n",*piVar5);
        }
      }
      else {
        if (iVar2 == 0) {
          __android_log_print(3,"FingerGoodix","sem_timedwait() succeeded\n");
          __android_log_print(3,"FingerGoodix","got up=================\n");
          (*event_notify)(2,0,0);
          uVar4 = 0;
          g_state = 0;
          goto LAB_00107fb8;
        }
        puVar3 = (undefined4 *)__errno();
        __android_log_print(3,"FingerGoodix","errno = %d \n",*puVar3);
      }
    } while ((param_1 < 1) || (iVar1 = iVar1 + -0x32, 0 < iVar1));
    __android_log_print(3,"FingerGoodix","wait finger up time out.\n");
    uVar4 = 0x83;
    g_state = 0;
  }
LAB_00107fb8:
  DAT_001283c8 = '\0';
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar4);
}



undefined8 device_setSpeed(void)

{
  gf_set_speed(4800000);
  return 0;
}



undefined8 device_getMode(undefined *param_1)

{
  *param_1 = (char)g_mode;
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void device_getVersion(void *param_1)

{
  int iVar1;
  undefined8 uVar2;
  undefined auStack_10c [4];
  undefined auStack_108 [128];
  undefined auStack_88 [64];
  undefined auStack_48 [64];
  long lStack_8;
  
  lStack_8 = ___stack_chk_guard;
  memset(auStack_108,0,0x100);
  __android_log_print(3,"FingerGoodix","fnCa_GetVersion");
  iVar1 = gx_ta_send_command(0x2a,auStack_10c,4,auStack_108,0x100);
  __android_log_print(3,"FingerGoodix","Ta version: %s",auStack_108);
  __android_log_print(3,"FingerGoodix","Navigation version: %s",auStack_88);
  __android_log_print(3,"FingerGoodix","Algorithm version: %s",auStack_48);
  if (iVar1 == 0) {
    if (param_1 == (void *)0x0) {
      uVar2 = 0;
    }
    else {
      memcpy(param_1,auStack_108,0x100);
      uVar2 = 0;
    }
  }
  else {
    uVar2 = 0xffffffff;
  }
  if (lStack_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar2);
}



undefined8 device_action(undefined8 param_1,long param_2)

{
  undefined8 uVar1;
  
  uVar1 = 0;
  if (param_2 == 0) {
    __android_log_print(3,"FingerGoodix","device_action input buffer is NULL.\n");
    uVar1 = 0xffffff7b;
  }
  return uVar1;
}



void device_notify(undefined8 param_1)

{
  event_notify = param_1;
  return;
}



void device_cancel_waitfinger(void)

{
  int iVar1;
  
  iVar1 = 0;
  __android_log_print(3,"FingerGoodix","device_cancel_waitfinger. g_state:%d ",g_state);
  DAT_001283c8 = 1;
  do {
    iVar1 = iVar1 + 1;
    DAT_001283c9 = 1;
    usleep(20000);
    if (g_state == 0) break;
  } while (iVar1 != 0xf);
  DAT_001283c9 = 0;
  __android_log_print(3,"FingerGoodix","device_cancel_waitfinger out. i = %d",iVar1);
  return;
}



undefined8 device_setMode(byte param_1)

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  
  uVar2 = (uint)param_1;
  __android_log_print(3,"FingerGoodix","%s ,mode = %d, g_mode = %d, ignore = %d\n","device_setMode",
                      uVar2,g_mode,DAT_001283c0);
  mutex_get_lock();
  g_rev_mode = (uint)param_1;
  if (g_mode != 3) {
    __android_log_print(3,"FingerGoodix"," Set mode : %d, g_mode = %d\n",uVar2);
    uVar3 = (uint)param_1;
    if ((param_1 == 0x10 || param_1 < 4) || (uVar3 == 0x56)) {
      if (uVar3 == g_mode) {
        if (uVar3 == 0) {
          gf_ready_spiclk();
          uVar2 = g_mode;
        }
        else if (uVar3 == 2) {
          gf_unready_spiclk();
          uVar2 = g_mode;
        }
        __android_log_print(3,"FingerGoodix"," has already in mode : %d\n",uVar2);
      }
      else {
        if ((g_mode - 2 < 2) || (g_mode == 0)) {
          __android_log_print(3,"FingerGoodix","Enable clock.\n");
          if (g_state != 0) {
            __android_log_print(3,"FingerGoodix","Cancel from state[%d] firstly.");
            device_cancel_waitfinger();
          }
          gf_ready_spiclk();
        }
        if (g_mode == 1) {
          g_state = 3;
          gf_delete_timer(&gx_timerid);
        }
        if (g_mode == 0x10) {
          gf_set_speed(4800000);
        }
        __android_log_print(3,"FingerGoodix",
                            "############ reset before read statue 0x%x g_mode %d \n",0,g_mode);
        gf_hw_reset();
        gf_enable_irq();
        iVar1 = fnCa_SetMode(uVar3);
        if (iVar1 != 0) {
          __android_log_print(3,"FingerGoodix","Failed to set mode.\n");
          gf_hw_reset();
          fnCa_SetMode(uVar3);
        }
        g_mode = uVar3;
        if (uVar3 == 1) {
          g_state = 1;
          __android_log_print(3,"FingerGoodix","### download fdt get down cfg g_state %d \n",1);
          fnCa_Cfg_FdtDown_Up(1);
        }
        else if (param_1 == 0x10) {
          g_state = 1;
          gx_setNav_state();
          gf_set_speed(9600000);
          gf_enable_irq();
          fnCa_Cfg_FdtDown_Up(1);
          DAT_001283c4 = 0;
        }
        else {
          g_state = 0;
        }
        if (g_mode == 2) {
          __android_log_print(3,"FingerGoodix","Disable clock in sleep mode.\n");
          gf_unready_spiclk();
        }
      }
    }
    else {
      __android_log_print(3,"FingerGoodix","Unsupport mode:0x%x\n",uVar3);
    }
    mutex_get_unlock();
    return 0;
  }
  if ((g_rev_mode == 1) && (g_state != 0)) {
    __android_log_print(3,"FingerGoodix","Ghost: Enter Key in FF.\n");
    device_cancel_waitfinger();
  }
  __android_log_print(3,"FingerGoodix","chip mode in FF, do\'t set mode \n");
  mutex_get_unlock();
  return 0;
}



void device_clear_waitfinger(void)

{
  __android_log_print(3,"FingerGoodix","device_clear_waitfinger ");
  DAT_001283c8 = 0;
  DAT_001283c9 = 0;
  return;
}



void device_irq_control(int param_1)

{
  if (param_1 == 0) {
    gf_disable_irq();
    return;
  }
  if (param_1 != 1) {
    return;
  }
  gf_enable_irq();
  return;
}



undefined8 device_pause_capture(void)

{
  __android_log_print(3,"FingerGoodix",
                      "check state after pause_capture, ff_flag:%d, g_mode:%d, rev_mode:%d g_state:%d\n"
                      ,0,g_mode,g_rev_mode,g_state);
  __android_log_print(3,"FingerGoodix","%s %d \n","device_pause_capture",0x572);
  g_state = 0;
  return 0;
}



undefined8 device_enable_spiclk(void)

{
  __android_log_print(3,"FingerGoodix","%s .\n","device_enable_spiclk");
  return 0;
}



undefined8 device_disable_spiclk(void)

{
  __android_log_print(3,"FingerGoodix","%s .\n","device_disable_spiclk");
  return 0;
}



undefined8 device_power_on(void)

{
  int iVar1;
  undefined8 uVar2;
  
  __android_log_print(3,"FingerGoodix","gf_power_on");
  if (DAT_001281e0 == 0) {
    __android_log_print(6,"FingerGoodix","g_device_handle is NULL to do IOCTL Ops.\n");
    uVar2 = 0xffffff7f;
  }
  else {
    iVar1 = ioctl(DAT_001281e0,0x4709);
    uVar2 = 0;
    if (iVar1 < 0) {
      __android_log_print(6,"FingerGoodix","Failed to do GF_IOC_POWER_ON.\n");
      uVar2 = 0xffffffff;
    }
  }
  return uVar2;
}



undefined8 device_power_off(void)

{
  int iVar1;
  undefined8 uVar2;
  
  __android_log_print(3,"FingerGoodix","gf_power_off");
  if (DAT_001281e0 == 0) {
    __android_log_print(6,"FingerGoodix","g_device_handle is NULL to do IOCTL Ops.\n");
    uVar2 = 0xffffff7f;
  }
  else {
    iVar1 = ioctl(DAT_001281e0,0x470a);
    uVar2 = 0;
    if (iVar1 < 0) {
      __android_log_print(6,"FingerGoodix","Failed to do GF_IOC_POWER_OFF.\n");
      uVar2 = 0xffffffff;
    }
  }
  return uVar2;
}



undefined8 device_set_screenoff_mode(undefined4 param_1)

{
  __android_log_print(3,"FingerGoodix","Set ScreenOff Flag: %d, g_ff_flag = %d\n",param_1,0);
  DAT_001283cc = param_1;
  return 0;
}



undefined8 device_set_recognize_flag(int param_1)

{
  __android_log_print(3,"FingerGoodix","%s %d \n","device_set_recognize_flag",0x5a8);
  if (param_1 != 0x6e) {
    return 0;
  }
  DAT_001283c0 = 2;
  mutex_get_lock();
  g_mode = 3;
  mutex_get_unlock();
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void device_check_reset(void)

{
  int iVar1;
  undefined4 uVar2;
  ushort local_a;
  long local_8;
  
  local_a = 0;
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","device_check_reset");
  iVar1 = fnCa_GetStatus(&local_a);
  if (iVar1 == 0) {
    if (((local_a >> 8 & 1) == 0) || (iVar1 = fnCa_CleanStatus(), iVar1 == 0)) {
      mutex_get_lock();
      gf_disable_irq();
      iVar1 = gf_hw_reset();
      if (iVar1 == 0) {
        local_a = 0;
        iVar1 = fnCa_GetStatus(&local_a);
        if (iVar1 == 0) {
          gf_enable_irq();
          mutex_get_unlock();
          uVar2 = 0;
          if ((local_a >> 8 & 1) == 0) {
            uVar2 = 0xffffffff;
            __android_log_print(3,"FingerGoodix","Failed to check:0x%x\n");
          }
        }
        else {
          uVar2 = 0xffffffff;
          __android_log_print(6,"FingerGoodix","Failed to get status:0x%x\n",local_a);
          gf_enable_irq();
          mutex_get_unlock();
        }
      }
      else {
        uVar2 = 0xffffffff;
        __android_log_print(6,"FingerGoodix","Failed to reset\n");
        gf_enable_irq();
        mutex_get_unlock();
      }
    }
    else {
      uVar2 = 0xffffffff;
      __android_log_print(6,"FingerGoodix","Failed to clean status:0x%x\n",local_a);
    }
  }
  else {
    uVar2 = 0xffffffff;
    __android_log_print(6,"FingerGoodix","Failed to get status:0x%x\n",local_a);
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar2);
}



undefined4 device_enable(void)

{
  int iVar1;
  undefined4 uVar2;
  
  iVar1 = gf_open();
  if (iVar1 == 0) {
    gf_ready_spiclk();
    gf_set_speed(4800000);
    iVar1 = device_check_reset();
    if (iVar1 == 0) {
      gf_hw_reset();
      init_netlink();
      sem_init((sem_t *)g_down_sem,0,0);
      sem_init((sem_t *)g_up_sem,0,0);
      iVar1 = sem_init((sem_t *)g_sigio_sem,0,0);
      GF_NavOpen(iVar1);
      DAT_001283c8 = 0;
      g_state = 0;
      DAT_001283c0 = 2;
      uVar2 = 0;
    }
    else {
      uVar2 = 0xffffffff;
      __android_log_print(6,"FingerGoodix","Failed to reset device!!!!!!!!!!!!!!!!\n");
    }
  }
  else {
    uVar2 = 0xffffffff;
    __android_log_print(6,"FingerGoodix","Failed to open device.\n");
  }
  return uVar2;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00108a54(int *param_1)

{
  int iVar1;
  int local_10 [2];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  iVar1 = munmap(*(void **)(param_1 + 4),(ulong)(param_1[6] + 0xfff) & 0xfffff000);
  if (iVar1 != 0) {
    __android_log_print(6,"FingerGoodix","Error::Unmapping ION Buffer failed with ret = %d\n",iVar1)
    ;
  }
  local_10[0] = param_1[2];
  close(param_1[1]);
  iVar1 = ioctl(*param_1,0xc0044901,local_10);
  if (iVar1 != 0) {
    __android_log_print(6,"FingerGoodix","Error::ION Memory FREE ioctl failed with ret = %d\n",iVar1
                       );
  }
  close(*param_1);
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(iVar1);
}



undefined8 gx_alipay_ta_start(void)

{
  undefined8 *puVar1;
  int iVar2;
  undefined4 *puVar3;
  undefined8 uVar4;
  long lVar5;
  
  __android_log_print(3,"FingerGoodix",&DAT_001115f0,"gx_alipay_ta_start");
  if ((g_alipay_handle == 0) ||
     (iVar2 = QSEECom_app_load_query(g_alipay_handle,"alipay"), iVar2 != -4)) {
    lVar5 = 0;
    do {
      puVar1 = (undefined8 *)((long)&ta_path + lVar5);
      lVar5 = lVar5 + 8;
      iVar2 = QSEECom_start_app(&g_alipay_handle,*puVar1,alipay_name,0x2040);
      if (iVar2 == 0) {
        __android_log_print(3,"FingerGoodix","Loading %s Succeed.",alipay_name);
        return 0;
      }
      puVar3 = (undefined4 *)__errno();
      __android_log_print(3,"FingerGoodix","Loading %s failed: ret=%d, errno=%d.",alipay_name,iVar2,
                          *puVar3);
    } while (lVar5 != 0x10);
    __android_log_print(3,"FingerGoodix","Loading %s failed: ret=%d, errno=%d.",alipay_name,iVar2,
                        *puVar3);
    uVar4 = 0xffffffff;
  }
  else {
    __android_log_print(3,"FingerGoodix","%s has been already loaded. ",alipay_name);
    uVar4 = 0;
  }
  return uVar4;
}



undefined8 gx_ta_stop(void)

{
  int iVar1;
  undefined8 uVar2;
  undefined4 *puVar3;
  
  __android_log_print(3,"FingerGoodix",&DAT_001115f0,"gx_ta_stop");
  if (g_ta_handle == 0) {
    __android_log_print(6,"FingerGoodix","g_ta_handle is NULL.");
    uVar2 = 0xffffffff;
  }
  else {
    iVar1 = QSEECom_shutdown_app(&g_ta_handle);
    if (iVar1 != 0) {
      puVar3 = (undefined4 *)__errno();
      __android_log_print(6,"FingerGoodix","Unload %s failed: ret=%d, errno=%d",ta_name,iVar1,
                          *puVar3);
      return 0xffffffff;
    }
    g_ta_handle = 0;
    __android_log_print(3,"FingerGoodix","Unload %s succeed.",ta_name);
    uVar2 = 0;
  }
  return uVar2;
}



undefined8 gx_ta_start(void)

{
  undefined8 *puVar1;
  int iVar2;
  undefined4 *puVar3;
  long lVar4;
  
  if (g_ta_handle != 0) {
    gx_ta_stop();
  }
  lVar4 = 0;
  __android_log_print(3,"FingerGoodix",&DAT_001115f0,"gx_ta_start");
  do {
    puVar1 = (undefined8 *)((long)&ta_path + lVar4);
    lVar4 = lVar4 + 8;
    iVar2 = QSEECom_start_app(&g_ta_handle,*puVar1,ta_name,ta_buf_size);
    if (iVar2 == 0) {
      __android_log_print(3,"FingerGoodix","Loading %s Succeed.",ta_name);
      return 0;
    }
    puVar3 = (undefined4 *)__errno();
    __android_log_print(3,"FingerGoodix","Loading %s failed: ret=%d, errno=%d.",ta_name,iVar2,
                        *puVar3);
  } while (lVar4 != 0x10);
  __android_log_print(6,"FingerGoodix","Loading %s failed: ret=%d, errno=%d.",ta_name,iVar2,*puVar3)
  ;
  return 0xffffffff;
}



undefined8 gx_alipay_ta_stop(void)

{
  int iVar1;
  undefined8 uVar2;
  undefined4 *puVar3;
  
  __android_log_print(3,"FingerGoodix",&DAT_001115f0,"gx_alipay_ta_stop");
  if (g_alipay_handle == 0) {
    __android_log_print(6,"FingerGoodix","*pp_alipay_handle is NULL.");
    uVar2 = 0xffffffff;
  }
  else {
    iVar1 = QSEECom_shutdown_app(&g_alipay_handle);
    if (iVar1 != 0) {
      puVar3 = (undefined4 *)__errno();
      __android_log_print(6,"FingerGoodix","Unload %s failed: ret=%d, errno=%d",alipay_name,iVar1,
                          *puVar3);
      return 0xffffffff;
    }
    g_alipay_handle = 0;
    __android_log_print(3,"FingerGoodix","Unload %s succeed.",alipay_name);
    uVar2 = 0;
  }
  return uVar2;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void gx_ta_send_command(char param_1,void *param_2,uint param_3,void *param_4,uint param_5)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  undefined4 *puVar4;
  undefined8 uVar5;
  undefined4 local_e10;
  undefined4 local_e0c;
  char cStack_e08;
  undefined auStack_e07 [1535];
  undefined auStack_808 [2048];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  pthread_mutex_lock((pthread_mutex_t *)&DAT_001283f0);
  __android_log_print(3,"FingerGoodix","%s, cmd = %d","gx_ta_send_command",param_1);
  if ((param_2 == (void *)0x0) || (param_4 == (void *)0x0)) {
    uVar5 = 0xffffffff;
    __android_log_print(6,"FingerGoodix","Bad input argument. NULL Buffer.");
    pthread_mutex_unlock((pthread_mutex_t *)&DAT_001283f0);
  }
  else if ((param_3 < 0x5f9) && (param_5 < 0x801)) {
    cStack_e08 = param_1;
    memcpy(auStack_e07,param_2,(ulong)param_3);
    uVar1 = param_3 + 1;
    if ((uVar1 & 0x3f) != 0) {
      uVar1 = param_3 + 0x41 & 0xffffffc0;
    }
    uVar2 = param_5;
    if ((param_5 & 0x3f) != 0) {
      uVar2 = param_5 + 0x40 & 0xffffffc0;
    }
    iVar3 = QSEECom_send_cmd(g_ta_handle,&cStack_e08,uVar1,auStack_808,uVar2);
    if ((iVar3 == 0) || (param_1 == '\x02')) {
      uVar5 = 0;
      memcpy(param_4,auStack_808,(ulong)param_5);
    }
    else {
      puVar4 = (undefined4 *)__errno();
      __android_log_print(6,"FingerGoodix","Failed to send cmd[%d], ret=%d, errno=%d",param_1,iVar3,
                          *puVar4);
      __android_log_print(6,"FingerGoodix","try to restart TA.");
      gx_ta_start();
      local_e10 = 0;
      local_e0c = 0;
      gx_ta_send_command(1,&local_e0c,4,&local_e10,4);
      iVar3 = gx_ta_send_command(2,0,0,&local_e10,4);
      if (iVar3 != 0) {
        __android_log_print(6,"FingerGoodix","reset fp failed after restart TA.");
      }
      uVar5 = 0xffffffff;
    }
    pthread_mutex_unlock((pthread_mutex_t *)&DAT_001283f0);
  }
  else {
    uVar5 = 0xffffffff;
    __android_log_print(6,"FingerGoodix",
                        "The maximum length for the send command is %d, and maximum RSP data length is %d"
                        ,0x5f8,0x800);
    pthread_mutex_unlock((pthread_mutex_t *)&DAT_001283f0);
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar5);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void gx_ta_send_modified_cmd_req(undefined4 param_1,void *param_2,uint *param_3)

{
  uint uVar1;
  long *plVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined8 uVar6;
  void *pvVar7;
  long lVar8;
  undefined4 *puVar9;
  int local_78 [2];
  int local_70;
  int local_6c;
  undefined8 local_68;
  undefined8 uStack_60;
  undefined8 local_58;
  undefined8 uStack_50;
  int local_48;
  int local_44;
  int local_40;
  void *local_38;
  uint local_30;
  ulong local_28;
  undefined8 local_20;
  undefined4 local_18;
  undefined4 local_14;
  int local_10;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","gx_ta_send_modified_cmd_req start:%d",param_1);
  pthread_mutex_lock((pthread_mutex_t *)&DAT_001283f0);
  plVar2 = g_ta_handle;
  if ((param_2 == (void *)0x0) || (param_3 == (uint *)0x0)) {
    __android_log_print(6,"FingerGoodix","%s param error","gx_ta_send_modified_cmd_req");
    pthread_mutex_unlock((pthread_mutex_t *)&DAT_001283f0);
    uVar6 = 0xffffffff;
    goto LAB_0010943c;
  }
  if (g_ta_handle == (long *)0x0) {
    __android_log_print(3,"FingerGoodix","Error ta_handle");
    pthread_mutex_unlock((pthread_mutex_t *)&DAT_001283f0);
    uVar6 = 0xffffffff;
    goto LAB_0010943c;
  }
  uVar1 = *param_3;
  local_48 = 0;
  local_40 = 0;
  iVar3 = open("/dev/ion",0);
  if (iVar3 < 0) {
    __android_log_print(6,"FingerGoodix","Error::Cannot open ION device\n");
LAB_00109350:
    __android_log_print(3,"FingerGoodix","Error allocating memory in ion\n");
    pthread_mutex_unlock((pthread_mutex_t *)&DAT_001283f0);
    uVar6 = 0xffffffff;
  }
  else {
    local_28 = (ulong)(uVar1 + 0xfff) & 0xfffff000;
    local_20 = 0x1000;
    local_38 = (void *)0x0;
    local_44 = 0;
    local_18 = 0x8000000;
    local_14 = 0;
    iVar4 = ioctl(iVar3,0xc0204900,&local_28);
    if (iVar4 == 0) {
      if (local_10 == 0) {
        __android_log_print(6,"FingerGoodix","Error::ION alloc data returned a NULL\n");
        goto joined_r0x00109480;
      }
      local_70 = local_10;
      iVar4 = ioctl(iVar3,0xc0084902);
      if (iVar4 != 0) {
        iVar4 = 0;
        __android_log_print(6,"FingerGoodix","Error::Failed doing ION_IOC_MAP call\n");
LAB_0010931c:
        local_78[0] = local_10;
        if (local_44 != 0) {
          close(local_44);
        }
        iVar5 = ioctl(iVar3,0xc0044901,local_78);
        if (iVar5 != 0) {
          __android_log_print(6,"FingerGoodix","Error::ION FREE ioctl returned error = %d\n",iVar5);
        }
        if (iVar3 != 0) goto LAB_00109488;
        goto joined_r0x00109490;
      }
      pvVar7 = mmap((void *)0x0,local_28,3,1,local_6c,0);
      if (pvVar7 == (void *)0xffffffffffffffff) {
        __android_log_print(6,"FingerGoodix","Error::ION MMAP failed\n");
        iVar4 = -1;
        if ((local_38 != (void *)0x0) && (iVar4 = munmap(local_38,local_28), iVar4 != 0)) {
          __android_log_print(6,"FingerGoodix",
                              "Error::Failed to unmap memory for load image. ret = %d\n",iVar4);
        }
        goto LAB_0010931c;
      }
      local_40 = local_10;
      local_44 = local_6c;
      local_48 = iVar3;
      local_38 = pvVar7;
      local_30 = uVar1;
    }
    else {
      __android_log_print(6,"FingerGoodix","Error::Error while trying to allocate data\n");
joined_r0x00109480:
      if (iVar3 != 0) {
        iVar4 = 0;
LAB_00109488:
        close(iVar3);
joined_r0x00109490:
        if (iVar4 != 0) goto LAB_00109350;
      }
    }
    uStack_60 = 0;
    local_58 = 0;
    uStack_50 = 0;
    puVar9 = (undefined4 *)*plVar2;
    *puVar9 = param_1;
    puVar9[1] = (int)local_38;
    puVar9[2] = *param_3;
    local_68 = CONCAT44(4,local_44);
    memcpy(local_38,param_2,(ulong)*param_3);
    lVar8 = *plVar2;
    *(undefined4 *)(lVar8 + 0x308) = 0;
    iVar3 = QSEECom_send_modified_cmd(plVar2,puVar9,0x40,lVar8 + 0x300,0x40,&local_68);
    if ((iVar3 == 0) && (-1 < *(int *)(lVar8 + 0x308))) {
      uVar1 = *(uint *)(lVar8 + 0x304);
      if ((uVar1 == 0) || (*param_3 < uVar1)) {
        *param_3 = 0;
      }
      else {
        *param_3 = uVar1;
        memcpy(param_2,local_38,(ulong)uVar1);
      }
      iVar3 = FUN_00108a54(&local_48);
      if (iVar3 == 0) {
        pthread_mutex_unlock((pthread_mutex_t *)&DAT_001283f0);
        uVar6 = 0;
      }
      else {
        __android_log_print(6,"FingerGoodix","return value of dealloc is %d",iVar3);
        pthread_mutex_unlock((pthread_mutex_t *)&DAT_001283f0);
        uVar6 = 0xffffffff;
      }
    }
    else {
      __android_log_print(3,"FingerGoodix",
                          "qsc_issue_send_modified_cmd_req: fail cmd = %d ret = %d               msg_rsp->status: %d"
                          ,param_1,iVar3);
      FUN_00108a54(&local_48);
      pthread_mutex_unlock((pthread_mutex_t *)&DAT_001283f0);
      uVar6 = 0xffffffff;
    }
  }
LAB_0010943c:
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar6);
}



undefined4
gx_alipay_ta_send_command
          (undefined4 param_1,void *param_2,uint param_3,undefined4 *param_4,uint *param_5)

{
  uint uVar1;
  int iVar2;
  long lVar3;
  long lVar4;
  undefined4 uVar5;
  undefined4 *puVar6;
  
  puVar6 = (undefined4 *)*g_alipay_handle;
  __android_log_print(3,"FingerGoodix","%s, cmd = %d input_len = %d output_len = %d",
                      "gx_alipay_ta_send_command",param_1,param_3,*param_5);
  if ((param_2 == (void *)0x0) || (param_4 == (undefined4 *)0x0)) {
    uVar5 = 0xffffffff;
    __android_log_print(6,"FingerGoodix","%s, Bad input argument. NULL Buffer.",
                        "gx_alipay_ta_send_command");
  }
  else if (param_3 < 0x5f9) {
    puVar6[1] = param_3;
    *puVar6 = param_1;
    memcpy(puVar6 + 2,param_2,(ulong)param_3);
    puVar6[0x404] = 0x1000;
    lVar3 = systemTime(1);
    __android_log_print(3,"FingerGoodix","%s, QSEECom_send_cmd begind, send_len=%d",
                        "gx_alipay_ta_send_command",0x1040);
    pthread_mutex_lock((pthread_mutex_t *)&DAT_001283f0);
    iVar2 = QSEECom_set_bandwidth(g_alipay_handle,1);
    if (iVar2 == 0) {
      iVar2 = QSEECom_send_cmd(g_alipay_handle,puVar6,0x1040,puVar6 + 0x402,0x1040);
      if (iVar2 == 0) {
        if (puVar6[0x403] == 0) {
          uVar1 = puVar6[0x404];
          if (*param_5 < uVar1) {
            __android_log_print(6,"FingerGoodix","cmd[%x] output buffer too short(%d > %d)",param_1)
            ;
          }
          else if (uVar1 == 0) {
            *param_4 = 0;
            *param_5 = 4;
          }
          else {
            memcpy(param_4,puVar6 + 0x405,(ulong)uVar1);
            *param_5 = puVar6[0x404];
          }
          __android_log_print(3,"FingerGoodix","Send cmd[%x] success, rsp_data_len=%d",param_1,
                              puVar6[0x404]);
          uVar5 = 0;
        }
        else {
          uVar5 = 0xffffffff;
          __android_log_print(6,"FingerGoodix","cmd[%x] rsp status error %x",param_1);
        }
      }
      else {
        puVar6 = (undefined4 *)__errno();
        uVar5 = 0xffffffff;
        __android_log_print(6,"FingerGoodix",
                            "%s, QSEECom_send_cmd error, ret=%d, errno=%d, ta maybe has crashed",
                            "gx_alipay_ta_send_command",iVar2,*puVar6);
      }
      iVar2 = QSEECom_set_bandwidth(g_alipay_handle,0);
      if (iVar2 != 0) {
        puVar6 = (undefined4 *)__errno();
        uVar5 = 0xffffffff;
        __android_log_print(6,"FingerGoodix","%s, QSEECom_set_bandwidth low error, errno=%d",
                            "gx_alipay_ta_send_command",*puVar6);
      }
      lVar4 = systemTime(1);
      __android_log_print(3,"FingerGoodix","%s, QSEECom_send_cmd done, time consumed = %ld",
                          "gx_alipay_ta_send_command",(lVar4 - lVar3) / 1000000);
      iVar2 = gx_alipay_ta_stop();
    }
    else {
      puVar6 = (undefined4 *)__errno();
      uVar5 = 0xffffffff;
      __android_log_print(6,"FingerGoodix","%s, QSEECom_set_bandwidth high error, errno=%d",
                          "gx_alipay_ta_send_command",*puVar6);
      iVar2 = gx_alipay_ta_stop();
    }
    if (iVar2 != 0) {
      uVar5 = 0xffffffff;
      __android_log_print(6,"FingerGoodix","%s, alipay_ta stop error.","gx_alipay_ta_send_command");
    }
    __android_log_print(3,"FingerGoodix","%s, before unlock","gx_alipay_ta_send_command");
    pthread_mutex_unlock((pthread_mutex_t *)&DAT_001283f0);
    __android_log_print(3,"FingerGoodix","%s, after unlock","gx_alipay_ta_send_command");
  }
  else {
    uVar5 = 0xffffffff;
    __android_log_print(6,"FingerGoodix","%s, Bad input argument. input_len.",
                        "gx_alipay_ta_send_command");
  }
  return uVar5;
}



void alipay_thread(void)

{
  int iVar1;
  uint uVar2;
  int *piVar3;
  ulong uVar4;
  
  do {
    if ((int)DAT_00128428 == 0) {
                    // WARNING: Subroutine does not return
      pthread_exit((void *)0x0);
    }
    iVar1 = gx_alipay_ta_start();
    if (iVar1 != 0) {
      __android_log_print(6,"FingerGoodix","%s, alipay_ta start error.","alipay_thread");
                    // WARNING: Subroutine does not return
      pthread_exit((void *)0x1);
    }
    while( true ) {
      iVar1 = sem_wait((sem_t *)&DAT_00128418);
      if (iVar1 != -1) break;
      piVar3 = (int *)__errno();
      if (*piVar3 != 4) {
        __android_log_print(6,"FingerGoodix","%s Fatal Error When sem_wait, errno = %d.",
                            "alipay_thread",*piVar3);
                    // WARNING: Subroutine does not return
        pthread_exit((void *)0x2);
      }
    }
    uVar4 = DAT_00128428;
    if ((int)DAT_00128428 != 0) {
      DAT_00128458 = gx_alipay_ta_send_command
                               (DAT_00128430,DAT_00128438,DAT_00128440,DAT_00128448,DAT_00128450);
      uVar2 = sem_post((sem_t *)&DAT_00128460);
      uVar4 = (ulong)uVar2;
    }
    iVar1 = gx_alipay_ta_stop(uVar4);
  } while (iVar1 == 0);
  __android_log_print(6,"FingerGoodix","%s, alipay_ta stop error.","alipay_thread");
                    // WARNING: Subroutine does not return
  pthread_exit((void *)0x3);
}



undefined8 gx_ta_send_command_ex(undefined param_1,long param_2,long param_3)

{
  __android_log_print(3,"FingerGoodix","%s, cmd = %d","gx_ta_send_command_ex",param_1);
  if ((param_2 != 0) && (param_3 != 0)) {
    return 0;
  }
  __android_log_print(6,"FingerGoodix","Bad input argument. NULL Buffer.");
  return 0;
}



void gx_alipay_thread_init(void)

{
  int iVar1;
  
  iVar1 = pthread_attr_init((pthread_attr_t *)&DAT_00128470);
  if (iVar1 != 0) {
    __android_log_print(6,"FingerGoodix","Failed in pthread_attr_init. ret = %d",iVar1);
    return;
  }
  iVar1 = pthread_attr_setstacksize((pthread_attr_t *)&DAT_00128470,0x40000);
  if (iVar1 == 0) {
    sem_init((sem_t *)&DAT_00128418,0,0);
    sem_init((sem_t *)&DAT_00128460,0,0);
    iVar1 = pthread_create(&DAT_001284a8,(pthread_attr_t *)&DAT_00128470,alipay_thread,(void *)0x0);
    if (iVar1 == 0) {
      DAT_00128428._0_4_ = 1;
      DataMemoryBarrier(2,3);
      return;
    }
    __android_log_print(6,"FingerGoodix","Failed in pthread_create. ret = %d",iVar1);
    return;
  }
  __android_log_print(6,"FingerGoodix","Failed in pthread_attr_setstacksize. ret = %d",iVar1);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void gx_alipay_lpthread_destory(void)

{
  int iVar1;
  undefined4 local_c;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  if (DAT_001284a8 == 0) {
    __android_log_print(6,"FingerGoodix","alipay thread doesn\'t run.");
  }
  else {
    DAT_00128428._0_4_ = 0;
    DataMemoryBarrier(2,3);
    iVar1 = pthread_attr_destroy((pthread_attr_t *)&DAT_00128470);
    if (iVar1 == 0) {
      iVar1 = pthread_join(DAT_001284a8,(void **)&local_c);
    }
    else {
      __android_log_print(6,"FingerGoodix","Failed in pthread_attr_destory. ret = %d",iVar1);
      iVar1 = pthread_join(DAT_001284a8,(void **)&local_c);
    }
    if (iVar1 == 0) {
      __android_log_print(3,"FingerGoodix","alipay_thread exit code: %d",local_c);
    }
    else {
      __android_log_print(6,"FingerGoodix","Failed in pthread_join: ret = %d.",iVar1);
    }
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



undefined4
gx_alipay_ta_send_command_asyn
          (undefined4 param_1,undefined8 param_2,undefined4 param_3,undefined8 param_4,
          undefined8 param_5)

{
  int iVar1;
  undefined4 uVar2;
  int *piVar3;
  
  DAT_00128430 = param_1;
  DAT_00128438 = param_2;
  DAT_00128440 = param_3;
  DAT_00128448 = param_4;
  DAT_00128450 = param_5;
  if (DAT_001284a8 == 0) {
    __android_log_print(6,"FingerGoodix","alipay thread doesn\'t run.");
    uVar2 = 0xffffffff;
  }
  else {
    sem_post((sem_t *)&DAT_00128418);
    while (iVar1 = sem_wait((sem_t *)&DAT_00128460), uVar2 = DAT_00128458, iVar1 == -1) {
      piVar3 = (int *)__errno();
      if (*piVar3 != 4) {
        __android_log_print(6,"FingerGoodix","%s Fatal Error When sem_wait, errno = %d.",
                            "gx_alipay_ta_send_command_asyn",*piVar3);
        return 0xffffffff;
      }
    }
  }
  return uVar2;
}



void FUN_00109e70(long param_1,undefined *param_2,int param_3)

{
  undefined *puVar1;
  int iVar2;
  undefined uVar3;
  undefined uVar4;
  undefined uVar5;
  undefined uVar6;
  undefined uVar7;
  undefined *puVar8;
  int iVar9;
  
  __android_log_print(3,"FingerGoodix","--------------------------------");
  if (param_1 != 0) {
    __android_log_print(3,"FingerGoodix","%s: (len: 0x%04x, %d)",param_1,param_3,param_3);
  }
  iVar2 = param_3 + 0xf;
  if (-1 < param_3) {
    iVar2 = param_3;
  }
  iVar2 = iVar2 >> 4;
  if (iVar2 < 1) {
    iVar9 = 0;
  }
  else {
    puVar8 = param_2;
    do {
      puVar1 = puVar8 + 0x10;
      __android_log_print(3,"FingerGoodix",
                          " %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x"
                          ,*puVar8,puVar8[1],puVar8[2],puVar8[3],puVar8[4],puVar8[5]);
      puVar8 = puVar1;
    } while (puVar1 != param_2 + ((ulong)(iVar2 - 1) + 1) * 0x10);
    iVar9 = iVar2 * -0x10;
    param_2 = param_2 + ((ulong)(iVar2 - 1) + 1) * 0x10;
  }
  param_3 = param_3 + iVar9;
  if (param_3 < 1) goto LAB_0010a08c;
  if (param_3 == 1) {
    uVar4 = 0;
LAB_0010a0bc:
    uVar5 = 0;
LAB_0010a0c0:
    uVar6 = 0;
LAB_0010a0c4:
    uVar7 = 0;
LAB_0010a0c8:
    uVar3 = 0;
  }
  else {
    uVar4 = param_2[1];
    if (param_3 == 2) goto LAB_0010a0bc;
    uVar5 = param_2[2];
    if (param_3 == 3) goto LAB_0010a0c0;
    uVar6 = param_2[3];
    if (param_3 == 4) goto LAB_0010a0c4;
    uVar7 = param_2[4];
    if (param_3 == 5) goto LAB_0010a0c8;
    uVar3 = param_2[5];
  }
  __android_log_print(3,"FingerGoodix",
                      " %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
                      *param_2,uVar4,uVar5,uVar6,uVar7,uVar3);
LAB_0010a08c:
  __android_log_print(3,"FingerGoodix","--------------------------------");
  return;
}



int fnCa_OpenSession(void)

{
  int iVar1;
  
  iVar1 = usleep(1000000);
  iVar1 = gx_ta_start(iVar1);
  if (iVar1 == 0) {
    __android_log_print(3,"FingerGoodix","Ta start success.");
    return 0;
  }
  __android_log_print(6,"FingerGoodix","Ta start failed.");
  return iVar1;
}



int fnCa_CloseSession(void)

{
  int iVar1;
  
  iVar1 = gx_ta_stop();
  if (iVar1 == 0) {
    __android_log_print(3,"FingerGoodix","Ta stop success.");
    return 0;
  }
  __android_log_print(6,"FingerGoodix","Ta close failed.");
  return iVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void fnCa_Init(undefined4 param_1)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 local_14 [2];
  undefined4 local_c;
  long local_8;
  
  local_c = 0;
  local_8 = ___stack_chk_guard;
  local_14[0] = param_1;
  iVar1 = gx_ta_send_command(1,local_14,4,&local_c,4);
  uVar2 = local_c;
  if (iVar1 != 0) {
    uVar2 = 0xffffffff;
  }
  if (local_8 != ___stack_chk_guard) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail(uVar2);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void fnCa_Reset(void)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 local_c;
  long local_8;
  
  local_c = 0;
  local_8 = ___stack_chk_guard;
  iVar1 = gx_ta_send_command(2,0,0,&local_c,4);
  uVar2 = local_c;
  if (iVar1 != 0) {
    uVar2 = 0xffffffff;
  }
  if (local_8 != ___stack_chk_guard) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail(uVar2);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void fnCa_SetMode(undefined4 param_1)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 local_14 [2];
  undefined4 local_c;
  long local_8;
  
  local_c = 0;
  local_8 = ___stack_chk_guard;
  local_14[0] = param_1;
  iVar1 = gx_ta_send_command(3,local_14,4,&local_c,4);
  uVar2 = local_c;
  if (iVar1 != 0) {
    uVar2 = 0xffffffff;
  }
  if (local_8 != ___stack_chk_guard) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail(uVar2);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void fnCa_GetMode(undefined4 *param_1)

{
  undefined8 uVar1;
  undefined4 local_10;
  undefined4 local_c;
  long local_8;
  
  local_c = 0;
  local_10 = 0;
  local_8 = ___stack_chk_guard;
  uVar1 = gx_ta_send_command(4,&local_c,4,&local_10,4);
  if ((int)uVar1 == 0) {
    *param_1 = local_10;
  }
  else {
    uVar1 = 0xffffffff;
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar1);
}



undefined8 fnCa_SetModeCancel(void)

{
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void fnCa_Register(undefined8 *param_1)

{
  undefined8 uVar1;
  undefined4 local_14;
  undefined8 local_10;
  long local_8;
  
  local_14 = 8;
  local_8 = ___stack_chk_guard;
  uVar1 = gx_ta_send_command(5,&local_14,4,&local_10);
  if ((int)uVar1 == 0) {
    if (param_1 == (undefined8 *)0x0) {
      uVar1 = 0;
    }
    else {
      *param_1 = local_10;
    }
  }
  else {
    uVar1 = 0xffffffff;
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar1);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void fnCa_CancelRegister(void)

{
  int iVar1;
  undefined4 local_10;
  undefined4 local_c;
  long local_8;
  
  local_10 = 0;
  local_c = 0;
  local_8 = ___stack_chk_guard;
  iVar1 = gx_ta_send_command(6,&local_c,4,&local_10,4);
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(-(uint)(iVar1 != 0));
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void fnCa_SaveRegisteredFp(undefined8 param_1,undefined4 param_2,undefined4 *param_3)

{
  int iVar1;
  undefined8 uVar2;
  undefined8 local_10;
  long local_8;
  
  local_10 = 0;
  local_8 = ___stack_chk_guard;
  iVar1 = gx_ta_send_command(7,param_1,param_2,&local_10,8);
  if ((iVar1 == 0) && ((int)local_10 - 1U < 8)) {
    uVar2 = 0;
    *param_3 = local_10._4_4_;
  }
  else {
    uVar2 = 0xffffffff;
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar2);
}



int fnCa_GetFpNameById(undefined4 param_1,undefined8 param_2)

{
  int iVar1;
  undefined4 local_4;
  
  local_4 = param_1;
  iVar1 = gx_ta_send_command(8,&local_4,4,param_2,0x80);
  return -(uint)(iVar1 != 0);
}



int fnCa_ChangeFpNameById(undefined4 param_1,undefined8 param_2,undefined4 param_3)

{
  int iVar1;
  undefined4 local_4;
  
  local_4 = param_1;
  iVar1 = gx_ta_send_command(9,&local_4,4,param_2,param_3);
  return -(uint)(iVar1 != 0);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void fnCa_enroll_verify(undefined8 *param_1)

{
  int iVar1;
  int iVar2;
  int local_40c;
  undefined8 local_408;
  undefined8 uStack_400;
  undefined8 local_3f8;
  undefined8 uStack_3f0;
  undefined8 local_3e8;
  undefined8 uStack_3e0;
  undefined8 local_3d8;
  undefined8 uStack_3d0;
  undefined4 local_3c8;
  undefined local_3c4;
  undefined auStack_3c3 [4];
  int local_3bf;
  int local_3bb;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","fnCa_enroll_verify");
  iVar2 = -1;
  local_40c = -1;
  memset(&local_408,0,0x400);
  local_3e8 = param_1[4];
  uStack_3e0 = param_1[5];
  local_3c8 = *(undefined4 *)(param_1 + 8);
  local_408 = *param_1;
  uStack_400 = param_1[1];
  local_3f8 = param_1[2];
  uStack_3f0 = param_1[3];
  local_3c4 = *(undefined *)((long)param_1 + 0x44);
  local_3d8 = param_1[6];
  uStack_3d0 = param_1[7];
  iVar1 = getKeyFromKeymaster(auStack_3c3,0x3bb);
  __android_log_print(3,"FingerGoodix","fnCa_enroll_verify22");
  if (iVar1 == 0) {
    __android_log_print(3,"FingerGoodix","fnCa gen hmac, get key OK!");
    gx_ta_send_command(0x34,&local_408,local_3bf + local_3bb + 0x45,&local_40c,4);
    __android_log_print(3,"FingerGoodix","fnCa_enroll_verify:result:%d\n",local_40c);
    iVar2 = -(uint)(local_40c != 0);
  }
  else {
    __android_log_print(6,"FingerGoodix","get key failed! ret: %d",iVar1);
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(iVar2);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void fnCa_Recognize(int param_1,void *param_2,ulong param_3,undefined4 *param_4,undefined4 *param_5)

{
  int iVar1;
  undefined4 uVar2;
  undefined8 uVar3;
  undefined4 local_2e0;
  undefined4 local_2dc;
  undefined8 local_2d8;
  undefined8 uStack_2d0;
  undefined8 local_2c8;
  undefined8 uStack_2c0;
  undefined8 local_2b8;
  undefined auStack_2b0 [156];
  undefined4 local_214;
  undefined auStack_210 [520];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  local_2d8 = 0;
  uStack_2d0 = 0;
  local_2c8 = 0;
  uStack_2c0 = 0;
  local_2b8 = 0;
  memset(auStack_2b0,0,0x2a4);
  local_2e0 = 0;
  local_2d8 = CONCAT44(local_2d8._4_4_,(int)(param_3 & 0xffffffff));
  local_2dc = 4;
  memcpy((void *)((long)&local_2d8 + 4),param_2,(param_3 & 0xffffffff) << 2);
  local_2b8 = CONCAT44(param_1,(undefined4)local_2b8);
  if (param_1 == 1) {
    iVar1 = gx_alipay_ta_start();
    if (iVar1 != 0) {
      __android_log_print(6,"FingerGoodix","%s, alipay_ta start error.","fnCa_Recognize");
      uVar3 = 0xffffffff;
      goto LAB_0010a7c4;
    }
    iVar1 = gx_ta_send_command(10,&local_2d8,0x28,auStack_2b0,0x2a4);
    if (iVar1 == 0) {
      memcpy(param_4,auStack_2b0,0x2a4);
      *param_5 = 0x2a4;
      __android_log_print(3,"FingerGoodix","fnCa_Recognize : TA return index = %d",*param_4);
      uVar2 = gx_alipay_ta_send_command(0xa001001,auStack_210,local_214,&local_2e0,&local_2dc);
      __android_log_print(3,"FingerGoodix","fnCa_Recognize : sync result to alipay ta, ret = %d",
                          uVar2);
      uVar3 = 0;
      goto LAB_0010a7c4;
    }
    iVar1 = gx_alipay_ta_stop();
    if (iVar1 != 0) {
      __android_log_print(6,"FingerGoodix","%s, alipay_ta stop error.","fnCa_Recognize");
    }
  }
  else {
    iVar1 = gx_ta_send_command(10,&local_2d8,0x28,auStack_2b0,0x2a4);
    if (iVar1 == 0) {
      memcpy(param_4,auStack_2b0,0x2a4);
      *param_5 = 0x2a4;
      __android_log_print(3,"FingerGoodix","fnCa_Recognize : TA return index = %d",*param_4);
      uVar3 = 0;
      goto LAB_0010a7c4;
    }
  }
  uVar3 = 0xffffffff;
LAB_0010a7c4:
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar3);
}



undefined8 fnCa_CancelRecognize(void)

{
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void fnCa_DelFpTemplates(undefined4 *param_1,uint param_2)

{
  int iVar1;
  undefined4 uVar2;
  uint *puVar3;
  undefined4 local_c;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  local_c = 0;
  puVar3 = (uint *)malloc((ulong)(param_2 + 1) << 2);
  uVar2 = *param_1;
  *puVar3 = param_2;
  __android_log_print(3,"FingerGoodix","fnCa_DelFpTemplates: id = %d,idCOunt = %d",uVar2,
                      (ulong)param_2);
  memcpy(puVar3 + 1,param_1,(ulong)param_2 << 2);
  iVar1 = gx_ta_send_command(0xc,puVar3,(param_2 + 1) * 4,&local_c,4);
  uVar2 = local_c;
  if (iVar1 != 0) {
    uVar2 = 0xffffffff;
  }
  if (local_8 != ___stack_chk_guard) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail(uVar2);
  }
  return;
}



undefined8 fnCa_GetFpTemplateIdList(long param_1,uint *param_2)

{
  int iVar1;
  uint *__ptr;
  long lVar2;
  undefined8 uVar3;
  uint uVar4;
  
  uVar4 = *param_2;
  __ptr = (uint *)malloc((ulong)(uVar4 + 1) << 2);
  if (__ptr == (uint *)0x0) {
    uVar3 = 0xffffffff;
  }
  else {
    iVar1 = gx_ta_send_command(0xd,param_1,4,__ptr,(uVar4 + 1) * 4);
    if (iVar1 == 0) {
      *param_2 = *__ptr;
      __android_log_print(3,"FingerGoodix","pCount = %d");
      lVar2 = 0;
      uVar4 = 0;
      if (*param_2 != 0) {
        do {
          uVar4 = uVar4 + 1;
          *(undefined4 *)(param_1 + lVar2) = *(undefined4 *)((long)__ptr + lVar2 + 4);
          lVar2 = lVar2 + 4;
        } while (uVar4 < *param_2);
      }
      free(__ptr);
      uVar3 = 0;
    }
    else {
      free(__ptr);
      uVar3 = 0xffffffff;
    }
  }
  return uVar3;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void fnCa_ChangeFpPassword(void *param_1,ulong param_2,void *param_3,uint param_4)

{
  int iVar1;
  undefined4 local_80c;
  undefined auStack_808 [2048];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  param_2 = param_2 & 0xffffffff;
  local_80c = 0;
  memset(auStack_808,0,0x800);
  memcpy(auStack_808,param_1,param_2);
  memcpy(auStack_808 + param_2 + 1,param_3,(ulong)param_4);
  iVar1 = gx_ta_send_command(0xe,auStack_808,param_4 + 1 + (int)param_2,&local_80c,4);
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(-(uint)(iVar1 != 0));
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void fnCa_VerifyFpPassword(undefined8 param_1,undefined4 param_2)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 local_c;
  long local_8;
  
  local_c = 0;
  local_8 = ___stack_chk_guard;
  iVar1 = gx_ta_send_command(0xf,param_1,param_2,&local_c,4);
  uVar2 = local_c;
  if (iVar1 != 0) {
    uVar2 = 0xffffffff;
  }
  if (local_8 != ___stack_chk_guard) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail(uVar2);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void fnCa_LoadFpAlogParams(void)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 local_c;
  long local_8;
  
  local_c = 0;
  local_8 = ___stack_chk_guard;
  iVar1 = gx_ta_send_command(0x10,0,0,&local_c,4);
  uVar2 = local_c;
  if (iVar1 != 0) {
    uVar2 = 0xffffffff;
  }
  if (local_8 != ___stack_chk_guard) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail(uVar2);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void fnCa_CleanStatus(undefined4 param_1)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 local_14 [2];
  undefined4 local_c;
  long local_8;
  
  local_c = 0;
  local_8 = ___stack_chk_guard;
  local_14[0] = param_1;
  iVar1 = gx_ta_send_command(0x13,local_14,4,&local_c,4);
  uVar2 = local_c;
  if (iVar1 != 0) {
    uVar2 = 0xffffffff;
  }
  if (local_8 != ___stack_chk_guard) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail(uVar2);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void fnCa_CleanLBStatus(undefined4 param_1)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 local_14 [2];
  undefined4 local_c;
  long local_8;
  
  local_c = 0;
  local_8 = ___stack_chk_guard;
  local_14[0] = param_1;
  iVar1 = gx_ta_send_command(0x1b,local_14,4,&local_c,4);
  uVar2 = local_c;
  if (iVar1 != 0) {
    uVar2 = 0xffffffff;
  }
  if (local_8 != ___stack_chk_guard) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail(uVar2);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void fnCa_GetStatus(undefined2 *param_1)

{
  int iVar1;
  undefined8 uVar2;
  undefined4 local_10;
  undefined4 local_c;
  long local_8;
  
  local_c = 0;
  local_8 = ___stack_chk_guard;
  local_10 = 0;
  __android_log_print(3,"FingerGoodix","fnCa_GetStatus(), in");
  iVar1 = gx_ta_send_command(0x12,&local_c,4,&local_10,4);
  __android_log_print(3,"FingerGoodix","fnCa_GetStatus(), out");
  if (iVar1 == 0) {
    uVar2 = 0;
    *param_1 = (short)local_10;
  }
  else {
    uVar2 = 0xffffffff;
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar2);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void fnCa_ConfirmStatus(undefined *param_1)

{
  undefined8 uVar1;
  undefined4 local_10;
  undefined4 local_c;
  long local_8;
  
  local_c = 0;
  local_10 = 0;
  local_8 = ___stack_chk_guard;
  uVar1 = gx_ta_send_command(0x26,&local_c,4,&local_10,4);
  if ((int)uVar1 == 0) {
    *param_1 = (char)local_10;
  }
  else {
    uVar1 = 0xffffffff;
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar1);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void fnCa_GetLBStatus(undefined *param_1)

{
  undefined8 uVar1;
  undefined4 local_10;
  undefined4 local_c;
  long local_8;
  
  local_c = 0;
  local_10 = 0;
  local_8 = ___stack_chk_guard;
  uVar1 = gx_ta_send_command(0x1a,&local_c,4,&local_10,4);
  if ((int)uVar1 == 0) {
    *param_1 = (char)local_10;
  }
  else {
    uVar1 = 0xffffffff;
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar1);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void fnCa_GetForceValue(undefined *param_1)

{
  undefined8 uVar1;
  undefined4 local_10;
  undefined4 local_c;
  long local_8;
  
  local_c = 0;
  local_10 = 0;
  local_8 = ___stack_chk_guard;
  uVar1 = gx_ta_send_command(0x1c,&local_c,4,&local_10,4);
  if ((int)uVar1 == 0) {
    *param_1 = (char)local_10;
  }
  else {
    uVar1 = 0xffffffff;
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar1);
}



undefined8
fnCa_ali_invoke_command
          (undefined4 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
          undefined8 param_5)

{
  int iVar1;
  long lVar2;
  long lVar3;
  long lVar4;
  undefined8 uVar5;
  
  lVar2 = systemTime(1);
  iVar1 = gx_alipay_ta_start();
  if (iVar1 == 0) {
    lVar3 = systemTime(1);
    iVar1 = gx_alipay_ta_send_command(param_1,param_2,param_3,param_4,param_5);
    lVar4 = systemTime(1);
    if (iVar1 == 0) {
      __android_log_print(3,"FingerGoodix","%s sucess, (time_load = %ld ms, time_cmd = %ld ms)",
                          "fnCa_ali_invoke_command",(lVar3 - lVar2) / 1000000,
                          (lVar4 - lVar2) / 1000000);
      uVar5 = 0;
    }
    else {
      uVar5 = 0xffffffff;
    }
  }
  else {
    __android_log_print(6,"FingerGoodix","%s, alipay_ta start error.","fnCa_ali_invoke_command");
    uVar5 = 0xffffffff;
  }
  return uVar5;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void fnCa_GetSessionID(undefined8 *param_1)

{
  undefined8 uVar1;
  undefined8 local_18;
  undefined8 local_10;
  long local_8;
  
  local_18 = 0;
  local_10 = 0;
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix",&DAT_001115f0,"fnCa_GetSessionID");
  uVar1 = gx_ta_send_command(0x30,&local_18,8,&local_10,8);
  if ((int)uVar1 == 0) {
    *param_1 = local_10;
  }
  else {
    uVar1 = 0xffffffff;
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar1);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void fnCa_SetSessionID(undefined8 param_1)

{
  undefined8 local_18;
  undefined auStack_c [4];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  local_18 = param_1;
  __android_log_print(3,"FingerGoodix",&DAT_001115f0,"fnCa_SetSessionID");
  gx_ta_send_command(0x2f,&local_18,8,auStack_c,4);
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void fnCa_ESDCheck(undefined *param_1)

{
  undefined8 uVar1;
  undefined4 local_10;
  undefined4 local_c;
  long local_8;
  
  local_c = 0;
  local_10 = 0;
  local_8 = ___stack_chk_guard;
  uVar1 = gx_ta_send_command(0x15,&local_c,4,&local_10,4);
  if ((int)uVar1 == 0) {
    *param_1 = (char)local_10;
  }
  else {
    uVar1 = 0xffffffff;
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar1);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void fnCa_FWIsUpdate(undefined *param_1)

{
  undefined8 uVar1;
  undefined4 local_10;
  undefined4 local_c;
  long local_8;
  
  local_c = 0;
  local_10 = 0;
  local_8 = ___stack_chk_guard;
  uVar1 = gx_ta_send_command(0x16,&local_c,4,&local_10,4);
  if ((int)uVar1 == 0) {
    *param_1 = (char)local_10;
  }
  else {
    uVar1 = 0xffffffff;
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar1);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void fnCa_FWUpdatePre(undefined *param_1)

{
  undefined8 uVar1;
  undefined4 local_10;
  undefined4 local_c;
  long local_8;
  
  local_c = 0;
  local_10 = 0;
  local_8 = ___stack_chk_guard;
  uVar1 = gx_ta_send_command(0x17,&local_c,4,&local_10,4);
  if ((int)uVar1 == 0) {
    *param_1 = (char)local_10;
  }
  else {
    uVar1 = 0xffffffff;
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar1);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void fnCa_FWUpdate(undefined *param_1)

{
  undefined8 uVar1;
  undefined4 local_10;
  undefined4 local_c;
  long local_8;
  
  local_c = 0;
  local_10 = 0;
  local_8 = ___stack_chk_guard;
  uVar1 = gx_ta_send_command(0x18,&local_c,4,&local_10,4);
  if ((int)uVar1 == 0) {
    *param_1 = (char)local_10;
  }
  else {
    uVar1 = 0xffffffff;
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar1);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void fnCa_DownloadCFG(undefined *param_1)

{
  undefined8 uVar1;
  undefined4 local_10;
  undefined4 local_c;
  long local_8;
  
  local_c = 0;
  local_10 = 0;
  local_8 = ___stack_chk_guard;
  uVar1 = gx_ta_send_command(0x19,&local_c,4,&local_10,4);
  if ((int)uVar1 == 0) {
    *param_1 = (char)local_10;
  }
  else {
    uVar1 = 0xffffffff;
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar1);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void fnCa_Calib(void)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 local_c;
  long local_8;
  
  local_c = 0;
  local_8 = ___stack_chk_guard;
  iVar1 = gx_ta_send_command(0x14,0,0,&local_c,4);
  uVar2 = local_c;
  if (iVar1 != 0) {
    uVar2 = 0xffffffff;
  }
  if (local_8 != ___stack_chk_guard) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail(uVar2);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void fnCa_DriverTest(void)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 local_10;
  undefined4 local_c;
  long local_8;
  
  local_10 = 0;
  local_c = 0;
  local_8 = ___stack_chk_guard;
  iVar1 = gx_ta_send_command(0x11,&local_c,4,&local_10,4);
  uVar2 = local_10;
  if (iVar1 != 0) {
    uVar2 = 0xffffffff;
  }
  if (local_8 != ___stack_chk_guard) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail(uVar2);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void fnCa_Fido_Recognize(void *param_1,ulong param_2,undefined *param_3,undefined4 *param_4,
                        undefined8 *param_5)

{
  int iVar1;
  undefined8 uVar2;
  undefined4 uStack_368;
  undefined auStack_364 [32];
  undefined4 local_344;
  undefined8 local_340;
  undefined8 uStack_338;
  undefined8 local_330;
  undefined8 uStack_328;
  undefined8 local_320;
  undefined8 uStack_318;
  undefined8 local_310;
  undefined8 uStack_308;
  undefined8 local_300;
  undefined auStack_2f8 [752];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  memset(auStack_2f8,0,0x2ec);
  __android_log_print(3,"FingerGoodix","fnCa_Fido_Recognize \n");
  local_300 = param_5[8];
  local_320 = param_5[4];
  uStack_318 = param_5[5];
  local_340 = *param_5;
  uStack_338 = param_5[1];
  local_330 = param_5[2];
  uStack_328 = param_5[3];
  local_310 = param_5[6];
  uStack_308 = param_5[7];
  uStack_368 = (undefined4)(param_2 & 0xffffffff);
  memcpy(auStack_364,param_1,(param_2 & 0xffffffff) << 2);
  local_344 = 2;
  iVar1 = gx_ta_send_command(10,&uStack_368,0x70,auStack_2f8,0x2ec);
  if (iVar1 == 0) {
    memcpy(param_3,auStack_2f8,0x2a4);
    *param_4 = 0x2a4;
    param_5[8] = local_300;
    *param_5 = local_340;
    param_5[1] = uStack_338;
    param_5[2] = local_330;
    param_5[3] = uStack_328;
    param_5[4] = local_320;
    param_5[5] = uStack_318;
    param_5[6] = local_310;
    param_5[7] = uStack_308;
    __android_log_print(3,"FingerGoodix","fnCa_Fido_Recognize : TA return,%d/%d",*param_4,*param_3);
    uVar2 = 0;
  }
  else {
    __android_log_print(3,"FingerGoodix","fnCa_Fido_Recognize : Failed.\n");
    uVar2 = 0xffffffff;
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar2);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void fnCa_DataInteraction(void *param_1,uint *param_2,int param_3)

{
  uint uVar1;
  int iVar2;
  void *pvVar3;
  undefined8 uVar4;
  char *pcVar5;
  uint local_c;
  long local_8;
  
  local_c = 0;
  local_8 = ___stack_chk_guard;
  if ((param_1 == (void *)0x0) || (param_2 == (uint *)0x0)) {
    uVar4 = 3;
    pcVar5 = "%s parameter error.";
  }
  else if (param_3 == 0) {
    local_c = *param_2;
    pvVar3 = malloc((long)(int)local_c);
    if (pvVar3 == (void *)0x0) {
      __android_log_print(6,"FingerGoodix","%s malloc fail.","fnCa_DataInteraction");
      *param_2 = 0;
      iVar2 = -1;
      goto LAB_0010b6e0;
    }
    iVar2 = gx_ta_send_modified_cmd_req(0x36,pvVar3,&local_c);
    if (iVar2 != 0) {
      __android_log_print(3,"FingerGoodix","%s read fail.","fnCa_DataInteraction");
      free(pvVar3);
      *param_2 = 0;
      iVar2 = -1;
      goto LAB_0010b6e0;
    }
    if (local_c <= *param_2) {
      *param_2 = local_c;
      memcpy(param_1,pvVar3,(long)(int)local_c);
      __android_log_print(3,"FingerGoodix","%s read success len %d","fnCa_DataInteraction",*param_2)
      ;
      free(pvVar3);
      iVar2 = 0;
      goto LAB_0010b6e0;
    }
    free(pvVar3);
    *param_2 = 0;
    uVar4 = 3;
    pcVar5 = "%s buf too short.";
  }
  else {
    iVar2 = 0;
    if (param_3 != 1) goto LAB_0010b6e0;
    uVar1 = *param_2;
    local_c = uVar1;
    pvVar3 = malloc((ulong)uVar1);
    if (pvVar3 != (void *)0x0) {
      memcpy(pvVar3,param_1,(long)(int)uVar1);
      iVar2 = gx_ta_send_modified_cmd_req(0x37,param_1,&local_c);
      free(pvVar3);
      iVar2 = -(uint)(iVar2 != 0);
      goto LAB_0010b6e0;
    }
    uVar4 = 6;
    pcVar5 = "%s malloc fail.";
  }
  __android_log_print(uVar4,"FingerGoodix",pcVar5,"fnCa_DataInteraction");
  iVar2 = -1;
LAB_0010b6e0:
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(iVar2);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void fnCa_GetBitmap(void *param_1,int *param_2,undefined8 *param_3,uint param_4)

{
  int iVar1;
  int *__ptr;
  void *__ptr_00;
  undefined8 uVar2;
  undefined8 uVar3;
  undefined8 uVar4;
  undefined8 uVar5;
  undefined8 uVar6;
  undefined4 uVar7;
  uint local_14 [2];
  int local_c;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  local_c = 0;
  local_14[0] = param_4;
  __android_log_print(3,"FingerGoodix","fnCa_GetBitmap begin.\n");
  if ((((local_14[0] < 5) && (param_2 != (int *)0x0)) && (param_3 != (undefined8 *)0x0)) &&
     (param_1 != (void *)0x0)) {
    __ptr = (int *)malloc(0x34);
    if (__ptr == (int *)0x0) {
      uVar7 = 0xffffffff;
      __android_log_print(6,"FingerGoodix","fnCa_GetBitmap: malloc fail.");
    }
    else {
      pthread_mutex_lock((pthread_mutex_t *)&DAT_001284c0);
      iVar1 = gx_ta_send_command(0x1d,local_14,4,__ptr,0x34);
      __android_log_print(3,"FingerGoodix","fnCa_GetBitmap: get bitmap ret:%d, *((int *)ptr=%d",
                          iVar1,*__ptr);
      if ((iVar1 == 0) && (*__ptr == 0)) {
        uVar2 = *(undefined8 *)(__ptr + 7);
        uVar3 = *(undefined8 *)(__ptr + 1);
        uVar4 = *(undefined8 *)(__ptr + 3);
        uVar5 = *(undefined8 *)(__ptr + 9);
        uVar6 = *(undefined8 *)(__ptr + 0xb);
        param_3[2] = *(undefined8 *)(__ptr + 5);
        param_3[3] = uVar2;
        *param_3 = uVar3;
        param_3[1] = uVar4;
        param_3[4] = uVar5;
        param_3[5] = uVar6;
        free(__ptr + 1);
        iVar1 = *param_2;
        if (iVar1 < 1) {
          uVar7 = 0xffffffff;
          pthread_mutex_unlock((pthread_mutex_t *)&DAT_001284c0);
        }
        else {
          local_c = iVar1;
          __ptr_00 = malloc((long)iVar1);
          iVar1 = fnCa_DataInteraction(__ptr_00,&local_c,0);
          pthread_mutex_unlock((pthread_mutex_t *)&DAT_001284c0);
          if (iVar1 == 0) {
            if (0 < local_c) {
              if (*param_2 < local_c) {
                uVar7 = 0xffffffff;
                free(__ptr_00);
                __android_log_print(3,"FingerGoodix","fnCa_GetBitmap: buf is too small.");
                goto LAB_0010ba20;
              }
              *param_2 = local_c;
              memcpy(param_1,__ptr_00,(long)local_c);
            }
            free(__ptr_00);
            uVar7 = 0;
          }
          else {
            uVar7 = 0xffffffff;
            free(__ptr_00);
            __android_log_print(3,"FingerGoodix","fnCa_GetBitmap: read bitmap fail.");
          }
        }
      }
      else {
        uVar7 = 0xffffffff;
        __android_log_print(3,"FingerGoodix","fnCa_GetBitmap: get bitmap fail.");
        free(__ptr);
        pthread_mutex_unlock((pthread_mutex_t *)&DAT_001284c0);
      }
    }
  }
  else {
    uVar7 = 0xffffffff;
    __android_log_print(6,"FingerGoodix","fnCa_GetBitmap parameter error.");
  }
LAB_0010ba20:
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar7);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void fnCa_reg_from_bmp(long param_1,int param_2,undefined4 *param_3)

{
  int iVar1;
  undefined8 uVar2;
  int local_24 [2];
  undefined auStack_1c [4];
  undefined8 local_18;
  undefined8 local_10;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  local_18 = 0;
  local_10 = 0;
  local_24[0] = param_2;
  if ((param_3 == (undefined4 *)0x0 || param_2 < 1) || (param_1 == 0)) {
    __android_log_print(6,"FingerGoodix","fnCa_reg_from_bmp:parameter is error.",param_2);
    uVar2 = 0xffffffff;
  }
  else {
    __android_log_print(3,"FingerGoodix","fnCa_reg_from_bmp:length = %d.",param_2);
    pthread_mutex_lock((pthread_mutex_t *)&DAT_001284c0);
    iVar1 = fnCa_DataInteraction(param_1,local_24,1);
    if (iVar1 == 0) {
      iVar1 = gx_ta_send_command(0x1e,auStack_1c,4,&local_18,0x10);
      if (iVar1 == 0) {
        *param_3 = (undefined4)local_18;
        param_3[1] = local_18._4_4_;
        param_3[2] = (undefined4)local_10;
        param_3[3] = local_10._4_4_;
        __android_log_print(3,"FingerGoodix",
                            "fnCa_reg_from_bmp:percent = %d, coverage = %d, quality = %d, overlay = %d."
                            ,local_18 & 0xffffffff,local_18._4_4_,local_10 & 0xffffffff,
                            local_10._4_4_);
      }
    }
    else {
      __android_log_print(3,"FingerGoodix","fnCa_reg_from_bmp: write bitmap fail.");
    }
    pthread_mutex_unlock((pthread_mutex_t *)&DAT_001284c0);
    uVar2 = 0;
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar2);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void fnCa_reg_from_bmp_cancel(void)

{
  int iVar1;
  undefined4 local_10;
  undefined4 local_c;
  long local_8;
  
  local_10 = 0;
  local_c = 0;
  local_8 = ___stack_chk_guard;
  iVar1 = gx_ta_send_command(0x21,&local_c,4,&local_10,4);
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(-(uint)(iVar1 != 0));
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void fnCa_reg_save(void *param_1,int param_2)

{
  int iVar1;
  undefined4 uVar2;
  size_t sVar3;
  undefined4 local_10c;
  char acStack_108 [256];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  local_10c = 0;
  memset(acStack_108,0,0xff);
  memcpy(acStack_108,param_1,(long)param_2);
  __android_log_print(3,"FingerGoodix","fnCa_reg_save:lable_len = %d,lable = %s.",param_2,
                      acStack_108);
  sVar3 = strlen(acStack_108);
  if (sVar3 < 5) {
    __android_log_print(3,"FingerGoodix","fnCa_reg_save:lable is too short.");
    uVar2 = 0xffffffff;
  }
  else {
    iVar1 = gx_ta_send_command(0x1f,acStack_108,param_2 + 1,&local_10c,4);
    uVar2 = local_10c;
    if (iVar1 != 0) {
      uVar2 = 0xffffffff;
    }
  }
  if (local_8 != ___stack_chk_guard) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail(uVar2);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void fnCa_verify_bmp(int *param_1,int param_2,ulong *param_3)

{
  int iVar1;
  int iVar2;
  int iVar3;
  void *__s;
  void *__dest;
  int local_24;
  undefined8 local_20;
  undefined8 local_18;
  undefined8 local_10;
  long local_8;
  
  local_10 = 0;
  local_8 = ___stack_chk_guard;
  local_20 = 0;
  local_18 = 0;
  if ((param_2 < 1 || param_3 == (ulong *)0x0) || (param_1 == (int *)0x0)) {
    __android_log_print(3,"FingerGoodix","fnCa_verify_bmp:buf is NULL.");
    iVar2 = -1;
  }
  else {
    iVar2 = *param_1;
    iVar3 = iVar2 + 1;
    __s = malloc((long)iVar3);
    memset(__s,0,(long)iVar3);
    memcpy(__s,param_1 + 1,(long)iVar2);
    __android_log_print(3,"FingerGoodix","fnCa_verify_bmp:lable_len = %d,lable = %s.",iVar2,__s);
    iVar1 = *(int *)((long)param_1 + (long)(iVar2 + 4));
    local_24 = iVar1;
    __dest = malloc((long)iVar1);
    memcpy(__dest,(void *)((long)param_1 + (long)(iVar2 + 8)),(long)iVar1);
    __android_log_print(3,"FingerGoodix","fnCa_verify_bmp:bitmap_len = %d.",iVar1);
    if (iVar2 + 8 + local_24 == param_2) {
      pthread_mutex_lock((pthread_mutex_t *)&DAT_001284c0);
      iVar2 = fnCa_DataInteraction(__dest,&local_24,1);
      if (iVar2 == 0) {
        iVar3 = gx_ta_send_command(0x20,__s,iVar3,&local_20,0x18);
        if (iVar3 == 0) {
          __android_log_print(3,"FingerGoodix",
                              "fnCa_verify_bmp:coverage = %d, quality = %d, result = %d, score = %d, update = %d, recognize_time = %d."
                              ,local_18._4_4_,local_10 & 0xffffffff,local_20 & 0xffffffff,
                              local_20._4_4_,local_18 & 0xffffffff,local_10._4_4_);
          param_3[2] = local_10;
          *param_3 = local_20;
          param_3[1] = local_18;
        }
        else {
          iVar2 = -1;
        }
      }
      pthread_mutex_unlock((pthread_mutex_t *)&DAT_001284c0);
      free(__s);
      free(__dest);
    }
    else {
      __android_log_print(3,"FingerGoodix","fnCa_verify_bmp:data length is error.");
      free(__s);
      free(__dest);
      iVar2 = -1;
    }
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(iVar2);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void fnCa_del_bmp_template(void *param_1,int param_2)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 local_10c;
  undefined auStack_108 [256];
  long local_8;
  
  local_10c = 0;
  local_8 = ___stack_chk_guard;
  memset(auStack_108,0,0xff);
  memcpy(auStack_108,param_1,(long)param_2);
  __android_log_print(3,"FingerGoodix","fnCa_del_bmp_template:lable_len = %d,lable = %s.",
                      param_2 + 1,auStack_108);
  iVar1 = gx_ta_send_command(0x22,auStack_108,param_2 + 1,&local_10c,4);
  uVar2 = local_10c;
  if (iVar1 != 0) {
    uVar2 = 0xffffffff;
  }
  if (local_8 != ___stack_chk_guard) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail(uVar2);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void fnCa_get_hardware_info(ulong *param_1)

{
  int iVar1;
  undefined auStack_2c [4];
  undefined8 local_28;
  ulong uStack_20;
  ulong local_18;
  undefined4 local_10;
  long local_8;
  
  local_18 = 0;
  local_28 = 0;
  uStack_20 = 0;
  local_8 = ___stack_chk_guard;
  local_10 = 0;
  iVar1 = gx_ta_send_command(0x23,auStack_2c,4,&local_28,0x1c);
  __android_log_print(3,"FingerGoodix","fnCa_get_hardware_info:row = %d, column = %d.",
                      local_28 & 0xffffffff,local_28._4_4_);
  if (param_1 != (ulong *)0x0) {
    param_1[2] = local_18;
    *(undefined4 *)(param_1 + 3) = local_10;
    *param_1 = local_28;
    param_1[1] = uStack_20;
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(-(uint)(iVar1 != 0));
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void fnCa_dump_data(long param_1,uint param_2)

{
  long lVar1;
  int iVar2;
  undefined8 uVar3;
  int iStack_1743c;
  undefined4 uStack_17438;
  undefined4 uStack_17434;
  undefined auStack_17418 [48];
  undefined auStack_173e8 [95208];
  
  lVar1 = ___stack_chk_guard;
  memset(auStack_173e8,0,0x173e0);
  if ((param_1 == 0) || (0xd < param_2)) {
    __android_log_print(6,"FingerGoodix","%s param error","fnCa_dump_data");
    uVar3 = 0xffffffff;
  }
  else {
    iStack_1743c = 0x173e0;
    iVar2 = fnCa_get_hardware_info(&uStack_17438);
    if (iVar2 == 0) {
      iVar2 = fnCa_GetBitmap(auStack_173e8,&iStack_1743c,auStack_17418,4);
      if ((iVar2 == 0) && (iStack_1743c == 0x173e0)) {
        gf_dump_data(auStack_173e8,param_2,uStack_17434,uStack_17438,param_1);
        uVar3 = 0;
      }
      else {
        __android_log_print(6,"FingerGoodix","get dump data  fail");
        uVar3 = 0xffffffff;
      }
    }
    else {
      __android_log_print(6,"FingerGoodix","get hardware info fail");
      uVar3 = 0xffffffff;
    }
  }
  if (lVar1 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar3);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void fnCa_mp_test(int param_1,ulong *param_2)

{
  int iVar1;
  undefined8 uVar2;
  int iVar3;
  undefined4 uVar4;
  ulong unaff_x26;
  int iVar5;
  int local_44 [3];
  int local_38;
  int local_34;
  undefined8 local_30;
  undefined8 local_28;
  undefined8 local_20;
  undefined8 local_18;
  undefined4 local_10;
  long local_8;
  
  uVar4 = (undefined4)unaff_x26;
  local_8 = ___stack_chk_guard;
  local_10 = 0;
  local_30 = 0;
  local_28 = 0;
  local_20 = 0;
  local_18 = 0;
  local_34 = 0xe;
  local_44[0] = param_1;
  __android_log_print(3,"FingerGoodix","fnCa_mp_test: %d.",param_1);
  iVar3 = local_44[0];
  if (local_44[0] == 0) {
    local_34 = 0;
    iVar1 = gx_ta_send_command(0x24,&local_34,4,&local_30,0x24);
  }
  else if (local_44[0] == 8) {
    local_34 = 10;
    iVar1 = gx_ta_send_command(0x24,&local_34,4,&local_38,4);
    local_34 = iVar3;
    if (0 < local_38) {
      iVar3 = 0;
      do {
        iVar3 = iVar3 + 1;
        gx_ta_send_command(0x24,&local_34,4,&local_30,0x24);
      } while (iVar3 < local_38);
    }
  }
  else if (local_44[0] == 2) {
    local_34 = 9;
    iVar5 = 0;
    iVar1 = gx_ta_send_command(0x24,&local_34,4,&local_38,4);
    local_34 = iVar3;
    if (0 < local_38) {
      iVar3 = 0;
      do {
        while( true ) {
          uVar4 = (undefined4)unaff_x26;
          gx_ta_send_command(0x24,&local_34,4,&local_30,0x24);
          if (local_30._4_4_ == 1) break;
          iVar3 = iVar3 + 1;
          unaff_x26 = local_18 & 0xffffffff;
          uVar4 = (undefined4)unaff_x26;
          if (local_38 <= iVar3) goto LAB_0010c5dc;
        }
        iVar3 = iVar3 + 1;
        iVar5 = iVar5 + 1;
      } while (iVar3 < local_38);
    }
LAB_0010c5dc:
    if (iVar5 == local_38) {
      local_30 = CONCAT44(1,(undefined4)local_30);
    }
    else {
      local_18 = CONCAT44(local_18._4_4_,uVar4);
    }
  }
  else {
    iVar1 = gx_ta_send_command(0x24,local_44,4,&local_30,0x24);
  }
  if (iVar1 == 0) {
    if (param_2 != (ulong *)0x0) {
      *param_2 = local_30;
      param_2[1] = local_28;
      param_2[2] = local_20;
      param_2[3] = local_18;
      *(undefined4 *)(param_2 + 4) = local_10;
      __android_log_print(3,"FingerGoodix","fnCa_mp_test step[%d] result:",local_44[0]);
      __android_log_print(3,"FingerGoodix","fnCa_mp_test selftest:%d",local_30 & 0xffffffff);
      __android_log_print(3,"FingerGoodix","fnCa_mp_test performance:%d",local_30._4_4_);
      __android_log_print(3,"FingerGoodix","fnCa_mp_test image_quality:%d",local_28 & 0xffffffff);
      __android_log_print(3,"FingerGoodix","fnCa_mp_test scene:%d",local_28._4_4_);
      __android_log_print(3,"FingerGoodix","fnCa_mp_test defect_detection:%d",local_20 & 0xffffffff)
      ;
      __android_log_print(3,"FingerGoodix","fnCa_mp_test pixel_detection:%d",local_20._4_4_);
      __android_log_print(3,"FingerGoodix","fnCa_mp_test time_ms:%d",local_18 & 0xffffffff);
      __android_log_print(3,"FingerGoodix","fnCa_mp_test quality:%d",local_18._4_4_);
      __android_log_print(3,"FingerGoodix","fnCa_mp_test coverage:%d",local_10);
    }
    uVar2 = 0;
  }
  else {
    __android_log_print(3,"FingerGoodix","fnCa_mp_test send cmd to ta failed!");
    uVar2 = 0xffffffff;
  }
  if (local_8 != ___stack_chk_guard) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail(uVar2);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void fnCa_update_template(undefined4 param_1)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 local_14 [2];
  undefined4 local_c;
  long local_8;
  
  local_c = 0;
  local_8 = ___stack_chk_guard;
  local_14[0] = param_1;
  __android_log_print(3,"FingerGoodix","fnCa_update_template:index = %d",param_1);
  iVar1 = gx_ta_send_command(0x27,local_14,4,&local_c,4);
  uVar2 = local_c;
  if (iVar1 != 0) {
    uVar2 = 0xffffffff;
  }
  if (local_8 != ___stack_chk_guard) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail(uVar2);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void fnCa_GetVersion(void *param_1)

{
  int iVar1;
  undefined8 uVar2;
  undefined auStack_10c [4];
  undefined auStack_108 [128];
  undefined auStack_88 [64];
  undefined auStack_48 [64];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  memset(auStack_108,0,0x100);
  __android_log_print(3,"FingerGoodix","fnCa_GetVersion");
  iVar1 = gx_ta_send_command(0x2a,auStack_10c,4,auStack_108,0x100);
  __android_log_print(3,"FingerGoodix","Ta version: %s",auStack_108);
  __android_log_print(3,"FingerGoodix","Navigation version: %s",auStack_88);
  __android_log_print(3,"FingerGoodix","Algorithm version: %s",auStack_48);
  if (iVar1 == 0) {
    if (param_1 == (void *)0x0) {
      uVar2 = 0;
    }
    else {
      memcpy(param_1,auStack_108,0x100);
      uVar2 = 0;
    }
  }
  else {
    uVar2 = 0xffffffff;
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar2);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void fnCa_SetEnrollCnt(ulong param_1,undefined4 param_2)

{
  undefined4 uVar1;
  int iVar2;
  undefined8 local_20;
  undefined4 local_18;
  undefined4 local_c;
  long local_8;
  
  local_20._4_4_ = (undefined4)(param_1 >> 0x20);
  uVar1 = local_20._4_4_;
  local_8 = ___stack_chk_guard;
  local_c = 0;
  local_20 = param_1;
  local_18 = param_2;
  __android_log_print(3,"FingerGoodix",
                      "fnCa_SetEnrollCnt: enroll_count_type = %d, enroll_session_type = %d ,count = %d."
                      ,uVar1,param_1 & 0xffffffff,param_2);
  iVar2 = gx_ta_send_command(0x2b,&local_20,0xc,&local_c,4);
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(-(uint)(iVar2 != 0));
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void fnCa_GetEnrollCnt(undefined4 *param_1)

{
  int iVar1;
  undefined8 uVar2;
  undefined4 local_c;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  if (param_1 == (undefined4 *)0x0) {
    __android_log_print(3,"FingerGoodix","fnCa_GetEnrollCnt:Parameter is error!");
    uVar2 = 0xffffffff;
  }
  else {
    __android_log_print(3,"FingerGoodix",
                        "fnCa_GetEnrollCnt:enroll_count_type = %d, enroll_session_type = %d",
                        param_1[1],*param_1);
    iVar1 = gx_ta_send_command(0x2c,param_1,0xc,&local_c,4);
    if (iVar1 == 0) {
      param_1[2] = local_c;
      __android_log_print(3,"FingerGoodix","fnCa_GetEnrollCnt count = %d.");
      uVar2 = 0;
    }
    else {
      uVar2 = 0xffffffff;
    }
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar2);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void fnCa_Pause_capture(void)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 local_c;
  long local_8;
  
  local_c = 0;
  local_8 = ___stack_chk_guard;
  iVar1 = gx_ta_send_command(0x2d,&local_c,4,&local_c,4);
  uVar2 = local_c;
  if (iVar1 != 0) {
    uVar2 = 0xffffffff;
  }
  if (local_8 != ___stack_chk_guard) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail(uVar2);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void fnCa_preprossor_init(void)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 local_10;
  undefined4 local_c;
  long local_8;
  
  local_10 = 0;
  local_c = 0;
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","fnCa_preprossor_init");
  iVar1 = gx_ta_send_command(0x29,&local_c,4,&local_10,4);
  uVar2 = local_10;
  if (iVar1 != 0) {
    uVar2 = 0xffffffff;
  }
  if (local_8 != ___stack_chk_guard) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail(uVar2);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void fnCa_NavGetStatus(long param_1,undefined4 param_2)

{
  int iVar1;
  undefined4 local_c;
  long local_8;
  
  local_c = 0;
  local_8 = ___stack_chk_guard;
  if (param_1 == 0) {
    __android_log_print(3,"FingerGoodix","Input PTR pNav is NULL.\n",0,param_2);
    iVar1 = -1;
  }
  else {
    iVar1 = gx_ta_send_command(0x50,&local_c,4);
    iVar1 = -(uint)(iVar1 != 0);
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(iVar1);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void fnCa_NavCleanStatus(long param_1,undefined4 param_2)

{
  int iVar1;
  undefined4 local_c;
  long local_8;
  
  local_c = 0;
  local_8 = ___stack_chk_guard;
  if (param_1 == 0) {
    __android_log_print(3,"FingerGoodix","Input PTR pNav is NULL.\n");
    iVar1 = -1;
  }
  else {
    iVar1 = gx_ta_send_command(0x51,param_1,param_2,&local_c,4);
    iVar1 = -(uint)(iVar1 != 0);
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(iVar1);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void fnCa_Nav(undefined *param_1)

{
  undefined8 uVar1;
  undefined4 local_10;
  undefined4 local_c;
  long local_8;
  
  local_10 = 0;
  local_c = 0;
  local_8 = ___stack_chk_guard;
  if (param_1 == (undefined *)0x0) {
    __android_log_print(3,"FingerGoodix","Input PTR pNav is NULL.\n");
    uVar1 = 0xffffffff;
  }
  else {
    uVar1 = gx_ta_send_command(0x52,&local_c,4,&local_10,4);
    if ((int)uVar1 == 0) {
      *param_1 = (char)local_10;
    }
    else {
      uVar1 = 0xffffffff;
    }
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar1);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void fnCa_NavGetBase(long param_1,undefined4 param_2)

{
  undefined8 uVar1;
  undefined4 local_c;
  long local_8;
  
  local_c = 0;
  local_8 = ___stack_chk_guard;
  if (param_1 == 0) {
    __android_log_print(3,"FingerGoodix","Input PTR pNav is NULL.\n",0,param_2);
    uVar1 = 0xffffffff;
  }
  else {
    uVar1 = gx_ta_send_command(0x53,&local_c,4);
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar1);
}



undefined8 fnCa_NavCapture(undefined4 param_1,long param_2)

{
  undefined8 uVar1;
  undefined4 local_4;
  
  local_4 = param_1;
  if (param_2 == 0) {
    __android_log_print(3,"FingerGoodix","Input PTR pNav is NULL.\n",0);
    uVar1 = 0xffffffff;
  }
  else {
    uVar1 = gx_ta_send_command(0x54,&local_4,4,param_2,1);
  }
  return uVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void fnCa_NavGetFrame(long param_1,undefined4 param_2)

{
  undefined8 uVar1;
  undefined4 local_c;
  long local_8;
  
  local_c = 0;
  local_8 = ___stack_chk_guard;
  if (param_1 == 0) {
    __android_log_print(3,"FingerGoodix","Input PTR pNav is NULL.\n",0,param_2);
    uVar1 = 0xffffffff;
  }
  else {
    uVar1 = gx_ta_send_command(0x55,&local_c,4);
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar1);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void fnCa_NavGetDebugFrame(long param_1,undefined4 param_2)

{
  undefined8 uVar1;
  undefined4 local_c;
  long local_8;
  
  local_c = 0;
  local_8 = ___stack_chk_guard;
  if (param_1 == 0) {
    __android_log_print(3,"FingerGoodix","Input PTR pNav is NULL.\n",0,param_2);
    uVar1 = 0xffffffff;
  }
  else {
    uVar1 = gx_ta_send_command(0x56,&local_c,4);
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar1);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void fnCa__SetSafeClass(undefined4 param_1)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 local_14 [2];
  undefined4 local_c;
  long local_8;
  
  local_c = 0;
  local_8 = ___stack_chk_guard;
  local_14[0] = param_1;
  iVar1 = gx_ta_send_command(100,local_14,4,&local_c,4);
  uVar2 = local_c;
  if (iVar1 != 0) {
    uVar2 = 0xffffffff;
  }
  if (local_8 != ___stack_chk_guard) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail(uVar2);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void fnCa_Cfg_FdtDown_Up(undefined4 param_1)

{
  undefined4 local_c;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  local_c = param_1;
  gx_ta_send_command(0x3c,&local_c,4,&local_c,4);
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void fnCa_UpdateFDTDownUp(undefined4 param_1)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 local_14 [2];
  undefined4 local_c;
  long local_8;
  
  local_c = 0;
  local_8 = ___stack_chk_guard;
  local_14[0] = param_1;
  iVar1 = gx_ta_send_command(0x3f,local_14,4,&local_c,4);
  uVar2 = local_c;
  if (iVar1 != 0) {
    uVar2 = 0xffffffff;
  }
  if (local_8 != ___stack_chk_guard) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail(uVar2);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void fnCa_ReverseChip(void)

{
  undefined4 local_c;
  long local_8;
  
  local_c = 0;
  local_8 = ___stack_chk_guard;
  gx_ta_send_command(0x3d,&local_c,4,&local_c,4);
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void fnCa_ResetChip(void)

{
  undefined4 local_c;
  long local_8;
  
  local_c = 0;
  local_8 = ___stack_chk_guard;
  gx_ta_send_command(0x3e,&local_c,4,&local_c,4);
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void fnCa_MFKeyFDT_isTouchedByFinger(void)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 local_10;
  undefined4 local_c;
  long local_8;
  
  local_10 = 0;
  local_c = 0;
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","fnCa_MFKeyFDT_isTouchedByFinger");
  iVar1 = gx_ta_send_command(0x46,&local_c,4,&local_10,4);
  uVar2 = local_10;
  if (iVar1 != 0) {
    uVar2 = 0xffffffff;
  }
  if (local_8 != ___stack_chk_guard) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail(uVar2);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void fnCa_set_active_group(undefined4 param_1)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 local_14 [2];
  undefined4 local_c;
  long local_8;
  
  local_c = 0;
  local_8 = ___stack_chk_guard;
  local_14[0] = param_1;
  iVar1 = gx_ta_send_command(0x31,local_14,4,&local_c,4);
  uVar2 = local_c;
  if (iVar1 != 0) {
    uVar2 = 0xffffffff;
  }
  if (local_8 != ___stack_chk_guard) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail(uVar2);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void fnCa_set_active_fpclient(undefined4 param_1)

{
  int iVar1;
  undefined4 local_14 [2];
  undefined4 local_c;
  long local_8;
  
  local_c = 0;
  local_8 = ___stack_chk_guard;
  local_14[0] = param_1;
  iVar1 = gx_ta_send_command(0x32,local_14,4,&local_c,4);
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(-(uint)(iVar1 != 0));
}



int fnCa_send_cmd_to_ta(int param_1)

{
  undefined4 uVar1;
  int iVar2;
  
  if (param_1 == 0x19) {
    uVar1 = 0x82;
  }
  else {
    uVar1 = 0x83;
    if (param_1 != 0x1a) {
      uVar1 = 0;
    }
  }
  iVar2 = gx_ta_send_command(uVar1);
  __android_log_print(3,"FingerGoodix","fnCa_send_cmd_to_ta ret:%d, cmd_id:%d",iVar2,param_1);
  return -(uint)(iVar2 != 0);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void fnCa_gen_auth_token_hmac(void *param_1,int param_2,void *param_3,int *param_4)

{
  int iVar1;
  undefined8 uVar2;
  size_t __n;
  undefined8 local_450;
  undefined8 uStack_448;
  undefined8 local_440;
  undefined8 uStack_438;
  undefined8 local_430;
  undefined8 uStack_428;
  undefined8 local_420;
  undefined8 uStack_418;
  undefined4 local_410;
  undefined local_40c;
  undefined auStack_408 [4];
  int aiStack_404 [8];
  undefined auStack_3e3 [987];
  long local_8;
  
  __n = (size_t)param_2;
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","fnCa gen hmac, token:%p, tokenLen=%d",param_1,param_2);
  memset(auStack_408,0,0x400);
  memcpy(auStack_408,param_1,__n);
  local_410 = 0;
  local_450 = 0;
  uStack_448 = 0;
  local_440 = 0;
  uStack_438 = 0;
  local_430 = 0;
  uStack_428 = 0;
  local_420 = 0;
  uStack_418 = 0;
  local_40c = 0;
  FUN_00109e70("FnCa1, TEE auth token",auStack_408,0x25);
  FUN_00109e70("FnCa1, TEE auth hmac",auStack_3e3,0x20);
  iVar1 = getKeyFromKeymaster(auStack_408 + __n,0x400 - param_2);
  if (iVar1 == 0) {
    __android_log_print(3,"FingerGoodix","fnCa gen hmac, get key OK!",0);
    iVar1 = gx_ta_send_command(0x33,auStack_408,
                               *(int *)((long)aiStack_404 + __n) +
                               *(int *)((long)aiStack_404 + __n + 4) + 0x45,&local_450);
    if (iVar1 == 0) {
      *param_4 = 0x28;
      __android_log_print(3,"FingerGoodix","fnCa gen hmac, outlen:%d",0x28);
      memcpy(param_3,(void *)((long)&uStack_438 + 5),(long)*param_4);
      FUN_00109e70("FnCa2, TEE auth token",&local_450,0x25);
      FUN_00109e70("FnCa2, TEE auth hmac",(long)&local_430 + 5,0x20);
      uVar2 = 0;
    }
    else {
      uVar2 = 0xffffffff;
    }
  }
  else {
    __android_log_print(6,"FingerGoodix","get key failed! ret: %d",iVar1);
    uVar2 = 0xffffffff;
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar2);
}



undefined8 FUN_0010d394(long param_1,undefined8 param_2)

{
  *(undefined8 *)(param_1 + 0x78) = param_2;
  return 0xffffffff;
}



undefined8 FUN_0010d3a0(void)

{
  return 0xffffffff;
}



undefined8 FUN_0010d3a8(void)

{
  return 0xffffffff;
}



undefined8 FUN_0010d3b0(void)

{
  return 0xffffffff;
}



undefined8 FUN_0010d3b8(void)

{
  return 0xffffffff;
}



undefined8 FUN_0010d3c0(void)

{
  return 0xffffffff;
}



int fnCa_OpenSession(void)

{
  int iVar1;
  
  iVar1 = usleep(1000000);
  iVar1 = gx_ta_start(iVar1);
  if (iVar1 == 0) {
    __android_log_print(3,"FingerGoodix","Ta start success.");
    return 0;
  }
  __android_log_print(6,"FingerGoodix","Ta start failed.");
  return iVar1;
}



void FUN_0010d3cc(void)

{
  __android_log_print(3,"FingerGoodix","fingerprint device enable");
  device_enable();
  return;
}



int fnCa_CloseSession(void)

{
  int iVar1;
  
  iVar1 = gx_ta_stop();
  if (iVar1 == 0) {
    __android_log_print(3,"FingerGoodix","Ta stop success.");
    return 0;
  }
  __android_log_print(6,"FingerGoodix","Ta close failed.");
  return iVar1;
}



void FUN_0010d3f8(void)

{
  __android_log_print(3,"FingerGoodix","fingerprint device disable.");
  device_disable();
  return;
}



undefined8 FUN_0010d420(undefined8 param_1,undefined8 param_2,undefined8 *param_3)

{
  int iVar1;
  undefined4 *__s;
  undefined8 uVar2;
  
  if (param_3 == (undefined8 *)0x0) {
    __android_log_print(6,"FingerGoodix","NULL device on open");
    uVar2 = 0xffffffea;
  }
  else {
    __s = (undefined4 *)malloc(0x2d8);
    memset(__s,0,0x2d8);
    *(undefined8 *)(__s + 2) = param_1;
    *__s = 0x48574454;
    *(code **)(__s + 0x1c) = FUN_0010de88;
    *(code **)(__s + 0xac) = FUN_0010d394;
    *(code **)(__s + 0x20) = fnCa_OpenSession;
    *(code **)(__s + 0x22) = fnCa_CloseSession;
    *(code **)(__s + 0x24) = FUN_0010d8f4;
    *(code **)(__s + 0x26) = fnCa_Reset;
    *(code **)(__s + 0x28) = FUN_0010dc1c;
    *(code **)(__s + 0x2a) = FUN_0010da98;
    *(code **)(__s + 0x2c) = fnCa_SetModeCancel;
    *(code **)(__s + 0x2e) = FUN_0010de78;
    *(code **)(__s + 0x30) = fnCa_CancelRegister;
    *(code **)(__s + 0x32) = FUN_0010de64;
    *(code **)(__s + 0x34) = FUN_0010de54;
    *(code **)(__s + 0x36) = FUN_0010de44;
    *(code **)(__s + 0x72) = fnCa_enroll_verify;
    *(code **)(__s + 0x38) = FUN_0010de28;
    *(code **)(__s + 0x3a) = fnCa_CancelRecognize;
    *(code **)(__s + 0x3c) = FUN_0010de18;
    *(code **)(__s + 0x3e) = FUN_0010de0c;
    *(code **)(__s + 0x40) = FUN_0010ddf8;
    *(code **)(__s + 0x42) = FUN_0010ddec;
    *(code **)(__s + 0x44) = fnCa_LoadFpAlogParams;
    *(code **)(__s + 0x6c) = FUN_0010ddd0;
    *(code **)(__s + 0x6e) = FUN_0010ddc8;
    *(code **)(__s + 0x70) = FUN_0010ddc0;
    *(code **)(__s + 0x46) = fnCa_DriverTest;
    *(code **)(__s + 0x76) = FUN_0010dda8;
    *(code **)(__s + 0x78) = FUN_0010dd98;
    *(code **)(__s + 0x7e) = fnCa_reg_from_bmp_cancel;
    *(code **)(__s + 0x7a) = FUN_0010dd88;
    __s[1] = 0x100;
    *(code **)(__s + 0xa6) = FUN_0010dd48;
    *(code **)(__s + 0x7c) = FUN_0010dd38;
    *(code **)(__s + 0x80) = FUN_0010dd2c;
    *(code **)(__s + 0x82) = FUN_0010dd24;
    *(code **)(__s + 0x84) = FUN_0010dd18;
    *(code **)(__s + 0x8a) = FUN_0010dd04;
    *(code **)(__s + 0x8c) = FUN_0010dcfc;
    *(code **)(__s + 0x86) = FUN_0010dcf4;
    *(code **)(__s + 0x88) = fnCa_preprossor_init;
    *(code **)(__s + 0x9e) = FUN_0010dcb8;
    *(code **)(__s + 0xa0) = FUN_0010dc80;
    *(code **)(__s + 0xa2) = FUN_0010dc28;
    *(code **)(__s + 0xa4) = set_fp_enabled;
    *(code **)(__s + 0x48) = FUN_0010d3a0;
    *(code **)(__s + 0x4a) = FUN_0010d3a8;
    *(code **)(__s + 0x4c) = FUN_0010d3b0;
    *(code **)(__s + 0x50) = FUN_0010dbe0;
    *(code **)(__s + 0x52) = FUN_0010dba8;
    *(code **)(__s + 0x54) = FUN_0010d3b8;
    *(code **)(__s + 0x56) = FUN_0010d3cc;
    *(code **)(__s + 0x58) = FUN_0010d3f8;
    *(code **)(__s + 0x5a) = FUN_0010db68;
    *(code **)(__s + 0x5c) = FUN_0010d3c0;
    *(code **)(__s + 0x5e) = FUN_0010db30;
    *(code **)(__s + 0x60) = FUN_0010daf8;
    *(code **)(__s + 0x62) = FUN_0010daf0;
    *(code **)(__s + 100) = FUN_0010da60;
    *(code **)(__s + 0x66) = FUN_0010da28;
    *(code **)(__s + 0x68) = FUN_0010da00;
    *(code **)(__s + 0x6a) = FUN_0010d9d8;
    *(code **)(__s + 0x4e) = FUN_0010d9d0;
    *(code **)(__s + 0x74) = FUN_0010d9b8;
    *(code **)(__s + 0x8e) = FUN_0010d984;
    *(code **)(__s + 0x96) = device_enable_spiclk;
    *(code **)(__s + 0x98) = device_disable_spiclk;
    *(code **)(__s + 0x90) = FUN_0010d974;
    *(code **)(__s + 0x92) = FUN_0010d96c;
    *param_3 = __s;
    *(code **)(__s + 0x94) = FUN_0010d964;
    *(code **)(__s + 0x9a) = FUN_0010d928;
    *(code **)(__s + 0x9c) = FUN_0010d900;
    *(code **)(__s + 0xa8) = FUN_0010d8ec;
    *(code **)(__s + 0xaa) = fnCa_send_cmd_to_ta;
    __android_log_print(3,"FingerGoodix","gxFingerPrint open succuss!");
    iVar1 = fnCa_OpenSession();
    if (iVar1 == 0) {
      __android_log_print(3,"FingerGoodix","before device_enable()",0);
      iVar1 = device_enable();
      if (iVar1 == 0) {
        __android_log_print(3,"FingerGoodix","fingerprint device enable");
        iVar1 = fnCa_Init(0);
        if (iVar1 == 0) {
          return 0;
        }
        __android_log_print(6,"FingerGoodix","fnCa_Init failed, result:%d");
        fnCa_CloseSession();
      }
      else {
        __android_log_print(6,"FingerGoodix","fingerprint device enable failed!");
        fnCa_CloseSession();
        __android_log_print(6,"FingerGoodix","fingerprint device enable failed! disable device");
      }
      device_disable();
      __android_log_print(6,"FingerGoodix","fingerprint device disbale device finish!");
      uVar2 = 0xffffffff;
    }
    else {
      __android_log_print(6,"FingerGoodix","OpenSession : %d!",iVar1);
      uVar2 = 0xffffffff;
    }
  }
  return uVar2;
}



void FUN_0010d8ec(void)

{
  fnCa_Init(0);
  return;
}



void FUN_0010d8f4(undefined8 param_1,undefined4 param_2)

{
  fnCa_Init(param_2);
  return;
}



int fnCa_send_cmd_to_ta(int param_1)

{
  undefined4 uVar1;
  int iVar2;
  
  if (param_1 == 0x19) {
    uVar1 = 0x82;
  }
  else {
    uVar1 = 0x83;
    if (param_1 != 0x1a) {
      uVar1 = 0;
    }
  }
  iVar2 = gx_ta_send_command(uVar1);
  __android_log_print(3,"FingerGoodix","fnCa_send_cmd_to_ta ret:%d, cmd_id:%d",iVar2,param_1);
  return -(uint)(iVar2 != 0);
}



void FUN_0010d900(void)

{
  __android_log_print(3,"FingerGoodix","fingerprint check reset.");
  device_check_reset();
  return;
}



void FUN_0010d928(undefined8 param_1,undefined4 param_2)

{
  __android_log_print(3,"FingerGoodix","fingerprint SetSafeClass. class = 0x%x",param_2);
  fnCa__SetSafeClass(param_2);
  return;
}



void FUN_0010d964(undefined8 param_1,undefined4 param_2)

{
  device_set_recognize_flag(param_2);
  return;
}



void FUN_0010d96c(void)

{
  device_set_screenoff_mode(1);
  return;
}



void FUN_0010d974(void)

{
  device_set_screenoff_mode(0);
  return;
}



undefined8 device_disable_spiclk(void)

{
  __android_log_print(3,"FingerGoodix","%s .\n","device_disable_spiclk");
  return 0;
}



undefined8 device_enable_spiclk(void)

{
  __android_log_print(3,"FingerGoodix","%s .\n","device_enable_spiclk");
  return 0;
}



void FUN_0010d984(void)

{
  __android_log_print(3,"FingerGoodix","%s %d \n","fingerprint_hal_pause_capture",0x10c);
  device_pause_capture();
  return;
}



void FUN_0010d9b8(undefined8 param_1,undefined8 param_2,undefined4 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6)

{
  fnCa_Fido_Recognize(param_2,param_3,param_4,param_5,param_6);
  return;
}



void FUN_0010d9d0(undefined8 param_1,undefined4 param_2)

{
  device_setSpeed(param_2);
  return;
}



void FUN_0010d9d8(void)

{
  __android_log_print(3,"FingerGoodix","fingerprint clear wait finger command.");
  device_clear_waitfinger();
  return;
}



void FUN_0010da00(void)

{
  __android_log_print(3,"FingerGoodix","fingerprint cancel wait finger command.");
  device_cancel_waitfinger();
  return;
}



void FUN_0010da28(undefined8 param_1,undefined8 param_2)

{
  __android_log_print(3,"FingerGoodix","fingerprint set notify function.");
  device_notify(param_2);
  return;
}



void FUN_0010da60(undefined8 param_1,undefined8 param_2)

{
  __android_log_print(3,"FingerGoodix","fingerprint get mode.");
  device_getMode(param_2);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0010da98(undefined8 param_1,undefined4 *param_2)

{
  long lVar1;
  long lVar2;
  
  lVar1 = ___stack_chk_guard;
  device_getMode();
  lVar2 = ___stack_chk_guard;
  *param_2 = 0;
  if (lVar1 == lVar2) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



void FUN_0010daf0(undefined8 param_1,undefined4 param_2)

{
  device_irq_control(param_2);
  return;
}



void FUN_0010daf8(undefined8 param_1,undefined4 param_2)

{
  __android_log_print(3,"FingerGoodix","fingerprint wait for finger up.");
  device_waitForFingerUp(param_2);
  return;
}



void FUN_0010db30(undefined8 param_1,undefined4 param_2)

{
  __android_log_print(3,"FingerGoodix","fingerprint wait for finger .");
  device_waitForFinger(param_2);
  return;
}



void FUN_0010db68(undefined8 param_1,undefined param_2,undefined8 param_3)

{
  __android_log_print(3,"FingerGoodix","fingerprint device action.");
  device_action(param_2,param_3);
  return;
}



void FUN_0010dba8(undefined8 param_1,undefined8 param_2)

{
  __android_log_print(3,"FingerGoodix","fingerprint get version.");
  device_getVersion(param_2);
  return;
}



void FUN_0010dbe0(undefined8 param_1,undefined4 param_2)

{
  __android_log_print(3,"FingerGoodix","fingerprint set mode. mode = 0x%x",param_2);
  device_setMode(param_2);
  return;
}



void FUN_0010dc1c(undefined8 param_1,undefined4 param_2)

{
  device_setMode(param_2);
  return;
}



void set_fp_enabled(undefined4 param_1)

{
  DAT_0012800c = param_1;
  return;
}



void FUN_0010dc28(undefined8 param_1,undefined4 param_2,undefined8 param_3,undefined8 param_4)

{
  __android_log_print(3,"FingerGoodix","fingerprint_gen_auth_token_hmac()");
  fnCa_gen_auth_token_hmac(param_1,param_2,param_3,param_4);
  return;
}



void FUN_0010dc80(undefined4 param_1)

{
  __android_log_print(3,"FingerGoodix","fingerprint_set_active_client()");
  fnCa_set_active_fpclient(param_1);
  return;
}



void FUN_0010dcb8(undefined4 param_1)

{
  __android_log_print(3,"FingerGoodix","fingerprint_set_active_group()");
  fnCa_set_active_group(param_1);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void fnCa_preprossor_init(void)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 uStack_10;
  undefined4 uStack_c;
  long lStack_8;
  
  uStack_10 = 0;
  uStack_c = 0;
  lStack_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","fnCa_preprossor_init");
  iVar1 = gx_ta_send_command(0x29,&uStack_c,4,&uStack_10,4);
  uVar2 = uStack_10;
  if (iVar1 != 0) {
    uVar2 = 0xffffffff;
  }
  if (lStack_8 != ___stack_chk_guard) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail(uVar2);
  }
  return;
}



void FUN_0010dcf4(undefined8 param_1,undefined4 param_2)

{
  fnCa_update_template(param_2);
  return;
}



void FUN_0010dcfc(undefined8 param_1,undefined8 param_2)

{
  fnCa_GetEnrollCnt(param_2);
  return;
}



void FUN_0010dd04(undefined8 param_1,undefined8 param_2,undefined4 param_3)

{
  fnCa_SetEnrollCnt(param_2,param_3);
  return;
}



void FUN_0010dd18(undefined8 param_1,undefined4 param_2,undefined8 param_3)

{
  fnCa_mp_test(param_2,param_3);
  return;
}



void FUN_0010dd24(undefined8 param_1,undefined8 param_2)

{
  fnCa_get_hardware_info(param_2);
  return;
}



void FUN_0010dd2c(undefined8 param_1,undefined8 param_2,undefined4 param_3)

{
  fnCa_del_bmp_template(param_2,param_3);
  return;
}



void FUN_0010dd38(undefined8 param_1,undefined8 param_2,undefined4 param_3,undefined8 param_4)

{
  fnCa_verify_bmp(param_2,param_3,param_4);
  return;
}



void FUN_0010dd48(undefined8 param_1,undefined8 param_2,undefined4 param_3)

{
  __android_log_print(3,"FingerGoodix","fingerprint dump data");
  fnCa_dump_data(param_2,param_3);
  return;
}



void FUN_0010dd88(undefined8 param_1,undefined8 param_2,undefined4 param_3)

{
  fnCa_reg_save(param_2,param_3);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void fnCa_reg_from_bmp_cancel(void)

{
  int iVar1;
  undefined4 uStack_10;
  undefined4 uStack_c;
  long lStack_8;
  
  uStack_10 = 0;
  uStack_c = 0;
  lStack_8 = ___stack_chk_guard;
  iVar1 = gx_ta_send_command(0x21,&uStack_c,4,&uStack_10,4);
  if (lStack_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(-(uint)(iVar1 != 0));
}



void FUN_0010dd98(undefined8 param_1,undefined8 param_2,undefined4 param_3,undefined8 param_4)

{
  fnCa_reg_from_bmp(param_2,param_3,param_4);
  return;
}



void FUN_0010dda8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined4 param_5)

{
  fnCa_GetBitmap(param_2,param_3,param_4,param_5);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void fnCa_DriverTest(void)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 uStack_10;
  undefined4 uStack_c;
  long lStack_8;
  
  uStack_10 = 0;
  uStack_c = 0;
  lStack_8 = ___stack_chk_guard;
  iVar1 = gx_ta_send_command(0x11,&uStack_c,4,&uStack_10,4);
  uVar2 = uStack_10;
  if (iVar1 != 0) {
    uVar2 = 0xffffffff;
  }
  if (lStack_8 != ___stack_chk_guard) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail(uVar2);
  }
  return;
}



void FUN_0010ddc0(undefined8 param_1,undefined8 param_2)

{
  fnCa_GetSessionID(param_2);
  return;
}



void FUN_0010ddc8(undefined8 param_1,undefined8 param_2)

{
  fnCa_SetSessionID(param_2);
  return;
}



void FUN_0010ddd0(undefined8 param_1,undefined4 param_2,undefined8 param_3,undefined4 param_4,
                 undefined8 param_5,undefined8 param_6)

{
  fnCa_ali_invoke_command(param_2,param_3,param_4,param_5,param_6);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void fnCa_LoadFpAlogParams(void)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 uStack_c;
  long lStack_8;
  
  uStack_c = 0;
  lStack_8 = ___stack_chk_guard;
  iVar1 = gx_ta_send_command(0x10,0,0,&uStack_c,4);
  uVar2 = uStack_c;
  if (iVar1 != 0) {
    uVar2 = 0xffffffff;
  }
  if (lStack_8 != ___stack_chk_guard) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail(uVar2);
  }
  return;
}



void FUN_0010ddec(undefined8 param_1,undefined8 param_2,undefined4 param_3)

{
  fnCa_VerifyFpPassword(param_2,param_3);
  return;
}



void FUN_0010ddf8(undefined8 param_1,undefined8 param_2,undefined4 param_3,undefined8 param_4,
                 undefined4 param_5)

{
  fnCa_ChangeFpPassword(param_2,param_3,param_4,param_5);
  return;
}



void FUN_0010de0c(undefined8 param_1,undefined8 param_2,undefined8 param_3)

{
  fnCa_GetFpTemplateIdList(param_2,param_3);
  return;
}



void FUN_0010de18(undefined8 param_1,undefined8 param_2,undefined4 param_3)

{
  fnCa_DelFpTemplates(param_2,param_3);
  return;
}



undefined8 fnCa_CancelRecognize(void)

{
  return 0;
}



void FUN_0010de28(undefined8 param_1,undefined4 param_2,undefined8 param_3,undefined4 param_4,
                 undefined8 param_5,undefined8 param_6)

{
  fnCa_Recognize(param_2,param_3,param_4,param_5,param_6);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void fnCa_enroll_verify(undefined8 *param_1)

{
  int iVar1;
  int iVar2;
  int iStack_40c;
  undefined8 uStack_408;
  undefined8 uStack_400;
  undefined8 uStack_3f8;
  undefined8 uStack_3f0;
  undefined8 uStack_3e8;
  undefined8 uStack_3e0;
  undefined8 uStack_3d8;
  undefined8 uStack_3d0;
  undefined4 uStack_3c8;
  undefined uStack_3c4;
  undefined auStack_3c3 [4];
  int iStack_3bf;
  int iStack_3bb;
  long lStack_8;
  
  lStack_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","fnCa_enroll_verify");
  iVar2 = -1;
  iStack_40c = -1;
  memset(&uStack_408,0,0x400);
  uStack_3e8 = param_1[4];
  uStack_3e0 = param_1[5];
  uStack_3c8 = *(undefined4 *)(param_1 + 8);
  uStack_408 = *param_1;
  uStack_400 = param_1[1];
  uStack_3f8 = param_1[2];
  uStack_3f0 = param_1[3];
  uStack_3c4 = *(undefined *)((long)param_1 + 0x44);
  uStack_3d8 = param_1[6];
  uStack_3d0 = param_1[7];
  iVar1 = getKeyFromKeymaster(auStack_3c3,0x3bb);
  __android_log_print(3,"FingerGoodix","fnCa_enroll_verify22");
  if (iVar1 == 0) {
    __android_log_print(3,"FingerGoodix","fnCa gen hmac, get key OK!");
    gx_ta_send_command(0x34,&uStack_408,iStack_3bf + iStack_3bb + 0x45,&iStack_40c,4);
    __android_log_print(3,"FingerGoodix","fnCa_enroll_verify:result:%d\n",iStack_40c);
    iVar2 = -(uint)(iStack_40c != 0);
  }
  else {
    __android_log_print(6,"FingerGoodix","get key failed! ret: %d",iVar1);
  }
  if (lStack_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(iVar2);
}



void FUN_0010de44(undefined8 param_1,undefined4 param_2,undefined8 param_3,undefined4 param_4)

{
  fnCa_ChangeFpNameById(param_2,param_3,param_4);
  return;
}



void FUN_0010de54(undefined8 param_1,undefined4 param_2,undefined8 param_3,undefined8 param_4)

{
  fnCa_GetFpNameById(param_2,param_3,param_4);
  return;
}



void FUN_0010de64(undefined8 param_1,undefined8 param_2,undefined4 param_3,undefined8 param_4)

{
  fnCa_SaveRegisteredFp(param_2,param_3,param_4);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void fnCa_CancelRegister(void)

{
  int iVar1;
  undefined4 uStack_10;
  undefined4 uStack_c;
  long lStack_8;
  
  uStack_10 = 0;
  uStack_c = 0;
  lStack_8 = ___stack_chk_guard;
  iVar1 = gx_ta_send_command(6,&uStack_c,4,&uStack_10,4);
  if (lStack_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(-(uint)(iVar1 != 0));
}



void FUN_0010de78(undefined8 param_1,undefined8 param_2)

{
  fnCa_Register(param_2);
  return;
}



undefined8 fnCa_SetModeCancel(void)

{
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void fnCa_Reset(void)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 uStack_c;
  long lStack_8;
  
  uStack_c = 0;
  lStack_8 = ___stack_chk_guard;
  iVar1 = gx_ta_send_command(2,0,0,&uStack_c,4);
  uVar2 = uStack_c;
  if (iVar1 != 0) {
    uVar2 = 0xffffffff;
  }
  if (lStack_8 != ___stack_chk_guard) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail(uVar2);
  }
  return;
}



undefined8 FUN_0010de88(void *param_1)

{
  undefined8 uVar1;
  
  if (param_1 == (void *)0x0) {
    uVar1 = 0xffffffff;
  }
  else {
    free(param_1);
    uVar1 = 0;
  }
  return uVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void netlink_thread(void)

{
  char cVar1;
  uint *puVar2;
  int __fd;
  __pid_t _Var3;
  int iVar4;
  uint uVar5;
  uint *puVar6;
  ssize_t sVar7;
  undefined4 *puVar8;
  ulong uVar9;
  int *piVar10;
  char *pcVar11;
  sockaddr local_70;
  undefined8 local_60;
  undefined4 local_58;
  iovec local_50;
  undefined local_40 [16];
  iovec *local_30;
  size_t local_28;
  void *local_20;
  size_t sStack_18;
  undefined8 local_10;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __fd = socket(0x10,3,0x19);
  if (__fd == -1) {
    piVar10 = (int *)__errno();
    pcVar11 = strerror(*piVar10);
    uVar9 = __android_log_print(6,"FingerGoodix","error getting socket: %s",pcVar11);
  }
  else {
    local_40._0_8_ = (void *)0x0;
    local_40._8_4_ = 0;
    local_40._12_4_ = 0;
    local_30 = (iovec *)0x0;
    local_28 = 0;
    local_20 = (void *)0x0;
    sStack_18 = 0;
    local_10._0_4_ = 0;
    local_10._4_4_ = 0;
    local_70.sa_data[6] = '\0';
    local_70.sa_data[7] = '\0';
    local_70.sa_data[8] = '\0';
    local_70.sa_data[9] = '\0';
    local_70.sa_family = 0x10;
    local_70.sa_data[0] = '\0';
    local_70.sa_data[1] = '\0';
    local_70.sa_data[2] = '\0';
    local_70.sa_data[3] = '\0';
    local_70.sa_data[4] = '\0';
    local_70.sa_data[5] = '\0';
    _Var3 = getpid();
    local_70.sa_data._2_4_ = _Var3;
    local_70.sa_data[6] = '\0';
    local_70.sa_data[7] = '\0';
    local_70.sa_data[8] = '\0';
    local_70.sa_data[9] = '\0';
    iVar4 = bind(__fd,&local_70,0xc);
    if (iVar4 < 0) {
      piVar10 = (int *)__errno();
      pcVar11 = strerror(*piVar10);
      __android_log_print(6,"FingerGoodix","bind failed: %s",pcVar11);
      uVar5 = close(__fd);
      uVar9 = (ulong)uVar5;
    }
    else {
      puVar6 = (uint *)malloc(0x410);
      nlh = puVar6;
      if (puVar6 != (uint *)0x0) {
        *puVar6 = 0x410;
        local_60 = 0x10;
        local_58 = 0;
        uVar5 = getpid();
        puVar2 = nlh;
        local_50.iov_base = nlh;
        puVar6[3] = uVar5;
        *(undefined2 *)((long)puVar2 + 6) = 0;
        *(undefined8 *)(puVar2 + 4) = 0x6f79206f6c6c6548;
        local_50.iov_len = (size_t)*puVar2;
        *(undefined2 *)(puVar2 + 6) = 0x2175;
        *(char *)((long)puVar2 + 0x1a) = '\0';
        local_40._0_8_ = &local_60;
        local_40._8_4_ = 0xc;
        local_40._12_4_ = 0;
        local_30 = &local_50;
        local_20 = (void *)0x0;
        sStack_18 = 0;
        local_10._0_4_ = 0;
        local_10._4_4_ = 0;
        local_28 = 1;
        sVar7 = sendmsg(__fd,(msghdr *)local_40,0);
        if ((int)sVar7 == -1) {
          piVar10 = (int *)__errno();
          pcVar11 = strerror(*piVar10);
          __android_log_print(6,"FingerGoodix","get error sendmsg = %s\n",pcVar11);
        }
        memset(nlh,0,0x410);
        do {
          sVar7 = recvmsg(__fd,(msghdr *)local_40,0);
          iVar4 = (int)sVar7;
          while( true ) {
            if (iVar4 < 0) {
              puVar8 = (undefined4 *)__errno();
              __android_log_print(3,"FingerGoodix","state<0, errno:%d",*puVar8);
            }
            cVar1 = *(char *)(nlh + 4);
            __android_log_print(3,"FingerGoodix","Received message: %d. gIRQFlag:%d\n",cVar1,
                                gIRQFlag);
            if ((cVar1 == '\0') && (gIRQFlag != 1)) break;
            gf_netlink_event(cVar1);
            sVar7 = recvmsg(__fd,(msghdr *)local_40,0);
            iVar4 = (int)sVar7;
          }
        } while( true );
      }
      __android_log_print(3,"FingerGoodix","malloc nlmsghdr error!\n");
      uVar5 = close(__fd);
      uVar9 = (ulong)uVar5;
    }
  }
  if (local_8 != ___stack_chk_guard) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail(uVar9);
  }
  return;
}



void init_netlink(void)

{
  int iVar1;
  
  __android_log_print(3,"FingerGoodix","Create netlink thread.\n");
  iVar1 = pthread_attr_init((pthread_attr_t *)&DAT_001284e8);
  if (iVar1 != 0) {
    __android_log_print(3,"FingerGoodix","Failed in pthread_attr_init. ret = %d\n",iVar1);
    return;
  }
  iVar1 = pthread_attr_setstacksize((pthread_attr_t *)&DAT_001284e8,0x20000);
  if (iVar1 == 0) {
    iVar1 = pthread_create(&DAT_00128520,(pthread_attr_t *)&DAT_001284e8,netlink_thread,(void *)0x0)
    ;
    if (iVar1 == 0) {
      return;
    }
    __android_log_print(3,"FingerGoodix","Failed in pthread_create. ret = %d\n",iVar1);
    return;
  }
  __android_log_print(3,"FingerGoodix","Failed in pthread_attr_setstacksize. ret = %d\n",iVar1);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void deinit_netlink(void)

{
  int iVar1;
  void *pvStack_10;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","Close netlink thread.\n");
  if (DAT_00128520 != 0) {
    iVar1 = pthread_attr_destroy((pthread_attr_t *)&DAT_001284e8);
    if (iVar1 != 0) {
      __android_log_print(3,"FingerGoodix","Failed in pthread_attr_destory. ret = %d\n",iVar1);
    }
    iVar1 = pthread_join(DAT_00128520,&pvStack_10);
    if (iVar1 == 0) {
      __android_log_print(3,"FingerGoodix","netlink channel exit code :\n");
    }
    else {
      __android_log_print(3,"FingerGoodix","Failed in  pthread_join.\n");
    }
    DAT_00128520 = 0;
  }
  free(nlh);
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(0);
}



undefined4 keymaster_ta_start(void)

{
  undefined4 uVar1;
  undefined4 *puVar2;
  
  uVar1 = 0;
  __android_log_print(3,"FingerGoodix",&DAT_001115f0,"keymaster_ta_start");
  if (g_keymaster_handle == 0) {
    uVar1 = QSEECom_start_app(&g_keymaster_handle,"/firmware/image",keymaster_name,comm_buf_size);
    puVar2 = (undefined4 *)__errno();
    __android_log_print(3,"FingerGoodix","Loading %s: ret=%d, errno=%d.",keymaster_name,uVar1,
                        *puVar2);
  }
  __android_log_print(3,"FingerGoodix","km handle=%p",g_keymaster_handle);
  return uVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void getKeyFromKeymaster(undefined4 *param_1,undefined4 param_2)

{
  int iVar1;
  int iVar2;
  int iVar3;
  undefined4 local_10;
  undefined4 local_c;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  keymaster_ta_start();
  if (g_keymaster_handle == 0) {
    iVar1 = 0;
  }
  else {
    iVar3 = 0;
    do {
      local_c = 2;
      local_10 = 0x205;
      iVar1 = QSEECom_send_cmd(g_keymaster_handle,&local_10,8,param_1,param_2);
      __android_log_print(3,"FingerGoodix",
                          "km get key ret:%d, token_rsp:%p, rsp.status:0x%x, rsp.offset:%d, rsp.len:%d"
                          ,iVar1,param_1,*param_1,param_1[1],param_1[2]);
      if ((5 < iVar3) || (iVar1 == 0)) {
        if (iVar3 < 6) {
          __android_log_print(3,"FingerGoodix","get key success.");
        }
        else {
          __android_log_print(6,"FingerGoodix","get key failed!");
          iVar1 = -1;
        }
        break;
      }
      iVar3 = iVar3 + 1;
      __android_log_print(3,"FingerGoodix","get key failed, will retry later.");
      iVar2 = usleep(100000);
      g_keymaster_handle = 0;
      keymaster_ta_start(iVar2);
    } while (g_keymaster_handle != 0);
  }
  if (local_8 != ___stack_chk_guard) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail(iVar1);
  }
  return;
}



undefined8 keymaster_ta_stop(void)

{
  int iVar1;
  undefined4 *puVar2;
  
  if (g_keymaster_handle == 0) {
    return 0;
  }
  iVar1 = QSEECom_shutdown_app(&g_keymaster_handle);
  if (iVar1 == 0) {
    g_keymaster_handle = 0;
    __android_log_print(3,"FingerGoodix","Unload %s succeed.",keymaster_name);
    return 0;
  }
  puVar2 = (undefined4 *)__errno();
  __android_log_print(6,"FingerGoodix","Unload %s failed: ret=%d, errno=%d",keymaster_name,iVar1,
                      *puVar2);
  return 0xffffffff;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0010e650(char *param_1,byte *param_2,int param_3,int param_4)

{
  byte *pbVar1;
  undefined8 uVar2;
  FILE *__s;
  size_t __n;
  byte *pbVar3;
  int iVar4;
  undefined2 local_408 [512];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  if ((((param_1 == (char *)0x0) || (param_2 == (byte *)0x0)) || (param_3 == 0)) || (param_4 == 0))
  {
    uVar2 = 0x3eb;
  }
  else {
    __s = fopen(param_1,"wb");
    if (__s == (FILE *)0x0) {
      uVar2 = 0;
    }
    else {
      iVar4 = 0;
      memset(local_408,0,0x400);
      do {
        pbVar1 = param_2 + (ulong)(param_3 - 1) + 1;
        pbVar3 = param_2;
        do {
          param_2 = pbVar3 + 1;
          sprintf((char *)local_408,"%d,",(ulong)*pbVar3);
          __n = strlen((char *)local_408);
          fwrite(local_408,1,__n,__s);
          pbVar3 = param_2;
        } while (param_2 != pbVar1);
        iVar4 = iVar4 + 1;
        local_408[0] = 10;
        fwrite(local_408,1,1,__s);
      } while (iVar4 != param_4);
      fflush(__s);
      fclose(__s);
      uVar2 = 0;
    }
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar2);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0010e79c(char *param_1,ushort *param_2,int param_3,int param_4)

{
  ushort *puVar1;
  undefined8 uVar2;
  FILE *__s;
  size_t __n;
  ushort *puVar3;
  int iVar4;
  undefined2 local_408 [512];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  if ((((param_1 == (char *)0x0) || (param_2 == (ushort *)0x0)) || (param_3 == 0)) || (param_4 == 0)
     ) {
    uVar2 = 0x3eb;
  }
  else {
    __s = fopen(param_1,"wb");
    if (__s == (FILE *)0x0) {
      uVar2 = 0;
    }
    else {
      iVar4 = 0;
      memset(local_408,0,0x400);
      do {
        puVar1 = param_2 + (ulong)(param_3 - 1) + 1;
        puVar3 = param_2;
        do {
          param_2 = puVar3 + 1;
          sprintf((char *)local_408,"%4d,",(ulong)*puVar3);
          __n = strlen((char *)local_408);
          fwrite(local_408,1,__n,__s);
          puVar3 = param_2;
        } while (param_2 != puVar1);
        iVar4 = iVar4 + 1;
        local_408[0] = 10;
        fwrite(local_408,1,1,__s);
      } while (iVar4 != param_4);
      fflush(__s);
      fclose(__s);
      uVar2 = 0;
    }
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar2);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0010e8ec(char *param_1,char *param_2)

{
  undefined8 uVar1;
  FILE *__stream;
  FILE *__s;
  size_t sVar2;
  undefined auStack_408 [1024];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","gf_dump_data_move_file");
  if ((param_1 == (char *)0x0) || (param_2 == (char *)0x0)) {
    uVar1 = 0x3eb;
  }
  else {
    __stream = fopen(param_2,"rb");
    if (__stream != (FILE *)0x0) {
      __s = fopen(param_1,"wb");
      if (__s != (FILE *)0x0) {
        ftell(__stream);
        memset(auStack_408,0,0x400);
        while( true ) {
          sVar2 = fread(auStack_408,1,0x400,__stream);
          if ((int)sVar2 < 1) break;
          fwrite(auStack_408,1,(long)(int)sVar2,__s);
        }
        remove(param_2);
        fclose(__stream);
        __stream = __s;
      }
      fclose(__stream);
    }
    uVar1 = 0;
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar1);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0010ea14(long param_1,undefined8 param_2,undefined8 param_3,undefined4 param_4,
                 undefined4 param_5)

{
  undefined4 uVar1;
  FILE *__s;
  size_t sVar2;
  byte *pbVar3;
  byte *pbVar4;
  char acStack_508 [256];
  char acStack_408 [1024];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","[%s] enter","gf_dump_base_frame");
  memset(acStack_508,0,0x100);
  sprintf(acStack_508,"%s%s_rawdata.csv",param_2,param_3);
  FUN_0010e79c(acStack_508,param_1 + 0x94f8,param_4,param_5);
  sprintf(acStack_508,"%s%s_kr.csv",param_2,param_3);
  FUN_0010e79c(acStack_508,param_1 + 0x78,param_4,param_5);
  sprintf(acStack_508,"%s%s_b.csv",param_2,param_3);
  uVar1 = FUN_0010e79c(acStack_508,param_1 + 0x4ab8,param_4,param_5);
  memset(acStack_408,0,0x400);
  sprintf(acStack_508,"%s%s_base_info.csv",param_2,param_3);
  __s = fopen(acStack_508,"wb");
  if (__s != (FILE *)0x0) {
    fwrite("preprocess version, ",1,0x14,__s);
    sVar2 = strlen((char *)(param_1 + 4));
    fwrite((char *)(param_1 + 4),1,sVar2,__s);
    fwrite(&DAT_001106f8,1,1,__s);
    fwrite("sensor id, ",1,0xb,__s);
    pbVar3 = (byte *)(param_1 + 100);
    do {
      pbVar4 = pbVar3 + 1;
      sprintf(acStack_408,"0x%02X, ",(ulong)*pbVar3);
      sVar2 = strlen(acStack_408);
      fwrite(acStack_408,1,sVar2,__s);
      pbVar3 = pbVar4;
    } while (pbVar4 != (byte *)(param_1 + 0x74));
    fwrite(&DAT_001106f8,1,1,__s);
    fwrite("chip id, ",1,9,__s);
    pbVar3 = (byte *)(param_1 + 0x44);
    do {
      pbVar4 = pbVar3 + 1;
      sprintf(acStack_408,"0x%02X, ",(ulong)*pbVar3);
      sVar2 = strlen(acStack_408);
      fwrite(acStack_408,1,sVar2,__s);
      pbVar3 = pbVar4;
    } while (pbVar4 != (byte *)(param_1 + 0x54));
    fwrite(&DAT_001106f8,1,1,__s);
    fwrite("vendor id, ",1,0xb,__s);
    pbVar3 = (byte *)(param_1 + 0x54);
    do {
      pbVar4 = pbVar3 + 1;
      sprintf(acStack_408,"0x%02X, ",(ulong)*pbVar3);
      sVar2 = strlen(acStack_408);
      fwrite(acStack_408,1,sVar2,__s);
      pbVar3 = pbVar4;
    } while ((byte *)(param_1 + 100) != pbVar4);
    fwrite(&DAT_001106f8,1,1,__s);
    fwrite("frame num, ",1,0xb,__s);
    sprintf(acStack_408,"%04d,",(ulong)*(uint *)(param_1 + 0x74));
    sVar2 = strlen(acStack_408);
    fwrite(acStack_408,1,sVar2,__s);
    fwrite(&DAT_001106f8,1,1,__s);
    fflush(__s);
    fclose(__s);
  }
  __android_log_print(3,"FingerGoodix","[%s] exit, err:%d","gf_dump_base_frame",uVar1);
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar1);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0010edbc(char *param_1)

{
  DIR *__dirp;
  dirent *pdVar1;
  undefined auStack_88 [128];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __dirp = opendir(param_1);
  if (__dirp == (DIR *)0x0) {
    __android_log_print(3,"FingerGoodix","[%s] cannot open directory: %s","hal_dump_empty_dir",
                        param_1);
  }
  else {
    chdir(param_1);
    while (pdVar1 = readdir(__dirp), pdVar1 != (dirent *)0x0) {
      lstat(pdVar1->d_name,(stat *)auStack_88);
      if ((auStack_88._16_4_ & 0xf000) == 0x8000) {
        remove(pdVar1->d_name);
      }
    }
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0010ee88(char *param_1)

{
  char *pcVar1;
  int iVar2;
  undefined2 *puVar3;
  size_t sVar4;
  char *pcVar5;
  undefined4 uVar6;
  char acStack_108 [256];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  memset(acStack_108,0,0x100);
  puVar3 = (undefined2 *)stpcpy(acStack_108,param_1);
  if (acStack_108[((int)puVar3 - (int)acStack_108) + -1] != '/') {
    *puVar3 = 0x2f;
  }
  sVar4 = strlen(acStack_108);
  if (1 < (int)sVar4) {
    pcVar5 = acStack_108 + 1;
    pcVar1 = acStack_108 + (ulong)((int)sVar4 - 2) + 2;
    do {
      while (*pcVar5 == '/') {
        *pcVar5 = '\0';
        iVar2 = access(acStack_108,0);
        if (iVar2 != 0) {
          iVar2 = mkdir(acStack_108,0x1ed);
          if (iVar2 == -1) {
            __android_log_print(6,"FingerGoodix","mkdir error");
            uVar6 = 0xffffffff;
            goto LAB_0010ef5c;
          }
        }
        *pcVar5 = '/';
        pcVar5 = pcVar5 + 1;
        if (pcVar5 == pcVar1) goto LAB_0010ef58;
      }
      pcVar5 = pcVar5 + 1;
    } while (pcVar5 != pcVar1);
  }
LAB_0010ef58:
  uVar6 = 0;
LAB_0010ef5c:
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar6);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void gf_dump_image_to_bmp_file(char *param_1,long param_2,uint param_3,int param_4)

{
  uint uVar1;
  undefined8 uVar2;
  FILE *__s;
  undefined local_15;
  int local_14;
  undefined4 local_10 [2];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  if ((((param_1 == (char *)0x0) || (param_2 == 0)) || (param_3 == 0)) || (param_4 == 0)) {
    uVar2 = 0x3eb;
  }
  else {
    uVar1 = param_3 + 3 & 0xfffffffc;
    DAT_001281c4 = uVar1 * param_4;
    DAT_001281aa = 0x436;
    DAT_001281a2 = DAT_001281c4 + 0x436;
    DAT_001281b0 = 0x28;
    DAT_001281b4 = param_3;
    DAT_001281b8 = param_4;
    __s = fopen(param_1,"wb");
    if (__s == (FILE *)0x0) {
      uVar2 = 0;
    }
    else {
      fwrite(&DAT_001281a0,1,2,__s);
      fwrite(&DAT_001281a2,1,4,__s);
      fwrite(&DAT_001281a6,1,2,__s);
      fwrite(&DAT_001281a8,1,2,__s);
      fwrite(&DAT_001281aa,1,4,__s);
      fwrite(&DAT_001281b0,1,0x28,__s);
      local_15 = 0;
      local_14 = 0;
      do {
        fwrite(&local_14,1,1,__s);
        fwrite(&local_14,1,1,__s);
        fwrite(&local_14,1,1,__s);
        fwrite(&local_15,1,1,__s);
        local_14 = local_14 + 1;
      } while (local_14 < 0x100);
      for (local_14 = param_4 + -1; -1 < local_14; local_14 = local_14 + -1) {
        fwrite((void *)(param_2 + (ulong)(param_3 * local_14)),1,(ulong)param_3,__s);
        if (param_3 < uVar1) {
          local_10[0] = 0;
          fwrite(local_10,1,(ulong)(uVar1 - param_3),__s);
        }
      }
      fflush(__s);
      fclose(__s);
      uVar2 = 0;
    }
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar2);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void gf_dump_data(int *param_1,uint param_2,undefined4 param_3,undefined4 param_4,long param_5)

{
  int *piVar1;
  int *piVar2;
  uint uVar3;
  int iVar4;
  tm *ptVar5;
  undefined8 uVar6;
  size_t sVar7;
  undefined4 *puVar8;
  char *pcVar9;
  int iVar10;
  undefined4 uVar11;
  time_t local_320;
  timeval tStack_318;
  undefined8 local_308;
  undefined8 uStack_300;
  undefined8 local_2f8;
  undefined4 local_2f0;
  undefined2 local_2ec;
  undefined8 local_208;
  undefined8 uStack_200;
  undefined8 local_1f8;
  undefined4 local_1f0;
  char acStack_1ec [228];
  undefined2 uStack_108;
  undefined auStack_106 [254];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  memset(&local_308,0,0x100);
  memset(&local_208,0,0x100);
  __android_log_print(3,"FingerGoodix","[%s] enter","gf_dump_data");
  if ((0xd < param_2 || param_5 == 0) || (param_1 == (int *)0x0)) {
    __android_log_print(6,"FingerGoodix","[%s] bad parameter","gf_dump_data");
    uVar6 = 0x3eb;
    goto LAB_0010f3a4;
  }
  __android_log_print(3,"FingerGoodix","[%s] operation:%d, result_str:%s","gf_dump_data",param_2,
                      param_5);
  local_320 = time((time_t *)0x0);
  memset(&uStack_108,0,0x100);
  ptVar5 = localtime(&local_320);
  gettimeofday(&tStack_318,(__timezone_ptr_t)0x0);
  sprintf((char *)&uStack_108,"%04d-%02d-%02d-%02d-%02d-%02d-%06ld",(ulong)(ptVar5->tm_year + 0x76c)
          ,(ulong)(ptVar5->tm_mon + 1),(ulong)(uint)ptVar5->tm_mday,(ulong)(uint)ptVar5->tm_hour,
          (ulong)(uint)ptVar5->tm_min,(ulong)(uint)ptVar5->tm_sec,tStack_318.tv_usec);
  uVar11 = (undefined4)((ulong)tStack_318.tv_usec >> 0x20);
  switch(param_2) {
  case 0:
  case 1:
  case 8:
    if (param_2 == 1) {
      sprintf((char *)&local_308,"%s%u/","/sdcard/gf_data/enroll/",(ulong)(uint)param_1[0x5cf3]);
    }
    else if (param_2 == 8) {
      local_308._0_1_ = '/';
      local_308._1_1_ = 's';
      local_308._2_1_ = 'd';
      local_308._3_1_ = 'c';
      local_308._4_1_ = 'a';
      local_308._5_1_ = 'r';
      local_308._6_1_ = 'd';
      local_308._7_1_ = '/';
      uStack_300._0_1_ = 'g';
      uStack_300._1_1_ = 'f';
      uStack_300._2_1_ = '_';
      uStack_300._3_1_ = 'd';
      uStack_300._4_1_ = 'a';
      uStack_300._5_1_ = 't';
      uStack_300._6_1_ = 'a';
      uStack_300._7_1_ = '/';
      local_2f8._0_1_ = 'f';
      local_2f8._1_1_ = 'r';
      local_2f8._2_1_ = 'r';
      local_2f8._3_1_ = '_';
      local_2f8._4_1_ = 'f';
      local_2f8._5_1_ = 'a';
      local_2f8._6_1_ = 'r';
      local_2f8._7_1_ = '/';
      local_2f0 = local_2f0 & 0xffffff00;
    }
    else {
      local_2f8._0_1_ = 'a';
      local_2f8._1_1_ = 'u';
      local_2f8._2_1_ = 't';
      local_2f8._3_1_ = 'h';
      local_2f8._4_1_ = 'e';
      local_2f8._5_1_ = 'n';
      local_2f8._6_1_ = 't';
      local_2f8._7_1_ = 'i';
      local_2f0._0_1_ = 'c';
      local_2f0._1_1_ = 'a';
      local_2f0._2_1_ = 't';
      local_2f0._3_1_ = 'e';
      local_2ec._0_1_ = '/';
      local_2ec._1_1_ = '\0';
      local_308._0_1_ = '/';
      local_308._1_1_ = 's';
      local_308._2_1_ = 'd';
      local_308._3_1_ = 'c';
      local_308._4_1_ = 'a';
      local_308._5_1_ = 'r';
      local_308._6_1_ = 'd';
      local_308._7_1_ = '/';
      uStack_300._0_1_ = 'g';
      uStack_300._1_1_ = 'f';
      uStack_300._2_1_ = '_';
      uStack_300._3_1_ = 'd';
      uStack_300._4_1_ = 'a';
      uStack_300._5_1_ = 't';
      uStack_300._6_1_ = 'a';
      uStack_300._7_1_ = '/';
    }
    iVar4 = FUN_0010ee88(&local_308);
    if (iVar4 < 0) {
      __android_log_print(6,"FingerGoodix","[%s] make directory(%s) fail:%d","gf_dump_data",
                          &local_308);
      uVar6 = 0;
      goto LAB_0010f3a4;
    }
    piVar2 = param_1 + 0x4a5e;
    FUN_0010ea14(param_1,&local_308,&uStack_108,param_3,param_4);
    sprintf((char *)&local_208,"%s%s_%s_calires.csv",&local_308,&uStack_108,param_5);
    FUN_0010e79c(&local_208,param_1 + 0x37ce,param_3,param_4);
    sprintf((char *)&local_208,"%s%s_%s_databmp.csv",&local_308,&uStack_108,param_5);
    FUN_0010e650(&local_208,piVar2,param_3,param_4);
    sprintf((char *)&local_208,"%s%s_%s_databmp.bmp",&local_308,&uStack_108,param_5);
    gf_dump_image_to_bmp_file(&local_208,piVar2,param_3,param_4);
    piVar1 = param_1 + 0x53a6;
    sprintf((char *)&local_208,"%s%s_%s_sitobmp.csv",&local_308,&uStack_108,param_5);
    FUN_0010e650(&local_208,piVar1,param_3,param_4);
    sprintf((char *)&local_208,"%s%s_%s_sitobmp.bmp",&local_308,&uStack_108,param_5);
    gf_dump_image_to_bmp_file(&local_208,piVar1,param_3,param_4);
    if (param_1[0x5cee] != 0) {
      piVar2 = piVar1;
    }
    if (param_2 == 1) {
      uVar3 = param_1[0x5cf2];
      pcVar9 = "%s%s_%s_selectbmp_%d_%d_%d_%d_%u.bmp";
      iVar4 = param_1[0x5cf1];
      iVar10 = param_1[0x5cf4];
LAB_0010f740:
      sprintf((char *)&local_208,pcVar9,&local_308,&uStack_108,param_5,(ulong)(uint)param_1[0x5cef],
              (ulong)(uint)param_1[0x5cf0],(ulong)uVar3,iVar4,uVar11,iVar10);
    }
    else {
      if (param_2 != 8) {
        uVar3 = param_1[0x5cf5];
        iVar4 = param_1[0x5cf6];
        pcVar9 = "%s%s_%s_selectbmp_%d_%d_%d_%u_%d.bmp";
        iVar10 = param_1[0x5cf7];
        goto LAB_0010f740;
      }
      sprintf((char *)&local_208,"%s%s_%s_selectbmp_%d_%d.bmp",&local_308,&uStack_108,param_5,
              (ulong)(uint)param_1[0x5cef],(ulong)(uint)param_1[0x5cf0]);
    }
    gf_dump_image_to_bmp_file(&local_208,piVar2,param_3,param_4);
    puVar8 = (undefined4 *)strstr((char *)&local_208,".bmp");
    *puVar8 = 0x7673632e;
    *(undefined *)(puVar8 + 1) = 0;
    uVar6 = FUN_0010e650(&local_208,piVar2,param_3,param_4);
    goto LAB_0010f3a4;
  case 2:
    FUN_0010edbc("/sdcard/gf_data/base/finger_base/");
    iVar4 = FUN_0010ee88("/sdcard/gf_data/base/finger_base/");
    if (iVar4 < 0) {
      __android_log_print(6,"FingerGoodix","[%s] make directory(%s) fail:%d","gf_dump_data",
                          "/sdcard/gf_data/base/finger_base/");
      uVar6 = 0;
    }
    else {
      uVar6 = FUN_0010ea14(param_1,"/sdcard/gf_data/base/finger_base/",&uStack_108,param_3,param_4);
      if (*param_1 != 0) {
        DAT_001281d8 = 0;
      }
    }
    goto LAB_0010f3a4;
  case 3:
  case 4:
    iVar4 = FUN_0010ee88("/sdcard/gf_data/test_sensor/");
    if (-1 < iVar4) {
      if (param_2 == 3) {
        sVar7 = strlen((char *)&uStack_108);
        *(undefined2 *)((long)&uStack_108 + sVar7) = 0x615f;
        *(undefined *)((long)&uStack_108 + sVar7 + 2) = 0;
      }
      else {
        sVar7 = strlen((char *)&uStack_108);
        *(undefined2 *)((long)&uStack_108 + sVar7) = 0x625f;
        *(undefined *)((long)&uStack_108 + sVar7 + 2) = 0;
      }
      local_208._0_1_ = '/';
      local_208._1_1_ = 's';
      local_208._2_1_ = 'd';
      local_208._3_1_ = 'c';
      local_208._4_1_ = 'a';
      local_208._5_1_ = 'r';
      local_208._6_1_ = 'd';
      local_208._7_1_ = '/';
      uStack_200._0_1_ = 'g';
      uStack_200._1_1_ = 'f';
      uStack_200._2_1_ = '_';
      uStack_200._3_1_ = 'd';
      uStack_200._4_1_ = 'a';
      uStack_200._5_1_ = 't';
      uStack_200._6_1_ = 'a';
      uStack_200._7_1_ = '/';
      local_1f8._0_1_ = 't';
      local_1f8._1_1_ = 'e';
      local_1f8._2_1_ = 's';
      local_1f8._3_1_ = 't';
      local_1f8._4_1_ = '_';
      local_1f8._5_1_ = 's';
      local_1f8._6_1_ = 'e';
      local_1f8._7_1_ = 'n';
      local_1f0._0_1_ = 's';
      local_1f0._1_1_ = 'o';
      local_1f0._2_1_ = 'r';
      local_1f0._3_1_ = '/';
      puVar8 = (undefined4 *)stpcpy(acStack_1ec,(char *)&uStack_108);
      *puVar8 = 0x7673632e;
      *(undefined *)(puVar8 + 1) = 0;
      uVar6 = FUN_0010e79c(&local_208,param_1 + 0x253e,param_3,param_4);
      goto LAB_0010f3a4;
    }
  default:
    uVar6 = 0;
    goto LAB_0010f3a4;
  case 5:
    pcVar9 = "/sdcard/gf_data/consistency/";
    iVar4 = FUN_0010ee88("/sdcard/gf_data/consistency/");
    if (-1 < iVar4) {
      __android_log_print(3,"FingerGoodix","[%s] OPERATION_TEST_BAD_POINT save data","gf_dump_data")
      ;
      sprintf((char *)&local_208,"%s%s_%d_rawdata.csv","/sdcard/gf_data/consistency/",&uStack_108,
              (ulong)(uint)param_1[0x1d]);
LAB_0010f480:
      uVar6 = FUN_0010e79c(&local_208,param_1 + 0x253e,param_3,param_4);
      goto LAB_0010f3a4;
    }
    break;
  case 9:
    pcVar9 = "/sdcard/gf_data/navigation/";
    iVar4 = FUN_0010ee88("/sdcard/gf_data/navigation/");
    if (-1 < iVar4) {
      sprintf((char *)&local_208,"%s%s_rawdata.csv","/sdcard/gf_data/navigation/",&uStack_108);
      goto LAB_0010f480;
    }
    break;
  case 10:
    pcVar9 = "/sdcard/gf_data/base/nav_base/";
    FUN_0010edbc("/sdcard/gf_data/base/nav_base/");
    iVar4 = FUN_0010ee88("/sdcard/gf_data/base/nav_base/");
    if (-1 < iVar4) {
      sprintf((char *)&local_208,"%s%s_rawdata.csv","/sdcard/gf_data/base/nav_base/",&uStack_108);
      uVar6 = FUN_0010e79c(&local_208,param_1 + 0x253e,param_3,param_4);
      DAT_001281d9 = 0;
      goto LAB_0010f3a4;
    }
  }
  __android_log_print(6,"FingerGoodix","[%s] make dir(%s) fail:%d","gf_dump_data",pcVar9);
  uVar6 = 0;
LAB_0010f3a4:
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar6);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void gf_dump_data_with_finger_id(long param_1)

{
  int iVar1;
  undefined8 uVar2;
  char *pcVar3;
  undefined4 *puVar4;
  undefined8 local_408;
  undefined8 uStack_400;
  undefined8 local_3f8;
  undefined4 local_3f0;
  undefined2 local_3ec;
  char acStack_308 [256];
  char acStack_208 [256];
  char acStack_108 [256];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","gf_dump_data_with_finger_id");
  if (param_1 != 0) {
    memset(&local_408,0,0x100);
    memset(acStack_308,0,0x100);
    memset(acStack_208,0,0x100);
    memset(acStack_108,0,0x100);
    if (*(int *)(param_1 + 4) == 1) {
      if (*(int *)(param_1 + 0xc) != 0) {
        local_3f8._0_1_ = 'e';
        local_3f8._1_1_ = 'n';
        local_3f8._2_1_ = 'r';
        local_3f8._3_1_ = 'o';
        local_3f8._4_1_ = 'l';
        local_3f8._5_1_ = 'l';
        local_3f8._6_1_ = '/';
        local_3f8._7_1_ = '\0';
        local_408._0_1_ = '/';
        local_408._1_1_ = 's';
        local_408._2_1_ = 'd';
        local_408._3_1_ = 'c';
        local_408._4_1_ = 'a';
        local_408._5_1_ = 'r';
        local_408._6_1_ = 'd';
        local_408._7_1_ = '/';
        uStack_400._0_1_ = 'g';
        uStack_400._1_1_ = 'f';
        uStack_400._2_1_ = '_';
        uStack_400._3_1_ = 'd';
        uStack_400._4_1_ = 'a';
        uStack_400._5_1_ = 't';
        uStack_400._6_1_ = 'a';
        uStack_400._7_1_ = '/';
        sprintf(acStack_308,"%s/%u/","/sdcard/gf_data/enroll/");
LAB_0010fa44:
        iVar1 = FUN_0010ee88(acStack_308);
        if (-1 < iVar1) {
          pcVar3 = stpcpy(acStack_108,acStack_308);
          puVar4 = (undefined4 *)stpcpy(pcVar3,&DAT_00128540);
          *puVar4 = 0x7478742e;
          *(undefined *)(puVar4 + 1) = 0;
          pcVar3 = stpcpy(acStack_208,(char *)&local_408);
          puVar4 = (undefined4 *)stpcpy(pcVar3,&DAT_00128540);
          *puVar4 = 0x7478742e;
          *(undefined *)(puVar4 + 1) = 0;
          FUN_0010e8ec(acStack_108,acStack_208);
          pcVar3 = stpcpy(acStack_108,acStack_308);
          puVar4 = (undefined4 *)stpcpy(pcVar3,&DAT_00128540);
          *puVar4 = 0x7673632e;
          *(undefined *)(puVar4 + 1) = 0;
          pcVar3 = stpcpy(acStack_208,(char *)&local_408);
          puVar4 = (undefined4 *)stpcpy(pcVar3,&DAT_00128540);
          *puVar4 = 0x7673632e;
          *(undefined *)(puVar4 + 1) = 0;
          FUN_0010e8ec(acStack_108,acStack_208);
          pcVar3 = stpcpy(acStack_108,acStack_308);
          puVar4 = (undefined4 *)stpcpy(pcVar3,&DAT_00128540);
          *puVar4 = 0x706d622e;
          *(char *)(puVar4 + 1) = '\0';
          pcVar3 = stpcpy(acStack_208,(char *)&local_408);
          puVar4 = (undefined4 *)stpcpy(pcVar3,&DAT_00128540);
          *puVar4 = 0x706d622e;
          *(char *)(puVar4 + 1) = '\0';
          FUN_0010e8ec(acStack_108,acStack_208);
        }
        goto LAB_0010fb6c;
      }
    }
    else {
      if (*(int *)(param_1 + 4) != 0) {
LAB_0010fb6c:
        uVar2 = 0;
        goto LAB_0010f9d8;
      }
      if (*(int *)(param_1 + 0xc) != 0) {
        local_3f8._0_1_ = 'a';
        local_3f8._1_1_ = 'u';
        local_3f8._2_1_ = 't';
        local_3f8._3_1_ = 'h';
        local_3f8._4_1_ = 'e';
        local_3f8._5_1_ = 'n';
        local_3f8._6_1_ = 't';
        local_3f8._7_1_ = 'i';
        local_408._0_1_ = '/';
        local_408._1_1_ = 's';
        local_408._2_1_ = 'd';
        local_408._3_1_ = 'c';
        local_408._4_1_ = 'a';
        local_408._5_1_ = 'r';
        local_408._6_1_ = 'd';
        local_408._7_1_ = '/';
        uStack_400._0_1_ = 'g';
        uStack_400._1_1_ = 'f';
        uStack_400._2_1_ = '_';
        uStack_400._3_1_ = 'd';
        uStack_400._4_1_ = 'a';
        uStack_400._5_1_ = 't';
        uStack_400._6_1_ = 'a';
        uStack_400._7_1_ = '/';
        local_3f0._0_1_ = 'c';
        local_3f0._1_1_ = 'a';
        local_3f0._2_1_ = 't';
        local_3f0._3_1_ = 'e';
        local_3ec._0_1_ = '/';
        local_3ec._1_1_ = '\0';
        sprintf(acStack_308,"%s%u/","/sdcard/gf_data/authenticate/");
        goto LAB_0010fa44;
      }
    }
  }
  uVar2 = 0x3eb;
LAB_0010f9d8:
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar2);
}



void gf_set_dump_data_flag(undefined param_1)

{
  DAT_00128640 = param_1;
  return;
}



uint gf_dump_data_flag(void)

{
  uint uVar1;
  
  uVar1 = property_get_bool("gf.debug.dump_data",0);
  if ((char)uVar1 < '\0') {
    uVar1 = 0;
  }
  return uVar1 | DAT_00128640;
}



void gf_set_dump_finger_base_flag(undefined param_1)

{
  DAT_001281d8 = param_1;
  return;
}



char gf_dump_finger_base_flag(void)

{
  char cVar1;
  
  cVar1 = gf_dump_data_flag();
  if (cVar1 != '\0') {
    cVar1 = DAT_001281d8 != '\0';
  }
  return cVar1;
}



char gf_dump_nav_base_flag(void)

{
  char cVar1;
  
  cVar1 = gf_dump_data_flag();
  if (cVar1 != '\0') {
    cVar1 = DAT_001281d9 != '\0';
  }
  return cVar1;
}



void gf_set_dump_nav_base_flag(undefined param_1)

{
  DAT_001281d9 = param_1;
  return;
}


