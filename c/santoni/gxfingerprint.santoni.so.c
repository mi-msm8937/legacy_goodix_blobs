typedef unsigned char   undefined;

typedef unsigned char    byte;
typedef unsigned char    dwfenc;
typedef unsigned int    dword;
typedef unsigned long    qword;
typedef unsigned int    uint;
typedef unsigned long    ulong;
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

typedef struct timezone timezone, *Ptimezone;

struct timezone {
    int tz_minuteswest;
    int tz_dsttime;
};

typedef struct itimerspec itimerspec, *Pitimerspec;

typedef struct timespec timespec, *Ptimespec;

typedef long __time_t;

struct timespec {
    __time_t tv_sec;
    long tv_nsec;
};

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

typedef uint __uid_t;

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

typedef union pthread_attr_t pthread_attr_t, *Ppthread_attr_t;

union pthread_attr_t {
    char __size[56];
    long __align;
};

typedef ulong pthread_t;

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

typedef struct Elf64_Sym Elf64_Sym, *PElf64_Sym;

struct Elf64_Sym {
    dword st_name;
    byte st_info;
    byte st_other;
    word st_shndx;
    qword st_value;
    qword st_size;
};




void FUN_00103e40(void)

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

ssize_t read(int __fd,void *__buf,size_t __nbytes)

{
  ssize_t sVar1;
  
  sVar1 = read(__fd,__buf,__nbytes);
  return sVar1;
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

ssize_t write(int __fd,void *__buf,size_t __n)

{
  ssize_t sVar1;
  
  sVar1 = write(__fd,__buf,__n);
  return sVar1;
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



void fs_mkdirs(void)

{
  fs_mkdirs();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int pthread_attr_setstacksize(pthread_attr_t *__attr,size_t __stacksize)

{
  int iVar1;
  
  iVar1 = pthread_attr_setstacksize(__attr,__stacksize);
  return iVar1;
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

long strtol(char *__nptr,char **__endptr,int __base)

{
  long lVar1;
  
  lVar1 = strtol(__nptr,__endptr,__base);
  return lVar1;
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



void property_get_int32(void)

{
  property_get_int32();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void pthread_exit(void *__retval)

{
                    // WARNING: Subroutine does not return
  pthread_exit(__retval);
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
  __cxa_finalize(&DAT_00127000);
  return;
}



void FUN_0010425c(code *param_1)

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
    iVar1 = DAT_001271e8;
    uVar2 = getpid();
    fcntl(iVar1,8,(ulong)uVar2);
    iVar1 = DAT_001271e8;
    uVar2 = fcntl(DAT_001271e8,3);
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
  
  iVar2 = DAT_001271e8;
  uVar1 = getpid();
  fcntl(iVar2,8,(ulong)uVar1);
  iVar2 = DAT_001271e8;
  uVar1 = fcntl(DAT_001271e8,3);
  iVar2 = fcntl(iVar2,4,(ulong)(uVar1 & 0xffffdfff));
  return iVar2;
}



undefined8 gf_enable_irq(void)

{
  int iVar1;
  undefined8 uVar2;
  
  __android_log_print(3,"FingerGoodix","gf_enable_irq");
  if (DAT_001271e8 == 0) {
    __android_log_print(6,"FingerGoodix","g_device_handle is NULL to do IOCTL Ops.\n");
    uVar2 = 0xffffff7f;
  }
  else {
    iVar1 = ioctl(DAT_001271e8,0x4701);
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
  if (DAT_001271e8 == 0) {
    __android_log_print(6,"FingerGoodix","g_device_handle is NULL to do IOCTL Ops.\n");
    uVar2 = 0xffffff7f;
  }
  else {
    iVar1 = ioctl(DAT_001271e8,0x4700);
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
  
  if (DAT_001271e8 == 0) {
    __android_log_print(6,"FingerGoodix","g_device_handle is NULL to do IOCTL Ops.\n");
    uVar2 = 0xffffff7f;
  }
  else {
    iVar1 = ioctl(DAT_001271e8,0x4703);
    uVar2 = 0;
    if (iVar1 < 0) {
      __android_log_print(6,"FingerGoodix","Failed to do GF_IOC_RESET.\n");
      uVar2 = 0xffffffff;
    }
  }
  return uVar2;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00104548(void)

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
      goto LAB_001045d8;
    }
    fnCa_FWUpdatePre(&local_9);
    if (local_9 != '\0') break;
    cVar2 = cVar2 + '\x01';
    __android_log_print(3,"FingerGoodix","Try to hold CPU. retry = %d\n",iVar4);
    iVar4 = iVar4 + 1;
    if (cVar2 == '\x05') {
      uVar3 = 0xffffffff;
      __android_log_print(3,"FingerGoodix","Failed to hold CPU in 5 times.\n");
LAB_001045d8:
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
  goto LAB_001045d8;
}



undefined8 gf_set_mode(undefined param_1)

{
  int iVar1;
  undefined8 uVar2;
  undefined local_1;
  
  local_1 = param_1;
  if (DAT_001271e8 == 0) {
    __android_log_print(6,"FingerGoodix","g_device_handle is NULL to do IOCTL Ops.\n");
    uVar2 = 0xffffff7f;
  }
  else {
    iVar1 = ioctl(DAT_001271e8,0x4001470d,&local_1);
    uVar2 = 0;
    if (iVar1 < 0) {
      __android_log_print(6,"FingerGoodix","Failed to do GF_IOC_SET_MODE.\n");
      uVar2 = 0xffffffff;
    }
  }
  return uVar2;
}



undefined8 gf_cool_boot(void)

{
  int iVar1;
  undefined8 uVar2;
  
  if (DAT_001271e8 == 0) {
    __android_log_print(6,"FingerGoodix","g_device_handle is NULL to do IOCTL Ops.\n");
    uVar2 = 0xffffff7f;
  }
  else {
    iVar1 = ioctl(DAT_001271e8,0x4704);
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
  if (DAT_001271e8 == 0) {
    __android_log_print(6,"FingerGoodix","g_device_handle is NULL to do IOCTL Ops.\n");
    uVar2 = 0xffffff7f;
  }
  else if (param_1 < 0xb71b01) {
    if (param_1 == DAT_001271ec) {
      __android_log_print(3,"FingerGoodix","Already in speed. [%d]\n");
      return 0;
    }
    DAT_001271ec = param_1;
    iVar1 = ioctl(DAT_001271e8,0x40044702,&local_4);
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
  
  __android_log_print(3,"FingerGoodix","gf_ready_spiclk. g_spi_clk = %d\n",DAT_001271f0);
  iVar1 = DAT_001271f0;
  if (DAT_001271f0 == 0) {
    DAT_001271f0 = 1;
    if (DAT_001271e8 == 0) {
      __android_log_print(6,"FingerGoodix","g_device_handle is NULL to do IOCTL Ops.\n");
      iVar1 = -0x81;
    }
    else {
      iVar1 = ioctl(DAT_001271e8,0x4706);
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
  
  __android_log_print(3,"FingerGoodix","gf_unready_spiclk. g_spi_clk = %d\n",DAT_001271f0);
  iVar1 = DAT_001271f0;
  if (DAT_001271f0 != 0) {
    DAT_001271f0 = 0;
    if (DAT_001271e8 == 0) {
      __android_log_print(6,"FingerGoodix","g_device_handle is NULL to do IOCTL Ops.\n");
      iVar1 = -0x81;
    }
    else {
      iVar1 = ioctl(DAT_001271e8,0x4707);
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
  if (DAT_001271e8 == 0) {
    __android_log_print(6,"FingerGoodix","g_device_handle is NULL to do IOCTL Ops.\n");
    uVar2 = 0xffffff7f;
  }
  else {
    iVar1 = ioctl(DAT_001271e8,0x4709);
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
  if (DAT_001271e8 == 0) {
    __android_log_print(6,"FingerGoodix","g_device_handle is NULL to do IOCTL Ops.\n");
    uVar2 = 0xffffff7f;
  }
  else {
    iVar1 = ioctl(DAT_001271e8,0x470a);
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
  
  if (DAT_001271e8 == 0) {
    __android_log_print(6,"FingerGoodix","g_device_handle is NULL to do IOCTL Ops.\n");
    uVar2 = 0xffffff7f;
  }
  else {
    iVar1 = ioctl(DAT_001271e8,0x4708,param_1);
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
  if (DAT_001271e8 == 0) {
    __android_log_print(6,"FingerGoodix","g_device_handle is NULL to do IOCTL Ops.\n");
    uVar2 = 0xffffff7f;
  }
  else {
    local_10 = CONCAT44(param_2,param_1);
    iVar1 = ioctl(DAT_001271e8,0x40084705,&local_10);
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
    uVar2 = FUN_00104548();
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
              FUN_00104548();
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
  pthread_mutex_lock((pthread_mutex_t *)&DAT_001271f8);
  if ((timerid != (timer_t)0x0) && (iVar1 = timer_delete(timerid), iVar1 == 0)) {
    __android_log_print(3,"FingerGoodix","delete timer success\n");
    timerid = (timer_t)0x0;
    iVar1 = pthread_mutex_unlock((pthread_mutex_t *)&DAT_001271f8);
    return iVar1;
  }
  timerid = (timer_t)0x0;
  iVar1 = pthread_mutex_unlock((pthread_mutex_t *)&DAT_001271f8);
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
  pthread_mutex_lock((pthread_mutex_t *)&DAT_001271f8);
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
        pthread_mutex_unlock((pthread_mutex_t *)&DAT_001271f8);
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
  
  iVar1 = pthread_mutex_lock((pthread_mutex_t *)&DAT_00127220);
  return iVar1;
}



int gf_esd_mutex_unlock(void)

{
  int iVar1;
  
  iVar1 = pthread_mutex_unlock((pthread_mutex_t *)&DAT_00127220);
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
  iVar1 = pthread_mutex_trylock((pthread_mutex_t *)&DAT_00127220);
  if (iVar1 == 0) {
    if ((DAT_001271ec == 4800000) && (1 < g_mode - 2U)) {
      uVar4 = 1;
      do {
        fnCa_FWIsUpdate(&local_9);
        if (local_9 == '\0') {
          gf_esd_check();
          gf_esd_mutex_unlock();
          goto LAB_0010522c;
        }
        if ((uVar4 & 0xff) == 3) {
          DAT_00127248 = DAT_00127248 + 1;
          __android_log_print(3,"FingerGoodix","Do update. esd check failed count %d \n");
          gf_fw_update();
          uVar3 = gf_esd_check();
        }
        else {
          __android_log_print(3,"FingerGoodix","%s %d count %d \n","loop_thread",0x1de,uVar4);
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
LAB_0010522c:
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
  if (DAT_001271e8 < 0) {
    __android_log_print(6,"FingerGoodix","g_device_handle is NULL to do IOCTL Ops.\n");
    uVar2 = 0xffffff7f;
  }
  else {
    iVar1 = ioctl(DAT_001271e8,0x470b);
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
  if (DAT_001271e8 == 0) {
    DAT_001271e8 = open("/dev/goodix_fp",2);
    if (DAT_001271e8 < 0) {
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
                            "/dev/goodix_fp",DAT_001271e8);
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
  if (DAT_001271e8 < 0) {
    __android_log_print(6,"FingerGoodix","g_device_handle is NULL to do IOCTL Ops.\n");
    uVar2 = 0xffffff7f;
  }
  else {
    __android_log_print(3,"FingerGoodix","%s,gf_release_gpio by ioctl","gf_release_gpio");
    iVar1 = ioctl(DAT_001271e8,0x470c);
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
  
  if (DAT_001271e8 == 0) {
    __android_log_print(3,"FingerGoodix","No device to be closed.\n");
    return;
  }
  __android_log_print(3,"FingerGoodix","Close device. Handle = %d\n");
  gf_release_gpio();
  __android_log_print(3,"FingerGoodix","%s,Close device,gf_release_gpio","gf_close");
  iVar1 = close(DAT_001271e8);
  __android_log_print(3,"FingerGoodix","Close device. Handle = %d\n, ret = %d",DAT_001271e8,iVar1);
  DAT_001271e8 = 0;
  return;
}



void FUN_0010560c(undefined4 param_1)

{
  switch(param_1) {
  case 1:
    __android_log_print(3,"FingerGoodix","NAV:KEY_LEFT\n",param_1);
    gf_send_key(0x69,1);
    gf_send_key(0x69,0);
    navResult = 9;
    return;
  case 2:
    __android_log_print(3,"FingerGoodix","NAV:KEY_RIGHT",param_1);
    gf_send_key(0x6a,1);
    gf_send_key(0x6a,0);
    navResult = 9;
    return;
  case 3:
    __android_log_print(3,"FingerGoodix","NAV:KEY_UP\n",param_1);
    gf_send_key(0x67,1);
    gf_send_key(0x67,0);
    navResult = 9;
    return;
  case 4:
    __android_log_print(3,"FingerGoodix","NAV:KEY_DOWN\n",param_1);
    gf_send_key(0x6c,1);
    gf_send_key(0x6c,0);
    navResult = 9;
    return;
  case 5:
    __android_log_print(3,"FingerGoodix","NAV:KEY_CLICK\n",param_1);
    gf_send_key(0xbd,1);
    gf_send_key(0xbd,0);
    navResult = 9;
    return;
  case 6:
    __android_log_print(3,"FingerGoodix","NAV:KEY_HEAVY\n",param_1);
    navResult = 9;
    return;
  case 7:
    __android_log_print(3,"FingerGoodix","NAV:TOO FAST.\n",param_1);
    navResult = 9;
    return;
  default:
    __android_log_print(3,"FingerGoodix","NAV: nav:%d\n",param_1);
    navResult = 9;
    return;
  case 10:
    __android_log_print(3,"FingerGoodix","NAV:NAV_DOUBLE\n",param_1);
    navResult = 9;
    return;
  case 0xb:
    __android_log_print(3,"FingerGoodix","NAV:NAV_LONG\n",param_1);
    navResult = 9;
    return;
  }
}



void FUN_00105894(undefined2 param_1)

{
  undefined2 local_2;
  
  local_2 = param_1;
  __android_log_print(3,"FingerGoodix","%s. status:%d, navResult:%d\n","NAV_DoSendKey",param_1,
                      navResult);
  if (navResult - 1 < 4) {
    FUN_0010560c();
    gf_delete_timer(&gx_doubleclicktimerid);
    DoubleClickCount = 0;
    DoubleClickFlag = 0;
    __android_log_print(3,"FingerGoodix","############## Set ic to up \n");
    return;
  }
  if ((navResult & 0xfffffffd) == 5) {
    if (DoubleClickFlag == 0) {
      navResult = 5;
      __android_log_print(3,"FingerGoodix","###### click !! \n");
      FUN_0010560c(navResult);
    }
    else if (DoubleClickCount == 2) {
      navResult = 10;
      __android_log_print(3,"FingerGoodix","###### double click !! \n");
      FUN_0010560c(navResult);
      gf_delete_timer(&gx_doubleclicktimerid);
      DoubleClickCount = 0;
      DoubleClickFlag = 0;
    }
  }
  else if (((navResult & 0xfffffff7) == 0) || (navResult == 6)) {
    __android_log_print(3,"FingerGoodix","##############################start again\n");
    fnCa_GetStatus(&local_2);
    __android_log_print(3,"FingerGoodix","###########%s status 0x%x \n","NAV_DoSendKey",local_2);
    fnCa_CleanStatus(local_2);
    fnCa_Cfg_FdtDown_Up(1);
    return;
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void NAV_dump(undefined4 param_1)

{
  undefined3 uVar1;
  int iVar2;
  char local_48 [8];
  ulong local_40;
  undefined8 local_38;
  undefined8 uStack_30;
  undefined8 local_28;
  undefined8 uStack_20;
  undefined8 local_18;
  undefined8 uStack_10;
  long local_8;
  
  local_48[0] = '\0';
  local_48[1] = '\0';
  local_48[2] = '\0';
  local_48[3] = '\0';
  local_48[4] = '\0';
  local_48[5] = '\0';
  local_48[6] = '\0';
  local_48[7] = '\0';
  local_40 = 0;
  local_38 = 0;
  uStack_30 = 0;
  local_8 = ___stack_chk_guard;
  local_28 = 0;
  uStack_20 = 0;
  local_18 = 0;
  uStack_10 = 0;
  iVar2 = property_get_int32("goodix.fp.debug",0);
  if (iVar2 == 1) {
    uVar1 = local_48._5_3_;
    switch(param_1) {
    case 0:
      local_48[0] = 'i';
      local_48[1] = 'n';
      local_48[2] = 'v';
      local_48[3] = 'a';
      local_48[4] = 'l';
      local_48[5] = 'i';
      local_48[6] = 'd';
      local_48[7] = '\0';
      break;
    case 1:
      local_48[0] = 'l';
      local_48[1] = 'e';
      local_48[2] = 'f';
      local_48[3] = 't';
      local_48[4] = '\0';
      local_48 = (char  [8])CONCAT35(uVar1,local_48._0_5_);
      break;
    case 2:
      local_48[0] = 'r';
      local_48[1] = 'i';
      local_48[2] = 'g';
      local_48[3] = 'h';
      local_48[4] = 't';
      local_48[5] = '\0';
      break;
    case 3:
      local_48[0] = 'u';
      local_48[1] = 'p';
      local_48[2] = '\0';
      break;
    case 4:
      local_48[0] = 'd';
      local_48[1] = 'o';
      local_48[2] = 'w';
      local_48[3] = 'n';
      local_48[4] = '\0';
      local_48 = (char  [8])CONCAT35(uVar1,local_48._0_5_);
      break;
    case 5:
      local_48[0] = 'c';
      local_48[1] = 'l';
      local_48[2] = 'i';
      local_48[3] = 'c';
      local_48[4] = 'k';
      local_48[5] = '\0';
      break;
    case 6:
      local_48[0] = 'h';
      local_48[1] = 'e';
      local_48[2] = 'a';
      local_48[3] = 'v';
      local_48[4] = 'y';
      local_48[5] = '\0';
      break;
    default:
      local_48[0] = 'f';
      local_48[1] = 'a';
      local_48[2] = 'i';
      local_48[3] = 'l';
      local_48[4] = '\0';
      local_48 = (char  [8])CONCAT35(uVar1,local_48._0_5_);
      break;
    case 8:
      local_48[0] = 'n';
      local_48[1] = 'u';
      local_48[2] = 'l';
      local_48[3] = 'l';
      local_48[4] = '\0';
      local_48 = (char  [8])CONCAT35(uVar1,local_48._0_5_);
      break;
    case 9:
      local_48[0] = 'c';
      local_48[1] = 'o';
      local_48[2] = 'm';
      local_48[3] = 'p';
      local_48[4] = 'l';
      local_48[5] = 'e';
      local_48[6] = 't';
      local_48[7] = 'e';
      local_40 = local_40 & 0xffffffffffffff00;
    }
    fnCa_dump_data(local_48,9);
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(0);
}



int GF_Navigation(ushort param_1)

{
  int iVar1;
  
  __android_log_print(3,"FingerGoodix","Signal in NAV\n");
  pthread_mutex_lock((pthread_mutex_t *)&DAT_00127258);
  __android_log_print(3,"FingerGoodix","NAV: status = 0x%x, gNav.eState:%d \n",param_1,DAT_00127284)
  ;
  if ((param_1 >> 1 & 1) == 0) {
    if ((param_1 >> 9 & 1) == 0) {
      if (param_1 == 0) goto LAB_00105c84;
      fnCa_CleanStatus(param_1);
      __android_log_print(3,"FingerGoodix","Should not come here. status:0x%x, state:%d\n",param_1,
                          DAT_00127284);
    }
    else {
      IsUpFlag = 1;
      fnCa_CleanStatus(param_1);
      __android_log_print(3,"FingerGoodix","Untouch\n");
      DAT_00127284 = 3;
    }
  }
  else {
    IsUpFlag = 0;
    DoubleClickTimeOutFlag = 0;
    gf_delete_timer(&gx_doubleclicktimerid);
    gf_doubleclick_init_timer(&gx_doubleclicktimerid,400000000,FUN_001060d0);
    LongPressFlag = 0;
    gf_delete_timer(&gx_longpresstimerid);
    gf_longpress_init_timer(&gx_longpresstimerid,1,FUN_00106088);
    fnCa_CleanStatus(param_1);
    __android_log_print(3,"FingerGoodix","Touch\n");
    DAT_00127284 = 2;
  }
  gf_disable_irq();
  if (DAT_00127284 != 0) {
    if (DAT_00127284 < 3) {
      __android_log_print(3,"FingerGoodix","Got Touch down Event when navigation\n");
      fnCa_Nav(&navResult,2);
      __android_log_print(3,"FingerGoodix","############ navResult %d \n",navResult);
      NAV_dump(navResult);
      if ((navResult & 0x7d) == 5) {
        DoubleClickFlag = 1;
        DoubleClickCount = DoubleClickCount + 1;
      }
      if ((navResult >> 7 & 1) == 0) {
        fnCa_UpdateFDTUpReg();
        DAT_00127284 = 0;
        fnCa_Cfg_FdtDown_Up(0);
      }
      else {
        __android_log_print(3,"FingerGoodix","Finger Untouched.\n");
        navResult = navResult & 0x7f;
        gf_delete_timer(&gx_longpresstimerid);
        fnCa_Cfg_FdtDown_Up(1);
        DAT_00127284 = 0;
        IsUpFlag = 1;
        FUN_00105894(param_1);
      }
      __android_log_print(3,"FingerGoodix","@@@@@gNav.eState = %d \n",DAT_00127284);
      gf_enable_irq();
      goto LAB_00105c84;
    }
    if (DAT_00127284 == 3) {
      __android_log_print(3,"FingerGoodix","%s Enter.\n","NAV_End");
      gf_delete_timer(&gx_longpresstimerid);
      DAT_00127284 = 0;
      fnCa_Cfg_FdtDown_Up(1);
      FUN_00105894(param_1);
      gf_enable_irq();
      goto LAB_00105c84;
    }
  }
  __android_log_print(3,"FingerGoodix","unexpect state. status:0x%x, state:%d\n",param_1);
  gf_enable_irq();
LAB_00105c84:
  __android_log_print(3,"FingerGoodix","LongPressFlag = %d\n",LongPressFlag);
  __android_log_print(3,"FingerGoodix",
                      "::::::::DoubleClickTimeOutFlag = %d,  DoubleClickFlag=%d, DoubleClickCount=%d\n"
                      ,DoubleClickTimeOutFlag,DoubleClickFlag,DoubleClickCount);
  if ((DoubleClickTimeOutFlag == 1) && (DoubleClickFlag == 1)) {
    if (IsUpFlag == 1) {
      navResult = 5;
      __android_log_print(3,"FingerGoodix","###### click !! \n");
      FUN_0010560c(navResult);
    }
    DoubleClickTimeOutFlag = 0;
    DoubleClickCount = 0;
    DoubleClickFlag = 0;
  }
  if (LongPressFlag == 1) {
    navResult = 0xb;
    __android_log_print(3,"FingerGoodix","###### long press !! \n");
    FUN_0010560c(navResult);
    LongPressFlag = 0;
    iVar1 = pthread_mutex_unlock((pthread_mutex_t *)&DAT_00127258);
    return iVar1;
  }
  iVar1 = pthread_mutex_unlock((pthread_mutex_t *)&DAT_00127258);
  return iVar1;
}



void FUN_00106088(void)

{
  gf_delete_timer(&gx_longpresstimerid);
  __android_log_print(3,"FingerGoodix","@@@@@@@gx_longpresstimerid timeout ~!!! \n");
  LongPressFlag = 1;
  GF_Navigation(0);
  return;
}



void FUN_001060d0(void)

{
  gf_delete_timer(&gx_doubleclicktimerid);
  __android_log_print(3,"FingerGoodix","@@@@@@@gx_doubleclicktimerid timeout ~!!! \n");
  DoubleClickTimeOutFlag = 1;
  GF_Navigation(0);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void GF_Navigation_F(int param_1,ushort param_2)

{
  char *pcVar1;
  ushort local_a;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","Signal in NAV\n");
  pthread_mutex_lock((pthread_mutex_t *)&DAT_00127258);
  __android_log_print(3,"FingerGoodix","NAV:g_state = %d, status = 0x%x, gNav.eState:%d \n",param_1,
                      param_2,DAT_00127284);
  if (param_1 == 1) {
    if (DAT_00127284 == 0) {
      LongPressFlag = 0;
      DoubleClickTimeOutFlag = 0;
      gf_delete_timer(&gx_doubleclicktimerid);
      gf_doubleclick_init_timer(&gx_doubleclicktimerid,400000000,FUN_001068c4);
      gf_delete_timer(&gx_longpresstimerid);
      gf_longpress_init_timer(&gx_longpresstimerid,1,FUN_00106878);
    }
    switch(DAT_00127284) {
    case 0:
      goto LAB_00106440;
    case 1:
    case 2:
      __android_log_print(3,"FingerGoodix",
                          "##################### %s, g_state=%d ,LongPressFlag = %d \n",
                          "NAV_DoNavInTA_f",1,LongPressFlag);
      break;
    case 3:
      fnCa_CleanStatus(param_2);
      local_a = param_2;
      __android_log_print(3,"FingerGoodix","%s Enter.\n","NAV_End_f");
      __android_log_print(3,"FingerGoodix","UnTouch.\n");
      DAT_00127284 = 0;
      fnCa_GetStatus(&local_a);
      fnCa_CleanStatus(local_a);
      fnCa_Cfg_FdtDown_Up(0);
      goto LAB_001061e0;
    default:
      goto switchD_0010635c_caseD_4;
    }
LAB_001066f4:
    __android_log_print(3,"FingerGoodix","Got Touch down Event when navigation\n");
    fnCa_Nav(&navResult,2);
    navResult = navResult & 0x7f;
    __android_log_print(3,"FingerGoodix","############ navResult %d \n",navResult);
    DAT_00127284 = 2;
    fnCa_Cfg_FdtDown_Up(0);
    gf_enable_irq();
  }
  else {
    if (param_1 != 3) {
      switch(DAT_00127284) {
      case 0:
        goto LAB_00106440;
      case 1:
      case 2:
        __android_log_print(3,"FingerGoodix",
                            "##################### %s, g_state=%d ,LongPressFlag = %d \n",
                            "NAV_DoNavInTA_f",param_1,LongPressFlag);
        break;
      case 3:
        goto switchD_001062b8_caseD_3;
      default:
        goto switchD_0010635c_caseD_4;
      }
LAB_001064ac:
      __android_log_print(3,"FingerGoodix","@@@@@gNav.eState = NAV_STATE_IDLE \n");
      DAT_00127284 = 0;
      gf_enable_irq();
      goto LAB_001061e0;
    }
    if (DoubleClickCount == 2) {
      __android_log_print(3,"FingerGoodix",
                          "@@@&&&@@@*****DoubleClickCount == 2, delete gx_doubleclicktimerid \n");
      gf_delete_timer(&gx_doubleclicktimerid);
      DoubleClickTimeOutFlag = 1;
    }
    gf_delete_timer(&gx_longpresstimerid);
    switch(DAT_00127284) {
    case 0:
LAB_00106440:
      fnCa_CleanStatus(param_2);
      gf_disable_irq();
      if ((param_2 >> 1 & 1) == 0) {
        __android_log_print(3,"FingerGoodix","Should not come here. status:0x%x, state:%d\n",param_2
                            ,DAT_00127284);
      }
      else {
        __android_log_print(3,"FingerGoodix","Touch\n");
        DAT_00127284 = 2;
        fnCa_SetMode(0x13);
      }
      __android_log_print(3,"FingerGoodix",
                          "##################### %s, g_state=%d ,LongPressFlag = %d \n",
                          "NAV_DoNavInTA_f",param_1,LongPressFlag);
      if (param_1 == 1) goto LAB_001066f4;
      if (param_1 != 3) goto LAB_001064ac;
      break;
    case 1:
    case 2:
      __android_log_print(3,"FingerGoodix",
                          "##################### %s, g_state=%d ,LongPressFlag = %d \n",
                          "NAV_DoNavInTA_f",3,LongPressFlag);
      break;
    case 3:
switchD_001062b8_caseD_3:
      fnCa_CleanStatus(param_2);
      local_a = param_2;
      __android_log_print(3,"FingerGoodix","%s Enter.\n","NAV_End_f");
      if (param_1 == 3) {
        __android_log_print(3,"FingerGoodix","UnTouch.\n");
        DAT_00127284 = 0;
        fnCa_GetStatus(&local_a);
        fnCa_CleanStatus(local_a);
        fnCa_Cfg_FdtDown_Up(1);
      }
      else {
        DAT_00127284 = 0;
        __android_log_print(3,"FingerGoodix","Should not come here. status:0x%x, state:%d\n",local_a
                            ,0);
      }
      goto LAB_001061e0;
    default:
switchD_0010635c_caseD_4:
      __android_log_print(3,"FingerGoodix","unexpect state. status:0x%x, state:%d\n",param_2);
      goto LAB_001061e0;
    }
    __android_log_print(3,"FingerGoodix","Got Touch up Event when navigation\n");
    if (navResult < 8) {
      if (navResult == 5) {
        __android_log_print(3,"FingerGoodix","@@@@@########@@@@ NAV_CLICK == navResult \n");
        DoubleClickCount = DoubleClickCount + 1;
        DoubleClickFlag = 1;
      }
      else {
        FUN_0010560c();
        DoubleClickCount = 0;
        DoubleClickFlag = 0;
        gf_delete_timer(&gx_doubleclicktimerid);
        gf_delete_timer(&gx_longpresstimerid);
      }
      DAT_00127284 = 0;
      __android_log_print(3,"FingerGoodix","############################## \n");
      fnCa_Cfg_FdtDown_Up(1);
      gf_enable_irq();
    }
    else {
      __android_log_print(3,"FingerGoodix","############################## \n");
      gf_hw_reset();
      fnCa_Cfg_FdtDown_Up(0);
      navResult = 0;
      DAT_00127284 = 3;
      gf_enable_irq();
    }
    gf_enable_irq();
  }
LAB_001061e0:
  __android_log_print(3,"FingerGoodix",
                      "::::::::DoubleClickTimeOutFlag = %d,  DoubleClickFlag=%d, DoubleClickCount=%d ,LongPressFlag = %d\n"
                      ,DoubleClickTimeOutFlag,DoubleClickFlag,DoubleClickCount,LongPressFlag);
  if ((DoubleClickTimeOutFlag == 1) && (DoubleClickFlag == 1)) {
    if (DoubleClickCount == 2) {
      pcVar1 = "###### double click !! \n";
      navResult = 10;
    }
    else {
      pcVar1 = "###### click !! \n";
      navResult = 5;
    }
    __android_log_print(3,"FingerGoodix",pcVar1);
    FUN_0010560c(navResult);
    DoubleClickTimeOutFlag = 0;
    DoubleClickCount = 0;
    DoubleClickFlag = 0;
    DAT_00127284 = 0;
  }
  if (LongPressFlag == 1) {
    navResult = 0xb;
    __android_log_print(3,"FingerGoodix","###### long press !! \n");
    FUN_0010560c(navResult);
    LongPressFlag = 0;
    DoubleClickCount = 0;
    DoubleClickFlag = 0;
    DAT_00127284 = 3;
  }
  pthread_mutex_unlock((pthread_mutex_t *)&DAT_00127258);
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



void FUN_00106878(void)

{
  gf_delete_timer(&gx_longpresstimerid);
  __android_log_print(3,"FingerGoodix","@@@@@@@gx_longpresstimerid timeout ~!!! \n");
  LongPressFlag = 1;
  GF_Navigation_F(0,0);
  return;
}



void FUN_001068c4(void)

{
  gf_delete_timer(&gx_doubleclicktimerid);
  __android_log_print(3,"FingerGoodix","@@@@@@@gx_doubleclicktimerid timeout ~!!! \n");
  DoubleClickTimeOutFlag = 1;
  GF_Navigation_F(0,0);
  return;
}



void GX_NavUpdateBase(void)

{
  fnCa_NavGetBase(DAT_00127288,0x800);
  return;
}



int GX_NavStateIdle(void)

{
  int iVar1;
  
  pthread_mutex_lock((pthread_mutex_t *)&DAT_00127318);
  gf_delete_timer(&gx_doubleclicktimerid);
  gf_delete_timer(&gx_longpresstimerid);
  DAT_00127284 = 0;
  iVar1 = pthread_mutex_unlock((pthread_mutex_t *)&DAT_00127318);
  return iVar1;
}



int mutex_get_lock(void)

{
  int iVar1;
  
  iVar1 = pthread_mutex_lock((pthread_mutex_t *)&DAT_00127370);
  return iVar1;
}



int mutex_get_unlock(void)

{
  int iVar1;
  
  iVar1 = pthread_mutex_unlock((pthread_mutex_t *)&DAT_00127370);
  return iVar1;
}



int gf_delete_timer(timer_t *param_1)

{
  int iVar1;
  
  __android_log_print(3,"FingerGoodix","delete timer \n");
  pthread_mutex_lock((pthread_mutex_t *)&DAT_00127398);
  if ((*param_1 != (timer_t)0x0) && (iVar1 = timer_delete(*param_1), iVar1 == 0)) {
    __android_log_print(3,"FingerGoodix","delete timer success\n");
    *param_1 = (timer_t)0x0;
    iVar1 = pthread_mutex_unlock((pthread_mutex_t *)&DAT_00127398);
    return iVar1;
  }
  *param_1 = (timer_t)0x0;
  iVar1 = pthread_mutex_unlock((pthread_mutex_t *)&DAT_00127398);
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
  gf_ready_spiclk();
  cVar2 = fnCa_MFKeyFDT_isTouchedByFinger();
  if (cVar2 == '\0') {
    __android_log_print(3,"FingerGoodix","===> Touch caused by Temperature.");
    fnCa_preprossor_init();
    iVar1 = g_mode;
    if (g_mode == 1) {
      __android_log_print(3,"FingerGoodix","DETECT FDT DOWN.");
      g_state = iVar1;
      fnCa_Cfg_FdtDown_Up(1);
    }
  }
  else {
    __android_log_print(3,"FingerGoodix","===> Touch By Finger. touch_by_finger:%d\n",cVar2);
    g_state = 3;
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
  pthread_mutex_lock((pthread_mutex_t *)&DAT_00127398);
  if (*param_1 == (timer_t)0x0) {
    local_48.sigev_value.sival_int = 0xff;
    local_48.sigev_notify = 2;
    local_48._sigev_un._sigev_thread._function = param_3;
    iVar1 = timer_create(0,&local_48,param_1);
    if (iVar1 == -1) {
      __android_log_print(3,"FingerGoodix","fail to timer_create");
      pthread_mutex_unlock((pthread_mutex_t *)&DAT_00127398);
    }
    else {
      iVar1 = timer_settime(*param_1,0,&local_68,(itimerspec *)0x0);
      if (iVar1 == -1) {
        __android_log_print(3,"FingerGoodix","fail to timer_settime");
        timer_delete(*param_1);
        pthread_mutex_unlock((pthread_mutex_t *)&DAT_00127398);
      }
      else {
        pthread_mutex_unlock((pthread_mutex_t *)&DAT_00127398);
        __android_log_print(3,"FingerGoodix","init and start timer success \n");
      }
    }
  }
  else {
    __android_log_print(3,"FingerGoodix","timer has been create \n");
    pthread_mutex_unlock((pthread_mutex_t *)&DAT_00127398);
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
  pthread_mutex_lock((pthread_mutex_t *)&DAT_00127398);
  if (*param_1 == (timer_t)0x0) {
    local_48.sigev_value.sival_int = 0xff;
    local_48.sigev_notify = 2;
    local_48._sigev_un._sigev_thread._function = param_3;
    iVar1 = timer_create(0,&local_48,param_1);
    if (iVar1 == -1) {
      __android_log_print(3,"FingerGoodix","fail to timer_create");
      pthread_mutex_unlock((pthread_mutex_t *)&DAT_00127398);
    }
    else {
      iVar1 = timer_settime(*param_1,0,&local_68,(itimerspec *)0x0);
      if (iVar1 == -1) {
        __android_log_print(3,"FingerGoodix","fail to timer_settime");
        timer_delete(*param_1);
        pthread_mutex_unlock((pthread_mutex_t *)&DAT_00127398);
      }
      else {
        pthread_mutex_unlock((pthread_mutex_t *)&DAT_00127398);
        __android_log_print(3,"FingerGoodix","init and start timer success \n");
      }
    }
  }
  else {
    __android_log_print(3,"FingerGoodix","timer has been create \n");
    pthread_mutex_unlock((pthread_mutex_t *)&DAT_00127398);
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
  pthread_mutex_lock((pthread_mutex_t *)&DAT_00127398);
  if (*param_1 == (timer_t)0x0) {
    local_48.sigev_value.sival_int = 0xff;
    local_48.sigev_notify = 2;
    local_48._sigev_un._sigev_thread._function = param_3;
    iVar1 = timer_create(0,&local_48,param_1);
    if (iVar1 == -1) {
      __android_log_print(3,"FingerGoodix","fail to timer_create");
      pthread_mutex_unlock((pthread_mutex_t *)&DAT_00127398);
    }
    else {
      iVar1 = timer_settime(*param_1,0,&local_68,(itimerspec *)0x0);
      if (iVar1 == -1) {
        __android_log_print(3,"FingerGoodix","fail to timer_settime");
        timer_delete(*param_1);
        pthread_mutex_unlock((pthread_mutex_t *)&DAT_00127398);
      }
      else {
        pthread_mutex_unlock((pthread_mutex_t *)&DAT_00127398);
        __android_log_print(3,"FingerGoodix","init and start timer success \n");
      }
    }
  }
  else {
    __android_log_print(3,"FingerGoodix","timer has been create \n");
    pthread_mutex_unlock((pthread_mutex_t *)&DAT_00127398);
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
  if (((uint)uVar2 >> 1 & 1) == 0) {
    if (((uint)uVar2 >> 9 & 1) != 0) {
      __android_log_print(3,"FingerGoodix","######INT status  = 0x%x \n",uVar2);
      fnCa_CleanStatus(uVar2);
      param_1 = (ulong)g_state;
      if (g_state == 3) goto LAB_00107230;
    }
  }
  else {
    param_1 = fnCa_CleanStatus(uVar2);
    if (g_state == 1) {
      __android_log_print(3,"FingerGoodix","IMAGE:key touch_status = 0x%x, g_state = %d \n",uVar2,1)
      ;
      g_state = 2;
      uVar1 = sem_post((sem_t *)g_down_sem);
      return (ulong)uVar1;
    }
    if (g_state == 3) {
      param_1 = 3;
LAB_00107230:
      __android_log_print(param_1,"FingerGoodix","IMAGE:key touch_status = 0x%x, g_state = %d \n",
                          uVar2,3);
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
    if ((param_1 >> 9 & 1) == 0) {
      __android_log_print(3,"FingerGoodix","Invalid status:0x%x in mode[%d]\n",param_1,g_mode);
      return;
    }
    __android_log_print(3,"FingerGoodix","######INT status  = 0x%x \n",param_1);
    fnCa_CleanStatus(param_1);
    if (g_state == 3) {
      __android_log_print(3,"FingerGoodix","KEY:key up touch_status = 0x%x, g_state = %d \n",param_1
                          ,3);
      (*event_notify)(4,0,0);
      gf_send_key(0x66,0);
      g_state = 1;
      gf_delete_timer(&gx_timerid);
      fnCa_UpdateFDTDownUp(0);
      fnCa_Cfg_FdtDown_Up(1);
      return;
    }
  }
  else {
    fnCa_CleanStatus(param_1);
    if (g_state == 1) {
      __android_log_print(3,"FingerGoodix","KEY:key down touch_status = 0x%x, g_state = %d \n",
                          param_1,1);
      (*event_notify)(3,0,0);
      gf_send_key(0xd4,1);
      g_state = 3;
      fnCa_Cfg_FdtDown_Up(0);
      gf_init_timer(&gx_timerid,5,gx_loop_thread);
      return;
    }
    if (g_state == 3) {
      __android_log_print(3,"FingerGoodix","KEY:key up touch_status = 0x%x, g_state = %d \n",param_1
                          ,3);
      gf_send_key(0xd4,0);
      g_state = 1;
      fnCa_Cfg_FdtDown_Up(1);
      gf_delete_timer(&gx_timerid);
      return;
    }
  }
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
    if ((param_1 >> 9 & 1) == 0) {
      uVar2 = __android_log_print(3,"FingerGoodix","Invalid status:0x%x in mode[%d]\n",param_1,
                                  g_mode);
      return uVar2;
    }
    __android_log_print(3,"FingerGoodix","######INT status  = 0x%x \n",param_1);
    fnCa_CleanStatus(param_1);
    uVar2 = (ulong)g_state;
    if (g_state == 3) {
LAB_001075b8:
      __android_log_print(uVar2,"FingerGoodix","FF:key touch_status = 0x%x, g_state = %d \n",param_1
                          ,3);
      fnCa_UpdateFDTDownUp(0);
      uVar1 = sem_post((sem_t *)g_up_sem);
      return (ulong)uVar1;
    }
  }
  else {
    uVar2 = fnCa_CleanStatus(param_1);
    if (g_state == 1) {
      DAT_001273c0 = g_state;
      __android_log_print(3,"FingerGoodix","FF:key touch_status = 0x%x, g_state = %d \n",param_1,1,
                          DAT_001273c4);
      g_state = 2;
      uVar1 = sem_post((sem_t *)g_down_sem);
      return (ulong)uVar1;
    }
    if (g_state == 3) {
      uVar2 = 3;
      goto LAB_001075b8;
    }
  }
  return uVar2;
}



void sig_in_nav(short param_1)

{
  if (DAT_001273c8 != 0x2202) {
    GF_Navigation(param_1);
    return;
  }
  if ((param_1 != 0x200) && (param_1 != 2)) {
    __android_log_print(3,"FingerGoodix",
                        "In sig_in_nav should not came here. cur_mode:%d,cur_state:%d",g_mode,
                        g_state);
    return;
  }
  if (g_state == 1) {
    GF_Navigation_F();
    g_state = 3;
  }
  else if (g_state == 3) {
    GF_Navigation_F();
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
  int iVar1;
  uint uVar2;
  ushort local_a;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  iVar1 = get_fp_enabled();
  if (iVar1 == 0) goto LAB_00107738;
  mutex_get_lock();
  if (param_1 != '\0') {
    __android_log_print(3,"FingerGoodix","no found command \n");
    mutex_get_unlock();
    goto LAB_00107738;
  }
  if ((g_mode == 2) && (g_state != 4)) {
    __android_log_print(6,"FingerGoodix","INT in Sleep mode.\n");
    mutex_get_unlock();
    goto LAB_00107738;
  }
  __android_log_print(3,"FingerGoodix","g_mode = %d\n");
  gf_ready_spiclk();
  fnCa_GetStatus(&local_a);
  __android_log_print(3,"FingerGoodix","%s %d status 0x%x g_mode %d g_state %d \n",
                      "gf_netlink_event",0x1cf,local_a,g_mode,g_state);
  if (((local_a & DAT_001273cc) == 0) || (local_a == 0x4400)) {
    uVar2 = (uint)local_a;
    if (((uVar2 & 0xffffff7f) == 2 || uVar2 == 8) ||
       (((uVar2 == 0x80 || (uVar2 == _DAT_001273d4)) || ((local_a & 0xfffd) == 0x200)))) {
      if ((local_a != 0x202 && local_a != 0x82) && ((local_a >> 7 & 1) != 0)) {
        fnCa_CleanStatus();
        __android_log_print(3,"FingerGoodix","Found REVERSE INT \n");
        if (DAT_001273d0 == 0) {
          __android_log_print(3,"FingerGoodix",
                              "#################### recv reverse int ,so update fdt base \n");
          fnCa_UpdateFDTDownUp(0);
        }
        else {
          fnCa_preprossor_init();
        }
        fnCa_Cfg_FdtDown_Up(1);
        DAT_001273d0 = 0;
        mutex_get_unlock();
        goto LAB_00107738;
      }
      if (g_mode == 2) {
        sig_in_sleep();
        mutex_get_unlock();
        goto LAB_00107738;
      }
      if (g_mode < 3) {
        if (g_mode == 0) {
          if (g_state != 0) {
            sig_in_image();
            mutex_get_unlock();
            goto LAB_00107738;
          }
          goto LAB_0010786c;
        }
        if (g_mode == 1) {
          sig_in_key();
          mutex_get_unlock();
          goto LAB_00107738;
        }
      }
      else {
        if (g_mode == 0x10) {
          sig_in_nav();
          mutex_get_unlock();
          goto LAB_00107738;
        }
        if (g_mode == 0x56) {
          sig_in_debug();
          mutex_get_unlock();
          goto LAB_00107738;
        }
        if (g_mode == 3) {
          sig_in_ff();
          mutex_get_unlock();
          goto LAB_00107738;
        }
      }
      __android_log_print(6,"FingerGoodix","Bad mode:%d\n");
      mutex_get_unlock();
      goto LAB_00107738;
    }
    __android_log_print(3,"FingerGoodix","#### Invalid int. g_mode = %d\n",g_mode);
    if ((g_mode == 3) && (g_state != 2)) {
      gf_unready_spiclk();
      mutex_get_unlock();
      goto LAB_00107738;
    }
  }
  else {
    fnCa_CleanStatus();
    __android_log_print(3,"FingerGoodix","Found RESET INT \n");
    fnCa_ResetChip();
    fnCa_SetMode(4);
    if (g_state == 4) {
      __android_log_print(3,"FingerGoodix","receive reset for check reset event \n");
      iVar1 = sem_post((sem_t *)g_check_reset_sem);
      mutex_get_unlock(iVar1);
      goto LAB_00107738;
    }
    if ((g_mode == 3) || (g_mode < 2)) {
      if (g_state == 1) {
        fnCa_Cfg_FdtDown_Up();
        DAT_001273d0 = 0;
        mutex_get_unlock();
        goto LAB_00107738;
      }
      if (g_state == 3) {
        fnCa_Cfg_FdtDown_Up(0);
        mutex_get_unlock();
        goto LAB_00107738;
      }
    }
    else {
      if (g_mode == 0x10) {
        gf_hw_reset();
        fnCa_SetMode(4);
        gf_set_speed(9600000);
        fnCa_Cfg_FdtDown_Up(1);
        GX_NavStateIdle();
        mutex_get_unlock();
        goto LAB_00107738;
      }
      __android_log_print(3,"FingerGoodix","CHIP RESET INT set to previos mode again. mode is %d");
      fnCa_SetMode(g_mode);
    }
  }
LAB_0010786c:
  mutex_get_unlock();
LAB_00107738:
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



undefined4 device_enable(void)

{
  int iVar1;
  undefined4 uVar2;
  
  iVar1 = gf_open();
  if (iVar1 == 0) {
    gf_ready_spiclk();
    gf_hw_reset();
    iVar1 = fnCa_OpenSession();
    uVar2 = 0;
    if (iVar1 != 0) {
      uVar2 = 0xffffffff;
      __android_log_print(6,"FingerGoodix","OpenSession : %d!",iVar1);
    }
  }
  else {
    uVar2 = 0xffffffff;
    __android_log_print(6,"FingerGoodix","Failed to open device.\n");
  }
  return uVar2;
}



undefined8 init_thread(void)

{
  init_netlink();
  sem_init((sem_t *)g_down_sem,0,0);
  sem_init((sem_t *)g_up_sem,0,0);
  sem_init((sem_t *)g_sigio_sem,0,0);
  sem_init((sem_t *)g_check_reset_sem,0,0);
  DAT_001273c4 = 0;
  g_state = 0;
  return 0;
}



undefined8 device_disable(void)

{
  g_state = 0;
  deinit_netlink();
  gf_close();
  DAT_001273c4 = 1;
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
  undefined2 local_2e;
  int local_2c;
  timespec local_28;
  timeval local_18;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  local_2c = 0;
  local_2e = 0;
  g_state = 1;
  __android_log_print(3,"FingerGoodix","===> Waiting Finger Down timeout_ms %d \n",param_1);
  mutex_get_lock();
  sem_getvalue((sem_t *)g_down_sem,&local_2c);
  iVar1 = local_2c;
  if (local_2c != 0) {
    iVar1 = sem_trywait((sem_t *)g_down_sem);
    g_state = 1;
  }
  gf_ready_spiclk(iVar1);
  __android_log_print(3,"FingerGoodix","%s FDT DOWN. Sem_value: %d\n","device_waitForFinger",
                      local_2c);
  fnCa_Cfg_FdtDown_Up(1);
  DAT_001273d0 = 0;
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
      if (iVar2 == -1) {
        piVar3 = (int *)__errno();
        if (*piVar3 == 0x6e) {
          if (DAT_001273c4 == '\x01') {
            uVar4 = 1;
            __android_log_print(3,"FingerGoodix","Wait for finger down canceled.");
            goto LAB_00107e10;
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
            __android_log_print(3,"FingerGoodix","got down status 0x%x=================\n",local_2e)
            ;
            gf_ready_spiclk();
            (*event_notify)(1,0,0);
          }
          goto LAB_00107e24;
        }
        __android_log_print(3,"FingerGoodix","Unknown return value.\n");
      }
    } while ((param_1 < 1) || (iVar1 = iVar1 + -0x32, 0 < iVar1));
    uVar4 = 0x83;
    fnCa_GetStatus(&local_2e);
    __android_log_print(3,"FingerGoodix","wait finger down time out status %d \n",local_2e);
LAB_00107e10:
    g_state = 0;
    iVar1 = gf_enable_irq();
    if (iVar1 < 0) {
      __android_log_print(3,"FingerGoodix","Failed to set para in gf_enable_irq.\n");
    }
  }
LAB_00107e24:
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar4);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void device_waitForFingerUp(int param_1)

{
  int iVar1;
  int iVar2;
  undefined4 *puVar3;
  int *piVar4;
  undefined8 uVar5;
  int local_2c;
  timespec local_28;
  timeval local_18;
  long local_8;
  
  local_2c = 0;
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","===> Wait Finger Up. g_up_ignore = %d\n",DAT_001273c0);
  if (DAT_001273c0 == 2) {
    DAT_001273c0 = 0;
  }
  g_state = 3;
  mutex_get_lock();
  sem_getvalue((sem_t *)g_up_sem,&local_2c);
  if (local_2c != 0) {
    sem_trywait((sem_t *)g_up_sem);
  }
  __android_log_print(3,"FingerGoodix","%s UP \n","device_waitForFingerUp");
  gf_ready_spiclk();
  fnCa_Cfg_FdtDown_Up(0);
  iVar1 = gf_enable_irq();
  if (iVar1 < 0) {
    uVar5 = 0xffffffff;
    __android_log_print(3,"FingerGoodix","Failed to set para in waitForFinger.\n");
    mutex_get_unlock();
  }
  else {
    mutex_get_unlock();
    __android_log_print(3,"FingerGoodix","%s %d \n","device_waitForFingerUp",0x44e);
    iVar1 = param_1;
    do {
      gettimeofday(&local_18,(__timezone_ptr_t)0x0);
      local_28.tv_nsec = local_18.tv_usec * 1000 + 50000000;
      local_28.tv_sec = local_18.tv_sec + local_28.tv_nsec / 1000000000;
      local_28.tv_nsec = local_28.tv_nsec % 1000000000;
      iVar2 = sem_timedwait((sem_t *)g_up_sem,&local_28);
      if (iVar2 == -1) {
        piVar4 = (int *)__errno();
        if (*piVar4 == 0x6e) {
          if (DAT_001273c4 == '\x01') {
            uVar5 = 2;
            __android_log_print(3,"FingerGoodix","Wait for finger up canceled.");
            g_state = 0;
            iVar1 = gf_enable_irq();
            if (iVar1 < 0) {
              __android_log_print(3,"FingerGoodix","Failed to set para in gf_enable_irq.\n");
            }
            goto LAB_00108180;
          }
        }
        else if (*piVar4 == 4) {
          __android_log_print(3,"FingerGoodix","sem_timedwait() EINTR \n");
        }
        else {
          __android_log_print(3,"FingerGoodix","errno = %d \n",*piVar4);
        }
      }
      else {
        if (iVar2 == 0) {
          uVar5 = 0;
          __android_log_print(3,"FingerGoodix","sem_timedwait() succeeded\n");
          __android_log_print(3,"FingerGoodix","got up=================\n");
          (*event_notify)(2,0,0);
          g_state = 0;
          goto LAB_00108180;
        }
        puVar3 = (undefined4 *)__errno();
        __android_log_print(3,"FingerGoodix","errno = %d \n",*puVar3);
      }
    } while ((param_1 < 1) || (iVar1 = iVar1 + -0x32, 0 < iVar1));
    uVar5 = 0x83;
    __android_log_print(3,"FingerGoodix","wait finger down time out.\n");
    g_state = 0;
  }
LAB_00108180:
  DAT_001273c4 = 0;
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar5);
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

undefined4 device_getVersion(long param_1)

{
  undefined4 uVar1;
  ulong uVar2;
  
  uVar1 = fnCa_GetVersion();
  uVar2 = strtol((char *)(param_1 + 0x240),(char **)0x0,0x10);
  DAT_001273c8 = (int)uVar2;
  __android_log_print(3,"FingerGoodix","CHIP ID = 0x%x ",uVar2 & 0xffffffff);
  if ((DAT_001273c8 != 0x220c && DAT_001273c8 != 0x2205) && (1 < DAT_001273c8 - 0x2207U)) {
    if (DAT_001273c8 == 0x2202) {
      __android_log_print(3,"FingerGoodix","MilanF or MilanFN is confirm!!");
      _DAT_001273d4 = 0x100;
      DAT_001273cc = 0x100;
    }
    else {
      if (DAT_001273c8 == 0x220a) {
        __android_log_print(3,"FingerGoodix","MilanK is confirm!!");
        _DAT_001273d4 = 0x800;
        DAT_001273cc = 0x800;
        return uVar1;
      }
      __android_log_print(3,"FingerGoodix","Unknown chip is confirm!!");
    }
    return uVar1;
  }
  __android_log_print(3,"FingerGoodix","MilanE or MilanG or MilanL is confirm!!");
  _DAT_001273d4 = 0x400;
  DAT_001273cc = 0x400;
  return uVar1;
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
  DAT_001273c4 = 1;
  do {
    iVar1 = iVar1 + 1;
    usleep(20000);
    if (g_state == 0) break;
  } while (iVar1 != 0xf);
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
                      uVar2,g_mode,DAT_001273c0);
  mutex_get_lock();
  g_rev_mode = (uint)param_1;
  if ((g_rev_mode != 2) && (g_mode == 3)) {
    if (param_1 != 1) {
      __android_log_print(3,"FingerGoodix","chip mode in FF, do\'t set mode \n");
      mutex_get_unlock();
      return 0;
    }
    if (g_state != 0) {
      __android_log_print(3,"FingerGoodix","Ghost: Enter Key in FF.\n");
      g_state = 1;
      device_cancel_waitfinger();
    }
    __android_log_print(3,"FingerGoodix","chip mode in FF, do\'t set mode \n");
    g_state = 1;
    mutex_get_unlock();
    return 0;
  }
  gf_set_mode(uVar2);
  __android_log_print(3,"FingerGoodix"," Set mode : %d, g_mode = %d\n",uVar2,g_mode);
  uVar3 = (uint)param_1;
  if ((uVar3 != 0x10 && 3 < uVar3) && (uVar3 != 0x56)) {
    __android_log_print(3,"FingerGoodix","Unsupport mode:0x%x\n",uVar3);
    goto LAB_00108688;
  }
  if (uVar3 == g_mode) {
    if (param_1 == 0) {
      gf_ready_spiclk();
      uVar2 = g_mode;
    }
    else if (param_1 == 2) {
      gf_unready_spiclk();
      uVar2 = g_mode;
    }
    __android_log_print(3,"FingerGoodix"," has already in mode : %d\n",uVar2);
    mutex_get_unlock();
    return 0;
  }
  if ((g_mode - 2 < 2) || (g_mode == 0)) {
    __android_log_print(3,"FingerGoodix","Enable clock.\n");
    if (g_state != 0) {
      __android_log_print(3,"FingerGoodix","Cancel from state[%d] firstly.");
      device_cancel_waitfinger();
    }
    gf_ready_spiclk();
  }
  if (g_mode == 1) {
    if (g_state == 3) {
      gf_delete_timer(&gx_timerid);
      goto LAB_001086d4;
    }
  }
  else {
LAB_001086d4:
    if (g_mode == 0x10) {
      gf_set_speed(4800000);
    }
  }
  __android_log_print(3,"FingerGoodix","############ reset before read statue 0x%x g_mode %d \n",0,
                      g_mode);
  gf_enable_irq();
  iVar1 = fnCa_SetMode(uVar2);
  if (iVar1 != 0) {
    __android_log_print(3,"FingerGoodix","Failed to set mode.\n");
    fnCa_SetMode(uVar2);
  }
  g_mode = uVar3;
  if (uVar3 == 1) {
    g_state = 3;
    __android_log_print(3,"FingerGoodix","### download fdt get down cfg g_state %d \n",3);
    fnCa_Cfg_FdtDown_Up(0);
  }
  else if (uVar3 == 0x10) {
    __android_log_print(3,"FingerGoodix","########### set speed in high for nav \n");
    gf_set_speed(9600000);
    GX_NavStateIdle();
    fnCa_Cfg_FdtDown_Up(1);
    g_state = 1;
    DAT_001273d0 = 0;
  }
  else {
    g_state = 0;
  }
  if (g_mode == 2) {
    __android_log_print(3,"FingerGoodix","Disable clock in sleep mode.\n");
    gf_unready_spiclk();
  }
LAB_00108688:
  mutex_get_unlock();
  return 0;
}



void device_clear_waitfinger(void)

{
  __android_log_print(3,"FingerGoodix","device_clear_waitfinger ");
  DAT_001273c4 = 0;
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



undefined8 device_update_fdtupreg(void)

{
  __android_log_print(3,"FingerGoodix","%s %d \n","device_update_fdtupreg",0x55c);
  fnCa_UpdateFDTUpReg();
  return 0;
}



undefined8 device_pause_capture(void)

{
  __android_log_print(3,"FingerGoodix","%s %d \n","device_pause_capture",0x564);
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
  if (DAT_001271e8 == 0) {
    __android_log_print(6,"FingerGoodix","g_device_handle is NULL to do IOCTL Ops.\n");
    uVar2 = 0xffffff7f;
  }
  else {
    iVar1 = ioctl(DAT_001271e8,0x4709);
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
  if (DAT_001271e8 == 0) {
    __android_log_print(6,"FingerGoodix","g_device_handle is NULL to do IOCTL Ops.\n");
    uVar2 = 0xffffff7f;
  }
  else {
    iVar1 = ioctl(DAT_001271e8,0x470a);
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
  DAT_001273d8 = param_1;
  return 0;
}



undefined8 device_set_recognize_flag(int param_1)

{
  __android_log_print(3,"FingerGoodix","%s %d \n","device_set_recognize_flag",0x599);
  if (param_1 != 0x6e) {
    return 0;
  }
  DAT_001273c0 = 2;
  mutex_get_lock();
  g_mode = 3;
  mutex_get_unlock();
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void device_check_reset(void)

{
  ushort uVar1;
  undefined4 uVar2;
  int iVar3;
  int *piVar4;
  undefined4 uVar5;
  ushort local_2a;
  timespec local_28;
  timeval local_18;
  long local_8;
  
  uVar2 = g_state;
  uVar1 = DAT_001273d4;
  local_8 = ___stack_chk_guard;
  local_2a = 0;
  __android_log_print(3,"FingerGoodix","device_check_reset");
  iVar3 = fnCa_GetStatus(&local_2a);
  if (iVar3 == 0) {
    if (((uVar1 & local_2a) == 0) || (iVar3 = fnCa_CleanStatus(), iVar3 == 0)) {
      g_state = 4;
      gf_enable_irq();
      iVar3 = gf_hw_reset();
      if (iVar3 == 0) {
        gettimeofday(&local_18,(__timezone_ptr_t)0x0);
        local_28.tv_sec = local_18.tv_sec + 2 + (local_18.tv_usec * 1000) / 1000000000;
        local_28.tv_nsec = (local_18.tv_usec * 1000) % 1000000000;
        do {
          while( true ) {
            iVar3 = sem_timedwait((sem_t *)g_check_reset_sem,&local_28);
            if (iVar3 != -1) break;
            piVar4 = (int *)__errno();
            if (*piVar4 != 4) {
              if (*piVar4 == 0x6e) {
                __android_log_print(3,"FingerGoodix","Reset Check Timed out.\n");
              }
              else {
                __android_log_print(3,"FingerGoodix","Reset Check errno = %d \n",*piVar4);
              }
              uVar5 = 0xffffffff;
              g_state = uVar2;
              goto LAB_00108cf8;
            }
            __android_log_print(3,"FingerGoodix","Reset Check sem_timedwait() EINTR \n");
          }
        } while (iVar3 != 0);
        __android_log_print(3,"FingerGoodix","Check Reset Success.\n");
        uVar5 = 0;
        g_state = uVar2;
      }
      else {
        uVar5 = 0xffffffff;
        __android_log_print(6,"FingerGoodix","Failed to reset\n");
        g_state = uVar2;
      }
    }
    else {
      uVar5 = 0xffffffff;
      __android_log_print(6,"FingerGoodix","Failed to clean status:0x%x\n",local_2a);
    }
  }
  else {
    uVar5 = 0xffffffff;
    __android_log_print(6,"FingerGoodix","Failed to get status:0x%x\n",local_2a);
  }
LAB_00108cf8:
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar5);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void device_check_template(undefined4 *param_1)

{
  int iVar1;
  undefined8 *__ptr;
  undefined8 uVar2;
  undefined4 uVar3;
  undefined4 local_c;
  long local_8;
  
  local_c = 5;
  local_8 = ___stack_chk_guard;
  __ptr = (undefined8 *)malloc(0x14);
  *(undefined4 *)(__ptr + 2) = 0;
  *__ptr = 0;
  __ptr[1] = 0;
  if (param_1 == (undefined4 *)0x0) {
    __android_log_print(3,"FingerGoodix","%s param error","device_check_template");
    free(__ptr);
    uVar2 = 0xffffffff;
  }
  else {
    iVar1 = fnCa_GetFpTemplateIdList(__ptr,&local_c);
    uVar3 = 0;
    if (iVar1 == 0) {
      uVar3 = local_c;
    }
    *param_1 = uVar3;
    free(__ptr);
    uVar2 = 0;
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar2);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00108e78(int *param_1)

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



undefined8 gx_ta_start(void)

{
  undefined8 *puVar1;
  int iVar2;
  undefined4 *puVar3;
  long lVar4;
  
  lVar4 = 0;
  __android_log_print(3,"FingerGoodix",&DAT_001110c0,"gx_ta_start");
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



undefined8 gx_alipay_ta_start(void)

{
  undefined8 *puVar1;
  int iVar2;
  undefined4 *puVar3;
  undefined8 uVar4;
  long lVar5;
  
  __android_log_print(3,"FingerGoodix",&DAT_001110c0,"gx_alipay_ta_start");
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
  
  __android_log_print(3,"FingerGoodix",&DAT_001110c0,"gx_ta_stop");
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



undefined8 gx_alipay_ta_stop(void)

{
  int iVar1;
  undefined8 uVar2;
  undefined4 *puVar3;
  
  __android_log_print(3,"FingerGoodix",&DAT_001110c0,"gx_alipay_ta_stop");
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

void gx_ta_send_command(undefined param_1,void *param_2,uint param_3,void *param_4,uint param_5)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  undefined4 *puVar4;
  undefined8 uVar5;
  undefined uStack_e08;
  undefined auStack_e07 [1535];
  undefined auStack_808 [2048];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  pthread_mutex_lock((pthread_mutex_t *)&DAT_00127400);
  if ((param_2 == (void *)0x0) || (param_4 == (void *)0x0)) {
    uVar5 = 0xffffffff;
    __android_log_print(6,"FingerGoodix","Bad input argument. NULL Buffer.");
    pthread_mutex_unlock((pthread_mutex_t *)&DAT_00127400);
  }
  else if ((param_3 < 0x5f9) && (param_5 < 0x801)) {
    uStack_e08 = param_1;
    memcpy(auStack_e07,param_2,(ulong)param_3);
    uVar1 = param_3 + 1;
    if ((uVar1 & 0x3f) != 0) {
      uVar1 = param_3 + 0x41 & 0xffffffc0;
    }
    uVar2 = param_5;
    if ((param_5 & 0x3f) != 0) {
      uVar2 = param_5 + 0x40 & 0xffffffc0;
    }
    iVar3 = QSEECom_send_cmd(g_ta_handle,&uStack_e08,uVar1,auStack_808,uVar2);
    if (iVar3 == 0) {
      uVar5 = 0;
      memcpy(param_4,auStack_808,(ulong)param_5);
    }
    else {
      puVar4 = (undefined4 *)__errno();
      uVar5 = 0xffffffff;
      __android_log_print(6,"FingerGoodix","Failed to send cmd[%d], ret=%d, errno=%d",param_1,iVar3,
                          *puVar4);
    }
    pthread_mutex_unlock((pthread_mutex_t *)&DAT_00127400);
  }
  else {
    uVar5 = 0xffffffff;
    __android_log_print(6,"FingerGoodix",
                        "The maximum length for the send command is %d, and maximum RSP data length is %d"
                        ,0x5f8,0x800);
    pthread_mutex_unlock((pthread_mutex_t *)&DAT_00127400);
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar5);
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
    pthread_mutex_lock((pthread_mutex_t *)&DAT_00127400);
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
    pthread_mutex_unlock((pthread_mutex_t *)&DAT_00127400);
    __android_log_print(3,"FingerGoodix","%s, after unlock","gx_alipay_ta_send_command");
  }
  else {
    uVar5 = 0xffffffff;
    __android_log_print(6,"FingerGoodix","%s, Bad input argument. input_len.",
                        "gx_alipay_ta_send_command");
  }
  return uVar5;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void alipay_thread(void)

{
  int iVar1;
  uint uVar2;
  int *piVar3;
  ulong uVar4;
  
  do {
    if ((int)_DAT_00127438 == 0) {
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
      iVar1 = sem_wait((sem_t *)&DAT_00127428);
      if (iVar1 != -1) break;
      piVar3 = (int *)__errno();
      if (*piVar3 != 4) {
        __android_log_print(6,"FingerGoodix","%s Fatal Error When sem_wait, errno = %d.",
                            "alipay_thread",*piVar3);
                    // WARNING: Subroutine does not return
        pthread_exit((void *)0x2);
      }
    }
    uVar4 = _DAT_00127438;
    if ((int)_DAT_00127438 != 0) {
      DAT_00127468 = gx_alipay_ta_send_command
                               (DAT_00127440,DAT_00127448,DAT_00127450,DAT_00127458,DAT_00127460);
      uVar2 = sem_post((sem_t *)&DAT_00127470);
      uVar4 = (ulong)uVar2;
    }
    iVar1 = gx_alipay_ta_stop(uVar4);
  } while (iVar1 == 0);
  __android_log_print(6,"FingerGoodix","%s, alipay_ta stop error.","alipay_thread");
                    // WARNING: Subroutine does not return
  pthread_exit((void *)0x3);
}



void gx_alipay_thread_init(void)

{
  int iVar1;
  
  iVar1 = pthread_attr_init((pthread_attr_t *)&DAT_00127480);
  if (iVar1 != 0) {
    __android_log_print(6,"FingerGoodix","Failed in pthread_attr_init. ret = %d",iVar1);
    return;
  }
  iVar1 = pthread_attr_setstacksize((pthread_attr_t *)&DAT_00127480,0x40000);
  if (iVar1 == 0) {
    sem_init((sem_t *)&DAT_00127428,0,0);
    sem_init((sem_t *)&DAT_00127470,0,0);
    iVar1 = pthread_create(&DAT_001274b8,(pthread_attr_t *)&DAT_00127480,alipay_thread,(void *)0x0);
    if (iVar1 == 0) {
      DAT_00127438 = 1;
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
  if (DAT_001274b8 == 0) {
    __android_log_print(6,"FingerGoodix","alipay thread doesn\'t run.");
  }
  else {
    DAT_00127438 = 0;
    DataMemoryBarrier(2,3);
    iVar1 = pthread_attr_destroy((pthread_attr_t *)&DAT_00127480);
    if (iVar1 == 0) {
      iVar1 = pthread_join(DAT_001274b8,(void **)&local_c);
    }
    else {
      __android_log_print(6,"FingerGoodix","Failed in pthread_attr_destory. ret = %d",iVar1);
      iVar1 = pthread_join(DAT_001274b8,(void **)&local_c);
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
  
  DAT_00127440 = param_1;
  DAT_00127448 = param_2;
  DAT_00127450 = param_3;
  DAT_00127458 = param_4;
  DAT_00127460 = param_5;
  if (DAT_001274b8 == 0) {
    __android_log_print(6,"FingerGoodix","alipay thread doesn\'t run.");
    uVar2 = 0xffffffff;
  }
  else {
    sem_post((sem_t *)&DAT_00127428);
    while (iVar1 = sem_wait((sem_t *)&DAT_00127470), uVar2 = DAT_00127468, iVar1 == -1) {
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



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// WARNING: Restarted to delay deadcode elimination for space: stack

void gx_ta_send_command_ex
               (byte param_1,void *param_2,uint param_3,void *param_4,uint param_5,void *param_6)

{
  uint **ppuVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  undefined8 uVar5;
  byte *pbVar6;
  uint *puVar7;
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
  byte *local_38;
  undefined4 local_30;
  size_t local_28;
  undefined8 local_20;
  undefined4 local_18;
  undefined4 local_14;
  int local_10;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","%s entry cmd %d","gx_ta_send_command_ex",param_1);
  if ((0x20000 < param_3 || 0x20000 < param_5) || (param_2 == (void *)0x0)) {
    __android_log_print(6,"FingerGoodix","Param is error.");
    uVar5 = 0xffffffff;
    goto LAB_00109f68;
  }
  pthread_mutex_lock((pthread_mutex_t *)&DAT_00127400);
  ppuVar1 = g_ta_handle;
  if (g_ta_handle == (uint **)0x0) {
    __android_log_print(3,"FingerGoodix","Error ta_handle");
    pthread_mutex_unlock((pthread_mutex_t *)&DAT_00127400);
    uVar5 = 0xffffffff;
    goto LAB_00109f68;
  }
  local_48 = 0;
  local_40 = 0;
  iVar2 = open("/dev/ion",0);
  if (iVar2 < 0) {
    __android_log_print(6,"FingerGoodix","Error::Cannot open ION device\n");
LAB_0010a088:
    __android_log_print(3,"FingerGoodix","Error allocating memory in ion\n");
    pthread_mutex_unlock((pthread_mutex_t *)&DAT_00127400);
    uVar5 = 0xffffffff;
  }
  else {
    local_28 = 0xc5000;
    local_20 = 0x1000;
    local_38 = (byte *)0x0;
    local_44 = 0;
    local_18 = 0x8000000;
    local_14 = 0;
    iVar3 = ioctl(iVar2,0xc0204900);
    if (iVar3 == 0) {
      if (local_10 == 0) {
        __android_log_print(6,"FingerGoodix","Error::ION alloc data returned a NULL\n");
        goto joined_r0x00109fd8;
      }
      local_70 = local_10;
      iVar3 = ioctl(iVar2,0xc0084902);
      if (iVar3 != 0) {
        iVar3 = 0;
        __android_log_print(6,"FingerGoodix","Error::Failed doing ION_IOC_MAP call\n");
LAB_00109e44:
        local_78[0] = local_10;
        if (local_44 != 0) {
          close(local_44);
        }
        iVar4 = ioctl(iVar2,0xc0044901,local_78);
        if (iVar4 != 0) {
          __android_log_print(6,"FingerGoodix","Error::ION FREE ioctl returned error = %d\n",iVar4);
        }
        if (iVar2 != 0) goto LAB_00109fb4;
        goto joined_r0x00109fbc;
      }
      pbVar6 = (byte *)mmap((void *)0x0,local_28,3,1,local_6c,0);
      if (pbVar6 == (byte *)0xffffffffffffffff) {
        __android_log_print(6,"FingerGoodix","Error::ION MMAP failed\n");
        iVar3 = -1;
        if ((local_38 != (byte *)0x0) && (iVar3 = munmap(local_38,local_28), iVar3 != 0)) {
          __android_log_print(6,"FingerGoodix",
                              "Error::Failed to unmap memory for load image. ret = %d\n",iVar3);
        }
        goto LAB_00109e44;
      }
      local_44 = local_6c;
      local_40 = local_10;
      local_30 = 0xc40ac;
      local_48 = iVar2;
      local_38 = pbVar6;
    }
    else {
      __android_log_print(6,"FingerGoodix","Error::Error while trying to allocate data\n");
joined_r0x00109fd8:
      if (iVar2 != 0) {
        iVar3 = 0;
LAB_00109fb4:
        close(iVar2);
joined_r0x00109fbc:
        if (iVar3 != 0) goto LAB_0010a088;
      }
    }
    local_68 = 0;
    uStack_60 = 0;
    local_58 = 0;
    uStack_50 = 0;
    *local_38 = param_1;
    memcpy(local_38 + 1,param_2,(ulong)param_3);
    puVar7 = *ppuVar1;
    *puVar7 = (uint)param_1;
    puVar7[1] = (uint)local_38;
    puVar7[2] = 0xc40ac;
    puVar7[0xc2] = 0;
    local_68 = CONCAT44(4,local_44);
    iVar2 = QSEECom_send_modified_cmd(ppuVar1,puVar7,0x40,puVar7 + 0xc0,0x40,&local_68);
    pbVar6 = local_38;
    if ((iVar2 == 0) && (-1 < (int)puVar7[0xc2])) {
      if (param_4 != (void *)0x0) {
        memcpy(param_4,local_38 + 0x20004,(ulong)param_5);
      }
      if (param_6 != (void *)0x0) {
        memcpy(param_6,pbVar6 + 0x40008,0x840a4);
      }
      iVar2 = FUN_00108e78(&local_48);
      if (iVar2 == 0) {
        pthread_mutex_unlock((pthread_mutex_t *)&DAT_00127400);
        __android_log_print(3,"FingerGoodix","%s exit cmd %d","gx_ta_send_command_ex",param_1);
        uVar5 = 0;
      }
      else {
        __android_log_print(6,"FingerGoodix","return value of dealloc is %d",iVar2);
        pthread_mutex_unlock((pthread_mutex_t *)&DAT_00127400);
        uVar5 = 0xffffffff;
      }
    }
    else {
      __android_log_print(3,"FingerGoodix",
                          "qsc_issue_send_modified_cmd_req: fail cmd = %d ret = %d               msg_rsp->status: %d"
                          ,param_1,iVar2);
      FUN_00108e78(&local_48);
      pthread_mutex_unlock((pthread_mutex_t *)&DAT_00127400);
      uVar5 = 0xffffffff;
    }
  }
LAB_00109f68:
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar5);
}



void FUN_0010a19c(undefined *param_1)

{
  __android_log_print(3,"FingerGoodix",
                      "fnCa_Init OTP[0-7]:0x%x-0x%x-0x%x-0x%x-0x%x-0x%x-0x%x-0x%x\n",*param_1,
                      param_1[1],param_1[2],param_1[3],param_1[4],param_1[5]);
  __android_log_print(3,"FingerGoodix",
                      "fnCa_Init OTP[8-15]:0x%x-0x%x-0x%x-0x%x-0x%x-0x%x-0x%x-0x%x\n",param_1[8],
                      param_1[9],param_1[10],param_1[0xb],param_1[0xc],param_1[0xd]);
  __android_log_print(3,"FingerGoodix",
                      "fnCa_Init OTP[16-23]:0x%x-0x%x-0x%x-0x%x-0x%x-0x%x-0x%x-0x%x\n",param_1[0x10]
                      ,param_1[0x11],param_1[0x12],param_1[0x13],param_1[0x14],param_1[0x15]);
  __android_log_print(3,"FingerGoodix",
                      "fnCa_Init OTP[24-31]:0x%x-0x%x-0x%x-0x%x-0x%x-0x%x-0x%x-0x%x\n",param_1[0x18]
                      ,param_1[0x19],param_1[0x1a],param_1[0x1b],param_1[0x1c],param_1[0x1d]);
  return;
}



int fnCa_OpenSession(void)

{
  int iVar1;
  
  iVar1 = gx_ta_start();
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
  ssize_t sVar2;
  undefined8 *puVar3;
  undefined8 uVar4;
  undefined4 local_70;
  undefined8 local_6c;
  undefined8 uStack_64;
  undefined8 local_5c;
  undefined8 uStack_54;
  undefined local_4c;
  undefined8 local_48;
  undefined8 uStack_40;
  undefined2 local_38;
  undefined8 local_30;
  undefined8 uStack_28;
  undefined8 local_20;
  undefined8 uStack_18;
  undefined local_10;
  undefined auStack_f [15];
  
  local_38 = 0x70;
  auStack_f._7_8_ = ___stack_chk_guard;
  local_48 = 0x2f6472616364732f;
  uStack_40 = 0x746f5f676678672e;
  local_10 = 0;
  local_30 = 0;
  uStack_28 = 0;
  local_20 = 0;
  uStack_18 = 0;
  iVar1 = open((char *)&local_48,2);
  if (iVar1 < 0) {
    __android_log_print(3,"FingerGoodix","open failed \n");
  }
  else {
    __android_log_print(3,"FingerGoodix","open success \n");
    sVar2 = read(iVar1,&local_30,0x21);
    if (sVar2 == 0x21) {
      __android_log_print(3,"FingerGoodix","read success \n");
    }
    else {
      local_30 = 0;
      uStack_28 = 0;
      local_20 = 0;
      uStack_18 = 0;
      local_10 = 0;
      __android_log_print(3,"FingerGoodix","read failed \n");
    }
    close(iVar1);
  }
  local_4c = local_10;
  local_6c = local_30;
  uStack_64 = uStack_28;
  local_5c = local_20;
  uStack_54 = uStack_18;
  local_70 = param_1;
  FUN_0010a19c(&local_6c);
  local_10 = 0;
  local_30 = 0;
  uStack_28 = 0;
  local_20 = 0;
  uStack_18 = 0;
  iVar1 = gx_ta_send_command(1,&local_70,0x28,&local_30,0x21);
  __android_log_print(6,"FingerGoodix","##Davy teeRet = %d ,data[32] = %x\n",iVar1,local_10);
  if (iVar1 == 0) {
    FUN_0010a19c(&local_30);
    puVar3 = &local_30;
    do {
      if (*(char *)puVar3 != -0x56) {
        iVar1 = open((char *)&local_48,0x42);
        if (iVar1 < 0) {
          uVar4 = 0;
        }
        else {
          write(iVar1,&local_30,0x21);
          close(iVar1);
          uVar4 = 0;
        }
        goto LAB_0010a534;
      }
      puVar3 = (undefined8 *)((long)puVar3 + 1);
    } while (puVar3 != (undefined8 *)auStack_f);
    __android_log_print(6,"FingerGoodix","error. This IC isn\'t GoodixFP");
  }
  uVar4 = 0xffffffff;
LAB_0010a534:
  if (auStack_f._7_8_ == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar4);
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

void fnCa_load_all_fpdata(void *param_1)

{
  int iVar1;
  undefined8 uVar2;
  undefined4 local_8c;
  undefined8 local_88;
  undefined8 uStack_80;
  undefined8 local_78;
  undefined8 uStack_70;
  undefined8 local_68;
  undefined8 uStack_60;
  undefined8 local_58;
  undefined8 uStack_50;
  undefined8 local_48;
  undefined8 uStack_40;
  undefined8 local_38;
  undefined8 uStack_30;
  undefined8 local_28;
  undefined8 uStack_20;
  undefined8 local_18;
  ulong local_10;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","fnCa_load_all_fpdata");
  local_8c = 0;
  local_88 = 0;
  uStack_80 = 0;
  local_78 = 0;
  uStack_70 = 0;
  local_68 = 0;
  uStack_60 = 0;
  local_58 = 0;
  uStack_50 = 0;
  local_48 = 0;
  uStack_40 = 0;
  local_38 = 0;
  uStack_30 = 0;
  local_28 = 0;
  uStack_20 = 0;
  local_18 = 0;
  local_10 = 0;
  iVar1 = gx_ta_send_command(0x39,&local_8c,4,&local_88,0x80);
  if (iVar1 == 0) {
    __android_log_print(3,"FingerGoodix","current_num:%d\n",local_10 & 0xffffffff);
    memcpy(param_1,&local_88,0x80);
    uVar2 = 0;
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



int fnCa_SetFpdbToTa(char *param_1,undefined8 param_2)

{
  int iVar1;
  size_t sVar2;
  
  __android_log_print(3,"FingerGoodix","fnCa_SetFpdbToTa");
  sVar2 = strlen(param_1);
  iVar1 = gx_ta_send_command(0x3a,param_1,sVar2,param_2,4);
  return -(uint)(iVar1 != 0);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void fnCa_set_user_id(undefined8 param_1)

{
  undefined8 local_18;
  long local_10;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  local_18 = param_1;
  __android_log_print(3,"FingerGoodix","fnCa_set_user_id");
  local_10 = -1;
  gx_ta_send_command(0x38,&local_18,8,&local_10,4);
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(-(uint)(local_10 != 0));
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
  if ((iVar1 == 0) && ((int)local_10 - 1U < 5)) {
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

void fnCa_Recognize(int param_1,void *param_2,ulong param_3,undefined4 *param_4,undefined4 *param_5,
                   undefined8 *param_6)

{
  int iVar1;
  undefined4 uVar2;
  undefined8 uVar3;
  undefined4 local_5e8;
  undefined4 local_5e4;
  undefined4 uStack_5e0;
  undefined auStack_5dc [20];
  int local_5c8;
  undefined8 local_544;
  undefined8 uStack_53c;
  undefined8 local_534;
  undefined8 uStack_52c;
  undefined8 local_524;
  undefined8 uStack_51c;
  undefined8 local_514;
  undefined8 uStack_50c;
  undefined4 local_504;
  undefined local_500;
  undefined auStack_4ff [4];
  int local_4fb;
  int local_4f7;
  undefined auStack_2f8 [156];
  undefined4 local_25c;
  undefined auStack_258 [592];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  memset(&uStack_5e0,0,0x2e8);
  memset(auStack_2f8,0,0x2ec);
  local_5e8 = 0;
  local_5e4 = 4;
  uStack_5e0 = (undefined4)(param_3 & 0xffffffff);
  memcpy(auStack_5dc,param_2,(param_3 & 0xffffffff) << 2);
  local_5c8 = param_1;
  if ((param_1 == 1) && (iVar1 = gx_alipay_ta_start(), iVar1 != 0)) {
    uVar3 = 0xffffffff;
    __android_log_print(6,"FingerGoodix","%s, alipay_ta start error.","fnCa_Recognize");
  }
  else {
    iVar1 = getKeyFromKeymaster(auStack_4ff,0x1bb);
    __android_log_print(6,"FingerGoodix","fnCa_Recognize-->get key status! ret: %d",iVar1);
    if (iVar1 == 0) {
      local_504 = *(undefined4 *)(param_6 + 8);
      local_544 = *param_6;
      uStack_53c = param_6[1];
      local_534 = param_6[2];
      uStack_52c = param_6[3];
      local_500 = *(undefined *)((long)param_6 + 0x44);
      local_524 = param_6[4];
      uStack_51c = param_6[5];
      local_514 = param_6[6];
      uStack_50c = param_6[7];
      iVar1 = gx_ta_send_command(10,&uStack_5e0,local_4fb + local_4f7 + 0xe1,auStack_2f8,0x2ec);
      if (iVar1 == 0) {
        uVar3 = 0;
        memcpy(param_4,auStack_2f8,0x2ec);
        *param_5 = 0x2ec;
        __android_log_print(3,"FingerGoodix","fnCa_Recognize : TA return index = %d",*param_4);
        if (param_1 == 1) {
          uVar2 = gx_alipay_ta_send_command(0xa001001,auStack_258,local_25c,&local_5e8,&local_5e4);
          __android_log_print(3,"FingerGoodix","fnCa_Recognize : sync result to alipay ta, ret = %d"
                              ,uVar2);
        }
      }
      else if ((param_1 == 1) && (iVar1 = gx_alipay_ta_stop(), iVar1 != 0)) {
        uVar3 = 0xffffffff;
        __android_log_print(6,"FingerGoodix","%s, alipay_ta stop error.","fnCa_Recognize");
      }
      else {
        uVar3 = 0xffffffff;
      }
    }
    else {
      uVar3 = 0xffffffff;
      __android_log_print(6,"FingerGoodix","fnCa_Recognize-->get key failed! ret: %d",iVar1);
    }
  }
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
  uint *__ptr;
  undefined4 local_c;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  local_c = 0;
  __ptr = (uint *)malloc((ulong)(param_2 + 1) << 2);
  uVar2 = *param_1;
  *__ptr = param_2;
  __android_log_print(3,"FingerGoodix","fnCa_DelFpTemplates: id = %d,idCOunt = %d",uVar2,
                      (ulong)param_2);
  memcpy(__ptr + 1,param_1,(ulong)param_2 << 2);
  iVar1 = gx_ta_send_command(0xc,__ptr,(param_2 + 1) * 4,&local_c,4);
  free(__ptr);
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
  undefined8 uVar1;
  undefined4 local_10;
  undefined4 local_c;
  long local_8;
  
  local_c = 0;
  local_10 = 0;
  local_8 = ___stack_chk_guard;
  uVar1 = gx_ta_send_command(0x12,&local_c,4,&local_10,4);
  if ((int)uVar1 == 0) {
    *param_1 = (short)local_10;
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
  __android_log_print(3,"FingerGoodix",&DAT_001110c0,"fnCa_GetSessionID");
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
  __android_log_print(3,"FingerGoodix",&DAT_001110c0,"fnCa_SetSessionID");
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
  undefined4 uStack_670;
  undefined auStack_66c [20];
  undefined4 local_658;
  undefined8 local_388;
  undefined8 uStack_380;
  undefined8 local_378;
  undefined8 uStack_370;
  undefined8 local_368;
  undefined8 uStack_360;
  undefined8 local_358;
  undefined8 uStack_350;
  undefined8 local_348;
  undefined auStack_340 [824];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  memset(auStack_340,0,0x334);
  __android_log_print(3,"FingerGoodix","fnCa_Fido_Recognize \n");
  local_348 = param_5[8];
  local_368 = param_5[4];
  uStack_360 = param_5[5];
  local_388 = *param_5;
  uStack_380 = param_5[1];
  local_378 = param_5[2];
  uStack_370 = param_5[3];
  local_358 = param_5[6];
  uStack_350 = param_5[7];
  uStack_670 = (undefined4)(param_2 & 0xffffffff);
  memcpy(auStack_66c,param_1,(param_2 & 0xffffffff) << 2);
  local_658 = 2;
  iVar1 = gx_ta_send_command(10,&uStack_670,0x330,auStack_340,0x334);
  if (iVar1 == 0) {
    memcpy(param_3,auStack_340,0x2ec);
    *param_4 = 0x2ec;
    param_5[8] = local_348;
    *param_5 = local_388;
    param_5[1] = uStack_380;
    param_5[2] = local_378;
    param_5[3] = uStack_370;
    param_5[4] = local_368;
    param_5[5] = uStack_360;
    param_5[6] = local_358;
    param_5[7] = uStack_350;
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

void fnCa_dump_data(long param_1,uint param_2)

{
  int iVar1;
  void *__ptr;
  undefined8 uVar2;
  char *pcVar3;
  undefined4 local_c;
  long local_8;
  
  local_c = 0;
  local_8 = ___stack_chk_guard;
  if ((param_1 == 0) || (0xd < param_2)) {
    pcVar3 = "%s param error";
  }
  else {
    __ptr = malloc(0x840a4);
    if (__ptr != (void *)0x0) {
      iVar1 = gx_ta_send_command_ex(0x37,&local_c,4,0,0,__ptr);
      if (iVar1 == 0) {
        gf_dump_data_interface(__ptr,param_2,param_1);
        free(__ptr);
        uVar2 = 0;
      }
      else {
        __android_log_print(6,"FingerGoodix","get dump data  fail");
        free(__ptr);
        uVar2 = 0xffffffff;
      }
      goto LAB_0010bb00;
    }
    pcVar3 = "%s malloc fail";
  }
  __android_log_print(6,"FingerGoodix",pcVar3,"fnCa_dump_data");
  uVar2 = 0xffffffff;
LAB_0010bb00:
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar2);
}



undefined8 fnCa_GetBitmap(void *param_1,int *param_2,undefined8 *param_3,uint param_4)

{
  int iVar1;
  undefined8 *__src;
  undefined8 uVar2;
  undefined8 uVar3;
  undefined8 uVar4;
  undefined8 uVar5;
  undefined8 uVar6;
  undefined8 uVar7;
  uint local_4;
  
  local_4 = param_4;
  __android_log_print(3,"FingerGoodix","fnCa_GetBitmap begin.\n");
  if ((((local_4 < 7) && (param_2 != (int *)0x0)) && (param_3 != (undefined8 *)0x0)) &&
     (param_1 != (void *)0x0)) {
    __src = (undefined8 *)malloc(0xf03c);
    if (__src == (undefined8 *)0x0) {
      __android_log_print(6,"FingerGoodix","malloc failed");
      uVar2 = 0xffffffff;
    }
    else {
      iVar1 = gx_ta_send_command_ex(0x1d,&local_4,4,__src,0xf03c,0);
      if (iVar1 == 0) {
        __android_log_print(3,"FingerGoodix","row:%d, col:%d.",*(undefined4 *)((long)__src + 0xf034)
                            ,*(undefined4 *)(__src + 0x1e07));
        uVar6 = *__src;
        uVar7 = __src[1];
        uVar4 = __src[2];
        uVar5 = __src[3];
        *(undefined4 *)(param_3 + 6) = *(undefined4 *)(__src + 6);
        uVar2 = __src[4];
        uVar3 = __src[5];
        *param_3 = uVar6;
        param_3[1] = uVar7;
        param_3[2] = uVar4;
        param_3[3] = uVar5;
        param_3[4] = uVar2;
        param_3[5] = uVar3;
        switch(local_4) {
        case 0:
        case 1:
        case 5:
        case 6:
          iVar1 = *(int *)(__src + 0x1e07) * *(int *)((long)__src + 0xf034);
          memcpy(param_1,(void *)((long)__src + 0x34),(long)iVar1);
          *param_2 = iVar1;
          break;
        case 2:
          memcpy(param_1,__src,0xf03c);
          break;
        case 3:
          iVar1 = *(int *)((long)__src + 0xf034) * *(int *)(__src + 0x1e07) * 2;
          memcpy(param_1,(void *)((long)__src + 0x5034),(long)iVar1);
          *param_2 = iVar1;
        }
      }
      free(__src);
      uVar2 = 0;
    }
    return uVar2;
  }
  __android_log_print(6,"FingerGoodix","fnCa_GetBitmap parameter error.");
  return 0xffffffff;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void fnCa_reg_from_bmp(long param_1,int param_2,undefined4 *param_3)

{
  int iVar1;
  undefined8 uVar2;
  undefined8 local_18;
  undefined8 local_10;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  local_18 = 0;
  local_10 = 0;
  if ((param_2 < 1 || param_3 == (undefined4 *)0x0) || (param_1 == 0)) {
    uVar2 = 0xffffffff;
    __android_log_print(6,"FingerGoodix","fnCa_reg_from_bmp:parameter is error.");
  }
  else {
    uVar2 = 0;
    __android_log_print(3,"FingerGoodix","fnCa_reg_from_bmp:length = %d.",param_2);
    iVar1 = gx_ta_send_command_ex(0x1e,param_1,param_2,&local_18,0x10,0);
    if (iVar1 == 0) {
      *param_3 = (undefined4)local_18;
      param_3[1] = local_18._4_4_;
      param_3[2] = (undefined4)local_10;
      param_3[3] = local_10._4_4_;
      __android_log_print(3,"FingerGoodix",
                          "fnCa_reg_from_bmp:percent = %d, coverage = %d, quality = %d, overlay = %d."
                         );
    }
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

void fnCa_verify_bmp(long param_1,int param_2,ulong *param_3)

{
  int iVar1;
  undefined8 local_28;
  undefined8 local_20;
  undefined8 local_18;
  undefined4 local_10;
  long local_8;
  
  local_18 = 0;
  local_28 = 0;
  local_20 = 0;
  local_8 = ___stack_chk_guard;
  local_10 = 0;
  if ((param_2 < 1 || param_3 == (ulong *)0x0) || (param_1 == 0)) {
    __android_log_print(3,"FingerGoodix","fnCa_verify_bmp:buf is NULL.",param_2);
  }
  else {
    iVar1 = gx_ta_send_command_ex(0x20,param_1,param_2,&local_28,0x1c,0);
    if (iVar1 == 0) {
      __android_log_print(3,"FingerGoodix",
                          "fnCa_verify_bmp:coverage = %d, quality = %d, result = %d, score = %d, update = %d, recognize_time = %d."
                          ,local_20._4_4_,local_18 & 0xffffffff,local_28 & 0xffffffff,local_28._4_4_
                          ,local_20 & 0xffffffff,local_18._4_4_);
      param_3[2] = local_18;
      *(undefined4 *)(param_3 + 3) = local_10;
      *param_3 = local_28;
      param_3[1] = local_20;
    }
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(0xffffffff);
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

void fnCa_mp_test(int param_1,undefined8 *param_2)

{
  int iVar1;
  undefined8 uVar2;
  int *piVar3;
  int iVar4;
  undefined4 uVar5;
  ulong unaff_x25;
  int iVar6;
  int local_54 [3];
  int local_48;
  int local_44;
  undefined8 local_40;
  undefined8 uStack_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined8 local_20;
  undefined8 uStack_18;
  undefined8 local_10;
  long local_8;
  
  uVar5 = (undefined4)unaff_x25;
  local_8 = ___stack_chk_guard;
  local_10 = 0;
  local_40 = 0;
  uStack_38 = 0;
  local_30 = 0;
  local_28 = 0;
  local_20 = 0;
  uStack_18 = 0;
  local_44 = 0x10;
  local_54[0] = param_1;
  __android_log_print(3,"FingerGoodix","fnCa_mp_test: %d.",param_1);
  iVar4 = local_54[0];
  if (local_54[0] == 0) {
    piVar3 = &local_44;
    local_44 = 0;
    gf_hw_reset();
    fnCa_SetMode(4);
  }
  else {
    if (local_54[0] == 9) {
      local_44 = 0xb;
      iVar1 = gx_ta_send_command(0x24,&local_44,4,&local_48,4);
      local_44 = iVar4;
      if (0 < local_48) {
        iVar4 = 0;
        do {
          iVar4 = iVar4 + 1;
          gx_ta_send_command(0x24,&local_44,4,&local_40,0x38);
        } while (iVar4 < local_48);
      }
      goto LAB_0010c314;
    }
    if (local_54[0] == 2) {
      local_44 = 10;
      iVar6 = 0;
      iVar1 = gx_ta_send_command(0x24,&local_44,4,&local_48,4);
      local_44 = iVar4;
      if (0 < local_48) {
        iVar4 = 0;
        do {
          while( true ) {
            uVar5 = (undefined4)unaff_x25;
            gx_ta_send_command(0x24,&local_44,4,&local_40,0x38);
            if (local_40._4_4_ == 1) break;
            iVar4 = iVar4 + 1;
            unaff_x25 = local_28 & 0xffffffff;
            uVar5 = (undefined4)unaff_x25;
            if (local_48 <= iVar4) goto LAB_0010c424;
          }
          iVar4 = iVar4 + 1;
          iVar6 = iVar6 + 1;
        } while (iVar4 < local_48);
      }
LAB_0010c424:
      if (iVar6 == local_48) {
        local_40 = CONCAT44(1,(undefined4)local_40);
      }
      else {
        local_28 = CONCAT44(local_28._4_4_,uVar5);
      }
      goto LAB_0010c314;
    }
    piVar3 = local_54;
  }
  iVar1 = gx_ta_send_command(0x24,piVar3,4,&local_40,0x38);
LAB_0010c314:
  if (iVar1 == 0) {
    if (param_2 != (undefined8 *)0x0) {
      param_2[6] = local_10;
      *param_2 = local_40;
      param_2[1] = uStack_38;
      param_2[2] = local_30;
      param_2[3] = local_28;
      param_2[4] = local_20;
      param_2[5] = uStack_18;
    }
    uVar2 = 0;
  }
  else {
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
  undefined auStack_28c [4];
  undefined auStack_288 [640];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  memset(auStack_288,0,0x280);
  __android_log_print(3,"FingerGoodix","fnCa_GetVersion");
  iVar1 = gx_ta_send_command(0x2a,auStack_28c,4,auStack_288,0x280);
  if (iVar1 == 0) {
    if (param_1 == (void *)0x0) {
      uVar2 = 0;
    }
    else {
      memcpy(param_1,auStack_288,0x280);
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

void fnCa_Nav(undefined *param_1,undefined4 param_2)

{
  undefined8 uVar1;
  undefined4 local_14 [2];
  undefined4 local_c;
  long local_8;
  
  local_c = 0;
  local_8 = ___stack_chk_guard;
  local_14[0] = param_2;
  if (param_1 == (undefined *)0x0) {
    __android_log_print(3,"FingerGoodix","Input PTR pNav is NULL.\n");
    uVar1 = 0xffffffff;
  }
  else {
    uVar1 = gx_ta_send_command(0x52,local_14,4,&local_c,4);
    if ((int)uVar1 == 0) {
      *param_1 = (char)local_c;
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

void fnCa_UpdateFDTUpReg(void)

{
  undefined4 local_c;
  long local_8;
  
  local_c = 0;
  local_8 = ___stack_chk_guard;
  gx_ta_send_command(0x40,&local_c,4,&local_c,4);
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void fnCa_SetLCDStatus(undefined4 param_1)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 local_14 [2];
  undefined4 local_c;
  long local_8;
  
  local_c = 0;
  local_8 = ___stack_chk_guard;
  local_14[0] = param_1;
  iVar1 = gx_ta_send_command(0x47,local_14,4,&local_c,4);
  __android_log_print(3,"FingerGoodix"," Status:%d, ret = %d\n",local_14[0],local_c);
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



int fnCa_send_cmd_to_ta(int param_1)

{
  undefined4 uVar1;
  int iVar2;
  
  if (param_1 == 0x96) {
    uVar1 = 0x82;
  }
  else {
    uVar1 = 0x83;
    if (param_1 != 0x97) {
      uVar1 = 0;
    }
  }
  iVar2 = gx_ta_send_command(uVar1);
  __android_log_print(3,"FingerGoodix","fnCa_send_cmd_to_ta ret:%d, cmd_id:%d",iVar2,param_1);
  return -(uint)(iVar2 != 0);
}



undefined8 FUN_0010cdd0(void)

{
  return 0xffffffff;
}



undefined8 FUN_0010cdd8(void)

{
  return 0xffffffff;
}



undefined8 FUN_0010cde0(void)

{
  return 0xffffffff;
}



undefined8 FUN_0010cde8(void)

{
  return 0xffffffff;
}



undefined8 FUN_0010cdf0(void)

{
  return 0xffffffff;
}



void FUN_0010cdf8(void)

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



void FUN_0010ce24(void)

{
  __android_log_print(3,"FingerGoodix","fingerprint device disable.");
  device_disable();
  return;
}



void FUN_0010ce4c(undefined8 param_1,undefined4 param_2)

{
  fnCa_Init(param_2);
  return;
}



undefined8 FUN_0010ce54(undefined8 param_1,undefined8 param_2,undefined8 *param_3)

{
  int iVar1;
  undefined4 *__s;
  undefined8 uVar2;
  
  if (param_3 == (undefined8 *)0x0) {
    __android_log_print(6,"FingerGoodix","NULL device on open");
    uVar2 = 0xffffffea;
  }
  else {
    __s = (undefined4 *)malloc(0x308);
    memset(__s,0,0x308);
    *(undefined8 *)(__s + 2) = param_1;
    *__s = 0x48574454;
    __s[1] = 0x100;
    *(code **)(__s + 0x1c) = FUN_0010d80c;
    *(code **)(__s + 0x20) = fnCa_OpenSession;
    *(code **)(__s + 0x22) = fnCa_CloseSession;
    *(code **)(__s + 0x24) = FUN_0010ce4c;
    *(code **)(__s + 0x26) = fnCa_Reset;
    *(code **)(__s + 0x28) = FUN_0010d6a8;
    *(code **)(__s + 0x2a) = FUN_0010d4e4;
    *(code **)(__s + 0x2c) = fnCa_SetModeCancel;
    *(code **)(__s + 0x2e) = FUN_0010d7f8;
    *(code **)(__s + 0x30) = fnCa_CancelRegister;
    *(code **)(__s + 0x32) = FUN_0010d7e4;
    *(code **)(__s + 0x34) = FUN_0010d7d4;
    *(code **)(__s + 0x36) = FUN_0010d7c4;
    *(code **)(__s + 0x38) = FUN_0010d7a8;
    *(code **)(__s + 0x3a) = fnCa_CancelRecognize;
    *(code **)(__s + 0x3c) = FUN_0010d798;
    *(code **)(__s + 0x3e) = FUN_0010d78c;
    *(code **)(__s + 0x40) = FUN_0010d778;
    *(code **)(__s + 0x42) = FUN_0010d76c;
    *(code **)(__s + 0x44) = fnCa_LoadFpAlogParams;
    *(code **)(__s + 0x72) = FUN_0010d750;
    *(code **)(__s + 0x74) = FUN_0010d748;
    *(code **)(__s + 0x76) = FUN_0010d740;
    *(code **)(__s + 0x46) = fnCa_DriverTest;
    *(code **)(__s + 0x7a) = FUN_0010d728;
    *(code **)(__s + 0x7c) = FUN_0010d718;
    *(code **)(__s + 0x82) = fnCa_reg_from_bmp_cancel;
    *(code **)(__s + 0x7e) = FUN_0010d708;
    *(code **)(__s + 0x80) = FUN_0010d6f8;
    *(code **)(__s + 0x84) = FUN_0010d6ec;
    *(code **)(__s + 0x8a) = FUN_0010d6e4;
    *(code **)(__s + 0x8c) = FUN_0010d6d8;
    *(code **)(__s + 0x92) = FUN_0010d6c4;
    *(code **)(__s + 0x94) = FUN_0010d6bc;
    *(code **)(__s + 0x8e) = FUN_0010d6b4;
    *(code **)(__s + 0x90) = fnCa_preprossor_init;
    *(code **)(__s + 0x48) = FUN_0010cdd0;
    *(code **)(__s + 0x4a) = FUN_0010cdd8;
    *(code **)(__s + 0x4c) = FUN_0010cde0;
    *(code **)(__s + 0x50) = FUN_0010d66c;
    *(code **)(__s + 0x52) = FUN_0010d5f4;
    *(code **)(__s + 0x54) = FUN_0010cde8;
    *(code **)(__s + 0x56) = FUN_0010cdf8;
    *(code **)(__s + 0x58) = FUN_0010ce24;
    *(code **)(__s + 0x5a) = FUN_0010d5b4;
    *(code **)(__s + 0x5c) = FUN_0010cdf0;
    *(code **)(__s + 0x5e) = FUN_0010d57c;
    *(code **)(__s + 0x60) = FUN_0010d544;
    *(code **)(__s + 0x62) = FUN_0010d53c;
    *(code **)(__s + 100) = FUN_0010d4ac;
    *(code **)(__s + 0x66) = FUN_0010d474;
    *(code **)(__s + 0x6e) = FUN_0010d44c;
    *(code **)(__s + 0x70) = FUN_0010d424;
    *(code **)(__s + 0x4e) = FUN_0010d41c;
    *(code **)(__s + 0x78) = FUN_0010d404;
    *(code **)(__s + 0x96) = FUN_0010d3cc;
    *(code **)(__s + 0x98) = FUN_0010d398;
    *(code **)(__s + 0xa0) = device_enable_spiclk;
    *(code **)(__s + 0xa2) = device_disable_spiclk;
    *(code **)(__s + 0x9a) = FUN_0010d388;
    *(code **)(__s + 0x9c) = FUN_0010d380;
    *(code **)(__s + 0x9e) = FUN_0010d378;
    *(code **)(__s + 0xa4) = FUN_0010d33c;
    *(code **)(__s + 0xa6) = FUN_0010d314;
    *(code **)(__s + 0xae) = FUN_0010d2d4;
    *(code **)(__s + 0xb4) = get_fp_enabled;
    *(code **)(__s + 0xb6) = fnCa_send_cmd_to_ta;
    *(code **)(__s + 0x68) = fnCa_load_all_fpdata;
    *(code **)(__s + 0x6a) = fnCa_SetFpdbToTa;
    *param_3 = __s;
    *(code **)(__s + 0xb0) = hal_gfcmd_m;
    *(code **)(__s + 0xb2) = set_fp_enabled;
    *(code **)(__s + 0x6c) = fnCa_set_user_id;
    __android_log_print(3,"FingerGoodix","gxFingerPrint open succuss!");
    iVar1 = device_enable();
    if (iVar1 == 0) {
      iVar1 = fnCa_Init();
      if (iVar1 == 0) {
        __android_log_print(3,"FingerGoodix","fingerprint device enable");
        init_thread();
        uVar2 = 0;
      }
      else {
        __android_log_print(6,"FingerGoodix","fnCa_Init : %d!",iVar1);
        fnCa_CloseSession();
        device_disable();
        uVar2 = 0xffffffff;
      }
    }
    else {
      __android_log_print(6,"FingerGoodix","fingerprint device enable failed!");
      fnCa_CloseSession();
      device_disable();
      uVar2 = 0xffffffff;
    }
  }
  return uVar2;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void fnCa_set_user_id(undefined8 param_1)

{
  undefined8 uStack_18;
  long lStack_10;
  long lStack_8;
  
  lStack_8 = ___stack_chk_guard;
  uStack_18 = param_1;
  __android_log_print(3,"FingerGoodix","fnCa_set_user_id");
  lStack_10 = -1;
  gx_ta_send_command(0x38,&uStack_18,8,&lStack_10,4);
  if (lStack_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(-(uint)(lStack_10 != 0));
}



int fnCa_SetFpdbToTa(char *param_1,undefined8 param_2)

{
  int iVar1;
  size_t sVar2;
  
  __android_log_print(3,"FingerGoodix","fnCa_SetFpdbToTa");
  sVar2 = strlen(param_1);
  iVar1 = gx_ta_send_command(0x3a,param_1,sVar2,param_2,4);
  return -(uint)(iVar1 != 0);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void fnCa_load_all_fpdata(void *param_1)

{
  int iVar1;
  undefined8 uVar2;
  undefined4 uStack_8c;
  undefined8 uStack_88;
  undefined8 uStack_80;
  undefined8 uStack_78;
  undefined8 uStack_70;
  undefined8 uStack_68;
  undefined8 uStack_60;
  undefined8 uStack_58;
  undefined8 uStack_50;
  undefined8 uStack_48;
  undefined8 uStack_40;
  undefined8 uStack_38;
  undefined8 uStack_30;
  undefined8 uStack_28;
  undefined8 uStack_20;
  undefined8 uStack_18;
  ulong uStack_10;
  long lStack_8;
  
  lStack_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","fnCa_load_all_fpdata");
  uStack_8c = 0;
  uStack_88 = 0;
  uStack_80 = 0;
  uStack_78 = 0;
  uStack_70 = 0;
  uStack_68 = 0;
  uStack_60 = 0;
  uStack_58 = 0;
  uStack_50 = 0;
  uStack_48 = 0;
  uStack_40 = 0;
  uStack_38 = 0;
  uStack_30 = 0;
  uStack_28 = 0;
  uStack_20 = 0;
  uStack_18 = 0;
  uStack_10 = 0;
  iVar1 = gx_ta_send_command(0x39,&uStack_8c,4,&uStack_88,0x80);
  if (iVar1 == 0) {
    __android_log_print(3,"FingerGoodix","current_num:%d\n",uStack_10 & 0xffffffff);
    memcpy(param_1,&uStack_88,0x80);
    uVar2 = 0;
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



int fnCa_send_cmd_to_ta(int param_1)

{
  undefined4 uVar1;
  int iVar2;
  
  if (param_1 == 0x96) {
    uVar1 = 0x82;
  }
  else {
    uVar1 = 0x83;
    if (param_1 != 0x97) {
      uVar1 = 0;
    }
  }
  iVar2 = gx_ta_send_command(uVar1);
  __android_log_print(3,"FingerGoodix","fnCa_send_cmd_to_ta ret:%d, cmd_id:%d",iVar2,param_1);
  return -(uint)(iVar2 != 0);
}



void FUN_0010d2d4(undefined8 param_1,undefined8 param_2,undefined4 param_3)

{
  __android_log_print(3,"FingerGoodix","fingerprint dump data");
  fnCa_dump_data(param_2,param_3);
  return;
}



void FUN_0010d314(void)

{
  __android_log_print(3,"FingerGoodix","fingerprint check reset.");
  device_check_reset();
  return;
}



void FUN_0010d33c(undefined8 param_1,undefined4 param_2)

{
  __android_log_print(3,"FingerGoodix","fingerprint SetSafeClass. class = 0x%x",param_2);
  fnCa__SetSafeClass(param_2);
  return;
}



void FUN_0010d378(undefined8 param_1,undefined4 param_2)

{
  device_set_recognize_flag(param_2);
  return;
}



void FUN_0010d380(void)

{
  device_set_screenoff_mode(1);
  return;
}



void FUN_0010d388(void)

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



void FUN_0010d398(void)

{
  __android_log_print(3,"FingerGoodix","%s %d \n","fingerprint_hal_pause_capture",0x108);
  device_pause_capture();
  return;
}



void FUN_0010d3cc(void)

{
  __android_log_print(3,"FingerGoodix","%s %d \n","fingerprint_hal_update_fdtupreg",0x103);
  device_update_fdtupreg();
  return;
}



void FUN_0010d404(undefined8 param_1,undefined8 param_2,undefined4 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6)

{
  fnCa_Fido_Recognize(param_2,param_3,param_4,param_5,param_6);
  return;
}



void FUN_0010d41c(undefined8 param_1,undefined4 param_2)

{
  device_setSpeed(param_2);
  return;
}



void FUN_0010d424(void)

{
  __android_log_print(3,"FingerGoodix","fingerprint clear wait finger command.");
  device_clear_waitfinger();
  return;
}



void FUN_0010d44c(void)

{
  __android_log_print(3,"FingerGoodix","fingerprint cancel wait finger command.");
  device_cancel_waitfinger();
  return;
}



void FUN_0010d474(undefined8 param_1,undefined8 param_2)

{
  __android_log_print(3,"FingerGoodix","fingerprint set notify function.");
  device_notify(param_2);
  return;
}



void FUN_0010d4ac(undefined8 param_1,undefined8 param_2)

{
  __android_log_print(3,"FingerGoodix","fingerprint get mode.");
  device_getMode(param_2);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0010d4e4(undefined8 param_1,undefined4 *param_2)

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



void FUN_0010d53c(undefined8 param_1,undefined4 param_2)

{
  device_irq_control(param_2);
  return;
}



void FUN_0010d544(undefined8 param_1,undefined4 param_2)

{
  __android_log_print(3,"FingerGoodix","fingerprint wait for finger up.");
  device_waitForFingerUp(param_2);
  return;
}



void FUN_0010d57c(undefined8 param_1,undefined4 param_2)

{
  __android_log_print(3,"FingerGoodix","fingerprint wait for finger .");
  device_waitForFinger(param_2);
  return;
}



void FUN_0010d5b4(undefined8 param_1,undefined param_2,undefined8 param_3)

{
  __android_log_print(3,"FingerGoodix","fingerprint device action.");
  device_action(param_2,param_3);
  return;
}



undefined4 FUN_0010d5f4(undefined8 param_1,long param_2)

{
  undefined4 uVar1;
  
  __android_log_print(3,"FingerGoodix","fingerprint get version.");
  uVar1 = device_getVersion(param_2);
  sprintf((char *)(param_2 + 0x180),"%s V%02x.%02x.%02x [%s_%s]","GX Hal",1,0,0x11,"May 24 2017",
          "12:54:51");
  return uVar1;
}



void FUN_0010d66c(undefined8 param_1,undefined4 param_2)

{
  __android_log_print(3,"FingerGoodix","fingerprint set mode. mode = 0x%x",param_2);
  device_setMode(param_2);
  return;
}



void FUN_0010d6a8(undefined8 param_1,undefined4 param_2)

{
  device_setMode(param_2);
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



void FUN_0010d6b4(undefined8 param_1,undefined4 param_2)

{
  fnCa_update_template(param_2);
  return;
}



void FUN_0010d6bc(undefined8 param_1,undefined8 param_2)

{
  fnCa_GetEnrollCnt(param_2);
  return;
}



void FUN_0010d6c4(undefined8 param_1,undefined8 param_2,undefined4 param_3)

{
  fnCa_SetEnrollCnt(param_2,param_3);
  return;
}



void FUN_0010d6d8(undefined8 param_1,undefined4 param_2,undefined8 param_3)

{
  fnCa_mp_test(param_2,param_3);
  return;
}



void FUN_0010d6e4(undefined8 param_1,undefined8 param_2)

{
  fnCa_get_hardware_info(param_2);
  return;
}



void FUN_0010d6ec(undefined8 param_1,undefined8 param_2,undefined4 param_3)

{
  fnCa_del_bmp_template(param_2,param_3);
  return;
}



void FUN_0010d6f8(undefined8 param_1,undefined8 param_2,undefined4 param_3,undefined8 param_4)

{
  fnCa_verify_bmp(param_2,param_3,param_4);
  return;
}



void FUN_0010d708(undefined8 param_1,undefined8 param_2,undefined4 param_3)

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



void FUN_0010d718(undefined8 param_1,undefined8 param_2,undefined4 param_3,undefined8 param_4)

{
  fnCa_reg_from_bmp(param_2,param_3,param_4);
  return;
}



void FUN_0010d728(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
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



void FUN_0010d740(undefined8 param_1,undefined8 param_2)

{
  fnCa_GetSessionID(param_2);
  return;
}



void FUN_0010d748(undefined8 param_1,undefined8 param_2)

{
  fnCa_SetSessionID(param_2);
  return;
}



void FUN_0010d750(undefined8 param_1,undefined4 param_2,undefined8 param_3,undefined4 param_4,
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



void FUN_0010d76c(undefined8 param_1,undefined8 param_2,undefined4 param_3)

{
  fnCa_VerifyFpPassword(param_2,param_3);
  return;
}



void FUN_0010d778(undefined8 param_1,undefined8 param_2,undefined4 param_3,undefined8 param_4,
                 undefined4 param_5)

{
  fnCa_ChangeFpPassword(param_2,param_3,param_4,param_5);
  return;
}



void FUN_0010d78c(undefined8 param_1,undefined8 param_2,undefined8 param_3)

{
  fnCa_GetFpTemplateIdList(param_2,param_3);
  return;
}



void FUN_0010d798(undefined8 param_1,undefined8 param_2,undefined4 param_3)

{
  fnCa_DelFpTemplates(param_2,param_3);
  return;
}



undefined8 fnCa_CancelRecognize(void)

{
  return 0;
}



void FUN_0010d7a8(undefined8 param_1,undefined4 param_2,undefined8 param_3,undefined4 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7)

{
  fnCa_Recognize(param_2,param_3,param_4,param_5,param_6,param_7);
  return;
}



void FUN_0010d7c4(undefined8 param_1,undefined4 param_2,undefined8 param_3,undefined4 param_4)

{
  fnCa_ChangeFpNameById(param_2,param_3,param_4);
  return;
}



void FUN_0010d7d4(undefined8 param_1,undefined4 param_2,undefined8 param_3,undefined8 param_4)

{
  fnCa_GetFpNameById(param_2,param_3,param_4);
  return;
}



void FUN_0010d7e4(undefined8 param_1,undefined8 param_2,undefined4 param_3,undefined8 param_4)

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



void FUN_0010d7f8(undefined8 param_1,undefined8 param_2)

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



int fnCa_OpenSession(void)

{
  int iVar1;
  
  iVar1 = gx_ta_start();
  if (iVar1 == 0) {
    __android_log_print(3,"FingerGoodix","Ta start success.");
    return 0;
  }
  __android_log_print(6,"FingerGoodix","Ta start failed.");
  return iVar1;
}



undefined8 FUN_0010d80c(void *param_1)

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
            __android_log_print(6,"FingerGoodix","Received message: %d. gIRQFlag:%d\n",cVar1,
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
  iVar1 = pthread_attr_init((pthread_attr_t *)&DAT_001274d0);
  if (iVar1 != 0) {
    __android_log_print(3,"FingerGoodix","Failed in pthread_attr_init. ret = %d\n",iVar1);
    return;
  }
  iVar1 = pthread_attr_setstacksize((pthread_attr_t *)&DAT_001274d0,0x20000);
  if (iVar1 == 0) {
    iVar1 = pthread_create(&DAT_00127508,(pthread_attr_t *)&DAT_001274d0,netlink_thread,(void *)0x0)
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
  if (DAT_00127508 != 0) {
    iVar1 = pthread_attr_destroy((pthread_attr_t *)&DAT_001274d0);
    if (iVar1 != 0) {
      __android_log_print(3,"FingerGoodix","Failed in pthread_attr_destory. ret = %d\n",iVar1);
    }
    __android_log_print(3,"FingerGoodix","Close netlink thread 2.\n");
    iVar1 = pthread_join(DAT_00127508,&pvStack_10);
    if (iVar1 == 0) {
      __android_log_print(3,"FingerGoodix","netlink channel exit code :\n");
    }
    else {
      __android_log_print(3,"FingerGoodix","Failed in  pthread_join.\n");
    }
    DAT_00127508 = 0;
  }
  free(nlh);
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(0);
}



undefined8 FUN_0010dce4(char *param_1,void *param_2,uint param_3)

{
  undefined8 uVar1;
  FILE *__s;
  
  if ((param_1 == (char *)0x0) || (param_2 == (void *)0x0)) {
    uVar1 = 0x3e9;
  }
  else {
    __s = fopen(param_1,"wb");
    if (__s != (FILE *)0x0) {
      fwrite(param_2,1,(ulong)param_3,__s);
      fflush(__s);
      fclose(__s);
      return 0;
    }
    uVar1 = 0;
  }
  return uVar1;
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
    uVar2 = 0x3e9;
  }
  else {
    uVar1 = param_3 + 3 & 0xfffffffc;
    DAT_00127194 = uVar1 * param_4;
    DAT_0012717a = 0x436;
    DAT_00127172 = DAT_00127194 + 0x436;
    DAT_00127180 = 0x28;
    DAT_00127184 = param_3;
    DAT_00127188 = param_4;
    __s = fopen(param_1,"wb");
    if (__s == (FILE *)0x0) {
      uVar2 = 0;
    }
    else {
      fwrite(&DAT_00127170,1,2,__s);
      fwrite(&DAT_00127172,1,4,__s);
      fwrite(&DAT_00127176,1,2,__s);
      fwrite(&DAT_00127178,1,2,__s);
      fwrite(&DAT_0012717a,1,4,__s);
      fwrite(&DAT_00127180,1,0x28,__s);
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

void gf_dump_data_interface(long param_1,uint param_2,long param_3)

{
  long lVar1;
  long lVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  int iVar6;
  int iVar7;
  undefined4 uVar8;
  tm *ptVar9;
  FILE *__s;
  size_t sVar10;
  byte *pbVar11;
  undefined4 *puVar12;
  char *pcVar13;
  byte *pbVar14;
  undefined4 uVar15;
  ulong uVar16;
  ulong uVar17;
  undefined4 uVar18;
  byte *local_830;
  time_t local_820;
  timeval tStack_818;
  undefined8 local_808;
  undefined8 uStack_800;
  undefined8 local_7f8;
  undefined4 local_7f0;
  char acStack_708 [256];
  char acStack_608 [256];
  char acStack_508 [256];
  char acStack_408 [1024];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  memset(&local_808,0,0x100);
  memset(acStack_708,0,0x100);
  __android_log_print(3,"FingerGoodix","[%s] enter","gf_dump_data_interface");
  if ((0xd < param_2 || param_3 == 0) || (param_1 == 0)) {
    __android_log_print(6,"FingerGoodix","[%s] bad parameter","gf_dump_data_interface");
    uVar8 = 0x3e9;
    goto LAB_0010e0ec;
  }
  iVar7 = *(int *)(param_1 + 0x5c09c);
  iVar3 = *(int *)(param_1 + 0x5c0a0);
  uVar5 = iVar3 * iVar7;
  __android_log_print(3,"FingerGoodix","operation:%d, result_str:%s, width:%d, height:%d.",param_2,
                      param_3,iVar7,iVar3);
  if (0x5000 < uVar5) {
    __android_log_print(6,"FingerGoodix","IMAGE_BUFFER_LEN is too small");
    uVar8 = 0xffffffff;
    goto LAB_0010e0ec;
  }
  local_820 = time((time_t *)0x0);
  memset(acStack_608,0,0x100);
  ptVar9 = localtime(&local_820);
  gettimeofday(&tStack_818,(__timezone_ptr_t)0x0);
  sprintf(acStack_608,"%04d-%02d-%02d-%02d-%02d-%02d-%06ld",(ulong)(ptVar9->tm_year + 0x76c),
          (ulong)(ptVar9->tm_mon + 1),(ulong)(uint)ptVar9->tm_mday,(ulong)(uint)ptVar9->tm_hour,
          (ulong)(uint)ptVar9->tm_min,(ulong)(uint)ptVar9->tm_sec,tStack_818.tv_usec);
  switch(param_2) {
  case 0:
  case 1:
    pcVar13 = "/data/gf_data/defect_pixel/";
    iVar6 = fs_mkdirs("/data/gf_data/defect_pixel/",0x1ed);
    if (-1 < iVar6) {
      sprintf(acStack_708,"%s%sbuf_a.bin","/data/gf_data/defect_pixel/",acStack_608);
      FUN_0010dce4(acStack_708,param_1 + 0x700a4,uVar5 * 2);
      sprintf(acStack_708,"%s%sbuf_b.bin","/data/gf_data/defect_pixel/",acStack_608);
      uVar8 = FUN_0010dce4(acStack_708,param_1 + 0x7a0a4,uVar5 * 2);
      if (param_2 == 1) {
        sprintf((char *)&local_808,"%s%u/","/data/gf_data/enroll/",
                (ulong)*(uint *)(param_1 + 0x32074));
      }
      else {
        local_7f8._0_1_ = 't';
        local_7f8._1_1_ = 'h';
        local_7f8._2_1_ = 'e';
        local_7f8._3_1_ = 'n';
        local_7f8._4_1_ = 't';
        local_7f8._5_1_ = 'i';
        local_7f8._6_1_ = 'c';
        local_7f8._7_1_ = 'a';
        local_7f0._0_1_ = 't';
        local_7f0._1_1_ = 'e';
        local_7f0._2_1_ = '/';
        local_7f0._3_1_ = '\0';
        local_808._0_1_ = '/';
        local_808._1_1_ = 'd';
        local_808._2_1_ = 'a';
        local_808._3_1_ = 't';
        local_808._4_1_ = 'a';
        local_808._5_1_ = '/';
        local_808._6_1_ = 'g';
        local_808._7_1_ = 'f';
        uStack_800._0_1_ = '_';
        uStack_800._1_1_ = 'd';
        uStack_800._2_1_ = 'a';
        uStack_800._3_1_ = 't';
        uStack_800._4_1_ = 'a';
        uStack_800._5_1_ = '/';
        uStack_800._6_1_ = 'a';
        uStack_800._7_1_ = 'u';
      }
      goto LAB_0010e3e8;
    }
LAB_0010e994:
    uVar8 = 0;
    __android_log_print(6,"FingerGoodix","[%s] make dir(%s) fail:%d","gf_dump_data_interface",
                        pcVar13);
    break;
  default:
    __android_log_print(6,"FingerGoodix","Not Support command \n");
    uVar8 = 0xffffffff;
    goto LAB_0010e0ec;
  case 5:
    iVar7 = fs_mkdirs("/data/gf_data/openshort/",0x1ed);
    if (iVar7 < 0) {
      uVar8 = 0;
      __android_log_print(6,"FingerGoodix","[%s] make dir(%s) fail:%d","gf_dump_data_interface",
                          "/data/gf_data/openshort/");
    }
    else {
      iVar7 = *(int *)(param_1 + 0x5c09c);
      iVar3 = *(int *)(param_1 + 0x5c0a0);
      sprintf(acStack_708,"%s%sbuf_a.bin","/data/gf_data/openshort/",acStack_608);
      iVar7 = iVar7 * iVar3 * 2;
      FUN_0010dce4(acStack_708,param_1 + 0x5c0a4,iVar7);
      sprintf(acStack_708,"%s%sbuf_b.bin","/data/gf_data/openshort/",acStack_608);
      uVar8 = FUN_0010dce4(acStack_708,param_1 + 0x660a4,iVar7);
    }
    break;
  case 8:
    uVar8 = 0;
    local_808._0_1_ = '/';
    local_808._1_1_ = 'd';
    local_808._2_1_ = 'a';
    local_808._3_1_ = 't';
    local_808._4_1_ = 'a';
    local_808._5_1_ = '/';
    local_808._6_1_ = 'g';
    local_808._7_1_ = 'f';
    uStack_800._0_1_ = '_';
    uStack_800._1_1_ = 'd';
    uStack_800._2_1_ = 'a';
    uStack_800._3_1_ = 't';
    uStack_800._4_1_ = 'a';
    uStack_800._5_1_ = '/';
    uStack_800._6_1_ = 'f';
    uStack_800._7_1_ = 'r';
    local_7f8._0_7_ = 0x2f7261665f72;
LAB_0010e3e8:
    iVar6 = fs_mkdirs(&local_808,0x1ed);
    if (iVar6 < 0) {
      __android_log_print(6,"FingerGoodix","[%s] make directory(%s) fail:%d",
                          "gf_dump_data_interface",&local_808,iVar6);
    }
    else {
      iVar6 = uVar5 * 2;
      __android_log_print(3,"FingerGoodix","[%s] enter","gf_dump_base_frame");
      memset(acStack_508,0,0x100);
      sprintf(acStack_508,"%s%s_rawdata.bin",&local_808,acStack_608);
      FUN_0010dce4(acStack_508,param_1 + 0x14060,iVar6);
      sprintf(acStack_508,"%s%s_kr.bin",&local_808,acStack_608);
      FUN_0010dce4(acStack_508,param_1 + 0x60,iVar6);
      sprintf(acStack_508,"%s%s_b.bin",&local_808,acStack_608);
      uVar8 = FUN_0010dce4(acStack_508,param_1 + 0xa060,iVar6);
      memset(acStack_408,0,0x400);
      sprintf(acStack_508,"%s%s_base_info.csv",&local_808,acStack_608);
      __s = fopen(acStack_508,"wb");
      uVar18 = (undefined4)((ulong)tStack_818.tv_usec >> 0x20);
      if (__s != (FILE *)0x0) {
        fwrite("algo version, ",1,0xe,__s);
        sVar10 = strlen((char *)(param_1 + 4));
        fwrite((char *)(param_1 + 4),1,sVar10,__s);
        fwrite("\n",1,1,__s);
        fwrite("sensor id, ",1,0xb,__s);
        pbVar11 = (byte *)(param_1 + 0x4a);
        do {
          pbVar14 = pbVar11 + 1;
          sprintf(acStack_408,"0x%02X, ",(ulong)*pbVar11);
          sVar10 = strlen(acStack_408);
          fwrite(acStack_408,1,sVar10,__s);
          pbVar11 = pbVar14;
        } while (pbVar14 != (byte *)(param_1 + 0x5a));
        fwrite("\n",1,1,__s);
        fwrite("product id, ",1,0xc,__s);
        pbVar11 = (byte *)(param_1 + 0x44);
        do {
          pbVar14 = pbVar11 + 1;
          sprintf(acStack_408,"0x%02X, ",(ulong)*pbVar11);
          sVar10 = strlen(acStack_408);
          fwrite(acStack_408,1,sVar10,__s);
          pbVar11 = pbVar14;
        } while (pbVar14 != (byte *)(param_1 + 0x46));
        fwrite("\n",1,1,__s);
        fwrite("vendor id, ",1,0xb,__s);
        local_830 = (byte *)(param_1 + 0x46);
        do {
          pbVar11 = local_830 + 1;
          sprintf(acStack_408,"0x%02X, ",(ulong)*local_830);
          sVar10 = strlen(acStack_408);
          fwrite(acStack_408,1,sVar10,__s);
          uVar18 = (undefined4)((ulong)tStack_818.tv_usec >> 0x20);
          local_830 = pbVar11;
        } while ((byte *)(param_1 + 0x4a) != pbVar11);
        fwrite("\n",1,1,__s);
        fwrite("frame num, ",1,0xb,__s);
        sprintf(acStack_408,"%04d,",(ulong)*(uint *)(param_1 + 0x5c));
        sVar10 = strlen(acStack_408);
        fwrite(acStack_408,1,sVar10,__s);
        fwrite("\n",1,1,__s);
        fflush(__s);
        fclose(__s);
      }
      lVar2 = param_1 + 0x28060;
      __android_log_print(3,"FingerGoodix","[%s] exit, err:%d","gf_dump_base_frame",uVar8);
      sprintf(acStack_708,"%s%s_%s_calires.bin",&local_808,acStack_608,param_3);
      FUN_0010dce4(acStack_708,param_1 + 0x1e060,iVar6);
      sprintf(acStack_708,"%s%s_%s_databmp.bin",&local_808,acStack_608,param_3);
      FUN_0010dce4(acStack_708,lVar2,uVar5);
      sprintf(acStack_708,"%s%s_%s_databmp.bmp",&local_808,acStack_608,param_3);
      gf_dump_image_to_bmp_file(acStack_708,lVar2,iVar7,iVar3);
      sprintf(acStack_708,"%s%s_%s_sitobmp.bin",&local_808,acStack_608,param_3);
      lVar1 = param_1 + 0x2d060;
      FUN_0010dce4(acStack_708,lVar1,uVar5);
      sprintf(acStack_708,"%s%s_%s_sitobmp.bmp",&local_808,acStack_608,param_3);
      gf_dump_image_to_bmp_file(acStack_708,lVar1,iVar7,iVar3);
      if (*(int *)(param_1 + 0x32060) != 0) {
        lVar2 = lVar1;
      }
      if (param_2 == 1) {
        uVar4 = *(uint *)(param_1 + 0x32070);
        pcVar13 = "%s%s_%s_selectbmp_%d_%d_%d_%d_%u.bmp";
        uVar8 = *(undefined4 *)(param_1 + 0x3206c);
        uVar15 = *(undefined4 *)(param_1 + 0x32078);
LAB_0010e8d4:
        sprintf(acStack_708,pcVar13,&local_808,acStack_608,param_3,
                (ulong)*(uint *)(param_1 + 0x32064),(ulong)*(uint *)(param_1 + 0x32068),(ulong)uVar4
                ,uVar8,uVar18,uVar15);
      }
      else {
        if (param_2 != 8) {
          uVar4 = *(uint *)(param_1 + 0x3207c);
          uVar8 = *(undefined4 *)(param_1 + 0x32080);
          pcVar13 = "%s%s_%s_selectbmp_%d_%d_%d_%u_%d.bmp";
          uVar15 = *(undefined4 *)(param_1 + 0x32084);
          goto LAB_0010e8d4;
        }
        sprintf(acStack_708,"%s%s_%s_selectbmp_%d_%d.bmp",&local_808,acStack_608,param_3,
                (ulong)*(uint *)(param_1 + 0x32064),(ulong)*(uint *)(param_1 + 0x32068));
      }
      gf_dump_image_to_bmp_file(acStack_708,lVar2,iVar7,iVar3);
      puVar12 = (undefined4 *)strstr(acStack_708,".bmp");
      *puVar12 = 0x6e69622e;
      *(undefined *)(puVar12 + 1) = 0;
      uVar8 = FUN_0010dce4(acStack_708,lVar2,uVar5);
    }
    break;
  case 9:
  case 10:
    iVar7 = *(int *)(param_1 + 0x5c088);
    iVar3 = *(int *)(param_1 + 0x5c08c);
    iVar6 = fs_mkdirs("/data/gf_data/base/nav_base/",0x1ed);
    if (iVar6 < 0) {
      uVar8 = 0;
      __android_log_print(6,"FingerGoodix","[%s] make dir(%s) fail:%d","gf_dump_data_interface",
                          "/data/gf_data/base/nav_base/");
    }
    else {
      pcVar13 = "/data/gf_data/navigation/";
      iVar6 = fs_mkdirs("/data/gf_data/navigation/",0x1ed);
      if (iVar6 < 0) goto LAB_0010e994;
      iVar3 = iVar3 * iVar7;
      uVar8 = 0;
      iVar7 = iVar3 * 2;
      if (*(int *)(param_1 + 0x5c094) == 1) {
        sprintf(acStack_708,"%s%s.bin","/data/gf_data/base/nav_base/",acStack_608);
        uVar8 = FUN_0010dce4(acStack_708,param_1 + 0x32088,iVar7);
      }
      if ((*(int *)(param_1 + 0x5c098) == 1) && (*(int *)(param_1 + 0x5c090) != 0)) {
        uVar16 = 0;
        uVar17 = 0;
        do {
          uVar5 = (int)uVar17 + 1;
          sprintf(acStack_708,"%s%s_%s_frame%d.bin","/data/gf_data/navigation/",acStack_608,param_3,
                  uVar17);
          lVar2 = uVar16 + 0x1a000;
          uVar16 = (ulong)(uint)((int)uVar16 + iVar3);
          uVar8 = FUN_0010dce4(acStack_708,param_1 + lVar2 * 2 + 0x88,iVar7);
          uVar17 = (ulong)uVar5;
        } while (uVar5 < *(uint *)(param_1 + 0x5c090));
      }
    }
  }
  __android_log_print(3,"FingerGoodix","[%s] exit","gf_dump_data_interface");
LAB_0010e0ec:
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar8);
}



undefined4 keymaster_ta_start(void)

{
  undefined4 uVar1;
  undefined4 *puVar2;
  
  uVar1 = 0;
  __android_log_print(3,"FingerGoodix",&DAT_001110c0,"keymaster_ta_start");
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



void FUN_0010ee2c(long param_1,undefined *param_2,int param_3)

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
  if (param_3 < 1) goto LAB_0010f048;
  if (param_3 == 1) {
    uVar4 = 0;
LAB_0010f078:
    uVar5 = 0;
LAB_0010f07c:
    uVar6 = 0;
LAB_0010f080:
    uVar7 = 0;
LAB_0010f084:
    uVar3 = 0;
  }
  else {
    uVar4 = param_2[1];
    if (param_3 == 2) goto LAB_0010f078;
    uVar5 = param_2[2];
    if (param_3 == 3) goto LAB_0010f07c;
    uVar6 = param_2[3];
    if (param_3 == 4) goto LAB_0010f080;
    uVar7 = param_2[4];
    if (param_3 == 5) goto LAB_0010f084;
    uVar3 = param_2[5];
  }
  __android_log_print(3,"FingerGoodix",
                      " %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
                      *param_2,uVar4,uVar5,uVar6,uVar7,uVar3);
LAB_0010f048:
  __android_log_print(3,"FingerGoodix","--------------------------------");
  return;
}



undefined8
FUN_0010f0bc(undefined4 param_1,void *param_2,int param_3,void *param_4,int param_5,int *param_6)

{
  int iVar1;
  ulong __size;
  undefined4 *__ptr;
  ulong __size_00;
  void *__ptr_00;
  size_t __n;
  undefined8 uVar2;
  
  if (param_2 == (void *)0x0) {
    __n = 0;
    __size = 4;
  }
  else {
    __size = (ulong)(param_3 + 4);
    __n = (size_t)param_3;
  }
  __ptr = (undefined4 *)malloc(__size);
  *__ptr = param_1;
  memcpy(__ptr + 1,param_2,__n);
  if (param_4 == (void *)0x0) {
    param_5 = 0;
    __size_00 = 8;
  }
  else {
    __size_00 = (ulong)(param_5 + 8);
  }
  __ptr_00 = malloc(__size_00);
  if (param_6 != (int *)0x0) {
    *param_6 = 0;
  }
  iVar1 = gx_ta_send_command(0x7f,__ptr,__size,__ptr_00,__size_00);
  if (iVar1 != 0) {
    uVar2 = 0xfffffffe;
    free(__ptr);
    if (__ptr_00 == (void *)0x0) {
      return 0xfffffffe;
    }
    goto LAB_0010f1f0;
  }
  iVar1 = *(int *)((long)__ptr_00 + 4);
  __android_log_print(3,"FingerGoodix","HAL ta_cmd[%d], rsp buf len:%d, rsp data len:%d",param_1,
                      param_5,iVar1);
  if (iVar1 < 1) {
LAB_0010f24c:
    uVar2 = 0;
  }
  else {
    if ((0 < param_5 && param_4 != (void *)0x0) && (iVar1 <= param_5)) {
      memcpy(param_4,(void *)((long)__ptr_00 + 8),(long)iVar1);
      if (param_6 != (int *)0x0) {
        *param_6 = iVar1;
      }
      goto LAB_0010f24c;
    }
    uVar2 = 0xffffffff;
    __android_log_print(6,"FingerGoodix","HAL ta_cmd[%d], data error!",param_1);
  }
  free(__ptr);
LAB_0010f1f0:
  free(__ptr_00);
  return uVar2;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void hal_gfcmd_m(long param_1,undefined4 param_2,undefined8 *param_3,int param_4,long param_5,
                int param_6,undefined4 *param_7)

{
  int iVar1;
  uint uVar2;
  ulong uVar3;
  int local_20c;
  undefined8 local_208;
  undefined8 uStack_200;
  undefined8 local_1f8;
  undefined8 uStack_1f0;
  undefined8 local_1e8;
  undefined8 uStack_1e0;
  undefined8 local_1d8;
  undefined8 uStack_1d0;
  undefined4 local_1c8;
  undefined local_1c4;
  undefined auStack_1c3 [4];
  int local_1bf;
  int local_1bb;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  if (param_1 == 0) {
LAB_0010f430:
    uVar3 = 0xffffffff;
  }
  else {
    switch(param_2) {
    case 2:
    case 5:
    case 10:
    case 0x50:
    case 0x51:
      __android_log_print(3,"FingerGoodix","HAL transmit cmd[%d] to TA",param_2);
      uVar3 = FUN_0010f0bc(param_2,param_3,param_4,param_5,param_6,param_7);
      break;
    case 3:
      if ((param_4 == 0x45) && (param_6 == 0x45)) {
        __android_log_print(3,"FingerGoodix","fnCa gen hmac, token:%p, tokenLen=%d",param_3,0x45);
        memset(&local_208,0,0x200);
        local_1c4 = *(undefined *)((long)param_3 + 0x44);
        local_1f8 = param_3[2];
        uStack_1f0 = param_3[3];
        local_1e8 = param_3[4];
        uStack_1e0 = param_3[5];
        local_1d8 = param_3[6];
        uStack_1d0 = param_3[7];
        local_1c8 = *(undefined4 *)(param_3 + 8);
        local_208 = *param_3;
        uStack_200 = param_3[1];
        FUN_0010ee2c("FnCa1, TEE auth token",&local_208,0x25);
        FUN_0010ee2c("FnCa1, TEE auth hmac",(long)&local_1e8 + 5,0x20);
        iVar1 = getKeyFromKeymaster(auStack_1c3,0x1bb);
        if (iVar1 == 0) {
          __android_log_print(3,"FingerGoodix","fnCa gen hmac, get key OK!",0);
          local_20c = 0;
          uVar2 = FUN_0010f0bc(3,&local_208,local_1bf + local_1bb + 0x45,param_5,0x45,&local_20c);
          uVar3 = (ulong)uVar2;
          if (uVar2 == 0) {
            if (local_20c == 0x45) {
              __android_log_print(3,"FingerGoodix","TA return OK.");
              FUN_0010ee2c("FnCa2, TEE auth token",param_5,0x25);
              FUN_0010ee2c("FnCa2, TEE auth hmac",param_5 + 0x25,0x20);
            }
            else {
              __android_log_print(3,"FingerGoodix","TA return failed, code: %d",0);
            }
            uVar3 = 0;
            *param_7 = 0x45;
          }
          else {
            __android_log_print(3,"FingerGoodix","TA return failed, code: %d",uVar3);
            *param_7 = 0;
          }
        }
        else {
          __android_log_print(6,"FingerGoodix","get key failed! ret: %d",iVar1);
          uVar3 = 0xffffffff;
          *param_7 = 0;
        }
        break;
      }
      goto LAB_0010f430;
    case 4:
      __android_log_print(3,"FingerGoodix","gfcmd_enroll_verify");
      local_20c = -1;
      memset(&local_208,0,0x200);
      local_1d8 = param_3[6];
      uStack_1d0 = param_3[7];
      local_1c8 = *(undefined4 *)(param_3 + 8);
      local_208 = *param_3;
      uStack_200 = param_3[1];
      local_1f8 = param_3[2];
      uStack_1f0 = param_3[3];
      local_1e8 = param_3[4];
      uStack_1e0 = param_3[5];
      local_1c4 = *(undefined *)((long)param_3 + 0x44);
      iVar1 = getKeyFromKeymaster(auStack_1c3,0x1bb);
      if (iVar1 == 0) {
        __android_log_print(3,"FingerGoodix","gfcmd gen hmac, get key OK!",0);
        FUN_0010f0bc(4,&local_208,local_1bf + local_1bb + 0x45,&local_20c,4,param_7);
        __android_log_print(3,"FingerGoodix","gfcmd_enroll_verify:result:%d\n",local_20c);
        uVar3 = (ulong)-(uint)(local_20c != 0);
      }
      else {
        __android_log_print(6,"FingerGoodix","get key failed! ret: %d",iVar1);
        uVar3 = 0xffffffff;
      }
      break;
    case 6:
    case 7:
      __android_log_print(3,"FingerGoodix","HAL consume cmd[%d]",param_2);
      uVar3 = 0;
      break;
    default:
      __android_log_print(6,"FingerGoodix","HAL gfCmdM, not support cmd:%d!",param_2);
      uVar3 = 0xffffffff;
    }
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar3);
}



void set_fp_enabled(undefined4 param_1)

{
  DAT_001271e0 = param_1;
  return;
}



int get_fp_enabled(void)

{
  if (DAT_001271e0 == 0) {
    __android_log_print(6,"FingerGoodix","HAL, fingerprint has been disabled!");
  }
  return DAT_001271e0;
}


