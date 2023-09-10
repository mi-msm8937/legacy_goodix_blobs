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

typedef struct BpInterface<android::IFingerPrintClient> BpInterface<android::IFingerPrintClient>, *PBpInterface<android::IFingerPrintClient>;

struct BpInterface<android::IFingerPrintClient> { // PlaceHolder Class Structure
};

typedef struct BpInterface<android::IFingerPrintService> BpInterface<android::IFingerPrintService>, *PBpInterface<android::IFingerPrintService>;

struct BpInterface<android::IFingerPrintService> { // PlaceHolder Class Structure
};

typedef struct BpInterface<android::IFingerPrint> BpInterface<android::IFingerPrint>, *PBpInterface<android::IFingerPrint>;

struct BpInterface<android::IFingerPrint> { // PlaceHolder Class Structure
};

typedef union sem_t sem_t, *Psem_t;

union sem_t {
    char __size[32];
    long __align;
};

typedef struct _IO_FILE FILE;

typedef long __ssize_t;

typedef __ssize_t ssize_t;

typedef int __pid_t;

typedef uint __useconds_t;

typedef long __suseconds_t;

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

typedef int pthread_once_t;

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

typedef uint pthread_key_t;

typedef union pthread_attr_t pthread_attr_t, *Ppthread_attr_t;

union pthread_attr_t {
    char __size[56];
    long __align;
};

typedef union pthread_condattr_t pthread_condattr_t, *Ppthread_condattr_t;

union pthread_condattr_t {
    char __size[4];
    int __align;
};

typedef struct timezone timezone, *Ptimezone;

struct timezone {
    int tz_minuteswest;
    int tz_dsttime;
};

typedef __time_t time_t;

typedef struct timeval timeval, *Ptimeval;

struct timeval {
    __time_t tv_sec;
    __suseconds_t tv_usec;
};

typedef struct timezone * __timezone_ptr_t;

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

typedef dword fpalgo_act_status;

typedef struct BpFingerPrintClient BpFingerPrintClient, *PBpFingerPrintClient;

struct BpFingerPrintClient { // PlaceHolder Structure
};

typedef struct hw_auth_token_t hw_auth_token_t, *Phw_auth_token_t;

struct hw_auth_token_t { // PlaceHolder Structure
};

typedef dword fingerprint_chip_mode;

typedef struct BpFingerPrint BpFingerPrint, *PBpFingerPrint;

struct BpFingerPrint { // PlaceHolder Structure
};

typedef struct BpFingerPrintService BpFingerPrintService, *PBpFingerPrintService;

struct BpFingerPrintService { // PlaceHolder Structure
};

typedef struct __forced_unwind __forced_unwind, *P__forced_unwind;

struct __forced_unwind { // PlaceHolder Structure
};

typedef struct __class_type_info __class_type_info, *P__class_type_info;

struct __class_type_info { // PlaceHolder Structure
};

typedef struct __foreign_exception __foreign_exception, *P__foreign_exception;

struct __foreign_exception { // PlaceHolder Structure
};

typedef struct __si_class_type_info __si_class_type_info, *P__si_class_type_info;

struct __si_class_type_info { // PlaceHolder Structure
};

typedef struct __upcast_result __upcast_result, *P__upcast_result;

struct __upcast_result { // PlaceHolder Structure
};

typedef struct __dyncast_result __dyncast_result, *P__dyncast_result;

struct __dyncast_result { // PlaceHolder Structure
};

typedef dword __sub_kind;

typedef struct exception exception, *Pexception;

struct exception { // PlaceHolder Structure
};

typedef struct bad_alloc bad_alloc, *Pbad_alloc;

struct bad_alloc { // PlaceHolder Structure
};

typedef struct type_info type_info, *Ptype_info;

struct type_info { // PlaceHolder Structure
};

typedef struct bad_cast bad_cast, *Pbad_cast;

struct bad_cast { // PlaceHolder Structure
};

typedef struct bad_exception bad_exception, *Pbad_exception;

struct bad_exception { // PlaceHolder Structure
};

typedef struct bad_typeid bad_typeid, *Pbad_typeid;

struct bad_typeid { // PlaceHolder Structure
};

typedef struct exception_ptr exception_ptr, *Pexception_ptr;

struct exception_ptr { // PlaceHolder Structure
};

typedef struct IBinder IBinder, *PIBinder;

struct IBinder { // PlaceHolder Structure
};

typedef struct sp sp, *Psp;

struct sp { // PlaceHolder Structure
};

typedef struct wp wp, *Pwp;

struct wp { // PlaceHolder Structure
};

typedef struct IFingerPrintClient IFingerPrintClient, *PIFingerPrintClient;

struct IFingerPrintClient { // PlaceHolder Structure
};

typedef struct Vector Vector, *PVector;

struct Vector { // PlaceHolder Structure
};

typedef struct IFingerPrintService IFingerPrintService, *PIFingerPrintService;

struct IFingerPrintService { // PlaceHolder Structure
};

typedef struct Parcel Parcel, *PParcel;

struct Parcel { // PlaceHolder Structure
};

typedef struct IInterface IInterface, *PIInterface;

struct IInterface { // PlaceHolder Structure
};

typedef struct String8 String8, *PString8;

struct String8 { // PlaceHolder Structure
};

typedef struct Mutex Mutex, *PMutex;

struct Mutex { // PlaceHolder Structure
};

typedef struct sp<android::FpService::Client> sp<android::FpService::Client>, *Psp<android::FpService::Client>;

struct sp<android::FpService::Client> { // PlaceHolder Structure
};

typedef struct RefBase RefBase, *PRefBase;

struct RefBase { // PlaceHolder Structure
};

typedef dword fpContext;

typedef struct BpRefBase BpRefBase, *PBpRefBase;

struct BpRefBase { // PlaceHolder Structure
};

typedef struct String16 String16, *PString16;

struct String16 { // PlaceHolder Structure
};

typedef struct BnInterface<android::IFingerPrint> BnInterface<android::IFingerPrint>, *PBnInterface<android::IFingerPrint>;

struct BnInterface<android::IFingerPrint> { // PlaceHolder Structure
};

typedef struct FpService FpService, *PFpService;

struct FpService { // PlaceHolder Structure
};

typedef struct BnFingerPrintClient BnFingerPrintClient, *PBnFingerPrintClient;

struct BnFingerPrintClient { // PlaceHolder Structure
};

typedef struct BnInterface<android::IFingerPrintClient> BnInterface<android::IFingerPrintClient>, *PBnInterface<android::IFingerPrintClient>;

struct BnInterface<android::IFingerPrintClient> { // PlaceHolder Structure
};

typedef struct BnFingerPrintService BnFingerPrintService, *PBnFingerPrintService;

struct BnFingerPrintService { // PlaceHolder Structure
};

typedef struct sp<android::FpService> sp<android::FpService>, *Psp<android::FpService>;

struct sp<android::FpService> { // PlaceHolder Structure
};

typedef struct IFingerPrint IFingerPrint, *PIFingerPrint;

struct IFingerPrint { // PlaceHolder Structure
};

typedef struct BnInterface<android::IFingerPrintService> BnInterface<android::IFingerPrintService>, *PBnInterface<android::IFingerPrintService>;

struct BnInterface<android::IFingerPrintService> { // PlaceHolder Structure
};

typedef struct sp<android::IFingerPrintClient> sp<android::IFingerPrintClient>, *Psp<android::IFingerPrintClient>;

struct sp<android::IFingerPrintClient> { // PlaceHolder Structure
};

typedef struct BnFingerPrint BnFingerPrint, *PBnFingerPrint;

struct BnFingerPrint { // PlaceHolder Structure
};

typedef struct BBinder BBinder, *PBBinder;

struct BBinder { // PlaceHolder Structure
};

typedef struct Client Client, *PClient;

struct Client { // PlaceHolder Structure
};

typedef struct recursive_init_error recursive_init_error, *Precursive_init_error;

struct recursive_init_error { // PlaceHolder Structure
};

typedef struct Elf64_Rela Elf64_Rela, *PElf64_Rela;

struct Elf64_Rela {
    qword r_offset; // location to apply the relocation action
    qword r_info; // the symbol table index and the type of relocation
    qword r_addend; // a constant addend used to compute the relocatable field value
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




void FUN_00114c00(void)

{
  (*(code *)(undefined *)0x0)();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

char * strerror(int __errnum)

{
  char *pcVar1;
  
  pcVar1 = strerror(__errnum);
  return pcVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void * memcpy(void *__dest,void *__src,size_t __n)

{
  void *pvVar1;
  
  pvVar1 = memcpy(__dest,__src,__n);
  return pvVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int gettimeofday(timeval *__tv,__timezone_ptr_t __tz)

{
  int iVar1;
  
  iVar1 = gettimeofday(__tv,__tz);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void android::Parcel::writeCString(char *param_1)

{
  writeCString(param_1);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void * memchr(void *__s,int __c,size_t __n)

{
  void *pvVar1;
  
  pvVar1 = memchr(__s,__c,__n);
  return pvVar1;
}



void __thiscall android::BpRefBase::BpRefBase(BpRefBase *this,sp *param_1)

{
  BpRefBase(this,param_1);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int sem_destroy(sem_t *__sem)

{
  int iVar1;
  
  iVar1 = sem_destroy(__sem);
  return iVar1;
}



void property_set(void)

{
  property_set();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void android::Parcel::write(void *param_1,ulong param_2)

{
  write(param_1,param_2);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void android::Parcel::writeInterfaceToken(String16 *param_1)

{
  writeInterfaceToken(param_1);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int usleep(__useconds_t __useconds)

{
  int iVar1;
  
  iVar1 = usleep(__useconds);
  return iVar1;
}



void __thiscall android::Parcel::Parcel(Parcel *this)

{
  Parcel(this);
  return;
}



void __thiscall android::String16::String16(String16 *this,char *param_1)

{
  String16(this,param_1);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int rename(char *__old,char *__new)

{
  int iVar1;
  
  iVar1 = rename(__old,__new);
  return iVar1;
}



void hw_get_module(void)

{
  hw_get_module();
  return;
}



void __thiscall android::Parcel::~Parcel(Parcel *this)

{
  ~Parcel(this);
  return;
}



void __thiscall android::RefBase::~RefBase(RefBase *this)

{
  ~RefBase(this);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int pthread_mutex_destroy(pthread_mutex_t *__mutex)

{
  int iVar1;
  
  iVar1 = pthread_mutex_destroy(__mutex);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int close(int __fd)

{
  int iVar1;
  
  iVar1 = close(__fd);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void android::Parcel::writeInt32(int param_1)

{
  writeInt32(param_1);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void android::String8::append(char *param_1)

{
  append(param_1);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void android::BpRefBase::onIncStrongAttempted(uint param_1,void *param_2)

{
  onIncStrongAttempted(param_1,param_2);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void android::RefBase::onLastWeakRef(void *param_1)

{
  onLastWeakRef(param_1);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int pthread_mutex_trylock(pthread_mutex_t *__mutex)

{
  int iVar1;
  
  iVar1 = pthread_mutex_trylock(__mutex);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void android::BpRefBase::onLastStrongRef(void *param_1)

{
  onLastStrongRef(param_1);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void free(void *__ptr)

{
  free(__ptr);
  return;
}



void __thiscall android::BBinder::BBinder(BBinder *this)

{
  BBinder(this);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int pthread_key_delete(pthread_key_t __key)

{
  int iVar1;
  
  iVar1 = pthread_key_delete(__key);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int strcmp(char *__s1,char *__s2)

{
  int iVar1;
  
  iVar1 = strcmp(__s1,__s2);
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

long atol(char *__nptr)

{
  long lVar1;
  
  lVar1 = atol(__nptr);
  return lVar1;
}



void __thiscall android::IInterface::~IInterface(IInterface *this)

{
  ~IInterface(this);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void android::BpRefBase::onFirstRef(void)

{
  onFirstRef();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int pthread_cond_destroy(pthread_cond_t *__cond)

{
  int iVar1;
  
  iVar1 = pthread_cond_destroy(__cond);
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

void android::checkCallingPermission(String16 *param_1)

{
  checkCallingPermission(param_1);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void android::Parcel::readStrongBinder(void)

{
  readStrongBinder();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

__pid_t getpid(void)

{
  __pid_t _Var1;
  
  _Var1 = getpid();
  return _Var1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void android::BBinder::localBinder(void)

{
  localBinder();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int sem_post(sem_t *__sem)

{
  int iVar1;
  
  iVar1 = sem_post(__sem);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int pthread_setspecific(pthread_key_t __key,void *__pointer)

{
  int iVar1;
  
  iVar1 = pthread_setspecific(__key,__pointer);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void * memmove(void *__dest,void *__src,size_t __n)

{
  void *pvVar1;
  
  pvVar1 = memmove(__dest,__src,__n);
  return pvVar1;
}



void __thiscall android::RefBase::RefBase(RefBase *this)

{
  RefBase(this);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void android::BBinder::unlinkToDeath(wp *param_1,void *param_2,uint param_3,wp *param_4)

{
  unlinkToDeath(param_1,param_2,param_3,param_4);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int pthread_once(pthread_once_t *__once_control,__init_routine *__init_routine)

{
  int iVar1;
  
  iVar1 = pthread_once(__once_control,__init_routine);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void android::Parcel::dataAvail(void)

{
  dataAvail();
  return;
}



void __google_potentially_blocking_region_end(void)

{
  __google_potentially_blocking_region_end();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

size_t strlen(char *__s)

{
  size_t sVar1;
  
  sVar1 = strlen(__s);
  return sVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void android::BBinder::onTransact(uint param_1,Parcel *param_2,Parcel *param_3,uint param_4)

{
  onTransact(param_1,param_2,param_3,param_4);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

char * strstr(char *__haystack,char *__needle)

{
  char *pcVar1;
  
  pcVar1 = strstr(__haystack,__needle);
  return pcVar1;
}



void __thiscall android::BpRefBase::~BpRefBase(BpRefBase *this)

{
  ~BpRefBase(this);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void * realloc(void *__ptr,size_t __size)

{
  void *pvVar1;
  
  pvVar1 = realloc(__ptr,__size);
  return pvVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void android::Parcel::readInplace(ulong param_1)

{
  readInplace(param_1);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void android::RefBase::decStrong(void *param_1)

{
  decStrong(param_1);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void android::Parcel::read(void *param_1,ulong param_2)

{
  read(param_1,param_2);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void android::BBinder::findObject(void *param_1)

{
  findObject(param_1);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int strncmp(char *__s1,char *__s2,size_t __n)

{
  int iVar1;
  
  iVar1 = strncmp(__s1,__s2,__n);
  return iVar1;
}



void android::BpRefBase::onLastStrongRef(void)

{
  onLastStrongRef();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int fputc(int __c,FILE *__stream)

{
  int iVar1;
  
  iVar1 = fputc(__c,__stream);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int snprintf(char *__s,size_t __maxlen,char *__format,...)

{
  int iVar1;
  
  iVar1 = snprintf(__s,__maxlen,__format);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void android::Parcel::writeStrongBinder(sp *param_1)

{
  writeStrongBinder(param_1);
  return;
}



void __android_log_print(void)

{
  __android_log_print();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void android::Parcel::writeInt64(long param_1)

{
  writeInt64(param_1);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int remove(char *__filename)

{
  int iVar1;
  
  iVar1 = remove(__filename);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int pthread_mutex_unlock(pthread_mutex_t *__mutex)

{
  int iVar1;
  
  iVar1 = pthread_mutex_unlock(__mutex);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void android::RefBase::onIncStrongAttempted(uint param_1,void *param_2)

{
  onIncStrongAttempted(param_1,param_2);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void android::IBinder::localBinder(void)

{
  localBinder();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void android::IInterface::asBinder(sp *param_1)

{
  asBinder(param_1);
  return;
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

size_t fwrite(void *__ptr,size_t __size,size_t __n,FILE *__s)

{
  size_t sVar1;
  
  sVar1 = fwrite(__ptr,__size,__n,__s);
  return sVar1;
}



void __thiscall android::IInterface::IInterface(IInterface *this)

{
  IInterface(this);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

long syscall(long __sysno,...)

{
  long lVar1;
  
  lVar1 = syscall(__sysno);
  return lVar1;
}



void android::BpRefBase::onFirstRef(void)

{
  onFirstRef();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void * memset(void *__s,int __c,size_t __n)

{
  void *pvVar1;
  
  pvVar1 = memset(__s,__c,__n);
  return pvVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int pthread_mutex_init(pthread_mutex_t *__mutex,pthread_mutexattr_t *__mutexattr)

{
  int iVar1;
  
  iVar1 = pthread_mutex_init(__mutex,__mutexattr);
  return iVar1;
}



void __google_potentially_blocking_region_begin(void)

{
  __google_potentially_blocking_region_begin();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void android::BBinder::transact(uint param_1,Parcel *param_2,Parcel *param_3,uint param_4)

{
  transact(param_1,param_2,param_3,param_4);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int sem_init(sem_t *__sem,int __pshared,uint __value)

{
  int iVar1;
  
  iVar1 = sem_init(__sem,__pshared,__value);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int stat(char *__file,stat *__buf)

{
  int iVar1;
  
  iVar1 = stat(__file,__buf);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void * pthread_getspecific(pthread_key_t __key)

{
  void *pvVar1;
  
  pvVar1 = pthread_getspecific(__key);
  return pvVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void android::BBinder::attachObject
               (void *param_1,void *param_2,void *param_3,
               _func_void_void_ptr_void_ptr_void_ptr *param_4)

{
  attachObject(param_1,param_2,param_3,param_4);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void android::IBinder::remoteBinder(void)

{
  remoteBinder();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void abort(void)

{
                    // WARNING: Subroutine does not return
  abort();
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void android::Parcel::readCString(void)

{
  readCString();
  return;
}



void property_get_int32(void)

{
  property_get_int32();
  return;
}



void __cxa_atexit(void)

{
  __cxa_atexit();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void android::Parcel::checkInterface(IBinder *param_1)

{
  checkInterface(param_1);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void android::IBinder::queryLocalInterface(String16 *param_1)

{
  queryLocalInterface(param_1);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int atoi(char *__nptr)

{
  int iVar1;
  
  iVar1 = atoi(__nptr);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void android::BBinder::pingBinder(void)

{
  pingBinder();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int memcmp(void *__s1,void *__s2,size_t __n)

{
  int iVar1;
  
  iVar1 = memcmp(__s1,__s2,__n);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

ssize_t write(int __fd,void *__buf,size_t __n)

{
  ssize_t sVar1;
  
  sVar1 = write(__fd,__buf,__n);
  return sVar1;
}



void __thiscall android::String8::~String8(String8 *this)

{
  ~String8(this);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void android::BBinder::getInterfaceDescriptor(void)

{
  getInterfaceDescriptor();
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

void android::RefBase::onLastStrongRef(void *param_1)

{
  onLastStrongRef(param_1);
  return;
}



void strzcmp16(void)

{
  strzcmp16();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int pthread_mutex_lock(pthread_mutex_t *__mutex)

{
  int iVar1;
  
  iVar1 = pthread_mutex_lock(__mutex);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void android::BBinder::detachObject(void *param_1)

{
  detachObject(param_1);
  return;
}



void android::BpRefBase::onIncStrongAttempted(void)

{
  onIncStrongAttempted();
  return;
}



void __cxa_finalize(void)

{
  __cxa_finalize();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void android::Parcel::readInt32(void)

{
  readInt32();
  return;
}



void __thiscall android::String8::String8(String8 *this,String16 *param_1)

{
  String8(this,param_1);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

tm * localtime(time_t *__timer)

{
  tm *ptVar1;
  
  ptVar1 = localtime(__timer);
  return ptVar1;
}



void __thiscall android::String8::String8(String8 *this,char *param_1)

{
  String8(this,param_1);
  return;
}



void __thiscall android::String16::~String16(String16 *this)

{
  ~String16(this);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int pthread_key_create(pthread_key_t *__key,__destr_function *__destr_function)

{
  int iVar1;
  
  iVar1 = pthread_key_create(__key,__destr_function);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void android::BBinder::dump(int param_1,Vector *param_2)

{
  dump(param_1,param_2);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void android::BBinder::isBinderAlive(void)

{
  isBinderAlive();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void android::IBinder::checkSubclass(void *param_1)

{
  checkSubclass(param_1);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void android::RefBase::onFirstRef(void)

{
  onFirstRef();
  return;
}



void property_get(void)

{
  property_get();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

time_t time(time_t *__timer)

{
  time_t tVar1;
  
  tVar1 = time(__timer);
  return tVar1;
}



void __stack_chk_fail(void)

{
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int fputs(char *__s,FILE *__stream)

{
  int iVar1;
  
  iVar1 = fputs(__s,__stream);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void android::Parcel::readInt64(void)

{
  readInt64();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void android::BBinder::linkToDeath(sp *param_1,void *param_2,uint param_3)

{
  linkToDeath(param_1,param_2,param_3);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int pthread_cond_init(pthread_cond_t *__cond,pthread_condattr_t *__cond_attr)

{
  int iVar1;
  
  iVar1 = pthread_cond_init(__cond,__cond_attr);
  return iVar1;
}



void __thiscall android::BBinder::~BBinder(BBinder *this)

{
  ~BBinder(this);
  return;
}



void __thiscall android::String8::String8(String8 *this)

{
  String8(this);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void android::RefBase::incStrong(void *param_1)

{
  incStrong(param_1);
  return;
}



void dl_iterate_phdr(void)

{
  dl_iterate_phdr();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int open(char *__file,int __oflag,...)

{
  int iVar1;
  
  iVar1 = open(__file,__oflag);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int sem_getvalue(sem_t *__sem,int *__sval)

{
  int iVar1;
  
  iVar1 = sem_getvalue(__sem,__sval);
  return iVar1;
}



// WARNING: Removing unreachable block (ram,0x00115404)

void entry(void *param_1)

{
  int *piVar1;
  int iVar2;
  char cVar3;
  bool bVar4;
  
  piVar1 = (int *)((long)param_1 + 0x10);
  do {
    iVar2 = *piVar1;
    cVar3 = '\x01';
    bVar4 = (bool)ExclusiveMonitorPass(piVar1,0x10);
    if (bVar4) {
      *piVar1 = iVar2 + -1;
      cVar3 = ExclusiveMonitorsStatus();
    }
  } while (cVar3 != '\0');
  if (iVar2 < 1) {
    operator_delete(param_1);
    return;
  }
  return;
}



void _FINI_0(void)

{
  __cxa_finalize(&DAT_00163000);
  return;
}



void _INIT_0(void)

{
  pthread_mutex_init((pthread_mutex_t *)android::ProcessRawDataLock,(pthread_mutexattr_t *)0x0);
  __cxa_atexit(android::Mutex::~Mutex,android::ProcessRawDataLock,&DAT_00163000);
  pthread_mutex_init((pthread_mutex_t *)android::mStatusCheckLock,(pthread_mutexattr_t *)0x0);
  __cxa_atexit(android::Mutex::~Mutex,android::mStatusCheckLock,&DAT_00163000);
  pthread_mutex_init((pthread_mutex_t *)&DAT_00163170,(pthread_mutexattr_t *)0x0);
  __cxa_atexit(android::Mutex::~Mutex,&DAT_00163170,&DAT_00163000);
  return;
}



void _INIT_1(void)

{
  android::String16::String16
            ((String16 *)&android::IFingerPrint::descriptor,"android.hardware.FingerPrint");
  __cxa_atexit(android::String16::~String16,&android::IFingerPrint::descriptor,&DAT_00163000);
  return;
}



void _INIT_2(void)

{
  android::String16::String16
            ((String16 *)&android::IFingerPrintClient::descriptor,
             "android.hardware.FingerPrintClient");
  __cxa_atexit(android::String16::~String16,&android::IFingerPrintClient::descriptor,&DAT_00163000);
  return;
}



void _INIT_3(void)

{
  android::String16::String16
            ((String16 *)&android::IFingerPrintService::descriptor,"android.hardware.IFpService");
  __cxa_atexit(android::String16::~String16,&android::IFingerPrintService::descriptor,&DAT_00163000)
  ;
  return;
}



void _INIT_4(void)

{
  DAT_00164f20 = 0;
  DAT_00164f28 = 0;
  DAT_00164f30 = 0;
  DAT_00164f38 = 0;
  DAT_00164f40 = 0;
  return;
}



void _INIT_5(void)

{
  int iVar1;
  
  DAT_00174f84 = 0;
  iVar1 = pthread_key_create(&DAT_00174f80,FUN_0012a578);
  DAT_00174f84 = iVar1 == 0;
  __cxa_atexit(FUN_0012a55c,&DAT_00174f80,&DAT_00163000);
  return;
}



void _INIT_6(void)

{
  __cxa_atexit(FUN_0012bc04,&PTR_PTR_FUN_00163040,&DAT_00163000);
  __cxa_atexit(FUN_0012bc00,&PTR_PTR_FUN_00163048,&DAT_00163000);
  return;
}



void FUN_00115658(code *param_1)

{
  if (param_1 != (code *)0x0) {
    (*param_1)();
  }
  return;
}



// android::FpService::getInfo(char*)

undefined8 android::FpService::getInfo(char *param_1)

{
  return 0;
}



// android::BnInterface<android::IFingerPrint>::onAsBinder()

BnInterface<> * __thiscall android::BnInterface<>::onAsBinder(BnInterface<> *this)

{
  return this + 8;
}



// android::BnInterface<android::IFingerPrintService>::onAsBinder()

BnInterface<> * __thiscall android::BnInterface<>::onAsBinder(BnInterface<> *this)

{
  return this + 8;
}



// android::FpService::setChipMode(fingerprint_chip_mode)

undefined8 __thiscall android::FpService::setChipMode(FpService *this,fingerprint_chip_mode param_1)

{
  __android_log_print(3,"FingerGoodix","setChipMode = %d ",param_1);
  (**(code **)(*(long *)(this + 0x148) + 0x140))(*(long *)(this + 0x148),param_1);
  *(fingerprint_chip_mode *)(this + 0xd8) = param_1;
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// android::FpService::getChipMode()

void __thiscall android::FpService::getChipMode(FpService *this)

{
  long lVar1;
  
  lVar1 = ___stack_chk_guard;
  (**(code **)(*(long *)(this + 0x148) + 0xa8))(*(long *)(this + 0x148));
  __android_log_print(3,"FingerGoodix","getChipMode = %d ",0);
  if (lVar1 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(0);
}



// android::FpService::setCurNotifyClientID(int)

undefined8 __thiscall android::FpService::setCurNotifyClientID(FpService *this,int param_1)

{
  undefined8 uVar1;
  
  if ((uint)param_1 < 7) {
    __android_log_print(3,"FingerGoodix","setCurNotifyClientID:%d",param_1);
    *(int *)(this + 0x2e4) = param_1;
    uVar1 = 0;
  }
  else {
    uVar1 = 0xffffffff;
  }
  return uVar1;
}



// android::FpService::Client::getInfo()

undefined1 * android::FpService::Client::getInfo(void)

{
  __android_log_print(3,"FingerGoodix","Client::getInfo");
  __android_log_print(3,"FingerGoodix","%s",algoVersion);
  return algoVersion;
}



// android::FpService::Client::requestPermission(char const*)

undefined8 __thiscall android::FpService::Client::requestPermission(Client *this,char *param_1)

{
  __android_log_print(3,"FingerGoodix","Client::requestPermission:%s",param_1);
  return 0;
}



// android::FpService::Client::sendScreenState(int)

undefined8 android::FpService::Client::sendScreenState(int param_1)

{
  __android_log_print(3,"FingerGoodix","Client::sendScreenState");
  return 0;
}



// android::FpService::Client::enroll_verify(hw_auth_token_t*)

void __thiscall android::FpService::Client::enroll_verify(Client *this,hw_auth_token_t *param_1)

{
  __android_log_print(3,"FingerGoodix","enroll_verify");
  (**(code **)(*(long *)(this + 0x28) + 0x1c8))(param_1);
  return;
}



// android::FpService::Client::setPauseRegisterState(int)

undefined8 __thiscall android::FpService::Client::setPauseRegisterState(Client *this,int param_1)

{
  __android_log_print(3,"FingerGoodix","Client::setPauseRegisterState,state:%d",param_1);
  return 0;
}



// android::FpService::Client::registRollback()

void __thiscall android::FpService::Client::registRollback(Client *this)

{
  __android_log_print(3,"FingerGoodix","Client::registRollback");
  (**(code **)(*(long *)this + 0x188))(this);
  return;
}



// android::FpService::Client::resetRegist()

void __thiscall android::FpService::Client::resetRegist(Client *this)

{
  __android_log_print(3,"FingerGoodix","Client::resetRegist");
  (**(code **)(*(long *)this + 0x188))(this);
  return;
}



// android::FpService::Client::weChatSetSessionId(unsigned long)

void __thiscall android::FpService::Client::weChatSetSessionId(Client *this,ulong param_1)

{
  __android_log_print(3,"FingerGoodix","%s, challenge = %ld",
                      "virtual android::status_t android::FpService::Client::weChatSetSessionId(uint64_t)"
                      ,param_1);
  (**(code **)(*(long *)(this + 0x28) + 0x1b8))(*(long *)(this + 0x28),param_1);
  return;
}



// android::FpService::Client::cancelRegist()

undefined8 __thiscall android::FpService::Client::cancelRegist(Client *this)

{
  long *plVar1;
  
  __android_log_print(3,"FingerGoodix","Client::cancelRegist");
  (**(code **)(*(long *)(this + 0x28) + 0xc0))(*(long *)(this + 0x28));
  plVar1 = *(long **)(this + 0x38);
  if (2 < *(int *)((long)plVar1 + 0xd4) - 2U) {
    return 0xffffffff;
  }
  (**(code **)(*plVar1 + 0x70))(plVar1,5);
  (**(code **)(*(long *)(this + 0x28) + 0x1a0))(*(long *)(this + 0x28));
  (**(code **)(**(long **)(this + 0x38) + 0x70))(*(long **)(this + 0x38),1);
  return 0;
}



// android::FpService::Client::cancelRecognize()

undefined8 __thiscall android::FpService::Client::cancelRecognize(Client *this)

{
  int iVar1;
  undefined8 uVar2;
  
  __android_log_print(3,"FingerGoodix","Client::cancelRecognize %d",
                      *(undefined4 *)(*(long *)(this + 0x38) + 0xd4));
  iVar1 = *(int *)(*(long *)(this + 0x38) + 0xd4);
  if ((iVar1 != 8) && (iVar1 != 1)) {
    if (iVar1 - 6U < 2) {
      __android_log_print(3,"FingerGoodix","Cancel status:%d\n");
      (**(code **)(**(long **)(this + 0x38) + 0x70))(*(long **)(this + 0x38),8);
      (**(code **)(*(long *)(this + 0x28) + 0x1a0))(*(long *)(this + 0x28));
      (**(code **)(**(long **)(this + 0x38) + 0x70))(*(long **)(this + 0x38),1);
      uVar2 = 0;
    }
    else {
      __android_log_print(3,"FingerGoodix","Cancel Failed. status:%d!");
      uVar2 = 0xffffffff;
    }
    return uVar2;
  }
  __android_log_print(3,"FingerGoodix","Already canceled!");
  return 0;
}



// android::FpService::Client::handleGenericNotify(int, int, int)

void __thiscall
android::FpService::Client::handleGenericNotify(Client *this,int param_1,int param_2,int param_3)

{
  __android_log_print(3,"FingerGoodix","handleGenericNotify,msgType:%d, ext1:%d, ext2:%d",param_1,
                      param_2,param_3);
  (**(code **)(**(long **)(this + 0x40) + 0x20))(*(long **)(this + 0x40),param_1,param_2,param_3);
  return;
}



// android::FpService::Client::handleNotifyData(int, int, char*)

void __thiscall
android::FpService::Client::handleNotifyData(Client *this,int param_1,int param_2,char *param_3)

{
  __android_log_print(3,"FingerGoodix","handleNotifyData clientID:%d",*(undefined4 *)(this + 0x48));
  (**(code **)(**(long **)(this + 0x40) + 0x28))(*(long **)(this + 0x40),param_1,param_2,param_3);
  return;
}



// android::FpService::Client::handleNotifyEvent(unsigned char, unsigned char)

void __thiscall
android::FpService::Client::handleNotifyEvent(Client *this,uchar param_1,uchar param_2)

{
  __android_log_print(3,"FingerGoodix","handleNotifyEvent clientID:%d",*(undefined4 *)(this + 0x48))
  ;
  (**(code **)(**(long **)(this + 0x40) + 0x20))(*(long **)(this + 0x40),5,param_1,param_2);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// android::FpService::RawDataProcessRequest()

void __thiscall android::FpService::RawDataProcessRequest(FpService *this)

{
  int local_c;
  long local_8;
  
  local_c = 0;
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","trigger rawdata signal sem!");
  (**(code **)(*(long *)(this + 0x148) + 0x1a8))(*(long *)(this + 0x148));
  sem_getvalue((sem_t *)&DAT_00163160,&local_c);
  if (local_c == 0) {
    sem_post((sem_t *)&DAT_00163160);
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(0);
}



// android::FpService::setStatus(fpalgo_act_status)

undefined8 __thiscall android::FpService::setStatus(FpService *this,fpalgo_act_status param_1)

{
  pthread_mutex_t *__mutex;
  undefined8 uVar1;
  
  __mutex = (pthread_mutex_t *)(this + 0xac);
  pthread_mutex_lock(__mutex);
                    // try { // try from 00115da4 to 00115da7 has its CatchHandler @ 00115ecc
  __android_log_print(3,"FingerGoodix","mCurStatus = %d , nextStatus = %d",
                      *(undefined4 *)(this + 0xd4),param_1);
  switch(param_1) {
  case 0:
  case 1:
  case 3:
  case 5:
  case 7:
  case 8:
  case 10:
  case 0xb:
  case 0xc:
  case 0xd:
  case 0xe:
  case 0xf:
    *(fpalgo_act_status *)(this + 0xd4) = param_1;
    pthread_mutex_unlock(__mutex);
    return 0;
  case 2:
    switch(*(undefined4 *)(this + 0xd4)) {
    case 0:
    case 1:
    case 3:
    case 5:
    case 6:
    case 7:
    case 8:
      uVar1 = 0;
      *(undefined4 *)(this + 0xd4) = 2;
      goto LAB_00115db4;
    case 2:
switchD_00115e08_caseD_6:
      pthread_mutex_unlock(__mutex);
      return 0;
    }
    break;
  case 4:
    uVar1 = 0xffffffff;
    if (*(int *)(this + 0xd4) - 2U < 2) {
      *(undefined4 *)(this + 0xd4) = 4;
      pthread_mutex_unlock(__mutex);
      return 0xffffffff;
    }
    goto LAB_00115db4;
  case 6:
    switch(*(undefined4 *)(this + 0xd4)) {
    case 0:
    case 1:
    case 2:
    case 3:
    case 5:
    case 7:
    case 8:
      uVar1 = 0;
      *(undefined4 *)(this + 0xd4) = 6;
      goto LAB_00115db4;
    case 6:
      goto switchD_00115e08_caseD_6;
    }
  }
  uVar1 = 0xffffffff;
LAB_00115db4:
  pthread_mutex_unlock(__mutex);
  return uVar1;
}



// android::FpService::Client::regist()

int __thiscall android::FpService::Client::regist(Client *this)

{
  int iVar1;
  long *plVar2;
  
  __android_log_print(3,"FingerGoodix","JEM,Client::register %d",
                      *(undefined4 *)(*(long *)(this + 0x38) + 0xd4));
  iVar1 = (**(code **)(*(long *)this + 0x188))(this);
  if (iVar1 != 0) {
    return iVar1;
  }
  pthread_mutex_lock((pthread_mutex_t *)ProcessRawDataLock);
  plVar2 = *(long **)(this + 0x38);
  if ((*(int *)((long)plVar2 + 0xd4) == 0) || (*(int *)((long)plVar2 + 0xd4) == 7)) {
                    // try { // try from 00115fcc to 00115fcf has its CatchHandler @ 00115fe0
    __android_log_print(6,"FingerGoodix","JEM,Client::register FAILED,CHECK STATUS!");
    iVar1 = -1;
    pthread_mutex_unlock((pthread_mutex_t *)ProcessRawDataLock);
  }
  else {
                    // try { // try from 00115f6c to 00115f9b has its CatchHandler @ 00115fe0
    (**(code **)(*plVar2 + 0x78))(plVar2,*(undefined4 *)(this + 0x48));
    (**(code **)(**(long **)(this + 0x38) + 0x70))(*(long **)(this + 0x38),2);
    (**(code **)(**(long **)(this + 0x38) + 0x80))(*(long **)(this + 0x38));
    iVar1 = 0;
    pthread_mutex_unlock((pthread_mutex_t *)ProcessRawDataLock);
  }
  return iVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// android::FpService::Client::recognize()

void __thiscall android::FpService::Client::recognize(Client *this)

{
  int iVar1;
  long lVar2;
  code *pcVar3;
  long local_10;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","FpService::Client::recognize");
  iVar1 = (**(code **)(*(long *)this + 0x188))(this);
  __android_log_print(3,"FingerGoodix","FpService::Client::recognize prepareFpEnv out");
  if (iVar1 == 0) {
    if (*(int *)(*(long *)(this + 0x38) + 0xd4) - 6U < 2) {
      __android_log_print(3,"FingerGoodix","Already recognize.");
      iVar1 = 0;
    }
    else {
      pthread_mutex_lock((pthread_mutex_t *)ProcessRawDataLock);
                    // try { // try from 00116094 to 00116103 has its CatchHandler @ 00116174
      (**(code **)(**(long **)(this + 0x38) + 0x70))(*(long **)(this + 0x38),6);
      lVar2 = *(long *)(this + 0x28);
      pcVar3 = *(code **)(lVar2 + 0x1c0);
      *(undefined4 *)(*(long *)(this + 0x38) + 0xa8) = 8;
      iVar1 = (*pcVar3)(lVar2,&local_10);
      if ((iVar1 == 0) && (local_10 != 0)) {
        *(undefined4 *)(*(long *)(this + 0x38) + 0x84) = 3;
      }
      else {
        *(undefined4 *)(*(long *)(this + 0x38) + 0x84) = 0;
      }
      (**(code **)(*(long *)(this + 0x28) + 0xa0))(*(long *)(this + 0x28),0);
      (**(code **)(**(long **)(this + 0x38) + 0x78))
                (*(long **)(this + 0x38),*(undefined4 *)(this + 0x48));
      (**(code **)(**(long **)(this + 0x38) + 0x80))(*(long **)(this + 0x38));
      pthread_mutex_unlock((pthread_mutex_t *)ProcessRawDataLock);
      iVar1 = 0;
    }
  }
  if (local_8 != ___stack_chk_guard) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail(iVar1);
  }
  return;
}



undefined8 FUN_00116188(long *param_1)

{
  int iVar1;
  undefined4 uVar2;
  
  iVar1 = *(int *)(*param_1 + 0xd4);
  uVar2 = *(undefined4 *)(*param_1 + 0xd8);
  __android_log_print(3,"FingerGoodix","wait to prepare AlgoEnv, mode=%d, status=%d",uVar2,iVar1);
  while (iVar1 - 2U < 8) {
    __android_log_print(3,"FingerGoodix","need wait, mode=%d, status=%d",uVar2,iVar1);
    usleep(50000);
    iVar1 = *(int *)(*param_1 + 0xd4);
  }
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// android::FpService::Client::prepareFpEnv()

void __thiscall android::FpService::Client::prepareFpEnv(Client *this)

{
  int iVar1;
  Client *pCVar2;
  Client *pCVar3;
  int iVar4;
  long *local_18;
  long *local_10;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  if ((*(char *)(*(long *)(this + 0x38) + 0x19c) == '\0') &&
     (iVar4 = (**(code **)(*(long *)(this + 0x28) + 0x220))(*(long *)(this + 0x28)), iVar4 == 0)) {
    *(undefined *)(*(long *)(this + 0x38) + 0x19c) = 1;
  }
  pthread_mutex_lock((pthread_mutex_t *)&DAT_00163170);
                    // try { // try from 00116294 to 00116323 has its CatchHandler @ 00116514
  __android_log_print(3,"FingerGoodix","prepare FpEnv, active client=%p",DAT_00163198);
  if (DAT_00163198 == (Client *)0x0) {
    DAT_00163198 = this;
                    // try { // try from 001164dc to 00116507 has its CatchHandler @ 00116514
    (**(code **)(*(long *)(this + 0x28) + 0x280))(*(undefined4 *)(this + 0x48));
    __android_log_print(3,"FingerGoodix","prepare FpEnv, LINE=%p",0xbb4);
    iVar4 = 0;
  }
  else {
    __android_log_print(3,"FingerGoodix","prepare FpEnv, LINE=%p",3000);
    pCVar2 = DAT_00163198;
    if (DAT_00163198 == this) {
      __android_log_print(3,"FingerGoodix","prepare FpEnv, LINE=%p",0xbbc);
      iVar4 = 0;
    }
    else {
      __android_log_print(3,"FingerGoodix","prepare FpEnv, LINE=%p",0xbbf);
      iVar1 = *(int *)(this + 0x48);
      if (iVar1 < *(int *)(pCVar2 + 0x48)) {
                    // try { // try from 00116440 to 00116467 has its CatchHandler @ 00116514
        __android_log_print(3,"FingerGoodix","prepare FpEnv, LINE=%p",0xbc7);
        local_18 = *(long **)(this + 0x38);
        if (local_18 != (long *)0x0) {
          android::RefBase::incStrong((void *)((long)local_18 + *(long *)(*local_18 + -0x18)));
        }
                    // try { // try from 0011646c to 0011646f has its CatchHandler @ 00116550
        iVar4 = FUN_00116188(&local_18);
        if (local_18 != (long *)0x0) {
          android::RefBase::decStrong((void *)((long)local_18 + *(long *)(*local_18 + -0x18)));
        }
      }
      else {
        __android_log_print(3,"FingerGoodix","prepare FpEnv, LINE=%p",0xbcc);
        local_10 = *(long **)(this + 0x38);
        if (local_10 != (long *)0x0) {
          android::RefBase::incStrong((void *)((long)local_10 + *(long *)(*local_10 + -0x18)));
        }
                    // try { // try from 00116328 to 0011632b has its CatchHandler @ 0011652c
        iVar4 = FUN_00116188(&local_10);
        if (local_10 != (long *)0x0) {
          android::RefBase::decStrong((void *)((long)local_10 + *(long *)(*local_10 + -0x18)));
        }
      }
                    // try { // try from 0011635c to 001163fb has its CatchHandler @ 00116514
      __android_log_print(3,"FingerGoodix","prepare FpEnv, LINE=%p",0xbd0);
      if (iVar4 == 0) {
        __android_log_print(3,"FingerGoodix","Change the active client.");
        (**(code **)(*(long *)this + 0x70))(this);
        (**(code **)(*(long *)this + 0xb8))(this);
        (**(code **)(**(long **)(this + 0x38) + 0x70))(*(long **)(this + 0x38),1);
        pCVar3 = this;
        if (*(int *)(pCVar2 + 0x48) != iVar1) {
          __android_log_print(3,"FingerGoodix","prepare FpEnv, LINE=%p",0xbdb);
          (**(code **)(*(long *)(this + 0x28) + 0x280))(iVar1);
          pCVar3 = this;
        }
      }
      else {
                    // try { // try from 001164a0 to 001164a3 has its CatchHandler @ 00116514
        __android_log_print(3,"FingerGoodix",
                            "Prepare FpEnv for a diffrent client has failed, errcode = %d",iVar4);
        pCVar3 = DAT_00163198;
      }
      DAT_00163198 = pCVar3;
      __android_log_print(3,"FingerGoodix","prepare FpEnv, LINE=%p",0xbe6);
    }
  }
  pthread_mutex_unlock((pthread_mutex_t *)&DAT_00163170);
  if (local_8 != ___stack_chk_guard) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail(iVar4);
  }
  return;
}



// android::Mutex::~Mutex()

int __thiscall android::Mutex::~Mutex(Mutex *this)

{
  int iVar1;
  
  iVar1 = pthread_mutex_destroy((pthread_mutex_t *)this);
  return iVar1;
}



// android::FpService::onTransact(unsigned int, android::Parcel const&, android::Parcel*, unsigned
// int)

void android::FpService::onTransact(uint param_1,Parcel *param_2,Parcel *param_3,uint param_4)

{
  if ((int)param_2 == 2) {
    getpid();
  }
  BnFingerPrintService::onTransact(param_1,param_2,param_3,param_4);
  return;
}



// non-virtual thunk to android::FpService::onTransact(unsigned int, android::Parcel const&,
// android::Parcel*, unsigned int)

void __thiscall
android::FpService::onTransact
          (FpService *this,uint param_1,Parcel *param_2,Parcel *param_3,uint param_4)

{
  onTransact((int)this - 8,(Parcel *)(ulong)param_1,param_2,(uint)param_3);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// android::FpService::Client::fillAuthTokenHmac(hw_auth_token_t*)

void __thiscall android::FpService::Client::fillAuthTokenHmac(Client *this,hw_auth_token_t *param_1)

{
  undefined4 uVar1;
  undefined8 local_30;
  undefined8 uStack_28;
  undefined8 local_20;
  undefined8 uStack_18;
  undefined8 local_10;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","gen hmac, sid:0x%lx, uid:0x%lx, time=0x%lx",
                      *(undefined8 *)(param_1 + 1),*(undefined8 *)(param_1 + 9),
                      *(undefined8 *)(param_1 + 0x1d));
  local_10 = 0;
  local_30 = 0;
  uStack_28 = 0;
  local_20 = 0;
  uStack_18 = 0;
  uVar1 = (**(code **)(*(long *)(this + 0x28) + 0x288))(param_1,0x45,&local_30);
  __android_log_print(3,"FingerGoodix","gen hmac, ret: %d, timestampAndHmacLen:%d.",uVar1,0x28);
  memcpy(param_1 + 0x1d,&local_30,0x28);
  __android_log_print(3,"FingerGoodix","gen hmac, token->timestamp=0x%016lx.",
                      *(undefined8 *)(param_1 + 0x1d));
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar1);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// android::FpService::Client::recognizeWithRestrict(unsigned int*, unsigned int, unsigned int)

void __thiscall
android::FpService::Client::recognizeWithRestrict
          (Client *this,uint *param_1,uint param_2,uint param_3)

{
  int iVar1;
  undefined8 uVar2;
  long lVar3;
  long local_10;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix",
                      "FpService::Client::recognizeWithRestrict, sectype = %d, length:%d",param_3,
                      (ulong)param_2);
  uVar2 = (**(code **)(*(long *)this + 0x188))(this);
  if ((int)uVar2 == 0) {
    if (*(int *)(*(long *)(this + 0x38) + 0xd4) - 6U < 2) {
      __android_log_print(3,"FingerGoodix","Already recognizeWithRestrict.");
      uVar2 = 0;
    }
    else {
      pthread_mutex_lock((pthread_mutex_t *)ProcessRawDataLock);
                    // try { // try from 00116768 to 001167f3 has its CatchHandler @ 00116864
      (**(code **)(**(long **)(this + 0x38) + 0x70))(*(long **)(this + 0x38),6);
      iVar1 = (**(code **)(*(long *)(this + 0x28) + 0x1c0))(*(long *)(this + 0x28),&local_10);
      if ((iVar1 == 0) && (local_10 != 0)) {
        lVar3 = *(long *)(this + 0x38);
        *(undefined4 *)(lVar3 + 0x84) = 3;
      }
      else {
        lVar3 = *(long *)(this + 0x38);
        *(uint *)(lVar3 + 0x84) = param_3;
      }
      *(uint *)(lVar3 + 0xa8) = param_2;
      *(undefined8 *)(lVar3 + 0x88) = 0;
      *(undefined8 *)(lVar3 + 0x90) = 0;
      *(undefined8 *)(lVar3 + 0x98) = 0;
      *(undefined8 *)(lVar3 + 0xa0) = 0;
      memcpy((void *)(*(long *)(this + 0x38) + 0x88),param_1,(ulong)param_2 << 2);
      (**(code **)(*(long *)(this + 0x28) + 0xa0))(*(long *)(this + 0x28),0);
      (**(code **)(**(long **)(this + 0x38) + 0x78))
                (*(long **)(this + 0x38),*(undefined4 *)(this + 0x48));
      (**(code **)(**(long **)(this + 0x38) + 0x80))(*(long **)(this + 0x38));
      pthread_mutex_unlock((pthread_mutex_t *)ProcessRawDataLock);
      uVar2 = 0;
    }
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar2);
}



// android::FpService::Client::recognizeFido(unsigned char*, int, unsigned char*, int)

int __thiscall
android::FpService::Client::recognizeFido
          (Client *this,uchar *param_1,int param_2,uchar *param_3,int param_4)

{
  int iVar1;
  long lVar2;
  
  __android_log_print(3,"FingerGoodix","Client::recognizeFido. \n");
  iVar1 = (**(code **)(*(long *)this + 0x188))(this);
  if (iVar1 != 0) {
    return iVar1;
  }
  pthread_mutex_lock((pthread_mutex_t *)ProcessRawDataLock);
                    // try { // try from 00116910 to 001169bb has its CatchHandler @ 00116a00
  (**(code **)(**(long **)(this + 0x38) + 0x70))(*(long **)(this + 0x38),6);
  *(undefined4 *)(*(long *)(this + 0x38) + 0xa8) = 8;
  __android_log_print(3,"FingerGoodix","Set Fido Verify.\n");
  lVar2 = *(long *)(this + 0x38);
  *(undefined *)(lVar2 + 0x150) = 1;
  if ((param_2 < 0x21) && (param_4 < 0x21)) {
    *(int *)(lVar2 + 0x174) = param_2;
    *(int *)(lVar2 + 0x198) = param_4;
    memcpy((void *)(lVar2 + 0x154),param_1,(long)param_2);
    memcpy((void *)(*(long *)(this + 0x38) + 0x178),param_3,(long)param_4);
    (**(code **)(*(long *)(this + 0x28) + 0xa0))(*(long *)(this + 0x28),0);
    (**(code **)(**(long **)(this + 0x38) + 0x78))
              (*(long **)(this + 0x38),*(undefined4 *)(this + 0x48));
    (**(code **)(**(long **)(this + 0x38) + 0x80))(*(long **)(this + 0x38));
    iVar1 = 0;
  }
  else {
                    // try { // try from 001169f4 to 001169f7 has its CatchHandler @ 00116a00
    __android_log_print(6,"FingerGoodix",
                        "Client::recognizeFido: aaidbuf or finalchanllenge_buf overflow");
    iVar1 = -1;
  }
  pthread_mutex_unlock((pthread_mutex_t *)ProcessRawDataLock);
  return iVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// android::FpService::dump(int, android::Vector<android::String16> const&)

void __thiscall android::FpService::dump(FpService *this,int param_1,Vector *param_2)

{
  bool bVar1;
  bool bVar2;
  char cVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  long lVar7;
  size_t sVar8;
  long lVar9;
  int iVar10;
  long lVar11;
  ulong uVar12;
  long lVar13;
  void *local_130;
  String16 aSStack_128 [8];
  long *local_120;
  long *local_118;
  long *local_110;
  char acStack_108 [256];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  android::String8::String8((String8 *)&local_130);
                    // try { // try from 00116a68 to 00116a6b has its CatchHandler @ 00116dc8
  android::String16::String16(aSStack_128,"android.permission.DUMP");
                    // try { // try from 00116a70 to 00116a73 has its CatchHandler @ 00116e2c
  cVar3 = android::checkCallingPermission(aSStack_128);
  android::String16::~String16(aSStack_128);
  if (cVar3 == '\0') {
                    // try { // try from 00116aa0 to 00116b7f has its CatchHandler @ 00116dc8
    snprintf(acStack_108,0x100,"Permission Denial: can\'t dump FpService from pid=%d, uid=%d\n",0x7b
             ,0x7b);
    android::String8::append((char *)&local_130);
    if (local_130 == (void *)0x0) {
      sVar8 = 0xffffffffffffffff;
    }
    else {
      sVar8 = *(long *)((long)local_130 + -0x10) - 1;
    }
    write(param_1,local_130,sVar8);
  }
  else {
    iVar10 = 0x32;
    do {
      iVar4 = pthread_mutex_trylock((pthread_mutex_t *)(this + 0x1a0));
      if (iVar4 == 0) {
        bVar2 = true;
        goto LAB_00116b3c;
      }
      usleep(60000);
      iVar10 = iVar10 + -1;
    } while (iVar10 != 0);
                    // try { // try from 00116d54 to 00116d57 has its CatchHandler @ 00116dc8
    android::String8::String8((String8 *)&local_110,"FingerPrintService may be deadlocked\n");
    if (local_110 == (long *)0x0) {
      sVar8 = 0xffffffffffffffff;
    }
    else {
      sVar8 = local_110[-2] - 1;
    }
                    // try { // try from 00116d6c to 00116d6f has its CatchHandler @ 00116ddc
    write(param_1,local_110,sVar8);
    bVar2 = false;
    android::String8::~String8((String8 *)&local_110);
LAB_00116b3c:
    uVar12 = 0;
    bVar1 = false;
    do {
      local_110 = *(long **)(this + 0x20);
      if (local_110 != (long *)0x0) {
        android::RefBase::incStrong((void *)((long)local_110 + *(long *)(*local_110 + -0x18)));
        if (local_110 != (long *)0x0) {
          local_120 = (long *)local_110[8];
          if (local_120 != (long *)0x0) {
                    // try { // try from 00116ba4 to 00116ba7 has its CatchHandler @ 00116e48
            android::RefBase::incStrong((void *)((long)local_120 + *(long *)(*local_120 + -0x18)));
          }
                    // try { // try from 00116bb0 to 00116bb3 has its CatchHandler @ 00116dec
          android::IInterface::asBinder((sp *)&local_120);
          sprintf(acStack_108,"Client[%d] (%p) PID: %d\n",uVar12,local_118,
                  (ulong)*(uint *)((long)local_110 + 0x4c));
          if (local_118 != (long *)0x0) {
            android::RefBase::decStrong((void *)((long)local_118 + *(long *)(*local_118 + -0x18)));
          }
          if (local_120 != (long *)0x0) {
            android::RefBase::decStrong((void *)((long)local_120 + *(long *)(*local_120 + -0x18)));
          }
                    // try { // try from 00116c10 to 00116c2b has its CatchHandler @ 00116e48
          android::String8::append((char *)&local_130);
          if (local_130 == (void *)0x0) {
            sVar8 = 0xffffffffffffffff;
          }
          else {
            sVar8 = *(long *)((long)local_130 + -0x10) - 1;
          }
          write(param_1,local_130,sVar8);
          if (local_110 != (long *)0x0) {
            android::RefBase::decStrong((void *)((long)local_110 + *(long *)(*local_110 + -0x18)));
          }
          bVar1 = true;
        }
      }
      uVar6 = (int)uVar12 + 1;
      uVar12 = (ulong)uVar6;
    } while (uVar6 != 7);
    if (!bVar1) {
      android::String8::append((char *)&local_130);
      if (local_130 == (void *)0x0) {
        sVar8 = 0xffffffffffffffff;
      }
      else {
        sVar8 = *(long *)((long)local_130 + -0x10) - 1;
      }
      write(param_1,local_130,sVar8);
    }
    if (bVar2) {
                    // try { // try from 00116d84 to 00116db3 has its CatchHandler @ 00116dc8
      pthread_mutex_unlock((pthread_mutex_t *)(this + 0x1a0));
    }
    iVar4 = *(int *)(param_2 + 0x10);
    lVar11 = 0;
    iVar10 = 0;
    while (iVar10 = iVar10 + 1, iVar10 < iVar4) {
      lVar13 = *(long *)(param_2 + 8);
                    // try { // try from 00116ca4 to 00116ca7 has its CatchHandler @ 00116dc8
      android::String16::String16((String16 *)&local_110,"-v");
      lVar13 = *(long *)(lVar13 + lVar11);
      if (lVar13 == 0) {
        lVar7 = -1;
      }
      else {
        lVar7 = (*(ulong *)(lVar13 + -0x10) >> 1) - 1;
      }
      lVar9 = -1;
      if (local_110 != (long *)0x0) {
        lVar9 = ((ulong)local_110[-2] >> 1) - 1;
      }
                    // try { // try from 00116cd4 to 00116cd7 has its CatchHandler @ 00116e40
      iVar5 = strzcmp16(lVar13,lVar7,local_110,lVar9);
      lVar11 = lVar11 + 8;
      android::String16::~String16((String16 *)&local_110);
      if (iVar5 == 0) {
                    // try { // try from 00116cf8 to 00116cfb has its CatchHandler @ 00116dc8
        android::String8::String8
                  ((String8 *)&local_110,(String16 *)(*(long *)(param_2 + 8) + lVar11));
        uVar6 = atoi((char *)local_110);
        sprintf(acStack_108,"Set Log Level to %d",(ulong)uVar6);
                    // try { // try from 00116d1c to 00116d1f has its CatchHandler @ 00116e44
        android::String8::append((char *)&local_130);
        android::String8::~String8((String8 *)&local_110);
      }
    }
  }
  android::String8::~String8((String8 *)&local_130);
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(0);
}



// non-virtual thunk to android::FpService::dump(int, android::Vector<android::String16> const&)

void __thiscall android::FpService::dump(FpService *this,int param_1,Vector *param_2)

{
  dump(this + -8,param_1,param_2);
  return;
}



// android::BnInterface<android::IFingerPrint>::getInterfaceDescriptor() const

undefined8 * android::BnInterface<>::getInterfaceDescriptor(void)

{
  return &IFingerPrint::descriptor;
}



// non-virtual thunk to android::BnInterface<android::IFingerPrint>::getInterfaceDescriptor() const

void __thiscall android::BnInterface<>::getInterfaceDescriptor(BnInterface<> *this)

{
  getInterfaceDescriptor();
  return;
}



// android::BnInterface<android::IFingerPrintService>::getInterfaceDescriptor() const

undefined8 * android::BnInterface<>::getInterfaceDescriptor(void)

{
  return &IFingerPrintService::descriptor;
}



// non-virtual thunk to android::BnInterface<android::IFingerPrintService>::getInterfaceDescriptor()
// const

void __thiscall android::BnInterface<>::getInterfaceDescriptor(BnInterface<> *this)

{
  getInterfaceDescriptor();
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// android::FpService::check(int)

void __thiscall android::FpService::check(FpService *this,int param_1)

{
  long lVar1;
  undefined8 uVar2;
  
  lVar1 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","finger print check,id is %d.",param_1);
  uVar2 = 0x85;
  if ((uint)param_1 < 7) {
    (**(code **)(*(long *)this + 0x48))(this);
    uVar2 = 0;
  }
  if (lVar1 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar2);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// android::FpService::Client::unRegist(int)

void __thiscall android::FpService::Client::unRegist(Client *this,int param_1)

{
  int iVar1;
  int local_10 [2];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","Client::unRegist");
  iVar1 = (**(code **)(*(long *)this + 0x188))(this);
  if (iVar1 == 0) {
    local_10[0] = param_1;
    (**(code **)(*(long *)this + 0xd0))(this,local_10,1);
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



// android::FpService::Client::delFpTemplates(unsigned int*, unsigned int)

void __thiscall android::FpService::Client::delFpTemplates(Client *this,uint *param_1,uint param_2)

{
  uint *puVar1;
  int iVar2;
  ulong uVar3;
  ulong uVar4;
  
  __android_log_print(3,"FingerGoodix","Client::delFpTemplates,count:%d",param_2);
  iVar2 = (**(code **)(*(long *)this + 0x188))(this);
  if (iVar2 == 0) {
    uVar4 = 0;
    if (0 < (int)param_2) {
      do {
        puVar1 = param_1 + uVar4;
        uVar3 = uVar4 & 0xffffffff;
        uVar4 = uVar4 + 1;
        __android_log_print(3,"FingerGoodix","Client::delFpTemplates,position:%d,value:%d",uVar3,
                            *puVar1);
      } while ((int)uVar4 < (int)param_2);
    }
    (**(code **)(*(long *)(this + 0x28) + 0xf0))(*(long *)(this + 0x28),param_1,param_2);
  }
  return;
}



// android::FpService::Client::getFpTemplateIdList(unsigned int*, unsigned int*)

ulong __thiscall
android::FpService::Client::getFpTemplateIdList(Client *this,uint *param_1,uint *param_2)

{
  uint uVar1;
  ulong uVar2;
  uint uVar3;
  uint *puVar4;
  
  __android_log_print(3,"FingerGoodix","Client::getFpTemplateIdList,pCount:%d",*param_2);
  uVar2 = (**(code **)(*(long *)this + 0x188))(this);
  if ((int)uVar2 == 0) {
    if (*param_2 != 0) {
      puVar4 = param_1;
      uVar3 = 0;
      do {
        uVar1 = uVar3 + 1;
        __android_log_print(3,"FingerGoodix","Client::getFpTemplateIdList,position:%d,value:%d",
                            uVar3,*puVar4);
        puVar4 = puVar4 + 1;
        uVar3 = uVar1;
      } while (uVar1 < *param_2);
    }
    __android_log_print(3,"FingerGoodix","Client::getFpTemplateIdList,mHardWareContext.device,%p",
                        *(undefined8 *)(this + 0x28));
    uVar2 = (**(code **)(*(long *)(this + 0x28) + 0xf8))(*(long *)(this + 0x28),param_1,param_2);
    uVar2 = uVar2 & 0xffffffff;
    if (*param_2 != 0) {
      uVar3 = 0;
      do {
        uVar1 = uVar3 + 1;
        __android_log_print(3,"FingerGoodix","Client::getFpTemplateIdList,position:%d,value:%d",
                            uVar3,*param_1);
        param_1 = param_1 + 1;
        uVar3 = uVar1;
      } while (uVar1 < *param_2);
    }
  }
  return uVar2;
}



// android::FpService::Client::driverTest()

int __thiscall android::FpService::Client::driverTest(Client *this)

{
  int iVar1;
  int iVar2;
  
  __android_log_print(3,"FingerGoodix","Client::driverTest");
  iVar1 = (**(code **)(*(long *)this + 0x188))(this);
  if ((iVar1 == 0) &&
     (iVar2 = (**(code **)(*(long *)(this + 0x28) + 0x118))(*(long *)(this + 0x28)), iVar2 == 0)) {
    __android_log_print(3,"FingerGoodix","fnCa_DriverTest run ok");
    return 0;
  }
  return iVar1;
}



// android::FpService::Client::getFpTemplateList(unsigned int*, unsigned int*, char**)

ulong __thiscall
android::FpService::Client::getFpTemplateList
          (Client *this,uint *param_1,uint *param_2,char **param_3)

{
  uint uVar1;
  ulong uVar2;
  int iVar3;
  long lVar4;
  
  __android_log_print(3,"FingerGoodix","Client::getFpTemplateList,count:%d",*param_1);
  uVar2 = (**(code **)(*(long *)this + 0x188))(this);
  if ((int)uVar2 == 0) {
    if ((param_2 == (uint *)0x0) || (param_3 == (char **)0x0)) {
      __android_log_print(6,"FingerGoodix","some of the params is NULL in getFpTemplateList");
      uVar2 = 0xffffffff;
    }
    else {
      uVar1 = (**(code **)(*(long *)(this + 0x28) + 0xf8))(*(long *)(this + 0x28),param_2,param_1);
      if (uVar1 != 0) {
        __android_log_print(6,"FingerGoodix","failed to fnCa_GetFpTemplateIdList");
        return (ulong)uVar1;
      }
      lVar4 = 0;
      if (*param_1 != 0) {
        do {
          (**(code **)(*(long *)this + 0xf8))(this,param_2[lVar4],param_3[lVar4]);
          __android_log_print(3,"FingerGoodix","get id:%d,name:%s",param_2[lVar4],param_3[lVar4]);
          iVar3 = (int)lVar4;
          lVar4 = lVar4 + 1;
        } while (iVar3 + 1U < *param_1);
      }
      uVar2 = 0;
    }
  }
  return uVar2;
}



// android::FpService::Client::alipayTzInvokeCommand(unsigned int, void*, unsigned int, void*,
// unsigned int*)

undefined8 __thiscall
android::FpService::Client::alipayTzInvokeCommand
          (Client *this,uint param_1,void *param_2,uint param_3,void *param_4,uint *param_5)

{
  undefined8 uVar1;
  
  __android_log_print(3,"FingerGoodix","Client[%d]::alipayTzInvokeCommand",
                      *(undefined4 *)(this + 0x48));
  uVar1 = (**(code **)(*(long *)this + 0x188))(this);
  if ((int)uVar1 == 0) {
    if ((param_4 == (void *)0x0 || param_5 == (uint *)0x0) || (param_2 == (void *)0x0)) {
      __android_log_print(6,"FingerGoodix","some of the params is NULL in getFpTemplateList");
      uVar1 = 0xffffffff;
    }
    else {
      uVar1 = (**(code **)(*(long *)(this + 0x28) + 0x1b0))
                        (*(long *)(this + 0x28),0xa001000,param_2,param_3);
    }
  }
  return uVar1;
}



// android::FpService::Client::enableFingerScreenUnlock()

undefined8 __thiscall android::FpService::Client::enableFingerScreenUnlock(Client *this)

{
  int iVar1;
  
  __android_log_print(3,"FingerGoodix","Client::enableFingerScreenUnlock");
  iVar1 = (**(code **)(*(long *)(this + 0x28) + 0x240))(*(long *)(this + 0x28));
  if (iVar1 == 0) {
    __android_log_print(3,"FingerGoodix","enable_finger_screen_unlock run ok");
  }
  return 0;
}



// android::FpService::Client::disableFingerScreenUnlock()

undefined8 __thiscall android::FpService::Client::disableFingerScreenUnlock(Client *this)

{
  int iVar1;
  
  __android_log_print(3,"FingerGoodix","Client::disableFingerScreenUnlock");
  iVar1 = (**(code **)(*(long *)(this + 0x28) + 0x248))(*(long *)(this + 0x28));
  if (iVar1 == 0) {
    __android_log_print(3,"FingerGoodix","disable_finger_screen_unlock run ok");
  }
  return 0;
}



// android::FpService::Client::setRecFlag(unsigned int)

undefined8 __thiscall android::FpService::Client::setRecFlag(Client *this,uint param_1)

{
  int iVar1;
  
  __android_log_print(3,"FingerGoodix","Client::setRecFlag fpFlag: %d",param_1);
  iVar1 = (**(code **)(*(long *)(this + 0x28) + 0x250))(*(long *)(this + 0x28),param_1);
  if (iVar1 == 0) {
    __android_log_print(3,"FingerGoodix","set_recognize_flag run ok");
  }
  return 0;
}



// android::FpService::Client::gfCmdM(int, unsigned char*, int, unsigned char*, int, int*)

undefined4 __thiscall
android::FpService::Client::gfCmdM
          (Client *this,int param_1,uchar *param_2,int param_3,uchar *param_4,int param_5,
          int *param_6)

{
  undefined4 uVar1;
  long lVar2;
  
  uVar1 = 0;
  if (param_1 - 0x19U < 2) {
    lVar2 = *(long *)(this + 0x28);
    *param_6 = param_5;
    uVar1 = (**(code **)(lVar2 + 0x2a8))(param_1,param_2,param_3,param_4,param_6);
    __android_log_print(3,"FingerGoodix","send_cmd_to_ta:ret:%d, command:%d, rsp data length:%d",
                        uVar1,param_1,*param_6);
  }
  return uVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// android::FpService::Client::query()

void __thiscall android::FpService::Client::query(Client *this)

{
  uint uVar1;
  int iVar2;
  undefined8 *__ptr;
  long lVar3;
  uint uVar4;
  undefined8 *puVar5;
  uint local_c;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","Client::query");
  uVar1 = (**(code **)(*(long *)this + 0x188))(this);
  if (uVar1 == 0) {
    local_c = 5;
    __ptr = (undefined8 *)malloc(0x14);
    if (__ptr == (undefined8 *)0x0) {
      uVar1 = 0xffffffff;
      __android_log_print(3,"FingerGoodix","Client:query fail to malloc memory");
    }
    else {
      lVar3 = *(long *)this;
      *__ptr = 0;
      __ptr[1] = 0;
      *(undefined4 *)(__ptr + 2) = 0;
      iVar2 = (**(code **)(lVar3 + 0xd8))(this,__ptr,&local_c);
      if (iVar2 == 0) {
        __android_log_print(3,"FingerGoodix","after add count,query count:%d,queryResult:0x%x",
                            local_c,0x50000);
        if (local_c == 0) {
          uVar1 = 0x50000;
        }
        else {
          uVar1 = 0x50000;
          uVar4 = 0;
          puVar5 = __ptr;
          do {
            uVar4 = uVar4 + 1;
            uVar1 = uVar1 | 1 << (ulong)(*(int *)puVar5 - 1U & 0x1f);
            __android_log_print(3,"FingerGoodix","add index:%d,queryResult:0x%x",*(int *)puVar5,
                                uVar1);
            puVar5 = (undefined8 *)((long)puVar5 + 4);
          } while (uVar4 < local_c);
        }
        __android_log_print(3,"FingerGoodix","after add index,query count:%d,queryResult:0x%x",
                            local_c,uVar1);
      }
      else {
        __android_log_print(6,"FingerGoodix","failed to query!!!,getFpTemplateIdList result:0x%x",
                            iVar2);
      }
      free(__ptr);
    }
  }
  if (local_8 != ___stack_chk_guard) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail(uVar1);
  }
  return;
}



// android::FpService::Client::setPasswd(char const*, char const*)

undefined8 __thiscall
android::FpService::Client::setPasswd(Client *this,char *param_1,char *param_2)

{
  undefined8 uVar1;
  size_t sVar2;
  size_t sVar3;
  long lVar4;
  
  __android_log_print(3,"FingerGoodix","Client::setPasswd,%s,%s",param_1,param_2);
  uVar1 = (**(code **)(*(long *)this + 0x188))(this);
  if ((int)uVar1 == 0) {
    if ((param_1 == (char *)0x0) || (param_2 == (char *)0x0)) {
      __android_log_print(3,"FingerGoodix","old password or new password is NULL");
      return 0x85;
    }
    lVar4 = *(long *)(this + 0x28);
    sVar2 = strlen(param_1);
    sVar3 = strlen(param_2);
    uVar1 = (**(code **)(lVar4 + 0x100))(lVar4,param_1,sVar2 & 0xffffffff,param_2,sVar3);
  }
  return uVar1;
}



// android::FpService::Client::checkPasswd(char const*)

undefined8 __thiscall android::FpService::Client::checkPasswd(Client *this,char *param_1)

{
  undefined8 uVar1;
  size_t sVar2;
  long lVar3;
  
  __android_log_print(3,"FingerGoodix","Client::checkPasswd :%s",param_1);
  uVar1 = (**(code **)(*(long *)this + 0x188))(this);
  if ((int)uVar1 == 0) {
    if (param_1 == (char *)0x0) {
      __android_log_print(3,"FingerGoodix","passwd is null");
      return 0x85;
    }
    lVar3 = *(long *)(this + 0x28);
    sVar2 = strlen(param_1);
    uVar1 = (**(code **)(lVar3 + 0x108))(lVar3,param_1,sVar2);
  }
  return uVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// android::FpService::Client::getFpNameById(int, char*)

void __thiscall android::FpService::Client::getFpNameById(Client *this,int param_1,char *param_2)

{
  long lVar1;
  uint uVar2;
  ulong uVar3;
  size_t sVar4;
  
  lVar1 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","Client::getFpNameById,%d",param_1);
  uVar3 = (**(code **)(*(long *)this + 0x188))(this);
  if ((int)uVar3 == 0) {
    uVar2 = (**(code **)(*(long *)(this + 0x28) + 0xd0))(*(long *)(this + 0x28),param_1,param_2);
    uVar3 = (ulong)uVar2;
    if (uVar2 == 0) {
      sVar4 = strlen(param_2);
      __android_log_print(3,"FingerGoodix",
                          "success to fnCa_GetFpNameById,count:%d,name:%s,length:%d",0x80,param_2,
                          sVar4 & 0xffffffff);
    }
    else {
      __android_log_print(6,"FingerGoodix","failed to fnCa_GetFpNameById,free pFpName");
    }
  }
  if (lVar1 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar3);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// android::FpService::Client::saveRegister(char const*)

void __thiscall android::FpService::Client::saveRegister(Client *this,char *param_1)

{
  long lVar1;
  int iVar2;
  undefined8 uVar3;
  undefined8 *__dest;
  size_t sVar4;
  
  lVar1 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","Client::saveRegister()");
  uVar3 = (**(code **)(*(long *)this + 0x188))(this);
  if ((int)uVar3 == 0) {
    __dest = (undefined8 *)malloc(0x80);
    if (__dest == (undefined8 *)0x0) {
      __android_log_print(6,"FingerGoodix","failed to malloc pFpName in saveRegister");
      uVar3 = 0xffffffff;
    }
    else {
      *__dest = 0;
      __dest[1] = 0;
      __dest[2] = 0;
      __dest[3] = 0;
      __dest[4] = 0;
      __dest[5] = 0;
      __dest[6] = 0;
      __dest[7] = 0;
      __dest[8] = 0;
      __dest[9] = 0;
      __dest[10] = 0;
      __dest[0xb] = 0;
      __dest[0xc] = 0;
      __dest[0xd] = 0;
      __dest[0xe] = 0;
      __dest[0xf] = 0;
      if (param_1 == (char *)0x0) {
        __android_log_print(6,"FingerGoodix","Client saveRegister name is NULL");
        iVar2 = 1;
      }
      else {
        __android_log_print(3,"FingerGoodix","Client saveRegister name:%s",param_1);
        sVar4 = strlen(param_1);
        if (0x7f < (uint)sVar4) {
          __android_log_print(3,"FingerGoodix","modify fp name is too long,count is %d.",
                              sVar4 & 0xffffffff);
          uVar3 = 0xffffffff;
          goto LAB_00117a78;
        }
        memcpy(__dest,param_1,sVar4 & 0xffffffff);
        iVar2 = (uint)sVar4 + 1;
      }
      iVar2 = (**(code **)(*(long *)(this + 0x28) + 200))(*(long *)(this + 0x28),__dest,iVar2);
      free(__dest);
      if (iVar2 == 0) {
        __android_log_print(3,"FingerGoodix","success to saveRegister(),index:%d",0);
        uVar3 = 0;
      }
      else {
        __android_log_print(6,"FingerGoodix","failed to saveRegister(),result:%d",iVar2);
        uVar3 = 0xffffffff;
      }
    }
  }
LAB_00117a78:
  if (lVar1 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar3);
}



// android::FpService::Client::modifyFpName(int, char const*)

ulong __thiscall android::FpService::Client::modifyFpName(Client *this,int param_1,char *param_2)

{
  int iVar1;
  ulong uVar2;
  undefined8 *__dest;
  size_t sVar3;
  int iVar4;
  
  __android_log_print(3,"FingerGoodix","Client::modifyFpName:%d",param_1);
  uVar2 = (**(code **)(*(long *)this + 0x188))(this);
  if ((int)uVar2 == 0) {
    __dest = (undefined8 *)malloc(0x80);
    if (__dest != (undefined8 *)0x0) {
      *__dest = 0;
      __dest[1] = 0;
      __dest[2] = 0;
      __dest[3] = 0;
      __dest[4] = 0;
      __dest[5] = 0;
      __dest[6] = 0;
      __dest[7] = 0;
      __dest[8] = 0;
      __dest[9] = 0;
      __dest[10] = 0;
      __dest[0xb] = 0;
      __dest[0xc] = 0;
      __dest[0xd] = 0;
      __dest[0xe] = 0;
      __dest[0xf] = 0;
      if (param_2 == (char *)0x0) {
        iVar4 = 1;
        __android_log_print(6,"FingerGoodix","pName is NULL!!!");
      }
      else {
        sVar3 = strlen(param_2);
        iVar1 = (int)sVar3;
        if (0x7f < iVar1) {
          __android_log_print(6,"FingerGoodix","modify fp name is too long,count is %d.",
                              sVar3 & 0xffffffff);
          return 0xffffffff;
        }
        iVar4 = iVar1 + 1;
        memcpy(__dest,param_2,(long)iVar1);
        __android_log_print(3,"FingerGoodix","modifyFpName is %s,pFpName is %s,length is %d",param_2
                            ,__dest,sVar3 & 0xffffffff);
      }
      __android_log_print(3,"FingerGoodix","call ta in modifyFpName");
      uVar2 = (**(code **)(*(long *)(this + 0x28) + 0xd8))
                        (*(long *)(this + 0x28),param_1,__dest,iVar4);
      free(__dest);
      return uVar2 & 0xffffffff;
    }
    __android_log_print(6,"FingerGoodix","failed to malloc pFpName in modifyFpName");
    uVar2 = 0xffffffff;
  }
  return uVar2;
}



// android::FpService::getClientByIdUnsafe(int)

undefined8 __thiscall android::FpService::getClientByIdUnsafe(FpService *this,int param_1)

{
  undefined8 uVar1;
  
  if ((uint)param_1 < 7) {
    uVar1 = *(undefined8 *)(this + (long)param_1 * 8 + 0x20);
  }
  else {
    __android_log_print(3,"FingerGoodix","Failed to getClientByIdUnsafe,invalide fingerprint Id:%d")
    ;
    uVar1 = 0;
  }
  return uVar1;
}



// android::FpService::Client::saveRegist(int)

ulong android::FpService::Client::saveRegist(int param_1)

{
  long *plVar1;
  ulong uVar2;
  
  plVar1 = (long *)(ulong)(uint)param_1;
  __android_log_print(3,"FingerGoodix","Client::saveRegist curStatus = %d",
                      *(undefined4 *)(plVar1[7] + 0xd4));
  uVar2 = (**(code **)(*plVar1 + 0x188))(plVar1);
  if ((int)uVar2 == 0) {
    if (*(int *)(plVar1[7] + 0xd4) == 4) {
      uVar2 = (**(code **)(*plVar1 + 0x98))(plVar1,"goodix");
      uVar2 = uVar2 & 0xffffffff;
      (**(code **)(*(long *)plVar1[7] + 0x70))((long *)plVar1[7],1);
    }
    else {
      __android_log_print(6,"FingerGoodix","Client::saveRegist , Enroll not complete!");
      uVar2 = 0xffffffff;
    }
  }
  return uVar2;
}



// android::FpService::Client::setActiveGroup(int)

undefined8 __thiscall android::FpService::Client::setActiveGroup(Client *this,int param_1)

{
  int iVar1;
  undefined8 uVar2;
  long *plVar3;
  
  __android_log_print(3,"FingerGoodix","Set the active group");
  uVar2 = (**(code **)(*(long *)this + 0x188))(this);
  if ((int)uVar2 != 0) {
    return uVar2;
  }
  __android_log_print(3,"FingerGoodix","Client[%d] set active group to %d",
                      *(undefined4 *)(this + 0x48),param_1);
  (**(code **)(*(long *)this + 0x70))(this);
  (**(code **)(*(long *)this + 0xb8))(this);
  (**(code **)(**(long **)(this + 0x38) + 0x70))(*(long **)(this + 0x38),1);
  (**(code **)(*(long *)(this + 0x28) + 0x198))(*(long *)(this + 0x28),notifyClient);
  __android_log_print(3,"FingerGoodix","set hal_notify");
  (**(code **)(*(long *)(this + 0x28) + 0x98))(*(long *)(this + 0x28));
  (**(code **)(*(long *)(this + 0x28) + 0x280))(*(undefined4 *)(this + 0x48));
  (**(code **)(*(long *)(this + 0x28) + 0x278))(param_1);
  plVar3 = *(long **)(this + 0x38);
  if (*(char *)((long)plVar3 + 0x19c) == '\0') {
    iVar1 = (**(code **)(*(long *)(this + 0x28) + 0x220))(*(long *)(this + 0x28));
    if (iVar1 == 0) {
      plVar3 = *(long **)(this + 0x38);
      *(undefined *)((long)plVar3 + 0x19c) = 1;
    }
    else {
      plVar3 = *(long **)(this + 0x38);
    }
  }
  (**(code **)(*plVar3 + 0x60))(plVar3,DAT_00163008);
  return 0;
}



// android::FpService::Client::setSafeClass(unsigned int)

int __thiscall android::FpService::Client::setSafeClass(Client *this,uint param_1)

{
  int iVar1;
  
  if (*(int *)(*(long *)(this + 0x38) + 0xd4) == 0) {
    __android_log_print(6,"FingerGoodix","%s, service is failed to init, nothing to do, just return"
                        ,
                        "virtual android::status_t android::FpService::Client::setSafeClass(uint32_t)"
                       );
    return 0x81;
  }
  __android_log_print(6,"FingerGoodix","FpService::Client::setSafeClass , enter, safeClass:%d",
                      param_1);
  iVar1 = (**(code **)(*(long *)(this + 0x28) + 0x268))(*(long *)(this + 0x28),param_1);
  if (iVar1 == 0) {
    DAT_0016300c = param_1;
  }
  __android_log_print(3,"FingerGoodix",
                      "FpService::Client::setSafeClass fnCa_SetSafeClass return:0x%08X",iVar1);
  return iVar1;
}



// android::BnInterface<android::IFingerPrint>::queryLocalInterface(android::String16 const&)

void __thiscall android::BnInterface<>::queryLocalInterface(BnInterface<> *this,String16 *param_1)

{
  int iVar1;
  long lVar2;
  long lVar3;
  long lVar4;
  BnInterface<> **in_x8;
  
  lVar4 = *(long *)param_1;
  if (lVar4 == 0) {
    lVar2 = -1;
  }
  else {
    lVar2 = (*(ulong *)(lVar4 + -0x10) >> 1) - 1;
  }
  lVar3 = -1;
  if (IFingerPrint::descriptor != 0) {
    lVar3 = (*(ulong *)(IFingerPrint::descriptor + -0x10) >> 1) - 1;
  }
  iVar1 = strzcmp16(lVar4,lVar2,IFingerPrint::descriptor,lVar3);
  if (iVar1 == 0) {
    *in_x8 = this;
    if (this != (BnInterface<> *)0x0) {
      android::RefBase::incStrong(this + *(long *)(*(long *)this + -0x18));
    }
    return;
  }
  *in_x8 = (BnInterface<> *)0x0;
  return;
}



// non-virtual thunk to
// android::BnInterface<android::IFingerPrint>::queryLocalInterface(android::String16 const&)

void __thiscall android::BnInterface<>::queryLocalInterface(BnInterface<> *this,String16 *param_1)

{
  queryLocalInterface(this + -8,param_1);
  return;
}



// android::BnInterface<android::IFingerPrintService>::queryLocalInterface(android::String16 const&)

void __thiscall android::BnInterface<>::queryLocalInterface(BnInterface<> *this,String16 *param_1)

{
  int iVar1;
  long lVar2;
  long lVar3;
  long lVar4;
  BnInterface<> **in_x8;
  
  lVar4 = *(long *)param_1;
  if (lVar4 == 0) {
    lVar2 = -1;
  }
  else {
    lVar2 = (*(ulong *)(lVar4 + -0x10) >> 1) - 1;
  }
  lVar3 = -1;
  if (IFingerPrintService::descriptor != 0) {
    lVar3 = (*(ulong *)(IFingerPrintService::descriptor + -0x10) >> 1) - 1;
  }
  iVar1 = strzcmp16(lVar4,lVar2,IFingerPrintService::descriptor,lVar3);
  if (iVar1 == 0) {
    *in_x8 = this;
    if (this != (BnInterface<> *)0x0) {
      android::RefBase::incStrong(this + *(long *)(*(long *)this + -0x18));
    }
    return;
  }
  *in_x8 = (BnInterface<> *)0x0;
  return;
}



// non-virtual thunk to
// android::BnInterface<android::IFingerPrintService>::queryLocalInterface(android::String16 const&)

void __thiscall android::BnInterface<>::queryLocalInterface(BnInterface<> *this,String16 *param_1)

{
  queryLocalInterface(this + -8,param_1);
  return;
}



// android::FpService::~FpService()

void __thiscall android::FpService::~FpService(FpService *this)

{
  int iVar1;
  long *plVar2;
  long **pplVar3;
  pthread_mutex_t *__mutex;
  
  *(undefined8 *)this = 0x15e5a8;
  *(undefined8 *)(this + 0x2e8) = 0x15e708;
  *(undefined8 *)(this + 8) = 0x15e648;
  pplVar3 = (long **)(this + 0x58);
  __android_log_print(6,"FingerGoodix","FingerPrintService is ~FpService()");
  __android_log_print(3,"FingerGoodix","but finger print is busy");
  DAT_001631a0 = 0;
  (**(code **)(*(long *)(this + 0x148) + 0x98))(*(long *)(this + 0x148));
  (**(code **)(*(long *)(this + 0x148) + 0x88))(*(long *)(this + 0x148));
  *(undefined4 *)(this + 0x2e0) = 1;
  iVar1 = (**(code **)(*(long *)(this + 0x148) + 0x160))(*(long *)(this + 0x148));
  if (iVar1 == 0) {
    __android_log_print(3,"FingerGoodix","success to disable device");
  }
  else {
    __android_log_print(3,"FingerGoodix","failed to disable device");
  }
  __mutex = (pthread_mutex_t *)(this + 0x2e0);
  __android_log_print(3,"FingerGoodix","FpService::~FpService(),fnCa_CloseSession");
  do {
    __mutex = __mutex + -1;
    pthread_mutex_destroy(__mutex);
  } while ((pthread_mutex_t *)(this + 0x1c8) != __mutex);
  pthread_mutex_destroy((pthread_mutex_t *)(this + 0x1a0));
  pthread_mutex_destroy((pthread_mutex_t *)(this + 0x10c));
  pthread_cond_destroy((pthread_cond_t *)(this + 0xdc));
  pthread_mutex_destroy((pthread_mutex_t *)(this + 0xac));
  do {
    pplVar3 = pplVar3 + -1;
    plVar2 = *pplVar3;
    if (plVar2 != (long *)0x0) {
      android::RefBase::decStrong((void *)((long)plVar2 + *(long *)(*plVar2 + -0x18)));
    }
  } while ((long **)(this + 0x20) != pplVar3);
  *(undefined **)this = &DAT_0015e258;
  *(undefined **)(this + 0x2e8) = &DAT_0015e368;
  *(undefined ***)(this + 8) = &PTR_queryLocalInterface_0015e2a8;
  android::BBinder::~BBinder((BBinder *)(this + 8));
  IFingerPrintService::~IFingerPrintService((IFingerPrintService *)this);
  android::RefBase::~RefBase((RefBase *)(this + 0x2e8));
  return;
}



// virtual thunk to android::FpService::~FpService()

void __thiscall android::FpService::~FpService(FpService *this)

{
  ~FpService(this + *(long *)(*(long *)this + -0x18));
  return;
}



// non-virtual thunk to android::FpService::~FpService()

void __thiscall android::FpService::~FpService(FpService *this)

{
  ~FpService(this + -8);
  return;
}



// android::FpService::~FpService()

void __thiscall android::FpService::~FpService(FpService *this)

{
  ~FpService(this);
  operator_delete(this);
  return;
}



// virtual thunk to android::FpService::~FpService()

void __thiscall android::FpService::~FpService(FpService *this)

{
  ~FpService(this + *(long *)(*(long *)this + -0x18));
  return;
}



// non-virtual thunk to android::FpService::~FpService()

void __thiscall android::FpService::~FpService(FpService *this)

{
  ~FpService(this + -8);
  return;
}



// android::BnFingerPrintService::~BnFingerPrintService()

void __thiscall android::BnFingerPrintService::~BnFingerPrintService(BnFingerPrintService *this)

{
  long *in_x1;
  long lVar1;
  
  lVar1 = *in_x1;
  *(long *)this = lVar1;
  *(long *)(this + *(long *)(lVar1 + -0x18)) = in_x1[0xc];
  *(long *)(this + 8) = in_x1[0xd];
  lVar1 = in_x1[1];
  *(long *)this = lVar1;
  *(long *)(this + *(long *)(lVar1 + -0x18)) = in_x1[10];
  *(long *)(this + 8) = in_x1[0xb];
  android::BBinder::~BBinder((BBinder *)(this + 8));
  IFingerPrintService::~IFingerPrintService((IFingerPrintService *)this);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// android::FpService::FpService()

void __thiscall android::FpService::FpService(FpService *this)

{
  int iVar1;
  long lVar2;
  undefined8 uVar3;
  undefined *puVar4;
  long *in_x1;
  code **ppcVar5;
  pthread_mutex_t *__mutex;
  undefined auStack_138 [8];
  undefined auStack_130 [8];
  long local_128;
  long local_120;
  undefined4 local_118;
  undefined4 uStack_114;
  int local_110;
  undefined auStack_108 [128];
  undefined auStack_88 [64];
  undefined auStack_48 [64];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  IFingerPrintService::IFingerPrintService((IFingerPrintService *)this);
                    // try { // try from 001184a8 to 001184ab has its CatchHandler @ 00118a2c
  android::BBinder::BBinder((BBinder *)(this + 8));
  lVar2 = in_x1[2];
  *(long *)this = lVar2;
  *(long *)(this + *(long *)(lVar2 + -0x18)) = in_x1[0xb];
  *(long *)(this + 8) = in_x1[0xc];
  lVar2 = in_x1[1];
  *(long *)this = lVar2;
  *(long *)(this + *(long *)(lVar2 + -0x18)) = in_x1[0xd];
  *(long *)(this + 8) = in_x1[0xe];
  lVar2 = *in_x1;
  *(long *)this = lVar2;
  *(long *)(this + *(long *)(lVar2 + -0x18)) = in_x1[0xf];
  *(long *)(this + 8) = in_x1[0x10];
  *(undefined8 *)(this + 0x28) = 0;
  *(undefined8 *)(this + 0x20) = 0;
  *(undefined8 *)(this + 0x38) = 0;
  *(undefined8 *)(this + 0x30) = 0;
  *(undefined8 *)(this + 0x48) = 0;
  *(undefined8 *)(this + 0x40) = 0;
  *(undefined8 *)(this + 0x50) = 0;
                    // try { // try from 0011852c to 0011852f has its CatchHandler @ 001188d8
  pthread_mutex_init((pthread_mutex_t *)(this + 0xac),(pthread_mutexattr_t *)0x0);
                    // try { // try from 0011853c to 0011853f has its CatchHandler @ 00118908
  pthread_cond_init((pthread_cond_t *)(this + 0xdc),(pthread_condattr_t *)0x0);
                    // try { // try from 0011854c to 0011854f has its CatchHandler @ 00118a04
  pthread_mutex_init((pthread_mutex_t *)(this + 0x10c),(pthread_mutexattr_t *)0x0);
  this[0x19c] = (FpService)0x0;
                    // try { // try from 00118560 to 00118563 has its CatchHandler @ 00118a70
  pthread_mutex_init((pthread_mutex_t *)(this + 0x1a0),(pthread_mutexattr_t *)0x0);
  __mutex = (pthread_mutex_t *)(this + 0x1c8);
  lVar2 = 6;
  do {
                    // try { // try from 00118578 to 0011857b has its CatchHandler @ 00118a44
    pthread_mutex_init(__mutex,(pthread_mutexattr_t *)0x0);
    lVar2 = lVar2 + -1;
    __mutex = __mutex + 1;
  } while (lVar2 != -1);
                    // try { // try from 001185a0 to 001188cf has its CatchHandler @ 00118a78
  __android_log_print(3,"FingerGoodix","FingerPrintService is constructing");
  *(undefined4 *)(this + 0x2e4) = 0;
  local_128 = 0;
  memset(auStack_108,0,0x100);
  *(undefined4 *)(this + 0x58) = 0;
  *(undefined4 *)(this + 0x5c) = 0;
  *(undefined4 *)(this + 0x60) = 0;
  *(undefined4 *)(this + 100) = 0;
  *(undefined4 *)(this + 0x68) = 0;
  *(undefined4 *)(this + 0x6c) = 0;
  *(undefined4 *)(this + 0x70) = 0;
  sem_init((sem_t *)&DAT_00163160,0,0);
  iVar1 = hw_get_module("gxfingerprint",&local_128);
  if (iVar1 == 0) {
    if (local_128 == 0) {
      __android_log_print(6,"FingerGoodix","No valid fingerprint module",0);
    }
    else {
      ppcVar5 = *(code ***)(local_128 + 0x20);
      *(long *)(this + 0x140) = local_128;
      if (*ppcVar5 == (code *)0x0) {
        __android_log_print(6,"FingerGoodix","No valid open method");
      }
      else {
        local_120 = 0;
        iVar1 = (**ppcVar5)(local_128,0,&local_120);
        if (iVar1 != 0) {
                    // try { // try from 0011893c to 0011894b has its CatchHandler @ 00118a78
          __android_log_print(6,"FingerGoodix","Can\'t open fingerprint methods, error: %d",iVar1);
          disable_goodix_fp_with_sys_prop();
          sem_destroy((sem_t *)&DAT_00163160);
          uVar3 = __cxa_allocate_exception(0x10);
                    // try { // try from 0011896c to 0011896f has its CatchHandler @ 001189fc
          FUN_00125e74(&local_118,"open hw module err",auStack_138);
                    // try { // try from 00118978 to 0011897b has its CatchHandler @ 001189b4
          FUN_001256c8(uVar3,&local_118);
          puVar4 = (undefined *)(CONCAT44(uStack_114,local_118) + -0x18);
          if (puVar4 != &DAT_00174f60) {
            entry(puVar4,auStack_130);
          }
                    // WARNING: Subroutine does not return
                    // try { // try from 001189b0 to 001189b3 has its CatchHandler @ 00118a78
          __cxa_throw(uVar3,&PTR_PTR____si_class_type_info_0015dec0,FUN_00124bc4);
        }
        enable_goodix_fp_with_sys_prop();
        if (*(int *)(local_120 + 4) != 0x100) {
          __android_log_print(3,"FingerGoodix","Wrong fp version. Expected %d, got %d",0x100);
        }
        *(long *)(this + 0x148) = local_120;
        *(undefined4 *)(this + 0x80) = 0;
        DAT_001631a0 = this;
        (**(code **)(local_120 + 0x198))(local_120,notifyClient);
        (**(code **)(*(long *)(this + 0x148) + 0x148))(*(long *)(this + 0x148),auStack_108);
        memset(algoVersion,0,0x100);
        sprintf(algoVersion,"Service version:%x.%x.%x %s %s,",1,0,0x11,"Jan  5 2018","15:36:14");
        sprintf(algoVersion,"%sTa version:%s,",algoVersion,auStack_108);
        sprintf(algoVersion,"%sNavigation version:%s,",algoVersion,auStack_88);
        sprintf(algoVersion,"%sAlgorithm version:%s.",algoVersion,auStack_48);
        __android_log_print(6,"FingerGoodix","%s",algoVersion);
        iVar1 = (**(code **)(*(long *)(this + 0x148) + 0x220))(*(long *)(this + 0x148));
        __android_log_print(3,"FingerGoodix","preprocessor init ret = %d",iVar1);
        this[0x19c] = (FpService)(iVar1 == 0);
        pthread_create((pthread_t *)(this + 0x138),(pthread_attr_t *)0x0,FUN_0011af8c,this);
        setStatus(this,1);
        local_118 = 0;
        iVar1 = property_get_int32("ro.register.count",0);
        if (0 < iVar1) {
          __android_log_print(3,"FingerGoodix","preprocessor init register_cnt = %d",iVar1);
          uStack_114 = 1;
          local_110 = iVar1;
          (**(code **)(*(long *)(this + 0x148) + 0x228))
                    (*(long *)(this + 0x148),CONCAT44(1,local_118),iVar1);
        }
        iVar1 = property_get_int32("ro.template.count",0);
        if (0 < iVar1) {
          __android_log_print(3,"FingerGoodix","preprocessor init study_cnt = %d",iVar1);
          uStack_114 = 0;
          local_110 = iVar1;
          (**(code **)(*(long *)(this + 0x148) + 0x228))(*(long *)(this + 0x148),local_118,iVar1);
        }
      }
    }
  }
  else {
    __android_log_print(6,"FingerGoodix","Can\'t open fingerprint HW Module, error: %d",iVar1);
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// android::FpService::FpService()

void __thiscall android::FpService::FpService(FpService *this)

{
  int iVar1;
  undefined8 uVar2;
  undefined *puVar3;
  code **ppcVar4;
  long lVar5;
  pthread_mutex_t *__mutex;
  undefined auStack_138 [8];
  undefined auStack_130 [8];
  long local_128;
  long local_120;
  undefined4 local_118;
  undefined4 uStack_114;
  int local_110;
  undefined auStack_108 [128];
  undefined auStack_88 [64];
  undefined auStack_48 [64];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  android::RefBase::RefBase((RefBase *)(this + 0x2e8));
                    // try { // try from 00118acc to 00118acf has its CatchHandler @ 00118f08
  IFingerPrintService::IFingerPrintService((IFingerPrintService *)this);
                    // try { // try from 00118adc to 00118adf has its CatchHandler @ 00119050
  android::BBinder::BBinder((BBinder *)(this + 8));
  *(undefined8 *)this = 0x15e5a8;
  *(undefined8 *)(this + 0x2e8) = 0x15e708;
  *(undefined8 *)(this + 8) = 0x15e648;
  *(undefined8 *)(this + 0x28) = 0;
  *(undefined8 *)(this + 0x20) = 0;
  *(undefined8 *)(this + 0x38) = 0;
  *(undefined8 *)(this + 0x30) = 0;
  *(undefined8 *)(this + 0x48) = 0;
  *(undefined8 *)(this + 0x40) = 0;
  *(undefined8 *)(this + 0x50) = 0;
                    // try { // try from 00118b2c to 00118b2f has its CatchHandler @ 00118ed8
  pthread_mutex_init((pthread_mutex_t *)(this + 0xac),(pthread_mutexattr_t *)0x0);
                    // try { // try from 00118b3c to 00118b3f has its CatchHandler @ 00119074
  pthread_cond_init((pthread_cond_t *)(this + 0xdc),(pthread_condattr_t *)0x0);
                    // try { // try from 00118b4c to 00118b4f has its CatchHandler @ 0011906c
  pthread_mutex_init((pthread_mutex_t *)(this + 0x10c),(pthread_mutexattr_t *)0x0);
  this[0x19c] = (FpService)0x0;
                    // try { // try from 00118b60 to 00118b63 has its CatchHandler @ 00118f48
  pthread_mutex_init((pthread_mutex_t *)(this + 0x1a0),(pthread_mutexattr_t *)0x0);
  __mutex = (pthread_mutex_t *)(this + 0x1c8);
  lVar5 = 6;
  do {
                    // try { // try from 00118b78 to 00118b7b has its CatchHandler @ 00118f1c
    pthread_mutex_init(__mutex,(pthread_mutexattr_t *)0x0);
    lVar5 = lVar5 + -1;
    __mutex = __mutex + 1;
  } while (lVar5 != -1);
                    // try { // try from 00118ba0 to 00118ecf has its CatchHandler @ 0011907c
  __android_log_print(3,"FingerGoodix","FingerPrintService is constructing");
  *(undefined4 *)(this + 0x2e4) = 0;
  local_128 = 0;
  memset(auStack_108,0,0x100);
  *(undefined4 *)(this + 0x58) = 0;
  *(undefined4 *)(this + 0x5c) = 0;
  *(undefined4 *)(this + 0x60) = 0;
  *(undefined4 *)(this + 100) = 0;
  *(undefined4 *)(this + 0x68) = 0;
  *(undefined4 *)(this + 0x6c) = 0;
  *(undefined4 *)(this + 0x70) = 0;
  sem_init((sem_t *)&DAT_00163160,0,0);
  iVar1 = hw_get_module("gxfingerprint",&local_128);
  if (iVar1 == 0) {
    if (local_128 == 0) {
      __android_log_print(6,"FingerGoodix","No valid fingerprint module",0);
    }
    else {
      ppcVar4 = *(code ***)(local_128 + 0x20);
      *(long *)(this + 0x140) = local_128;
      if (*ppcVar4 == (code *)0x0) {
        __android_log_print(6,"FingerGoodix","No valid open method");
      }
      else {
        local_120 = 0;
        iVar1 = (**ppcVar4)(local_128,0,&local_120);
        if (iVar1 != 0) {
                    // try { // try from 00118f88 to 00118f97 has its CatchHandler @ 0011907c
          __android_log_print(6,"FingerGoodix","Can\'t open fingerprint methods, error: %d",iVar1);
          disable_goodix_fp_with_sys_prop();
          sem_destroy((sem_t *)&DAT_00163160);
          uVar2 = __cxa_allocate_exception(0x10);
                    // try { // try from 00118fb8 to 00118fbb has its CatchHandler @ 00119048
          FUN_00125e74(&local_118,"open hw module err",auStack_138);
                    // try { // try from 00118fc4 to 00118fc7 has its CatchHandler @ 00119000
          FUN_001256c8(uVar2,&local_118);
          puVar3 = (undefined *)(CONCAT44(uStack_114,local_118) + -0x18);
          if (puVar3 != &DAT_00174f60) {
            entry(puVar3,auStack_130);
          }
                    // WARNING: Subroutine does not return
                    // try { // try from 00118ffc to 00118fff has its CatchHandler @ 0011907c
          __cxa_throw(uVar2,&PTR_PTR____si_class_type_info_0015dec0,FUN_00124bc4);
        }
        enable_goodix_fp_with_sys_prop();
        if (*(int *)(local_120 + 4) != 0x100) {
          __android_log_print(3,"FingerGoodix","Wrong fp version. Expected %d, got %d",0x100);
        }
        *(long *)(this + 0x148) = local_120;
        *(undefined4 *)(this + 0x80) = 0;
        DAT_001631a0 = this;
        (**(code **)(local_120 + 0x198))(local_120,notifyClient);
        (**(code **)(*(long *)(this + 0x148) + 0x148))(*(long *)(this + 0x148),auStack_108);
        memset(algoVersion,0,0x100);
        sprintf(algoVersion,"Service version:%x.%x.%x %s %s,",1,0,0x11,"Jan  5 2018","15:36:14");
        sprintf(algoVersion,"%sTa version:%s,",algoVersion,auStack_108);
        sprintf(algoVersion,"%sNavigation version:%s,",algoVersion,auStack_88);
        sprintf(algoVersion,"%sAlgorithm version:%s.",algoVersion,auStack_48);
        __android_log_print(6,"FingerGoodix","%s",algoVersion);
        iVar1 = (**(code **)(*(long *)(this + 0x148) + 0x220))(*(long *)(this + 0x148));
        __android_log_print(3,"FingerGoodix","preprocessor init ret = %d",iVar1);
        this[0x19c] = (FpService)(iVar1 == 0);
        pthread_create((pthread_t *)(this + 0x138),(pthread_attr_t *)0x0,FUN_0011af8c,this);
        setStatus(this,1);
        local_118 = 0;
        iVar1 = property_get_int32("ro.register.count",0);
        if (0 < iVar1) {
          __android_log_print(3,"FingerGoodix","preprocessor init register_cnt = %d",iVar1);
          uStack_114 = 1;
          local_110 = iVar1;
          (**(code **)(*(long *)(this + 0x148) + 0x228))
                    (*(long *)(this + 0x148),CONCAT44(1,local_118),iVar1);
        }
        iVar1 = property_get_int32("ro.template.count",0);
        if (0 < iVar1) {
          __android_log_print(3,"FingerGoodix","preprocessor init study_cnt = %d",iVar1);
          uStack_114 = 0;
          local_110 = iVar1;
          (**(code **)(*(long *)(this + 0x148) + 0x228))(*(long *)(this + 0x148),local_118,iVar1);
        }
      }
    }
  }
  else {
    __android_log_print(6,"FingerGoodix","Can\'t open fingerprint HW Module, error: %d",iVar1);
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



// android::FpService::~FpService()

void __thiscall android::FpService::~FpService(FpService *this)

{
  int iVar1;
  long *plVar2;
  long *in_x1;
  long lVar3;
  long **pplVar4;
  pthread_mutex_t *__mutex;
  
  lVar3 = *in_x1;
  *(long *)this = lVar3;
  *(long *)(this + *(long *)(lVar3 + -0x18)) = in_x1[0xf];
  pplVar4 = (long **)(this + 0x58);
  *(long *)(this + 8) = in_x1[0x10];
  __android_log_print(6,"FingerGoodix","FingerPrintService is ~FpService()");
  __android_log_print(3,"FingerGoodix","but finger print is busy");
  DAT_001631a0 = 0;
  (**(code **)(*(long *)(this + 0x148) + 0x98))(*(long *)(this + 0x148));
  (**(code **)(*(long *)(this + 0x148) + 0x88))(*(long *)(this + 0x148));
  *(undefined4 *)(this + 0x2e0) = 1;
  iVar1 = (**(code **)(*(long *)(this + 0x148) + 0x160))(*(long *)(this + 0x148));
  if (iVar1 == 0) {
    __android_log_print(3,"FingerGoodix","success to disable device");
  }
  else {
    __android_log_print(3,"FingerGoodix","failed to disable device");
  }
  __mutex = (pthread_mutex_t *)(this + 0x2e0);
  __android_log_print(3,"FingerGoodix","FpService::~FpService(),fnCa_CloseSession");
  do {
    __mutex = __mutex + -1;
    pthread_mutex_destroy(__mutex);
  } while ((pthread_mutex_t *)(this + 0x1c8) != __mutex);
  pthread_mutex_destroy((pthread_mutex_t *)(this + 0x1a0));
  pthread_mutex_destroy((pthread_mutex_t *)(this + 0x10c));
  pthread_cond_destroy((pthread_cond_t *)(this + 0xdc));
  pthread_mutex_destroy((pthread_mutex_t *)(this + 0xac));
  do {
    pplVar4 = pplVar4 + -1;
    plVar2 = *pplVar4;
    if (plVar2 != (long *)0x0) {
      android::RefBase::decStrong((void *)((long)plVar2 + *(long *)(*plVar2 + -0x18)));
    }
  } while ((long **)(this + 0x20) != pplVar4);
  lVar3 = in_x1[1];
  *(long *)this = lVar3;
  *(long *)(this + *(long *)(lVar3 + -0x18)) = in_x1[0xd];
  *(long *)(this + 8) = in_x1[0xe];
  lVar3 = in_x1[2];
  *(long *)this = lVar3;
  *(long *)(this + *(long *)(lVar3 + -0x18)) = in_x1[0xb];
  *(long *)(this + 8) = in_x1[0xc];
  android::BBinder::~BBinder((BBinder *)(this + 8));
  IFingerPrintService::~IFingerPrintService((IFingerPrintService *)this);
  return;
}



// android::FpService::setFingerPrintBusy(int)

void __thiscall android::FpService::setFingerPrintBusy(FpService *this,int param_1)

{
  *(undefined4 *)(this + ((long)param_1 + 0x14) * 4 + 8) = 1;
  return;
}



// android::FpService::setFingerPrintFree(int)

void __thiscall android::FpService::setFingerPrintFree(FpService *this,int param_1)

{
  *(undefined4 *)(this + ((long)param_1 + 0x14) * 4 + 8) = 0;
  return;
}



// android::imageEventCallback(unsigned char, unsigned char)

void android::imageEventCallback(uchar param_1,uchar param_2)

{
  __android_log_print(3,"FingerGoodix","imageEventCallback");
  return;
}



// android::BnFingerPrint::~BnFingerPrint()

void __thiscall android::BnFingerPrint::~BnFingerPrint(BnFingerPrint *this)

{
  long *in_x1;
  long lVar1;
  
  lVar1 = *in_x1;
  *(long *)this = lVar1;
  *(long *)(this + *(long *)(lVar1 + -0x18)) = in_x1[0xc];
  *(long *)(this + 8) = in_x1[0xd];
  lVar1 = in_x1[1];
  *(long *)this = lVar1;
  *(long *)(this + *(long *)(lVar1 + -0x18)) = in_x1[10];
  *(long *)(this + 8) = in_x1[0xb];
  android::BBinder::~BBinder((BBinder *)(this + 8));
  IFingerPrint::~IFingerPrint((IFingerPrint *)this);
  return;
}



// android::FpService::Client::checkPid() const

undefined8 __thiscall android::FpService::Client::checkPid(Client *this)

{
  if (*(int *)(this + 0x4c) != 0x7b) {
    __android_log_print(3,"FingerGoodix",
                        "attempt to use a locked fp from a different process (old pid %d, new pid %d)"
                        ,*(int *)(this + 0x4c),0x7b);
    return 0x10;
  }
  return 0;
}



// android::FpService::Client::lock()

undefined4 __thiscall android::FpService::Client::lock(Client *this)

{
  undefined4 uVar1;
  
  __android_log_print(3,"FingerGoodix","FingerPrintService::lock (pid %d)",0x7b);
  pthread_mutex_lock((pthread_mutex_t *)(this + 0x78));
                    // try { // try from 0011938c to 0011938f has its CatchHandler @ 001193f0
  pthread_mutex_lock((pthread_mutex_t *)(this + 0x50));
  if (*(int *)(this + 0x4c) == 0) {
    *(undefined4 *)(this + 0x4c) = 0x7b;
    uVar1 = 0;
  }
  else {
                    // try { // try from 001193c8 to 001193cb has its CatchHandler @ 001193d4
    uVar1 = checkPid(this);
  }
  pthread_mutex_unlock((pthread_mutex_t *)(this + 0x50));
  pthread_mutex_unlock((pthread_mutex_t *)(this + 0x78));
  return uVar1;
}



// android::FpService::Client::unlock()

int __thiscall android::FpService::Client::unlock(Client *this)

{
  int iVar1;
  long *plVar2;
  
  __android_log_print(3,"FingerGoodix","FingerPrintService::unlock (pid %d)",0x7b);
  pthread_mutex_lock((pthread_mutex_t *)(this + 0x78));
                    // try { // try from 00119440 to 00119443 has its CatchHandler @ 001194d4
  pthread_mutex_lock((pthread_mutex_t *)(this + 0x50));
                    // try { // try from 00119448 to 0011948b has its CatchHandler @ 001194b8
  iVar1 = checkPid(this);
  if (iVar1 == 0) {
    *(undefined4 *)(this + 0x4c) = 0;
    __android_log_print(3,"FingerGoodix","clear mFpClient (pid %d)",0x7b);
    plVar2 = *(long **)(this + 0x40);
    if (plVar2 != (long *)0x0) {
      android::RefBase::decStrong((void *)((long)plVar2 + *(long *)(*plVar2 + -0x18)));
      *(undefined8 *)(this + 0x40) = 0;
    }
  }
  pthread_mutex_unlock((pthread_mutex_t *)(this + 0x50));
  pthread_mutex_unlock((pthread_mutex_t *)(this + 0x78));
  return iVar1;
}



// android::FpService::Client::reset2KeyMode()

void __thiscall android::FpService::Client::reset2KeyMode(Client *this)

{
  int iVar1;
  
  __android_log_print(3,"FingerGoodix","reset2KeyMode");
  iVar1 = (**(code **)(*(long *)this + 0x188))(this);
  if (iVar1 == 0) {
    (**(code **)(*(long *)(this + 0x28) + 0x128))(*(long *)(this + 0x28));
  }
  return;
}



// android::FpService::Client::disconnect()

undefined4 __thiscall android::FpService::Client::disconnect(Client *this)

{
  int iVar1;
  long *plVar2;
  undefined4 uVar3;
  
  __android_log_print(3,"FingerGoodix","Client::disconnect E (pid %d)",0x7b);
  pthread_mutex_lock((pthread_mutex_t *)(this + 0x78));
                    // try { // try from 0011957c to 0011957f has its CatchHandler @ 00119724
  pthread_mutex_lock((pthread_mutex_t *)(this + 0x50));
                    // try { // try from 00119584 to 0011963f has its CatchHandler @ 00119738
  iVar1 = checkPid(this);
  if (iVar1 == 0) {
    if (*(int *)(this + 0x4c) < 1) {
      __android_log_print(3,"FingerGoodix",
                          "fp is unlocked (mClientPid = %d), don\'t tear down hardware");
      uVar3 = 0xffffffff;
    }
    else {
      iVar1 = reset2KeyMode(this);
      if (iVar1 == 0) {
        __android_log_print(3,"FingerGoodix","success to reset2KeyMode");
      }
      else {
                    // try { // try from 00119678 to 0011971f has its CatchHandler @ 00119738
        __android_log_print(3,"FingerGoodix","failed to reset2KeyMode");
      }
      plVar2 = *(long **)(this + 0x38);
      if (*(int *)(this + 0x48) == *(int *)((long)plVar2 + 0x2e4)) {
        iVar1 = *(int *)((long)plVar2 + 0xd4);
        if (iVar1 - 2U < 2) {
          (**(code **)(*(long *)(this + 0x28) + 0xc0))(*(long *)(this + 0x28));
          (**(code **)(**(long **)(this + 0x38) + 0x70))(*(long **)(this + 0x38),5);
        }
        else if (iVar1 - 6U < 2) {
          (**(code **)(*(long *)(this + 0x28) + 0xe8))(*(long *)(this + 0x28));
          (**(code **)(**(long **)(this + 0x38) + 0x70))(*(long **)(this + 0x38),8);
        }
        else if (iVar1 - 10U < 2) {
          (**(code **)(*plVar2 + 0x70))(plVar2,0xc);
        }
        (**(code **)(*(long *)(this + 0x28) + 0x1a0))(*(long *)(this + 0x28));
        (**(code **)(**(long **)(this + 0x38) + 0x70))(*(long **)(this + 0x38),1);
        plVar2 = *(long **)(this + 0x38);
      }
      (**(code **)(*plVar2 + 0x40))(plVar2,this + 0x40);
      setFingerPrintFree(*(FpService **)(this + 0x38),*(int *)(this + 0x48));
      uVar3 = 0;
    }
  }
  else {
    __android_log_print(3,"FingerGoodix","different client - don\'t disconnect");
    uVar3 = 0xffffffff;
  }
  pthread_mutex_unlock((pthread_mutex_t *)(this + 0x50));
  pthread_mutex_unlock((pthread_mutex_t *)(this + 0x78));
  return uVar3;
}



// android::FpService::Client::~Client()

void __thiscall android::FpService::Client::~Client(Client *this)

{
  long *plVar1;
  long *in_x1;
  long lVar2;
  
  lVar2 = *in_x1;
  *(long *)this = lVar2;
  *(long *)(this + *(long *)(lVar2 + -0x18)) = in_x1[0xf];
  *(long *)(this + 8) = in_x1[0x10];
  __android_log_print(3,"FingerGoodix","Client::~Client X (pid %d)",0x7b);
  *(undefined4 *)(this + 0x4c) = 0x7b;
  disconnect(this);
  pthread_mutex_destroy((pthread_mutex_t *)(this + 0x78));
  pthread_mutex_destroy((pthread_mutex_t *)(this + 0x50));
  plVar1 = *(long **)(this + 0x40);
  if (plVar1 != (long *)0x0) {
    android::RefBase::decStrong((void *)((long)plVar1 + *(long *)(*plVar1 + -0x18)));
  }
  plVar1 = *(long **)(this + 0x38);
  if (plVar1 != (long *)0x0) {
    android::RefBase::decStrong((void *)((long)plVar1 + *(long *)(*plVar1 + -0x18)));
  }
  lVar2 = in_x1[1];
  *(long *)this = lVar2;
  *(long *)(this + *(long *)(lVar2 + -0x18)) = in_x1[0xd];
  *(long *)(this + 8) = in_x1[0xe];
  lVar2 = in_x1[2];
  *(long *)this = lVar2;
  *(long *)(this + *(long *)(lVar2 + -0x18)) = in_x1[0xb];
  *(long *)(this + 8) = in_x1[0xc];
  android::BBinder::~BBinder((BBinder *)(this + 8));
  IFingerPrint::~IFingerPrint((IFingerPrint *)this);
  return;
}



// android::FpService::Client::~Client()

void __thiscall android::FpService::Client::~Client(Client *this)

{
  long *plVar1;
  
  *(undefined8 *)this = 0x15f168;
  *(undefined8 *)(this + 0xa0) = 0x15f3d0;
  *(undefined8 *)(this + 8) = 0x15f310;
  __android_log_print(3,"FingerGoodix","Client::~Client X (pid %d)",0x7b);
  *(undefined4 *)(this + 0x4c) = 0x7b;
  disconnect(this);
  pthread_mutex_destroy((pthread_mutex_t *)(this + 0x78));
  pthread_mutex_destroy((pthread_mutex_t *)(this + 0x50));
  plVar1 = *(long **)(this + 0x40);
  if (plVar1 != (long *)0x0) {
    android::RefBase::decStrong((void *)((long)plVar1 + *(long *)(*plVar1 + -0x18)));
  }
  plVar1 = *(long **)(this + 0x38);
  if (plVar1 != (long *)0x0) {
    android::RefBase::decStrong((void *)((long)plVar1 + *(long *)(*plVar1 + -0x18)));
  }
  *(undefined **)this = &DAT_0015ebd8;
  *(undefined **)(this + 0xa0) = &DAT_0015ee08;
  *(undefined ***)(this + 8) = &PTR_queryLocalInterface_0015ed48;
  android::BBinder::~BBinder((BBinder *)(this + 8));
  IFingerPrint::~IFingerPrint((IFingerPrint *)this);
  android::RefBase::~RefBase((RefBase *)(this + 0xa0));
  return;
}



// virtual thunk to android::FpService::Client::~Client()

void __thiscall android::FpService::Client::~Client(Client *this)

{
  ~Client(this + *(long *)(*(long *)this + -0x18));
  return;
}



// non-virtual thunk to android::FpService::Client::~Client()

void __thiscall android::FpService::Client::~Client(Client *this)

{
  ~Client(this + -8);
  return;
}



// android::FpService::Client::~Client()

void __thiscall android::FpService::Client::~Client(Client *this)

{
  ~Client(this);
  operator_delete(this);
  return;
}



// virtual thunk to android::FpService::Client::~Client()

void __thiscall android::FpService::Client::~Client(Client *this)

{
  ~Client(this + *(long *)(*(long *)this + -0x18));
  return;
}



// non-virtual thunk to android::FpService::Client::~Client()

void __thiscall android::FpService::Client::~Client(Client *this)

{
  ~Client(this + -8);
  return;
}



// android::FpService::Client::sysHalSetMode(int)

undefined8 __thiscall android::FpService::Client::sysHalSetMode(Client *this,int param_1)

{
  long *plVar1;
  int iVar2;
  int iVar3;
  
  if (param_1 < 0) {
    iVar2 = -param_1;
    iVar3 = 1;
  }
  else {
    if (param_1 < 10000) {
      return 0xffffffff;
    }
    iVar3 = 2;
    iVar2 = param_1 + -10000;
  }
  __android_log_print(3,"FingerGoodix","app change mode to: %d.",iVar2);
  (**(code **)(*(long *)this + 0xb8))(this);
  plVar1 = *(long **)(this + 0x38);
  if (*(int *)((long)plVar1 + 0xd4) - 2U < 3) {
    (**(code **)(*(long *)this + 0x70))(this);
    plVar1 = *(long **)(this + 0x38);
  }
  (**(code **)(*plVar1 + 0x60))(plVar1,iVar2);
  if (iVar3 == 2) {
    DAT_00163008 = iVar2;
  }
  return 0;
}



// android::FpService::Client::setMode(int)

undefined8 __thiscall android::FpService::Client::setMode(Client *this,int param_1)

{
  int iVar1;
  undefined8 uVar2;
  
  __android_log_print(3,"FingerGoodix","gx_fpd set mode: %d.",param_1);
  uVar2 = (**(code **)(*(long *)this + 0x188))(this);
  if (((int)uVar2 != 0) || (uVar2 = sysHalSetMode(this,param_1), (int)uVar2 == 0)) {
    return uVar2;
  }
  __android_log_print(3,"FingerGoodix","Client::setMode=%d ,but no longer support.return 0!",param_1
                     );
  if ((param_1 != 2) && (param_1 != 0x10)) {
    if (param_1 != 1) {
      __android_log_print(3,"FingerGoodix","Should not support to set mode[%d].\n",param_1);
      return 0xffffffff;
    }
    iVar1 = (**(code **)(**(long **)(this + 0x38) + 0x68))(*(long **)(this + 0x38));
    if (iVar1 != 0x10) goto LAB_00119b58;
  }
  (**(code **)(**(long **)(this + 0x38) + 0x60))(*(long **)(this + 0x38),param_1);
LAB_00119b58:
  (**(code **)(*(long *)(this + 0x28) + 0x128))(*(long *)(this + 0x28));
  (**(code **)(**(long **)(this + 0x38) + 0x70))(*(long **)(this + 0x38),1);
  return 0;
}



// android::sp<android::FpService::Client>::TEMPNAMEPLACEHOLDERVALUE(android::sp<android::FpService::Client>
// const&)

sp<> * __thiscall android::sp<>::operator=(sp<> *this,sp *param_1)

{
  long *plVar1;
  long *plVar2;
  
  plVar2 = *(long **)param_1;
  if (plVar2 != (long *)0x0) {
    android::RefBase::incStrong((void *)((long)plVar2 + *(long *)(*plVar2 + -0x18)));
  }
  plVar1 = *(long **)this;
  if (plVar1 != (long *)0x0) {
    android::RefBase::decStrong((void *)((long)plVar1 + *(long *)(*plVar1 + -0x18)));
  }
  *(long **)this = plVar2;
  return this;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// android::notifyClient(int, int, int)

void android::notifyClient(int param_1,int param_2,int param_3)

{
  int iVar1;
  long *local_10;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","notifyClient,type:%d,msg:%d,ext:%d,clientID:%d",param_1,
                      param_2,param_3,*(undefined4 *)((long)DAT_001631a0 + 0x2e4));
  local_10 = (long *)0x0;
  if (*(uint *)((long)DAT_001631a0 + 0x2e4) < 7) {
                    // try { // try from 00119c88 to 00119cd3 has its CatchHandler @ 00119d8c
    sp<>::operator=((sp<> *)&local_10,
                    (sp *)(DAT_001631a0 + (long)(int)*(uint *)((long)DAT_001631a0 + 0x2e4) + 4));
    if (local_10 != (long *)0x0) goto LAB_00119c94;
LAB_00119d3c:
    __android_log_print(6,"FingerGoodix","client is null");
  }
  else {
                    // try { // try from 00119d30 to 00119d67 has its CatchHandler @ 00119d8c
    __android_log_print(6,"FingerGoodix","Invalid NotifyClientID");
    if (local_10 == (long *)0x0) goto LAB_00119d3c;
LAB_00119c94:
    iVar1 = (**(code **)(*DAT_001631a0 + 0x68))(DAT_001631a0);
    if (iVar1 != 1) {
      (**(code **)(*local_10 + 0x170))(local_10,param_1,param_2,param_3);
      if (local_10 != (long *)0x0) {
        android::RefBase::decStrong((void *)((long)local_10 + *(long *)(*local_10 + -0x18)));
      }
      goto LAB_00119cf0;
    }
    __android_log_print(3,"FingerGoodix","it is in MODE_KEY,don\'t report event to Application");
  }
  if (local_10 != (long *)0x0) {
    android::RefBase::decStrong((void *)((long)local_10 + *(long *)(*local_10 + -0x18)));
  }
LAB_00119cf0:
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// android::FpService::Client::mp_test(int, int)

void __thiscall android::FpService::Client::mp_test(Client *this,int param_1,int param_2)

{
  int iVar1;
  long *plVar2;
  undefined8 uVar3;
  int iVar4;
  long lVar5;
  undefined8 local_30;
  undefined8 local_28;
  undefined8 local_20;
  undefined8 uStack_18;
  undefined4 local_10;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","mp_test");
  iVar1 = (**(code **)(*(long *)this + 0x188))(this);
  if (iVar1 != 0) goto LAB_00119e1c;
  local_30 = 0;
  local_28 = 0;
  local_20 = 0;
  uStack_18 = 0;
  local_10 = 0;
  __android_log_print(3,"FingerGoodix","%s. cmd = %d\n",
                      "android::status_t android::FpService::Client::mp_test(int, int)",param_1);
  if (1000 < param_1) {
    if (param_1 != 0x3e9) {
      if (param_1 == 0x3f1) {
        pthread_mutex_lock((pthread_mutex_t *)mStatusCheckLock);
                    // try { // try from 0011a214 to 0011a217 has its CatchHandler @ 0011a87c
        iVar1 = (**(code **)(*(long *)(this + 0x28) + 0x210))(*(long *)(this + 0x28),7,&local_30);
        plVar2 = *(long **)(this + 0x38);
        if (*(int *)((long)plVar2 + 0xd4) - 0xdU < 2) {
                    // try { // try from 0011a43c to 0011a467 has its CatchHandler @ 0011a87c
          (**(code **)(*plVar2 + 0x70))(plVar2,0xf);
          (**(code **)(*(long *)(this + 0x28) + 0x1a0))(*(long *)(this + 0x28));
          (**(code **)(**(long **)(this + 0x38) + 0x70))(*(long **)(this + 0x38),1);
          iVar1 = 0;
          pthread_mutex_unlock((pthread_mutex_t *)mStatusCheckLock);
        }
        else {
          pthread_mutex_unlock((pthread_mutex_t *)mStatusCheckLock);
        }
      }
      else {
        if (param_1 == 0x3ea) {
          iVar1 = (**(code **)(*(long *)(this + 0x28) + 0x210))(*(long *)(this + 0x28),1,&local_30);
          if ((iVar1 == 0) && ((int)local_30 == 1)) {
            iVar1 = (**(code **)(*(long *)(this + 0x28) + 0x270))(*(long *)(this + 0x28));
            if (iVar1 == 0) {
              __android_log_print(3,"FingerGoodix","CMD_SELFTEST SUCCESS.\n");
              iVar1 = 0;
            }
            else {
              iVar1 = -1;
              __android_log_print(3,"FingerGoodix","CMD_SELFTEST failed. selftest:%d, ret:%d.\n",
                                  local_30 & 0xffffffff,0);
            }
            goto LAB_00119e1c;
          }
        }
        else if (param_1 == 0x3eb) {
          __android_log_print(3,"FingerGoodix","FINGERPRINT_MP_TEST:%d",
                              *(undefined4 *)(*(long *)(this + 0x38) + 0xd4));
          pthread_mutex_lock((pthread_mutex_t *)ProcessRawDataLock);
                    // try { // try from 0011a048 to 0011a09f has its CatchHandler @ 0011a868
          (**(code **)(*(long *)(this + 0x28) + 0x210))(*(long *)(this + 0x28),8,&local_30);
          (**(code **)(**(long **)(this + 0x38) + 0x70))(*(long **)(this + 0x38),0xd);
          (**(code **)(**(long **)(this + 0x38) + 0x78))
                    (*(long **)(this + 0x38),*(undefined4 *)(this + 0x48));
          (**(code **)(**(long **)(this + 0x38) + 0x80))(*(long **)(this + 0x38));
          notifyClient(6000,0,0);
          iVar1 = 0;
          pthread_mutex_unlock((pthread_mutex_t *)ProcessRawDataLock);
          goto LAB_00119e1c;
        }
        iVar1 = -1;
      }
      goto LAB_00119e1c;
    }
    lVar5 = *(long *)(this + 0x28);
    uVar3 = 0;
    goto LAB_0011a304;
  }
  if (param_1 == 9) {
    (**(code **)(*(long *)(this + 0x28) + 0x1a8))(*(long *)(this + 0x28));
    iVar1 = (**(code **)(*(long *)(this + 0x28) + 0x210))(*(long *)(this + 0x28),0,&local_30);
    if (iVar1 == 0) {
      if ((int)local_30 == -2) {
        __android_log_print(3,"FingerGoodix","###### init status %d \n");
        notifyClient(0x1194,9,6);
      }
      else {
        notifyClient(0x1194,9,0);
      }
    }
    (**(code **)(*(long *)(this + 0x28) + 0x210))(*(long *)(this + 0x28),8,&local_30);
    goto LAB_00119e1c;
  }
  if (param_1 == 10) {
    iVar1 = (**(code **)(*(long *)(this + 0x28) + 0x210))(*(long *)(this + 0x28),1,&local_30);
    if ((iVar1 == 0) && ((int)local_30 == 1)) {
      iVar1 = (**(code **)(*(long *)(this + 0x28) + 0x270))(*(long *)(this + 0x28));
      if (iVar1 == 0) {
        __android_log_print(3,"FingerGoodix","service mp_test:selftest success.");
        notifyClient(0x1194,0,0);
        iVar1 = 0;
        goto LAB_00119e1c;
      }
    }
    iVar1 = -1;
    __android_log_print(3,"FingerGoodix","service mp_test:selftest failed.");
    notifyClient(0x1194,0,4);
    goto LAB_00119e1c;
  }
  if (param_1 == 0xb) {
    (**(code **)(*(long *)(this + 0x28) + 0x138))(*(long *)(this + 0x28),1);
    (**(code **)(*(long *)(this + 0x28) + 0x210))(*(long *)(this + 0x28),2,&local_30);
    (**(code **)(*(long *)(this + 0x28) + 0x138))(*(long *)(this + 0x28),0);
    (**(code **)(*(long *)(this + 0x28) + 0x238))(*(long *)(this + 0x28));
    if (local_30._4_4_ == 1) {
LAB_0011a160:
      iVar1 = 0;
      __android_log_print(3,"FingerGoodix","service mp_test:performance success.");
      notifyClient(0x1194,2,0);
      goto LAB_00119e1c;
    }
LAB_00119fb8:
    iVar1 = -1;
    __android_log_print(3,"FingerGoodix","service mp_test:performance failed.");
    notifyClient(0x1194,2,4);
    goto LAB_00119e1c;
  }
  if (param_1 == 0xc) {
    (**(code **)(*(long *)(this + 0x28) + 0x210))(*(long *)(this + 0x28),3,&local_30);
    if ((int)local_28 == 1) {
      __android_log_print(3,"FingerGoodix","service mp_test:image quality success.");
      notifyClient(0x1194,4,0);
    }
    else {
      iVar1 = -1;
      __android_log_print(3,"FingerGoodix","service mp_test:image quality failed.");
      notifyClient(0x1194,4,4);
    }
    goto LAB_00119e1c;
  }
  if (param_1 == 0xd) {
    (**(code **)(*(long *)(this + 0x28) + 0x210))(*(long *)(this + 0x28),4,&local_30);
    if (local_28._4_4_ == 1) {
      __android_log_print(3,"FingerGoodix","service mp_test:scene success.");
      notifyClient(0x1194,5,0);
    }
    else {
      iVar1 = -1;
      __android_log_print(3,"FingerGoodix","service mp_test:scene failed.");
      notifyClient(0x1194,5,4);
    }
    goto LAB_00119e1c;
  }
  if (param_1 == 0xe) {
    (**(code **)(*(long *)(this + 0x28) + 0x188))(*(long *)(this + 0x28),0);
    iVar1 = (**(code **)(*(long *)(this + 0x28) + 0x210))(*(long *)(this + 0x28),5,&local_30);
    if ((iVar1 == 0) && ((int)local_20 == 1)) {
      iVar1 = 0;
      __android_log_print(3,"FingerGoodix","service mp_test:defect detection pass.");
      iVar4 = 0;
    }
    else {
      iVar1 = -1;
      __android_log_print(3,"FingerGoodix","service mp_test:defect detection failed.");
      iVar4 = 4;
    }
    notifyClient(0x1194,6,iVar4);
    (**(code **)(*(long *)(this + 0x28) + 0x188))(*(long *)(this + 0x28),1);
    goto LAB_00119e1c;
  }
  if (param_1 == 0xf) {
    (**(code **)(*(long *)(this + 0x28) + 0x138))(*(long *)(this + 0x28),1);
    (**(code **)(*(long *)(this + 0x28) + 0x210))(*(long *)(this + 0x28),2,&local_30);
    (**(code **)(*(long *)(this + 0x28) + 0x138))(*(long *)(this + 0x28),0);
    (**(code **)(*(long *)(this + 0x28) + 0x238))(*(long *)(this + 0x28));
    local_10 = 0;
    local_30 = 0;
    local_28 = 0;
    local_20 = 0;
    uStack_18 = 0;
    (**(code **)(*(long *)(this + 0x28) + 0x210))(*(long *)(this + 0x28),6,&local_30);
    if (local_20._4_4_ == 1) {
      iVar1 = 0;
      __android_log_print(3,"FingerGoodix","service mp_test:pixel_detection success.");
      notifyClient(0x1194,7,0);
    }
    else {
      iVar1 = -1;
      __android_log_print(3,"FingerGoodix","service mp_test:pixel_detection failed.");
      notifyClient(0x1194,7,4);
    }
    goto LAB_00119e1c;
  }
  if (param_1 == 0x10) {
    lVar5 = *(long *)(this + 0x28);
    uVar3 = 7;
LAB_0011a304:
    iVar1 = (**(code **)(lVar5 + 0x210))(lVar5,uVar3,&local_30);
  }
  else {
    if (param_1 == 0x11) {
      if (0 < param_2) {
        iVar1 = (**(code **)(*(long *)(this + 0x28) + 0x178))(*(long *)(this + 0x28),param_2);
        if (iVar1 == 0x83) {
          iVar1 = -1;
          __android_log_print(3,"FingerGoodix","service mp_test:finger down timeout.");
          notifyClient(0x1194,1,1);
        }
        else if (iVar1 == 0) {
          iVar1 = 0;
          __android_log_print(3,"FingerGoodix","service mp_test:finger down success.");
          notifyClient(0x1194,1,0);
        }
        else {
          iVar1 = -1;
          __android_log_print(3,"FingerGoodix","service mp_test:finger down failed.");
          notifyClient(0x1194,1,4);
        }
        goto LAB_00119e1c;
      }
    }
    else {
      if (param_1 != 0x12) {
        if (param_1 == 0x15) {
          __android_log_print(3,"FingerGoodix","service mp_test:check ring enable.");
          lVar5 = *(long *)(this + 0x28);
          uVar3 = 0xb;
        }
        else {
          if (param_1 != 0x16) {
            if (param_1 == 0x17) {
              iVar1 = (**(code **)(*(long *)(this + 0x28) + 0x270))(*(long *)(this + 0x28));
              if (iVar1 == 0) {
                iVar1 = -1;
                __android_log_print(3,"FingerGoodix","service mp_test:CheckReset success.");
                notifyClient(0x1194,8,0);
              }
              else {
                iVar1 = 0;
                __android_log_print(3,"FingerGoodix","service mp_test:CheckReset failed.");
                notifyClient(0x1194,8,4);
              }
              goto LAB_00119e1c;
            }
            if (param_1 != 0x18) {
              iVar1 = -1;
              __android_log_print(6,"FingerGoodix","service mp_test:case error.");
              goto LAB_00119e1c;
            }
            uStack_18 = CONCAT44(0xffffffff,(undefined4)uStack_18);
            local_28 = CONCAT44(0xffffffff,(int)local_28);
            local_30 = CONCAT44(0xffffffff,(int)local_30);
            (**(code **)(*(long *)(this + 0x28) + 0x138))(*(long *)(this + 0x28),1);
            (**(code **)(*(long *)(this + 0x28) + 0x210))(*(long *)(this + 0x28),0xd,&local_30);
            (**(code **)(*(long *)(this + 0x28) + 0x138))(*(long *)(this + 0x28),0);
            (**(code **)(*(long *)(this + 0x28) + 0x238))(*(long *)(this + 0x28));
            if (uStack_18._4_4_ == 0) {
              __android_log_print(3,"FingerGoodix","service mp_test:quality success.");
              notifyClient(0x1194,4,0);
            }
            else {
              __android_log_print(3,"FingerGoodix","service mp_test:quality failed.");
              notifyClient(0x1194,4,4);
            }
            if (local_28._4_4_ == 0) {
              __android_log_print(3,"FingerGoodix","service mp_test:scene success.");
              notifyClient(0x1194,5,0);
            }
            else {
              __android_log_print(3,"FingerGoodix","service mp_test:scene failed.");
              notifyClient(0x1194,5,4);
            }
            if (local_30._4_4_ == 0) goto LAB_0011a160;
            goto LAB_00119fb8;
          }
          __android_log_print(3,"FingerGoodix","service mp_test:check ring disable.");
          lVar5 = *(long *)(this + 0x28);
          uVar3 = 0xc;
        }
        goto LAB_0011a304;
      }
      if (0 < param_2) {
        iVar1 = (**(code **)(*(long *)(this + 0x28) + 0x180))(*(long *)(this + 0x28),param_2);
        if (iVar1 == 0x83) {
          iVar1 = -1;
          __android_log_print(3,"FingerGoodix","service mp_test:finger up timeout.");
          notifyClient(0x1194,3,1);
        }
        else if (iVar1 == 0) {
          iVar1 = 0;
          __android_log_print(3,"FingerGoodix","service mp_test:finger up success.");
          notifyClient(0x1194,3,0);
        }
        else {
          iVar1 = -1;
          __android_log_print(3,"FingerGoodix","service mp_test:finger up failed.");
          notifyClient(0x1194,3,4);
        }
        goto LAB_00119e1c;
      }
    }
    iVar1 = -1;
    __android_log_print(3,"FingerGoodix","Time out param error. time = %d.",param_2);
  }
LAB_00119e1c:
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(iVar1);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// android::FpService::Client::SendCmd(int, char*, int, char**, int*)

void __thiscall
android::FpService::Client::SendCmd
          (Client *this,int param_1,char *param_2,int param_3,char **param_4,int *param_5)

{
  int iVar1;
  undefined4 *puVar2;
  char *pcVar3;
  undefined8 *puVar4;
  long *plVar5;
  undefined4 local_18;
  undefined4 uStack_14;
  undefined4 local_10;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","FpService::Client::SendCmd cmd = %d.",param_1);
  iVar1 = (**(code **)(*(long *)this + 0x188))(this);
  if (iVar1 == 0) {
    if (param_5 != (int *)0x0) {
      *param_5 = 0;
      *param_4 = (char *)0x0;
    }
    switch(param_1) {
    case 0:
      pthread_mutex_lock((pthread_mutex_t *)mStatusCheckLock);
      plVar5 = *(long **)(this + 0x38);
      if (*(int *)((long)plVar5 + 0xd4) - 10U < 2) {
                    // try { // try from 0011acd8 to 0011ad03 has its CatchHandler @ 0011adec
        (**(code **)(*plVar5 + 0x70))(plVar5,0xc);
        (**(code **)(*(long *)(this + 0x28) + 0x1a0))(*(long *)(this + 0x28));
        (**(code **)(**(long **)(this + 0x38) + 0x70))(*(long **)(this + 0x38),1);
        iVar1 = 0;
      }
      else {
        iVar1 = -1;
      }
      pthread_mutex_unlock((pthread_mutex_t *)mStatusCheckLock);
      break;
    case 1:
      __android_log_print(3,"FingerGoodix","FINGERPRINT_CMD_GET_BITMAP:%d",
                          *(undefined4 *)(*(long *)(this + 0x38) + 0xd4));
      pthread_mutex_lock((pthread_mutex_t *)ProcessRawDataLock);
                    // try { // try from 0011ac28 to 0011ac57 has its CatchHandler @ 0011add8
      (**(code **)(**(long **)(this + 0x38) + 0x70))(*(long **)(this + 0x38),10);
      (**(code **)(**(long **)(this + 0x38) + 0x78))
                (*(long **)(this + 0x38),*(undefined4 *)(this + 0x48));
      (**(code **)(**(long **)(this + 0x38) + 0x80))(*(long **)(this + 0x38));
      iVar1 = 0;
      pthread_mutex_unlock((pthread_mutex_t *)ProcessRawDataLock);
      break;
    case 2:
      puVar4 = (undefined8 *)malloc(0x10);
      *puVar4 = 0;
      puVar4[1] = 0;
      if (param_2 == (char *)0x0) {
        __android_log_print(6,"FingerGoodix","Error_%d:in_buffer is NULL.",0x85b);
      }
      else {
        (**(code **)(*(long *)(this + 0x28) + 0x1e0))(*(long *)(this + 0x28),param_2,param_3,puVar4)
        ;
      }
      *param_4 = (char *)puVar4;
      iVar1 = 0;
      *param_5 = 0x10;
      break;
    case 3:
      iVar1 = 0;
      (**(code **)(*(long *)(this + 0x28) + 0x1f8))(*(long *)(this + 0x28));
      break;
    case 4:
      if (param_2 == (char *)0x0) {
        iVar1 = 0;
        __android_log_print(6,"FingerGoodix","Error_%d:in_buffer is NULL.",0x86a);
      }
      else {
        iVar1 = 0;
        (**(code **)(*(long *)(this + 0x28) + 0x1e8))(*(long *)(this + 0x28),param_2,param_3);
      }
      break;
    case 5:
      puVar4 = (undefined8 *)malloc(0x18);
      puVar4[2] = 0;
      *puVar4 = 0;
      puVar4[1] = 0;
      if (param_2 == (char *)0x0) {
        __android_log_print(6,"FingerGoodix","Error_%d:in_buffer is NULL.",0x879);
      }
      else {
        (**(code **)(*(long *)(this + 0x28) + 0x1f0))(*(long *)(this + 0x28),param_2,param_3,puVar4)
        ;
      }
      *param_4 = (char *)puVar4;
      iVar1 = 0;
      *param_5 = 0x18;
      break;
    case 6:
      if (param_2 == (char *)0x0) {
        iVar1 = 0;
        __android_log_print(6,"FingerGoodix","Error_%d:in_buffer is NULL.",0x89f);
      }
      else {
        iVar1 = 0;
        (**(code **)(*(long *)(this + 0x28) + 0x200))(*(long *)(this + 0x28),param_2,param_3);
      }
      break;
    default:
      if (param_1 < 0x3e9) {
        iVar1 = 0;
        __android_log_print(6,"FingerGoodix","SendCmd:command not find!");
      }
      else {
        (**(code **)(**(long **)(this + 0x38) + 0x60))(*(long **)(this + 0x38),0);
        (**(code **)(**(long **)(this + 0x38) + 0x78))
                  (*(long **)(this + 0x38),*(undefined4 *)(this + 0x48));
        if ((param_2 == (char *)0x0) || (param_3 < 1)) {
          iVar1 = -1;
        }
        else {
          iVar1 = mp_test(this,param_1,*(int *)param_2);
        }
        if (param_1 == 0x3f1) {
          (**(code **)(**(long **)(this + 0x38) + 0x60))(*(long **)(this + 0x38),2);
        }
      }
      break;
    case 8:
      iVar1 = 0;
      pcVar3 = (char *)malloc(0x1c);
      (**(code **)(*(long *)(this + 0x28) + 0x208))(*(long *)(this + 0x28),pcVar3);
      *param_4 = pcVar3;
      *param_5 = 0x1c;
      break;
    case 9:
    case 10:
    case 0xb:
    case 0xc:
    case 0xd:
    case 0xe:
    case 0xf:
    case 0x10:
    case 0x11:
    case 0x12:
    case 0x15:
    case 0x16:
    case 0x17:
    case 0x18:
      __android_log_print(3,"FingerGoodix","FINGERPRINT_CMD_MP_TEST");
      pthread_mutex_lock((pthread_mutex_t *)ProcessRawDataLock);
      if (param_1 != 10) {
                    // try { // try from 0011aa8c to 0011aaa7 has its CatchHandler @ 0011ae00
        (**(code **)(**(long **)(this + 0x38) + 0x60))(*(long **)(this + 0x38),0);
      }
      (**(code **)(**(long **)(this + 0x38) + 0x78))
                (*(long **)(this + 0x38),*(undefined4 *)(this + 0x48));
      if ((param_2 == (char *)0x0) || (param_3 < 1)) {
        iVar1 = -1;
      }
      else {
                    // try { // try from 0011acc0 to 0011acc3 has its CatchHandler @ 0011ae00
        iVar1 = mp_test(this,param_1,*(int *)param_2);
      }
      if (param_1 == 0x10) {
                    // try { // try from 0011adcc to 0011adcf has its CatchHandler @ 0011ae00
        (**(code **)(**(long **)(this + 0x38) + 0x60))(*(long **)(this + 0x38),2);
      }
      pthread_mutex_unlock((pthread_mutex_t *)ProcessRawDataLock);
      break;
    case 0x13:
      if (param_2 == (char *)0x0) {
        iVar1 = 0;
        __android_log_print(6,"FingerGoodix","Error_%d:in_buffer is NULL.",0x8e3);
      }
      else {
        local_10 = *(undefined4 *)param_2;
        iVar1 = 0;
        local_18 = 1;
        uStack_14 = 1;
        (**(code **)(*(long *)(this + 0x28) + 0x228))(*(long *)(this + 0x28),0x100000001,local_10);
      }
      break;
    case 0x14:
      iVar1 = 0;
      puVar2 = (undefined4 *)malloc(4);
      local_18 = 1;
      uStack_14 = 1;
      (**(code **)(*(long *)(this + 0x28) + 0x230))(*(long *)(this + 0x28),&local_18);
      *param_4 = (char *)puVar2;
      *puVar2 = local_10;
      *param_5 = 4;
    }
  }
  if (local_8 != ___stack_chk_guard) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail(iVar1);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// android::postData2Client(int, int, char*)

void android::postData2Client(int param_1,int param_2,char *param_3)

{
  long *local_10;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","postData2Client,msgType:%d,length:%d,clientID:%d",param_1,
                      param_2,*(undefined4 *)(DAT_001631a0 + 0x2e4));
  local_10 = (long *)0x0;
  if (*(uint *)(DAT_001631a0 + 0x2e4) < 7) {
                    // try { // try from 0011aea4 to 0011aec7 has its CatchHandler @ 0011af64
    sp<>::operator=((sp<> *)&local_10,
                    (sp *)(DAT_001631a0 + ((long)(int)*(uint *)(DAT_001631a0 + 0x2e4) + 4) * 8));
  }
  else {
                    // try { // try from 0011af20 to 0011af3f has its CatchHandler @ 0011af64
    __android_log_print(6,"FingerGoodix","Invalid NotifyClientID");
  }
  if (local_10 == (long *)0x0) {
    __android_log_print(6,"FingerGoodix","client is null");
    if (local_10 != (long *)0x0) {
      android::RefBase::decStrong((void *)((long)local_10 + *(long *)(*local_10 + -0x18)));
    }
  }
  else {
    (**(code **)(*local_10 + 0x178))(local_10,param_1,param_2,param_3);
    if (local_10 != (long *)0x0) {
      android::RefBase::decStrong((void *)((long)local_10 + *(long *)(*local_10 + -0x18)));
    }
  }
  if (local_8 != ___stack_chk_guard) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail();
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0011af8c(long *param_1)

{
  uint uVar1;
  undefined4 uVar2;
  ulong uVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  char *pcVar7;
  code *pcVar8;
  long lVar9;
  undefined auStack_640 [692];
  int local_38c;
  undefined8 local_388;
  undefined8 uStack_380;
  undefined8 local_378;
  undefined8 local_370;
  int local_368;
  undefined8 local_360;
  undefined8 uStack_358;
  undefined8 local_350;
  undefined8 uStack_348;
  undefined8 local_340;
  undefined8 uStack_338;
  undefined auStack_330 [64];
  undefined auStack_2f0 [64];
  int local_2b0;
  int local_2ac;
  undefined4 local_2a8;
  undefined4 local_2a4;
  int local_298;
  int local_214;
  char acStack_210 [520];
  undefined8 local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","create RawDataProcessLoop!");
  lVar9 = param_1[0x29];
LAB_0011b018:
  do {
    while( true ) {
      while( true ) {
        __android_log_print(3,"FingerGoodix","RawDataProcessLoop waiting signal!");
        iVar4 = (**(code **)(*param_1 + 0x68))(param_1);
        if ((iVar4 == 0x10) || (iVar4 == 1)) {
          __android_log_print(3,"FingerGoodix","Don\'t change sensor mode in KEY or NAV mode[%d]\n",
                              iVar4);
        }
        else {
          (**(code **)(*param_1 + 0x60))(param_1,DAT_00163008);
          __android_log_print(3,"FingerGoodix","RawDataProcessLoop set to default mode[%d]",
                              DAT_00163008);
        }
        iVar4 = sem_wait((sem_t *)&DAT_00163160);
        __android_log_print(3,"FingerGoodix","RawDataProcessLoop got signal!");
        uVar1 = *(uint *)((long)param_1 + 0xd4) & 0xfffffffb;
        if ((uVar1 != 8 && uVar1 != 1) && (*(uint *)((long)param_1 + 0xd4) != 0xf)) break;
        __android_log_print(3,"FingerGoodix","No need to wait for finer status 1 : %d\n");
      }
      (**(code **)(*param_1 + 0x60))(param_1,0);
      __android_log_print(3,"FingerGoodix","RawDataProcessLoop set to IMAGE mode");
      if (iVar4 == 0) break;
      __android_log_print(3,"FingerGoodix","EventProcessThread wait signal error!");
    }
    while( true ) {
      local_38c = 0;
      memcpy(auStack_330,"success",0x80);
      local_360 = 0;
      uStack_358 = 0;
      local_350 = 0;
      uStack_348 = 0;
      local_340 = 0;
      uStack_338 = 0;
      pthread_mutex_lock((pthread_mutex_t *)android::ProcessRawDataLock);
      uVar1 = *(uint *)((long)param_1 + 0xd4);
      if (((uVar1 & 0xfffffffb) == 8 || (uVar1 & 0xfffffffb) == 1) || (uVar1 == 0xf)) break;
      if (uVar1 == 6) {
                    // try { // try from 0011b1c8 to 0011b227 has its CatchHandler @ 0011c12c
        __android_log_print(3,"FingerGoodix","EventProcessThread wait hal_Up! status:%d");
        iVar4 = (**(code **)(lVar9 + 0x180))(lVar9,0);
        if (iVar4 != 0) {
          if (iVar4 != 2) {
            __android_log_print(3,"FingerGoodix",
                                "EventProcessThread wait hal_UP error, goto RAWDATALOOP!");
            goto LAB_0011b158;
          }
          __android_log_print(3,"FingerGoodix","EventProcessThread cancel hal_UP go to waitting!");
          goto LAB_0011b228;
        }
        uVar1 = *(uint *)((long)param_1 + 0xd4) & 0xfffffffb;
        if ((uVar1 != 8 && uVar1 != 1) && (*(uint *)((long)param_1 + 0xd4) != 0xf))
        goto LAB_0011b118;
                    // try { // try from 0011b2fc to 0011b7a7 has its CatchHandler @ 0011c12c
        __android_log_print(3,"FingerGoodix","No need to wait for finer status 3 : %d\n");
        goto LAB_0011b214;
      }
LAB_0011b118:
                    // try { // try from 0011b124 to 0011b157 has its CatchHandler @ 0011c12c
      __android_log_print(3,"FingerGoodix","EventProcessThread wait hal_Down! status:%d");
      iVar4 = (**(code **)(lVar9 + 0x178))(lVar9,0);
      if (iVar4 != 0) {
        if (iVar4 != 1) {
          __android_log_print(3,"FingerGoodix",
                              "EventProcessThread wait hal_Down error, goto RAWDATALOOP!");
          goto LAB_0011b158;
        }
        __android_log_print(3,"FingerGoodix","EventProcessThread cancel hal_Down goto waitting!");
        goto LAB_0011b228;
      }
                    // try { // try from 0011b244 to 0011b29f has its CatchHandler @ 0011c12c
      __android_log_print(3,"FingerGoodix","EventProcessThread wait hal_Down! status:%d",
                          *(undefined4 *)((long)param_1 + 0xd4));
      switch(*(undefined4 *)((long)param_1 + 0xd4)) {
      case 2:
        local_388 = 0;
        __android_log_print(3,"FingerGoodix","EventProcessThread reg pending to registering");
        (**(code **)(*param_1 + 0x70))(param_1,3);
        (**(code **)(lVar9 + 0x138))(lVar9,1);
        (**(code **)(lVar9 + 0xb8))(lVar9,&local_388);
        (**(code **)(lVar9 + 0x138))(lVar9,0);
        (**(code **)(lVar9 + 0x238))(lVar9);
        uVar3 = local_388;
        uVar1 = (uint)local_388;
        __android_log_print(3,"FingerGoodix","TA return progress = %d. Status:%d",
                            local_388 & 0xffffffff,local_388._4_4_);
        if (*(int *)((long)param_1 + 0xd4) != 3) {
          __android_log_print(3,"FingerGoodix",
                              "EventProcessThread registering,but status be changed to %d,then cancel reg"
                             );
          (**(code **)(lVar9 + 0xc0))(lVar9);
          (**(code **)(lVar9 + 0x180))(lVar9,0);
          goto LAB_0011b288;
        }
        iVar4 = property_get_int32("goodix.fp.debug",0);
        if (iVar4 == 1) {
          local_38c = 0x100000;
          pcVar7 = (char *)malloc(0x100000);
          iVar4 = (**(code **)(lVar9 + 0x1d8))(lVar9,pcVar7,&local_38c,&local_360,0);
          if ((pcVar7 != (char *)0x0) && (iVar4 == 0)) {
            android::postData2Client(0x1b,0x30,(char *)&local_360);
            android::postData2Client(0x1a,local_38c,pcVar7);
            local_38c = 0x100000;
            iVar4 = (**(code **)(lVar9 + 0x1d8))(lVar9,pcVar7,&local_38c,&local_360,3);
            if (iVar4 == 0) {
              android::postData2Client(0x1d,local_38c,pcVar7);
            }
          }
          free(pcVar7);
          if (local_388._4_4_ == 0) {
            (**(code **)(lVar9 + 0x298))(lVar9,auStack_330,1);
          }
          else {
                    // try { // try from 0011bfd8 to 0011c0f3 has its CatchHandler @ 0011c12c
            (**(code **)(lVar9 + 0x298))(lVar9,auStack_2f0,1);
          }
        }
        if (uVar1 < 100) {
          __android_log_print(3,"FingerGoodix",
                              "EventProcessThread registering,notify result,and set to pending!,current precent:%d"
                              ,uVar3 & 0xffffffff);
          if (local_388._4_4_ == 1) {
            android::notifyClient(0x1c,uVar1,0);
          }
          else if (local_388._4_4_ == 2) {
            android::notifyClient(0x1e,uVar1,0);
          }
          else if (local_388._4_4_ == 3) {
            android::notifyClient(0x14,uVar1,0);
          }
          else if (local_388._4_4_ == 4) {
            android::notifyClient(0x22,uVar1,0);
          }
          else if ((local_388._4_4_ == 0xb) || (local_388._4_4_ == 5)) {
            android::notifyClient(0x15,uVar1,0);
          }
          else if (local_388._4_4_ == 7) {
            android::notifyClient(0x16,uVar1,0);
          }
          else if (local_388._4_4_ == 8) {
            android::notifyClient(0x21,uVar1,0);
          }
          else if (local_388._4_4_ == 6) {
            android::notifyClient(0x1f,uVar1,0);
          }
          else if (local_388._4_4_ == 9) {
            android::notifyClient(0x20,uVar1,0);
          }
          else {
            if (local_388._4_4_ == 10) {
              __android_log_print(3,"FingerGoodix",
                                  "enroll: Bias temperature lead to fake fingerdown");
              iVar4 = *(int *)((long)param_1 + 0xd4);
              if (iVar4 != 3) break;
              (**(code **)(*param_1 + 0x70))(param_1,2);
              goto LAB_0011b288;
            }
            android::notifyClient(0x11,uVar1,0);
          }
          pthread_mutex_lock((pthread_mutex_t *)android::mStatusCheckLock);
          if (*(int *)((long)param_1 + 0xd4) == 3) {
                    // try { // try from 0011bfc0 to 0011bfc3 has its CatchHandler @ 0011c118
            (**(code **)(*param_1 + 0x70))(param_1,2);
          }
          pthread_mutex_unlock((pthread_mutex_t *)android::mStatusCheckLock);
        }
        else if (uVar1 == 100) {
                    // try { // try from 0011bdf8 to 0011bf7f has its CatchHandler @ 0011c12c
          __android_log_print(3,"FingerGoodix",
                              "EventProcessThread registering,notify result,and set to idle!");
          (**(code **)(*param_1 + 0x70))(param_1,4);
          android::notifyClient(0x11,100,0);
          android::notifyClient(0x18,100,0);
        }
        else {
          __android_log_print(3,"FingerGoodix",
                              "EventProcessThread registering,Algorithm error , pre is invalid!");
          (**(code **)(*param_1 + 0x70))(param_1,4);
          android::notifyClient(0x16,uVar1,0);
        }
        iVar4 = *(int *)((long)param_1 + 0xd4);
        if (iVar4 - 2U < 3) {
          iVar4 = (**(code **)(lVar9 + 0x180))(lVar9,0);
          if ((iVar4 != 0) || (*(char *)((long)param_1 + 0x19c) != '\0')) goto LAB_0011b288;
          iVar5 = (**(code **)(lVar9 + 0x220))(lVar9);
          iVar4 = *(int *)((long)param_1 + 0xd4);
          if (iVar5 == 0) {
            *(undefined *)((long)param_1 + 0x19c) = 1;
          }
        }
        break;
      default:
        __android_log_print(6,"FingerGoodix",
                            "EventProcessThread actStatus error!ignore getdata!current actStatus:%d"
                           );
        (**(code **)(lVar9 + 0x238))(lVar9);
        (**(code **)(lVar9 + 0x188))(lVar9,1);
        goto LAB_0011b288;
      case 6:
        __android_log_print(3,"FingerGoodix","EventProcessThread reg pending to matching!");
        (**(code **)(*param_1 + 0x70))(param_1,7);
        uVar2 = *(undefined4 *)(param_1 + 0x15);
        iVar4 = *(int *)((long)param_1 + 0x84);
        memset(&local_2b0,0,0x2a4);
        local_388 = local_388 & 0xffffffff00000000;
        (**(code **)(lVar9 + 0x138))(lVar9,1);
        __android_log_print(3,"FingerGoodix","isFidoVerify value : %d\n",
                            *(undefined *)(param_1 + 0x2a));
        if (*(char *)(param_1 + 0x2a) == '\0') {
                    // try { // try from 0011b7f0 to 0011b897 has its CatchHandler @ 0011c12c
          __android_log_print(3,"FingerGoodix","NOT Fido path pending to matching!, sectype = %d",
                              iVar4);
          iVar5 = (**(code **)(lVar9 + 0xe0))
                            (lVar9,iVar4,param_1 + 0x11,uVar2,&local_2b0,&local_388);
        }
        else {
          __android_log_print(3,"FingerGoodix","Fido path pending to matching!");
          iVar5 = (**(code **)(lVar9 + 0x1d0))
                            (lVar9,param_1 + 0x11,uVar2,&local_2b0,&local_388,(long)param_1 + 0x154)
          ;
        }
        iVar6 = property_get_int32("goodix.fp.debug",0);
        if (iVar6 == 1) {
          __android_log_print(3,"FingerGoodix","dump for debug");
          local_38c = 0x100000;
          pcVar7 = (char *)malloc(0x100000);
          iVar6 = (**(code **)(lVar9 + 0x1d8))(lVar9,pcVar7,&local_38c,&local_360,1);
          if ((pcVar7 != (char *)0x0) && (iVar6 == 0)) {
            android::postData2Client(0x109,0x30,(char *)&local_360);
            android::postData2Client(0x108,local_38c,pcVar7);
            local_38c = 0x100000;
            iVar6 = (**(code **)(lVar9 + 0x1d8))(lVar9,pcVar7,&local_38c,&local_360,3);
            if (iVar6 == 0) {
              android::postData2Client(0x10a,local_38c,pcVar7);
            }
          }
          free(pcVar7);
          if (local_298 == 0) {
            (**(code **)(lVar9 + 0x298))(lVar9,auStack_330,0);
          }
          else {
            (**(code **)(lVar9 + 0x298))(lVar9,auStack_2f0,0);
          }
        }
        iVar6 = property_get_int32("goodix.fp.debug.analyse",0);
        if (iVar6 == 1) {
          memcpy(auStack_640,&local_2b0,0x2a4);
          writeDataToRecordFile();
        }
        __android_log_print(3,"FingerGoodix",
                            "Match Pending: status:%d. verifyIndex:%d, verifyScore:%d, quality:%d, coverage:%d\n"
                            ,*(undefined4 *)((long)param_1 + 0xd4),local_2b0,local_2ac,local_2a4,
                            local_2a8);
        if (*(int *)((long)param_1 + 0xd4) == 7) {
          if (iVar5 < 0) goto LAB_0011b850;
          if (local_2b0 != 0xcc) {
            if (local_2b0 == 0xbb) {
              if (local_2ac != 0xbb) goto LAB_0011b9c0;
              __android_log_print(3,"FingerGoodix","Recognize: Sensor Defect Fail.");
              android::notifyClient(0x20,0,0);
            }
            else if (local_2b0 < 1) {
              android::notifyClient(0x103,0,0);
            }
            else {
LAB_0011b9c0:
                    // try { // try from 0011b9d4 to 0011bcef has its CatchHandler @ 0011c12c
              __android_log_print(3,"FingerGoodix","Recognize end. ret = %d, index = %d\n",iVar5);
              if (*(char *)(param_1 + 0x2a) == '\0') {
                android::postData2Client(0x101,(uint)local_388,(char *)&local_2b0);
              }
              else {
                __android_log_print(3,"FingerGoodix","FIDO Recognize return UVT1.RspLength:%d\n",
                                    local_214);
                android::postData2Client(0x107,local_214,acStack_210);
              }
              if (iVar4 != 1) {
                (**(code **)(lVar9 + 0x218))(lVar9,local_2b0);
              }
            }
LAB_0011b850:
            (**(code **)(lVar9 + 0x138))(lVar9,0);
            (**(code **)(lVar9 + 0x238))(lVar9);
            __android_log_print(3,"FingerGoodix","Recognize end,the return: %d. status : %d",iVar5,
                                *(undefined4 *)((long)param_1 + 0xd4));
            pthread_mutex_lock((pthread_mutex_t *)android::mStatusCheckLock);
            if ((*(int *)((long)param_1 + 0xd4) == 7) && (local_2b0 < 1)) {
                    // try { // try from 0011bf94 to 0011bfab has its CatchHandler @ 0011c134
              __android_log_print(3,"FingerGoodix",
                                  "Recognize fail, setStatus FPALGO_ACT_MATCH_PENDING.");
              (**(code **)(*param_1 + 0x70))(param_1,6);
            }
            pthread_mutex_unlock((pthread_mutex_t *)android::mStatusCheckLock);
            pcVar8 = *(code **)(lVar9 + 0x180);
            *(undefined *)(param_1 + 0x2a) = 0;
                    // try { // try from 0011b8d0 to 0011b94b has its CatchHandler @ 0011c12c
            iVar4 = (*pcVar8)(lVar9,0);
            if ((iVar4 == 0) && (*(char *)((long)param_1 + 0x19c) == '\0')) {
                    // try { // try from 0011bd20 to 0011bdd3 has its CatchHandler @ 0011c12c
              __android_log_print(3,"FingerGoodix","Recognize failed. We need update base.");
              iVar4 = (**(code **)(lVar9 + 0x220))(lVar9);
              if (iVar4 == 0) {
                *(undefined *)((long)param_1 + 0x19c) = 1;
              }
            }
            __android_log_print(3,"FingerGoodix","Recognize end.");
            goto LAB_0011b288;
          }
          if (local_2ac != 0xcc) goto LAB_0011b9c0;
          __android_log_print(3,"FingerGoodix","Recognize: Bias temperature lead to fake fingerdown"
                             );
          iVar4 = *(int *)((long)param_1 + 0xd4);
          if (iVar4 == 7) {
            (**(code **)(*param_1 + 0x70))(param_1,6);
            iVar4 = *(int *)((long)param_1 + 0xd4);
            *(undefined *)(param_1 + 0x2a) = 0;
          }
          else {
            *(undefined *)(param_1 + 0x2a) = 0;
          }
        }
        else {
          (**(code **)(lVar9 + 0x138))(lVar9,0);
          (**(code **)(lVar9 + 0xe8))(lVar9);
          (**(code **)(lVar9 + 0x180))(lVar9,0);
          __android_log_print(3,"FingerGoodix","Matching status changed to :%d!",
                              *(undefined4 *)((long)param_1 + 0xd4));
          *(undefined *)(param_1 + 0x2a) = 0;
          iVar4 = *(int *)((long)param_1 + 0xd4);
        }
        break;
      case 10:
        __android_log_print(3,"FingerGoodix","EventProcessThread get bitmap.");
        local_38c = 0x100000;
        pcVar7 = (char *)malloc(0x100000);
        (**(code **)(*param_1 + 0x70))(param_1,0xb);
        (**(code **)(lVar9 + 0x138))(lVar9,1);
        iVar4 = (**(code **)(lVar9 + 0x1d8))(lVar9,pcVar7,&local_38c,&local_360,2);
        (**(code **)(lVar9 + 0x138))(lVar9,0);
        (**(code **)(lVar9 + 0x238))(lVar9);
        if (*(int *)((long)param_1 + 0xd4) == 0xb) {
          if ((((iVar4 == 0) && (pcVar7 != (char *)0x0)) && (0xf < local_360._4_4_)) &&
             (0x41 < (int)local_360)) {
            android::postData2Client(0x12e,0x30,(char *)&local_360);
            android::postData2Client(300,local_38c,pcVar7);
            local_38c = 0x100000;
            iVar4 = (**(code **)(lVar9 + 0x1d8))(lVar9,pcVar7,&local_38c,&local_360,3);
            if (iVar4 == 0) {
              android::postData2Client(0x12f,local_38c,pcVar7);
            }
            iVar4 = property_get_int32("goodix.fp.debug",0);
            if (iVar4 == 1) {
              (**(code **)(lVar9 + 0x298))(lVar9,auStack_330,8);
            }
            usleep(200000);
          }
          else {
            android::notifyClient(0x12d,0,0);
          }
          free(pcVar7);
          pthread_mutex_lock((pthread_mutex_t *)android::mStatusCheckLock);
                    // try { // try from 0011b958 to 0011b95b has its CatchHandler @ 0011c0f8
          iVar4 = (**(code **)(lVar9 + 0x180))(lVar9,0);
                    // try { // try from 0011bcfc to 0011bcff has its CatchHandler @ 0011c0f8
          if (((iVar4 == 0) && (*(char *)((long)param_1 + 0x19c) == '\0')) &&
             (iVar4 = (**(code **)(lVar9 + 0x220))(lVar9), iVar4 == 0)) {
            *(undefined *)((long)param_1 + 0x19c) = 1;
          }
          pthread_mutex_unlock((pthread_mutex_t *)android::mStatusCheckLock);
          iVar4 = *(int *)((long)param_1 + 0xd4);
          if (iVar4 == 0xb) {
                    // try { // try from 0011b990 to 0011b993 has its CatchHandler @ 0011c12c
            (**(code **)(*param_1 + 0x70))(param_1,10);
            goto LAB_0011b288;
          }
        }
        else {
          (**(code **)(lVar9 + 0x180))(lVar9,0);
          free(pcVar7);
          iVar4 = *(int *)((long)param_1 + 0xd4);
        }
        break;
      case 0xd:
        __android_log_print(3,"FingerGoodix","EventProcessThread mp test.");
        local_388 = 0;
        uStack_380 = 0;
        local_378 = 0;
        local_370 = 0;
        local_368 = 0;
        (**(code **)(*param_1 + 0x70))(param_1,0xe);
        (**(code **)(lVar9 + 0x138))(lVar9,1);
        (**(code **)(lVar9 + 0x210))(lVar9,2,&local_388);
        (**(code **)(lVar9 + 0x138))(lVar9,0);
        (**(code **)(lVar9 + 0x238))(lVar9);
        if (local_388._4_4_ == 1) {
          __android_log_print(3,"FingerGoodix","service mp_test:performance success.");
          android::notifyClient(0x1773,(int)local_370,0);
        }
        else {
          __android_log_print(3,"FingerGoodix","service mp_test:performance failed.");
          android::notifyClient(0x1773,-1,0);
        }
        (**(code **)(lVar9 + 0x210))(lVar9,6,&local_388);
        if (local_378._4_4_ == 1) {
          __android_log_print(3,"FingerGoodix","service mp_test:pixel_detection success.");
          android::notifyClient(0x1775,1,0);
        }
        else {
          __android_log_print(3,"FingerGoodix","service mp_test:pixel_detection failed.");
          android::notifyClient(0x1775,-1,0);
        }
        (**(code **)(lVar9 + 0x210))(lVar9,3,&local_388);
        android::notifyClient(0x1771,local_368,local_370._4_4_);
        (**(code **)(lVar9 + 0x210))(lVar9,4,&local_388);
        if (uStack_380._4_4_ == 1) {
          __android_log_print(3,"FingerGoodix","service mp_test:scene success.");
          android::notifyClient(0x1772,(int)local_370,0);
        }
        else {
          __android_log_print(3,"FingerGoodix","service mp_test:scene failed.");
          android::notifyClient(0x1772,-1,0);
        }
        android::notifyClient(0x1774,1,0);
        if (*(int *)((long)param_1 + 0xd4) - 0xdU < 2) {
          (**(code **)(lVar9 + 0x180))(lVar9,0);
        }
        else {
          __android_log_print(3,"FingerGoodix","MP Test status changed to %d.\n");
        }
        (**(code **)(*param_1 + 0x70))(param_1,1);
LAB_0011b288:
        iVar4 = *(int *)((long)param_1 + 0xd4);
      }
      __android_log_print(3,"FingerGoodix","EventProcessThread end,then check status %d",iVar4);
      if (((*(uint *)((long)param_1 + 0xd4) & 0xfffffffb) != 2) &&
         (*(uint *)((long)param_1 + 0xd4) != 10)) {
        pthread_mutex_unlock((pthread_mutex_t *)android::ProcessRawDataLock);
        goto LAB_0011b018;
      }
LAB_0011b158:
      pthread_mutex_unlock((pthread_mutex_t *)android::ProcessRawDataLock);
    }
    __android_log_print(3,"FingerGoodix","No need to wait for finer up status 2 : %d\n");
LAB_0011b214:
    (**(code **)(*param_1 + 0x60))(param_1,2);
LAB_0011b228:
    pthread_mutex_unlock((pthread_mutex_t *)android::ProcessRawDataLock);
  } while( true );
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// android::FpService::removeClient(android::sp<android::IFingerPrintClient> const&)

void __thiscall android::FpService::removeClient(FpService *this,sp *param_1)

{
  pthread_mutex_t *__mutex;
  long *plVar1;
  long *plVar2;
  long **pplVar3;
  int iVar4;
  long *local_30;
  long *local_28;
  long *local_20;
  long *local_18;
  long *local_10;
  long local_8;
  
  pplVar3 = (long **)(this + 0x20);
  local_8 = ___stack_chk_guard;
  __mutex = (pthread_mutex_t *)(this + 0x1a0);
  __android_log_print(3,"FingerGoodix","FingerPrintService::removeClient,pid=%d",0x7b);
  iVar4 = 0;
  do {
    local_30 = (long *)0x0;
                    // try { // try from 0011c2f8 to 0011c2fb has its CatchHandler @ 0011c4cc
    pthread_mutex_lock(__mutex);
    if (*pplVar3 == (long *)0x0) {
                    // try { // try from 0011c31c to 0011c31f has its CatchHandler @ 0011c4c4
      __android_log_print(3,"FingerGoodix","mClient[%d] is unused",iVar4);
LAB_0011c320:
      pthread_mutex_unlock(__mutex);
      if (local_30 != (long *)0x0) {
        android::RefBase::decStrong((void *)((long)local_30 + *(long *)(*local_30 + -0x18)));
      }
    }
    else {
                    // try { // try from 0011c1d4 to 0011c203 has its CatchHandler @ 0011c4c4
      sp<>::operator=((sp<> *)&local_30,(sp *)pplVar3);
      if (local_30 == (long *)0x0) {
        plVar2 = *pplVar3;
        if (plVar2 != (long *)0x0) {
                    // try { // try from 0011c3a0 to 0011c3ff has its CatchHandler @ 0011c4c4
          android::RefBase::decStrong((void *)((long)plVar2 + *(long *)(*plVar2 + -0x18)));
          *pplVar3 = (long *)0x0;
        }
        __android_log_print(3,"FingerGoodix","mClient[%d] is null",iVar4);
        goto LAB_0011c320;
      }
      local_28 = *(long **)param_1;
      if (local_28 != (long *)0x0) {
        android::RefBase::incStrong((void *)((long)local_28 + *(long *)(*local_28 + -0x18)));
      }
                    // try { // try from 0011c20c to 0011c20f has its CatchHandler @ 0011c4bc
      android::IInterface::asBinder((sp *)&local_28);
      local_18 = (long *)local_30[8];
      if (local_18 != (long *)0x0) {
                    // try { // try from 0011c230 to 0011c233 has its CatchHandler @ 0011c4b4
        android::RefBase::incStrong((void *)((long)local_18 + *(long *)(*local_18 + -0x18)));
      }
                    // try { // try from 0011c23c to 0011c23f has its CatchHandler @ 0011c430
      android::IInterface::asBinder((sp *)&local_18);
      plVar1 = local_10;
      plVar2 = local_20;
      if (local_10 != (long *)0x0) {
        android::RefBase::decStrong((void *)((long)local_10 + *(long *)(*local_10 + -0x18)));
      }
      if (local_18 != (long *)0x0) {
        android::RefBase::decStrong((void *)((long)local_18 + *(long *)(*local_18 + -0x18)));
      }
      if (local_20 != (long *)0x0) {
        android::RefBase::decStrong((void *)((long)local_20 + *(long *)(*local_20 + -0x18)));
      }
      if (local_28 != (long *)0x0) {
        android::RefBase::decStrong((void *)((long)local_28 + *(long *)(*local_28 + -0x18)));
      }
      if (plVar2 == plVar1) {
        __android_log_print(3,"FingerGoodix","found fingerprint client,remove it now");
        plVar2 = *(long **)(this + (long)iVar4 * 8 + 0x20);
        if (plVar2 != (long *)0x0) {
          android::RefBase::decStrong((void *)((long)plVar2 + *(long *)(*plVar2 + -0x18)));
          *(undefined8 *)(this + (long)iVar4 * 8 + 0x20) = 0;
        }
        pthread_mutex_unlock(__mutex);
        if (local_30 != (long *)0x0) {
          android::RefBase::decStrong((void *)((long)local_30 + *(long *)(*local_30 + -0x18)));
        }
        goto LAB_0011c354;
      }
      pthread_mutex_unlock(__mutex);
      if (local_30 != (long *)0x0) {
        android::RefBase::decStrong((void *)((long)local_30 + *(long *)(*local_30 + -0x18)));
      }
    }
    pplVar3 = pplVar3 + 1;
    iVar4 = iVar4 + 1;
    if (iVar4 == 7) {
LAB_0011c354:
      if (local_8 == ___stack_chk_guard) {
        return;
      }
                    // WARNING: Subroutine does not return
      __stack_chk_fail();
    }
  } while( true );
}



// android::sp<android::FpService>::TEMPNAMEPLACEHOLDERVALUE(android::sp<android::FpService> const&)

sp<> * __thiscall android::sp<>::operator=(sp<> *this,sp *param_1)

{
  long *plVar1;
  long *plVar2;
  
  plVar2 = *(long **)param_1;
  if (plVar2 != (long *)0x0) {
    android::RefBase::incStrong((void *)((long)plVar2 + *(long *)(*plVar2 + -0x18)));
  }
  plVar1 = *(long **)this;
  if (plVar1 != (long *)0x0) {
    android::RefBase::decStrong((void *)((long)plVar1 + *(long *)(*plVar1 + -0x18)));
  }
  *(long **)this = plVar2;
  return this;
}



// android::sp<android::IFingerPrintClient>::TEMPNAMEPLACEHOLDERVALUE(android::sp<android::IFingerPrintClient>
// const&)

sp<> * __thiscall android::sp<>::operator=(sp<> *this,sp *param_1)

{
  long *plVar1;
  long *plVar2;
  
  plVar2 = *(long **)param_1;
  if (plVar2 != (long *)0x0) {
    android::RefBase::incStrong((void *)((long)plVar2 + *(long *)(*plVar2 + -0x18)));
  }
  plVar1 = *(long **)this;
  if (plVar1 != (long *)0x0) {
    android::RefBase::decStrong((void *)((long)plVar1 + *(long *)(*plVar1 + -0x18)));
  }
  *(long **)this = plVar2;
  return this;
}



// android::FpService::Client::Client(android::sp<android::FpService> const&,
// android::sp<android::IFingerPrintClient> const&, android::fpContext, int, int)

void __thiscall
android::FpService::Client::Client
          (Client *this,sp *param_1,sp *param_2,fpContext param_3,int param_4,int param_5)

{
  long lVar1;
  int in_w6;
  undefined4 in_w7;
  
  IFingerPrint::IFingerPrint((IFingerPrint *)this);
                    // try { // try from 0011c5dc to 0011c5df has its CatchHandler @ 0011c6f4
  android::BBinder::BBinder((BBinder *)(this + 8));
  lVar1 = *(long *)(param_1 + 0x10);
  *(long *)this = lVar1;
  *(undefined8 *)(this + *(long *)(lVar1 + -0x18)) = *(undefined8 *)(param_1 + 0x58);
  *(undefined8 *)(this + 8) = *(undefined8 *)(param_1 + 0x60);
  lVar1 = *(long *)(param_1 + 8);
  *(long *)this = lVar1;
  *(undefined8 *)(this + *(long *)(lVar1 + -0x18)) = *(undefined8 *)(param_1 + 0x68);
  *(undefined8 *)(this + 8) = *(undefined8 *)(param_1 + 0x70);
  lVar1 = *(long *)param_1;
  *(long *)this = lVar1;
  *(undefined8 *)(this + *(long *)(lVar1 + -0x18)) = *(undefined8 *)(param_1 + 0x78);
  *(undefined8 *)(this + 8) = *(undefined8 *)(param_1 + 0x80);
  *(undefined8 *)(this + 0x38) = 0;
  *(undefined8 *)(this + 0x40) = 0;
                    // try { // try from 0011c648 to 0011c64b has its CatchHandler @ 0011c77c
  pthread_mutex_init((pthread_mutex_t *)(this + 0x50),(pthread_mutexattr_t *)0x0);
                    // try { // try from 0011c658 to 0011c65b has its CatchHandler @ 0011c76c
  pthread_mutex_init((pthread_mutex_t *)(this + 0x78),(pthread_mutexattr_t *)0x0);
                    // try { // try from 0011c67c to 0011c6d7 has its CatchHandler @ 0011c70c
  __android_log_print(3,"FingerGoodix",
                      "FingerPrintService client(class:FingerPrint) is constructing,clientID = %d",
                      in_w6);
  sp<>::operator=((sp<> *)(this + 0x38),param_2);
  sp<>::operator=((sp<> *)(this + 0x40),(sp *)(ulong)param_3);
  *(ulong *)(this + 0x20) = (ulong)(uint)param_4;
  *(ulong *)(this + 0x28) = (ulong)(uint)param_5;
  *(undefined4 *)(this + 0x4c) = in_w7;
  this[0x30] = (Client)0x0;
  *(int *)(this + 0x48) = in_w6;
  setFingerPrintBusy(*(FpService **)(this + 0x38),in_w6);
  __android_log_print(3,"FingerGoodix","Set finger print busy flag in client construct");
  return;
}



// android::FpService::Client::Client(android::sp<android::FpService> const&,
// android::sp<android::IFingerPrintClient> const&, android::fpContext, int, int)

void __thiscall
android::FpService::Client::Client
          (Client *this,sp *param_1,sp *param_2,fpContext param_3,int param_4,int param_5)

{
  undefined4 in_w6;
  
  android::RefBase::RefBase((RefBase *)(this + 0xa0));
                    // try { // try from 0011c7e0 to 0011c7e3 has its CatchHandler @ 0011c8d4
  IFingerPrint::IFingerPrint((IFingerPrint *)this);
                    // try { // try from 0011c7f0 to 0011c7f3 has its CatchHandler @ 0011c968
  android::BBinder::BBinder((BBinder *)(this + 8));
  *(undefined8 *)(this + 0x38) = 0;
  *(undefined8 *)this = 0x15f168;
  *(undefined8 *)(this + 0xa0) = 0x15f3d0;
  *(undefined8 *)(this + 8) = 0x15f310;
  *(undefined8 *)(this + 0x40) = 0;
                    // try { // try from 0011c828 to 0011c82b has its CatchHandler @ 0011c958
  pthread_mutex_init((pthread_mutex_t *)(this + 0x50),(pthread_mutexattr_t *)0x0);
                    // try { // try from 0011c838 to 0011c83b has its CatchHandler @ 0011c948
  pthread_mutex_init((pthread_mutex_t *)(this + 0x78),(pthread_mutexattr_t *)0x0);
                    // try { // try from 0011c85c to 0011c8b7 has its CatchHandler @ 0011c8e8
  __android_log_print(3,"FingerGoodix",
                      "FingerPrintService client(class:FingerPrint) is constructing,clientID = %d",
                      param_5);
  sp<>::operator=((sp<> *)(this + 0x38),param_1);
  sp<>::operator=((sp<> *)(this + 0x40),param_2);
  *(ulong *)(this + 0x20) = (ulong)param_3;
  *(ulong *)(this + 0x28) = (ulong)(uint)param_4;
  *(undefined4 *)(this + 0x4c) = in_w6;
  this[0x30] = (Client)0x0;
  *(int *)(this + 0x48) = param_5;
  setFingerPrintBusy(*(FpService **)(this + 0x38),param_5);
  __android_log_print(3,"FingerGoodix","Set finger print busy flag in client construct");
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// android::FpService::connect(android::sp<android::IFingerPrintClient> const&, int)

void __thiscall android::FpService::connect(FpService *this,sp *param_1,int param_2)

{
  long *plVar1;
  undefined8 uVar2;
  undefined8 uVar3;
  long **in_x8;
  long lVar4;
  FpService *pFVar5;
  long *local_58;
  long *local_50;
  long *local_48;
  long *local_40;
  long *local_38;
  long *local_30;
  long *local_28;
  long *local_20;
  long *local_18;
  long *local_10;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","finger print service is connecting,client id is %d,pid = %d"
                      ,param_2,0x7b);
  local_58 = (long *)0x0;
  if (*(int *)(this + 0x74) == param_2) {
    param_2 = 0;
    lVar4 = 0;
    pFVar5 = this;
    if (*(long *)(this + 0x20) == 0) goto LAB_0011cca8;
LAB_0011ca08:
                    // try { // try from 0011ca1c to 0011ca4f has its CatchHandler @ 0011cfd4
    sp<>::operator=((sp<> *)&local_58,(sp *)(this + (lVar4 + 4) * 8));
    if (local_58 == (long *)0x0) {
      plVar1 = *(long **)(pFVar5 + 0x20);
      if (plVar1 != (long *)0x0) {
        android::RefBase::decStrong((void *)((long)plVar1 + *(long *)(*plVar1 + -0x18)));
        *(undefined8 *)(pFVar5 + 0x20) = 0;
      }
      __android_log_print(3,"FingerGoodix","FingerPrintService::connect client is unused.");
LAB_0011cb3c:
      local_30 = *(long **)param_1;
      if (local_30 != (long *)0x0) {
        android::RefBase::incStrong((void *)((long)local_30 + *(long *)(*local_30 + -0x18)));
      }
                    // try { // try from 0011cb74 to 0011cb77 has its CatchHandler @ 0011cf3c
      android::IInterface::asBinder((sp *)&local_30);
      local_20 = (long *)local_58[8];
      if (local_20 != (long *)0x0) {
                    // try { // try from 0011cb9c to 0011cb9f has its CatchHandler @ 0011ceec
        android::RefBase::incStrong((void *)((long)local_20 + *(long *)(*local_20 + -0x18)));
      }
                    // try { // try from 0011cbb0 to 0011cbb3 has its CatchHandler @ 0011cf84
      android::IInterface::asBinder((sp *)&local_20);
      plVar1 = local_28;
      if (local_18 != (long *)0x0) {
        android::RefBase::decStrong((void *)((long)local_18 + *(long *)(*local_18 + -0x18)));
      }
      if (local_20 != (long *)0x0) {
        android::RefBase::decStrong((void *)((long)local_20 + *(long *)(*local_20 + -0x18)));
      }
      if (local_28 != (long *)0x0) {
        android::RefBase::decStrong((void *)((long)local_28 + *(long *)(*local_28 + -0x18)));
      }
      if (local_30 != (long *)0x0) {
        android::RefBase::decStrong((void *)((long)local_30 + *(long *)(*local_30 + -0x18)));
      }
      if (plVar1 != local_18) {
        if (*(int *)(this + lVar4 * 4 + 0x58) != 0) {
                    // try { // try from 0011cc54 to 0011ccb3 has its CatchHandler @ 0011cfd4
          __android_log_print(6,"FingerGoodix",
                              "FingerPrintService::connect client is busy, disconnect it and reset busy flag."
                             );
          (**(code **)(*local_58 + 0x28))(local_58);
          if (local_58 != (long *)0x0) {
            android::RefBase::decStrong((Client *)((long)local_58 + *(long *)(*local_58 + -0x18)));
          }
          local_58 = (long *)0x0;
          *(undefined4 *)(this + lVar4 * 4 + 0x58) = 0;
        }
        __android_log_print(3,"FingerGoodix",
                            "FingerPrintService::connect X(pid %d),client is exist. but not same",
                            0x7b);
        goto LAB_0011cca8;
      }
    }
    else {
      local_50 = *(long **)param_1;
      if (local_50 != (long *)0x0) {
        android::RefBase::incStrong((void *)((long)local_50 + *(long *)(*local_50 + -0x18)));
      }
                    // try { // try from 0011ca60 to 0011ca63 has its CatchHandler @ 0011cfa8
      android::IInterface::asBinder((sp *)&local_50);
      local_40 = (long *)local_58[8];
      if (local_40 != (long *)0x0) {
                    // try { // try from 0011ca88 to 0011ca8b has its CatchHandler @ 0011cf44
        android::RefBase::incStrong((void *)((long)local_40 + *(long *)(*local_40 + -0x18)));
      }
                    // try { // try from 0011ca9c to 0011ca9f has its CatchHandler @ 0011cfb0
      android::IInterface::asBinder((sp *)&local_40);
      plVar1 = local_48;
      if (local_38 != (long *)0x0) {
        android::RefBase::decStrong((void *)((long)local_38 + *(long *)(*local_38 + -0x18)));
      }
      if (local_40 != (long *)0x0) {
        android::RefBase::decStrong((void *)((long)local_40 + *(long *)(*local_40 + -0x18)));
      }
      if (local_48 != (long *)0x0) {
        android::RefBase::decStrong((void *)((long)local_48 + *(long *)(*local_48 + -0x18)));
      }
      if (local_50 != (long *)0x0) {
        android::RefBase::decStrong((void *)((long)local_50 + *(long *)(*local_50 + -0x18)));
      }
      if (plVar1 != local_38) {
                    // try { // try from 0011cb38 to 0011cb63 has its CatchHandler @ 0011cfd4
        __android_log_print(3,"FingerGoodix",
                            "FingerPrintService::connect X(pid %d),client is exist.",0x7b);
        goto LAB_0011cb3c;
      }
    }
    __android_log_print(3,"FingerGoodix","FingerPrintService::connect X(pid %d) the same client",
                        0x7b);
    *in_x8 = local_58;
    if (local_58 == (long *)0x0) goto LAB_0011cda4;
    android::RefBase::incStrong((Client *)((long)local_58 + *(long *)(*local_58 + -0x18)));
  }
  else if ((uint)param_2 < 7) {
    lVar4 = (long)param_2;
    pFVar5 = this + lVar4 * 8;
    if (*(long *)(this + lVar4 * 8 + 0x20) != 0) goto LAB_0011ca08;
LAB_0011cca8:
    pthread_mutex_lock((pthread_mutex_t *)(this + 0x1a0));
    local_10 = (long *)this;
                    // try { // try from 0011cccc to 0011cccf has its CatchHandler @ 0011cf34
    android::RefBase::incStrong(this + *(long *)(*(long *)this + -0x18));
    uVar2 = *(undefined8 *)(this + 0x140);
    uVar3 = *(undefined8 *)(this + 0x148);
                    // try { // try from 0011cce0 to 0011cce3 has its CatchHandler @ 0011cf2c
    plVar1 = (long *)operator_new(0xb0);
                    // try { // try from 0011ccfc to 0011ccff has its CatchHandler @ 0011ce98
    Client::Client((Client *)plVar1,(sp *)&local_10,param_1,(fpContext)uVar2,(int)uVar3,param_2);
                    // try { // try from 0011cd10 to 0011cd2f has its CatchHandler @ 0011cf2c
    android::RefBase::incStrong((Client *)((long)plVar1 + *(long *)(*plVar1 + -0x18)));
    if (local_58 != (long *)0x0) {
      android::RefBase::decStrong((Client *)((long)local_58 + *(long *)(*local_58 + -0x18)));
    }
    local_58 = plVar1;
    if (local_10 != (long *)0x0) {
      android::RefBase::decStrong((FpService *)((long)local_10 + *(long *)(*local_10 + -0x18)));
    }
                    // try { // try from 0011cd5c to 0011cd7f has its CatchHandler @ 0011cf34
    sp<>::operator=((sp<> *)(this + (lVar4 + 4) * 8),(sp *)&local_58);
    *in_x8 = local_58;
    if (local_58 != (long *)0x0) {
      android::RefBase::incStrong((Client *)((long)local_58 + *(long *)(*local_58 + -0x18)));
    }
    pthread_mutex_unlock((pthread_mutex_t *)(this + 0x1a0));
  }
  else {
                    // try { // try from 0011cdf0 to 0011ce8f has its CatchHandler @ 0011cfd4
    __android_log_print(6,"FingerGoodix","Warning: Invalid clientId:%d",param_2);
    *in_x8 = (long *)0x0;
  }
  if (local_58 != (long *)0x0) {
    android::RefBase::decStrong((Client *)((long)local_58 + *(long *)(*local_58 + -0x18)));
  }
LAB_0011cda4:
  if (local_8 != ___stack_chk_guard) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail();
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// android::FpService::Client::connect(android::sp<android::IFingerPrintClient> const&)

void __thiscall android::FpService::Client::connect(Client *this,sp *param_1)

{
  long *plVar1;
  int iVar2;
  undefined8 uVar3;
  long *local_28;
  long *local_20;
  long *local_18;
  long *local_10;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","Client::connect (pid %d)",0x7b);
  pthread_mutex_lock((pthread_mutex_t *)(this + 0x78));
                    // try { // try from 0011d040 to 0011d043 has its CatchHandler @ 0011d204
  pthread_mutex_lock((pthread_mutex_t *)(this + 0x50));
  if ((*(int *)(this + 0x4c) != 0) && (iVar2 = checkPid(this), iVar2 != 0)) {
    __android_log_print(3,"FingerGoodix","Tried to connect to a locked fp (old pid %d, new pid %d)",
                        *(undefined4 *)(this + 0x4c),0x7b);
    uVar3 = 0x10;
    goto LAB_0011d15c;
  }
  if (*(long *)(this + 0x40) == 0) {
LAB_0011d1a0:
    *(undefined4 *)(this + 0x4c) = 0x7b;
                    // try { // try from 0011d1b0 to 0011d1f7 has its CatchHandler @ 0011d294
    sp<>::operator=((sp<> *)(this + 0x40),param_1);
    __android_log_print(3,"FingerGoodix","Client::connect X (pid %d)",0x7b);
  }
  else {
    local_28 = *(long **)param_1;
    if (local_28 != (long *)0x0) {
                    // try { // try from 0011d074 to 0011d077 has its CatchHandler @ 0011d28c
      android::RefBase::incStrong((void *)((long)local_28 + *(long *)(*local_28 + -0x18)));
    }
                    // try { // try from 0011d088 to 0011d08b has its CatchHandler @ 0011d284
    android::IInterface::asBinder((sp *)&local_28);
    local_18 = *(long **)(this + 0x40);
    if (local_18 != (long *)0x0) {
                    // try { // try from 0011d0ac to 0011d0af has its CatchHandler @ 0011d27c
      android::RefBase::incStrong((void *)((long)local_18 + *(long *)(*local_18 + -0x18)));
    }
                    // try { // try from 0011d0bc to 0011d0bf has its CatchHandler @ 0011d218
    android::IInterface::asBinder((sp *)&local_18);
    plVar1 = local_20;
    if (local_10 != (long *)0x0) {
      android::RefBase::decStrong((void *)((long)local_10 + *(long *)(*local_10 + -0x18)));
    }
    if (local_18 != (long *)0x0) {
      android::RefBase::decStrong((void *)((long)local_18 + *(long *)(*local_18 + -0x18)));
    }
    if (local_20 != (long *)0x0) {
      android::RefBase::decStrong((void *)((long)local_20 + *(long *)(*local_20 + -0x18)));
    }
    if (local_28 != (long *)0x0) {
      android::RefBase::decStrong((void *)((long)local_28 + *(long *)(*local_28 + -0x18)));
    }
    if (plVar1 != local_10) goto LAB_0011d1a0;
                    // try { // try from 0011d154 to 0011d157 has its CatchHandler @ 0011d294
    __android_log_print(3,"FingerGoodix","Client::Connect to the same client");
  }
  uVar3 = 0;
LAB_0011d15c:
  pthread_mutex_unlock((pthread_mutex_t *)(this + 0x50));
  pthread_mutex_unlock((pthread_mutex_t *)(this + 0x78));
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar3);
}



// android::IFingerPrint::getInterfaceDescriptor() const

undefined8 * android::IFingerPrint::getInterfaceDescriptor(void)

{
  return &descriptor;
}



// android::BpInterface<android::IFingerPrint>::onAsBinder()

undefined8 __thiscall android::BpInterface<>::onAsBinder(BpInterface<> *this)

{
  return *(undefined8 *)(this + 0x10);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// BpFingerPrint::gfCmdM(int, unsigned char*, int, unsigned char*, int, int*)

void __thiscall
BpFingerPrint::gfCmdM
          (BpFingerPrint *this,int param_1,uchar *param_2,int param_3,uchar *param_4,int param_5,
          int *param_6)

{
  undefined4 uVar1;
  int iVar2;
  Parcel aPStack_d8 [104];
  Parcel aPStack_70 [104];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","client, gfCmdM");
  android::Parcel::Parcel(aPStack_d8);
                    // try { // try from 0011d320 to 0011d323 has its CatchHandler @ 0011d490
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011d328 to 0011d46b has its CatchHandler @ 0011d474
  android::IFingerPrint::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  iVar2 = (int)aPStack_d8;
  android::Parcel::writeInt32(iVar2);
  android::Parcel::writeInt32(iVar2);
  android::Parcel::writeInt32(iVar2);
  if (0 < param_3) {
    android::Parcel::write(aPStack_d8,(ulong)param_2);
  }
  (**(code **)(**(long **)(this + 0x10) + 0x28))
            (*(long **)(this + 0x10),0x26,aPStack_d8,aPStack_70,0);
  uVar1 = android::Parcel::readInt32();
  iVar2 = android::Parcel::readInt32();
  *param_6 = iVar2;
  if (iVar2 < 1) {
    __android_log_print(3,"FingerGoodix","client, no rsp data.");
  }
  else if ((param_5 < iVar2) || (param_4 == (uchar *)0x0)) {
    __android_log_print(6,"FingerGoodix",
                        "client, get rsp data failed! rsp_buf=%p, rsp_buf_len=%d, rsp_data_len=%d",
                        param_4,param_5,iVar2);
  }
  else {
    android::Parcel::read(aPStack_70,(ulong)param_4);
    __android_log_print(3,"FingerGoodix","client, get rsp data OK. rsp_data_len=%d",iVar2);
  }
  android::Parcel::~Parcel(aPStack_70);
  android::Parcel::~Parcel(aPStack_d8);
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar1);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// BpFingerPrint::setRecFlag(unsigned int)

void BpFingerPrint::setRecFlag(uint param_1)

{
  undefined4 uVar1;
  Parcel aPStack_d8 [104];
  Parcel aPStack_70 [104];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","client, %s",
                      "virtual android::status_t BpFingerPrint::setRecFlag(uint32_t)");
  android::Parcel::Parcel(aPStack_d8);
                    // try { // try from 0011d4f8 to 0011d4fb has its CatchHandler @ 0011d5a8
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011d500 to 0011d547 has its CatchHandler @ 0011d58c
  android::IFingerPrint::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  android::Parcel::writeInt32((int)aPStack_d8);
  (**(code **)(**(long **)((ulong)param_1 + 0x10) + 0x28))
            (*(long **)((ulong)param_1 + 0x10),0x1f,aPStack_d8,aPStack_70,0);
  uVar1 = android::Parcel::readInt32();
  android::Parcel::~Parcel(aPStack_70);
  android::Parcel::~Parcel(aPStack_d8);
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar1);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// BpFingerPrint::setSafeClass(unsigned int)

void BpFingerPrint::setSafeClass(uint param_1)

{
  undefined4 uVar1;
  Parcel aPStack_d8 [104];
  Parcel aPStack_70 [104];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","client,setSafeClass");
  android::Parcel::Parcel(aPStack_d8);
                    // try { // try from 0011d608 to 0011d60b has its CatchHandler @ 0011d6b8
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011d610 to 0011d657 has its CatchHandler @ 0011d69c
  android::IFingerPrint::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  android::Parcel::writeInt32((int)aPStack_d8);
  (**(code **)(**(long **)((ulong)param_1 + 0x10) + 0x28))
            (*(long **)((ulong)param_1 + 0x10),0x22,aPStack_d8,aPStack_70,0);
  uVar1 = android::Parcel::readInt32();
  android::Parcel::~Parcel(aPStack_70);
  android::Parcel::~Parcel(aPStack_d8);
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar1);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// BpFingerPrint::disableFingerScreenUnlock()

void __thiscall BpFingerPrint::disableFingerScreenUnlock(BpFingerPrint *this)

{
  undefined4 uVar1;
  Parcel aPStack_d8 [104];
  Parcel aPStack_70 [104];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","client,disableFingerScreenUnlock");
  android::Parcel::Parcel(aPStack_d8);
                    // try { // try from 0011d710 to 0011d713 has its CatchHandler @ 0011d7b0
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011d718 to 0011d753 has its CatchHandler @ 0011d794
  android::IFingerPrint::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  (**(code **)(**(long **)(this + 0x10) + 0x28))
            (*(long **)(this + 0x10),0x1e,aPStack_d8,aPStack_70,0);
  uVar1 = android::Parcel::readInt32();
  android::Parcel::~Parcel(aPStack_70);
  android::Parcel::~Parcel(aPStack_d8);
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar1);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// BpFingerPrint::enableFingerScreenUnlock()

void __thiscall BpFingerPrint::enableFingerScreenUnlock(BpFingerPrint *this)

{
  undefined4 uVar1;
  Parcel aPStack_d8 [104];
  Parcel aPStack_70 [104];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","client,enableFingerScreenUnlock");
  android::Parcel::Parcel(aPStack_d8);
                    // try { // try from 0011d808 to 0011d80b has its CatchHandler @ 0011d8a8
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011d810 to 0011d84b has its CatchHandler @ 0011d88c
  android::IFingerPrint::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  (**(code **)(**(long **)(this + 0x10) + 0x28))
            (*(long **)(this + 0x10),0x1d,aPStack_d8,aPStack_70,0);
  uVar1 = android::Parcel::readInt32();
  android::Parcel::~Parcel(aPStack_70);
  android::Parcel::~Parcel(aPStack_d8);
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar1);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// BpFingerPrint::alipayTzInvokeCommand(unsigned int, void*, unsigned int, void*, unsigned int*)

void __thiscall
BpFingerPrint::alipayTzInvokeCommand
          (BpFingerPrint *this,uint param_1,void *param_2,uint param_3,void *param_4,uint *param_5)

{
  int iVar1;
  undefined4 uVar2;
  uint uVar3;
  Parcel aPStack_d8 [104];
  Parcel aPStack_70 [104];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","client,alipayTzInvokeCommand");
  android::Parcel::Parcel(aPStack_d8);
                    // try { // try from 0011d920 to 0011d923 has its CatchHandler @ 0011da10
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011d928 to 0011d9ab has its CatchHandler @ 0011d9f4
  android::IFingerPrint::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  iVar1 = (int)aPStack_d8;
  android::Parcel::writeInt32(iVar1);
  android::Parcel::writeInt32(iVar1);
  android::Parcel::write(aPStack_d8,(ulong)param_2);
  (**(code **)(**(long **)(this + 0x10) + 0x28))
            (*(long **)(this + 0x10),0x1b,aPStack_d8,aPStack_70,0);
  uVar2 = android::Parcel::readInt32();
  uVar3 = android::Parcel::readInt32();
  *param_5 = uVar3;
  android::Parcel::read(aPStack_70,(ulong)param_4);
  android::Parcel::~Parcel(aPStack_70);
  android::Parcel::~Parcel(aPStack_d8);
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar2);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// BpFingerPrint::fillAuthTokenHmac(hw_auth_token_t*)

void __thiscall BpFingerPrint::fillAuthTokenHmac(BpFingerPrint *this,hw_auth_token_t *param_1)

{
  undefined4 uVar1;
  int iVar2;
  Parcel aPStack_d8 [104];
  Parcel aPStack_70 [104];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","client, fillAuthTokenHmac");
  android::Parcel::Parcel(aPStack_d8);
                    // try { // try from 0011da70 to 0011da73 has its CatchHandler @ 0011db7c
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011da78 to 0011db57 has its CatchHandler @ 0011db60
  android::IFingerPrint::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  android::Parcel::writeInt32((int)aPStack_d8);
  android::Parcel::write(aPStack_d8,(ulong)param_1);
  (**(code **)(**(long **)(this + 0x10) + 0x28))
            (*(long **)(this + 0x10),0x24,aPStack_d8,aPStack_70,0);
  uVar1 = android::Parcel::readInt32();
  iVar2 = android::Parcel::readInt32();
  if (iVar2 == 0x45) {
    android::Parcel::read(aPStack_70,(ulong)param_1);
    __android_log_print(3,"FingerGoodix","client, fillAuthTokenHmac OK!");
  }
  else {
    __android_log_print(3,"FingerGoodix","client, fillAuthTokenHmac fialed!");
  }
  android::Parcel::~Parcel(aPStack_70);
  android::Parcel::~Parcel(aPStack_d8);
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar1);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// BpFingerPrint::setActiveGroup(int)

void BpFingerPrint::setActiveGroup(int param_1)

{
  undefined4 uVar1;
  Parcel aPStack_d8 [104];
  Parcel aPStack_70 [104];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,0,"client, setActiveGroup");
  android::Parcel::Parcel(aPStack_d8);
                    // try { // try from 0011dbd8 to 0011dbdb has its CatchHandler @ 0011dc88
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011dbe0 to 0011dc27 has its CatchHandler @ 0011dc6c
  android::IFingerPrint::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  android::Parcel::writeInt32((int)aPStack_d8);
  (**(code **)(**(long **)((ulong)(uint)param_1 + 0x10) + 0x28))
            (*(long **)((ulong)(uint)param_1 + 0x10),0x23,aPStack_d8,aPStack_70,0);
  uVar1 = android::Parcel::readInt32();
  android::Parcel::~Parcel(aPStack_70);
  android::Parcel::~Parcel(aPStack_d8);
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar1);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// BpFingerPrint::getFpNameById(int, char*)

void __thiscall BpFingerPrint::getFpNameById(BpFingerPrint *this,int param_1,char *param_2)

{
  int iVar1;
  Parcel aPStack_d8 [104];
  Parcel aPStack_70 [104];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","client,getFpNameById,%d",param_1);
  android::Parcel::Parcel(aPStack_d8);
                    // try { // try from 0011dcf4 to 0011dcf7 has its CatchHandler @ 0011dddc
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011dcfc to 0011ddb7 has its CatchHandler @ 0011ddc0
  android::IFingerPrint::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  android::Parcel::writeInt32((int)aPStack_d8);
  (**(code **)(**(long **)(this + 0x10) + 0x28))
            (*(long **)(this + 0x10),0x19,aPStack_d8,aPStack_70,0);
  iVar1 = android::Parcel::readInt32();
  if (iVar1 == 0) {
    if (param_2 != (char *)0x0) {
      iVar1 = android::Parcel::read(aPStack_70,(ulong)param_2);
    }
  }
  else {
    __android_log_print(6,"FingerGoodix","failed to getFpNameId");
  }
  android::Parcel::~Parcel(aPStack_70);
  android::Parcel::~Parcel(aPStack_d8);
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(iVar1);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// BpFingerPrint::driverTest()

void __thiscall BpFingerPrint::driverTest(BpFingerPrint *this)

{
  undefined4 uVar1;
  Parcel aPStack_d8 [104];
  Parcel aPStack_70 [104];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","client,driverTest");
  android::Parcel::Parcel(aPStack_d8);
                    // try { // try from 0011de34 to 0011de37 has its CatchHandler @ 0011ded4
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011de3c to 0011de77 has its CatchHandler @ 0011deb8
  android::IFingerPrint::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  (**(code **)(**(long **)(this + 0x10) + 0x28))
            (*(long **)(this + 0x10),0x17,aPStack_d8,aPStack_70,0);
  uVar1 = android::Parcel::readInt32();
  android::Parcel::~Parcel(aPStack_70);
  android::Parcel::~Parcel(aPStack_d8);
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar1);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// BpFingerPrint::setPauseRegisterState(int)

void BpFingerPrint::setPauseRegisterState(int param_1)

{
  undefined4 uVar1;
  Parcel aPStack_d8 [104];
  Parcel aPStack_70 [104];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","client,setPauseRegisterState");
  android::Parcel::Parcel(aPStack_d8);
                    // try { // try from 0011df34 to 0011df37 has its CatchHandler @ 0011dffc
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011df3c to 0011df9f has its CatchHandler @ 0011dfe0
  android::IFingerPrint::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  android::Parcel::writeInt32((int)aPStack_d8);
  (**(code **)(**(long **)((ulong)(uint)param_1 + 0x10) + 0x28))
            (*(long **)((ulong)(uint)param_1 + 0x10),0x16,aPStack_d8,aPStack_70,0);
  uVar1 = android::Parcel::readInt32();
  __android_log_print(3,"FingerGoodix","setPauseRegisterState,result:%d",uVar1);
  android::Parcel::~Parcel(aPStack_70);
  android::Parcel::~Parcel(aPStack_d8);
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar1);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// BpFingerPrint::getFpTemplateIdList(unsigned int*, unsigned int*)

void __thiscall BpFingerPrint::getFpTemplateIdList(BpFingerPrint *this,uint *param_1,uint *param_2)

{
  int iVar1;
  uint uVar2;
  Parcel aPStack_d8 [104];
  Parcel aPStack_70 [104];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","client,getFpTemplateIdList");
  android::Parcel::Parcel(aPStack_d8);
                    // try { // try from 0011e064 to 0011e067 has its CatchHandler @ 0011e158
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011e06c to 0011e133 has its CatchHandler @ 0011e13c
  android::IFingerPrint::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  (**(code **)(**(long **)(this + 0x10) + 0x28))
            (*(long **)(this + 0x10),0x15,aPStack_d8,aPStack_70,0);
  iVar1 = android::Parcel::readInt32();
  if (iVar1 == 0) {
    uVar2 = android::Parcel::readInt32();
    *param_2 = uVar2;
    android::Parcel::read(aPStack_70,(ulong)param_1);
    __android_log_print(3,"FingerGoodix","pIdList:%d,%d,%d",*param_1,param_1[1],param_1[2]);
  }
  else {
    *param_2 = 0;
  }
  android::Parcel::~Parcel(aPStack_70);
  android::Parcel::~Parcel(aPStack_d8);
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(iVar1);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// BpFingerPrint::delFpTemplates(unsigned int*, unsigned int)

void BpFingerPrint::delFpTemplates(uint *param_1,uint param_2)

{
  undefined4 uVar1;
  Parcel aPStack_d8 [104];
  Parcel aPStack_70 [104];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","client,delFpTemplates");
  android::Parcel::Parcel(aPStack_d8);
                    // try { // try from 0011e1bc to 0011e1bf has its CatchHandler @ 0011e27c
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011e1c4 to 0011e21b has its CatchHandler @ 0011e260
  android::IFingerPrint::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  android::Parcel::writeInt32((int)aPStack_d8);
  android::Parcel::write(aPStack_d8,(ulong)param_2);
  (**(code **)(**(long **)(param_1 + 4) + 0x28))
            (*(long **)(param_1 + 4),0x14,aPStack_d8,aPStack_70,0);
  uVar1 = android::Parcel::readInt32();
  android::Parcel::~Parcel(aPStack_70);
  android::Parcel::~Parcel(aPStack_d8);
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar1);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// BpFingerPrint::cancelRecognize()

void __thiscall BpFingerPrint::cancelRecognize(BpFingerPrint *this)

{
  undefined4 uVar1;
  Parcel aPStack_d8 [104];
  Parcel aPStack_70 [104];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","client,cancel recognize");
  android::Parcel::Parcel(aPStack_d8);
                    // try { // try from 0011e2d4 to 0011e2d7 has its CatchHandler @ 0011e374
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011e2dc to 0011e317 has its CatchHandler @ 0011e358
  android::IFingerPrint::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  (**(code **)(**(long **)(this + 0x10) + 0x28))
            (*(long **)(this + 0x10),0x11,aPStack_d8,aPStack_70,0);
  uVar1 = android::Parcel::readInt32();
  android::Parcel::~Parcel(aPStack_70);
  android::Parcel::~Parcel(aPStack_d8);
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar1);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// BpFingerPrint::recognizeFido(unsigned char*, int, unsigned char*, int)

void BpFingerPrint::recognizeFido(uchar *param_1,int param_2,uchar *param_3,int param_4)

{
  int iVar1;
  undefined4 uVar2;
  Parcel aPStack_d8 [104];
  Parcel aPStack_70 [104];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","client,recognize fido");
  android::Parcel::Parcel(aPStack_d8);
                    // try { // try from 0011e3e4 to 0011e3e7 has its CatchHandler @ 0011e4c4
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011e3ec to 0011e45f has its CatchHandler @ 0011e4a8
  android::IFingerPrint::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  iVar1 = (int)aPStack_d8;
  android::Parcel::writeInt32(iVar1);
  android::Parcel::write(aPStack_d8,(ulong)(uint)param_2);
  android::Parcel::writeInt32(iVar1);
  android::Parcel::write(aPStack_d8,(ulong)(uint)param_4);
  (**(code **)(**(long **)(param_1 + 0x10) + 0x28))
            (*(long **)(param_1 + 0x10),0x20,aPStack_d8,aPStack_70,0);
  uVar2 = android::Parcel::readInt32();
  android::Parcel::~Parcel(aPStack_70);
  android::Parcel::~Parcel(aPStack_d8);
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar2);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// BpFingerPrint::recognizeWithRestrict(unsigned int*, unsigned int, unsigned int)

void BpFingerPrint::recognizeWithRestrict(uint *param_1,uint param_2,uint param_3)

{
  long lVar1;
  int iVar2;
  undefined4 uVar3;
  ulong uVar4;
  ulong uVar5;
  Parcel aPStack_d8 [104];
  Parcel aPStack_70 [104];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","client,recognizeWithRestrict");
  __android_log_print(3,"FingerGoodix","arrayLen:%d",param_3);
  if (param_3 != 0) {
    uVar5 = 0;
    do {
      lVar1 = uVar5 * 4;
      uVar4 = uVar5 & 0xffffffff;
      uVar5 = uVar5 + 1;
      __android_log_print(3,"FingerGoodix","array index:%d,value:%d",uVar4,
                          *(undefined4 *)((ulong)param_2 + lVar1));
    } while (uVar5 != (ulong)(param_3 - 1) + 1);
  }
  android::Parcel::Parcel(aPStack_d8);
                    // try { // try from 0011e58c to 0011e58f has its CatchHandler @ 0011e640
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011e594 to 0011e5f7 has its CatchHandler @ 0011e658
  android::IFingerPrint::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  iVar2 = (int)aPStack_d8;
  android::Parcel::writeInt32(iVar2);
  android::Parcel::write(aPStack_d8,(ulong)param_2);
  android::Parcel::writeInt32(iVar2);
  (**(code **)(**(long **)(param_1 + 4) + 0x28))
            (*(long **)(param_1 + 4),0x10,aPStack_d8,aPStack_70,0);
  uVar3 = android::Parcel::readInt32();
  android::Parcel::~Parcel(aPStack_70);
  android::Parcel::~Parcel(aPStack_d8);
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar3);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// BpFingerPrint::recognize()

void __thiscall BpFingerPrint::recognize(BpFingerPrint *this)

{
  undefined4 uVar1;
  Parcel aPStack_d8 [104];
  Parcel aPStack_70 [104];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","client,recognize");
  android::Parcel::Parcel(aPStack_d8);
                    // try { // try from 0011e6b8 to 0011e6bb has its CatchHandler @ 0011e758
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011e6c0 to 0011e6fb has its CatchHandler @ 0011e73c
  android::IFingerPrint::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  (**(code **)(**(long **)(this + 0x10) + 0x28))
            (*(long **)(this + 0x10),0xf,aPStack_d8,aPStack_70,0);
  uVar1 = android::Parcel::readInt32();
  android::Parcel::~Parcel(aPStack_70);
  android::Parcel::~Parcel(aPStack_d8);
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar1);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// BpFingerPrint::saveRegist(int)

void BpFingerPrint::saveRegist(int param_1)

{
  undefined4 uVar1;
  Parcel aPStack_d8 [104];
  Parcel aPStack_70 [104];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","client,save regist");
  android::Parcel::Parcel(aPStack_d8);
                    // try { // try from 0011e7b8 to 0011e7bb has its CatchHandler @ 0011e868
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011e7c0 to 0011e807 has its CatchHandler @ 0011e84c
  android::IFingerPrint::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  android::Parcel::writeInt32((int)aPStack_d8);
  (**(code **)(**(long **)((ulong)(uint)param_1 + 0x10) + 0x28))
            (*(long **)((ulong)(uint)param_1 + 0x10),0xd,aPStack_d8,aPStack_70,0);
  uVar1 = android::Parcel::readInt32();
  android::Parcel::~Parcel(aPStack_70);
  android::Parcel::~Parcel(aPStack_d8);
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar1);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// BpFingerPrint::unRegist(int)

void BpFingerPrint::unRegist(int param_1)

{
  undefined4 uVar1;
  Parcel aPStack_d8 [104];
  Parcel aPStack_70 [104];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","client,unRegist");
  android::Parcel::Parcel(aPStack_d8);
                    // try { // try from 0011e8c8 to 0011e8cb has its CatchHandler @ 0011e978
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011e8d0 to 0011e917 has its CatchHandler @ 0011e95c
  android::IFingerPrint::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  android::Parcel::writeInt32((int)aPStack_d8);
  (**(code **)(**(long **)((ulong)(uint)param_1 + 0x10) + 0x28))
            (*(long **)((ulong)(uint)param_1 + 0x10),0xc,aPStack_d8,aPStack_70,0);
  uVar1 = android::Parcel::readInt32();
  android::Parcel::~Parcel(aPStack_70);
  android::Parcel::~Parcel(aPStack_d8);
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar1);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// BpFingerPrint::resetRegist()

void __thiscall BpFingerPrint::resetRegist(BpFingerPrint *this)

{
  undefined4 uVar1;
  Parcel aPStack_d8 [104];
  Parcel aPStack_70 [104];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","client,reset regist");
  android::Parcel::Parcel(aPStack_d8);
                    // try { // try from 0011e9d0 to 0011e9d3 has its CatchHandler @ 0011ea70
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011e9d8 to 0011ea13 has its CatchHandler @ 0011ea54
  android::IFingerPrint::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  (**(code **)(**(long **)(this + 0x10) + 0x28))
            (*(long **)(this + 0x10),0xb,aPStack_d8,aPStack_70,0);
  uVar1 = android::Parcel::readInt32();
  android::Parcel::~Parcel(aPStack_70);
  android::Parcel::~Parcel(aPStack_d8);
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar1);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// BpFingerPrint::registRollback()

void __thiscall BpFingerPrint::registRollback(BpFingerPrint *this)

{
  undefined4 uVar1;
  Parcel aPStack_d8 [104];
  Parcel aPStack_70 [104];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","client,regist roll back");
  android::Parcel::Parcel(aPStack_d8);
                    // try { // try from 0011eac8 to 0011eacb has its CatchHandler @ 0011eb68
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011ead0 to 0011eb0b has its CatchHandler @ 0011eb4c
  android::IFingerPrint::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  (**(code **)(**(long **)(this + 0x10) + 0x28))(*(long **)(this + 0x10),10,aPStack_d8,aPStack_70,0)
  ;
  uVar1 = android::Parcel::readInt32();
  android::Parcel::~Parcel(aPStack_70);
  android::Parcel::~Parcel(aPStack_d8);
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar1);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// BpFingerPrint::cancelRegist()

void __thiscall BpFingerPrint::cancelRegist(BpFingerPrint *this)

{
  undefined4 uVar1;
  Parcel aPStack_d8 [104];
  Parcel aPStack_70 [104];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","client,cancel regist");
  android::Parcel::Parcel(aPStack_d8);
                    // try { // try from 0011ebc0 to 0011ebc3 has its CatchHandler @ 0011ec60
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011ebc8 to 0011ec03 has its CatchHandler @ 0011ec44
  android::IFingerPrint::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  (**(code **)(**(long **)(this + 0x10) + 0x28))(*(long **)(this + 0x10),9,aPStack_d8,aPStack_70,0);
  uVar1 = android::Parcel::readInt32();
  android::Parcel::~Parcel(aPStack_70);
  android::Parcel::~Parcel(aPStack_d8);
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar1);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// BpFingerPrint::regist()

void __thiscall BpFingerPrint::regist(BpFingerPrint *this)

{
  undefined4 uVar1;
  Parcel aPStack_d8 [104];
  Parcel aPStack_70 [104];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","client,regist");
  android::Parcel::Parcel(aPStack_d8);
                    // try { // try from 0011ecb8 to 0011ecbb has its CatchHandler @ 0011ed58
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011ecc0 to 0011ecfb has its CatchHandler @ 0011ed3c
  android::IFingerPrint::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  (**(code **)(**(long **)(this + 0x10) + 0x28))(*(long **)(this + 0x10),8,aPStack_d8,aPStack_70,0);
  uVar1 = android::Parcel::readInt32();
  android::Parcel::~Parcel(aPStack_70);
  android::Parcel::~Parcel(aPStack_d8);
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar1);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// BpFingerPrint::enroll_verify(hw_auth_token_t*)

void __thiscall BpFingerPrint::enroll_verify(BpFingerPrint *this,hw_auth_token_t *param_1)

{
  undefined4 uVar1;
  Parcel aPStack_d8 [104];
  Parcel aPStack_70 [104];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","client,enroll_verify");
  android::Parcel::Parcel(aPStack_d8);
                    // try { // try from 0011edb8 to 0011edbb has its CatchHandler @ 0011ee78
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011edc0 to 0011ee17 has its CatchHandler @ 0011ee5c
  android::IFingerPrint::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  android::Parcel::writeInt32((int)aPStack_d8);
  android::Parcel::write(aPStack_d8,(ulong)param_1);
  (**(code **)(**(long **)(this + 0x10) + 0x28))
            (*(long **)(this + 0x10),0x25,aPStack_d8,aPStack_70,0);
  uVar1 = android::Parcel::readInt32();
  android::Parcel::~Parcel(aPStack_70);
  android::Parcel::~Parcel(aPStack_d8);
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar1);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// BpFingerPrint::sendScreenState(int)

void BpFingerPrint::sendScreenState(int param_1)

{
  undefined4 uVar1;
  Parcel aPStack_d8 [104];
  Parcel aPStack_70 [104];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","client,sendScreenState");
  android::Parcel::Parcel(aPStack_d8);
                    // try { // try from 0011eed8 to 0011eedb has its CatchHandler @ 0011ef88
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011eee0 to 0011ef27 has its CatchHandler @ 0011ef6c
  android::IFingerPrint::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  android::Parcel::writeInt32((int)aPStack_d8);
  (**(code **)(**(long **)((ulong)(uint)param_1 + 0x10) + 0x28))
            (*(long **)((ulong)(uint)param_1 + 0x10),7,aPStack_d8,aPStack_70,0);
  uVar1 = android::Parcel::readInt32();
  android::Parcel::~Parcel(aPStack_70);
  android::Parcel::~Parcel(aPStack_d8);
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar1);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// BpFingerPrint::query()

void __thiscall BpFingerPrint::query(BpFingerPrint *this)

{
  undefined4 uVar1;
  Parcel aPStack_d8 [104];
  Parcel aPStack_70 [104];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","client,query");
  android::Parcel::Parcel(aPStack_d8);
                    // try { // try from 0011efe0 to 0011efe3 has its CatchHandler @ 0011f080
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011efe8 to 0011f023 has its CatchHandler @ 0011f064
  android::IFingerPrint::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  (**(code **)(**(long **)(this + 0x10) + 0x28))(*(long **)(this + 0x10),5,aPStack_d8,aPStack_70,0);
  uVar1 = android::Parcel::readInt32();
  android::Parcel::~Parcel(aPStack_70);
  android::Parcel::~Parcel(aPStack_d8);
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar1);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// BpFingerPrint::setMode(int)

void BpFingerPrint::setMode(int param_1)

{
  undefined4 uVar1;
  Parcel aPStack_d8 [104];
  Parcel aPStack_70 [104];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","client,setmode.\n");
  android::Parcel::Parcel(aPStack_d8);
                    // try { // try from 0011f0e0 to 0011f0e3 has its CatchHandler @ 0011f190
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011f0e8 to 0011f12f has its CatchHandler @ 0011f174
  android::IFingerPrint::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  android::Parcel::writeInt32((int)aPStack_d8);
  (**(code **)(**(long **)((ulong)(uint)param_1 + 0x10) + 0x28))
            (*(long **)((ulong)(uint)param_1 + 0x10),4,aPStack_d8,aPStack_70,0);
  uVar1 = android::Parcel::readInt32();
  android::Parcel::~Parcel(aPStack_70);
  android::Parcel::~Parcel(aPStack_d8);
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar1);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// BpFingerPrint::disconnect()

void __thiscall BpFingerPrint::disconnect(BpFingerPrint *this)

{
  undefined4 uVar1;
  Parcel aPStack_d8 [104];
  Parcel aPStack_70 [104];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","client,disconnect");
  android::Parcel::Parcel(aPStack_d8);
                    // try { // try from 0011f1e8 to 0011f1eb has its CatchHandler @ 0011f288
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011f1f0 to 0011f22b has its CatchHandler @ 0011f26c
  android::IFingerPrint::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  (**(code **)(**(long **)(this + 0x10) + 0x28))(*(long **)(this + 0x10),2,aPStack_d8,aPStack_70,0);
  uVar1 = android::Parcel::readInt32();
  android::Parcel::~Parcel(aPStack_70);
  android::Parcel::~Parcel(aPStack_d8);
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar1);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// BpFingerPrint::weChatSetSessionId(unsigned long)

void BpFingerPrint::weChatSetSessionId(ulong param_1)

{
  undefined4 uVar1;
  Parcel aPStack_d8 [104];
  Parcel aPStack_70 [104];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","client, %s",
                      "virtual android::status_t BpFingerPrint::weChatSetSessionId(uint64_t)");
  android::Parcel::Parcel(aPStack_d8);
                    // try { // try from 0011f2f4 to 0011f2f7 has its CatchHandler @ 0011f3a4
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011f2fc to 0011f343 has its CatchHandler @ 0011f388
  android::IFingerPrint::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  android::Parcel::writeInt64((long)aPStack_d8);
  (**(code **)(**(long **)(param_1 + 0x10) + 0x28))
            (*(long **)(param_1 + 0x10),0x1c,aPStack_d8,aPStack_70,0);
  uVar1 = android::Parcel::readInt32();
  android::Parcel::~Parcel(aPStack_70);
  android::Parcel::~Parcel(aPStack_d8);
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar1);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// BpFingerPrint::getInfo()

void __thiscall BpFingerPrint::getInfo(BpFingerPrint *this)

{
  undefined8 uVar1;
  Parcel aPStack_d8 [104];
  Parcel aPStack_70 [104];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","client,getInfo");
  android::Parcel::Parcel(aPStack_d8);
                    // try { // try from 0011f3fc to 0011f3ff has its CatchHandler @ 0011f49c
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011f404 to 0011f43f has its CatchHandler @ 0011f480
  android::IFingerPrint::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  (**(code **)(**(long **)(this + 0x10) + 0x28))(*(long **)(this + 0x10),3,aPStack_d8,aPStack_70,0);
  uVar1 = android::Parcel::readCString();
  android::Parcel::~Parcel(aPStack_70);
  android::Parcel::~Parcel(aPStack_d8);
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar1);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// BpFingerPrint::modifyFpName(int, char const*)

void BpFingerPrint::modifyFpName(int param_1,char *param_2)

{
  undefined4 uVar1;
  Parcel aPStack_d8 [104];
  Parcel aPStack_70 [104];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","client,modifyFpName");
  android::Parcel::Parcel(aPStack_d8);
                    // try { // try from 0011f504 to 0011f507 has its CatchHandler @ 0011f5dc
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011f50c to 0011f57b has its CatchHandler @ 0011f5c0
  android::IFingerPrint::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  android::Parcel::writeInt32((int)aPStack_d8);
  android::Parcel::writeCString((char *)aPStack_d8);
  (**(code **)(**(long **)((ulong)(uint)param_1 + 0x10) + 0x28))
            (*(long **)((ulong)(uint)param_1 + 0x10),0x18,aPStack_d8,aPStack_70,0);
  uVar1 = android::Parcel::readInt32();
  __android_log_print(3,"FingerGoodix","modifyFpName,result:%d",uVar1);
  android::Parcel::~Parcel(aPStack_70);
  android::Parcel::~Parcel(aPStack_d8);
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar1);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// BpFingerPrint::checkPasswd(char const*)

void BpFingerPrint::checkPasswd(char *param_1)

{
  undefined4 uVar1;
  Parcel aPStack_d8 [104];
  Parcel aPStack_70 [104];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","client,check passwd");
  android::Parcel::Parcel(aPStack_d8);
                    // try { // try from 0011f63c to 0011f63f has its CatchHandler @ 0011f6ec
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011f644 to 0011f68b has its CatchHandler @ 0011f6d0
  android::IFingerPrint::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  android::Parcel::writeCString((char *)aPStack_d8);
  (**(code **)(**(long **)(param_1 + 0x10) + 0x28))
            (*(long **)(param_1 + 0x10),0x13,aPStack_d8,aPStack_70,0);
  uVar1 = android::Parcel::readInt32();
  android::Parcel::~Parcel(aPStack_70);
  android::Parcel::~Parcel(aPStack_d8);
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar1);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// BpFingerPrint::setPasswd(char const*, char const*)

void BpFingerPrint::setPasswd(char *param_1,char *param_2)

{
  undefined4 uVar1;
  Parcel aPStack_d8 [104];
  Parcel aPStack_70 [104];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","client,set passwd");
  android::Parcel::Parcel(aPStack_d8);
                    // try { // try from 0011f750 to 0011f753 has its CatchHandler @ 0011f80c
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011f758 to 0011f7ab has its CatchHandler @ 0011f7f0
  android::IFingerPrint::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  android::Parcel::writeCString((char *)aPStack_d8);
  android::Parcel::writeCString((char *)aPStack_d8);
  (**(code **)(**(long **)(param_1 + 0x10) + 0x28))
            (*(long **)(param_1 + 0x10),0x12,aPStack_d8,aPStack_70,0);
  uVar1 = android::Parcel::readInt32();
  android::Parcel::~Parcel(aPStack_70);
  android::Parcel::~Parcel(aPStack_d8);
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar1);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// BpFingerPrint::saveRegister(char const*)

void __thiscall BpFingerPrint::saveRegister(BpFingerPrint *this,char *param_1)

{
  undefined4 uVar1;
  Parcel aPStack_d8 [104];
  Parcel aPStack_70 [104];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","client,save register(),name");
  android::Parcel::Parcel(aPStack_d8);
                    // try { // try from 0011f86c to 0011f86f has its CatchHandler @ 0011f950
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011f874 to 0011f92b has its CatchHandler @ 0011f934
  android::IFingerPrint::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  if (param_1 == (char *)0x0) {
    __android_log_print(6,"FingerGoodix","saveRegister name is NULL");
  }
  else {
    android::Parcel::writeCString((char *)aPStack_d8);
    __android_log_print(3,"FingerGoodix","saveRegister name:%s",param_1);
  }
  (**(code **)(**(long **)(this + 0x10) + 0x28))
            (*(long **)(this + 0x10),0xe,aPStack_d8,aPStack_70,0);
  uVar1 = android::Parcel::readInt32();
  android::Parcel::~Parcel(aPStack_70);
  android::Parcel::~Parcel(aPStack_d8);
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar1);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// BpFingerPrint::requestPermission(char const*)

void BpFingerPrint::requestPermission(char *param_1)

{
  undefined4 uVar1;
  Parcel aPStack_d8 [104];
  Parcel aPStack_70 [104];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","client,request permission");
  android::Parcel::Parcel(aPStack_d8);
                    // try { // try from 0011f9b0 to 0011f9b3 has its CatchHandler @ 0011fa60
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011f9b8 to 0011f9ff has its CatchHandler @ 0011fa44
  android::IFingerPrint::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  android::Parcel::writeCString((char *)aPStack_d8);
  (**(code **)(**(long **)(param_1 + 0x10) + 0x28))
            (*(long **)(param_1 + 0x10),6,aPStack_d8,aPStack_70,0);
  uVar1 = android::Parcel::readInt32();
  android::Parcel::~Parcel(aPStack_70);
  android::Parcel::~Parcel(aPStack_d8);
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar1);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// BpFingerPrint::SendCmd(int, char*, int, char**, int*)

void __thiscall
BpFingerPrint::SendCmd
          (BpFingerPrint *this,int param_1,char *param_2,int param_3,char **param_4,int *param_5)

{
  undefined4 uVar1;
  int iVar2;
  char *__ptr;
  Parcel aPStack_d8 [104];
  Parcel aPStack_70 [104];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","client,SendCmd");
  android::Parcel::Parcel(aPStack_d8);
                    // try { // try from 0011fad8 to 0011fadb has its CatchHandler @ 0011fc04
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011fae0 to 0011fb83 has its CatchHandler @ 0011fbe8
  android::IFingerPrint::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  iVar2 = (int)aPStack_d8;
  android::Parcel::writeInt32(iVar2);
  android::Parcel::writeInt32(iVar2);
  if ((param_3 != 0) && (param_2 != (char *)0x0)) {
    android::Parcel::write(aPStack_d8,(ulong)param_2);
  }
  (**(code **)(**(long **)(this + 0x10) + 0x28))
            (*(long **)(this + 0x10),0x21,aPStack_d8,aPStack_70,0);
  uVar1 = android::Parcel::readInt32();
  iVar2 = android::Parcel::readInt32();
  if (iVar2 != 0) {
    __ptr = (char *)malloc((long)iVar2);
    uVar1 = android::Parcel::read(aPStack_70,(ulong)__ptr);
    if (param_5 == (int *)0x0) {
      free(__ptr);
    }
    else {
      *param_4 = __ptr;
    }
  }
  *param_5 = iVar2;
  android::Parcel::~Parcel(aPStack_70);
  android::Parcel::~Parcel(aPStack_d8);
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar1);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// BpFingerPrint::connect(android::sp<android::IFingerPrintClient> const&)

void __thiscall BpFingerPrint::connect(BpFingerPrint *this,sp *param_1)

{
  undefined4 uVar1;
  long *local_e8;
  long *local_e0;
  Parcel aPStack_d8 [104];
  Parcel aPStack_70 [104];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","client,connect");
  android::Parcel::Parcel(aPStack_d8);
                    // try { // try from 0011fc64 to 0011fc67 has its CatchHandler @ 0011fdc8
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011fc6c to 0011fc9f has its CatchHandler @ 0011fdc0
  android::IFingerPrint::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  local_e8 = *(long **)param_1;
  if (local_e8 != (long *)0x0) {
    android::RefBase::incStrong((void *)((long)local_e8 + *(long *)(*local_e8 + -0x18)));
  }
                    // try { // try from 0011fcac to 0011fcaf has its CatchHandler @ 0011fdb8
  android::IInterface::asBinder((sp *)&local_e8);
                    // try { // try from 0011fcb8 to 0011fcbb has its CatchHandler @ 0011fd64
  android::Parcel::writeStrongBinder((sp *)aPStack_d8);
  if (local_e0 != (long *)0x0) {
    android::RefBase::decStrong((void *)((long)local_e0 + *(long *)(*local_e0 + -0x18)));
  }
  if (local_e8 != (long *)0x0) {
    android::RefBase::decStrong((void *)((long)local_e8 + *(long *)(*local_e8 + -0x18)));
  }
                    // try { // try from 0011fd14 to 0011fd1f has its CatchHandler @ 0011fdc0
  (**(code **)(**(long **)(this + 0x10) + 0x28))(*(long **)(this + 0x10),1,aPStack_d8,aPStack_70,0);
  uVar1 = android::Parcel::readInt32();
  android::Parcel::~Parcel(aPStack_70);
  android::Parcel::~Parcel(aPStack_d8);
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar1);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// android::BnFingerPrint::onTransact(unsigned int, android::Parcel const&, android::Parcel*,
// unsigned int)

void android::BnFingerPrint::onTransact(uint param_1,Parcel *param_2,Parcel *param_3,uint param_4)

{
  char cVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  long *plVar7;
  ulong uVar8;
  undefined8 *puVar9;
  undefined8 *puVar10;
  undefined8 uVar11;
  undefined8 uVar12;
  char *pcVar13;
  ulong uVar14;
  code *pcVar15;
  void *pvVar16;
  long lVar17;
  void *pvVar18;
  size_t sVar19;
  undefined4 local_60;
  undefined4 uStack_5c;
  undefined8 local_58;
  void *local_50 [5];
  undefined8 uStack_28;
  undefined8 local_20;
  undefined8 uStack_18;
  undefined4 local_10;
  undefined local_c;
  long local_8;
  
  pcVar13 = (char *)(ulong)param_4;
  plVar7 = (long *)(ulong)param_1;
  local_8 = ___stack_chk_guard;
  switch((int)param_2) {
  case 1:
    uVar2 = 0xffffffff;
    __android_log_print(3,"FingerGoodix","server,connect");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      android::Parcel::readStrongBinder();
                    // try { // try from 00120668 to 0012066b has its CatchHandler @ 00121230
      IFingerPrintClient::asInterface((sp *)&local_58);
      if (local_58 != (long *)0x0) {
        android::RefBase::decStrong((void *)((long)local_58 + *(long *)(*local_58 + -0x18)));
      }
                    // try { // try from 00120698 to 001206a7 has its CatchHandler @ 00121258
      (**(code **)(*plVar7 + 0x20))(plVar7,&local_60);
      uVar2 = android::Parcel::writeInt32(param_4);
      plVar7 = (long *)CONCAT44(uStack_5c,local_60);
      if (plVar7 != (long *)0x0) {
        android::RefBase::decStrong((void *)((long)plVar7 + *(long *)(*plVar7 + -0x18)));
      }
    }
    goto LAB_0011fe20;
  case 2:
    __android_log_print(3,"FingerGoodix","server,disconnect");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      uVar2 = 0;
      (**(code **)(*plVar7 + 0x28))(plVar7);
      android::Parcel::writeInt32(param_4);
      goto LAB_0011fe20;
    }
    break;
  case 3:
    __android_log_print(3,"FingerGoodix","server,get info");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      uVar2 = 0;
      (**(code **)(*plVar7 + 0x30))(plVar7);
      android::Parcel::writeCString(pcVar13);
      goto LAB_0011fe20;
    }
    break;
  case 4:
    __android_log_print(3,"FingerGoodix","server,eng test");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      pcVar15 = *(code **)(*plVar7 + 0x38);
LAB_0012009c:
      uVar2 = 0;
      uVar3 = android::Parcel::readInt32();
      (*pcVar15)(plVar7,uVar3);
      android::Parcel::writeInt32(param_4);
      goto LAB_0011fe20;
    }
    break;
  case 5:
    __android_log_print(3,"FingerGoodix","server,query");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      uVar2 = 0;
      (**(code **)(*plVar7 + 0x48))(plVar7);
      android::Parcel::writeInt32(param_4);
      goto LAB_0011fe20;
    }
    break;
  case 6:
    __android_log_print(3,"FingerGoodix","server,request permission");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      pcVar15 = *(code **)(*plVar7 + 0x50);
LAB_0012028c:
      uVar2 = 0;
      uVar11 = android::Parcel::readCString();
      (*pcVar15)(plVar7,uVar11);
      android::Parcel::writeInt32(param_4);
      goto LAB_0011fe20;
    }
    break;
  case 7:
    __android_log_print(3,"FingerGoodix","server,send screen state");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      pcVar15 = *(code **)(*plVar7 + 0x58);
      goto LAB_0012009c;
    }
    break;
  case 8:
    __android_log_print(3,"FingerGoodix","server,regist");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      uVar2 = 0;
      (**(code **)(*plVar7 + 0x68))(plVar7);
      android::Parcel::writeInt32(param_4);
      goto LAB_0011fe20;
    }
    break;
  case 9:
    __android_log_print(3,"FingerGoodix","server,cancel regist");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      uVar2 = 0;
      (**(code **)(*plVar7 + 0x70))(plVar7);
      android::Parcel::writeInt32(param_4);
      goto LAB_0011fe20;
    }
    break;
  case 10:
    __android_log_print(3,"FingerGoodix","server,regist roll back");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      uVar2 = 0;
      (**(code **)(*plVar7 + 0x78))(plVar7);
      android::Parcel::writeInt32(param_4);
      goto LAB_0011fe20;
    }
    break;
  case 0xb:
    __android_log_print(3,"FingerGoodix","server,reset regist");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      uVar2 = 0;
      (**(code **)(*plVar7 + 0x80))(plVar7);
      android::Parcel::writeInt32(param_4);
      goto LAB_0011fe20;
    }
    break;
  case 0xc:
    __android_log_print(3,"FingerGoodix","server,unRegist");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      pcVar15 = *(code **)(*plVar7 + 0x88);
      goto LAB_0012009c;
    }
    break;
  case 0xd:
    __android_log_print(3,"FingerGoodix","server,save regist");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      pcVar15 = *(code **)(*plVar7 + 0x90);
      goto LAB_0012009c;
    }
    break;
  case 0xe:
    __android_log_print(3,"FingerGoodix","server,save register()");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      pcVar15 = *(code **)(*plVar7 + 0x98);
      goto LAB_0012028c;
    }
    break;
  case 0xf:
    __android_log_print(3,"FingerGoodix","server,recognize");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      uVar2 = 0;
      (**(code **)(*plVar7 + 0xa0))(plVar7);
      android::Parcel::writeInt32(param_4);
      goto LAB_0011fe20;
    }
    break;
  case 0x10:
    __android_log_print(3,"FingerGoodix","server,recognizeWithRestrict");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      uVar6 = android::Parcel::readInt32();
      sVar19 = (ulong)uVar6 << 2;
      __android_log_print(3,"FingerGoodix","server receiver restrict count:%d",uVar6);
      pvVar18 = malloc(sVar19);
      if (pvVar18 == (void *)0x0) {
        uVar2 = 0xffffffff;
        __android_log_print(6,"FingerGoodix",
                            "IFingerPrint TRANSACTION_FP_RECOGNIZE_WITH_RESTRICT out of memory");
        goto LAB_0011fe20;
      }
      memset(pvVar18,0,sVar19);
      android::Parcel::read(param_3,(ulong)pvVar18);
      uVar2 = android::Parcel::readInt32();
      (**(code **)(*plVar7 + 0xa8))(plVar7,pvVar18,(ulong)uVar6,uVar2);
LAB_00120e40:
      uVar2 = 0;
      android::Parcel::writeInt32(param_4);
      free(pvVar18);
      goto LAB_0011fe20;
    }
    break;
  case 0x11:
    __android_log_print(3,"FingerGoodix","server,cancel recognize");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      uVar2 = 0;
      (**(code **)(*plVar7 + 0xb8))(plVar7);
      android::Parcel::writeInt32(param_4);
      goto LAB_0011fe20;
    }
    break;
  case 0x12:
    __android_log_print(3,"FingerGoodix","server,set passwd");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      uVar2 = 0;
      uVar11 = android::Parcel::readCString();
      uVar12 = android::Parcel::readCString();
      (**(code **)(*plVar7 + 0xc0))(plVar7,uVar11,uVar12);
      android::Parcel::writeInt32(param_4);
      goto LAB_0011fe20;
    }
    break;
  case 0x13:
    __android_log_print(3,"FingerGoodix","server,check passwd");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      uVar2 = 0;
      uVar11 = android::Parcel::readCString();
      (**(code **)(*plVar7 + 200))(plVar7,uVar11);
      android::Parcel::writeInt32(param_4);
      goto LAB_0011fe20;
    }
    break;
  case 0x14:
    __android_log_print(3,"FingerGoodix","server,delFpTemplates");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      uVar8 = android::Parcel::readInt32();
      sVar19 = (uVar8 & 0xffffffff) << 2;
      pvVar18 = malloc(sVar19);
      if (pvVar18 == (void *)0x0) {
        uVar2 = 0xffffffff;
        __android_log_print(6,"FingerGoodix",
                            "IFingerPrint TRANSACTION_FP_DELETE_TEMPLATE out of memory");
        goto LAB_0011fe20;
      }
      memset(pvVar18,0,sVar19);
      android::Parcel::read(param_3,(ulong)pvVar18);
      (**(code **)(*plVar7 + 0xd0))(plVar7,pvVar18,uVar8 & 0xffffffff);
      goto LAB_00120e40;
    }
    break;
  case 0x15:
    uVar2 = 0xffffffff;
    __android_log_print(3,"FingerGoodix","server,getFpTemplateIdList");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      local_58 = (long *)CONCAT44(local_58._4_4_,5);
      puVar9 = (undefined8 *)malloc(0x14);
      if (puVar9 == (undefined8 *)0x0) {
        __android_log_print(6,"FingerGoodix",
                            "IFingerPrint TRANSACTION_FP_GET_TEMPLATE_LIST out of memory");
      }
      else {
        lVar17 = *plVar7;
        *puVar9 = 0;
        puVar9[1] = 0;
        *(undefined4 *)(puVar9 + 2) = 0;
        iVar4 = (**(code **)(lVar17 + 0xd8))(plVar7,puVar9,&local_58);
        android::Parcel::writeInt32(param_4);
        if (iVar4 == 0) {
          android::Parcel::writeInt32(param_4);
          android::Parcel::write(pcVar13,(ulong)puVar9);
          __android_log_print(3,"FingerGoodix","templelist:%d,%d,%d",*(undefined4 *)puVar9,
                              *(undefined4 *)((long)puVar9 + 4),*(undefined4 *)(puVar9 + 1));
        }
        else {
          android::Parcel::writeInt32(param_4);
          android::Parcel::write(pcVar13,(ulong)puVar9);
        }
        uVar2 = 0;
        free(puVar9);
      }
    }
    goto LAB_0011fe20;
  case 0x16:
    __android_log_print(3,"FingerGoodix","server,setPauseRegisterState");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      uVar2 = 0;
      uVar3 = android::Parcel::readInt32();
      (**(code **)(*plVar7 + 0xe0))(plVar7,uVar3);
      android::Parcel::writeInt32(param_4);
      goto LAB_0011fe20;
    }
    break;
  case 0x17:
    __android_log_print(3,"FingerGoodix","server,driverTest");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      uVar2 = 0;
      (**(code **)(*plVar7 + 0xe8))(plVar7);
      android::Parcel::writeInt32(param_4);
      goto LAB_0011fe20;
    }
    break;
  case 0x18:
    __android_log_print(3,"FingerGoodix","server,modifyFpName");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      uVar2 = 0;
      uVar3 = android::Parcel::readInt32();
      uVar11 = android::Parcel::readCString();
      (**(code **)(*plVar7 + 0xf0))(plVar7,uVar3,uVar11);
      android::Parcel::writeInt32(param_4);
      goto LAB_0011fe20;
    }
    break;
  case 0x19:
    __android_log_print(3,"FingerGoodix","server,getFpNameById");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      uVar3 = android::Parcel::readInt32();
      puVar9 = (undefined8 *)malloc(0x80);
      if (puVar9 == (undefined8 *)0x0) {
        uVar2 = 0xffffffff;
        __android_log_print(6,"FingerGoodix","failed to malloc pName in server\'s getFpNameById");
        android::Parcel::writeInt32(param_4);
      }
      else {
        lVar17 = *plVar7;
        *puVar9 = 0;
        puVar9[1] = 0;
        puVar9[2] = 0;
        puVar9[3] = 0;
        puVar9[4] = 0;
        puVar9[5] = 0;
        puVar9[6] = 0;
        puVar9[7] = 0;
        puVar9[8] = 0;
        puVar9[9] = 0;
        puVar9[10] = 0;
        puVar9[0xb] = 0;
        puVar9[0xc] = 0;
        puVar9[0xd] = 0;
        puVar9[0xe] = 0;
        puVar9[0xf] = 0;
        uVar2 = 0;
        (**(code **)(lVar17 + 0xf8))(plVar7,uVar3,puVar9);
        android::Parcel::writeInt32(param_4);
        android::Parcel::write(pcVar13,(ulong)puVar9);
        free(puVar9);
      }
      goto LAB_0011fe20;
    }
    break;
  case 0x1a:
    uVar2 = 0xffffffff;
    __android_log_print(3,"FingerGoodix","server,getFpTemplateList");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      local_58 = (long *)CONCAT44(local_58._4_4_,5);
      puVar9 = (undefined8 *)malloc(0x14);
      if (puVar9 == (undefined8 *)0x0) {
        __android_log_print(6,"FingerGoodix","failed to malloc pIdList memory!!!");
      }
      else {
        *puVar9 = 0;
        puVar9[1] = 0;
        *(undefined4 *)(puVar9 + 2) = 0;
        lVar17 = 0;
        do {
          puVar10 = (undefined8 *)malloc(0x80);
          *(undefined8 **)((long)local_50 + lVar17) = puVar10;
          if (puVar10 == (undefined8 *)0x0) {
            uVar2 = 0xffffffff;
            __android_log_print(6,"FingerGoodix","failed to malloc pNameLists");
            goto LAB_0011fe20;
          }
          lVar17 = lVar17 + 8;
          *puVar10 = 0;
          puVar10[1] = 0;
          puVar10[2] = 0;
          puVar10[3] = 0;
          puVar10[4] = 0;
          puVar10[5] = 0;
          puVar10[6] = 0;
          puVar10[7] = 0;
          puVar10[8] = 0;
          puVar10[9] = 0;
          puVar10[10] = 0;
          puVar10[0xb] = 0;
          puVar10[0xc] = 0;
          puVar10[0xd] = 0;
          puVar10[0xe] = 0;
          puVar10[0xf] = 0;
        } while (lVar17 != 0x28);
        iVar4 = (**(code **)(*plVar7 + 0x100))(plVar7,&local_58,puVar9,local_50);
        android::Parcel::writeInt32(param_4);
        if (iVar4 == 0) {
          android::Parcel::writeInt32(param_4);
          if ((uint)local_58 != 0) {
            android::Parcel::write(pcVar13,(ulong)puVar9);
            __android_log_print(3,"FingerGoodix","write pIdList to reply");
            if ((uint)local_58 != 0) {
              uVar8 = 0;
              do {
                android::Parcel::writeCString(pcVar13);
                __android_log_print(3,"FingerGoodix","write pNameLists[%d] to reply,name:%s",
                                    uVar8 & 0xffffffff,local_50[uVar8]);
                iVar4 = (int)uVar8;
                uVar8 = uVar8 + 1;
              } while (iVar4 + 1U < (uint)local_58);
            }
          }
        }
        else {
          __android_log_print(6,"FingerGoodix","server,failed to getFpTemplateList");
        }
        free(puVar9);
        uVar8 = 0;
        __android_log_print(3,"FingerGoodix","free pIdList");
        do {
          free(local_50[uVar8]);
          uVar14 = uVar8 & 0xffffffff;
          uVar8 = uVar8 + 1;
          __android_log_print(3,"FingerGoodix","free pNameList[%d]",uVar14);
        } while (uVar8 != 5);
        uVar2 = 0;
      }
    }
    goto LAB_0011fe20;
  case 0x1b:
    uVar2 = 0xffffffff;
    __android_log_print(3,"FingerGoodix","server,alipay_tz_invoke_command");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      uVar2 = 0;
      uVar3 = android::Parcel::readInt32();
      uVar8 = android::Parcel::readInt32();
      pvVar18 = malloc(uVar8 & 0xffffffff);
      android::Parcel::read(param_3,(ulong)pvVar18);
      local_58 = (long *)CONCAT44(local_58._4_4_,0x800);
      pvVar16 = malloc(0x800);
      (**(code **)(*plVar7 + 0x118))(plVar7,uVar3,pvVar18,uVar8 & 0xffffffff,pvVar16,&local_58);
      free(pvVar18);
      android::Parcel::writeInt32(param_4);
      android::Parcel::writeInt32(param_4);
      android::Parcel::write(pcVar13,(ulong)pvVar16);
      free(pvVar16);
    }
    goto LAB_0011fe20;
  case 0x1c:
    __android_log_print(3,"FingerGoodix","server, weChatSetSessionId");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      uVar2 = 0;
      uVar11 = android::Parcel::readInt64();
      (**(code **)(*plVar7 + 0x138))(plVar7,uVar11);
      android::Parcel::writeInt32(param_4);
      goto LAB_0011fe20;
    }
    break;
  case 0x1d:
    __android_log_print(3,"FingerGoodix","server,enableFingerScreenUnlock");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      uVar2 = 0;
      (**(code **)(*plVar7 + 0x120))(plVar7);
      android::Parcel::writeInt32(param_4);
      goto LAB_0011fe20;
    }
    break;
  case 0x1e:
    __android_log_print(3,"FingerGoodix","server,disableFingerScreenUnlock");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      uVar2 = 0;
      (**(code **)(*plVar7 + 0x128))(plVar7);
      android::Parcel::writeInt32(param_4);
      goto LAB_0011fe20;
    }
    break;
  case 0x1f:
    __android_log_print(3,"FingerGoodix","server,setRecFlag");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      uVar2 = 0;
      uVar3 = android::Parcel::readInt32();
      (**(code **)(*plVar7 + 0x140))(plVar7,uVar3);
      android::Parcel::writeInt32(param_4);
      goto LAB_0011fe20;
    }
    break;
  case 0x20:
    __android_log_print(3,"FingerGoodix","server,recognize fido");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      iVar4 = android::Parcel::readInt32();
      pvVar18 = malloc((long)iVar4);
      if (pvVar18 != (void *)0x0) {
        memset(pvVar18,0,(long)iVar4);
        android::Parcel::read(param_3,(ulong)pvVar18);
        iVar5 = android::Parcel::readInt32();
        sVar19 = (size_t)iVar5;
        pvVar16 = malloc(sVar19);
        if (pvVar16 != (void *)0x0) {
          uVar2 = 0;
          memset(pvVar16,0,sVar19);
          android::Parcel::read(param_3,(ulong)pvVar16);
          (**(code **)(*plVar7 + 0xb0))(plVar7,pvVar18,iVar4,pvVar16,sVar19);
          android::Parcel::writeInt32(param_4);
          free(pvVar18);
          free(pvVar16);
          goto LAB_0011fe20;
        }
      }
      uVar2 = 0xffffffff;
      __android_log_print(6,"FingerGoodix",
                          "IFingerPrint TRANSACTION_FP_RECOGNIZE_FIDO out of memory");
      goto LAB_0011fe20;
    }
    break;
  case 0x21:
    uVar2 = 0xffffffff;
    __android_log_print(3,"FingerGoodix","server,send cmd.");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      local_60 = 0;
      local_58 = (long *)0x0;
      pvVar18 = (void *)0x0;
      uVar2 = android::Parcel::readInt32();
      iVar4 = android::Parcel::readInt32();
      if (iVar4 != 0) {
        pvVar18 = malloc((long)iVar4);
        android::Parcel::read(param_3,(ulong)pvVar18);
      }
      (**(code **)(*plVar7 + 0x40))(plVar7,uVar2,pvVar18,iVar4,&local_58,&local_60);
      android::Parcel::writeInt32(param_4);
      android::Parcel::writeInt32(param_4);
      if (local_58 != (long *)0x0) {
        android::Parcel::write(pcVar13,(ulong)local_58);
        free(local_58);
      }
      uVar2 = 0;
      free(pvVar18);
    }
    goto LAB_0011fe20;
  case 0x22:
    __android_log_print(3,"FingerGoodix","server,save regist");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      pcVar15 = *(code **)(*plVar7 + 0x130);
      goto LAB_0012009c;
    }
    break;
  case 0x23:
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      uVar2 = 0;
      uVar3 = android::Parcel::readInt32();
      (**(code **)(*plVar7 + 0x108))(plVar7,uVar3);
      android::Parcel::writeInt32(param_4);
      goto LAB_0011fe20;
    }
    break;
  case 0x24:
    uVar2 = 0xffffffff;
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      iVar4 = android::Parcel::readInt32();
      if (iVar4 < 1) {
        uVar2 = 0;
        (**(code **)(*plVar7 + 0x110))(plVar7,local_50);
        android::Parcel::writeInt32(param_4);
        android::Parcel::writeInt32(param_4);
      }
      else {
        uVar2 = 0;
        android::Parcel::read(param_3,(ulong)local_50);
        (**(code **)(*plVar7 + 0x110))(plVar7,local_50);
        android::Parcel::writeInt32(param_4);
        android::Parcel::writeInt32(param_4);
        android::Parcel::write(pcVar13,(ulong)local_50);
      }
    }
    goto LAB_0011fe20;
  case 0x25:
    uVar2 = 0xffffffff;
    __android_log_print(3,"FingerGoodix","server,verify");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      local_10 = 0;
      local_50[0] = (void *)0x0;
      local_50[1] = (void *)0x0;
      local_50[2] = (void *)0x0;
      local_50[3] = (void *)0x0;
      local_50[4] = (void *)0x0;
      uStack_28 = 0;
      local_20 = 0;
      uStack_18 = 0;
      local_c = 0;
      iVar4 = android::Parcel::readInt32();
      if (0 < iVar4) {
        android::Parcel::read(param_3,(ulong)local_50);
      }
      uVar2 = 0;
      (**(code **)(*plVar7 + 0x60))(plVar7,local_50);
      android::Parcel::writeInt32(param_4);
    }
    goto LAB_0011fe20;
  case 0x26:
    __android_log_print(3,"FingerGoodix","server, gfCmdM");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      pvVar18 = (void *)0x0;
      uVar2 = android::Parcel::readInt32();
      iVar4 = android::Parcel::readInt32();
      iVar5 = android::Parcel::readInt32();
      if (0 < iVar4) {
        pvVar18 = malloc((long)iVar4);
        android::Parcel::read(param_3,(ulong)pvVar18);
      }
      pvVar16 = (void *)0x0;
      if (0 < iVar5) {
        pvVar16 = malloc((long)iVar5);
      }
      local_58 = (long *)((ulong)local_58._4_4_ << 0x20);
      (**(code **)(*plVar7 + 0x148))(plVar7,uVar2,pvVar18,iVar4,pvVar16,iVar5);
      android::Parcel::writeInt32(param_4);
      android::Parcel::writeInt32(param_4);
      if (0 < (int)(uint)local_58) {
        android::Parcel::write(pcVar13,(ulong)pvVar16);
      }
      if (pvVar18 != (void *)0x0) {
        free(pvVar18);
      }
      if (pvVar16 != (void *)0x0) {
        free(pvVar16);
      }
      uVar2 = 0;
      goto LAB_0011fe20;
    }
    break;
  default:
    uVar2 = android::BBinder::onTransact(param_1 + 8,param_2,param_3,param_4);
    goto LAB_0011fe20;
  }
  uVar2 = 0xffffffff;
LAB_0011fe20:
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar2);
}



// non-virtual thunk to android::BnFingerPrint::onTransact(unsigned int, android::Parcel const&,
// android::Parcel*, unsigned int)

void __thiscall
android::BnFingerPrint::onTransact
          (BnFingerPrint *this,uint param_1,Parcel *param_2,Parcel *param_3,uint param_4)

{
  onTransact((int)this - 8,(Parcel *)(ulong)param_1,param_2,(uint)param_3);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// BpFingerPrint::getFpTemplateList(unsigned int*, unsigned int*, char**)

void __thiscall
BpFingerPrint::getFpTemplateList(BpFingerPrint *this,uint *param_1,uint *param_2,char **param_3)

{
  int iVar1;
  uint uVar2;
  char *pcVar3;
  Parcel aPStack_d8 [104];
  Parcel aPStack_70 [104];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","client,getFpTemplateList");
  if ((param_2 == (uint *)0x0 || param_3 == (char **)0x0) || (param_1 == (uint *)0x0)) {
    __android_log_print(6,"FingerGoodix","some of the params is NULL,just return");
    iVar1 = -1;
  }
  else {
    android::Parcel::Parcel(aPStack_d8);
                    // try { // try from 00121308 to 0012130b has its CatchHandler @ 00121474
    android::Parcel::Parcel(aPStack_70);
                    // try { // try from 00121310 to 0012143b has its CatchHandler @ 00121488
    android::IFingerPrint::getInterfaceDescriptor();
    android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
    (**(code **)(**(long **)(this + 0x10) + 0x28))
              (*(long **)(this + 0x10),0x1a,aPStack_d8,aPStack_70,0);
    iVar1 = android::Parcel::readInt32();
    if (iVar1 == 0) {
      uVar2 = android::Parcel::readInt32();
      *param_1 = uVar2;
      __android_log_print(3,"FingerGoodix","success to getFpTemplate,count:%d");
      if ((*param_1 != 0) && (android::Parcel::read(aPStack_70,(ulong)param_2), *param_1 != 0)) {
        uVar2 = 0;
        do {
          pcVar3 = (char *)android::Parcel::readCString();
          *param_3 = pcVar3;
          __android_log_print(3,"FingerGoodix","pNameList[%d] is %s",uVar2);
          uVar2 = uVar2 + 1;
          param_3 = param_3 + 1;
        } while (uVar2 < *param_1);
      }
    }
    else {
      __android_log_print(6,"FingerGoodix","failed to getFpTemplateList");
      *param_1 = 0;
    }
    __android_log_print(3,"FingerGoodix","return from getFpTemplateList");
    android::Parcel::~Parcel(aPStack_70);
    android::Parcel::~Parcel(aPStack_d8);
  }
  if (local_8 != ___stack_chk_guard) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail(iVar1);
  }
  return;
}



// android::IFingerPrint::IFingerPrint()

void __thiscall android::IFingerPrint::IFingerPrint(IFingerPrint *this)

{
  long lVar1;
  long *in_x1;
  
  android::IInterface::IInterface((IInterface *)this);
  lVar1 = *in_x1;
  *(long *)this = lVar1;
  *(long *)(this + *(long *)(lVar1 + -0x18)) = in_x1[3];
  return;
}



// android::IFingerPrint::IFingerPrint()

void __thiscall android::IFingerPrint::IFingerPrint(IFingerPrint *this)

{
  android::RefBase::RefBase((RefBase *)(this + 8));
                    // try { // try from 00121500 to 00121503 has its CatchHandler @ 00121528
  android::IInterface::IInterface((IInterface *)this);
  *(undefined8 *)this = 0x15fc78;
  *(undefined8 *)(this + 8) = 0x15fe00;
  return;
}



// android::IFingerPrint::~IFingerPrint()

void __thiscall android::IFingerPrint::~IFingerPrint(IFingerPrint *this)

{
  long *in_x1;
  long lVar1;
  
  lVar1 = *in_x1;
  *(long *)this = lVar1;
  *(long *)(this + *(long *)(lVar1 + -0x18)) = in_x1[3];
  android::IInterface::~IInterface((IInterface *)this);
  return;
}



// BpFingerPrint::~BpFingerPrint()

void __thiscall BpFingerPrint::~BpFingerPrint(BpFingerPrint *this)

{
  *(undefined **)this = &DAT_0015f738;
  *(undefined **)(this + 0x28) = &DAT_0015f900;
  *(undefined **)(this + 8) = &DAT_0015f8a0;
  android::BpRefBase::~BpRefBase((BpRefBase *)(this + 8));
  android::IFingerPrint::~IFingerPrint((IFingerPrint *)this);
  android::RefBase::~RefBase((RefBase *)(this + 0x28));
  return;
}



// non-virtual thunk to BpFingerPrint::~BpFingerPrint()

void __thiscall BpFingerPrint::~BpFingerPrint(BpFingerPrint *this)

{
  ~BpFingerPrint(this + -8);
  return;
}



// virtual thunk to BpFingerPrint::~BpFingerPrint()

void __thiscall BpFingerPrint::~BpFingerPrint(BpFingerPrint *this)

{
  ~BpFingerPrint(this + *(long *)(*(long *)this + -0x18));
  return;
}



// BpFingerPrint::~BpFingerPrint()

void __thiscall BpFingerPrint::~BpFingerPrint(BpFingerPrint *this)

{
  *(undefined **)this = &DAT_0015f738;
  *(undefined **)(this + 0x28) = &DAT_0015f900;
  *(undefined **)(this + 8) = &DAT_0015f8a0;
  android::BpRefBase::~BpRefBase((BpRefBase *)(this + 8));
  android::IFingerPrint::~IFingerPrint((IFingerPrint *)this);
  android::RefBase::~RefBase((RefBase *)(this + 0x28));
  operator_delete(this);
  return;
}



// non-virtual thunk to BpFingerPrint::~BpFingerPrint()

void __thiscall BpFingerPrint::~BpFingerPrint(BpFingerPrint *this)

{
  ~BpFingerPrint(this + -8);
  return;
}



// virtual thunk to BpFingerPrint::~BpFingerPrint()

void __thiscall BpFingerPrint::~BpFingerPrint(BpFingerPrint *this)

{
  ~BpFingerPrint(this + *(long *)(*(long *)this + -0x18));
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// android::IFingerPrint::asInterface(android::sp<android::IBinder> const&)

void android::IFingerPrint::asInterface(sp *param_1)

{
  long lVar1;
  undefined8 *puVar2;
  long *plVar3;
  long *plVar4;
  long **in_x8;
  long *local_10;
  
  lVar1 = ___stack_chk_guard;
  puVar2 = *(undefined8 **)param_1;
  *in_x8 = (long *)0x0;
  if (puVar2 != (undefined8 *)0x0) {
                    // try { // try from 001216bc to 001216bf has its CatchHandler @ 0012185c
    (**(code **)*puVar2)(puVar2,&descriptor);
    if (local_10 != (long *)0x0) {
                    // try { // try from 001216d8 to 001216f7 has its CatchHandler @ 00121838
      android::RefBase::incStrong((void *)((long)local_10 + *(long *)(*local_10 + -0x18)));
    }
    plVar3 = *in_x8;
    if (plVar3 != (long *)0x0) {
      android::RefBase::decStrong((void *)((long)plVar3 + *(long *)(*plVar3 + -0x18)));
    }
    *in_x8 = local_10;
    if (local_10 != (long *)0x0) {
      android::RefBase::decStrong((void *)((long)local_10 + *(long *)(*local_10 + -0x18)));
      local_10 = *in_x8;
    }
    if (local_10 == (long *)0x0) {
                    // try { // try from 00121750 to 00121753 has its CatchHandler @ 0012185c
      plVar3 = (long *)operator_new(0x38);
                    // try { // try from 00121760 to 00121763 has its CatchHandler @ 00121830
      android::RefBase::RefBase((RefBase *)(plVar3 + 5));
                    // try { // try from 00121774 to 00121777 has its CatchHandler @ 00121828
      IFingerPrint((IFingerPrint *)plVar3);
                    // try { // try from 00121788 to 0012178b has its CatchHandler @ 001217e0
      android::BpRefBase::BpRefBase((BpRefBase *)(plVar3 + 1),(sp *)&PTR_DAT_0015f960);
      *plVar3 = 0x15f9a8;
      plVar3[5] = 0x15fb70;
      plVar3[1] = 0x15fb10;
                    // try { // try from 001217b4 to 001217d3 has its CatchHandler @ 0012185c
      android::RefBase::incStrong(plVar3 + 5);
      plVar4 = *in_x8;
      if (plVar4 != (long *)0x0) {
        android::RefBase::decStrong((void *)((long)plVar4 + *(long *)(*plVar4 + -0x18)));
      }
      *in_x8 = plVar3;
    }
  }
  if (lVar1 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



// android::IFingerPrint::~IFingerPrint()

void __thiscall android::IFingerPrint::~IFingerPrint(IFingerPrint *this)

{
  *(undefined8 *)this = 0x15fc78;
  *(undefined8 *)(this + 8) = 0x15fe00;
  android::IInterface::~IInterface((IInterface *)this);
  android::RefBase::~RefBase((RefBase *)(this + 8));
  return;
}



// virtual thunk to android::IFingerPrint::~IFingerPrint()

void __thiscall android::IFingerPrint::~IFingerPrint(IFingerPrint *this)

{
  ~IFingerPrint(this + *(long *)(*(long *)this + -0x18));
  return;
}



// android::IFingerPrint::~IFingerPrint()

void __thiscall android::IFingerPrint::~IFingerPrint(IFingerPrint *this)

{
  ~IFingerPrint(this);
  operator_delete(this);
  return;
}



// virtual thunk to android::IFingerPrint::~IFingerPrint()

void __thiscall android::IFingerPrint::~IFingerPrint(IFingerPrint *this)

{
  ~IFingerPrint(this + *(long *)(*(long *)this + -0x18));
  return;
}



// android::IFingerPrintClient::getInterfaceDescriptor() const

undefined8 * android::IFingerPrintClient::getInterfaceDescriptor(void)

{
  return &descriptor;
}



// android::BnInterface<android::IFingerPrintClient>::onAsBinder()

BnInterface<> * __thiscall android::BnInterface<>::onAsBinder(BnInterface<> *this)

{
  return this + 8;
}



// android::BnInterface<android::IFingerPrintClient>::getInterfaceDescriptor() const

undefined8 * android::BnInterface<>::getInterfaceDescriptor(void)

{
  return &IFingerPrintClient::descriptor;
}



// non-virtual thunk to android::BnInterface<android::IFingerPrintClient>::getInterfaceDescriptor()
// const

void __thiscall android::BnInterface<>::getInterfaceDescriptor(BnInterface<> *this)

{
  getInterfaceDescriptor();
  return;
}



// android::BpInterface<android::IFingerPrintClient>::onAsBinder()

undefined8 __thiscall android::BpInterface<>::onAsBinder(BpInterface<> *this)

{
  return *(undefined8 *)(this + 0x10);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// BpFingerPrintClient::dataCallback(int, int, char*)

void __thiscall
BpFingerPrintClient::dataCallback(BpFingerPrintClient *this,int param_1,int param_2,char *param_3)

{
  int iVar1;
  Parcel aPStack_d8 [104];
  Parcel aPStack_70 [104];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","client dataCallback,type is %d.",param_1);
  android::Parcel::Parcel(aPStack_d8);
                    // try { // try from 00121980 to 00121983 has its CatchHandler @ 00121a5c
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 00121988 to 00121a37 has its CatchHandler @ 00121a40
  android::IFingerPrintClient::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  iVar1 = (int)aPStack_d8;
  android::Parcel::writeInt32(iVar1);
  if (param_3 == (char *)0x0) {
    __android_log_print(3,"FingerGoodix","dataCallback,msgData is null");
  }
  else {
    android::Parcel::writeInt32(iVar1);
    android::Parcel::write(aPStack_d8,(ulong)param_3);
  }
  (**(code **)(**(long **)(this + 0x10) + 0x28))(*(long **)(this + 0x10),2,aPStack_d8,aPStack_70,1);
  android::Parcel::~Parcel(aPStack_70);
  android::Parcel::~Parcel(aPStack_d8);
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// BpFingerPrintClient::notifyCallback(int, int, int)

void BpFingerPrintClient::notifyCallback(int param_1,int param_2,int param_3)

{
  int iVar1;
  Parcel aPStack_d8 [104];
  Parcel aPStack_70 [104];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","client notifyCallback");
  android::Parcel::Parcel(aPStack_d8);
                    // try { // try from 00121ac8 to 00121acb has its CatchHandler @ 00121b84
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 00121ad0 to 00121b27 has its CatchHandler @ 00121b68
  android::IFingerPrintClient::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  iVar1 = (int)aPStack_d8;
  android::Parcel::writeInt32(iVar1);
  android::Parcel::writeInt32(iVar1);
  android::Parcel::writeInt32(iVar1);
  (**(code **)(**(long **)((ulong)(uint)param_1 + 0x10) + 0x28))
            (*(long **)((ulong)(uint)param_1 + 0x10),1,aPStack_d8,aPStack_70,1);
  android::Parcel::~Parcel(aPStack_70);
  android::Parcel::~Parcel(aPStack_d8);
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



// android::BnFingerPrintClient::onTransact(unsigned int, android::Parcel const&, android::Parcel*,
// unsigned int)

undefined8
android::BnFingerPrintClient::onTransact(uint param_1,Parcel *param_2,Parcel *param_3,uint param_4)

{
  char cVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  int iVar5;
  long *plVar6;
  long lVar7;
  undefined8 uVar8;
  
  plVar6 = (long *)(ulong)param_1;
  if ((int)param_2 == 1) {
    __android_log_print(3,"FingerGoodix","server,NOTIFY_CALLBACK");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      uVar2 = android::Parcel::readInt32();
      uVar3 = android::Parcel::readInt32();
      uVar4 = android::Parcel::readInt32();
      (**(code **)(*plVar6 + 0x20))(plVar6,uVar2,uVar3,uVar4);
      return 0;
    }
  }
  else {
    if ((int)param_2 != 2) {
      uVar8 = android::BBinder::onTransact(param_1 + 8,param_2,param_3,param_4);
      return uVar8;
    }
    __android_log_print(3,"FingerGoodix","server,DATA_CALLBACK");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      uVar2 = android::Parcel::readInt32();
      lVar7 = android::Parcel::dataAvail();
      if (lVar7 == 0) {
        uVar8 = 0;
        lVar7 = 0;
      }
      else {
        iVar5 = android::Parcel::readInt32();
        lVar7 = (long)iVar5;
        uVar8 = android::Parcel::readInplace((ulong)param_3);
      }
      (**(code **)(*plVar6 + 0x28))(plVar6,uVar2,lVar7,uVar8);
      return 0;
    }
  }
  return 0xffffffff;
}



// non-virtual thunk to android::BnFingerPrintClient::onTransact(unsigned int, android::Parcel
// const&, android::Parcel*, unsigned int)

void __thiscall
android::BnFingerPrintClient::onTransact
          (BnFingerPrintClient *this,uint param_1,Parcel *param_2,Parcel *param_3,uint param_4)

{
  onTransact((int)this - 8,(Parcel *)(ulong)param_1,param_2,(uint)param_3);
  return;
}



// android::BnInterface<android::IFingerPrintClient>::queryLocalInterface(android::String16 const&)

void __thiscall android::BnInterface<>::queryLocalInterface(BnInterface<> *this,String16 *param_1)

{
  int iVar1;
  long lVar2;
  long lVar3;
  long lVar4;
  BnInterface<> **in_x8;
  
  lVar4 = *(long *)param_1;
  if (lVar4 == 0) {
    lVar2 = -1;
  }
  else {
    lVar2 = (*(ulong *)(lVar4 + -0x10) >> 1) - 1;
  }
  lVar3 = -1;
  if (IFingerPrintClient::descriptor != 0) {
    lVar3 = (*(ulong *)(IFingerPrintClient::descriptor + -0x10) >> 1) - 1;
  }
  iVar1 = strzcmp16(lVar4,lVar2,IFingerPrintClient::descriptor,lVar3);
  if (iVar1 == 0) {
    *in_x8 = this;
    if (this != (BnInterface<> *)0x0) {
      android::RefBase::incStrong(this + *(long *)(*(long *)this + -0x18));
    }
    return;
  }
  *in_x8 = (BnInterface<> *)0x0;
  return;
}



// non-virtual thunk to
// android::BnInterface<android::IFingerPrintClient>::queryLocalInterface(android::String16 const&)

void __thiscall android::BnInterface<>::queryLocalInterface(BnInterface<> *this,String16 *param_1)

{
  queryLocalInterface(this + -8,param_1);
  return;
}



// android::IFingerPrintClient::IFingerPrintClient()

void __thiscall android::IFingerPrintClient::IFingerPrintClient(IFingerPrintClient *this)

{
  long lVar1;
  long *in_x1;
  
  android::IInterface::IInterface((IInterface *)this);
  lVar1 = *in_x1;
  *(long *)this = lVar1;
  *(long *)(this + *(long *)(lVar1 + -0x18)) = in_x1[3];
  return;
}



// android::IFingerPrintClient::IFingerPrintClient()

void __thiscall android::IFingerPrintClient::IFingerPrintClient(IFingerPrintClient *this)

{
  android::RefBase::RefBase((RefBase *)(this + 8));
                    // try { // try from 00121e00 to 00121e03 has its CatchHandler @ 00121e28
  android::IInterface::IInterface((IInterface *)this);
  *(undefined8 *)this = 0x160d38;
  *(undefined8 *)(this + 8) = 0x160da0;
  return;
}



// android::IFingerPrintClient::~IFingerPrintClient()

void __thiscall android::IFingerPrintClient::~IFingerPrintClient(IFingerPrintClient *this)

{
  long *in_x1;
  long lVar1;
  
  lVar1 = *in_x1;
  *(long *)this = lVar1;
  *(long *)(this + *(long *)(lVar1 + -0x18)) = in_x1[3];
  android::IInterface::~IInterface((IInterface *)this);
  return;
}



// BpFingerPrintClient::~BpFingerPrintClient()

void __thiscall BpFingerPrintClient::~BpFingerPrintClient(BpFingerPrintClient *this)

{
  *(undefined **)this = &DAT_00160a38;
  *(undefined **)(this + 0x28) = &DAT_00160ae0;
  *(undefined **)(this + 8) = &DAT_00160a80;
  android::BpRefBase::~BpRefBase((BpRefBase *)(this + 8));
  android::IFingerPrintClient::~IFingerPrintClient((IFingerPrintClient *)this);
  android::RefBase::~RefBase((RefBase *)(this + 0x28));
  return;
}



// non-virtual thunk to BpFingerPrintClient::~BpFingerPrintClient()

void __thiscall BpFingerPrintClient::~BpFingerPrintClient(BpFingerPrintClient *this)

{
  ~BpFingerPrintClient(this + -8);
  return;
}



// virtual thunk to BpFingerPrintClient::~BpFingerPrintClient()

void __thiscall BpFingerPrintClient::~BpFingerPrintClient(BpFingerPrintClient *this)

{
  ~BpFingerPrintClient(this + *(long *)(*(long *)this + -0x18));
  return;
}



// BpFingerPrintClient::~BpFingerPrintClient()

void __thiscall BpFingerPrintClient::~BpFingerPrintClient(BpFingerPrintClient *this)

{
  *(undefined **)this = &DAT_00160a38;
  *(undefined **)(this + 0x28) = &DAT_00160ae0;
  *(undefined **)(this + 8) = &DAT_00160a80;
  android::BpRefBase::~BpRefBase((BpRefBase *)(this + 8));
  android::IFingerPrintClient::~IFingerPrintClient((IFingerPrintClient *)this);
  android::RefBase::~RefBase((RefBase *)(this + 0x28));
  operator_delete(this);
  return;
}



// non-virtual thunk to BpFingerPrintClient::~BpFingerPrintClient()

void __thiscall BpFingerPrintClient::~BpFingerPrintClient(BpFingerPrintClient *this)

{
  ~BpFingerPrintClient(this + -8);
  return;
}



// virtual thunk to BpFingerPrintClient::~BpFingerPrintClient()

void __thiscall BpFingerPrintClient::~BpFingerPrintClient(BpFingerPrintClient *this)

{
  ~BpFingerPrintClient(this + *(long *)(*(long *)this + -0x18));
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// android::IFingerPrintClient::asInterface(android::sp<android::IBinder> const&)

void android::IFingerPrintClient::asInterface(sp *param_1)

{
  long lVar1;
  undefined8 *puVar2;
  long *plVar3;
  long *plVar4;
  long **in_x8;
  long *local_10;
  
  lVar1 = ___stack_chk_guard;
  puVar2 = *(undefined8 **)param_1;
  *in_x8 = (long *)0x0;
  if (puVar2 != (undefined8 *)0x0) {
                    // try { // try from 00121fbc to 00121fbf has its CatchHandler @ 0012215c
    (**(code **)*puVar2)(puVar2,&descriptor);
    if (local_10 != (long *)0x0) {
                    // try { // try from 00121fd8 to 00121ff7 has its CatchHandler @ 00122138
      android::RefBase::incStrong((void *)((long)local_10 + *(long *)(*local_10 + -0x18)));
    }
    plVar3 = *in_x8;
    if (plVar3 != (long *)0x0) {
      android::RefBase::decStrong((void *)((long)plVar3 + *(long *)(*plVar3 + -0x18)));
    }
    *in_x8 = local_10;
    if (local_10 != (long *)0x0) {
      android::RefBase::decStrong((void *)((long)local_10 + *(long *)(*local_10 + -0x18)));
      local_10 = *in_x8;
    }
    if (local_10 == (long *)0x0) {
                    // try { // try from 00122050 to 00122053 has its CatchHandler @ 0012215c
      plVar3 = (long *)operator_new(0x38);
                    // try { // try from 00122060 to 00122063 has its CatchHandler @ 00122130
      android::RefBase::RefBase((RefBase *)(plVar3 + 5));
                    // try { // try from 00122074 to 00122077 has its CatchHandler @ 00122128
      IFingerPrintClient((IFingerPrintClient *)plVar3);
                    // try { // try from 00122088 to 0012208b has its CatchHandler @ 001220e0
      android::BpRefBase::BpRefBase((BpRefBase *)(plVar3 + 1),(sp *)&PTR_DAT_00160b40);
      *plVar3 = 0x160b88;
      plVar3[5] = 0x160c30;
      plVar3[1] = 0x160bd0;
                    // try { // try from 001220b4 to 001220d3 has its CatchHandler @ 0012215c
      android::RefBase::incStrong(plVar3 + 5);
      plVar4 = *in_x8;
      if (plVar4 != (long *)0x0) {
        android::RefBase::decStrong((void *)((long)plVar4 + *(long *)(*plVar4 + -0x18)));
      }
      *in_x8 = plVar3;
    }
  }
  if (lVar1 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



// android::IFingerPrintClient::~IFingerPrintClient()

void __thiscall android::IFingerPrintClient::~IFingerPrintClient(IFingerPrintClient *this)

{
  *(undefined8 *)this = 0x160d38;
  *(undefined8 *)(this + 8) = 0x160da0;
  android::IInterface::~IInterface((IInterface *)this);
  android::RefBase::~RefBase((RefBase *)(this + 8));
  return;
}



// virtual thunk to android::IFingerPrintClient::~IFingerPrintClient()

void __thiscall android::IFingerPrintClient::~IFingerPrintClient(IFingerPrintClient *this)

{
  ~IFingerPrintClient(this + *(long *)(*(long *)this + -0x18));
  return;
}



// android::IFingerPrintClient::~IFingerPrintClient()

void __thiscall android::IFingerPrintClient::~IFingerPrintClient(IFingerPrintClient *this)

{
  ~IFingerPrintClient(this);
  operator_delete(this);
  return;
}



// virtual thunk to android::IFingerPrintClient::~IFingerPrintClient()

void __thiscall android::IFingerPrintClient::~IFingerPrintClient(IFingerPrintClient *this)

{
  ~IFingerPrintClient(this + *(long *)(*(long *)this + -0x18));
  return;
}



// android::IFingerPrintService::getInterfaceDescriptor() const

undefined8 * android::IFingerPrintService::getInterfaceDescriptor(void)

{
  return &descriptor;
}



// android::BpInterface<android::IFingerPrintService>::onAsBinder()

undefined8 __thiscall android::BpInterface<>::onAsBinder(BpInterface<> *this)

{
  return *(undefined8 *)(this + 0x10);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// BpFingerPrintService::connect(android::sp<android::IFingerPrintClient> const&, int)

void BpFingerPrintService::connect(sp *param_1,int param_2)

{
  long *local_f0;
  long *local_e8;
  long *local_e0;
  Parcel aPStack_d8 [104];
  Parcel aPStack_70 [104];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  android::Parcel::Parcel(aPStack_d8);
                    // try { // try from 00122250 to 00122253 has its CatchHandler @ 0012241c
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 00122258 to 0012228b has its CatchHandler @ 00122414
  android::IFingerPrintService::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  local_f0 = *(long **)(ulong)(uint)param_2;
  if (local_f0 != (long *)0x0) {
    android::RefBase::incStrong((void *)((long)local_f0 + *(long *)(*local_f0 + -0x18)));
  }
                    // try { // try from 00122298 to 0012229b has its CatchHandler @ 0012240c
  android::IInterface::asBinder((sp *)&local_f0);
                    // try { // try from 001222a4 to 001222a7 has its CatchHandler @ 001223cc
  android::Parcel::writeStrongBinder((sp *)aPStack_d8);
  if (local_e8 != (long *)0x0) {
    android::RefBase::decStrong((void *)((long)local_e8 + *(long *)(*local_e8 + -0x18)));
  }
  if (local_f0 != (long *)0x0) {
    android::RefBase::decStrong((void *)((long)local_f0 + *(long *)(*local_f0 + -0x18)));
  }
                    // try { // try from 001222e8 to 0012231f has its CatchHandler @ 00122414
  android::Parcel::writeInt32((int)aPStack_d8);
  (**(code **)(**(long **)(param_1 + 0x10) + 0x28))
            (*(long **)(param_1 + 0x10),2,aPStack_d8,aPStack_70,0);
  android::Parcel::readStrongBinder();
                    // try { // try from 00122328 to 0012232b has its CatchHandler @ 0012238c
  android::IFingerPrint::asInterface((sp *)&local_e0);
  if (local_e0 != (long *)0x0) {
    android::RefBase::decStrong((void *)((long)local_e0 + *(long *)(*local_e0 + -0x18)));
  }
  android::Parcel::~Parcel(aPStack_70);
  android::Parcel::~Parcel(aPStack_d8);
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// BpFingerPrintService::check(int)

void BpFingerPrintService::check(int param_1)

{
  undefined4 uVar1;
  Parcel aPStack_d8 [104];
  Parcel aPStack_70 [104];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","client,check");
  android::Parcel::Parcel(aPStack_d8);
                    // try { // try from 0012247c to 0012247f has its CatchHandler @ 0012252c
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 00122484 to 001224cb has its CatchHandler @ 00122510
  android::IFingerPrintService::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  android::Parcel::writeInt32((int)aPStack_d8);
  (**(code **)(**(long **)((ulong)(uint)param_1 + 0x10) + 0x28))
            (*(long **)((ulong)(uint)param_1 + 0x10),1,aPStack_d8,aPStack_70,0);
  uVar1 = android::Parcel::readInt32();
  android::Parcel::~Parcel(aPStack_70);
  android::Parcel::~Parcel(aPStack_d8);
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar1);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// android::BnFingerPrintService::onTransact(unsigned int, android::Parcel const&, android::Parcel*,
// unsigned int)

void android::BnFingerPrintService::onTransact
               (uint param_1,Parcel *param_2,Parcel *param_3,uint param_4)

{
  char cVar1;
  undefined4 uVar2;
  long *plVar3;
  undefined8 uVar4;
  code *pcVar5;
  long *local_28;
  long *local_20;
  long *local_18;
  long *local_10;
  long local_8;
  
  plVar3 = (long *)(ulong)param_1;
  local_8 = ___stack_chk_guard;
  if ((int)param_2 == 1) {
    __android_log_print(3,"FingerGoodix","server,check");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 == '\0') {
      uVar4 = 0xffffffff;
    }
    else {
      uVar2 = android::Parcel::readInt32();
      (**(code **)(*plVar3 + 0x20))(plVar3,uVar2);
      android::Parcel::writeInt32(param_4);
      uVar4 = 0;
    }
  }
  else if ((int)param_2 == 2) {
    __android_log_print(3,"FingerGoodix","server,connect");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    uVar4 = 0xffffffff;
    if (cVar1 != '\0') {
      android::Parcel::readStrongBinder();
                    // try { // try from 001225f8 to 001225fb has its CatchHandler @ 0012275c
      IFingerPrintClient::asInterface((sp *)&local_10);
      if (local_10 != (long *)0x0) {
        android::RefBase::decStrong((void *)((long)local_10 + *(long *)(*local_10 + -0x18)));
      }
      pcVar5 = *(code **)(*plVar3 + 0x28);
                    // try { // try from 00122624 to 0012263f has its CatchHandler @ 0012280c
      uVar2 = android::Parcel::readInt32();
      (*pcVar5)(plVar3,&local_28,uVar2);
      local_18 = local_20;
      if (local_20 != (long *)0x0) {
                    // try { // try from 00122660 to 00122663 has its CatchHandler @ 00122804
        android::RefBase::incStrong((void *)((long)local_20 + *(long *)(*local_20 + -0x18)));
      }
                    // try { // try from 0012266c to 0012266f has its CatchHandler @ 001227fc
      android::IInterface::asBinder((sp *)&local_18);
                    // try { // try from 00122678 to 0012267b has its CatchHandler @ 00122784
      android::Parcel::writeStrongBinder((sp *)(ulong)param_4);
      if (local_10 != (long *)0x0) {
        android::RefBase::decStrong((void *)((long)local_10 + *(long *)(*local_10 + -0x18)));
      }
      if (local_18 != (long *)0x0) {
        android::RefBase::decStrong((void *)((long)local_18 + *(long *)(*local_18 + -0x18)));
      }
      if (local_20 != (long *)0x0) {
        android::RefBase::decStrong((void *)((long)local_20 + *(long *)(*local_20 + -0x18)));
      }
      if (local_28 != (long *)0x0) {
        android::RefBase::decStrong((void *)((long)local_28 + *(long *)(*local_28 + -0x18)));
      }
      uVar4 = 0;
    }
  }
  else {
    uVar4 = android::BBinder::onTransact(param_1 + 8,param_2,param_3,param_4);
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar4);
}



// non-virtual thunk to android::BnFingerPrintService::onTransact(unsigned int, android::Parcel
// const&, android::Parcel*, unsigned int)

void __thiscall
android::BnFingerPrintService::onTransact
          (BnFingerPrintService *this,uint param_1,Parcel *param_2,Parcel *param_3,uint param_4)

{
  onTransact((int)this - 8,(Parcel *)(ulong)param_1,param_2,(uint)param_3);
  return;
}



// android::IFingerPrintService::IFingerPrintService()

void __thiscall android::IFingerPrintService::IFingerPrintService(IFingerPrintService *this)

{
  long lVar1;
  long *in_x1;
  
  android::IInterface::IInterface((IInterface *)this);
  lVar1 = *in_x1;
  *(long *)this = lVar1;
  *(long *)(this + *(long *)(lVar1 + -0x18)) = in_x1[3];
  return;
}



// android::IFingerPrintService::IFingerPrintService()

void __thiscall android::IFingerPrintService::IFingerPrintService(IFingerPrintService *this)

{
  android::RefBase::RefBase((RefBase *)(this + 8));
                    // try { // try from 00122884 to 00122887 has its CatchHandler @ 001228ac
  android::IInterface::IInterface((IInterface *)this);
  *(undefined8 *)this = 0x161978;
  *(undefined8 *)(this + 8) = 0x1619e0;
  return;
}



// android::IFingerPrintService::~IFingerPrintService()

void __thiscall android::IFingerPrintService::~IFingerPrintService(IFingerPrintService *this)

{
  long *in_x1;
  long lVar1;
  
  lVar1 = *in_x1;
  *(long *)this = lVar1;
  *(long *)(this + *(long *)(lVar1 + -0x18)) = in_x1[3];
  android::IInterface::~IInterface((IInterface *)this);
  return;
}



// BpFingerPrintService::~BpFingerPrintService()

void __thiscall BpFingerPrintService::~BpFingerPrintService(BpFingerPrintService *this)

{
  *(undefined **)this = &DAT_00161678;
  *(undefined **)(this + 0x28) = &DAT_00161720;
  *(undefined **)(this + 8) = &DAT_001616c0;
  android::BpRefBase::~BpRefBase((BpRefBase *)(this + 8));
  android::IFingerPrintService::~IFingerPrintService((IFingerPrintService *)this);
  android::RefBase::~RefBase((RefBase *)(this + 0x28));
  return;
}



// non-virtual thunk to BpFingerPrintService::~BpFingerPrintService()

void __thiscall BpFingerPrintService::~BpFingerPrintService(BpFingerPrintService *this)

{
  ~BpFingerPrintService(this + -8);
  return;
}



// virtual thunk to BpFingerPrintService::~BpFingerPrintService()

void __thiscall BpFingerPrintService::~BpFingerPrintService(BpFingerPrintService *this)

{
  ~BpFingerPrintService(this + *(long *)(*(long *)this + -0x18));
  return;
}



// BpFingerPrintService::~BpFingerPrintService()

void __thiscall BpFingerPrintService::~BpFingerPrintService(BpFingerPrintService *this)

{
  *(undefined **)this = &DAT_00161678;
  *(undefined **)(this + 0x28) = &DAT_00161720;
  *(undefined **)(this + 8) = &DAT_001616c0;
  android::BpRefBase::~BpRefBase((BpRefBase *)(this + 8));
  android::IFingerPrintService::~IFingerPrintService((IFingerPrintService *)this);
  android::RefBase::~RefBase((RefBase *)(this + 0x28));
  operator_delete(this);
  return;
}



// non-virtual thunk to BpFingerPrintService::~BpFingerPrintService()

void __thiscall BpFingerPrintService::~BpFingerPrintService(BpFingerPrintService *this)

{
  ~BpFingerPrintService(this + -8);
  return;
}



// virtual thunk to BpFingerPrintService::~BpFingerPrintService()

void __thiscall BpFingerPrintService::~BpFingerPrintService(BpFingerPrintService *this)

{
  ~BpFingerPrintService(this + *(long *)(*(long *)this + -0x18));
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// android::IFingerPrintService::asInterface(android::sp<android::IBinder> const&)

void android::IFingerPrintService::asInterface(sp *param_1)

{
  long lVar1;
  undefined8 *puVar2;
  long *plVar3;
  long *plVar4;
  long **in_x8;
  long *local_10;
  
  lVar1 = ___stack_chk_guard;
  puVar2 = *(undefined8 **)param_1;
  *in_x8 = (long *)0x0;
  if (puVar2 != (undefined8 *)0x0) {
                    // try { // try from 00122a40 to 00122a43 has its CatchHandler @ 00122be0
    (**(code **)*puVar2)(puVar2,&descriptor);
    if (local_10 != (long *)0x0) {
                    // try { // try from 00122a5c to 00122a7b has its CatchHandler @ 00122bbc
      android::RefBase::incStrong((void *)((long)local_10 + *(long *)(*local_10 + -0x18)));
    }
    plVar3 = *in_x8;
    if (plVar3 != (long *)0x0) {
      android::RefBase::decStrong((void *)((long)plVar3 + *(long *)(*plVar3 + -0x18)));
    }
    *in_x8 = local_10;
    if (local_10 != (long *)0x0) {
      android::RefBase::decStrong((void *)((long)local_10 + *(long *)(*local_10 + -0x18)));
      local_10 = *in_x8;
    }
    if (local_10 == (long *)0x0) {
                    // try { // try from 00122ad4 to 00122ad7 has its CatchHandler @ 00122be0
      plVar3 = (long *)operator_new(0x38);
                    // try { // try from 00122ae4 to 00122ae7 has its CatchHandler @ 00122bb4
      android::RefBase::RefBase((RefBase *)(plVar3 + 5));
                    // try { // try from 00122af8 to 00122afb has its CatchHandler @ 00122bac
      IFingerPrintService((IFingerPrintService *)plVar3);
                    // try { // try from 00122b0c to 00122b0f has its CatchHandler @ 00122b64
      android::BpRefBase::BpRefBase((BpRefBase *)(plVar3 + 1),(sp *)&PTR_DAT_00161780);
      *plVar3 = 0x1617c8;
      plVar3[5] = 0x161870;
      plVar3[1] = 0x161810;
                    // try { // try from 00122b38 to 00122b57 has its CatchHandler @ 00122be0
      android::RefBase::incStrong(plVar3 + 5);
      plVar4 = *in_x8;
      if (plVar4 != (long *)0x0) {
        android::RefBase::decStrong((void *)((long)plVar4 + *(long *)(*plVar4 + -0x18)));
      }
      *in_x8 = plVar3;
    }
  }
  if (lVar1 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



// android::IFingerPrintService::~IFingerPrintService()

void __thiscall android::IFingerPrintService::~IFingerPrintService(IFingerPrintService *this)

{
  *(undefined8 *)this = 0x161978;
  *(undefined8 *)(this + 8) = 0x1619e0;
  android::IInterface::~IInterface((IInterface *)this);
  android::RefBase::~RefBase((RefBase *)(this + 8));
  return;
}



// virtual thunk to android::IFingerPrintService::~IFingerPrintService()

void __thiscall android::IFingerPrintService::~IFingerPrintService(IFingerPrintService *this)

{
  ~IFingerPrintService(this + *(long *)(*(long *)this + -0x18));
  return;
}



// android::IFingerPrintService::~IFingerPrintService()

void __thiscall android::IFingerPrintService::~IFingerPrintService(IFingerPrintService *this)

{
  ~IFingerPrintService(this);
  operator_delete(this);
  return;
}



// virtual thunk to android::IFingerPrintService::~IFingerPrintService()

void __thiscall android::IFingerPrintService::~IFingerPrintService(IFingerPrintService *this)

{
  ~IFingerPrintService(this + *(long *)(*(long *)this + -0x18));
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00122c74(undefined8 param_1,undefined8 param_2)

{
  undefined4 uVar1;
  int iVar2;
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
  undefined4 local_10;
  undefined local_c;
  long local_8;
  
  local_68 = 0;
  uStack_60 = 0;
  local_8 = ___stack_chk_guard;
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
  local_c = 0;
  uVar1 = property_get(param_1,&local_68,0);
  __android_log_print(3,"FingerGoodix","getprop[%s] return: %d, prop: %s",param_1,uVar1,&local_68);
  iVar2 = property_set(param_1,param_2);
  __android_log_print(3,"FingerGoodix","setprop[%s] to \'%s\', return: %d",param_1,param_2,iVar2);
  if (iVar2 != 0) {
    __android_log_print(6,"FingerGoodix","Failed to setprop[%s]",param_1);
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



// WARNING: Unknown calling convention -- yet parameter storage is locked
// check_sys_prop()

undefined8 check_sys_prop(void)

{
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// WARNING: Unknown calling convention -- yet parameter storage is locked
// disable_goodix_fp_with_sys_prop()

void disable_goodix_fp_with_sys_prop(void)

{
  ulong uVar1;
  undefined4 uVar2;
  int iVar3;
  char *pcVar4;
  undefined8 local_c8;
  undefined8 uStack_c0;
  undefined8 local_b8;
  undefined8 uStack_b0;
  undefined8 local_a8;
  undefined8 uStack_a0;
  undefined8 local_98;
  undefined8 uStack_90;
  undefined8 local_88;
  undefined8 uStack_80;
  undefined8 local_78;
  undefined4 local_70;
  undefined local_6c;
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
  undefined4 local_10;
  undefined local_c;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  local_c8 = 0;
  uStack_c0 = 0;
  local_b8 = 0;
  uStack_b0 = 0;
  local_a8 = 0;
  uStack_a0 = 0;
  local_98 = 0;
  uStack_90 = 0;
  local_88 = 0;
  uStack_80 = 0;
  local_78 = 0;
  local_70 = 0;
  local_6c = 0;
  uVar2 = property_get("persist.sys.fp.vendor",&local_c8,0);
  __android_log_print(3,"FingerGoodix","getprop[%s] return: %d, prop: %s","persist.sys.fp.vendor",
                      uVar2,&local_c8);
  iVar3 = strcmp((char *)&local_c8,"goodix");
  if (iVar3 != 0) {
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
    local_c = 0;
    uVar2 = property_get("ro.bootmode",&local_68,0);
    __android_log_print(3,"FingerGoodix","getprop[%s] return: %d, prop: %s","ro.bootmode",uVar2,
                        &local_68);
    pcVar4 = strstr((char *)&local_68,"ffbm");
    if (pcVar4 == (char *)0x0) {
      FUN_00122c74("persist.sys.fp.vendor","switchf");
    }
    else {
      FUN_00122c74("persist.sys.fp.vendor",&DAT_00140e28);
    }
  }
  uVar1 = (ulong)local_68 >> 8;
  local_68 = CONCAT71((uint7)uVar1 & 0xffffffffffff00,0x30);
  FUN_00122c74("persist.sys.fp.goodix",&local_68);
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// WARNING: Unknown calling convention -- yet parameter storage is locked
// enable_goodix_fp_with_sys_prop()

void enable_goodix_fp_with_sys_prop(void)

{
  undefined2 local_10 [4];
  long local_8;
  
  local_10[0] = 0x31;
  local_8 = ___stack_chk_guard;
  FUN_00122c74("persist.sys.fp.goodix",local_10);
  FUN_00122c74("persist.sys.fp.vendor","goodix");
  local_10[0] = 0x31;
  FUN_00122c74("persist.sys.fp.onstart",local_10);
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void writeDataToRecordFile(undefined4 *param_1)

{
  int iVar1;
  int __fd;
  tm *ptVar2;
  undefined4 local_b8;
  undefined4 local_b4;
  time_t local_b0;
  long local_a8;
  undefined auStack_a0 [128];
  long local_20;
  long lStack_18;
  undefined4 local_10;
  undefined local_c;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix",
                      "writeDataToRecordFile: Index = %d , score = %d,id = %d,update=%d,size= %d\n",
                      *param_1,param_1[1],param_1[4],param_1[5],param_1[0xa8]);
  stat("/sdcard/MIUI/debug_log/1.dat",(stat *)auStack_a0);
  __android_log_print(3,"FingerGoodix","writeDataToRecordFile-->size:%lld\n",auStack_a0._48_8_);
  if (1000000 < (long)auStack_a0._48_8_) {
    __android_log_print(3,"FingerGoodix","writeDataToRecordFile:bak");
    remove("/sdcard/MIUI/debug_log/2.dat");
    rename("/sdcard/MIUI/debug_log/1.dat","/sdcard/MIUI/debug_log/2.dat");
  }
  __fd = open("/sdcard/MIUI/debug_log/1.dat",0x441,0x1ff);
  local_10 = 0;
  local_c = 0;
  local_20 = 0;
  lStack_18 = 0;
  local_b8 = 0;
  local_b0 = time((time_t *)0x0);
  ptVar2 = localtime(&local_b0);
  snprintf(auStack_a0 + 0x80,0x15,"%04d%02d%02d%02d%02d%02d",(ulong)(ptVar2->tm_year + 0x76c),
           (ulong)(ptVar2->tm_mon + 1),(ulong)(uint)ptVar2->tm_mday,(ulong)(uint)ptVar2->tm_hour,
           (ulong)(uint)ptVar2->tm_min,ptVar2->tm_sec);
  if (param_1[4] == 0) {
    local_b8 = 0;
  }
  else {
    iVar1 = param_1[1];
    param_1[1] = iVar1 + 300;
    if ((param_1[5] == 1) && (0x14a < iVar1 + 300)) {
      local_b8 = 2;
    }
    else {
      local_b8 = 1;
    }
  }
  if (__fd < 1) {
    __android_log_print(6,"FingerGoodix","%s open file failed","writeDataToRecordFile");
  }
  else {
    local_a8 = atol(auStack_a0 + 0x80);
    local_b4 = 0;
    __android_log_print(3,"FingerGoodix","writeDataToRecordFile-->timestamp:%lld\n",local_a8);
    __android_log_print(3,"FingerGoodix","writeDataToRecordFile-->result:%lld\n",local_b8);
    __android_log_print(3,"FingerGoodix","writeDataToRecordFile-->verifyScore:%lld\n",param_1[1]);
    __android_log_print(3,"FingerGoodix","writeDataToRecordFile-->verifyID:%lld\n",param_1[4]);
    __android_log_print(3,"FingerGoodix","writeDataToRecordFile-->template_size:%lld\n",
                        param_1[0xa8]);
    write(__fd,&local_a8,8);
    write(__fd,&local_b8,4);
    write(__fd,param_1 + 1,4);
    write(__fd,param_1 + 4,4);
    write(__fd,param_1 + 0xa8,4);
    write(__fd,&local_b4,4);
    close(__fd);
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



int setAuthenticateTime(void)

{
  int iVar1;
  
  iVar1 = gettimeofday((timeval *)&start,(__timezone_ptr_t)0x0);
  return iVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void getAuthenticateLastTime(void)

{
  int local_18;
  int local_10;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  gettimeofday((timeval *)&local_18,(__timezone_ptr_t)0x0);
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail((local_10 - (int)_DAT_00175200) + (local_18 - (int)start) * 1000000);
}



// __cxxabiv1::__class_type_info::__do_upcast(__cxxabiv1::__class_type_info const*, void**) const

bool __thiscall
__cxxabiv1::__class_type_info::__do_upcast
          (__class_type_info *this,__class_type_info *param_1,void **param_2)

{
  bool bVar1;
  void *local_18;
  uint local_10;
  undefined4 local_c;
  undefined8 local_8;
  
  local_18 = (void *)0x0;
  local_10 = 0;
  local_c = 0x10;
  local_8 = 0;
  (**(code **)(*(long *)this + 0x30))(this,param_1,*param_2,&local_18);
  bVar1 = (local_10 & 6) == 6;
  if (bVar1) {
    *param_2 = local_18;
  }
  return bVar1;
}



// __cxxabiv1::__class_type_info::__do_find_public_src(long, void const*,
// __cxxabiv1::__class_type_info const*, void const*) const

undefined4 __thiscall
__cxxabiv1::__class_type_info::__do_find_public_src
          (__class_type_info *this,long param_1,void *param_2,__class_type_info *param_3,
          void *param_4)

{
  undefined4 uVar1;
  
  uVar1 = 6;
  if (param_4 != param_2) {
    uVar1 = 1;
  }
  return uVar1;
}



// __cxxabiv1::__class_type_info::~__class_type_info()

void __thiscall __cxxabiv1::__class_type_info::~__class_type_info(__class_type_info *this)

{
  *(undefined ***)this = &PTR____class_type_info_001620d0;
  FUN_00124ab8();
  return;
}



// __cxxabiv1::__class_type_info::~__class_type_info()

void __thiscall __cxxabiv1::__class_type_info::~__class_type_info(__class_type_info *this)

{
  ~__class_type_info(this);
  operator_delete(this);
  return;
}



// __cxxabiv1::__class_type_info::__do_upcast(__cxxabiv1::__class_type_info const*, void const*,
// __cxxabiv1::__class_type_info::__upcast_result&) const

undefined8 __thiscall
__cxxabiv1::__class_type_info::__do_upcast
          (__class_type_info *this,__class_type_info *param_1,void *param_2,__upcast_result *param_3
          )

{
  int iVar1;
  char *__s1;
  
  __s1 = *(char **)(this + 8);
  if (__s1 != *(char **)(param_1 + 8)) {
    if (*__s1 != '*') {
      iVar1 = strcmp(__s1,*(char **)(param_1 + 8));
      if (iVar1 == 0) goto LAB_001233fc;
    }
    return 0;
  }
LAB_001233fc:
  *(void **)param_3 = param_2;
  *(undefined8 *)(param_3 + 0x10) = 0x10;
  *(undefined4 *)(param_3 + 8) = 6;
  return 1;
}



// __cxxabiv1::__class_type_info::__do_catch(std::type_info const*, void**, unsigned int) const

undefined __thiscall
__cxxabiv1::__class_type_info::__do_catch
          (__class_type_info *this,type_info *param_1,void **param_2,uint param_3)

{
  undefined uVar1;
  int iVar2;
  char *__s1;
  
  __s1 = *(char **)(this + 8);
  if (__s1 == *(char **)(param_1 + 8)) {
    return 1;
  }
  if ((*__s1 != '*') && (iVar2 = strcmp(__s1,*(char **)(param_1 + 8)), iVar2 == 0)) {
    return 1;
  }
  if (3 < param_3) {
    return 0;
  }
  uVar1 = (**(code **)(*(long *)param_1 + 0x28))(param_1,this,param_2);
  return uVar1;
}



// __cxxabiv1::__class_type_info::__do_dyncast(long, __cxxabiv1::__class_type_info::__sub_kind,
// __cxxabiv1::__class_type_info const*, void const*, __cxxabiv1::__class_type_info const*, void
// const*, __cxxabiv1::__class_type_info::__dyncast_result&) const

undefined8 __thiscall
__cxxabiv1::__class_type_info::__do_dyncast
          (__class_type_info *this,long param_1,__sub_kind param_2,__class_type_info *param_3,
          void *param_4,__class_type_info *param_5,void *param_6,__dyncast_result *param_7)

{
  int iVar1;
  char *__s2;
  char *__s1;
  
  __s1 = *(char **)(this + 8);
  if (param_4 == param_6) {
    if (__s1 == *(char **)(param_5 + 8)) {
LAB_001235a8:
      *(__sub_kind *)(param_7 + 0xc) = param_2;
      return 0;
    }
    if (*__s1 == '*') {
      if (__s1 != *(char **)(param_3 + 8)) {
        return 0;
      }
      goto LAB_00123588;
    }
    iVar1 = strcmp(__s1,*(char **)(param_5 + 8));
    if (iVar1 == 0) goto LAB_001235a8;
    __s2 = *(char **)(param_3 + 8);
    if (__s1 == __s2) goto LAB_00123588;
  }
  else {
    __s2 = *(char **)(param_3 + 8);
    if (__s1 == __s2) goto LAB_00123588;
    if (*__s1 == '*') {
      return 0;
    }
  }
  iVar1 = strcmp(__s1,__s2);
  if (iVar1 != 0) {
    return 0;
  }
LAB_00123588:
  *(void **)param_7 = param_4;
  *(__sub_kind *)(param_7 + 8) = param_2;
  *(undefined4 *)(param_7 + 0x10) = 1;
  return 0;
}



// operator delete(void*)

void operator_delete(void *param_1)

{
  free(param_1);
  return;
}



char * FUN_001235d0(void)

{
  return "__gnu_cxx::__concurrence_lock_error";
}



char * FUN_001235dc(void)

{
  return "__gnu_cxx::__concurrence_unlock_error";
}



void FUN_001235e8(undefined8 *param_1)

{
  *param_1 = &PTR_FUN_0015cfc0;
  std::exception::~exception((exception *)param_1);
  return;
}



void FUN_001235f8(undefined8 *param_1)

{
  *param_1 = &PTR_FUN_0015cff0;
  std::exception::~exception((exception *)param_1);
  return;
}



void FUN_00123608(undefined8 *param_1)

{
  *param_1 = &PTR_FUN_0015cfc0;
  std::exception::~exception((exception *)param_1);
  operator_delete(param_1);
  return;
}



void FUN_00123638(undefined8 *param_1)

{
  *param_1 = &PTR_FUN_0015cff0;
  std::exception::~exception((exception *)param_1);
  operator_delete(param_1);
  return;
}



void FUN_00123668(void)

{
  undefined8 *puVar1;
  
  puVar1 = (undefined8 *)__cxa_allocate_exception(8);
  *puVar1 = &PTR_FUN_0015cfc0;
                    // WARNING: Subroutine does not return
  __cxa_throw(puVar1,&PTR_PTR____si_class_type_info_00162120,FUN_001235e8);
}



void FUN_00123698(void)

{
  undefined8 *puVar1;
  
  puVar1 = (undefined8 *)__cxa_allocate_exception(8);
  *puVar1 = &PTR_FUN_0015cff0;
                    // WARNING: Subroutine does not return
  __cxa_throw(puVar1,&PTR_PTR____si_class_type_info_00162138,FUN_001235f8);
}



undefined8 * __cxa_allocate_exception(long param_1)

{
  uint uVar1;
  int iVar2;
  undefined8 *puVar3;
  ulong uVar4;
  long extraout_x1;
  ulong uVar5;
  
  puVar3 = (undefined8 *)malloc(param_1 + 0x80U);
  if (puVar3 != (undefined8 *)0x0) {
LAB_001236ec:
    *puVar3 = 0;
    puVar3[1] = 0;
    puVar3[2] = 0;
    puVar3[3] = 0;
    puVar3[4] = 0;
    puVar3[5] = 0;
    puVar3[6] = 0;
    puVar3[7] = 0;
    puVar3[8] = 0;
    puVar3[9] = 0;
    puVar3[10] = 0;
    puVar3[0xb] = 0;
    puVar3[0xc] = 0;
    puVar3[0xd] = 0;
    puVar3[0xe] = 0;
    puVar3[0xf] = 0;
    return puVar3 + 0x10;
  }
                    // try { // try from 00123734 to 00123737 has its CatchHandler @ 001237a8
  iVar2 = pthread_mutex_lock((pthread_mutex_t *)&DAT_00164f20);
  if (iVar2 == 0) {
    if (param_1 + 0x80U < 0x401) {
      uVar5 = 0;
      uVar4 = DAT_00174f50;
      do {
        if ((uVar4 & 1) == 0) {
          DAT_00174f50 = 1L << (uVar5 & 0x3f) | DAT_00174f50;
          puVar3 = &DAT_00164f50 + uVar5 * 0x80;
                    // try { // try from 0012379c to 001237a7 has its CatchHandler @ 001237bc
          iVar2 = pthread_mutex_unlock((pthread_mutex_t *)&DAT_00164f20);
          if (iVar2 == 0) goto LAB_001236ec;
          FUN_00123698();
                    // catch() { ... } // from try @ 00123734 with catch @ 001237a8
                    // catch() { ... } // from try @ 001237b4 with catch @ 001237a8
          if (extraout_x1 != -1) {
                    // WARNING: Subroutine does not return
            _Unwind_Resume();
          }
          goto LAB_001237b8;
        }
        uVar1 = (int)uVar5 + 1;
        uVar5 = (ulong)uVar1;
        uVar4 = uVar4 >> 1;
      } while (uVar1 != 0x40);
    }
                    // WARNING: Subroutine does not return
    std::terminate();
  }
                    // try { // try from 001237b4 to 001237b7 has its CatchHandler @ 001237a8
  FUN_00123668();
LAB_001237b8:
                    // WARNING: Subroutine does not return
  __cxa_call_unexpected();
}



// WARNING: Removing unreachable block (ram,0x0012384c)

void __cxa_free_exception(undefined8 *param_1)

{
  int iVar1;
  long extraout_x1;
  long lVar2;
  long extraout_x1_00;
  
  if ((param_1 < &DAT_00164f50) || ((undefined8 *)0x174f4f < param_1)) {
    free(param_1 + -0x10);
    return;
  }
                    // try { // try from 00123804 to 00123807 has its CatchHandler @ 00123884
  iVar1 = pthread_mutex_lock((pthread_mutex_t *)&DAT_00164f20);
  if (iVar1 == 0) {
    DAT_00174f50 = DAT_00174f50 &
                   (1L << ((ulong)(param_1 + -0x2c9ea) >> 10 & 0x3f) ^ 0xffffffffffffffffU);
                    // try { // try from 00123828 to 00123873 has its CatchHandler @ 00123874
    iVar1 = pthread_mutex_unlock((pthread_mutex_t *)&DAT_00164f20);
    if (iVar1 == 0) {
      return;
    }
    FUN_00123698();
    lVar2 = extraout_x1;
  }
  else {
                    // try { // try from 00123880 to 00123883 has its CatchHandler @ 00123884
    FUN_00123668();
    lVar2 = extraout_x1_00;
                    // catch() { ... } // from try @ 00123804 with catch @ 00123884
                    // catch() { ... } // from try @ 00123880 with catch @ 00123884
  }
                    // catch() { ... } // from try @ 00123828 with catch @ 00123874
  if (lVar2 == -1) {
                    // WARNING: Subroutine does not return
    __cxa_call_unexpected();
  }
                    // WARNING: Subroutine does not return
  _Unwind_Resume();
}



undefined8 * __cxa_allocate_dependent_exception(void)

{
  uint uVar1;
  int iVar2;
  undefined8 *puVar3;
  ulong uVar4;
  ulong uVar5;
  long extraout_x1;
  
  puVar3 = (undefined8 *)malloc(0x70);
  if (puVar3 != (undefined8 *)0x0) {
LAB_001238a8:
    *puVar3 = 0;
    puVar3[1] = 0;
    puVar3[2] = 0;
    puVar3[3] = 0;
    puVar3[4] = 0;
    puVar3[5] = 0;
    puVar3[6] = 0;
    puVar3[7] = 0;
    puVar3[8] = 0;
    puVar3[9] = 0;
    puVar3[10] = 0;
    puVar3[0xb] = 0;
    puVar3[0xc] = 0;
    puVar3[0xd] = 0;
    return puVar3;
  }
                    // try { // try from 001238e8 to 001238eb has its CatchHandler @ 0012396c
  iVar2 = pthread_mutex_lock((pthread_mutex_t *)&DAT_00164f20);
  if (iVar2 == 0) {
    uVar4 = 0;
    uVar5 = DAT_00163318;
    while ((uVar5 & 1) != 0) {
      uVar1 = (int)uVar4 + 1;
      uVar4 = (ulong)uVar1;
      uVar5 = uVar5 >> 1;
      if (uVar1 == 0x40) {
                    // WARNING: Subroutine does not return
        std::terminate();
      }
    }
    DAT_00163318 = 1L << (uVar4 & 0x3f) | DAT_00163318;
    puVar3 = &DAT_00163320 + uVar4 * 0xe;
                    // try { // try from 00123950 to 0012395b has its CatchHandler @ 00123960
    iVar2 = pthread_mutex_unlock((pthread_mutex_t *)&DAT_00164f20);
    if (iVar2 == 0) goto LAB_001238a8;
    FUN_00123698();
  }
                    // try { // try from 0012395c to 0012395f has its CatchHandler @ 0012396c
  FUN_00123668();
                    // catch() { ... } // from try @ 00123950 with catch @ 00123960
  if (extraout_x1 == -1) {
                    // WARNING: Subroutine does not return
    __cxa_call_unexpected();
  }
                    // WARNING: Subroutine does not return
  _Unwind_Resume();
}



// WARNING: Removing unreachable block (ram,0x00123a14)

void __cxa_free_dependent_exception(undefined8 *param_1)

{
  int iVar1;
  long extraout_x1;
  long lVar2;
  long extraout_x1_00;
  
  if ((param_1 < &DAT_00163320) || ((undefined8 *)0x164f1f < param_1)) {
    free(param_1);
    return;
  }
                    // try { // try from 001239d0 to 001239d3 has its CatchHandler @ 00123a4c
  iVar1 = pthread_mutex_lock((pthread_mutex_t *)&DAT_00164f20);
  if (iVar1 == 0) {
    DAT_00163318 = DAT_00163318 &
                   (1L << (SUB168(ZEXT416((int)param_1 - 0x163320U >> 4) *
                                  ZEXT816(0x2492492492492494),8) & 0x3f) ^ 0xffffffffffffffffU);
                    // try { // try from 001239f4 to 00123a3b has its CatchHandler @ 00123a3c
    iVar1 = pthread_mutex_unlock((pthread_mutex_t *)&DAT_00164f20);
    if (iVar1 == 0) {
      return;
    }
    FUN_00123698();
    lVar2 = extraout_x1;
  }
  else {
                    // try { // try from 00123a48 to 00123a4b has its CatchHandler @ 00123a4c
    FUN_00123668();
    lVar2 = extraout_x1_00;
                    // catch() { ... } // from try @ 001239d0 with catch @ 00123a4c
                    // catch() { ... } // from try @ 00123a48 with catch @ 00123a4c
  }
                    // catch() { ... } // from try @ 001239f4 with catch @ 00123a3c
  if (lVar2 == -1) {
                    // WARNING: Subroutine does not return
    __cxa_call_unexpected();
  }
                    // WARNING: Subroutine does not return
  _Unwind_Resume();
}



// std::exception::~exception()

void __thiscall std::exception::~exception(exception *this)

{
  return;
}



// std::bad_exception::~bad_exception()

void __thiscall std::bad_exception::~bad_exception(bad_exception *this)

{
  *(undefined ***)this = &PTR__bad_exception_001621d0;
  exception::~exception((exception *)this);
  return;
}



// std::exception::what() const

char * std::exception::what(void)

{
  return "std::exception";
}



// std::bad_exception::what() const

char * std::bad_exception::what(void)

{
  return "std::bad_exception";
}



// std::exception::~exception()

void __thiscall std::exception::~exception(exception *this)

{
  ~exception(this);
  operator_delete(this);
  return;
}



// std::bad_exception::~bad_exception()

void __thiscall std::bad_exception::~bad_exception(bad_exception *this)

{
  ~bad_exception(this);
  operator_delete(this);
  return;
}



// __cxxabiv1::__forced_unwind::~__forced_unwind()

void __thiscall __cxxabiv1::__forced_unwind::~__forced_unwind(__forced_unwind *this)

{
  return;
}



// __cxxabiv1::__forced_unwind::~__forced_unwind()

void __thiscall __cxxabiv1::__forced_unwind::~__forced_unwind(__forced_unwind *this)

{
  ~__forced_unwind(this);
  operator_delete(this);
  return;
}



// __cxxabiv1::__foreign_exception::~__foreign_exception()

void __thiscall __cxxabiv1::__foreign_exception::~__foreign_exception(__foreign_exception *this)

{
  return;
}



// __cxxabiv1::__foreign_exception::~__foreign_exception()

void __thiscall __cxxabiv1::__foreign_exception::~__foreign_exception(__foreign_exception *this)

{
  ~__foreign_exception(this);
  operator_delete(this);
  return;
}



void FUN_00123b1c(byte *param_1,ulong *param_2)

{
  uint uVar1;
  byte bVar2;
  ulong uVar3;
  ulong uVar4;
  ulong uVar5;
  
  uVar5 = 0;
  uVar4 = 0;
  do {
    bVar2 = *param_1;
    uVar3 = uVar4 & 0x3f;
    uVar1 = (int)uVar4 + 7;
    uVar4 = (ulong)uVar1;
    uVar5 = uVar5 | ((ulong)bVar2 & 0x7f) << uVar3;
    param_1 = param_1 + 1;
  } while ((char)bVar2 < '\0');
  if ((uVar1 < 0x40) && ((bVar2 >> 6 & 1) != 0)) {
    uVar5 = -1L << (uVar4 & 0x3f) | uVar5;
  }
  *param_2 = uVar5;
  return;
}



ulong * FUN_00123b5c(byte param_1,ulong *param_2,ulong *param_3,ulong *param_4)

{
  byte bVar1;
  ulong uVar2;
  ulong *puVar3;
  ulong *puVar4;
  ulong uVar5;
  ulong *local_8;
  
  if (param_1 != 0x50) {
    switch(param_1 & 0xf) {
    case 0:
    case 4:
    case 0xc:
      puVar4 = param_3 + 1;
      local_8 = (ulong *)*param_3;
      break;
    case 1:
      local_8 = (ulong *)0x0;
      uVar5 = 0;
      puVar3 = param_3;
      do {
        puVar4 = (ulong *)((long)puVar3 + 1);
        bVar1 = *(byte *)puVar3;
        uVar2 = uVar5 & 0x3f;
        uVar5 = (ulong)((int)uVar5 + 7);
        local_8 = (ulong *)((ulong)local_8 | ((ulong)bVar1 & 0x7f) << uVar2);
        puVar3 = puVar4;
      } while ((char)bVar1 < '\0');
      break;
    case 2:
      puVar4 = (ulong *)((long)param_3 + 2);
      local_8 = (ulong *)(ulong)*(ushort *)param_3;
      break;
    case 3:
      puVar4 = (ulong *)((long)param_3 + 4);
      local_8 = (ulong *)(ulong)*(uint *)param_3;
      break;
    default:
                    // WARNING: Subroutine does not return
      abort();
    case 9:
      puVar4 = (ulong *)FUN_00123b1c(param_3,&local_8);
      break;
    case 10:
      puVar4 = (ulong *)((long)param_3 + 2);
      local_8 = (ulong *)(long)*(short *)param_3;
      break;
    case 0xb:
      puVar4 = (ulong *)((long)param_3 + 4);
      local_8 = (ulong *)(long)(int)*(uint *)param_3;
    }
    if (local_8 != (ulong *)0x0) {
      if ((param_1 & 0x70) != 0x10) {
        param_3 = param_2;
      }
      local_8 = (ulong *)((long)local_8 + (long)param_3);
      if ((char)param_1 < '\0') {
        local_8 = (ulong *)*local_8;
      }
    }
    *param_4 = (ulong)local_8;
    return puVar4;
  }
  puVar4 = (ulong *)((long)param_3 + 7U & 0xfffffffffffffff8);
  *param_4 = *puVar4;
  return puVar4 + 1;
}



undefined8 FUN_00123c6c(byte param_1,undefined8 param_2)

{
  byte bVar1;
  undefined8 uVar2;
  
  if (param_1 == 0xff) {
    return 0;
  }
  bVar1 = param_1 & 0x70;
  if (bVar1 == 0x20) {
    uVar2 = _Unwind_GetTextRelBase(param_2);
    return uVar2;
  }
  if (bVar1 < 0x21) {
    if ((param_1 & 0x70) == 0) {
      return 0;
    }
    if (bVar1 == 0x10) {
      return 0;
    }
  }
  else {
    if (bVar1 == 0x40) {
      uVar2 = _Unwind_GetRegionStart(param_2);
      return uVar2;
    }
    if (bVar1 == 0x50) {
      return 0;
    }
    if (bVar1 == 0x30) {
      uVar2 = _Unwind_GetDataRelBase(param_2);
      return uVar2;
    }
  }
                    // WARNING: Subroutine does not return
  abort();
}



void FUN_00123ce8(long param_1,char *param_2,undefined8 *param_3)

{
  byte bVar1;
  char cVar2;
  ulong uVar3;
  undefined8 uVar4;
  char *pcVar5;
  byte *pbVar6;
  byte *pbVar7;
  ulong uVar8;
  ulong uVar9;
  
  if (param_1 == 0) {
    uVar4 = 0;
  }
  else {
    uVar4 = _Unwind_GetRegionStart();
  }
  *param_3 = uVar4;
  cVar2 = *param_2;
  if (cVar2 == -1) {
    param_3[1] = uVar4;
    pbVar6 = (byte *)(param_2 + 2);
    cVar2 = param_2[1];
    *(char *)(param_3 + 5) = cVar2;
  }
  else {
    uVar4 = FUN_00123c6c(cVar2,param_1);
    pcVar5 = (char *)FUN_00123b5c(cVar2,uVar4,param_2 + 1,param_3 + 1);
    pbVar6 = (byte *)(pcVar5 + 1);
    cVar2 = *pcVar5;
    *(char *)(param_3 + 5) = cVar2;
  }
  if (cVar2 == -1) {
    param_3[3] = 0;
  }
  else {
    uVar9 = 0;
    uVar8 = 0;
    pbVar7 = pbVar6;
    do {
      pbVar6 = pbVar7 + 1;
      bVar1 = *pbVar7;
      uVar3 = uVar8 & 0x3f;
      uVar8 = (ulong)((int)uVar8 + 7);
      uVar9 = uVar9 | ((ulong)bVar1 & 0x7f) << uVar3;
      pbVar7 = pbVar6;
    } while ((char)bVar1 < '\0');
    param_3[3] = pbVar6 + uVar9;
  }
  uVar9 = 0;
  *(byte *)((long)param_3 + 0x29) = *pbVar6;
  uVar8 = 0;
  pbVar6 = pbVar6 + 1;
  do {
    pbVar7 = pbVar6 + 1;
    bVar1 = *pbVar6;
    uVar3 = uVar8 & 0x3f;
    uVar8 = (ulong)((int)uVar8 + 7);
    uVar9 = uVar9 | ((ulong)bVar1 & 0x7f) << uVar3;
    pbVar6 = pbVar7;
  } while ((char)bVar1 < '\0');
  param_3[4] = pbVar7 + uVar9;
  return;
}



char FUN_00123df4(long param_1,long *param_2,long **param_3,ulong param_4)

{
  byte bVar1;
  ulong uVar2;
  long **pplVar3;
  char cVar4;
  ulong uVar5;
  ulong uVar6;
  long lVar7;
  byte *pbVar8;
  long **local_8;
  byte *pbVar9;
  
  pbVar8 = (byte *)(*(long *)(param_1 + 0x18) + ~param_4);
  do {
    uVar6 = 0;
    uVar5 = 0;
    pbVar9 = pbVar8;
    do {
      pbVar8 = pbVar9 + 1;
      bVar1 = *pbVar9;
      uVar2 = uVar5 & 0x3f;
      uVar5 = (ulong)((int)uVar5 + 7);
      uVar6 = uVar6 | ((ulong)bVar1 & 0x7f) << uVar2;
      pbVar9 = pbVar8;
    } while ((char)bVar1 < '\0');
    if (uVar6 == 0) {
      return '\0';
    }
    bVar1 = *(byte *)(param_1 + 0x28);
    if (bVar1 == 0xff) {
      lVar7 = 0;
    }
    else {
      switch(bVar1 & 7) {
      case 0:
      case 4:
        lVar7 = uVar6 * -8;
        break;
      default:
                    // WARNING: Subroutine does not return
        abort();
      case 2:
        lVar7 = uVar6 * -2;
        break;
      case 3:
        lVar7 = uVar6 * -4;
      }
    }
    FUN_00123b5c(bVar1,*(undefined8 *)(param_1 + 0x10),*(long *)(param_1 + 0x18) + lVar7,&local_8);
    pplVar3 = local_8;
    local_8 = param_3;
    cVar4 = (**(code **)(*param_2 + 0x10))(param_2);
    if (cVar4 != '\0') {
      local_8 = (long **)*local_8;
    }
    cVar4 = (*(code *)(*pplVar3)[4])(pplVar3,param_2,&local_8,1);
  } while (cVar4 == '\0');
  return cVar4;
}



undefined8
__gxx_personality_v0(int param_1,uint param_2,long param_3,ulong *param_4,undefined8 param_5)

{
  bool bVar1;
  bool bVar2;
  ulong **ppuVar3;
  undefined uVar4;
  byte bVar5;
  char cVar6;
  int iVar7;
  ulong uVar8;
  byte *pbVar9;
  undefined8 uVar10;
  undefined8 uVar11;
  byte *pbVar12;
  long lVar13;
  long lVar14;
  ulong uVar15;
  ulong uVar16;
  ulong uVar17;
  undefined **local_70;
  ulong **local_68;
  ulong local_60;
  int local_4c;
  int local_48;
  undefined4 uStack_44;
  long local_40;
  ulong **local_38;
  long local_30;
  long local_28;
  undefined8 local_20;
  long local_18;
  byte *local_10;
  byte local_8;
  undefined local_7;
  
  local_4c = 0;
  if (param_1 != 1) {
    return 3;
  }
  bVar1 = 1 < param_3 + 0xb8b1aabcbcd4d500U;
  if ((param_2 == 6) <= bVar1) {
    local_60 = _Unwind_GetLanguageSpecificData(param_5);
    if (local_60 == 0) {
      return 8;
    }
    pbVar9 = (byte *)FUN_00123ce8(param_5,local_60,&local_30);
    local_20 = FUN_00123c6c(local_8,param_5);
    lVar13 = _Unwind_GetIPInfo(param_5,&local_4c);
    uVar17 = lVar13 - (ulong)(local_4c == 0);
    if (pbVar9 < local_10) {
      do {
        uVar4 = local_7;
        uVar10 = FUN_00123c6c(local_7,0);
        uVar10 = FUN_00123b5c(uVar4,uVar10,pbVar9,&local_48);
        uVar4 = local_7;
        uVar11 = FUN_00123c6c(local_7,0);
        uVar10 = FUN_00123b5c(uVar4,uVar11,uVar10,&local_40);
        uVar4 = local_7;
        uVar11 = FUN_00123c6c(local_7,0);
        pbVar12 = (byte *)FUN_00123b5c(uVar4,uVar11,uVar10,&local_38);
        uVar15 = 0;
        uVar8 = 0;
        do {
          pbVar9 = pbVar12 + 1;
          bVar5 = *pbVar12;
          uVar16 = uVar8 & 0x3f;
          uVar8 = (ulong)((int)uVar8 + 7);
          uVar15 = uVar15 | ((ulong)bVar5 & 0x7f) << uVar16;
          pbVar12 = pbVar9;
        } while ((char)bVar5 < '\0');
        uVar8 = CONCAT44(uStack_44,local_48) + local_30;
        if (uVar17 < uVar8) break;
        if (uVar17 < uVar8 + local_40) {
          if (local_38 == (ulong **)0x0) {
            return 8;
          }
          uVar17 = (long)local_38 + local_28;
          if (uVar15 == 0) {
            if (uVar17 == 0) {
              return 8;
            }
          }
          else {
            if (uVar17 == 0) {
              return 8;
            }
            local_10 = local_10 + (uVar15 - 1);
            if (local_10 != (byte *)0x0) {
              if ((param_2 >> 3 & 1) == 0) {
                if (bVar1) {
                  local_68 = (ulong **)0x0;
                  local_70 = &__cxxabiv1::__foreign_exception::typeinfo;
                }
                else {
                  local_68 = (ulong **)(param_4 + 4);
                  if ((*param_4 & 1) != 0) {
                    local_68 = (ulong **)param_4[-10];
                  }
                  local_70 = (undefined **)local_68[-0xe];
                }
              }
              else {
                local_68 = (ulong **)0x0;
                local_70 = &__cxxabiv1::__forced_unwind::typeinfo;
              }
              bVar2 = false;
              goto LAB_0012428c;
            }
          }
          iVar7 = 2;
          goto LAB_00124198;
        }
      } while (pbVar9 < local_10);
    }
    uVar17 = 0;
    iVar7 = 1;
LAB_00124198:
    local_68 = (ulong **)0x0;
    local_48 = 0;
    local_10 = (byte *)0x0;
    goto LAB_001241a4;
  }
  local_60 = param_4[-3];
  uVar17 = param_4[-2];
  local_48 = *(int *)((long)param_4 + -0x24);
  if (uVar17 == 0) {
    if ((param_2 >> 3 & 1) != 0) {
                    // WARNING: Subroutine does not return
      std::terminate();
    }
LAB_00123fcc:
    FUN_0012a3b4(param_4);
  }
  if ((param_2 >> 3 & 1) == 0) {
LAB_00124038:
    if (local_48 < 0) {
      FUN_00123ce8(param_5,local_60,&local_30);
      local_20 = FUN_00123c6c(local_8,param_5);
      uVar8 = FUN_00123c6c(local_8,param_5);
      param_4[-2] = uVar8;
    }
    goto LAB_00123fdc;
  }
  goto LAB_00123fd8;
LAB_0012428c:
  lVar13 = FUN_00123b1c(local_10,&local_48);
  FUN_00123b1c(lVar13,&local_40);
  uVar8 = CONCAT44(uStack_44,local_48);
  if (uVar8 == 0) {
    bVar2 = true;
  }
  else if ((long)uVar8 < 1) {
    if (bVar1 < (local_70 != (undefined **)0x0 && (param_2 & 8) == 0)) {
      bVar5 = FUN_00123df4(&local_30,local_70,local_68);
      bVar5 = bVar5 ^ 1;
    }
    else {
      uVar16 = 0;
      uVar15 = 0;
      pbVar9 = (byte *)(local_18 + ~uVar8);
      do {
        bVar5 = *pbVar9;
        uVar8 = uVar15 & 0x3f;
        uVar15 = (ulong)((int)uVar15 + 7);
        uVar16 = uVar16 | ((ulong)bVar5 & 0x7f) << uVar8;
        pbVar9 = pbVar9 + 1;
      } while ((char)bVar5 < '\0');
      bVar5 = uVar16 == 0;
    }
    if (bVar5 != 0) {
LAB_001243f0:
      iVar7 = 3;
      goto LAB_001241a4;
    }
  }
  else {
    if (local_8 == 0xff) {
      lVar14 = 0;
    }
    else {
      switch(local_8 & 7) {
      case 0:
      case 4:
        lVar14 = uVar8 * -8;
        break;
      default:
                    // WARNING: Subroutine does not return
        abort();
      case 2:
        lVar14 = uVar8 * -2;
        break;
      case 3:
        lVar14 = uVar8 * -4;
      }
    }
    FUN_00123b5c(local_8,local_20,local_18 + lVar14,&local_38);
    ppuVar3 = local_38;
    if (local_38 == (ulong **)0x0) goto LAB_001243f0;
    if (local_70 != (undefined **)0x0) {
      local_38 = local_68;
      cVar6 = (**(code **)(*local_70 + 0x10))(local_70);
      if (cVar6 != '\0') {
        local_38 = (ulong **)*local_38;
      }
      cVar6 = (*(code *)(*ppuVar3)[4])(ppuVar3,local_70,&local_38,1);
      if (cVar6 != '\0') {
        local_68 = local_38;
        goto LAB_001243f0;
      }
    }
  }
  if (local_40 == 0) goto LAB_00124444;
  local_10 = (byte *)(lVar13 + local_40);
  goto LAB_0012428c;
LAB_00124444:
  if (!bVar2) {
    return 8;
  }
  local_48 = 0;
  iVar7 = 2;
LAB_001241a4:
  if ((param_2 & 1) != 0) {
    if (iVar7 == 2) {
      return 8;
    }
    if (!bVar1) {
      param_4[-3] = local_60;
      *(int *)((long)param_4 + -0x24) = local_48;
      param_4[-4] = (ulong)local_10;
      param_4[-1] = (ulong)local_68;
      param_4[-2] = uVar17;
      return 6;
    }
    return 6;
  }
  if (((param_2 >> 3 & 1) == 0) && (!bVar1)) {
    if (iVar7 == 1) goto LAB_00123fcc;
    goto LAB_00124038;
  }
  if (iVar7 == 1) {
                    // WARNING: Subroutine does not return
    std::terminate();
  }
LAB_00123fd8:
  if (local_48 < 0) {
                    // try { // try from 0012446c to 0012446f has its CatchHandler @ 001241f8
    lVar13 = std::unexpected();
    __cxa_begin_catch();
                    // WARNING: Subroutine does not return
    __cxxabiv1::__unexpected(*(_func_void **)(lVar13 + -0x40));
  }
LAB_00123fdc:
  _Unwind_SetGR(param_5,0,param_4);
  _Unwind_SetGR(param_5,1,(long)local_48);
  _Unwind_SetIP(param_5,uVar17);
  return 7;
}



void __cxa_call_unexpected(long param_1)

{
  __cxa_begin_catch();
                    // WARNING: Subroutine does not return
                    // try { // try from 001244a4 to 001244a7 has its CatchHandler @ 001244a8
  __cxxabiv1::__unexpected(*(_func_void **)(param_1 + -0x40));
}



// __cxxabiv1::__terminate(void (*)())

void __cxxabiv1::__terminate(_func_void *param_1)

{
                    // try { // try from 00124568 to 0012456f has its CatchHandler @ 00124570
  (*param_1)();
                    // WARNING: Subroutine does not return
  abort();
}



// WARNING: Unknown calling convention -- yet parameter storage is locked
// std::set_terminate(void (*)())

undefined * std::set_terminate(_func_void *param_1)

{
  char cVar1;
  bool bVar2;
  undefined *puVar3;
  
  do {
    puVar3 = __cxxabiv1::__terminate_handler;
    cVar1 = '\x01';
    bVar2 = (bool)ExclusiveMonitorPass(&__cxxabiv1::__terminate_handler,0x10);
    if (bVar2) {
      cVar1 = ExclusiveMonitorsStatus();
      __cxxabiv1::__terminate_handler = param_1;
    }
  } while (cVar1 != '\0');
  return puVar3;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked
// std::get_terminate()

undefined * std::get_terminate(void)

{
  return __cxxabiv1::__terminate_handler;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked
// std::terminate()

void std::terminate(void)

{
  _func_void *p_Var1;
  
  p_Var1 = (_func_void *)get_terminate();
                    // WARNING: Subroutine does not return
  __cxxabiv1::__terminate(p_Var1);
}



// __cxxabiv1::__unexpected(void (*)())

void __cxxabiv1::__unexpected(_func_void *param_1)

{
  (*param_1)();
                    // WARNING: Subroutine does not return
  std::terminate();
}



// WARNING: Unknown calling convention -- yet parameter storage is locked
// std::set_unexpected(void (*)())

undefined * std::set_unexpected(_func_void *param_1)

{
  char cVar1;
  bool bVar2;
  undefined *puVar3;
  
  do {
    puVar3 = __cxxabiv1::__unexpected_handler;
    cVar1 = '\x01';
    bVar2 = (bool)ExclusiveMonitorPass(&__cxxabiv1::__unexpected_handler,0x10);
    if (bVar2) {
      cVar1 = ExclusiveMonitorsStatus();
      __cxxabiv1::__unexpected_handler = param_1;
    }
  } while (cVar1 != '\0');
  return puVar3;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked
// std::get_unexpected()

undefined * std::get_unexpected(void)

{
  return __cxxabiv1::__unexpected_handler;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked
// std::unexpected()

void std::unexpected(void)

{
  _func_void *p_Var1;
  
  p_Var1 = (_func_void *)get_unexpected();
                    // WARNING: Subroutine does not return
  __cxxabiv1::__unexpected(p_Var1);
}



void FUN_00124624(uint param_1,long param_2)

{
  int iVar1;
  char cVar2;
  bool bVar3;
  int *piVar4;
  
  if (1 < param_1) {
                    // WARNING: Subroutine does not return
    __cxxabiv1::__terminate(*(_func_void **)(param_2 + -0x38));
  }
  piVar4 = (int *)(param_2 + -0x60);
  do {
    iVar1 = *piVar4;
    cVar2 = '\x01';
    bVar3 = (bool)ExclusiveMonitorPass(piVar4,0x10);
    if (bVar3) {
      *piVar4 = iVar1 + -1;
      cVar2 = ExclusiveMonitorsStatus();
    }
  } while (cVar2 != '\0');
  if (iVar1 + -1 == 0) {
    if (*(code **)(param_2 + -0x48) != (code *)0x0) {
      (**(code **)(param_2 + -0x48))(param_2 + 0x20);
    }
    __cxa_free_exception(param_2 + 0x20);
    return;
  }
  return;
}



void __cxa_throw(long param_1,undefined8 param_2,undefined8 param_3)

{
  long lVar1;
  undefined8 uVar2;
  
  lVar1 = __cxa_get_globals();
  *(int *)(lVar1 + 8) = *(int *)(lVar1 + 8) + 1;
  *(undefined8 *)(param_1 + -0x68) = param_3;
  *(undefined8 *)(param_1 + -0x70) = param_2;
  *(undefined4 *)(param_1 + -0x80) = 1;
  uVar2 = std::get_unexpected();
  *(undefined8 *)(param_1 + -0x60) = uVar2;
  uVar2 = std::get_terminate();
  *(undefined8 *)(param_1 + -0x58) = uVar2;
  *(undefined8 *)(param_1 + -0x20) = 0x474e5543432b2b00;
  *(code **)(param_1 + -0x18) = FUN_00124624;
  _Unwind_RaiseException(param_1 + -0x20);
  __cxa_begin_catch(param_1 + -0x20);
                    // WARNING: Subroutine does not return
  std::terminate();
}



void __cxa_rethrow(void)

{
  long *plVar1;
  long lVar2;
  
  plVar1 = (long *)__cxa_get_globals();
  lVar2 = *plVar1;
  *(int *)(plVar1 + 1) = *(int *)(plVar1 + 1) + 1;
  if (lVar2 != 0) {
    if (*(long *)(lVar2 + 0x50) + 0xb8b1aabcbcd4d500U < 2) {
      *(int *)(lVar2 + 0x28) = -*(int *)(lVar2 + 0x28);
    }
    else {
      *plVar1 = 0;
    }
    _Unwind_Resume_or_Rethrow(lVar2 + 0x50);
    __cxa_begin_catch(lVar2 + 0x50);
  }
                    // WARNING: Subroutine does not return
  std::terminate();
}



// operator new(unsigned long)

void * operator_new(ulong param_1)

{
  void *pvVar1;
  code *pcVar2;
  undefined8 *puVar3;
  
  if (param_1 == 0) {
    param_1 = 1;
  }
  pvVar1 = malloc(param_1);
  while( true ) {
    if (pvVar1 != (void *)0x0) {
      return pvVar1;
    }
    pcVar2 = (code *)std::get_new_handler();
    if (pcVar2 == (code *)0x0) break;
    (*pcVar2)();
    pvVar1 = malloc(param_1);
  }
  puVar3 = (undefined8 *)__cxa_allocate_exception(8);
  *puVar3 = &PTR__bad_alloc_001623d0;
                    // WARNING: Subroutine does not return
  __cxa_throw(puVar3,&std::bad_alloc::typeinfo,std::bad_alloc::~bad_alloc);
}



void __cxa_pure_virtual(void)

{
  write(2,"pure virtual method called\n",0x1b);
                    // WARNING: Subroutine does not return
  std::terminate();
}



void __cxa_deleted_virtual(void)

{
  write(2,"deleted virtual method called\n",0x1e);
                    // WARNING: Subroutine does not return
  std::terminate();
}



// __cxxabiv1::__si_class_type_info::~__si_class_type_info()

void __thiscall __cxxabiv1::__si_class_type_info::~__si_class_type_info(__si_class_type_info *this)

{
  *(undefined ***)this = &PTR____si_class_type_info_00162280;
  __class_type_info::~__class_type_info((__class_type_info *)this);
  return;
}



// __cxxabiv1::__si_class_type_info::~__si_class_type_info()

void __thiscall __cxxabiv1::__si_class_type_info::~__si_class_type_info(__si_class_type_info *this)

{
  ~__si_class_type_info(this);
  operator_delete(this);
  return;
}



// __cxxabiv1::__si_class_type_info::__do_dyncast(long, __cxxabiv1::__class_type_info::__sub_kind,
// __cxxabiv1::__class_type_info const*, void const*, __cxxabiv1::__class_type_info const*, void
// const*, __cxxabiv1::__class_type_info::__dyncast_result&) const

undefined __thiscall
__cxxabiv1::__si_class_type_info::__do_dyncast
          (__si_class_type_info *this,long param_1,__sub_kind param_2,__class_type_info *param_3,
          void *param_4,__class_type_info *param_5,void *param_6,__dyncast_result *param_7)

{
  char cVar1;
  undefined uVar2;
  int iVar3;
  undefined4 uVar4;
  char *__s1;
  
  __s1 = *(char **)(this + 8);
  if (__s1 == *(char **)(param_3 + 8)) {
LAB_00124910:
    *(void **)param_7 = param_4;
    *(__sub_kind *)(param_7 + 8) = param_2;
    if (-1 < param_1) {
      uVar4 = 6;
      if (param_6 != (void *)((long)param_4 + param_1)) {
        uVar4 = 1;
      }
      *(undefined4 *)(param_7 + 0x10) = uVar4;
      return 0;
    }
    uVar2 = 0;
    if (param_1 == -2) {
      *(undefined4 *)(param_7 + 0x10) = 1;
    }
  }
  else {
    cVar1 = *__s1;
    if (cVar1 != '*') {
      iVar3 = strcmp(__s1,*(char **)(param_3 + 8));
      if (iVar3 == 0) goto LAB_00124910;
    }
    if (param_4 == param_6) {
      if (__s1 == *(char **)(param_5 + 8)) {
LAB_001249ac:
        *(__sub_kind *)(param_7 + 0xc) = param_2;
        return 0;
      }
      if (cVar1 != '*') {
        iVar3 = strcmp(__s1,*(char **)(param_5 + 8));
        if (iVar3 == 0) goto LAB_001249ac;
      }
    }
    uVar2 = (**(code **)(**(long **)(this + 0x10) + 0x38))
                      (*(long **)(this + 0x10),param_1,param_2,param_3,param_4,param_5,param_6);
  }
  return uVar2;
}



// __cxxabiv1::__si_class_type_info::__do_find_public_src(long, void const*,
// __cxxabiv1::__class_type_info const*, void const*) const

undefined4 __thiscall
__cxxabiv1::__si_class_type_info::__do_find_public_src
          (__si_class_type_info *this,long param_1,void *param_2,__class_type_info *param_3,
          void *param_4)

{
  undefined4 uVar1;
  int iVar2;
  char *__s1;
  
  if (param_4 == param_2) {
    __s1 = *(char **)(this + 8);
    if (__s1 == *(char **)(param_3 + 8)) {
      return 6;
    }
    if ((*__s1 != '*') && (iVar2 = strcmp(__s1,*(char **)(param_3 + 8)), iVar2 == 0)) {
      return 6;
    }
  }
  uVar1 = (**(code **)(**(long **)(this + 0x10) + 0x40))
                    (*(long **)(this + 0x10),param_1,param_2,param_3,param_4);
  return uVar1;
}



// __cxxabiv1::__si_class_type_info::__do_upcast(__cxxabiv1::__class_type_info const*, void const*,
// __cxxabiv1::__class_type_info::__upcast_result&) const

char __thiscall
__cxxabiv1::__si_class_type_info::__do_upcast
          (__si_class_type_info *this,__class_type_info *param_1,void *param_2,
          __upcast_result *param_3)

{
  char cVar1;
  
  cVar1 = __class_type_info::__do_upcast((__class_type_info *)this,param_1,param_2,param_3);
  if (cVar1 == '\0') {
    cVar1 = (**(code **)(**(long **)(this + 0x10) + 0x30))
                      (*(long **)(this + 0x10),param_1,param_2,param_3);
  }
  return cVar1;
}



void FUN_00124ab8(void)

{
  return;
}



undefined8 FUN_00124abc(void)

{
  return 0;
}



undefined8 FUN_00124ac4(void)

{
  return 0;
}



undefined8 FUN_00124acc(void)

{
  return 0;
}



void operator_delete(void *param_1)

{
  free(param_1);
  return;
}



bool FUN_00124ad8(long param_1,long param_2)

{
  int iVar1;
  char *__s1;
  
  __s1 = *(char **)(param_1 + 8);
  if (__s1 == *(char **)(param_2 + 8)) {
    return true;
  }
  if (*__s1 != '*') {
    iVar1 = strcmp(__s1,*(char **)(param_2 + 8));
    return iVar1 == 0;
  }
  return false;
}



undefined8 FUN_00124b28(long param_1)

{
  return *(undefined8 *)(param_1 + 8);
}



undefined8 FUN_00124b30(long param_1)

{
  return *(undefined8 *)(param_1 + 8);
}



// WARNING: Removing unreachable block (ram,0x00124bb4)

void FUN_00124b38(undefined8 *param_1)

{
  int iVar1;
  char cVar2;
  bool bVar3;
  undefined *puVar4;
  int *piVar5;
  
  *param_1 = &PTR_FUN_0015d060;
  puVar4 = (undefined *)(param_1[1] + -0x18);
  if (puVar4 != &DAT_00174f60) {
    piVar5 = (int *)(param_1[1] + -8);
    do {
      iVar1 = *piVar5;
      cVar2 = '\x01';
      bVar3 = (bool)ExclusiveMonitorPass(piVar5,0x10);
      if (bVar3) {
        *piVar5 = iVar1 + -1;
        cVar2 = ExclusiveMonitorsStatus();
      }
    } while (cVar2 != '\0');
    if (iVar1 < 1) {
      operator_delete(puVar4);
    }
  }
  std::exception::~exception((exception *)param_1);
  return;
}



// WARNING: Removing unreachable block (ram,0x00124c40)

void FUN_00124bc4(undefined8 *param_1)

{
  int iVar1;
  char cVar2;
  bool bVar3;
  undefined *puVar4;
  int *piVar5;
  
  *param_1 = &PTR_FUN_0015d150;
  puVar4 = (undefined *)(param_1[1] + -0x18);
  if (puVar4 != &DAT_00174f60) {
    piVar5 = (int *)(param_1[1] + -8);
    do {
      iVar1 = *piVar5;
      cVar2 = '\x01';
      bVar3 = (bool)ExclusiveMonitorPass(piVar5,0x10);
      if (bVar3) {
        *piVar5 = iVar1 + -1;
        cVar2 = ExclusiveMonitorsStatus();
      }
    } while (cVar2 != '\0');
    if (iVar1 < 1) {
      operator_delete(puVar4);
    }
  }
  std::exception::~exception((exception *)param_1);
  return;
}



// WARNING: Removing unreachable block (ram,0x00124ccc)

void FUN_00124c50(undefined8 *param_1)

{
  int iVar1;
  char cVar2;
  bool bVar3;
  undefined *puVar4;
  int *piVar5;
  
  *param_1 = &PTR_FUN_0015d150;
  puVar4 = (undefined *)(param_1[1] + -0x18);
  if (puVar4 != &DAT_00174f60) {
    piVar5 = (int *)(param_1[1] + -8);
    do {
      iVar1 = *piVar5;
      cVar2 = '\x01';
      bVar3 = (bool)ExclusiveMonitorPass(piVar5,0x10);
      if (bVar3) {
        *piVar5 = iVar1 + -1;
        cVar2 = ExclusiveMonitorsStatus();
      }
    } while (cVar2 != '\0');
    if (iVar1 < 1) {
      operator_delete(puVar4);
    }
  }
  std::exception::~exception((exception *)param_1);
  return;
}



// WARNING: Removing unreachable block (ram,0x00124d58)

void FUN_00124cdc(undefined8 *param_1)

{
  int iVar1;
  char cVar2;
  bool bVar3;
  undefined *puVar4;
  int *piVar5;
  
  *param_1 = &PTR_FUN_0015d150;
  puVar4 = (undefined *)(param_1[1] + -0x18);
  if (puVar4 != &DAT_00174f60) {
    piVar5 = (int *)(param_1[1] + -8);
    do {
      iVar1 = *piVar5;
      cVar2 = '\x01';
      bVar3 = (bool)ExclusiveMonitorPass(piVar5,0x10);
      if (bVar3) {
        *piVar5 = iVar1 + -1;
        cVar2 = ExclusiveMonitorsStatus();
      }
    } while (cVar2 != '\0');
    if (iVar1 < 1) {
      operator_delete(puVar4);
    }
  }
  std::exception::~exception((exception *)param_1);
  return;
}



// WARNING: Removing unreachable block (ram,0x00124de4)

void FUN_00124d68(undefined8 *param_1)

{
  int iVar1;
  char cVar2;
  bool bVar3;
  undefined *puVar4;
  int *piVar5;
  
  *param_1 = &PTR_FUN_0015d150;
  puVar4 = (undefined *)(param_1[1] + -0x18);
  if (puVar4 != &DAT_00174f60) {
    piVar5 = (int *)(param_1[1] + -8);
    do {
      iVar1 = *piVar5;
      cVar2 = '\x01';
      bVar3 = (bool)ExclusiveMonitorPass(piVar5,0x10);
      if (bVar3) {
        *piVar5 = iVar1 + -1;
        cVar2 = ExclusiveMonitorsStatus();
      }
    } while (cVar2 != '\0');
    if (iVar1 < 1) {
      operator_delete(puVar4);
    }
  }
  std::exception::~exception((exception *)param_1);
  return;
}



// WARNING: Removing unreachable block (ram,0x00124e70)

void FUN_00124df4(undefined8 *param_1)

{
  int iVar1;
  char cVar2;
  bool bVar3;
  undefined *puVar4;
  int *piVar5;
  
  *param_1 = &PTR_FUN_0015d060;
  puVar4 = (undefined *)(param_1[1] + -0x18);
  if (puVar4 != &DAT_00174f60) {
    piVar5 = (int *)(param_1[1] + -8);
    do {
      iVar1 = *piVar5;
      cVar2 = '\x01';
      bVar3 = (bool)ExclusiveMonitorPass(piVar5,0x10);
      if (bVar3) {
        *piVar5 = iVar1 + -1;
        cVar2 = ExclusiveMonitorsStatus();
      }
    } while (cVar2 != '\0');
    if (iVar1 < 1) {
      operator_delete(puVar4);
    }
  }
  std::exception::~exception((exception *)param_1);
  return;
}



// WARNING: Removing unreachable block (ram,0x00124efc)

void FUN_00124e80(undefined8 *param_1)

{
  int iVar1;
  char cVar2;
  bool bVar3;
  undefined *puVar4;
  int *piVar5;
  
  *param_1 = &PTR_FUN_0015d060;
  puVar4 = (undefined *)(param_1[1] + -0x18);
  if (puVar4 != &DAT_00174f60) {
    piVar5 = (int *)(param_1[1] + -8);
    do {
      iVar1 = *piVar5;
      cVar2 = '\x01';
      bVar3 = (bool)ExclusiveMonitorPass(piVar5,0x10);
      if (bVar3) {
        *piVar5 = iVar1 + -1;
        cVar2 = ExclusiveMonitorsStatus();
      }
    } while (cVar2 != '\0');
    if (iVar1 < 1) {
      operator_delete(puVar4);
    }
  }
  std::exception::~exception((exception *)param_1);
  return;
}



// WARNING: Removing unreachable block (ram,0x00124f88)

void FUN_00124f0c(undefined8 *param_1)

{
  int iVar1;
  char cVar2;
  bool bVar3;
  undefined *puVar4;
  int *piVar5;
  
  *param_1 = &PTR_FUN_0015d060;
  puVar4 = (undefined *)(param_1[1] + -0x18);
  if (puVar4 != &DAT_00174f60) {
    piVar5 = (int *)(param_1[1] + -8);
    do {
      iVar1 = *piVar5;
      cVar2 = '\x01';
      bVar3 = (bool)ExclusiveMonitorPass(piVar5,0x10);
      if (bVar3) {
        *piVar5 = iVar1 + -1;
        cVar2 = ExclusiveMonitorsStatus();
      }
    } while (cVar2 != '\0');
    if (iVar1 < 1) {
      operator_delete(puVar4);
    }
  }
  std::exception::~exception((exception *)param_1);
  return;
}



// WARNING: Removing unreachable block (ram,0x00125014)

void FUN_00124f98(undefined8 *param_1)

{
  int iVar1;
  char cVar2;
  bool bVar3;
  undefined *puVar4;
  int *piVar5;
  
  *param_1 = &PTR_FUN_0015d060;
  puVar4 = (undefined *)(param_1[1] + -0x18);
  if (puVar4 != &DAT_00174f60) {
    piVar5 = (int *)(param_1[1] + -8);
    do {
      iVar1 = *piVar5;
      cVar2 = '\x01';
      bVar3 = (bool)ExclusiveMonitorPass(piVar5,0x10);
      if (bVar3) {
        *piVar5 = iVar1 + -1;
        cVar2 = ExclusiveMonitorsStatus();
      }
    } while (cVar2 != '\0');
    if (iVar1 < 1) {
      operator_delete(puVar4);
    }
  }
  std::exception::~exception((exception *)param_1);
  return;
}



// WARNING: Removing unreachable block (ram,0x001250a8)

void FUN_00125024(undefined8 *param_1)

{
  int iVar1;
  char cVar2;
  bool bVar3;
  undefined *puVar4;
  int *piVar5;
  
  *param_1 = &PTR_FUN_0015d150;
  puVar4 = (undefined *)(param_1[1] + -0x18);
  if (puVar4 != &DAT_00174f60) {
    piVar5 = (int *)(param_1[1] + -8);
    do {
      iVar1 = *piVar5;
      cVar2 = '\x01';
      bVar3 = (bool)ExclusiveMonitorPass(piVar5,0x10);
      if (bVar3) {
        *piVar5 = iVar1 + -1;
        cVar2 = ExclusiveMonitorsStatus();
      }
    } while (cVar2 != '\0');
    if (iVar1 < 1) {
      operator_delete(puVar4);
    }
  }
  std::exception::~exception((exception *)param_1);
  operator_delete(param_1);
  return;
}



// WARNING: Removing unreachable block (ram,0x0012513c)

void FUN_001250b8(undefined8 *param_1)

{
  int iVar1;
  char cVar2;
  bool bVar3;
  undefined *puVar4;
  int *piVar5;
  
  *param_1 = &PTR_FUN_0015d150;
  puVar4 = (undefined *)(param_1[1] + -0x18);
  if (puVar4 != &DAT_00174f60) {
    piVar5 = (int *)(param_1[1] + -8);
    do {
      iVar1 = *piVar5;
      cVar2 = '\x01';
      bVar3 = (bool)ExclusiveMonitorPass(piVar5,0x10);
      if (bVar3) {
        *piVar5 = iVar1 + -1;
        cVar2 = ExclusiveMonitorsStatus();
      }
    } while (cVar2 != '\0');
    if (iVar1 < 1) {
      operator_delete(puVar4);
    }
  }
  std::exception::~exception((exception *)param_1);
  operator_delete(param_1);
  return;
}



// WARNING: Removing unreachable block (ram,0x001251d0)

void FUN_0012514c(undefined8 *param_1)

{
  int iVar1;
  char cVar2;
  bool bVar3;
  undefined *puVar4;
  int *piVar5;
  
  *param_1 = &PTR_FUN_0015d150;
  puVar4 = (undefined *)(param_1[1] + -0x18);
  if (puVar4 != &DAT_00174f60) {
    piVar5 = (int *)(param_1[1] + -8);
    do {
      iVar1 = *piVar5;
      cVar2 = '\x01';
      bVar3 = (bool)ExclusiveMonitorPass(piVar5,0x10);
      if (bVar3) {
        *piVar5 = iVar1 + -1;
        cVar2 = ExclusiveMonitorsStatus();
      }
    } while (cVar2 != '\0');
    if (iVar1 < 1) {
      operator_delete(puVar4);
    }
  }
  std::exception::~exception((exception *)param_1);
  operator_delete(param_1);
  return;
}



// WARNING: Removing unreachable block (ram,0x00125264)

void FUN_001251e0(undefined8 *param_1)

{
  int iVar1;
  char cVar2;
  bool bVar3;
  undefined *puVar4;
  int *piVar5;
  
  *param_1 = &PTR_FUN_0015d150;
  puVar4 = (undefined *)(param_1[1] + -0x18);
  if (puVar4 != &DAT_00174f60) {
    piVar5 = (int *)(param_1[1] + -8);
    do {
      iVar1 = *piVar5;
      cVar2 = '\x01';
      bVar3 = (bool)ExclusiveMonitorPass(piVar5,0x10);
      if (bVar3) {
        *piVar5 = iVar1 + -1;
        cVar2 = ExclusiveMonitorsStatus();
      }
    } while (cVar2 != '\0');
    if (iVar1 < 1) {
      operator_delete(puVar4);
    }
  }
  std::exception::~exception((exception *)param_1);
  operator_delete(param_1);
  return;
}



// WARNING: Removing unreachable block (ram,0x001252f8)

void FUN_00125274(undefined8 *param_1)

{
  int iVar1;
  char cVar2;
  bool bVar3;
  undefined *puVar4;
  int *piVar5;
  
  *param_1 = &PTR_FUN_0015d060;
  puVar4 = (undefined *)(param_1[1] + -0x18);
  if (puVar4 != &DAT_00174f60) {
    piVar5 = (int *)(param_1[1] + -8);
    do {
      iVar1 = *piVar5;
      cVar2 = '\x01';
      bVar3 = (bool)ExclusiveMonitorPass(piVar5,0x10);
      if (bVar3) {
        *piVar5 = iVar1 + -1;
        cVar2 = ExclusiveMonitorsStatus();
      }
    } while (cVar2 != '\0');
    if (iVar1 < 1) {
      operator_delete(puVar4);
    }
  }
  std::exception::~exception((exception *)param_1);
  operator_delete(param_1);
  return;
}



// WARNING: Removing unreachable block (ram,0x0012538c)

void FUN_00125308(undefined8 *param_1)

{
  int iVar1;
  char cVar2;
  bool bVar3;
  undefined *puVar4;
  int *piVar5;
  
  *param_1 = &PTR_FUN_0015d060;
  puVar4 = (undefined *)(param_1[1] + -0x18);
  if (puVar4 != &DAT_00174f60) {
    piVar5 = (int *)(param_1[1] + -8);
    do {
      iVar1 = *piVar5;
      cVar2 = '\x01';
      bVar3 = (bool)ExclusiveMonitorPass(piVar5,0x10);
      if (bVar3) {
        *piVar5 = iVar1 + -1;
        cVar2 = ExclusiveMonitorsStatus();
      }
    } while (cVar2 != '\0');
    if (iVar1 < 1) {
      operator_delete(puVar4);
    }
  }
  std::exception::~exception((exception *)param_1);
  operator_delete(param_1);
  return;
}



// WARNING: Removing unreachable block (ram,0x00125420)

void FUN_0012539c(undefined8 *param_1)

{
  int iVar1;
  char cVar2;
  bool bVar3;
  undefined *puVar4;
  int *piVar5;
  
  *param_1 = &PTR_FUN_0015d060;
  puVar4 = (undefined *)(param_1[1] + -0x18);
  if (puVar4 != &DAT_00174f60) {
    piVar5 = (int *)(param_1[1] + -8);
    do {
      iVar1 = *piVar5;
      cVar2 = '\x01';
      bVar3 = (bool)ExclusiveMonitorPass(piVar5,0x10);
      if (bVar3) {
        *piVar5 = iVar1 + -1;
        cVar2 = ExclusiveMonitorsStatus();
      }
    } while (cVar2 != '\0');
    if (iVar1 < 1) {
      operator_delete(puVar4);
    }
  }
  std::exception::~exception((exception *)param_1);
  operator_delete(param_1);
  return;
}



// WARNING: Removing unreachable block (ram,0x001254b4)

void FUN_00125430(undefined8 *param_1)

{
  int iVar1;
  char cVar2;
  bool bVar3;
  undefined *puVar4;
  int *piVar5;
  
  *param_1 = &PTR_FUN_0015d060;
  puVar4 = (undefined *)(param_1[1] + -0x18);
  if (puVar4 != &DAT_00174f60) {
    piVar5 = (int *)(param_1[1] + -8);
    do {
      iVar1 = *piVar5;
      cVar2 = '\x01';
      bVar3 = (bool)ExclusiveMonitorPass(piVar5,0x10);
      if (bVar3) {
        *piVar5 = iVar1 + -1;
        cVar2 = ExclusiveMonitorsStatus();
      }
    } while (cVar2 != '\0');
    if (iVar1 < 1) {
      operator_delete(puVar4);
    }
  }
  std::exception::~exception((exception *)param_1);
  operator_delete(param_1);
  return;
}



// WARNING: Removing unreachable block (ram,0x00125548)

void FUN_001254c4(undefined8 *param_1)

{
  int iVar1;
  char cVar2;
  bool bVar3;
  undefined *puVar4;
  int *piVar5;
  
  *param_1 = &PTR_FUN_0015d060;
  puVar4 = (undefined *)(param_1[1] + -0x18);
  if (puVar4 != &DAT_00174f60) {
    piVar5 = (int *)(param_1[1] + -8);
    do {
      iVar1 = *piVar5;
      cVar2 = '\x01';
      bVar3 = (bool)ExclusiveMonitorPass(piVar5,0x10);
      if (bVar3) {
        *piVar5 = iVar1 + -1;
        cVar2 = ExclusiveMonitorsStatus();
      }
    } while (cVar2 != '\0');
    if (iVar1 < 1) {
      operator_delete(puVar4);
    }
  }
  std::exception::~exception((exception *)param_1);
  operator_delete(param_1);
  return;
}



void FUN_00125558(undefined8 *param_1)

{
  *param_1 = &PTR_FUN_0015d060;
                    // try { // try from 00125574 to 00125577 has its CatchHandler @ 00125584
  FUN_001297e4(param_1 + 1);
  return;
}



void FUN_00125598(undefined8 *param_1)

{
  *param_1 = &PTR_FUN_0015d060;
                    // try { // try from 001255b4 to 001255b7 has its CatchHandler @ 001255d0
  FUN_001297e4(param_1 + 1);
  *param_1 = &PTR_FUN_0015d090;
  return;
}



void FUN_001255e4(undefined8 *param_1)

{
  *param_1 = &PTR_FUN_0015d060;
                    // try { // try from 00125600 to 00125603 has its CatchHandler @ 0012561c
  FUN_001297e4(param_1 + 1);
  *param_1 = &PTR_FUN_0015d0c0;
  return;
}



void FUN_00125630(undefined8 *param_1)

{
  *param_1 = &PTR_FUN_0015d060;
                    // try { // try from 0012564c to 0012564f has its CatchHandler @ 00125668
  FUN_001297e4(param_1 + 1);
  *param_1 = &PTR_FUN_0015d0f0;
  return;
}



void FUN_0012567c(undefined8 *param_1)

{
  *param_1 = &PTR_FUN_0015d060;
                    // try { // try from 00125698 to 0012569b has its CatchHandler @ 001256b4
  FUN_001297e4(param_1 + 1);
  *param_1 = &PTR_FUN_0015d120;
  return;
}



void FUN_001256c8(undefined8 *param_1)

{
  *param_1 = &PTR_FUN_0015d150;
                    // try { // try from 001256e4 to 001256e7 has its CatchHandler @ 001256f4
  FUN_001297e4(param_1 + 1);
  return;
}



void FUN_00125708(undefined8 *param_1)

{
  *param_1 = &PTR_FUN_0015d150;
                    // try { // try from 00125724 to 00125727 has its CatchHandler @ 00125740
  FUN_001297e4(param_1 + 1);
  *param_1 = &PTR_FUN_0015d180;
  return;
}



void FUN_00125754(undefined8 *param_1)

{
  *param_1 = &PTR_FUN_0015d150;
                    // try { // try from 00125770 to 00125773 has its CatchHandler @ 0012578c
  FUN_001297e4(param_1 + 1);
  *param_1 = &PTR_FUN_0015d1b0;
  return;
}



void FUN_001257a0(undefined8 *param_1)

{
  *param_1 = &PTR_FUN_0015d150;
                    // try { // try from 001257bc to 001257bf has its CatchHandler @ 001257d8
  FUN_001297e4(param_1 + 1);
  *param_1 = &PTR_FUN_0015d1e0;
  return;
}



// WARNING: Removing unreachable block (ram,0x00125818)

void FUN_001257ec(void *param_1)

{
  int *piVar1;
  int iVar2;
  char cVar3;
  bool bVar4;
  
  piVar1 = (int *)((long)param_1 + 0x10);
  do {
    iVar2 = *piVar1;
    cVar3 = '\x01';
    bVar4 = (bool)ExclusiveMonitorPass(piVar1,0x10);
    if (bVar4) {
      *piVar1 = iVar2 + -1;
      cVar3 = ExclusiveMonitorsStatus();
    }
  } while (cVar3 != '\0');
  if (0 < iVar2) {
    return;
  }
  operator_delete(param_1);
  return;
}



undefined8 FUN_00125830(undefined8 *param_1)

{
  return *param_1;
}



undefined8 FUN_00125838(undefined8 *param_1,undefined8 param_2)

{
  *param_1 = param_2;
  return param_2;
}



long FUN_00125844(long *param_1)

{
  return *param_1 + -0x18;
}



undefined8 FUN_00125850(undefined8 *param_1)

{
  return *param_1;
}



long FUN_00125858(long *param_1)

{
  return *param_1 + *(long *)(*param_1 + -0x18);
}



void FUN_00125868(long *param_1,ulong param_2,undefined8 param_3)

{
  if (param_2 <= *(ulong *)(*param_1 + -0x18)) {
    return;
  }
                    // WARNING: Subroutine does not return
  FUN_0012ace0("%s: __pos (which is %zu) > this->size() (which is %zu)",param_3,param_2);
}



void FUN_001258a0(long *param_1,long param_2,ulong param_3,undefined8 param_4)

{
  if (param_3 <= (ulong)((0x3ffffffffffffff9 - *(long *)(*param_1 + -0x18)) + param_2)) {
    return;
  }
                    // WARNING: Subroutine does not return
  FUN_0012ab78(param_4);
}



ulong FUN_001258d8(long *param_1,long param_2,ulong param_3)

{
  ulong uVar1;
  
  uVar1 = *(long *)(*param_1 + -0x18) - param_2;
  if (param_3 < uVar1) {
    uVar1 = param_3;
  }
  return uVar1;
}



bool FUN_001258f0(ulong *param_1,ulong param_2)

{
  bool bVar1;
  ulong uVar2;
  
  uVar2 = *param_1;
  bVar1 = true;
  if (uVar2 <= param_2) {
    bVar1 = uVar2 + *(long *)(uVar2 - 0x18) < param_2;
  }
  return bVar1;
}



void FUN_00125914(undefined *param_1,undefined *param_2,size_t param_3)

{
  if (param_3 != 1) {
    memcpy(param_1,param_2,param_3);
    return;
  }
  *param_1 = *param_2;
  return;
}



void FUN_00125930(undefined *param_1,undefined *param_2,size_t param_3)

{
  if (param_3 != 1) {
    memmove(param_1,param_2,param_3);
    return;
  }
  *param_1 = *param_2;
  return;
}



void FUN_0012594c(byte *param_1,size_t param_2,byte param_3)

{
  if (param_2 != 1) {
    memset(param_1,(uint)param_3,param_2);
    return;
  }
  *param_1 = param_3;
  return;
}



void FUN_0012596c(undefined *param_1,undefined *param_2,long param_3)

{
  if (param_3 - (long)param_2 != 1) {
    memcpy(param_1,param_2,param_3 - (long)param_2);
    return;
  }
  *param_1 = *param_2;
  return;
}



void FUN_0012598c(undefined *param_1,undefined *param_2,long param_3)

{
  if (param_3 - (long)param_2 != 1) {
    memcpy(param_1,param_2,param_3 - (long)param_2);
    return;
  }
  *param_1 = *param_2;
  return;
}



void FUN_001259ac(undefined *param_1,undefined *param_2,long param_3)

{
  if (param_3 - (long)param_2 != 1) {
    memcpy(param_1,param_2,param_3 - (long)param_2);
    return;
  }
  *param_1 = *param_2;
  return;
}



void FUN_001259cc(undefined *param_1,undefined *param_2,long param_3)

{
  if (param_3 - (long)param_2 != 1) {
    memcpy(param_1,param_2,param_3 - (long)param_2);
    return;
  }
  *param_1 = *param_2;
  return;
}



undefined4 FUN_001259ec(long param_1,long param_2)

{
  undefined4 uVar1;
  
  param_1 = param_1 - param_2;
  if (0x7fffffff < param_1) {
    return 0x7fffffff;
  }
  uVar1 = 0x80000000;
  if (-0x80000001 < param_1) {
    uVar1 = (undefined4)param_1;
  }
  return uVar1;
}



undefined * FUN_00125a14(void)

{
  return &DAT_00174f60;
}



void FUN_00125a20(undefined8 *param_1)

{
  *param_1 = &DAT_00174f78;
  return;
}



void FUN_00125a30(undefined8 *param_1)

{
  *param_1 = &DAT_00174f78;
  return;
}



void FUN_00125a40(ulong **param_1,long *param_2,ulong param_3,ulong param_4)

{
  void *__src;
  void *pvVar1;
  ulong uVar2;
  ulong *puVar3;
  ulong *__dest;
  ulong uVar4;
  long lVar5;
  
  lVar5 = *param_2;
  uVar4 = *(ulong *)(lVar5 + -0x18);
  if (uVar4 < param_3) {
                    // WARNING: Subroutine does not return
    FUN_0012ace0("%s: __pos (which is %zu) > this->size() (which is %zu)",
                 "basic_string::basic_string",param_3,uVar4);
  }
  __src = (void *)(lVar5 + param_3);
  uVar2 = uVar4 - param_3;
  if (param_4 < uVar4 - param_3) {
    uVar2 = param_4;
  }
  pvVar1 = (void *)(lVar5 + uVar2 + param_3);
  if (__src == pvVar1) {
    *param_1 = (ulong *)&DAT_00174f78;
    return;
  }
  if ((pvVar1 != (void *)0x0) && (__src == (void *)0x0)) {
                    // WARNING: Subroutine does not return
    FUN_0012a95c("basic_string::_S_construct null not valid");
  }
  uVar4 = (long)pvVar1 - (long)__src;
  if (0x3ffffffffffffff9 < uVar4) {
                    // WARNING: Subroutine does not return
    FUN_0012ab78("basic_string::_S_create");
  }
  if ((uVar4 + 0x39 < 0x1001) || (uVar4 == 0)) {
    puVar3 = (ulong *)operator_new(uVar4 + 0x19);
    puVar3[1] = uVar4;
    *(undefined4 *)(puVar3 + 2) = 0;
    __dest = puVar3 + 3;
    if (uVar4 == 1) {
      *(undefined *)(puVar3 + 3) = *(undefined *)(lVar5 + param_3);
      goto LAB_00125b14;
    }
  }
  else {
    uVar2 = (uVar4 + 0x1000) - (uVar4 + 0x39 & 0xfff);
    if (0x3ffffffffffffff9 < uVar2) {
      uVar2 = 0x3ffffffffffffff9;
    }
    puVar3 = (ulong *)operator_new(uVar2 + 0x19);
    __dest = puVar3 + 3;
    puVar3[1] = uVar2;
    *(undefined4 *)(puVar3 + 2) = 0;
  }
  __dest = (ulong *)memcpy(__dest,__src,uVar4);
LAB_00125b14:
  if (puVar3 != (ulong *)&DAT_00174f60) {
    *puVar3 = uVar4;
    *(undefined *)((long)puVar3 + uVar4 + 0x18) = 0;
  }
  *param_1 = __dest;
  return;
}



void FUN_00125bbc(ulong **param_1,long *param_2,ulong param_3,ulong param_4)

{
  void *__src;
  void *pvVar1;
  ulong uVar2;
  ulong *puVar3;
  ulong *__dest;
  ulong uVar4;
  long lVar5;
  
  lVar5 = *param_2;
  uVar4 = *(ulong *)(lVar5 + -0x18);
  if (uVar4 < param_3) {
                    // WARNING: Subroutine does not return
    FUN_0012ace0("%s: __pos (which is %zu) > this->size() (which is %zu)",
                 "basic_string::basic_string",param_3,uVar4);
  }
  __src = (void *)(lVar5 + param_3);
  uVar2 = uVar4 - param_3;
  if (param_4 < uVar4 - param_3) {
    uVar2 = param_4;
  }
  pvVar1 = (void *)(lVar5 + uVar2 + param_3);
  if (__src == pvVar1) {
    *param_1 = (ulong *)&DAT_00174f78;
    return;
  }
  if ((pvVar1 != (void *)0x0) && (__src == (void *)0x0)) {
                    // WARNING: Subroutine does not return
    FUN_0012a95c("basic_string::_S_construct null not valid");
  }
  uVar4 = (long)pvVar1 - (long)__src;
  if (0x3ffffffffffffff9 < uVar4) {
                    // WARNING: Subroutine does not return
    FUN_0012ab78("basic_string::_S_create");
  }
  if ((uVar4 + 0x39 < 0x1001) || (uVar4 == 0)) {
    puVar3 = (ulong *)operator_new(uVar4 + 0x19);
    puVar3[1] = uVar4;
    *(undefined4 *)(puVar3 + 2) = 0;
    __dest = puVar3 + 3;
    if (uVar4 == 1) {
      *(undefined *)(puVar3 + 3) = *(undefined *)(lVar5 + param_3);
      goto LAB_00125c90;
    }
  }
  else {
    uVar2 = (uVar4 + 0x1000) - (uVar4 + 0x39 & 0xfff);
    if (0x3ffffffffffffff9 < uVar2) {
      uVar2 = 0x3ffffffffffffff9;
    }
    puVar3 = (ulong *)operator_new(uVar2 + 0x19);
    __dest = puVar3 + 3;
    puVar3[1] = uVar2;
    *(undefined4 *)(puVar3 + 2) = 0;
  }
  __dest = (ulong *)memcpy(__dest,__src,uVar4);
LAB_00125c90:
  if (puVar3 != (ulong *)&DAT_00174f60) {
    *puVar3 = uVar4;
    *(undefined *)((long)puVar3 + uVar4 + 0x18) = 0;
  }
  *param_1 = __dest;
  return;
}



void FUN_00125d38(ulong **param_1,undefined *param_2,ulong param_3)

{
  ulong uVar1;
  ulong *puVar2;
  ulong *__dest;
  
  if (param_2 == param_2 + param_3) {
    *param_1 = (ulong *)&DAT_00174f78;
    return;
  }
  if ((param_2 + param_3 != (undefined *)0x0) && (param_2 == (undefined *)0x0)) {
                    // WARNING: Subroutine does not return
    FUN_0012a95c("basic_string::_S_construct null not valid");
  }
  if (0x3ffffffffffffff9 < param_3) {
                    // WARNING: Subroutine does not return
    FUN_0012ab78("basic_string::_S_create");
  }
  if (param_3 - 0xfc8 < 0xffffffffffffefff) {
    uVar1 = (param_3 + 0x1000) - (param_3 + 0x39 & 0xfff);
    if (0x3ffffffffffffff9 < uVar1) {
      uVar1 = 0x3ffffffffffffff9;
    }
    puVar2 = (ulong *)operator_new(uVar1 + 0x19);
    __dest = puVar2 + 3;
    puVar2[1] = uVar1;
    *(undefined4 *)(puVar2 + 2) = 0;
  }
  else {
    puVar2 = (ulong *)operator_new(param_3 + 0x19);
    puVar2[1] = param_3;
    *(undefined4 *)(puVar2 + 2) = 0;
    __dest = puVar2 + 3;
    if (param_3 == 1) {
      *(undefined *)(puVar2 + 3) = *param_2;
      goto LAB_00125de8;
    }
  }
  __dest = (ulong *)memcpy(__dest,param_2,param_3);
LAB_00125de8:
  if (puVar2 != (ulong *)&DAT_00174f60) {
    *puVar2 = param_3;
    *(undefined *)((long)puVar2 + param_3 + 0x18) = 0;
  }
  *param_1 = __dest;
  return;
}



void FUN_00125e74(size_t **param_1,char *param_2)

{
  size_t __n;
  size_t sVar1;
  size_t *psVar2;
  size_t *__dest;
  
  if (param_2 == (char *)0x0) {
                    // WARNING: Subroutine does not return
    FUN_0012a95c("basic_string::_S_construct null not valid");
  }
  __n = strlen(param_2);
  if (__n == 0) {
    *param_1 = (size_t *)&DAT_00174f78;
    return;
  }
  if (0x3ffffffffffffff9 < __n) {
                    // WARNING: Subroutine does not return
    FUN_0012ab78("basic_string::_S_create");
  }
  if (__n - 0xfc8 < 0xffffffffffffefff) {
    sVar1 = (__n + 0x1000) - (__n + 0x39 & 0xfff);
    if (0x3ffffffffffffff9 < sVar1) {
      sVar1 = 0x3ffffffffffffff9;
    }
    psVar2 = (size_t *)operator_new(sVar1 + 0x19);
    __dest = psVar2 + 3;
    psVar2[1] = sVar1;
    *(undefined4 *)(psVar2 + 2) = 0;
  }
  else {
    psVar2 = (size_t *)operator_new(__n + 0x19);
    psVar2[1] = __n;
    *(undefined4 *)(psVar2 + 2) = 0;
    __dest = psVar2 + 3;
    if (__n == 1) {
      *(char *)(psVar2 + 3) = *param_2;
      goto LAB_00125f1c;
    }
  }
  __dest = (size_t *)memcpy(__dest,param_2,__n);
LAB_00125f1c:
  if (psVar2 != (size_t *)&DAT_00174f60) {
    *psVar2 = __n;
    *(undefined *)((long)psVar2 + __n + 0x18) = 0;
  }
  *param_1 = __dest;
  return;
}



void FUN_00125fb4(ulong **param_1,ulong param_2,uint param_3)

{
  ulong uVar1;
  ulong *puVar2;
  ulong *__s;
  
  if (param_2 == 0) {
    __s = (ulong *)&DAT_00174f78;
    goto LAB_00125fe0;
  }
  if (0x3ffffffffffffff9 < param_2) {
                    // WARNING: Subroutine does not return
    FUN_0012ab78("basic_string::_S_create");
  }
  if (param_2 + 0x39 < 0x1001) {
    puVar2 = (ulong *)operator_new(param_2 + 0x19);
    puVar2[1] = param_2;
    *(undefined4 *)(puVar2 + 2) = 0;
    __s = puVar2 + 3;
    if (param_2 != 1) goto LAB_00126050;
    *(char *)(puVar2 + 3) = (char)(param_3 & 0xff);
  }
  else {
    uVar1 = (param_2 + 0x1000) - (param_2 + 0x39 & 0xfff);
    if (0x3ffffffffffffff9 < uVar1) {
      uVar1 = 0x3ffffffffffffff9;
    }
    puVar2 = (ulong *)operator_new(uVar1 + 0x19);
    __s = puVar2 + 3;
    puVar2[1] = uVar1;
    *(undefined4 *)(puVar2 + 2) = 0;
LAB_00126050:
    __s = (ulong *)memset(__s,param_3 & 0xff,param_2);
  }
  if (puVar2 != (ulong *)&DAT_00174f60) {
    *puVar2 = param_2;
    *(undefined *)((long)puVar2 + param_2 + 0x18) = 0;
  }
LAB_00125fe0:
  *param_1 = __s;
  return;
}



void FUN_001260b8(undefined8 *param_1,undefined8 *param_2)

{
  *param_1 = *param_2;
  *param_2 = &DAT_00174f78;
  return;
}



void FUN_001260d0(ulong **param_1,undefined *param_2,ulong param_3)

{
  ulong uVar1;
  ulong *puVar2;
  ulong *__dest;
  
  if (param_2 == param_2 + param_3) {
    *param_1 = (ulong *)&DAT_00174f78;
    return;
  }
  if ((param_2 + param_3 != (undefined *)0x0) && (param_2 == (undefined *)0x0)) {
                    // WARNING: Subroutine does not return
    FUN_0012a95c("basic_string::_S_construct null not valid");
  }
  if (0x3ffffffffffffff9 < param_3) {
                    // WARNING: Subroutine does not return
    FUN_0012ab78("basic_string::_S_create");
  }
  if (param_3 - 0xfc8 < 0xffffffffffffefff) {
    uVar1 = (param_3 + 0x1000) - (param_3 + 0x39 & 0xfff);
    if (0x3ffffffffffffff9 < uVar1) {
      uVar1 = 0x3ffffffffffffff9;
    }
    puVar2 = (ulong *)operator_new(uVar1 + 0x19);
    __dest = puVar2 + 3;
    puVar2[1] = uVar1;
    *(undefined4 *)(puVar2 + 2) = 0;
  }
  else {
    puVar2 = (ulong *)operator_new(param_3 + 0x19);
    puVar2[1] = param_3;
    *(undefined4 *)(puVar2 + 2) = 0;
    __dest = puVar2 + 3;
    if (param_3 == 1) {
      *(undefined *)(puVar2 + 3) = *param_2;
      goto LAB_00126180;
    }
  }
  __dest = (ulong *)memcpy(__dest,param_2,param_3);
LAB_00126180:
  if (puVar2 != (ulong *)&DAT_00174f60) {
    *puVar2 = param_3;
    *(undefined *)((long)puVar2 + param_3 + 0x18) = 0;
  }
  *param_1 = __dest;
  return;
}



// WARNING: Removing unreachable block (ram,0x00126254)

void FUN_0012620c(long *param_1)

{
  int iVar1;
  char cVar2;
  bool bVar3;
  undefined *puVar4;
  int *piVar5;
  
  puVar4 = (undefined *)(*param_1 + -0x18);
  if (puVar4 != &DAT_00174f60) {
    piVar5 = (int *)(*param_1 + -8);
    do {
      iVar1 = *piVar5;
      cVar2 = '\x01';
      bVar3 = (bool)ExclusiveMonitorPass(piVar5,0x10);
      if (bVar3) {
        *piVar5 = iVar1 + -1;
        cVar2 = ExclusiveMonitorsStatus();
      }
    } while (cVar2 != '\0');
    if (iVar1 < 1) {
      operator_delete(puVar4);
      return;
    }
  }
  return;
}



void FUN_00126264(long *param_1,long *param_2)

{
  long lVar1;
  long lVar2;
  
  lVar2 = *param_1;
  if (*(int *)(lVar2 + -8) < 0) {
    *(undefined4 *)(lVar2 + -8) = 0;
  }
  lVar1 = *param_2;
  if (*(int *)(lVar1 + -8) < 0) {
    *(undefined4 *)(lVar1 + -8) = 0;
  }
  *param_1 = lVar1;
  *param_2 = lVar2;
  return;
}



undefined8 FUN_00126294(undefined8 *param_1)

{
  return *param_1;
}



long FUN_0012629c(long *param_1)

{
  return *param_1 + *(long *)(*param_1 + -0x18);
}



void FUN_001262ac(long *param_1)

{
  long *in_x8;
  
  *in_x8 = *param_1 + *(long *)(*param_1 + -0x18);
  return;
}



void FUN_001262c4(undefined8 *param_1)

{
  undefined8 *in_x8;
  
  *in_x8 = *param_1;
  return;
}



undefined8 FUN_001262d4(undefined8 *param_1)

{
  return *param_1;
}



long FUN_001262dc(long *param_1)

{
  return *param_1 + *(long *)(*param_1 + -0x18);
}



void FUN_001262ec(long *param_1)

{
  long *in_x8;
  
  *in_x8 = *param_1 + *(long *)(*param_1 + -0x18);
  return;
}



void FUN_00126304(undefined8 *param_1)

{
  undefined8 *in_x8;
  
  *in_x8 = *param_1;
  return;
}



undefined8 FUN_00126314(long *param_1)

{
  return *(undefined8 *)(*param_1 + -0x18);
}



undefined8 FUN_00126320(long *param_1)

{
  return *(undefined8 *)(*param_1 + -0x18);
}



undefined8 FUN_0012632c(void)

{
  return 0x3ffffffffffffff9;
}



undefined8 FUN_00126338(long *param_1)

{
  return *(undefined8 *)(*param_1 + -0x10);
}



// WARNING: Removing unreachable block (ram,0x001264b4)

void FUN_00126344(size_t **param_1,ulong param_2)

{
  int iVar1;
  char cVar2;
  bool bVar3;
  size_t *psVar4;
  size_t *psVar5;
  size_t __n;
  size_t *psVar6;
  ulong uVar7;
  
  psVar6 = *param_1;
  uVar7 = psVar6[-2];
  if ((param_2 != uVar7) || (0 < *(int *)(psVar6 + -1))) {
    if (param_2 < psVar6[-3]) {
      param_2 = psVar6[-3];
    }
    if (0x3ffffffffffffff9 < param_2) {
                    // WARNING: Subroutine does not return
      FUN_0012ab78("basic_string::_S_create");
    }
    if (uVar7 < param_2) {
      if (param_2 < uVar7 << 1) {
        param_2 = uVar7 << 1;
      }
      if ((0x1000 < param_2 + 0x39) && (uVar7 < param_2)) {
        param_2 = (param_2 + 0x1000) - (param_2 + 0x39 & 0xfff);
        if (0x3ffffffffffffff9 < param_2) {
          param_2 = 0x3ffffffffffffff9;
        }
      }
    }
    psVar4 = (size_t *)operator_new(param_2 + 0x19);
    __n = psVar6[-3];
    psVar4[1] = param_2;
    *(undefined4 *)(psVar4 + 2) = 0;
    if (__n != 0) {
      if (__n == 1) {
        *(undefined *)(psVar4 + 3) = *(undefined *)psVar6;
        __n = psVar6[-3];
      }
      else {
        memcpy(psVar4 + 3,psVar6,__n);
        __n = psVar6[-3];
      }
    }
    if (psVar4 != (size_t *)&DAT_00174f60) {
      *psVar4 = __n;
      *(undefined *)((long)psVar4 + __n + 0x18) = 0;
    }
    psVar6 = *param_1 + -3;
    if (psVar6 != (size_t *)&DAT_00174f60) {
      psVar5 = *param_1 + -1;
      do {
        iVar1 = *(int *)psVar5;
        cVar2 = '\x01';
        bVar3 = (bool)ExclusiveMonitorPass(psVar5,0x10);
        if (bVar3) {
          *(int *)psVar5 = iVar1 + -1;
          cVar2 = ExclusiveMonitorsStatus();
        }
      } while (cVar2 != '\0');
      if (iVar1 < 1) {
        operator_delete(psVar6);
      }
    }
    *param_1 = psVar4 + 3;
  }
  return;
}



void FUN_001264d0(long *param_1)

{
  if (*(ulong *)(*param_1 + -0x10) <= *(ulong *)(*param_1 + -0x18)) {
    return;
  }
                    // try { // try from 001264f8 to 001264fb has its CatchHandler @ 00126504
  FUN_00126344(param_1,0);
  return;
}



undefined8 FUN_00126510(undefined8 *param_1,undefined *param_2,ulong param_3)

{
  ulong uVar1;
  undefined *__dest;
  long lVar2;
  undefined *puVar3;
  
  puVar3 = (undefined *)*param_1;
  lVar2 = *(long *)(puVar3 + -0x18);
  if (0x3ffffffffffffff9U - lVar2 < param_3) {
                    // WARNING: Subroutine does not return
    FUN_0012ab78("basic_string::append");
  }
  uVar1 = param_3 + lVar2;
  if ((*(ulong *)(puVar3 + -0x10) < uVar1) || (0 < *(int *)(puVar3 + -8))) {
    if ((puVar3 <= param_2) && (param_2 <= puVar3 + lVar2)) {
      lVar2 = (long)param_2 - (long)puVar3;
      FUN_00126344(param_1,uVar1);
      puVar3 = (undefined *)*param_1;
      param_2 = puVar3 + lVar2;
      lVar2 = *(long *)(puVar3 + -0x18);
      __dest = puVar3 + lVar2;
      goto joined_r0x00126608;
    }
    FUN_00126344(param_1,uVar1);
    puVar3 = (undefined *)*param_1;
    lVar2 = *(long *)(puVar3 + -0x18);
  }
  __dest = puVar3 + lVar2;
joined_r0x00126608:
  if (param_3 == 1) {
    puVar3[lVar2] = *param_2;
    puVar3 = (undefined *)*param_1;
  }
  else {
    memcpy(__dest,param_2,param_3);
    puVar3 = (undefined *)*param_1;
  }
  if (puVar3 == &DAT_00174f78) {
    return 0;
  }
  *(ulong *)(puVar3 + -0x18) = uVar1;
  *(undefined4 *)(puVar3 + -8) = 0;
  puVar3[uVar1] = 0;
  return 0;
}



undefined8 FUN_00126658(long *param_1,ulong param_2,byte param_3)

{
  ulong uVar1;
  void *__s;
  long lVar2;
  undefined *puVar3;
  long lVar4;
  
  lVar2 = *param_1;
  lVar4 = *(long *)(lVar2 + -0x18);
  if (0x3ffffffffffffff9U - lVar4 < param_2) {
                    // WARNING: Subroutine does not return
    FUN_0012ab78("basic_string::append");
  }
  uVar1 = param_2 + lVar4;
  if ((*(ulong *)(lVar2 + -0x10) < uVar1) || (0 < *(int *)(lVar2 + -8))) {
    FUN_00126344(param_1,uVar1);
    lVar2 = *param_1;
    lVar4 = *(long *)(lVar2 + -0x18);
    __s = (void *)(lVar2 + lVar4);
  }
  else {
    __s = (void *)(lVar2 + lVar4);
  }
  if (param_2 == 1) {
    *(byte *)(lVar2 + lVar4) = param_3;
    puVar3 = (undefined *)*param_1;
  }
  else {
    memset(__s,(uint)param_3,param_2);
    puVar3 = (undefined *)*param_1;
  }
  if (puVar3 == &DAT_00174f78) {
    return 0;
  }
  *(ulong *)(puVar3 + -0x18) = uVar1;
  *(undefined4 *)(puVar3 + -8) = 0;
  puVar3[uVar1] = 0;
  return 0;
}



bool FUN_0012675c(long *param_1)

{
  return *(long *)(*param_1 + -0x18) == 0;
}



long FUN_00126770(long *param_1,long param_2)

{
  return *param_1 + param_2;
}



long FUN_0012677c(long *param_1,ulong param_2)

{
  if (param_2 < *(ulong *)(*param_1 + -0x18)) {
    return *param_1 + param_2;
  }
                    // WARNING: Subroutine does not return
  FUN_0012ace0("basic_string::at: __n (which is %zu) >= this->size() (which is %zu)");
}



undefined8 FUN_001267ac(undefined8 *param_1)

{
  return *param_1;
}



long FUN_001267b4(long *param_1)

{
  return *param_1 + *(long *)(*param_1 + -0x18) + -1;
}



undefined8 FUN_001267c8(undefined8 param_1,char *param_2)

{
  size_t sVar1;
  
  sVar1 = strlen(param_2);
  if (sVar1 != 0) {
    FUN_00126510(param_1,param_2,sVar1);
  }
  return param_1;
}



long * FUN_00126808(long *param_1,undefined param_2)

{
  ulong uVar1;
  long lVar2;
  long lVar3;
  undefined *puVar4;
  
  lVar2 = *param_1;
  lVar3 = *(long *)(lVar2 + -0x18);
  uVar1 = lVar3 + 1;
  if ((*(ulong *)(lVar2 + -0x10) < uVar1) || (0 < *(int *)(lVar2 + -8))) {
    FUN_00126344(param_1,uVar1);
    lVar2 = *param_1;
    lVar3 = *(long *)(lVar2 + -0x18);
  }
  *(undefined *)(lVar2 + lVar3) = param_2;
  puVar4 = (undefined *)*param_1;
  if (puVar4 == &DAT_00174f78) {
    return param_1;
  }
  *(ulong *)(puVar4 + -0x18) = uVar1;
  *(undefined4 *)(puVar4 + -8) = 0;
  puVar4[uVar1] = 0;
  return param_1;
}



undefined8 FUN_001268a8(undefined8 param_1,undefined8 param_2,long param_3)

{
  if (param_3 != 0) {
    FUN_00126510();
  }
  return param_1;
}



long * FUN_001268d0(long *param_1,undefined8 *param_2)

{
  ulong uVar1;
  undefined *puVar2;
  long lVar3;
  long lVar4;
  size_t __n;
  
  puVar2 = (undefined *)*param_2;
  __n = *(size_t *)(puVar2 + -0x18);
  if (__n != 0) {
    lVar4 = *param_1;
    lVar3 = *(long *)(lVar4 + -0x18);
    uVar1 = lVar3 + __n;
    if ((*(ulong *)(lVar4 + -0x10) < uVar1) || (0 < *(int *)(lVar4 + -8))) {
      FUN_00126344(param_1,uVar1);
      lVar4 = *param_1;
      puVar2 = (undefined *)*param_2;
      lVar3 = *(long *)(lVar4 + -0x18);
    }
    if (__n == 1) {
      *(undefined *)(lVar4 + lVar3) = *puVar2;
    }
    else {
      memcpy((void *)(lVar4 + lVar3),puVar2,__n);
    }
    puVar2 = (undefined *)*param_1;
    if (puVar2 != &DAT_00174f78) {
      *(undefined4 *)(puVar2 + -8) = 0;
      *(ulong *)(puVar2 + -0x18) = uVar1;
      puVar2[uVar1] = 0;
    }
  }
  return param_1;
}



long * thunk_FUN_001268d0(long *param_1,undefined8 *param_2)

{
  ulong uVar1;
  undefined *puVar2;
  long lVar3;
  long lVar4;
  size_t __n;
  
  puVar2 = (undefined *)*param_2;
  __n = *(size_t *)(puVar2 + -0x18);
  if (__n != 0) {
    lVar4 = *param_1;
    lVar3 = *(long *)(lVar4 + -0x18);
    uVar1 = lVar3 + __n;
    if ((*(ulong *)(lVar4 + -0x10) < uVar1) || (0 < *(int *)(lVar4 + -8))) {
      FUN_00126344(param_1,uVar1);
      lVar4 = *param_1;
      puVar2 = (undefined *)*param_2;
      lVar3 = *(long *)(lVar4 + -0x18);
    }
    if (__n == 1) {
      *(undefined *)(lVar4 + lVar3) = *puVar2;
    }
    else {
      memcpy((void *)(lVar4 + lVar3),puVar2,__n);
    }
    puVar2 = (undefined *)*param_1;
    if (puVar2 != &DAT_00174f78) {
      *(undefined4 *)(puVar2 + -8) = 0;
      *(ulong *)(puVar2 + -0x18) = uVar1;
      puVar2[uVar1] = 0;
    }
  }
  return param_1;
}



long * FUN_00126994(long *param_1,long *param_2,ulong param_3,ulong param_4)

{
  size_t __n;
  undefined *puVar1;
  long lVar2;
  long lVar3;
  ulong uVar4;
  long lVar5;
  
  lVar5 = *param_2;
  uVar4 = *(ulong *)(lVar5 + -0x18);
  if (uVar4 < param_3) {
                    // WARNING: Subroutine does not return
    FUN_0012ace0("%s: __pos (which is %zu) > this->size() (which is %zu)","basic_string::append",
                 param_3,uVar4);
  }
  __n = uVar4 - param_3;
  if (param_4 < uVar4 - param_3) {
    __n = param_4;
  }
  if (__n != 0) {
    lVar2 = *param_1;
    lVar3 = *(long *)(lVar2 + -0x18);
    uVar4 = __n + lVar3;
    if ((*(ulong *)(lVar2 + -0x10) < uVar4) || (0 < *(int *)(lVar2 + -8))) {
      FUN_00126344(param_1,uVar4);
      lVar2 = *param_1;
      lVar5 = *param_2;
      lVar3 = *(long *)(lVar2 + -0x18);
    }
    if (__n == 1) {
      *(undefined *)(lVar2 + lVar3) = *(undefined *)(lVar5 + param_3);
    }
    else {
      memcpy((void *)(lVar2 + lVar3),(void *)(lVar5 + param_3),__n);
    }
    puVar1 = (undefined *)*param_1;
    if (puVar1 != &DAT_00174f78) {
      *(undefined4 *)(puVar1 + -8) = 0;
      *(ulong *)(puVar1 + -0x18) = uVar4;
      puVar1[uVar4] = 0;
    }
  }
  return param_1;
}



undefined8 FUN_00126a90(undefined8 param_1,undefined8 param_2,long param_3)

{
  if (param_3 != 0) {
    FUN_00126510();
  }
  return param_1;
}



undefined8 FUN_00126ab8(undefined8 param_1,char *param_2)

{
  size_t sVar1;
  
  sVar1 = strlen(param_2);
  if (sVar1 != 0) {
    FUN_00126510(param_1,param_2,sVar1);
  }
  return param_1;
}



undefined8 FUN_00126af8(undefined8 param_1,long param_2,undefined param_3)

{
  if (param_2 != 0) {
    FUN_00126658(param_1,param_2,param_3);
  }
  return param_1;
}



undefined8 FUN_00126b24(undefined8 param_1,undefined8 param_2,long param_3)

{
  if (param_3 != 0) {
    FUN_00126510();
  }
  return param_1;
}



void FUN_00126b4c(long *param_1,undefined param_2)

{
  ulong uVar1;
  long lVar2;
  long lVar3;
  undefined *puVar4;
  
  lVar2 = *param_1;
  lVar3 = *(long *)(lVar2 + -0x18);
  uVar1 = lVar3 + 1;
  if ((*(ulong *)(lVar2 + -0x10) < uVar1) || (0 < *(int *)(lVar2 + -8))) {
    FUN_00126344(param_1,uVar1);
    lVar2 = *param_1;
    lVar3 = *(long *)(lVar2 + -0x18);
  }
  *(undefined *)(lVar2 + lVar3) = param_2;
  puVar4 = (undefined *)*param_1;
  if (puVar4 == &DAT_00174f78) {
    return;
  }
  *(ulong *)(puVar4 + -0x18) = uVar1;
  *(undefined4 *)(puVar4 + -8) = 0;
  puVar4[uVar1] = 0;
  return;
}



void FUN_00126be4(long *param_1,long *param_2)

{
  long lVar1;
  long lVar2;
  
  lVar2 = *param_1;
  if (*(int *)(lVar2 + -8) < 0) {
    *(undefined4 *)(lVar2 + -8) = 0;
  }
  lVar1 = *param_2;
  if (*(int *)(lVar1 + -8) < 0) {
    *(undefined4 *)(lVar1 + -8) = 0;
  }
  *param_1 = lVar1;
  *param_2 = lVar2;
  return;
}



ulong * FUN_00126c14(ulong param_1,uint param_2)

{
  ulong uVar1;
  ulong *puVar2;
  ulong *__s;
  
  if (param_1 == 0) {
    return (ulong *)&DAT_00174f78;
  }
  if (0x3ffffffffffffff9 < param_1) {
                    // WARNING: Subroutine does not return
    FUN_0012ab78("basic_string::_S_create");
  }
  if (param_1 + 0x39 < 0x1001) {
    puVar2 = (ulong *)operator_new(param_1 + 0x19);
    puVar2[1] = param_1;
    *(undefined4 *)(puVar2 + 2) = 0;
    __s = puVar2 + 3;
    if (param_1 == 1) {
      *(char *)(puVar2 + 3) = (char)(param_2 & 0xff);
      goto LAB_00126cb8;
    }
  }
  else {
    uVar1 = (param_1 + 0x1000) - (param_1 + 0x39 & 0xfff);
    if (0x3ffffffffffffff9 < uVar1) {
      uVar1 = 0x3ffffffffffffff9;
    }
    puVar2 = (ulong *)operator_new(uVar1 + 0x19);
    __s = puVar2 + 3;
    puVar2[1] = uVar1;
    *(undefined4 *)(puVar2 + 2) = 0;
  }
  __s = (ulong *)memset(__s,param_2 & 0xff,param_1);
LAB_00126cb8:
  if (puVar2 != (ulong *)&DAT_00174f60) {
    *puVar2 = param_1;
    *(undefined *)((long)puVar2 + param_1 + 0x18) = 0;
  }
  return __s;
}



ulong * FUN_00126d0c(ulong param_1,uint param_2)

{
  ulong uVar1;
  ulong *puVar2;
  ulong *__s;
  
  if (param_1 == 0) {
    return (ulong *)&DAT_00174f78;
  }
  if (0x3ffffffffffffff9 < param_1) {
                    // WARNING: Subroutine does not return
    FUN_0012ab78("basic_string::_S_create");
  }
  if (param_1 + 0x39 < 0x1001) {
    puVar2 = (ulong *)operator_new(param_1 + 0x19);
    puVar2[1] = param_1;
    *(undefined4 *)(puVar2 + 2) = 0;
    __s = puVar2 + 3;
    if (param_1 == 1) {
      *(char *)(puVar2 + 3) = (char)(param_2 & 0xff);
      goto LAB_00126db0;
    }
  }
  else {
    uVar1 = (param_1 + 0x1000) - (param_1 + 0x39 & 0xfff);
    if (0x3ffffffffffffff9 < uVar1) {
      uVar1 = 0x3ffffffffffffff9;
    }
    puVar2 = (ulong *)operator_new(uVar1 + 0x19);
    __s = puVar2 + 3;
    puVar2[1] = uVar1;
    *(undefined4 *)(puVar2 + 2) = 0;
  }
  __s = (ulong *)memset(__s,param_2 & 0xff,param_1);
LAB_00126db0:
  if (puVar2 != (ulong *)&DAT_00174f60) {
    *puVar2 = param_1;
    *(undefined *)((long)puVar2 + param_1 + 0x18) = 0;
  }
  return __s;
}



size_t FUN_00126e04(long *param_1,undefined *param_2,ulong param_3,ulong param_4)

{
  size_t __n;
  ulong uVar1;
  long lVar2;
  
  lVar2 = *param_1;
  uVar1 = *(ulong *)(lVar2 + -0x18);
  if (uVar1 < param_4) {
                    // WARNING: Subroutine does not return
    FUN_0012ace0("%s: __pos (which is %zu) > this->size() (which is %zu)","basic_string::copy",
                 param_4,uVar1);
  }
  __n = uVar1 - param_4;
  if (param_3 < uVar1 - param_4) {
    __n = param_3;
  }
  if (__n != 0) {
    if (__n == 1) {
      *param_2 = *(undefined *)(lVar2 + param_4);
      return 1;
    }
    memcpy(param_2,(void *)(lVar2 + param_4),__n);
  }
  return __n;
}



void FUN_00126e90(long *param_1,long *param_2)

{
  long lVar1;
  long lVar2;
  
  lVar2 = *param_1;
  if (*(int *)(lVar2 + -8) < 0) {
    *(undefined4 *)(lVar2 + -8) = 0;
  }
  lVar1 = *param_2;
  if (*(int *)(lVar1 + -8) < 0) {
    *(undefined4 *)(lVar1 + -8) = 0;
  }
  *param_1 = lVar1;
  *param_2 = lVar2;
  return;
}



undefined8 FUN_00126ec0(undefined8 *param_1)

{
  return *param_1;
}



undefined8 FUN_00126ec8(undefined8 *param_1)

{
  return *param_1;
}



void FUN_00126ed0(void)

{
  return;
}



ulong FUN_00126ed8(long *param_1,char *param_2,ulong param_3,ulong param_4)

{
  bool bVar1;
  char cVar2;
  int iVar3;
  ulong uVar4;
  ulong uVar5;
  long lVar6;
  
  lVar6 = *param_1;
  uVar5 = *(ulong *)(lVar6 + -0x18);
  if (param_4 == 0) {
    uVar4 = param_3;
    if (uVar5 < param_3) {
      uVar4 = 0xffffffffffffffff;
    }
  }
  else {
    uVar4 = 0xffffffffffffffff;
    if ((param_4 <= uVar5) && (param_3 <= uVar5 - param_4)) {
      cVar2 = *param_2;
      uVar4 = param_3 + 1;
      do {
        if ((*(char *)(lVar6 + param_3) == cVar2) &&
           (iVar3 = memcmp((void *)(lVar6 + uVar4),param_2 + 1,param_4 - 1), iVar3 == 0)) {
          return param_3;
        }
        param_3 = param_3 + 1;
        bVar1 = uVar4 <= uVar5 - param_4;
        uVar4 = uVar4 + 1;
      } while (bVar1);
      uVar4 = 0xffffffffffffffff;
    }
  }
  return uVar4;
}



ulong FUN_00126f94(long *param_1,char **param_2,ulong param_3)

{
  bool bVar1;
  char cVar2;
  int iVar3;
  ulong uVar4;
  char *pcVar5;
  ulong uVar6;
  ulong uVar7;
  long lVar8;
  
  pcVar5 = *param_2;
  lVar8 = *param_1;
  uVar4 = *(ulong *)(pcVar5 + -0x18);
  uVar7 = *(ulong *)(lVar8 + -0x18);
  if (uVar4 == 0) {
    uVar6 = param_3;
    if (uVar7 < param_3) {
      uVar6 = 0xffffffffffffffff;
    }
  }
  else {
    uVar6 = 0xffffffffffffffff;
    if ((uVar4 <= uVar7) && (param_3 <= uVar7 - uVar4)) {
      cVar2 = *pcVar5;
      uVar6 = param_3 + 1;
      do {
        if ((*(char *)(lVar8 + param_3) == cVar2) &&
           (iVar3 = memcmp((void *)(lVar8 + uVar6),pcVar5 + 1,uVar4 - 1), iVar3 == 0)) {
          return param_3;
        }
        param_3 = param_3 + 1;
        bVar1 = uVar6 <= uVar7 - uVar4;
        uVar6 = uVar6 + 1;
      } while (bVar1);
      uVar6 = 0xffffffffffffffff;
    }
  }
  return uVar6;
}



ulong FUN_00127058(long *param_1,char *param_2,ulong param_3)

{
  char cVar1;
  int iVar2;
  size_t sVar3;
  ulong uVar4;
  ulong uVar5;
  long lVar6;
  
  sVar3 = strlen(param_2);
  lVar6 = *param_1;
  uVar4 = *(ulong *)(lVar6 + -0x18);
  if (sVar3 == 0) {
    uVar5 = param_3;
    if (uVar4 < param_3) {
      uVar5 = 0xffffffffffffffff;
    }
  }
  else {
    uVar5 = 0xffffffffffffffff;
    if ((sVar3 <= uVar4) && (param_3 <= uVar4 - sVar3)) {
      cVar1 = *param_2;
      uVar5 = param_3;
      do {
        uVar5 = uVar5 + 1;
        if ((*(char *)(lVar6 + param_3) == cVar1) &&
           (iVar2 = memcmp((void *)(lVar6 + uVar5),param_2 + 1,sVar3 - 1), iVar2 == 0)) {
          return param_3;
        }
        param_3 = param_3 + 1;
      } while (uVar5 <= uVar4 - sVar3);
      uVar5 = 0xffffffffffffffff;
    }
  }
  return uVar5;
}



long FUN_00127130(long *param_1,byte param_2,ulong param_3)

{
  void *pvVar1;
  long lVar2;
  
  lVar2 = *param_1;
  if (*(ulong *)(lVar2 + -0x18) <= param_3) {
    return -1;
  }
  pvVar1 = memchr((void *)(lVar2 + param_3),(uint)param_2,*(ulong *)(lVar2 + -0x18) - param_3);
  lVar2 = (long)pvVar1 - lVar2;
  if (pvVar1 == (void *)0x0) {
    lVar2 = -1;
  }
  return lVar2;
}



ulong FUN_00127184(long *param_1,void **param_2,ulong param_3)

{
  bool bVar1;
  int iVar2;
  ulong uVar3;
  ulong __n;
  void *__s2;
  long lVar4;
  
  __s2 = *param_2;
  lVar4 = *param_1;
  __n = *(ulong *)((long)__s2 + -0x18);
  uVar3 = *(ulong *)(lVar4 + -0x18);
  if (uVar3 < __n) {
    return 0xffffffffffffffff;
  }
  uVar3 = uVar3 - __n;
  if (uVar3 < param_3) {
    param_3 = uVar3;
  }
  do {
    iVar2 = memcmp((void *)(lVar4 + param_3),__s2,__n);
    if (iVar2 == 0) {
      return param_3;
    }
    bVar1 = param_3 != 0;
    param_3 = param_3 - 1;
  } while (bVar1);
  return 0xffffffffffffffff;
}



ulong FUN_00127218(long *param_1,void *param_2,ulong param_3,ulong param_4)

{
  bool bVar1;
  int iVar2;
  ulong uVar3;
  long lVar4;
  
  lVar4 = *param_1;
  uVar3 = *(ulong *)(lVar4 + -0x18);
  if (uVar3 < param_4) {
    return 0xffffffffffffffff;
  }
  uVar3 = uVar3 - param_4;
  if (param_3 < uVar3) {
    uVar3 = param_3;
  }
  do {
    iVar2 = memcmp((void *)(lVar4 + uVar3),param_2,param_4);
    if (iVar2 == 0) {
      return uVar3;
    }
    bVar1 = uVar3 != 0;
    uVar3 = uVar3 - 1;
  } while (bVar1);
  return 0xffffffffffffffff;
}



ulong FUN_001272ac(long *param_1,char *param_2,ulong param_3)

{
  bool bVar1;
  int iVar2;
  size_t __n;
  ulong uVar3;
  long lVar4;
  
  __n = strlen(param_2);
  lVar4 = *param_1;
  uVar3 = *(ulong *)(lVar4 + -0x18);
  if (uVar3 < __n) {
    return 0xffffffffffffffff;
  }
  uVar3 = uVar3 - __n;
  if (param_3 < uVar3) {
    uVar3 = param_3;
  }
  do {
    iVar2 = memcmp((void *)(lVar4 + uVar3),param_2,__n);
    if (iVar2 == 0) {
      return uVar3;
    }
    bVar1 = uVar3 != 0;
    uVar3 = uVar3 - 1;
  } while (bVar1);
  return 0xffffffffffffffff;
}



void FUN_00127354(long *param_1,char param_2,ulong param_3)

{
  char *pcVar1;
  ulong uVar2;
  long lVar3;
  
  lVar3 = *(long *)(*param_1 + -0x18);
  if (lVar3 != 0) {
    uVar2 = lVar3 - 1;
    if (uVar2 < param_3) {
      param_3 = uVar2;
    }
    do {
      if (param_3 == 0xffffffffffffffff) {
        return;
      }
      pcVar1 = (char *)(*param_1 + param_3);
      param_3 = param_3 - 1;
    } while (*pcVar1 != param_2);
  }
  return;
}



ulong FUN_0012739c(long *param_1,void *param_2,ulong param_3,size_t param_4)

{
  void *pvVar1;
  long lVar2;
  ulong uVar3;
  
  if (param_4 != 0) {
    lVar2 = *param_1;
    uVar3 = *(ulong *)(lVar2 + -0x18);
    if (param_3 < uVar3) {
      do {
        pvVar1 = memchr(param_2,(uint)*(byte *)(lVar2 + param_3),param_4);
        if (pvVar1 != (void *)0x0) {
          return param_3;
        }
        param_3 = param_3 + 1;
      } while (param_3 < uVar3);
    }
  }
  return 0xffffffffffffffff;
}



void FUN_00127428(void)

{
  FUN_0012739c();
  return;
}



void FUN_00127434(undefined8 param_1,char *param_2,undefined8 param_3)

{
  size_t sVar1;
  
  sVar1 = strlen(param_2);
  FUN_0012739c(param_1,param_2,param_3,sVar1);
  return;
}



long FUN_00127470(long *param_1,byte param_2,ulong param_3)

{
  void *pvVar1;
  long lVar2;
  
  lVar2 = *param_1;
  if (*(ulong *)(lVar2 + -0x18) <= param_3) {
    return -1;
  }
  pvVar1 = memchr((void *)(lVar2 + param_3),(uint)param_2,*(ulong *)(lVar2 + -0x18) - param_3);
  lVar2 = (long)pvVar1 - lVar2;
  if (pvVar1 == (void *)0x0) {
    lVar2 = -1;
  }
  return lVar2;
}



ulong FUN_001274c4(long *param_1,void **param_2,ulong param_3)

{
  void *pvVar1;
  long lVar2;
  ulong uVar3;
  void *__s;
  size_t __n;
  long lVar4;
  
  __s = *param_2;
  lVar4 = *param_1;
  __n = *(size_t *)((long)__s + -0x18);
  lVar2 = *(long *)(lVar4 + -0x18);
  if ((__n != 0) && (lVar2 != 0)) {
    uVar3 = lVar2 - 1;
    if (uVar3 < param_3) {
      param_3 = uVar3;
    }
    do {
      pvVar1 = memchr(__s,(uint)*(byte *)(lVar4 + param_3),__n);
      if (pvVar1 != (void *)0x0) {
        return param_3;
      }
      param_3 = param_3 - 1;
    } while (param_3 != 0xffffffffffffffff);
    return 0xffffffffffffffff;
  }
  return 0xffffffffffffffff;
}



ulong FUN_00127544(long *param_1,void *param_2,ulong param_3,size_t param_4)

{
  bool bVar1;
  long lVar2;
  ulong uVar3;
  void *pvVar4;
  long lVar5;
  
  lVar5 = *param_1;
  lVar2 = *(long *)(lVar5 + -0x18);
  if ((param_4 != 0) && (lVar2 != 0)) {
    uVar3 = lVar2 - 1;
    if (uVar3 < param_3) {
      param_3 = uVar3;
    }
    do {
      pvVar4 = memchr(param_2,(uint)*(byte *)(lVar5 + param_3),param_4);
      if (pvVar4 != (void *)0x0) {
        return param_3;
      }
      bVar1 = param_3 != 0;
      param_3 = param_3 - 1;
    } while (bVar1);
  }
  return 0xffffffffffffffff;
}



ulong FUN_001275c4(long *param_1,char *param_2,ulong param_3)

{
  size_t __n;
  void *pvVar1;
  long lVar2;
  ulong uVar3;
  long lVar4;
  
  __n = strlen(param_2);
  lVar4 = *param_1;
  lVar2 = *(long *)(lVar4 + -0x18);
  if ((__n != 0) && (lVar2 != 0)) {
    uVar3 = lVar2 - 1;
    if (uVar3 < param_3) {
      param_3 = uVar3;
    }
    do {
      pvVar1 = memchr(param_2,(uint)*(byte *)(lVar4 + param_3),__n);
      if (pvVar1 != (void *)0x0) {
        return param_3;
      }
      param_3 = param_3 - 1;
    } while (param_3 != 0xffffffffffffffff);
    return 0xffffffffffffffff;
  }
  return 0xffffffffffffffff;
}



void FUN_00127658(long *param_1,char param_2,ulong param_3)

{
  char *pcVar1;
  ulong uVar2;
  long lVar3;
  
  lVar3 = *(long *)(*param_1 + -0x18);
  if (lVar3 != 0) {
    uVar2 = lVar3 - 1;
    if (uVar2 < param_3) {
      param_3 = uVar2;
    }
    do {
      if (param_3 == 0xffffffffffffffff) {
        return;
      }
      pcVar1 = (char *)(*param_1 + param_3);
      param_3 = param_3 - 1;
    } while (*pcVar1 != param_2);
  }
  return;
}



ulong FUN_001276a0(long *param_1,void **param_2,ulong param_3)

{
  void *pvVar1;
  void *__s;
  long lVar2;
  ulong uVar3;
  size_t __n;
  
  lVar2 = *param_1;
  __s = *param_2;
  uVar3 = *(ulong *)(lVar2 + -0x18);
  __n = *(size_t *)((long)__s + -0x18);
  if (param_3 < uVar3) {
    do {
      pvVar1 = memchr(__s,(uint)*(byte *)(lVar2 + param_3),__n);
      if (pvVar1 == (void *)0x0) {
        return param_3;
      }
      param_3 = param_3 + 1;
    } while (param_3 < uVar3);
  }
  return 0xffffffffffffffff;
}



ulong FUN_00127724(long *param_1,void *param_2,ulong param_3,size_t param_4)

{
  void *pvVar1;
  long lVar2;
  ulong uVar3;
  
  lVar2 = *param_1;
  uVar3 = *(ulong *)(lVar2 + -0x18);
  if (param_3 < uVar3) {
    do {
      pvVar1 = memchr(param_2,(uint)*(byte *)(lVar2 + param_3),param_4);
      if (pvVar1 == (void *)0x0) {
        return param_3;
      }
      param_3 = param_3 + 1;
    } while (param_3 < uVar3);
  }
  return 0xffffffffffffffff;
}



ulong FUN_001277a8(long *param_1,char *param_2,ulong param_3)

{
  size_t __n;
  void *pvVar1;
  long lVar2;
  ulong uVar3;
  
  __n = strlen(param_2);
  lVar2 = *param_1;
  uVar3 = *(ulong *)(lVar2 + -0x18);
  if (param_3 < uVar3) {
    do {
      pvVar1 = memchr(param_2,(uint)*(byte *)(lVar2 + param_3),__n);
      if (pvVar1 == (void *)0x0) {
        return param_3;
      }
      param_3 = param_3 + 1;
    } while (param_3 < uVar3);
  }
  return 0xffffffffffffffff;
}



ulong FUN_00127838(long *param_1,char param_2,ulong param_3)

{
  char *pcVar1;
  long lVar2;
  
  lVar2 = *param_1;
  if (*(ulong *)(lVar2 + -0x18) <= param_3) {
    return 0xffffffffffffffff;
  }
  pcVar1 = (char *)(lVar2 + param_3);
  if (*pcVar1 == param_2) {
    do {
      param_3 = param_3 + 1;
      if (*(ulong *)(lVar2 + -0x18) <= param_3) {
        return 0xffffffffffffffff;
      }
    } while (*(char *)(lVar2 + param_3) == *pcVar1);
  }
  return param_3;
}



ulong FUN_00127884(long *param_1,void **param_2,ulong param_3)

{
  ulong uVar1;
  void *pvVar2;
  long lVar3;
  void *__s;
  long lVar4;
  size_t __n;
  
  lVar4 = *param_1;
  __s = *param_2;
  lVar3 = *(long *)(lVar4 + -0x18);
  __n = *(size_t *)((long)__s + -0x18);
  if (lVar3 == 0) {
    return 0xffffffffffffffff;
  }
  uVar1 = lVar3 - 1;
  if (uVar1 < param_3) {
    param_3 = uVar1;
  }
  do {
    pvVar2 = memchr(__s,(uint)*(byte *)(lVar4 + param_3),__n);
    if (pvVar2 == (void *)0x0) {
      return param_3;
    }
    param_3 = param_3 - 1;
  } while (param_3 != 0xffffffffffffffff);
  return 0xffffffffffffffff;
}



ulong FUN_00127900(long *param_1,void *param_2,ulong param_3,size_t param_4)

{
  ulong uVar1;
  bool bVar2;
  void *pvVar3;
  long lVar4;
  long lVar5;
  
  lVar5 = *param_1;
  lVar4 = *(long *)(lVar5 + -0x18);
  if (lVar4 == 0) {
    return 0xffffffffffffffff;
  }
  uVar1 = lVar4 - 1;
  if (uVar1 < param_3) {
    param_3 = uVar1;
  }
  do {
    pvVar3 = memchr(param_2,(uint)*(byte *)(lVar5 + param_3),param_4);
    if (pvVar3 == (void *)0x0) {
      return param_3;
    }
    bVar2 = param_3 != 0;
    param_3 = param_3 - 1;
  } while (bVar2);
  return 0xffffffffffffffff;
}



ulong FUN_00127990(long *param_1,char *param_2,ulong param_3)

{
  ulong uVar1;
  size_t __n;
  void *pvVar2;
  long lVar3;
  long lVar4;
  
  __n = strlen(param_2);
  lVar4 = *param_1;
  lVar3 = *(long *)(lVar4 + -0x18);
  if (lVar3 == 0) {
    return 0xffffffffffffffff;
  }
  uVar1 = lVar3 - 1;
  if (uVar1 < param_3) {
    param_3 = uVar1;
  }
  do {
    pvVar2 = memchr(param_2,(uint)*(byte *)(lVar4 + param_3),__n);
    if (pvVar2 == (void *)0x0) {
      return param_3;
    }
    param_3 = param_3 - 1;
  } while (param_3 != 0xffffffffffffffff);
  return 0xffffffffffffffff;
}



ulong FUN_00127a20(long *param_1,char param_2,ulong param_3)

{
  ulong uVar1;
  bool bVar2;
  ulong uVar3;
  long lVar4;
  
  uVar3 = 0xffffffffffffffff;
  lVar4 = *(long *)(*param_1 + -0x18);
  if (lVar4 != 0) {
    uVar1 = lVar4 - 1;
    uVar3 = param_3;
    if (uVar1 < param_3) {
      uVar3 = uVar1;
    }
    while (*(char *)(*param_1 + uVar3) == param_2) {
      bVar2 = uVar3 == 0;
      uVar3 = uVar3 - 1;
      if (bVar2) {
        return 0xffffffffffffffff;
      }
    }
  }
  return uVar3;
}



undefined8 FUN_00127a6c(long *param_1,ulong param_2)

{
  undefined8 in_x8;
  
  if (param_2 <= *(ulong *)(*param_1 + -0x18)) {
    FUN_00125a40();
    return in_x8;
  }
                    // WARNING: Subroutine does not return
  FUN_0012ace0("%s: __pos (which is %zu) > this->size() (which is %zu)","basic_string::substr",
               param_2,*(ulong *)(*param_1 + -0x18));
}



int FUN_00127ad0(void **param_1,void **param_2)

{
  size_t __n;
  int iVar1;
  ulong uVar2;
  long lVar3;
  ulong uVar4;
  
  uVar4 = *(ulong *)((long)*param_2 + -0x18);
  uVar2 = *(ulong *)((long)*param_1 + -0x18);
  __n = uVar4;
  if (uVar2 < uVar4) {
    __n = uVar2;
  }
  iVar1 = memcmp(*param_1,*param_2,__n);
  if (iVar1 == 0) {
    iVar1 = 0x7fffffff;
    lVar3 = uVar2 - uVar4;
    if (lVar3 < 0x80000000) {
      iVar1 = -0x80000000;
      if (-0x80000001 < lVar3) {
        iVar1 = (int)lVar3;
      }
      return iVar1;
    }
  }
  return iVar1;
}



int FUN_00127b38(long *param_1,ulong param_2,ulong param_3,void **param_4)

{
  ulong uVar1;
  size_t __n;
  int iVar2;
  ulong uVar3;
  long lVar4;
  
  uVar3 = *(ulong *)(*param_1 + -0x18);
  if (uVar3 < param_2) {
                    // WARNING: Subroutine does not return
    FUN_0012ace0("%s: __pos (which is %zu) > this->size() (which is %zu)","basic_string::compare",
                 param_2,uVar3);
  }
  uVar1 = uVar3 - param_2;
  if (param_3 < uVar3 - param_2) {
    uVar1 = param_3;
  }
  uVar3 = *(ulong *)((long)*param_4 + -0x18);
  __n = uVar1;
  if (uVar3 < uVar1) {
    __n = uVar3;
  }
  iVar2 = memcmp((void *)(*param_1 + param_2),*param_4,__n);
  if (iVar2 == 0) {
    iVar2 = 0x7fffffff;
    lVar4 = uVar1 - uVar3;
    if (lVar4 < 0x80000000) {
      iVar2 = -0x80000000;
      if (-0x80000001 < lVar4) {
        iVar2 = (int)lVar4;
      }
      return iVar2;
    }
  }
  return iVar2;
}



int FUN_00127bd4(long *param_1,ulong param_2,ulong param_3,long *param_4,ulong param_5,ulong param_6
                )

{
  ulong uVar1;
  size_t __n;
  int iVar2;
  ulong uVar3;
  ulong uVar4;
  long lVar5;
  
  uVar4 = *(ulong *)(*param_1 + -0x18);
  if (uVar4 < param_2) {
                    // WARNING: Subroutine does not return
    FUN_0012ace0("%s: __pos (which is %zu) > this->size() (which is %zu)","basic_string::compare",
                 param_2,uVar4);
  }
  uVar3 = *(ulong *)(*param_4 + -0x18);
  if (param_5 <= uVar3) {
    uVar3 = uVar3 - param_5;
    uVar1 = uVar4 - param_2;
    if (param_3 < uVar4 - param_2) {
      uVar1 = param_3;
    }
    if (param_6 < uVar3) {
      uVar3 = param_6;
    }
    __n = uVar1;
    if (uVar3 < uVar1) {
      __n = uVar3;
    }
    iVar2 = memcmp((void *)(*param_1 + param_2),(void *)(*param_4 + param_5),__n);
    if (iVar2 == 0) {
      iVar2 = 0x7fffffff;
      lVar5 = uVar1 - uVar3;
      if (lVar5 < 0x80000000) {
        iVar2 = -0x80000000;
        if (-0x80000001 < lVar5) {
          iVar2 = (int)lVar5;
        }
        return iVar2;
      }
    }
    return iVar2;
  }
                    // WARNING: Subroutine does not return
  FUN_0012ace0("%s: __pos (which is %zu) > this->size() (which is %zu)","basic_string::compare",
               param_5);
}



int FUN_00127c9c(void **param_1,char *param_2)

{
  size_t __n;
  int iVar1;
  size_t sVar2;
  ulong uVar3;
  long lVar4;
  void *__s1;
  
  __s1 = *param_1;
  sVar2 = strlen(param_2);
  uVar3 = *(ulong *)((long)__s1 + -0x18);
  __n = sVar2;
  if (uVar3 < sVar2) {
    __n = uVar3;
  }
  iVar1 = memcmp(__s1,param_2,__n);
  if (iVar1 == 0) {
    iVar1 = 0x7fffffff;
    lVar4 = uVar3 - sVar2;
    if (lVar4 < 0x80000000) {
      iVar1 = -0x80000000;
      if (-0x80000001 < lVar4) {
        iVar1 = (int)lVar4;
      }
      return iVar1;
    }
  }
  return iVar1;
}



int FUN_00127d18(long *param_1,ulong param_2,ulong param_3,char *param_4)

{
  ulong uVar1;
  size_t __n;
  int iVar2;
  size_t sVar3;
  ulong uVar4;
  long lVar5;
  
  lVar5 = *param_1;
  uVar4 = *(ulong *)(lVar5 + -0x18);
  if (uVar4 < param_2) {
                    // WARNING: Subroutine does not return
    FUN_0012ace0("%s: __pos (which is %zu) > this->size() (which is %zu)","basic_string::compare",
                 param_2,uVar4);
  }
  uVar1 = uVar4 - param_2;
  if (param_3 < uVar4 - param_2) {
    uVar1 = param_3;
  }
  sVar3 = strlen(param_4);
  __n = sVar3;
  if (uVar1 < sVar3) {
    __n = uVar1;
  }
  iVar2 = memcmp((void *)(lVar5 + param_2),param_4,__n);
  if (iVar2 == 0) {
    iVar2 = 0x7fffffff;
    lVar5 = uVar1 - sVar3;
    if (lVar5 < 0x80000000) {
      iVar2 = -0x80000000;
      if (-0x80000001 < lVar5) {
        iVar2 = (int)lVar5;
      }
      return iVar2;
    }
  }
  return iVar2;
}



int FUN_00127dcc(long *param_1,ulong param_2,ulong param_3,void *param_4,ulong param_5)

{
  ulong uVar1;
  size_t __n;
  int iVar2;
  ulong uVar3;
  long lVar4;
  
  uVar3 = *(ulong *)(*param_1 + -0x18);
  if (uVar3 < param_2) {
                    // WARNING: Subroutine does not return
    FUN_0012ace0("%s: __pos (which is %zu) > this->size() (which is %zu)","basic_string::compare",
                 param_2,uVar3);
  }
  uVar1 = uVar3 - param_2;
  if (param_3 < uVar3 - param_2) {
    uVar1 = param_3;
  }
  __n = uVar1;
  if (param_5 < uVar1) {
    __n = param_5;
  }
  iVar2 = memcmp((void *)(*param_1 + param_2),param_4,__n);
  if (iVar2 == 0) {
    iVar2 = 0x7fffffff;
    lVar4 = uVar1 - param_5;
    if (lVar4 < 0x80000000) {
      iVar2 = -0x80000000;
      if (-0x80000001 < lVar4) {
        iVar2 = (int)lVar4;
      }
      return iVar2;
    }
  }
  return iVar2;
}



void FUN_00127e68(undefined8 *param_1,undefined8 param_2)

{
  *param_1 = param_2;
  return;
}



undefined * FUN_00127e70(void)

{
  return &DAT_00174f60;
}



uint FUN_00127e7c(long param_1)

{
  return *(uint *)(param_1 + 0x10) >> 0x1f;
}



bool FUN_00127e88(long param_1)

{
  return 0 < *(int *)(param_1 + 0x10);
}



void FUN_00127e98(long param_1)

{
  *(undefined4 *)(param_1 + 0x10) = 0xffffffff;
  return;
}



void FUN_00127ea4(long param_1)

{
  *(undefined4 *)(param_1 + 0x10) = 0;
  return;
}



void FUN_00127eac(long *param_1,long param_2)

{
  if (param_1 == (long *)&DAT_00174f60) {
    return;
  }
  *(undefined4 *)(param_1 + 2) = 0;
  *param_1 = param_2;
  *(undefined *)((long)param_1 + param_2 + 0x18) = 0;
  return;
}



long FUN_00127ed4(long param_1)

{
  return param_1 + 0x18;
}



void FUN_00127edc(ulong param_1,ulong param_2)

{
  void *pvVar1;
  ulong uVar2;
  
  if (0x3ffffffffffffff9 < param_1) {
                    // WARNING: Subroutine does not return
    FUN_0012ab78("basic_string::_S_create");
  }
  uVar2 = param_1 + 0x19;
  if (param_2 < param_1) {
    if (param_1 < param_2 << 1) {
      param_1 = param_2 << 1;
    }
    if ((0x1000 < param_1 + 0x39) && (param_2 < param_1)) {
      param_1 = (param_1 + 0x1000) - (param_1 + 0x39 & 0xfff);
      if (0x3ffffffffffffff9 < param_1) {
        param_1 = 0x3ffffffffffffff9;
      }
    }
    uVar2 = param_1 + 0x19;
  }
  pvVar1 = operator_new(uVar2);
  *(ulong *)((long)pvVar1 + 8) = param_1;
  *(undefined4 *)((long)pvVar1 + 0x10) = 0;
  return;
}



// WARNING: Removing unreachable block (ram,0x00128154)

void FUN_00127f74(long *param_1,size_t param_2,long param_3,long param_4)

{
  ulong uVar1;
  int iVar2;
  char cVar3;
  bool bVar4;
  undefined *puVar5;
  undefined *puVar6;
  int *piVar7;
  undefined *puVar8;
  size_t __n;
  undefined auStack_8 [8];
  
  puVar8 = (undefined *)*param_1;
  uVar1 = (param_4 - param_3) + *(long *)(puVar8 + -0x18);
  __n = (*(long *)(puVar8 + -0x18) - param_2) - param_3;
  if ((*(ulong *)(puVar8 + -0x10) < uVar1) || (0 < *(int *)(puVar8 + -8))) {
    puVar5 = (undefined *)FUN_00127edc(uVar1,*(ulong *)(puVar8 + -0x10),auStack_8);
    if (param_2 != 0) {
      if (param_2 == 1) {
        puVar5[0x18] = *(undefined *)*param_1;
      }
      else {
        memcpy(puVar5 + 0x18,(undefined *)*param_1,param_2);
      }
    }
    if (__n != 0) {
      param_4 = param_2 + 0x18 + param_4;
      if (__n == 1) {
        puVar5[param_4] = *(undefined *)(*param_1 + param_3 + param_2);
      }
      else {
        memcpy(puVar5 + param_4,(void *)(*param_1 + param_3 + param_2),__n);
      }
    }
    puVar8 = puVar5 + 0x18;
    puVar6 = (undefined *)(*param_1 + -0x18);
    if (puVar6 != &DAT_00174f60) {
      piVar7 = (int *)(*param_1 + -8);
      do {
        iVar2 = *piVar7;
        cVar3 = '\x01';
        bVar4 = (bool)ExclusiveMonitorPass(piVar7,0x10);
        if (bVar4) {
          *piVar7 = iVar2 + -1;
          cVar3 = ExclusiveMonitorsStatus();
        }
      } while (cVar3 != '\0');
      if (iVar2 < 1) {
        operator_delete(puVar6);
      }
    }
    *param_1 = (long)puVar8;
    if (puVar5 == &DAT_00174f60) {
      return;
    }
  }
  else {
    if ((param_3 != param_4) && (__n != 0)) {
      if (__n == 1) {
        puVar8[param_4 + param_2] = puVar8[param_3 + param_2];
        puVar8 = (undefined *)*param_1;
      }
      else {
        memmove(puVar8 + param_4 + param_2,puVar8 + param_3 + param_2,__n);
        puVar8 = (undefined *)*param_1;
      }
    }
    if (puVar8 == &DAT_00174f78) {
      return;
    }
  }
  *(ulong *)(puVar8 + -0x18) = uVar1;
  *(undefined4 *)(puVar8 + -8) = 0;
  puVar8[uVar1] = 0;
  return;
}



void FUN_00128164(undefined8 *param_1)

{
  undefined *puVar1;
  
  puVar1 = (undefined *)*param_1;
  if (puVar1 != &DAT_00174f78) {
    if (0 < *(int *)(puVar1 + -8)) {
      FUN_00127f74(param_1,0,0,0);
      puVar1 = (undefined *)*param_1;
    }
    *(undefined4 *)(puVar1 + -8) = 0xffffffff;
  }
  return;
}



void FUN_001281c0(undefined8 *param_1)

{
  undefined *puVar1;
  
  puVar1 = (undefined *)*param_1;
  if ((-1 < *(int *)(puVar1 + -8)) && (puVar1 != &DAT_00174f78)) {
    if (*(int *)(puVar1 + -8) != 0) {
      FUN_00127f74(param_1,0,0,0);
      puVar1 = (undefined *)*param_1;
    }
    *(undefined4 *)(puVar1 + -8) = 0xffffffff;
  }
  return;
}



void FUN_0012821c(long *param_1)

{
  FUN_00127f74(param_1,0,*(undefined8 *)(*param_1 + -0x18),0);
  return;
}



long * FUN_00128230(long *param_1,ulong param_2,ulong param_3)

{
  ulong uVar1;
  
  if (param_2 <= *(ulong *)(*param_1 + -0x18)) {
    uVar1 = *(ulong *)(*param_1 + -0x18) - param_2;
    if (param_3 < uVar1) {
      uVar1 = param_3;
    }
    FUN_00127f74(param_1,param_2,uVar1,0);
    return param_1;
  }
                    // WARNING: Subroutine does not return
  FUN_0012ace0("%s: __pos (which is %zu) > this->size() (which is %zu)","basic_string::erase",
               param_2);
}



long FUN_00128290(long *param_1,long param_2)

{
  long lVar1;
  long lVar2;
  
  lVar2 = *param_1;
  FUN_00127f74(param_1,param_2 - lVar2,1,0);
  lVar1 = *param_1;
  *(undefined4 *)(lVar1 + -8) = 0xffffffff;
  return lVar1 + (param_2 - lVar2);
}



long FUN_001282d4(long *param_1,long param_2,long param_3)

{
  long lVar1;
  long lVar2;
  
  if (param_3 - param_2 == 0) {
    return param_2;
  }
  lVar2 = *param_1;
  FUN_00127f74(param_1,param_2 - lVar2,param_3 - param_2,0);
  lVar1 = *param_1;
  *(undefined4 *)(lVar1 + -8) = 0xffffffff;
  return lVar1 + (param_2 - lVar2);
}



long * FUN_00128330(long *param_1,long param_2,long param_3,ulong param_4,byte param_5)

{
  if ((ulong)((0x3ffffffffffffff9 - *(long *)(*param_1 + -0x18)) + param_3) < param_4) {
                    // WARNING: Subroutine does not return
    FUN_0012ab78("basic_string::_M_replace_aux");
  }
  FUN_00127f74();
  if (param_4 != 0) {
    if (param_4 == 1) {
      *(byte *)(*param_1 + param_2) = param_5;
      return param_1;
    }
    memset((void *)(*param_1 + param_2),(uint)param_5,param_4);
  }
  return param_1;
}



long * FUN_001283cc(long *param_1,long param_2,undefined8 param_3,undefined *param_4,size_t param_5)

{
  FUN_00127f74();
  if (param_5 != 0) {
    if (param_5 == 1) {
      *(undefined *)(*param_1 + param_2) = *param_4;
      return param_1;
    }
    memcpy((void *)(*param_1 + param_2),param_4,param_5);
  }
  return param_1;
}



undefined8 * FUN_00128448(undefined8 *param_1,undefined *param_2,size_t param_3)

{
  undefined *__dest;
  undefined *puVar1;
  
  __dest = (undefined *)*param_1;
  puVar1 = __dest + -0x18;
  if (0x3ffffffffffffff9 < param_3) {
                    // WARNING: Subroutine does not return
    FUN_0012ab78("basic_string::assign");
  }
  if (((param_2 < __dest) || (__dest + *(long *)(__dest + -0x18) < param_2)) ||
     (0 < *(int *)(__dest + -8))) {
    FUN_00127f74(param_1,0,*(long *)(__dest + -0x18),param_3);
    if (param_3 == 0) {
      return param_1;
    }
    if (param_3 != 1) {
      memcpy((undefined *)*param_1,param_2,param_3);
      return param_1;
    }
    *(undefined *)*param_1 = *param_2;
    return param_1;
  }
  if ((ulong)((long)param_2 - (long)__dest) < param_3) {
    if (param_2 == __dest) goto LAB_00128500;
    if (param_3 != 1) {
      memmove(__dest,param_2,param_3);
      __dest = (undefined *)*param_1;
      puVar1 = __dest + -0x18;
      goto LAB_00128500;
    }
  }
  else if (param_3 != 1) {
    memcpy(__dest,param_2,param_3);
    __dest = (undefined *)*param_1;
    puVar1 = __dest + -0x18;
    goto LAB_00128500;
  }
  *__dest = *param_2;
  __dest = (undefined *)*param_1;
  puVar1 = __dest + -0x18;
LAB_00128500:
  if (puVar1 != &DAT_00174f60) {
    *(undefined4 *)(__dest + -8) = 0;
    *(size_t *)(__dest + -0x18) = param_3;
    __dest[param_3] = 0;
  }
  return param_1;
}



undefined8 FUN_00128570(undefined8 param_1)

{
  FUN_00128448();
  return param_1;
}



void FUN_00128594(undefined8 param_1,long *param_2,ulong param_3,ulong param_4)

{
  ulong uVar1;
  ulong uVar2;
  
  uVar2 = *(ulong *)(*param_2 + -0x18);
  if (param_3 <= uVar2) {
    uVar1 = uVar2 - param_3;
    if (param_4 < uVar2 - param_3) {
      uVar1 = param_4;
    }
    FUN_00128448(param_1,*param_2 + param_3,uVar1);
    return;
  }
                    // WARNING: Subroutine does not return
  FUN_0012ace0("%s: __pos (which is %zu) > this->size() (which is %zu)","basic_string::assign",
               param_3,uVar2);
}



void FUN_001285e0(undefined8 param_1,char *param_2)

{
  size_t sVar1;
  
  sVar1 = strlen(param_2);
  FUN_00128448(param_1,param_2,sVar1);
  return;
}



void FUN_00128614(undefined8 param_1,char *param_2)

{
  size_t sVar1;
  
  sVar1 = strlen(param_2);
  FUN_00128448(param_1,param_2,sVar1);
  return;
}



undefined8 * thunk_FUN_00128448(undefined8 *param_1,undefined *param_2,size_t param_3)

{
  undefined *__dest;
  undefined *puVar1;
  
  __dest = (undefined *)*param_1;
  puVar1 = __dest + -0x18;
  if (0x3ffffffffffffff9 < param_3) {
                    // WARNING: Subroutine does not return
    FUN_0012ab78("basic_string::assign");
  }
  if (((param_2 < __dest) || (__dest + *(long *)(__dest + -0x18) < param_2)) ||
     (0 < *(int *)(__dest + -8))) {
    FUN_00127f74(param_1,0,*(long *)(__dest + -0x18),param_3);
    if (param_3 == 0) {
      return param_1;
    }
    if (param_3 != 1) {
      memcpy((undefined *)*param_1,param_2,param_3);
      return param_1;
    }
    *(undefined *)*param_1 = *param_2;
    return param_1;
  }
  if ((ulong)((long)param_2 - (long)__dest) < param_3) {
    if (param_2 == __dest) goto LAB_00128500;
    if (param_3 != 1) {
      memmove(__dest,param_2,param_3);
      __dest = (undefined *)*param_1;
      puVar1 = __dest + -0x18;
      goto LAB_00128500;
    }
  }
  else if (param_3 != 1) {
    memcpy(__dest,param_2,param_3);
    __dest = (undefined *)*param_1;
    puVar1 = __dest + -0x18;
    goto LAB_00128500;
  }
  *__dest = *param_2;
  __dest = (undefined *)*param_1;
  puVar1 = __dest + -0x18;
LAB_00128500:
  if (puVar1 != &DAT_00174f60) {
    *(undefined4 *)(__dest + -8) = 0;
    *(size_t *)(__dest + -0x18) = param_3;
    __dest[param_3] = 0;
  }
  return param_1;
}



long * FUN_0012864c(long *param_1,ulong param_2,undefined *param_3,ulong param_4)

{
  undefined *__src;
  long lVar1;
  undefined *__dest;
  ulong uVar2;
  undefined *puVar3;
  size_t __n;
  
  puVar3 = (undefined *)*param_1;
  uVar2 = *(ulong *)(puVar3 + -0x18);
  if (uVar2 < param_2) {
                    // WARNING: Subroutine does not return
    FUN_0012ace0("%s: __pos (which is %zu) > this->size() (which is %zu)","basic_string::insert",
                 param_2,uVar2);
  }
  if (param_4 <= 0x3ffffffffffffff9 - uVar2) {
    if (((param_3 < puVar3) || (puVar3 + uVar2 < param_3)) || (0 < *(int *)(puVar3 + -8))) {
      FUN_00127f74(param_1,param_2,0,param_4);
      if (param_4 != 0) {
        if (param_4 == 1) {
          *(undefined *)(*param_1 + param_2) = *param_3;
        }
        else {
          memcpy((void *)(*param_1 + param_2),param_3,param_4);
        }
      }
    }
    else {
      FUN_00127f74(param_1,param_2,0);
      lVar1 = *param_1;
      __src = param_3 + (lVar1 - (long)puVar3);
      __dest = (undefined *)(lVar1 + param_2);
      if (__src + param_4 <= __dest) {
        if (param_4 != 1) {
          memcpy(__dest,__src,param_4);
          return param_1;
        }
        *(undefined *)(lVar1 + param_2) = param_3[lVar1 - (long)puVar3];
        return param_1;
      }
      if (__src < __dest) {
        __n = (long)__dest - (long)__src;
        if (__n == 1) {
          *(undefined *)(lVar1 + param_2) = param_3[lVar1 - (long)puVar3];
        }
        else {
          __dest = (undefined *)memcpy(__dest,__src,__n);
        }
        if (param_4 - __n == 1) {
          __dest[__n] = __dest[param_4];
        }
        else {
          memcpy(__dest + __n,__dest + param_4,param_4 - __n);
        }
      }
      else if (param_4 == 1) {
        *(undefined *)(lVar1 + param_2) = __src[1];
      }
      else {
        memcpy(__dest,__src + param_4,param_4);
      }
    }
    return param_1;
  }
                    // WARNING: Subroutine does not return
  FUN_0012ab78("basic_string::insert");
}



void FUN_00128828(long *param_1,long param_2)

{
  FUN_0012864c(param_1,param_2 - *param_1);
  return;
}



void FUN_00128834(undefined8 param_1,undefined8 param_2,long *param_3,ulong param_4,ulong param_5)

{
  ulong uVar1;
  ulong uVar2;
  
  uVar2 = *(ulong *)(*param_3 + -0x18);
  if (param_4 <= uVar2) {
    uVar1 = uVar2 - param_4;
    if (param_5 < uVar2 - param_4) {
      uVar1 = param_5;
    }
    FUN_0012864c(param_1,param_2,*param_3 + param_4,uVar1);
    return;
  }
                    // WARNING: Subroutine does not return
  FUN_0012ace0("%s: __pos (which is %zu) > this->size() (which is %zu)","basic_string::insert",
               param_4,uVar2);
}



void FUN_00128880(undefined8 param_1,undefined8 param_2,char *param_3)

{
  size_t sVar1;
  
  sVar1 = strlen(param_3);
  FUN_0012864c(param_1,param_2,param_3,sVar1);
  return;
}



void FUN_001288bc(void)

{
  FUN_0012864c();
  return;
}



void FUN_001288c8(long *param_1)

{
  ulong uVar1;
  
  uVar1 = *(ulong *)(*param_1 + -0x18) - 1;
  if (uVar1 <= *(ulong *)(*param_1 + -0x18)) {
    FUN_00127f74(param_1,uVar1,1,0);
    return;
  }
                    // WARNING: Subroutine does not return
  FUN_0012ace0("%s: __pos (which is %zu) > this->size() (which is %zu)","basic_string::erase");
}



void FUN_0012890c(long *param_1,ulong param_2,undefined param_3)

{
  ulong uVar1;
  
  uVar1 = *(ulong *)(*param_1 + -0x18);
  if (0x3ffffffffffffff9 < param_2) {
                    // WARNING: Subroutine does not return
    FUN_0012ab78("basic_string::resize",param_2,param_3);
  }
  if (uVar1 < param_2) {
    if (param_2 - uVar1 != 0) {
      FUN_00126658(param_1,param_2 - uVar1);
      return;
    }
  }
  else if (param_2 < uVar1) {
    FUN_00127f74(param_1,param_2,uVar1 - param_2,0);
    return;
  }
  return;
}



void FUN_00128970(undefined8 param_1,undefined8 param_2)

{
  FUN_0012890c(param_1,param_2,0);
  return;
}



undefined * FUN_00128978(undefined8 *param_1)

{
  undefined *puVar1;
  
  puVar1 = (undefined *)*param_1;
  if ((-1 < *(int *)(puVar1 + -8)) && (puVar1 != &DAT_00174f78)) {
    if (*(int *)(puVar1 + -8) != 0) {
      FUN_00127f74(param_1,0,0,0);
      puVar1 = (undefined *)*param_1;
    }
    *(undefined4 *)(puVar1 + -8) = 0xffffffff;
  }
  return puVar1;
}



undefined * FUN_001289d8(undefined8 *param_1)

{
  undefined *puVar1;
  
  puVar1 = (undefined *)*param_1;
  if ((-1 < *(int *)(puVar1 + -8)) && (puVar1 != &DAT_00174f78)) {
    if (*(int *)(puVar1 + -8) != 0) {
      FUN_00127f74(param_1,0,0,0);
      puVar1 = (undefined *)*param_1;
    }
    *(undefined4 *)(puVar1 + -8) = 0xffffffff;
  }
  return puVar1;
}



undefined * FUN_00128a38(undefined8 *param_1,long param_2)

{
  undefined *puVar1;
  
  puVar1 = (undefined *)*param_1;
  if ((-1 < *(int *)(puVar1 + -8)) && (puVar1 != &DAT_00174f78)) {
    if (*(int *)(puVar1 + -8) != 0) {
      FUN_00127f74(param_1,0,0,0);
      puVar1 = (undefined *)*param_1;
    }
    *(undefined4 *)(puVar1 + -8) = 0xffffffff;
  }
  return puVar1 + param_2;
}



undefined8 * FUN_00128a9c(undefined8 *param_1)

{
  undefined *puVar1;
  undefined8 *in_x8;
  
  puVar1 = (undefined *)*param_1;
  if ((-1 < *(int *)(puVar1 + -8)) && (puVar1 != &DAT_00174f78)) {
    if (*(int *)(puVar1 + -8) != 0) {
      FUN_00127f74(param_1,0,0,0);
      puVar1 = (undefined *)*param_1;
    }
    *(undefined4 *)(puVar1 + -8) = 0xffffffff;
  }
  *in_x8 = puVar1;
  return in_x8;
}



undefined * FUN_00128b08(undefined8 *param_1)

{
  undefined *puVar1;
  
  puVar1 = (undefined *)*param_1;
  if ((-1 < *(int *)(puVar1 + -8)) && (puVar1 != &DAT_00174f78)) {
    if (*(int *)(puVar1 + -8) != 0) {
      FUN_00127f74(param_1,0,0,0);
      puVar1 = (undefined *)*param_1;
    }
    *(undefined4 *)(puVar1 + -8) = 0xffffffff;
  }
  return puVar1 + *(long *)(puVar1 + -0x18);
}



undefined8 * FUN_00128b6c(undefined8 *param_1)

{
  undefined *puVar1;
  undefined8 *in_x8;
  
  puVar1 = (undefined *)*param_1;
  if ((-1 < *(int *)(puVar1 + -8)) && (puVar1 != &DAT_00174f78)) {
    if (*(int *)(puVar1 + -8) != 0) {
      FUN_00127f74(param_1,0,0,0);
      puVar1 = (undefined *)*param_1;
    }
    *(undefined4 *)(puVar1 + -8) = 0xffffffff;
  }
  *in_x8 = puVar1 + *(long *)(puVar1 + -0x18);
  return in_x8;
}



undefined * FUN_00128be0(undefined8 *param_1)

{
  undefined *puVar1;
  long lVar2;
  
  puVar1 = (undefined *)*param_1;
  lVar2 = *(long *)(puVar1 + -0x18);
  if ((-1 < *(int *)(puVar1 + -8)) && (puVar1 != &DAT_00174f78)) {
    if (*(int *)(puVar1 + -8) != 0) {
      FUN_00127f74(param_1,0,0,0);
      puVar1 = (undefined *)*param_1;
    }
    *(undefined4 *)(puVar1 + -8) = 0xffffffff;
  }
  return puVar1 + lVar2 + -1;
}



undefined * FUN_00128c48(undefined8 *param_1,ulong param_2)

{
  undefined *puVar1;
  
  puVar1 = (undefined *)*param_1;
  if (param_2 < *(ulong *)(puVar1 + -0x18)) {
    if ((-1 < *(int *)(puVar1 + -8)) && (puVar1 != &DAT_00174f78)) {
      if (*(int *)(puVar1 + -8) != 0) {
        FUN_00127f74(param_1,0,0,0);
        puVar1 = (undefined *)*param_1;
      }
      *(undefined4 *)(puVar1 + -8) = 0xffffffff;
    }
    return puVar1 + param_2;
  }
                    // WARNING: Subroutine does not return
  FUN_0012ace0("basic_string::at: __n (which is %zu) >= this->size() (which is %zu)");
}



long * FUN_00128cc4(long *param_1,undefined param_2)

{
  FUN_00127f74(param_1,0,*(undefined8 *)(*param_1 + -0x18),1);
  *(undefined *)*param_1 = param_2;
  return param_1;
}



long FUN_00128d04(long *param_1,long param_2,undefined param_3)

{
  long lVar1;
  
  param_2 = param_2 - *param_1;
  if (*(long *)(*param_1 + -0x18) != 0x3ffffffffffffff9) {
    FUN_00127f74(param_1,param_2,0,1);
    *(undefined *)(*param_1 + param_2) = param_3;
    lVar1 = *param_1;
    *(undefined4 *)(lVar1 + -8) = 0xffffffff;
    return lVar1 + param_2;
  }
                    // WARNING: Subroutine does not return
  FUN_0012ab78("basic_string::_M_replace_aux");
}



byte ** FUN_00128d7c(byte **param_1,size_t param_2,byte param_3)

{
  undefined8 uVar1;
  
  uVar1 = *(undefined8 *)(*param_1 + -0x18);
  if (0x3ffffffffffffff9 < param_2) {
                    // WARNING: Subroutine does not return
    FUN_0012ab78("basic_string::_M_replace_aux",*param_1,uVar1);
  }
  FUN_00127f74(param_1,0,uVar1,param_2);
  if (param_2 != 0) {
    if (param_2 == 1) {
      **param_1 = param_3;
      return param_1;
    }
    memset(*param_1,(uint)param_3,param_2);
  }
  return param_1;
}



long * FUN_00128e10(long *param_1,ulong param_2,ulong param_3,byte param_4)

{
  if (*(ulong *)(*param_1 + -0x18) < param_2) {
                    // WARNING: Subroutine does not return
    FUN_0012ace0("%s: __pos (which is %zu) > this->size() (which is %zu)","basic_string::insert",
                 param_2);
  }
  if (param_3 <= 0x3ffffffffffffff9 - *(ulong *)(*param_1 + -0x18)) {
    FUN_00127f74(param_1,param_2,0,param_3);
    if (param_3 != 0) {
      if (param_3 == 1) {
        *(byte *)(*param_1 + param_2) = param_4;
        return param_1;
      }
      memset((void *)(*param_1 + param_2),(uint)param_4,param_3);
    }
    return param_1;
  }
                    // WARNING: Subroutine does not return
  FUN_0012ab78("basic_string::_M_replace_aux");
}



long * FUN_00128ed0(long *param_1,long param_2,long param_3,ulong param_4,byte param_5)

{
  long lVar1;
  
  lVar1 = param_2 - *param_1;
  if ((ulong)((0x3ffffffffffffff9 - *(long *)(*param_1 + -0x18)) + (param_3 - param_2)) < param_4) {
                    // WARNING: Subroutine does not return
    FUN_0012ab78("basic_string::_M_replace_aux");
  }
  FUN_00127f74(param_1,lVar1);
  if (param_4 != 0) {
    if (param_4 == 1) {
      *(byte *)(*param_1 + lVar1) = param_5;
      return param_1;
    }
    memset((void *)(*param_1 + lVar1),(uint)param_5,param_4);
  }
  return param_1;
}



long * FUN_00128f74(long *param_1,ulong param_2,ulong param_3,ulong param_4,byte param_5)

{
  ulong uVar1;
  ulong uVar2;
  
  uVar2 = *(ulong *)(*param_1 + -0x18);
  if (uVar2 < param_2) {
                    // WARNING: Subroutine does not return
    FUN_0012ace0("%s: __pos (which is %zu) > this->size() (which is %zu)","basic_string::replace",
                 param_2,uVar2);
  }
  uVar1 = uVar2 - param_2;
  if (param_3 < uVar2 - param_2) {
    uVar1 = param_3;
  }
  if (param_4 <= (0x3ffffffffffffff9 - uVar2) + uVar1) {
    FUN_00127f74();
    if (param_4 != 0) {
      if (param_4 == 1) {
        *(byte *)(*param_1 + param_2) = param_5;
        return param_1;
      }
      memset((void *)(*param_1 + param_2),(uint)param_5,param_4);
    }
    return param_1;
  }
                    // WARNING: Subroutine does not return
  FUN_0012ab78("basic_string::_M_replace_aux");
}



void FUN_00129040(long *param_1,long param_2,ulong param_3,uint param_4)

{
  param_2 = param_2 - *param_1;
  if (0x3ffffffffffffff9U - *(long *)(*param_1 + -0x18) < param_3) {
                    // WARNING: Subroutine does not return
    FUN_0012ab78("basic_string::_M_replace_aux");
  }
  FUN_00127f74(param_1,param_2,0,param_3);
  if (param_3 != 0) {
    if (param_3 != 1) {
      memset((void *)(*param_1 + param_2),param_4 & 0xff,param_3);
      return;
    }
    *(char *)(*param_1 + param_2) = (char)(param_4 & 0xff);
  }
  return;
}



// WARNING: Removing unreachable block (ram,0x00129368)

long * FUN_001290d8(long *param_1,ulong param_2,ulong param_3,undefined *param_4,ulong param_5)

{
  undefined *puVar1;
  ulong uVar2;
  int iVar3;
  char cVar4;
  bool bVar5;
  long lVar6;
  ulong *puVar7;
  undefined *puVar8;
  long lVar9;
  ulong uVar10;
  ulong *__dest;
  undefined auStack_8 [8];
  
  puVar8 = (undefined *)*param_1;
  uVar10 = *(ulong *)(puVar8 + -0x18);
  if (uVar10 < param_2) {
                    // WARNING: Subroutine does not return
    FUN_0012ace0("%s: __pos (which is %zu) > this->size() (which is %zu)","basic_string::replace",
                 param_2);
  }
  uVar2 = uVar10 - param_2;
  if (param_3 < uVar10 - param_2) {
    uVar2 = param_3;
  }
  if ((0x3ffffffffffffff9 - uVar10) + uVar2 < param_5) {
                    // WARNING: Subroutine does not return
    FUN_0012ab78("basic_string::replace");
  }
  if (((param_4 < puVar8) || (puVar8 + uVar10 < param_4)) || (0 < *(int *)(puVar8 + -8))) {
    FUN_00127f74(param_1,param_2,uVar2,param_5);
    if (param_5 != 0) {
      if (param_5 == 1) {
        *(undefined *)(*param_1 + param_2) = *param_4;
      }
      else {
        memcpy((void *)(*param_1 + param_2),param_4,param_5);
      }
    }
    return param_1;
  }
  puVar1 = param_4 + param_5;
  if (puVar8 + param_2 < puVar1) {
    if (param_4 < puVar8 + uVar2 + param_2) {
      if (param_4 == puVar1) {
        __dest = (ulong *)&DAT_00174f78;
      }
      else {
        if ((puVar1 != (undefined *)0x0) && (param_4 == (undefined *)0x0)) {
                    // WARNING: Subroutine does not return
          FUN_0012a95c("basic_string::_S_construct null not valid");
        }
        puVar7 = (ulong *)FUN_00127edc(param_5,0,auStack_8);
        __dest = puVar7 + 3;
        if (param_5 == 1) {
          *(undefined *)(puVar7 + 3) = *param_4;
        }
        else {
          memcpy(__dest,param_4,param_5);
        }
        if (puVar7 != (ulong *)&DAT_00174f60) {
          *(undefined4 *)(puVar7 + 2) = 0;
          *puVar7 = param_5;
          *(undefined *)((long)puVar7 + param_5 + 0x18) = 0;
        }
      }
                    // try { // try from 00129284 to 00129287 has its CatchHandler @ 0012939c
      FUN_00127f74(param_1,param_2,uVar2,param_5);
      if (param_5 != 0) {
        if (param_5 == 1) {
          *(undefined *)(*param_1 + param_2) = *(undefined *)__dest;
        }
        else {
          memcpy((void *)(*param_1 + param_2),__dest,param_5);
        }
      }
      if (__dest + -3 == (ulong *)&DAT_00174f60) {
        return param_1;
      }
      puVar7 = __dest + -1;
      do {
        iVar3 = *(int *)puVar7;
        cVar4 = '\x01';
        bVar5 = (bool)ExclusiveMonitorPass(puVar7,0x10);
        if (bVar5) {
          *(int *)puVar7 = iVar3 + -1;
          cVar4 = ExclusiveMonitorsStatus();
        }
      } while (cVar4 != '\0');
      if (0 < iVar3) {
        return param_1;
      }
      operator_delete(__dest + -3);
      return param_1;
    }
    lVar6 = (param_5 - (long)puVar8) - uVar2;
  }
  else {
    lVar6 = -(long)puVar8;
  }
  FUN_00127f74(param_1,param_2,uVar2,param_5);
  lVar9 = *param_1;
  if (param_5 == 1) {
    *(undefined *)(lVar9 + param_2) = param_4[lVar9 + lVar6];
    return param_1;
  }
  memcpy((void *)(lVar9 + param_2),param_4 + lVar9 + lVar6,param_5);
  return param_1;
}



void FUN_001293c0(void)

{
  FUN_001290d8();
  return;
}



void FUN_001293cc(void)

{
  long *in_x3;
  ulong in_x4;
  
  if (in_x4 <= *(ulong *)(*in_x3 + -0x18)) {
    FUN_001290d8();
    return;
  }
                    // WARNING: Subroutine does not return
  FUN_0012ace0("%s: __pos (which is %zu) > this->size() (which is %zu)","basic_string::replace",
               in_x4,*(ulong *)(*in_x3 + -0x18));
}



void FUN_00129418(undefined8 param_1,undefined8 param_2,undefined8 param_3,char *param_4)

{
  size_t sVar1;
  
  sVar1 = strlen(param_4);
  FUN_001290d8(param_1,param_2,param_3,param_4,sVar1);
  return;
}



void FUN_0012945c(long *param_1,long param_2,long param_3)

{
  FUN_001290d8(param_1,param_2 - *param_1,param_3 - param_2);
  return;
}



void FUN_0012946c(long *param_1,long param_2,long param_3,long *param_4)

{
  FUN_001290d8(param_1,param_2 - *param_1,param_3 - param_2,*param_4,
               *(undefined8 *)(*param_4 + -0x18));
  return;
}



void FUN_00129484(long *param_1,long param_2,long param_3,char *param_4)

{
  size_t sVar1;
  
  sVar1 = strlen(param_4);
  FUN_001290d8(param_1,param_2 - *param_1,param_3 - param_2,param_4,sVar1);
  return;
}



void FUN_001294d4(long *param_1,long param_2,long param_3,long param_4,long param_5)

{
  FUN_001290d8(param_1,param_2 - *param_1,param_3 - param_2,param_4,param_5 - param_4);
  return;
}



void FUN_001294e8(long *param_1,long param_2,long param_3,long param_4,long param_5)

{
  FUN_001290d8(param_1,param_2 - *param_1,param_3 - param_2,param_4,param_5 - param_4);
  return;
}



void FUN_001294fc(long *param_1,long param_2,long param_3)

{
  FUN_001290d8(param_1,param_2 - *param_1,param_3 - param_2);
  return;
}



void FUN_0012950c(long *param_1,long param_2,long param_3,long param_4,long param_5)

{
  FUN_001290d8(param_1,param_2 - *param_1,param_3 - param_2,param_4,param_5 - param_4);
  return;
}



void FUN_00129520(long *param_1,long param_2,long param_3,long param_4,long param_5)

{
  FUN_001290d8(param_1,param_2 - *param_1,param_3 - param_2,param_4,param_5 - param_4);
  return;
}



// WARNING: Removing unreachable block (ram,0x00129604)

size_t * FUN_00129534(size_t *param_1,undefined8 param_2)

{
  char cVar1;
  bool bVar2;
  size_t *psVar3;
  size_t *psVar4;
  size_t __n;
  
  if (*(int *)(param_1 + 2) < 0) {
    psVar3 = (size_t *)FUN_00127edc(*param_1,param_1[1],param_2);
    __n = *param_1;
    psVar4 = psVar3 + 3;
    if (__n != 0) {
      psVar4 = psVar3 + 3;
      if (__n == 1) {
        *(undefined *)(psVar3 + 3) = *(undefined *)(param_1 + 3);
        __n = *param_1;
      }
      else {
        psVar4 = (size_t *)memcpy(psVar4,param_1 + 3,__n);
        __n = *param_1;
      }
    }
    if (psVar3 != (size_t *)&DAT_00174f60) {
      *(undefined4 *)(psVar3 + 2) = 0;
      *psVar3 = __n;
      *(undefined *)((long)psVar3 + __n + 0x18) = 0;
    }
  }
  else {
    if (param_1 != (size_t *)&DAT_00174f60) {
      psVar4 = param_1 + 2;
      do {
        cVar1 = '\x01';
        bVar2 = (bool)ExclusiveMonitorPass(psVar4,0x10);
        if (bVar2) {
          *(int *)psVar4 = *(int *)psVar4 + 1;
          cVar1 = ExclusiveMonitorsStatus();
        }
      } while (cVar1 != '\0');
    }
    psVar4 = param_1 + 3;
  }
  return psVar4;
}



// WARNING: Removing unreachable block (ram,0x00129650)

void FUN_00129610(undefined *param_1)

{
  int *piVar1;
  int iVar2;
  char cVar3;
  bool bVar4;
  
  if (param_1 != &DAT_00174f60) {
    piVar1 = (int *)(param_1 + 0x10);
    do {
      iVar2 = *piVar1;
      cVar3 = '\x01';
      bVar4 = (bool)ExclusiveMonitorPass(piVar1,0x10);
      if (bVar4) {
        *piVar1 = iVar2 + -1;
        cVar3 = ExclusiveMonitorsStatus();
      }
    } while (cVar3 != '\0');
    if (iVar2 < 1) {
      operator_delete(param_1);
      return;
    }
  }
  return;
}



void operator_delete(void *param_1)

{
  free(param_1);
  return;
}



// WARNING: Removing unreachable block (ram,0x001296a0)

undefined * FUN_00129664(undefined *param_1)

{
  int *piVar1;
  char cVar2;
  bool bVar3;
  
  if (param_1 != &DAT_00174f60) {
    piVar1 = (int *)(param_1 + 0x10);
    do {
      cVar2 = '\x01';
      bVar3 = (bool)ExclusiveMonitorPass(piVar1,0x10);
      if (bVar3) {
        *piVar1 = *piVar1 + 1;
        cVar2 = ExclusiveMonitorsStatus();
      }
    } while (cVar2 != '\0');
  }
  return param_1 + 0x18;
}



size_t * FUN_001296b0(size_t *param_1,undefined8 param_2,long param_3)

{
  size_t *psVar1;
  size_t *__dest;
  ulong uVar2;
  size_t __n;
  ulong uVar3;
  
  uVar2 = param_1[1];
  uVar3 = param_3 + *param_1;
  if (0x3ffffffffffffff9 < uVar3) {
                    // WARNING: Subroutine does not return
    FUN_0012ab78("basic_string::_S_create");
  }
  if ((uVar2 < uVar3) && (uVar3 < uVar2 << 1)) {
    uVar3 = uVar2 << 1;
  }
  if ((0x1000 < uVar3 + 0x39) && (uVar2 < uVar3)) {
    uVar3 = (uVar3 + 0x1000) - (uVar3 + 0x39 & 0xfff);
    if (0x3ffffffffffffff9 < uVar3) {
      uVar3 = 0x3ffffffffffffff9;
    }
  }
  psVar1 = (size_t *)operator_new(uVar3 + 0x19);
  __n = *param_1;
  __dest = psVar1 + 3;
  psVar1[1] = uVar3;
  *(undefined4 *)(psVar1 + 2) = 0;
  if (__n != 0) {
    __dest = psVar1 + 3;
    if (__n == 1) {
      *(undefined *)(psVar1 + 3) = *(undefined *)(param_1 + 3);
      __n = *param_1;
    }
    else {
      __dest = (size_t *)memcpy(__dest,param_1 + 3,__n);
      __n = *param_1;
    }
  }
  if (psVar1 != (size_t *)&DAT_00174f60) {
    *psVar1 = __n;
    *(undefined *)((long)psVar1 + __n + 0x18) = 0;
    return __dest;
  }
  return __dest;
}



// WARNING: Removing unreachable block (ram,0x00129868)

void FUN_001297e4(long *param_1,long *param_2)

{
  char cVar1;
  bool bVar2;
  int *piVar3;
  long lVar4;
  undefined auStack_8 [8];
  
  lVar4 = *param_2;
  if (-1 < *(int *)(lVar4 + -8)) {
    if ((undefined *)(lVar4 + -0x18) != &DAT_00174f60) {
      piVar3 = (int *)(lVar4 + -8);
      do {
        cVar1 = '\x01';
        bVar2 = (bool)ExclusiveMonitorPass(piVar3,0x10);
        if (bVar2) {
          *piVar3 = *piVar3 + 1;
          cVar1 = ExclusiveMonitorsStatus();
        }
      } while (cVar1 != '\0');
    }
    *param_1 = lVar4;
    return;
  }
  lVar4 = FUN_001296b0((undefined *)(lVar4 + -0x18),auStack_8,0);
  *param_1 = lVar4;
  return;
}



// WARNING: Removing unreachable block (ram,0x00129948)
// WARNING: Removing unreachable block (ram,0x00129954)

long * FUN_00129874(long *param_1,long *param_2)

{
  int iVar1;
  char cVar2;
  bool bVar3;
  long lVar4;
  int *piVar5;
  long lVar6;
  undefined auStack_8 [8];
  
  lVar4 = *param_1;
  lVar6 = *param_2;
  if (lVar4 != lVar6) {
    if (*(int *)(lVar6 + -8) < 0) {
      lVar6 = FUN_001296b0((undefined *)(lVar6 + -0x18),auStack_8,0);
      lVar4 = *param_1;
    }
    else if ((undefined *)(lVar6 + -0x18) != &DAT_00174f60) {
      piVar5 = (int *)(lVar6 + -8);
      do {
        cVar2 = '\x01';
        bVar3 = (bool)ExclusiveMonitorPass(piVar5,0x10);
        if (bVar3) {
          *piVar5 = *piVar5 + 1;
          cVar2 = ExclusiveMonitorsStatus();
        }
      } while (cVar2 != '\0');
      lVar4 = *param_1;
    }
    if ((undefined *)(lVar4 + -0x18) != &DAT_00174f60) {
      piVar5 = (int *)(lVar4 + -8);
      do {
        iVar1 = *piVar5;
        cVar2 = '\x01';
        bVar3 = (bool)ExclusiveMonitorPass(piVar5,0x10);
        if (bVar3) {
          *piVar5 = iVar1 + -1;
          cVar2 = ExclusiveMonitorsStatus();
        }
      } while (cVar2 != '\0');
      if (iVar1 < 1) {
        operator_delete((undefined *)(lVar4 + -0x18));
      }
    }
    *param_1 = lVar6;
  }
  return param_1;
}



// WARNING: Removing unreachable block (ram,0x00129a38)
// WARNING: Removing unreachable block (ram,0x00129a44)

long * FUN_00129964(long *param_1,long *param_2)

{
  int iVar1;
  char cVar2;
  bool bVar3;
  long lVar4;
  int *piVar5;
  long lVar6;
  undefined auStack_8 [8];
  
  lVar4 = *param_1;
  lVar6 = *param_2;
  if (lVar4 != lVar6) {
    if (*(int *)(lVar6 + -8) < 0) {
      lVar6 = FUN_001296b0((undefined *)(lVar6 + -0x18),auStack_8,0);
      lVar4 = *param_1;
    }
    else if ((undefined *)(lVar6 + -0x18) != &DAT_00174f60) {
      piVar5 = (int *)(lVar6 + -8);
      do {
        cVar2 = '\x01';
        bVar3 = (bool)ExclusiveMonitorPass(piVar5,0x10);
        if (bVar3) {
          *piVar5 = *piVar5 + 1;
          cVar2 = ExclusiveMonitorsStatus();
        }
      } while (cVar2 != '\0');
      lVar4 = *param_1;
    }
    if ((undefined *)(lVar4 + -0x18) != &DAT_00174f60) {
      piVar5 = (int *)(lVar4 + -8);
      do {
        iVar1 = *piVar5;
        cVar2 = '\x01';
        bVar3 = (bool)ExclusiveMonitorPass(piVar5,0x10);
        if (bVar3) {
          *piVar5 = iVar1 + -1;
          cVar2 = ExclusiveMonitorsStatus();
        }
      } while (cVar2 != '\0');
      if (iVar1 < 1) {
        operator_delete((undefined *)(lVar4 + -0x18));
      }
    }
    *param_1 = lVar6;
  }
  return param_1;
}



void FUN_00129a54(char *param_1)

{
  size_t sVar1;
  undefined8 *in_x8;
  
  sVar1 = strlen(param_1);
  *in_x8 = &DAT_00174f78;
                    // try { // try from 00129a94 to 00129ab7 has its CatchHandler @ 00129acc
  FUN_00126344();
  if (sVar1 != 0) {
    FUN_00126510();
  }
  FUN_001268d0();
  return;
}



void FUN_00129af4(void)

{
  undefined8 *in_x8;
  
  *in_x8 = &DAT_00174f78;
                    // try { // try from 00129b2c to 00129b4b has its CatchHandler @ 00129b60
  FUN_00126344();
  FUN_00126658();
  FUN_001268d0();
  return;
}



// WARNING: Removing unreachable block (ram,0x00129c14)

void FUN_00129b88(long *param_1)

{
  char cVar1;
  bool bVar2;
  long lVar3;
  int *piVar4;
  long *in_x8;
  undefined auStack_8 [8];
  
  lVar3 = *param_1;
  if (*(int *)(lVar3 + -8) < 0) {
    lVar3 = FUN_001296b0((undefined *)(lVar3 + -0x18),auStack_8,0);
  }
  else if ((undefined *)(lVar3 + -0x18) != &DAT_00174f60) {
    piVar4 = (int *)(lVar3 + -8);
    do {
      cVar1 = '\x01';
      bVar2 = (bool)ExclusiveMonitorPass(piVar4,0x10);
      if (bVar2) {
        *piVar4 = *piVar4 + 1;
        cVar1 = ExclusiveMonitorsStatus();
      }
    } while (cVar1 != '\0');
  }
  *in_x8 = lVar3;
                    // try { // try from 00129bc8 to 00129bcb has its CatchHandler @ 00129c20
  FUN_001268d0();
  return;
}



void FUN_00129c48(ulong **param_1,undefined *param_2,undefined *param_3)

{
  ulong uVar1;
  ulong *puVar2;
  ulong *__dest;
  ulong __n;
  
  if (param_2 == param_3) {
    *param_1 = (ulong *)&DAT_00174f78;
    return;
  }
  if ((param_2 == (undefined *)0x0) && (param_3 != (undefined *)0x0)) {
                    // WARNING: Subroutine does not return
    FUN_0012a95c("basic_string::_S_construct null not valid");
  }
  __n = (long)param_3 - (long)param_2;
  if (0x3ffffffffffffff9 < __n) {
                    // WARNING: Subroutine does not return
    FUN_0012ab78("basic_string::_S_create");
  }
  if ((__n + 0x39 < 0x1001) || (__n == 0)) {
    puVar2 = (ulong *)operator_new(__n + 0x19);
    puVar2[1] = __n;
    *(undefined4 *)(puVar2 + 2) = 0;
    __dest = puVar2 + 3;
    if (__n == 1) {
      *(undefined *)(puVar2 + 3) = *param_2;
      goto LAB_00129cf0;
    }
  }
  else {
    uVar1 = (__n + 0x1000) - (__n + 0x39 & 0xfff);
    if (0x3ffffffffffffff9 < uVar1) {
      uVar1 = 0x3ffffffffffffff9;
    }
    puVar2 = (ulong *)operator_new(uVar1 + 0x19);
    __dest = puVar2 + 3;
    puVar2[1] = uVar1;
    *(undefined4 *)(puVar2 + 2) = 0;
  }
  __dest = (ulong *)memcpy(__dest,param_2,__n);
LAB_00129cf0:
  if (puVar2 != (ulong *)&DAT_00174f60) {
    *puVar2 = __n;
    *(undefined *)((long)puVar2 + __n + 0x18) = 0;
  }
  *param_1 = __dest;
  return;
}



void FUN_00129d7c(ulong **param_1,undefined *param_2,undefined *param_3)

{
  ulong uVar1;
  ulong *puVar2;
  ulong *__dest;
  ulong __n;
  
  if (param_2 == param_3) {
    *param_1 = (ulong *)&DAT_00174f78;
    return;
  }
  if ((param_2 == (undefined *)0x0) && (param_3 != (undefined *)0x0)) {
                    // WARNING: Subroutine does not return
    FUN_0012a95c("basic_string::_S_construct null not valid");
  }
  __n = (long)param_3 - (long)param_2;
  if (0x3ffffffffffffff9 < __n) {
                    // WARNING: Subroutine does not return
    FUN_0012ab78("basic_string::_S_create");
  }
  if ((__n + 0x39 < 0x1001) || (__n == 0)) {
    puVar2 = (ulong *)operator_new(__n + 0x19);
    puVar2[1] = __n;
    *(undefined4 *)(puVar2 + 2) = 0;
    __dest = puVar2 + 3;
    if (__n == 1) {
      *(undefined *)(puVar2 + 3) = *param_2;
      goto LAB_00129e24;
    }
  }
  else {
    uVar1 = (__n + 0x1000) - (__n + 0x39 & 0xfff);
    if (0x3ffffffffffffff9 < uVar1) {
      uVar1 = 0x3ffffffffffffff9;
    }
    puVar2 = (ulong *)operator_new(uVar1 + 0x19);
    __dest = puVar2 + 3;
    puVar2[1] = uVar1;
    *(undefined4 *)(puVar2 + 2) = 0;
  }
  __dest = (ulong *)memcpy(__dest,param_2,__n);
LAB_00129e24:
  if (puVar2 != (ulong *)&DAT_00174f60) {
    *puVar2 = __n;
    *(undefined *)((long)puVar2 + __n + 0x18) = 0;
  }
  *param_1 = __dest;
  return;
}



void FUN_00129eb0(ulong **param_1,undefined *param_2,undefined *param_3)

{
  ulong uVar1;
  ulong *puVar2;
  ulong *__dest;
  ulong __n;
  
  if (param_2 == param_3) {
    *param_1 = (ulong *)&DAT_00174f78;
    return;
  }
  __n = (long)param_3 - (long)param_2;
  if (0x3ffffffffffffff9 < __n) {
                    // WARNING: Subroutine does not return
    FUN_0012ab78("basic_string::_S_create");
  }
  if ((__n + 0x39 < 0x1001) || (__n == 0)) {
    puVar2 = (ulong *)operator_new(__n + 0x19);
    puVar2[1] = __n;
    *(undefined4 *)(puVar2 + 2) = 0;
    __dest = puVar2 + 3;
    if (__n == 1) {
      *(undefined *)(puVar2 + 3) = *param_2;
      goto LAB_00129f44;
    }
  }
  else {
    uVar1 = (__n + 0x1000) - (__n + 0x39 & 0xfff);
    if (0x3ffffffffffffff9 < uVar1) {
      uVar1 = 0x3ffffffffffffff9;
    }
    puVar2 = (ulong *)operator_new(uVar1 + 0x19);
    __dest = puVar2 + 3;
    puVar2[1] = uVar1;
    *(undefined4 *)(puVar2 + 2) = 0;
  }
  __dest = (ulong *)memcpy(__dest,param_2,__n);
LAB_00129f44:
  if (puVar2 != (ulong *)&DAT_00174f60) {
    *puVar2 = __n;
    *(undefined *)((long)puVar2 + __n + 0x18) = 0;
  }
  *param_1 = __dest;
  return;
}



ulong * FUN_00129fd0(undefined *param_1,undefined *param_2)

{
  ulong uVar1;
  ulong *puVar2;
  ulong *__dest;
  ulong __n;
  
  if (param_1 == param_2) {
    return (ulong *)&DAT_00174f78;
  }
  __n = (long)param_2 - (long)param_1;
  if (0x3ffffffffffffff9 < __n) {
                    // WARNING: Subroutine does not return
    FUN_0012ab78("basic_string::_S_create");
  }
  if ((__n + 0x39 < 0x1001) || (__n == 0)) {
    puVar2 = (ulong *)operator_new(__n + 0x19);
    puVar2[1] = __n;
    *(undefined4 *)(puVar2 + 2) = 0;
    __dest = puVar2 + 3;
    if (__n == 1) {
      *(undefined *)(puVar2 + 3) = *param_1;
      goto LAB_0012a060;
    }
  }
  else {
    uVar1 = (__n + 0x1000) - (__n + 0x39 & 0xfff);
    if (0x3ffffffffffffff9 < uVar1) {
      uVar1 = 0x3ffffffffffffff9;
    }
    puVar2 = (ulong *)operator_new(uVar1 + 0x19);
    __dest = puVar2 + 3;
    puVar2[1] = uVar1;
    *(undefined4 *)(puVar2 + 2) = 0;
  }
  __dest = (ulong *)memcpy(__dest,param_1,__n);
LAB_0012a060:
  if (puVar2 != (ulong *)&DAT_00174f60) {
    *puVar2 = __n;
    *(undefined *)((long)puVar2 + __n + 0x18) = 0;
  }
  return __dest;
}



ulong * FUN_0012a0e8(undefined *param_1,undefined *param_2)

{
  ulong *puVar1;
  ulong *__dest;
  ulong __n;
  ulong uVar2;
  
  if (param_1 == param_2) {
    return (ulong *)&DAT_00174f78;
  }
  if ((param_1 == (undefined *)0x0) && (param_2 != (undefined *)0x0)) {
                    // WARNING: Subroutine does not return
    FUN_0012a95c("basic_string::_S_construct null not valid");
  }
  __n = (long)param_2 - (long)param_1;
  if (0x3ffffffffffffff9 < __n) {
                    // WARNING: Subroutine does not return
    FUN_0012ab78("basic_string::_S_create");
  }
  if ((__n + 0x39 < 0x1001) || (__n == 0)) {
    puVar1 = (ulong *)operator_new(__n + 0x19);
    puVar1[1] = __n;
    *(undefined4 *)(puVar1 + 2) = 0;
    __dest = puVar1 + 3;
    if (__n == 1) {
      *(undefined *)(puVar1 + 3) = *param_1;
      goto LAB_0012a190;
    }
  }
  else {
    uVar2 = (__n + 0x1000) - (__n + 0x39 & 0xfff);
    if (0x3ffffffffffffff9 < uVar2) {
      uVar2 = 0x3ffffffffffffff9;
    }
    puVar1 = (ulong *)operator_new(uVar2 + 0x19);
    __dest = puVar1 + 3;
    puVar1[1] = uVar2;
    *(undefined4 *)(puVar1 + 2) = 0;
  }
  __dest = (ulong *)memcpy(__dest,param_1,__n);
LAB_0012a190:
  if (puVar1 != (ulong *)&DAT_00174f60) {
    *puVar1 = __n;
    *(undefined *)((long)puVar1 + __n + 0x18) = 0;
  }
  return __dest;
}



ulong * FUN_0012a218(undefined *param_1,undefined *param_2)

{
  ulong *puVar1;
  ulong *__dest;
  ulong __n;
  ulong uVar2;
  
  if (param_1 == param_2) {
    return (ulong *)&DAT_00174f78;
  }
  if ((param_1 == (undefined *)0x0) && (param_2 != (undefined *)0x0)) {
                    // WARNING: Subroutine does not return
    FUN_0012a95c("basic_string::_S_construct null not valid");
  }
  __n = (long)param_2 - (long)param_1;
  if (0x3ffffffffffffff9 < __n) {
                    // WARNING: Subroutine does not return
    FUN_0012ab78("basic_string::_S_create");
  }
  if ((__n + 0x39 < 0x1001) || (__n == 0)) {
    puVar1 = (ulong *)operator_new(__n + 0x19);
    puVar1[1] = __n;
    *(undefined4 *)(puVar1 + 2) = 0;
    __dest = puVar1 + 3;
    if (__n == 1) {
      *(undefined *)(puVar1 + 3) = *param_1;
      goto LAB_0012a2c0;
    }
  }
  else {
    uVar2 = (__n + 0x1000) - (__n + 0x39 & 0xfff);
    if (0x3ffffffffffffff9 < uVar2) {
      uVar2 = 0x3ffffffffffffff9;
    }
    puVar1 = (ulong *)operator_new(uVar2 + 0x19);
    __dest = puVar1 + 3;
    puVar1[1] = uVar2;
    *(undefined4 *)(puVar1 + 2) = 0;
  }
  __dest = (ulong *)memcpy(__dest,param_1,__n);
LAB_0012a2c0:
  if (puVar1 != (ulong *)&DAT_00174f60) {
    *puVar1 = __n;
    *(undefined *)((long)puVar1 + __n + 0x18) = 0;
  }
  return __dest;
}



bool FUN_0012a348(long *param_1,long *param_2)

{
  return *param_1 == *param_2;
}



bool FUN_0012a35c(long *param_1,long *param_2)

{
  return *param_1 == *param_2;
}



// std::bad_alloc::what() const

char * std::bad_alloc::what(void)

{
  return "std::bad_alloc";
}



// std::bad_alloc::~bad_alloc()

void __thiscall std::bad_alloc::~bad_alloc(bad_alloc *this)

{
  *(undefined ***)this = &PTR__bad_alloc_001623d0;
  exception::~exception((exception *)this);
  return;
}



// std::bad_alloc::~bad_alloc()

void __thiscall std::bad_alloc::~bad_alloc(bad_alloc *this)

{
  ~bad_alloc(this);
  operator_delete(this);
  return;
}



void FUN_0012a3b4(long *param_1)

{
  if ((param_1 != (long *)0x0) && (__cxa_begin_catch(), *param_1 + 0xb8b1aabcbcd4d500U < 2)) {
                    // WARNING: Subroutine does not return
    __cxxabiv1::__terminate((_func_void *)param_1[-7]);
  }
                    // WARNING: Subroutine does not return
  std::terminate();
}



undefined8 __cxa_get_exception_ptr(long param_1)

{
  return *(undefined8 *)(param_1 + -8);
}



long __cxa_begin_catch(long *param_1)

{
  int iVar1;
  int iVar2;
  long **pplVar3;
  long *plVar4;
  long *plVar5;
  
  pplVar3 = (long **)__cxa_get_globals();
  plVar5 = *pplVar3;
  plVar4 = param_1 + -10;
  if (*param_1 + 0xb8b1aabcbcd4d500U < 2) {
    iVar2 = *(int *)(param_1 + -5);
    if (iVar2 < 0) {
      iVar2 = -iVar2;
    }
    iVar1 = *(int *)(pplVar3 + 1);
    *(int *)(param_1 + -5) = iVar2 + 1;
    *(int *)(pplVar3 + 1) = iVar1 + -1;
    if (plVar5 != plVar4) {
      param_1[-6] = (long)plVar5;
      *pplVar3 = plVar4;
    }
    return param_1[-1];
  }
  if (plVar5 == (long *)0x0) {
    *pplVar3 = plVar4;
    return 0;
  }
                    // WARNING: Subroutine does not return
  std::terminate();
}



void __cxa_end_catch(void)

{
  long *plVar1;
  long lVar2;
  int iVar3;
  
  plVar1 = (long *)__cxa_get_globals_fast();
  lVar2 = *plVar1;
  if (lVar2 != 0) {
    if (1 < *(long *)(lVar2 + 0x50) + 0xb8b1aabcbcd4d500U) {
      *plVar1 = 0;
      _Unwind_DeleteException(lVar2 + 0x50);
      return;
    }
    iVar3 = *(int *)(lVar2 + 0x28);
    if (iVar3 < 0) {
      iVar3 = iVar3 + 1;
      if (iVar3 == 0) {
        *plVar1 = *(long *)(lVar2 + 0x20);
        *(undefined4 *)(lVar2 + 0x28) = 0;
        return;
      }
    }
    else {
      iVar3 = iVar3 + -1;
      if (iVar3 == 0) {
        *plVar1 = *(long *)(lVar2 + 0x20);
        _Unwind_DeleteException(lVar2 + 0x50);
        return;
      }
      if (iVar3 == -1) {
                    // WARNING: Subroutine does not return
        std::terminate();
      }
    }
    *(int *)(lVar2 + 0x28) = iVar3;
  }
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked
// std::uncaught_exception()

bool std::uncaught_exception(void)

{
  long lVar1;
  
  lVar1 = __cxa_get_globals();
  return *(int *)(lVar1 + 8) != 0;
}



pthread_key_t * FUN_0012a55c(pthread_key_t *param_1)

{
  code *UNRECOVERED_JUMPTABLE;
  uint uVar1;
  pthread_key_t *ppVar2;
  
  if (param_1 == (pthread_key_t *)0x0) {
                    // WARNING: Treating indirect jump as call
    UNRECOVERED_JUMPTABLE = (code *)SoftwareBreakpoint(1000,0x12a578);
    ppVar2 = (pthread_key_t *)(*UNRECOVERED_JUMPTABLE)();
    return ppVar2;
  }
  if (*(char *)(param_1 + 1) == '\0') {
    return param_1;
  }
  uVar1 = pthread_key_delete(*param_1);
  return (pthread_key_t *)(ulong)uVar1;
}



void FUN_0012a578(long *param_1)

{
  long lVar1;
  long lVar2;
  
  if (param_1 == (long *)0x0) {
    return;
  }
  lVar1 = *param_1;
  while (lVar1 != 0) {
    lVar2 = *(long *)(lVar1 + 0x20);
    _Unwind_DeleteException(lVar1 + 0x50);
    lVar1 = lVar2;
  }
  free(param_1);
  return;
}



undefined * __cxa_get_globals_fast(void)

{
  undefined *puVar1;
  
  if (DAT_00174f84 == '\0') {
    return &DAT_00174f88;
  }
                    // try { // try from 0012a5f0 to 0012a5f3 has its CatchHandler @ 0012a5fc
  puVar1 = (undefined *)pthread_getspecific(DAT_00174f80);
  return puVar1;
}



undefined8 * __cxa_get_globals(void)

{
  int iVar1;
  undefined8 *__pointer;
  
  if (DAT_00174f84 == '\0') {
    __pointer = (undefined8 *)&DAT_00174f88;
  }
  else {
                    // try { // try from 0012a644 to 0012a66b has its CatchHandler @ 0012a680
    __pointer = (undefined8 *)pthread_getspecific(DAT_00174f80);
    if (__pointer == (undefined8 *)0x0) {
      __pointer = (undefined8 *)malloc(0x10);
      if ((__pointer == (undefined8 *)0x0) ||
         (iVar1 = pthread_setspecific(DAT_00174f80,__pointer), iVar1 != 0)) {
                    // WARNING: Subroutine does not return
        std::terminate();
      }
      *__pointer = 0;
      *(undefined4 *)(__pointer + 1) = 0;
    }
  }
  return __pointer;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked
// std::set_new_handler(void (*)())

_func_void * std::set_new_handler(_func_void *param_1)

{
  char cVar1;
  bool bVar2;
  _func_void *p_Var3;
  
  do {
    p_Var3 = DAT_00174f98;
    cVar1 = '\x01';
    bVar2 = (bool)ExclusiveMonitorPass(0x174f98,0x10);
    if (bVar2) {
      cVar1 = ExclusiveMonitorsStatus();
      DAT_00174f98 = param_1;
    }
  } while (cVar1 != '\0');
  return p_Var3;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked
// std::get_new_handler()

undefined8 std::get_new_handler(void)

{
  return DAT_00174f98;
}



// WARNING: Removing unreachable block (ram,0x0012a7ac)
// WARNING: Removing unreachable block (ram,0x0012a840)
// WARNING: Removing unreachable block (ram,0x0012a7c0)
// __gnu_cxx::__verbose_terminate_handler()

void __gnu_cxx::__verbose_terminate_handler(void)

{
  long lVar1;
  char *pcVar2;
  char *__s;
  size_t __n;
  
  if (DAT_00174fa0 == '\0') {
    DAT_00174fa0 = '\x01';
    lVar1 = __cxa_current_exception_type();
    if (lVar1 != 0) {
      pcVar2 = *(char **)(lVar1 + 8);
      if (*pcVar2 == '*') {
        pcVar2 = pcVar2 + 1;
      }
      __s = (char *)__cxa_demangle(pcVar2,0,0);
      fwrite("terminate called after throwing an instance of \'",1,0x30,(FILE *)pthread_mutex_init);
      fputs(pcVar2,(FILE *)pthread_mutex_init);
      do {
        fwrite(&DAT_00141600,1,2,(FILE *)pthread_mutex_init);
                    // try { // try from 0012a774 to 0012a777 has its CatchHandler @ 0012a7b8
        __cxa_rethrow();
        fputs(__s,(FILE *)pthread_mutex_init);
      } while( true );
    }
    pcVar2 = "terminate called without an active exception\n";
    __n = 0x2d;
  }
  else {
    __n = 0x1d;
    pcVar2 = "terminate called recursively\n";
  }
  fwrite(pcVar2,1,__n,(FILE *)pthread_mutex_init);
                    // WARNING: Subroutine does not return
  abort();
}



// WARNING: Removing unreachable block (ram,0x0012a878)

void FUN_0012a84c(void *param_1)

{
  int *piVar1;
  int iVar2;
  char cVar3;
  bool bVar4;
  
  piVar1 = (int *)((long)param_1 + 0x10);
  do {
    iVar2 = *piVar1;
    cVar3 = '\x01';
    bVar4 = (bool)ExclusiveMonitorPass(piVar1,0x10);
    if (bVar4) {
      *piVar1 = iVar2 + -1;
      cVar3 = ExclusiveMonitorsStatus();
    }
  } while (cVar3 != '\0');
  if (iVar2 < 1) {
    operator_delete(param_1);
    return;
  }
  return;
}



void FUN_0012a88c(void)

{
  undefined8 *puVar1;
  
  puVar1 = (undefined8 *)__cxa_allocate_exception(8);
  *puVar1 = &PTR__bad_exception_001621d0;
                    // WARNING: Subroutine does not return
  __cxa_throw(puVar1,&std::bad_exception::typeinfo,std::bad_exception::~bad_exception);
}



void FUN_0012a8c0(void)

{
  undefined8 *puVar1;
  
  puVar1 = (undefined8 *)__cxa_allocate_exception(8);
  *puVar1 = &PTR__bad_alloc_001623d0;
                    // WARNING: Subroutine does not return
  __cxa_throw(puVar1,&std::bad_alloc::typeinfo,std::bad_alloc::~bad_alloc);
}



void FUN_0012a8f4(void)

{
  undefined8 *puVar1;
  
  puVar1 = (undefined8 *)__cxa_allocate_exception(8);
  *puVar1 = &PTR__bad_cast_00162620;
                    // WARNING: Subroutine does not return
  __cxa_throw(puVar1,&std::bad_cast::typeinfo,std::bad_cast::~bad_cast);
}



void FUN_0012a928(void)

{
  undefined8 *puVar1;
  
  puVar1 = (undefined8 *)__cxa_allocate_exception(8);
  *puVar1 = &PTR__bad_typeid_00162670;
                    // WARNING: Subroutine does not return
  __cxa_throw(puVar1,&std::bad_typeid::typeinfo,std::bad_typeid::~bad_typeid);
}



void FUN_0012a95c(undefined8 param_1)

{
  undefined8 uVar1;
  undefined auStack_18 [8];
  undefined auStack_10 [8];
  long local_8;
  
  uVar1 = __cxa_allocate_exception(0x10);
                    // try { // try from 0012a988 to 0012a98b has its CatchHandler @ 0012a9d4
  FUN_00125e74(&local_8,param_1,auStack_18);
                    // try { // try from 0012a994 to 0012a997 has its CatchHandler @ 0012a9e8
  FUN_00125558(uVar1,&local_8);
  if ((undefined *)(local_8 + -0x18) != &DAT_00174f60) {
    FUN_0012a84c((undefined *)(local_8 + -0x18),auStack_10);
  }
                    // WARNING: Subroutine does not return
  __cxa_throw(uVar1,&PTR_PTR____si_class_type_info_001622e0,FUN_00124b38);
}



void FUN_0012aa10(undefined8 param_1)

{
  undefined8 uVar1;
  undefined auStack_18 [8];
  undefined auStack_10 [8];
  long local_8;
  
  uVar1 = __cxa_allocate_exception(0x10);
                    // try { // try from 0012aa3c to 0012aa3f has its CatchHandler @ 0012aa88
  FUN_00125e74(&local_8,param_1,auStack_18);
                    // try { // try from 0012aa48 to 0012aa4b has its CatchHandler @ 0012aa9c
  FUN_00125598(uVar1,&local_8);
  if ((undefined *)(local_8 + -0x18) != &DAT_00174f60) {
    FUN_0012a84c((undefined *)(local_8 + -0x18),auStack_10);
  }
                    // WARNING: Subroutine does not return
  __cxa_throw(uVar1,&PTR_PTR____si_class_type_info_001622f8,FUN_00124e80);
}



void FUN_0012aac4(undefined8 param_1)

{
  undefined8 uVar1;
  undefined auStack_18 [8];
  undefined auStack_10 [8];
  long local_8;
  
  uVar1 = __cxa_allocate_exception(0x10);
                    // try { // try from 0012aaf0 to 0012aaf3 has its CatchHandler @ 0012ab3c
  FUN_00125e74(&local_8,param_1,auStack_18);
                    // try { // try from 0012aafc to 0012aaff has its CatchHandler @ 0012ab50
  FUN_001255e4(uVar1,&local_8);
  if ((undefined *)(local_8 + -0x18) != &DAT_00174f60) {
    FUN_0012a84c((undefined *)(local_8 + -0x18),auStack_10);
  }
                    // WARNING: Subroutine does not return
  __cxa_throw(uVar1,&PTR_PTR____si_class_type_info_00162310,FUN_00124df4);
}



void FUN_0012ab78(undefined8 param_1)

{
  undefined8 uVar1;
  undefined auStack_18 [8];
  undefined auStack_10 [8];
  long local_8;
  
  uVar1 = __cxa_allocate_exception(0x10);
                    // try { // try from 0012aba4 to 0012aba7 has its CatchHandler @ 0012abf0
  FUN_00125e74(&local_8,param_1,auStack_18);
                    // try { // try from 0012abb0 to 0012abb3 has its CatchHandler @ 0012ac04
  FUN_00125630(uVar1,&local_8);
  if ((undefined *)(local_8 + -0x18) != &DAT_00174f60) {
    FUN_0012a84c((undefined *)(local_8 + -0x18),auStack_10);
  }
                    // WARNING: Subroutine does not return
  __cxa_throw(uVar1,&PTR_PTR____si_class_type_info_00162328,FUN_00124f0c);
}



void FUN_0012ac2c(undefined8 param_1)

{
  undefined8 uVar1;
  undefined auStack_18 [8];
  undefined auStack_10 [8];
  long local_8;
  
  uVar1 = __cxa_allocate_exception(0x10);
                    // try { // try from 0012ac58 to 0012ac5b has its CatchHandler @ 0012aca4
  FUN_00125e74(&local_8,param_1,auStack_18);
                    // try { // try from 0012ac64 to 0012ac67 has its CatchHandler @ 0012acb8
  FUN_0012567c(uVar1,&local_8);
  if ((undefined *)(local_8 + -0x18) != &DAT_00174f60) {
    FUN_0012a84c((undefined *)(local_8 + -0x18),auStack_10);
  }
                    // WARNING: Subroutine does not return
  __cxa_throw(uVar1,&PTR_PTR____si_class_type_info_00162340,FUN_00124f98);
}



void FUN_0012ace0(char *param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  long lVar1;
  size_t sVar2;
  undefined8 uVar3;
  undefined *local_120;
  undefined *puStack_118;
  undefined *local_110;
  undefined8 uStack_108;
  undefined auStack_f8 [8];
  undefined auStack_f0 [8];
  long local_e8;
  undefined auStack_40 [8];
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined8 local_20;
  undefined8 local_18;
  undefined8 local_10;
  undefined8 local_8;
  
  local_38 = param_2;
  local_30 = param_3;
  local_28 = param_4;
  local_20 = param_5;
  local_18 = param_6;
  local_10 = param_7;
  local_8 = param_8;
  sVar2 = strlen(param_1);
  lVar1 = -(sVar2 + 0x21e & 0xfffffffffffffff0);
  local_110 = auStack_40;
  uStack_108 = 0xffffff80ffffffc8;
  local_120 = (undefined *)register0x00000008;
  puStack_118 = (undefined *)register0x00000008;
  FUN_0012b9cc(&stack0xfffffffffffffeb0 + lVar1,sVar2 + 0x200,param_1,&local_120);
  uVar3 = __cxa_allocate_exception(0x10);
                    // try { // try from 0012adac to 0012adaf has its CatchHandler @ 0012adf8
  FUN_00125e74(&local_e8,&stack0xfffffffffffffeb0 + lVar1,auStack_f8);
                    // try { // try from 0012adb8 to 0012adbb has its CatchHandler @ 0012ae0c
  FUN_0012567c(uVar3,&local_e8);
  if ((undefined *)(local_e8 + -0x18) != &DAT_00174f60) {
    FUN_0012a84c((undefined *)(local_e8 + -0x18),auStack_f0);
  }
                    // WARNING: Subroutine does not return
  __cxa_throw(uVar3,&PTR_PTR____si_class_type_info_00162340,FUN_00124f98);
}



void FUN_0012ae34(undefined8 param_1)

{
  undefined8 uVar1;
  undefined auStack_18 [8];
  undefined auStack_10 [8];
  long local_8;
  
  uVar1 = __cxa_allocate_exception(0x10);
                    // try { // try from 0012ae60 to 0012ae63 has its CatchHandler @ 0012aeac
  FUN_00125e74(&local_8,param_1,auStack_18);
                    // try { // try from 0012ae6c to 0012ae6f has its CatchHandler @ 0012aec0
  FUN_001256c8(uVar1,&local_8);
  if ((undefined *)(local_8 + -0x18) != &DAT_00174f60) {
    FUN_0012a84c((undefined *)(local_8 + -0x18),auStack_10);
  }
                    // WARNING: Subroutine does not return
  __cxa_throw(uVar1,&PTR_PTR____si_class_type_info_0015dec0,FUN_00124bc4);
}



void FUN_0012aee8(undefined8 param_1)

{
  undefined8 uVar1;
  undefined auStack_18 [8];
  undefined auStack_10 [8];
  long local_8;
  
  uVar1 = __cxa_allocate_exception(0x10);
                    // try { // try from 0012af14 to 0012af17 has its CatchHandler @ 0012af60
  FUN_00125e74(&local_8,param_1,auStack_18);
                    // try { // try from 0012af20 to 0012af23 has its CatchHandler @ 0012af74
  FUN_00125708(uVar1,&local_8);
  if ((undefined *)(local_8 + -0x18) != &DAT_00174f60) {
    FUN_0012a84c((undefined *)(local_8 + -0x18),auStack_10);
  }
                    // WARNING: Subroutine does not return
  __cxa_throw(uVar1,&PTR_PTR____si_class_type_info_00162358,FUN_00124d68);
}



void FUN_0012af9c(undefined8 param_1)

{
  undefined8 uVar1;
  undefined auStack_18 [8];
  undefined auStack_10 [8];
  long local_8;
  
  uVar1 = __cxa_allocate_exception(0x10);
                    // try { // try from 0012afc8 to 0012afcb has its CatchHandler @ 0012b014
  FUN_00125e74(&local_8,param_1,auStack_18);
                    // try { // try from 0012afd4 to 0012afd7 has its CatchHandler @ 0012b028
  FUN_00125754(uVar1,&local_8);
  if ((undefined *)(local_8 + -0x18) != &DAT_00174f60) {
    FUN_0012a84c((undefined *)(local_8 + -0x18),auStack_10);
  }
                    // WARNING: Subroutine does not return
  __cxa_throw(uVar1,&PTR_PTR____si_class_type_info_00162370,FUN_00124c50);
}



void FUN_0012b050(undefined8 param_1)

{
  undefined8 uVar1;
  undefined auStack_18 [8];
  undefined auStack_10 [8];
  long local_8;
  
  uVar1 = __cxa_allocate_exception(0x10);
                    // try { // try from 0012b07c to 0012b07f has its CatchHandler @ 0012b0c8
  FUN_00125e74(&local_8,param_1,auStack_18);
                    // try { // try from 0012b088 to 0012b08b has its CatchHandler @ 0012b0dc
  FUN_001257a0(uVar1,&local_8);
  if ((undefined *)(local_8 + -0x18) != &DAT_00174f60) {
    FUN_0012a84c((undefined *)(local_8 + -0x18),auStack_10);
  }
                    // WARNING: Subroutine does not return
  __cxa_throw(uVar1,&PTR_PTR____si_class_type_info_00162388,FUN_00124cdc);
}



void FUN_0012b104(undefined8 param_1)

{
  undefined8 uVar1;
  undefined auStack_18 [8];
  undefined auStack_10 [8];
  long local_8;
  
  uVar1 = __cxa_allocate_exception(0x10);
                    // try { // try from 0012b130 to 0012b133 has its CatchHandler @ 0012b17c
  FUN_00125e74(&local_8,param_1,auStack_18);
  FUN_00139f18(uVar1,&local_8);
  if ((undefined *)(local_8 + -0x18) != &DAT_00174f60) {
    FUN_0012a84c((undefined *)(local_8 + -0x18),auStack_10);
  }
                    // WARNING: Subroutine does not return
  __cxa_throw(uVar1,&PTR_PTR____si_class_type_info_001626e0,FUN_00139df8);
}



void FUN_0012b190(undefined4 param_1)

{
  undefined8 *puVar1;
  long *plVar2;
  undefined auStack_10 [8];
  long local_8;
  
  puVar1 = (undefined8 *)__cxa_allocate_exception(0x20);
  plVar2 = (long *)FUN_0012bcd4();
                    // try { // try from 0012b1cc to 0012b1cf has its CatchHandler @ 0012b230
  (**(code **)(*plVar2 + 0x18))(plVar2,param_1);
                    // try { // try from 0012b1d8 to 0012b1db has its CatchHandler @ 0012b244
  FUN_001256c8(puVar1,&local_8);
  if ((undefined *)(local_8 + -0x18) != &DAT_00174f60) {
    FUN_0012a84c((undefined *)(local_8 + -0x18),auStack_10);
  }
  *(undefined4 *)(puVar1 + 2) = param_1;
  puVar1[3] = plVar2;
  *puVar1 = &PTR_FUN_001625a0;
                    // WARNING: Subroutine does not return
  __cxa_throw(puVar1,&PTR_PTR____si_class_type_info_00162520,FUN_0012bc80);
}



void FUN_0012b26c(undefined4 param_1)

{
  undefined8 *puVar1;
  undefined8 uVar2;
  undefined auStack_18 [8];
  undefined auStack_10 [8];
  long local_8;
  
  puVar1 = (undefined8 *)__cxa_allocate_exception(0x20);
  uVar2 = FUN_0012b6a0();
                    // try { // try from 0012b2a8 to 0012b2ab has its CatchHandler @ 0012b30c
  FUN_00125e74(&local_8,"std::future_error",auStack_10);
                    // try { // try from 0012b2b4 to 0012b2b7 has its CatchHandler @ 0012b320
  FUN_00125558(puVar1,&local_8);
  if ((undefined *)(local_8 + -0x18) != &DAT_00174f60) {
    FUN_0012a84c((undefined *)(local_8 + -0x18),auStack_18);
  }
  *(undefined4 *)(puVar1 + 2) = param_1;
  puVar1[3] = uVar2;
  *puVar1 = &PTR_FUN_0015d240;
                    // WARNING: Subroutine does not return
  __cxa_throw(puVar1,&PTR_PTR____si_class_type_info_00162408,FUN_0012b470);
}



void FUN_0012b348(void)

{
  undefined8 *puVar1;
  
  puVar1 = (undefined8 *)__cxa_allocate_exception(8);
  *puVar1 = &PTR_FUN_0015d210;
                    // WARNING: Subroutine does not return
  __cxa_throw(puVar1,&PTR_PTR____si_class_type_info_001623f0,FUN_0012b3dc);
}



void FUN_0012b37c(undefined4 param_1)

{
  undefined8 uVar1;
  
  uVar1 = __cxa_allocate_exception(0x18);
                    // try { // try from 0012b3a0 to 0012b3a3 has its CatchHandler @ 0012b3bc
  FUN_0012b7a0(uVar1,param_1);
                    // WARNING: Subroutine does not return
  __cxa_throw(uVar1,&PTR_PTR____si_class_type_info_001624c8,FUN_0012b760);
}



char * FUN_0012b3d0(void)

{
  return "bad_function_call";
}



void FUN_0012b3dc(undefined8 *param_1)

{
  *param_1 = &PTR_FUN_0015d210;
  std::exception::~exception((exception *)param_1);
  return;
}



void FUN_0012b3ec(undefined8 *param_1)

{
  *param_1 = &PTR_FUN_0015d210;
  std::exception::~exception((exception *)param_1);
  operator_delete(param_1);
  return;
}



char * FUN_0012b41c(void)

{
  return "future";
}



void FUN_0012b428(undefined8 *param_1)

{
  *param_1 = &PTR_FUN_00162470;
  FUN_0012bcc0();
  return;
}



void FUN_0012b43c(undefined8 *param_1)

{
  *param_1 = &PTR_FUN_00162470;
  FUN_0012bcc0();
  operator_delete(param_1);
  return;
}



void FUN_0012b470(undefined8 *param_1)

{
  *param_1 = &PTR_FUN_0015d240;
  FUN_00124b38();
  return;
}



void FUN_0012b480(undefined8 *param_1)

{
  *param_1 = &PTR_FUN_0015d240;
  FUN_00124b38();
  operator_delete(param_1);
  return;
}



void FUN_0012b4b0(undefined8 param_1,undefined4 param_2)

{
  undefined8 *in_x8;
  
  *in_x8 = &DAT_00174f78;
  switch(param_2) {
  case 1:
    FUN_00128448();
    return;
  case 2:
    FUN_00128448();
    return;
  case 3:
    FUN_00128448();
    return;
  case 4:
    FUN_00128448();
    return;
  default:
                    // try { // try from 0012b4ec to 0012b597 has its CatchHandler @ 0012b5a8
    FUN_00128448();
    return;
  }
}



// WARNING: Removing unreachable block (ram,0x0012b690)

long FUN_0012b60c(long param_1)

{
  int iVar1;
  char cVar2;
  bool bVar3;
  int *piVar4;
  long local_8;
  
  (**(code **)(**(long **)(param_1 + 0x18) + 0x18))
            (*(long **)(param_1 + 0x18),*(undefined4 *)(param_1 + 0x10));
  if ((undefined *)(local_8 + -0x18) != &DAT_00174f60) {
    piVar4 = (int *)(local_8 + -8);
    do {
      iVar1 = *piVar4;
      cVar2 = '\x01';
      bVar3 = (bool)ExclusiveMonitorPass(piVar4,0x10);
      if (bVar3) {
        *piVar4 = iVar1 + -1;
        cVar2 = ExclusiveMonitorsStatus();
      }
    } while (cVar2 != '\0');
    if (iVar1 < 1) {
      operator_delete((undefined *)(local_8 + -0x18));
    }
  }
  return local_8;
}



undefined ** FUN_0012b6a0(void)

{
  int iVar1;
  
  if (((DAT_00174fa8 & 1) == 0) && (iVar1 = __cxa_guard_acquire(&DAT_00174fa8), iVar1 != 0)) {
    __cxa_guard_release(&DAT_00174fa8);
    __cxa_atexit(FUN_0012b428,&PTR_PTR_FUN_00163038,&DAT_00163000);
    return &PTR_PTR_FUN_00163038;
  }
  return &PTR_PTR_FUN_00163038;
}



void FUN_0012b710(undefined8 *param_1)

{
  *param_1 = &PTR___cxa_pure_virtual_00162440;
  std::__exception_ptr::exception_ptr::exception_ptr((exception_ptr *)(param_1 + 1));
  return;
}



void FUN_0012b720(undefined8 *param_1)

{
  *param_1 = &PTR___cxa_pure_virtual_00162440;
  std::__exception_ptr::exception_ptr::~exception_ptr((exception_ptr *)(param_1 + 1));
  return;
}



void FUN_0012b730(undefined8 *param_1)

{
  *param_1 = &PTR___cxa_pure_virtual_00162440;
  std::__exception_ptr::exception_ptr::~exception_ptr((exception_ptr *)(param_1 + 1));
  operator_delete(param_1);
  return;
}



void FUN_0012b760(undefined8 *param_1)

{
  *param_1 = &PTR_FUN_001624f0;
  FUN_00124bc4();
  return;
}



void FUN_0012b770(undefined8 *param_1)

{
  *param_1 = &PTR_FUN_001624f0;
  FUN_00124bc4();
  operator_delete(param_1);
  return;
}



// WARNING: Removing unreachable block (ram,0x0012b848)

void FUN_0012b7a0(undefined8 *param_1,undefined4 param_2)

{
  int iVar1;
  char cVar2;
  bool bVar3;
  int *piVar4;
  undefined auStack_18 [16];
  long local_8;
  
  FUN_00125e74(&local_8,"regex_error",auStack_18);
                    // try { // try from 0012b7d8 to 0012b7db has its CatchHandler @ 0012b858
  FUN_001256c8(param_1,&local_8);
  if ((undefined *)(local_8 + -0x18) != &DAT_00174f60) {
    piVar4 = (int *)(local_8 + -8);
    do {
      iVar1 = *piVar4;
      cVar2 = '\x01';
      bVar3 = (bool)ExclusiveMonitorPass(piVar4,0x10);
      if (bVar3) {
        *piVar4 = iVar1 + -1;
        cVar2 = ExclusiveMonitorsStatus();
      }
    } while (cVar2 != '\0');
    if (iVar1 < 1) {
      operator_delete((undefined *)(local_8 + -0x18));
    }
  }
  *(undefined4 *)(param_1 + 2) = param_2;
  *param_1 = &PTR_FUN_001624f0;
  return;
}



void FUN_0012b8c0(void *param_1,long param_2)

{
  long lVar1;
  void *__src;
  size_t __n;
  undefined auStack_70 [59];
  undefined auStack_35 [53];
  
  __n = param_2 - (long)param_1;
  __src = memcpy(auStack_70,
                 "not enough space for format expansion (Please submit full bug report at http://gcc.gnu.org/bugs.html):\n    "
                 ,0x6c);
  lVar1 = -(__n + 0x8a & 0xfffffffffffffff0);
  memcpy(&stack0xffffffffffffff60 + lVar1,__src,0x6b);
  memcpy(auStack_35 + lVar1,param_1,__n);
  auStack_35[__n + lVar1] = 0;
                    // WARNING: Subroutine does not return
  FUN_0012a95c(&stack0xffffffffffffff60 + lVar1);
}



ulong FUN_0012b938(void *param_1,ulong param_2,ulong param_3)

{
  undefined auVar1 [16];
  size_t __n;
  ulong uVar2;
  undefined *puVar3;
  ulong uVar4;
  undefined local_39 [25];
  
  puVar3 = local_39 + 1;
  do {
    auVar1._8_8_ = 0;
    auVar1._0_8_ = param_3;
    uVar2 = param_3 / 10;
    puVar3 = puVar3 + -1;
    *puVar3 = PTR_s___xX0123456789abcdef0123456789AB_00163058
              [(param_3 -
               ((SUB168(auVar1 * ZEXT816(0xcccccccccccccccd),8) & 0xfffffffffffffff8) + uVar2 * 2))
               + 4];
    param_3 = uVar2;
  } while (uVar2 != 0);
  uVar2 = (long)(local_39 + 1) - (long)puVar3;
  uVar4 = uVar2 & 0xffffffff;
  __n = (size_t)(int)uVar2;
  if (param_2 < __n) {
    uVar4 = 0xffffffff;
  }
  else {
    memcpy(param_1,local_39 + (1 - __n),__n);
  }
  return uVar4;
}



long FUN_0012b9cc(char *param_1,long param_2,char *param_3,undefined8 *param_4)

{
  char *pcVar1;
  char cVar2;
  char cVar3;
  int iVar4;
  char *pcVar5;
  char *pcVar6;
  char **ppcVar8;
  char **ppcVar9;
  int iVar10;
  long lVar11;
  char *pcVar7;
  
  pcVar1 = param_1 + param_2 + -1;
  ppcVar8 = (char **)*param_4;
  lVar11 = param_4[1];
  iVar10 = *(int *)(param_4 + 3);
  pcVar6 = param_1;
LAB_0012ba14:
  do {
    cVar3 = *param_3;
    while( true ) {
      if (cVar3 == '\0') {
        *pcVar6 = '\0';
        return (long)pcVar6 - (long)param_1;
      }
      ppcVar9 = ppcVar8;
      if (pcVar6 < pcVar1) break;
LAB_0012baf8:
      while( true ) {
        FUN_0012b8c0(param_1,pcVar6);
LAB_0012bb04:
        iVar4 = iVar10 + 8;
        if (iVar4 < 1) {
          ppcVar8 = (char **)(lVar11 + iVar10);
          iVar10 = iVar4;
        }
        else {
          ppcVar8 = ppcVar9;
          ppcVar9 = (char **)((long)ppcVar9 + 0xfU & 0xfffffffffffffff8);
          iVar10 = iVar4;
        }
LAB_0012ba64:
        pcVar5 = *ppcVar8;
        cVar3 = *pcVar5;
        pcVar7 = pcVar6;
        if (cVar3 == '\0') break;
        do {
          pcVar6 = pcVar7 + 1;
          *pcVar7 = cVar3;
          pcVar5 = pcVar5 + 1;
          cVar3 = *pcVar5;
          if (cVar3 == '\0') goto LAB_0012ba88;
          pcVar7 = pcVar6;
        } while (pcVar6 != pcVar1);
      }
LAB_0012ba88:
      param_3 = param_3 + 2;
      cVar3 = *param_3;
      ppcVar8 = ppcVar9;
    }
    if (cVar3 != '%') {
LAB_0012ba08:
      *pcVar6 = cVar3;
      param_3 = param_3 + 1;
      pcVar6 = pcVar6 + 1;
      goto LAB_0012ba14;
    }
    cVar2 = param_3[1];
    if (cVar2 == 's') {
      if (iVar10 < 0) goto LAB_0012bb04;
      ppcVar9 = (char **)((long)ppcVar8 + 0xfU & 0xfffffffffffffff8);
      goto LAB_0012ba64;
    }
    if (cVar2 != 'z') {
      param_3 = param_3 + (cVar2 == '%');
      goto LAB_0012ba08;
    }
    if (param_3[2] != 'u') goto LAB_0012ba08;
    if (iVar10 < 0) {
      iVar4 = iVar10 + 8;
      if (iVar4 < 1) {
        ppcVar9 = (char **)(lVar11 + iVar10);
        iVar10 = iVar4;
      }
      else {
        ppcVar8 = (char **)((long)ppcVar8 + 0xfU & 0xfffffffffffffff8);
        iVar10 = iVar4;
      }
    }
    else {
      ppcVar8 = (char **)((long)ppcVar8 + 0xfU & 0xfffffffffffffff8);
    }
    iVar4 = FUN_0012b938(pcVar6,(long)pcVar1 - (long)pcVar6,*ppcVar9);
    ppcVar9 = ppcVar8;
    if (iVar4 < 1) goto LAB_0012baf8;
    pcVar6 = pcVar6 + iVar4;
    param_3 = param_3 + 3;
  } while( true );
}



char * FUN_0012bb5c(void)

{
  return "generic";
}



char * FUN_0012bb68(void)

{
  return "system";
}



undefined  [16] FUN_0012bb74(undefined8 param_1,ulong param_2)

{
  undefined auVar1 [16];
  
  auVar1._0_8_ = param_2 & 0xffffffff;
  auVar1._8_8_ = param_1;
  return auVar1;
}



bool FUN_0012bb84(long *param_1,undefined8 param_2,int *param_3)

{
  int iVar1;
  long extraout_x1;
  
  iVar1 = (**(code **)(*param_1 + 0x20))();
  if (*(long *)(param_3 + 2) != extraout_x1) {
    return false;
  }
  return *param_3 == iVar1;
}



bool FUN_0012bbd4(long param_1,int *param_2,int param_3)

{
  if (*(long *)(param_2 + 2) != param_1) {
    return false;
  }
  return *param_2 == param_3;
}



void FUN_0012bc00(void)

{
  return;
}



void FUN_0012bc04(void)

{
  return;
}



void operator_delete(void *param_1)

{
  free(param_1);
  return;
}



void operator_delete(void *param_1)

{
  free(param_1);
  return;
}



void FUN_0012bc10(undefined8 param_1,int param_2)

{
  strerror(param_2);
  FUN_00125e74();
  return;
}



void FUN_0012bc48(undefined8 param_1,int param_2)

{
  strerror(param_2);
  FUN_00125e74();
  return;
}



void FUN_0012bc80(undefined8 *param_1)

{
  *param_1 = &PTR_FUN_001625a0;
  FUN_00124bc4();
  return;
}



void FUN_0012bc90(undefined8 *param_1)

{
  *param_1 = &PTR_FUN_001625a0;
  FUN_00124bc4();
  operator_delete(param_1);
  return;
}



void FUN_0012bcc0(void)

{
  return;
}



void operator_delete(void *param_1)

{
  free(param_1);
  return;
}



undefined ** FUN_0012bcc8(void)

{
  return &PTR_PTR_FUN_00163048;
}



undefined ** FUN_0012bcd4(void)

{
  return &PTR_PTR_FUN_00163040;
}



void FUN_0012bce0(undefined4 *param_1)

{
  (**(code **)(**(long **)(param_1 + 2) + 0x20))(*(long **)(param_1 + 2),*param_1);
  return;
}



// std::bad_cast::what() const

char * std::bad_cast::what(void)

{
  return "std::bad_cast";
}



// std::bad_cast::~bad_cast()

void __thiscall std::bad_cast::~bad_cast(bad_cast *this)

{
  *(undefined ***)this = &PTR__bad_cast_00162620;
  exception::~exception((exception *)this);
  return;
}



// std::bad_cast::~bad_cast()

void __thiscall std::bad_cast::~bad_cast(bad_cast *this)

{
  ~bad_cast(this);
  operator_delete(this);
  return;
}



// std::bad_typeid::what() const

char * std::bad_typeid::what(void)

{
  return "std::bad_typeid";
}



// std::bad_typeid::~bad_typeid()

void __thiscall std::bad_typeid::~bad_typeid(bad_typeid *this)

{
  *(undefined ***)this = &PTR__bad_typeid_00162670;
  exception::~exception((exception *)this);
  return;
}



// std::bad_typeid::~bad_typeid()

void __thiscall std::bad_typeid::~bad_typeid(bad_typeid *this)

{
  ~bad_typeid(this);
  operator_delete(this);
  return;
}



long FUN_0012bd90(long param_1,undefined4 param_2,long param_3,long param_4)

{
  long lVar1;
  int iVar2;
  
  switch(param_2) {
  case 1:
  case 2:
  case 3:
  case 4:
  case 0xb:
  case 0x21:
  case 0x2b:
  case 0x2d:
  case 0x36:
  case 0x37:
  case 0x38:
  case 0x39:
  case 0x3a:
  case 0x3c:
  case 0x3d:
  case 0x3f:
  case 0x4b:
  case 0x4c:
    if (param_3 == 0) {
      return 0;
    }
switchD_0012bdbc_caseD_2a:
    if ((param_4 != 0) && (iVar2 = *(int *)(param_1 + 0x28), iVar2 < *(int *)(param_1 + 0x2c))) {
LAB_0012bdd8:
      *(int *)(param_1 + 0x28) = iVar2 + 1;
      lVar1 = *(long *)(param_1 + 0x20) + (long)iVar2 * 0x18;
      if (lVar1 != 0) {
        *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar2 * 0x18) = param_2;
        *(long *)(lVar1 + 8) = param_3;
        *(long *)(lVar1 + 0x10) = param_4;
        return lVar1;
      }
    }
LAB_0012bda0:
    return 0;
  default:
    goto LAB_0012bda0;
  case 9:
  case 10:
  case 0xc:
  case 0xd:
  case 0xe:
  case 0xf:
  case 0x10:
  case 0x11:
  case 0x12:
  case 0x13:
  case 0x14:
  case 0x15:
  case 0x16:
  case 0x17:
  case 0x22:
  case 0x23:
  case 0x24:
  case 0x25:
  case 0x26:
  case 0x28:
  case 0x33:
  case 0x34:
  case 0x35:
  case 0x3b:
  case 0x3e:
  case 0x42:
  case 0x43:
  case 0x44:
  case 0x48:
  case 0x49:
  case 0x4a:
    if (param_3 == 0) {
      return 0;
    }
  case 0x19:
  case 0x1a:
  case 0x1b:
  case 0x1c:
  case 0x1d:
  case 0x1e:
  case 0x1f:
  case 0x20:
  case 0x29:
  case 0x2e:
  case 0x2f:
    iVar2 = *(int *)(param_1 + 0x28);
    if (*(int *)(param_1 + 0x2c) <= iVar2) {
      return 0;
    }
    goto LAB_0012bdd8;
  case 0x2a:
  case 0x30:
    goto switchD_0012bdbc_caseD_2a;
  }
}



long FUN_0012be30(long param_1,long param_2,int param_3)

{
  long lVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0x28);
  if (iVar2 < *(int *)(param_1 + 0x2c)) {
    *(int *)(param_1 + 0x28) = iVar2 + 1;
    lVar1 = *(long *)(param_1 + 0x20) + (long)iVar2 * 0x18;
    if ((lVar1 != 0 && param_2 != 0) && (param_3 != 0)) {
      *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar2 * 0x18) = 0;
      *(long *)(lVar1 + 8) = param_2;
      *(int *)(lVar1 + 0x10) = param_3;
      return lVar1;
    }
  }
  return 0;
}



int ** FUN_0012be90(long param_1,int **param_2,int param_3)

{
  int iVar1;
  char cVar2;
  int *piVar3;
  char *pcVar4;
  undefined4 uVar5;
  int **ppiVar6;
  
  pcVar4 = *(char **)(param_1 + 0x18);
  cVar2 = *pcVar4;
  ppiVar6 = param_2;
  do {
    if ((cVar2 == 'V') || (cVar2 == 'r')) {
      *(char **)(param_1 + 0x18) = pcVar4 + 1;
      if (cVar2 != 'r') {
        if (cVar2 != 'V') goto LAB_0012bef4;
        uVar5 = 0x1d;
        if (param_3 == 0) {
          uVar5 = 0x1a;
        }
        *(int *)(param_1 + 0x50) = *(int *)(param_1 + 0x50) + 9;
        goto LAB_0012bf08;
      }
      uVar5 = 0x1c;
      if (param_3 == 0) {
        uVar5 = 0x19;
      }
      *(int *)(param_1 + 0x50) = *(int *)(param_1 + 0x50) + 9;
      piVar3 = (int *)FUN_0012bd90(param_1,uVar5,0,0);
      *ppiVar6 = piVar3;
    }
    else {
      if (cVar2 != 'K') {
        if (((param_3 == 0) && (cVar2 == 'F')) && (param_2 != ppiVar6)) {
          do {
            piVar3 = *param_2;
            iVar1 = *piVar3;
            if (iVar1 == 0x1a) {
              *piVar3 = 0x1d;
            }
            else if (iVar1 == 0x1b) {
              *piVar3 = 0x1e;
            }
            else if (iVar1 == 0x19) {
              *piVar3 = 0x1c;
            }
            param_2 = (int **)(piVar3 + 2);
          } while (param_2 != ppiVar6);
        }
        return ppiVar6;
      }
      *(char **)(param_1 + 0x18) = pcVar4 + 1;
LAB_0012bef4:
      uVar5 = 0x1e;
      if (param_3 == 0) {
        uVar5 = 0x1b;
      }
      *(int *)(param_1 + 0x50) = *(int *)(param_1 + 0x50) + 6;
LAB_0012bf08:
      piVar3 = (int *)FUN_0012bd90(param_1,uVar5,0,0);
      *ppiVar6 = piVar3;
    }
    if (piVar3 == (int *)0x0) {
      return (int **)0x0;
    }
    pcVar4 = *(char **)(param_1 + 0x18);
    ppiVar6 = (int **)(piVar3 + 2);
    cVar2 = *pcVar4;
  } while( true );
}



long FUN_0012c040(long param_1,int param_2)

{
  long lVar1;
  undefined4 uVar2;
  byte bVar3;
  uint uVar4;
  long lVar5;
  uint uVar6;
  char *pcVar7;
  undefined *puVar8;
  uint uVar9;
  int iVar10;
  int iVar11;
  byte *pbVar12;
  long lVar13;
  uint uVar14;
  int iVar15;
  undefined8 uVar16;
  long lVar17;
  
  pcVar7 = *(char **)(param_1 + 0x18);
  if (*pcVar7 != 'S') {
    return 0;
  }
  *(char **)(param_1 + 0x18) = pcVar7 + 1;
  if (pcVar7[1] != '\0') {
    *(char **)(param_1 + 0x18) = pcVar7 + 2;
    bVar3 = pcVar7[1];
    uVar6 = (uint)bVar3;
    uVar14 = bVar3 - 0x30;
    if (((uVar14 & 0xff) < 10) || (bVar3 == 0x5f)) {
      if (bVar3 == 0x5f) {
        uVar4 = 0;
        goto LAB_0012c17c;
      }
    }
    else if (0x19 < (byte)(bVar3 + 0xbf)) goto LAB_0012c10c;
    uVar9 = 0;
    do {
      uVar4 = (uVar9 * 0x24 + uVar6) - 0x37;
      if ((uVar14 & 0xff) < 10) {
        uVar4 = (uVar9 * 0x24 + uVar6) - 0x30;
      }
      else if (0x19 < (uVar6 - 0x41 & 0xff)) {
        return 0;
      }
      uVar6 = 0;
      if (uVar4 < uVar9) {
        return 0;
      }
      pbVar12 = *(byte **)(param_1 + 0x18);
      if (*pbVar12 != 0) {
        *(byte **)(param_1 + 0x18) = pbVar12 + 1;
        uVar6 = (uint)*pbVar12;
        if (uVar6 == 0x5f) goto LAB_0012c178;
      }
      uVar14 = uVar6 - 0x30;
      uVar9 = uVar4;
    } while( true );
  }
  uVar6 = 0;
LAB_0012c10c:
  uVar14 = *(uint *)(param_1 + 0x10) >> 3 & 1;
  if (uVar14 < (param_2 != 0)) {
    uVar14 = (uint)((byte)(**(char **)(param_1 + 0x18) + 0xbdU) < 2);
  }
  if (uVar6 == 0x74) {
    puVar8 = &UNK_0015d720;
  }
  else if (uVar6 == 0x61) {
    puVar8 = &UNK_0015d758;
  }
  else if (uVar6 == 0x62) {
    puVar8 = &UNK_0015d790;
  }
  else if (uVar6 == 0x73) {
    puVar8 = &UNK_0015d7c8;
  }
  else if (uVar6 == 0x69) {
    puVar8 = &UNK_0015d800;
  }
  else if (uVar6 == 0x6f) {
    puVar8 = &UNK_0015d838;
  }
  else {
    if (uVar6 != 100) {
      return 0;
    }
    puVar8 = &UNK_0015d870;
  }
  lVar5 = *(long *)(puVar8 + 0x28);
  if (lVar5 == 0) {
    iVar15 = *(int *)(param_1 + 0x2c);
    iVar10 = *(int *)(param_1 + 0x28);
  }
  else {
    iVar10 = *(int *)(param_1 + 0x28);
    iVar15 = *(int *)(param_1 + 0x2c);
    uVar2 = *(undefined4 *)(puVar8 + 0x30);
    lVar17 = 0;
    if (iVar10 < iVar15) {
      lVar13 = (long)iVar10;
      iVar10 = iVar10 + 1;
      *(int *)(param_1 + 0x28) = iVar10;
      lVar1 = *(long *)(param_1 + 0x20) + lVar13 * 0x18;
      if (lVar1 != 0) {
        *(undefined4 *)(*(long *)(param_1 + 0x20) + lVar13 * 0x18) = 0x18;
        *(long *)(lVar1 + 8) = lVar5;
        *(undefined4 *)(lVar1 + 0x10) = uVar2;
        lVar17 = lVar1;
      }
    }
    *(long *)(param_1 + 0x48) = lVar17;
  }
  if (uVar14 == 0) {
    uVar16 = *(undefined8 *)(puVar8 + 8);
    iVar11 = *(int *)(puVar8 + 0x10);
  }
  else {
    uVar16 = *(undefined8 *)(puVar8 + 0x18);
    iVar11 = *(int *)(puVar8 + 0x20);
  }
  *(int *)(param_1 + 0x50) = *(int *)(param_1 + 0x50) + iVar11;
  if (iVar15 <= iVar10) {
    return 0;
  }
  *(int *)(param_1 + 0x28) = iVar10 + 1;
  lVar5 = *(long *)(param_1 + 0x20) + (long)iVar10 * 0x18;
  if (lVar5 != 0) {
    *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar10 * 0x18) = 0x18;
    *(undefined8 *)(lVar5 + 8) = uVar16;
    *(int *)(lVar5 + 0x10) = iVar11;
    return lVar5;
  }
  return 0;
LAB_0012c178:
  uVar4 = uVar4 + 1;
LAB_0012c17c:
  if (*(uint *)(param_1 + 0x38) <= uVar4) {
    return 0;
  }
  lVar5 = *(long *)(*(long *)(param_1 + 0x30) + (ulong)uVar4 * 8);
  *(int *)(param_1 + 0x40) = *(int *)(param_1 + 0x40) + 1;
  return lVar5;
}



void FUN_0012c300(int *param_1,int *param_2,undefined4 *param_3)

{
  int *piVar1;
  
  if (param_3 == (undefined4 *)0x0) {
switchD_0012c354_caseD_5:
    return;
  }
  do {
    switch(*param_3) {
    case 1:
    case 2:
    case 3:
    case 9:
    case 10:
    case 0xb:
    case 0xc:
    case 0xd:
    case 0xe:
    case 0xf:
    case 0x10:
    case 0x11:
    case 0x12:
    case 0x13:
    case 0x14:
    case 0x15:
    case 0x16:
    case 0x17:
    case 0x19:
    case 0x1a:
    case 0x1b:
    case 0x1c:
    case 0x1d:
    case 0x1e:
    case 0x1f:
    case 0x20:
    case 0x21:
    case 0x22:
    case 0x25:
    case 0x26:
    case 0x28:
    case 0x29:
    case 0x2a:
    case 0x2b:
    case 0x2c:
    case 0x2d:
    case 0x2e:
    case 0x2f:
    case 0x30:
    case 0x33:
    case 0x34:
    case 0x35:
    case 0x36:
    case 0x37:
    case 0x38:
    case 0x39:
    case 0x3a:
    case 0x3b:
    case 0x3c:
    case 0x3d:
    case 0x3e:
    case 0x3f:
    case 0x42:
    case 0x48:
    case 0x49:
    case 0x4a:
    case 0x4b:
    case 0x4c:
switchD_0012c354_caseD_1:
      piVar1 = *(int **)(param_3 + 2);
      break;
    case 4:
      *param_1 = *param_1 + 1;
      piVar1 = *(int **)(param_3 + 2);
      break;
    default:
      goto switchD_0012c354_caseD_5;
    case 7:
    case 8:
    case 0x32:
      param_3 = *(undefined4 **)(param_3 + 4);
      goto joined_r0x0012c374;
    case 0x23:
    case 0x24:
      piVar1 = *(int **)(param_3 + 2);
      if (*piVar1 == 5) {
        *param_2 = *param_2 + 1;
        goto switchD_0012c354_caseD_1;
      }
      break;
    case 0x43:
    case 0x44:
    case 0x45:
    case 0x46:
      param_3 = *(undefined4 **)(param_3 + 2);
      goto joined_r0x0012c374;
    }
    FUN_0012c300(param_1,param_2,piVar1);
    param_3 = *(undefined4 **)(param_3 + 4);
joined_r0x0012c374:
    if (param_3 == (undefined4 *)0x0) {
      return;
    }
  } while( true );
}



void FUN_0012c3cc(undefined *param_1,undefined param_2)

{
  long lVar1;
  
  lVar1 = *(long *)(param_1 + 0x100);
  if (lVar1 != 0xff) {
    *(long *)(param_1 + 0x100) = lVar1 + 1;
    param_1[lVar1] = param_2;
    param_1[0x108] = param_2;
    return;
  }
  param_1[0xff] = 0;
  (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
  *(undefined8 *)(param_1 + 0x100) = 1;
  *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
  *param_1 = param_2;
  param_1[0x108] = param_2;
  return;
}



long FUN_0012c444(byte **param_1)

{
  ulong uVar1;
  bool bVar2;
  byte *pbVar3;
  ulong uVar4;
  byte bVar5;
  ulong uVar6;
  
  pbVar3 = *param_1;
  bVar5 = *pbVar3;
  bVar2 = bVar5 == 0x6e;
  if (bVar2) {
    *param_1 = pbVar3 + 1;
    uVar6 = 0xffffffffffffffff;
    bVar5 = pbVar3[1];
  }
  else {
    uVar6 = 0;
  }
  if ((byte)(bVar5 - 0x30) < 10) {
    pbVar3 = *param_1;
    uVar4 = 0;
    do {
      pbVar3 = pbVar3 + 1;
      *param_1 = pbVar3;
      uVar1 = (ulong)bVar5;
      bVar5 = *pbVar3;
      uVar4 = (uVar4 * 10 + uVar1) - 0x30;
    } while ((byte)(bVar5 - 0x30) < 10);
  }
  else {
    uVar4 = 0;
  }
  return (uVar4 ^ uVar6) + (ulong)bVar2;
}



undefined8 FUN_0012c4cc(long param_1,ulong *param_2)

{
  uint uVar1;
  ulong uVar2;
  int *piVar3;
  int iVar4;
  
  if (*(long *)(param_1 + 0x120) == 0) {
    *(undefined4 *)(param_1 + 0x130) = 1;
  }
  else {
    piVar3 = *(int **)(*(long *)(*(long *)(param_1 + 0x120) + 8) + 0x10);
    uVar2 = *param_2 & 0xffffffff;
    if ((piVar3 != (int *)0x0) && (*piVar3 == 0x2f)) {
      iVar4 = (int)*param_2;
      if (iVar4 < 1) {
        if (iVar4 != 0) {
          return 0;
        }
      }
      else {
        do {
          piVar3 = *(int **)(piVar3 + 4);
          uVar1 = (int)uVar2 - 1;
          uVar2 = (ulong)uVar1;
          if (piVar3 == (int *)0x0) {
            return 0;
          }
          if (*piVar3 != 0x2f) {
            return 0;
          }
        } while (uVar1 != 0);
      }
      return *(undefined8 *)(piVar3 + 2);
    }
  }
  return 0;
}



int * FUN_0012c548(undefined8 param_1,undefined4 *param_2)

{
  int *piVar1;
  
  if (param_2 != (undefined4 *)0x0) {
    do {
      switch(*param_2) {
      case 0:
      case 6:
      case 0x18:
      case 0x27:
      case 0x31:
      case 0x40:
      case 0x45:
      case 0x47:
      case 0x4a:
      case 0x4b:
        goto LAB_0012c594;
      case 5:
        piVar1 = (int *)FUN_0012c4cc(param_1,param_2 + 2);
        if ((piVar1 != (int *)0x0) && (*piVar1 == 0x2f)) {
          return piVar1;
        }
        goto LAB_0012c594;
      case 7:
      case 8:
      case 0x32:
        goto switchD_0012c5b0_caseD_7;
      }
      piVar1 = (int *)FUN_0012c548(param_1,*(undefined8 *)(param_2 + 2));
      if (piVar1 != (int *)0x0) {
        return piVar1;
      }
switchD_0012c5b0_caseD_7:
      param_2 = *(undefined4 **)(param_2 + 4);
    } while (param_2 != (undefined4 *)0x0);
  }
LAB_0012c594:
  return (int *)0x0;
}



void FUN_0012c5e0(void *param_1,size_t param_2,void **param_3)

{
  void *pvVar1;
  void *__size;
  
  __size = param_3[2];
  pvVar1 = (void *)((long)param_3[1] + param_2 + 1);
  if (__size < pvVar1) {
    if (*(int *)(param_3 + 3) != 0) {
      return;
    }
    if ((__size != (void *)0x0) || (__size = (void *)0x2, (void *)0x2 < pvVar1)) {
      do {
        __size = (void *)((long)__size * 2);
      } while (__size < pvVar1);
    }
    pvVar1 = realloc(*param_3,(size_t)__size);
    if (pvVar1 == (void *)0x0) {
      free(*param_3);
      *param_3 = (void *)0x0;
      param_3[1] = (void *)0x0;
      param_3[2] = (void *)0x0;
      *(undefined4 *)(param_3 + 3) = 1;
      return;
    }
    *param_3 = pvVar1;
    param_3[2] = __size;
  }
  if (*(int *)(param_3 + 3) != 0) {
    return;
  }
  memcpy((void *)((long)*param_3 + (long)param_3[1]),param_1,param_2);
  *(undefined *)((long)*param_3 + param_2 + (long)param_3[1]) = 0;
  param_3[1] = (void *)((long)param_3[1] + param_2);
  return;
}



void FUN_0012c6d0(char *param_1,char *param_2)

{
  char *pcVar1;
  char cVar2;
  size_t sVar3;
  long lVar4;
  
  sVar3 = strlen(param_2);
  if (sVar3 != 0) {
    pcVar1 = param_2 + sVar3;
    lVar4 = *(long *)(param_1 + 0x100);
    do {
      while (cVar2 = *param_2, lVar4 == 0xff) {
        param_2 = param_2 + 1;
        param_1[0xff] = '\0';
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *(undefined8 *)(param_1 + 0x100) = 1;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        *param_1 = cVar2;
        param_1[0x108] = cVar2;
        lVar4 = 1;
        if (param_2 == pcVar1) {
          return;
        }
      }
      *(long *)(param_1 + 0x100) = lVar4 + 1;
      param_2 = param_2 + 1;
      param_1[lVar4] = cVar2;
      param_1[0x108] = cVar2;
      lVar4 = lVar4 + 1;
    } while (param_2 != pcVar1);
  }
  return;
}



long FUN_0012c784(long param_1,int param_2)

{
  char cVar1;
  int iVar2;
  long lVar3;
  void *__s1;
  
  lVar3 = (long)param_2;
  __s1 = *(void **)(param_1 + 0x18);
  if (lVar3 <= *(long *)(param_1 + 8) - (long)__s1) {
    *(long *)(param_1 + 0x18) = (long)__s1 + lVar3;
    if (((*(uint *)(param_1 + 0x10) >> 2 & 1) != 0) && (*(char *)((long)__s1 + lVar3) == '$')) {
      *(long *)(param_1 + 0x18) = (long)__s1 + lVar3 + 1;
    }
    if ((((9 < param_2) && (iVar2 = memcmp(__s1,"_GLOBAL_",8), iVar2 == 0)) &&
        ((cVar1 = *(char *)((long)__s1 + 8), cVar1 == '_' || cVar1 == '.' || (cVar1 == '$')))) &&
       (*(char *)((long)__s1 + 9) == 'N')) {
      *(int *)(param_1 + 0x50) = (*(int *)(param_1 + 0x50) + 0x16) - param_2;
      lVar3 = FUN_0012be30(param_1,"(anonymous namespace)",0x15);
      return lVar3;
    }
    iVar2 = *(int *)(param_1 + 0x28);
    if (iVar2 < *(int *)(param_1 + 0x2c)) {
      *(int *)(param_1 + 0x28) = iVar2 + 1;
      lVar3 = *(long *)(param_1 + 0x20) + (long)iVar2 * 0x18;
      if ((param_2 != 0 && __s1 != (void *)0x0) && (lVar3 != 0)) {
        *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar2 * 0x18) = 0;
        *(void **)(lVar3 + 8) = __s1;
        *(int *)(lVar3 + 0x10) = param_2;
        return lVar3;
      }
    }
  }
  return 0;
}



void FUN_0012c8d8(char *param_1,undefined8 param_2)

{
  char cVar1;
  size_t sVar2;
  long lVar3;
  size_t sVar4;
  char local_20 [32];
  
  sprintf(local_20,"%ld",param_2);
  sVar2 = strlen(local_20);
  if (sVar2 != 0) {
    sVar4 = 0;
    lVar3 = *(long *)(param_1 + 0x100);
    do {
      while (cVar1 = local_20[sVar4], lVar3 == 0xff) {
        sVar4 = sVar4 + 1;
        param_1[0xff] = '\0';
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *(undefined8 *)(param_1 + 0x100) = 1;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        *param_1 = cVar1;
        param_1[0x108] = cVar1;
        lVar3 = 1;
        if (sVar4 == sVar2) {
          return;
        }
      }
      *(long *)(param_1 + 0x100) = lVar3 + 1;
      sVar4 = sVar4 + 1;
      param_1[lVar3] = cVar1;
      param_1[0x108] = cVar1;
      lVar3 = lVar3 + 1;
    } while (sVar4 != sVar2);
  }
  return;
}



undefined8 FUN_0012c9a4(long param_1)

{
  byte bVar1;
  bool bVar2;
  undefined8 uVar3;
  byte *pbVar4;
  long lVar5;
  ulong uVar6;
  
  pbVar4 = *(byte **)(param_1 + 0x18);
  bVar1 = *pbVar4;
  bVar2 = bVar1 == 0x6e;
  if (bVar2) {
    *(byte **)(param_1 + 0x18) = pbVar4 + 1;
    bVar1 = pbVar4[1];
  }
  if ((byte)(bVar1 - 0x30) < 10) {
    pbVar4 = *(byte **)(param_1 + 0x18);
    lVar5 = 0;
    do {
      pbVar4 = pbVar4 + 1;
      uVar6 = (ulong)bVar1;
      *(byte **)(param_1 + 0x18) = pbVar4;
      bVar1 = *pbVar4;
      lVar5 = lVar5 * 10 + uVar6 + -0x30;
    } while ((byte)(bVar1 - 0x30) < 10);
    if ((0 < lVar5) && (!bVar2)) {
      uVar3 = FUN_0012c784();
      *(undefined8 *)(param_1 + 0x48) = uVar3;
      return uVar3;
    }
  }
  return 0;
}



long FUN_0012ca4c(long param_1)

{
  byte bVar1;
  long lVar2;
  long lVar3;
  byte *pbVar4;
  
  pbVar4 = *(byte **)(param_1 + 0x18);
  bVar1 = *pbVar4;
  if (bVar1 != 0x5f) {
    if ((bVar1 != 0x6e) && ((byte)(bVar1 - 0x30) < 10)) {
      lVar2 = 0;
      do {
        pbVar4 = pbVar4 + 1;
        *(byte **)(param_1 + 0x18) = pbVar4;
        lVar3 = lVar2 * 10 + (ulong)bVar1;
        bVar1 = *pbVar4;
        lVar2 = lVar3 + -0x30;
      } while ((byte)(bVar1 - 0x30) < 10);
      lVar3 = lVar3 + -0x2f;
      if (bVar1 == 0x5f) goto LAB_0012cac8;
    }
    return -1;
  }
  lVar3 = 0;
LAB_0012cac8:
  *(byte **)(param_1 + 0x18) = pbVar4 + 1;
  return lVar3;
}



ulong FUN_0012cad8(long param_1)

{
  long lVar1;
  byte bVar2;
  bool bVar3;
  char *pcVar4;
  long lVar5;
  byte *pbVar6;
  
  pcVar4 = *(char **)(param_1 + 0x18);
  if (*pcVar4 == '_') {
    pbVar6 = (byte *)(pcVar4 + 1);
    *(byte **)(param_1 + 0x18) = pbVar6;
    bVar2 = pcVar4[1];
    if (bVar2 == 0x6e) {
      pbVar6 = (byte *)(pcVar4 + 2);
      *(byte **)(param_1 + 0x18) = pbVar6;
      bVar2 = pcVar4[2];
      if (9 < (byte)(bVar2 - 0x30)) {
        return 1;
      }
      bVar3 = true;
    }
    else {
      if (9 < (byte)(bVar2 - 0x30)) {
        return 1;
      }
      bVar3 = false;
    }
    lVar5 = 0;
    do {
      pbVar6 = pbVar6 + 1;
      *(byte **)(param_1 + 0x18) = pbVar6;
      lVar1 = lVar5 * 10 + (ulong)bVar2;
      bVar2 = *pbVar6;
      lVar5 = lVar1 + -0x30;
    } while ((byte)(bVar2 - 0x30) < 10);
    if (bVar3) {
      return lVar1 - 0x31U >> 0x3f;
    }
  }
  return 1;
}



long FUN_0012cb7c(long param_1)

{
  int iVar1;
  byte bVar2;
  byte *pbVar3;
  long lVar4;
  long lVar5;
  byte *pbVar6;
  char *pcVar7;
  
  pcVar7 = *(char **)(param_1 + 0x18);
  if (*pcVar7 != 'T') {
    return 0;
  }
  pbVar6 = (byte *)(pcVar7 + 1);
  *(byte **)(param_1 + 0x18) = pbVar6;
  bVar2 = pcVar7[1];
  if (bVar2 == 0x5f) {
    lVar5 = 0;
  }
  else {
    if (bVar2 == 0x6e) {
      return 0;
    }
    if (9 < (byte)(bVar2 - 0x30)) {
      return 0;
    }
    lVar4 = 0;
    pbVar3 = (byte *)(pcVar7 + 2);
    do {
      pbVar6 = pbVar3;
      *(byte **)(param_1 + 0x18) = pbVar6;
      lVar5 = lVar4 * 10 + (ulong)bVar2;
      bVar2 = *pbVar6;
      lVar4 = lVar5 + -0x30;
      pbVar3 = pbVar6 + 1;
    } while ((byte)(bVar2 - 0x30) < 10);
    lVar5 = lVar5 + -0x2f;
    if (bVar2 != 0x5f) {
      return 0;
    }
  }
  iVar1 = *(int *)(param_1 + 0x28);
  *(byte **)(param_1 + 0x18) = pbVar6 + 1;
  *(int *)(param_1 + 0x40) = *(int *)(param_1 + 0x40) + 1;
  if (iVar1 < *(int *)(param_1 + 0x2c)) {
    *(int *)(param_1 + 0x28) = iVar1 + 1;
    lVar4 = *(long *)(param_1 + 0x20) + (long)iVar1 * 0x18;
    if (lVar4 != 0) {
      *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar1 * 0x18) = 5;
      *(long *)(lVar4 + 8) = lVar5;
      return lVar4;
    }
  }
  return 0;
}



undefined8 FUN_0012cc68(long param_1,uint param_2)

{
  byte *pbVar1;
  char *pcVar2;
  char *pcVar3;
  char cVar4;
  
  if (param_2 == 0) {
    pbVar1 = *(byte **)(param_1 + 0x18);
    if (*pbVar1 == 0) {
      return 0;
    }
    *(byte **)(param_1 + 0x18) = pbVar1 + 1;
    param_2 = (uint)*pbVar1;
  }
  if (param_2 == 0x68) {
    pcVar3 = *(char **)(param_1 + 0x18);
    cVar4 = *pcVar3;
    pcVar2 = pcVar3;
    if (cVar4 == 'n') {
      pcVar2 = pcVar3 + 1;
      *(char **)(param_1 + 0x18) = pcVar2;
      cVar4 = pcVar3[1];
    }
    if ((byte)(cVar4 - 0x30U) < 10) {
      do {
        pcVar2 = pcVar2 + 1;
        *(char **)(param_1 + 0x18) = pcVar2;
        cVar4 = *pcVar2;
      } while ((byte)(cVar4 - 0x30U) < 10);
      goto LAB_0012cce8;
    }
  }
  else {
    if (param_2 != 0x76) {
      return 0;
    }
    FUN_0012c444(param_1 + 0x18);
    if (**(char **)(param_1 + 0x18) != '_') {
      return 0;
    }
    *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
    FUN_0012c444(param_1 + 0x18);
    pcVar2 = *(char **)(param_1 + 0x18);
  }
  cVar4 = *pcVar2;
LAB_0012cce8:
  if (cVar4 != '_') {
    return 0;
  }
  *(char **)(param_1 + 0x18) = pcVar2 + 1;
  return 1;
}



long FUN_0012cd54(long param_1)

{
  undefined4 uVar1;
  byte bVar2;
  char cVar3;
  int iVar4;
  long lVar5;
  int *piVar6;
  undefined8 uVar7;
  undefined8 uVar8;
  int *piVar9;
  undefined8 uVar10;
  int *piVar11;
  char *pcVar12;
  long *plVar13;
  undefined8 uVar14;
  long lVar15;
  char *pcVar16;
  char **ppcVar17;
  undefined8 local_28;
  undefined8 local_20;
  undefined8 local_18;
  long local_8;
  
  pcVar12 = *(char **)(param_1 + 0x18);
  uVar14 = *(undefined8 *)(param_1 + 0x48);
  if (1 < (byte)(*pcVar12 + 0xb7U)) {
    return 0;
  }
  pcVar16 = pcVar12 + 1;
  *(char **)(param_1 + 0x18) = pcVar16;
  cVar3 = pcVar12[1];
  if (cVar3 == 'E') {
    *(char **)(param_1 + 0x18) = pcVar12 + 2;
    uVar14 = FUN_0012bd90(param_1,0x2f,0,0);
    return uVar14;
  }
  plVar13 = &local_8;
  local_8 = 0;
LAB_0012cdc4:
  switch(cVar3) {
  case 'I':
  case 'J':
    lVar5 = FUN_0012cd54(param_1);
    break;
  default:
    lVar5 = FUN_0012e994(param_1);
    break;
  case 'L':
    lVar5 = FUN_00131534(param_1);
    break;
  case 'X':
    pcVar12 = pcVar16 + 1;
    uVar1 = *(undefined4 *)(param_1 + 0x54);
    *(char **)(param_1 + 0x18) = pcVar12;
    *(undefined4 *)(param_1 + 0x54) = 1;
    cVar3 = pcVar16[1];
    if (cVar3 == 'L') {
      lVar5 = FUN_00131534(param_1);
      pcVar12 = *(char **)(param_1 + 0x18);
    }
    else if (cVar3 == 'T') {
      lVar5 = FUN_0012cb7c(param_1);
      pcVar12 = *(char **)(param_1 + 0x18);
    }
    else if (cVar3 == 's') {
      if (pcVar16[2] == 'r') {
        *(char **)(param_1 + 0x18) = pcVar16 + 3;
        uVar7 = FUN_0012e994(param_1);
        uVar8 = FUN_00130340(param_1);
        if (**(char **)(param_1 + 0x18) == 'I') {
          uVar10 = FUN_0012cd54(param_1);
          uVar8 = FUN_0012bd90(param_1,4,uVar8,uVar10);
        }
        lVar5 = FUN_0012bd90(param_1,1,uVar7,uVar8);
        pcVar12 = *(char **)(param_1 + 0x18);
      }
      else {
        if (pcVar16[2] != 'p') goto LAB_0012ceb0;
        *(char **)(param_1 + 0x18) = pcVar16 + 3;
        uVar7 = FUN_001316ac(param_1);
        lVar5 = FUN_0012bd90(param_1,0x4a,uVar7,0);
        pcVar12 = *(char **)(param_1 + 0x18);
      }
    }
    else {
      if (cVar3 == 'f') {
        if (pcVar16[2] != 'p') goto LAB_0012ceb0;
        *(char **)(param_1 + 0x18) = pcVar16 + 3;
        if (pcVar16[3] == 'T') {
          lVar15 = 0;
          *(char **)(param_1 + 0x18) = pcVar16 + 4;
        }
        else {
          iVar4 = FUN_0012ca4c(param_1);
          lVar15 = (long)(iVar4 + 1);
          if (iVar4 + 1 == 0) {
            pcVar12 = *(char **)(param_1 + 0x18);
            goto LAB_0012cfbc;
          }
        }
        iVar4 = *(int *)(param_1 + 0x28);
        if (iVar4 < *(int *)(param_1 + 0x2c)) {
          *(int *)(param_1 + 0x28) = iVar4 + 1;
          lVar5 = *(long *)(param_1 + 0x20) + (long)iVar4 * 0x18;
          if (lVar5 != 0) {
            *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar4 * 0x18) = 6;
            *(long *)(lVar5 + 8) = lVar15;
            pcVar12 = *(char **)(param_1 + 0x18);
            goto LAB_0012cf5c;
          }
        }
        goto switchD_0012d218_caseD_4;
      }
      if ((byte)(cVar3 - 0x30U) < 10) {
LAB_0012cf3c:
        lVar5 = FUN_00130340(param_1);
        pcVar12 = *(char **)(param_1 + 0x18);
        if (lVar5 != 0) {
          if (*pcVar12 == 'I') {
            uVar7 = FUN_0012cd54(param_1);
            lVar5 = FUN_0012bd90(param_1,4,lVar5,uVar7);
            pcVar12 = *(char **)(param_1 + 0x18);
          }
          goto LAB_0012cf5c;
        }
      }
      else {
        if (cVar3 == 'o') {
          if (pcVar16[2] == 'n') {
            *(char **)(param_1 + 0x18) = pcVar16 + 3;
            goto LAB_0012cf3c;
          }
        }
        else if (((cVar3 == 't') || (cVar3 == 'i')) && (pcVar16[2] == 'l')) {
          uVar7 = 0;
          if (cVar3 == 't') {
            uVar7 = FUN_0012e994(param_1);
            pcVar12 = *(char **)(param_1 + 0x18);
          }
          *(char **)(param_1 + 0x18) = pcVar12 + 2;
          uVar8 = FUN_0012e240(param_1,0x45);
          lVar5 = FUN_0012bd90(param_1,0x30,uVar7,uVar8);
          pcVar12 = *(char **)(param_1 + 0x18);
          goto LAB_0012cf5c;
        }
LAB_0012ceb0:
        piVar6 = (int *)FUN_0013014c(param_1);
        if (piVar6 != (int *)0x0) {
          iVar4 = *piVar6;
          if (iVar4 == 0x31) {
            ppcVar17 = *(char ***)(piVar6 + 2);
            pcVar12 = *ppcVar17;
            *(int *)(param_1 + 0x50) = *(int *)(param_1 + 0x50) + *(int *)(ppcVar17 + 2) + -2;
            iVar4 = strcmp(pcVar12,"st");
            if (iVar4 == 0) {
              uVar7 = FUN_0012e994(param_1);
LAB_0012d28c:
              lVar5 = FUN_0012bd90(param_1,0x36,piVar6,uVar7);
              pcVar12 = *(char **)(param_1 + 0x18);
              goto LAB_0012cf5c;
            }
            switch(*(undefined4 *)((long)ppcVar17 + 0x14)) {
            case 0:
              goto switchD_0012d218_caseD_0;
            case 1:
              cVar3 = *pcVar12;
              if (((cVar3 == 'm') || (cVar3 == 'p')) && (pcVar12[1] == cVar3)) {
                if (**(char **)(param_1 + 0x18) != '_') {
                  uVar7 = FUN_001316ac(param_1);
                  uVar7 = FUN_0012bd90(param_1,0x38,uVar7,uVar7);
                  goto LAB_0012d28c;
                }
                *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
              }
              goto switchD_0012d218_caseD_1;
            case 2:
              goto switchD_0012d0f0_caseD_2;
            case 3:
              goto switchD_0012d0f0_caseD_3;
            }
          }
          else if (iVar4 == 0x32) {
            switch(piVar6[2]) {
            case 0:
switchD_0012d218_caseD_0:
              lVar5 = FUN_0012bd90(param_1,0x35,piVar6,0);
              pcVar12 = *(char **)(param_1 + 0x18);
              goto LAB_0012cf5c;
            case 1:
              goto switchD_0012d218_caseD_1;
            case 2:
              pcVar12 = (char *)0x0;
switchD_0012d0f0_caseD_2:
              if (((**(char ***)(piVar6 + 2))[1] == 'c') &&
                 ((cVar3 = ***(char ***)(piVar6 + 2), (byte)(cVar3 + 0x8eU) < 2 ||
                  ((byte)(cVar3 + 0x9dU) < 2)))) {
                uVar7 = FUN_0012e994(param_1);
              }
              else {
                uVar7 = FUN_001316ac(param_1);
              }
              iVar4 = strcmp(pcVar12,"cl");
              if (iVar4 == 0) {
                uVar8 = FUN_0012e240(param_1,0x45);
              }
              else {
                iVar4 = strcmp(pcVar12,"dt");
                if ((iVar4 == 0) || (iVar4 = strcmp(pcVar12,"pt"), iVar4 == 0)) {
                  uVar8 = FUN_00130340(param_1);
                  if (**(char **)(param_1 + 0x18) == 'I') {
                    uVar10 = FUN_0012cd54(param_1);
                    uVar8 = FUN_0012bd90(param_1,4,uVar8,uVar10);
                  }
                }
                else {
                  uVar8 = FUN_001316ac(param_1);
                }
              }
              uVar7 = FUN_0012bd90(param_1,0x38,uVar7,uVar8);
              lVar5 = FUN_0012bd90(param_1,0x37,piVar6,uVar7);
              pcVar12 = *(char **)(param_1 + 0x18);
              goto LAB_0012cf5c;
            case 3:
              pcVar12 = (char *)0x0;
switchD_0012d0f0_caseD_3:
              iVar4 = strcmp(pcVar12,"qu");
              if (iVar4 == 0) {
                local_18 = FUN_001316ac(param_1);
                pcVar12 = *(char **)(param_1 + 0x18);
                cVar3 = *pcVar12;
                if (cVar3 == 'L') {
                  piVar9 = (int *)FUN_00131534(param_1);
                  pcVar12 = *(char **)(param_1 + 0x18);
                  cVar3 = *pcVar12;
LAB_0012d54c:
                  if (cVar3 == 'L') {
                    lVar5 = FUN_00131534(param_1);
                  }
                  else if (cVar3 == 'T') {
                    lVar5 = FUN_0012cb7c(param_1);
                  }
                  else if (cVar3 == 's') {
                    if (pcVar12[1] == 'r') {
                      *(char **)(param_1 + 0x18) = pcVar12 + 2;
                      uVar7 = FUN_0012e994(param_1);
                      uVar8 = FUN_00130340(param_1);
                      if (**(char **)(param_1 + 0x18) == 'I') {
                        uVar10 = FUN_0012cd54(param_1);
                        uVar8 = FUN_0012bd90(param_1,4,uVar8,uVar10);
                      }
                      lVar5 = FUN_0012bd90(param_1,1,uVar7,uVar8);
                    }
                    else {
                      if (pcVar12[1] != 'p') goto LAB_0012d5a4;
                      *(char **)(param_1 + 0x18) = pcVar12 + 2;
                      uVar7 = FUN_001316ac(param_1);
                      lVar5 = FUN_0012bd90(param_1,0x4a,uVar7,0);
                    }
                  }
                  else if (cVar3 == 'f') {
                    if (pcVar12[1] == 'p') {
                      *(char **)(param_1 + 0x18) = pcVar12 + 2;
                      if (pcVar12[2] == 'T') {
                        lVar15 = 0;
                        *(char **)(param_1 + 0x18) = pcVar12 + 3;
                      }
                      else {
                        iVar4 = FUN_0012ca4c(param_1);
                        if (iVar4 + 1 == 0) goto LAB_0012da04;
                        lVar15 = (long)(iVar4 + 1);
                      }
                      iVar4 = *(int *)(param_1 + 0x28);
                      lVar5 = 0;
                      if (iVar4 < *(int *)(param_1 + 0x2c)) {
                        *(int *)(param_1 + 0x28) = iVar4 + 1;
                        lVar5 = *(long *)(param_1 + 0x20) + (long)iVar4 * 0x18;
                        if (lVar5 != 0) {
                          *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar4 * 0x18) = 6;
                          *(long *)(lVar5 + 8) = lVar15;
                        }
                      }
                    }
                    else {
LAB_0012d5a4:
                      piVar11 = (int *)FUN_0013014c(param_1);
                      if (piVar11 == (int *)0x0) {
LAB_0012da04:
                        lVar5 = 0;
                      }
                      else {
                        iVar4 = *piVar11;
                        if (iVar4 == 0x31) {
                          ppcVar17 = *(char ***)(piVar11 + 2);
                          pcVar12 = *ppcVar17;
                          *(int *)(param_1 + 0x50) =
                               *(int *)(param_1 + 0x50) + *(int *)(ppcVar17 + 2) + -2;
                          iVar4 = strcmp(pcVar12,"st");
                          if (iVar4 != 0) {
                            lVar5 = 0;
                            switch(*(undefined4 *)((long)ppcVar17 + 0x14)) {
                            case 0:
                              goto switchD_0012d998_caseD_0;
                            case 1:
                              goto switchD_0012da00_caseD_1;
                            case 2:
                              goto switchD_0012da00_caseD_2;
                            case 3:
                              goto switchD_0012da00_caseD_3;
                            default:
                              goto switchD_0012d998_caseD_4;
                            }
                          }
                          uVar7 = FUN_0012e994(param_1);
                        }
                        else {
                          if (iVar4 == 0x32) {
                            lVar5 = 0;
                            switch(piVar11[2]) {
                            case 0:
switchD_0012d998_caseD_0:
                              lVar5 = FUN_0012bd90(param_1,0x35,piVar11,0);
                              break;
                            case 1:
                              goto switchD_0012d998_caseD_1;
                            case 2:
                              pcVar12 = (char *)0x0;
switchD_0012da00_caseD_2:
                              if ((**(char ***)(piVar11 + 2))[1] == 'c') {
                                cVar3 = ***(char ***)(piVar11 + 2);
                                bVar2 = cVar3 + 0x8e;
                                if ((1 < bVar2) && (1 < (byte)(cVar3 + 0x9dU))) goto LAB_0012dcbc;
                                local_20 = FUN_0012e994(param_1,bVar2,pcVar12,0);
                              }
                              else {
LAB_0012dcbc:
                                local_20 = FUN_001316ac(param_1);
                              }
                              iVar4 = strcmp(pcVar12,"cl");
                              if (iVar4 == 0) {
                                uVar7 = FUN_0012e240(param_1,0x45);
                              }
                              else {
                                iVar4 = strcmp(pcVar12,"dt");
                                if ((iVar4 == 0) || (iVar4 = strcmp(pcVar12,"pt"), iVar4 == 0)) {
                                  uVar7 = FUN_00130340(param_1);
                                  if (**(char **)(param_1 + 0x18) == 'I') {
                                    uVar8 = FUN_0012cd54(param_1);
                                    uVar7 = FUN_0012bd90(param_1,4,uVar7,uVar8);
                                  }
                                }
                                else {
                                  uVar7 = FUN_001316ac(param_1);
                                }
                              }
                              uVar7 = FUN_0012bd90(param_1,0x38,local_20,uVar7);
                              lVar5 = FUN_0012bd90(param_1,0x37,piVar11,uVar7);
                              break;
                            case 3:
                              pcVar12 = (char *)0x0;
switchD_0012da00_caseD_3:
                              iVar4 = strcmp(pcVar12,"qu");
                              if (iVar4 == 0) {
                                local_20 = FUN_001316ac(param_1);
                                local_28 = FUN_001316ac(param_1);
                                uVar7 = FUN_001316ac(param_1);
                              }
                              else {
                                if ((*pcVar12 != 'n') ||
                                   ((pcVar12[1] != 'a' && (pcVar12[1] != 'w')))) goto LAB_0012da04;
                                local_20 = FUN_0012e240(param_1,0x5f);
                                local_28 = FUN_0012e994(param_1);
                                pcVar12 = *(char **)(param_1 + 0x18);
                                cVar3 = *pcVar12;
                                if (cVar3 != 'E') {
                                  if (cVar3 == 'p') {
                                    lVar5 = 0;
                                    if (pcVar12[1] == 'i') {
                                      *(char **)(param_1 + 0x18) = pcVar12 + 2;
                                      uVar7 = FUN_0012e240(param_1,0x45);
                                      goto LAB_0012ddf4;
                                    }
                                  }
                                  else {
                                    if (cVar3 != 'i') goto LAB_0012da04;
                                    lVar5 = 0;
                                    if (pcVar12[1] == 'l') {
                                      uVar7 = FUN_001316ac(param_1);
                                      goto LAB_0012ddf4;
                                    }
                                  }
                                  break;
                                }
                                uVar7 = 0;
                                *(char **)(param_1 + 0x18) = pcVar12 + 1;
                              }
LAB_0012ddf4:
                              uVar7 = FUN_0012bd90(param_1,0x3b,local_28,uVar7);
                              uVar7 = FUN_0012bd90(param_1,0x3a,local_20,uVar7);
                              lVar5 = FUN_0012bd90(param_1,0x39,piVar11,uVar7);
                            }
                            goto switchD_0012d998_caseD_4;
                          }
                          if (iVar4 != 0x33) goto LAB_0012da04;
                          if (**(char **)(param_1 + 0x18) == '_') {
                            *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
                            uVar7 = FUN_0012e240(param_1,0x45);
                            goto LAB_0012d5ec;
                          }
switchD_0012d998_caseD_1:
                          uVar7 = FUN_001316ac(param_1);
                        }
LAB_0012d5ec:
                        lVar5 = FUN_0012bd90(param_1,0x36,piVar11,uVar7);
                      }
                    }
                  }
                  else {
                    if (9 < (byte)(cVar3 - 0x30U)) {
                      if (cVar3 != 'o') goto LAB_0012d584;
                      if (pcVar12[1] != 'n') goto LAB_0012d5a4;
                      *(char **)(param_1 + 0x18) = pcVar12 + 2;
                    }
                    lVar5 = FUN_00130340(param_1);
                    if ((lVar5 != 0) && (**(char **)(param_1 + 0x18) == 'I')) {
                      uVar7 = FUN_0012cd54(param_1);
                      lVar5 = FUN_0012bd90(param_1,4,lVar5,uVar7);
                    }
                  }
                }
                else {
                  if (cVar3 == 'T') {
                    piVar9 = (int *)FUN_0012cb7c(param_1);
                    pcVar12 = *(char **)(param_1 + 0x18);
                    cVar3 = *pcVar12;
                    goto LAB_0012d54c;
                  }
                  if (cVar3 == 's') {
                    if (pcVar12[1] == 'r') {
                      *(char **)(param_1 + 0x18) = pcVar12 + 2;
                      piVar9 = (int *)FUN_0012e994(param_1);
                      uVar7 = FUN_00130340(param_1);
                      if (**(char **)(param_1 + 0x18) != 'I') {
                        piVar9 = (int *)FUN_0012bd90(param_1,1,piVar9,uVar7);
                        pcVar12 = *(char **)(param_1 + 0x18);
                        cVar3 = *pcVar12;
                        goto LAB_0012d54c;
                      }
                      uVar8 = FUN_0012cd54(param_1);
                      uVar7 = FUN_0012bd90(param_1,4,uVar7,uVar8);
                      uVar8 = 1;
                      goto LAB_0012d538;
                    }
                    if (pcVar12[1] != 'p') goto LAB_0012d4e8;
                    *(char **)(param_1 + 0x18) = pcVar12 + 2;
                    piVar9 = (int *)FUN_001316ac(param_1);
                    uVar7 = 0x4a;
LAB_0012d88c:
                    piVar9 = (int *)FUN_0012bd90(param_1,uVar7,piVar9,0);
LAB_0012d898:
                    pcVar12 = *(char **)(param_1 + 0x18);
LAB_0012d89c:
                    cVar3 = *pcVar12;
                    goto LAB_0012d54c;
                  }
                  if (cVar3 == 'f') {
                    if (pcVar12[1] != 'p') goto LAB_0012d4e8;
                    *(char **)(param_1 + 0x18) = pcVar12 + 2;
                    if (pcVar12[2] == 'T') {
                      pcVar12 = pcVar12 + 3;
                      lVar5 = 0;
                      *(char **)(param_1 + 0x18) = pcVar12;
                    }
                    else {
                      iVar4 = FUN_0012ca4c(param_1);
                      pcVar12 = *(char **)(param_1 + 0x18);
                      if (iVar4 + 1 == 0) {
LAB_0012d8a8:
                        piVar9 = (int *)0x0;
                        cVar3 = *pcVar12;
                        goto LAB_0012d54c;
                      }
                      lVar5 = (long)(iVar4 + 1);
                    }
                    iVar4 = *(int *)(param_1 + 0x28);
                    if (iVar4 < *(int *)(param_1 + 0x2c)) {
                      *(int *)(param_1 + 0x28) = iVar4 + 1;
                      piVar9 = (int *)(*(long *)(param_1 + 0x20) + (long)iVar4 * 0x18);
                      if (piVar9 == (int *)0x0) goto LAB_0012d89c;
                      *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar4 * 0x18) = 6;
                      *(long *)(piVar9 + 2) = lVar5;
                      cVar3 = *pcVar12;
                    }
                    else {
                      cVar3 = *pcVar12;
                      piVar9 = (int *)0x0;
                    }
                    goto LAB_0012d54c;
                  }
                  if ((byte)(cVar3 - 0x30U) < 10) {
LAB_0012d700:
                    piVar9 = (int *)FUN_00130340(param_1);
                    pcVar12 = *(char **)(param_1 + 0x18);
                    cVar3 = *pcVar12;
                    if ((piVar9 != (int *)0x0) && (cVar3 == 'I')) {
                      uVar7 = FUN_0012cd54(param_1);
                      uVar8 = 4;
                      goto LAB_0012d538;
                    }
                    goto LAB_0012d54c;
                  }
                  if (cVar3 == 'o') {
                    if (pcVar12[1] == 'n') {
                      *(char **)(param_1 + 0x18) = pcVar12 + 2;
                      goto LAB_0012d700;
                    }
                  }
                  else if (((cVar3 == 't') || (cVar3 == 'i')) && (pcVar12[1] == 'l')) {
                    uVar7 = 0;
                    if (cVar3 == 't') {
                      uVar7 = FUN_0012e994(param_1);
                      pcVar12 = *(char **)(param_1 + 0x18);
                    }
                    *(char **)(param_1 + 0x18) = pcVar12 + 2;
                    uVar8 = FUN_0012e240(param_1,0x45);
                    piVar9 = (int *)FUN_0012bd90(param_1,0x30,uVar7,uVar8);
                    pcVar12 = *(char **)(param_1 + 0x18);
                    cVar3 = *pcVar12;
                    goto LAB_0012d54c;
                  }
LAB_0012d4e8:
                  piVar9 = (int *)FUN_0013014c(param_1);
                  if (piVar9 == (int *)0x0) goto LAB_0012d898;
                  iVar4 = *piVar9;
                  if (iVar4 == 0x31) {
                    ppcVar17 = *(char ***)(piVar9 + 2);
                    pcVar12 = *ppcVar17;
                    *(int *)(param_1 + 0x50) =
                         *(int *)(param_1 + 0x50) + *(int *)(ppcVar17 + 2) + -2;
                    iVar4 = strcmp(pcVar12,"st");
                    if (iVar4 != 0) {
                      switch(*(undefined4 *)((long)ppcVar17 + 0x14)) {
                      case 0:
                        goto switchD_0012d918_caseD_0;
                      case 1:
                        goto switchD_0012da84_caseD_1;
                      case 2:
                        goto switchD_0012da84_caseD_2;
                      case 3:
                        goto switchD_0012da84_caseD_3;
                      default:
                        goto switchD_0012d918_caseD_4;
                      }
                    }
                    uVar7 = FUN_0012e994(param_1);
                    uVar8 = 0x36;
                    goto LAB_0012d538;
                  }
                  if (iVar4 != 0x32) {
                    if (iVar4 == 0x33) {
                      if (**(char **)(param_1 + 0x18) != '_') goto switchD_0012d918_caseD_1;
                      *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
                      uVar7 = FUN_0012e240(param_1,0x45);
                      goto LAB_0012d530;
                    }
switchD_0012d918_caseD_4:
                    pcVar12 = *(char **)(param_1 + 0x18);
                    goto LAB_0012d8a8;
                  }
                  switch(piVar9[2]) {
                  case 0:
switchD_0012d918_caseD_0:
                    uVar7 = 0x35;
                    goto LAB_0012d88c;
                  case 1:
                    goto switchD_0012d918_caseD_1;
                  case 2:
                    pcVar12 = (char *)0x0;
switchD_0012da84_caseD_2:
                    if (((**(char ***)(piVar9 + 2))[1] == 'c') &&
                       ((cVar3 = ***(char ***)(piVar9 + 2), (byte)(cVar3 + 0x8eU) < 2 ||
                        ((byte)(cVar3 + 0x9dU) < 2)))) {
                      local_20 = FUN_0012e994(param_1);
                    }
                    else {
                      local_20 = FUN_001316ac(param_1);
                    }
                    iVar4 = strcmp(pcVar12,"cl");
                    if (iVar4 == 0) {
                      uVar7 = FUN_0012e240(param_1,0x45);
                    }
                    else {
                      iVar4 = strcmp(pcVar12,"dt");
                      if ((iVar4 == 0) || (iVar4 = strcmp(pcVar12,"pt"), iVar4 == 0)) {
                        uVar7 = FUN_00130340(param_1);
                        if (**(char **)(param_1 + 0x18) == 'I') {
                          uVar8 = FUN_0012cd54(param_1);
                          uVar7 = FUN_0012bd90(param_1,4,uVar7,uVar8);
                        }
                      }
                      else {
                        uVar7 = FUN_001316ac(param_1);
                      }
                    }
                    uVar7 = FUN_0012bd90(param_1,0x38,local_20,uVar7);
                    uVar8 = 0x37;
                    goto LAB_0012d538;
                  case 3:
                    pcVar12 = (char *)0x0;
switchD_0012da84_caseD_3:
                    iVar4 = strcmp(pcVar12,"qu");
                    if (iVar4 == 0) {
                      local_20 = FUN_001316ac(param_1);
                      uVar7 = FUN_001316ac(param_1);
                      uVar8 = FUN_001316ac(param_1);
LAB_0012dc6c:
                      uVar7 = FUN_0012bd90(param_1,0x3b,uVar7,uVar8);
                      uVar7 = FUN_0012bd90(param_1,0x3a,local_20,uVar7);
                      uVar8 = 0x39;
                      goto LAB_0012d538;
                    }
                    if ((*pcVar12 != 'n') || ((pcVar12[1] != 'a' && (pcVar12[1] != 'w'))))
                    goto switchD_0012d918_caseD_4;
                    local_20 = FUN_0012e240(param_1,0x5f);
                    uVar7 = FUN_0012e994(param_1);
                    pcVar12 = *(char **)(param_1 + 0x18);
                    cVar3 = *pcVar12;
                    if (cVar3 == 'E') {
                      uVar8 = 0;
                      *(char **)(param_1 + 0x18) = pcVar12 + 1;
                      goto LAB_0012dc6c;
                    }
                    if (cVar3 == 'p') {
                      if (pcVar12[1] == 'i') {
                        *(char **)(param_1 + 0x18) = pcVar12 + 2;
                        uVar8 = FUN_0012e240(param_1,0x45);
                        goto LAB_0012dc6c;
                      }
                    }
                    else {
                      if (cVar3 != 'i') {
                        piVar9 = (int *)0x0;
                        goto LAB_0012d54c;
                      }
                      if (pcVar12[1] == 'l') {
                        uVar8 = FUN_001316ac(param_1);
                        goto LAB_0012dc6c;
                      }
                    }
                    piVar9 = (int *)0x0;
LAB_0012d584:
                    if (((cVar3 != 't') && (cVar3 != 'i')) || (pcVar12[1] != 'l'))
                    goto LAB_0012d5a4;
                    uVar7 = 0;
                    if (cVar3 == 't') {
                      uVar7 = FUN_0012e994(param_1);
                    }
                    *(long *)(param_1 + 0x18) = *(long *)(param_1 + 0x18) + 2;
                    uVar8 = FUN_0012e240(param_1,0x45);
                    lVar5 = FUN_0012bd90(param_1,0x30,uVar7,uVar8);
                    break;
                  default:
                    goto switchD_0012d918_caseD_4;
                  }
                }
              }
              else {
                if ((*pcVar12 != 'n') || ((pcVar12[1] != 'a' && (pcVar12[1] != 'w')))) break;
                local_18 = FUN_0012e240(param_1,0x5f);
                piVar9 = (int *)FUN_0012e994(param_1);
                pcVar12 = *(char **)(param_1 + 0x18);
                cVar3 = *pcVar12;
                if (cVar3 != 'E') {
                  if (cVar3 == 'p') {
                    lVar5 = 0;
                    if (pcVar12[1] == 'i') {
                      *(char **)(param_1 + 0x18) = pcVar12 + 2;
                      lVar5 = FUN_0012e240(param_1,0x45);
                      goto switchD_0012d998_caseD_4;
                    }
                  }
                  else {
                    lVar5 = 0;
                    if ((cVar3 == 'i') && (pcVar12[1] == 'l')) {
                      lVar5 = FUN_001316ac(param_1);
                      goto switchD_0012d998_caseD_4;
                    }
                  }
                  goto LAB_0012cf5c;
                }
                lVar5 = 0;
                *(char **)(param_1 + 0x18) = pcVar12 + 1;
              }
switchD_0012d998_caseD_4:
              uVar7 = FUN_0012bd90(param_1,0x3b,piVar9,lVar5);
              uVar7 = FUN_0012bd90(param_1,0x3a,local_18,uVar7);
              lVar5 = FUN_0012bd90(param_1,0x39,piVar6,uVar7);
              pcVar12 = *(char **)(param_1 + 0x18);
              goto LAB_0012cf5c;
            }
          }
          else if (iVar4 == 0x33) {
            if (**(char **)(param_1 + 0x18) == '_') {
              *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
              uVar7 = FUN_0012e240(param_1,0x45);
              goto LAB_0012d28c;
            }
switchD_0012d218_caseD_1:
            uVar7 = FUN_001316ac(param_1);
            goto LAB_0012d28c;
          }
        }
switchD_0012d218_caseD_4:
        pcVar12 = *(char **)(param_1 + 0x18);
      }
LAB_0012cfbc:
      lVar5 = 0;
    }
LAB_0012cf5c:
    *(undefined4 *)(param_1 + 0x54) = uVar1;
    if (*pcVar12 != 'E') {
      return 0;
    }
    *(char **)(param_1 + 0x18) = pcVar12 + 1;
  }
  if (lVar5 == 0) {
    return 0;
  }
  lVar5 = FUN_0012bd90(param_1,0x2f,lVar5,0);
  *plVar13 = lVar5;
  if (lVar5 == 0) {
    return 0;
  }
  pcVar16 = *(char **)(param_1 + 0x18);
  plVar13 = (long *)(lVar5 + 0x10);
  cVar3 = *pcVar16;
  if (cVar3 == 'E') {
    *(undefined8 *)(param_1 + 0x48) = uVar14;
    *(char **)(param_1 + 0x18) = pcVar16 + 1;
    return local_8;
  }
  goto LAB_0012cdc4;
switchD_0012da84_caseD_1:
  cVar3 = *pcVar12;
  if (((cVar3 == 'm') || (cVar3 == 'p')) && (pcVar12[1] == cVar3)) {
    if (**(char **)(param_1 + 0x18) != '_') {
      uVar7 = FUN_001316ac(param_1);
      uVar7 = FUN_0012bd90(param_1,0x38,uVar7,uVar7);
      uVar8 = 0x36;
      goto LAB_0012d538;
    }
    *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
  }
switchD_0012d918_caseD_1:
  uVar7 = FUN_001316ac(param_1);
LAB_0012d530:
  uVar8 = 0x36;
LAB_0012d538:
  piVar9 = (int *)FUN_0012bd90(param_1,uVar8,piVar9,uVar7);
  pcVar12 = *(char **)(param_1 + 0x18);
  cVar3 = *pcVar12;
  goto LAB_0012d54c;
switchD_0012da00_caseD_1:
  cVar3 = *pcVar12;
  if (((cVar3 == 'm') || (cVar3 == 'p')) && (pcVar12[1] == cVar3)) {
    cVar3 = **(char **)(param_1 + 0x18);
    if (cVar3 != '_') {
      uVar7 = FUN_001316ac(param_1,cVar3,pcVar12,0);
      uVar7 = FUN_0012bd90(param_1,0x38,uVar7,uVar7);
      goto LAB_0012d5ec;
    }
    *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
  }
  goto switchD_0012d998_caseD_1;
}



undefined8 FUN_0012e240(long param_1,char param_2)

{
  undefined4 uVar1;
  char cVar2;
  int iVar3;
  int *piVar4;
  undefined8 uVar5;
  long lVar6;
  long lVar7;
  undefined8 uVar8;
  undefined8 uVar9;
  char *pcVar10;
  long *plVar11;
  char **ppcVar12;
  long local_8;
  
  pcVar10 = *(char **)(param_1 + 0x18);
  plVar11 = &local_8;
  local_8 = 0;
  if (*pcVar10 == param_2) {
    *(char **)(param_1 + 0x18) = pcVar10 + 1;
    uVar5 = FUN_0012bd90(param_1,0x2e,0,0);
    return uVar5;
  }
  do {
    uVar1 = *(undefined4 *)(param_1 + 0x54);
    *(undefined4 *)(param_1 + 0x54) = 1;
    cVar2 = *pcVar10;
    if (cVar2 == 'L') {
      lVar6 = FUN_00131534(param_1);
LAB_0012e404:
      *(undefined4 *)(param_1 + 0x54) = uVar1;
      if (lVar6 == 0) {
        return 0;
      }
    }
    else {
      if (cVar2 == 'T') {
        lVar6 = FUN_0012cb7c(param_1);
        goto LAB_0012e404;
      }
      if (cVar2 == 's') {
        if (pcVar10[1] == 'r') {
          *(char **)(param_1 + 0x18) = pcVar10 + 2;
          uVar5 = FUN_0012e994(param_1);
          uVar8 = FUN_00130340(param_1);
          if (**(char **)(param_1 + 0x18) == 'I') {
            uVar9 = FUN_0012cd54(param_1);
            uVar8 = FUN_0012bd90(param_1,4,uVar8,uVar9);
          }
          lVar6 = FUN_0012bd90(param_1,1,uVar5,uVar8);
        }
        else {
          if (pcVar10[1] != 'p') goto LAB_0012e2f4;
          *(char **)(param_1 + 0x18) = pcVar10 + 2;
          uVar5 = FUN_001316ac(param_1);
          lVar6 = FUN_0012bd90(param_1,0x4a,uVar5,0);
        }
        goto LAB_0012e404;
      }
      if (cVar2 == 'f') {
        if (pcVar10[1] != 'p') goto LAB_0012e2f4;
        *(char **)(param_1 + 0x18) = pcVar10 + 2;
        if (pcVar10[2] == 'T') {
          lVar7 = 0;
          *(char **)(param_1 + 0x18) = pcVar10 + 3;
        }
        else {
          iVar3 = FUN_0012ca4c(param_1);
          if (iVar3 + 1 == 0) goto switchD_0012e598_caseD_4;
          lVar7 = (long)(iVar3 + 1);
        }
        iVar3 = *(int *)(param_1 + 0x28);
        if (*(int *)(param_1 + 0x2c) <= iVar3) goto switchD_0012e598_caseD_4;
        *(int *)(param_1 + 0x28) = iVar3 + 1;
        lVar6 = *(long *)(param_1 + 0x20) + (long)iVar3 * 0x18;
        if (lVar6 == 0) goto switchD_0012e598_caseD_4;
        *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar3 * 0x18) = 6;
        *(long *)(lVar6 + 8) = lVar7;
      }
      else {
        if (9 < (byte)(cVar2 - 0x30U)) {
          if (cVar2 == 'o') {
            if (pcVar10[1] == 'n') {
              *(char **)(param_1 + 0x18) = pcVar10 + 2;
              goto LAB_0012e368;
            }
          }
          else if (((cVar2 == 't') || (cVar2 == 'i')) && (pcVar10[1] == 'l')) {
            uVar5 = 0;
            if (cVar2 == 't') {
              uVar5 = FUN_0012e994(param_1);
              pcVar10 = *(char **)(param_1 + 0x18);
            }
            *(char **)(param_1 + 0x18) = pcVar10 + 2;
            uVar8 = FUN_0012e240(param_1,0x45);
            lVar6 = FUN_0012bd90(param_1,0x30,uVar5,uVar8);
            goto LAB_0012e404;
          }
LAB_0012e2f4:
          piVar4 = (int *)FUN_0013014c(param_1);
          if (piVar4 == (int *)0x0) goto switchD_0012e598_caseD_4;
          iVar3 = *piVar4;
          if (iVar3 == 0x31) {
            ppcVar12 = *(char ***)(piVar4 + 2);
            pcVar10 = *ppcVar12;
            *(int *)(param_1 + 0x50) = *(int *)(param_1 + 0x50) + *(int *)(ppcVar12 + 2) + -2;
            iVar3 = strcmp(pcVar10,"st");
            if (iVar3 != 0) {
              switch(*(undefined4 *)((long)ppcVar12 + 0x14)) {
              case 0:
                goto switchD_0012e598_caseD_0;
              case 1:
                goto switchD_0012e5c0_caseD_1;
              case 2:
                goto switchD_0012e5c0_caseD_2;
              case 3:
                goto switchD_0012e5c0_caseD_3;
              default:
                goto switchD_0012e598_caseD_4;
              }
            }
            uVar5 = FUN_0012e994(param_1);
          }
          else {
            if (iVar3 == 0x32) {
              switch(piVar4[2]) {
              case 0:
switchD_0012e598_caseD_0:
                lVar6 = FUN_0012bd90(param_1,0x35,piVar4,0);
                goto LAB_0012e404;
              case 1:
                goto switchD_0012e598_caseD_1;
              case 2:
                pcVar10 = (char *)0x0;
switchD_0012e5c0_caseD_2:
                if (((**(char ***)(piVar4 + 2))[1] == 'c') &&
                   ((cVar2 = ***(char ***)(piVar4 + 2), (byte)(cVar2 + 0x8eU) < 2 ||
                    ((byte)(cVar2 + 0x9dU) < 2)))) {
                  uVar5 = FUN_0012e994(param_1);
                }
                else {
                  uVar5 = FUN_001316ac(param_1);
                }
                iVar3 = strcmp(pcVar10,"cl");
                if (iVar3 == 0) {
                  uVar8 = FUN_0012e240(param_1,0x45);
                }
                else {
                  iVar3 = strcmp(pcVar10,"dt");
                  if ((iVar3 == 0) || (iVar3 = strcmp(pcVar10,"pt"), iVar3 == 0)) {
                    uVar8 = FUN_00130340(param_1);
                    if (**(char **)(param_1 + 0x18) == 'I') {
                      uVar9 = FUN_0012cd54(param_1);
                      uVar8 = FUN_0012bd90(param_1,4,uVar8,uVar9);
                    }
                  }
                  else {
                    uVar8 = FUN_001316ac(param_1);
                  }
                }
                uVar5 = FUN_0012bd90(param_1,0x38,uVar5,uVar8);
                lVar6 = FUN_0012bd90(param_1,0x37,piVar4,uVar5);
                goto LAB_0012e404;
              case 3:
                pcVar10 = (char *)0x0;
switchD_0012e5c0_caseD_3:
                iVar3 = strcmp(pcVar10,"qu");
                if (iVar3 == 0) {
                  uVar5 = FUN_001316ac(param_1);
                  uVar8 = FUN_001316ac(param_1);
                  uVar9 = FUN_001316ac(param_1);
                }
                else {
                  if ((*pcVar10 != 'n') || ((pcVar10[1] != 'a' && (pcVar10[1] != 'w'))))
                  goto switchD_0012e598_caseD_4;
                  uVar5 = FUN_0012e240(param_1,0x5f);
                  uVar8 = FUN_0012e994(param_1);
                  pcVar10 = *(char **)(param_1 + 0x18);
                  cVar2 = *pcVar10;
                  if (cVar2 == 'E') {
                    uVar9 = 0;
                    *(char **)(param_1 + 0x18) = pcVar10 + 1;
                  }
                  else if (cVar2 == 'p') {
                    if (pcVar10[1] != 'i') goto switchD_0012e598_caseD_4;
                    *(char **)(param_1 + 0x18) = pcVar10 + 2;
                    uVar9 = FUN_0012e240(param_1,0x45);
                  }
                  else {
                    if ((cVar2 != 'i') || (pcVar10[1] != 'l')) {
switchD_0012e598_caseD_4:
                      *(undefined4 *)(param_1 + 0x54) = uVar1;
                      return 0;
                    }
                    uVar9 = FUN_001316ac(param_1);
                  }
                }
                uVar8 = FUN_0012bd90(param_1,0x3b,uVar8,uVar9);
                uVar5 = FUN_0012bd90(param_1,0x3a,uVar5,uVar8);
                lVar6 = FUN_0012bd90(param_1,0x39,piVar4,uVar5);
                goto LAB_0012e404;
              default:
                goto switchD_0012e598_caseD_4;
              }
            }
            if (iVar3 != 0x33) goto switchD_0012e598_caseD_4;
            if (**(char **)(param_1 + 0x18) == '_') {
              *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
              uVar5 = FUN_0012e240(param_1,0x45);
              goto LAB_0012e33c;
            }
switchD_0012e598_caseD_1:
            uVar5 = FUN_001316ac(param_1);
          }
LAB_0012e33c:
          lVar6 = FUN_0012bd90(param_1,0x36,piVar4,uVar5);
          goto LAB_0012e404;
        }
LAB_0012e368:
        lVar6 = FUN_00130340(param_1);
        if (lVar6 == 0) goto switchD_0012e598_caseD_4;
        if (**(char **)(param_1 + 0x18) == 'I') {
          uVar5 = FUN_0012cd54(param_1);
          lVar6 = FUN_0012bd90(param_1,4,lVar6,uVar5);
          goto LAB_0012e404;
        }
      }
      *(undefined4 *)(param_1 + 0x54) = uVar1;
    }
    lVar6 = FUN_0012bd90(param_1,0x2e,lVar6,0);
    *plVar11 = lVar6;
    if (lVar6 == 0) {
      return 0;
    }
    pcVar10 = *(char **)(param_1 + 0x18);
    plVar11 = (long *)(lVar6 + 0x10);
    if (*pcVar10 == param_2) {
      *(char **)(param_1 + 0x18) = pcVar10 + 1;
      return local_8;
    }
  } while( true );
switchD_0012e5c0_caseD_1:
  cVar2 = *pcVar10;
  if (((cVar2 == 'm') || (cVar2 == 'p')) && (pcVar10[1] == cVar2)) {
    if (**(char **)(param_1 + 0x18) != '_') {
      uVar5 = FUN_001316ac(param_1);
      uVar5 = FUN_0012bd90(param_1,0x38,uVar5,uVar5);
      goto LAB_0012e33c;
    }
    *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
  }
  goto switchD_0012e598_caseD_1;
}



int * FUN_0012e994(long param_1)

{
  bool bVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  int iVar6;
  byte bVar7;
  char cVar8;
  code *UNRECOVERED_JUMPTABLE_00;
  uint uVar9;
  int iVar10;
  int **ppiVar11;
  int *piVar12;
  undefined8 uVar13;
  long lVar14;
  long lVar15;
  ulong uVar16;
  undefined8 uVar17;
  undefined8 uVar18;
  ushort uVar19;
  int *piVar20;
  byte *pbVar21;
  byte *pbVar22;
  byte *pbVar23;
  char *pcVar24;
  int *local_8;
  
  pbVar22 = *(byte **)(param_1 + 0x18);
  bVar7 = *pbVar22;
  if ((bVar7 == 0x56 || bVar7 == 0x72) || (uVar9 = (uint)bVar7, uVar9 == 0x4b)) {
    ppiVar11 = (int **)FUN_0012be90(param_1,&local_8,0);
    if (ppiVar11 == (int **)0x0) {
      return (int *)0x0;
    }
    if (**(char **)(param_1 + 0x18) == 'F') {
      piVar12 = (int *)FUN_00131d14(param_1);
      *ppiVar11 = piVar12;
    }
    else {
      piVar12 = (int *)FUN_0012e994();
      *ppiVar11 = piVar12;
    }
    if (piVar12 == (int *)0x0) {
      return (int *)0x0;
    }
    if (*piVar12 - 0x1fU < 2) {
      piVar20 = *(int **)(piVar12 + 2);
      *(int **)(piVar12 + 2) = local_8;
      local_8 = *ppiVar11;
      *ppiVar11 = piVar20;
    }
    if (local_8 == (int *)0x0) {
      return (int *)0x0;
    }
    iVar10 = *(int *)(param_1 + 0x38);
    if (*(int *)(param_1 + 0x3c) <= iVar10) {
      return (int *)0x0;
    }
    *(int **)(*(long *)(param_1 + 0x30) + (long)iVar10 * 8) = local_8;
    *(int *)(param_1 + 0x38) = iVar10 + 1;
    return local_8;
  }
  switch(uVar9) {
  case 0x30:
  case 0x31:
  case 0x32:
  case 0x33:
  case 0x34:
  case 0x35:
  case 0x36:
  case 0x37:
  case 0x38:
  case 0x39:
  case 0x4e:
  case 0x5a:
    local_8 = (int *)FUN_001308c4(param_1);
    break;
  default:
    goto switchD_0012ea10_caseD_3a;
  case 0x41:
    pbVar21 = pbVar22 + 1;
    *(byte **)(param_1 + 0x18) = pbVar21;
    if (pbVar22[1] == 0x5f) {
      lVar14 = 0;
    }
    else {
      if ((byte)(pbVar22[1] - 0x30) < 10) {
        pbVar22 = pbVar22 + 2;
        do {
          pbVar23 = pbVar22;
          *(byte **)(param_1 + 0x18) = pbVar23;
          pbVar22 = pbVar23 + 1;
        } while ((byte)(*pbVar23 - 0x30) < 10);
        lVar14 = FUN_0012be30(param_1,pbVar21,(int)pbVar23 - (int)pbVar21);
joined_r0x0012f46c:
        if (lVar14 == 0) goto LAB_0012ebb8;
        pbVar21 = *(byte **)(param_1 + 0x18);
      }
      else {
        uVar2 = *(undefined4 *)(param_1 + 0x54);
        *(undefined4 *)(param_1 + 0x54) = 1;
        bVar7 = pbVar22[1];
        if (bVar7 == 0x4c) {
          lVar14 = FUN_00131534(param_1);
LAB_0012f468:
          *(undefined4 *)(param_1 + 0x54) = uVar2;
          goto joined_r0x0012f46c;
        }
        if (bVar7 == 0x54) {
          lVar14 = FUN_0012cb7c(param_1);
          goto LAB_0012f468;
        }
        if (bVar7 == 0x73) {
          if (pbVar22[2] == 0x72) {
            *(byte **)(param_1 + 0x18) = pbVar22 + 3;
            uVar13 = FUN_0012e994(param_1);
            uVar17 = FUN_00130340(param_1);
            if (**(char **)(param_1 + 0x18) == 'I') {
              uVar18 = FUN_0012cd54(param_1);
              uVar17 = FUN_0012bd90(param_1,4,uVar17,uVar18);
              lVar14 = FUN_0012bd90(param_1,1,uVar13,uVar17);
            }
            else {
              lVar14 = FUN_0012bd90(param_1,1,uVar13,uVar17);
            }
          }
          else {
            if (pbVar22[2] != 0x70) goto LAB_0012f40c;
            *(byte **)(param_1 + 0x18) = pbVar22 + 3;
            uVar13 = FUN_001316ac(param_1);
            lVar14 = FUN_0012bd90(param_1,0x4a,uVar13,0);
          }
          goto LAB_0012f468;
        }
        if (bVar7 != 0x66) {
          if ((byte)(bVar7 - 0x30) < 10) {
LAB_0012f4e0:
            lVar14 = FUN_00130340(param_1);
            if (lVar14 != 0) {
              pbVar21 = *(byte **)(param_1 + 0x18);
              if (*pbVar21 != 0x49) {
                *(undefined4 *)(param_1 + 0x54) = uVar2;
                goto LAB_0012eba8;
              }
              uVar13 = FUN_0012cd54(param_1);
              lVar14 = FUN_0012bd90(param_1,4,lVar14,uVar13);
              goto LAB_0012f468;
            }
          }
          else {
            if (bVar7 == 0x6f) {
              if (pbVar22[2] == 0x6e) {
                *(byte **)(param_1 + 0x18) = pbVar22 + 3;
                goto LAB_0012f4e0;
              }
            }
            else if (((bVar7 == 0x74) || (bVar7 == 0x69)) && (pbVar22[2] == 0x6c)) {
              uVar13 = 0;
              if (bVar7 == 0x74) {
                uVar13 = FUN_0012e994(param_1);
              }
              *(long *)(param_1 + 0x18) = *(long *)(param_1 + 0x18) + 2;
              uVar17 = FUN_0012e240(param_1,0x45);
              lVar14 = FUN_0012bd90(param_1,0x30,uVar13,uVar17);
              goto LAB_0012f468;
            }
LAB_0012f40c:
            piVar12 = (int *)FUN_0013014c(param_1);
            if (piVar12 != (int *)0x0) {
              iVar10 = *piVar12;
              if (iVar10 == 0x31) {
                pcVar24 = **(char ***)(piVar12 + 2);
                *(int *)(param_1 + 0x50) =
                     *(int *)(param_1 + 0x50) + *(int *)(*(char ***)(piVar12 + 2) + 2) + -2;
                iVar10 = strcmp(pcVar24,"st");
                if (iVar10 == 0) {
                  uVar13 = FUN_0012e994(param_1);
LAB_0012f454:
                  lVar14 = FUN_0012bd90(param_1,0x36,piVar12,uVar13);
                  goto LAB_0012f468;
                }
                switch(*(undefined4 *)(*(long *)(piVar12 + 2) + 0x14)) {
                case 0:
                  goto switchD_0012f7a4_caseD_0;
                case 1:
                  cVar8 = *pcVar24;
                  if (((cVar8 == 'm') || (cVar8 == 'p')) && (pcVar24[1] == cVar8)) {
                    if (**(char **)(param_1 + 0x18) != '_') {
                      uVar13 = FUN_001316ac(param_1);
                      uVar13 = FUN_0012bd90(param_1,0x38,uVar13,uVar13);
                      goto LAB_0012f454;
                    }
                    *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
                  }
                  goto switchD_0012f7a4_caseD_1;
                case 2:
                  goto switchD_0012f9d0_caseD_2;
                case 3:
                  goto switchD_0012f9d0_caseD_3;
                }
              }
              else if (iVar10 == 0x32) {
                switch(piVar12[2]) {
                case 0:
switchD_0012f7a4_caseD_0:
                  lVar14 = FUN_0012bd90(param_1,0x35,piVar12,0);
                  goto LAB_0012f468;
                case 1:
                  goto switchD_0012f7a4_caseD_1;
                case 2:
                  pcVar24 = (char *)0x0;
switchD_0012f9d0_caseD_2:
                  if (((**(char ***)(piVar12 + 2))[1] == 'c') &&
                     ((cVar8 = ***(char ***)(piVar12 + 2), (byte)(cVar8 + 0x8eU) < 2 ||
                      ((byte)(cVar8 + 0x9dU) < 2)))) {
                    uVar13 = FUN_0012e994(param_1);
                  }
                  else {
                    uVar13 = FUN_001316ac(param_1);
                  }
                  iVar10 = strcmp(pcVar24,"cl");
                  if (iVar10 == 0) {
                    uVar17 = FUN_0012e240(param_1,0x45);
                  }
                  else {
                    iVar10 = strcmp(pcVar24,"dt");
                    if ((iVar10 == 0) || (iVar10 = strcmp(pcVar24,"pt"), iVar10 == 0)) {
                      uVar17 = FUN_00130340(param_1);
                      if (**(char **)(param_1 + 0x18) == 'I') {
                        uVar18 = FUN_0012cd54(param_1);
                        uVar17 = FUN_0012bd90(param_1,4,uVar17,uVar18);
                      }
                    }
                    else {
                      uVar17 = FUN_001316ac(param_1);
                    }
                  }
                  uVar13 = FUN_0012bd90(param_1,0x38,uVar13,uVar17);
                  lVar14 = FUN_0012bd90(param_1,0x37,piVar12,uVar13);
                  goto LAB_0012f468;
                case 3:
                  pcVar24 = (char *)0x0;
switchD_0012f9d0_caseD_3:
                  iVar10 = strcmp(pcVar24,"qu");
                  if (iVar10 == 0) {
                    uVar13 = FUN_001316ac(param_1);
                    uVar17 = FUN_001316ac(param_1);
                    uVar18 = FUN_001316ac(param_1);
LAB_0012f84c:
                    uVar17 = FUN_0012bd90(param_1,0x3b,uVar17,uVar18);
                    uVar13 = FUN_0012bd90(param_1,0x3a,uVar13,uVar17);
                    lVar14 = FUN_0012bd90(param_1,0x39,piVar12,uVar13);
                    goto LAB_0012f468;
                  }
                  if ((*pcVar24 == 'n') && ((pcVar24[1] == 'a' || (pcVar24[1] == 'w')))) {
                    uVar13 = FUN_0012e240(param_1,0x5f);
                    uVar17 = FUN_0012e994(param_1);
                    pcVar24 = *(char **)(param_1 + 0x18);
                    cVar8 = *pcVar24;
                    if (cVar8 == 'E') {
                      uVar18 = 0;
                      *(char **)(param_1 + 0x18) = pcVar24 + 1;
                      goto LAB_0012f84c;
                    }
                    if (cVar8 == 'p') {
                      if (pcVar24[1] == 'i') {
                        *(char **)(param_1 + 0x18) = pcVar24 + 2;
                        uVar18 = FUN_0012e240(param_1,0x45);
                        goto LAB_0012f84c;
                      }
                    }
                    else if ((cVar8 == 'i') && (pcVar24[1] == 'l')) {
                      uVar18 = FUN_001316ac(param_1);
                      goto LAB_0012f84c;
                    }
                  }
                }
              }
              else if (iVar10 == 0x33) {
                if (**(char **)(param_1 + 0x18) == '_') {
                  *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
                  uVar13 = FUN_0012e240(param_1,0x45);
                  goto LAB_0012f454;
                }
switchD_0012f7a4_caseD_1:
                uVar13 = FUN_001316ac(param_1);
                goto LAB_0012f454;
              }
            }
          }
switchD_0012f7a4_caseD_4:
          *(undefined4 *)(param_1 + 0x54) = uVar2;
          goto LAB_0012ebb8;
        }
        if (pbVar22[2] != 0x70) goto LAB_0012f40c;
        *(byte **)(param_1 + 0x18) = pbVar22 + 3;
        if (pbVar22[3] == 0x54) {
          iVar10 = 0;
          *(byte **)(param_1 + 0x18) = pbVar22 + 4;
        }
        else {
          iVar10 = FUN_0012ca4c(param_1);
          iVar10 = iVar10 + 1;
          if (iVar10 == 0) goto switchD_0012f7a4_caseD_4;
        }
        iVar6 = *(int *)(param_1 + 0x28);
        if (*(int *)(param_1 + 0x2c) <= iVar6) goto switchD_0012f7a4_caseD_4;
        *(int *)(param_1 + 0x28) = iVar6 + 1;
        lVar14 = *(long *)(param_1 + 0x20) + (long)iVar6 * 0x18;
        if (lVar14 == 0) goto switchD_0012f7a4_caseD_4;
        *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar6 * 0x18) = 6;
        *(long *)(lVar14 + 8) = (long)iVar10;
        *(undefined4 *)(param_1 + 0x54) = uVar2;
        pbVar21 = *(byte **)(param_1 + 0x18);
      }
LAB_0012eba8:
      if (*pbVar21 != 0x5f) goto LAB_0012ebb8;
    }
    *(byte **)(param_1 + 0x18) = pbVar21 + 1;
    uVar13 = FUN_0012e994(param_1);
    local_8 = (int *)FUN_0012bd90(param_1,0x2a,lVar14,uVar13);
    break;
  case 0x43:
    *(byte **)(param_1 + 0x18) = pbVar22 + 1;
    uVar13 = FUN_0012e994(param_1);
    local_8 = (int *)FUN_0012bd90(param_1,0x25,uVar13,0);
    break;
  case 0x44:
    *(byte **)(param_1 + 0x18) = pbVar22 + 1;
    if (pbVar22[1] == 0) {
      return (int *)0x0;
    }
    *(byte **)(param_1 + 0x18) = pbVar22 + 2;
    switch(pbVar22[1]) {
    case 0x46:
      iVar10 = *(int *)(param_1 + 0x28);
      if (*(int *)(param_1 + 0x2c) <= iVar10) {
        uRam0000000000000000 = 0;
                    // WARNING: Treating indirect jump as call
        UNRECOVERED_JUMPTABLE_00 = (code *)SoftwareBreakpoint(1000,0x12f4cc);
        piVar12 = (int *)(*UNRECOVERED_JUMPTABLE_00)();
        return piVar12;
      }
      *(int *)(param_1 + 0x28) = iVar10 + 1;
      local_8 = (int *)(*(long *)(param_1 + 0x20) + (long)iVar10 * 0x18);
      *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar10 * 0x18) = 0x2c;
      bVar1 = (byte)(pbVar22[2] - 0x30) < 10;
      *(ushort *)(local_8 + 4) = (ushort)bVar1;
      if (bVar1) {
        FUN_0012c444(param_1 + 0x18);
      }
      piVar12 = local_8;
      uVar13 = FUN_0012e994(param_1);
      *(undefined8 *)(piVar12 + 2) = uVar13;
      if (*(long *)(local_8 + 2) == 0) {
        return (int *)0x0;
      }
      FUN_0012c444(param_1 + 0x18);
      pcVar24 = *(char **)(param_1 + 0x18);
      uVar19 = 0;
      if (*pcVar24 != '\0') {
        *(char **)(param_1 + 0x18) = pcVar24 + 1;
        uVar19 = (ushort)(*pcVar24 == 's');
      }
      *(ushort *)((long)local_8 + 0x12) = uVar19;
      return local_8;
    default:
      goto switchD_0012ea10_caseD_3a;
    case 0x54:
    case 0x74:
      uVar2 = *(undefined4 *)(param_1 + 0x54);
      *(undefined4 *)(param_1 + 0x54) = 1;
      bVar7 = pbVar22[2];
      if (bVar7 == 0x4c) {
        lVar14 = FUN_00131534(param_1);
      }
      else if (bVar7 == 0x54) {
        lVar14 = FUN_0012cb7c(param_1);
      }
      else if (bVar7 == 0x73) {
        if (pbVar22[3] == 0x72) {
          *(byte **)(param_1 + 0x18) = pbVar22 + 4;
          uVar13 = FUN_0012e994(param_1);
          uVar17 = FUN_00130340(param_1);
          if (**(char **)(param_1 + 0x18) == 'I') {
            uVar18 = FUN_0012cd54(param_1);
            uVar17 = FUN_0012bd90(param_1,4,uVar17,uVar18);
            lVar14 = FUN_0012bd90(param_1,1,uVar13,uVar17);
          }
          else {
            lVar14 = FUN_0012bd90(param_1,1,uVar13,uVar17);
          }
        }
        else {
          if (pbVar22[3] != 0x70) goto LAB_0012f1f0;
          *(byte **)(param_1 + 0x18) = pbVar22 + 4;
          uVar13 = FUN_001316ac(param_1);
          lVar14 = FUN_0012bd90(param_1,0x4a,uVar13,0);
        }
      }
      else if (bVar7 == 0x66) {
        if (pbVar22[3] != 0x70) goto LAB_0012f1f0;
        *(byte **)(param_1 + 0x18) = pbVar22 + 4;
        if (pbVar22[4] == 0x54) {
          iVar10 = 0;
          *(byte **)(param_1 + 0x18) = pbVar22 + 5;
        }
        else {
          iVar10 = FUN_0012ca4c(param_1);
          iVar10 = iVar10 + 1;
          if (iVar10 == 0) goto LAB_0012fa60;
        }
        iVar6 = *(int *)(param_1 + 0x28);
        if (*(int *)(param_1 + 0x2c) <= iVar6) goto LAB_0012fa60;
        *(int *)(param_1 + 0x28) = iVar6 + 1;
        lVar15 = *(long *)(param_1 + 0x20) + (long)iVar6 * 0x18;
        lVar14 = 0;
        if (lVar15 != 0) {
          *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar6 * 0x18) = 6;
          *(long *)(lVar15 + 8) = (long)iVar10;
          lVar14 = lVar15;
        }
      }
      else {
        if ((byte)(bVar7 - 0x30) < 10) {
LAB_0012f5f8:
          lVar14 = FUN_00130340(param_1);
          if (lVar14 != 0) {
            if (**(char **)(param_1 + 0x18) == 'I') {
              uVar13 = FUN_0012cd54(param_1);
              lVar14 = FUN_0012bd90(param_1,4,lVar14,uVar13);
            }
            goto switchD_0012fc64_caseD_4;
          }
        }
        else {
          if (bVar7 == 0x6f) {
            if (pbVar22[3] == 0x6e) {
              *(byte **)(param_1 + 0x18) = pbVar22 + 4;
              goto LAB_0012f5f8;
            }
          }
          else if (((bVar7 == 0x74) || (bVar7 == 0x69)) && (pbVar22[3] == 0x6c)) {
            uVar13 = 0;
            if (bVar7 == 0x74) {
              uVar13 = FUN_0012e994(param_1);
            }
            *(long *)(param_1 + 0x18) = *(long *)(param_1 + 0x18) + 2;
            uVar17 = FUN_0012e240(param_1,0x45);
            lVar14 = FUN_0012bd90(param_1,0x30,uVar13,uVar17);
            goto switchD_0012fc64_caseD_4;
          }
LAB_0012f1f0:
          piVar12 = (int *)FUN_0013014c(param_1);
          if (piVar12 != (int *)0x0) {
            iVar10 = *piVar12;
            if (iVar10 == 0x31) {
              pcVar24 = **(char ***)(piVar12 + 2);
              *(int *)(param_1 + 0x50) =
                   *(int *)(param_1 + 0x50) + *(int *)(*(char ***)(piVar12 + 2) + 2) + -2;
              iVar10 = strcmp(pcVar24,"st");
              if (iVar10 != 0) {
                lVar14 = 0;
                switch(*(undefined4 *)(*(long *)(piVar12 + 2) + 0x14)) {
                case 0:
                  goto switchD_0012fc64_caseD_0;
                case 1:
                  goto switchD_0012fa4c_caseD_1;
                case 2:
                  goto switchD_0012fa4c_caseD_2;
                case 3:
                  goto switchD_0012fa4c_caseD_3;
                default:
                  goto switchD_0012fc64_caseD_4;
                }
              }
              uVar13 = FUN_0012e994(param_1);
            }
            else {
              if (iVar10 == 0x32) {
                lVar14 = 0;
                switch(piVar12[2]) {
                case 0:
switchD_0012fc64_caseD_0:
                  lVar14 = FUN_0012bd90(param_1,0x35,piVar12,0);
                  break;
                case 1:
                  goto switchD_0012fc64_caseD_1;
                case 2:
                  pcVar24 = (char *)0x0;
switchD_0012fa4c_caseD_2:
                  if ((**(char ***)(piVar12 + 2))[1] == 'c') {
                    cVar8 = ***(char ***)(piVar12 + 2);
                    bVar7 = cVar8 + 0x8e;
                    if ((1 < bVar7) && (1 < (byte)(cVar8 + 0x9dU))) goto LAB_0012fc94;
                    uVar13 = FUN_0012e994(param_1,bVar7,0);
                  }
                  else {
LAB_0012fc94:
                    uVar13 = FUN_001316ac(param_1);
                  }
                  iVar10 = strcmp(pcVar24,"cl");
                  if (iVar10 == 0) {
                    uVar17 = FUN_0012e240(param_1,0x45);
                  }
                  else {
                    iVar10 = strcmp(pcVar24,"dt");
                    if ((iVar10 == 0) || (iVar10 = strcmp(pcVar24,"pt"), iVar10 == 0)) {
                      uVar17 = FUN_00130340(param_1);
                      if (**(char **)(param_1 + 0x18) == 'I') {
                        uVar18 = FUN_0012cd54(param_1);
                        uVar17 = FUN_0012bd90(param_1,4,uVar17,uVar18);
                      }
                    }
                    else {
                      uVar17 = FUN_001316ac(param_1);
                    }
                  }
                  uVar13 = FUN_0012bd90(param_1,0x38,uVar13,uVar17);
                  lVar14 = FUN_0012bd90(param_1,0x37,piVar12,uVar13);
                  break;
                case 3:
                  pcVar24 = (char *)0x0;
switchD_0012fa4c_caseD_3:
                  iVar10 = strcmp(pcVar24,"qu");
                  if (iVar10 == 0) {
                    uVar13 = FUN_001316ac(param_1);
                    uVar17 = FUN_001316ac(param_1);
                    uVar18 = FUN_001316ac(param_1);
                  }
                  else {
                    if ((*pcVar24 != 'n') || ((pcVar24[1] != 'a' && (pcVar24[1] != 'w'))))
                    goto LAB_0012fa60;
                    uVar13 = FUN_0012e240(param_1,0x5f);
                    uVar17 = FUN_0012e994(param_1);
                    pcVar24 = *(char **)(param_1 + 0x18);
                    cVar8 = *pcVar24;
                    if (cVar8 != 'E') {
                      if (cVar8 == 'p') {
                        if (pcVar24[1] == 'i') {
                          *(char **)(param_1 + 0x18) = pcVar24 + 2;
                          uVar18 = FUN_0012e240(param_1,0x45);
                          goto LAB_0012fe04;
                        }
                      }
                      else if ((cVar8 == 'i') && (pcVar24[1] == 'l')) {
                        uVar18 = FUN_001316ac(param_1);
                        goto LAB_0012fe04;
                      }
                      goto LAB_0012fa60;
                    }
                    uVar18 = 0;
                    *(char **)(param_1 + 0x18) = pcVar24 + 1;
                  }
LAB_0012fe04:
                  uVar17 = FUN_0012bd90(param_1,0x3b,uVar17,uVar18);
                  uVar13 = FUN_0012bd90(param_1,0x3a,uVar13,uVar17);
                  lVar14 = FUN_0012bd90(param_1,0x39,piVar12,uVar13);
                }
                goto switchD_0012fc64_caseD_4;
              }
              if (iVar10 != 0x33) goto LAB_0012fa60;
              if (**(char **)(param_1 + 0x18) == '_') {
                *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
                uVar13 = FUN_0012e240(param_1,0x45);
                goto LAB_0012f238;
              }
switchD_0012fc64_caseD_1:
              uVar13 = FUN_001316ac(param_1);
            }
LAB_0012f238:
            lVar14 = FUN_0012bd90(param_1,0x36,piVar12,uVar13);
            goto switchD_0012fc64_caseD_4;
          }
        }
LAB_0012fa60:
        lVar14 = 0;
      }
switchD_0012fc64_caseD_4:
      *(undefined4 *)(param_1 + 0x54) = uVar2;
      local_8 = (int *)FUN_0012bd90(param_1,0x42,lVar14,0);
      if (local_8 == (int *)0x0) {
        return (int *)0x0;
      }
      pcVar24 = *(char **)(param_1 + 0x18);
      if (*pcVar24 == '\0') {
        return (int *)0x0;
      }
      *(char **)(param_1 + 0x18) = pcVar24 + 1;
      if (*pcVar24 != 'E') {
        return (int *)0x0;
      }
      goto LAB_0012eaf8;
    case 0x61:
      piVar12 = (int *)FUN_0012be30(param_1,&DAT_00141de8,4);
      return piVar12;
    case 100:
      iVar10 = *(int *)(param_1 + 0x28);
      if (iVar10 < *(int *)(param_1 + 0x2c)) {
        *(int *)(param_1 + 0x28) = iVar10 + 1;
        piVar12 = (int *)(*(long *)(param_1 + 0x20) + (long)iVar10 * 0x18);
        if (piVar12 != (int *)0x0) {
          *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar10 * 0x18) = 0x27;
          *(undefined ***)(piVar12 + 2) = &PTR_s_decimal64_0015d660;
          *(int *)(param_1 + 0x50) = *(int *)(param_1 + 0x50) + 9;
          return piVar12;
        }
      }
      break;
    case 0x65:
      iVar10 = *(int *)(param_1 + 0x28);
      if (iVar10 < *(int *)(param_1 + 0x2c)) {
        *(int *)(param_1 + 0x28) = iVar10 + 1;
        piVar12 = (int *)(*(long *)(param_1 + 0x20) + (long)iVar10 * 0x18);
        if (piVar12 != (int *)0x0) {
          *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar10 * 0x18) = 0x27;
          *(undefined ***)(piVar12 + 2) = &PTR_s_decimal128_0015d680;
          *(int *)(param_1 + 0x50) = *(int *)(param_1 + 0x50) + 10;
          return piVar12;
        }
      }
      break;
    case 0x66:
      iVar10 = *(int *)(param_1 + 0x28);
      if (iVar10 < *(int *)(param_1 + 0x2c)) {
        *(int *)(param_1 + 0x28) = iVar10 + 1;
        piVar12 = (int *)(*(long *)(param_1 + 0x20) + (long)iVar10 * 0x18);
        if (piVar12 != (int *)0x0) {
          *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar10 * 0x18) = 0x27;
          *(undefined ***)(piVar12 + 2) = &PTR_s_decimal32_0015d640;
          *(int *)(param_1 + 0x50) = *(int *)(param_1 + 0x50) + 9;
          return piVar12;
        }
      }
      break;
    case 0x68:
      iVar10 = *(int *)(param_1 + 0x28);
      if (iVar10 < *(int *)(param_1 + 0x2c)) {
        *(int *)(param_1 + 0x28) = iVar10 + 1;
        piVar12 = (int *)(*(long *)(param_1 + 0x20) + (long)iVar10 * 0x18);
        if (piVar12 != (int *)0x0) {
          *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar10 * 0x18) = 0x27;
          *(undefined ***)(piVar12 + 2) = &PTR_DAT_0015d6a0;
          *(int *)(param_1 + 0x50) = *(int *)(param_1 + 0x50) + 4;
          return piVar12;
        }
      }
      break;
    case 0x69:
      iVar10 = *(int *)(param_1 + 0x28);
      if (iVar10 < *(int *)(param_1 + 0x2c)) {
        *(int *)(param_1 + 0x28) = iVar10 + 1;
        piVar12 = (int *)(*(long *)(param_1 + 0x20) + (long)iVar10 * 0x18);
        if (piVar12 != (int *)0x0) {
          *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar10 * 0x18) = 0x27;
          *(undefined ***)(piVar12 + 2) = &PTR_s_char32_t_0015d6e0;
          *(int *)(param_1 + 0x50) = *(int *)(param_1 + 0x50) + 8;
          return piVar12;
        }
      }
      break;
    case 0x6e:
      iVar10 = *(int *)(param_1 + 0x28);
      if (iVar10 < *(int *)(param_1 + 0x2c)) {
        *(int *)(param_1 + 0x28) = iVar10 + 1;
        piVar12 = (int *)(*(long *)(param_1 + 0x20) + (long)iVar10 * 0x18);
        if (piVar12 != (int *)0x0) {
          *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar10 * 0x18) = 0x27;
          *(undefined ***)(piVar12 + 2) = &PTR_s_decltype_nullptr__0015d700;
          *(int *)(param_1 + 0x50) = *(int *)(param_1 + 0x50) + 0x11;
          return piVar12;
        }
      }
      break;
    case 0x70:
      uVar13 = FUN_0012e994(param_1);
      local_8 = (int *)FUN_0012bd90(param_1,0x4a,uVar13,0);
      goto LAB_0012eaf4;
    case 0x73:
      iVar10 = *(int *)(param_1 + 0x28);
      if (iVar10 < *(int *)(param_1 + 0x2c)) {
        *(int *)(param_1 + 0x28) = iVar10 + 1;
        piVar12 = (int *)(*(long *)(param_1 + 0x20) + (long)iVar10 * 0x18);
        if (piVar12 != (int *)0x0) {
          *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar10 * 0x18) = 0x27;
          *(undefined ***)(piVar12 + 2) = &PTR_s_char16_t_0015d6c0;
          *(int *)(param_1 + 0x50) = *(int *)(param_1 + 0x50) + 8;
          return piVar12;
        }
      }
      break;
    case 0x76:
      local_8 = (int *)FUN_00131e44(param_1);
      goto LAB_0012eaf4;
    }
LAB_0012f338:
    local_8 = (int *)0x0;
                    // WARNING: Treating indirect jump as call
    UNRECOVERED_JUMPTABLE_00 = (code *)SoftwareBreakpoint(1000,0x12f348);
    piVar12 = (int *)(*UNRECOVERED_JUMPTABLE_00)(uRam0000000000000008);
    return piVar12;
  case 0x46:
    local_8 = (int *)FUN_00131d14(param_1);
    break;
  case 0x47:
    *(byte **)(param_1 + 0x18) = pbVar22 + 1;
    uVar13 = FUN_0012e994(param_1);
    local_8 = (int *)FUN_0012bd90(param_1,0x26,uVar13,0);
    break;
  case 0x4d:
    *(byte **)(param_1 + 0x18) = pbVar22 + 1;
    lVar14 = FUN_0012e994(param_1);
    if ((lVar14 == 0) || (lVar15 = FUN_0012e994(param_1), lVar15 == 0)) {
LAB_0012ebb8:
      local_8 = (int *)0x0;
    }
    else {
      local_8 = (int *)FUN_0012bd90(param_1,0x2b,lVar14,lVar15);
    }
    break;
  case 0x4f:
    *(byte **)(param_1 + 0x18) = pbVar22 + 1;
    uVar13 = FUN_0012e994(param_1);
    local_8 = (int *)FUN_0012bd90(param_1,0x24,uVar13,0);
    break;
  case 0x50:
    *(byte **)(param_1 + 0x18) = pbVar22 + 1;
    uVar13 = FUN_0012e994(param_1);
    local_8 = (int *)FUN_0012bd90(param_1,0x22,uVar13,0);
    break;
  case 0x52:
    *(byte **)(param_1 + 0x18) = pbVar22 + 1;
    uVar13 = FUN_0012e994(param_1);
    local_8 = (int *)FUN_0012bd90(param_1,0x23,uVar13,0);
    break;
  case 0x53:
    bVar7 = pbVar22[1];
    if (((9 < (byte)(bVar7 - 0x30)) && (bVar7 != 0x5f)) && (0x19 < (byte)(bVar7 + 0xbf))) {
      local_8 = (int *)FUN_001308c4(param_1);
      if (local_8 == (int *)0x0) {
        return (int *)0x0;
      }
      if (*local_8 == 0x18) {
        return local_8;
      }
      goto LAB_0012eaf8;
    }
    local_8 = (int *)FUN_0012c040(param_1,0);
    if (**(char **)(param_1 + 0x18) != 'I') {
      return local_8;
    }
LAB_0012eda0:
    piVar12 = local_8;
    uVar13 = FUN_0012cd54(param_1);
    local_8 = (int *)FUN_0012bd90(param_1,4,piVar12,uVar13);
    break;
  case 0x54:
    local_8 = (int *)FUN_0012cb7c(param_1);
    pcVar24 = *(char **)(param_1 + 0x18);
    if (*pcVar24 == 'I') {
      if (*(int *)(param_1 + 0x58) == 0) {
        if (local_8 == (int *)0x0) {
          return (int *)0x0;
        }
        iVar10 = *(int *)(param_1 + 0x38);
        if (*(int *)(param_1 + 0x3c) <= iVar10) {
          return (int *)0x0;
        }
        *(int **)(*(long *)(param_1 + 0x30) + (long)iVar10 * 8) = local_8;
        *(int *)(param_1 + 0x38) = iVar10 + 1;
        goto LAB_0012eda0;
      }
      uVar2 = *(undefined4 *)(param_1 + 0x28);
      uVar3 = *(undefined4 *)(param_1 + 0x38);
      uVar4 = *(undefined4 *)(param_1 + 0x40);
      uVar5 = *(undefined4 *)(param_1 + 0x50);
      uVar13 = FUN_0012cd54(param_1);
      if (**(char **)(param_1 + 0x18) == 'I') {
        if (local_8 == (int *)0x0) {
          return (int *)0x0;
        }
        iVar10 = *(int *)(param_1 + 0x38);
        if (*(int *)(param_1 + 0x3c) <= iVar10) {
          return (int *)0x0;
        }
        *(int **)(*(long *)(param_1 + 0x30) + (long)iVar10 * 8) = local_8;
        *(int *)(param_1 + 0x38) = iVar10 + 1;
        local_8 = (int *)FUN_0012bd90(param_1,4,local_8,uVar13);
      }
      else {
        *(char **)(param_1 + 0x18) = pcVar24;
        *(undefined4 *)(param_1 + 0x28) = uVar2;
        *(undefined4 *)(param_1 + 0x38) = uVar3;
        *(undefined4 *)(param_1 + 0x40) = uVar4;
        *(undefined4 *)(param_1 + 0x50) = uVar5;
      }
    }
    break;
  case 0x55:
    *(byte **)(param_1 + 0x18) = pbVar22 + 1;
    local_8 = (int *)FUN_0012c9a4(param_1);
    uVar13 = FUN_0012e994(param_1);
    local_8 = (int *)FUN_0012bd90(param_1,0x21,uVar13,local_8);
    break;
  case 0x61:
  case 0x62:
  case 99:
  case 100:
  case 0x65:
  case 0x66:
  case 0x67:
  case 0x68:
  case 0x69:
  case 0x6a:
  case 0x6c:
  case 0x6d:
  case 0x6e:
  case 0x6f:
  case 0x73:
  case 0x74:
  case 0x76:
  case 0x77:
  case 0x78:
  case 0x79:
  case 0x7a:
    iVar10 = *(int *)(param_1 + 0x28);
    uVar16 = -(ulong)(uVar9 - 0x61 >> 0x1f) & 0xffffffe000000000 | (ulong)(uVar9 - 0x61) << 5;
    if (iVar10 < *(int *)(param_1 + 0x2c)) {
      *(int *)(param_1 + 0x28) = iVar10 + 1;
      piVar12 = (int *)(*(long *)(param_1 + 0x20) + (long)iVar10 * 0x18);
      if (piVar12 != (int *)0x0) {
        *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar10 * 0x18) = 0x27;
        *(undefined **)(piVar12 + 2) = &UNK_0015d300 + uVar16;
        iVar10 = *(int *)(&DAT_0015d308 + uVar16);
        *(byte **)(param_1 + 0x18) = pbVar22 + 1;
        *(int *)(param_1 + 0x50) = *(int *)(param_1 + 0x50) + iVar10;
        return piVar12;
      }
    }
    goto LAB_0012f338;
  case 0x75:
    *(byte **)(param_1 + 0x18) = pbVar22 + 1;
    uVar13 = FUN_0012c9a4(param_1);
    local_8 = (int *)FUN_0012bd90(param_1,0x28,uVar13,0);
  }
LAB_0012eaf4:
  if (local_8 != (int *)0x0) {
LAB_0012eaf8:
    iVar10 = *(int *)(param_1 + 0x38);
    if (iVar10 < *(int *)(param_1 + 0x3c)) {
      *(int **)(*(long *)(param_1 + 0x30) + (long)iVar10 * 8) = local_8;
      *(int *)(param_1 + 0x38) = iVar10 + 1;
      return local_8;
    }
  }
switchD_0012ea10_caseD_3a:
  return (int *)0x0;
switchD_0012fa4c_caseD_1:
  cVar8 = *pcVar24;
  if (((cVar8 == 'm') || (cVar8 == 'p')) && (pcVar24[1] == cVar8)) {
    cVar8 = **(char **)(param_1 + 0x18);
    if (cVar8 != '_') {
      uVar13 = FUN_001316ac(param_1,cVar8,0);
      uVar13 = FUN_0012bd90(param_1,0x38,uVar13,uVar13);
      goto LAB_0012f238;
    }
    *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
  }
  goto switchD_0012fc64_caseD_1;
}



long FUN_0013003c(long param_1)

{
  char cVar1;
  long lVar2;
  char *pcVar3;
  long *plVar4;
  long local_8;
  
  pcVar3 = *(char **)(param_1 + 0x18);
  local_8 = 0;
  cVar1 = *pcVar3;
  if ((cVar1 != 'E' && cVar1 != '\0') && (plVar4 = &local_8, cVar1 != '.')) {
    while (((cVar1 != 'O' && (cVar1 != 'R')) || (pcVar3[1] != 'E'))) {
      lVar2 = FUN_0012e994(param_1);
      if (lVar2 == 0) {
        return 0;
      }
      lVar2 = FUN_0012bd90(param_1,0x2e,lVar2,0);
      *plVar4 = lVar2;
      plVar4 = (long *)(lVar2 + 0x10);
      if (lVar2 == 0) {
        return 0;
      }
      pcVar3 = *(char **)(param_1 + 0x18);
      cVar1 = *pcVar3;
      if ((cVar1 == 'E' || cVar1 == '\0') || (cVar1 == '.')) break;
    }
    if (local_8 != 0) {
      if (*(long *)(local_8 + 0x10) != 0) {
        return local_8;
      }
      if (**(int **)(local_8 + 8) == 0x27) {
        lVar2 = *(long *)(*(int **)(local_8 + 8) + 2);
        if (*(int *)(lVar2 + 0x1c) == 9) {
          *(int *)(param_1 + 0x50) = *(int *)(param_1 + 0x50) - *(int *)(lVar2 + 8);
          *(undefined8 *)(local_8 + 8) = 0;
          return local_8;
        }
        return local_8;
      }
      return local_8;
    }
  }
  return 0;
}



long FUN_0013014c(long param_1)

{
  int iVar1;
  long lVar2;
  undefined4 uVar3;
  byte bVar4;
  uint uVar5;
  undefined8 uVar6;
  long lVar7;
  byte *pbVar8;
  int iVar9;
  int iVar10;
  byte bVar11;
  byte bVar12;
  
  pbVar8 = *(byte **)(param_1 + 0x18);
  if (*pbVar8 == 0) {
    bVar12 = 0;
    bVar11 = 0;
  }
  else {
    *(byte **)(param_1 + 0x18) = pbVar8 + 1;
    bVar11 = *pbVar8;
    if (pbVar8[1] == 0) {
      bVar12 = 0;
    }
    else {
      *(byte **)(param_1 + 0x18) = pbVar8 + 2;
      bVar12 = pbVar8[1];
      if (bVar11 == 0x76) {
        uVar5 = bVar12 - 0x30;
        if ((uVar5 & 0xff) < 10) {
          lVar7 = FUN_0012c9a4();
          iVar9 = *(int *)(param_1 + 0x28);
          if (*(int *)(param_1 + 0x2c) <= iVar9) {
            return 0;
          }
          *(int *)(param_1 + 0x28) = iVar9 + 1;
          lVar2 = *(long *)(param_1 + 0x20) + (long)iVar9 * 0x18;
          if (lVar7 == 0) {
            return 0;
          }
          if (lVar2 == 0) {
            return 0;
          }
          *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar9 * 0x18) = 0x32;
          *(uint *)(lVar2 + 8) = uVar5;
          *(long *)(lVar2 + 0x10) = lVar7;
          return lVar2;
        }
      }
      else if ((bVar12 == 0x76) && (bVar11 == 99)) {
        uVar3 = *(undefined4 *)(param_1 + 0x58);
        *(uint *)(param_1 + 0x58) = (uint)(*(int *)(param_1 + 0x54) == 0);
        uVar6 = FUN_0012e994();
        if (*(int *)(param_1 + 0x58) == 0) {
          lVar7 = FUN_0012bd90(param_1,0x33,uVar6,0);
          *(undefined4 *)(param_1 + 0x58) = uVar3;
        }
        else {
          lVar7 = FUN_0012bd90(param_1,0x34,uVar6,0);
          *(undefined4 *)(param_1 + 0x58) = uVar3;
        }
        return lVar7;
      }
    }
  }
  iVar10 = 0x3d;
  iVar9 = 0;
  do {
    iVar1 = iVar9 + (iVar10 - iVar9) / 2;
    bVar4 = *(&PTR_DAT_0015d8a8)[(long)iVar1 * 3];
    if (bVar11 == bVar4) {
      bVar4 = (&PTR_DAT_0015d8a8)[(long)iVar1 * 3][1];
      if (bVar12 == bVar4) {
        iVar9 = *(int *)(param_1 + 0x28);
        if (*(int *)(param_1 + 0x2c) <= iVar9) {
          return 0;
        }
        *(int *)(param_1 + 0x28) = iVar9 + 1;
        lVar7 = *(long *)(param_1 + 0x20) + (long)iVar9 * 0x18;
        if (lVar7 != 0) {
          *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar9 * 0x18) = 0x31;
          *(undefined ***)(lVar7 + 8) = &PTR_DAT_0015d8a8 + (long)iVar1 * 3;
          return lVar7;
        }
        return 0;
      }
      if (bVar4 <= bVar12) goto LAB_001301e4;
    }
    else if (bVar4 <= bVar11) {
LAB_001301e4:
      iVar9 = iVar1 + 1;
      iVar1 = iVar10;
    }
    iVar10 = iVar1;
    if (iVar9 == iVar10) {
      return 0;
    }
  } while( true );
}



int * FUN_00130340(long param_1)

{
  int iVar1;
  byte bVar2;
  int iVar3;
  undefined8 uVar4;
  int *piVar5;
  long lVar6;
  char *pcVar7;
  char *pcVar8;
  ulong uVar9;
  char cVar10;
  byte *pbVar11;
  bool bVar12;
  int *local_8;
  
  pcVar8 = *(char **)(param_1 + 0x18);
  cVar10 = *pcVar8;
  if ((byte)(cVar10 - 0x30U) < 10) {
    local_8 = (int *)FUN_0012c9a4();
    pcVar7 = *(char **)(param_1 + 0x18);
    cVar10 = *pcVar7;
    goto joined_r0x00130498;
  }
  if ((byte)(cVar10 + 0x9fU) < 0x1a) {
    local_8 = (int *)FUN_0013014c();
    if ((local_8 != (int *)0x0) && (*local_8 == 0x31)) {
      pcVar8 = **(char ***)(local_8 + 2);
      *(int *)(param_1 + 0x50) =
           *(int *)(param_1 + 0x50) + *(int *)(*(char ***)(local_8 + 2) + 2) + 7;
      iVar3 = strcmp(pcVar8,"li");
      if (iVar3 == 0) {
        uVar4 = FUN_0012c9a4(param_1);
        local_8 = (int *)FUN_0012bd90(param_1,0x36,local_8,uVar4);
      }
    }
    pcVar7 = *(char **)(param_1 + 0x18);
    cVar10 = *pcVar7;
    goto joined_r0x00130498;
  }
  if (1 < (byte)(cVar10 + 0xbdU)) {
    if (cVar10 == 'L') {
      *(char **)(param_1 + 0x18) = pcVar8 + 1;
      local_8 = (int *)FUN_0012c9a4();
      if (local_8 == (int *)0x0) {
        return (int *)0x0;
      }
      iVar3 = FUN_0012cad8(param_1);
      if (iVar3 == 0) {
        return (int *)0x0;
      }
      cVar10 = **(char **)(param_1 + 0x18);
      pcVar7 = *(char **)(param_1 + 0x18);
      goto joined_r0x00130498;
    }
    if (cVar10 != 'U') {
      return (int *)0x0;
    }
    if (pcVar8[1] == 'l') {
      pcVar7 = pcVar8 + 1;
      *(char **)(param_1 + 0x18) = pcVar7;
      cVar10 = pcVar8[1];
      if (cVar10 == 'l') {
        *(char **)(param_1 + 0x18) = pcVar8 + 2;
        lVar6 = FUN_0013003c();
        pcVar7 = *(char **)(param_1 + 0x18);
        if (lVar6 == 0) goto LAB_001306cc;
        cVar10 = *pcVar7;
        if (cVar10 == 'E') {
          *(char **)(param_1 + 0x18) = pcVar7 + 1;
          if (pcVar7[1] == '_') {
            pcVar8 = pcVar7 + 2;
            iVar3 = 0;
            *(char **)(param_1 + 0x18) = pcVar8;
          }
          else {
            if (pcVar7[1] == 'n') {
              return (int *)0x0;
            }
            local_8 = (int *)0x0;
            iVar3 = FUN_0012c444(param_1 + 0x18);
            pcVar7 = *(char **)(param_1 + 0x18);
            cVar10 = *pcVar7;
            if (cVar10 != '_') goto joined_r0x00130498;
            iVar3 = iVar3 + 1;
            pcVar8 = pcVar7 + 1;
            *(char **)(param_1 + 0x18) = pcVar8;
            if (iVar3 < 0) {
              cVar10 = pcVar7[1];
              pcVar7 = pcVar8;
              local_8 = (int *)0x0;
              goto joined_r0x00130498;
            }
          }
          iVar1 = *(int *)(param_1 + 0x28);
          if (iVar1 < *(int *)(param_1 + 0x2c)) {
            *(int *)(param_1 + 0x28) = iVar1 + 1;
            local_8 = (int *)(*(long *)(param_1 + 0x20) + (long)iVar1 * 0x18);
            if (local_8 != (int *)0x0) {
              *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar1 * 0x18) = 0x45;
              *(long *)(local_8 + 2) = lVar6;
              local_8[4] = iVar3;
              iVar3 = *(int *)(param_1 + 0x38);
              if (iVar3 < *(int *)(param_1 + 0x3c)) goto LAB_00130620;
            }
          }
          cVar10 = *pcVar8;
          local_8 = (int *)0x0;
          pcVar7 = pcVar8;
          goto joined_r0x00130498;
        }
      }
    }
    else {
      if (pcVar8[1] != 't') {
        return (int *)0x0;
      }
      pcVar7 = pcVar8 + 1;
      *(char **)(param_1 + 0x18) = pcVar7;
      cVar10 = pcVar8[1];
      if (cVar10 == 't') {
        *(char **)(param_1 + 0x18) = pcVar8 + 2;
        lVar6 = FUN_0012ca4c();
        if ((-1 < lVar6) && (iVar3 = *(int *)(param_1 + 0x28), iVar3 < *(int *)(param_1 + 0x2c))) {
          *(int *)(param_1 + 0x28) = iVar3 + 1;
          local_8 = (int *)(*(long *)(param_1 + 0x20) + (long)iVar3 * 0x18);
          if (local_8 != (int *)0x0) {
            *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar3 * 0x18) = 0x47;
            *(long *)(local_8 + 2) = lVar6;
            iVar3 = *(int *)(param_1 + 0x38);
            if (iVar3 < *(int *)(param_1 + 0x3c)) {
LAB_00130620:
              *(int **)(*(long *)(param_1 + 0x30) + (long)iVar3 * 8) = local_8;
              *(int *)(param_1 + 0x38) = iVar3 + 1;
              cVar10 = **(char **)(param_1 + 0x18);
              pcVar7 = *(char **)(param_1 + 0x18);
              goto joined_r0x00130498;
            }
          }
        }
        pcVar7 = *(char **)(param_1 + 0x18);
LAB_001306cc:
        cVar10 = *pcVar7;
        local_8 = (int *)0x0;
        goto joined_r0x00130498;
      }
    }
    local_8 = (int *)0x0;
    goto joined_r0x00130498;
  }
  piVar5 = *(int **)(param_1 + 0x48);
  if ((piVar5 == (int *)0x0) || ((*piVar5 != 0 && (*piVar5 != 0x18)))) {
    if (cVar10 == 'C') goto LAB_00130810;
    if (cVar10 != 'D') {
      return (int *)0x0;
    }
LAB_001306fc:
    switch(pcVar8[1]) {
    case '0':
      iVar3 = 1;
      break;
    case '1':
      iVar3 = 2;
      break;
    case '2':
      iVar3 = 3;
      break;
    default:
switchD_00130720_caseD_33:
      return (int *)0x0;
    case '4':
      iVar3 = 4;
      break;
    case '5':
      iVar3 = 5;
    }
    iVar1 = *(int *)(param_1 + 0x28);
    pcVar7 = pcVar8 + 2;
    *(char **)(param_1 + 0x18) = pcVar7;
    if (iVar1 < *(int *)(param_1 + 0x2c)) {
      *(int *)(param_1 + 0x28) = iVar1 + 1;
      local_8 = (int *)(*(long *)(param_1 + 0x20) + (long)iVar1 * 0x18);
      if ((local_8 != (int *)0x0) && (piVar5 != (int *)0x0)) {
        *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar1 * 0x18) = 8;
        local_8[2] = iVar3;
        *(int **)(local_8 + 4) = piVar5;
        cVar10 = pcVar8[2];
        goto joined_r0x00130498;
      }
    }
  }
  else {
    *(int *)(param_1 + 0x50) = *(int *)(param_1 + 0x50) + piVar5[4];
    cVar10 = *pcVar8;
    if (cVar10 != 'C') {
      if (cVar10 != 'D') {
        local_8 = (int *)0x0;
        pcVar7 = pcVar8;
        goto joined_r0x00130498;
      }
      goto LAB_001306fc;
    }
LAB_00130810:
    switch(pcVar8[1]) {
    case '1':
      iVar3 = 1;
      break;
    case '2':
      iVar3 = 2;
      break;
    case '3':
      iVar3 = 3;
      break;
    case '4':
      iVar3 = 4;
      break;
    case '5':
      iVar3 = 5;
      break;
    default:
      goto switchD_00130720_caseD_33;
    }
    iVar1 = *(int *)(param_1 + 0x28);
    pcVar7 = pcVar8 + 2;
    *(char **)(param_1 + 0x18) = pcVar7;
    if (iVar1 < *(int *)(param_1 + 0x2c)) {
      *(int *)(param_1 + 0x28) = iVar1 + 1;
      local_8 = (int *)(*(long *)(param_1 + 0x20) + (long)iVar1 * 0x18);
      if ((local_8 != (int *)0x0) && (piVar5 != (int *)0x0)) {
        *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar1 * 0x18) = 7;
        local_8[2] = iVar3;
        *(int **)(local_8 + 4) = piVar5;
        cVar10 = pcVar8[2];
        goto joined_r0x00130498;
      }
    }
  }
  pcVar7 = pcVar8 + 2;
  cVar10 = *pcVar7;
  local_8 = (int *)0x0;
joined_r0x00130498:
  if (cVar10 != 'B') {
    return local_8;
  }
  do {
    *(char **)(param_1 + 0x18) = pcVar7 + 1;
    bVar12 = false;
    bVar2 = pcVar7[1];
    if (bVar2 == 0x6e) {
      *(char **)(param_1 + 0x18) = pcVar7 + 2;
      bVar12 = true;
      bVar2 = pcVar7[2];
      if ((byte)(bVar2 - 0x30) < 10) goto LAB_001303f8;
LAB_001304c8:
      uVar4 = 0;
    }
    else {
      if (9 < (byte)(bVar2 - 0x30)) goto LAB_001304c8;
LAB_001303f8:
      pbVar11 = *(byte **)(param_1 + 0x18);
      lVar6 = 0;
      do {
        pbVar11 = pbVar11 + 1;
        uVar9 = (ulong)bVar2;
        *(byte **)(param_1 + 0x18) = pbVar11;
        bVar2 = *pbVar11;
        lVar6 = lVar6 * 10 + uVar9 + -0x30;
      } while ((byte)(bVar2 - 0x30) < 10);
      if ((lVar6 < 1) || (bVar12)) goto LAB_001304c8;
      uVar4 = FUN_0012c784(param_1);
      *(undefined8 *)(param_1 + 0x48) = uVar4;
    }
    local_8 = (int *)FUN_0012bd90(param_1,0x4b,local_8,uVar4);
    pcVar7 = *(char **)(param_1 + 0x18);
    if (*pcVar7 != 'B') {
      return local_8;
    }
  } while( true );
}



long FUN_001308c4(long param_1)

{
  int iVar1;
  int iVar2;
  long lVar3;
  char *pcVar4;
  long *plVar5;
  int *piVar6;
  undefined8 uVar7;
  undefined8 uVar8;
  char *pcVar9;
  long lVar10;
  int *piVar11;
  undefined *puVar12;
  char cVar13;
  long lVar14;
  long local_8;
  
  puVar12 = *(undefined **)(param_1 + 0x18);
  switch(*puVar12) {
  case 0x4e:
    *(undefined **)(param_1 + 0x18) = puVar12 + 1;
    plVar5 = (long *)FUN_0012be90(param_1,&local_8,1);
    if (plVar5 == (long *)0x0) {
      return 0;
    }
    pcVar4 = *(char **)(param_1 + 0x18);
    cVar13 = *pcVar4;
    if (cVar13 == 'O') {
      if (cVar13 == 'R') goto LAB_00130d20;
      uVar8 = 0x20;
      iVar1 = *(int *)(param_1 + 0x50) + 3;
    }
    else {
      lVar3 = 0;
      if (cVar13 != 'R') {
        lVar14 = 0;
        goto LAB_00130a40;
      }
LAB_00130d20:
      uVar8 = 0x1f;
      iVar1 = *(int *)(param_1 + 0x50) + 2;
    }
    *(int *)(param_1 + 0x50) = iVar1;
    *(char **)(param_1 + 0x18) = pcVar4 + 1;
    lVar14 = 0;
    lVar3 = FUN_0012bd90(param_1,uVar8,0,0);
    pcVar4 = *(char **)(param_1 + 0x18);
    cVar13 = *pcVar4;
LAB_00130a40:
    do {
      if (cVar13 == '\0') {
LAB_00130cc8:
        *plVar5 = 0;
        return 0;
      }
      pcVar9 = pcVar4;
      if (cVar13 == 'D') {
        if ((pcVar4[1] & 0xdfU) != 0x54) {
          lVar10 = FUN_00130340(param_1);
          goto LAB_00130cb0;
        }
        lVar10 = FUN_0012e994();
        goto LAB_00130cb0;
      }
      do {
        if ((((byte)(cVar13 - 0x30U) < 10) || ((byte)(cVar13 + 0x9fU) < 0x1a)) ||
           ((cVar13 == 'C' || cVar13 == 'U' || (cVar13 == 'L')))) {
          lVar10 = FUN_00130340(param_1);
          if (lVar14 != 0) goto LAB_00130c2c;
LAB_00130c40:
          if (cVar13 == 'S') goto LAB_00130c7c;
        }
        else {
          if (cVar13 == 'S') {
            lVar10 = FUN_0012c040(param_1,1);
            if (lVar14 != 0) {
LAB_00130c2c:
              uVar8 = 1;
LAB_00130c30:
              lVar10 = FUN_0012bd90(param_1,uVar8,lVar14,lVar10);
              goto LAB_00130c40;
            }
            pcVar4 = *(char **)(param_1 + 0x18);
            cVar13 = *pcVar4;
            lVar14 = lVar10;
            goto LAB_00130a40;
          }
          if (cVar13 == 'I') {
            if (lVar14 != 0) {
              lVar10 = FUN_0012cd54(param_1);
              uVar8 = 4;
              goto LAB_00130c30;
            }
            goto LAB_00130cc8;
          }
          if (cVar13 != 'T') {
            if (cVar13 == 'E') {
              *plVar5 = lVar14;
              if (lVar14 == 0) {
                return 0;
              }
              if (lVar3 != 0) {
                *(long *)(lVar3 + 8) = local_8;
                local_8 = lVar3;
              }
              if (**(char **)(param_1 + 0x18) == 'E') {
                *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
                return local_8;
              }
              return 0;
            }
            if ((cVar13 != 'M') || (lVar14 == 0)) goto LAB_00130cc8;
            pcVar4 = pcVar9 + 1;
            *(char **)(param_1 + 0x18) = pcVar4;
            cVar13 = pcVar9[1];
            goto LAB_00130a40;
          }
          lVar10 = FUN_0012cb7c(param_1);
LAB_00130cb0:
          if (lVar14 != 0) goto LAB_00130c2c;
        }
        pcVar9 = *(char **)(param_1 + 0x18);
        cVar13 = *pcVar9;
        lVar14 = lVar10;
      } while (cVar13 == 'E');
      if ((lVar10 == 0) || (iVar1 = *(int *)(param_1 + 0x38), *(int *)(param_1 + 0x3c) <= iVar1))
      goto LAB_00130cc8;
      *(long *)(*(long *)(param_1 + 0x30) + (long)iVar1 * 8) = lVar10;
      *(int *)(param_1 + 0x38) = iVar1 + 1;
LAB_00130c7c:
      pcVar4 = *(char **)(param_1 + 0x18);
      cVar13 = *pcVar4;
      lVar14 = lVar10;
    } while( true );
  default:
    lVar3 = FUN_00130340(param_1);
    if (**(char **)(param_1 + 0x18) == 'I') {
      if (lVar3 == 0) {
        return 0;
      }
      iVar1 = *(int *)(param_1 + 0x38);
      if (*(int *)(param_1 + 0x3c) <= iVar1) {
        return 0;
      }
      *(long *)(*(long *)(param_1 + 0x30) + (long)iVar1 * 8) = lVar3;
      *(int *)(param_1 + 0x38) = iVar1 + 1;
      uVar8 = FUN_0012cd54(param_1);
      lVar3 = FUN_0012bd90(param_1,4,lVar3,uVar8);
    }
    break;
  case 0x53:
    if (puVar12[1] == 't') {
      *(undefined **)(param_1 + 0x18) = puVar12 + 2;
      uVar8 = FUN_0012be30(param_1,&DAT_00141e08,3);
      uVar7 = FUN_00130340(param_1);
      lVar3 = FUN_0012bd90(param_1,1,uVar8,uVar7);
      *(int *)(param_1 + 0x50) = *(int *)(param_1 + 0x50) + 3;
      if (**(char **)(param_1 + 0x18) != 'I') {
        return lVar3;
      }
      if (lVar3 == 0) {
        return 0;
      }
      iVar1 = *(int *)(param_1 + 0x38);
      if (*(int *)(param_1 + 0x3c) <= iVar1) {
        return 0;
      }
      *(long *)(*(long *)(param_1 + 0x30) + (long)iVar1 * 8) = lVar3;
      *(int *)(param_1 + 0x38) = iVar1 + 1;
    }
    else {
      lVar3 = FUN_0012c040(param_1,0);
      if (**(char **)(param_1 + 0x18) != 'I') {
        return lVar3;
      }
    }
    uVar8 = FUN_0012cd54(param_1);
    lVar3 = FUN_0012bd90(param_1,4,lVar3,uVar8);
    break;
  case 0x55:
    lVar3 = FUN_00130340(param_1);
    return lVar3;
  case 0x5a:
    *(undefined **)(param_1 + 0x18) = puVar12 + 1;
    uVar8 = FUN_00130e70(param_1,0);
    pcVar4 = *(char **)(param_1 + 0x18);
    if (*pcVar4 != 'E') {
      return 0;
    }
    *(char **)(param_1 + 0x18) = pcVar4 + 1;
    if (pcVar4[1] == 's') {
      *(char **)(param_1 + 0x18) = pcVar4 + 2;
      iVar1 = FUN_0012cad8(param_1);
      if (iVar1 == 0) {
        return 0;
      }
      piVar6 = (int *)FUN_0012be30(param_1,"string literal",0xe);
    }
    else if (pcVar4[1] == 'd') {
      *(char **)(param_1 + 0x18) = pcVar4 + 2;
      iVar1 = FUN_0012ca4c(param_1);
      if (iVar1 < 0) {
        return 0;
      }
      piVar11 = (int *)FUN_001308c4(param_1);
      if ((((piVar11 != (int *)0x0) && (*piVar11 != 0x45)) && (*piVar11 != 0x47)) &&
         (iVar2 = FUN_0012cad8(param_1), iVar2 == 0)) {
        return 0;
      }
      iVar2 = *(int *)(param_1 + 0x28);
      piVar6 = (int *)0x0;
      if (iVar2 < *(int *)(param_1 + 0x2c)) {
        *(int *)(param_1 + 0x28) = iVar2 + 1;
        piVar6 = (int *)(*(long *)(param_1 + 0x20) + (long)iVar2 * 0x18);
        if (piVar6 != (int *)0x0) {
          *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar2 * 0x18) = 0x46;
          piVar6[4] = iVar1;
          *(int **)(piVar6 + 2) = piVar11;
        }
      }
    }
    else {
      piVar6 = (int *)FUN_001308c4(param_1);
      if (((piVar6 != (int *)0x0) && (*piVar6 != 0x45)) &&
         ((*piVar6 != 0x47 && (iVar1 = FUN_0012cad8(param_1), iVar1 == 0)))) {
        return 0;
      }
    }
    lVar3 = FUN_0012bd90(param_1,2,uVar8,piVar6);
    return lVar3;
  }
  return lVar3;
}



uint * FUN_00130e70(long param_1,int param_2)

{
  uint **ppuVar1;
  char cVar2;
  byte bVar3;
  int iVar4;
  uint uVar5;
  uint *puVar6;
  long lVar7;
  int *piVar8;
  undefined8 uVar9;
  char *pcVar10;
  long lVar11;
  uint *puVar12;
  ulong uVar13;
  char *pcVar14;
  
  pcVar10 = *(char **)(param_1 + 0x18);
  if ((*pcVar10 != 'T') && (*pcVar10 != 'G')) {
    puVar6 = (uint *)FUN_001308c4();
    if ((puVar6 != (uint *)0x0) && ((param_2 != 0 && ((*(uint *)(param_1 + 0x10) & 1) == 0)))) {
      for (; *puVar6 - 0x1c < 5; puVar6 = *(uint **)(puVar6 + 2)) {
      }
      if (*puVar6 == 2) {
        piVar8 = *(int **)(puVar6 + 4);
        iVar4 = *piVar8;
        while (iVar4 - 0x1cU < 5) {
          piVar8 = *(int **)(piVar8 + 2);
          iVar4 = *piVar8;
        }
        *(int **)(puVar6 + 4) = piVar8;
      }
      return puVar6;
    }
    cVar2 = **(char **)(param_1 + 0x18);
    if (cVar2 == 'E' || cVar2 == '\0') {
      return puVar6;
    }
    puVar12 = puVar6;
    if (puVar6 == (uint *)0x0) {
      return (uint *)0x0;
    }
    do {
      uVar5 = *puVar12;
      if (uVar5 == 4) {
        puVar12 = *(uint **)(puVar12 + 2);
        goto joined_r0x00130fb8;
      }
    } while (((3 < uVar5) && (uVar5 - 0x1c < 5)) &&
            (ppuVar1 = (uint **)(puVar12 + 2), puVar12 = *ppuVar1, *ppuVar1 != (uint *)0x0));
LAB_00130f0c:
    if (cVar2 == 'J') goto LAB_0013145c;
    lVar11 = 0;
    goto LAB_00130ffc;
  }
  iVar4 = *(int *)(param_1 + 0x50);
  *(int *)(param_1 + 0x50) = iVar4 + 0x14;
  if (*pcVar10 == 'T') {
    *(char **)(param_1 + 0x18) = pcVar10 + 1;
    if (pcVar10[1] == '\0') {
      return (uint *)0x0;
    }
    *(char **)(param_1 + 0x18) = pcVar10 + 2;
    switch(pcVar10[1]) {
    case 'C':
      lVar11 = FUN_0012e994(param_1);
      lVar7 = FUN_0012c444(param_1 + 0x18);
      if (lVar7 < 0) {
        return (uint *)0x0;
      }
      if (**(char **)(param_1 + 0x18) != '_') {
        return (uint *)0x0;
      }
      *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
      puVar6 = (uint *)FUN_0012e994(param_1);
      uVar9 = 0xb;
      *(int *)(param_1 + 0x50) = *(int *)(param_1 + 0x50) + 5;
      break;
    default:
      return (uint *)0x0;
    case 'F':
      puVar6 = (uint *)FUN_0012e994(param_1);
      uVar9 = 0xe;
      lVar11 = 0;
      break;
    case 'H':
      puVar6 = (uint *)FUN_001308c4(param_1);
      uVar9 = 0x14;
      lVar11 = 0;
      break;
    case 'I':
      puVar6 = (uint *)FUN_0012e994(param_1);
      uVar9 = 0xc;
      lVar11 = 0;
      break;
    case 'J':
      puVar6 = (uint *)FUN_0012e994(param_1);
      uVar9 = 0x12;
      lVar11 = 0;
      break;
    case 'S':
      puVar6 = (uint *)FUN_0012e994(param_1);
      uVar9 = 0xd;
      lVar11 = 0;
      break;
    case 'T':
      *(int *)(param_1 + 0x50) = iVar4 + 10;
      puVar6 = (uint *)FUN_0012e994(param_1);
      uVar9 = 10;
      lVar11 = 0;
      break;
    case 'V':
      *(int *)(param_1 + 0x50) = iVar4 + 0xf;
      puVar6 = (uint *)FUN_0012e994(param_1);
      uVar9 = 9;
      lVar11 = 0;
      break;
    case 'W':
      puVar6 = (uint *)FUN_001308c4(param_1);
      uVar9 = 0x15;
      lVar11 = 0;
      break;
    case 'c':
      iVar4 = FUN_0012cc68(param_1,0);
      if (iVar4 == 0) {
        return (uint *)0x0;
      }
      iVar4 = FUN_0012cc68(param_1,0);
      if (iVar4 == 0) {
        return (uint *)0x0;
      }
      puVar6 = (uint *)FUN_00130e70(param_1,0);
      uVar9 = 0x11;
      lVar11 = 0;
      break;
    case 'h':
      iVar4 = FUN_0012cc68(param_1,0x68);
      if (iVar4 == 0) {
        return (uint *)0x0;
      }
      puVar6 = (uint *)FUN_00130e70(param_1,0);
      uVar9 = 0xf;
      lVar11 = 0;
      break;
    case 'v':
      iVar4 = FUN_0012cc68(param_1,0x76);
      if (iVar4 == 0) {
        return (uint *)0x0;
      }
      puVar6 = (uint *)FUN_00130e70(param_1,0);
      uVar9 = 0x10;
      lVar11 = 0;
    }
    goto LAB_00131030;
  }
  if (*pcVar10 != 'G') {
    return (uint *)0x0;
  }
  *(char **)(param_1 + 0x18) = pcVar10 + 1;
  if (pcVar10[1] == '\0') {
    return (uint *)0x0;
  }
  *(char **)(param_1 + 0x18) = pcVar10 + 2;
  switch(pcVar10[1]) {
  case 'A':
    puVar6 = (uint *)FUN_00130e70(param_1,0);
    uVar9 = 0x17;
    lVar11 = 0;
    break;
  default:
    return (uint *)0x0;
  case 'R':
    puVar6 = (uint *)FUN_001308c4(param_1);
    iVar4 = *(int *)(param_1 + 0x28);
    if (iVar4 < *(int *)(param_1 + 0x2c)) {
      *(int *)(param_1 + 0x28) = iVar4 + 1;
      lVar11 = *(long *)(param_1 + 0x20) + (long)iVar4 * 0x18;
      if (lVar11 == 0) goto LAB_00131518;
      *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar4 * 0x18) = 0x41;
      uVar9 = FUN_0012c444(param_1 + 0x18);
      *(undefined8 *)(lVar11 + 8) = uVar9;
    }
    else {
LAB_00131518:
      lVar11 = 0;
    }
    uVar9 = 0x16;
    break;
  case 'T':
    if ((pcVar10[2] == '\0') || (*(char **)(param_1 + 0x18) = pcVar10 + 3, pcVar10[2] != 'n')) {
      puVar6 = (uint *)FUN_00130e70(param_1,0);
      uVar9 = 0x48;
      lVar11 = 0;
    }
    else {
      puVar6 = (uint *)FUN_00130e70(param_1,0);
      uVar9 = 0x49;
      lVar11 = 0;
    }
    break;
  case 'V':
    puVar6 = (uint *)FUN_001308c4(param_1);
    uVar9 = 0x13;
    lVar11 = 0;
    break;
  case 'r':
    lVar11 = FUN_0012c444(param_1 + 0x18);
    if (lVar11 < 2) {
      return (uint *)0x0;
    }
    pcVar10 = *(char **)(param_1 + 0x18);
    if (*pcVar10 == '\0') {
      return (uint *)0x0;
    }
    pcVar14 = pcVar10 + 1;
    *(char **)(param_1 + 0x18) = pcVar14;
    if (*pcVar10 != '_') {
      return (uint *)0x0;
    }
    lVar11 = lVar11 + -1;
    puVar12 = (uint *)0x0;
    do {
      if (*pcVar14 == '\0') {
        return (uint *)0x0;
      }
      uVar13 = 0;
      if (*pcVar14 == '$') {
        bVar3 = pcVar14[1];
        uVar5 = (uint)bVar3;
        if (bVar3 == 0x53) {
          uVar5 = 0x2f;
        }
        else if (bVar3 == 0x5f) {
          uVar5 = 0x2e;
        }
        else if (bVar3 != 0x24) {
          return (uint *)0x0;
        }
        iVar4 = *(int *)(param_1 + 0x28);
        if (*(int *)(param_1 + 0x2c) <= iVar4) {
LAB_00131520:
          *(long *)(param_1 + 0x18) = *(long *)(param_1 + 0x18) + 2;
          return (uint *)0x0;
        }
        *(int *)(param_1 + 0x28) = iVar4 + 1;
        puVar6 = (uint *)(*(long *)(param_1 + 0x20) + (long)iVar4 * 0x18);
        if (puVar6 == (uint *)0x0) goto LAB_00131520;
        *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar4 * 0x18) = 0x40;
        lVar7 = -2;
        puVar6[2] = uVar5;
        pcVar14 = (char *)(*(long *)(param_1 + 0x18) + 2);
        *(char **)(param_1 + 0x18) = pcVar14;
      }
      else {
        do {
          uVar13 = uVar13 + 1;
          if ((lVar11 <= (long)uVar13) || (pcVar14[uVar13] == '\0')) break;
        } while (pcVar14[uVar13] != '$');
        lVar7 = -uVar13;
        puVar6 = (uint *)FUN_0012be30(param_1,pcVar14,uVar13 & 0xffffffff);
        pcVar14 = (char *)(*(long *)(param_1 + 0x18) + uVar13);
        *(char **)(param_1 + 0x18) = pcVar14;
        if (puVar6 == (uint *)0x0) {
          return (uint *)0x0;
        }
      }
      lVar11 = lVar11 + lVar7;
      if ((puVar12 != (uint *)0x0) &&
         (puVar6 = (uint *)FUN_0012bd90(param_1,0x3f,puVar12), puVar6 == (uint *)0x0)) {
        return (uint *)0x0;
      }
      puVar12 = puVar6;
    } while (0 < lVar11);
    uVar9 = 0x3e;
    lVar11 = 0;
  }
  goto LAB_00131030;
joined_r0x00130fb8:
  if (puVar12 == (uint *)0x0) goto LAB_00130fe4;
  uVar5 = *puVar12;
  if (8 < uVar5) {
    if (uVar5 == 0x34) goto LAB_00130f0c;
    goto LAB_00130fe4;
  }
  if (6 < uVar5) goto LAB_00130f0c;
  if (1 < uVar5 - 1) goto LAB_00130fe4;
  puVar12 = *(uint **)(puVar12 + 4);
  goto joined_r0x00130fb8;
LAB_00130fe4:
  if (cVar2 == 'J') {
LAB_0013145c:
    *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
  }
  lVar11 = FUN_0012e994(param_1);
  if (lVar11 == 0) {
LAB_00131510:
    lVar11 = 0;
  }
  else {
LAB_00130ffc:
    lVar7 = FUN_0013003c(param_1);
    if (lVar7 == 0) goto LAB_00131510;
    lVar11 = FUN_0012bd90(param_1,0x29,lVar11,lVar7);
  }
  uVar9 = 3;
LAB_00131030:
  puVar6 = (uint *)FUN_0012bd90(param_1,uVar9,puVar6,lVar11);
  return puVar6;
}



undefined8 FUN_00131534(long param_1)

{
  char cVar1;
  int *piVar2;
  undefined8 uVar3;
  char cVar4;
  char *pcVar5;
  int iVar6;
  char *pcVar7;
  undefined8 uVar8;
  
  pcVar7 = *(char **)(param_1 + 0x18);
  if (*pcVar7 != 'L') {
    return 0;
  }
  pcVar5 = pcVar7 + 1;
  *(char **)(param_1 + 0x18) = pcVar5;
  cVar1 = pcVar7[1];
  if (cVar1 == 'Z') {
    cVar4 = 'Z';
    if (cVar1 == '_') goto LAB_0013165c;
  }
  else {
    if (cVar1 != '_') {
      piVar2 = (int *)FUN_0012e994();
      if (piVar2 == (int *)0x0) {
        return 0;
      }
      if ((*piVar2 == 0x27) && (*(int *)(*(long *)(piVar2 + 2) + 0x1c) != 0)) {
        *(int *)(param_1 + 0x50) = *(int *)(param_1 + 0x50) - *(int *)(*(long *)(piVar2 + 2) + 8);
      }
      pcVar5 = *(char **)(param_1 + 0x18);
      uVar8 = 0x3c;
      cVar1 = *pcVar5;
      pcVar7 = pcVar5;
      if (cVar1 == 'n') {
        pcVar7 = pcVar5 + 1;
        *(char **)(param_1 + 0x18) = pcVar7;
        uVar8 = 0x3d;
        cVar1 = pcVar5[1];
      }
      pcVar5 = pcVar7;
      if (cVar1 == 'E') {
        iVar6 = 0;
      }
      else {
        do {
          if (cVar1 == '\0') {
            return 0;
          }
          pcVar5 = pcVar5 + 1;
          *(char **)(param_1 + 0x18) = pcVar5;
          cVar1 = *pcVar5;
        } while (cVar1 != 'E');
        iVar6 = (int)pcVar5 - (int)pcVar7;
      }
      uVar3 = FUN_0012be30(param_1,pcVar7,iVar6);
      uVar8 = FUN_0012bd90(param_1,uVar8,piVar2,uVar3);
      pcVar5 = *(char **)(param_1 + 0x18);
      cVar4 = *pcVar5;
      goto LAB_0013160c;
    }
LAB_0013165c:
    pcVar5 = pcVar7 + 2;
    *(char **)(param_1 + 0x18) = pcVar5;
    cVar4 = pcVar7[2];
  }
  uVar8 = 0;
  if (cVar4 == 'Z') {
    *(char **)(param_1 + 0x18) = pcVar5 + 1;
    uVar8 = FUN_00130e70(param_1,0);
    pcVar5 = *(char **)(param_1 + 0x18);
    cVar4 = *pcVar5;
  }
LAB_0013160c:
  if (cVar4 != 'E') {
    return 0;
  }
  *(char **)(param_1 + 0x18) = pcVar5 + 1;
  return uVar8;
}



int * FUN_001316ac(long param_1)

{
  char cVar1;
  int iVar2;
  int *piVar3;
  undefined8 uVar4;
  undefined8 uVar5;
  undefined8 uVar6;
  char *pcVar7;
  long lVar8;
  char **ppcVar9;
  
  pcVar7 = *(char **)(param_1 + 0x18);
  cVar1 = *pcVar7;
  if (cVar1 == 'L') {
    piVar3 = (int *)FUN_00131534();
    return piVar3;
  }
  if (cVar1 == 'T') {
    piVar3 = (int *)FUN_0012cb7c();
    return piVar3;
  }
  if (cVar1 == 's') {
    if (pcVar7[1] == 'r') {
      *(char **)(param_1 + 0x18) = pcVar7 + 2;
      piVar3 = (int *)FUN_0012e994();
      uVar4 = FUN_00130340(param_1);
      if (**(char **)(param_1 + 0x18) == 'I') {
        uVar6 = FUN_0012cd54(param_1);
        uVar4 = FUN_0012bd90(param_1,4,uVar4,uVar6);
      }
      uVar6 = 1;
      goto LAB_0013179c;
    }
    if (pcVar7[1] == 'p') {
      *(char **)(param_1 + 0x18) = pcVar7 + 2;
      piVar3 = (int *)FUN_001316ac();
      uVar6 = 0x4a;
      uVar4 = 0;
      goto LAB_001318d8;
    }
  }
  else if (cVar1 == 'f') {
    if (pcVar7[1] == 'p') {
      *(char **)(param_1 + 0x18) = pcVar7 + 2;
      if (pcVar7[2] == 'T') {
        lVar8 = 0;
        *(char **)(param_1 + 0x18) = pcVar7 + 3;
      }
      else {
        iVar2 = FUN_0012ca4c();
        lVar8 = (long)(iVar2 + 1);
        if (iVar2 + 1 == 0) {
          return (int *)0x0;
        }
      }
      iVar2 = *(int *)(param_1 + 0x28);
      if (*(int *)(param_1 + 0x2c) <= iVar2) {
        return (int *)0x0;
      }
      *(int *)(param_1 + 0x28) = iVar2 + 1;
      piVar3 = (int *)(*(long *)(param_1 + 0x20) + (long)iVar2 * 0x18);
      if (piVar3 == (int *)0x0) {
        return (int *)0x0;
      }
      *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar2 * 0x18) = 6;
      *(long *)(piVar3 + 2) = lVar8;
      return piVar3;
    }
  }
  else {
    if ((byte)(cVar1 - 0x30U) < 10) {
LAB_001316f8:
      piVar3 = (int *)FUN_00130340(param_1);
      if (piVar3 == (int *)0x0) {
        return (int *)0x0;
      }
      if (**(char **)(param_1 + 0x18) != 'I') {
        return piVar3;
      }
      uVar4 = FUN_0012cd54(param_1);
      uVar6 = 4;
      goto LAB_001318d8;
    }
    if (cVar1 == 'o') {
      if (pcVar7[1] == 'n') {
        *(char **)(param_1 + 0x18) = pcVar7 + 2;
        goto LAB_001316f8;
      }
    }
    else if (((cVar1 == 't') || (cVar1 == 'i')) && (pcVar7[1] == 'l')) {
      piVar3 = (int *)0x0;
      if (cVar1 == 't') {
        piVar3 = (int *)FUN_0012e994(param_1);
        pcVar7 = *(char **)(param_1 + 0x18);
      }
      *(char **)(param_1 + 0x18) = pcVar7 + 2;
      uVar4 = FUN_0012e240(param_1,0x45);
      uVar6 = 0x30;
      goto LAB_001318d8;
    }
  }
  piVar3 = (int *)FUN_0013014c(param_1);
  if (piVar3 == (int *)0x0) {
    return (int *)0x0;
  }
  iVar2 = *piVar3;
  if (iVar2 == 0x31) {
    ppcVar9 = *(char ***)(piVar3 + 2);
    pcVar7 = *ppcVar9;
    *(int *)(param_1 + 0x50) = *(int *)(param_1 + 0x50) + *(int *)(ppcVar9 + 2) + -2;
    iVar2 = strcmp(pcVar7,"st");
    if (iVar2 != 0) {
      switch(*(undefined4 *)((long)ppcVar9 + 0x14)) {
      case 0:
        goto switchD_00131940_caseD_0;
      case 1:
        goto switchD_001319c4_caseD_1;
      case 2:
        goto switchD_001319c4_caseD_2;
      case 3:
        goto switchD_001319c4_caseD_3;
      default:
        goto switchD_00131940_caseD_4;
      }
    }
    uVar4 = FUN_0012e994(param_1);
  }
  else {
    if (iVar2 == 0x32) {
      switch(piVar3[2]) {
      case 0:
switchD_00131940_caseD_0:
        uVar6 = 0x35;
        uVar4 = 0;
LAB_001318d8:
        piVar3 = (int *)FUN_0012bd90(param_1,uVar6,piVar3,uVar4);
        return piVar3;
      case 1:
        goto switchD_00131940_caseD_1;
      case 2:
        pcVar7 = (char *)0x0;
switchD_001319c4_caseD_2:
        if (((**(char ***)(piVar3 + 2))[1] == 'c') &&
           ((cVar1 = ***(char ***)(piVar3 + 2), (byte)(cVar1 + 0x8eU) < 2 ||
            ((byte)(cVar1 + 0x9dU) < 2)))) {
          uVar4 = FUN_0012e994(param_1);
        }
        else {
          uVar4 = FUN_001316ac(param_1);
        }
        iVar2 = strcmp(pcVar7,"cl");
        if (iVar2 == 0) {
          uVar6 = FUN_0012e240(param_1,0x45);
        }
        else {
          iVar2 = strcmp(pcVar7,"dt");
          if ((iVar2 == 0) || (iVar2 = strcmp(pcVar7,"pt"), iVar2 == 0)) {
            uVar6 = FUN_00130340(param_1);
            if (**(char **)(param_1 + 0x18) == 'I') {
              uVar5 = FUN_0012cd54(param_1);
              uVar6 = FUN_0012bd90(param_1,4,uVar6,uVar5);
            }
          }
          else {
            uVar6 = FUN_001316ac(param_1);
          }
        }
        uVar4 = FUN_0012bd90(param_1,0x38,uVar4,uVar6);
        uVar6 = 0x37;
        goto LAB_0013179c;
      case 3:
        pcVar7 = (char *)0x0;
switchD_001319c4_caseD_3:
        iVar2 = strcmp(pcVar7,"qu");
        if (iVar2 == 0) {
          uVar4 = FUN_001316ac(param_1);
          uVar6 = FUN_001316ac(param_1);
          uVar5 = FUN_001316ac(param_1);
        }
        else {
          if (*pcVar7 != 'n') {
            return (int *)0x0;
          }
          if ((pcVar7[1] != 'a') && (pcVar7[1] != 'w')) {
            return (int *)0x0;
          }
          uVar4 = FUN_0012e240(param_1,0x5f);
          uVar6 = FUN_0012e994(param_1);
          pcVar7 = *(char **)(param_1 + 0x18);
          cVar1 = *pcVar7;
          if (cVar1 == 'E') {
            uVar5 = 0;
            *(char **)(param_1 + 0x18) = pcVar7 + 1;
          }
          else if (cVar1 == 'p') {
            if (pcVar7[1] != 'i') {
              return (int *)0x0;
            }
            *(char **)(param_1 + 0x18) = pcVar7 + 2;
            uVar5 = FUN_0012e240(param_1,0x45);
          }
          else {
            if ((cVar1 != 'i') || (pcVar7[1] != 'l')) {
switchD_00131940_caseD_4:
              return (int *)0x0;
            }
            uVar5 = FUN_001316ac(param_1);
          }
        }
        uVar6 = FUN_0012bd90(param_1,0x3b,uVar6,uVar5);
        uVar4 = FUN_0012bd90(param_1,0x3a,uVar4,uVar6);
        uVar6 = 0x39;
        goto LAB_0013179c;
      default:
        goto switchD_00131940_caseD_4;
      }
    }
    if (iVar2 != 0x33) {
      return (int *)0x0;
    }
    if (**(char **)(param_1 + 0x18) == '_') {
      *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
      uVar4 = FUN_0012e240(param_1,0x45);
      goto LAB_00131790;
    }
switchD_00131940_caseD_1:
    uVar4 = FUN_001316ac(param_1);
  }
LAB_00131790:
  uVar6 = 0x36;
LAB_0013179c:
  piVar3 = (int *)FUN_0012bd90(param_1,uVar6,piVar3,uVar4);
  return piVar3;
switchD_001319c4_caseD_1:
  cVar1 = *pcVar7;
  if (((cVar1 == 'm') || (cVar1 == 'p')) && (pcVar7[1] == cVar1)) {
    if (**(char **)(param_1 + 0x18) != '_') {
      uVar4 = FUN_001316ac(param_1);
      uVar4 = FUN_0012bd90(param_1,0x38,uVar4,uVar4);
      goto LAB_00131790;
    }
    *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
  }
  goto switchD_00131940_caseD_1;
}



undefined8 FUN_00131d14(long param_1)

{
  char *pcVar1;
  char cVar2;
  int iVar3;
  long lVar4;
  long lVar5;
  undefined8 uVar6;
  char *pcVar7;
  undefined8 uVar8;
  
  pcVar7 = *(char **)(param_1 + 0x18);
  if (*pcVar7 != 'F') {
    return 0;
  }
  pcVar1 = pcVar7 + 1;
  *(char **)(param_1 + 0x18) = pcVar1;
  cVar2 = pcVar7[1];
  if (cVar2 == 'Y') {
    pcVar1 = pcVar7 + 2;
    *(char **)(param_1 + 0x18) = pcVar1;
    cVar2 = pcVar7[2];
  }
  if (cVar2 == 'J') {
    *(char **)(param_1 + 0x18) = pcVar1 + 1;
  }
  lVar4 = FUN_0012e994();
  if ((lVar4 == 0) || (lVar5 = FUN_0013003c(param_1), lVar5 == 0)) {
    uVar6 = 0;
  }
  else {
    uVar6 = FUN_0012bd90(param_1,0x29,lVar4,lVar5);
  }
  pcVar7 = *(char **)(param_1 + 0x18);
  cVar2 = *pcVar7;
  if (cVar2 == 'O') {
    if (cVar2 == 'R') goto LAB_00131e2c;
    uVar8 = 0x20;
    iVar3 = *(int *)(param_1 + 0x50) + 3;
  }
  else {
    if (cVar2 != 'R') {
      if (cVar2 != 'E') {
        return 0;
      }
      goto LAB_00131db4;
    }
LAB_00131e2c:
    uVar8 = 0x1f;
    iVar3 = *(int *)(param_1 + 0x50) + 2;
  }
  *(int *)(param_1 + 0x50) = iVar3;
  *(char **)(param_1 + 0x18) = pcVar7 + 1;
  uVar6 = FUN_0012bd90(param_1,uVar8,uVar6,0);
  pcVar7 = *(char **)(param_1 + 0x18);
  if (*pcVar7 != 'E') {
    return 0;
  }
LAB_00131db4:
  *(char **)(param_1 + 0x18) = pcVar7 + 1;
  return uVar6;
}


/*
Unable to decompile 'FUN_00131e44'
Cause: 
Low-level Error: Could not finish collapsing block structure
*/


// WARNING: Type propagation algorithm not settling

void FUN_00134578(undefined *param_1,uint param_2,long *param_3)

{
  char *pcVar1;
  byte *pbVar2;
  undefined uVar3;
  char cVar4;
  bool bVar5;
  int iVar6;
  long lVar7;
  long **pplVar8;
  int *piVar9;
  long lVar10;
  char *pcVar11;
  long lVar12;
  size_t sVar13;
  undefined8 *puVar14;
  int iVar15;
  uint uVar16;
  long lVar17;
  long lVar18;
  long *plVar19;
  long ***ppplVar20;
  long *plVar21;
  long ***ppplVar22;
  int *piVar23;
  char **ppcVar24;
  long *plVar25;
  long ***ppplVar26;
  long **pplVar27;
  long ***ppplVar28;
  ulong uVar29;
  byte bVar30;
  int iVar31;
  undefined8 *puVar32;
  size_t sVar33;
  byte *pbVar34;
  byte *pbVar35;
  uint uVar36;
  undefined8 unaff_x22;
  ulong uVar37;
  undefined8 uVar38;
  ulong uVar39;
  undefined8 uVar40;
  long ***local_90;
  long *local_88;
  long **local_80;
  long *local_78;
  long *local_70;
  long ***local_68 [2];
  long *local_58;
  long *local_50;
  long ***local_48;
  long ****local_40;
  long *local_38;
  undefined4 local_30;
  undefined4 uStack_2c;
  long ***local_28;
  long *****local_20;
  long *local_18;
  ulong local_10;
  long ***local_8;
  
  if (param_3 == (long *)0x0) goto LAB_001345f4;
  if (*(int *)(param_1 + 0x130) != 0) {
    return;
  }
  iVar6 = *(int *)param_3;
  switch(iVar6) {
  case 0:
    if ((param_2 >> 2 & 1) == 0) {
      iVar6 = *(int *)(param_3 + 2);
      lVar10 = param_3[1];
      if ((long)iVar6 != 0) {
        lVar18 = 0;
        lVar12 = *(long *)(param_1 + 0x100);
        do {
          uVar3 = *(undefined *)(lVar10 + lVar18);
          if (lVar12 == 0xff) {
            param_1[0xff] = 0;
            (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
            lVar7 = 1;
            lVar12 = 0;
            *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
          }
          else {
            lVar7 = lVar12 + 1;
          }
          *(long *)(param_1 + 0x100) = lVar7;
          lVar18 = lVar18 + 1;
          param_1[lVar12] = uVar3;
          param_1[0x108] = uVar3;
          lVar12 = lVar7;
        } while (iVar6 != lVar18);
      }
    }
    else {
      pbVar34 = (byte *)param_3[1];
      pbVar2 = pbVar34 + *(int *)(param_3 + 2);
      while (pbVar34 < pbVar2) {
        bVar30 = *pbVar34;
        if (((3 < (long)pbVar2 - (long)pbVar34) && (bVar30 == 0x5f)) &&
           ((pbVar34[1] == 0x5f &&
            ((bVar30 = 0x5f, pbVar34[2] == 0x55 && (pbVar35 = pbVar34 + 3, pbVar35 < pbVar2)))))) {
          uVar39 = 0;
          do {
            bVar30 = *pbVar35;
            uVar16 = (uint)bVar30;
            uVar36 = uVar16 - 0x30;
            if (9 < (uVar36 & 0xff)) {
              if ((uVar16 - 0x41 & 0xff) < 6) {
                uVar36 = uVar16 - 0x37;
              }
              else {
                if (5 < (uVar16 - 0x61 & 0xff)) {
                  if (((pbVar35 < pbVar2) && (bVar30 == 0x5f)) && (uVar39 < 0x100)) {
                    lVar10 = *(long *)(param_1 + 0x100);
                    if (lVar10 == 0xff) {
                      param_1[0xff] = 0;
                      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
                      *(undefined8 *)(param_1 + 0x100) = 0;
                      lVar10 = 0;
                      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
                    }
                    *(long *)(param_1 + 0x100) = lVar10 + 1;
                    param_1[lVar10] = (char)uVar39;
                    param_1[0x108] = (char)uVar39;
                    goto LAB_00136c74;
                  }
                  break;
                }
                uVar36 = bVar30 - 0x57;
              }
            }
            pbVar35 = pbVar35 + 1;
            uVar39 = (long)(int)uVar36 + uVar39 * 0x10;
          } while (pbVar35 != pbVar2);
          bVar30 = 0x5f;
        }
        lVar10 = *(long *)(param_1 + 0x100);
        if (lVar10 == 0xff) {
          param_1[0xff] = 0;
          (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
          lVar18 = 1;
          lVar10 = 0;
          *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        }
        else {
          lVar18 = lVar10 + 1;
        }
        *(long *)(param_1 + 0x100) = lVar18;
        param_1[lVar10] = bVar30;
        param_1[0x108] = bVar30;
        pbVar35 = pbVar34;
LAB_00136c74:
        pbVar34 = pbVar35 + 1;
      }
    }
    break;
  case 1:
  case 2:
    FUN_00134578(param_1,param_2,param_3[1]);
    lVar10 = *(long *)(param_1 + 0x100);
    if ((param_2 >> 2 & 1) == 0) {
      if (lVar10 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar18 = 1;
        *param_1 = 0x3a;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
LAB_001346c8:
        lVar10 = lVar18 + 1;
      }
      else {
        lVar18 = lVar10 + 1;
        *(long *)(param_1 + 0x100) = lVar18;
        param_1[lVar10] = 0x3a;
        param_1[0x108] = 0x3a;
        if (lVar18 != 0xff) goto LAB_001346c8;
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar10 = 1;
        lVar18 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
      *(long *)(param_1 + 0x100) = lVar10;
      param_1[lVar18] = 0x3a;
      param_1[0x108] = 0x3a;
    }
    else {
      if (lVar10 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar18 = 1;
        lVar10 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
      else {
        lVar18 = lVar10 + 1;
      }
      *(long *)(param_1 + 0x100) = lVar18;
      param_1[lVar10] = 0x2e;
      param_1[0x108] = 0x2e;
    }
    piVar9 = (int *)param_3[2];
    if (*piVar9 == 0x46) {
      FUN_0012c6d0(param_1,"{default arg#");
      FUN_0012c8d8(param_1,(long)(piVar9[4] + 1));
      FUN_0012c6d0(param_1,&DAT_00141e20);
      piVar9 = *(int **)(piVar9 + 2);
    }
    FUN_00134578(param_1,param_2,piVar9);
    break;
  case 3:
    uVar38 = *(undefined8 *)(param_1 + 0x128);
    *(undefined8 *)(param_1 + 0x128) = 0;
    plVar21 = (long *)param_3[1];
    if (plVar21 != (long *)0x0) {
      iVar6 = *(int *)plVar21;
      ppplVar26 = *(long ****)(param_1 + 0x120);
      local_80 = (long **)0x0;
      *(long ****)(param_1 + 0x128) = &local_80;
      local_78 = plVar21;
      local_70._0_4_ = 0;
      local_68[0] = ppplVar26;
      if (iVar6 - 0x1cU < 5) {
        plVar21 = (long *)plVar21[1];
        if (plVar21 != (long *)0x0) {
          iVar6 = *(int *)plVar21;
          local_68[1] = &local_80;
          *(long *****)(param_1 + 0x128) = local_68 + 1;
          local_58 = plVar21;
          local_50._0_4_ = 0;
          local_48 = ppplVar26;
          if (4 < iVar6 - 0x1cU) {
            uVar39 = 2;
            goto LAB_00137be4;
          }
          plVar21 = (long *)plVar21[1];
          if (plVar21 != (long *)0x0) {
            iVar6 = *(int *)plVar21;
            local_40 = local_68 + 1;
            local_38 = plVar21;
            *(long ******)(param_1 + 0x128) = &local_40;
            local_30 = 0;
            local_28 = ppplVar26;
            if (4 < iVar6 - 0x1cU) {
              uVar39 = 3;
              goto LAB_00137be4;
            }
            plVar21 = (long *)plVar21[1];
            if (plVar21 != (long *)0x0) {
              iVar6 = *(int *)plVar21;
              local_20 = &local_40;
              local_18 = plVar21;
              *(long *****)(param_1 + 0x128) = &local_28 + 1;
              local_10 = local_10 & 0xffffffff00000000;
              local_8 = ppplVar26;
              if (4 < iVar6 - 0x1cU) {
                uVar39 = 4;
                goto LAB_00137be4;
              }
            }
          }
        }
      }
      else {
        uVar39 = 1;
LAB_00137be4:
        uVar37 = uVar39;
        if (iVar6 == 4) {
          *(long *****)(param_1 + 0x120) = &local_90;
          local_90 = ppplVar26;
          local_88 = plVar21;
LAB_00137d04:
          FUN_00134578(param_1,param_2,param_3[2]);
          if (*(int *)plVar21 == 4) {
            *(long ****)(param_1 + 0x120) = local_90;
          }
          iVar6 = (int)uVar37;
          uVar36 = iVar6 - 1;
          if (*(int *)(&local_70 + (ulong)uVar36 * 4) == 0) {
            FUN_0012c3cc(param_1,0x20);
            FUN_00137f84(param_1,param_2,(&local_78)[(ulong)uVar36 * 4]);
          }
          if (uVar36 != 0) {
            uVar36 = iVar6 - 2;
            if (*(int *)(&local_70 + (ulong)uVar36 * 4) == 0) {
              FUN_0012c3cc(param_1,0x20);
              FUN_00137f84(param_1,param_2,(&local_78)[(ulong)uVar36 * 4]);
            }
            if (uVar36 != 0) {
              uVar36 = iVar6 - 3;
              if (*(int *)(&local_70 + (ulong)uVar36 * 4) == 0) {
                FUN_0012c3cc(param_1,0x20);
                FUN_00137f84(param_1,param_2,(&local_78)[(ulong)uVar36 * 4]);
              }
              if ((uVar36 != 0) && ((int)local_70 == 0)) {
                FUN_0012c3cc(param_1,0x20);
                FUN_00137f84(param_1,param_2,local_78);
                *(undefined8 *)(param_1 + 0x128) = uVar38;
                return;
              }
            }
          }
          *(undefined8 *)(param_1 + 0x128) = uVar38;
          return;
        }
        if (iVar6 != 2) goto LAB_00137d04;
        plVar25 = (long *)plVar21[2];
        if (*(int *)plVar25 == 0x46) {
          plVar25 = (long *)plVar25[1];
        }
        if (4 < *(int *)plVar25 - 0x1cU) goto LAB_00137d04;
        iVar6 = (int)uVar39;
        if (iVar6 != 4) {
          uVar37 = (ulong)(iVar6 - 1);
          ppplVar28 = &local_80 + uVar39 * 4;
          *(long ****)(param_1 + 0x128) = ppplVar28;
          ppplVar22 = &local_80 + uVar37 * 4;
          uVar29 = (ulong)(iVar6 + 1U);
          plVar19 = (&local_78)[uVar37 * 4];
          *ppplVar28 = *ppplVar22;
          (&local_78)[uVar39 * 4] = plVar19;
          ppplVar20 = local_68[uVar37 * 4];
          (&local_70)[uVar39 * 4] = (&local_70)[uVar37 * 4];
          local_68[uVar39 * 4] = ppplVar20;
          (&local_80)[uVar39 * 4] = (long **)ppplVar22;
          (&local_78)[uVar37 * 4] = plVar25;
          *(undefined4 *)(&local_70 + uVar37 * 4) = 0;
          local_68[uVar37 * 4] = ppplVar26;
          plVar25 = (long *)plVar25[1];
          uVar37 = uVar29;
          if (4 < *(int *)plVar25 - 0x1cU) goto LAB_00137d04;
          if (iVar6 + 1U != 4) {
            uVar37 = (ulong)(iVar6 + 2U);
            ppplVar22 = &local_80 + uVar29 * 4;
            *(long ****)(param_1 + 0x128) = ppplVar22;
            plVar19 = (&local_78)[uVar39 * 4];
            *ppplVar22 = *ppplVar28;
            (&local_78)[uVar29 * 4] = plVar19;
            ppplVar22 = local_68[uVar39 * 4];
            (&local_70)[uVar29 * 4] = (&local_70)[uVar39 * 4];
            local_68[uVar29 * 4] = ppplVar22;
            (&local_80)[uVar29 * 4] = (long **)ppplVar28;
            (&local_78)[uVar39 * 4] = plVar25;
            *(undefined4 *)(&local_70 + uVar39 * 4) = 0;
            local_68[uVar39 * 4] = ppplVar26;
            plVar25 = (long *)plVar25[1];
            if (4 < *(int *)plVar25 - 0x1cU) goto LAB_00137d04;
            if (iVar6 + 2U != 4) {
              local_10 = CONCAT44(uStack_2c,local_30);
              local_18 = local_38;
              local_20 = &local_40;
              local_8 = local_28;
              *(long *****)(param_1 + 0x128) = &local_28 + 1;
              local_30 = 0;
              if (4 < *(int *)plVar25[1] - 0x1cU) {
                uVar37 = 4;
                local_38 = plVar25;
                local_28 = ppplVar26;
                goto LAB_00137d04;
              }
            }
          }
        }
      }
    }
    *(undefined4 *)(param_1 + 0x130) = 1;
    break;
  case 4:
    uVar38 = *(undefined8 *)(param_1 + 0x160);
    uVar40 = *(undefined8 *)(param_1 + 0x128);
    *(long **)(param_1 + 0x160) = param_3;
    *(undefined8 *)(param_1 + 0x128) = 0;
    piVar9 = (int *)param_3[1];
    if (((((param_2 >> 2 & 1) == 0) || (*piVar9 != 0)) || (piVar9[4] != 6)) ||
       (iVar6 = strncmp(*(char **)(piVar9 + 2),"JArray",6), iVar6 != 0)) {
      FUN_00134578(param_1,param_2,piVar9);
      if (param_1[0x108] == '<') {
        FUN_0012c3cc(param_1,0x20);
      }
      lVar10 = *(long *)(param_1 + 0x100);
      if (lVar10 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar18 = 1;
        lVar10 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
      else {
        lVar18 = lVar10 + 1;
      }
      *(long *)(param_1 + 0x100) = lVar18;
      param_1[lVar10] = 0x3c;
      param_1[0x108] = 0x3c;
      FUN_00134578(param_1,param_2,param_3[2]);
      if (param_1[0x108] == '>') {
        FUN_0012c3cc(param_1,0x20);
      }
      lVar10 = *(long *)(param_1 + 0x100);
      if (lVar10 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar18 = 1;
        lVar10 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
      else {
        lVar18 = lVar10 + 1;
      }
      *(long *)(param_1 + 0x100) = lVar18;
      param_1[lVar10] = 0x3e;
      param_1[0x108] = 0x3e;
    }
    else {
      FUN_00134578(param_1,param_2,param_3[2]);
      FUN_0012c6d0(param_1,&DAT_00141e30);
    }
    *(undefined8 *)(param_1 + 0x128) = uVar40;
    *(undefined8 *)(param_1 + 0x160) = uVar38;
    break;
  case 5:
    piVar9 = (int *)FUN_0012c4cc(param_1,param_3 + 1);
    if (piVar9 != (int *)0x0) {
      if (*piVar9 != 0x2f) {
LAB_00135790:
        puVar32 = *(undefined8 **)(param_1 + 0x120);
        *(undefined8 *)(param_1 + 0x120) = *puVar32;
        FUN_00134578(param_1,param_2);
        *(undefined8 **)(param_1 + 0x120) = puVar32;
        return;
      }
      iVar6 = *(int *)(param_1 + 0x134);
      while (0 < iVar6) {
        piVar9 = *(int **)(piVar9 + 4);
        iVar6 = iVar6 + -1;
        if ((piVar9 == (int *)0x0) || (*piVar9 != 0x2f)) goto LAB_001345f4;
      }
      if ((iVar6 == 0) && (*(long *)(piVar9 + 2) != 0)) goto LAB_00135790;
    }
    goto LAB_001345f4;
  case 6:
    lVar18 = param_3[1];
    lVar10 = *(long *)(param_1 + 0x100);
    if (lVar18 != 0) {
      if (lVar10 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x7b;
        lVar10 = 2;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        param_1[1] = 0x70;
LAB_0013666c:
        lVar12 = lVar10 + 1;
        *(long *)(param_1 + 0x100) = lVar12;
        param_1[lVar10] = 0x61;
        param_1[0x108] = 0x61;
        if (lVar12 == 0xff) {
          param_1[0xff] = 0;
          (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
          *param_1 = 0x72;
          lVar10 = 2;
          *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
          param_1[1] = 0x6d;
        }
        else {
LAB_00136688:
          lVar7 = lVar12 + 1;
          *(long *)(param_1 + 0x100) = lVar7;
          param_1[lVar12] = 0x72;
          param_1[0x108] = 0x72;
          if (lVar7 != 0xff) goto LAB_001366a4;
          param_1[0xff] = 0;
          (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
          *param_1 = 0x6d;
          lVar10 = 1;
          *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        }
      }
      else {
        lVar12 = lVar10 + 1;
        *(long *)(param_1 + 0x100) = lVar12;
        param_1[lVar10] = 0x7b;
        param_1[0x108] = 0x7b;
        if (lVar12 == 0xff) {
          param_1[0xff] = 0;
          (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
          *param_1 = 0x70;
          lVar12 = 2;
          *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
          param_1[1] = 0x61;
          goto LAB_00136688;
        }
        lVar10 = lVar10 + 2;
        *(long *)(param_1 + 0x100) = lVar10;
        param_1[lVar12] = 0x70;
        param_1[0x108] = 0x70;
        if (lVar10 != 0xff) goto LAB_0013666c;
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x61;
        lVar7 = 2;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        param_1[1] = 0x72;
LAB_001366a4:
        lVar10 = lVar7 + 1;
        *(long *)(param_1 + 0x100) = lVar10;
        param_1[lVar7] = 0x6d;
        param_1[0x108] = 0x6d;
        if (lVar10 == 0xff) {
          param_1[0xff] = 0;
          (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
          lVar12 = 1;
          lVar10 = 0;
          *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
          goto LAB_001366c4;
        }
      }
      lVar12 = lVar10 + 1;
LAB_001366c4:
      *(long *)(param_1 + 0x100) = lVar12;
      param_1[lVar10] = 0x23;
      param_1[0x108] = 0x23;
      sVar33 = 0;
      sprintf((char *)&local_80,"%ld",lVar18);
      sVar13 = strlen((char *)&local_80);
      lVar10 = *(long *)(param_1 + 0x100);
      lVar18 = lVar10;
      if (sVar13 != 0) {
        do {
          cVar4 = *(char *)((long)&local_80 + sVar33);
          if (lVar18 == 0xff) {
            param_1[0xff] = 0;
            (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
            lVar10 = 1;
            lVar18 = 0;
            *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
          }
          else {
            lVar10 = lVar18 + 1;
          }
          *(long *)(param_1 + 0x100) = lVar10;
          sVar33 = sVar33 + 1;
          param_1[lVar18] = cVar4;
          param_1[0x108] = cVar4;
          lVar18 = lVar10;
        } while (sVar33 != sVar13);
      }
      if (lVar10 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar18 = 1;
        lVar10 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
      else {
        lVar18 = lVar10 + 1;
      }
      *(long *)(param_1 + 0x100) = lVar18;
      param_1[lVar10] = 0x7d;
      param_1[0x108] = 0x7d;
      return;
    }
    if (lVar10 == 0xff) {
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      *param_1 = 0x74;
      lVar10 = 2;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 0x68;
LAB_00134ff4:
      lVar18 = lVar10 + 1;
      *(long *)(param_1 + 0x100) = lVar18;
      param_1[lVar10] = 0x69;
      param_1[0x108] = 0x69;
      if (lVar18 != 0xff) goto LAB_00135010;
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar10 = 1;
      lVar18 = 0;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    }
    else {
      lVar18 = lVar10 + 1;
      *(long *)(param_1 + 0x100) = lVar18;
      param_1[lVar10] = 0x74;
      param_1[0x108] = 0x74;
      if (lVar18 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x68;
        lVar18 = 2;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        param_1[1] = 0x69;
      }
      else {
        lVar10 = lVar10 + 2;
        *(long *)(param_1 + 0x100) = lVar10;
        param_1[lVar18] = 0x68;
        param_1[0x108] = 0x68;
        if (lVar10 != 0xff) goto LAB_00134ff4;
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x69;
        lVar18 = 1;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
LAB_00135010:
      lVar10 = lVar18 + 1;
    }
    *(long *)(param_1 + 0x100) = lVar10;
    param_1[lVar18] = 0x73;
    param_1[0x108] = 0x73;
    break;
  case 7:
    FUN_00134578(param_1,param_2,param_3[2]);
    break;
  case 8:
    lVar10 = *(long *)(param_1 + 0x100);
    if (lVar10 == 0xff) {
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar18 = 1;
      lVar10 = 0;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    }
    else {
      lVar18 = lVar10 + 1;
    }
    *(long *)(param_1 + 0x100) = lVar18;
    param_1[lVar10] = 0x7e;
    param_1[0x108] = 0x7e;
    FUN_00134578(param_1,param_2,param_3[2]);
    break;
  case 9:
    pcVar11 = "vtable for ";
    lVar10 = *(long *)(param_1 + 0x100);
    do {
      cVar4 = *pcVar11;
      if (lVar10 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar18 = 1;
        lVar10 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
      else {
        lVar18 = lVar10 + 1;
      }
      *(long *)(param_1 + 0x100) = lVar18;
      pcVar11 = pcVar11 + 1;
      param_1[lVar10] = cVar4;
      param_1[0x108] = cVar4;
      lVar10 = lVar18;
    } while (pcVar11 != "");
    FUN_00134578(param_1,param_2,param_3[1]);
    break;
  case 10:
    pcVar11 = "VTT for ";
    lVar10 = *(long *)(param_1 + 0x100);
    do {
      cVar4 = *pcVar11;
      if (lVar10 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar18 = 1;
        lVar10 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
      else {
        lVar18 = lVar10 + 1;
      }
      *(long *)(param_1 + 0x100) = lVar18;
      pcVar11 = pcVar11 + 1;
      param_1[lVar10] = cVar4;
      param_1[0x108] = cVar4;
      lVar10 = lVar18;
    } while (pcVar11 != "");
    FUN_00134578(param_1,param_2,param_3[1]);
    break;
  case 0xb:
    lVar10 = 0;
    lVar18 = *(long *)(param_1 + 0x100);
    do {
      cVar4 = "construction vtable for "[lVar10];
      if (lVar18 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar12 = 1;
        lVar18 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
      else {
        lVar12 = lVar18 + 1;
      }
      *(long *)(param_1 + 0x100) = lVar12;
      lVar10 = lVar10 + 1;
      param_1[lVar18] = cVar4;
      param_1[0x108] = cVar4;
      lVar18 = lVar12;
    } while (lVar10 != 0x18);
    FUN_00134578(param_1,param_2,param_3[1]);
    lVar10 = *(long *)(param_1 + 0x100);
    if (lVar10 == 0xff) {
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar10 = 2;
      *param_1 = 0x2d;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 0x69;
LAB_00136440:
      lVar18 = lVar10 + 1;
      *(long *)(param_1 + 0x100) = lVar18;
      param_1[lVar10] = 0x6e;
      param_1[0x108] = 0x6e;
      if (lVar18 != 0xff) goto LAB_0013645c;
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar10 = 1;
      lVar18 = 0;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    }
    else {
      lVar18 = lVar10 + 1;
      *(long *)(param_1 + 0x100) = lVar18;
      param_1[lVar10] = 0x2d;
      param_1[0x108] = 0x2d;
      if (lVar18 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x69;
        lVar18 = 2;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        param_1[1] = 0x6e;
      }
      else {
        lVar10 = lVar10 + 2;
        *(long *)(param_1 + 0x100) = lVar10;
        param_1[lVar18] = 0x69;
        param_1[0x108] = 0x69;
        if (lVar10 != 0xff) goto LAB_00136440;
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x6e;
        lVar18 = 1;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
LAB_0013645c:
      lVar10 = lVar18 + 1;
    }
    *(long *)(param_1 + 0x100) = lVar10;
    param_1[lVar18] = 0x2d;
    param_1[0x108] = 0x2d;
    FUN_00134578(param_1,param_2,param_3[2]);
    break;
  case 0xc:
    pcVar11 = "typeinfo for ";
    lVar10 = *(long *)(param_1 + 0x100);
    do {
      cVar4 = *pcVar11;
      if (lVar10 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar18 = 1;
        lVar10 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
      else {
        lVar18 = lVar10 + 1;
      }
      *(long *)(param_1 + 0x100) = lVar18;
      pcVar11 = pcVar11 + 1;
      param_1[lVar10] = cVar4;
      param_1[0x108] = cVar4;
      lVar10 = lVar18;
    } while (pcVar11 != "");
    FUN_00134578(param_1,param_2,param_3[1]);
    break;
  case 0xd:
    lVar10 = 0;
    lVar18 = *(long *)(param_1 + 0x100);
    do {
      cVar4 = "typeinfo name for "[lVar10];
      if (lVar18 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar12 = 1;
        lVar18 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
      else {
        lVar12 = lVar18 + 1;
      }
      *(long *)(param_1 + 0x100) = lVar12;
      lVar10 = lVar10 + 1;
      param_1[lVar18] = cVar4;
      param_1[0x108] = cVar4;
      lVar18 = lVar12;
    } while (lVar10 != 0x12);
    FUN_00134578(param_1,param_2,param_3[1]);
    break;
  case 0xe:
    pcVar11 = "typeinfo fn for ";
    lVar10 = *(long *)(param_1 + 0x100);
    do {
      cVar4 = *pcVar11;
      if (lVar10 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar18 = 1;
        lVar10 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
      else {
        lVar18 = lVar10 + 1;
      }
      *(long *)(param_1 + 0x100) = lVar18;
      pcVar11 = pcVar11 + 1;
      param_1[lVar10] = cVar4;
      param_1[0x108] = cVar4;
      lVar10 = lVar18;
    } while (pcVar11 != "");
    FUN_00134578(param_1,param_2,param_3[1]);
    break;
  case 0xf:
    lVar10 = 0;
    lVar18 = *(long *)(param_1 + 0x100);
    do {
      cVar4 = "non-virtual thunk to "[lVar10];
      if (lVar18 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar12 = 1;
        lVar18 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
      else {
        lVar12 = lVar18 + 1;
      }
      *(long *)(param_1 + 0x100) = lVar12;
      lVar10 = lVar10 + 1;
      param_1[lVar18] = cVar4;
      param_1[0x108] = cVar4;
      lVar18 = lVar12;
    } while (lVar10 != 0x15);
    FUN_00134578(param_1,param_2,param_3[1]);
    break;
  case 0x10:
    lVar10 = 0;
    lVar18 = *(long *)(param_1 + 0x100);
    do {
      cVar4 = "virtual thunk to "[lVar10];
      if (lVar18 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar12 = 1;
        lVar18 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
      else {
        lVar12 = lVar18 + 1;
      }
      *(long *)(param_1 + 0x100) = lVar12;
      lVar10 = lVar10 + 1;
      param_1[lVar18] = cVar4;
      param_1[0x108] = cVar4;
      lVar18 = lVar12;
    } while (lVar10 != 0x11);
    FUN_00134578(param_1,param_2,param_3[1]);
    break;
  case 0x11:
    lVar10 = 0;
    lVar18 = *(long *)(param_1 + 0x100);
    do {
      cVar4 = "covariant return thunk to "[lVar10];
      if (lVar18 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar12 = 1;
        lVar18 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
      else {
        lVar12 = lVar18 + 1;
      }
      *(long *)(param_1 + 0x100) = lVar12;
      lVar10 = lVar10 + 1;
      param_1[lVar18] = cVar4;
      param_1[0x108] = cVar4;
      lVar18 = lVar12;
    } while (lVar10 != 0x1a);
    FUN_00134578(param_1,param_2,param_3[1]);
    break;
  case 0x12:
    pcVar11 = "java Class for ";
    lVar10 = *(long *)(param_1 + 0x100);
    do {
      cVar4 = *pcVar11;
      if (lVar10 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar18 = 1;
        lVar10 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
      else {
        lVar18 = lVar10 + 1;
      }
      *(long *)(param_1 + 0x100) = lVar18;
      pcVar11 = pcVar11 + 1;
      param_1[lVar10] = cVar4;
      param_1[0x108] = cVar4;
      lVar10 = lVar18;
    } while (pcVar11 != "");
    FUN_00134578(param_1,param_2,param_3[1]);
    break;
  case 0x13:
    FUN_0012c6d0(param_1,"guard variable for ");
    FUN_00134578(param_1,param_2,param_3[1]);
    break;
  case 0x14:
    FUN_0012c6d0(param_1,"TLS init function for ");
    FUN_00134578(param_1,param_2,param_3[1]);
    break;
  case 0x15:
    FUN_0012c6d0(param_1,"TLS wrapper function for ");
    FUN_00134578(param_1,param_2,param_3[1]);
    break;
  case 0x16:
    FUN_0012c6d0(param_1,"reference temporary #");
    FUN_00134578(param_1,param_2,param_3[2]);
    FUN_0012c6d0(param_1," for ");
    FUN_00134578(param_1,param_2,param_3[1]);
    break;
  case 0x17:
    FUN_0012c6d0(param_1,"hidden alias for ");
    FUN_00134578(param_1,param_2,param_3[1]);
    break;
  case 0x18:
    iVar6 = *(int *)(param_3 + 2);
    lVar10 = param_3[1];
    if ((long)iVar6 != 0) {
      lVar18 = 0;
      lVar12 = *(long *)(param_1 + 0x100);
      do {
        uVar3 = *(undefined *)(lVar10 + lVar18);
        if (lVar12 == 0xff) {
          param_1[0xff] = 0;
          (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
          lVar7 = 1;
          lVar12 = 0;
          *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        }
        else {
          lVar7 = lVar12 + 1;
        }
        *(long *)(param_1 + 0x100) = lVar7;
        lVar18 = lVar18 + 1;
        param_1[lVar12] = uVar3;
        param_1[0x108] = uVar3;
        lVar12 = lVar7;
      } while (iVar6 != lVar18);
    }
    break;
  case 0x19:
  case 0x1a:
  case 0x1b:
    local_80 = *(long ***)(param_1 + 0x128);
    pplVar27 = local_80;
    if (local_80 == (long **)0x0) {
      local_80 = (long **)0x0;
      bVar5 = false;
    }
    else {
      do {
        if (*(int *)(pplVar27 + 2) == 0) {
          if (2 < *(int *)pplVar27[1] - 0x19U) break;
          if (iVar6 == *(int *)pplVar27[1]) {
            FUN_00134578(param_1,param_2,param_3[1]);
            return;
          }
        }
        pplVar27 = (long **)*pplVar27;
      } while (pplVar27 != (long **)0x0);
      bVar5 = false;
    }
    goto LAB_00134e74;
  case 0x1c:
  case 0x1d:
  case 0x1e:
  case 0x1f:
  case 0x20:
  case 0x21:
  case 0x22:
  case 0x25:
  case 0x26:
    local_80 = *(long ***)(param_1 + 0x128);
    bVar5 = false;
LAB_00134e74:
    local_68[0] = *(long ****)(param_1 + 0x120);
    *(long ****)(param_1 + 0x128) = &local_80;
    local_78 = param_3;
LAB_00134e90:
    lVar10 = local_78[1];
LAB_00134e94:
    plVar21 = local_78;
    local_70._0_4_ = 0;
    FUN_00134578(param_1,param_2,lVar10);
    if ((int)local_70 == 0) {
      FUN_00137f84(param_1,param_2,plVar21);
    }
    *(long ***)(param_1 + 0x128) = local_80;
    if (bVar5) {
      *(undefined8 *)(param_1 + 0x120) = unaff_x22;
    }
    break;
  case 0x23:
  case 0x24:
    plVar21 = (long *)param_3[1];
    bVar5 = false;
    iVar6 = *(int *)plVar21;
    if (iVar6 == 5) {
      uVar36 = *(uint *)(param_1 + 0x148);
      pplVar27 = *(long ***)(param_1 + 0x140);
      if ((int)uVar36 < 1) {
LAB_0013693c:
        if (*(int *)(param_1 + 0x14c) <= (int)uVar36) {
LAB_00137e68:
          *(undefined4 *)(param_1 + 0x130) = 1;
          return;
        }
        uVar39 = -(ulong)(uVar36 >> 0x1f) & 0xfffffff000000000 | (ulong)uVar36 << 4;
        plVar25 = *(long **)(param_1 + 0x120);
        *(uint *)(param_1 + 0x148) = uVar36 + 1;
        *(long **)((long)pplVar27 + uVar39) = plVar21;
        puVar32 = (undefined8 *)((long)pplVar27 + uVar39 + 8);
        if (plVar25 != (long *)0x0) {
          uVar36 = *(uint *)(param_1 + 0x158);
          iVar6 = *(int *)(param_1 + 0x15c);
          if ((int)uVar36 < iVar6) {
            uVar39 = -(ulong)(uVar36 >> 0x1f) & 0xfffffff000000000 | (ulong)uVar36 << 4;
            puVar14 = puVar32;
            iVar31 = uVar36 + 1;
            do {
              iVar15 = iVar31;
              puVar32 = (undefined8 *)(*(long *)(param_1 + 0x150) + uVar39);
              puVar32[1] = plVar25[1];
              *puVar14 = puVar32;
              plVar25 = (long *)*plVar25;
              if (plVar25 == (long *)0x0) {
                *(int *)(param_1 + 0x158) = iVar15;
                goto LAB_001369c0;
              }
              uVar39 = uVar39 + 0x10;
              puVar14 = puVar32;
              iVar31 = iVar15 + 1;
            } while (iVar15 + 1 != iVar6 + 1);
            *(int *)(param_1 + 0x158) = iVar15;
          }
          goto LAB_00137e68;
        }
LAB_001369c0:
        *puVar32 = 0;
        bVar5 = false;
        plVar21 = (long *)FUN_0012c4cc(param_1,plVar21 + 1);
        if (plVar21 == (long *)0x0) goto LAB_001345f4;
LAB_00136b80:
        iVar6 = *(int *)plVar21;
        if (iVar6 != 0x2f) goto LAB_00134ed0;
        iVar6 = *(int *)(param_1 + 0x134);
        while (0 < iVar6) {
          plVar21 = (long *)plVar21[2];
          iVar6 = iVar6 + -1;
          if ((plVar21 == (long *)0x0) || (*(int *)plVar21 != 0x2f)) goto LAB_001345ec;
        }
        if ((iVar6 == 0) && (plVar21 = (long *)plVar21[1], plVar21 != (long *)0x0)) {
          iVar6 = *(int *)plVar21;
          goto LAB_00134ed0;
        }
LAB_001345ec:
        if (!bVar5) goto LAB_001345f4;
      }
      else {
        pplVar8 = pplVar27;
        if (plVar21 != *pplVar27) {
          do {
            pplVar8 = pplVar8 + 2;
            if (pplVar8 == pplVar27 + ((ulong)(uVar36 - 1) + 1) * 2) goto LAB_0013693c;
          } while (plVar21 != *pplVar8);
        }
        unaff_x22 = *(undefined8 *)(param_1 + 0x120);
        *(long **)(param_1 + 0x120) = pplVar8[1];
        bVar5 = true;
        plVar21 = (long *)FUN_0012c4cc(param_1,plVar21 + 1);
        if (plVar21 != (long *)0x0) goto LAB_00136b80;
      }
      *(undefined8 *)(param_1 + 0x120) = unaff_x22;
LAB_001345f4:
      *(undefined4 *)(param_1 + 0x130) = 1;
      return;
    }
LAB_00134ed0:
    if ((iVar6 == 0x23) || (*(int *)param_3 == iVar6)) {
      local_80 = *(long ***)(param_1 + 0x128);
      param_3 = plVar21;
      goto LAB_00134e74;
    }
    if (iVar6 != 0x24) {
      local_80 = *(long ***)(param_1 + 0x128);
      goto LAB_00134e74;
    }
    lVar10 = plVar21[1];
    local_80 = *(long ***)(param_1 + 0x128);
    local_68[0] = *(long ****)(param_1 + 0x120);
    *(long ****)(param_1 + 0x128) = &local_80;
    local_78 = param_3;
    if (lVar10 == 0) goto LAB_00134e90;
    goto LAB_00134e94;
  case 0x27:
    if ((param_2 >> 2 & 1) == 0) {
      lVar10 = (long)*(int *)((long *)param_3[1] + 1);
      lVar18 = *(long *)param_3[1];
      if (lVar10 != 0) {
        lVar12 = 0;
        lVar7 = *(long *)(param_1 + 0x100);
        do {
          uVar3 = *(undefined *)(lVar18 + lVar12);
          if (lVar7 == 0xff) {
            param_1[0xff] = 0;
            (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
            lVar17 = 1;
            lVar7 = 0;
            *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
          }
          else {
            lVar17 = lVar7 + 1;
          }
          *(long *)(param_1 + 0x100) = lVar17;
          lVar12 = lVar12 + 1;
          param_1[lVar7] = uVar3;
          param_1[0x108] = uVar3;
          lVar7 = lVar17;
        } while (lVar10 != lVar12);
      }
    }
    else {
      lVar10 = (long)*(int *)(param_3[1] + 0x18);
      lVar18 = *(long *)(param_3[1] + 0x10);
      if (lVar10 != 0) {
        lVar12 = 0;
        lVar7 = *(long *)(param_1 + 0x100);
        do {
          uVar3 = *(undefined *)(lVar18 + lVar12);
          if (lVar7 == 0xff) {
            param_1[0xff] = 0;
            (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
            lVar17 = 1;
            lVar7 = 0;
            *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
          }
          else {
            lVar17 = lVar7 + 1;
          }
          *(long *)(param_1 + 0x100) = lVar17;
          lVar12 = lVar12 + 1;
          param_1[lVar7] = uVar3;
          param_1[0x108] = uVar3;
          lVar7 = lVar17;
        } while (lVar10 != lVar12);
      }
    }
    break;
  case 0x28:
    FUN_00134578(param_1,param_2,param_3[1]);
    break;
  case 0x29:
    if ((param_2 >> 5 & 1) == 0) {
      if ((param_3[1] != 0) && ((param_2 >> 6 & 1) == 0)) {
        local_80 = *(long ***)(param_1 + 0x128);
        *(long ****)(param_1 + 0x128) = &local_80;
        local_68[0] = *(long ****)(param_1 + 0x120);
        local_70._0_4_ = 0;
        local_78 = param_3;
        FUN_00134578(param_1,param_2 & 0xffffff9f,param_3[1]);
        *(long ***)(param_1 + 0x128) = local_80;
        if ((int)local_70 != 0) {
          return;
        }
        FUN_0012c3cc(param_1,0x20);
      }
      FUN_00138de0(param_1,param_2 & 0xffffff9f,param_3 + 2,*(undefined8 *)(param_1 + 0x128));
    }
    else {
      FUN_00138de0(param_1,param_2 & 0xffffff9f,param_3 + 2,*(undefined8 *)(param_1 + 0x128));
      if (param_3[1] != 0) {
        FUN_00134578(param_1,param_2 & 0xffffff9f);
      }
    }
    break;
  case 0x2a:
    pplVar27 = *(long ***)(param_1 + 0x128);
    local_68[0] = *(long ****)(param_1 + 0x120);
    *(long ****)(param_1 + 0x128) = &local_80;
    local_70._0_4_ = 0;
    local_80 = pplVar27;
    if ((pplVar27 == (long **)0x0) || (2 < *(int *)pplVar27[1] - 0x19U)) {
      local_78 = param_3;
      FUN_00134578(param_1,param_2,param_3[2]);
      *(long ***)(param_1 + 0x128) = pplVar27;
      if ((int)local_70 != 0) {
        return;
      }
    }
    else {
      pplVar8 = pplVar27;
      ppplVar26 = &local_80;
      uVar39 = 1;
      do {
        ppplVar28 = ppplVar26;
        uVar37 = uVar39;
        if (*(int *)(pplVar8 + 2) == 0) {
          if (3 < (uint)uVar39) {
            *(undefined4 *)(param_1 + 0x130) = 1;
            return;
          }
          uVar37 = (ulong)((uint)uVar39 + 1);
          ppplVar28 = &local_80 + uVar39 * 4;
          plVar21 = pplVar8[1];
          *ppplVar28 = (long **)*pplVar8;
          (&local_78)[uVar39 * 4] = plVar21;
          ppplVar22 = (long ***)pplVar8[3];
          (&local_70)[uVar39 * 4] = pplVar8[2];
          local_68[uVar39 * 4] = ppplVar22;
          (&local_80)[uVar39 * 4] = (long **)ppplVar26;
          *(long ****)(param_1 + 0x128) = ppplVar28;
          *(undefined4 *)(pplVar8 + 2) = 1;
        }
        pplVar8 = (long **)*pplVar8;
      } while ((pplVar8 != (long **)0x0) &&
              (ppplVar26 = ppplVar28, uVar39 = uVar37, *(int *)pplVar8[1] - 0x19U < 3));
      local_78 = param_3;
      FUN_00134578(param_1,param_2,param_3[2]);
      *(long ***)(param_1 + 0x128) = pplVar27;
      if ((int)local_70 != 0) {
        return;
      }
      if ((int)uVar37 != 1) {
        do {
          uVar36 = (int)uVar37 - 1;
          uVar37 = (ulong)uVar36;
          FUN_00137f84(param_1,param_2,(&local_78)[uVar37 * 4]);
        } while (uVar36 != 1);
        pplVar27 = *(long ***)(param_1 + 0x128);
      }
    }
    FUN_00138b18(param_1,param_2,param_3 + 1,pplVar27);
    break;
  case 0x2b:
  case 0x2d:
    local_80 = *(long ***)(param_1 + 0x128);
    *(long ****)(param_1 + 0x128) = &local_80;
    local_68[0] = *(long ****)(param_1 + 0x120);
    local_70._0_4_ = 0;
    local_78 = param_3;
    FUN_00134578(param_1,param_2,param_3[2]);
    if ((int)local_70 == 0) {
      FUN_00137f84(param_1,param_2,param_3);
    }
    *(long ***)(param_1 + 0x128) = local_80;
    break;
  case 0x2c:
    if (*(short *)((long)param_3 + 0x12) != 0) {
      lVar10 = *(long *)(param_1 + 0x100);
      if (lVar10 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar10 = 2;
        *param_1 = 0x5f;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        param_1[1] = 0x53;
LAB_00136878:
        lVar18 = lVar10 + 1;
        *(long *)(param_1 + 0x100) = lVar18;
        param_1[lVar10] = 0x61;
        param_1[0x108] = 0x61;
        if (lVar18 == 0xff) {
          param_1[0xff] = 0;
          (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
          *param_1 = 0x74;
          lVar10 = 1;
          *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
          goto LAB_001368b0;
        }
LAB_00136894:
        lVar10 = lVar18 + 1;
        *(long *)(param_1 + 0x100) = lVar10;
        param_1[lVar18] = 0x74;
        param_1[0x108] = 0x74;
        if (lVar10 != 0xff) goto LAB_001368b0;
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar18 = 1;
        lVar10 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
      else {
        lVar18 = lVar10 + 1;
        *(long *)(param_1 + 0x100) = lVar18;
        param_1[lVar10] = 0x5f;
        param_1[0x108] = 0x5f;
        if (lVar18 == 0xff) {
          param_1[0xff] = 0;
          (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
          *param_1 = 0x53;
          lVar18 = 2;
          *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
          param_1[1] = 0x61;
          goto LAB_00136894;
        }
        lVar10 = lVar10 + 2;
        *(long *)(param_1 + 0x100) = lVar10;
        param_1[lVar18] = 0x53;
        param_1[0x108] = 0x53;
        if (lVar10 != 0xff) goto LAB_00136878;
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x61;
        lVar10 = 2;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        param_1[1] = 0x74;
LAB_001368b0:
        lVar18 = lVar10 + 1;
      }
      *(long *)(param_1 + 0x100) = lVar18;
      param_1[lVar10] = 0x20;
      param_1[0x108] = 0x20;
    }
    if (*(undefined **)(param_3[1] + 8) == &UNK_0015d400) {
      lVar10 = *(long *)(param_1 + 0x100);
    }
    else {
      FUN_00134578(param_1,param_2);
      lVar18 = *(long *)(param_1 + 0x100);
      if (lVar18 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar10 = 1;
        lVar18 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
      else {
        lVar10 = lVar18 + 1;
      }
      *(long *)(param_1 + 0x100) = lVar10;
      param_1[lVar18] = 0x20;
      param_1[0x108] = 0x20;
    }
    if (*(short *)(param_3 + 2) == 0) {
      if (lVar10 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar10 = 2;
        *param_1 = 0x5f;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        param_1[1] = 0x46;
LAB_00136594:
        lVar18 = lVar10 + 1;
        *(long *)(param_1 + 0x100) = lVar18;
        param_1[lVar10] = 0x72;
        param_1[0x108] = 0x72;
        if (lVar18 == 0xff) {
          param_1[0xff] = 0;
          (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
          *param_1 = 0x61;
          lVar10 = 2;
          *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
          param_1[1] = 99;
        }
        else {
LAB_001365b0:
          lVar12 = lVar18 + 1;
          *(long *)(param_1 + 0x100) = lVar12;
          param_1[lVar18] = 0x61;
          param_1[0x108] = 0x61;
          if (lVar12 != 0xff) goto LAB_001365cc;
          param_1[0xff] = 0;
          (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
          *param_1 = 99;
          lVar10 = 1;
          *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        }
      }
      else {
        lVar18 = lVar10 + 1;
        *(long *)(param_1 + 0x100) = lVar18;
        param_1[lVar10] = 0x5f;
        param_1[0x108] = 0x5f;
        if (lVar18 == 0xff) {
          param_1[0xff] = 0;
          (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
          *param_1 = 0x46;
          lVar18 = 2;
          *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
          param_1[1] = 0x72;
          goto LAB_001365b0;
        }
        lVar10 = lVar10 + 2;
        *(long *)(param_1 + 0x100) = lVar10;
        param_1[lVar18] = 0x46;
        param_1[0x108] = 0x46;
        if (lVar10 != 0xff) goto LAB_00136594;
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x72;
        lVar12 = 2;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        param_1[1] = 0x61;
LAB_001365cc:
        lVar10 = lVar12 + 1;
        *(long *)(param_1 + 0x100) = lVar10;
        param_1[lVar12] = 99;
        param_1[0x108] = 99;
        if (lVar10 == 0xff) {
          param_1[0xff] = 0;
          (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
          lVar18 = 1;
          lVar10 = 0;
          *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
          goto LAB_001365ec;
        }
      }
      lVar18 = lVar10 + 1;
LAB_001365ec:
      *(long *)(param_1 + 0x100) = lVar18;
      param_1[lVar10] = 0x74;
      param_1[0x108] = 0x74;
      return;
    }
    if (lVar10 == 0xff) {
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar10 = 2;
      *param_1 = 0x5f;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 0x41;
LAB_00135b08:
      lVar18 = lVar10 + 1;
      *(long *)(param_1 + 0x100) = lVar18;
      param_1[lVar10] = 99;
      param_1[0x108] = 99;
      if (lVar18 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 99;
        lVar10 = 2;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        param_1[1] = 0x75;
      }
      else {
LAB_00135b24:
        lVar12 = lVar18 + 1;
        *(long *)(param_1 + 0x100) = lVar12;
        param_1[lVar18] = 99;
        param_1[0x108] = 99;
        if (lVar12 != 0xff) goto LAB_00135b40;
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x75;
        lVar10 = 1;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
LAB_00135b5c:
      lVar18 = lVar10 + 1;
    }
    else {
      lVar18 = lVar10 + 1;
      *(long *)(param_1 + 0x100) = lVar18;
      param_1[lVar10] = 0x5f;
      param_1[0x108] = 0x5f;
      if (lVar18 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x41;
        lVar18 = 2;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        param_1[1] = 99;
        goto LAB_00135b24;
      }
      lVar10 = lVar10 + 2;
      *(long *)(param_1 + 0x100) = lVar10;
      param_1[lVar18] = 0x41;
      param_1[0x108] = 0x41;
      if (lVar10 != 0xff) goto LAB_00135b08;
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      *param_1 = 99;
      lVar12 = 2;
      param_1[1] = 99;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
LAB_00135b40:
      lVar10 = lVar12 + 1;
      *(long *)(param_1 + 0x100) = lVar10;
      param_1[lVar12] = 0x75;
      param_1[0x108] = 0x75;
      if (lVar10 != 0xff) goto LAB_00135b5c;
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar18 = 1;
      lVar10 = 0;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    }
    *(long *)(param_1 + 0x100) = lVar18;
    param_1[lVar10] = 0x6d;
    param_1[0x108] = 0x6d;
    break;
  case 0x2e:
  case 0x2f:
    if (param_3[1] != 0) {
      FUN_00134578(param_1,param_2);
    }
    if (param_3[2] != 0) {
      uVar37 = *(ulong *)(param_1 + 0x100);
      uVar39 = uVar37;
      if (0xfd < uVar37) {
        param_1[uVar37] = 0;
        uVar39 = 0;
        (**(code **)(param_1 + 0x110))(param_1,uVar37,*(undefined8 *)(param_1 + 0x118));
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
      param_1[uVar39] = 0x2c;
      *(ulong *)(param_1 + 0x100) = uVar39 + 2;
      param_1[uVar39 + 1] = 0x20;
      param_1[0x108] = 0x20;
      lVar10 = *(long *)(param_1 + 0x138);
      FUN_00134578(param_1,param_2,param_3[2]);
      if ((*(long *)(param_1 + 0x138) == lVar10) && (*(long *)(param_1 + 0x100) == uVar39 + 2)) {
        *(ulong *)(param_1 + 0x100) = uVar39;
      }
    }
    break;
  case 0x30:
    lVar10 = param_3[2];
    if (param_3[1] != 0) {
      FUN_00134578(param_1,param_2);
    }
    lVar18 = *(long *)(param_1 + 0x100);
    if (lVar18 == 0xff) {
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar12 = 1;
      lVar18 = 0;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    }
    else {
      lVar12 = lVar18 + 1;
    }
    *(long *)(param_1 + 0x100) = lVar12;
    param_1[lVar18] = 0x7b;
    param_1[0x108] = 0x7b;
    FUN_00134578(param_1,param_2,lVar10);
    lVar10 = *(long *)(param_1 + 0x100);
    if (lVar10 == 0xff) {
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar18 = 1;
      lVar10 = 0;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    }
    else {
      lVar18 = lVar10 + 1;
    }
    *(long *)(param_1 + 0x100) = lVar18;
    param_1[lVar10] = 0x7d;
    param_1[0x108] = 0x7d;
    break;
  case 0x31:
    lVar18 = param_3[1];
    pcVar11 = "operator";
    iVar6 = *(int *)(lVar18 + 0x10);
    lVar10 = *(long *)(param_1 + 0x100);
    do {
      cVar4 = *pcVar11;
      if (lVar10 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar12 = 1;
        lVar10 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
      else {
        lVar12 = lVar10 + 1;
      }
      *(long *)(param_1 + 0x100) = lVar12;
      pcVar11 = pcVar11 + 1;
      param_1[lVar10] = cVar4;
      param_1[0x108] = cVar4;
      lVar10 = lVar12;
    } while (pcVar11 != "");
    pcVar11 = *(char **)(lVar18 + 8);
    if ((byte)(*pcVar11 + 0x9fU) < 0x1a) {
      if (lVar12 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar12 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
      *(long *)(param_1 + 0x100) = lVar12 + 1;
      param_1[lVar12] = 0x20;
      param_1[0x108] = 0x20;
      pcVar11 = *(char **)(lVar18 + 8);
    }
    lVar10 = (long)iVar6;
    if (pcVar11[lVar10 + -1] == ' ') {
      lVar10 = (long)(iVar6 + -1);
    }
    if (lVar10 != 0) {
      pcVar1 = pcVar11 + lVar10;
      lVar10 = *(long *)(param_1 + 0x100);
      do {
        cVar4 = *pcVar11;
        if (lVar10 == 0xff) {
          param_1[0xff] = 0;
          (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
          lVar18 = 1;
          lVar10 = 0;
          *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        }
        else {
          lVar18 = lVar10 + 1;
        }
        *(long *)(param_1 + 0x100) = lVar18;
        pcVar11 = pcVar11 + 1;
        param_1[lVar10] = cVar4;
        param_1[0x108] = cVar4;
        lVar10 = lVar18;
      } while (pcVar11 != pcVar1);
    }
    break;
  case 0x32:
    lVar10 = 0;
    lVar18 = *(long *)(param_1 + 0x100);
    do {
      cVar4 = "operator "[lVar10];
      if (lVar18 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar12 = 1;
        lVar18 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
      else {
        lVar12 = lVar18 + 1;
      }
      *(long *)(param_1 + 0x100) = lVar12;
      lVar10 = lVar10 + 1;
      param_1[lVar18] = cVar4;
      param_1[0x108] = cVar4;
      lVar18 = lVar12;
    } while (lVar10 != 9);
    FUN_00134578(param_1,param_2,param_3[2]);
    break;
  default:
    *(undefined4 *)(param_1 + 0x130) = 1;
    break;
  case 0x34:
    lVar10 = 0;
    lVar18 = *(long *)(param_1 + 0x100);
    do {
      cVar4 = "operator "[lVar10];
      if (lVar18 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar12 = 1;
        lVar18 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
      else {
        lVar12 = lVar18 + 1;
      }
      *(long *)(param_1 + 0x100) = lVar12;
      lVar10 = lVar10 + 1;
      param_1[lVar18] = cVar4;
      param_1[0x108] = cVar4;
      lVar18 = lVar12;
    } while (lVar10 != 9);
    if (*(long **)(param_1 + 0x160) != (long *)0x0) {
      local_80 = *(long ***)(param_1 + 0x120);
      *(long ****)(param_1 + 0x120) = &local_80;
      local_78 = *(long **)(param_1 + 0x160);
    }
    if (*(int *)param_3[1] == 4) {
      FUN_00134578(param_1,param_2,*(undefined8 *)((int *)param_3[1] + 2));
      if (*(long *)(param_1 + 0x160) != 0) {
        *(long ***)(param_1 + 0x120) = local_80;
      }
      if (param_1[0x108] == '<') {
        lVar10 = *(long *)(param_1 + 0x100);
        if (lVar10 == 0xff) {
          param_1[0xff] = 0;
          (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
          *(undefined8 *)(param_1 + 0x100) = 0;
          lVar10 = 0;
          *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        }
        *(long *)(param_1 + 0x100) = lVar10 + 1;
        param_1[lVar10] = 0x20;
        param_1[0x108] = 0x20;
      }
      lVar10 = *(long *)(param_1 + 0x100);
      if (lVar10 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar10 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
      *(long *)(param_1 + 0x100) = lVar10 + 1;
      param_1[lVar10] = 0x3c;
      param_1[0x108] = 0x3c;
      FUN_00134578(param_1,param_2,*(undefined8 *)(param_3[1] + 0x10));
      if (param_1[0x108] == '>') {
        lVar10 = *(long *)(param_1 + 0x100);
        if (lVar10 == 0xff) {
          param_1[0xff] = 0;
          (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
          *(undefined8 *)(param_1 + 0x100) = 0;
          lVar10 = 0;
          *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        }
        *(long *)(param_1 + 0x100) = lVar10 + 1;
        param_1[lVar10] = 0x20;
        param_1[0x108] = 0x20;
      }
      lVar10 = *(long *)(param_1 + 0x100);
      if (lVar10 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar10 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
      *(long *)(param_1 + 0x100) = lVar10 + 1;
      param_1[lVar10] = 0x3e;
      param_1[0x108] = 0x3e;
    }
    else {
      FUN_00134578(param_1,param_2);
      if (*(long *)(param_1 + 0x160) != 0) {
        *(long ***)(param_1 + 0x120) = local_80;
      }
    }
    break;
  case 0x35:
    FUN_00139090(param_1,param_2,param_3[1]);
    break;
  case 0x36:
    piVar23 = (int *)param_3[1];
    piVar9 = (int *)param_3[2];
    if (*piVar23 == 0x31) {
      pcVar11 = **(char ***)(piVar23 + 2);
      iVar6 = strcmp(pcVar11,"ad");
      if (iVar6 == 0) {
        iVar6 = *piVar9;
        if (iVar6 != 3) goto LAB_00136a08;
        if ((**(int **)(piVar9 + 2) == 1) && (**(int **)(piVar9 + 4) == 0x29)) {
          piVar9 = *(int **)(piVar9 + 2);
        }
      }
      else {
        iVar6 = *piVar9;
LAB_00136a08:
        if (iVar6 == 0x38) {
          FUN_00139164(param_1,param_2,*(undefined8 *)(piVar9 + 2));
          FUN_00139090(param_1,param_2,piVar23);
          return;
        }
      }
      FUN_00139090(param_1,param_2,piVar23);
      iVar6 = strcmp(pcVar11,"gs");
      if (iVar6 == 0) {
        FUN_00134578(param_1,param_2,piVar9);
        return;
      }
      iVar6 = strcmp(pcVar11,"st");
      if (iVar6 == 0) {
        FUN_0012c3cc(param_1,0x28);
        FUN_00134578(param_1,param_2,piVar9);
        lVar10 = *(long *)(param_1 + 0x100);
        if (lVar10 == 0xff) {
          param_1[0xff] = 0;
          (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
          lVar10 = 0;
          *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        }
        *(long *)(param_1 + 0x100) = lVar10 + 1;
        param_1[lVar10] = 0x29;
        param_1[0x108] = 0x29;
        return;
      }
    }
    else if (*piVar23 == 0x33) {
      lVar10 = *(long *)(param_1 + 0x100);
      if (lVar10 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar10 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
      *(long *)(param_1 + 0x100) = lVar10 + 1;
      param_1[lVar10] = 0x28;
      param_1[0x108] = 0x28;
      FUN_00134578(param_1,param_2,*(undefined8 *)(piVar23 + 2));
      FUN_0012c3cc(param_1,0x29);
    }
    else {
      FUN_00139090(param_1,param_2,piVar23);
    }
    FUN_00139164(param_1,param_2,piVar9);
    break;
  case 0x37:
    piVar9 = (int *)param_3[2];
    if (*piVar9 != 0x38) goto LAB_001345f4;
    ppcVar24 = *(char ***)((int *)param_3[1] + 2);
    pcVar11 = *ppcVar24;
    if ((pcVar11[1] == 'c') && (((byte)(*pcVar11 + 0x8eU) < 2 || ((byte)(*pcVar11 + 0x9dU) < 2)))) {
      FUN_00139090(param_1,param_2);
      FUN_0012c3cc(param_1,0x3c);
      FUN_00134578(param_1,param_2,*(undefined8 *)(param_3[2] + 8));
      FUN_0012c6d0(param_1,&DAT_001420d0);
      FUN_00134578(param_1,param_2,*(undefined8 *)(param_3[2] + 0x10));
      FUN_0012c3cc(param_1,0x29);
    }
    else {
      if ((*(int *)param_3[1] == 0x31) && ((*(int *)(ppcVar24 + 2) == 1 && (*ppcVar24[1] == '>'))))
      {
        FUN_0012c3cc(param_1,0x28);
        piVar9 = (int *)param_3[2];
        pcVar11 = **(char ***)(param_3[1] + 8);
      }
      iVar6 = strcmp(pcVar11,"cl");
      piVar9 = *(int **)(piVar9 + 2);
      if ((iVar6 == 0) && (*piVar9 == 3)) {
        if (**(int **)(piVar9 + 4) != 0x29) {
          *(undefined4 *)(param_1 + 0x130) = 1;
        }
        FUN_00139164(param_1,param_2,*(undefined8 *)(piVar9 + 2));
      }
      else {
        FUN_00139164(param_1,param_2);
      }
      lVar10 = param_3[1];
      pcVar11 = **(char ***)(lVar10 + 8);
      iVar6 = strcmp(pcVar11,"ix");
      if (iVar6 == 0) {
        FUN_0012c3cc(param_1,0x5b);
        FUN_00134578(param_1,param_2,*(undefined8 *)(param_3[2] + 0x10));
        FUN_0012c3cc(param_1,0x5d);
      }
      else {
        iVar6 = strcmp(pcVar11,"cl");
        if (iVar6 != 0) {
          FUN_00139090(param_1,param_2,lVar10);
        }
        FUN_00139164(param_1,param_2,*(undefined8 *)(param_3[2] + 0x10));
      }
      if (((*(int *)param_3[1] == 0x31) &&
          (lVar10 = *(long *)((int *)param_3[1] + 2), *(int *)(lVar10 + 0x10) == 1)) &&
         (**(char **)(lVar10 + 8) == '>')) {
        FUN_0012c3cc(param_1,0x29);
      }
    }
    break;
  case 0x38:
    *(undefined4 *)(param_1 + 0x130) = 1;
    break;
  case 0x39:
    piVar9 = (int *)param_3[2];
    if ((*piVar9 != 0x3a) || (piVar23 = *(int **)(piVar9 + 4), *piVar23 != 0x3b)) goto LAB_001345f4;
    lVar12 = param_3[1];
    lVar10 = *(long *)(piVar9 + 2);
    uVar38 = *(undefined8 *)(piVar23 + 2);
    lVar18 = *(long *)(piVar23 + 4);
    iVar6 = strcmp(**(char ***)(lVar12 + 8),"qu");
    if (iVar6 == 0) {
      FUN_00139164(param_1,param_2);
      FUN_00139090(param_1,param_2,lVar12);
      FUN_00139164(param_1,param_2,uVar38);
      FUN_0012c6d0(param_1,&DAT_00142008);
      FUN_00139164(param_1,param_2,lVar18);
    }
    else {
      FUN_0012c6d0(param_1,&DAT_00142010);
      if (*(long *)(lVar10 + 8) != 0) {
        FUN_00139164(param_1,param_2);
        FUN_0012c3cc(param_1,0x20);
      }
      FUN_00134578(param_1,param_2,uVar38);
      if (lVar18 != 0) {
        FUN_00139164(param_1,param_2,lVar18);
      }
    }
    break;
  case 0x3a:
  case 0x3b:
    *(undefined4 *)(param_1 + 0x130) = 1;
    break;
  case 0x3c:
  case 0x3d:
    uVar36 = 0;
    if ((*(int *)param_3[1] == 0x27) &&
       (uVar36 = *(uint *)(*(long *)((int *)param_3[1] + 2) + 0x1c), uVar36 != 0)) {
      if (uVar36 < 7) {
        if (*(int *)param_3[2] == 0) {
          if (iVar6 == 0x3d) {
            FUN_0012c3cc(param_1,0x2d);
          }
          FUN_00134578(param_1,param_2,param_3[2]);
          switch(uVar36) {
          case 2:
            FUN_0012c3cc(param_1,0x75);
            return;
          case 3:
            FUN_0012c3cc(param_1,0x6c);
            return;
          case 4:
            FUN_0012c6d0(param_1,&DAT_00142018);
            return;
          case 5:
            FUN_0012c6d0(param_1,&DAT_00142020);
            return;
          case 6:
            FUN_0012c6d0(param_1,"ull");
            return;
          default:
            return;
          }
        }
      }
      else if ((((uVar36 == 7) && (piVar9 = (int *)param_3[2], *piVar9 == 0)) && (piVar9[4] == 1))
              && (iVar6 == 0x3c)) {
        if (**(char **)(piVar9 + 2) == '0') {
          FUN_0012c6d0(param_1,"false");
          return;
        }
        if (**(char **)(piVar9 + 2) == '1') {
          FUN_0012c6d0(param_1,&DAT_00142030);
          return;
        }
      }
    }
    lVar10 = *(long *)(param_1 + 0x100);
    if (lVar10 == 0xff) {
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar18 = 1;
      lVar10 = 0;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    }
    else {
      lVar18 = lVar10 + 1;
    }
    *(long *)(param_1 + 0x100) = lVar18;
    param_1[lVar10] = 0x28;
    param_1[0x108] = 0x28;
    FUN_00134578(param_1,param_2,param_3[1]);
    lVar10 = *(long *)(param_1 + 0x100);
    if (lVar10 == 0xff) {
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar18 = 1;
      lVar10 = 0;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    }
    else {
      lVar18 = lVar10 + 1;
    }
    *(long *)(param_1 + 0x100) = lVar18;
    param_1[lVar10] = 0x29;
    param_1[0x108] = 0x29;
    if (*(int *)param_3 == 0x3d) {
      FUN_0012c3cc(param_1,0x2d);
    }
    if (uVar36 == 8) {
      FUN_0012c3cc(param_1,0x5b);
      FUN_00134578(param_1,param_2,param_3[2]);
      FUN_0012c3cc(param_1,0x5d);
    }
    else {
      FUN_00134578(param_1,param_2,param_3[2]);
    }
    break;
  case 0x3e:
    pcVar11 = "java resource ";
    lVar10 = *(long *)(param_1 + 0x100);
    do {
      cVar4 = *pcVar11;
      if (lVar10 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar18 = 1;
        lVar10 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
      else {
        lVar18 = lVar10 + 1;
      }
      *(long *)(param_1 + 0x100) = lVar18;
      pcVar11 = pcVar11 + 1;
      param_1[lVar10] = cVar4;
      param_1[0x108] = cVar4;
      lVar10 = lVar18;
    } while (pcVar11 != "");
    FUN_00134578(param_1,param_2,param_3[1]);
    break;
  case 0x3f:
    FUN_00134578(param_1,param_2,param_3[1]);
    FUN_00134578(param_1,param_2,param_3[2]);
    break;
  case 0x40:
    lVar10 = *(long *)(param_1 + 0x100);
    uVar3 = *(undefined *)(param_3 + 1);
    if (lVar10 == 0xff) {
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar18 = 1;
      lVar10 = 0;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    }
    else {
      lVar18 = lVar10 + 1;
    }
    *(long *)(param_1 + 0x100) = lVar18;
    param_1[lVar10] = uVar3;
    param_1[0x108] = uVar3;
    break;
  case 0x41:
    sprintf((char *)&local_80,"%ld",param_3[1]);
    sVar33 = strlen((char *)&local_80);
    if (sVar33 != 0) {
      sVar13 = 0;
      lVar10 = *(long *)(param_1 + 0x100);
      do {
        cVar4 = *(char *)((long)&local_80 + sVar13);
        if (lVar10 == 0xff) {
          param_1[0xff] = 0;
          (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
          lVar18 = 1;
          lVar10 = 0;
          *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        }
        else {
          lVar18 = lVar10 + 1;
        }
        *(long *)(param_1 + 0x100) = lVar18;
        sVar13 = sVar13 + 1;
        param_1[lVar10] = cVar4;
        param_1[0x108] = cVar4;
        lVar10 = lVar18;
      } while (sVar13 != sVar33);
    }
    break;
  case 0x42:
    pcVar11 = "decltype (";
    lVar10 = *(long *)(param_1 + 0x100);
    do {
      cVar4 = *pcVar11;
      if (lVar10 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar18 = 1;
        lVar10 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
      else {
        lVar18 = lVar10 + 1;
      }
      *(long *)(param_1 + 0x100) = lVar18;
      pcVar11 = pcVar11 + 1;
      param_1[lVar10] = cVar4;
      param_1[0x108] = cVar4;
      lVar10 = lVar18;
    } while (pcVar11 != "");
    FUN_00134578(param_1,param_2,param_3[1]);
    lVar10 = *(long *)(param_1 + 0x100);
    if (lVar10 == 0xff) {
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar18 = 1;
      lVar10 = 0;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    }
    else {
      lVar18 = lVar10 + 1;
    }
    *(long *)(param_1 + 0x100) = lVar18;
    param_1[lVar10] = 0x29;
    param_1[0x108] = 0x29;
    break;
  case 0x43:
    lVar10 = 0;
    lVar18 = *(long *)(param_1 + 0x100);
    do {
      cVar4 = "global constructors keyed to "[lVar10];
      if (lVar18 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar12 = 1;
        lVar18 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
      else {
        lVar12 = lVar18 + 1;
      }
      *(long *)(param_1 + 0x100) = lVar12;
      lVar10 = lVar10 + 1;
      param_1[lVar18] = cVar4;
      param_1[0x108] = cVar4;
      lVar18 = lVar12;
    } while (lVar10 != 0x1d);
    FUN_00134578(param_1,param_2,param_3[1]);
    break;
  case 0x44:
    lVar10 = 0;
    lVar18 = *(long *)(param_1 + 0x100);
    do {
      cVar4 = "global destructors keyed to "[lVar10];
      if (lVar18 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar12 = 1;
        lVar18 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
      else {
        lVar12 = lVar18 + 1;
      }
      *(long *)(param_1 + 0x100) = lVar12;
      lVar10 = lVar10 + 1;
      param_1[lVar18] = cVar4;
      param_1[0x108] = cVar4;
      lVar18 = lVar12;
    } while (lVar10 != 0x1c);
    FUN_00134578(param_1,param_2,param_3[1]);
    break;
  case 0x45:
    pcVar11 = "{lambda(";
    lVar10 = *(long *)(param_1 + 0x100);
    do {
      cVar4 = *pcVar11;
      if (lVar10 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar18 = 1;
        lVar10 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
      else {
        lVar18 = lVar10 + 1;
      }
      *(long *)(param_1 + 0x100) = lVar18;
      pcVar11 = pcVar11 + 1;
      param_1[lVar10] = cVar4;
      param_1[0x108] = cVar4;
      lVar10 = lVar18;
    } while (pcVar11 != "");
    FUN_00134578(param_1,param_2,param_3[1]);
    lVar10 = *(long *)(param_1 + 0x100);
    if (lVar10 == 0xff) {
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar18 = 1;
      *param_1 = 0x29;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
LAB_001362e0:
      lVar10 = lVar18 + 1;
    }
    else {
      lVar18 = lVar10 + 1;
      *(long *)(param_1 + 0x100) = lVar18;
      param_1[lVar10] = 0x29;
      param_1[0x108] = 0x29;
      if (lVar18 != 0xff) goto LAB_001362e0;
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar10 = 1;
      lVar18 = 0;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    }
    *(long *)(param_1 + 0x100) = lVar10;
    param_1[lVar18] = 0x23;
    param_1[0x108] = 0x23;
    sVar33 = 0;
    sprintf((char *)&local_80,"%ld",(long)(*(int *)(param_3 + 2) + 1));
    sVar13 = strlen((char *)&local_80);
    lVar10 = *(long *)(param_1 + 0x100);
    lVar18 = lVar10;
    if (sVar13 != 0) {
      do {
        cVar4 = *(char *)((long)&local_80 + sVar33);
        if (lVar18 == 0xff) {
          param_1[0xff] = 0;
          (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
          lVar10 = 1;
          lVar18 = 0;
          *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        }
        else {
          lVar10 = lVar18 + 1;
        }
        *(long *)(param_1 + 0x100) = lVar10;
        sVar33 = sVar33 + 1;
        param_1[lVar18] = cVar4;
        param_1[0x108] = cVar4;
        lVar18 = lVar10;
      } while (sVar33 != sVar13);
    }
    if (lVar10 == 0xff) {
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar18 = 1;
      lVar10 = 0;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    }
    else {
      lVar18 = lVar10 + 1;
    }
    *(long *)(param_1 + 0x100) = lVar18;
    param_1[lVar10] = 0x7d;
    param_1[0x108] = 0x7d;
    break;
  case 0x47:
    pcVar11 = "{unnamed type#";
    lVar10 = *(long *)(param_1 + 0x100);
    do {
      cVar4 = *pcVar11;
      if (lVar10 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar18 = 1;
        lVar10 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
      else {
        lVar18 = lVar10 + 1;
      }
      *(long *)(param_1 + 0x100) = lVar18;
      pcVar11 = pcVar11 + 1;
      param_1[lVar10] = cVar4;
      param_1[0x108] = cVar4;
      lVar10 = lVar18;
    } while (pcVar11 != "");
    sVar33 = 0;
    sprintf((char *)&local_80,"%ld",param_3[1] + 1);
    sVar13 = strlen((char *)&local_80);
    lVar10 = *(long *)(param_1 + 0x100);
    lVar18 = lVar10;
    if (sVar13 != 0) {
      do {
        cVar4 = *(char *)((long)&local_80 + sVar33);
        if (lVar18 == 0xff) {
          param_1[0xff] = 0;
          (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
          lVar10 = 1;
          lVar18 = 0;
          *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        }
        else {
          lVar10 = lVar18 + 1;
        }
        *(long *)(param_1 + 0x100) = lVar10;
        sVar33 = sVar33 + 1;
        param_1[lVar18] = cVar4;
        param_1[0x108] = cVar4;
        lVar18 = lVar10;
      } while (sVar33 != sVar13);
    }
    if (lVar10 == 0xff) {
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar18 = 1;
      lVar10 = 0;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    }
    else {
      lVar18 = lVar10 + 1;
    }
    *(long *)(param_1 + 0x100) = lVar18;
    param_1[lVar10] = 0x7d;
    param_1[0x108] = 0x7d;
    break;
  case 0x48:
    lVar10 = 0;
    lVar18 = *(long *)(param_1 + 0x100);
    do {
      cVar4 = "transaction clone for "[lVar10];
      if (lVar18 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar12 = 1;
        lVar18 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
      else {
        lVar12 = lVar18 + 1;
      }
      *(long *)(param_1 + 0x100) = lVar12;
      lVar10 = lVar10 + 1;
      param_1[lVar18] = cVar4;
      param_1[0x108] = cVar4;
      lVar18 = lVar12;
    } while (lVar10 != 0x16);
    FUN_00134578(param_1,param_2,param_3[1]);
    break;
  case 0x49:
    lVar10 = 0;
    lVar18 = *(long *)(param_1 + 0x100);
    do {
      cVar4 = "non-transaction clone for "[lVar10];
      if (lVar18 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar12 = 1;
        lVar18 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
      else {
        lVar12 = lVar18 + 1;
      }
      *(long *)(param_1 + 0x100) = lVar12;
      lVar10 = lVar10 + 1;
      param_1[lVar18] = cVar4;
      param_1[0x108] = cVar4;
      lVar18 = lVar12;
    } while (lVar10 != 0x1a);
    FUN_00134578(param_1,param_2,param_3[1]);
    break;
  case 0x4a:
    iVar6 = 0;
    piVar9 = (int *)FUN_0012c548(param_1,param_3[1]);
    if (piVar9 == (int *)0x0) {
      FUN_00139164(param_1,param_2,param_3[1]);
      FUN_0012c6d0(param_1,&DAT_00142058);
    }
    else {
      do {
        if ((*piVar9 != 0x2f) || (*(long *)(piVar9 + 2) == 0)) {
          lVar10 = param_3[1];
          if (iVar6 == 0) {
            return;
          }
          goto LAB_00135588;
        }
        piVar9 = *(int **)(piVar9 + 4);
        iVar6 = iVar6 + 1;
      } while (piVar9 != (int *)0x0);
      lVar10 = param_3[1];
LAB_00135588:
      iVar31 = 0;
      do {
        *(int *)(param_1 + 0x134) = iVar31;
        FUN_00134578(param_1,param_2,lVar10);
        if (iVar31 < iVar6 + -1) {
          lVar18 = *(long *)(param_1 + 0x100);
          if (lVar18 == 0xff) {
            param_1[0xff] = 0;
            (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
            *param_1 = 0x2c;
            lVar12 = 1;
            *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
LAB_001355d8:
            lVar18 = lVar12 + 1;
          }
          else {
            lVar12 = lVar18 + 1;
            *(long *)(param_1 + 0x100) = lVar12;
            param_1[lVar18] = 0x2c;
            param_1[0x108] = 0x2c;
            if (lVar12 != 0xff) goto LAB_001355d8;
            param_1[0xff] = 0;
            (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
            lVar18 = 1;
            lVar12 = 0;
            *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
          }
          *(long *)(param_1 + 0x100) = lVar18;
          param_1[lVar12] = 0x20;
          param_1[0x108] = 0x20;
        }
        iVar31 = iVar31 + 1;
      } while (iVar31 != iVar6);
    }
    break;
  case 0x4b:
    FUN_00134578(param_1,param_2,param_3[1]);
    lVar10 = *(long *)(param_1 + 0x100);
    if (lVar10 == 0xff) {
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      *param_1 = 0x5b;
      lVar10 = 2;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 0x61;
LAB_00135650:
      lVar18 = lVar10 + 1;
      *(long *)(param_1 + 0x100) = lVar18;
      param_1[lVar10] = 0x62;
      param_1[0x108] = 0x62;
      if (lVar18 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x69;
        lVar10 = 1;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        goto LAB_00135688;
      }
LAB_0013566c:
      lVar10 = lVar18 + 1;
      *(long *)(param_1 + 0x100) = lVar10;
      param_1[lVar18] = 0x69;
      param_1[0x108] = 0x69;
      if (lVar10 != 0xff) goto LAB_00135688;
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar18 = 1;
      lVar10 = 0;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    }
    else {
      lVar18 = lVar10 + 1;
      *(long *)(param_1 + 0x100) = lVar18;
      param_1[lVar10] = 0x5b;
      param_1[0x108] = 0x5b;
      if (lVar18 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x61;
        lVar18 = 2;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        param_1[1] = 0x62;
        goto LAB_0013566c;
      }
      lVar10 = lVar10 + 2;
      *(long *)(param_1 + 0x100) = lVar10;
      param_1[lVar18] = 0x61;
      param_1[0x108] = 0x61;
      if (lVar10 != 0xff) goto LAB_00135650;
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      *param_1 = 0x62;
      lVar10 = 2;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 0x69;
LAB_00135688:
      lVar18 = lVar10 + 1;
    }
    *(long *)(param_1 + 0x100) = lVar18;
    param_1[lVar10] = 0x3a;
    param_1[0x108] = 0x3a;
    FUN_00134578(param_1,param_2,param_3[2]);
    lVar10 = *(long *)(param_1 + 0x100);
    if (lVar10 == 0xff) {
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar18 = 1;
      lVar10 = 0;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    }
    else {
      lVar18 = lVar10 + 1;
    }
    *(long *)(param_1 + 0x100) = lVar18;
    param_1[lVar10] = 0x5d;
    param_1[0x108] = 0x5d;
    break;
  case 0x4c:
    pcVar11 = " [clone ";
    FUN_00134578(param_1,param_2,param_3[1]);
    lVar10 = *(long *)(param_1 + 0x100);
    do {
      cVar4 = *pcVar11;
      if (lVar10 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar18 = 1;
        lVar10 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
      else {
        lVar18 = lVar10 + 1;
      }
      *(long *)(param_1 + 0x100) = lVar18;
      pcVar11 = pcVar11 + 1;
      param_1[lVar10] = cVar4;
      param_1[0x108] = cVar4;
      lVar10 = lVar18;
    } while (pcVar11 != "");
    FUN_00134578(param_1,param_2,param_3[2]);
    lVar10 = *(long *)(param_1 + 0x100);
    if (lVar10 == 0xff) {
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar18 = 1;
      lVar10 = 0;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    }
    else {
      lVar18 = lVar10 + 1;
    }
    *(long *)(param_1 + 0x100) = lVar18;
    param_1[lVar10] = 0x5d;
    param_1[0x108] = 0x5d;
  }
  return;
}



void FUN_00137f84(undefined *param_1,uint param_2,undefined4 *param_3)

{
  char cVar1;
  long lVar2;
  long lVar3;
  long lVar4;
  undefined uVar5;
  char *pcVar6;
  
  switch(*param_3) {
  case 3:
    param_3 = *(undefined4 **)(param_3 + 2);
  default:
LAB_00137fc0:
    FUN_00134578(param_1,param_2,param_3);
    return;
  case 0x19:
  case 0x1c:
    lVar2 = 0;
    lVar3 = *(long *)(param_1 + 0x100);
    do {
      cVar1 = " restrict"[lVar2];
      if (lVar3 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar4 = 1;
        lVar3 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
      else {
        lVar4 = lVar3 + 1;
      }
      *(long *)(param_1 + 0x100) = lVar4;
      lVar2 = lVar2 + 1;
      param_1[lVar3] = cVar1;
      param_1[0x108] = cVar1;
      lVar3 = lVar4;
    } while (lVar2 != 9);
    break;
  case 0x1a:
  case 0x1d:
    lVar2 = 0;
    lVar3 = *(long *)(param_1 + 0x100);
    do {
      cVar1 = " volatile"[lVar2];
      if (lVar3 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar4 = 1;
        lVar3 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
      else {
        lVar4 = lVar3 + 1;
      }
      *(long *)(param_1 + 0x100) = lVar4;
      lVar2 = lVar2 + 1;
      param_1[lVar3] = cVar1;
      param_1[0x108] = cVar1;
      lVar3 = lVar4;
    } while (lVar2 != 9);
    break;
  case 0x1b:
  case 0x1e:
    lVar2 = *(long *)(param_1 + 0x100);
    if (lVar2 == 0xff) {
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      *param_1 = 0x20;
      lVar2 = 2;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 99;
LAB_0013818c:
      lVar3 = lVar2 + 1;
      *(long *)(param_1 + 0x100) = lVar3;
      param_1[lVar2] = 0x6f;
      param_1[0x108] = 0x6f;
      if (lVar3 == 0xff) {
        param_1[0xff] = 0;
        uVar5 = 0x74;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x6e;
        lVar3 = 2;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        param_1[1] = 0x73;
      }
      else {
LAB_001381a8:
        lVar2 = lVar3 + 1;
        *(long *)(param_1 + 0x100) = lVar2;
        param_1[lVar3] = 0x6e;
        param_1[0x108] = 0x6e;
        if (lVar2 != 0xff) goto LAB_001381c4;
        uVar5 = 0x74;
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x73;
        lVar3 = 1;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
      goto LAB_001382a8;
    }
    lVar3 = lVar2 + 1;
    *(long *)(param_1 + 0x100) = lVar3;
    param_1[lVar2] = 0x20;
    param_1[0x108] = 0x20;
    if (lVar3 == 0xff) {
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      *param_1 = 99;
      lVar3 = 2;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 0x6f;
      goto LAB_001381a8;
    }
    lVar2 = lVar2 + 2;
    *(long *)(param_1 + 0x100) = lVar2;
    param_1[lVar3] = 99;
    param_1[0x108] = 99;
    if (lVar2 != 0xff) goto LAB_0013818c;
    param_1[0xff] = 0;
    (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
    *param_1 = 0x6f;
    lVar2 = 2;
    *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    param_1[1] = 0x6e;
LAB_001381c4:
    lVar3 = lVar2 + 1;
    *(long *)(param_1 + 0x100) = lVar3;
    param_1[lVar2] = 0x73;
    param_1[0x108] = 0x73;
    uVar5 = 0x74;
    if (lVar3 != 0xff) goto LAB_001382a8;
    goto LAB_001381e0;
  case 0x1f:
    lVar3 = *(long *)(param_1 + 0x100);
    if (lVar3 == 0xff) {
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar2 = 1;
      lVar3 = 0;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    }
    else {
      lVar2 = lVar3 + 1;
    }
    *(long *)(param_1 + 0x100) = lVar2;
    param_1[lVar3] = 0x20;
    param_1[0x108] = 0x20;
    goto LAB_00138230;
  case 0x20:
    lVar3 = *(long *)(param_1 + 0x100);
    if (lVar3 == 0xff) {
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar2 = 1;
      lVar3 = 0;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    }
    else {
      lVar2 = lVar3 + 1;
    }
    *(long *)(param_1 + 0x100) = lVar2;
    param_1[lVar3] = 0x20;
    param_1[0x108] = 0x20;
    goto LAB_00138280;
  case 0x21:
    lVar2 = *(long *)(param_1 + 0x100);
    if (lVar2 == 0xff) {
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar3 = 1;
      lVar2 = 0;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    }
    else {
      lVar3 = lVar2 + 1;
    }
    *(long *)(param_1 + 0x100) = lVar3;
    param_1[lVar2] = 0x20;
    param_1[0x108] = 0x20;
    param_3 = *(undefined4 **)(param_3 + 4);
    goto LAB_00137fc0;
  case 0x22:
    if ((param_2 >> 2 & 1) == 0) {
      lVar2 = *(long *)(param_1 + 0x100);
      if (lVar2 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar3 = 1;
        lVar2 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
      else {
        lVar3 = lVar2 + 1;
      }
      *(long *)(param_1 + 0x100) = lVar3;
      param_1[lVar2] = 0x2a;
      param_1[0x108] = 0x2a;
    }
    break;
  case 0x23:
    lVar2 = *(long *)(param_1 + 0x100);
LAB_00138230:
    if (lVar2 == 0xff) {
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar3 = 1;
      lVar2 = 0;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    }
    else {
      lVar3 = lVar2 + 1;
    }
    *(long *)(param_1 + 0x100) = lVar3;
    param_1[lVar2] = 0x26;
    param_1[0x108] = 0x26;
    break;
  case 0x24:
    lVar2 = *(long *)(param_1 + 0x100);
LAB_00138280:
    if (lVar2 == 0xff) {
      uVar5 = 0x26;
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar3 = 1;
      *param_1 = 0x26;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    }
    else {
      lVar3 = lVar2 + 1;
      *(long *)(param_1 + 0x100) = lVar3;
      param_1[lVar2] = 0x26;
      param_1[0x108] = 0x26;
      uVar5 = 0x26;
      if (lVar3 == 0xff) {
LAB_001381e0:
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,lVar3,*(undefined8 *)(param_1 + 0x118));
        lVar2 = 1;
        lVar3 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        goto LAB_001382ac;
      }
    }
LAB_001382a8:
    lVar2 = lVar3 + 1;
LAB_001382ac:
    *(long *)(param_1 + 0x100) = lVar2;
    param_1[lVar3] = uVar5;
    param_1[0x108] = uVar5;
    return;
  case 0x25:
    pcVar6 = "complex ";
    lVar2 = *(long *)(param_1 + 0x100);
    do {
      cVar1 = *pcVar6;
      if (lVar2 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar3 = 1;
        lVar2 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
      else {
        lVar3 = lVar2 + 1;
      }
      *(long *)(param_1 + 0x100) = lVar3;
      pcVar6 = pcVar6 + 1;
      param_1[lVar2] = cVar1;
      param_1[0x108] = cVar1;
      lVar2 = lVar3;
    } while (pcVar6 != "");
    break;
  case 0x26:
    pcVar6 = "imaginary ";
    lVar2 = *(long *)(param_1 + 0x100);
    do {
      cVar1 = *pcVar6;
      if (lVar2 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar3 = 1;
        lVar2 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
      else {
        lVar3 = lVar2 + 1;
      }
      *(long *)(param_1 + 0x100) = lVar3;
      pcVar6 = pcVar6 + 1;
      param_1[lVar2] = cVar1;
      param_1[0x108] = cVar1;
      lVar2 = lVar3;
    } while (pcVar6 != "");
    break;
  case 0x2b:
    if (param_1[0x108] != '(') {
      lVar2 = *(long *)(param_1 + 0x100);
      if (lVar2 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar3 = 1;
        lVar2 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
      else {
        lVar3 = lVar2 + 1;
      }
      *(long *)(param_1 + 0x100) = lVar3;
      param_1[lVar2] = 0x20;
      param_1[0x108] = 0x20;
    }
    FUN_00134578(param_1,param_2,*(undefined8 *)(param_3 + 2));
    lVar2 = *(long *)(param_1 + 0x100);
    if (lVar2 == 0xff) {
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar2 = 2;
      *param_1 = 0x3a;
      param_1[1] = 0x3a;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
LAB_00138494:
      lVar3 = lVar2 + 1;
    }
    else {
      lVar3 = lVar2 + 1;
      *(long *)(param_1 + 0x100) = lVar3;
      param_1[lVar2] = 0x3a;
      param_1[0x108] = 0x3a;
      if (lVar3 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x3a;
        lVar2 = 1;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        goto LAB_00138494;
      }
      lVar2 = lVar2 + 2;
      *(long *)(param_1 + 0x100) = lVar2;
      param_1[lVar3] = 0x3a;
      param_1[0x108] = 0x3a;
      if (lVar2 != 0xff) goto LAB_00138494;
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar3 = 1;
      lVar2 = 0;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    }
    *(long *)(param_1 + 0x100) = lVar3;
    param_1[lVar2] = 0x2a;
    param_1[0x108] = 0x2a;
    break;
  case 0x2d:
    pcVar6 = " __vector(";
    lVar2 = *(long *)(param_1 + 0x100);
    do {
      cVar1 = *pcVar6;
      if (lVar2 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar3 = 1;
        lVar2 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
      else {
        lVar3 = lVar2 + 1;
      }
      *(long *)(param_1 + 0x100) = lVar3;
      pcVar6 = pcVar6 + 1;
      param_1[lVar2] = cVar1;
      param_1[0x108] = cVar1;
      lVar2 = lVar3;
    } while (pcVar6 != "");
    FUN_00134578(param_1,param_2,*(undefined8 *)(param_3 + 2));
    lVar2 = *(long *)(param_1 + 0x100);
    if (lVar2 == 0xff) {
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar3 = 1;
      lVar2 = 0;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    }
    else {
      lVar3 = lVar2 + 1;
    }
    *(long *)(param_1 + 0x100) = lVar3;
    param_1[lVar2] = 0x29;
    param_1[0x108] = 0x29;
  }
  return;
}



void FUN_00138804(undefined *param_1,uint param_2,undefined8 *param_3,int param_4)

{
  char cVar1;
  int iVar2;
  long lVar3;
  long lVar4;
  int *piVar5;
  undefined8 uVar6;
  char *pcVar7;
  undefined8 uVar8;
  
  if (param_3 != (undefined8 *)0x0) {
    iVar2 = *(int *)(param_1 + 0x130);
    while (iVar2 == 0) {
      if (*(int *)(param_3 + 2) == 0) {
        piVar5 = (int *)param_3[1];
        iVar2 = *piVar5;
        if ((param_4 != 0) || (4 < iVar2 - 0x1cU)) {
          *(undefined4 *)(param_3 + 2) = 1;
          uVar8 = *(undefined8 *)(param_1 + 0x120);
          *(undefined8 *)(param_1 + 0x120) = param_3[3];
          if (iVar2 == 0x29) {
            FUN_00138de0(param_1,param_2,piVar5 + 4,*param_3);
            *(undefined8 *)(param_1 + 0x120) = uVar8;
            return;
          }
          if (iVar2 == 0x2a) {
            FUN_00138b18(param_1,param_2,piVar5 + 2,*param_3);
            *(undefined8 *)(param_1 + 0x120) = uVar8;
            return;
          }
          if (iVar2 == 2) {
            uVar6 = *(undefined8 *)(param_1 + 0x128);
            *(undefined8 *)(param_1 + 0x128) = 0;
            FUN_00134578(param_1,param_2,*(undefined8 *)(piVar5 + 2));
            *(undefined8 *)(param_1 + 0x128) = uVar6;
            lVar3 = *(long *)(param_1 + 0x100);
            if ((param_2 >> 2 & 1) != 0) {
              if (lVar3 == 0xff) {
                param_1[0xff] = 0;
                (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
                lVar4 = 1;
                lVar3 = 0;
                *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
              }
              else {
                lVar4 = lVar3 + 1;
              }
              *(long *)(param_1 + 0x100) = lVar4;
              param_1[lVar3] = 0x2e;
              param_1[0x108] = 0x2e;
              goto LAB_00138998;
            }
            if (lVar3 == 0xff) {
              param_1[0xff] = 0;
              (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
              lVar4 = 1;
              *param_1 = 0x3a;
              *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
LAB_0013896c:
              lVar3 = lVar4 + 1;
            }
            else {
              lVar4 = lVar3 + 1;
              *(long *)(param_1 + 0x100) = lVar4;
              param_1[lVar3] = 0x3a;
              param_1[0x108] = 0x3a;
              if (lVar4 != 0xff) goto LAB_0013896c;
              param_1[0xff] = 0;
              (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
              lVar3 = 1;
              lVar4 = 0;
              *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
            }
            *(long *)(param_1 + 0x100) = lVar3;
            param_1[lVar4] = 0x3a;
            param_1[0x108] = 0x3a;
LAB_00138998:
            piVar5 = *(int **)(param_3[1] + 0x10);
            iVar2 = *piVar5;
            if (iVar2 != 0x46) goto LAB_001389b8;
            pcVar7 = "{default arg#";
            lVar3 = *(long *)(param_1 + 0x100);
            do {
              cVar1 = *pcVar7;
              if (lVar3 == 0xff) {
                param_1[0xff] = 0;
                (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
                lVar4 = 1;
                lVar3 = 0;
                *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
              }
              else {
                lVar4 = lVar3 + 1;
              }
              *(long *)(param_1 + 0x100) = lVar4;
              pcVar7 = pcVar7 + 1;
              param_1[lVar3] = cVar1;
              param_1[0x108] = cVar1;
              lVar3 = lVar4;
            } while (pcVar7 != "");
            FUN_0012c8d8(param_1,(long)(piVar5[4] + 1));
            FUN_0012c6d0(param_1,&DAT_00141e20);
            do {
              piVar5 = *(int **)(piVar5 + 2);
              iVar2 = *piVar5;
LAB_001389b8:
            } while (iVar2 - 0x1cU < 5);
            FUN_00134578(param_1,param_2,piVar5);
            *(undefined8 *)(param_1 + 0x120) = uVar8;
            return;
          }
          FUN_00137f84(param_1,param_2);
          *(undefined8 *)(param_1 + 0x120) = uVar8;
        }
      }
      param_3 = (undefined8 *)*param_3;
      if (param_3 == (undefined8 *)0x0) {
        return;
      }
      iVar2 = *(int *)(param_1 + 0x130);
    }
  }
  return;
}



void FUN_00138b18(undefined *param_1,undefined4 param_2,long *param_3,long *param_4)

{
  long *plVar1;
  long lVar2;
  long lVar3;
  
  plVar1 = param_4;
  if (param_4 != (long *)0x0) {
    do {
      if (*(int *)(plVar1 + 2) == 0) {
        if (*(int *)plVar1[1] == 0x2a) {
          FUN_00138804(param_1,param_2,param_4,0);
          lVar3 = *(long *)(param_1 + 0x100);
          goto joined_r0x00138c80;
        }
        lVar3 = *(long *)(param_1 + 0x100);
        if (lVar3 == 0xff) {
          param_1[0xff] = 0;
          (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
          lVar2 = 1;
          *param_1 = 0x20;
          *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
LAB_00138c1c:
          lVar3 = lVar2 + 1;
        }
        else {
          lVar2 = lVar3 + 1;
          *(long *)(param_1 + 0x100) = lVar2;
          param_1[lVar3] = 0x20;
          param_1[0x108] = 0x20;
          if (lVar2 != 0xff) goto LAB_00138c1c;
          param_1[0xff] = 0;
          (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
          lVar3 = 1;
          lVar2 = 0;
          *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        }
        *(long *)(param_1 + 0x100) = lVar3;
        param_1[lVar2] = 0x28;
        param_1[0x108] = 0x28;
        FUN_00138804(param_1,param_2,param_4,0);
        lVar3 = *(long *)(param_1 + 0x100);
        lVar2 = lVar3 + 1;
        if (lVar3 == 0xff) {
          param_1[0xff] = 0;
          (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
          lVar2 = 1;
          lVar3 = 0;
          *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        }
        *(long *)(param_1 + 0x100) = lVar2;
        param_1[lVar3] = 0x29;
        param_1[0x108] = 0x29;
        goto LAB_00138b64;
      }
      plVar1 = (long *)*plVar1;
    } while (plVar1 != (long *)0x0);
    FUN_00138804(param_1,param_2,param_4,0);
  }
  lVar2 = *(long *)(param_1 + 0x100);
LAB_00138b64:
  if (lVar2 == 0xff) {
    param_1[0xff] = 0;
    (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
    lVar3 = 1;
    lVar2 = 0;
    *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
  }
  else {
    lVar3 = lVar2 + 1;
  }
  *(long *)(param_1 + 0x100) = lVar3;
  param_1[lVar2] = 0x20;
  param_1[0x108] = 0x20;
joined_r0x00138c80:
  if (lVar3 == 0xff) {
    param_1[0xff] = 0;
    (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
    *param_1 = 0x5b;
    param_1[0x108] = 0x5b;
    lVar2 = 1;
    lVar3 = *param_3;
    *(undefined8 *)(param_1 + 0x100) = 1;
    *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    if (lVar3 == 0) goto LAB_00138bbc;
LAB_00138ba4:
    FUN_00134578(param_1,param_2);
    lVar2 = *(long *)(param_1 + 0x100);
  }
  else {
    lVar2 = lVar3 + 1;
    *(long *)(param_1 + 0x100) = lVar2;
    param_1[lVar3] = 0x5b;
    param_1[0x108] = 0x5b;
    if (*param_3 != 0) goto LAB_00138ba4;
  }
  if (lVar2 == 0xff) {
    param_1[0xff] = 0;
    (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
    *(undefined8 *)(param_1 + 0x100) = 1;
    *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    *param_1 = 0x5d;
    param_1[0x108] = 0x5d;
    return;
  }
LAB_00138bbc:
  *(long *)(param_1 + 0x100) = lVar2 + 1;
  param_1[lVar2] = 0x5d;
  param_1[0x108] = 0x5d;
  return;
}



void FUN_00138de0(undefined *param_1,undefined4 param_2,long *param_3,long *param_4)

{
  int iVar1;
  byte bVar2;
  long *plVar3;
  long lVar4;
  long lVar5;
  undefined8 uVar6;
  
  if (param_4 != (long *)0x0) {
    iVar1 = *(int *)(param_4 + 2);
    plVar3 = param_4;
joined_r0x00138e0c:
    if (iVar1 == 0) {
      switch(*(undefined4 *)plVar3[1]) {
      case 0x19:
      case 0x1a:
      case 0x1b:
      case 0x21:
      case 0x25:
      case 0x26:
      case 0x2b:
        bVar2 = param_1[0x108];
LAB_00138ef0:
        if (bVar2 == 0x20) goto LAB_00138f5c;
        lVar5 = *(long *)(param_1 + 0x100);
        if (lVar5 == 0xff) {
          param_1[0xff] = 0;
          (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
          lVar4 = 1;
          lVar5 = 0;
          *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        }
        else {
          lVar4 = lVar5 + 1;
        }
        *(long *)(param_1 + 0x100) = lVar4;
        param_1[lVar5] = 0x20;
        param_1[0x108] = 0x20;
        if (lVar4 != 0xff) goto LAB_00138f68;
LAB_00138f20:
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,lVar4,*(undefined8 *)(param_1 + 0x118));
        lVar5 = 1;
        lVar4 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        break;
      default:
        plVar3 = (long *)*plVar3;
        if (plVar3 != (long *)0x0) goto code_r0x00138e48;
        goto LAB_00138e50;
      case 0x22:
      case 0x23:
      case 0x24:
        bVar2 = param_1[0x108];
        if ((bVar2 & 0xfd) != 0x28) goto LAB_00138ef0;
LAB_00138f5c:
        lVar4 = *(long *)(param_1 + 0x100);
        if (lVar4 == 0xff) goto LAB_00138f20;
LAB_00138f68:
        lVar5 = lVar4 + 1;
      }
      *(long *)(param_1 + 0x100) = lVar5;
      param_1[lVar4] = 0x28;
      param_1[0x108] = 0x28;
      uVar6 = *(undefined8 *)(param_1 + 0x128);
      *(undefined8 *)(param_1 + 0x128) = 0;
      FUN_00138804(param_1,param_2,param_4,0);
      lVar4 = *(long *)(param_1 + 0x100);
      if (lVar4 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar5 = 1;
        lVar4 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
      else {
        lVar5 = lVar4 + 1;
      }
      *(long *)(param_1 + 0x100) = lVar5;
      param_1[lVar4] = 0x29;
      param_1[0x108] = 0x29;
      goto joined_r0x00138e74;
    }
  }
LAB_00138e50:
  uVar6 = *(undefined8 *)(param_1 + 0x128);
  *(undefined8 *)(param_1 + 0x128) = 0;
  FUN_00138804(param_1,param_2,param_4,0);
  lVar5 = *(long *)(param_1 + 0x100);
joined_r0x00138e74:
  if (lVar5 == 0xff) {
    param_1[0xff] = 0;
    (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
    *param_1 = 0x28;
    param_1[0x108] = 0x28;
    lVar4 = 1;
    lVar5 = *param_3;
    *(undefined8 *)(param_1 + 0x100) = 1;
    *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    if (lVar5 != 0) goto LAB_00138e94;
  }
  else {
    lVar4 = lVar5 + 1;
    *(long *)(param_1 + 0x100) = lVar4;
    param_1[lVar5] = 0x28;
    param_1[0x108] = 0x28;
    if (*param_3 != 0) {
LAB_00138e94:
      FUN_00134578(param_1,param_2);
      lVar4 = *(long *)(param_1 + 0x100);
    }
    if (lVar4 == 0xff) {
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar5 = 1;
      lVar4 = 0;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      goto LAB_00138eb0;
    }
  }
  lVar5 = lVar4 + 1;
LAB_00138eb0:
  *(long *)(param_1 + 0x100) = lVar5;
  param_1[lVar4] = 0x29;
  param_1[0x108] = 0x29;
  FUN_00138804(param_1,param_2,param_4,1);
  *(undefined8 *)(param_1 + 0x128) = uVar6;
  return;
code_r0x00138e48:
  iVar1 = *(int *)(plVar3 + 2);
  goto joined_r0x00138e0c;
}



void FUN_00139090(undefined *param_1,undefined8 param_2,int *param_3)

{
  undefined uVar1;
  long lVar2;
  long lVar3;
  long lVar4;
  long lVar5;
  
  if (*param_3 != 0x31) {
    FUN_00134578();
    return;
  }
  lVar4 = (long)*(int *)(*(long *)(param_3 + 2) + 0x10);
  lVar5 = *(long *)(*(long *)(param_3 + 2) + 8);
  if (lVar4 != 0) {
    lVar3 = 0;
    lVar2 = *(long *)(param_1 + 0x100);
    do {
      while (uVar1 = *(undefined *)(lVar5 + lVar3), lVar2 == 0xff) {
        lVar3 = lVar3 + 1;
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *(undefined8 *)(param_1 + 0x100) = 1;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        *param_1 = uVar1;
        param_1[0x108] = uVar1;
        lVar2 = 1;
        if (lVar4 == lVar3) {
          return;
        }
      }
      *(long *)(param_1 + 0x100) = lVar2 + 1;
      lVar3 = lVar3 + 1;
      param_1[lVar2] = uVar1;
      param_1[0x108] = uVar1;
      lVar2 = lVar2 + 1;
    } while (lVar4 != lVar3);
  }
  return;
}



void FUN_00139164(long param_1,undefined4 param_2,uint *param_3)

{
  uint uVar1;
  long lVar2;
  long lVar3;
  
  uVar1 = *param_3;
  if ((uVar1 != 0x30 && 1 < uVar1) && (uVar1 != 6)) {
    lVar3 = *(long *)(param_1 + 0x100);
    if (lVar3 == 0xff) {
      *(undefined *)(param_1 + 0xff) = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar2 = 1;
      lVar3 = 0;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    }
    else {
      lVar2 = lVar3 + 1;
    }
    *(long *)(param_1 + 0x100) = lVar2;
    *(undefined *)(param_1 + lVar3) = 0x28;
    *(undefined *)(param_1 + 0x108) = 0x28;
    FUN_00134578(param_1,param_2,param_3);
    lVar3 = *(long *)(param_1 + 0x100);
    if (lVar3 == 0xff) {
      *(undefined *)(param_1 + 0xff) = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar2 = 1;
      lVar3 = 0;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    }
    else {
      lVar2 = lVar3 + 1;
    }
    *(long *)(param_1 + 0x100) = lVar2;
    *(undefined *)(param_1 + lVar3) = 0x29;
    *(undefined *)(param_1 + 0x108) = 0x29;
    return;
  }
  FUN_00134578(param_1);
  return;
}



bool FUN_0013926c(char *param_1,code *param_2,undefined8 param_3)

{
  char *pcVar1;
  char cVar2;
  long lVar3;
  long lVar4;
  long lVar5;
  code *pcVar6;
  char cVar7;
  int iVar8;
  int iVar9;
  size_t sVar10;
  undefined8 uVar11;
  long lVar12;
  undefined4 uVar13;
  char *pcVar14;
  undefined auStack_230 [16];
  char *local_1c8;
  char *local_1c0;
  uint local_1b8;
  char *local_1b0;
  undefined *local_1a8;
  undefined4 local_1a0;
  int local_19c;
  undefined *local_198;
  undefined4 local_190;
  int local_18c;
  undefined4 local_188;
  undefined8 local_180;
  undefined4 local_178;
  undefined4 local_174;
  undefined4 local_170;
  undefined auStack_168 [256];
  long local_68;
  undefined local_60;
  code *local_58;
  undefined8 local_50;
  undefined8 local_48;
  undefined8 local_40;
  int local_38;
  undefined4 local_34;
  undefined8 local_30;
  undefined *local_28;
  undefined4 local_20;
  uint local_1c;
  undefined *local_18;
  undefined4 local_10;
  uint local_c;
  undefined8 local_8;
  
  cVar7 = *param_1;
  if ((cVar7 == '_') && (param_1[1] == 'Z')) {
    iVar9 = 1;
  }
  else {
    iVar9 = 0;
    iVar8 = strncmp(param_1,"_GLOBAL_",8);
    if ((iVar8 == 0) && ((cVar2 = param_1[8], cVar2 == '_' || cVar2 == '.' || (cVar2 == '$')))) {
      cVar2 = param_1[9];
      if (((cVar2 == 'I') || (iVar9 = 0, cVar2 == 'D')) &&
         ((iVar9 = 0, param_1[10] == '_' && (iVar9 = 2, cVar2 != 'I')))) {
        iVar9 = 3;
      }
    }
  }
  sVar10 = strlen(param_1);
  local_18c = (int)sVar10;
  local_19c = local_18c << 1;
  local_1c0 = param_1 + sVar10;
  lVar3 = -((long)local_19c * 0x18 + 0x10);
  local_1a8 = &stack0xfffffffffffffde0 + lVar3;
  local_1b8 = 0x11;
  lVar4 = -((-(sVar10 >> 0x1f & 1) & 0xfffffff800000000 | (sVar10 & 0xffffffff) << 3) + 0x16 &
           0xfffffffffffffff0);
  local_198 = &stack0xfffffffffffffde0 + lVar4 + lVar3;
  local_1a0 = 0;
  local_190 = 0;
  local_188 = 0;
  local_180 = 0;
  local_178 = 0;
  local_174 = 0;
  local_170 = 0;
  local_1c8 = param_1;
  if (iVar9 == 1) {
    if (cVar7 != '_') {
      return false;
    }
    if (param_1[1] != 'Z') {
      return false;
    }
    local_1b0 = param_1 + 2;
    lVar12 = FUN_00130e70(&local_1c8,1);
    if ((local_1b8 & 1) == 0) {
LAB_0013968c:
      cVar7 = *local_1b0;
    }
    else {
      while (pcVar1 = local_1b0, cVar7 = *local_1b0, cVar7 == '.') {
        cVar7 = local_1b0[1];
        if (((byte)(cVar7 + 0x9fU) < 0x1a) || (cVar7 == '_')) {
          cVar7 = local_1b0[2];
          pcVar14 = local_1b0 + 2;
          if (0x19 < (byte)(cVar7 + 0x9fU)) goto LAB_00139680;
          do {
            do {
              pcVar14 = pcVar14 + 1;
              cVar7 = *pcVar14;
            } while ((byte)(cVar7 + 0x9fU) < 0x1a);
LAB_00139680:
          } while (cVar7 == '_');
        }
        else {
          if (9 < (byte)(cVar7 - 0x30U)) goto LAB_0013968c;
          cVar7 = *local_1b0;
          pcVar14 = local_1b0;
        }
        while (cVar7 == '.') {
          while( true ) {
            if (9 < (byte)(pcVar14[1] - 0x30U)) goto LAB_00139610;
            cVar7 = pcVar14[2];
            pcVar14 = pcVar14 + 2;
            if (9 < (byte)(cVar7 - 0x30U)) break;
            do {
              pcVar14 = pcVar14 + 1;
            } while ((byte)(*pcVar14 - 0x30U) < 10);
            if (*pcVar14 != '.') goto LAB_00139610;
          }
        }
LAB_00139610:
        iVar8 = (int)local_1b0;
        local_1b0 = pcVar14;
        uVar11 = FUN_0012be30(&local_1c8,pcVar1,(int)pcVar14 - iVar8);
        lVar12 = FUN_0012bd90(&local_1c8,0x4c,lVar12,uVar11);
      }
    }
  }
  else if (iVar9 == 0) {
    local_1b0 = param_1;
    local_1a8 = &stack0xfffffffffffffde0 + lVar3;
    local_198 = &stack0xfffffffffffffde0 + lVar4 + lVar3;
    lVar12 = FUN_0012e994(&local_1c8);
    cVar7 = *local_1b0;
  }
  else {
    pcVar1 = param_1 + 0xb;
    uVar13 = 0x43;
    if (iVar9 != 2) {
      uVar13 = 0x44;
    }
    if ((param_1[0xb] == '_') && (param_1[0xc] == 'Z')) {
      local_1b0 = param_1 + 0xd;
      local_1a8 = &stack0xfffffffffffffde0 + lVar3;
      local_198 = &stack0xfffffffffffffde0 + lVar4 + lVar3;
      uVar11 = FUN_00130e70(&local_1c8,0);
    }
    else {
      local_1b0 = pcVar1;
      local_1a8 = &stack0xfffffffffffffde0 + lVar3;
      local_198 = &stack0xfffffffffffffde0 + lVar4 + lVar3;
      sVar10 = strlen(pcVar1);
      uVar11 = FUN_0012be30(&local_1c8,pcVar1,sVar10);
    }
    lVar12 = FUN_0012bd90(&local_1c8,uVar13,uVar11,0);
    pcVar1 = local_1b0;
    sVar10 = strlen(local_1b0);
    local_1b0 = pcVar1 + sVar10;
    cVar7 = pcVar1[sVar10];
  }
  if ((cVar7 == '\0') && (lVar12 != 0)) {
    local_68 = 0;
    local_60 = 0;
    local_48 = 0;
    local_40 = 0;
    local_34 = 0;
    local_30 = 0;
    local_38 = 0;
    local_28 = (undefined *)0x0;
    local_20 = 0;
    local_1c = 0;
    local_18 = (undefined *)0x0;
    local_10 = 0;
    local_c = 0;
    local_58 = param_2;
    local_50 = param_3;
    FUN_0012c300(&local_c,&local_1c,lVar12);
    local_8 = 0;
    local_c = local_1c * local_c;
    lVar5 = -((-(ulong)(local_1c >> 0x1f) & 0xfffffff000000000 | (ulong)local_1c << 4) + 0x10);
    local_28 = &stack0xfffffffffffffde0 + lVar5 + lVar4 + lVar3;
    local_18 = &stack0xfffffffffffffde0 +
               ((lVar5 + lVar4 + lVar3) -
               ((-(ulong)(local_c >> 0x1f) & 0xfffffff000000000 | (ulong)local_c << 4) + 0x10));
    FUN_00134578(auStack_168,0x11,lVar12);
    uVar11 = local_50;
    pcVar6 = local_58;
    lVar3 = local_68;
    auStack_168[local_68] = 0;
    (*pcVar6)(auStack_168,lVar3,uVar11);
    return local_38 == 0;
  }
  return false;
}



char * __cxa_demangle(long param_1,char *param_2,ulong *param_3,undefined4 *param_4)

{
  int iVar1;
  size_t sVar2;
  char *__src;
  ulong uVar3;
  char *local_20;
  undefined8 local_18;
  ulong local_10;
  int local_8;
  
  if ((param_1 == 0) || ((param_2 != (char *)0x0 && (param_3 == (ulong *)0x0)))) {
    if (param_4 == (undefined4 *)0x0) {
      return (char *)0x0;
    }
    *param_4 = 0xfffffffd;
  }
  else {
    local_20 = (char *)0x0;
    local_18 = 0;
    local_10 = 0;
    local_8 = 0;
    iVar1 = FUN_0013926c(param_1,FUN_0012c5e0,&local_20);
    __src = local_20;
    if (iVar1 == 0) {
      free(local_20);
      if (param_4 == (undefined4 *)0x0) {
        return (char *)0x0;
      }
    }
    else {
      uVar3 = 1;
      if (local_8 == 0) {
        uVar3 = local_10;
      }
      if (local_20 != (char *)0x0) {
        if (param_2 == (char *)0x0) {
          if (param_3 != (ulong *)0x0) {
            *param_3 = uVar3;
          }
        }
        else {
          sVar2 = strlen(local_20);
          if (sVar2 < *param_3) {
            memcpy(param_2,__src,sVar2 + 1);
            free(__src);
            __src = param_2;
          }
          else {
            free(param_2);
            *param_3 = uVar3;
          }
        }
        if (param_4 == (undefined4 *)0x0) {
          return __src;
        }
        *param_4 = 0;
        return __src;
      }
      if (param_4 == (undefined4 *)0x0) {
        return (char *)0x0;
      }
      if (uVar3 == 1) {
        *param_4 = 0xffffffff;
        return (char *)0x0;
      }
    }
    *param_4 = 0xfffffffe;
  }
  return (char *)0x0;
}



undefined4 __gcclibcxx_demangle_callback(long param_1,long param_2)

{
  int iVar1;
  undefined4 uVar2;
  
  if ((param_1 == 0) || (param_2 == 0)) {
    uVar2 = 0xfffffffd;
  }
  else {
    iVar1 = FUN_0013926c();
    uVar2 = 0xfffffffe;
    if (iVar1 != 0) {
      uVar2 = 0;
    }
  }
  return uVar2;
}



// std::__exception_ptr::exception_ptr::_M_safe_bool_dummy()

void std::__exception_ptr::exception_ptr::_M_safe_bool_dummy(void)

{
  return;
}



void FUN_00139840(uint param_1,long param_2)

{
  int iVar1;
  char cVar2;
  bool bVar3;
  int *piVar4;
  long lVar5;
  
  lVar5 = *(long *)(param_2 + -0x50);
  if (1 < param_1) {
                    // WARNING: Subroutine does not return
    __cxxabiv1::__terminate(*(_func_void **)(lVar5 + -0x58));
  }
  __cxa_free_dependent_exception(param_2 + -0x50);
  piVar4 = (int *)(lVar5 + -0x80);
  do {
    iVar1 = *piVar4;
    cVar2 = '\x01';
    bVar3 = (bool)ExclusiveMonitorPass(piVar4,0x10);
    if (bVar3) {
      *piVar4 = iVar1 + -1;
      cVar2 = ExclusiveMonitorsStatus();
    }
  } while (cVar2 != '\0');
  if (iVar1 + -1 == 0) {
    if (*(code **)(lVar5 + -0x68) != (code *)0x0) {
      (**(code **)(lVar5 + -0x68))(lVar5);
    }
    __cxa_free_exception(lVar5);
    return;
  }
  return;
}



// std::__exception_ptr::exception_ptr::exception_ptr()

void __thiscall std::__exception_ptr::exception_ptr::exception_ptr(exception_ptr *this)

{
  *(undefined8 *)this = 0;
  return;
}



// std::__exception_ptr::exception_ptr::exception_ptr(void
// (std::__exception_ptr::exception_ptr::*)())

void __thiscall
std::__exception_ptr::exception_ptr::exception_ptr(exception_ptr *this,_func_void *param_1)

{
  *(undefined8 *)this = 0;
  return;
}



// std::__exception_ptr::exception_ptr::_M_addref()

void __thiscall std::__exception_ptr::exception_ptr::_M_addref(exception_ptr *this)

{
  char cVar1;
  bool bVar2;
  int *piVar3;
  
  if (*(long *)this != 0) {
    piVar3 = (int *)(*(long *)this + -0x80);
    do {
      cVar1 = '\x01';
      bVar2 = (bool)ExclusiveMonitorPass(piVar3,0x10);
      if (bVar2) {
        *piVar3 = *piVar3 + 1;
        cVar1 = ExclusiveMonitorsStatus();
      }
    } while (cVar1 != '\0');
  }
  return;
}



// std::__exception_ptr::exception_ptr::exception_ptr(void*)

void __thiscall
std::__exception_ptr::exception_ptr::exception_ptr(exception_ptr *this,void *param_1)

{
  *(void **)this = param_1;
  _M_addref(this);
  return;
}



// std::__exception_ptr::exception_ptr::exception_ptr(std::__exception_ptr::exception_ptr const&)

void __thiscall
std::__exception_ptr::exception_ptr::exception_ptr(exception_ptr *this,exception_ptr *param_1)

{
  *(undefined8 *)this = *(undefined8 *)param_1;
  _M_addref(this);
  return;
}



// std::__exception_ptr::exception_ptr::_M_release()

void __thiscall std::__exception_ptr::exception_ptr::_M_release(exception_ptr *this)

{
  int iVar1;
  char cVar2;
  bool bVar3;
  long lVar4;
  int *piVar5;
  
  lVar4 = *(long *)this;
  if (lVar4 != 0) {
    piVar5 = (int *)(lVar4 + -0x80);
    do {
      iVar1 = *piVar5;
      cVar2 = '\x01';
      bVar3 = (bool)ExclusiveMonitorPass(piVar5,0x10);
      if (bVar3) {
        *piVar5 = iVar1 + -1;
        cVar2 = ExclusiveMonitorsStatus();
      }
    } while (cVar2 != '\0');
    if (iVar1 + -1 == 0) {
      if (*(code **)(lVar4 + -0x68) != (code *)0x0) {
        (**(code **)(lVar4 + -0x68))(*(undefined8 *)this);
      }
      __cxa_free_exception(*(undefined8 *)this);
      *(undefined8 *)this = 0;
    }
  }
  return;
}



// std::__exception_ptr::exception_ptr::~exception_ptr()

void __thiscall std::__exception_ptr::exception_ptr::~exception_ptr(exception_ptr *this)

{
  int iVar1;
  char cVar2;
  bool bVar3;
  long lVar4;
  int *piVar5;
  
  lVar4 = *(long *)this;
  if (lVar4 != 0) {
    piVar5 = (int *)(lVar4 + -0x80);
    do {
      iVar1 = *piVar5;
      cVar2 = '\x01';
      bVar3 = (bool)ExclusiveMonitorPass(piVar5,0x10);
      if (bVar3) {
        *piVar5 = iVar1 + -1;
        cVar2 = ExclusiveMonitorsStatus();
      }
    } while (cVar2 != '\0');
    if (iVar1 + -1 == 0) {
      if (*(code **)(lVar4 + -0x68) != (code *)0x0) {
        (**(code **)(lVar4 + -0x68))(*(undefined8 *)this);
      }
      __cxa_free_exception(*(undefined8 *)this);
      *(undefined8 *)this = 0;
    }
  }
  return;
}



// std::__exception_ptr::exception_ptr::_M_get() const

undefined8 __thiscall std::__exception_ptr::exception_ptr::_M_get(exception_ptr *this)

{
  return *(undefined8 *)this;
}



// std::__exception_ptr::exception_ptr::swap(std::__exception_ptr::exception_ptr&)

void __thiscall
std::__exception_ptr::exception_ptr::swap(exception_ptr *this,exception_ptr *param_1)

{
  undefined8 uVar1;
  
  uVar1 = *(undefined8 *)this;
  *(undefined8 *)this = *(undefined8 *)param_1;
  *(undefined8 *)param_1 = uVar1;
  return;
}



// std::__exception_ptr::exception_ptr::TEMPNAMEPLACEHOLDERVALUE(std::__exception_ptr::exception_ptr
// const&)

exception_ptr * __thiscall
std::__exception_ptr::exception_ptr::operator=(exception_ptr *this,exception_ptr *param_1)

{
  exception_ptr aeStack_8 [8];
  
  exception_ptr(aeStack_8,param_1);
  swap(aeStack_8,this);
  ~exception_ptr(aeStack_8);
  return this;
}



// std::__exception_ptr::exception_ptr::TEMPNAMEPLACEHOLDERVALUE() const

bool __thiscall std::__exception_ptr::exception_ptr::operator!(exception_ptr *this)

{
  return *(long *)this == 0;
}



// std::__exception_ptr::exception_ptr::operator void (std::__exception_ptr::exception_ptr::*)()()
// const

_func_void * __thiscall
std::__exception_ptr::exception_ptr::operator_cast_to_function_pointer(exception_ptr *this)

{
  if (*(long *)this != 0) {
    return _M_safe_bool_dummy;
  }
  return (_func_void *)0x0;
}



// std::__exception_ptr::exception_ptr::__cxa_exception_type() const

undefined8 __thiscall std::__exception_ptr::exception_ptr::__cxa_exception_type(exception_ptr *this)

{
  return *(undefined8 *)(*(long *)this + -0x70);
}



// std::__exception_ptr::TEMPNAMEPLACEHOLDERVALUE(std::__exception_ptr::exception_ptr const&,
// std::__exception_ptr::exception_ptr const&)

bool std::__exception_ptr::operator==(exception_ptr *param_1,exception_ptr *param_2)

{
  return *(long *)param_1 == *(long *)param_2;
}



// std::__exception_ptr::TEMPNAMEPLACEHOLDERVALUE(std::__exception_ptr::exception_ptr const&,
// std::__exception_ptr::exception_ptr const&)

byte std::__exception_ptr::operator!=(exception_ptr *param_1,exception_ptr *param_2)

{
  byte bVar1;
  
  bVar1 = operator==(param_1,param_2);
  return bVar1 ^ 1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked
// std::current_exception()

void std::current_exception(void)

{
  undefined8 *puVar1;
  void **ppvVar2;
  void **ppvVar3;
  exception_ptr *in_x8;
  
  puVar1 = (undefined8 *)__cxa_get_globals();
  ppvVar3 = (void **)*puVar1;
  if ((ppvVar3 != (void **)0x0) && ((long)ppvVar3[10] + 0xb8b1aabcbcd4d500U < 2)) {
    ppvVar2 = ppvVar3 + 0xe;
    if (((ulong)ppvVar3[10] & 1) != 0) {
      ppvVar2 = (void **)*ppvVar3;
    }
    __exception_ptr::exception_ptr::exception_ptr(in_x8,ppvVar2);
    return;
  }
  __exception_ptr::exception_ptr::exception_ptr(in_x8);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked
// std::rethrow_exception(std::__exception_ptr::exception_ptr)

void std::rethrow_exception(exception_ptr param_1)

{
  char cVar1;
  bool bVar2;
  long lVar3;
  long *plVar4;
  int *piVar5;
  
  lVar3 = __exception_ptr::exception_ptr::_M_get((exception_ptr *)(ulong)(byte)param_1);
  plVar4 = (long *)__cxa_allocate_dependent_exception();
  piVar5 = (int *)(lVar3 + -0x80);
  *plVar4 = lVar3;
  do {
    cVar1 = '\x01';
    bVar2 = (bool)ExclusiveMonitorPass(piVar5,0x10);
    if (bVar2) {
      *piVar5 = *piVar5 + 1;
      cVar1 = ExclusiveMonitorsStatus();
    }
  } while (cVar1 != '\0');
  lVar3 = get_unexpected();
  plVar4[2] = lVar3;
  lVar3 = get_terminate();
  plVar4[3] = lVar3;
  plVar4[10] = 0x474e5543432b2b01;
  plVar4[0xb] = (long)FUN_00139840;
  _Unwind_RaiseException(plVar4 + 10);
  __cxa_begin_catch(plVar4 + 10);
                    // WARNING: Subroutine does not return
  terminate();
}



long __cxa_current_exception_type(void)

{
  long **pplVar1;
  long *plVar2;
  long lVar3;
  
  pplVar1 = (long **)__cxa_get_globals();
  plVar2 = *pplVar1;
  if (plVar2 == (long *)0x0) {
    lVar3 = 0;
  }
  else {
    if ((plVar2[10] & 1U) != 0) {
      plVar2 = (long *)(*plVar2 + -0x70);
    }
    lVar3 = *plVar2;
  }
  return lVar3;
}



// WARNING: Removing unreachable block (ram,0x00139bc8)
// WARNING: Removing unreachable block (ram,0x00139c64)
// WARNING: Removing unreachable block (ram,0x00139c98)
// WARNING: Removing unreachable block (ram,0x00139c6c)

undefined8 __cxa_guard_acquire(uint *param_1)

{
  uint uVar1;
  uint uVar2;
  char cVar3;
  bool bVar4;
  undefined8 uVar5;
  
  __google_potentially_blocking_region_begin();
  if (*(char *)param_1 != '\0') {
LAB_00139bd0:
    uVar5 = 0;
LAB_00139bd4:
    __google_potentially_blocking_region_end();
    return uVar5;
  }
LAB_00139ba8:
  uVar1 = *param_1;
  if (uVar1 == 0) goto code_r0x00139bb4;
  goto LAB_00139bbc;
code_r0x00139bb4:
  cVar3 = '\x01';
  bVar4 = (bool)ExclusiveMonitorPass(param_1,0x10);
  if (bVar4) {
    *param_1 = 0x100;
    cVar3 = ExclusiveMonitorsStatus();
  }
  if (cVar3 == '\0') {
LAB_00139bbc:
    if (uVar1 == 0) {
      uVar5 = 1;
      goto LAB_00139bd4;
    }
    if (uVar1 != 1) {
      if (uVar1 == 0x100) {
        do {
          uVar2 = *param_1;
          if (uVar2 != 0x100) break;
          cVar3 = '\x01';
          bVar4 = (bool)ExclusiveMonitorPass(param_1,0x10);
          if (bVar4) {
            *param_1 = 0x10100;
            cVar3 = ExclusiveMonitorsStatus();
          }
        } while (cVar3 != '\0');
        uVar1 = 0x10100;
        if (uVar2 != 0x100) {
          if (uVar2 == 1) goto LAB_00139bd0;
          if (uVar2 == 0) goto LAB_00139ba8;
        }
      }
                    // try { // try from 00139c28 to 00139c2b has its CatchHandler @ 00139c7c
      syscall(0x62,param_1,0,(ulong)uVar1,0);
      goto LAB_00139ba8;
    }
    goto LAB_00139bd0;
  }
  goto LAB_00139ba8;
}



// WARNING: Removing unreachable block (ram,0x00139d1c)

void __cxa_guard_abort(uint *param_1)

{
  uint uVar1;
  char cVar2;
  bool bVar3;
  
  do {
    uVar1 = *param_1;
    cVar2 = '\x01';
    bVar3 = (bool)ExclusiveMonitorPass(param_1,0x10);
    if (bVar3) {
      *param_1 = 0;
      cVar2 = ExclusiveMonitorsStatus();
    }
  } while (cVar2 != '\0');
  if ((uVar1 & 0x10000) != 0) {
                    // try { // try from 00139d10 to 00139d13 has its CatchHandler @ 00139d28
    syscall(0x62,param_1,1,0x7fffffff);
    return;
  }
  return;
}



// WARNING: Removing unreachable block (ram,0x00139d94)

void __cxa_guard_release(uint *param_1)

{
  uint uVar1;
  char cVar2;
  bool bVar3;
  
  do {
    uVar1 = *param_1;
    cVar2 = '\x01';
    bVar3 = (bool)ExclusiveMonitorPass(param_1,0x10);
    if (bVar3) {
      *param_1 = 1;
      cVar2 = ExclusiveMonitorsStatus();
    }
  } while (cVar2 != '\0');
  if ((uVar1 & 0x10000) != 0) {
                    // try { // try from 00139d88 to 00139d8b has its CatchHandler @ 00139da8
    syscall(0x62,param_1,1,0x7fffffff);
    return;
  }
  return;
}



// __gnu_cxx::recursive_init_error::~recursive_init_error()

void __thiscall __gnu_cxx::recursive_init_error::~recursive_init_error(recursive_init_error *this)

{
  *(undefined ***)this = &PTR__recursive_init_error_001626c0;
  std::exception::~exception((exception *)this);
  return;
}



// __gnu_cxx::recursive_init_error::~recursive_init_error()

void __thiscall __gnu_cxx::recursive_init_error::~recursive_init_error(recursive_init_error *this)

{
  ~recursive_init_error(this);
  operator_delete(this);
  return;
}



undefined8 FUN_00139df0(long param_1)

{
  return *(undefined8 *)(param_1 + 8);
}



// WARNING: Removing unreachable block (ram,0x00139e74)

void FUN_00139df8(undefined8 *param_1)

{
  int iVar1;
  char cVar2;
  bool bVar3;
  undefined *puVar4;
  int *piVar5;
  
  *param_1 = &PTR_FUN_0015de90;
  puVar4 = (undefined *)(param_1[1] + -0x18);
  if (puVar4 != &DAT_00174f60) {
    piVar5 = (int *)(param_1[1] + -8);
    do {
      iVar1 = *piVar5;
      cVar2 = '\x01';
      bVar3 = (bool)ExclusiveMonitorPass(piVar5,0x10);
      if (bVar3) {
        *piVar5 = iVar1 + -1;
        cVar2 = ExclusiveMonitorsStatus();
      }
    } while (cVar2 != '\0');
    if (iVar1 < 1) {
      operator_delete(puVar4);
    }
  }
  std::exception::~exception((exception *)param_1);
  return;
}



// WARNING: Removing unreachable block (ram,0x00139f08)

void FUN_00139e84(undefined8 *param_1)

{
  int iVar1;
  char cVar2;
  bool bVar3;
  undefined *puVar4;
  int *piVar5;
  
  *param_1 = &PTR_FUN_0015de90;
  puVar4 = (undefined *)(param_1[1] + -0x18);
  if (puVar4 != &DAT_00174f60) {
    piVar5 = (int *)(param_1[1] + -8);
    do {
      iVar1 = *piVar5;
      cVar2 = '\x01';
      bVar3 = (bool)ExclusiveMonitorPass(piVar5,0x10);
      if (bVar3) {
        *piVar5 = iVar1 + -1;
        cVar2 = ExclusiveMonitorsStatus();
      }
    } while (cVar2 != '\0');
    if (iVar1 < 1) {
      operator_delete(puVar4);
    }
  }
  std::exception::~exception((exception *)param_1);
  operator_delete(param_1);
  return;
}



void FUN_00139f18(undefined8 *param_1)

{
  *param_1 = &PTR_FUN_0015de90;
                    // try { // try from 00139f34 to 00139f37 has its CatchHandler @ 00139f44
  FUN_001297e4(param_1 + 1);
  return;
}



void FUN_00139f6c(long param_1,undefined *param_2,char param_3)

{
  uint uVar1;
  undefined uVar2;
  undefined *puVar3;
  undefined *puVar4;
  
  uVar1 = *(uint *)(param_1 + 0x18);
  *param_2 = 0x25;
  if ((uVar1 >> 0xb & 1) == 0) {
    puVar3 = param_2 + 1;
  }
  else {
    puVar3 = param_2 + 2;
    param_2[1] = 0x2b;
  }
  puVar4 = puVar3;
  if ((uVar1 >> 10 & 1) != 0) {
    puVar4 = puVar3 + 1;
    *puVar3 = 0x23;
  }
  *puVar4 = 0x2e;
  puVar4[1] = 0x2a;
  puVar3 = puVar4 + 2;
  if (param_3 != '\0') {
    puVar3 = puVar4 + 3;
    puVar4[2] = param_3;
  }
  if ((uVar1 & 0x104) != 4) {
    if ((uVar1 & 0x104) != 0x100) {
      uVar2 = 0x47;
      if ((uVar1 & 0x4000) == 0) {
        uVar2 = 0x67;
      }
      *puVar3 = uVar2;
      puVar3[1] = 0;
      return;
    }
    uVar2 = 0x45;
    if ((uVar1 & 0x4000) == 0) {
      uVar2 = 0x65;
    }
    *puVar3 = uVar2;
    puVar3[1] = 0;
    return;
  }
  *puVar3 = 0x66;
  puVar3[1] = 0;
  return;
}



bool FUN_0013a034(long param_1,long param_2,byte **param_3)

{
  byte *pbVar1;
  byte *pbVar2;
  ulong uVar3;
  byte bVar4;
  bool bVar5;
  ulong uVar6;
  ulong uVar7;
  byte *pbVar8;
  
  pbVar8 = *param_3;
  uVar6 = *(long *)(pbVar8 + -0x18) - 1;
  uVar3 = param_2 - 1U;
  if (uVar6 < param_2 - 1U) {
    uVar3 = uVar6;
  }
  if (uVar3 == 0) {
    bVar5 = true;
  }
  else {
    uVar7 = 0;
    do {
      pbVar1 = (byte *)(param_1 + uVar7);
      uVar7 = uVar7 + 1;
      pbVar2 = pbVar8 + uVar6;
      uVar6 = uVar6 - 1;
      bVar5 = *pbVar2 == *pbVar1;
      if (uVar3 <= uVar7) break;
    } while (bVar5);
  }
  bVar4 = *(byte *)(param_1 + uVar3);
  while ((uVar6 != 0 && (bVar5 != false))) {
    pbVar1 = pbVar8 + uVar6;
    uVar6 = uVar6 - 1;
    bVar5 = *pbVar1 == bVar4;
  }
  if ('\0' < (char)bVar4) {
    bVar5 = (bool)(bVar5 & *pbVar8 <= bVar4);
  }
  return bVar5;
}



void FUN_0013a0c8(byte *param_1,ulong *param_2)

{
  byte bVar1;
  ulong uVar2;
  ulong uVar3;
  ulong uVar4;
  
  uVar3 = 0;
  uVar4 = 0;
  do {
    bVar1 = *param_1;
    uVar2 = uVar4 & 0x3f;
    uVar4 = (ulong)((int)uVar4 + 7);
    uVar3 = uVar3 | ((ulong)bVar1 & 0x7f) << uVar2;
    param_1 = param_1 + 1;
  } while ((char)bVar1 < '\0');
  *param_2 = uVar3;
  return;
}



void FUN_0013a0f0(byte *param_1,ulong *param_2)

{
  uint uVar1;
  byte bVar2;
  ulong uVar3;
  ulong uVar4;
  ulong uVar5;
  
  uVar4 = 0;
  uVar5 = 0;
  do {
    bVar2 = *param_1;
    uVar3 = uVar5 & 0x3f;
    uVar1 = (int)uVar5 + 7;
    uVar5 = (ulong)uVar1;
    uVar4 = uVar4 | ((ulong)bVar2 & 0x7f) << uVar3;
    param_1 = param_1 + 1;
  } while ((char)bVar2 < '\0');
  if ((uVar1 < 0x40) && ((bVar2 >> 6 & 1) != 0)) {
    uVar4 = -1L << (uVar5 & 0x3f) | uVar4;
  }
  *param_2 = uVar4;
  return;
}



ulong ** FUN_0013a130(byte param_1,ulong **param_2,ulong **param_3,ulong **param_4)

{
  ulong **ppuVar1;
  ulong **local_8;
  
  if (param_1 == 0x50) {
    local_8 = (ulong **)((long)param_3 + 7U & 0xfffffffffffffff8);
    ppuVar1 = local_8 + 1;
    local_8 = (ulong **)*local_8;
  }
  else {
    switch(param_1 & 0xf) {
    case 0:
    case 4:
    case 0xc:
      ppuVar1 = param_3 + 1;
      local_8 = (ulong **)*param_3;
      break;
    case 1:
      ppuVar1 = (ulong **)FUN_0013a0c8(param_3,&local_8);
      break;
    case 2:
      ppuVar1 = (ulong **)((long)param_3 + 2);
      local_8 = (ulong **)(ulong)*(ushort *)param_3;
      break;
    case 3:
      ppuVar1 = (ulong **)((long)param_3 + 4);
      local_8 = (ulong **)(ulong)*(uint *)param_3;
      break;
    default:
                    // WARNING: Subroutine does not return
      abort();
    case 9:
      ppuVar1 = (ulong **)FUN_0013a0f0(param_3,&local_8);
      break;
    case 10:
      ppuVar1 = (ulong **)((long)param_3 + 2);
      local_8 = (ulong **)(long)*(short *)param_3;
      break;
    case 0xb:
      ppuVar1 = (ulong **)((long)param_3 + 4);
      local_8 = (ulong **)(long)(int)*(uint *)param_3;
    }
    if (local_8 != (ulong **)0x0) {
      if ((param_1 & 0x70) != 0x10) {
        param_3 = param_2;
      }
      local_8 = (ulong **)((long)local_8 + (long)param_3);
      if ((char)param_1 < '\0') {
        local_8 = (ulong **)*local_8;
      }
    }
  }
  *param_4 = (ulong *)local_8;
  return ppuVar1;
}



void FUN_0013a220(void)

{
  DAT_00174fb0 = 8;
  DAT_00174fb1 = 8;
  DAT_00174fb2 = 8;
  DAT_00174fb3 = 8;
  DAT_00174fb4 = 8;
  DAT_00174fb5 = 8;
  DAT_00174fb6 = 8;
  DAT_00174fb7 = 8;
  DAT_00174fb8 = 8;
  DAT_00174fb9 = 8;
  DAT_00174fba = 8;
  DAT_00174fbb = 8;
  DAT_00174fbc = 8;
  DAT_00174fbd = 8;
  DAT_00174fbe = 8;
  DAT_00174fbf = 8;
  DAT_00174fc0 = 8;
  DAT_00174fc1 = 8;
  DAT_00174fc2 = 8;
  DAT_00174fc3 = 8;
  DAT_00174fc4 = 8;
  DAT_00174fc5 = 8;
  DAT_00174fc6 = 8;
  DAT_00174fc7 = 8;
  DAT_00174fc8 = 8;
  DAT_00174fc9 = 8;
  DAT_00174fca = 8;
  DAT_00174fcb = 8;
  DAT_00174fcc = 8;
  DAT_00174fcd = 8;
  DAT_00174fce = 8;
  DAT_00174fcf = 8;
  DAT_00174ff0 = 8;
  DAT_00174ff1 = 8;
  DAT_00174ff2 = 8;
  DAT_00174ff3 = 8;
  DAT_00174ff4 = 8;
  DAT_00174ff5 = 8;
  DAT_00174ff6 = 8;
  DAT_00174ff7 = 8;
  DAT_00174ff8 = 8;
  DAT_00174ff9 = 8;
  DAT_00174ffa = 8;
  DAT_00174ffb = 8;
  DAT_00174ffc = 8;
  DAT_00174ffd = 8;
  DAT_00174ffe = 8;
  DAT_00174fff = 8;
  DAT_00175000 = 8;
  DAT_00175001 = 8;
  DAT_00175002 = 8;
  DAT_00175003 = 8;
  DAT_00175004 = 8;
  DAT_00175005 = 8;
  DAT_00175006 = 8;
  DAT_00175007 = 8;
  DAT_00175008 = 8;
  DAT_00175009 = 8;
  DAT_0017500a = 8;
  DAT_0017500b = 8;
  DAT_0017500c = 8;
  DAT_0017500d = 8;
  DAT_0017500e = 8;
  DAT_0017500f = 8;
  DAT_00175010 = 8;
  return;
}



void FUN_0013a334(long param_1,undefined8 param_2,undefined8 *param_3)

{
  if (DAT_00174fcf == '\b') {
    *param_3 = param_2;
    if ((*(ulong *)(param_1 + 0x340) >> 0x3e & 1) != 0) {
      *(undefined *)(param_1 + 0x377) = 0;
    }
    *(undefined8 **)(param_1 + 0xf8) = param_3;
    return;
  }
                    // WARNING: Subroutine does not return
  abort();
}



undefined8 * _Unwind_GetGR(long param_1,int param_2)

{
  undefined8 *puVar1;
  
  if (param_2 < 0x62) {
    puVar1 = *(undefined8 **)(param_1 + (long)param_2 * 8);
    if (((*(ulong *)(param_1 + 0x340) >> 0x3e & 1) == 0) ||
       (*(char *)(param_1 + param_2 + 0x358) == '\0')) {
      if ((&DAT_00174fb0)[param_2] != '\b') goto LAB_0013a380;
      puVar1 = (undefined8 *)*puVar1;
    }
    return puVar1;
  }
LAB_0013a380:
                    // WARNING: Subroutine does not return
  abort();
}



long FUN_0013a3c8(long param_1,long param_2)

{
  void **__dest;
  void **__src;
  long lVar1;
  undefined auStack_8 [8];
  
  if ((((*(ulong *)(param_2 + 0x340) >> 0x3e & 1) == 0) || (*(char *)(param_2 + 0x377) == '\0')) &&
     (*(long *)(param_2 + 0xf8) == 0)) {
    FUN_0013a334(param_2,*(undefined8 *)(param_2 + 0x310),auStack_8);
  }
  lVar1 = 0;
  while( true ) {
    __dest = *(void ***)(param_1 + lVar1 * 8);
    __src = *(void ***)(param_2 + lVar1 * 8);
    if (*(char *)(param_1 + lVar1 + 0x358) != '\0') break;
    if ((*(char *)(param_2 + lVar1 + 0x358) == '\0') || (__dest == (void **)0x0)) {
      if ((__dest != (void **)0x0 && __src != (void **)0x0) && (__src != __dest)) {
        memcpy(__dest,__src,(ulong)(byte)(&DAT_00174fb0)[lVar1]);
      }
    }
    else {
      if ((&DAT_00174fb0)[lVar1] != '\b') break;
      *__dest = __src;
    }
    lVar1 = lVar1 + 1;
    if (lVar1 == 0x61) {
      if ((((*(ulong *)(param_1 + 0x340) >> 0x3e & 1) == 0) ||
          (lVar1 = 0, *(char *)(param_1 + 0x377) == '\0')) &&
         (lVar1 = 0, *(long *)(param_1 + 0xf8) == 0)) {
        lVar1 = _Unwind_GetGR(param_2,0x1f);
        lVar1 = (lVar1 - *(long *)(param_1 + 0x310)) + *(long *)(param_2 + 0x350);
      }
      return lVar1;
    }
  }
                    // WARNING: Subroutine does not return
  abort();
}



undefined8 _Unwind_GetCFA(long param_1)

{
  return *(undefined8 *)(param_1 + 0x310);
}



void _Unwind_SetGR(long param_1,int param_2,undefined8 param_3)

{
  if (0x61 < param_2) {
LAB_0013a4ec:
                    // WARNING: Subroutine does not return
    abort();
  }
  if (((*(ulong *)(param_1 + 0x340) >> 0x3e & 1) == 0) ||
     (*(char *)(param_1 + param_2 + 0x358) == '\0')) {
    if ((&DAT_00174fb0)[param_2] != '\b') goto LAB_0013a4ec;
    **(undefined8 **)(param_1 + (long)param_2 * 8) = param_3;
  }
  else {
    *(undefined8 *)(param_1 + (long)param_2 * 8) = param_3;
  }
  return;
}



undefined8 _Unwind_GetIP(long param_1)

{
  return *(undefined8 *)(param_1 + 0x318);
}



undefined8 _Unwind_GetIPInfo(long param_1,uint *param_2)

{
  undefined8 uVar1;
  
  uVar1 = *(undefined8 *)(param_1 + 0x318);
  *param_2 = (uint)((ulong)*(undefined8 *)(param_1 + 0x340) >> 0x3f);
  return uVar1;
}



void _Unwind_SetIP(long param_1,undefined8 param_2)

{
  *(undefined8 *)(param_1 + 0x318) = param_2;
  return;
}



undefined8 _Unwind_GetLanguageSpecificData(long param_1)

{
  return *(undefined8 *)(param_1 + 800);
}



undefined8 _Unwind_GetRegionStart(long param_1)

{
  return *(undefined8 *)(param_1 + 0x338);
}



undefined8 _Unwind_FindEnclosingFunction(long param_1)

{
  long lVar1;
  undefined auStack_18 [16];
  undefined8 local_8;
  
  lVar1 = _Unwind_Find_FDE(param_1 + -1,auStack_18);
  if (lVar1 == 0) {
    local_8 = 0;
  }
  return local_8;
}



undefined8 _Unwind_GetDataRelBase(long param_1)

{
  return *(undefined8 *)(param_1 + 0x330);
}



undefined8 _Unwind_GetTextRelBase(long param_1)

{
  return *(undefined8 *)(param_1 + 0x328);
}



undefined8 FUN_0013a5a0(byte param_1,undefined8 param_2)

{
  byte bVar1;
  undefined8 uVar2;
  
  if (param_1 != 0xff) {
    bVar1 = param_1 & 0x70;
    if (bVar1 == 0x20) {
      uVar2 = _Unwind_GetTextRelBase(param_2);
      return uVar2;
    }
    if (bVar1 < 0x21) {
      if (((param_1 & 0x70) != 0) && (bVar1 != 0x10)) {
LAB_0013a608:
                    // WARNING: Subroutine does not return
        abort();
      }
    }
    else {
      if (bVar1 == 0x40) {
        uVar2 = _Unwind_GetRegionStart();
        return uVar2;
      }
      if (bVar1 != 0x50) {
        if (bVar1 == 0x30) {
          uVar2 = _Unwind_GetDataRelBase();
          return uVar2;
        }
        goto LAB_0013a608;
      }
    }
  }
  return 0;
}



void FUN_0013a618(byte *param_1,byte *param_2,long param_3,void *param_4)

{
  byte bVar1;
  byte bVar2;
  undefined uVar3;
  undefined *puVar4;
  byte *pbVar5;
  void *pvVar6;
  long lVar7;
  undefined8 uVar8;
  long lVar9;
  ulong uVar10;
  long lVar11;
  ulong uVar12;
  long *plVar13;
  undefined4 uVar14;
  undefined *puVar15;
  undefined *puVar16;
  ulong local_18;
  long local_10;
  long local_8;
  
  *(undefined8 *)((long)param_4 + 0x620) = 0;
  puVar4 = &stack0xffffffffffffff70;
  puVar16 = (undefined *)0x0;
LAB_0013a660:
  while( true ) {
    while( true ) {
      pbVar5 = param_1;
      if ((param_2 <= pbVar5) ||
         (uVar12 = *(ulong *)((long)param_4 + 0x648),
         (ulong)(*(long *)(param_3 + 0x318) - (*(long *)(param_3 + 0x340) >> 0x3f)) <= uVar12)) {
        return;
      }
      bVar2 = *pbVar5;
      uVar10 = (ulong)bVar2;
      param_1 = pbVar5 + 1;
      bVar1 = bVar2 & 0xc0;
      if (bVar1 != 0x40) break;
      *(ulong *)((long)param_4 + 0x648) =
           uVar12 + (uVar10 & 0x3f) * *(long *)((long)param_4 + 0x660);
    }
    if (bVar1 == 0x80) break;
    if (bVar1 != 0xc0) goto code_r0x0013a6e0;
    *(undefined4 *)((long)param_4 + (uVar10 & 0x3f) * 0x10 + 8) = 0;
  }
  local_18 = uVar10 & 0x3f;
  goto LAB_0013a780;
code_r0x0013a6e0:
  switch(bVar2) {
  case 0:
    goto LAB_0013a660;
  case 1:
    uVar3 = *(undefined *)((long)param_4 + 0x670);
    uVar8 = FUN_0013a5a0(uVar3,param_3);
    param_1 = (byte *)FUN_0013a130(uVar3,uVar8,param_1,&local_8);
    *(long *)((long)param_4 + 0x648) = local_8;
    goto LAB_0013a660;
  case 2:
    *(ulong *)((long)param_4 + 0x648) = uVar12 + (ulong)pbVar5[1] * *(long *)((long)param_4 + 0x660)
    ;
    param_1 = pbVar5 + 2;
    goto LAB_0013a660;
  case 3:
    *(ulong *)((long)param_4 + 0x648) =
         uVar12 + (ulong)*(ushort *)(pbVar5 + 1) * *(long *)((long)param_4 + 0x660);
    param_1 = pbVar5 + 3;
    goto LAB_0013a660;
  case 4:
    *(ulong *)((long)param_4 + 0x648) =
         uVar12 + (ulong)*(uint *)(pbVar5 + 1) * *(long *)((long)param_4 + 0x660);
    param_1 = pbVar5 + 5;
    goto LAB_0013a660;
  case 5:
    param_1 = (byte *)FUN_0013a0c8(param_1,&local_18);
LAB_0013a780:
    param_1 = (byte *)FUN_0013a0c8(param_1,&local_10);
    lVar11 = *(long *)((long)param_4 + 0x658);
    lVar9 = local_10;
    break;
  case 6:
  case 8:
    param_1 = (byte *)FUN_0013a0c8(param_1,&local_18);
    if (local_18 < 0x62) {
      *(undefined4 *)((long)param_4 + local_18 * 0x10 + 8) = 0;
    }
    goto LAB_0013a660;
  case 7:
    param_1 = (byte *)FUN_0013a0c8(param_1,&local_18);
    if (local_18 < 0x62) {
      *(undefined4 *)((long)param_4 + local_18 * 0x10 + 8) = 6;
    }
    goto LAB_0013a660;
  case 9:
    uVar8 = FUN_0013a0c8(param_1,&local_18);
    param_1 = (byte *)FUN_0013a0c8(uVar8,&local_8);
    if (0x61 < local_18) goto LAB_0013a660;
    lVar7 = local_18 * 0x10;
    *(undefined4 *)((long)param_4 + lVar7 + 8) = 2;
    lVar9 = local_8;
    goto LAB_0013aadc;
  case 10:
    if (puVar16 == (undefined *)0x0) {
      puVar15 = puVar4 + -0x660;
      puVar4 = puVar4 + -0x660;
    }
    else {
      puVar15 = puVar4;
      puVar4 = puVar16;
      puVar16 = *(undefined **)(puVar16 + 0x620);
    }
    pvVar6 = memcpy(puVar4,param_4,0x648);
    *(void **)((long)param_4 + 0x620) = pvVar6;
    puVar4 = puVar15;
    goto LAB_0013a660;
  case 0xb:
    puVar15 = *(undefined **)((long)param_4 + 0x620);
    memcpy(param_4,puVar15,0x648);
    *(undefined **)(puVar15 + 0x620) = puVar16;
    puVar16 = puVar15;
    goto LAB_0013a660;
  case 0xc:
    uVar8 = FUN_0013a0c8(param_1,&local_10);
    *(long *)((long)param_4 + 0x630) = local_10;
    param_1 = (byte *)FUN_0013a0c8(uVar8,&local_10);
    *(long *)((long)param_4 + 0x628) = local_10;
    goto LAB_0013a8c4;
  case 0xd:
    param_1 = (byte *)FUN_0013a0c8(param_1,&local_10);
    *(long *)((long)param_4 + 0x630) = local_10;
LAB_0013a8c4:
    *(undefined4 *)((long)param_4 + 0x640) = 1;
    goto LAB_0013a660;
  case 0xe:
    param_1 = (byte *)FUN_0013a0c8(param_1,&local_10);
    lVar9 = local_10;
    goto LAB_0013a990;
  case 0xf:
    *(byte **)((long)param_4 + 0x638) = param_1;
    *(undefined4 *)((long)param_4 + 0x640) = 2;
    goto LAB_0013aa40;
  case 0x10:
    param_1 = (byte *)FUN_0013a0c8(param_1,&local_18);
    if (0x61 < local_18) goto LAB_0013aa40;
    uVar14 = 3;
    goto LAB_0013aa38;
  case 0x11:
    uVar8 = FUN_0013a0c8(param_1,&local_18);
    param_1 = (byte *)FUN_0013a0f0(uVar8,&local_8);
    lVar11 = *(long *)((long)param_4 + 0x658);
    lVar9 = local_8;
    break;
  case 0x12:
    uVar8 = FUN_0013a0c8(param_1,&local_10);
    *(long *)((long)param_4 + 0x630) = local_10;
    param_1 = (byte *)FUN_0013a0f0(uVar8,&local_8);
    *(undefined4 *)((long)param_4 + 0x640) = 1;
    goto LAB_0013a984;
  case 0x13:
    param_1 = (byte *)FUN_0013a0f0(param_1,&local_8);
LAB_0013a984:
    lVar9 = local_8 * *(long *)((long)param_4 + 0x658);
LAB_0013a990:
    *(long *)((long)param_4 + 0x628) = lVar9;
    goto LAB_0013a660;
  case 0x14:
    uVar8 = FUN_0013a0c8(param_1,&local_18);
    param_1 = (byte *)FUN_0013a0c8(uVar8,&local_10);
    lVar11 = *(long *)((long)param_4 + 0x658);
    lVar9 = local_10;
    goto LAB_0013a9f0;
  case 0x15:
    uVar8 = FUN_0013a0c8(param_1,&local_18);
    param_1 = (byte *)FUN_0013a0f0(uVar8,&local_8);
    lVar11 = *(long *)((long)param_4 + 0x658);
    lVar9 = local_8;
LAB_0013a9f0:
    if (0x61 < local_18) goto LAB_0013a660;
    lVar7 = local_18 * 0x10;
    *(undefined4 *)((long)param_4 + lVar7 + 8) = 4;
    lVar9 = lVar9 * lVar11;
    goto LAB_0013aadc;
  case 0x16:
    param_1 = (byte *)FUN_0013a0c8(param_1,&local_18);
    if (0x61 < local_18) goto LAB_0013aa40;
    uVar14 = 5;
LAB_0013aa38:
    *(undefined4 *)((long)param_4 + local_18 * 0x10 + 8) = uVar14;
    *(byte **)((long)param_4 + local_18 * 0x10) = param_1;
LAB_0013aa40:
    lVar9 = FUN_0013a0c8(param_1,&local_10);
    param_1 = (byte *)(lVar9 + local_10);
    goto LAB_0013a660;
  default:
    goto switchD_0013a6ec_caseD_17;
  case 0x2d:
    lVar9 = 0x10;
    local_18 = 0x10;
    lVar7 = 0;
    plVar13 = (long *)((long)param_4 + 0x100);
    do {
      *(undefined4 *)(plVar13 + 1) = 1;
      lVar9 = lVar9 + 1;
      *plVar13 = lVar7;
      lVar7 = lVar7 + 8;
      plVar13 = plVar13 + 2;
    } while (lVar9 != 0x20);
    goto LAB_0013a660;
  case 0x2e:
    param_1 = (byte *)FUN_0013a0c8(param_1,&local_10);
    *(long *)(param_3 + 0x350) = local_10;
    goto LAB_0013a660;
  case 0x2f:
    uVar8 = FUN_0013a0c8(param_1,&local_18);
    param_1 = (byte *)FUN_0013a0c8(uVar8,&local_10);
    lVar9 = *(long *)((long)param_4 + 0x658);
    if (0x61 < local_18) goto LAB_0013a660;
    lVar7 = local_18 * 0x10;
    *(undefined4 *)((long)param_4 + lVar7 + 8) = 1;
    lVar9 = -(lVar9 * local_10);
    goto LAB_0013aadc;
  }
  if (0x61 < local_18) goto LAB_0013a660;
  lVar7 = local_18 * 0x10;
  *(undefined4 *)((long)param_4 + lVar7 + 8) = 1;
  lVar9 = lVar9 * lVar11;
LAB_0013aadc:
  *(long *)((long)param_4 + lVar7) = lVar9;
  goto LAB_0013a660;
switchD_0013a6ec_caseD_17:
                    // WARNING: Subroutine does not return
  abort();
}



undefined8 FUN_0013ab10(long param_1,long *param_2)

{
  byte bVar1;
  char cVar2;
  uint *puVar3;
  long lVar4;
  int *piVar5;
  size_t sVar6;
  long *plVar7;
  byte *pbVar8;
  byte *pbVar9;
  byte *pbVar10;
  long lVar11;
  undefined8 uVar12;
  ulong uVar13;
  int iVar14;
  long *plVar15;
  long lVar16;
  uint *puVar17;
  char *pcVar18;
  ulong local_18;
  long local_10;
  long local_8;
  char *pcVar19;
  
  memset(param_2,0,0x680);
  *(undefined8 *)(param_1 + 0x350) = 0;
  *(undefined8 *)(param_1 + 800) = 0;
  if (*(long *)(param_1 + 0x318) == 0) {
    return 5;
  }
  puVar3 = (uint *)_Unwind_Find_FDE(*(long *)(param_1 + 0x318) +
                                    (-1 - (*(long *)(param_1 + 0x340) >> 0x3f)),param_1 + 0x328);
  if (puVar3 == (uint *)0x0) {
    if (**(int **)(param_1 + 0x318) != -0x2d7fee98) {
      return 5;
    }
    if ((*(int **)(param_1 + 0x318))[1] != -0x2bffffff) {
      return 5;
    }
    lVar16 = *(long *)(param_1 + 0x310);
    param_2[0xc6] = 0x1f;
    *(undefined4 *)(param_2 + 200) = 1;
    lVar11 = lVar16 + 0x130;
    param_2[0xc5] = 0x130;
    lVar4 = 8;
    plVar7 = param_2;
    do {
      *(undefined4 *)(plVar7 + 1) = 1;
      *plVar7 = lVar4;
      lVar4 = lVar4 + 8;
      plVar7 = plVar7 + 2;
    } while (lVar4 != 0x100);
    for (piVar5 = (int *)(lVar16 + 0x250); *piVar5 != 0;
        piVar5 = (int *)((long)piVar5 + (ulong)(uint)piVar5[1])) {
      if (*piVar5 == 0x46508001) {
        plVar7 = param_2 + 0x80;
        do {
          *(undefined4 *)(plVar7 + 1) = 1;
          plVar15 = plVar7 + 2;
          *plVar7 = (long)piVar5 + ((-0x3f0 - lVar11) - (long)param_2) + (long)plVar7;
          plVar7 = plVar15;
        } while (plVar15 != param_2 + 0xc0);
      }
    }
    *(undefined *)((long)param_2 + 0x673) = 1;
    param_2[0x3e] = (lVar16 + 0x230) - lVar11;
    *(undefined4 *)(param_2 + 0x3f) = 1;
    *(undefined4 *)(param_2 + 0xc1) = 4;
    param_2[0xc0] = *(long *)(lVar16 + 0x238) - lVar11;
    param_2[0xcd] = 0x60;
LAB_0013af0c:
    uVar12 = 0;
  }
  else {
    puVar17 = (uint *)((long)puVar3 + (4 - (long)(int)puVar3[1]));
    param_2[0xc9] = *(long *)(param_1 + 0x338);
    pcVar19 = (char *)((long)puVar17 + 9);
    sVar6 = strlen(pcVar19);
    plVar15 = (long *)(pcVar19 + sVar6 + 1);
    plVar7 = plVar15;
    if ((*(char *)((long)puVar17 + 9) == 'e') && (*(char *)((long)puVar17 + 10) == 'h')) {
      plVar7 = plVar15 + 1;
      pcVar19 = (char *)((long)puVar17 + 0xb);
      param_2[0xcf] = *plVar15;
    }
    if (*(byte *)(puVar17 + 2) < 4) {
LAB_0013ace8:
      uVar12 = FUN_0013a0c8(plVar7,&local_18);
      param_2[0xcc] = local_18;
      pbVar8 = (byte *)FUN_0013a0f0(uVar12,&local_10);
      param_2[0xcb] = local_10;
      if (*(char *)(puVar17 + 2) == '\x01') {
        pbVar9 = pbVar8 + 1;
        uVar13 = (ulong)*pbVar8;
      }
      else {
        pbVar9 = (byte *)FUN_0013a0c8(pbVar8,&local_18);
        uVar13 = local_18;
      }
      param_2[0xcd] = uVar13;
      *(undefined *)((long)param_2 + 0x671) = 0xff;
      pbVar8 = (byte *)0x0;
      if (*pcVar19 == 'z') {
        pcVar19 = pcVar19 + 1;
        pbVar9 = (byte *)FUN_0013a0c8(pbVar9,&local_18);
        *(undefined *)((long)param_2 + 0x672) = 1;
        pbVar8 = pbVar9 + local_18;
      }
      while( true ) {
        pcVar18 = pcVar19 + 1;
        cVar2 = *pcVar19;
        if (cVar2 == '\0') break;
        pcVar19 = pcVar18;
        if (cVar2 == 'L') {
          *(byte *)((long)param_2 + 0x671) = *pbVar9;
LAB_0013ada4:
          pbVar9 = pbVar9 + 1;
        }
        else {
          if (cVar2 == 'R') {
            *(byte *)(param_2 + 0xce) = *pbVar9;
            goto LAB_0013ada4;
          }
          if (cVar2 == 'P') {
            bVar1 = *pbVar9;
            uVar12 = FUN_0013a5a0(bVar1,param_1);
            pbVar9 = (byte *)FUN_0013a130(bVar1,uVar12,pbVar9 + 1,&local_8);
            param_2[0xca] = local_8;
          }
          else {
            pbVar10 = pbVar8;
            if (cVar2 != 'S') goto LAB_0013ae14;
            *(undefined *)((long)param_2 + 0x673) = 1;
          }
        }
      }
      pbVar10 = pbVar9;
      if (pbVar8 != (byte *)0x0) {
        pbVar10 = pbVar8;
      }
LAB_0013ae14:
      if (pbVar10 != (byte *)0x0) {
        FUN_0013a618(pbVar10,(long)puVar17 + (ulong)*puVar17 + 4,param_1,param_2);
        if (*(byte *)(param_2 + 0xce) == 0xff) {
          iVar14 = 0;
        }
        else {
          switch(*(byte *)(param_2 + 0xce) & 7) {
          case 0:
          case 4:
            iVar14 = 8;
            break;
          default:
                    // WARNING: Subroutine does not return
            abort();
          case 2:
            iVar14 = 2;
            break;
          case 3:
            iVar14 = 4;
          }
        }
        lVar4 = 0;
        lVar11 = (long)puVar3 + (ulong)(uint)(iVar14 << 1) + 8;
        if (*(char *)((long)param_2 + 0x672) != '\0') {
          lVar11 = FUN_0013a0c8(lVar11,&local_8);
          lVar4 = lVar11 + local_8;
        }
        cVar2 = *(char *)((long)param_2 + 0x671);
        if (cVar2 != -1) {
          uVar12 = FUN_0013a5a0(cVar2,param_1);
          lVar11 = FUN_0013a130(cVar2,uVar12,lVar11,&local_8);
          *(long *)(param_1 + 800) = local_8;
        }
        if (lVar4 == 0) {
          lVar4 = lVar11;
        }
        FUN_0013a618(lVar4,(long)puVar3 + (ulong)*puVar3 + 4,param_1,param_2);
        goto LAB_0013af0c;
      }
    }
    else if ((*(char *)plVar7 == '\b') && (*(char *)((long)plVar7 + 1) == '\0')) {
      plVar7 = (long *)((long)plVar7 + 2);
      goto LAB_0013ace8;
    }
    uVar12 = 3;
  }
  return uVar12;
}



// WARNING: Restarted to delay deadcode elimination for space: stack

ulong * FUN_0013af34(byte *param_1,byte *param_2,undefined8 param_3,ulong *param_4)

{
  byte bVar1;
  int iVar2;
  ulong uVar3;
  int iVar4;
  ulong *puVar5;
  undefined8 uVar6;
  long lVar7;
  ulong *puVar8;
  ulong **ppuVar9;
  byte *pbVar10;
  ulong *puVar11;
  uint uVar12;
  uint uVar13;
  int local_220 [2];
  ulong *local_218;
  ulong local_210;
  ulong *local_208;
  ulong *local_200 [64];
  uint uVar14;
  
  local_200[0] = param_4;
  uVar12 = 1;
LAB_0013af84:
  pbVar10 = param_1;
  if (param_2 <= pbVar10) {
    if (uVar12 != 0) {
      return local_200[(int)(uVar12 - 1)];
    }
switchD_0013b340_caseD_3:
                    // WARNING: Subroutine does not return
    abort();
  }
  bVar1 = *pbVar10;
  param_1 = pbVar10 + 1;
  uVar13 = (uint)bVar1;
  uVar14 = (uint)bVar1;
  if (bVar1 < 0x21) {
    if (bVar1 < 0x1f) {
      if (uVar14 == 0x10) {
        param_1 = (byte *)FUN_0013a0c8(param_1,&local_218);
        puVar5 = local_218;
      }
      else if (uVar14 < 0x11) {
        if (uVar14 == 10) {
          puVar5 = (ulong *)(ulong)*(ushort *)(pbVar10 + 1);
LAB_0013b190:
          param_1 = pbVar10 + 3;
        }
        else if (uVar14 < 0xb) {
          if (uVar13 == 6) goto LAB_0013b2cc;
          if (uVar13 < 7) {
            if (bVar1 != 3) goto switchD_0013b340_caseD_3;
            param_1 = pbVar10 + 9;
            puVar5 = *(ulong **)(pbVar10 + 1);
          }
          else {
            param_1 = pbVar10 + 2;
            if (uVar13 == 8) {
              puVar5 = (ulong *)(ulong)pbVar10[1];
            }
            else {
              if (uVar13 != 9) goto switchD_0013b340_caseD_3;
              puVar5 = (ulong *)(long)(char)pbVar10[1];
            }
          }
        }
        else {
          if (uVar14 == 0xd) {
            puVar5 = (ulong *)(long)*(int *)(pbVar10 + 1);
          }
          else {
            if (0xd < uVar14) {
              param_1 = pbVar10 + 9;
              if ((bVar1 == 0xe) || (bVar1 == 0xf)) {
                puVar5 = *(ulong **)(pbVar10 + 1);
                goto LAB_0013b4a4;
              }
              goto switchD_0013b340_caseD_3;
            }
            if (bVar1 == 0xb) {
              puVar5 = (ulong *)(long)*(short *)(pbVar10 + 1);
              goto LAB_0013b190;
            }
            if (bVar1 != 0xc) goto switchD_0013b340_caseD_3;
            puVar5 = (ulong *)(ulong)*(uint *)(pbVar10 + 1);
          }
          param_1 = pbVar10 + 5;
        }
      }
      else if (uVar14 == 0x15) {
        local_210 = (ulong)pbVar10[1];
        param_1 = pbVar10 + 2;
        if ((long)(int)(uVar12 - 1) <= (long)local_210) goto switchD_0013b340_caseD_3;
        puVar5 = local_200[(long)(int)(uVar12 - 1) - local_210];
      }
      else {
        if (0x15 < uVar14) {
          if (uVar14 == 0x19) goto LAB_0013b2cc;
          if (0x19 < uVar14) goto LAB_0013b390;
          iVar4 = uVar12 - 1;
          iVar2 = uVar12 - 2;
          if (uVar14 == 0x16) {
            if ((int)uVar12 < 2) goto switchD_0013b340_caseD_3;
            puVar5 = local_200[iVar4];
            local_200[iVar4] = local_200[iVar2];
            local_200[iVar2] = puVar5;
          }
          else {
            if ((uVar14 != 0x17) || ((int)uVar12 < 3)) goto switchD_0013b340_caseD_3;
            puVar5 = local_200[iVar4];
            puVar11 = local_200[(int)(uVar12 - 3)];
            local_200[iVar4] = local_200[iVar2];
            local_200[iVar2] = puVar11;
            local_200[(int)(uVar12 - 3)] = puVar5;
          }
          goto LAB_0013af84;
        }
        if (uVar14 == 0x12) {
          if (uVar12 == 0) goto switchD_0013b340_caseD_3;
          iVar4 = uVar12 - 1;
        }
        else {
          if (uVar14 < 0x12) {
            param_1 = (byte *)FUN_0013a0f0(param_1,&local_208);
            puVar5 = local_208;
            goto LAB_0013b4a4;
          }
          if (uVar14 == 0x13) {
            if (uVar12 == 0) goto switchD_0013b340_caseD_3;
            uVar12 = uVar12 - 1;
            goto LAB_0013af84;
          }
          if ((uVar14 != 0x14) || ((int)uVar12 < 2)) goto switchD_0013b340_caseD_3;
          iVar4 = uVar12 - 2;
        }
        puVar5 = local_200[iVar4];
      }
    }
    else {
LAB_0013b2cc:
      if (uVar12 == 0) goto switchD_0013b340_caseD_3;
      uVar12 = uVar12 - 1;
      ppuVar9 = (ulong **)local_200[(int)uVar12];
      if (uVar13 == 0x1f) {
        puVar5 = (ulong *)-(long)ppuVar9;
      }
      else if (uVar13 < 0x20) {
        if (uVar13 == 6) {
switchD_0013b340_caseD_8:
          puVar5 = *ppuVar9;
        }
        else {
          if (bVar1 != 0x19) goto switchD_0013b340_caseD_3;
          puVar5 = (ulong *)(((ulong)ppuVar9 ^ (long)ppuVar9 >> 0x3f) - ((long)ppuVar9 >> 0x3f));
        }
      }
      else if (uVar13 == 0x23) {
        param_1 = (byte *)FUN_0013a0c8(param_1,&local_218);
        puVar5 = (ulong *)((long)ppuVar9 + (long)local_218);
      }
      else if (uVar13 == 0x94) {
        param_1 = pbVar10 + 2;
        switch(pbVar10[1]) {
        case 1:
          puVar5 = (ulong *)(ulong)*(byte *)ppuVar9;
          break;
        case 2:
          puVar5 = (ulong *)(ulong)*(ushort *)ppuVar9;
          break;
        default:
          goto switchD_0013b340_caseD_3;
        case 4:
          puVar5 = (ulong *)(ulong)*(uint *)ppuVar9;
          break;
        case 8:
          goto switchD_0013b340_caseD_8;
        }
      }
      else {
        if (uVar13 != 0x20) goto switchD_0013b340_caseD_3;
        puVar5 = (ulong *)~(ulong)ppuVar9;
      }
    }
  }
  else if (uVar14 < 0x50) {
    if (0x2f < uVar13) {
      puVar5 = (ulong *)(ulong)(uVar13 - 0x30);
      goto LAB_0013b4a4;
    }
    if (0x27 < uVar13) {
      if (uVar14 < 0x2f) {
        if (0x28 < uVar14) goto LAB_0013b390;
        if (uVar12 == 0) goto switchD_0013b340_caseD_3;
        uVar12 = uVar12 - 1;
        param_1 = pbVar10 + 3;
        if (local_200[(int)uVar12] != (ulong *)0x0) {
          param_1 = pbVar10 + 3 + *(short *)(pbVar10 + 1);
        }
      }
      else {
        param_1 = pbVar10 + (long)*(short *)(pbVar10 + 1) + 3;
      }
      goto LAB_0013af84;
    }
    if ((uVar14 < 0x24) && (0x22 < uVar14)) goto LAB_0013b2cc;
LAB_0013b390:
    if ((int)uVar12 < 2) goto switchD_0013b340_caseD_3;
    uVar13 = uVar12 - 2;
    puVar8 = local_200[(int)uVar13];
    puVar11 = local_200[(int)(uVar12 - 1)];
    uVar12 = uVar13;
    switch(bVar1) {
    case 0x1a:
      puVar5 = (ulong *)((ulong)puVar11 & (ulong)puVar8);
      break;
    case 0x1b:
      puVar5 = (ulong *)0x0;
      if (puVar11 != (ulong *)0x0) {
        puVar5 = (ulong *)((long)puVar8 / (long)puVar11);
      }
      break;
    case 0x1c:
      puVar5 = (ulong *)((long)puVar8 - (long)puVar11);
      break;
    case 0x1d:
      uVar3 = 0;
      if (puVar11 != (ulong *)0x0) {
        uVar3 = (ulong)puVar8 / (ulong)puVar11;
      }
      puVar5 = (ulong *)((long)puVar8 - uVar3 * (long)puVar11);
      break;
    case 0x1e:
      puVar5 = (ulong *)((long)puVar11 * (long)puVar8);
      break;
    default:
      goto switchD_0013b340_caseD_3;
    case 0x21:
      puVar5 = (ulong *)((ulong)puVar11 | (ulong)puVar8);
      break;
    case 0x22:
      puVar5 = (ulong *)((long)puVar11 + (long)puVar8);
      break;
    case 0x24:
      puVar5 = (ulong *)((long)puVar8 << ((ulong)puVar11 & 0x3f));
      break;
    case 0x25:
      puVar5 = (ulong *)((ulong)puVar8 >> ((ulong)puVar11 & 0x3f));
      break;
    case 0x26:
      puVar5 = (ulong *)((long)puVar8 >> ((ulong)puVar11 & 0x3f));
      break;
    case 0x27:
      puVar5 = (ulong *)((ulong)puVar11 ^ (ulong)puVar8);
      break;
    case 0x29:
      puVar5 = (ulong *)(ulong)(puVar8 == puVar11);
      break;
    case 0x2a:
      puVar5 = (ulong *)(ulong)((long)puVar11 <= (long)puVar8);
      break;
    case 0x2b:
      puVar5 = (ulong *)(ulong)((long)puVar11 < (long)puVar8);
      break;
    case 0x2c:
      puVar5 = (ulong *)(ulong)((long)puVar8 <= (long)puVar11);
      break;
    case 0x2d:
      puVar5 = (ulong *)(ulong)((long)puVar8 < (long)puVar11);
      break;
    case 0x2e:
      puVar5 = (ulong *)(ulong)(puVar8 != puVar11);
    }
  }
  else {
    if (uVar14 != 0x90) {
      if (uVar14 < 0x91) {
        if (bVar1 < 0x70) {
          iVar4 = uVar13 - 0x50;
          goto LAB_0013b1f8;
        }
        param_1 = (byte *)FUN_0013a0f0(param_1,&local_210);
        lVar7 = _Unwind_GetGR(param_3,uVar14 - 0x70);
      }
      else {
        if (uVar14 == 0x94) goto LAB_0013b2cc;
        if (0x94 < uVar14) {
          if (uVar14 != 0x96) {
            if (uVar14 == 0xf1) {
              bVar1 = pbVar10[1];
              uVar6 = FUN_0013a5a0(bVar1,param_3);
              param_1 = (byte *)FUN_0013a130(bVar1,uVar6,pbVar10 + 2,&local_208);
              puVar5 = local_208;
              goto LAB_0013b4a4;
            }
            goto switchD_0013b340_caseD_3;
          }
          goto LAB_0013af84;
        }
        if (bVar1 != 0x92) goto switchD_0013b340_caseD_3;
        uVar6 = FUN_0013a0c8(param_1,local_220);
        param_1 = (byte *)FUN_0013a0f0(uVar6,&local_210);
        lVar7 = _Unwind_GetGR(param_3,local_220[0]);
      }
      puVar5 = (ulong *)(lVar7 + local_210);
      goto LAB_0013b4a4;
    }
    param_1 = (byte *)FUN_0013a0c8(param_1,local_220);
    iVar4 = local_220[0];
LAB_0013b1f8:
    puVar5 = (ulong *)_Unwind_GetGR(param_3,iVar4);
  }
LAB_0013b4a4:
  if (0x3f < uVar12) goto switchD_0013b340_caseD_3;
  local_200[(int)uVar12] = puVar5;
  uVar12 = uVar12 + 1;
  goto LAB_0013af84;
}



void FUN_0013b4e8(void *param_1,long *param_2)

{
  ulong uVar1;
  int iVar2;
  long lVar3;
  long lVar4;
  long lVar5;
  undefined *puVar6;
  long *plVar7;
  undefined auStack_3d0 [8];
  long local_3c8;
  long alStack_3c0 [31];
  long local_2c8;
  ulong local_80;
  char acStack_68 [31];
  char local_49;
  
  memcpy(alStack_3c0,param_1,0x3c0);
  if ((((local_80 >> 0x3e & 1) == 0) || (local_49 == '\0')) && (local_2c8 == 0)) {
    FUN_0013a334(alStack_3c0,*(undefined8 *)((long)param_1 + 0x310),auStack_3d0);
  }
  if ((*(ulong *)((long)param_1 + 0x340) >> 0x3e & 1) != 0) {
    *(undefined *)((long)param_1 + 0x377) = 0;
  }
  iVar2 = *(int *)(param_2 + 200);
  *(undefined8 *)((long)param_1 + 0xf8) = 0;
  if (iVar2 == 1) {
    lVar3 = _Unwind_GetGR(alStack_3c0,*(undefined4 *)(param_2 + 0xc6));
    lVar3 = lVar3 + param_2[0xc5];
  }
  else {
    if (iVar2 != 2) {
LAB_0013b630:
                    // WARNING: Subroutine does not return
      abort();
    }
    lVar3 = FUN_0013a0c8(param_2[199],&local_3c8);
    lVar3 = FUN_0013af34(lVar3,lVar3 + local_3c8,alStack_3c0,0);
  }
  *(long *)((long)param_1 + 0x310) = lVar3;
  puVar6 = (undefined *)((long)param_1 + 0x358);
  lVar5 = 0;
  plVar7 = param_2;
  do {
    switch(*(undefined4 *)(plVar7 + 1)) {
    case 1:
      lVar4 = lVar3 + *plVar7;
      break;
    case 2:
      if (acStack_68[(int)*plVar7] != '\0') {
        lVar4 = _Unwind_GetGR(alStack_3c0);
        goto LAB_0013b620;
      }
      lVar4 = alStack_3c0[(int)*plVar7];
      break;
    case 3:
      lVar4 = FUN_0013a0c8(*plVar7,&local_3c8);
      lVar4 = FUN_0013af34(lVar4,lVar4 + local_3c8,alStack_3c0,lVar3);
      break;
    case 4:
      lVar4 = lVar3 + *plVar7;
      goto LAB_0013b620;
    case 5:
      lVar4 = FUN_0013a0c8(*plVar7,&local_3c8);
      lVar4 = FUN_0013af34(lVar4,lVar4 + local_3c8,alStack_3c0,lVar3);
LAB_0013b620:
      if ((byte)(&DAT_00174fb0)[lVar5] < 9) {
        *puVar6 = 1;
        goto LAB_0013b6a0;
      }
      goto LAB_0013b630;
    default:
      goto switchD_0013b5f8_caseD_5;
    }
    if ((*(ulong *)((long)param_1 + 0x340) >> 0x3e & 1) != 0) {
      *puVar6 = 0;
    }
LAB_0013b6a0:
    *(long *)((long)param_1 + lVar5 * 8) = lVar4;
switchD_0013b5f8_caseD_5:
    lVar5 = lVar5 + 1;
    plVar7 = plVar7 + 2;
    puVar6 = puVar6 + 1;
    if (lVar5 == 0x62) {
      uVar1 = *(ulong *)((long)param_1 + 0x340) & 0x7fffffffffffffff;
      if (*(char *)((long)param_2 + 0x673) != '\0') {
        uVar1 = *(ulong *)((long)param_1 + 0x340) | 0x8000000000000000;
      }
      *(ulong *)((long)param_1 + 0x340) = uVar1;
      return;
    }
  } while( true );
}



void FUN_0013b6f4(void *param_1,undefined8 param_2,undefined8 param_3)

{
  int iVar1;
  undefined8 unaff_x30;
  undefined auStack_688 [8];
  undefined auStack_680 [1576];
  undefined8 local_58;
  undefined8 local_50;
  undefined4 local_40;
  
  memset(param_1,0,0x3c0);
  *(undefined8 *)((long)param_1 + 0x318) = unaff_x30;
  *(undefined8 *)((long)param_1 + 0x340) = 0x4000000000000000;
  iVar1 = FUN_0013ab10(param_1,auStack_680);
  if (iVar1 == 0) {
    iVar1 = pthread_once((pthread_once_t *)&DAT_00175014,FUN_0013a220);
    if ((iVar1 != 0) && (DAT_00174fb0 == '\0')) {
      FUN_0013a220();
    }
    FUN_0013a334(param_1,param_2,auStack_688);
    local_58 = 0;
    local_40 = 1;
    local_50 = 0x1f;
    FUN_0013b4e8(param_1,auStack_680);
    *(undefined8 *)((long)param_1 + 0x318) = param_3;
    return;
  }
                    // WARNING: Subroutine does not return
  abort();
}



void FUN_0013b7d0(long param_1,long param_2)

{
  undefined8 uVar1;
  
  FUN_0013b4e8();
  if (*(int *)(param_2 + *(long *)(param_2 + 0x668) * 0x10 + 8) == 6) {
    *(undefined8 *)(param_1 + 0x318) = 0;
  }
  else {
    uVar1 = _Unwind_GetGR(param_1);
    *(undefined8 *)(param_1 + 0x318) = uVar1;
  }
  return;
}



undefined8 FUN_0013b81c(undefined8 *param_1,long param_2)

{
  int iVar1;
  long lVar2;
  undefined8 uVar3;
  uint uVar4;
  undefined auStack_680 [1616];
  code *local_30;
  
  do {
    iVar1 = FUN_0013ab10(param_2,auStack_680);
    lVar2 = _Unwind_GetCFA(param_2);
    uVar4 = 4;
    if (lVar2 + (*(long *)(param_2 + 0x340) >> 0x3f) != param_1[3]) {
      uVar4 = 0;
    }
    if (iVar1 != 0) {
      return 2;
    }
    if (local_30 != (code *)0x0) {
      uVar3 = (*local_30)(1,uVar4 | 2,*param_1,param_1,param_2);
      if ((int)uVar3 == 7) {
        return uVar3;
      }
      if ((int)uVar3 != 8) {
        return 2;
      }
    }
    if (uVar4 != 0) {
                    // WARNING: Subroutine does not return
      abort();
    }
    FUN_0013b7d0(param_2,auStack_680);
  } while( true );
}



undefined4 FUN_0013b8dc(undefined8 *param_1,undefined8 param_2)

{
  int iVar1;
  int iVar2;
  code *pcVar3;
  undefined8 uVar4;
  undefined4 uVar5;
  undefined auStack_680 [1616];
  code *local_30;
  
  pcVar3 = (code *)param_1[2];
  uVar4 = param_1[3];
  while( true ) {
    iVar1 = FUN_0013ab10(param_2,auStack_680);
    if ((iVar1 != 5) && (iVar1 != 0)) {
      return 2;
    }
    uVar5 = 10;
    if (iVar1 == 5) {
      uVar5 = 0x1a;
    }
    iVar2 = (*pcVar3)(1,uVar5,*param_1,param_1,param_2,uVar4);
    if (iVar2 != 0) break;
    if (iVar1 == 5) {
      return 5;
    }
    if (local_30 != (code *)0x0) {
      iVar1 = (*local_30)(1,10,*param_1,param_1,param_2);
      if (iVar1 == 7) {
        return 7;
      }
      if (iVar1 != 8) {
        return 2;
      }
    }
    FUN_0013b7d0(param_2,auStack_680);
  }
  return 2;
}



long __frame_state_for(long param_1,long param_2)

{
  char cVar1;
  int iVar2;
  undefined8 *puVar3;
  undefined8 *puVar4;
  long lVar5;
  char *pcVar6;
  undefined auStack_a40 [792];
  long local_728;
  undefined8 local_700;
  undefined8 local_6f0;
  undefined8 local_680;
  undefined8 local_678 [196];
  undefined8 local_58;
  undefined2 local_50;
  int local_40;
  undefined2 local_18;
  undefined8 local_8;
  
  local_728 = param_1 + 1;
  memset(auStack_a40,0,0x3c0);
  local_700 = 0x4000000000000000;
  iVar2 = FUN_0013ab10(auStack_a40,&local_680);
  lVar5 = 0;
  if ((iVar2 == 0) && (local_40 != 2)) {
    puVar3 = local_678;
    pcVar6 = (char *)(param_2 + 0x334);
    puVar4 = (undefined8 *)(param_2 + 0x20);
    do {
      cVar1 = *(char *)puVar3;
      *pcVar6 = cVar1;
      if ((cVar1 == '\x01') || (cVar1 == '\x02')) {
        *puVar4 = puVar3[-1];
      }
      else {
        *puVar4 = 0;
      }
      puVar3 = puVar3 + 2;
      pcVar6 = pcVar6 + 1;
      puVar4 = puVar4 + 1;
    } while (puVar3 != &local_58);
    *(undefined8 *)(param_2 + 0x10) = local_58;
    *(undefined2 *)(param_2 + 0x330) = local_50;
    *(undefined2 *)(param_2 + 0x332) = local_18;
    *(undefined8 *)(param_2 + 0x18) = local_6f0;
    *(undefined8 *)(param_2 + 8) = local_8;
    lVar5 = param_2;
  }
  return lVar5;
}



void FUN_0013babc(void)

{
  return;
}



undefined  [16] _Unwind_RaiseException(undefined8 *param_1,undefined8 param_2)

{
  undefined auVar1 [16];
  int iVar2;
  long lVar3;
  undefined auStack_e00 [960];
  undefined auStack_a40 [784];
  undefined8 local_730;
  undefined8 local_728;
  long local_700;
  undefined auStack_680 [1616];
  code *local_30;
  
  FUN_0013b6f4(auStack_e00,&stack0x00000000);
  memcpy(auStack_a40,auStack_e00,0x3c0);
  do {
    iVar2 = FUN_0013ab10(auStack_a40,auStack_680);
    if ((iVar2 == 5) || (iVar2 != 0)) goto LAB_0013bbf8;
    if (local_30 != (code *)0x0) {
      iVar2 = (*local_30)(1,1,*param_1,param_1,auStack_a40);
      if (iVar2 == 6) {
        param_1[2] = 0;
        lVar3 = _Unwind_GetCFA(auStack_a40);
        param_1[3] = lVar3 + (local_700 >> 0x3f);
        memcpy(auStack_a40,auStack_e00,0x3c0);
        iVar2 = FUN_0013b81c(param_1,auStack_a40);
        if (iVar2 == 7) {
          FUN_0013a3c8(auStack_e00,auStack_a40);
          FUN_0013babc(local_730,local_728);
        }
LAB_0013bbf8:
        auVar1._8_8_ = param_2;
        auVar1._0_8_ = param_1;
        return auVar1;
      }
      if (iVar2 != 8) goto LAB_0013bbf8;
    }
    FUN_0013b7d0(auStack_a40,auStack_680);
  } while( true );
}



undefined  [16] _Unwind_ForcedUnwind(long param_1,undefined8 param_2,undefined8 param_3)

{
  undefined auVar1 [16];
  int iVar2;
  undefined auStack_780 [960];
  undefined auStack_3c0 [784];
  undefined8 local_b0;
  undefined8 local_a8;
  
  FUN_0013b6f4(auStack_780,&stack0x00000000);
  memcpy(auStack_3c0,auStack_780,0x3c0);
  *(undefined8 *)(param_1 + 0x10) = param_2;
  *(undefined8 *)(param_1 + 0x18) = param_3;
  iVar2 = FUN_0013b8dc(param_1,auStack_3c0);
  if (iVar2 == 7) {
    FUN_0013a3c8(auStack_780,auStack_3c0);
    FUN_0013babc(local_b0,local_a8);
  }
  auVar1._8_8_ = param_2;
  auVar1._0_8_ = param_1;
  return auVar1;
}



undefined  [16] _Unwind_Resume(long param_1,undefined8 param_2)

{
  undefined auVar1 [16];
  int iVar2;
  undefined auStack_780 [960];
  undefined auStack_3c0 [784];
  undefined8 local_b0;
  undefined8 local_a8;
  
  FUN_0013b6f4(auStack_780,&stack0x00000000);
  memcpy(auStack_3c0,auStack_780,0x3c0);
  if (*(long *)(param_1 + 0x10) == 0) {
    iVar2 = FUN_0013b81c(param_1,auStack_3c0);
  }
  else {
    iVar2 = FUN_0013b8dc(param_1,auStack_3c0);
  }
  if (iVar2 != 7) {
                    // WARNING: Subroutine does not return
    abort();
  }
  FUN_0013a3c8(auStack_780,auStack_3c0);
  FUN_0013babc(local_b0,local_a8);
  auVar1._8_8_ = param_2;
  auVar1._0_8_ = param_1;
  return auVar1;
}



undefined  [16] _Unwind_Resume_or_Rethrow(long param_1,undefined8 param_2)

{
  undefined auVar1 [16];
  int iVar2;
  undefined auStack_780 [960];
  undefined auStack_3c0 [784];
  undefined8 local_b0;
  undefined8 local_a8;
  
  if (*(long *)(param_1 + 0x10) == 0) {
    _Unwind_RaiseException();
  }
  else {
    FUN_0013b6f4(auStack_780,&stack0x00000000);
    memcpy(auStack_3c0,auStack_780,0x3c0);
    iVar2 = FUN_0013b8dc(param_1,auStack_3c0);
    if (iVar2 != 7) {
                    // WARNING: Subroutine does not return
      abort();
    }
    FUN_0013a3c8(auStack_780,auStack_3c0);
    FUN_0013babc(local_b0,local_a8);
  }
  auVar1._8_8_ = param_2;
  auVar1._0_8_ = param_1;
  return auVar1;
}



void _Unwind_DeleteException(long param_1)

{
  if (*(code **)(param_1 + 8) != (code *)0x0) {
    (**(code **)(param_1 + 8))(1,param_1);
  }
  return;
}



undefined8 _Unwind_Backtrace(code *param_1,undefined8 param_2)

{
  int iVar1;
  int iVar2;
  undefined auStack_a40 [960];
  undefined auStack_680 [1664];
  
  FUN_0013b6f4(auStack_a40,&stack0x00000000);
  while (((iVar1 = FUN_0013ab10(auStack_a40,auStack_680), iVar1 == 5 || (iVar1 == 0)) &&
         (iVar2 = (*param_1)(auStack_a40,param_2), iVar2 == 0))) {
    if (iVar1 == 5) {
      return 5;
    }
    FUN_0013b7d0(auStack_a40,auStack_680);
  }
  return 3;
}



void FUN_0013c014(byte *param_1,ulong *param_2)

{
  byte bVar1;
  ulong uVar2;
  ulong uVar3;
  ulong uVar4;
  
  uVar3 = 0;
  uVar4 = 0;
  do {
    bVar1 = *param_1;
    uVar2 = uVar4 & 0x3f;
    uVar4 = (ulong)((int)uVar4 + 7);
    uVar3 = uVar3 | ((ulong)bVar1 & 0x7f) << uVar2;
    param_1 = param_1 + 1;
  } while ((char)bVar1 < '\0');
  *param_2 = uVar3;
  return;
}



void FUN_0013c03c(byte *param_1,ulong *param_2)

{
  uint uVar1;
  byte bVar2;
  ulong uVar3;
  ulong uVar4;
  ulong uVar5;
  
  uVar4 = 0;
  uVar5 = 0;
  do {
    bVar2 = *param_1;
    uVar3 = uVar5 & 0x3f;
    uVar1 = (int)uVar5 + 7;
    uVar5 = (ulong)uVar1;
    uVar4 = uVar4 | ((ulong)bVar2 & 0x7f) << uVar3;
    param_1 = param_1 + 1;
  } while ((char)bVar2 < '\0');
  if ((uVar1 < 0x40) && ((bVar2 >> 6 & 1) != 0)) {
    uVar4 = -1L << (uVar5 & 0x3f) | uVar4;
  }
  *param_2 = uVar4;
  return;
}



int FUN_0013c07c(undefined8 param_1,long param_2,long param_3)

{
  int iVar1;
  
  iVar1 = -(uint)(*(ulong *)(param_2 + 8) < *(ulong *)(param_3 + 8));
  if (*(ulong *)(param_3 + 8) < *(ulong *)(param_2 + 8)) {
    iVar1 = 1;
  }
  return iVar1;
}



void FUN_0013c098(undefined8 param_1,code *param_2,long param_3,ulong param_4,int param_5)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  undefined8 uVar4;
  ulong uVar5;
  ulong uVar6;
  ulong uVar7;
  
  iVar3 = (int)param_4;
  while( true ) {
    uVar1 = iVar3 * 2 + 1;
    uVar5 = (ulong)uVar1;
    if (param_5 <= (int)uVar1) {
      return;
    }
    uVar2 = iVar3 * 2 + 2;
    if ((int)uVar2 < param_5) {
      uVar5 = -(ulong)(uVar1 >> 0x1f) & 0xfffffff800000000 | uVar5 << 3;
      iVar3 = (*param_2)(param_1,*(undefined8 *)(param_3 + uVar5),
                         *(undefined8 *)(param_3 + uVar5 + 8));
      if (iVar3 < 0) {
        uVar1 = uVar2;
      }
      uVar5 = (ulong)uVar1;
    }
    uVar6 = -(param_4 >> 0x1f & 1) & 0xfffffff800000000 | (param_4 & 0xffffffff) << 3;
    uVar7 = -(uVar5 >> 0x1f) & 0xfffffff800000000 | uVar5 << 3;
    iVar3 = (*param_2)(param_1,*(undefined8 *)(param_3 + uVar6),*(undefined8 *)(param_3 + uVar7));
    if (-1 < iVar3) break;
    uVar4 = *(undefined8 *)(param_3 + uVar6);
    *(undefined8 *)(param_3 + uVar6) = *(undefined8 *)(param_3 + uVar7);
    *(undefined8 *)(param_3 + uVar7) = uVar4;
    iVar3 = (int)uVar5;
    param_4 = uVar5;
  }
  return;
}



void FUN_0013c158(undefined8 param_1,undefined8 param_2,long param_3)

{
  long lVar1;
  long lVar2;
  uint uVar3;
  undefined8 uVar4;
  int iVar5;
  ulong uVar6;
  ulong uVar7;
  long lVar8;
  
  uVar6 = *(ulong *)(param_3 + 8);
  lVar2 = param_3 + 0x10;
  uVar7 = uVar6 >> 1;
  while( true ) {
    uVar3 = (int)uVar7 - 1;
    uVar7 = (ulong)uVar3;
    if ((int)uVar3 < 0) break;
    FUN_0013c098(param_1,param_2,lVar2,uVar3,uVar6 & 0xffffffff);
  }
  lVar8 = 0;
  iVar5 = (int)uVar6 + -1;
  lVar1 = lVar2 + (long)iVar5 * 8;
  for (; 0 < iVar5; iVar5 = iVar5 + -1) {
    uVar4 = *(undefined8 *)(param_3 + 0x10);
    *(undefined8 *)(param_3 + 0x10) = *(undefined8 *)(lVar1 + lVar8);
    *(undefined8 *)(lVar1 + lVar8) = uVar4;
    lVar8 = lVar8 + -8;
    FUN_0013c098(param_1,param_2,lVar2,0,iVar5);
  }
  return;
}



undefined8 FUN_0013c20c(byte param_1)

{
  undefined8 uVar1;
  
  if (param_1 == 0xff) {
    uVar1 = 0;
  }
  else {
    switch(param_1 & 7) {
    case 0:
    case 4:
      uVar1 = 8;
      break;
    default:
                    // WARNING: Subroutine does not return
      abort();
    case 2:
      uVar1 = 2;
      break;
    case 3:
      uVar1 = 4;
    }
  }
  return uVar1;
}



undefined8 FUN_0013c26c(byte param_1,long param_2)

{
  byte bVar1;
  bool bVar2;
  
  if (param_1 != 0xff) {
    bVar1 = param_1 & 0x70;
    if (bVar1 == 0x20) {
      return *(undefined8 *)(param_2 + 8);
    }
    if (bVar1 < 0x21) {
      bVar2 = bVar1 == 0x10;
      if ((param_1 & 0x70) == 0) {
        return 0;
      }
    }
    else {
      if (bVar1 == 0x30) {
        return *(undefined8 *)(param_2 + 0x10);
      }
      bVar2 = bVar1 == 0x50;
    }
    if (!bVar2) {
                    // WARNING: Subroutine does not return
      abort();
    }
  }
  return 0;
}



undefined8 FUN_0013c2cc(byte param_1,long param_2)

{
  byte bVar1;
  bool bVar2;
  
  if (param_1 != 0xff) {
    bVar1 = param_1 & 0x70;
    if (bVar1 == 0x20) {
      return *(undefined8 *)(param_2 + 8);
    }
    if (bVar1 < 0x21) {
      bVar2 = bVar1 == 0x10;
      if ((param_1 & 0x70) == 0) {
        return 0;
      }
    }
    else {
      if (bVar1 == 0x30) {
        return *(undefined8 *)(param_2 + 0x10);
      }
      bVar2 = bVar1 == 0x50;
    }
    if (!bVar2) {
                    // WARNING: Subroutine does not return
      abort();
    }
  }
  return 0;
}



ulong ** FUN_0013c32c(byte param_1,ulong **param_2,ulong **param_3,ulong **param_4)

{
  ulong **ppuVar1;
  ulong **local_8;
  
  if (param_1 == 0x50) {
    local_8 = (ulong **)((long)param_3 + 7U & 0xfffffffffffffff8);
    ppuVar1 = local_8 + 1;
    local_8 = (ulong **)*local_8;
  }
  else {
    switch(param_1 & 0xf) {
    case 0:
    case 4:
    case 0xc:
      ppuVar1 = param_3 + 1;
      local_8 = (ulong **)*param_3;
      break;
    case 1:
      ppuVar1 = (ulong **)FUN_0013c014(param_3,&local_8);
      break;
    case 2:
      ppuVar1 = (ulong **)((long)param_3 + 2);
      local_8 = (ulong **)(ulong)*(ushort *)param_3;
      break;
    case 3:
      ppuVar1 = (ulong **)((long)param_3 + 4);
      local_8 = (ulong **)(ulong)*(uint *)param_3;
      break;
    default:
                    // WARNING: Subroutine does not return
      abort();
    case 9:
      ppuVar1 = (ulong **)FUN_0013c03c(param_3,&local_8);
      break;
    case 10:
      ppuVar1 = (ulong **)((long)param_3 + 2);
      local_8 = (ulong **)(long)*(short *)param_3;
      break;
    case 0xb:
      ppuVar1 = (ulong **)((long)param_3 + 4);
      local_8 = (ulong **)(long)(int)*(uint *)param_3;
    }
    if (local_8 != (ulong **)0x0) {
      if ((param_1 & 0x70) != 0x10) {
        param_3 = param_2;
      }
      local_8 = (ulong **)((long)local_8 + (long)param_3);
      if ((char)param_1 < '\0') {
        local_8 = (ulong **)*local_8;
      }
    }
  }
  *param_4 = (ulong *)local_8;
  return ppuVar1;
}



int FUN_0013c41c(long param_1,long param_2,long param_3)

{
  int iVar1;
  ushort uVar2;
  undefined8 uVar3;
  ulong local_10;
  ulong local_8;
  
  uVar2 = *(ushort *)(param_1 + 0x20) >> 3 & 0xff;
  uVar3 = FUN_0013c26c(uVar2,param_1);
  FUN_0013c32c(uVar2,uVar3,param_2 + 8,&local_10);
  FUN_0013c32c(*(ushort *)(param_1 + 0x20) >> 3,uVar3,param_3 + 8,&local_8);
  iVar1 = -(uint)(local_10 < local_8);
  if (local_8 < local_10) {
    iVar1 = 1;
  }
  return iVar1;
}



byte FUN_0013c4ac(long param_1)

{
  char cVar1;
  byte bVar2;
  size_t sVar3;
  undefined8 uVar4;
  long lVar5;
  byte *pbVar6;
  char *pcVar7;
  char *pcVar8;
  undefined auStack_18 [8];
  undefined auStack_10 [8];
  undefined auStack_8 [8];
  
  pcVar8 = (char *)(param_1 + 9);
  sVar3 = strlen(pcVar8);
  pcVar7 = pcVar8 + sVar3 + 1;
  if (3 < *(byte *)(param_1 + 8)) {
    if (pcVar8[sVar3 + 1] != '\b') {
      return 0xff;
    }
    if (pcVar7[1] != '\0') {
      return 0xff;
    }
    pcVar7 = pcVar7 + 2;
  }
  if (*(char *)(param_1 + 9) == 'z') {
    uVar4 = FUN_0013c014(pcVar7,auStack_10);
    lVar5 = FUN_0013c03c(uVar4,auStack_8);
    if (*(char *)(param_1 + 8) == '\x01') {
      lVar5 = lVar5 + 1;
    }
    else {
      lVar5 = FUN_0013c014(lVar5,auStack_10);
    }
    pbVar6 = (byte *)FUN_0013c014(lVar5,auStack_10);
    for (pcVar8 = (char *)(param_1 + 10); cVar1 = *pcVar8, cVar1 != 'R'; pcVar8 = pcVar8 + 1) {
      if (cVar1 == 'P') {
        pbVar6 = (byte *)FUN_0013c32c(*pbVar6 & 0x7f,0,pbVar6 + 1,auStack_18);
      }
      else {
        if (cVar1 != 'L') goto LAB_0013c504;
        pbVar6 = pbVar6 + 1;
      }
    }
    bVar2 = *pbVar6;
  }
  else {
LAB_0013c504:
    bVar2 = 0;
  }
  return bVar2;
}



uint * FUN_0013c5a8(long param_1,uint *param_2,long param_3)

{
  ulong uVar1;
  undefined8 uVar2;
  long lVar3;
  ulong uVar4;
  undefined8 uVar5;
  ulong uVar6;
  long lVar7;
  ulong local_10;
  ulong local_8;
  
  uVar1 = (ulong)(*(ushort *)(param_1 + 0x20) >> 3) & 0xff;
  uVar2 = FUN_0013c26c(uVar1,param_1);
  lVar3 = 0;
  do {
    if (*param_2 == 0) {
      return (uint *)0x0;
    }
    if (param_2[1] != 0) {
      lVar7 = lVar3;
      if (((*(byte *)(param_1 + 0x20) >> 2 & 1) != 0) &&
         (lVar7 = (long)param_2 + (4 - (long)(int)param_2[1]), lVar7 != lVar3)) {
        uVar4 = FUN_0013c4ac(lVar7);
        uVar1 = uVar4 & 0xffffffff;
        uVar2 = FUN_0013c26c(uVar4,param_1);
      }
      if ((uint)uVar1 == 0) {
        local_10 = *(ulong *)(param_2 + 2);
        local_8 = *(ulong *)(param_2 + 4);
        uVar4 = local_10;
      }
      else {
        uVar5 = FUN_0013c32c(uVar1 & 0xff,uVar2,param_2 + 2,&local_10);
        FUN_0013c32c((uint)uVar1 & 0xf,0,uVar5,&local_8);
        uVar4 = FUN_0013c20c(uVar1 & 0xff);
        uVar6 = 0xffffffffffffffff;
        if ((uVar4 & 0xffffffff) < 8) {
          uVar6 = (1L << ((uVar4 & 7) << 3)) - 1;
        }
        uVar4 = uVar6 & local_10;
      }
      lVar3 = lVar7;
      if ((uVar4 != 0) && (param_3 - local_10 < local_8)) {
        return param_2;
      }
    }
    param_2 = (uint *)((long)param_2 + (ulong)*param_2 + 4);
  } while( true );
}



void FUN_0013c708(long param_1)

{
  FUN_0013c4ac((param_1 + 4) - (long)*(int *)(param_1 + 4));
  return;
}



undefined8 FUN_0013c718(ulong *param_1,ulong param_2,ulong *param_3)

{
  long lVar1;
  ulong uVar2;
  char cVar3;
  int iVar4;
  bool bVar5;
  byte bVar6;
  undefined uVar7;
  undefined8 uVar8;
  undefined8 uVar9;
  ulong *puVar10;
  undefined8 *puVar11;
  ulong *puVar12;
  ulong uVar13;
  int *piVar14;
  int *piVar15;
  ulong *puVar16;
  ulong uVar17;
  ulong *puVar18;
  ulong uVar19;
  int *piVar20;
  int *piVar21;
  ulong uVar22;
  undefined8 local_40;
  ulong local_38;
  long local_30;
  ulong local_28;
  ulong local_20;
  undefined8 local_18;
  undefined8 local_10;
  
  piVar14 = (int *)param_1[2];
  uVar17 = *param_1;
  if ((param_2 < 0x30) || (*(int *)(param_3 + 5) == 0)) {
    if (param_2 < 0x1a) {
      return 0xffffffff;
    }
  }
  else {
    if ((param_1[4] == DAT_00163150) && (param_1[5] == DAT_00175020)) {
      puVar18 = DAT_00175028;
      puVar12 = (ulong *)0x0;
      puVar16 = (ulong *)0x0;
      while (puVar10 = puVar18, puVar10 != (ulong *)0x0) {
        if ((*puVar10 <= *param_3) && (*param_3 < puVar10[1])) {
          uVar17 = puVar10[2];
          piVar15 = (int *)puVar10[3];
          if (puVar10 != DAT_00175028) {
            puVar16[5] = puVar10[5];
            puVar10[5] = (ulong)DAT_00175028;
            DAT_00175028 = puVar10;
          }
          goto LAB_0013c924;
        }
        puVar12 = puVar10;
        if ((*puVar10 | puVar10[1]) == 0) break;
        puVar18 = (ulong *)puVar10[5];
        if (puVar18 != (ulong *)0x0) {
          puVar16 = puVar10;
        }
      }
      goto LAB_0013c840;
    }
    puVar11 = &DAT_00175060;
    DAT_00163150 = param_1[4];
    DAT_00175020 = param_1[5];
    do {
      puVar11[-6] = 0;
      puVar11[-5] = 0;
      puVar11[-1] = puVar11;
      puVar11 = puVar11 + 6;
    } while (puVar11 != (undefined8 *)0x1751e0);
    DAT_001751a8 = 0;
    DAT_00175028 = &DAT_00175030;
    *(undefined4 *)(param_3 + 5) = 0;
  }
  puVar16 = (ulong *)0x0;
  puVar12 = (ulong *)0x0;
LAB_0013c840:
  uVar22 = (ulong)*(ushort *)(param_1 + 3);
  uVar13 = 0;
  uVar19 = 0;
  bVar5 = false;
  piVar20 = (int *)0x0;
  piVar15 = (int *)0x0;
  while (uVar22 = uVar22 - 1, uVar22 != 0xffffffffffffffff) {
    iVar4 = *piVar14;
    piVar21 = piVar15;
    if (iVar4 == 1) {
      uVar2 = uVar17 + *(long *)(piVar14 + 4);
      if ((uVar2 <= *param_3) && (*param_3 < uVar2 + *(long *)(piVar14 + 10))) {
        bVar5 = true;
        uVar13 = uVar2 + *(long *)(piVar14 + 10);
        uVar19 = uVar2;
      }
    }
    else {
      piVar21 = piVar14;
      if ((iVar4 != 0x6474e550) && (piVar21 = piVar15, iVar4 == 2)) {
        piVar20 = piVar14;
      }
    }
    piVar14 = piVar14 + 0xe;
    piVar15 = piVar21;
  }
  if (!bVar5) {
    return 0;
  }
  if (param_2 >= 0x30) {
    if ((puVar16 != (ulong *)0x0) && (puVar12 != (ulong *)0x0)) {
      puVar16[5] = puVar12[5];
      puVar12[5] = (ulong)DAT_00175028;
      DAT_00175028 = puVar12;
    }
    puVar12 = DAT_00175028;
    DAT_00175028[2] = uVar17;
    puVar12[3] = (ulong)piVar15;
    puVar12[4] = (ulong)piVar20;
    *puVar12 = uVar19;
    puVar12[1] = uVar13;
  }
LAB_0013c924:
  if (piVar15 == (int *)0x0) {
    return 0;
  }
  lVar1 = uVar17 + *(long *)(piVar15 + 4);
  if (*(char *)(uVar17 + *(long *)(piVar15 + 4)) != '\x01') {
    return 1;
  }
  uVar7 = *(undefined *)(lVar1 + 1);
  uVar8 = FUN_0013c2cc(uVar7,param_3);
  uVar8 = FUN_0013c32c(uVar7,uVar8,lVar1 + 4,&local_40);
  cVar3 = *(char *)(lVar1 + 2);
  if ((cVar3 != -1) && (*(char *)(lVar1 + 3) == ';')) {
    uVar9 = FUN_0013c2cc(cVar3,param_3);
    piVar14 = (int *)FUN_0013c32c(cVar3,uVar9,uVar8,&local_38);
    if (local_38 == 0) {
      return 1;
    }
    if (((ulong)piVar14 & 3) == 0) {
      uVar17 = *param_3;
      if (uVar17 < (ulong)(lVar1 + *piVar14)) {
        return 1;
      }
      local_38 = local_38 - 1;
      if (uVar17 < (ulong)(lVar1 + piVar14[local_38 * 2])) {
        uVar13 = 0;
        uVar19 = local_38;
        do {
          uVar22 = uVar19;
          if (uVar22 <= uVar13) {
                    // WARNING: Subroutine does not return
            abort();
          }
          uVar2 = uVar22 + uVar13;
          local_38 = uVar2 >> 1;
          uVar19 = local_38;
        } while ((uVar17 < (ulong)(lVar1 + piVar14[uVar2 & 0xfffffffffffffffe])) ||
                (uVar13 = local_38 + 1, uVar19 = uVar22,
                (ulong)(lVar1 + piVar14[(uVar2 & 0xfffffffffffffffe) + 2]) <= uVar17));
      }
      uVar17 = lVar1 + piVar14[local_38 * 2 + 1];
      bVar6 = FUN_0013c708(uVar17);
      uVar13 = FUN_0013c20c(bVar6);
      FUN_0013c32c(bVar6 & 0xf,0,uVar17 + (uVar13 & 0xffffffff) + 8,&local_30);
      iVar4 = piVar14[local_38 * 2];
      if (*param_3 < (ulong)(lVar1 + iVar4 + local_30)) {
        param_3[4] = uVar17;
      }
      param_3[3] = lVar1 + iVar4;
      return 1;
    }
  }
  local_28 = param_3[1];
  local_20 = param_3[2];
  local_10 = 4;
  local_30 = 0;
  local_18 = local_40;
  uVar17 = FUN_0013c5a8(&local_30,local_40,*param_3);
  param_3[4] = uVar17;
  if (uVar17 != 0) {
    uVar7 = FUN_0013c708();
    uVar8 = FUN_0013c2cc(uVar7,param_3);
    FUN_0013c32c(uVar7,uVar8,param_3[4] + 8,&local_38);
    param_3[3] = local_38;
  }
  return 1;
}



int FUN_0013cb38(undefined8 param_1,long param_2,long param_3)

{
  int iVar1;
  undefined uVar2;
  undefined8 uVar3;
  ulong local_10;
  ulong local_8;
  
  uVar2 = FUN_0013c708(param_2);
  uVar3 = FUN_0013c26c(uVar2,param_1);
  FUN_0013c32c(uVar2,uVar3,param_2 + 8,&local_10);
  uVar2 = FUN_0013c708(param_3);
  uVar3 = FUN_0013c26c(uVar2,param_1);
  FUN_0013c32c(uVar2,uVar3,param_3 + 8,&local_8);
  iVar1 = -(uint)(local_10 < local_8);
  if (local_8 < local_10) {
    iVar1 = 1;
  }
  return iVar1;
}



long FUN_0013cbd4(ulong *param_1,uint *param_2)

{
  ushort uVar1;
  uint uVar2;
  long lVar3;
  ulong uVar4;
  ulong uVar5;
  long lVar6;
  long lVar7;
  undefined8 uVar8;
  ulong local_8;
  
  uVar8 = 0;
  uVar2 = 0;
  lVar7 = 0;
  lVar3 = 0;
  do {
    if (*param_2 == 0) {
      return lVar7;
    }
    if (param_2[1] != 0) {
      lVar6 = (long)param_2 + (4 - (long)(int)param_2[1]);
      if (lVar6 != lVar3) {
        uVar2 = FUN_0013c4ac(lVar6);
        if (uVar2 == 0xff) {
          return -1;
        }
        uVar8 = FUN_0013c26c((char)uVar2,param_1);
        uVar1 = *(ushort *)(param_1 + 4);
        lVar3 = lVar6;
        if ((uVar1 & 0x7f8) == 0x7f8) {
          *(ushort *)(param_1 + 4) = uVar1 & 0xf800 | uVar1 & 7 | (ushort)((uVar2 & 0xff) << 3);
        }
        else if ((uVar1 >> 3 & 0xff) != uVar2) {
          *(byte *)(param_1 + 4) = *(byte *)(param_1 + 4) | 4;
        }
      }
      FUN_0013c32c(uVar2 & 0xff,uVar8,param_2 + 2,&local_8);
      uVar4 = FUN_0013c20c(uVar2 & 0xff);
      uVar5 = 0xffffffffffffffff;
      if ((uVar4 & 0xffffffff) < 8) {
        uVar5 = (1L << ((uVar4 & 7) << 3)) - 1;
      }
      if (((uVar5 & local_8) != 0) && (lVar7 = lVar7 + 1, local_8 < *param_1)) {
        *param_1 = local_8;
      }
    }
    param_2 = (uint *)((long)param_2 + (ulong)*param_2 + 4);
  } while( true );
}



void FUN_0013cd34(long param_1,long *param_2,uint *param_3)

{
  ulong uVar1;
  undefined8 uVar2;
  long lVar3;
  ulong uVar4;
  ulong uVar5;
  long lVar6;
  long lVar7;
  ulong local_8;
  
  uVar1 = (ulong)(*(ushort *)(param_1 + 0x20) >> 3) & 0xff;
  uVar2 = FUN_0013c26c(uVar1,param_1);
  lVar3 = 0;
  for (; *param_3 != 0; param_3 = (uint *)((long)param_3 + (ulong)*param_3 + 4)) {
    if (param_3[1] != 0) {
      lVar7 = lVar3;
      if (((*(byte *)(param_1 + 0x20) >> 2 & 1) != 0) &&
         (lVar7 = (long)param_3 + (4 - (long)(int)param_3[1]), lVar7 != lVar3)) {
        uVar4 = FUN_0013c4ac(lVar7);
        uVar1 = uVar4 & 0xffffffff;
        uVar2 = FUN_0013c26c(uVar4,param_1);
      }
      if ((int)uVar1 == 0) {
        uVar4 = *(ulong *)(param_3 + 2);
      }
      else {
        FUN_0013c32c(uVar1 & 0xff,uVar2,param_3 + 2,&local_8);
        uVar5 = FUN_0013c20c(uVar1 & 0xff);
        uVar4 = 0xffffffffffffffff;
        if ((uVar5 & 0xffffffff) < 8) {
          uVar4 = (1L << ((uVar5 & 7) << 3)) - 1;
        }
        uVar4 = uVar4 & local_8;
      }
      lVar3 = lVar7;
      if ((uVar4 != 0) && (lVar7 = *param_2, lVar7 != 0)) {
        lVar6 = *(long *)(lVar7 + 8);
        *(long *)(lVar7 + 8) = lVar6 + 1;
        *(uint **)(lVar7 + (lVar6 + 2) * 8) = param_3;
      }
    }
  }
  return;
}



long FUN_0013ce68(ulong *param_1,ulong param_2)

{
  ushort uVar1;
  ushort uVar2;
  ulong *puVar3;
  void *pvVar4;
  byte bVar5;
  uint uVar6;
  int iVar7;
  undefined8 uVar8;
  undefined8 uVar9;
  long lVar10;
  ulong uVar11;
  long *plVar12;
  size_t __size;
  ulong uVar13;
  ulong *puVar14;
  ulong *puVar15;
  code *pcVar16;
  ulong uVar17;
  ulong *puVar18;
  long lVar19;
  ulong uVar20;
  ulong *puVar21;
  ulong local_18;
  ulong *local_10;
  void *local_8;
  
  if ((*(byte *)(param_1 + 4) & 1) != 0) goto LAB_0013ce94;
  uVar17 = (ulong)(*(uint *)(param_1 + 4) >> 0xb);
  if (uVar17 == 0) {
    if ((*(byte *)(param_1 + 4) >> 1 & 1) == 0) {
      uVar17 = FUN_0013cbd4(param_1,param_1[3]);
      if (uVar17 != 0xffffffffffffffff) goto LAB_0013cf0c;
LAB_0013cecc:
      param_1[4] = 0;
      *(undefined2 *)(param_1 + 4) = 0x7f8;
      param_1[3] = (ulong)&DAT_001751b8;
    }
    else {
      for (plVar12 = (long *)param_1[3]; *plVar12 != 0; plVar12 = plVar12 + 1) {
        lVar10 = FUN_0013cbd4(param_1);
        if (lVar10 == -1) goto LAB_0013cecc;
        uVar17 = uVar17 + lVar10;
      }
LAB_0013cf0c:
      uVar6 = (uint)uVar17 & 0x1fffff;
      if (uVar6 == uVar17) {
        uVar6 = *(uint *)(param_1 + 4) & 0x7ff | uVar6 << 0xb;
      }
      else {
        uVar6 = *(uint *)(param_1 + 4) & 0x7ff;
      }
      *(uint *)(param_1 + 4) = uVar6;
      if (uVar17 != 0) goto LAB_0013cf34;
    }
  }
  else {
LAB_0013cf34:
    __size = (uVar17 + 2) * 8;
    local_10 = (ulong *)malloc(__size);
    if (local_10 != (ulong *)0x0) {
      local_10[1] = 0;
      local_8 = malloc(__size);
      if (local_8 != (void *)0x0) {
        *(undefined8 *)((long)local_8 + 8) = 0;
      }
      if ((*(byte *)(param_1 + 4) >> 1 & 1) == 0) {
        FUN_0013cd34(param_1,&local_10,param_1[3]);
      }
      else {
        for (plVar12 = (long *)param_1[3]; *plVar12 != 0; plVar12 = plVar12 + 1) {
          FUN_0013cd34(param_1,&local_10);
        }
      }
      pvVar4 = local_8;
      puVar3 = local_10;
      if ((local_10 != (ulong *)0x0) && (local_10[1] != uVar17)) {
LAB_0013d28c:
                    // WARNING: Subroutine does not return
        abort();
      }
      if ((*(byte *)(param_1 + 4) >> 2 & 1) == 0) {
        if ((*(ushort *)(param_1 + 4) & 0x7f8) == 0) {
          pcVar16 = FUN_0013c07c;
        }
        else {
          pcVar16 = FUN_0013c41c;
        }
      }
      else {
        pcVar16 = FUN_0013cb38;
      }
      if (local_8 == (void *)0x0) {
        FUN_0013c158(param_1,pcVar16,local_10);
      }
      else {
        puVar18 = local_10 + 2;
        uVar20 = local_10[1];
        puVar14 = &DAT_001751b0;
        puVar21 = puVar18;
        for (uVar13 = 0; uVar13 != uVar20; uVar13 = uVar13 + 1) {
          while ((puVar14 != &DAT_001751b0 &&
                 (iVar7 = (*pcVar16)(param_1,*puVar21,*puVar14), iVar7 < 0))) {
            puVar15 = *(ulong **)((long)pvVar4 + (long)puVar14 + (0x10 - (long)puVar18));
            *(undefined8 *)((long)pvVar4 + (long)puVar14 + (0x10 - (long)puVar18)) = 0;
            puVar14 = puVar15;
          }
          *(ulong **)((long)pvVar4 + uVar13 * 8 + 0x10) = puVar14;
          puVar14 = puVar21;
          puVar21 = puVar21 + 1;
        }
        lVar10 = 0;
        uVar13 = 0;
        for (uVar11 = 0; uVar11 != uVar20; uVar11 = uVar11 + 1) {
          if (*(long *)((long)pvVar4 + uVar11 * 8 + 0x10) == 0) {
            lVar19 = lVar10 + 2;
            lVar10 = lVar10 + 1;
            *(ulong *)((long)pvVar4 + lVar19 * 8) = *puVar18;
          }
          else {
            lVar19 = uVar13 + 2;
            uVar13 = uVar13 + 1;
            puVar3[lVar19] = *puVar18;
          }
          puVar18 = puVar18 + 1;
        }
        puVar3[1] = uVar13;
        *(long *)((long)pvVar4 + 8) = lVar10;
        if (*(long *)((long)local_8 + 8) + local_10[1] != uVar17) goto LAB_0013d28c;
        FUN_0013c158(param_1,pcVar16);
        pvVar4 = local_8;
        puVar3 = local_10;
        lVar10 = *(long *)((long)local_8 + 8);
        if (lVar10 != 0) {
          uVar17 = local_10[1];
          lVar19 = lVar10 << 3;
          do {
            lVar10 = lVar10 + -1;
            uVar13 = *(ulong *)((long)pvVar4 + lVar19 + 8);
            puVar18 = puVar3 + uVar17;
            while (uVar17 != 0) {
              iVar7 = (*pcVar16)(param_1,puVar18[1],uVar13);
              if (iVar7 < 1) break;
              *(ulong *)((long)(puVar18 + -1) + lVar19 + 0x10) = puVar18[1];
              uVar17 = uVar17 - 1;
              puVar18 = puVar18 + -1;
            }
            lVar19 = lVar19 + -8;
            puVar3[uVar17 + lVar10 + 2] = uVar13;
          } while (lVar10 != 0);
          puVar3[1] = puVar3[1] + *(long *)((long)pvVar4 + 8);
        }
        free(local_8);
      }
      *local_10 = param_1[3];
      param_1[3] = (ulong)local_10;
      *(byte *)(param_1 + 4) = *(byte *)(param_1 + 4) | 1;
    }
  }
  if (param_2 < *param_1) {
    return 0;
  }
LAB_0013ce94:
  bVar5 = *(byte *)(param_1 + 4);
  if ((bVar5 & 1) == 0) {
    if ((bVar5 >> 1 & 1) == 0) {
      lVar10 = FUN_0013c5a8(param_1,param_1[3],param_2);
      return lVar10;
    }
    for (plVar12 = (long *)param_1[3]; *plVar12 != 0; plVar12 = plVar12 + 1) {
      lVar10 = FUN_0013c5a8(param_1,*plVar12,param_2);
      if (lVar10 != 0) {
        return lVar10;
      }
    }
  }
  else if ((bVar5 >> 2 & 1) == 0) {
    if ((*(ushort *)(param_1 + 4) & 0x7f8) == 0) {
      uVar17 = 0;
      uVar13 = *(ulong *)(param_1[3] + 8);
      while (uVar20 = uVar13, uVar17 < uVar20) {
        uVar13 = uVar20 + uVar17 >> 1;
        lVar10 = *(long *)(param_1[3] + (uVar13 + 2) * 8);
        if (*(ulong *)(lVar10 + 8) <= param_2) {
          if (param_2 < *(ulong *)(lVar10 + 8) + *(long *)(lVar10 + 0x10)) {
            return lVar10;
          }
          uVar17 = uVar13 + 1;
          uVar13 = uVar20;
        }
      }
    }
    else {
      uVar1 = *(ushort *)(param_1 + 4) >> 3;
      uVar2 = uVar1 & 0xff;
      uVar20 = param_1[3];
      uVar17 = 0;
      uVar8 = FUN_0013c26c(uVar2,param_1);
      uVar13 = *(ulong *)(uVar20 + 8);
      while (uVar11 = uVar13, uVar17 < uVar11) {
        uVar13 = uVar11 + uVar17 >> 1;
        lVar10 = *(long *)(uVar20 + (uVar13 + 2) * 8);
        uVar9 = FUN_0013c32c(uVar2,uVar8,lVar10 + 8,&local_18);
        FUN_0013c32c(uVar1 & 0xf,0,uVar9,&local_10);
        if (local_18 <= param_2) {
          if (param_2 < local_18 + (long)local_10) {
            return lVar10;
          }
          uVar17 = uVar13 + 1;
          uVar13 = uVar11;
        }
      }
    }
  }
  else {
    uVar20 = param_1[3];
    uVar17 = 0;
    uVar13 = *(ulong *)(uVar20 + 8);
    while (uVar11 = uVar13, uVar17 < uVar11) {
      uVar13 = uVar11 + uVar17 >> 1;
      lVar10 = *(long *)(uVar20 + (uVar13 + 2) * 8);
      bVar5 = FUN_0013c708(lVar10);
      uVar8 = FUN_0013c26c(bVar5,param_1);
      uVar8 = FUN_0013c32c(bVar5,uVar8,lVar10 + 8,&local_18);
      FUN_0013c32c(bVar5 & 0xf,0,uVar8,&local_10);
      if (local_18 <= param_2) {
        if (param_2 < local_18 + (long)local_10) {
          return lVar10;
        }
        uVar17 = uVar13 + 1;
        uVar13 = uVar11;
      }
    }
  }
  return 0;
}



int * __register_frame_info_bases
                (int *param_1,undefined8 *param_2,undefined8 param_3,undefined8 param_4)

{
  uint uVar1;
  
  if ((param_1 != (int *)0x0) && (*param_1 != 0)) {
    *param_2 = 0xffffffffffffffff;
    param_2[4] = 0;
    param_2[3] = param_1;
    param_2[1] = param_3;
    param_2[2] = param_4;
    *(undefined2 *)(param_2 + 4) = 0x7f8;
    pthread_mutex_lock((pthread_mutex_t *)&DAT_001751c0);
    param_2[5] = DAT_001751e8;
    DAT_001751e8 = param_2;
    uVar1 = pthread_mutex_unlock((pthread_mutex_t *)&DAT_001751c0);
    return (int *)(ulong)uVar1;
  }
  return param_1;
}



void __register_frame_info(undefined8 param_1,undefined8 param_2)

{
  __register_frame_info_bases(param_1,param_2,0,0);
  return;
}



void __register_frame(int *param_1)

{
  void *pvVar1;
  
  if (*param_1 != 0) {
    pvVar1 = malloc(0x30);
    __register_frame_info(param_1,pvVar1);
    return;
  }
  return;
}



// WARNING: Removing unreachable block (ram,0x0013d548)

int __register_frame_info_table_bases
              (undefined8 param_1,undefined8 *param_2,undefined8 param_3,undefined8 param_4)

{
  int iVar1;
  
  param_2[4] = 0;
  param_2[3] = param_1;
  *(undefined *)(param_2 + 4) = 2;
  param_2[1] = param_3;
  *param_2 = 0xffffffffffffffff;
  param_2[2] = param_4;
  *(ushort *)(param_2 + 4) = *(ushort *)(param_2 + 4) | 0x7f8;
  pthread_mutex_lock((pthread_mutex_t *)&DAT_001751c0);
  param_2[5] = DAT_001751e8;
  DAT_001751e8 = param_2;
  iVar1 = pthread_mutex_unlock((pthread_mutex_t *)&DAT_001751c0);
  return iVar1;
}



void __register_frame_info_table(undefined8 param_1,undefined8 param_2)

{
  __register_frame_info_table_bases(param_1,param_2,0,0);
  return;
}



void __register_frame_table(undefined8 param_1)

{
  void *pvVar1;
  
  pvVar1 = malloc(0x30);
  __register_frame_info_table(param_1,pvVar1);
  return;
}



long __deregister_frame_info_bases(int *param_1)

{
  long *plVar1;
  long lVar2;
  
  if ((param_1 == (int *)0x0) || (*param_1 == 0)) {
    return 0;
  }
  pthread_mutex_lock((pthread_mutex_t *)&DAT_001751c0);
  plVar1 = &DAT_001751e8;
  for (lVar2 = DAT_001751e8; lVar2 != 0; lVar2 = *(long *)(lVar2 + 0x28)) {
    if (*(int **)(lVar2 + 0x18) == param_1) goto LAB_0013d61c;
    plVar1 = (long *)(lVar2 + 0x28);
  }
  plVar1 = &DAT_001751f0;
  while (lVar2 = *plVar1, lVar2 != 0) {
    if ((*(byte *)(lVar2 + 0x20) & 1) == 0) {
      if (*(int **)(lVar2 + 0x18) == param_1) goto LAB_0013d61c;
    }
    else if (**(int ***)(lVar2 + 0x18) == param_1) {
      *plVar1 = *(long *)(lVar2 + 0x28);
      free(*(void **)(lVar2 + 0x18));
      break;
    }
    plVar1 = (long *)(lVar2 + 0x28);
  }
LAB_0013d65c:
  pthread_mutex_unlock((pthread_mutex_t *)&DAT_001751c0);
  if (lVar2 != 0) {
    return lVar2;
  }
                    // WARNING: Subroutine does not return
  abort();
LAB_0013d61c:
  *plVar1 = *(long *)(lVar2 + 0x28);
  goto LAB_0013d65c;
}



long __deregister_frame_info(int *param_1)

{
  long *plVar1;
  long lVar2;
  
  if ((param_1 == (int *)0x0) || (*param_1 == 0)) {
    return 0;
  }
  pthread_mutex_lock((pthread_mutex_t *)&DAT_001751c0);
  plVar1 = &DAT_001751e8;
  for (lVar2 = DAT_001751e8; lVar2 != 0; lVar2 = *(long *)(lVar2 + 0x28)) {
    if (*(int **)(lVar2 + 0x18) == param_1) goto LAB_0013d61c;
    plVar1 = (long *)(lVar2 + 0x28);
  }
  plVar1 = &DAT_001751f0;
  while (lVar2 = *plVar1, lVar2 != 0) {
    if ((*(byte *)(lVar2 + 0x20) & 1) == 0) {
      if (*(int **)(lVar2 + 0x18) == param_1) goto LAB_0013d61c;
    }
    else if (**(int ***)(lVar2 + 0x18) == param_1) {
      *plVar1 = *(long *)(lVar2 + 0x28);
      free(*(void **)(lVar2 + 0x18));
      break;
    }
    plVar1 = (long *)(lVar2 + 0x28);
  }
LAB_0013d65c:
  pthread_mutex_unlock((pthread_mutex_t *)&DAT_001751c0);
  if (lVar2 != 0) {
    return lVar2;
  }
                    // WARNING: Subroutine does not return
  abort();
LAB_0013d61c:
  *plVar1 = *(long *)(lVar2 + 0x28);
  goto LAB_0013d65c;
}



void __deregister_frame(int *param_1)

{
  void *__ptr;
  
  if (*param_1 != 0) {
    __ptr = (void *)__deregister_frame_info();
    free(__ptr);
    return;
  }
  return;
}



// WARNING: Removing unreachable block (ram,0x0013d858)

long _Unwind_Find_FDE(ulong param_1,ulong *param_2)

{
  byte bVar1;
  ushort uVar2;
  int iVar3;
  ulong **ppuVar4;
  undefined8 uVar5;
  ulong *puVar6;
  ulong *puVar7;
  ulong local_30;
  ulong local_28;
  ulong local_20;
  ulong local_18;
  long local_10;
  undefined4 local_8;
  
  pthread_mutex_lock((pthread_mutex_t *)&DAT_001751c0);
  for (puVar7 = DAT_001751f0; puVar7 != (ulong *)0x0; puVar7 = (ulong *)puVar7[5]) {
    if (*puVar7 <= param_1) {
      local_10 = FUN_0013ce68(puVar7,param_1);
      if (local_10 != 0) goto LAB_0013d790;
      break;
    }
  }
  do {
    puVar7 = DAT_001751e8;
    if (DAT_001751e8 == (ulong *)0x0) {
      local_10 = 0;
      break;
    }
    DAT_001751e8 = (ulong *)DAT_001751e8[5];
    local_10 = FUN_0013ce68(puVar7,param_1);
    ppuVar4 = &DAT_001751f0;
    for (puVar6 = DAT_001751f0; (puVar6 != (ulong *)0x0 && (*puVar7 <= *puVar6));
        puVar6 = (ulong *)puVar6[5]) {
      ppuVar4 = (ulong **)(puVar6 + 5);
    }
    puVar7[5] = (ulong)puVar6;
    *ppuVar4 = puVar7;
  } while (local_10 == 0);
LAB_0013d790:
  pthread_mutex_unlock((pthread_mutex_t *)&DAT_001751c0);
  if (local_10 == 0) {
    local_8 = 1;
    local_28 = 0;
    local_20 = 0;
    local_18 = 0;
    local_10 = 0;
    local_30 = param_1;
    iVar3 = dl_iterate_phdr(FUN_0013c718,&local_30);
    if (iVar3 < 0) {
      return 0;
    }
    if (local_10 == 0) {
      return 0;
    }
    *param_2 = local_28;
    param_2[1] = local_20;
    local_30 = local_18;
  }
  else {
    *param_2 = puVar7[1];
    bVar1 = *(byte *)(puVar7 + 4);
    param_2[1] = puVar7[2];
    uVar2 = *(ushort *)(puVar7 + 4) >> 3 & 0xff;
    if ((bVar1 >> 2 & 1) != 0) {
      uVar2 = FUN_0013c708(local_10);
    }
    uVar5 = FUN_0013c26c(uVar2 & 0xff,puVar7);
    FUN_0013c32c(uVar2 & 0xff,uVar5,local_10 + 8,&local_30);
  }
  param_2[2] = local_30;
  return local_10;
}


