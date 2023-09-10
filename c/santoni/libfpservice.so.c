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

typedef __time_t time_t;

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

typedef union pthread_condattr_t pthread_condattr_t, *Ppthread_condattr_t;

union pthread_condattr_t {
    char __size[4];
    int __align;
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

typedef dword fpalgo_act_status;

typedef struct BpFingerPrintClient BpFingerPrintClient, *PBpFingerPrintClient;

struct BpFingerPrintClient { // PlaceHolder Structure
};

typedef dword Recognize_Status;

typedef struct BpFingerPrint BpFingerPrint, *PBpFingerPrint;

struct BpFingerPrint { // PlaceHolder Structure
};

typedef struct BpFingerPrintService BpFingerPrintService, *PBpFingerPrintService;

struct BpFingerPrintService { // PlaceHolder Structure
};

typedef dword Register_Status;

typedef dword fingerprint_chip_mode;

typedef struct __class_type_info __class_type_info, *P__class_type_info;

struct __class_type_info { // PlaceHolder Structure
};

typedef struct __foreign_exception __foreign_exception, *P__foreign_exception;

struct __foreign_exception { // PlaceHolder Structure
};

typedef struct __forced_unwind __forced_unwind, *P__forced_unwind;

struct __forced_unwind { // PlaceHolder Structure
};

typedef struct __si_class_type_info __si_class_type_info, *P__si_class_type_info;

struct __si_class_type_info { // PlaceHolder Structure
};

typedef struct __dyncast_result __dyncast_result, *P__dyncast_result;

struct __dyncast_result { // PlaceHolder Structure
};

typedef dword __sub_kind;

typedef struct __upcast_result __upcast_result, *P__upcast_result;

struct __upcast_result { // PlaceHolder Structure
};

typedef struct exception exception, *Pexception;

struct exception { // PlaceHolder Structure
};

typedef struct bad_alloc bad_alloc, *Pbad_alloc;

struct bad_alloc { // PlaceHolder Structure
};

typedef struct bad_exception bad_exception, *Pbad_exception;

struct bad_exception { // PlaceHolder Structure
};

typedef struct type_info type_info, *Ptype_info;

struct type_info { // PlaceHolder Structure
};

typedef struct BpRefBase BpRefBase, *PBpRefBase;

struct BpRefBase { // PlaceHolder Structure
};

typedef struct String16 String16, *PString16;

struct String16 { // PlaceHolder Structure
};

typedef struct sp sp, *Psp;

struct sp { // PlaceHolder Structure
};

typedef struct IBinder IBinder, *PIBinder;

struct IBinder { // PlaceHolder Structure
};

typedef struct wp wp, *Pwp;

struct wp { // PlaceHolder Structure
};

typedef struct BnInterface<android::IFingerPrint> BnInterface<android::IFingerPrint>, *PBnInterface<android::IFingerPrint>;

struct BnInterface<android::IFingerPrint> { // PlaceHolder Structure
};

typedef struct IFingerPrintClient IFingerPrintClient, *PIFingerPrintClient;

struct IFingerPrintClient { // PlaceHolder Structure
};

typedef struct FpService FpService, *PFpService;

struct FpService { // PlaceHolder Structure
};

typedef struct Vector Vector, *PVector;

struct Vector { // PlaceHolder Structure
};

typedef struct BnFingerPrintClient BnFingerPrintClient, *PBnFingerPrintClient;

struct BnFingerPrintClient { // PlaceHolder Structure
};

typedef struct IFingerPrintService IFingerPrintService, *PIFingerPrintService;

struct IFingerPrintService { // PlaceHolder Structure
};

typedef struct Parcel Parcel, *PParcel;

struct Parcel { // PlaceHolder Structure
};

typedef struct BnInterface<android::IFingerPrintClient> BnInterface<android::IFingerPrintClient>, *PBnInterface<android::IFingerPrintClient>;

struct BnInterface<android::IFingerPrintClient> { // PlaceHolder Structure
};

typedef struct IInterface IInterface, *PIInterface;

struct IInterface { // PlaceHolder Structure
};

typedef struct String8 String8, *PString8;

struct String8 { // PlaceHolder Structure
};

typedef struct BnFingerPrintService BnFingerPrintService, *PBnFingerPrintService;

struct BnFingerPrintService { // PlaceHolder Structure
};

typedef struct sp<android::FpService> sp<android::FpService>, *Psp<android::FpService>;

struct sp<android::FpService> { // PlaceHolder Structure
};

typedef struct Mutex Mutex, *PMutex;

struct Mutex { // PlaceHolder Structure
};

typedef struct sp<android::FpService::Client> sp<android::FpService::Client>, *Psp<android::FpService::Client>;

struct sp<android::FpService::Client> { // PlaceHolder Structure
};

typedef struct IFingerPrint IFingerPrint, *PIFingerPrint;

struct IFingerPrint { // PlaceHolder Structure
};

typedef struct RefBase RefBase, *PRefBase;

struct RefBase { // PlaceHolder Structure
};

typedef dword fpContext;

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

typedef struct Elf64_Sym Elf64_Sym, *PElf64_Sym;

struct Elf64_Sym {
    dword st_name;
    byte st_info;
    byte st_other;
    word st_shndx;
    qword st_value;
    qword st_size;
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




void FUN_00112510(void)

{
  (*(code *)(undefined *)0x0)();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void * memcpy(void *__dest,void *__src,size_t __n)

{
  void *pvVar1;
  
  pvVar1 = memcpy(__dest,__src,__n);
  return pvVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void android::Parcel::writeCString(char *param_1)

{
  writeCString(param_1);
  return;
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

void android::String16::size(void)

{
  size();
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

void android::BBinder::pingBinder(void)

{
  pingBinder();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void android::Parcel::writeNoException(void)

{
  writeNoException();
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



// WARNING: Unknown calling convention -- yet parameter storage is locked

tm * localtime(time_t *__timer)

{
  tm *ptVar1;
  
  ptVar1 = localtime(__timer);
  return ptVar1;
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

void android::Parcel::readExceptionCode(void)

{
  readExceptionCode();
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



void entry(void)

{
  __cxa_finalize(&DAT_00146000);
  return;
}



void _INIT_0(void)

{
  pthread_mutex_init((pthread_mutex_t *)android::ProcessRawDataLock,(pthread_mutexattr_t *)0x0);
  __cxa_atexit(android::Mutex::~Mutex,android::ProcessRawDataLock,&DAT_00146000);
  pthread_mutex_init((pthread_mutex_t *)android::mStatusCheckLock,(pthread_mutexattr_t *)0x0);
  __cxa_atexit(android::Mutex::~Mutex,android::mStatusCheckLock,&DAT_00146000);
  return;
}



void _INIT_1(void)

{
  pthread_mutex_init((pthread_mutex_t *)&DAT_00146318,(pthread_mutexattr_t *)0x0);
  __cxa_atexit(android::Mutex::~Mutex,&DAT_00146318,&DAT_00146000);
  return;
}



void _INIT_2(void)

{
  android::String16::String16
            ((String16 *)&android::IFingerPrint::descriptor,"android.hardware.FingerPrint");
  __cxa_atexit(android::String16::~String16,&android::IFingerPrint::descriptor,&DAT_00146000);
  return;
}



void _INIT_3(void)

{
  android::String16::String16
            ((String16 *)&android::IFingerPrintClient::descriptor,
             "android.hardware.FingerPrintClient");
  __cxa_atexit(android::String16::~String16,&android::IFingerPrintClient::descriptor,&DAT_00146000);
  return;
}



void _INIT_4(void)

{
  android::String16::String16
            ((String16 *)&android::IFingerPrintService::descriptor,"android.hardware.IFpService");
  __cxa_atexit(android::String16::~String16,&android::IFingerPrintService::descriptor,&DAT_00146000)
  ;
  return;
}



void _INIT_5(void)

{
  DAT_00147f70 = 0;
  DAT_00147f78 = 0;
  DAT_00147f80 = 0;
  DAT_00147f88 = 0;
  DAT_00147f90 = 0;
  return;
}



void _INIT_6(void)

{
  int iVar1;
  
  DAT_00157fac = 0;
  iVar1 = pthread_key_create(&DAT_00157fa8,FUN_00122768);
  DAT_00157fac = iVar1 == 0;
  __cxa_atexit(FUN_0012274c,&DAT_00157fa8,&DAT_00146000);
  return;
}



void FUN_00112e48(code *param_1)

{
  if (param_1 != (code *)0x0) {
    (*param_1)();
  }
  return;
}



// android::FpService::setDefaultMode()

void __thiscall android::FpService::setDefaultMode(FpService *this)

{
  (**(code **)(*(long *)this + 0x68))(this,*(undefined4 *)(this + 0x2f8));
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
  (**(code **)(*(long *)(this + 0x158) + 0x140))(*(long *)(this + 0x158),param_1);
  *(fingerprint_chip_mode *)(this + 0xe8) = param_1;
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// android::FpService::getChipMode()

void __thiscall android::FpService::getChipMode(FpService *this)

{
  long lVar1;
  
  lVar1 = ___stack_chk_guard;
  (**(code **)(*(long *)(this + 0x158) + 0xa8))(*(long *)(this + 0x158));
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
    *(int *)(this + 0x2f4) = param_1;
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



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// android::FpService::Client::set_fpdb_to_ta(char*)

void __thiscall android::FpService::Client::set_fpdb_to_ta(Client *this,char *param_1)

{
  ulong uVar1;
  uint local_c;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","set_fpdb_to_ta");
  local_c = 0xffffffff;
  uVar1 = (**(code **)(*(long *)this + 0x160))(this);
  if ((int)uVar1 == 0) {
    (**(code **)(*(long *)(this + 0x28) + 0x1a8))(param_1,&local_c);
    __android_log_print(3,"FingerGoodix","set_fpdb_to_ta,result:%d",local_c);
    uVar1 = (ulong)local_c;
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar1);
}



// android::FpService::Client::set_user_id(unsigned long)

void __thiscall android::FpService::Client::set_user_id(Client *this,ulong param_1)

{
  __android_log_print(3,"FingerGoodix","client:set_user_id");
  (**(code **)(*(long *)(this + 0x28) + 0x1b0))(param_1);
  return;
}



// android::FpService::Client::sendScreenState(int)

undefined8 android::FpService::Client::sendScreenState(int param_1)

{
  __android_log_print(3,"FingerGoodix","Client::sendScreenState");
  return 0;
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
  (**(code **)(*(long *)this + 0x160))(this);
  return;
}



// android::FpService::Client::resetRegist()

void __thiscall android::FpService::Client::resetRegist(Client *this)

{
  __android_log_print(3,"FingerGoodix","Client::resetRegist");
  (**(code **)(*(long *)this + 0x160))(this);
  return;
}



// android::FpService::Client::weChatSetSessionId(unsigned long)

void __thiscall android::FpService::Client::weChatSetSessionId(Client *this,ulong param_1)

{
  __android_log_print(3,"FingerGoodix","%s, challenge = %ld",
                      "virtual android::status_t android::FpService::Client::weChatSetSessionId(uint64_t)"
                      ,param_1);
  (**(code **)(*(long *)(this + 0x28) + 0x1d0))(*(long *)(this + 0x28),param_1);
  return;
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
  (**(code **)(*(long *)(this + 0x158) + 0x1c0))(*(long *)(this + 0x158));
  sem_getvalue((sem_t *)&DAT_00146040,&local_c);
  if (local_c == 0) {
    sem_post((sem_t *)&DAT_00146040);
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
  
  __mutex = (pthread_mutex_t *)(this + 0xbc);
  pthread_mutex_lock(__mutex);
                    // try { // try from 001134c0 to 001134c3 has its CatchHandler @ 001135e8
  __android_log_print(3,"FingerGoodix","mCurStatus = %d , nextStatus = %d",
                      *(undefined4 *)(this + 0xe4),param_1);
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
  case 0x10:
    *(fpalgo_act_status *)(this + 0xe4) = param_1;
    pthread_mutex_unlock(__mutex);
    return 0;
  case 2:
    switch(*(undefined4 *)(this + 0xe4)) {
    case 0:
    case 1:
    case 3:
    case 5:
    case 6:
    case 7:
    case 8:
      uVar1 = 0;
      *(undefined4 *)(this + 0xe4) = 2;
      goto LAB_001134d0;
    case 2:
switchD_00113524_caseD_6:
      pthread_mutex_unlock(__mutex);
      return 0;
    }
    break;
  case 4:
    uVar1 = 0xffffffff;
    if (*(int *)(this + 0xe4) - 2U < 2) {
      *(undefined4 *)(this + 0xe4) = 4;
      pthread_mutex_unlock(__mutex);
      return 0xffffffff;
    }
    goto LAB_001134d0;
  case 6:
    switch(*(undefined4 *)(this + 0xe4)) {
    case 0:
    case 1:
    case 2:
    case 3:
    case 5:
    case 7:
    case 8:
      uVar1 = 0;
      *(undefined4 *)(this + 0xe4) = 6;
      goto LAB_001134d0;
    case 6:
      goto switchD_00113524_caseD_6;
    }
  }
  uVar1 = 0xffffffff;
LAB_001134d0:
  pthread_mutex_unlock(__mutex);
  return uVar1;
}



// android::FpService::Client::regist()

int __thiscall android::FpService::Client::regist(Client *this)

{
  int iVar1;
  long *plVar2;
  
  __android_log_print(3,"FingerGoodix","JEM,Client::register %d",
                      *(undefined4 *)(*(long *)(this + 0x38) + 0xe4));
  iVar1 = (**(code **)(*(long *)this + 0x160))(this);
  if (iVar1 != 0) {
    return iVar1;
  }
  pthread_mutex_lock((pthread_mutex_t *)ProcessRawDataLock);
  plVar2 = *(long **)(this + 0x38);
  if ((*(int *)((long)plVar2 + 0xe4) == 0) || (*(int *)((long)plVar2 + 0xe4) == 7)) {
                    // try { // try from 001136e8 to 001136eb has its CatchHandler @ 001136fc
    __android_log_print(6,"FingerGoodix","JEM,Client::register FAILED,CHECK STATUS!");
    iVar1 = -1;
    pthread_mutex_unlock((pthread_mutex_t *)ProcessRawDataLock);
  }
  else {
                    // try { // try from 00113688 to 001136b7 has its CatchHandler @ 001136fc
    (**(code **)(*plVar2 + 0x88))(plVar2,*(undefined4 *)(this + 0x48));
    (**(code **)(**(long **)(this + 0x38) + 0x80))(*(long **)(this + 0x38),2);
    (**(code **)(**(long **)(this + 0x38) + 0x90))(*(long **)(this + 0x38));
    iVar1 = 0;
    pthread_mutex_unlock((pthread_mutex_t *)ProcessRawDataLock);
  }
  return iVar1;
}



// android::FpService::Client::cancelRegist()

undefined8 __thiscall android::FpService::Client::cancelRegist(Client *this)

{
  long *plVar1;
  
  __android_log_print(3,"FingerGoodix","Client::cancelRegist");
  pthread_mutex_lock((pthread_mutex_t *)mStatusCheckLock);
  if (*(int *)(*(long *)(this + 0x38) + 0x2f4) == *(int *)(this + 0x48)) {
                    // try { // try from 001137a0 to 001137ef has its CatchHandler @ 00113810
    (**(code **)(*(long *)(this + 0x28) + 0xc0))(*(long *)(this + 0x28));
    plVar1 = *(long **)(this + 0x38);
    if (*(int *)((long)plVar1 + 0xe4) - 2U < 3) {
      (**(code **)(*plVar1 + 0x80))(plVar1,5);
      (**(code **)(*(long *)(this + 0x28) + 0x1b8))(*(long *)(this + 0x28));
      (**(code **)(**(long **)(this + 0x38) + 0x80))(*(long **)(this + 0x38),1);
      pthread_mutex_unlock((pthread_mutex_t *)mStatusCheckLock);
      return 0;
    }
  }
  else {
                    // try { // try from 00113770 to 00113773 has its CatchHandler @ 00113810
    __android_log_print(3,"FingerGoodix","false!current notify id:%d,clientID:%d");
  }
  pthread_mutex_unlock((pthread_mutex_t *)mStatusCheckLock);
  return 0xffffffff;
}



// android::FpService::Client::saveRegist(int)

int android::FpService::Client::saveRegist(int param_1)

{
  int iVar1;
  long *plVar2;
  
  plVar2 = (long *)(ulong)(uint)param_1;
  __android_log_print(3,"FingerGoodix","Client::saveRegist curStatus = %d",
                      *(undefined4 *)(plVar2[7] + 0xe4));
  iVar1 = (**(code **)(*plVar2 + 0x160))(plVar2);
  if (iVar1 != 0) {
    return iVar1;
  }
  pthread_mutex_lock((pthread_mutex_t *)mStatusCheckLock);
  if (*(int *)(plVar2[7] + 0xe4) == 4) {
                    // try { // try from 001138ec to 0011390b has its CatchHandler @ 00113910
    iVar1 = (**(code **)(*plVar2 + 0xa8))(plVar2,"goodix");
    (**(code **)(*(long *)plVar2[7] + 0x80))((long *)plVar2[7],1);
  }
  else {
                    // try { // try from 001138b4 to 001138b7 has its CatchHandler @ 00113910
    __android_log_print(6,"FingerGoodix","Client::saveRegist , Enroll not complete!");
    iVar1 = -1;
  }
  pthread_mutex_unlock((pthread_mutex_t *)mStatusCheckLock);
  return iVar1;
}



// android::FpService::Client::cancelRecognize()

undefined8 __thiscall android::FpService::Client::cancelRecognize(Client *this)

{
  int iVar1;
  
  __android_log_print(3,"FingerGoodix","Client::cancelRecognize %d",
                      *(undefined4 *)(*(long *)(this + 0x38) + 0xe4));
  pthread_mutex_lock((pthread_mutex_t *)mStatusCheckLock);
  if (*(int *)(*(long *)(this + 0x38) + 0x2f4) != *(int *)(this + 0x48)) {
                    // try { // try from 0011398c to 0011398f has its CatchHandler @ 00113a78
    __android_log_print(3,"FingerGoodix","false!current notify id:%d,clientID:%d");
LAB_00113990:
    pthread_mutex_unlock((pthread_mutex_t *)mStatusCheckLock);
    return 0xffffffff;
  }
  iVar1 = *(int *)(*(long *)(this + 0x38) + 0xe4);
  if ((iVar1 == 8) || (iVar1 == 1)) {
    __android_log_print(3,"FingerGoodix","Already canceled!");
  }
  else {
    if (1 < iVar1 - 6U) {
                    // try { // try from 001139e0 to 001139fb has its CatchHandler @ 00113a78
      __android_log_print(3,"FingerGoodix","Cancel Failed. status:%d!");
      goto LAB_00113990;
    }
                    // try { // try from 00113a2c to 00113a6f has its CatchHandler @ 00113a78
    __android_log_print(3,"FingerGoodix","Cancel status:%d\n");
    (**(code **)(**(long **)(this + 0x38) + 0x80))(*(long **)(this + 0x38),8);
    (**(code **)(*(long *)(this + 0x28) + 0x1b8))(*(long *)(this + 0x28));
    (**(code **)(**(long **)(this + 0x38) + 0x80))(*(long **)(this + 0x38),1);
  }
  pthread_mutex_unlock((pthread_mutex_t *)mStatusCheckLock);
  return 0;
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
// android::FpService::Client::load_all_fpdata(void*)

void __thiscall android::FpService::Client::load_all_fpdata(Client *this,void *param_1)

{
  int iVar1;
  undefined auStack_408 [1024];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","load_all_fpdata");
  memset(auStack_408,0,0x400);
  iVar1 = (**(code **)(*(long *)this + 0x160))(this);
  if (iVar1 == 0) {
    __android_log_print(3,"FingerGoodix","prepare to load_all_fpdata.");
    (**(code **)(*(long *)(this + 0x28) + 0x1a0))(auStack_408);
    memcpy(param_1,auStack_408,0x80);
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(iVar1);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// android::FpService::Client::recognize(void*)

void __thiscall android::FpService::Client::recognize(Client *this,void *param_1)

{
  undefined8 uVar1;
  int iVar2;
  undefined8 uVar3;
  long lVar4;
  long lVar5;
  long local_10;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","FpService::Client::recognize");
                    // WARNING: Load size is inaccurate
  calculate_token_t = *param_1;
  DAT_001462c8 = *(undefined8 *)((long)param_1 + 8);
  DAT_001462d0 = *(undefined8 *)((long)param_1 + 0x10);
  DAT_001462d8 = *(undefined8 *)((long)param_1 + 0x18);
  DAT_001462e0 = *(undefined8 *)((long)param_1 + 0x20);
  DAT_001462e8 = *(undefined8 *)((long)param_1 + 0x28);
  DAT_001462f0 = *(undefined8 *)((long)param_1 + 0x30);
  DAT_001462f8 = *(undefined8 *)((long)param_1 + 0x38);
  DAT_00146300 = *(undefined4 *)((long)param_1 + 0x40);
  DAT_00146304 = *(undefined *)((long)param_1 + 0x44);
  uVar3 = (**(code **)(*(long *)this + 0x160))(this);
  if ((int)uVar3 == 0) {
    if (*(int *)(*(long *)(this + 0x38) + 0xe4) - 6U < 2) {
      __android_log_print(3,"FingerGoodix","Already recognize.");
      uVar3 = 0;
    }
    else {
      pthread_mutex_lock((pthread_mutex_t *)ProcessRawDataLock);
                    // try { // try from 00113c88 to 00113d1b has its CatchHandler @ 00113d88
      (**(code **)(**(long **)(this + 0x38) + 0x80))(*(long **)(this + 0x38),6);
      lVar5 = *(long *)(this + 0x38);
      *(undefined4 *)(lVar5 + 0x9c) = 5;
      uVar1 = DAT_00146058;
      uVar3 = DAT_00146050;
      *(undefined8 *)(lVar5 + 0x94) = DAT_00146060;
      *(undefined8 *)(lVar5 + 0x84) = uVar3;
      *(undefined8 *)(lVar5 + 0x8c) = uVar1;
      iVar2 = (**(code **)(*(long *)(this + 0x28) + 0x1d8))(*(long *)(this + 0x28),&local_10);
      if ((iVar2 == 0) && (local_10 != 0)) {
        lVar5 = *(long *)(this + 0x38);
        *(undefined4 *)(lVar5 + 0x80) = 3;
      }
      else {
        lVar5 = *(long *)(this + 0x38);
        *(undefined4 *)(lVar5 + 0x80) = 0;
      }
      lVar4 = *(long *)(this + 0x28);
      *(undefined *)(lVar5 + 0x160) = 0;
      (**(code **)(lVar4 + 0xa0))(lVar4,0);
      (**(code **)(**(long **)(this + 0x38) + 0x88))
                (*(long **)(this + 0x38),*(undefined4 *)(this + 0x48));
      (**(code **)(**(long **)(this + 0x38) + 0x90))(*(long **)(this + 0x38));
      pthread_mutex_unlock((pthread_mutex_t *)ProcessRawDataLock);
      uVar3 = 0;
    }
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar3);
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
  uVar2 = (**(code **)(*(long *)this + 0x160))(this);
  if ((int)uVar2 == 0) {
    if (*(int *)(*(long *)(this + 0x38) + 0xe4) - 6U < 2) {
      __android_log_print(3,"FingerGoodix","Already recognizeWithRestrict.");
      uVar2 = 0;
    }
    else {
      pthread_mutex_lock((pthread_mutex_t *)ProcessRawDataLock);
                    // try { // try from 00113e38 to 00113ec3 has its CatchHandler @ 00113f34
      (**(code **)(**(long **)(this + 0x38) + 0x80))(*(long **)(this + 0x38),6);
      iVar1 = (**(code **)(*(long *)(this + 0x28) + 0x1d8))(*(long *)(this + 0x28),&local_10);
      if ((iVar1 == 0) && (local_10 != 0)) {
        lVar3 = *(long *)(this + 0x38);
        *(undefined4 *)(lVar3 + 0x80) = 3;
      }
      else {
        lVar3 = *(long *)(this + 0x38);
        *(uint *)(lVar3 + 0x80) = param_3;
      }
      *(uint *)(lVar3 + 0x9c) = param_2;
      *(undefined8 *)(lVar3 + 0x84) = 0;
      *(undefined8 *)(lVar3 + 0x8c) = 0;
      *(undefined8 *)(lVar3 + 0x94) = 0;
      memcpy((void *)(*(long *)(this + 0x38) + 0x84),param_1,(ulong)param_2 << 2);
      (**(code **)(*(long *)(this + 0x28) + 0xa0))(*(long *)(this + 0x28),0);
      (**(code **)(**(long **)(this + 0x38) + 0x88))
                (*(long **)(this + 0x38),*(undefined4 *)(this + 0x48));
      (**(code **)(**(long **)(this + 0x38) + 0x90))(*(long **)(this + 0x38));
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
  undefined8 uVar1;
  undefined8 uVar2;
  int iVar3;
  long lVar4;
  
  __android_log_print(3,"FingerGoodix","Client::recognizeFido. \n");
  iVar3 = (**(code **)(*(long *)this + 0x160))(this);
  if (iVar3 != 0) {
    return iVar3;
  }
  pthread_mutex_lock((pthread_mutex_t *)ProcessRawDataLock);
                    // try { // try from 00113fe0 to 001140a7 has its CatchHandler @ 001140ec
  (**(code **)(**(long **)(this + 0x38) + 0x80))(*(long **)(this + 0x38),6);
  lVar4 = *(long *)(this + 0x38);
  *(undefined4 *)(lVar4 + 0x9c) = 5;
  uVar2 = DAT_00146058;
  uVar1 = DAT_00146050;
  *(undefined8 *)(lVar4 + 0x94) = DAT_00146060;
  *(undefined8 *)(lVar4 + 0x84) = uVar1;
  *(undefined8 *)(lVar4 + 0x8c) = uVar2;
  __android_log_print(3,"FingerGoodix","Set Fido Verify.\n");
  lVar4 = *(long *)(this + 0x38);
  *(undefined *)(lVar4 + 0x160) = 1;
  if ((param_2 < 0x21) && (param_4 < 0x21)) {
    *(int *)(lVar4 + 0x184) = param_2;
    *(int *)(lVar4 + 0x1a8) = param_4;
    memcpy((void *)(lVar4 + 0x164),param_1,(long)param_2);
    memcpy((void *)(*(long *)(this + 0x38) + 0x188),param_3,(long)param_4);
    (**(code **)(*(long *)(this + 0x28) + 0xa0))(*(long *)(this + 0x28),0);
    (**(code **)(**(long **)(this + 0x38) + 0x88))
              (*(long **)(this + 0x38),*(undefined4 *)(this + 0x48));
    (**(code **)(**(long **)(this + 0x38) + 0x90))(*(long **)(this + 0x38));
    iVar3 = 0;
  }
  else {
                    // try { // try from 001140e0 to 001140e3 has its CatchHandler @ 001140ec
    __android_log_print(6,"FingerGoodix",
                        "Client::recognizeFido: aaidbuf or finalchanllenge_buf overflow");
    iVar3 = -1;
  }
  pthread_mutex_unlock((pthread_mutex_t *)ProcessRawDataLock);
  return iVar3;
}



// android::FpService::Client::setPasswd(char const*, char const*)

ulong __thiscall android::FpService::Client::setPasswd(Client *this,char *param_1,char *param_2)

{
  int iVar1;
  ulong uVar2;
  size_t sVar3;
  size_t sVar4;
  long lVar5;
  
  __android_log_print(3,"FingerGoodix","Client::setPasswd,%s,%s",param_1,param_2);
  uVar2 = (**(code **)(*(long *)this + 0x160))(this);
  if ((int)uVar2 == 0) {
    if ((param_1 == (char *)0x0) || (param_2 == (char *)0x0)) {
      __android_log_print(3,"FingerGoodix","old password or new password is NULL");
      return 0x85;
    }
    pthread_mutex_lock((pthread_mutex_t *)(this + 0x78));
                    // try { // try from 0011417c to 001141cf has its CatchHandler @ 00114284
    iVar1 = (**(code **)(**(long **)(this + 0x38) + 0x70))(*(long **)(this + 0x38));
    if (iVar1 == 0) {
                    // try { // try from 0011423c to 0011427f has its CatchHandler @ 00114284
      (**(code **)(*(long *)(this + 0x28) + 0x140))(*(long *)(this + 0x28),2);
      __android_log_print(3,"FingerGoodix","it is in MODE_IMAGE,set it to MODE_KEY");
    }
    lVar5 = *(long *)(this + 0x28);
    sVar3 = strlen(param_1);
    sVar4 = strlen(param_2);
    uVar2 = (**(code **)(lVar5 + 0x100))(lVar5,param_1,sVar3 & 0xffffffff,param_2,sVar4);
    uVar2 = uVar2 & 0xffffffff;
    iVar1 = (**(code **)(**(long **)(this + 0x38) + 0x70))(*(long **)(this + 0x38));
    if (iVar1 == 1) {
      (**(code **)(*(long *)(this + 0x28) + 0x140))(*(long *)(this + 0x28),0);
      __android_log_print(3,"FingerGoodix","set it back to MODE_IMAGE");
    }
    pthread_mutex_unlock((pthread_mutex_t *)(this + 0x78));
  }
  return uVar2;
}



// android::FpService::Client::checkPasswd(char const*)

ulong __thiscall android::FpService::Client::checkPasswd(Client *this,char *param_1)

{
  int iVar1;
  ulong uVar2;
  size_t sVar3;
  long lVar4;
  
  __android_log_print(3,"FingerGoodix","Client::checkPasswd :%s",param_1);
  uVar2 = (**(code **)(*(long *)this + 0x160))(this);
  if ((int)uVar2 == 0) {
    if (param_1 == (char *)0x0) {
      __android_log_print(3,"FingerGoodix","passwd is null");
      return 0x85;
    }
    pthread_mutex_lock((pthread_mutex_t *)(this + 0x78));
                    // try { // try from 00114308 to 0011436f has its CatchHandler @ 001143f0
    iVar1 = (**(code **)(**(long **)(this + 0x38) + 0x70))(*(long **)(this + 0x38));
    if (iVar1 == 0) {
      (**(code **)(*(long *)(this + 0x28) + 0x140))(*(long *)(this + 0x28),2);
      __android_log_print(3,"FingerGoodix","it is in MODE_IMAGE,set it to MODE_KEY");
    }
    lVar4 = *(long *)(this + 0x28);
    sVar3 = strlen(param_1);
    uVar2 = (**(code **)(lVar4 + 0x108))(lVar4,param_1,sVar3);
    uVar2 = uVar2 & 0xffffffff;
    iVar1 = (**(code **)(**(long **)(this + 0x38) + 0x70))(*(long **)(this + 0x38));
    if (iVar1 == 1) {
                    // try { // try from 001143d4 to 001143eb has its CatchHandler @ 001143f0
      (**(code **)(*(long *)(this + 0x28) + 0x140))(*(long *)(this + 0x28),0);
      __android_log_print(3,"FingerGoodix","set it back to MODE_IMAGE");
    }
    pthread_mutex_unlock((pthread_mutex_t *)(this + 0x78));
  }
  return uVar2;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// android::FpService::dump(int, android::Vector<android::String16> const&)

void android::FpService::dump(int param_1,Vector *param_2)

{
  String8 aSStack_10 [8];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  android::String8::String8(aSStack_10);
  android::String8::~String8(aSStack_10);
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(0);
}



// non-virtual thunk to android::FpService::dump(int, android::Vector<android::String16> const&)

void __thiscall android::FpService::dump(FpService *this,int param_1,Vector *param_2)

{
  dump((int)this + -8,(Vector *)(ulong)(uint)param_1);
  return;
}



// android::BnInterface<android::IFingerPrint>::queryLocalInterface(android::String16 const&)

void __thiscall android::BnInterface<>::queryLocalInterface(BnInterface<> *this,String16 *param_1)

{
  undefined8 uVar1;
  int iVar2;
  undefined8 uVar3;
  undefined8 uVar4;
  BnInterface<> **in_x8;
  undefined8 uVar5;
  
  uVar5 = *(undefined8 *)param_1;
  uVar3 = android::String16::size();
  uVar1 = IFingerPrint::descriptor;
  uVar4 = android::String16::size();
  iVar2 = strzcmp16(uVar5,uVar3,uVar1,uVar4);
  if (iVar2 == 0) {
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
  undefined8 uVar1;
  int iVar2;
  undefined8 uVar3;
  undefined8 uVar4;
  BnInterface<> **in_x8;
  undefined8 uVar5;
  
  uVar5 = *(undefined8 *)param_1;
  uVar3 = android::String16::size();
  uVar1 = IFingerPrintService::descriptor;
  uVar4 = android::String16::size();
  iVar2 = strzcmp16(uVar5,uVar3,uVar1,uVar4);
  if (iVar2 == 0) {
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



// android::FpService::getClientLockById(int)

FpService * __thiscall android::FpService::getClientLockById(FpService *this,int param_1)

{
  FpService *pFVar1;
  
  if ((uint)param_1 < 7) {
    pFVar1 = this + (long)param_1 * 0x28 + 0x1d8;
  }
  else {
    __android_log_print(3,"FingerGoodix","Failed to getClientLockById,invalide fingerprint Id:%d",
                        param_1);
    pFVar1 = (FpService *)0x0;
  }
  return pFVar1;
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
  iVar1 = (**(code **)(*(long *)this + 0x160))(this);
  if (iVar1 == 0) {
    local_10[0] = param_1;
    (**(code **)(*(long *)this + 0xe0))(this,local_10,1);
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
  iVar2 = (**(code **)(*(long *)this + 0x160))(this);
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
  uVar2 = (**(code **)(*(long *)this + 0x160))(this);
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
  iVar1 = (**(code **)(*(long *)this + 0x160))(this);
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
  uVar2 = (**(code **)(*(long *)this + 0x160))(this);
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
          (**(code **)(*(long *)this + 0x108))(this,param_2[lVar4],param_3[lVar4]);
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
  uVar1 = (**(code **)(*(long *)this + 0x160))(this);
  if ((int)uVar1 == 0) {
    if ((param_4 == (void *)0x0 || param_5 == (uint *)0x0) || (param_2 == (void *)0x0)) {
      __android_log_print(6,"FingerGoodix","some of the params is NULL in getFpTemplateList");
      uVar1 = 0xffffffff;
    }
    else {
      uVar1 = (**(code **)(*(long *)(this + 0x28) + 0x1c8))
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
  iVar1 = (**(code **)(*(long *)(this + 0x28) + 0x268))(*(long *)(this + 0x28));
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
  iVar1 = (**(code **)(*(long *)(this + 0x28) + 0x270))(*(long *)(this + 0x28));
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
  iVar1 = (**(code **)(*(long *)(this + 0x28) + 0x278))(*(long *)(this + 0x28),param_1);
  if (iVar1 == 0) {
    __android_log_print(3,"FingerGoodix","set_recognize_flag run ok");
  }
  return 0;
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
  uVar1 = (**(code **)(*(long *)this + 0x160))(this);
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
      iVar2 = (**(code **)(lVar3 + 0xe8))(this,__ptr,&local_c);
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
  uVar3 = (**(code **)(*(long *)this + 0x160))(this);
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
          goto LAB_00114f24;
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
LAB_00114f24:
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
  uVar2 = (**(code **)(*(long *)this + 0x160))(this);
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
  uVar3 = (**(code **)(*(long *)this + 0x160))(this);
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



// android::FpService::Client::setSafeClass(unsigned int)

int __thiscall android::FpService::Client::setSafeClass(Client *this,uint param_1)

{
  int iVar1;
  
  if (*(int *)(*(long *)(this + 0x38) + 0xe4) == 0) {
    __android_log_print(6,"FingerGoodix","%s, service is failed to init, nothing to do, just return"
                        ,
                        "virtual android::status_t android::FpService::Client::setSafeClass(uint32_t)"
                       );
    return 0x81;
  }
  __android_log_print(6,"FingerGoodix","FpService::Client::setSafeClass , enter, safeClass:%d",
                      param_1);
  iVar1 = (**(code **)(*(long *)(this + 0x28) + 0x290))(*(long *)(this + 0x28),param_1);
  if (iVar1 == 0) {
    DAT_00146008 = param_1;
  }
  __android_log_print(3,"FingerGoodix",
                      "FpService::Client::setSafeClass fnCa_SetSafeClass return:0x%08X",iVar1);
  return iVar1;
}



// android::FpService::~FpService()

void __thiscall android::FpService::~FpService(FpService *this)

{
  int iVar1;
  long *plVar2;
  long **pplVar3;
  pthread_mutex_t *__mutex;
  
  *(undefined8 *)this = 0x141b08;
  *(undefined8 *)(this + 0x300) = 0x141c78;
  *(undefined8 *)(this + 8) = 0x141bb8;
  pplVar3 = (long **)(this + 0x58);
  __android_log_print(6,"FingerGoodix","FingerPrintService is ~FpService()");
  __android_log_print(3,"FingerGoodix","but finger print is busy");
  DAT_00146068 = 0;
  if (*(long *)(this + 0x158) != 0) {
    (**(code **)(*(long *)(this + 0x158) + 0x98))();
    (**(code **)(*(long *)(this + 0x158) + 0x88))(*(long *)(this + 0x158));
    *(undefined4 *)(this + 0x2f0) = 1;
    iVar1 = (**(code **)(*(long *)(this + 0x158) + 0x160))(*(long *)(this + 0x158));
    if (iVar1 == 0) {
      __android_log_print(3,"FingerGoodix","success to disable device");
    }
    else {
      __android_log_print(3,"FingerGoodix","failed to disable device");
    }
    __android_log_print(3,"FingerGoodix","FpService::~FpService(),fnCa_CloseSession");
  }
  __mutex = (pthread_mutex_t *)(this + 0x2f0);
  do {
    __mutex = __mutex + -1;
    pthread_mutex_destroy(__mutex);
  } while ((pthread_mutex_t *)(this + 0x1d8) != __mutex);
  pthread_mutex_destroy((pthread_mutex_t *)(this + 0x1b0));
  pthread_mutex_destroy((pthread_mutex_t *)(this + 0x11c));
  pthread_cond_destroy((pthread_cond_t *)(this + 0xec));
  pthread_mutex_destroy((pthread_mutex_t *)(this + 0xbc));
  do {
    pplVar3 = pplVar3 + -1;
    plVar2 = *pplVar3;
    if (plVar2 != (long *)0x0) {
      android::RefBase::decStrong((void *)((long)plVar2 + *(long *)(*plVar2 + -0x18)));
    }
  } while ((long **)(this + 0x20) != pplVar3);
  *(undefined **)this = &DAT_001417b8;
  *(undefined **)(this + 0x300) = &DAT_001418c8;
  *(undefined ***)(this + 8) = &PTR_queryLocalInterface_00141808;
  android::BBinder::~BBinder((BBinder *)(this + 8));
  IFingerPrintService::~IFingerPrintService((IFingerPrintService *)this);
  android::RefBase::~RefBase((RefBase *)(this + 0x300));
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



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// android::FpService::set_prop_goodix_fp(char)

void __thiscall android::FpService::set_prop_goodix_fp(FpService *this,char param_1)

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
  
  local_18 = 0;
  local_8 = ___stack_chk_guard;
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
  local_10 = 0;
  local_c = 0;
  uVar1 = property_get("persist.sys.fp.goodix",&local_68,0);
  __android_log_print(3,"FingerGoodix","getprop[%s] return: %d, prop: %s","persist.sys.fp.goodix",
                      uVar1,&local_68);
  iVar2 = property_set("persist.sys.fp.goodix",&local_68);
  __android_log_print(3,"FingerGoodix","setprop[%s] to \'%s\', return: %d","persist.sys.fp.goodix",
                      &local_68,iVar2);
  if (iVar2 != 0) {
    __android_log_print(6,"FingerGoodix","Failed to setprop[%s]","persist.sys.fp.goodix");
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
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



// android::FpService::FpService()

void __thiscall android::FpService::FpService(FpService *this)

{
  long lVar1;
  long *in_x1;
  pthread_mutex_t *__mutex;
  
  IFingerPrintService::IFingerPrintService((IFingerPrintService *)this);
                    // try { // try from 001157e8 to 001157eb has its CatchHandler @ 0011593c
  android::BBinder::BBinder((BBinder *)(this + 8));
  lVar1 = in_x1[2];
  *(long *)this = lVar1;
  *(long *)(this + *(long *)(lVar1 + -0x18)) = in_x1[0xb];
  *(long *)(this + 8) = in_x1[0xc];
  lVar1 = in_x1[1];
  *(long *)this = lVar1;
  *(long *)(this + *(long *)(lVar1 + -0x18)) = in_x1[0xd];
  *(long *)(this + 8) = in_x1[0xe];
  lVar1 = *in_x1;
  *(long *)this = lVar1;
  *(long *)(this + *(long *)(lVar1 + -0x18)) = in_x1[0xf];
  *(long *)(this + 8) = in_x1[0x10];
  *(undefined8 *)(this + 0x28) = 0;
  *(undefined8 *)(this + 0x20) = 0;
  *(undefined8 *)(this + 0x38) = 0;
  *(undefined8 *)(this + 0x30) = 0;
  *(undefined8 *)(this + 0x48) = 0;
  *(undefined8 *)(this + 0x40) = 0;
  *(undefined8 *)(this + 0x50) = 0;
                    // try { // try from 0011586c to 0011586f has its CatchHandler @ 00115a1c
  pthread_mutex_init((pthread_mutex_t *)(this + 0xbc),(pthread_mutexattr_t *)0x0);
                    // try { // try from 0011587c to 0011587f has its CatchHandler @ 00115a14
  pthread_cond_init((pthread_cond_t *)(this + 0xec),(pthread_condattr_t *)0x0);
                    // try { // try from 0011588c to 0011588f has its CatchHandler @ 00115a0c
  pthread_mutex_init((pthread_mutex_t *)(this + 0x11c),(pthread_mutexattr_t *)0x0);
  this[0x1ac] = (FpService)0x0;
                    // try { // try from 001158a0 to 001158a3 has its CatchHandler @ 00115a04
  pthread_mutex_init((pthread_mutex_t *)(this + 0x1b0),(pthread_mutexattr_t *)0x0);
  __mutex = (pthread_mutex_t *)(this + 0x1d8);
  lVar1 = 6;
  do {
                    // try { // try from 001158b8 to 001158bb has its CatchHandler @ 00115974
    pthread_mutex_init(__mutex,(pthread_mutexattr_t *)0x0);
    lVar1 = lVar1 + -1;
    __mutex = __mutex + 1;
  } while (lVar1 != -1);
  DAT_00146050._0_4_ = 1;
  DAT_00146050._4_4_ = 2;
  *(undefined4 *)(this + 0x2f8) = 1;
  DAT_00146058._4_4_ = 4;
  DAT_00146058._0_4_ = 3;
  DAT_00146060._0_4_ = 5;
  DAT_00146060._4_4_ = 3;
                    // try { // try from 0011591c to 0011591f has its CatchHandler @ 00115954
  __android_log_print(3,"FingerGoodix","FingerPrintService is constructing");
  return;
}



// android::FpService::FpService()

void __thiscall android::FpService::FpService(FpService *this)

{
  long lVar1;
  pthread_mutex_t *__mutex;
  
  android::RefBase::RefBase((RefBase *)(this + 0x300));
                    // try { // try from 00115a60 to 00115a63 has its CatchHandler @ 00115b90
  IFingerPrintService::IFingerPrintService((IFingerPrintService *)this);
                    // try { // try from 00115a70 to 00115a73 has its CatchHandler @ 00115c74
  android::BBinder::BBinder((BBinder *)(this + 8));
  *(undefined8 *)this = 0x141b08;
  *(undefined8 *)(this + 0x300) = 0x141c78;
  *(undefined8 *)(this + 8) = 0x141bb8;
  *(undefined8 *)(this + 0x28) = 0;
  *(undefined8 *)(this + 0x20) = 0;
  *(undefined8 *)(this + 0x38) = 0;
  *(undefined8 *)(this + 0x30) = 0;
  *(undefined8 *)(this + 0x48) = 0;
  *(undefined8 *)(this + 0x40) = 0;
  *(undefined8 *)(this + 0x50) = 0;
                    // try { // try from 00115ac0 to 00115ac3 has its CatchHandler @ 00115c6c
  pthread_mutex_init((pthread_mutex_t *)(this + 0xbc),(pthread_mutexattr_t *)0x0);
                    // try { // try from 00115ad0 to 00115ad3 has its CatchHandler @ 00115c64
  pthread_cond_init((pthread_cond_t *)(this + 0xec),(pthread_condattr_t *)0x0);
                    // try { // try from 00115ae0 to 00115ae3 has its CatchHandler @ 00115c5c
  pthread_mutex_init((pthread_mutex_t *)(this + 0x11c),(pthread_mutexattr_t *)0x0);
  this[0x1ac] = (FpService)0x0;
                    // try { // try from 00115af4 to 00115af7 has its CatchHandler @ 00115bf0
  pthread_mutex_init((pthread_mutex_t *)(this + 0x1b0),(pthread_mutexattr_t *)0x0);
  __mutex = (pthread_mutex_t *)(this + 0x1d8);
  lVar1 = 6;
  do {
                    // try { // try from 00115b0c to 00115b0f has its CatchHandler @ 00115bc4
    pthread_mutex_init(__mutex,(pthread_mutexattr_t *)0x0);
    lVar1 = lVar1 + -1;
    __mutex = __mutex + 1;
  } while (lVar1 != -1);
  DAT_00146050._0_4_ = 1;
  DAT_00146050._4_4_ = 2;
  *(undefined4 *)(this + 0x2f8) = 1;
  DAT_00146058._4_4_ = 4;
  DAT_00146058._0_4_ = 3;
  DAT_00146060._0_4_ = 5;
  DAT_00146060._4_4_ = 3;
                    // try { // try from 00115b70 to 00115b73 has its CatchHandler @ 00115ba4
  __android_log_print(3,"FingerGoodix","FingerPrintService is constructing");
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// android::FpService::init()

void __thiscall android::FpService::init(FpService *this)

{
  int iVar1;
  undefined8 uVar2;
  code **ppcVar3;
  long local_2a8;
  long local_2a0;
  undefined4 local_298;
  undefined4 uStack_294;
  int local_290;
  undefined auStack_288 [128];
  undefined auStack_208 [64];
  undefined auStack_1c8 [64];
  undefined auStack_188 [64];
  char acStack_148 [64];
  undefined auStack_108 [64];
  char acStack_c8 [64];
  undefined auStack_88 [64];
  undefined auStack_48 [64];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","FingerPrintService is initializing");
  *(undefined4 *)(this + 0x2f4) = 0;
  local_2a8 = 0;
  memset(auStack_288,0,0x280);
  *(undefined4 *)(this + 0x58) = 0;
  *(undefined4 *)(this + 0x5c) = 0;
  *(undefined4 *)(this + 0x60) = 0;
  *(undefined4 *)(this + 100) = 0;
  *(undefined4 *)(this + 0x68) = 0;
  *(undefined4 *)(this + 0x6c) = 0;
  *(undefined4 *)(this + 0x70) = 0;
  sem_init((sem_t *)&DAT_00146040,0,0);
  iVar1 = hw_get_module("gxfingerprint",&local_2a8);
  if (iVar1 == 0) {
    if (local_2a8 == 0) {
      __android_log_print(6,"FingerGoodix","No valid fingerprint module");
      uVar2 = 0xffffffff;
    }
    else {
      ppcVar3 = *(code ***)(local_2a8 + 0x20);
      *(long *)(this + 0x150) = local_2a8;
      if (*ppcVar3 == (code *)0x0) {
        __android_log_print(6,"FingerGoodix","No valid open method",ppcVar3,0);
        uVar2 = 0xffffffff;
      }
      else {
        local_2a0 = 0;
        iVar1 = (**ppcVar3)(local_2a8,0,&local_2a0);
        if (iVar1 == 0) {
          enable_goodix_fp_with_sys_prop();
          if (*(int *)(local_2a0 + 4) != 0x100) {
            __android_log_print(3,"FingerGoodix","Wrong fp version. Expected %d, got %d",0x100);
          }
          *(long *)(this + 0x158) = local_2a0;
          *(undefined4 *)(this + 0x7c) = 0;
          DAT_00146068 = this;
          (**(code **)(local_2a0 + 0x198))(local_2a0,notifyClient);
          (**(code **)(*(long *)(this + 0x158) + 0x148))(*(long *)(this + 0x158),auStack_288);
          (**(code **)(*(long *)(this + 0x158) + 0x228))(*(long *)(this + 0x158),this + 0xa0);
          __android_log_print(6,"FingerGoodix",
                              "##################################################################");
          __android_log_print(6,"FingerGoodix","SOFT VERSION INFO");
          __android_log_print(6,"FingerGoodix","         TARGET_MODE=%s","debug");
          __android_log_print(6,"FingerGoodix","PACKAGE_VERSION_CODE=%s","");
          __android_log_print(6,"FingerGoodix","PACKAGE_VERSION_NAME=%s","");
          __android_log_print(6,"FingerGoodix","          GIT_BRANCH=%s","A13_new");
          __android_log_print(6,"FingerGoodix","           COMMIT_ID=%s",
                              "25c663ef1953ad1dc2133804973618c76630aebb");
          __android_log_print(6,"FingerGoodix","          BUILD_TIME=%s","2017.05.24_12:54:44");
          sprintf(acStack_148,"GX Srv V%02x.%02x.%02x [%s_%s]",1,0,0x16,"May 24 2017","12:54:46");
          sprintf(acStack_c8,"Flow V%02x.%02x.%02x [%s_%s]",1,0,6,"May 24 2017","12:54:46");
          memset(algoVersion,0,0x1ff);
          sprintf(algoVersion,"%sSERVICE VERSION=%s.\n",algoVersion,acStack_148);
          sprintf(algoVersion,"%sHAL VERSION=%s.\n",algoVersion,auStack_108);
          sprintf(algoVersion,"%sTA VERSION=%s.\n",algoVersion,auStack_288);
          sprintf(algoVersion,"%sALG VERSION=%s.\n",algoVersion,auStack_1c8);
          sprintf(algoVersion,"%sNAVIGATION VERSION=%s.\n",algoVersion,auStack_208);
          sprintf(algoVersion,"%sFLOW VERSION=%s.\n",algoVersion,acStack_c8);
          sprintf(algoVersion,"%sBASE VERSION=%s.\n",algoVersion,auStack_88);
          sprintf(algoVersion,"%sCONSISTENCY VERSION=%s.\n",algoVersion,auStack_188);
          sprintf(algoVersion,"%sVERSION ChipId=%s.\n",algoVersion,auStack_48);
          sprintf(algoVersion,"%sHardwareInfo VendorId=0x%x.\n",algoVersion,(ulong)(byte)this[0xb8])
          ;
          __android_log_print(6,"FingerGoodix","%s",algoVersion);
          if (this[0xb8] == (FpService)0x10) {
            __android_log_print(6,"FingerGoodix","Chip type>>> Ofilm Chip");
          }
          else if (this[0xb8] == (FpService)0x0) {
            __android_log_print(6,"FingerGoodix","Chip type>>> Qiutech Chip");
          }
          __android_log_print(6,"FingerGoodix",
                              "##################################################################");
          iVar1 = (**(code **)(*(long *)(this + 0x158) + 0x240))(*(long *)(this + 0x158));
          __android_log_print(3,"FingerGoodix","preprocessor init ret = %d",iVar1);
          this[0x1ac] = (FpService)(iVar1 == 0);
          pthread_create((pthread_t *)(this + 0x148),(pthread_attr_t *)0x0,FUN_00117504,this);
          (**(code **)(*(long *)this + 0x80))(this,1);
          local_298 = 0;
          iVar1 = property_get_int32("ro.register.count",0);
          if (0 < iVar1) {
            __android_log_print(3,"FingerGoodix","preprocessor init register_cnt = %d",iVar1);
            uStack_294 = 1;
            local_290 = iVar1;
            (**(code **)(*(long *)(this + 0x158) + 0x248))
                      (*(long *)(this + 0x158),CONCAT44(1,local_298),iVar1);
          }
          iVar1 = property_get_int32("ro.template.count",0);
          if (iVar1 < 1) {
            uVar2 = 0;
          }
          else {
            __android_log_print(3,"FingerGoodix","preprocessor init study_cnt = %d",iVar1);
            uStack_294 = 0;
            local_290 = iVar1;
            (**(code **)(*(long *)(this + 0x158) + 0x248))(*(long *)(this + 0x158),local_298,iVar1);
            uVar2 = 0;
          }
        }
        else {
          __android_log_print(6,"FingerGoodix","Can\'t open fingerprint methods, error: %d",iVar1);
          disable_goodix_fp_with_sys_prop();
          sem_destroy((sem_t *)&DAT_00146040);
          uVar2 = 0xffffffff;
        }
      }
    }
  }
  else {
    __android_log_print(6,"FingerGoodix","Can\'t open fingerprint HW Module, %s error: %d",
                        "gxfingerprint",iVar1);
    uVar2 = 0xffffffff;
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar2);
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
  DAT_00146068 = 0;
  if (*(long *)(this + 0x158) != 0) {
    (**(code **)(*(long *)(this + 0x158) + 0x98))();
    (**(code **)(*(long *)(this + 0x158) + 0x88))(*(long *)(this + 0x158));
    *(undefined4 *)(this + 0x2f0) = 1;
    iVar1 = (**(code **)(*(long *)(this + 0x158) + 0x160))(*(long *)(this + 0x158));
    if (iVar1 == 0) {
      __android_log_print(3,"FingerGoodix","success to disable device");
    }
    else {
      __android_log_print(3,"FingerGoodix","failed to disable device");
    }
    __android_log_print(3,"FingerGoodix","FpService::~FpService(),fnCa_CloseSession");
  }
  __mutex = (pthread_mutex_t *)(this + 0x2f0);
  do {
    __mutex = __mutex + -1;
    pthread_mutex_destroy(__mutex);
  } while ((pthread_mutex_t *)(this + 0x1d8) != __mutex);
  pthread_mutex_destroy((pthread_mutex_t *)(this + 0x1b0));
  pthread_mutex_destroy((pthread_mutex_t *)(this + 0x11c));
  pthread_cond_destroy((pthread_cond_t *)(this + 0xec));
  pthread_mutex_destroy((pthread_mutex_t *)(this + 0xbc));
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
                    // try { // try from 00116574 to 00116577 has its CatchHandler @ 001165d8
  pthread_mutex_lock((pthread_mutex_t *)(this + 0x50));
  if (*(int *)(this + 0x4c) == 0) {
    *(undefined4 *)(this + 0x4c) = 0x7b;
    uVar1 = 0;
  }
  else {
                    // try { // try from 001165b0 to 001165b3 has its CatchHandler @ 001165bc
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
                    // try { // try from 00116628 to 0011662b has its CatchHandler @ 001166bc
  pthread_mutex_lock((pthread_mutex_t *)(this + 0x50));
                    // try { // try from 00116630 to 00116673 has its CatchHandler @ 001166a0
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
  iVar1 = (**(code **)(*(long *)this + 0x160))(this);
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
                    // try { // try from 00116764 to 00116767 has its CatchHandler @ 00116954
  pthread_mutex_lock((pthread_mutex_t *)(this + 0x50));
                    // try { // try from 0011676c to 001167d3 has its CatchHandler @ 00116938
  iVar1 = checkPid(this);
  if (iVar1 != 0) {
                    // try { // try from 001168a4 to 001168c3 has its CatchHandler @ 00116938
    __android_log_print(3,"FingerGoodix","different client - don\'t disconnect");
    uVar3 = 0xffffffff;
    goto LAB_001167d4;
  }
  if (*(int *)(this + 0x4c) < 1) {
    __android_log_print(3,"FingerGoodix",
                        "fp is unlocked (mClientPid = %d), don\'t tear down hardware");
    uVar3 = 0xffffffff;
    goto LAB_001167d4;
  }
  iVar1 = reset2KeyMode(this);
  if (iVar1 == 0) {
    __android_log_print(3,"FingerGoodix","success to reset2KeyMode");
    plVar2 = *(long **)(this + 0x38);
    if (*(int *)(this + 0x48) == *(int *)((long)plVar2 + 0x2f4)) {
LAB_00116824:
      pthread_mutex_lock((pthread_mutex_t *)mStatusCheckLock);
      plVar2 = *(long **)(this + 0x38);
      iVar1 = *(int *)((long)plVar2 + 0xe4);
      if (iVar1 - 2U < 2) {
                    // try { // try from 001168d8 to 00116933 has its CatchHandler @ 0011695c
        (**(code **)(*(long *)(this + 0x28) + 0xc0))(*(long *)(this + 0x28));
        (**(code **)(**(long **)(this + 0x38) + 0x80))(*(long **)(this + 0x38),5);
      }
      else if (iVar1 - 6U < 2) {
        (**(code **)(*(long *)(this + 0x28) + 0xe8))(*(long *)(this + 0x28));
        (**(code **)(**(long **)(this + 0x38) + 0x80))(*(long **)(this + 0x38),8);
      }
      else if (iVar1 - 10U < 2) {
        (**(code **)(*plVar2 + 0x80))(plVar2,0xc);
      }
                    // try { // try from 00116868 to 00116883 has its CatchHandler @ 0011695c
      (**(code **)(*(long *)(this + 0x28) + 0x1b8))(*(long *)(this + 0x28));
      (**(code **)(**(long **)(this + 0x38) + 0x80))(*(long **)(this + 0x38),1);
      pthread_mutex_unlock((pthread_mutex_t *)mStatusCheckLock);
      plVar2 = *(long **)(this + 0x38);
    }
  }
  else {
                    // try { // try from 0011680c to 0011682f has its CatchHandler @ 00116938
    __android_log_print(3,"FingerGoodix","failed to reset2KeyMode");
    plVar2 = *(long **)(this + 0x38);
    if (*(int *)(this + 0x48) == *(int *)((long)plVar2 + 0x2f4)) goto LAB_00116824;
  }
  (**(code **)(*plVar2 + 0x40))(plVar2,this + 0x40);
  setFingerPrintFree(*(FpService **)(this + 0x38),*(int *)(this + 0x48));
  uVar3 = 0;
LAB_001167d4:
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
  deactivateClient(this);
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
  
  *(undefined8 *)this = 0x1426d8;
  *(undefined8 *)(this + 0xa0) = 0x142948;
  *(undefined8 *)(this + 8) = 0x142888;
  deactivateClient(this);
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
  *(undefined **)this = &DAT_00142148;
  *(undefined **)(this + 0xa0) = &DAT_00142378;
  *(undefined ***)(this + 8) = &PTR_queryLocalInterface_001422b8;
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
  (**(code **)(*(long *)this + 200))(this);
  plVar1 = *(long **)(this + 0x38);
  if (*(int *)((long)plVar1 + 0xe4) - 2U < 3) {
    (**(code **)(*(long *)this + 0x80))(this);
    plVar1 = *(long **)(this + 0x38);
  }
  (**(code **)(*plVar1 + 0x68))(plVar1,iVar2);
  if (iVar3 == 2) {
    *(int *)(*(long *)(this + 0x38) + 0x2f8) = iVar2;
  }
  return 0;
}



// android::FpService::Client::setMode(int)

undefined8 __thiscall android::FpService::Client::setMode(Client *this,int param_1)

{
  undefined8 uVar1;
  
  __android_log_print(3,"FingerGoodix","gx_fpd set mode: %d.",param_1);
  uVar1 = (**(code **)(*(long *)this + 0x160))(this);
  if (((int)uVar1 == 0) && (uVar1 = sysHalSetMode(this,param_1), (int)uVar1 != 0)) {
    pthread_mutex_lock((pthread_mutex_t *)mStatusCheckLock);
                    // try { // try from 00116d28 to 00116d83 has its CatchHandler @ 00116dc0
    __android_log_print(3,"FingerGoodix","Client::setMode=%d ,but no longer support.return 0!",
                        param_1);
    if ((param_1 == 2) || ((param_1 == 0x10 || (param_1 == 1)))) {
                    // try { // try from 00116db8 to 00116dbb has its CatchHandler @ 00116dc0
      (**(code **)(**(long **)(this + 0x38) + 0x68))(*(long **)(this + 0x38),param_1);
    }
    else {
      __android_log_print(3,"FingerGoodix","Should not support to set mode[%d].\n",param_1);
    }
    (**(code **)(*(long *)(this + 0x28) + 0x128))(*(long *)(this + 0x28));
    (**(code **)(**(long **)(this + 0x38) + 0x80))(*(long **)(this + 0x38),1);
    pthread_mutex_unlock((pthread_mutex_t *)mStatusCheckLock);
    return 0;
  }
  return uVar1;
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
  long *local_10;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","notifyClient,type:%d,msg:%d,ext:%d,clientID:%d",param_1,
                      param_2,param_3,*(undefined4 *)(DAT_00146068 + 0x2f4));
  local_10 = (long *)0x0;
  if (*(uint *)(DAT_00146068 + 0x2f4) < 7) {
                    // try { // try from 00116ec4 to 00116ee7 has its CatchHandler @ 00116f84
    sp<>::operator=((sp<> *)&local_10,
                    (sp *)(DAT_00146068 + ((long)(int)*(uint *)(DAT_00146068 + 0x2f4) + 4) * 8));
  }
  else {
                    // try { // try from 00116f40 to 00116f5f has its CatchHandler @ 00116f84
    __android_log_print(6,"FingerGoodix","Invalid NotifyClientID");
  }
  if (local_10 == (long *)0x0) {
    __android_log_print(6,"FingerGoodix","client is null");
    if (local_10 != (long *)0x0) {
      android::RefBase::decStrong((void *)((long)local_10 + *(long *)(*local_10 + -0x18)));
    }
  }
  else {
    (**(code **)(*local_10 + 0x180))(local_10,param_1,param_2,param_3);
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
// android::postData2Client(int, int, char*)

void android::postData2Client(int param_1,int param_2,char *param_3)

{
  long *local_10;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","postData2Client,msgType:%d,length:%d,clientID:%d",param_1,
                      param_2,*(undefined4 *)(DAT_00146068 + 0x2f4));
  local_10 = (long *)0x0;
  if (*(uint *)(DAT_00146068 + 0x2f4) < 7) {
                    // try { // try from 0011703c to 0011705f has its CatchHandler @ 001170fc
    sp<>::operator=((sp<> *)&local_10,
                    (sp *)(DAT_00146068 + ((long)(int)*(uint *)(DAT_00146068 + 0x2f4) + 4) * 8));
  }
  else {
                    // try { // try from 001170b8 to 001170d7 has its CatchHandler @ 001170fc
    __android_log_print(6,"FingerGoodix","Invalid NotifyClientID");
  }
  if (local_10 == (long *)0x0) {
    __android_log_print(6,"FingerGoodix","client is null");
    if (local_10 != (long *)0x0) {
      android::RefBase::decStrong((void *)((long)local_10 + *(long *)(*local_10 + -0x18)));
    }
  }
  else {
    (**(code **)(*local_10 + 0x188))(local_10,param_1,param_2,param_3);
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
// android::FpService::RegisterDump(Register_Status)

void __thiscall android::FpService::RegisterDump(FpService *this,Register_Status param_1)

{
  int iVar1;
  char *__ptr;
  int local_84;
  undefined8 local_80;
  undefined8 uStack_78;
  undefined8 local_70;
  undefined8 uStack_68;
  undefined8 local_60;
  undefined8 uStack_58;
  undefined4 local_50;
  char local_48 [8];
  undefined8 local_40;
  undefined8 local_38;
  undefined8 uStack_30;
  undefined8 local_28;
  undefined8 uStack_20;
  undefined8 local_18;
  undefined8 uStack_10;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  local_84 = 0;
  local_48[0] = '\0';
  local_48[1] = '\0';
  local_48[2] = '\0';
  local_48[3] = '\0';
  local_48[4] = '\0';
  local_48[5] = '\0';
  local_48[6] = '\0';
  local_48[7] = '\0';
  local_40._0_1_ = '\0';
  local_40._1_1_ = '\0';
  local_40._2_1_ = '\0';
  local_40._3_1_ = '\0';
  local_40._4_1_ = '\0';
  local_40._5_1_ = '\0';
  local_40._6_1_ = '\0';
  local_40._7_1_ = '\0';
  local_38 = 0;
  uStack_30 = 0;
  local_28 = 0;
  uStack_20 = 0;
  local_18 = 0;
  uStack_10 = 0;
  local_80 = 0;
  uStack_78 = 0;
  local_70 = 0;
  uStack_68 = 0;
  local_60 = 0;
  uStack_58 = 0;
  local_50 = 0;
  iVar1 = property_get_int32("goodix.fp.debug",0);
  if (iVar1 == 1) {
    local_84 = *(int *)(this + 0xa0) * *(int *)(this + 0xa4);
    __ptr = (char *)malloc((long)local_84);
    iVar1 = (**(code **)(*(long *)(this + 0x158) + 0x1e8))
                      (*(long *)(this + 0x158),__ptr,&local_84,&local_80,0);
    if ((__ptr != (char *)0x0) && (iVar1 == 0)) {
      postData2Client(0x1b,0x34,(char *)&local_80);
      postData2Client(0x1a,local_84,__ptr);
    }
    free(__ptr);
    switch(param_1) {
    case 0:
      local_48[0] = 's';
      local_48[1] = 'u';
      local_48[2] = 'c';
      local_48[3] = 'c';
      local_48[4] = 'e';
      local_48[5] = 's';
      local_48[6] = 's';
      local_48[7] = '\0';
      break;
    case 1:
      local_48[0] = 'd';
      local_48[1] = 'u';
      local_48[2] = 'p';
      local_48[3] = 'l';
      local_48[4] = 'i';
      local_48[5] = 'c';
      local_48[6] = 'a';
      local_48[7] = 't';
      local_40._0_1_ = 'e';
      local_40._1_1_ = '\0';
      break;
    case 2:
      local_48[0] = 'o';
      local_48[1] = 'v';
      local_48[2] = 'e';
      local_48[3] = 'r';
      local_48[4] = 'l';
      local_48[5] = 'a';
      local_48[6] = 'y';
      local_48[7] = '\0';
      break;
    case 3:
      local_48[0] = 'l';
      local_48[1] = 'o';
      local_48[2] = 'w';
      local_48[3] = '_';
      local_48[4] = 'c';
      local_48[5] = 'o';
      local_48[6] = 'v';
      local_48[7] = 'e';
      local_40._0_1_ = 'r';
      local_40._1_1_ = '\0';
      break;
    case 4:
      local_48[0] = 'b';
      local_48[1] = 'a';
      local_48[2] = 'd';
      local_48[3] = '_';
      local_48[4] = 'i';
      local_48[5] = 'm';
      local_48[6] = 'a';
      local_48[7] = 'g';
      local_40._0_1_ = 'e';
      local_40._1_1_ = '\0';
      break;
    default:
      goto switchD_00117254_caseD_5;
    case 9:
      local_48[0] = 'd';
      local_48[1] = 'e';
      local_48[2] = 'f';
      local_48[3] = 'e';
      local_48[4] = 'c';
      local_48[5] = 't';
      local_48[6] = '_';
      local_48[7] = 'p';
      local_40._0_1_ = 'i';
      local_40._1_1_ = 'x';
      local_40._2_1_ = 'e';
      local_40._3_1_ = 'l';
      local_40._4_1_ = '_';
      local_40._5_1_ = 'f';
      local_40._6_1_ = 'a';
      local_40._7_1_ = 'i';
      local_38 = CONCAT62(local_38._2_6_,0x6c);
    }
    (**(code **)(*(long *)(this + 0x158) + 0x2b8))(*(long *)(this + 0x158),local_48,1);
  }
switchD_00117254_caseD_5:
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(0);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// android::FpService::RecognizeDump(Recognize_Status)

void __thiscall android::FpService::RecognizeDump(FpService *this,Recognize_Status param_1)

{
  undefined4 uVar1;
  int iVar2;
  char *__ptr;
  int local_84;
  undefined8 local_80;
  undefined8 uStack_78;
  undefined8 local_70;
  undefined8 uStack_68;
  undefined8 local_60;
  undefined8 uStack_58;
  undefined4 local_50;
  char local_48 [8];
  undefined8 local_40;
  undefined8 local_38;
  undefined8 uStack_30;
  undefined8 local_28;
  undefined8 uStack_20;
  undefined8 local_18;
  undefined8 uStack_10;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  local_84 = 0;
  local_48[0] = '\0';
  local_48[1] = '\0';
  local_48[2] = '\0';
  local_48[3] = '\0';
  local_48[4] = '\0';
  local_48[5] = '\0';
  local_48[6] = '\0';
  local_48[7] = '\0';
  local_40._0_1_ = '\0';
  local_40._1_1_ = '\0';
  local_40._2_1_ = '\0';
  local_40._3_1_ = '\0';
  local_40._4_1_ = '\0';
  local_40._5_1_ = '\0';
  local_40._6_1_ = '\0';
  local_40._7_1_ = '\0';
  local_38 = 0;
  uStack_30 = 0;
  local_28 = 0;
  uStack_20 = 0;
  local_18 = 0;
  uStack_10 = 0;
  local_80 = 0;
  uStack_78 = 0;
  local_70 = 0;
  uStack_68 = 0;
  local_60 = 0;
  uStack_58 = 0;
  local_50 = 0;
  iVar2 = property_get_int32("goodix.fp.debug",0);
  if (iVar2 == 1) {
    local_84 = *(int *)(this + 0xa0) * *(int *)(this + 0xa4);
    __ptr = (char *)malloc((long)local_84);
    iVar2 = (**(code **)(*(long *)(this + 0x158) + 0x1e8))
                      (*(long *)(this + 0x158),__ptr,&local_84,&local_80,1);
    if ((__ptr != (char *)0x0) && (iVar2 == 0)) {
      postData2Client(0x109,0x34,(char *)&local_80);
      postData2Client(0x108,local_84,__ptr);
    }
    free(__ptr);
    uVar1 = local_38._4_4_;
    switch(param_1) {
    case 0:
      local_48[0] = 's';
      local_48[1] = 'u';
      local_48[2] = 'c';
      local_48[3] = 'c';
      local_48[4] = 'e';
      local_48[5] = 's';
      local_48[6] = 's';
      local_48[7] = '\0';
      break;
    default:
      goto switchD_00117444_caseD_1;
    case 2:
      local_38 = CONCAT62(local_38._2_6_,0x6c);
      local_48[0] = 'p';
      local_48[1] = 'r';
      local_48[2] = 'e';
      local_48[3] = 'p';
      local_48[4] = 'r';
      local_48[5] = 'o';
      local_48[6] = 'c';
      local_48[7] = 'e';
      local_40._0_1_ = 's';
      local_40._1_1_ = 's';
      local_40._2_1_ = 'o';
      local_40._3_1_ = 'r';
      local_40._4_1_ = '_';
      local_40._5_1_ = 'f';
      local_40._6_1_ = 'a';
      local_40._7_1_ = 'i';
      break;
    case 3:
      local_48[0] = 'b';
      local_48[1] = 'a';
      local_48[2] = 'd';
      local_48[3] = '_';
      local_48[4] = 'i';
      local_48[5] = 'a';
      local_48[6] = 'm';
      local_48[7] = 'g';
      local_40._0_1_ = 'e';
      local_40._1_1_ = '\0';
      break;
    case 4:
      local_38 = CONCAT62(local_38._2_6_,0x6c);
      local_48[0] = 'd';
      local_48[1] = 'e';
      local_48[2] = 'f';
      local_48[3] = 'e';
      local_48[4] = 'c';
      local_48[5] = 't';
      local_48[6] = '_';
      local_48[7] = 'p';
      local_40._0_1_ = 'i';
      local_40._1_1_ = 'x';
      local_40._2_1_ = 'e';
      local_40._3_1_ = 'l';
      local_40._4_1_ = '_';
      local_40._5_1_ = 'f';
      local_40._6_1_ = 'a';
      local_40._7_1_ = 'i';
      break;
    case 5:
      local_38 = CONCAT44(uVar1,0x316c65);
      local_48[0] = 'd';
      local_48[1] = 'e';
      local_48[2] = 'f';
      local_48[3] = 'e';
      local_48[4] = 'c';
      local_48[5] = 't';
      local_48[6] = '_';
      local_48[7] = 'p';
      local_40._0_1_ = 'i';
      local_40._1_1_ = 'x';
      local_40._2_1_ = 'e';
      local_40._3_1_ = 'l';
      local_40._4_1_ = '_';
      local_40._5_1_ = 'l';
      local_40._6_1_ = 'e';
      local_40._7_1_ = 'v';
      break;
    case 6:
      local_48[0] = 'd';
      local_48[1] = 'e';
      local_48[2] = 'f';
      local_48[3] = 'e';
      local_48[4] = 'c';
      local_48[5] = 't';
      local_48[6] = '_';
      local_48[7] = 'p';
      local_40._0_1_ = 'i';
      local_40._1_1_ = 'x';
      local_40._2_1_ = 'e';
      local_40._3_1_ = 'l';
      local_40._4_1_ = '_';
      local_40._5_1_ = 'l';
      local_40._6_1_ = 'e';
      local_40._7_1_ = 'v';
      local_38 = CONCAT44(uVar1,0x326c65);
    }
    (**(code **)(*(long *)(this + 0x158) + 0x2b8))(*(long *)(this + 0x158),local_48,0);
  }
switchD_00117444_caseD_1:
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(0);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00117504(long *param_1)

{
  uint uVar1;
  undefined4 uVar2;
  ulong uVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  void *__ptr;
  code *pcVar7;
  long lVar8;
  undefined auStack_630 [756];
  int local_33c;
  undefined8 local_338;
  undefined8 uStack_330;
  undefined8 local_328;
  undefined8 local_320;
  undefined8 local_318;
  undefined8 uStack_310;
  ulong local_308;
  int local_300;
  int local_2fc;
  undefined4 local_2f8;
  undefined4 local_2f4;
  Recognize_Status local_2e8;
  int local_264;
  char acStack_260 [592];
  char local_10 [8];
  undefined8 local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","create RawDataProcessLoop!");
  lVar8 = param_1[0x2b];
  do {
    while( true ) {
      while( true ) {
        __android_log_print(3,"FingerGoodix","RawDataProcessLoop waiting signal!");
        (**(code **)(*param_1 + 0x78))(param_1);
        __android_log_print(3,"FingerGoodix","RawDataProcessLoop set to default mode");
        iVar4 = (**(code **)(*param_1 + 0x70))(param_1);
        if ((iVar4 == 0x10) || (iVar4 == 1)) {
          __android_log_print(3,"FingerGoodix","Don\'t change sensor mode in KEY or NAV mode[%d]\n",
                              iVar4);
        }
        else {
          __android_log_print(3,"FingerGoodix","RawDataProcessLoop set to SLEEP mode");
        }
        iVar4 = sem_wait((sem_t *)&DAT_00146040);
        __android_log_print(3,"FingerGoodix","RawDataProcessLoop got signal!");
        uVar1 = *(uint *)((long)param_1 + 0xe4) & 0xfffffffb;
        if ((uVar1 != 8 && uVar1 != 1) && (*(uint *)((long)param_1 + 0xe4) != 0x10)) break;
        __android_log_print(3,"FingerGoodix","No need to wait for finer status 1 : %d\n");
      }
      (**(code **)(*param_1 + 0x68))(param_1,0);
      __android_log_print(3,"FingerGoodix","RawDataProcessLoop set to IMAGE mode");
      if (iVar4 == 0) break;
      __android_log_print(3,"FingerGoodix","EventProcessThread wait signal error!");
    }
    while( true ) {
      pthread_mutex_lock((pthread_mutex_t *)android::ProcessRawDataLock);
      uVar1 = *(uint *)((long)param_1 + 0xe4) & 0xfffffffb;
      if ((uVar1 == 8 || uVar1 == 1) || (*(uint *)((long)param_1 + 0xe4) == 0x10)) break;
                    // try { // try from 001176d8 to 00117757 has its CatchHandler @ 00118414
      __android_log_print(3,"FingerGoodix","EventProcessThread wait hal_Down! status:%d");
      iVar4 = (**(code **)(lVar8 + 0x178))(lVar8,0);
      if (iVar4 != 0) {
        if (iVar4 != 1) {
                    // try { // try from 00117690 to 00117693 has its CatchHandler @ 00118414
          __android_log_print(3,"FingerGoodix",
                              "EventProcessThread wait hal_Down error, goto RAWDATALOOP!");
          goto LAB_00117694;
        }
                    // try { // try from 00117f14 to 001180ef has its CatchHandler @ 00118414
        __android_log_print(3,"FingerGoodix","EventProcessThread cancel hal_Down goto waitting!");
        goto LAB_00117770;
      }
      __android_log_print(3,"FingerGoodix","EventProcessThread wait hal_Down! status:%d",
                          *(undefined4 *)((long)param_1 + 0xe4));
      switch(*(undefined4 *)((long)param_1 + 0xe4)) {
      case 2:
        local_338 = 0;
        __android_log_print(3,"FingerGoodix","###EventProcessThread reg pending to registering");
        (**(code **)(*param_1 + 0x80))(param_1,3);
        (**(code **)(lVar8 + 0x138))(lVar8,1);
        (**(code **)(lVar8 + 0xb8))(lVar8,&local_338);
        (**(code **)(lVar8 + 0x138))(lVar8,0);
        (**(code **)(lVar8 + 0x260))(lVar8);
        uVar3 = local_338;
        uVar1 = (uint)local_338;
        __android_log_print(3,"FingerGoodix","TA return progress = %d. Status:%d",
                            local_338 & 0xffffffff,local_338._4_4_);
        if (*(int *)((long)param_1 + 0xe4) != 3) {
          __android_log_print(3,"FingerGoodix",
                              "EventProcessThread registering,but status be changed to %d,then cancel reg"
                             );
          (**(code **)(lVar8 + 0xc0))(lVar8);
          (**(code **)(lVar8 + 600))(lVar8);
          (**(code **)(lVar8 + 0x180))(lVar8,0);
          break;
        }
        android::FpService::RegisterDump((FpService *)param_1,local_338._4_4_);
        if (uVar1 < 100) {
                    // try { // try from 0011819c to 001181ff has its CatchHandler @ 00118414
          __android_log_print(3,"FingerGoodix",
                              "EventProcessThread registering,notify result,and set to pending!,current precent:%d"
                              ,uVar3 & 0xffffffff);
          if (local_338._4_4_ == 1) {
            android::notifyClient(0x1c,uVar1,0);
          }
          else if (local_338._4_4_ == 2) {
            android::notifyClient(0x1e,uVar1,0);
          }
          else if (local_338._4_4_ == 3) {
            android::notifyClient(0x14,uVar1,0);
          }
          else if (local_338._4_4_ == 4) {
            android::notifyClient(0x15,uVar1,0);
          }
          else if (local_338._4_4_ == 5) {
            android::notifyClient(0x16,uVar1,0);
          }
          else if (local_338._4_4_ == 6) {
            android::notifyClient(0x1f,uVar1,0);
          }
          else if (local_338._4_4_ == 9) {
            android::notifyClient(0x20,uVar1,0);
          }
          else {
            if (local_338._4_4_ == 10) {
              __android_log_print(3,"FingerGoodix",
                                  "enroll: Bias temperature lead to fake fingerdown");
              iVar4 = *(int *)((long)param_1 + 0xe4);
              if (iVar4 != 3) goto LAB_00117748;
              (**(code **)(*param_1 + 0x80))(param_1,2);
              break;
            }
            android::notifyClient(0x11,uVar1,0);
          }
          pthread_mutex_lock((pthread_mutex_t *)android::mStatusCheckLock);
          if (*(int *)((long)param_1 + 0xe4) == 3) {
                    // try { // try from 001182dc to 001182df has its CatchHandler @ 0011841c
            (**(code **)(*param_1 + 0x80))(param_1,2);
          }
          pthread_mutex_unlock((pthread_mutex_t *)android::mStatusCheckLock);
        }
        else if (uVar1 == 100) {
                    // try { // try from 00118220 to 001182c7 has its CatchHandler @ 00118414
          __android_log_print(3,"FingerGoodix",
                              "EventProcessThread registering,notify result,and set to idle!");
          (**(code **)(*param_1 + 0x80))(param_1,4);
          android::notifyClient(0x11,100,0);
          android::notifyClient(0x18,100,0);
        }
        else {
          __android_log_print(3,"FingerGoodix",
                              "EventProcessThread registering,Algorithm error , pre is invalid!");
          (**(code **)(*param_1 + 0x80))(param_1,4);
          android::notifyClient(0x16,uVar1,0);
        }
        (**(code **)(lVar8 + 600))(lVar8);
        iVar4 = *(int *)((long)param_1 + 0xe4);
        if (iVar4 - 2U < 3) {
LAB_00117ffc:
          iVar4 = (**(code **)(lVar8 + 0x180))(lVar8,0);
          if ((iVar4 != 0) || (*(FpService *)((long)param_1 + 0x1ac) != (FpService)0x0)) break;
          iVar5 = (**(code **)(lVar8 + 0x240))(lVar8);
          iVar4 = *(int *)((long)param_1 + 0xe4);
          if (iVar5 == 0) {
            *(FpService *)((long)param_1 + 0x1ac) = (FpService)0x1;
          }
        }
        goto LAB_00117748;
      default:
        __android_log_print(6,"FingerGoodix",
                            "EventProcessThread actStatus error!ignore getdata!current actStatus:%d"
                           );
        (**(code **)(lVar8 + 0x260))(lVar8);
        (**(code **)(lVar8 + 0x188))(lVar8,1);
        break;
      case 6:
        __android_log_print(3,"FingerGoodix","EventProcessThread reg pending to matching!");
        (**(code **)(*param_1 + 0x80))(param_1,7);
        uVar2 = *(undefined4 *)((long)param_1 + 0x9c);
        iVar4 = *(int *)(param_1 + 0x10);
        memset(&local_300,0,0x2ec);
        local_338 = local_338 & 0xffffffff00000000;
        (**(code **)(lVar8 + 0x138))(lVar8,1);
        __android_log_print(3,"FingerGoodix","isFidoVerify value : %d\n",
                            *(FpService *)(param_1 + 0x2c));
        if (*(FpService *)(param_1 + 0x2c) == (FpService)0x0) {
                    // try { // try from 00117d78 to 00117e27 has its CatchHandler @ 00118414
          __android_log_print(3,"FingerGoodix","NOT Fido path pending to matching!, sectype = %d",
                              iVar4);
          iVar5 = (**(code **)(lVar8 + 0xe0))
                            (lVar8,iVar4,(FpService *)((long)param_1 + 0x84),uVar2,&local_300,
                             &local_338,&android::calculate_token_t);
        }
        else {
          __android_log_print(3,"FingerGoodix","Fido path pending to matching!");
          iVar5 = (**(code **)(lVar8 + 0x1e0))
                            (lVar8,(FpService *)((long)param_1 + 0x84),uVar2,&local_300,&local_338,
                             (FpService *)((long)param_1 + 0x164));
        }
        android::FpService::RecognizeDump((FpService *)param_1,local_2e8);
        iVar6 = property_get_int32("goodix.fp.miui.analyse",0);
        if (iVar6 == 1) {
          __android_log_print(3,"FingerGoodix","shasha");
          memcpy(auStack_630,&local_300,0x2ec);
          writeDataToRecordFile();
        }
        __android_log_print(3,"FingerGoodix",
                            "Match Pending: status:%d. verifyIndex:%d, verifyScore:%d, quality:%d, coverage:%d\n"
                            ,*(undefined4 *)((long)param_1 + 0xe4),local_300,local_2fc,local_2f4,
                            local_2f8);
        if (*(int *)((long)param_1 + 0xe4) == 7) {
          if (iVar5 < 0) goto LAB_00117dd8;
          if (local_300 == 0xcc) {
            if (local_2fc != 0xcc) goto LAB_00117f28;
                    // try { // try from 00118128 to 0011816f has its CatchHandler @ 00118414
            __android_log_print(3,"FingerGoodix",
                                "Recognize: Bias temperature lead to fake fingerdown");
            if (*(int *)((long)param_1 + 0xe4) == 7) {
              (**(code **)(*param_1 + 0x80))(param_1,6);
            }
            pcVar7 = *(code **)(lVar8 + 600);
            *(FpService *)(param_1 + 0x2c) = (FpService)0x0;
            (*pcVar7)(lVar8);
          }
          else {
            if (local_300 == 0xbb) {
              if (local_2fc != 0xbb) goto LAB_00117f28;
              __android_log_print(3,"FingerGoodix","Recognize: Sensor Defect Fail.");
              android::notifyClient(0x20,0,0);
            }
            else if (local_300 < 1) {
              android::notifyClient(0x103,0,0);
            }
            else {
LAB_00117f28:
              __android_log_print(3,"FingerGoodix","Recognize end. ret = %d, index = %d\n",iVar5);
              if (*(FpService *)(param_1 + 0x2c) == (FpService)0x0) {
                android::postData2Client(0x101,(uint)local_338,(char *)&local_300);
              }
              else {
                __android_log_print(3,"FingerGoodix","FIDO Recognize return UVT1.RspLength:%d\n",
                                    local_264);
                android::postData2Client(0x107,local_264,acStack_260);
              }
              if (iVar4 != 1) {
                (**(code **)(lVar8 + 0x238))(lVar8,local_300);
              }
            }
LAB_00117dd8:
            (**(code **)(lVar8 + 600))(lVar8);
            (**(code **)(lVar8 + 0x138))(lVar8,0);
            (**(code **)(lVar8 + 0x260))(lVar8);
            __android_log_print(3,"FingerGoodix","Recognize end,the return: %d. status : %d",iVar5,
                                *(undefined4 *)((long)param_1 + 0xe4));
            pthread_mutex_lock((pthread_mutex_t *)android::mStatusCheckLock);
            if (*(int *)((long)param_1 + 0xe4) == 7) {
                    // try { // try from 00118104 to 00118107 has its CatchHandler @ 00118404
              (**(code **)(*param_1 + 0x80))(param_1,6);
            }
            pthread_mutex_unlock((pthread_mutex_t *)android::mStatusCheckLock);
            *(FpService *)(param_1 + 0x2c) = (FpService)0x0;
            if (*(int *)((long)param_1 + 0xe4) - 6U < 2) goto LAB_00117ffc;
                    // try { // try from 00117e60 to 00117eab has its CatchHandler @ 00118414
            __android_log_print(3,"FingerGoodix","No need to wait up. status:%d\n");
          }
        }
        else {
          (**(code **)(lVar8 + 0x138))(lVar8,0);
          (**(code **)(lVar8 + 0xe8))(lVar8);
          (**(code **)(lVar8 + 600))(lVar8);
          (**(code **)(lVar8 + 0x180))(lVar8,0);
          __android_log_print(3,"FingerGoodix","Matching status changed to :%d!",
                              *(undefined4 *)((long)param_1 + 0xe4));
          *(FpService *)(param_1 + 0x2c) = (FpService)0x0;
        }
        break;
      case 10:
        local_33c = 0;
        local_338 = 0;
        uStack_330 = 0;
        local_328 = 0;
        local_320 = 0;
        local_318 = 0;
        uStack_310 = 0;
        local_308 = local_308 & 0xffffffff00000000;
        __android_log_print(3,"FingerGoodix","EventProcessThread get bitmap.");
        __ptr = malloc(0xf03c);
        if (__ptr == (void *)0x0) {
          __android_log_print(6,"FingerGoodix","malloc fail");
        }
        else {
          local_33c = 0xf03c;
          (**(code **)(*param_1 + 0x80))(param_1,0xb);
          (**(code **)(lVar8 + 0x138))(lVar8,1);
          iVar4 = (**(code **)(lVar8 + 0x1e8))(lVar8,__ptr,&local_33c,&local_338,2);
          (**(code **)(lVar8 + 0x138))(lVar8,0);
          (**(code **)(lVar8 + 0x260))(lVar8);
          if (*(int *)((long)param_1 + 0xe4) == 0xb) {
            if (((iVar4 == 0) && (0xf < (int)local_338._4_4_)) && (0x41 < (int)(uint)local_338)) {
              local_33c = *(int *)(param_1 + 0x14) * *(int *)((long)param_1 + 0xa4);
              android::postData2Client(0x12e,0x34,(char *)&local_338);
              android::postData2Client(300,local_33c,(char *)((long)__ptr + 0x34));
              android::postData2Client(0x12f,local_33c << 1,(char *)((long)__ptr + 0x5034));
              iVar4 = property_get_int32("goodix.fp.debug",0);
              if (iVar4 == 1) {
                local_10[0] = 'S';
                local_10[1] = 'U';
                local_10[2] = 'C';
                local_10[3] = 'C';
                local_10[4] = 'E';
                local_10[5] = 'S';
                local_10[6] = 'S';
                local_10[7] = '\0';
                    // try { // try from 00118304 to 001183e3 has its CatchHandler @ 00118414
                (**(code **)(lVar8 + 0x2b8))(lVar8,local_10,8);
              }
              usleep(200000);
            }
            else {
              android::notifyClient(0x12d,0,0);
            }
            free(__ptr);
            pthread_mutex_lock((pthread_mutex_t *)android::mStatusCheckLock);
                    // try { // try from 00117eb8 to 00117ebb has its CatchHandler @ 001183e8
            iVar4 = (**(code **)(lVar8 + 0x180))(lVar8,0);
                    // try { // try from 0011817c to 0011817f has its CatchHandler @ 001183e8
            if (((iVar4 == 0) && (*(FpService *)((long)param_1 + 0x1ac) == (FpService)0x0)) &&
               (iVar4 = (**(code **)(lVar8 + 0x240))(lVar8), iVar4 == 0)) {
              *(FpService *)((long)param_1 + 0x1ac) = (FpService)0x1;
            }
            pthread_mutex_unlock((pthread_mutex_t *)android::mStatusCheckLock);
            iVar4 = *(int *)((long)param_1 + 0xe4);
            if (iVar4 != 0xb) goto LAB_00117748;
                    // try { // try from 00117eec to 00117eef has its CatchHandler @ 00118414
            (**(code **)(*param_1 + 0x80))(param_1,10);
          }
          else {
            (**(code **)(lVar8 + 0x180))(lVar8,0);
            free(__ptr);
          }
        }
        break;
      case 0xd:
        __android_log_print(3,"FingerGoodix","EventProcessThread mp test.");
        local_338 = 0;
        uStack_330 = 0;
        local_328 = 0;
        local_320 = 0;
        local_318 = 0;
        uStack_310 = 0;
        local_308 = 0;
        (**(code **)(*param_1 + 0x80))(param_1,0xf);
        (**(code **)(lVar8 + 0x138))(lVar8,1);
        (**(code **)(lVar8 + 0x230))(lVar8,2,&local_338);
        (**(code **)(lVar8 + 0x138))(lVar8,0);
        (**(code **)(lVar8 + 0x260))(lVar8);
        if (local_338._4_4_ == 1) {
          __android_log_print(3,"FingerGoodix","service mp_test:performance success.");
          android::notifyClient(0x1773,(int)local_320,0);
        }
        else {
          __android_log_print(3,"FingerGoodix","service mp_test:performance failed.");
          android::notifyClient(0x1773,-1,0);
        }
        (**(code **)(lVar8 + 0x230))(lVar8,7,&local_338);
        if (local_328._4_4_ == 1) {
          __android_log_print(3,"FingerGoodix","service mp_test:pixel_detection success.");
          android::notifyClient(0x1775,1,0);
        }
        else {
          __android_log_print(3,"FingerGoodix","service mp_test:pixel_detection failed.");
          android::notifyClient(0x1775,-1,0);
        }
        (**(code **)(lVar8 + 0x230))(lVar8,3,&local_338);
        android::notifyClient(0x1771,(int)local_318,local_320._4_4_);
        (**(code **)(lVar8 + 0x230))(lVar8,5,&local_338);
        if (uStack_330._4_4_ == 1) {
          __android_log_print(3,"FingerGoodix","service mp_test:scene success.");
          android::notifyClient(0x1772,(int)local_320,0);
        }
        else {
          __android_log_print(3,"FingerGoodix","service mp_test:scene failed.");
          android::notifyClient(0x1772,-1,0);
        }
        android::notifyClient(0x1774,1,0);
        if ((*(uint *)((long)param_1 + 0xe4) & 0xfffffffd) == 0xd) goto LAB_00117a10;
LAB_0011786c:
        __android_log_print(3,"FingerGoodix","MP Test status changed to %d.\n");
        goto LAB_00117880;
      case 0xe:
        __android_log_print(3,"FingerGoodix","EventProcessThread mp test coverage.");
        local_338 = 0;
        uStack_330 = 0;
        local_328 = 0;
        local_320 = 0;
        local_318 = 0;
        uStack_310 = 0;
        local_308 = 0;
        (**(code **)(*param_1 + 0x80))(param_1,0xf);
        (**(code **)(lVar8 + 0x138))(lVar8,1);
        (**(code **)(lVar8 + 0x230))(lVar8,4,&local_338);
        (**(code **)(lVar8 + 0x138))(lVar8,0);
        (**(code **)(lVar8 + 0x260))(lVar8);
        android::notifyClient(0x1771,local_320._4_4_,(int)local_318);
        android::notifyClient(0x1774,1,0);
        if (1 < *(int *)((long)param_1 + 0xe4) - 0xeU) goto LAB_0011786c;
LAB_00117a10:
        (**(code **)(lVar8 + 0x180))(lVar8,0);
LAB_00117880:
        (**(code **)(*param_1 + 0x80))(param_1,1);
      }
      iVar4 = *(int *)((long)param_1 + 0xe4);
LAB_00117748:
      __android_log_print(3,"FingerGoodix","EventProcessThread end,then check status %d",iVar4);
      if (((*(uint *)((long)param_1 + 0xe4) & 0xfffffffb) != 2) &&
         (*(uint *)((long)param_1 + 0xe4) != 10)) goto LAB_00117770;
LAB_00117694:
      pthread_mutex_unlock((pthread_mutex_t *)android::ProcessRawDataLock);
    }
                    // try { // try from 0011778c to 00117d2f has its CatchHandler @ 00118414
    __android_log_print(3,"FingerGoodix","No need to wait for finer up status 2 : %d\n");
    (**(code **)(*param_1 + 0x68))(param_1,2);
LAB_00117770:
    pthread_mutex_unlock((pthread_mutex_t *)android::ProcessRawDataLock);
  } while( true );
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// android::FpService::Client::mp_test(int, int)

void __thiscall android::FpService::Client::mp_test(Client *this,int param_1,int param_2)

{
  int iVar1;
  int iVar2;
  long *plVar3;
  undefined8 uVar4;
  long lVar5;
  char local_81;
  undefined8 local_80;
  undefined8 local_78;
  undefined8 local_70;
  undefined8 uStack_68;
  undefined8 local_60;
  undefined8 uStack_58;
  undefined8 local_50;
  char local_48 [8];
  undefined8 uStack_40;
  undefined8 local_38;
  undefined8 uStack_30;
  undefined8 local_28;
  undefined8 uStack_20;
  undefined8 local_18;
  undefined8 uStack_10;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","mp_test");
  iVar1 = (**(code **)(*(long *)this + 0x160))(this);
  if (iVar1 != 0) goto LAB_00118498;
  local_81 = '\0';
  local_80 = 0;
  local_78 = 0;
  local_70 = 0;
  uStack_68 = 0;
  local_60 = 0;
  uStack_58 = 0;
  local_50 = 0;
  __android_log_print(3,"FingerGoodix","%s. cmd = %d\n",
                      "android::status_t android::FpService::Client::mp_test(int, int)",param_1);
  (**(code **)(*(long *)(this + 0x28) + 400))(*(long *)(this + 0x28),&local_81);
  if (local_81 == '\x03') {
    __android_log_print(3,"FingerGoodix","%s mode %d \n",
                        "android::status_t android::FpService::Client::mp_test(int, int)",3);
    goto LAB_00118498;
  }
  if (999 < param_1) {
    if (param_1 == 0x3e9) {
      if (2 < *(int *)(*(long *)(this + 0x38) + 0xe4) - 0xdU) {
        lVar5 = *(long *)(this + 0x28);
        uVar4 = 0;
        goto LAB_0011881c;
      }
      goto LAB_001187e4;
    }
    if (param_1 == 0x3f1) {
      pthread_mutex_lock((pthread_mutex_t *)mStatusCheckLock);
                    // try { // try from 00118a64 to 00118a67 has its CatchHandler @ 00119124
      iVar1 = (**(code **)(*(long *)(this + 0x28) + 0x230))(*(long *)(this + 0x28),8,&local_80);
      plVar3 = *(long **)(this + 0x38);
      if (*(int *)((long)plVar3 + 0xe4) - 0xdU < 3) {
                    // try { // try from 00118cb8 to 00118ce3 has its CatchHandler @ 00119124
        (**(code **)(*plVar3 + 0x80))(plVar3,0x10);
        (**(code **)(*(long *)(this + 0x28) + 0x1b8))(*(long *)(this + 0x28));
        (**(code **)(**(long **)(this + 0x38) + 0x80))(*(long **)(this + 0x38),1);
        iVar1 = 0;
        pthread_mutex_unlock((pthread_mutex_t *)mStatusCheckLock);
      }
      else {
        pthread_mutex_unlock((pthread_mutex_t *)mStatusCheckLock);
      }
      goto LAB_00118498;
    }
    if (param_1 == 0x3ea) {
      iVar2 = (**(code **)(*(long *)(this + 0x28) + 0x230))(*(long *)(this + 0x28),1,&local_80);
      if ((iVar2 == 0) && ((int)local_80 == 1)) {
        iVar1 = (**(code **)(*(long *)(this + 0x28) + 0x298))(*(long *)(this + 0x28));
        if (iVar1 == 0) {
          __android_log_print(3,"FingerGoodix","CMD_SELFTEST SUCCESS.\n");
          iVar1 = 0;
        }
        else {
          iVar1 = -1;
          __android_log_print(3,"FingerGoodix","CMD_SELFTEST failed. selftest:%d, ret:%d.\n",
                              local_80 & 0xffffffff,0);
        }
      }
      else {
        iVar1 = -1;
        __android_log_print(6,"FingerGoodix","Selftest:%d, ret:%d\n",local_80 & 0xffffffff,iVar2);
      }
      goto LAB_00118498;
    }
    if (param_1 == 1000) {
      __android_log_print(3,"FingerGoodix","FINGERPRINT_MP_TEST Coverage:%d",
                          *(undefined4 *)(*(long *)(this + 0x38) + 0xe4));
      if (*(int *)(*(long *)(this + 0x38) + 0xe4) - 0xdU < 3) {
LAB_001187e4:
        iVar1 = 0;
        __android_log_print(6,"FingerGoodix","Service has already in MP_TEST.\n");
        goto LAB_00118498;
      }
      pthread_mutex_lock((pthread_mutex_t *)ProcessRawDataLock);
                    // try { // try from 001188a0 to 001188df has its CatchHandler @ 00119110
      (**(code **)(**(long **)(this + 0x38) + 0x80))(*(long **)(this + 0x38),0xe);
      (**(code **)(**(long **)(this + 0x38) + 0x88))
                (*(long **)(this + 0x38),*(undefined4 *)(this + 0x48));
      (**(code **)(**(long **)(this + 0x38) + 0x90))(*(long **)(this + 0x38));
      notifyClient(6000,0,0);
    }
    else {
      iVar1 = -1;
      if (param_1 != 0x3eb) goto LAB_00118498;
      __android_log_print(3,"FingerGoodix","FINGERPRINT_MP_TEST:%d",
                          *(undefined4 *)(*(long *)(this + 0x38) + 0xe4));
      if (*(int *)(*(long *)(this + 0x38) + 0xe4) - 0xdU < 3) goto LAB_001187e4;
      pthread_mutex_lock((pthread_mutex_t *)ProcessRawDataLock);
                    // try { // try from 00118728 to 0011877f has its CatchHandler @ 00119138
      (**(code **)(*(long *)(this + 0x28) + 0x230))(*(long *)(this + 0x28),9,&local_80);
      (**(code **)(**(long **)(this + 0x38) + 0x80))(*(long **)(this + 0x38),0xd);
      (**(code **)(**(long **)(this + 0x38) + 0x88))
                (*(long **)(this + 0x38),*(undefined4 *)(this + 0x48));
      (**(code **)(**(long **)(this + 0x38) + 0x90))(*(long **)(this + 0x38));
      notifyClient(6000,0,0);
    }
    iVar1 = 0;
    pthread_mutex_unlock((pthread_mutex_t *)ProcessRawDataLock);
    goto LAB_00118498;
  }
  if (param_1 == 9) {
    (**(code **)(*(long *)(this + 0x28) + 0x1c0))(*(long *)(this + 0x28));
    iVar1 = (**(code **)(*(long *)(this + 0x28) + 0x230))(*(long *)(this + 0x28),0,&local_80);
    postData2Client(9,0x38,(char *)&local_80);
    if ((iVar1 == 0) && ((int)local_80 == -2)) {
      notifyClient(0x1194,9,6);
    }
    else {
      notifyClient(0x1194,9,0);
    }
    (**(code **)(*(long *)(this + 0x28) + 0x230))(*(long *)(this + 0x28),9,&local_80);
    goto LAB_00118498;
  }
  if (param_1 == 10) {
    iVar2 = (**(code **)(*(long *)(this + 0x28) + 0x230))(*(long *)(this + 0x28),1,&local_80);
    postData2Client(0,0x38,(char *)&local_80);
    if ((iVar2 == 0) && ((int)local_80 == 1)) {
      notifyClient(0x1194,0,0);
    }
    else {
      iVar1 = -1;
      __android_log_print(3,"FingerGoodix","service mp_test:selftest failed.");
      notifyClient(0x1194,0,4);
    }
    goto LAB_00118498;
  }
  if (param_1 == 0xb) {
    (**(code **)(*(long *)(this + 0x28) + 0x138))(*(long *)(this + 0x28),1);
    (**(code **)(*(long *)(this + 0x28) + 0x230))(*(long *)(this + 0x28),2,&local_80);
    (**(code **)(*(long *)(this + 0x28) + 0x138))(*(long *)(this + 0x28),0);
    (**(code **)(*(long *)(this + 0x28) + 0x260))(*(long *)(this + 0x28));
    postData2Client(2,0x38,(char *)&local_80);
    if (local_80._4_4_ == 1) {
LAB_00118950:
      iVar1 = 0;
      __android_log_print(3,"FingerGoodix","service mp_test:performance success.");
      notifyClient(0x1194,2,0);
      goto LAB_00118498;
    }
LAB_00118684:
    iVar1 = -1;
    __android_log_print(3,"FingerGoodix","service mp_test:performance failed.");
    notifyClient(0x1194,2,4);
    goto LAB_00118498;
  }
  if (param_1 == 0xc) {
    (**(code **)(*(long *)(this + 0x28) + 0x230))(*(long *)(this + 0x28),3,&local_80);
    postData2Client(4,0x38,(char *)&local_80);
    if ((int)local_78 == 1) {
      __android_log_print(3,"FingerGoodix","service mp_test:image quality success.");
      notifyClient(0x1194,4,0);
    }
    else {
      iVar1 = -1;
      __android_log_print(3,"FingerGoodix","service mp_test:image quality failed.");
      notifyClient(0x1194,4,4);
    }
    goto LAB_00118498;
  }
  if (param_1 == 0xd) {
    (**(code **)(*(long *)(this + 0x28) + 0x230))(*(long *)(this + 0x28),5,&local_80);
    postData2Client(5,0x38,(char *)&local_80);
    if (local_78._4_4_ == 1) {
      __android_log_print(3,"FingerGoodix","service mp_test:scene success.");
      notifyClient(0x1194,5,0);
    }
    else {
      iVar1 = -1;
      __android_log_print(3,"FingerGoodix","service mp_test:scene failed.");
      notifyClient(0x1194,5,4);
    }
    goto LAB_00118498;
  }
  if (param_1 == 0xe) {
    local_48[0] = '\0';
    local_48[1] = '\0';
    local_48[2] = '\0';
    local_48[3] = '\0';
    local_48[4] = '\0';
    local_48[5] = '\0';
    local_48[6] = '\0';
    local_48[7] = '\0';
    uStack_40 = 0;
    local_38 = 0;
    uStack_30 = 0;
    local_28 = 0;
    uStack_20 = 0;
    local_18 = 0;
    uStack_10 = 0;
    (**(code **)(*(long *)(this + 0x28) + 0x188))(*(long *)(this + 0x28),0);
    iVar1 = (**(code **)(*(long *)(this + 0x28) + 0x230))(*(long *)(this + 0x28),6,&local_80);
    iVar2 = property_get_int32("goodix.fp.debug",0);
    if (iVar2 == 1) {
      if ((int)local_70 == 1) {
        local_48[0] = 's';
        local_48[1] = 'u';
        local_48[2] = 'c';
        local_48[3] = 'c';
        local_48[4] = 'e';
        local_48[5] = 's';
        local_48[6] = 's';
        local_48[7] = '\0';
      }
      else {
        local_48[0] = 'f';
        local_48[1] = 'a';
        local_48[2] = 'i';
        local_48[3] = 'l';
        local_48[4] = 'e';
        local_48[5] = 'd';
        local_48[6] = '\0';
      }
      (**(code **)(*(long *)(this + 0x28) + 0x2b8))(*(long *)(this + 0x28),local_48,5);
    }
    postData2Client(6,0x38,(char *)&local_80);
    if ((iVar1 == 0) && ((int)local_70 == 1)) {
      __android_log_print(3,"FingerGoodix","service mp_test:defect detection pass.");
      notifyClient(0x1194,6,0);
      (**(code **)(*(long *)(this + 0x28) + 0x188))(*(long *)(this + 0x28),1);
      iVar1 = 0;
    }
    else {
      iVar1 = -1;
      __android_log_print(3,"FingerGoodix","service mp_test:defect detection failed.");
      notifyClient(0x1194,6,4);
      (**(code **)(*(long *)(this + 0x28) + 0x188))(*(long *)(this + 0x28),1);
    }
    goto LAB_00118498;
  }
  if (param_1 == 0xf) {
    (**(code **)(*(long *)(this + 0x28) + 0x138))(*(long *)(this + 0x28),1);
    (**(code **)(*(long *)(this + 0x28) + 0x230))(*(long *)(this + 0x28),2,&local_80);
    (**(code **)(*(long *)(this + 0x28) + 0x138))(*(long *)(this + 0x28),0);
    (**(code **)(*(long *)(this + 0x28) + 0x260))(*(long *)(this + 0x28));
    (**(code **)(*(long *)(this + 0x28) + 0x230))(*(long *)(this + 0x28),7,&local_80);
    postData2Client(7,0x38,(char *)&local_80);
    if (local_70._4_4_ == 1) {
      iVar1 = 0;
      __android_log_print(3,"FingerGoodix","service mp_test:pixel_detection success.");
      notifyClient(0x1194,7,0);
    }
    else {
      iVar1 = -1;
      __android_log_print(3,"FingerGoodix","service mp_test:pixel_detection failed.");
      notifyClient(0x1194,7,4);
    }
    goto LAB_00118498;
  }
  if (param_1 == 0x10) {
    lVar5 = *(long *)(this + 0x28);
    uVar4 = 8;
LAB_0011881c:
    iVar1 = (**(code **)(lVar5 + 0x230))(lVar5,uVar4,&local_80);
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
        goto LAB_00118498;
      }
    }
    else {
      if (param_1 != 0x12) {
        if (param_1 == 0x15) {
          __android_log_print(3,"FingerGoodix","service mp_test:check ring enable.");
          lVar5 = *(long *)(this + 0x28);
          uVar4 = 0xe;
        }
        else {
          if (param_1 != 0x16) {
            if (param_1 == 0x17) {
              iVar1 = (**(code **)(*(long *)(this + 0x28) + 0x298))(*(long *)(this + 0x28));
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
              goto LAB_00118498;
            }
            if (param_1 != 0x18) {
              iVar1 = -1;
              __android_log_print(6,"FingerGoodix","service mp_test:case error.");
              goto LAB_00118498;
            }
            (**(code **)(*(long *)(this + 0x28) + 0x138))(*(long *)(this + 0x28),1);
            (**(code **)(*(long *)(this + 0x28) + 0x230))(*(long *)(this + 0x28),0xc,&local_80);
            (**(code **)(*(long *)(this + 0x28) + 0x138))(*(long *)(this + 0x28),0);
            (**(code **)(*(long *)(this + 0x28) + 0x260))(*(long *)(this + 0x28));
            postData2Client(4,0x38,(char *)&local_80);
            postData2Client(2,0x38,(char *)&local_80);
            postData2Client(5,0x38,(char *)&local_80);
            if ((int)local_78 == 0) {
              __android_log_print(3,"FingerGoodix","service mp_test:quality success.");
              notifyClient(0x1194,4,0);
            }
            else {
              __android_log_print(3,"FingerGoodix","service mp_test:quality failed.");
              notifyClient(0x1194,4,4);
            }
            if (local_78._4_4_ == 0) {
              __android_log_print(3,"FingerGoodix","service mp_test:scene success.");
              notifyClient(0x1194,5,0);
            }
            else {
              __android_log_print(3,"FingerGoodix","service mp_test:scene failed.");
              notifyClient(0x1194,5,4);
            }
            if (local_80._4_4_ == 0) goto LAB_00118950;
            goto LAB_00118684;
          }
          __android_log_print(3,"FingerGoodix","service mp_test:check ring disable.");
          lVar5 = *(long *)(this + 0x28);
          uVar4 = 0xf;
        }
        goto LAB_0011881c;
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
        goto LAB_00118498;
      }
    }
    iVar1 = -1;
    __android_log_print(3,"FingerGoodix","Time out param error. time = %d.",param_2);
  }
LAB_00118498:
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
  undefined4 uVar1;
  int iVar2;
  undefined4 *puVar3;
  undefined8 *puVar4;
  long *plVar5;
  long lVar6;
  undefined8 uVar7;
  undefined4 local_18;
  undefined4 uStack_14;
  undefined4 local_10;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","FpService::Client::SendCmd cmd = %d.",param_1);
  iVar2 = (**(code **)(*(long *)this + 0x160))(this);
  if (iVar2 != 0) goto LAB_0011925c;
  if (param_5 != (int *)0x0) {
    *param_5 = 0;
    *param_4 = (char *)0x0;
  }
  switch(param_1) {
  case 0:
    pthread_mutex_lock((pthread_mutex_t *)mStatusCheckLock);
    plVar5 = *(long **)(this + 0x38);
    if (*(int *)((long)plVar5 + 0xe4) - 10U < 2) {
                    // try { // try from 00119588 to 001195b3 has its CatchHandler @ 0011969c
      (**(code **)(*plVar5 + 0x80))(plVar5,0xc);
      (**(code **)(*(long *)(this + 0x28) + 0x1b8))(*(long *)(this + 0x28));
      (**(code **)(**(long **)(this + 0x38) + 0x80))(*(long **)(this + 0x38),1);
      iVar2 = 0;
    }
    else {
      iVar2 = -1;
    }
    pthread_mutex_unlock((pthread_mutex_t *)mStatusCheckLock);
    break;
  case 1:
    __android_log_print(3,"FingerGoodix","FINGERPRINT_CMD_GET_BITMAP:%d",
                        *(undefined4 *)(*(long *)(this + 0x38) + 0xe4));
    pthread_mutex_lock((pthread_mutex_t *)ProcessRawDataLock);
                    // try { // try from 00119450 to 0011947f has its CatchHandler @ 00119688
    (**(code **)(**(long **)(this + 0x38) + 0x80))(*(long **)(this + 0x38),10);
    (**(code **)(**(long **)(this + 0x38) + 0x88))
              (*(long **)(this + 0x38),*(undefined4 *)(this + 0x48));
    (**(code **)(**(long **)(this + 0x38) + 0x90))(*(long **)(this + 0x38));
    iVar2 = 0;
    pthread_mutex_unlock((pthread_mutex_t *)ProcessRawDataLock);
    break;
  case 2:
    puVar4 = (undefined8 *)malloc(0x10);
    *puVar4 = 0;
    puVar4[1] = 0;
    if (param_2 == (char *)0x0) {
      __android_log_print(6,"FingerGoodix","Error_%d:in_buffer is NULL.",0x9a0);
    }
    else {
      (**(code **)(*(long *)(this + 0x28) + 0x1f0))(*(long *)(this + 0x28),param_2,param_3,puVar4);
    }
    *param_4 = (char *)puVar4;
    iVar2 = 0;
    *param_5 = 0x10;
    break;
  case 3:
    iVar2 = 0;
    (**(code **)(*(long *)(this + 0x28) + 0x208))(*(long *)(this + 0x28));
    break;
  case 4:
    if (param_2 == (char *)0x0) {
      iVar2 = 0;
      __android_log_print(6,"FingerGoodix","Error_%d:in_buffer is NULL.",0x9af);
    }
    else {
      iVar2 = 0;
      (**(code **)(*(long *)(this + 0x28) + 0x1f8))(*(long *)(this + 0x28),param_2,param_3);
    }
    break;
  case 5:
    puVar4 = (undefined8 *)malloc(0x1c);
    puVar4[2] = 0;
    *puVar4 = 0;
    puVar4[1] = 0;
    *(undefined4 *)(puVar4 + 3) = 0;
    if (param_2 == (char *)0x0) {
      __android_log_print(6,"FingerGoodix","Error_%d:in_buffer is NULL.",0x9be);
    }
    else {
      (**(code **)(*(long *)(this + 0x28) + 0x200))(*(long *)(this + 0x28),param_2,param_3,puVar4);
    }
    *param_4 = (char *)puVar4;
    iVar2 = 0;
    *param_5 = 0x1c;
    break;
  case 6:
    if (param_2 == (char *)0x0) {
      iVar2 = 0;
      __android_log_print(6,"FingerGoodix","Error_%d:in_buffer is NULL.",0x9e4);
    }
    else {
      iVar2 = 0;
      (**(code **)(*(long *)(this + 0x28) + 0x210))(*(long *)(this + 0x28),param_2,param_3);
    }
    break;
  default:
    if (param_1 < 1000) {
      iVar2 = 0;
      __android_log_print(6,"FingerGoodix","SendCmd:command not find!");
    }
    else {
      (**(code **)(**(long **)(this + 0x38) + 0x68))(*(long **)(this + 0x38),0);
      (**(code **)(**(long **)(this + 0x38) + 0x88))
                (*(long **)(this + 0x38),*(undefined4 *)(this + 0x48));
      if ((param_2 == (char *)0x0) || (param_3 < 1)) {
        iVar2 = -1;
      }
      else {
        iVar2 = mp_test(this,param_1,*(int *)param_2);
      }
      if (param_1 == 0x3f1) {
        (**(code **)(**(long **)(this + 0x38) + 0x68))(*(long **)(this + 0x38),2);
      }
    }
    break;
  case 8:
    puVar4 = (undefined8 *)malloc(0x1c);
    if (puVar4 != (undefined8 *)0x0) {
      lVar6 = *(long *)(this + 0x38);
      iVar2 = 0;
      uVar7 = *(undefined8 *)(lVar6 + 0xa8);
      *puVar4 = *(undefined8 *)(lVar6 + 0xa0);
      puVar4[1] = uVar7;
      puVar4[2] = *(undefined8 *)(lVar6 + 0xb0);
      uVar1 = *(undefined4 *)(lVar6 + 0xb8);
      *param_4 = (char *)puVar4;
      *(undefined4 *)(puVar4 + 3) = uVar1;
      *param_5 = 0x1c;
      break;
    }
    goto LAB_00119304;
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
    pthread_mutex_lock((pthread_mutex_t *)ProcessRawDataLock);
                    // try { // try from 0011932c to 00119347 has its CatchHandler @ 001196b0
    (**(code **)(**(long **)(this + 0x38) + 0x68))(*(long **)(this + 0x38),0);
    (**(code **)(**(long **)(this + 0x38) + 0x88))
              (*(long **)(this + 0x38),*(undefined4 *)(this + 0x48));
    if ((param_2 == (char *)0x0) || (param_3 < 1)) {
      iVar2 = -1;
    }
    else {
                    // try { // try from 00119570 to 00119573 has its CatchHandler @ 001196b0
      iVar2 = mp_test(this,param_1,*(int *)param_2);
    }
    if (param_1 == 0x10) {
                    // try { // try from 0011967c to 0011967f has its CatchHandler @ 001196b0
      (**(code **)(**(long **)(this + 0x38) + 0x68))(*(long **)(this + 0x38),1);
    }
    pthread_mutex_unlock((pthread_mutex_t *)ProcessRawDataLock);
    break;
  case 0x13:
    if (param_2 == (char *)0x0) {
      iVar2 = 0;
      __android_log_print(6,"FingerGoodix","Error_%d:in_buffer is NULL.",0xa30);
      break;
    }
    local_10 = *(undefined4 *)param_2;
    local_18 = 1;
    uStack_14 = 1;
    (**(code **)(*(long *)(this + 0x28) + 0x248))(*(long *)(this + 0x28),0x100000001,local_10);
LAB_00119304:
    iVar2 = 0;
    break;
  case 0x14:
    iVar2 = 0;
    puVar3 = (undefined4 *)malloc(4);
    local_18 = 1;
    uStack_14 = 1;
    (**(code **)(*(long *)(this + 0x28) + 0x250))(*(long *)(this + 0x28),&local_18);
    *param_4 = (char *)puVar3;
    *puVar3 = local_10;
    *param_5 = 4;
  }
LAB_0011925c:
  if (local_8 != ___stack_chk_guard) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail(iVar2);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// android::FpService::removeClient(android::sp<android::IFingerPrintClient> const&)

void __thiscall android::FpService::removeClient(FpService *this,sp *param_1)

{
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
  
  local_8 = ___stack_chk_guard;
  pplVar3 = (long **)(this + 0x20);
  __android_log_print(3,"FingerGoodix","FingerPrintService::removeClient,pid=%d",0x7b);
  iVar4 = 0;
  do {
    local_30 = (long *)0x0;
    if (*pplVar3 == (long *)0x0) {
                    // try { // try from 00119880 to 00119883 has its CatchHandler @ 00119984
      __android_log_print(3,"FingerGoodix","mClient[%d] is unused",iVar4);
LAB_00119884:
      if (local_30 != (long *)0x0) {
        android::RefBase::decStrong((void *)((long)local_30 + *(long *)(*local_30 + -0x18)));
      }
    }
    else {
                    // try { // try from 0011974c to 00119777 has its CatchHandler @ 00119984
      sp<>::operator=((sp<> *)&local_30,(sp *)pplVar3);
      if (local_30 == (long *)0x0) {
        plVar2 = *pplVar3;
        if (plVar2 != (long *)0x0) {
                    // try { // try from 001198fc to 0011995b has its CatchHandler @ 00119984
          android::RefBase::decStrong((void *)((long)plVar2 + *(long *)(*plVar2 + -0x18)));
          *pplVar3 = (long *)0x0;
        }
        __android_log_print(3,"FingerGoodix","mClient[%d] is null",iVar4);
        goto LAB_00119884;
      }
      local_28 = *(long **)param_1;
      if (local_28 != (long *)0x0) {
        android::RefBase::incStrong((void *)((long)local_28 + *(long *)(*local_28 + -0x18)));
      }
                    // try { // try from 00119780 to 00119783 has its CatchHandler @ 00119a10
      android::IInterface::asBinder((sp *)&local_28);
      local_18 = (long *)local_30[8];
      if (local_18 != (long *)0x0) {
                    // try { // try from 001197a4 to 001197a7 has its CatchHandler @ 001199ac
        android::RefBase::incStrong((void *)((long)local_18 + *(long *)(*local_18 + -0x18)));
      }
                    // try { // try from 001197b0 to 001197b3 has its CatchHandler @ 001199ec
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
        if (local_30 != (long *)0x0) {
          android::RefBase::decStrong((void *)((long)local_30 + *(long *)(*local_30 + -0x18)));
        }
        goto LAB_001198b0;
      }
      if (local_30 != (long *)0x0) {
        android::RefBase::decStrong((void *)((long)local_30 + *(long *)(*local_30 + -0x18)));
      }
    }
    pplVar3 = pplVar3 + 1;
    iVar4 = iVar4 + 1;
    if (iVar4 == 7) {
LAB_001198b0:
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
                    // try { // try from 00119b20 to 00119b23 has its CatchHandler @ 00119c38
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
                    // try { // try from 00119b8c to 00119b8f has its CatchHandler @ 00119cc0
  pthread_mutex_init((pthread_mutex_t *)(this + 0x50),(pthread_mutexattr_t *)0x0);
                    // try { // try from 00119b9c to 00119b9f has its CatchHandler @ 00119cb0
  pthread_mutex_init((pthread_mutex_t *)(this + 0x78),(pthread_mutexattr_t *)0x0);
                    // try { // try from 00119bc0 to 00119c1b has its CatchHandler @ 00119c50
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
                    // try { // try from 00119d24 to 00119d27 has its CatchHandler @ 00119e18
  IFingerPrint::IFingerPrint((IFingerPrint *)this);
                    // try { // try from 00119d34 to 00119d37 has its CatchHandler @ 00119eac
  android::BBinder::BBinder((BBinder *)(this + 8));
  *(undefined8 *)(this + 0x38) = 0;
  *(undefined8 *)this = 0x1426d8;
  *(undefined8 *)(this + 0xa0) = 0x142948;
  *(undefined8 *)(this + 8) = 0x142888;
  *(undefined8 *)(this + 0x40) = 0;
                    // try { // try from 00119d6c to 00119d6f has its CatchHandler @ 00119e9c
  pthread_mutex_init((pthread_mutex_t *)(this + 0x50),(pthread_mutexattr_t *)0x0);
                    // try { // try from 00119d7c to 00119d7f has its CatchHandler @ 00119e8c
  pthread_mutex_init((pthread_mutex_t *)(this + 0x78),(pthread_mutexattr_t *)0x0);
                    // try { // try from 00119da0 to 00119dfb has its CatchHandler @ 00119e2c
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
  uint uVar1;
  long *plVar2;
  undefined8 uVar3;
  undefined8 uVar4;
  long **in_x8;
  long lVar5;
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
  local_38 = (long *)0x0;
  if (6 < (uint)param_2) {
                    // try { // try from 00119f44 to 00119f47 has its CatchHandler @ 0011a2ec
    __android_log_print(6,"FingerGoodix","Warning: Invalid clientId:%d",param_2);
    *in_x8 = (long *)0x0;
    goto LAB_00119f50;
  }
                    // try { // try from 00119fa8 to 00119fab has its CatchHandler @ 0011a2ec
  pthread_mutex_lock((pthread_mutex_t *)(this + 0x1b0));
  lVar5 = (long)param_2;
  if (*(long *)(this + lVar5 * 8 + 0x20) == 0) {
LAB_0011a1a8:
    local_10 = (long *)this;
    android::RefBase::incStrong(this + *(long *)(*(long *)this + -0x18));
    uVar3 = *(undefined8 *)(this + 0x150);
    uVar4 = *(undefined8 *)(this + 0x158);
                    // try { // try from 0011a1d4 to 0011a1d7 has its CatchHandler @ 0011a3c8
    plVar2 = (long *)operator_new(0xb0);
                    // try { // try from 0011a1f0 to 0011a1f3 has its CatchHandler @ 0011a34c
    Client::Client((Client *)plVar2,(sp *)&local_10,param_1,(fpContext)uVar3,(int)uVar4,param_2);
                    // try { // try from 0011a204 to 0011a223 has its CatchHandler @ 0011a3c8
    android::RefBase::incStrong((Client *)((long)plVar2 + *(long *)(*plVar2 + -0x18)));
    if (local_38 != (long *)0x0) {
      android::RefBase::decStrong((Client *)((long)local_38 + *(long *)(*local_38 + -0x18)));
    }
    local_38 = plVar2;
    if (local_10 != (long *)0x0) {
      android::RefBase::decStrong((FpService *)((long)local_10 + *(long *)(*local_10 + -0x18)));
    }
                    // try { // try from 0011a250 to 0011a273 has its CatchHandler @ 0011a378
    sp<>::operator=((sp<> *)(this + (lVar5 + 4) * 8),(sp *)&local_38);
  }
  else {
                    // try { // try from 00119fd0 to 00119fff has its CatchHandler @ 0011a378
    sp<>::operator=((sp<> *)&local_38,(sp *)(this + (lVar5 + 4) * 8));
    if (local_38 == (long *)0x0) {
      plVar2 = *(long **)(this + lVar5 * 8 + 0x20);
      if (plVar2 != (long *)0x0) {
        android::RefBase::decStrong((void *)((long)plVar2 + *(long *)(*plVar2 + -0x18)));
        *(undefined8 *)(this + lVar5 * 8 + 0x20) = 0;
      }
      __android_log_print(3,"FingerGoodix","FingerPrintService::connect client is unused.");
      goto LAB_0011a1a8;
    }
    local_30 = *(long **)param_1;
    if (local_30 != (long *)0x0) {
      android::RefBase::incStrong((void *)((long)local_30 + *(long *)(*local_30 + -0x18)));
    }
                    // try { // try from 0011a010 to 0011a013 has its CatchHandler @ 0011a318
    android::IInterface::asBinder((sp *)&local_30);
    local_20 = (long *)local_38[8];
    if (local_20 != (long *)0x0) {
                    // try { // try from 0011a03c to 0011a03f has its CatchHandler @ 0011a380
      android::RefBase::incStrong((void *)((long)local_20 + *(long *)(*local_20 + -0x18)));
    }
                    // try { // try from 0011a050 to 0011a053 has its CatchHandler @ 0011a3a4
    android::IInterface::asBinder((sp *)&local_20);
    plVar2 = local_28;
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
    if (plVar2 != local_18) {
                    // try { // try from 0011a0ec to 0011a1c3 has its CatchHandler @ 0011a378
      __android_log_print(3,"FingerGoodix","FingerPrintService::connect X(pid %d),client is exist.",
                          0x7b);
      __android_log_print(3,"FingerGoodix","fpservice: mCurStatus:%d\n",*(undefined4 *)(this + 0xe4)
                         );
      uVar1 = *(uint *)(this + 0xe4);
      if ((uVar1 - 0xd < 3 || uVar1 - 10 < 2) || ((uVar1 & 0xfffffffb) - 2 < 2)) {
                    // try { // try from 0011a28c to 0011a2e3 has its CatchHandler @ 0011a378
        (**(code **)(*(long *)(this + 0x158) + 0x1b8))(*(long *)(this + 0x158));
      }
      (**(code **)(*(long *)this + 0x80))(this,1);
      (**(code **)(*local_38 + 0x28))(local_38);
      if (local_38 != (long *)0x0) {
        android::RefBase::decStrong((Client *)((long)local_38 + *(long *)(*local_38 + -0x18)));
      }
      local_38 = (long *)0x0;
      setFingerPrintFree(this,0x7b);
      __android_log_print(3,"FingerGoodix",
                          "FingerPrintService::connect X(pid %d),client is exist. but not same",0x7b
                         );
      goto LAB_0011a1a8;
    }
    __android_log_print(3,"FingerGoodix","FingerPrintService::connect X(pid %d) the same client",
                        0x7b);
  }
  *in_x8 = local_38;
  if (local_38 != (long *)0x0) {
    android::RefBase::incStrong((Client *)((long)local_38 + *(long *)(*local_38 + -0x18)));
  }
  pthread_mutex_unlock((pthread_mutex_t *)(this + 0x1b0));
LAB_00119f50:
  if (local_38 != (long *)0x0) {
    android::RefBase::decStrong((Client *)((long)local_38 + *(long *)(*local_38 + -0x18)));
  }
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
                    // try { // try from 0011a434 to 0011a437 has its CatchHandler @ 0011a5f8
  pthread_mutex_lock((pthread_mutex_t *)(this + 0x50));
  if ((*(int *)(this + 0x4c) != 0) && (iVar2 = checkPid(this), iVar2 != 0)) {
    __android_log_print(3,"FingerGoodix","Tried to connect to a locked fp (old pid %d, new pid %d)",
                        *(undefined4 *)(this + 0x4c),0x7b);
    uVar3 = 0x10;
    goto LAB_0011a550;
  }
  if (*(long *)(this + 0x40) == 0) {
LAB_0011a594:
    *(undefined4 *)(this + 0x4c) = 0x7b;
                    // try { // try from 0011a5a4 to 0011a5eb has its CatchHandler @ 0011a688
    sp<>::operator=((sp<> *)(this + 0x40),param_1);
    __android_log_print(3,"FingerGoodix","Client::connect X (pid %d)",0x7b);
  }
  else {
    local_28 = *(long **)param_1;
    if (local_28 != (long *)0x0) {
                    // try { // try from 0011a468 to 0011a46b has its CatchHandler @ 0011a680
      android::RefBase::incStrong((void *)((long)local_28 + *(long *)(*local_28 + -0x18)));
    }
                    // try { // try from 0011a47c to 0011a47f has its CatchHandler @ 0011a678
    android::IInterface::asBinder((sp *)&local_28);
    local_18 = *(long **)(this + 0x40);
    if (local_18 != (long *)0x0) {
                    // try { // try from 0011a4a0 to 0011a4a3 has its CatchHandler @ 0011a670
      android::RefBase::incStrong((void *)((long)local_18 + *(long *)(*local_18 + -0x18)));
    }
                    // try { // try from 0011a4b0 to 0011a4b3 has its CatchHandler @ 0011a60c
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
    if (plVar1 != local_10) goto LAB_0011a594;
                    // try { // try from 0011a548 to 0011a54b has its CatchHandler @ 0011a688
    __android_log_print(3,"FingerGoodix","Client::Connect to the same client");
  }
  uVar3 = 0;
LAB_0011a550:
  pthread_mutex_unlock((pthread_mutex_t *)(this + 0x50));
  pthread_mutex_unlock((pthread_mutex_t *)(this + 0x78));
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar3);
}



// android::FpService::Client::gfCmdM(int, unsigned char*, int, unsigned char*, int, int*)

undefined4 __thiscall
android::FpService::Client::gfCmdM
          (Client *this,int param_1,uchar *param_2,int param_3,uchar *param_4,int param_5,
          int *param_6)

{
  undefined4 uVar1;
  long lVar2;
  
  __android_log_print(3,"FingerGoodix","M gfCmdM, cmd:%d, req_data_len:%d",param_1,param_3);
  if (param_1 == 7) {
    (**(code **)(*(long *)(this + 0x28) + 0x2c8))(0);
    return 0;
  }
  if (param_1 < 8) {
    if (param_1 == 1) {
      if (param_3 == 4) {
        uVar1 = *(undefined4 *)param_2;
        __android_log_print(3,"FingerGoodix","M gfCmdM, set active froup:%d",uVar1);
        (**(code **)(*(long *)this + 0x168))(this,uVar1);
        return 0;
      }
      uVar1 = 0xffffffff;
    }
    else {
      if (param_1 != 6) goto LAB_0011a808;
      uVar1 = 0;
      (**(code **)(*(long *)(this + 0x28) + 0x2c8))(1);
    }
    return uVar1;
  }
  if (param_1 - 0x96U < 2) {
    lVar2 = *(long *)(this + 0x28);
    *param_6 = param_5;
    uVar1 = (**(code **)(lVar2 + 0x2d8))(param_1,param_2,param_3,param_4,param_6);
    __android_log_print(3,"FingerGoodix","send_cmd_to_ta:ret:%d, command:%d, rsp data length:%d",
                        uVar1,param_1,*param_6);
    return uVar1;
  }
LAB_0011a808:
  __android_log_print(3,"FingerGoodix","service pass the cmd to HAL.");
  uVar1 = (**(code **)(*(long *)(this + 0x28) + 0x2c0))
                    (*(long *)(this + 0x28),param_1,param_2,param_3,param_4,param_5,param_6);
  return uVar1;
}



// android::FpService::Client::getFingerPrintId()

undefined4 __thiscall android::FpService::Client::getFingerPrintId(Client *this)

{
  return *(undefined4 *)(this + 0x48);
}



// android::FpService::Client::deactivateClient()

void __thiscall android::FpService::Client::deactivateClient(Client *this)

{
  undefined4 uVar1;
  
  if (DAT_00146310 != this) {
    return;
  }
  uVar1 = getFingerPrintId(this);
  __android_log_print(3,"FingerGoodix","remove active client:%d",uVar1);
  DAT_00146310 = (Client *)0x0;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// android::FpService::switchClient(android::FpService::Client*, android::FpService::Client*)

void __thiscall android::FpService::switchClient(FpService *this,Client *param_1,Client *param_2)

{
  undefined4 uVar1;
  uint uVar2;
  uint local_c;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  if (param_2 != (Client *)0x0) {
    uVar1 = Client::getFingerPrintId(param_2);
    __android_log_print(3,"FingerGoodix","Swicth client, old client id:%d",uVar1);
  }
  if (param_1 != (Client *)0x0) {
    uVar2 = Client::getFingerPrintId(param_1);
    __android_log_print(3,"FingerGoodix","Swicth client, new client id:%d",uVar2);
    __android_log_print(3,"FingerGoodix","Cancel old action");
    (**(code **)(*(long *)param_1 + 200))(param_1);
    (**(code **)(*(long *)param_1 + 0x80))(param_1);
    local_c = uVar2;
    (**(code **)(*(long *)(this + 0x158) + 0x2c0))(*(long *)(this + 0x158),0x51,&local_c,4,0,0,0);
    DAT_00146310 = param_1;
    (**(code **)(*(long *)this + 0x88))(this,uVar2);
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(0);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// android::FpService::Client::prepareFpEnv()

void __thiscall android::FpService::Client::prepareFpEnv(Client *this)

{
  Client *this_00;
  int iVar1;
  int iVar2;
  long *plVar3;
  undefined8 uVar4;
  undefined4 local_14;
  long *local_10;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  iVar1 = (**(code **)(*(long *)(this + 0x28) + 0x2d0))();
  if (iVar1 == 0) {
    __android_log_print(6,"FingerGoodix","prepare FpEnv, fingerprint has been disabled!");
    uVar4 = 0xffffffff;
    goto LAB_0011ab6c;
  }
  pthread_mutex_lock((pthread_mutex_t *)&DAT_00146318);
                    // try { // try from 0011aa98 to 0011aaeb has its CatchHandler @ 0011ac2c
  __android_log_print(3,"FingerGoodix","prepare FpEnv, active client=%p",DAT_00146310);
  this_00 = DAT_00146310;
  if (DAT_00146310 == (Client *)0x0) {
    local_14 = *(undefined4 *)(this + 0x48);
    DAT_00146310 = this;
    (**(code **)(*(long *)(this + 0x28) + 0x2c0))(*(long *)(this + 0x28),0x51,&local_14,4,0,0,0);
  }
  else if (this != DAT_00146310) {
    iVar1 = getFingerPrintId(this);
    iVar2 = getFingerPrintId(this_00);
    plVar3 = *(long **)(this + 0x38);
    if (iVar2 < iVar1) {
      local_10 = plVar3;
      if (plVar3 == (long *)0x0) {
        plVar3 = (long *)0x0;
      }
      else {
        android::RefBase::incStrong((FpService *)((long)plVar3 + *(long *)(*plVar3 + -0x18)));
        plVar3 = local_10;
      }
      iVar1 = *(int *)((long)plVar3 + 0xe4);
                    // try { // try from 0011ab0c to 0011ab23 has its CatchHandler @ 0011ac44
      __android_log_print(3,"FingerGoodix","wait to prepare AlgoEnv, mode=%d, status=%d",
                          *(undefined4 *)(plVar3 + 0x1d),iVar1);
      if (iVar1 - 2U < 8) {
        do {
          usleep(50000);
        } while (*(int *)((long)local_10 + 0xe4) - 2U < 8);
LAB_0011ab38:
        android::RefBase::decStrong((FpService *)((long)local_10 + *(long *)(*local_10 + -0x18)));
      }
      else if (local_10 != (long *)0x0) goto LAB_0011ab38;
                    // try { // try from 0011ab58 to 0011ab5b has its CatchHandler @ 0011ac2c
      switchClient(*(FpService **)(this + 0x38),this,this_00);
    }
    else {
                    // try { // try from 0011aba0 to 0011abf7 has its CatchHandler @ 0011ac2c
      switchClient((FpService *)plVar3,this,this_00);
      __android_log_print(3,"FingerGoodix","Change the active client.");
    }
  }
  pthread_mutex_unlock((pthread_mutex_t *)&DAT_00146318);
  uVar4 = 0;
LAB_0011ab6c:
  if (local_8 != ___stack_chk_guard) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail(uVar4);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// android::FpService::Client::setActiveGroup(int)

void __thiscall android::FpService::Client::setActiveGroup(Client *this,int param_1)

{
  int iVar1;
  undefined4 local_10;
  int local_c;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","Set the active group");
  iVar1 = (**(code **)(*(long *)this + 0x160))(this);
  if (iVar1 == 0) {
    if (DAT_00146340 == param_1) {
      __android_log_print(3,"FingerGoodix","The active group is not changed.");
    }
    else {
      DAT_00146340 = param_1;
      __android_log_print(3,"FingerGoodix","Client[%d] set active group to %d",
                          *(undefined4 *)(this + 0x48),param_1);
      (**(code **)(*(long *)this + 0x80))(this);
      (**(code **)(*(long *)this + 200))(this);
      (**(code **)(*(long *)(this + 0x28) + 0x98))(*(long *)(this + 0x28));
      local_10 = *(undefined4 *)(this + 0x48);
      (**(code **)(*(long *)(this + 0x28) + 0x2c0))(*(long *)(this + 0x28),0x51,&local_10,4,0,0,0);
      local_c = param_1;
      (**(code **)(*(long *)(this + 0x28) + 0x2c0))(*(long *)(this + 0x28),0x50,&local_c,4,0,0,0);
      (**(code **)(**(long **)(this + 0x38) + 0x78))(*(long **)(this + 0x38));
    }
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(iVar1);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0011ade0(undefined8 param_1,undefined8 param_2)

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
      FUN_0011ade0("persist.sys.fp.vendor","switchf");
    }
    else {
      FUN_0011ade0("persist.sys.fp.vendor",&DAT_00136c58);
    }
  }
  uVar1 = (ulong)local_68 >> 8;
  local_68 = CONCAT71((uint7)uVar1 & 0xffffffffffff00,0x30);
  FUN_0011ade0("persist.sys.fp.goodix",&local_68);
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
  FUN_0011ade0("persist.sys.fp.goodix",local_10);
  FUN_0011ade0("persist.sys.fp.vendor","goodix");
  local_10[0] = 0x31;
  FUN_0011ade0("persist.sys.fp.onstart",local_10);
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
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
                    // try { // try from 0011b180 to 0011b183 has its CatchHandler @ 0011b2f8
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011b188 to 0011b2d3 has its CatchHandler @ 0011b2dc
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
            (*(long **)(this + 0x10),0x23,aPStack_d8,aPStack_70,0);
  android::Parcel::readExceptionCode();
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
                    // try { // try from 0011b360 to 0011b363 has its CatchHandler @ 0011b418
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011b368 to 0011b3b7 has its CatchHandler @ 0011b3fc
  android::IFingerPrint::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  android::Parcel::writeInt32((int)aPStack_d8);
  (**(code **)(**(long **)((ulong)param_1 + 0x10) + 0x28))
            (*(long **)((ulong)param_1 + 0x10),0x1f,aPStack_d8,aPStack_70,0);
  android::Parcel::readExceptionCode();
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
                    // try { // try from 0011b478 to 0011b47b has its CatchHandler @ 0011b530
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011b480 to 0011b4cf has its CatchHandler @ 0011b514
  android::IFingerPrint::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  android::Parcel::writeInt32((int)aPStack_d8);
  (**(code **)(**(long **)((ulong)param_1 + 0x10) + 0x28))
            (*(long **)((ulong)param_1 + 0x10),0x22,aPStack_d8,aPStack_70,0);
  android::Parcel::readExceptionCode();
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
                    // try { // try from 0011b588 to 0011b58b has its CatchHandler @ 0011b630
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011b590 to 0011b5d3 has its CatchHandler @ 0011b614
  android::IFingerPrint::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  (**(code **)(**(long **)(this + 0x10) + 0x28))
            (*(long **)(this + 0x10),0x1e,aPStack_d8,aPStack_70,0);
  android::Parcel::readExceptionCode();
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
                    // try { // try from 0011b688 to 0011b68b has its CatchHandler @ 0011b730
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011b690 to 0011b6d3 has its CatchHandler @ 0011b714
  android::IFingerPrint::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  (**(code **)(**(long **)(this + 0x10) + 0x28))
            (*(long **)(this + 0x10),0x1d,aPStack_d8,aPStack_70,0);
  android::Parcel::readExceptionCode();
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
                    // try { // try from 0011b7a8 to 0011b7ab has its CatchHandler @ 0011b8a0
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011b7b0 to 0011b83b has its CatchHandler @ 0011b884
  android::IFingerPrint::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  iVar1 = (int)aPStack_d8;
  android::Parcel::writeInt32(iVar1);
  android::Parcel::writeInt32(iVar1);
  android::Parcel::write(aPStack_d8,(ulong)param_2);
  (**(code **)(**(long **)(this + 0x10) + 0x28))
            (*(long **)(this + 0x10),0x1b,aPStack_d8,aPStack_70,0);
  android::Parcel::readExceptionCode();
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
                    // try { // try from 0011b90c to 0011b90f has its CatchHandler @ 0011b9fc
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011b914 to 0011b9d7 has its CatchHandler @ 0011b9e0
  android::IFingerPrint::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  android::Parcel::writeInt32((int)aPStack_d8);
  (**(code **)(**(long **)(this + 0x10) + 0x28))
            (*(long **)(this + 0x10),0x19,aPStack_d8,aPStack_70,0);
  android::Parcel::readExceptionCode();
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
                    // try { // try from 0011ba54 to 0011ba57 has its CatchHandler @ 0011bafc
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011ba5c to 0011ba9f has its CatchHandler @ 0011bae0
  android::IFingerPrint::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  (**(code **)(**(long **)(this + 0x10) + 0x28))
            (*(long **)(this + 0x10),0x17,aPStack_d8,aPStack_70,0);
  android::Parcel::readExceptionCode();
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
                    // try { // try from 0011bb5c to 0011bb5f has its CatchHandler @ 0011bc2c
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011bb64 to 0011bbcf has its CatchHandler @ 0011bc10
  android::IFingerPrint::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  android::Parcel::writeInt32((int)aPStack_d8);
  (**(code **)(**(long **)((ulong)(uint)param_1 + 0x10) + 0x28))
            (*(long **)((ulong)(uint)param_1 + 0x10),0x16,aPStack_d8,aPStack_70,0);
  android::Parcel::readExceptionCode();
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
                    // try { // try from 0011bc94 to 0011bc97 has its CatchHandler @ 0011bd90
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011bc9c to 0011bd6b has its CatchHandler @ 0011bd74
  android::IFingerPrint::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  (**(code **)(**(long **)(this + 0x10) + 0x28))
            (*(long **)(this + 0x10),0x15,aPStack_d8,aPStack_70,0);
  android::Parcel::readExceptionCode();
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
                    // try { // try from 0011bdf4 to 0011bdf7 has its CatchHandler @ 0011bebc
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011bdfc to 0011be5b has its CatchHandler @ 0011bea0
  android::IFingerPrint::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  android::Parcel::writeInt32((int)aPStack_d8);
  android::Parcel::write(aPStack_d8,(ulong)param_2);
  (**(code **)(**(long **)(param_1 + 4) + 0x28))
            (*(long **)(param_1 + 4),0x14,aPStack_d8,aPStack_70,0);
  android::Parcel::readExceptionCode();
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
                    // try { // try from 0011bf14 to 0011bf17 has its CatchHandler @ 0011bfbc
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011bf1c to 0011bf5f has its CatchHandler @ 0011bfa0
  android::IFingerPrint::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  (**(code **)(**(long **)(this + 0x10) + 0x28))
            (*(long **)(this + 0x10),0x11,aPStack_d8,aPStack_70,0);
  android::Parcel::readExceptionCode();
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
                    // try { // try from 0011c02c to 0011c02f has its CatchHandler @ 0011c114
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011c034 to 0011c0af has its CatchHandler @ 0011c0f8
  android::IFingerPrint::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  iVar1 = (int)aPStack_d8;
  android::Parcel::writeInt32(iVar1);
  android::Parcel::write(aPStack_d8,(ulong)(uint)param_2);
  android::Parcel::writeInt32(iVar1);
  android::Parcel::write(aPStack_d8,(ulong)(uint)param_4);
  (**(code **)(**(long **)(param_1 + 0x10) + 0x28))
            (*(long **)(param_1 + 0x10),0x20,aPStack_d8,aPStack_70,0);
  android::Parcel::readExceptionCode();
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
                    // try { // try from 0011c1dc to 0011c1df has its CatchHandler @ 0011c298
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011c1e4 to 0011c24f has its CatchHandler @ 0011c2b0
  android::IFingerPrint::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  iVar2 = (int)aPStack_d8;
  android::Parcel::writeInt32(iVar2);
  android::Parcel::write(aPStack_d8,(ulong)param_2);
  android::Parcel::writeInt32(iVar2);
  (**(code **)(**(long **)(param_1 + 4) + 0x28))
            (*(long **)(param_1 + 4),0x10,aPStack_d8,aPStack_70,0);
  android::Parcel::readExceptionCode();
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
// BpFingerPrint::recognize(void*)

void __thiscall BpFingerPrint::recognize(BpFingerPrint *this,void *param_1)

{
  undefined4 uVar1;
  Parcel aPStack_d8 [104];
  Parcel aPStack_70 [104];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","client,recognize");
  android::Parcel::Parcel(aPStack_d8);
                    // try { // try from 0011c318 to 0011c31b has its CatchHandler @ 0011c3e0
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011c320 to 0011c37f has its CatchHandler @ 0011c3c4
  android::IFingerPrint::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  android::Parcel::writeInt32((int)aPStack_d8);
  android::Parcel::write(aPStack_d8,(ulong)param_1);
  (**(code **)(**(long **)(this + 0x10) + 0x28))
            (*(long **)(this + 0x10),0xf,aPStack_d8,aPStack_70,0);
  android::Parcel::readExceptionCode();
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
                    // try { // try from 0011c440 to 0011c443 has its CatchHandler @ 0011c4f8
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011c448 to 0011c497 has its CatchHandler @ 0011c4dc
  android::IFingerPrint::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  android::Parcel::writeInt32((int)aPStack_d8);
  (**(code **)(**(long **)((ulong)(uint)param_1 + 0x10) + 0x28))
            (*(long **)((ulong)(uint)param_1 + 0x10),0xd,aPStack_d8,aPStack_70,0);
  android::Parcel::readExceptionCode();
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
                    // try { // try from 0011c558 to 0011c55b has its CatchHandler @ 0011c610
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011c560 to 0011c5af has its CatchHandler @ 0011c5f4
  android::IFingerPrint::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  android::Parcel::writeInt32((int)aPStack_d8);
  (**(code **)(**(long **)((ulong)(uint)param_1 + 0x10) + 0x28))
            (*(long **)((ulong)(uint)param_1 + 0x10),0xc,aPStack_d8,aPStack_70,0);
  android::Parcel::readExceptionCode();
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
                    // try { // try from 0011c668 to 0011c66b has its CatchHandler @ 0011c710
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011c670 to 0011c6b3 has its CatchHandler @ 0011c6f4
  android::IFingerPrint::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  (**(code **)(**(long **)(this + 0x10) + 0x28))
            (*(long **)(this + 0x10),0xb,aPStack_d8,aPStack_70,0);
  android::Parcel::readExceptionCode();
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
                    // try { // try from 0011c768 to 0011c76b has its CatchHandler @ 0011c810
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011c770 to 0011c7b3 has its CatchHandler @ 0011c7f4
  android::IFingerPrint::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  (**(code **)(**(long **)(this + 0x10) + 0x28))(*(long **)(this + 0x10),10,aPStack_d8,aPStack_70,0)
  ;
  android::Parcel::readExceptionCode();
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
                    // try { // try from 0011c868 to 0011c86b has its CatchHandler @ 0011c910
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011c870 to 0011c8b3 has its CatchHandler @ 0011c8f4
  android::IFingerPrint::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  (**(code **)(**(long **)(this + 0x10) + 0x28))(*(long **)(this + 0x10),9,aPStack_d8,aPStack_70,0);
  android::Parcel::readExceptionCode();
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
                    // try { // try from 0011c968 to 0011c96b has its CatchHandler @ 0011ca10
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011c970 to 0011c9b3 has its CatchHandler @ 0011c9f4
  android::IFingerPrint::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  (**(code **)(**(long **)(this + 0x10) + 0x28))(*(long **)(this + 0x10),8,aPStack_d8,aPStack_70,0);
  android::Parcel::readExceptionCode();
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
// BpFingerPrint::load_all_fpdata(void*)

void __thiscall BpFingerPrint::load_all_fpdata(BpFingerPrint *this,void *param_1)

{
  undefined4 uVar1;
  int iVar2;
  Parcel aPStack_d8 [104];
  Parcel aPStack_70 [104];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  android::Parcel::Parcel(aPStack_d8);
                    // try { // try from 0011ca58 to 0011ca5b has its CatchHandler @ 0011cb74
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011ca60 to 0011cb4f has its CatchHandler @ 0011cb58
  android::IFingerPrint::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  android::Parcel::writeInt32((int)aPStack_d8);
  android::Parcel::write(aPStack_d8,(ulong)param_1);
  (**(code **)(**(long **)(this + 0x10) + 0x28))
            (*(long **)(this + 0x10),0x25,aPStack_d8,aPStack_70,0);
  android::Parcel::readExceptionCode();
  uVar1 = android::Parcel::readInt32();
  iVar2 = android::Parcel::readInt32();
  if (iVar2 == 0x80) {
    android::Parcel::read(aPStack_70,(ulong)param_1);
    __android_log_print(3,"FingerGoodix","client, load_all_fpdata OK!");
  }
  else {
    __android_log_print(3,"FingerGoodix","client, load_all_fpdata fialed!");
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
                    // try { // try from 0011cbd4 to 0011cbd7 has its CatchHandler @ 0011cc8c
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011cbdc to 0011cc2b has its CatchHandler @ 0011cc70
  android::IFingerPrint::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  android::Parcel::writeInt32((int)aPStack_d8);
  (**(code **)(**(long **)((ulong)(uint)param_1 + 0x10) + 0x28))
            (*(long **)((ulong)(uint)param_1 + 0x10),7,aPStack_d8,aPStack_70,0);
  android::Parcel::readExceptionCode();
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
                    // try { // try from 0011cce4 to 0011cce7 has its CatchHandler @ 0011cd8c
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011ccec to 0011cd2f has its CatchHandler @ 0011cd70
  android::IFingerPrint::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  (**(code **)(**(long **)(this + 0x10) + 0x28))(*(long **)(this + 0x10),5,aPStack_d8,aPStack_70,0);
  android::Parcel::readExceptionCode();
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
                    // try { // try from 0011cdec to 0011cdef has its CatchHandler @ 0011cea4
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011cdf4 to 0011ce43 has its CatchHandler @ 0011ce88
  android::IFingerPrint::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  android::Parcel::writeInt32((int)aPStack_d8);
  (**(code **)(**(long **)((ulong)(uint)param_1 + 0x10) + 0x28))
            (*(long **)((ulong)(uint)param_1 + 0x10),4,aPStack_d8,aPStack_70,0);
  android::Parcel::readExceptionCode();
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
                    // try { // try from 0011cefc to 0011ceff has its CatchHandler @ 0011cfa4
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011cf04 to 0011cf47 has its CatchHandler @ 0011cf88
  android::IFingerPrint::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  (**(code **)(**(long **)(this + 0x10) + 0x28))(*(long **)(this + 0x10),2,aPStack_d8,aPStack_70,0);
  android::Parcel::readExceptionCode();
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
                    // try { // try from 0011d010 to 0011d013 has its CatchHandler @ 0011d0c8
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011d018 to 0011d067 has its CatchHandler @ 0011d0ac
  android::IFingerPrint::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  android::Parcel::writeInt64((long)aPStack_d8);
  (**(code **)(**(long **)(param_1 + 0x10) + 0x28))
            (*(long **)(param_1 + 0x10),0x1c,aPStack_d8,aPStack_70,0);
  android::Parcel::readExceptionCode();
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
// BpFingerPrint::set_user_id(unsigned long)

void BpFingerPrint::set_user_id(ulong param_1)

{
  undefined4 uVar1;
  Parcel aPStack_d8 [104];
  Parcel aPStack_70 [104];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","client,set_user_id");
  android::Parcel::Parcel(aPStack_d8);
                    // try { // try from 0011d128 to 0011d12b has its CatchHandler @ 0011d1e0
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011d130 to 0011d17f has its CatchHandler @ 0011d1c4
  android::IFingerPrint::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  android::Parcel::writeInt64((long)aPStack_d8);
  (**(code **)(**(long **)(param_1 + 0x10) + 0x28))
            (*(long **)(param_1 + 0x10),0x24,aPStack_d8,aPStack_70,0);
  android::Parcel::readExceptionCode();
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
                    // try { // try from 0011d238 to 0011d23b has its CatchHandler @ 0011d2e8
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011d240 to 0011d28b has its CatchHandler @ 0011d2cc
  android::IFingerPrint::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  (**(code **)(**(long **)(this + 0x10) + 0x28))(*(long **)(this + 0x10),3,aPStack_d8,aPStack_70,0);
  android::Parcel::readExceptionCode();
  android::Parcel::readInt32();
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
                    // try { // try from 0011d350 to 0011d353 has its CatchHandler @ 0011d430
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011d358 to 0011d3cf has its CatchHandler @ 0011d414
  android::IFingerPrint::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  android::Parcel::writeInt32((int)aPStack_d8);
  android::Parcel::writeCString((char *)aPStack_d8);
  (**(code **)(**(long **)((ulong)(uint)param_1 + 0x10) + 0x28))
            (*(long **)((ulong)(uint)param_1 + 0x10),0x18,aPStack_d8,aPStack_70,0);
  android::Parcel::readExceptionCode();
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
                    // try { // try from 0011d490 to 0011d493 has its CatchHandler @ 0011d548
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011d498 to 0011d4e7 has its CatchHandler @ 0011d52c
  android::IFingerPrint::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  android::Parcel::writeCString((char *)aPStack_d8);
  (**(code **)(**(long **)(param_1 + 0x10) + 0x28))
            (*(long **)(param_1 + 0x10),0x13,aPStack_d8,aPStack_70,0);
  android::Parcel::readExceptionCode();
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
                    // try { // try from 0011d5ac to 0011d5af has its CatchHandler @ 0011d670
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011d5b4 to 0011d60f has its CatchHandler @ 0011d654
  android::IFingerPrint::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  android::Parcel::writeCString((char *)aPStack_d8);
  android::Parcel::writeCString((char *)aPStack_d8);
  (**(code **)(**(long **)(param_1 + 0x10) + 0x28))
            (*(long **)(param_1 + 0x10),0x12,aPStack_d8,aPStack_70,0);
  android::Parcel::readExceptionCode();
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
                    // try { // try from 0011d6d0 to 0011d6d3 has its CatchHandler @ 0011d7bc
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011d6d8 to 0011d797 has its CatchHandler @ 0011d7a0
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
  android::Parcel::readExceptionCode();
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
                    // try { // try from 0011d81c to 0011d81f has its CatchHandler @ 0011d8d4
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011d824 to 0011d873 has its CatchHandler @ 0011d8b8
  android::IFingerPrint::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  android::Parcel::writeCString((char *)aPStack_d8);
  (**(code **)(**(long **)(param_1 + 0x10) + 0x28))
            (*(long **)(param_1 + 0x10),6,aPStack_d8,aPStack_70,0);
  android::Parcel::readExceptionCode();
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
// BpFingerPrint::set_fpdb_to_ta(char*)

void __thiscall BpFingerPrint::set_fpdb_to_ta(BpFingerPrint *this,char *param_1)

{
  undefined4 uVar1;
  size_t sVar2;
  Parcel aPStack_d8 [104];
  Parcel aPStack_70 [104];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  sVar2 = strlen(param_1);
  __android_log_print(3,"FingerGoodix","client,set_fpdb_to_ta,data_len:%d",sVar2 & 0xffffffff);
  android::Parcel::Parcel(aPStack_d8);
                    // try { // try from 0011d944 to 0011d947 has its CatchHandler @ 0011da14
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011d94c to 0011d9b3 has its CatchHandler @ 0011d9f8
  android::IFingerPrint::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  android::Parcel::writeInt32((int)aPStack_d8);
  if (0 < (int)sVar2) {
    android::Parcel::write(aPStack_d8,(ulong)param_1);
  }
  (**(code **)(**(long **)(this + 0x10) + 0x28))
            (*(long **)(this + 0x10),0x26,aPStack_d8,aPStack_70,0);
  android::Parcel::readExceptionCode();
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
  int iVar1;
  undefined4 uVar2;
  char *__ptr;
  Parcel aPStack_d8 [104];
  Parcel aPStack_70 [104];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","client,SendCmd");
  android::Parcel::Parcel(aPStack_d8);
                    // try { // try from 0011da8c to 0011da8f has its CatchHandler @ 0011dbbc
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011da94 to 0011db43 has its CatchHandler @ 0011dba0
  android::IFingerPrint::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  iVar1 = (int)aPStack_d8;
  android::Parcel::writeInt32(iVar1);
  android::Parcel::writeInt32(iVar1);
  if ((param_3 != 0) && (param_2 != (char *)0x0)) {
    android::Parcel::write(aPStack_d8,(ulong)param_2);
  }
  (**(code **)(**(long **)(this + 0x10) + 0x28))
            (*(long **)(this + 0x10),0x21,aPStack_d8,aPStack_70,0);
  android::Parcel::readExceptionCode();
  iVar1 = android::Parcel::readInt32();
  if (iVar1 != 0) {
    __ptr = (char *)malloc((long)iVar1);
    android::Parcel::read(aPStack_70,(ulong)__ptr);
    if (param_5 == (int *)0x0) {
      free(__ptr);
    }
    else {
      *param_4 = __ptr;
    }
  }
  uVar2 = android::Parcel::readInt32();
  *param_5 = iVar1;
  android::Parcel::~Parcel(aPStack_70);
  android::Parcel::~Parcel(aPStack_d8);
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar2);
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
                    // try { // try from 0011dc1c to 0011dc1f has its CatchHandler @ 0011dd88
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011dc24 to 0011dc57 has its CatchHandler @ 0011dd80
  android::IFingerPrint::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  local_e8 = *(long **)param_1;
  if (local_e8 != (long *)0x0) {
    android::RefBase::incStrong((void *)((long)local_e8 + *(long *)(*local_e8 + -0x18)));
  }
                    // try { // try from 0011dc64 to 0011dc67 has its CatchHandler @ 0011dd78
  android::IInterface::asBinder((sp *)&local_e8);
                    // try { // try from 0011dc70 to 0011dc73 has its CatchHandler @ 0011dd24
  android::Parcel::writeStrongBinder((sp *)aPStack_d8);
  if (local_e0 != (long *)0x0) {
    android::RefBase::decStrong((void *)((long)local_e0 + *(long *)(*local_e0 + -0x18)));
  }
  if (local_e8 != (long *)0x0) {
    android::RefBase::decStrong((void *)((long)local_e8 + *(long *)(*local_e8 + -0x18)));
  }
                    // try { // try from 0011dccc to 0011dcdf has its CatchHandler @ 0011dd80
  (**(code **)(**(long **)(this + 0x10) + 0x28))(*(long **)(this + 0x10),1,aPStack_d8,aPStack_70,0);
  android::Parcel::readExceptionCode();
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
  int iVar3;
  undefined4 uVar4;
  int iVar5;
  uint uVar6;
  long *plVar7;
  undefined8 uVar8;
  void *pvVar9;
  char *__s;
  ulong uVar10;
  undefined8 uVar11;
  undefined8 *puVar12;
  char *pcVar13;
  ulong uVar14;
  code *pcVar15;
  undefined8 *puVar16;
  long lVar17;
  void *pvVar18;
  size_t sVar19;
  undefined4 local_98;
  undefined4 uStack_94;
  undefined8 local_90;
  void *local_88 [5];
  undefined8 uStack_60;
  undefined8 local_58;
  undefined8 uStack_50;
  ulong local_48;
  undefined8 uStack_40;
  undefined8 local_38;
  undefined8 uStack_30;
  undefined8 local_28;
  undefined8 uStack_20;
  undefined8 local_18;
  undefined8 uStack_10;
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
                    // try { // try from 0011e840 to 0011e843 has its CatchHandler @ 0011f448
      IFingerPrintClient::asInterface((sp *)&local_90);
      if (local_90 != (long *)0x0) {
        android::RefBase::decStrong((void *)((long)local_90 + *(long *)(*local_90 + -0x18)));
      }
                    // try { // try from 0011e870 to 0011e88b has its CatchHandler @ 0011f420
      (**(code **)(*plVar7 + 0x20))(plVar7,&local_98);
      android::Parcel::writeNoException();
      uVar2 = android::Parcel::writeInt32(param_4);
      plVar7 = (long *)CONCAT44(uStack_94,local_98);
      if (plVar7 != (long *)0x0) {
        android::RefBase::decStrong((void *)((long)plVar7 + *(long *)(*plVar7 + -0x18)));
      }
    }
    goto LAB_0011dde0;
  case 2:
    __android_log_print(3,"FingerGoodix","server,disconnect");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      uVar2 = 0;
      android::Parcel::writeNoException();
      (**(code **)(*plVar7 + 0x28))(plVar7);
      android::Parcel::writeInt32(param_4);
      goto LAB_0011dde0;
    }
    break;
  case 3:
    __android_log_print(3,"FingerGoodix","server,get info");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      uVar2 = 0;
      android::Parcel::writeNoException();
      __s = (char *)(**(code **)(*plVar7 + 0x30))(plVar7);
      __android_log_print(3,"FingerGoodix","server,get info %s",__s);
      strlen(__s);
      android::Parcel::writeInt32(param_4);
      strlen(__s);
      android::Parcel::write(pcVar13,(ulong)__s);
      goto LAB_0011dde0;
    }
    break;
  case 4:
    __android_log_print(3,"FingerGoodix","server,eng test");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      android::Parcel::writeNoException();
      pcVar15 = *(code **)(*plVar7 + 0x38);
LAB_0011e17c:
      uVar2 = 0;
      uVar4 = android::Parcel::readInt32();
      (*pcVar15)(plVar7,uVar4);
      android::Parcel::writeInt32(param_4);
      goto LAB_0011dde0;
    }
    break;
  case 5:
    __android_log_print(3,"FingerGoodix","server,query");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      uVar2 = 0;
      android::Parcel::writeNoException();
      (**(code **)(*plVar7 + 0x48))(plVar7);
      android::Parcel::writeInt32(param_4);
      goto LAB_0011dde0;
    }
    break;
  case 6:
    __android_log_print(3,"FingerGoodix","server,request permission");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      android::Parcel::writeNoException();
      pcVar15 = *(code **)(*plVar7 + 0x50);
      uVar8 = android::Parcel::readCString();
LAB_0011df00:
      uVar2 = 0;
      (*pcVar15)(plVar7,uVar8);
      android::Parcel::writeInt32(param_4);
      goto LAB_0011dde0;
    }
    break;
  case 7:
    __android_log_print(3,"FingerGoodix","server,send screen state");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      android::Parcel::writeNoException();
      pcVar15 = *(code **)(*plVar7 + 0x58);
      goto LAB_0011e17c;
    }
    break;
  case 8:
    __android_log_print(3,"FingerGoodix","server,regist");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      uVar2 = 0;
      android::Parcel::writeNoException();
      (**(code **)(*plVar7 + 0x78))(plVar7);
      android::Parcel::writeInt32(param_4);
      goto LAB_0011dde0;
    }
    break;
  case 9:
    __android_log_print(3,"FingerGoodix","server,cancel regist");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      uVar2 = 0;
      android::Parcel::writeNoException();
      (**(code **)(*plVar7 + 0x80))(plVar7);
      android::Parcel::writeInt32(param_4);
      goto LAB_0011dde0;
    }
    break;
  case 10:
    __android_log_print(3,"FingerGoodix","server,regist roll back");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      uVar2 = 0;
      android::Parcel::writeNoException();
      (**(code **)(*plVar7 + 0x88))(plVar7);
      android::Parcel::writeInt32(param_4);
      goto LAB_0011dde0;
    }
    break;
  case 0xb:
    __android_log_print(3,"FingerGoodix","server,reset regist");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      uVar2 = 0;
      android::Parcel::writeNoException();
      (**(code **)(*plVar7 + 0x90))(plVar7);
      android::Parcel::writeInt32(param_4);
      goto LAB_0011dde0;
    }
    break;
  case 0xc:
    __android_log_print(3,"FingerGoodix","server,unRegist");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      android::Parcel::writeNoException();
      pcVar15 = *(code **)(*plVar7 + 0x98);
      goto LAB_0011e17c;
    }
    break;
  case 0xd:
    __android_log_print(3,"FingerGoodix","server,save regist");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      android::Parcel::writeNoException();
      pcVar15 = *(code **)(*plVar7 + 0xa0);
      goto LAB_0011e17c;
    }
    break;
  case 0xe:
    __android_log_print(3,"FingerGoodix","server,save register()");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      android::Parcel::writeNoException();
      pcVar15 = *(code **)(*plVar7 + 0xa8);
      uVar8 = android::Parcel::readCString();
      goto LAB_0011df00;
    }
    break;
  case 0xf:
    uVar2 = 0xffffffff;
    __android_log_print(3,"FingerGoodix","server,recognize");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      local_48 = local_48 & 0xffffff0000000000;
      local_88[0] = (void *)0x0;
      local_88[1] = (void *)0x0;
      local_88[2] = (void *)0x0;
      local_88[3] = (void *)0x0;
      local_88[4] = (void *)0x0;
      uStack_60 = 0;
      local_58 = 0;
      uStack_50 = 0;
      iVar5 = android::Parcel::readInt32();
      if (0 < iVar5) {
        android::Parcel::read(param_3,(ulong)local_88);
      }
      uVar2 = 0;
      android::Parcel::writeNoException();
      (**(code **)(*plVar7 + 0xb0))(plVar7,local_88);
      android::Parcel::writeInt32(param_4);
    }
    goto LAB_0011dde0;
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
        goto LAB_0011dde0;
      }
      memset(pvVar18,0,sVar19);
      android::Parcel::read(param_3,(ulong)pvVar18);
      uVar2 = android::Parcel::readInt32();
      android::Parcel::writeNoException();
      (**(code **)(*plVar7 + 0xb8))(plVar7,pvVar18,(ulong)uVar6,uVar2);
LAB_0011eb68:
      uVar2 = 0;
      android::Parcel::writeInt32(param_4);
      free(pvVar18);
      goto LAB_0011dde0;
    }
    break;
  case 0x11:
    __android_log_print(3,"FingerGoodix","server,cancel recognize");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      uVar2 = 0;
      android::Parcel::writeNoException();
      (**(code **)(*plVar7 + 200))(plVar7);
      android::Parcel::writeInt32(param_4);
      goto LAB_0011dde0;
    }
    break;
  case 0x12:
    __android_log_print(3,"FingerGoodix","server,set passwd");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      uVar2 = 0;
      uVar8 = android::Parcel::readCString();
      uVar11 = android::Parcel::readCString();
      android::Parcel::writeNoException();
      (**(code **)(*plVar7 + 0xd0))(plVar7,uVar8,uVar11);
      android::Parcel::writeInt32(param_4);
      goto LAB_0011dde0;
    }
    break;
  case 0x13:
    __android_log_print(3,"FingerGoodix","server,check passwd");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      uVar2 = 0;
      uVar8 = android::Parcel::readCString();
      android::Parcel::writeNoException();
      (**(code **)(*plVar7 + 0xd8))(plVar7,uVar8);
      android::Parcel::writeInt32(param_4);
      goto LAB_0011dde0;
    }
    break;
  case 0x14:
    __android_log_print(3,"FingerGoodix","server,delFpTemplates");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      uVar10 = android::Parcel::readInt32();
      sVar19 = (uVar10 & 0xffffffff) << 2;
      pvVar18 = malloc(sVar19);
      if (pvVar18 == (void *)0x0) {
        uVar2 = 0xffffffff;
        __android_log_print(6,"FingerGoodix",
                            "IFingerPrint TRANSACTION_FP_DELETE_TEMPLATE out of memory");
        goto LAB_0011dde0;
      }
      memset(pvVar18,0,sVar19);
      android::Parcel::read(param_3,(ulong)pvVar18);
      android::Parcel::writeNoException();
      (**(code **)(*plVar7 + 0xe0))(plVar7,pvVar18,uVar10 & 0xffffffff);
      goto LAB_0011eb68;
    }
    break;
  case 0x15:
    uVar2 = 0xffffffff;
    __android_log_print(3,"FingerGoodix","server,getFpTemplateIdList");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 == '\0') goto LAB_0011dde0;
    local_90 = (long *)CONCAT44(local_90._4_4_,5);
    puVar16 = (undefined8 *)malloc(0x14);
    if (puVar16 == (undefined8 *)0x0) {
      __android_log_print(6,"FingerGoodix",
                          "IFingerPrint TRANSACTION_FP_GET_TEMPLATE_LIST out of memory");
      goto LAB_0011dde0;
    }
    lVar17 = *plVar7;
    *puVar16 = 0;
    puVar16[1] = 0;
    *(undefined4 *)(puVar16 + 2) = 0;
    iVar5 = (**(code **)(lVar17 + 0xe8))(plVar7,puVar16,&local_90);
    android::Parcel::writeInt32(param_4);
    if (iVar5 == 0) {
      android::Parcel::writeInt32(param_4);
      android::Parcel::write(pcVar13,(ulong)puVar16);
      __android_log_print(3,"FingerGoodix","templelist:%d,%d,%d",*(undefined4 *)puVar16,
                          *(undefined4 *)((long)puVar16 + 4),*(undefined4 *)(puVar16 + 1));
    }
    else {
      android::Parcel::writeInt32(param_4);
      android::Parcel::write(pcVar13,(ulong)puVar16);
    }
    goto LAB_0011eac8;
  case 0x16:
    __android_log_print(3,"FingerGoodix","server,setPauseRegisterState");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      uVar2 = 0;
      uVar4 = android::Parcel::readInt32();
      android::Parcel::writeNoException();
      (**(code **)(*plVar7 + 0xf0))(plVar7,uVar4);
      android::Parcel::writeInt32(param_4);
      goto LAB_0011dde0;
    }
    break;
  case 0x17:
    __android_log_print(3,"FingerGoodix","server,driverTest");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      uVar2 = 0;
      android::Parcel::writeNoException();
      (**(code **)(*plVar7 + 0xf8))(plVar7);
      android::Parcel::writeInt32(param_4);
      goto LAB_0011dde0;
    }
    break;
  case 0x18:
    __android_log_print(3,"FingerGoodix","server,modifyFpName");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      uVar2 = 0;
      uVar4 = android::Parcel::readInt32();
      uVar8 = android::Parcel::readCString();
      android::Parcel::writeNoException();
      (**(code **)(*plVar7 + 0x100))(plVar7,uVar4,uVar8);
      android::Parcel::writeInt32(param_4);
      goto LAB_0011dde0;
    }
    break;
  case 0x19:
    __android_log_print(3,"FingerGoodix","server,getFpNameById");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      uVar4 = android::Parcel::readInt32();
      puVar16 = (undefined8 *)malloc(0x80);
      if (puVar16 == (undefined8 *)0x0) {
        uVar2 = 0xffffffff;
        __android_log_print(6,"FingerGoodix","failed to malloc pName in server\'s getFpNameById");
        android::Parcel::writeInt32(param_4);
      }
      else {
        lVar17 = *plVar7;
        *puVar16 = 0;
        puVar16[1] = 0;
        puVar16[2] = 0;
        puVar16[3] = 0;
        puVar16[4] = 0;
        puVar16[5] = 0;
        puVar16[6] = 0;
        puVar16[7] = 0;
        puVar16[8] = 0;
        puVar16[9] = 0;
        puVar16[10] = 0;
        puVar16[0xb] = 0;
        puVar16[0xc] = 0;
        puVar16[0xd] = 0;
        puVar16[0xe] = 0;
        puVar16[0xf] = 0;
        uVar2 = 0;
        (**(code **)(lVar17 + 0x108))(plVar7,uVar4,puVar16);
        android::Parcel::writeNoException();
        android::Parcel::writeInt32(param_4);
        android::Parcel::write(pcVar13,(ulong)puVar16);
        free(puVar16);
      }
      goto LAB_0011dde0;
    }
    break;
  case 0x1a:
    uVar2 = 0xffffffff;
    __android_log_print(3,"FingerGoodix","server,getFpTemplateList");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      local_90 = (long *)CONCAT44(local_90._4_4_,5);
      puVar16 = (undefined8 *)malloc(0x14);
      if (puVar16 == (undefined8 *)0x0) {
        __android_log_print(6,"FingerGoodix","failed to malloc pIdList memory!!!");
      }
      else {
        *puVar16 = 0;
        puVar16[1] = 0;
        *(undefined4 *)(puVar16 + 2) = 0;
        lVar17 = 0;
        do {
          puVar12 = (undefined8 *)malloc(0x80);
          *(undefined8 **)((long)local_88 + lVar17) = puVar12;
          if (puVar12 == (undefined8 *)0x0) {
            uVar2 = 0xffffffff;
            __android_log_print(6,"FingerGoodix","failed to malloc pNameLists");
            goto LAB_0011dde0;
          }
          lVar17 = lVar17 + 8;
          *puVar12 = 0;
          puVar12[1] = 0;
          puVar12[2] = 0;
          puVar12[3] = 0;
          puVar12[4] = 0;
          puVar12[5] = 0;
          puVar12[6] = 0;
          puVar12[7] = 0;
          puVar12[8] = 0;
          puVar12[9] = 0;
          puVar12[10] = 0;
          puVar12[0xb] = 0;
          puVar12[0xc] = 0;
          puVar12[0xd] = 0;
          puVar12[0xe] = 0;
          puVar12[0xf] = 0;
        } while (lVar17 != 0x28);
        iVar5 = (**(code **)(*plVar7 + 0x110))(plVar7,&local_90,puVar16,local_88);
        android::Parcel::writeNoException();
        android::Parcel::writeInt32(param_4);
        if (iVar5 == 0) {
          android::Parcel::writeInt32(param_4);
          if ((uint)local_90 != 0) {
            android::Parcel::write(pcVar13,(ulong)puVar16);
            __android_log_print(3,"FingerGoodix","write pIdList to reply");
            if ((uint)local_90 != 0) {
              uVar10 = 0;
              do {
                android::Parcel::writeCString(pcVar13);
                __android_log_print(3,"FingerGoodix","write pNameLists[%d] to reply,name:%s",
                                    uVar10 & 0xffffffff,local_88[uVar10]);
                iVar5 = (int)uVar10;
                uVar10 = uVar10 + 1;
              } while (iVar5 + 1U < (uint)local_90);
            }
          }
        }
        else {
          __android_log_print(6,"FingerGoodix","server,failed to getFpTemplateList");
        }
        free(puVar16);
        uVar10 = 0;
        __android_log_print(3,"FingerGoodix","free pIdList");
        do {
          free(local_88[uVar10]);
          uVar14 = uVar10 & 0xffffffff;
          uVar10 = uVar10 + 1;
          __android_log_print(3,"FingerGoodix","free pNameList[%d]",uVar14);
        } while (uVar10 != 5);
        uVar2 = 0;
      }
    }
    goto LAB_0011dde0;
  case 0x1b:
    uVar2 = 0xffffffff;
    __android_log_print(3,"FingerGoodix","server,alipay_tz_invoke_command");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      uVar2 = 0;
      uVar4 = android::Parcel::readInt32();
      uVar10 = android::Parcel::readInt32();
      pvVar18 = malloc(uVar10 & 0xffffffff);
      android::Parcel::read(param_3,(ulong)pvVar18);
      local_90 = (long *)CONCAT44(local_90._4_4_,0x800);
      pvVar9 = malloc(0x800);
      (**(code **)(*plVar7 + 0x118))(plVar7,uVar4,pvVar18,uVar10 & 0xffffffff,pvVar9,&local_90);
      free(pvVar18);
      android::Parcel::writeNoException();
      android::Parcel::writeInt32(param_4);
      android::Parcel::writeInt32(param_4);
      android::Parcel::write(pcVar13,(ulong)pvVar9);
      free(pvVar9);
    }
    goto LAB_0011dde0;
  case 0x1c:
    __android_log_print(3,"FingerGoodix","server, weChatSetSessionId");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      uVar2 = 0;
      uVar8 = android::Parcel::readInt64();
      (**(code **)(*plVar7 + 0x138))(plVar7,uVar8);
      android::Parcel::writeNoException();
      android::Parcel::writeInt32(param_4);
      goto LAB_0011dde0;
    }
    break;
  case 0x1d:
    __android_log_print(3,"FingerGoodix","server,enableFingerScreenUnlock");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      uVar2 = 0;
      android::Parcel::writeNoException();
      (**(code **)(*plVar7 + 0x120))(plVar7);
      android::Parcel::writeInt32(param_4);
      goto LAB_0011dde0;
    }
    break;
  case 0x1e:
    __android_log_print(3,"FingerGoodix","server,disableFingerScreenUnlock");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      uVar2 = 0;
      android::Parcel::writeNoException();
      (**(code **)(*plVar7 + 0x128))(plVar7);
      android::Parcel::writeInt32(param_4);
      goto LAB_0011dde0;
    }
    break;
  case 0x1f:
    __android_log_print(3,"FingerGoodix","server,setRecFlag");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      uVar2 = 0;
      uVar4 = android::Parcel::readInt32();
      android::Parcel::writeNoException();
      (**(code **)(*plVar7 + 0x140))(plVar7,uVar4);
      android::Parcel::writeInt32(param_4);
      goto LAB_0011dde0;
    }
    break;
  case 0x20:
    __android_log_print(3,"FingerGoodix","server,recognize fido");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      iVar5 = android::Parcel::readInt32();
      pvVar18 = malloc((long)iVar5);
      if (pvVar18 != (void *)0x0) {
        memset(pvVar18,0,(long)iVar5);
        android::Parcel::read(param_3,(ulong)pvVar18);
        iVar3 = android::Parcel::readInt32();
        sVar19 = (size_t)iVar3;
        pvVar9 = malloc(sVar19);
        if (pvVar9 != (void *)0x0) {
          uVar2 = 0;
          memset(pvVar9,0,sVar19);
          android::Parcel::read(param_3,(ulong)pvVar9);
          android::Parcel::writeNoException();
          (**(code **)(*plVar7 + 0xc0))(plVar7,pvVar18,iVar5,pvVar9,sVar19);
          android::Parcel::writeInt32(param_4);
          free(pvVar18);
          free(pvVar9);
          goto LAB_0011dde0;
        }
      }
      uVar2 = 0xffffffff;
      __android_log_print(6,"FingerGoodix",
                          "IFingerPrint TRANSACTION_FP_RECOGNIZE_FIDO out of memory");
      goto LAB_0011dde0;
    }
    break;
  case 0x21:
    uVar2 = 0xffffffff;
    __android_log_print(3,"FingerGoodix","server,send cmd.");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      local_98 = 0;
      local_90 = (long *)0x0;
      pvVar18 = (void *)0x0;
      uVar2 = android::Parcel::readInt32();
      iVar5 = android::Parcel::readInt32();
      if (iVar5 != 0) {
        pvVar18 = malloc((long)iVar5);
        android::Parcel::read(param_3,(ulong)pvVar18);
      }
      android::Parcel::writeNoException();
      (**(code **)(*plVar7 + 0x40))(plVar7,uVar2,pvVar18,iVar5,&local_90,&local_98);
      __android_log_print(3,"FingerGoodix","---TRANSACTION_FP_SEND_CMD----out_length = %d,%s",
                          local_98,local_90);
      android::Parcel::writeInt32(param_4);
      if (local_90 != (long *)0x0) {
        android::Parcel::write(pcVar13,(ulong)local_90);
        free(local_90);
      }
      uVar2 = 0;
      android::Parcel::writeInt32(param_4);
      free(pvVar18);
    }
    goto LAB_0011dde0;
  case 0x22:
    __android_log_print(3,"FingerGoodix","server,save regist");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      android::Parcel::writeNoException();
      pcVar15 = *(code **)(*plVar7 + 0x130);
      goto LAB_0011e17c;
    }
    break;
  case 0x23:
    uVar2 = 0xffffffff;
    __android_log_print(3,"FingerGoodix","server, gfCmdM");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 == '\0') goto LAB_0011dde0;
    pvVar18 = (void *)0x0;
    uVar2 = android::Parcel::readInt32();
    iVar5 = android::Parcel::readInt32();
    iVar3 = android::Parcel::readInt32();
    if (0 < iVar5) {
      pvVar18 = malloc((long)iVar5);
      android::Parcel::read(param_3,(ulong)pvVar18);
    }
    puVar16 = (undefined8 *)0x0;
    if (0 < iVar3) {
      puVar16 = (undefined8 *)malloc((long)iVar3);
    }
    local_90 = (long *)((ulong)local_90._4_4_ << 0x20);
    (**(code **)(*plVar7 + 0x148))(plVar7,uVar2,pvVar18,iVar5,puVar16,iVar3);
    android::Parcel::writeNoException();
    android::Parcel::writeInt32(param_4);
    android::Parcel::writeInt32(param_4);
    if (0 < (int)(uint)local_90) {
      android::Parcel::write(pcVar13,(ulong)puVar16);
    }
    if (pvVar18 != (void *)0x0) {
      free(pvVar18);
    }
    if (puVar16 == (undefined8 *)0x0) {
      uVar2 = 0;
      goto LAB_0011dde0;
    }
LAB_0011eac8:
    uVar2 = 0;
    free(puVar16);
    goto LAB_0011dde0;
  case 0x24:
    __android_log_print(3,"FingerGoodix","server,set_user_id");
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      android::Parcel::writeNoException();
      pcVar15 = *(code **)(*plVar7 + 0x70);
      uVar8 = android::Parcel::readInt64();
      goto LAB_0011df00;
    }
    break;
  case 0x25:
    uVar2 = 0xffffffff;
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      local_88[0] = (void *)0x0;
      local_88[1] = (void *)0x0;
      local_88[2] = (void *)0x0;
      local_88[3] = (void *)0x0;
      local_88[4] = (void *)0x0;
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
      uStack_10 = 0;
      iVar5 = android::Parcel::readInt32();
      if (iVar5 < 1) {
        uVar2 = 0;
        android::Parcel::writeNoException();
        (**(code **)(*plVar7 + 0x60))(plVar7,local_88);
        android::Parcel::writeInt32(param_4);
        android::Parcel::writeInt32(param_4);
      }
      else {
        uVar2 = 0;
        android::Parcel::read(param_3,(ulong)local_88);
        android::Parcel::writeNoException();
        (**(code **)(*plVar7 + 0x60))(plVar7,local_88);
        android::Parcel::writeInt32(param_4);
        android::Parcel::writeInt32(param_4);
        android::Parcel::write(pcVar13,(ulong)local_88);
      }
    }
    goto LAB_0011dde0;
  case 0x26:
    cVar1 = android::Parcel::checkInterface((IBinder *)param_3);
    if (cVar1 != '\0') {
      pvVar18 = (void *)0x0;
      iVar5 = android::Parcel::readInt32();
      if (iVar5 != 0) {
        pvVar18 = malloc((long)iVar5);
        android::Parcel::read(param_3,(ulong)pvVar18);
      }
      uVar2 = 0;
      __android_log_print(3,"FingerGoodix","server,set fpdb to data");
      android::Parcel::writeNoException();
      (**(code **)(*plVar7 + 0x68))(plVar7,pvVar18);
      android::Parcel::writeInt32(param_4);
      free(pvVar18);
      goto LAB_0011dde0;
    }
    break;
  default:
    uVar2 = android::BBinder::onTransact(param_1 + 8,param_2,param_3,param_4);
    goto LAB_0011dde0;
  }
  uVar2 = 0xffffffff;
LAB_0011dde0:
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
                    // try { // try from 0011f4f8 to 0011f4fb has its CatchHandler @ 0011f66c
    android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011f500 to 0011f633 has its CatchHandler @ 0011f680
    android::IFingerPrint::getInterfaceDescriptor();
    android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
    (**(code **)(**(long **)(this + 0x10) + 0x28))
              (*(long **)(this + 0x10),0x1a,aPStack_d8,aPStack_70,0);
    android::Parcel::readExceptionCode();
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
                    // try { // try from 0011f6f8 to 0011f6fb has its CatchHandler @ 0011f720
  android::IInterface::IInterface((IInterface *)this);
  *(undefined8 *)this = 0x1431f8;
  *(undefined8 *)(this + 8) = 0x143380;
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
  *(undefined **)this = &DAT_00142cb8;
  *(undefined **)(this + 0x28) = &DAT_00142e80;
  *(undefined **)(this + 8) = &DAT_00142e20;
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
  *(undefined **)this = &DAT_00142cb8;
  *(undefined **)(this + 0x28) = &DAT_00142e80;
  *(undefined **)(this + 8) = &DAT_00142e20;
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
                    // try { // try from 0011f8b4 to 0011f8b7 has its CatchHandler @ 0011fa54
    (**(code **)*puVar2)(puVar2,&descriptor);
    if (local_10 != (long *)0x0) {
                    // try { // try from 0011f8d0 to 0011f8ef has its CatchHandler @ 0011fa30
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
                    // try { // try from 0011f948 to 0011f94b has its CatchHandler @ 0011fa54
      plVar3 = (long *)operator_new(0x38);
                    // try { // try from 0011f958 to 0011f95b has its CatchHandler @ 0011fa28
      android::RefBase::RefBase((RefBase *)(plVar3 + 5));
                    // try { // try from 0011f96c to 0011f96f has its CatchHandler @ 0011fa20
      IFingerPrint((IFingerPrint *)plVar3);
                    // try { // try from 0011f980 to 0011f983 has its CatchHandler @ 0011f9d8
      android::BpRefBase::BpRefBase((BpRefBase *)(plVar3 + 1),(sp *)&PTR_DAT_00142ee0);
      *plVar3 = 0x142f28;
      plVar3[5] = 0x1430f0;
      plVar3[1] = 0x143090;
                    // try { // try from 0011f9ac to 0011f9cb has its CatchHandler @ 0011fa54
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
  *(undefined8 *)this = 0x1431f8;
  *(undefined8 *)(this + 8) = 0x143380;
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
                    // try { // try from 0011fb78 to 0011fb7b has its CatchHandler @ 0011fc54
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011fb80 to 0011fc2f has its CatchHandler @ 0011fc38
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
                    // try { // try from 0011fcc0 to 0011fcc3 has its CatchHandler @ 0011fd7c
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 0011fcc8 to 0011fd1f has its CatchHandler @ 0011fd60
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
  undefined8 uVar1;
  int iVar2;
  undefined8 uVar3;
  undefined8 uVar4;
  BnInterface<> **in_x8;
  undefined8 uVar5;
  
  uVar5 = *(undefined8 *)param_1;
  uVar3 = android::String16::size();
  uVar1 = IFingerPrintClient::descriptor;
  uVar4 = android::String16::size();
  iVar2 = strzcmp16(uVar5,uVar3,uVar1,uVar4);
  if (iVar2 == 0) {
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
                    // try { // try from 0011fffc to 0011ffff has its CatchHandler @ 00120024
  android::IInterface::IInterface((IInterface *)this);
  *(undefined8 *)this = 0x1442b8;
  *(undefined8 *)(this + 8) = 0x144320;
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
  *(undefined **)this = &DAT_00143fb8;
  *(undefined **)(this + 0x28) = &DAT_00144060;
  *(undefined **)(this + 8) = &DAT_00144000;
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
  *(undefined **)this = &DAT_00143fb8;
  *(undefined **)(this + 0x28) = &DAT_00144060;
  *(undefined **)(this + 8) = &DAT_00144000;
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
                    // try { // try from 001201b8 to 001201bb has its CatchHandler @ 00120358
    (**(code **)*puVar2)(puVar2,&descriptor);
    if (local_10 != (long *)0x0) {
                    // try { // try from 001201d4 to 001201f3 has its CatchHandler @ 00120334
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
                    // try { // try from 0012024c to 0012024f has its CatchHandler @ 00120358
      plVar3 = (long *)operator_new(0x38);
                    // try { // try from 0012025c to 0012025f has its CatchHandler @ 0012032c
      android::RefBase::RefBase((RefBase *)(plVar3 + 5));
                    // try { // try from 00120270 to 00120273 has its CatchHandler @ 00120324
      IFingerPrintClient((IFingerPrintClient *)plVar3);
                    // try { // try from 00120284 to 00120287 has its CatchHandler @ 001202dc
      android::BpRefBase::BpRefBase((BpRefBase *)(plVar3 + 1),(sp *)&PTR_DAT_001440c0);
      *plVar3 = 0x144108;
      plVar3[5] = 0x1441b0;
      plVar3[1] = 0x144150;
                    // try { // try from 001202b0 to 001202cf has its CatchHandler @ 00120358
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
  *(undefined8 *)this = 0x1442b8;
  *(undefined8 *)(this + 8) = 0x144320;
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
                    // try { // try from 0012044c to 0012044f has its CatchHandler @ 00120620
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 00120454 to 00120487 has its CatchHandler @ 00120618
  android::IFingerPrintService::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  local_f0 = *(long **)(ulong)(uint)param_2;
  if (local_f0 != (long *)0x0) {
    android::RefBase::incStrong((void *)((long)local_f0 + *(long *)(*local_f0 + -0x18)));
  }
                    // try { // try from 00120494 to 00120497 has its CatchHandler @ 00120610
  android::IInterface::asBinder((sp *)&local_f0);
                    // try { // try from 001204a0 to 001204a3 has its CatchHandler @ 001205d0
  android::Parcel::writeStrongBinder((sp *)aPStack_d8);
  if (local_e8 != (long *)0x0) {
    android::RefBase::decStrong((void *)((long)local_e8 + *(long *)(*local_e8 + -0x18)));
  }
  if (local_f0 != (long *)0x0) {
    android::RefBase::decStrong((void *)((long)local_f0 + *(long *)(*local_f0 + -0x18)));
  }
                    // try { // try from 001204e4 to 00120523 has its CatchHandler @ 00120618
  android::Parcel::writeInt32((int)aPStack_d8);
  (**(code **)(**(long **)(param_1 + 0x10) + 0x28))
            (*(long **)(param_1 + 0x10),2,aPStack_d8,aPStack_70,0);
  android::Parcel::readExceptionCode();
  android::Parcel::readStrongBinder();
                    // try { // try from 0012052c to 0012052f has its CatchHandler @ 00120590
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
                    // try { // try from 00120680 to 00120683 has its CatchHandler @ 00120738
  android::Parcel::Parcel(aPStack_70);
                    // try { // try from 00120688 to 001206d7 has its CatchHandler @ 0012071c
  android::IFingerPrintService::getInterfaceDescriptor();
  android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
  android::Parcel::writeInt32((int)aPStack_d8);
  (**(code **)(**(long **)((ulong)(uint)param_1 + 0x10) + 0x28))
            (*(long **)((ulong)(uint)param_1 + 0x10),1,aPStack_d8,aPStack_70,0);
  android::Parcel::readExceptionCode();
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
      android::Parcel::writeNoException();
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
                    // try { // try from 00120804 to 00120807 has its CatchHandler @ 00120980
      IFingerPrintClient::asInterface((sp *)&local_10);
      if (local_10 != (long *)0x0) {
        android::RefBase::decStrong((void *)((long)local_10 + *(long *)(*local_10 + -0x18)));
      }
      pcVar5 = *(code **)(*plVar3 + 0x28);
                    // try { // try from 00120830 to 0012084b has its CatchHandler @ 00120a30
      uVar2 = android::Parcel::readInt32();
      (*pcVar5)(plVar3,&local_28,uVar2);
                    // try { // try from 00120850 to 00120877 has its CatchHandler @ 00120a28
      android::Parcel::writeNoException();
      local_18 = local_20;
      if (local_20 != (long *)0x0) {
        android::RefBase::incStrong((void *)((long)local_20 + *(long *)(*local_20 + -0x18)));
      }
                    // try { // try from 00120880 to 00120883 has its CatchHandler @ 00120a20
      android::IInterface::asBinder((sp *)&local_18);
                    // try { // try from 0012088c to 0012088f has its CatchHandler @ 001209a8
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
                    // try { // try from 00120aa8 to 00120aab has its CatchHandler @ 00120ad0
  android::IInterface::IInterface((IInterface *)this);
  *(undefined8 *)this = 0x144ef8;
  *(undefined8 *)(this + 8) = 0x144f60;
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
  *(undefined **)this = &DAT_00144bf8;
  *(undefined **)(this + 0x28) = &DAT_00144ca0;
  *(undefined **)(this + 8) = &DAT_00144c40;
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
  *(undefined **)this = &DAT_00144bf8;
  *(undefined **)(this + 0x28) = &DAT_00144ca0;
  *(undefined **)(this + 8) = &DAT_00144c40;
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
                    // try { // try from 00120c64 to 00120c67 has its CatchHandler @ 00120e04
    (**(code **)*puVar2)(puVar2,&descriptor);
    if (local_10 != (long *)0x0) {
                    // try { // try from 00120c80 to 00120c9f has its CatchHandler @ 00120de0
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
                    // try { // try from 00120cf8 to 00120cfb has its CatchHandler @ 00120e04
      plVar3 = (long *)operator_new(0x38);
                    // try { // try from 00120d08 to 00120d0b has its CatchHandler @ 00120dd8
      android::RefBase::RefBase((RefBase *)(plVar3 + 5));
                    // try { // try from 00120d1c to 00120d1f has its CatchHandler @ 00120dd0
      IFingerPrintService((IFingerPrintService *)plVar3);
                    // try { // try from 00120d30 to 00120d33 has its CatchHandler @ 00120d88
      android::BpRefBase::BpRefBase((BpRefBase *)(plVar3 + 1),(sp *)&PTR_DAT_00144d00);
      *plVar3 = 0x144d48;
      plVar3[5] = 0x144df0;
      plVar3[1] = 0x144d90;
                    // try { // try from 00120d5c to 00120d7b has its CatchHandler @ 00120e04
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
  *(undefined8 *)this = 0x144ef8;
  *(undefined8 *)(this + 8) = 0x144f60;
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

void saveGrayBitmap(undefined8 param_1,void *param_2,int param_3,int *param_4,char param_5,
                   char param_6)

{
  undefined uVar1;
  void *__dest;
  undefined *puVar2;
  undefined8 uVar3;
  int iVar4;
  undefined local_440;
  undefined local_43f;
  undefined local_43e;
  undefined local_43d;
  undefined local_436;
  undefined local_435;
  undefined local_432;
  byte local_42e;
  byte local_42a;
  undefined local_426;
  undefined local_424;
  undefined local_40a [1026];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  memset(&local_440,0,0x436);
  __dest = malloc(0xc800);
  if (param_2 == (void *)0x0) {
    uVar3 = 0xffffffff;
  }
  else {
    local_440 = 0x42;
    local_43d = 0x28;
    local_432 = 0x28;
    local_42e = param_6 + 3U & 0xfc;
    local_42a = param_5 + 3U & 0xfc;
    local_43f = 0x4d;
    iVar4 = 0;
    local_43e = 0x36;
    local_436 = 0x36;
    local_426 = 1;
    local_435 = 4;
    local_424 = 8;
    puVar2 = local_40a;
    do {
      uVar1 = (undefined)iVar4;
      *puVar2 = uVar1;
      iVar4 = iVar4 + 1;
      puVar2[1] = uVar1;
      puVar2[2] = uVar1;
      puVar2 = puVar2 + 4;
    } while (iVar4 != 0x100);
    memcpy(__dest,&local_440,0x436);
    memcpy((void *)((long)__dest + 0x436),param_2,(long)param_3);
    if (param_4 + 5 != (int *)0x0) {
      memcpy(param_4 + 5,__dest,(long)(param_3 + 0x436));
      *param_4 = param_3 + 0x436;
    }
    free(__dest);
    uVar3 = 0;
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar3);
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
                      "writeDataToRecordFile,shasha: Index = %d , score = %d,id = %d,update=%d,size= %d\n"
                      ,*param_1,param_1[1],param_1[4],param_1[5],param_1[0xba]);
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
                        param_1[0xba]);
    write(__fd,&local_a8,8);
    write(__fd,&local_b8,4);
    write(__fd,param_1 + 1,4);
    write(__fd,param_1 + 4,4);
    write(__fd,param_1 + 0xba,4);
    write(__fd,&local_b4,4);
    close(__fd);
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



// operator delete(void*)

void operator_delete(void *param_1)

{
  free(param_1);
  return;
}



void FUN_001212fc(byte *param_1,ulong *param_2)

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



ulong * FUN_0012133c(byte param_1,ulong *param_2,ulong *param_3,ulong *param_4)

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
      puVar4 = (ulong *)FUN_001212fc(param_3,&local_8);
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



undefined8 FUN_0012144c(byte param_1,undefined8 param_2)

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



void FUN_001214c8(long param_1,char *param_2,undefined8 *param_3)

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
    uVar4 = FUN_0012144c(cVar2,param_1);
    pcVar5 = (char *)FUN_0012133c(cVar2,uVar4,param_2 + 1,param_3 + 1);
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



char FUN_001215d4(long param_1,long *param_2,long **param_3,ulong param_4)

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
    FUN_0012133c(bVar1,*(undefined8 *)(param_1 + 0x10),*(long *)(param_1 + 0x18) + lVar7,&local_8);
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
    pbVar9 = (byte *)FUN_001214c8(param_5,local_60,&local_30);
    local_20 = FUN_0012144c(local_8,param_5);
    lVar13 = _Unwind_GetIPInfo(param_5,&local_4c);
    uVar17 = lVar13 - (ulong)(local_4c == 0);
    if (pbVar9 < local_10) {
      do {
        uVar4 = local_7;
        uVar10 = FUN_0012144c(local_7,0);
        uVar10 = FUN_0012133c(uVar4,uVar10,pbVar9,&local_48);
        uVar4 = local_7;
        uVar11 = FUN_0012144c(local_7,0);
        uVar10 = FUN_0012133c(uVar4,uVar11,uVar10,&local_40);
        uVar4 = local_7;
        uVar11 = FUN_0012144c(local_7,0);
        pbVar12 = (byte *)FUN_0012133c(uVar4,uVar11,uVar10,&local_38);
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
              goto LAB_00121a6c;
            }
          }
          iVar7 = 2;
          goto LAB_00121978;
        }
      } while (pbVar9 < local_10);
    }
    uVar17 = 0;
    iVar7 = 1;
LAB_00121978:
    local_68 = (ulong **)0x0;
    local_48 = 0;
    local_10 = (byte *)0x0;
    goto LAB_00121984;
  }
  local_60 = param_4[-3];
  uVar17 = param_4[-2];
  local_48 = *(int *)((long)param_4 + -0x24);
  if (uVar17 == 0) {
    if ((param_2 >> 3 & 1) != 0) {
                    // WARNING: Subroutine does not return
      std::terminate();
    }
LAB_001217ac:
    FUN_001224dc(param_4);
  }
  if ((param_2 >> 3 & 1) == 0) {
LAB_00121818:
    if (local_48 < 0) {
      FUN_001214c8(param_5,local_60,&local_30);
      local_20 = FUN_0012144c(local_8,param_5);
      uVar8 = FUN_0012144c(local_8,param_5);
      param_4[-2] = uVar8;
    }
    goto LAB_001217bc;
  }
  goto LAB_001217b8;
LAB_00121a6c:
  lVar13 = FUN_001212fc(local_10,&local_48);
  FUN_001212fc(lVar13,&local_40);
  uVar8 = CONCAT44(uStack_44,local_48);
  if (uVar8 == 0) {
    bVar2 = true;
  }
  else if ((long)uVar8 < 1) {
    if (bVar1 < (local_70 != (undefined **)0x0 && (param_2 & 8) == 0)) {
      bVar5 = FUN_001215d4(&local_30,local_70,local_68);
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
LAB_00121bd0:
      iVar7 = 3;
      goto LAB_00121984;
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
    FUN_0012133c(local_8,local_20,local_18 + lVar14,&local_38);
    ppuVar3 = local_38;
    if (local_38 == (ulong **)0x0) goto LAB_00121bd0;
    if (local_70 != (undefined **)0x0) {
      local_38 = local_68;
      cVar6 = (**(code **)(*local_70 + 0x10))(local_70);
      if (cVar6 != '\0') {
        local_38 = (ulong **)*local_38;
      }
      cVar6 = (*(code *)(*ppuVar3)[4])(ppuVar3,local_70,&local_38,1);
      if (cVar6 != '\0') {
        local_68 = local_38;
        goto LAB_00121bd0;
      }
    }
  }
  if (local_40 == 0) goto LAB_00121c24;
  local_10 = (byte *)(lVar13 + local_40);
  goto LAB_00121a6c;
LAB_00121c24:
  if (!bVar2) {
    return 8;
  }
  local_48 = 0;
  iVar7 = 2;
LAB_00121984:
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
    if (iVar7 == 1) goto LAB_001217ac;
    goto LAB_00121818;
  }
  if (iVar7 == 1) {
                    // WARNING: Subroutine does not return
    std::terminate();
  }
LAB_001217b8:
  if (local_48 < 0) {
                    // try { // try from 00121c4c to 00121c4f has its CatchHandler @ 001219d8
    lVar13 = std::unexpected();
    __cxa_begin_catch();
                    // WARNING: Subroutine does not return
    __cxxabiv1::__unexpected(*(_func_void **)(lVar13 + -0x40));
  }
LAB_001217bc:
  _Unwind_SetGR(param_5,0,param_4);
  _Unwind_SetGR(param_5,1,(long)local_48);
  _Unwind_SetIP(param_5,uVar17);
  return 7;
}



void __cxa_call_unexpected(long param_1)

{
  __cxa_begin_catch();
                    // WARNING: Subroutine does not return
                    // try { // try from 00121c84 to 00121c87 has its CatchHandler @ 00121c88
  __cxxabiv1::__unexpected(*(_func_void **)(param_1 + -0x40));
}



// __cxxabiv1::__terminate(void (*)())

void __cxxabiv1::__terminate(_func_void *param_1)

{
                    // try { // try from 00121d48 to 00121d4f has its CatchHandler @ 00121d50
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



void FUN_00121e04(uint param_1,long param_2)

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
  *(code **)(param_1 + -0x18) = FUN_00121e04;
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
  *puVar3 = &PTR__bad_alloc_00145650;
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



// std::bad_alloc::what() const

char * std::bad_alloc::what(void)

{
  return "std::bad_alloc";
}



// std::bad_alloc::~bad_alloc()

void __thiscall std::bad_alloc::~bad_alloc(bad_alloc *this)

{
  *(undefined ***)this = &PTR__bad_alloc_00145650;
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



char * FUN_00122058(void)

{
  return "__gnu_cxx::__concurrence_lock_error";
}



char * FUN_00122064(void)

{
  return "__gnu_cxx::__concurrence_unlock_error";
}



void FUN_00122070(undefined8 *param_1)

{
  *param_1 = &PTR_FUN_00140830;
  std::exception::~exception((exception *)param_1);
  return;
}



void FUN_00122080(undefined8 *param_1)

{
  *param_1 = &PTR_FUN_00140860;
  std::exception::~exception((exception *)param_1);
  return;
}



void FUN_00122090(undefined8 *param_1)

{
  *param_1 = &PTR_FUN_00140830;
  std::exception::~exception((exception *)param_1);
  operator_delete(param_1);
  return;
}



void FUN_001220c0(undefined8 *param_1)

{
  *param_1 = &PTR_FUN_00140860;
  std::exception::~exception((exception *)param_1);
  operator_delete(param_1);
  return;
}



void FUN_001220f0(void)

{
  undefined8 *puVar1;
  
  puVar1 = (undefined8 *)__cxa_allocate_exception(8);
  *puVar1 = &PTR_FUN_00140830;
                    // WARNING: Subroutine does not return
  __cxa_throw(puVar1,&PTR_PTR____si_class_type_info_00145670,FUN_00122070);
}



void FUN_00122120(void)

{
  undefined8 *puVar1;
  
  puVar1 = (undefined8 *)__cxa_allocate_exception(8);
  *puVar1 = &PTR_FUN_00140860;
                    // WARNING: Subroutine does not return
  __cxa_throw(puVar1,&PTR_PTR____si_class_type_info_00145688,FUN_00122080);
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
LAB_00122174:
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
                    // try { // try from 001221bc to 001221bf has its CatchHandler @ 00122230
  iVar2 = pthread_mutex_lock((pthread_mutex_t *)&DAT_00147f70);
  if (iVar2 == 0) {
    if (param_1 + 0x80U < 0x401) {
      uVar5 = 0;
      uVar4 = DAT_00157fa0;
      do {
        if ((uVar4 & 1) == 0) {
          DAT_00157fa0 = 1L << (uVar5 & 0x3f) | DAT_00157fa0;
          puVar3 = &DAT_00147fa0 + uVar5 * 0x80;
                    // try { // try from 00122224 to 0012222f has its CatchHandler @ 00122244
          iVar2 = pthread_mutex_unlock((pthread_mutex_t *)&DAT_00147f70);
          if (iVar2 == 0) goto LAB_00122174;
          FUN_00122120();
                    // catch() { ... } // from try @ 001221bc with catch @ 00122230
                    // catch() { ... } // from try @ 0012223c with catch @ 00122230
          if (extraout_x1 != -1) {
                    // WARNING: Subroutine does not return
            _Unwind_Resume();
          }
          goto LAB_00122240;
        }
        uVar1 = (int)uVar5 + 1;
        uVar5 = (ulong)uVar1;
        uVar4 = uVar4 >> 1;
      } while (uVar1 != 0x40);
    }
                    // WARNING: Subroutine does not return
    std::terminate();
  }
                    // try { // try from 0012223c to 0012223f has its CatchHandler @ 00122230
  FUN_001220f0();
LAB_00122240:
                    // WARNING: Subroutine does not return
  __cxa_call_unexpected();
}



// WARNING: Removing unreachable block (ram,0x001222d4)

void __cxa_free_exception(undefined8 *param_1)

{
  int iVar1;
  long extraout_x1;
  long lVar2;
  long extraout_x1_00;
  
  if ((param_1 < &DAT_00147fa0) || ((undefined8 *)0x157f9f < param_1)) {
    free(param_1 + -0x10);
    return;
  }
                    // try { // try from 0012228c to 0012228f has its CatchHandler @ 0012230c
  iVar1 = pthread_mutex_lock((pthread_mutex_t *)&DAT_00147f70);
  if (iVar1 == 0) {
    DAT_00157fa0 = DAT_00157fa0 &
                   (1L << ((ulong)(param_1 + -0x28ff4) >> 10 & 0x3f) ^ 0xffffffffffffffffU);
                    // try { // try from 001222b0 to 001222fb has its CatchHandler @ 001222fc
    iVar1 = pthread_mutex_unlock((pthread_mutex_t *)&DAT_00147f70);
    if (iVar1 == 0) {
      return;
    }
    FUN_00122120();
    lVar2 = extraout_x1;
  }
  else {
                    // try { // try from 00122308 to 0012230b has its CatchHandler @ 0012230c
    FUN_001220f0();
    lVar2 = extraout_x1_00;
                    // catch() { ... } // from try @ 0012228c with catch @ 0012230c
                    // catch() { ... } // from try @ 00122308 with catch @ 0012230c
  }
                    // catch() { ... } // from try @ 001222b0 with catch @ 001222fc
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
LAB_00122330:
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
                    // try { // try from 00122370 to 00122373 has its CatchHandler @ 001223f4
  iVar2 = pthread_mutex_lock((pthread_mutex_t *)&DAT_00147f70);
  if (iVar2 == 0) {
    uVar4 = 0;
    uVar5 = DAT_00146360;
    while ((uVar5 & 1) != 0) {
      uVar1 = (int)uVar4 + 1;
      uVar4 = (ulong)uVar1;
      uVar5 = uVar5 >> 1;
      if (uVar1 == 0x40) {
                    // WARNING: Subroutine does not return
        std::terminate();
      }
    }
    DAT_00146360 = 1L << (uVar4 & 0x3f) | DAT_00146360;
    puVar3 = &DAT_00146370 + uVar4 * 0xe;
                    // try { // try from 001223d8 to 001223e3 has its CatchHandler @ 001223e8
    iVar2 = pthread_mutex_unlock((pthread_mutex_t *)&DAT_00147f70);
    if (iVar2 == 0) goto LAB_00122330;
    FUN_00122120();
  }
                    // try { // try from 001223e4 to 001223e7 has its CatchHandler @ 001223f4
  FUN_001220f0();
                    // catch() { ... } // from try @ 001223d8 with catch @ 001223e8
  if (extraout_x1 == -1) {
                    // WARNING: Subroutine does not return
    __cxa_call_unexpected();
  }
                    // WARNING: Subroutine does not return
  _Unwind_Resume();
}



// WARNING: Removing unreachable block (ram,0x0012249c)

void __cxa_free_dependent_exception(undefined8 *param_1)

{
  int iVar1;
  long extraout_x1;
  long lVar2;
  long extraout_x1_00;
  
  if ((param_1 < &DAT_00146370) || ((undefined8 *)0x147f6f < param_1)) {
    free(param_1);
    return;
  }
                    // try { // try from 00122458 to 0012245b has its CatchHandler @ 001224d4
  iVar1 = pthread_mutex_lock((pthread_mutex_t *)&DAT_00147f70);
  if (iVar1 == 0) {
    DAT_00146360 = DAT_00146360 &
                   (1L << (SUB168(ZEXT416((int)param_1 - 0x146370U >> 4) *
                                  ZEXT816(0x2492492492492494),8) & 0x3f) ^ 0xffffffffffffffffU);
                    // try { // try from 0012247c to 001224c3 has its CatchHandler @ 001224c4
    iVar1 = pthread_mutex_unlock((pthread_mutex_t *)&DAT_00147f70);
    if (iVar1 == 0) {
      return;
    }
    FUN_00122120();
    lVar2 = extraout_x1;
  }
  else {
                    // try { // try from 001224d0 to 001224d3 has its CatchHandler @ 001224d4
    FUN_001220f0();
    lVar2 = extraout_x1_00;
                    // catch() { ... } // from try @ 00122458 with catch @ 001224d4
                    // catch() { ... } // from try @ 001224d0 with catch @ 001224d4
  }
                    // catch() { ... } // from try @ 0012247c with catch @ 001224c4
  if (lVar2 == -1) {
                    // WARNING: Subroutine does not return
    __cxa_call_unexpected();
  }
                    // WARNING: Subroutine does not return
  _Unwind_Resume();
}



void FUN_001224dc(long *param_1)

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



// std::exception::~exception()

void __thiscall std::exception::~exception(exception *this)

{
  return;
}



// std::bad_exception::~bad_exception()

void __thiscall std::bad_exception::~bad_exception(bad_exception *this)

{
  *(undefined ***)this = &PTR__bad_exception_00145730;
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



pthread_key_t * FUN_0012274c(pthread_key_t *param_1)

{
  code *UNRECOVERED_JUMPTABLE;
  uint uVar1;
  pthread_key_t *ppVar2;
  
  if (param_1 == (pthread_key_t *)0x0) {
                    // WARNING: Treating indirect jump as call
    UNRECOVERED_JUMPTABLE = (code *)SoftwareBreakpoint(1000,0x122768);
    ppVar2 = (pthread_key_t *)(*UNRECOVERED_JUMPTABLE)();
    return ppVar2;
  }
  if (*(char *)(param_1 + 1) == '\0') {
    return param_1;
  }
  uVar1 = pthread_key_delete(*param_1);
  return (pthread_key_t *)(ulong)uVar1;
}



void FUN_00122768(long *param_1)

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
  
  if (DAT_00157fac == '\0') {
    return &DAT_00157fb0;
  }
                    // try { // try from 001227e0 to 001227e3 has its CatchHandler @ 001227ec
  puVar1 = (undefined *)pthread_getspecific(DAT_00157fa8);
  return puVar1;
}



undefined8 * __cxa_get_globals(void)

{
  int iVar1;
  undefined8 *__pointer;
  
  if (DAT_00157fac == '\0') {
    __pointer = (undefined8 *)&DAT_00157fb0;
  }
  else {
                    // try { // try from 00122834 to 0012285b has its CatchHandler @ 00122870
    __pointer = (undefined8 *)pthread_getspecific(DAT_00157fa8);
    if (__pointer == (undefined8 *)0x0) {
      __pointer = (undefined8 *)malloc(0x10);
      if ((__pointer == (undefined8 *)0x0) ||
         (iVar1 = pthread_setspecific(DAT_00157fa8,__pointer), iVar1 != 0)) {
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
    p_Var3 = DAT_00157fc0;
    cVar1 = '\x01';
    bVar2 = (bool)ExclusiveMonitorPass(0x157fc0,0x10);
    if (bVar2) {
      cVar1 = ExclusiveMonitorsStatus();
      DAT_00157fc0 = param_1;
    }
  } while (cVar1 != '\0');
  return p_Var3;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked
// std::get_new_handler()

undefined8 std::get_new_handler(void)

{
  return DAT_00157fc0;
}



// __cxxabiv1::__si_class_type_info::~__si_class_type_info()

void __thiscall __cxxabiv1::__si_class_type_info::~__si_class_type_info(__si_class_type_info *this)

{
  *(undefined ***)this = &PTR____si_class_type_info_001457e0;
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
LAB_00122988:
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
      if (iVar3 == 0) goto LAB_00122988;
    }
    if (param_4 == param_6) {
      if (__s1 == *(char **)(param_5 + 8)) {
LAB_00122a24:
        *(__sub_kind *)(param_7 + 0xc) = param_2;
        return 0;
      }
      if (cVar1 != '*') {
        iVar3 = strcmp(__s1,*(char **)(param_5 + 8));
        if (iVar3 == 0) goto LAB_00122a24;
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



void FUN_00122b30(void)

{
  return;
}



undefined8 FUN_00122b34(void)

{
  return 0;
}



undefined8 FUN_00122b3c(void)

{
  return 0;
}



undefined8 FUN_00122b44(void)

{
  return 0;
}



void operator_delete(void *param_1)

{
  free(param_1);
  return;
}



bool FUN_00122b50(long param_1,long param_2)

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



// WARNING: Removing unreachable block (ram,0x00122c90)
// WARNING: Removing unreachable block (ram,0x00122d24)
// WARNING: Removing unreachable block (ram,0x00122ca4)
// __gnu_cxx::__verbose_terminate_handler()

void __gnu_cxx::__verbose_terminate_handler(void)

{
  long lVar1;
  char *pcVar2;
  char *__s;
  size_t __n;
  
  if (DAT_00157fc8 == '\0') {
    DAT_00157fc8 = '\x01';
    lVar1 = __cxa_current_exception_type();
    if (lVar1 != 0) {
      pcVar2 = *(char **)(lVar1 + 8);
      if (*pcVar2 == '*') {
        pcVar2 = pcVar2 + 1;
      }
      __s = (char *)__cxa_demangle(pcVar2,0,0);
      fwrite("terminate called after throwing an instance of \'",1,0x30,(FILE *)sem_init);
      fputs(pcVar2,(FILE *)sem_init);
      do {
        fwrite(&DAT_00137ee8,1,2,(FILE *)sem_init);
                    // try { // try from 00122c58 to 00122c5b has its CatchHandler @ 00122c9c
        __cxa_rethrow();
        fputs(__s,(FILE *)sem_init);
      } while( true );
    }
    pcVar2 = "terminate called without an active exception\n";
    __n = 0x2d;
  }
  else {
    __n = 0x1d;
    pcVar2 = "terminate called recursively\n";
  }
  fwrite(pcVar2,1,__n,(FILE *)sem_init);
                    // WARNING: Subroutine does not return
  abort();
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
  *(undefined ***)this = &PTR____class_type_info_00145870;
  FUN_00122b30();
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
      if (iVar1 == 0) goto LAB_00122e24;
    }
    return 0;
  }
LAB_00122e24:
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
LAB_00122fd0:
      *(__sub_kind *)(param_7 + 0xc) = param_2;
      return 0;
    }
    if (*__s1 == '*') {
      if (__s1 != *(char **)(param_3 + 8)) {
        return 0;
      }
      goto LAB_00122fb0;
    }
    iVar1 = strcmp(__s1,*(char **)(param_5 + 8));
    if (iVar1 == 0) goto LAB_00122fd0;
    __s2 = *(char **)(param_3 + 8);
    if (__s1 == __s2) goto LAB_00122fb0;
  }
  else {
    __s2 = *(char **)(param_3 + 8);
    if (__s1 == __s2) goto LAB_00122fb0;
    if (*__s1 == '*') {
      return 0;
    }
  }
  iVar1 = strcmp(__s1,__s2);
  if (iVar1 != 0) {
    return 0;
  }
LAB_00122fb0:
  *(void **)param_7 = param_4;
  *(__sub_kind *)(param_7 + 8) = param_2;
  *(undefined4 *)(param_7 + 0x10) = 1;
  return 0;
}



long FUN_00122ff4(long param_1,undefined4 param_2,long param_3,long param_4)

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
switchD_00123020_caseD_2a:
    if ((param_4 != 0) && (iVar2 = *(int *)(param_1 + 0x28), iVar2 < *(int *)(param_1 + 0x2c))) {
LAB_0012303c:
      *(int *)(param_1 + 0x28) = iVar2 + 1;
      lVar1 = *(long *)(param_1 + 0x20) + (long)iVar2 * 0x18;
      if (lVar1 != 0) {
        *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar2 * 0x18) = param_2;
        *(long *)(lVar1 + 8) = param_3;
        *(long *)(lVar1 + 0x10) = param_4;
        return lVar1;
      }
    }
LAB_00123004:
    return 0;
  default:
    goto LAB_00123004;
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
    goto LAB_0012303c;
  case 0x2a:
  case 0x30:
    goto switchD_00123020_caseD_2a;
  }
}



long FUN_00123094(long param_1,long param_2,int param_3)

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



int ** FUN_001230f4(long param_1,int **param_2,int param_3)

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
        if (cVar2 != 'V') goto LAB_00123158;
        uVar5 = 0x1d;
        if (param_3 == 0) {
          uVar5 = 0x1a;
        }
        *(int *)(param_1 + 0x50) = *(int *)(param_1 + 0x50) + 9;
        goto LAB_0012316c;
      }
      uVar5 = 0x1c;
      if (param_3 == 0) {
        uVar5 = 0x19;
      }
      *(int *)(param_1 + 0x50) = *(int *)(param_1 + 0x50) + 9;
      piVar3 = (int *)FUN_00122ff4(param_1,uVar5,0,0);
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
LAB_00123158:
      uVar5 = 0x1e;
      if (param_3 == 0) {
        uVar5 = 0x1b;
      }
      *(int *)(param_1 + 0x50) = *(int *)(param_1 + 0x50) + 6;
LAB_0012316c:
      piVar3 = (int *)FUN_00122ff4(param_1,uVar5,0,0);
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



long FUN_001232a4(long param_1,int param_2)

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
        goto LAB_001233e0;
      }
    }
    else if (0x19 < (byte)(bVar3 + 0xbf)) goto LAB_00123370;
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
        if (uVar6 == 0x5f) goto LAB_001233dc;
      }
      uVar14 = uVar6 - 0x30;
      uVar9 = uVar4;
    } while( true );
  }
  uVar6 = 0;
LAB_00123370:
  uVar14 = *(uint *)(param_1 + 0x10) >> 3 & 1;
  if (uVar14 < (param_2 != 0)) {
    uVar14 = (uint)((byte)(**(char **)(param_1 + 0x18) + 0xbdU) < 2);
  }
  if (uVar6 == 0x74) {
    puVar8 = &UNK_00140ce0;
  }
  else if (uVar6 == 0x61) {
    puVar8 = &UNK_00140d18;
  }
  else if (uVar6 == 0x62) {
    puVar8 = &UNK_00140d50;
  }
  else if (uVar6 == 0x73) {
    puVar8 = &UNK_00140d88;
  }
  else if (uVar6 == 0x69) {
    puVar8 = &UNK_00140dc0;
  }
  else if (uVar6 == 0x6f) {
    puVar8 = &UNK_00140df8;
  }
  else {
    if (uVar6 != 100) {
      return 0;
    }
    puVar8 = &UNK_00140e30;
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
LAB_001233dc:
  uVar4 = uVar4 + 1;
LAB_001233e0:
  if (*(uint *)(param_1 + 0x38) <= uVar4) {
    return 0;
  }
  lVar5 = *(long *)(*(long *)(param_1 + 0x30) + (ulong)uVar4 * 8);
  *(int *)(param_1 + 0x40) = *(int *)(param_1 + 0x40) + 1;
  return lVar5;
}



void FUN_00123564(int *param_1,int *param_2,undefined4 *param_3)

{
  int *piVar1;
  
  if (param_3 == (undefined4 *)0x0) {
switchD_001235b8_caseD_5:
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
switchD_001235b8_caseD_1:
      piVar1 = *(int **)(param_3 + 2);
      break;
    case 4:
      *param_1 = *param_1 + 1;
      piVar1 = *(int **)(param_3 + 2);
      break;
    default:
      goto switchD_001235b8_caseD_5;
    case 7:
    case 8:
    case 0x32:
      param_3 = *(undefined4 **)(param_3 + 4);
      goto joined_r0x001235d8;
    case 0x23:
    case 0x24:
      piVar1 = *(int **)(param_3 + 2);
      if (*piVar1 == 5) {
        *param_2 = *param_2 + 1;
        goto switchD_001235b8_caseD_1;
      }
      break;
    case 0x43:
    case 0x44:
    case 0x45:
    case 0x46:
      param_3 = *(undefined4 **)(param_3 + 2);
      goto joined_r0x001235d8;
    }
    FUN_00123564(param_1,param_2,piVar1);
    param_3 = *(undefined4 **)(param_3 + 4);
joined_r0x001235d8:
    if (param_3 == (undefined4 *)0x0) {
      return;
    }
  } while( true );
}



void FUN_00123630(undefined *param_1,undefined param_2)

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



long FUN_001236a8(byte **param_1)

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



undefined8 FUN_00123730(long param_1,ulong *param_2)

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



int * FUN_001237ac(undefined8 param_1,undefined4 *param_2)

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
        goto LAB_001237f8;
      case 5:
        piVar1 = (int *)FUN_00123730(param_1,param_2 + 2);
        if ((piVar1 != (int *)0x0) && (*piVar1 == 0x2f)) {
          return piVar1;
        }
        goto LAB_001237f8;
      case 7:
      case 8:
      case 0x32:
        goto switchD_00123814_caseD_7;
      }
      piVar1 = (int *)FUN_001237ac(param_1,*(undefined8 *)(param_2 + 2));
      if (piVar1 != (int *)0x0) {
        return piVar1;
      }
switchD_00123814_caseD_7:
      param_2 = *(undefined4 **)(param_2 + 4);
    } while (param_2 != (undefined4 *)0x0);
  }
LAB_001237f8:
  return (int *)0x0;
}



void FUN_00123844(void *param_1,size_t param_2,void **param_3)

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



void FUN_00123934(char *param_1,char *param_2)

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



long FUN_001239e8(long param_1,int param_2)

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
      lVar3 = FUN_00123094(param_1,"(anonymous namespace)",0x15);
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



void FUN_00123b3c(char *param_1,undefined8 param_2)

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



undefined8 FUN_00123c08(long param_1)

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
      uVar3 = FUN_001239e8();
      *(undefined8 *)(param_1 + 0x48) = uVar3;
      return uVar3;
    }
  }
  return 0;
}



long FUN_00123cb0(long param_1)

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
      if (bVar1 == 0x5f) goto LAB_00123d2c;
    }
    return -1;
  }
  lVar3 = 0;
LAB_00123d2c:
  *(byte **)(param_1 + 0x18) = pbVar4 + 1;
  return lVar3;
}



ulong FUN_00123d3c(long param_1)

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



long FUN_00123de0(long param_1)

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



undefined8 FUN_00123ecc(long param_1,uint param_2)

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
      goto LAB_00123f4c;
    }
  }
  else {
    if (param_2 != 0x76) {
      return 0;
    }
    FUN_001236a8(param_1 + 0x18);
    if (**(char **)(param_1 + 0x18) != '_') {
      return 0;
    }
    *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
    FUN_001236a8(param_1 + 0x18);
    pcVar2 = *(char **)(param_1 + 0x18);
  }
  cVar4 = *pcVar2;
LAB_00123f4c:
  if (cVar4 != '_') {
    return 0;
  }
  *(char **)(param_1 + 0x18) = pcVar2 + 1;
  return 1;
}



long FUN_00123fb8(long param_1)

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
    uVar14 = FUN_00122ff4(param_1,0x2f,0,0);
    return uVar14;
  }
  plVar13 = &local_8;
  local_8 = 0;
LAB_00124028:
  switch(cVar3) {
  case 'I':
  case 'J':
    lVar5 = FUN_00123fb8(param_1);
    break;
  default:
    lVar5 = FUN_00125bf8(param_1);
    break;
  case 'L':
    lVar5 = FUN_00128798(param_1);
    break;
  case 'X':
    pcVar12 = pcVar16 + 1;
    uVar1 = *(undefined4 *)(param_1 + 0x54);
    *(char **)(param_1 + 0x18) = pcVar12;
    *(undefined4 *)(param_1 + 0x54) = 1;
    cVar3 = pcVar16[1];
    if (cVar3 == 'L') {
      lVar5 = FUN_00128798(param_1);
      pcVar12 = *(char **)(param_1 + 0x18);
    }
    else if (cVar3 == 'T') {
      lVar5 = FUN_00123de0(param_1);
      pcVar12 = *(char **)(param_1 + 0x18);
    }
    else if (cVar3 == 's') {
      if (pcVar16[2] == 'r') {
        *(char **)(param_1 + 0x18) = pcVar16 + 3;
        uVar7 = FUN_00125bf8(param_1);
        uVar8 = FUN_001275a4(param_1);
        if (**(char **)(param_1 + 0x18) == 'I') {
          uVar10 = FUN_00123fb8(param_1);
          uVar8 = FUN_00122ff4(param_1,4,uVar8,uVar10);
        }
        lVar5 = FUN_00122ff4(param_1,1,uVar7,uVar8);
        pcVar12 = *(char **)(param_1 + 0x18);
      }
      else {
        if (pcVar16[2] != 'p') goto LAB_00124114;
        *(char **)(param_1 + 0x18) = pcVar16 + 3;
        uVar7 = FUN_00128910(param_1);
        lVar5 = FUN_00122ff4(param_1,0x4a,uVar7,0);
        pcVar12 = *(char **)(param_1 + 0x18);
      }
    }
    else {
      if (cVar3 == 'f') {
        if (pcVar16[2] != 'p') goto LAB_00124114;
        *(char **)(param_1 + 0x18) = pcVar16 + 3;
        if (pcVar16[3] == 'T') {
          lVar15 = 0;
          *(char **)(param_1 + 0x18) = pcVar16 + 4;
        }
        else {
          iVar4 = FUN_00123cb0(param_1);
          lVar15 = (long)(iVar4 + 1);
          if (iVar4 + 1 == 0) {
            pcVar12 = *(char **)(param_1 + 0x18);
            goto LAB_00124220;
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
            goto LAB_001241c0;
          }
        }
        goto switchD_0012447c_caseD_4;
      }
      if ((byte)(cVar3 - 0x30U) < 10) {
LAB_001241a0:
        lVar5 = FUN_001275a4(param_1);
        pcVar12 = *(char **)(param_1 + 0x18);
        if (lVar5 != 0) {
          if (*pcVar12 == 'I') {
            uVar7 = FUN_00123fb8(param_1);
            lVar5 = FUN_00122ff4(param_1,4,lVar5,uVar7);
            pcVar12 = *(char **)(param_1 + 0x18);
          }
          goto LAB_001241c0;
        }
      }
      else {
        if (cVar3 == 'o') {
          if (pcVar16[2] == 'n') {
            *(char **)(param_1 + 0x18) = pcVar16 + 3;
            goto LAB_001241a0;
          }
        }
        else if (((cVar3 == 't') || (cVar3 == 'i')) && (pcVar16[2] == 'l')) {
          uVar7 = 0;
          if (cVar3 == 't') {
            uVar7 = FUN_00125bf8(param_1);
            pcVar12 = *(char **)(param_1 + 0x18);
          }
          *(char **)(param_1 + 0x18) = pcVar12 + 2;
          uVar8 = FUN_001254a4(param_1,0x45);
          lVar5 = FUN_00122ff4(param_1,0x30,uVar7,uVar8);
          pcVar12 = *(char **)(param_1 + 0x18);
          goto LAB_001241c0;
        }
LAB_00124114:
        piVar6 = (int *)FUN_001273b0(param_1);
        if (piVar6 != (int *)0x0) {
          iVar4 = *piVar6;
          if (iVar4 == 0x31) {
            ppcVar17 = *(char ***)(piVar6 + 2);
            pcVar12 = *ppcVar17;
            *(int *)(param_1 + 0x50) = *(int *)(param_1 + 0x50) + *(int *)(ppcVar17 + 2) + -2;
            iVar4 = strcmp(pcVar12,"st");
            if (iVar4 == 0) {
              uVar7 = FUN_00125bf8(param_1);
LAB_001244f0:
              lVar5 = FUN_00122ff4(param_1,0x36,piVar6,uVar7);
              pcVar12 = *(char **)(param_1 + 0x18);
              goto LAB_001241c0;
            }
            switch(*(undefined4 *)((long)ppcVar17 + 0x14)) {
            case 0:
              goto switchD_0012447c_caseD_0;
            case 1:
              cVar3 = *pcVar12;
              if (((cVar3 == 'm') || (cVar3 == 'p')) && (pcVar12[1] == cVar3)) {
                if (**(char **)(param_1 + 0x18) != '_') {
                  uVar7 = FUN_00128910(param_1);
                  uVar7 = FUN_00122ff4(param_1,0x38,uVar7,uVar7);
                  goto LAB_001244f0;
                }
                *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
              }
              goto switchD_0012447c_caseD_1;
            case 2:
              goto switchD_00124354_caseD_2;
            case 3:
              goto switchD_00124354_caseD_3;
            }
          }
          else if (iVar4 == 0x32) {
            switch(piVar6[2]) {
            case 0:
switchD_0012447c_caseD_0:
              lVar5 = FUN_00122ff4(param_1,0x35,piVar6,0);
              pcVar12 = *(char **)(param_1 + 0x18);
              goto LAB_001241c0;
            case 1:
              goto switchD_0012447c_caseD_1;
            case 2:
              pcVar12 = (char *)0x0;
switchD_00124354_caseD_2:
              if (((**(char ***)(piVar6 + 2))[1] == 'c') &&
                 ((cVar3 = ***(char ***)(piVar6 + 2), (byte)(cVar3 + 0x8eU) < 2 ||
                  ((byte)(cVar3 + 0x9dU) < 2)))) {
                uVar7 = FUN_00125bf8(param_1);
              }
              else {
                uVar7 = FUN_00128910(param_1);
              }
              iVar4 = strcmp(pcVar12,"cl");
              if (iVar4 == 0) {
                uVar8 = FUN_001254a4(param_1,0x45);
              }
              else {
                iVar4 = strcmp(pcVar12,"dt");
                if ((iVar4 == 0) || (iVar4 = strcmp(pcVar12,"pt"), iVar4 == 0)) {
                  uVar8 = FUN_001275a4(param_1);
                  if (**(char **)(param_1 + 0x18) == 'I') {
                    uVar10 = FUN_00123fb8(param_1);
                    uVar8 = FUN_00122ff4(param_1,4,uVar8,uVar10);
                  }
                }
                else {
                  uVar8 = FUN_00128910(param_1);
                }
              }
              uVar7 = FUN_00122ff4(param_1,0x38,uVar7,uVar8);
              lVar5 = FUN_00122ff4(param_1,0x37,piVar6,uVar7);
              pcVar12 = *(char **)(param_1 + 0x18);
              goto LAB_001241c0;
            case 3:
              pcVar12 = (char *)0x0;
switchD_00124354_caseD_3:
              iVar4 = strcmp(pcVar12,"qu");
              if (iVar4 == 0) {
                local_18 = FUN_00128910(param_1);
                pcVar12 = *(char **)(param_1 + 0x18);
                cVar3 = *pcVar12;
                if (cVar3 == 'L') {
                  piVar9 = (int *)FUN_00128798(param_1);
                  pcVar12 = *(char **)(param_1 + 0x18);
                  cVar3 = *pcVar12;
LAB_001247b0:
                  if (cVar3 == 'L') {
                    lVar5 = FUN_00128798(param_1);
                  }
                  else if (cVar3 == 'T') {
                    lVar5 = FUN_00123de0(param_1);
                  }
                  else if (cVar3 == 's') {
                    if (pcVar12[1] == 'r') {
                      *(char **)(param_1 + 0x18) = pcVar12 + 2;
                      uVar7 = FUN_00125bf8(param_1);
                      uVar8 = FUN_001275a4(param_1);
                      if (**(char **)(param_1 + 0x18) == 'I') {
                        uVar10 = FUN_00123fb8(param_1);
                        uVar8 = FUN_00122ff4(param_1,4,uVar8,uVar10);
                      }
                      lVar5 = FUN_00122ff4(param_1,1,uVar7,uVar8);
                    }
                    else {
                      if (pcVar12[1] != 'p') goto LAB_00124808;
                      *(char **)(param_1 + 0x18) = pcVar12 + 2;
                      uVar7 = FUN_00128910(param_1);
                      lVar5 = FUN_00122ff4(param_1,0x4a,uVar7,0);
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
                        iVar4 = FUN_00123cb0(param_1);
                        if (iVar4 + 1 == 0) goto LAB_00124c68;
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
LAB_00124808:
                      piVar11 = (int *)FUN_001273b0(param_1);
                      if (piVar11 == (int *)0x0) {
LAB_00124c68:
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
                              goto switchD_00124bfc_caseD_0;
                            case 1:
                              goto switchD_00124c64_caseD_1;
                            case 2:
                              goto switchD_00124c64_caseD_2;
                            case 3:
                              goto switchD_00124c64_caseD_3;
                            default:
                              goto switchD_00124bfc_caseD_4;
                            }
                          }
                          uVar7 = FUN_00125bf8(param_1);
                        }
                        else {
                          if (iVar4 == 0x32) {
                            lVar5 = 0;
                            switch(piVar11[2]) {
                            case 0:
switchD_00124bfc_caseD_0:
                              lVar5 = FUN_00122ff4(param_1,0x35,piVar11,0);
                              break;
                            case 1:
                              goto switchD_00124bfc_caseD_1;
                            case 2:
                              pcVar12 = (char *)0x0;
switchD_00124c64_caseD_2:
                              if ((**(char ***)(piVar11 + 2))[1] == 'c') {
                                cVar3 = ***(char ***)(piVar11 + 2);
                                bVar2 = cVar3 + 0x8e;
                                if ((1 < bVar2) && (1 < (byte)(cVar3 + 0x9dU))) goto LAB_00124f20;
                                local_20 = FUN_00125bf8(param_1,bVar2,pcVar12,0);
                              }
                              else {
LAB_00124f20:
                                local_20 = FUN_00128910(param_1);
                              }
                              iVar4 = strcmp(pcVar12,"cl");
                              if (iVar4 == 0) {
                                uVar7 = FUN_001254a4(param_1,0x45);
                              }
                              else {
                                iVar4 = strcmp(pcVar12,"dt");
                                if ((iVar4 == 0) || (iVar4 = strcmp(pcVar12,"pt"), iVar4 == 0)) {
                                  uVar7 = FUN_001275a4(param_1);
                                  if (**(char **)(param_1 + 0x18) == 'I') {
                                    uVar8 = FUN_00123fb8(param_1);
                                    uVar7 = FUN_00122ff4(param_1,4,uVar7,uVar8);
                                  }
                                }
                                else {
                                  uVar7 = FUN_00128910(param_1);
                                }
                              }
                              uVar7 = FUN_00122ff4(param_1,0x38,local_20,uVar7);
                              lVar5 = FUN_00122ff4(param_1,0x37,piVar11,uVar7);
                              break;
                            case 3:
                              pcVar12 = (char *)0x0;
switchD_00124c64_caseD_3:
                              iVar4 = strcmp(pcVar12,"qu");
                              if (iVar4 == 0) {
                                local_20 = FUN_00128910(param_1);
                                local_28 = FUN_00128910(param_1);
                                uVar7 = FUN_00128910(param_1);
                              }
                              else {
                                if ((*pcVar12 != 'n') ||
                                   ((pcVar12[1] != 'a' && (pcVar12[1] != 'w')))) goto LAB_00124c68;
                                local_20 = FUN_001254a4(param_1,0x5f);
                                local_28 = FUN_00125bf8(param_1);
                                pcVar12 = *(char **)(param_1 + 0x18);
                                cVar3 = *pcVar12;
                                if (cVar3 != 'E') {
                                  if (cVar3 == 'p') {
                                    lVar5 = 0;
                                    if (pcVar12[1] == 'i') {
                                      *(char **)(param_1 + 0x18) = pcVar12 + 2;
                                      uVar7 = FUN_001254a4(param_1,0x45);
                                      goto LAB_00125058;
                                    }
                                  }
                                  else {
                                    if (cVar3 != 'i') goto LAB_00124c68;
                                    lVar5 = 0;
                                    if (pcVar12[1] == 'l') {
                                      uVar7 = FUN_00128910(param_1);
                                      goto LAB_00125058;
                                    }
                                  }
                                  break;
                                }
                                uVar7 = 0;
                                *(char **)(param_1 + 0x18) = pcVar12 + 1;
                              }
LAB_00125058:
                              uVar7 = FUN_00122ff4(param_1,0x3b,local_28,uVar7);
                              uVar7 = FUN_00122ff4(param_1,0x3a,local_20,uVar7);
                              lVar5 = FUN_00122ff4(param_1,0x39,piVar11,uVar7);
                            }
                            goto switchD_00124bfc_caseD_4;
                          }
                          if (iVar4 != 0x33) goto LAB_00124c68;
                          if (**(char **)(param_1 + 0x18) == '_') {
                            *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
                            uVar7 = FUN_001254a4(param_1,0x45);
                            goto LAB_00124850;
                          }
switchD_00124bfc_caseD_1:
                          uVar7 = FUN_00128910(param_1);
                        }
LAB_00124850:
                        lVar5 = FUN_00122ff4(param_1,0x36,piVar11,uVar7);
                      }
                    }
                  }
                  else {
                    if (9 < (byte)(cVar3 - 0x30U)) {
                      if (cVar3 != 'o') goto LAB_001247e8;
                      if (pcVar12[1] != 'n') goto LAB_00124808;
                      *(char **)(param_1 + 0x18) = pcVar12 + 2;
                    }
                    lVar5 = FUN_001275a4(param_1);
                    if ((lVar5 != 0) && (**(char **)(param_1 + 0x18) == 'I')) {
                      uVar7 = FUN_00123fb8(param_1);
                      lVar5 = FUN_00122ff4(param_1,4,lVar5,uVar7);
                    }
                  }
                }
                else {
                  if (cVar3 == 'T') {
                    piVar9 = (int *)FUN_00123de0(param_1);
                    pcVar12 = *(char **)(param_1 + 0x18);
                    cVar3 = *pcVar12;
                    goto LAB_001247b0;
                  }
                  if (cVar3 == 's') {
                    if (pcVar12[1] == 'r') {
                      *(char **)(param_1 + 0x18) = pcVar12 + 2;
                      piVar9 = (int *)FUN_00125bf8(param_1);
                      uVar7 = FUN_001275a4(param_1);
                      if (**(char **)(param_1 + 0x18) != 'I') {
                        piVar9 = (int *)FUN_00122ff4(param_1,1,piVar9,uVar7);
                        pcVar12 = *(char **)(param_1 + 0x18);
                        cVar3 = *pcVar12;
                        goto LAB_001247b0;
                      }
                      uVar8 = FUN_00123fb8(param_1);
                      uVar7 = FUN_00122ff4(param_1,4,uVar7,uVar8);
                      uVar8 = 1;
                      goto LAB_0012479c;
                    }
                    if (pcVar12[1] != 'p') goto LAB_0012474c;
                    *(char **)(param_1 + 0x18) = pcVar12 + 2;
                    piVar9 = (int *)FUN_00128910(param_1);
                    uVar7 = 0x4a;
LAB_00124af0:
                    piVar9 = (int *)FUN_00122ff4(param_1,uVar7,piVar9,0);
LAB_00124afc:
                    pcVar12 = *(char **)(param_1 + 0x18);
LAB_00124b00:
                    cVar3 = *pcVar12;
                    goto LAB_001247b0;
                  }
                  if (cVar3 == 'f') {
                    if (pcVar12[1] != 'p') goto LAB_0012474c;
                    *(char **)(param_1 + 0x18) = pcVar12 + 2;
                    if (pcVar12[2] == 'T') {
                      pcVar12 = pcVar12 + 3;
                      lVar5 = 0;
                      *(char **)(param_1 + 0x18) = pcVar12;
                    }
                    else {
                      iVar4 = FUN_00123cb0(param_1);
                      pcVar12 = *(char **)(param_1 + 0x18);
                      if (iVar4 + 1 == 0) {
LAB_00124b0c:
                        piVar9 = (int *)0x0;
                        cVar3 = *pcVar12;
                        goto LAB_001247b0;
                      }
                      lVar5 = (long)(iVar4 + 1);
                    }
                    iVar4 = *(int *)(param_1 + 0x28);
                    if (iVar4 < *(int *)(param_1 + 0x2c)) {
                      *(int *)(param_1 + 0x28) = iVar4 + 1;
                      piVar9 = (int *)(*(long *)(param_1 + 0x20) + (long)iVar4 * 0x18);
                      if (piVar9 == (int *)0x0) goto LAB_00124b00;
                      *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar4 * 0x18) = 6;
                      *(long *)(piVar9 + 2) = lVar5;
                      cVar3 = *pcVar12;
                    }
                    else {
                      cVar3 = *pcVar12;
                      piVar9 = (int *)0x0;
                    }
                    goto LAB_001247b0;
                  }
                  if ((byte)(cVar3 - 0x30U) < 10) {
LAB_00124964:
                    piVar9 = (int *)FUN_001275a4(param_1);
                    pcVar12 = *(char **)(param_1 + 0x18);
                    cVar3 = *pcVar12;
                    if ((piVar9 != (int *)0x0) && (cVar3 == 'I')) {
                      uVar7 = FUN_00123fb8(param_1);
                      uVar8 = 4;
                      goto LAB_0012479c;
                    }
                    goto LAB_001247b0;
                  }
                  if (cVar3 == 'o') {
                    if (pcVar12[1] == 'n') {
                      *(char **)(param_1 + 0x18) = pcVar12 + 2;
                      goto LAB_00124964;
                    }
                  }
                  else if (((cVar3 == 't') || (cVar3 == 'i')) && (pcVar12[1] == 'l')) {
                    uVar7 = 0;
                    if (cVar3 == 't') {
                      uVar7 = FUN_00125bf8(param_1);
                      pcVar12 = *(char **)(param_1 + 0x18);
                    }
                    *(char **)(param_1 + 0x18) = pcVar12 + 2;
                    uVar8 = FUN_001254a4(param_1,0x45);
                    piVar9 = (int *)FUN_00122ff4(param_1,0x30,uVar7,uVar8);
                    pcVar12 = *(char **)(param_1 + 0x18);
                    cVar3 = *pcVar12;
                    goto LAB_001247b0;
                  }
LAB_0012474c:
                  piVar9 = (int *)FUN_001273b0(param_1);
                  if (piVar9 == (int *)0x0) goto LAB_00124afc;
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
                        goto switchD_00124b7c_caseD_0;
                      case 1:
                        goto switchD_00124ce8_caseD_1;
                      case 2:
                        goto switchD_00124ce8_caseD_2;
                      case 3:
                        goto switchD_00124ce8_caseD_3;
                      default:
                        goto switchD_00124b7c_caseD_4;
                      }
                    }
                    uVar7 = FUN_00125bf8(param_1);
                    uVar8 = 0x36;
                    goto LAB_0012479c;
                  }
                  if (iVar4 != 0x32) {
                    if (iVar4 == 0x33) {
                      if (**(char **)(param_1 + 0x18) != '_') goto switchD_00124b7c_caseD_1;
                      *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
                      uVar7 = FUN_001254a4(param_1,0x45);
                      goto LAB_00124794;
                    }
switchD_00124b7c_caseD_4:
                    pcVar12 = *(char **)(param_1 + 0x18);
                    goto LAB_00124b0c;
                  }
                  switch(piVar9[2]) {
                  case 0:
switchD_00124b7c_caseD_0:
                    uVar7 = 0x35;
                    goto LAB_00124af0;
                  case 1:
                    goto switchD_00124b7c_caseD_1;
                  case 2:
                    pcVar12 = (char *)0x0;
switchD_00124ce8_caseD_2:
                    if (((**(char ***)(piVar9 + 2))[1] == 'c') &&
                       ((cVar3 = ***(char ***)(piVar9 + 2), (byte)(cVar3 + 0x8eU) < 2 ||
                        ((byte)(cVar3 + 0x9dU) < 2)))) {
                      local_20 = FUN_00125bf8(param_1);
                    }
                    else {
                      local_20 = FUN_00128910(param_1);
                    }
                    iVar4 = strcmp(pcVar12,"cl");
                    if (iVar4 == 0) {
                      uVar7 = FUN_001254a4(param_1,0x45);
                    }
                    else {
                      iVar4 = strcmp(pcVar12,"dt");
                      if ((iVar4 == 0) || (iVar4 = strcmp(pcVar12,"pt"), iVar4 == 0)) {
                        uVar7 = FUN_001275a4(param_1);
                        if (**(char **)(param_1 + 0x18) == 'I') {
                          uVar8 = FUN_00123fb8(param_1);
                          uVar7 = FUN_00122ff4(param_1,4,uVar7,uVar8);
                        }
                      }
                      else {
                        uVar7 = FUN_00128910(param_1);
                      }
                    }
                    uVar7 = FUN_00122ff4(param_1,0x38,local_20,uVar7);
                    uVar8 = 0x37;
                    goto LAB_0012479c;
                  case 3:
                    pcVar12 = (char *)0x0;
switchD_00124ce8_caseD_3:
                    iVar4 = strcmp(pcVar12,"qu");
                    if (iVar4 == 0) {
                      local_20 = FUN_00128910(param_1);
                      uVar7 = FUN_00128910(param_1);
                      uVar8 = FUN_00128910(param_1);
LAB_00124ed0:
                      uVar7 = FUN_00122ff4(param_1,0x3b,uVar7,uVar8);
                      uVar7 = FUN_00122ff4(param_1,0x3a,local_20,uVar7);
                      uVar8 = 0x39;
                      goto LAB_0012479c;
                    }
                    if ((*pcVar12 != 'n') || ((pcVar12[1] != 'a' && (pcVar12[1] != 'w'))))
                    goto switchD_00124b7c_caseD_4;
                    local_20 = FUN_001254a4(param_1,0x5f);
                    uVar7 = FUN_00125bf8(param_1);
                    pcVar12 = *(char **)(param_1 + 0x18);
                    cVar3 = *pcVar12;
                    if (cVar3 == 'E') {
                      uVar8 = 0;
                      *(char **)(param_1 + 0x18) = pcVar12 + 1;
                      goto LAB_00124ed0;
                    }
                    if (cVar3 == 'p') {
                      if (pcVar12[1] == 'i') {
                        *(char **)(param_1 + 0x18) = pcVar12 + 2;
                        uVar8 = FUN_001254a4(param_1,0x45);
                        goto LAB_00124ed0;
                      }
                    }
                    else {
                      if (cVar3 != 'i') {
                        piVar9 = (int *)0x0;
                        goto LAB_001247b0;
                      }
                      if (pcVar12[1] == 'l') {
                        uVar8 = FUN_00128910(param_1);
                        goto LAB_00124ed0;
                      }
                    }
                    piVar9 = (int *)0x0;
LAB_001247e8:
                    if (((cVar3 != 't') && (cVar3 != 'i')) || (pcVar12[1] != 'l'))
                    goto LAB_00124808;
                    uVar7 = 0;
                    if (cVar3 == 't') {
                      uVar7 = FUN_00125bf8(param_1);
                    }
                    *(long *)(param_1 + 0x18) = *(long *)(param_1 + 0x18) + 2;
                    uVar8 = FUN_001254a4(param_1,0x45);
                    lVar5 = FUN_00122ff4(param_1,0x30,uVar7,uVar8);
                    break;
                  default:
                    goto switchD_00124b7c_caseD_4;
                  }
                }
              }
              else {
                if ((*pcVar12 != 'n') || ((pcVar12[1] != 'a' && (pcVar12[1] != 'w')))) break;
                local_18 = FUN_001254a4(param_1,0x5f);
                piVar9 = (int *)FUN_00125bf8(param_1);
                pcVar12 = *(char **)(param_1 + 0x18);
                cVar3 = *pcVar12;
                if (cVar3 != 'E') {
                  if (cVar3 == 'p') {
                    lVar5 = 0;
                    if (pcVar12[1] == 'i') {
                      *(char **)(param_1 + 0x18) = pcVar12 + 2;
                      lVar5 = FUN_001254a4(param_1,0x45);
                      goto switchD_00124bfc_caseD_4;
                    }
                  }
                  else {
                    lVar5 = 0;
                    if ((cVar3 == 'i') && (pcVar12[1] == 'l')) {
                      lVar5 = FUN_00128910(param_1);
                      goto switchD_00124bfc_caseD_4;
                    }
                  }
                  goto LAB_001241c0;
                }
                lVar5 = 0;
                *(char **)(param_1 + 0x18) = pcVar12 + 1;
              }
switchD_00124bfc_caseD_4:
              uVar7 = FUN_00122ff4(param_1,0x3b,piVar9,lVar5);
              uVar7 = FUN_00122ff4(param_1,0x3a,local_18,uVar7);
              lVar5 = FUN_00122ff4(param_1,0x39,piVar6,uVar7);
              pcVar12 = *(char **)(param_1 + 0x18);
              goto LAB_001241c0;
            }
          }
          else if (iVar4 == 0x33) {
            if (**(char **)(param_1 + 0x18) == '_') {
              *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
              uVar7 = FUN_001254a4(param_1,0x45);
              goto LAB_001244f0;
            }
switchD_0012447c_caseD_1:
            uVar7 = FUN_00128910(param_1);
            goto LAB_001244f0;
          }
        }
switchD_0012447c_caseD_4:
        pcVar12 = *(char **)(param_1 + 0x18);
      }
LAB_00124220:
      lVar5 = 0;
    }
LAB_001241c0:
    *(undefined4 *)(param_1 + 0x54) = uVar1;
    if (*pcVar12 != 'E') {
      return 0;
    }
    *(char **)(param_1 + 0x18) = pcVar12 + 1;
  }
  if (lVar5 == 0) {
    return 0;
  }
  lVar5 = FUN_00122ff4(param_1,0x2f,lVar5,0);
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
  goto LAB_00124028;
switchD_00124ce8_caseD_1:
  cVar3 = *pcVar12;
  if (((cVar3 == 'm') || (cVar3 == 'p')) && (pcVar12[1] == cVar3)) {
    if (**(char **)(param_1 + 0x18) != '_') {
      uVar7 = FUN_00128910(param_1);
      uVar7 = FUN_00122ff4(param_1,0x38,uVar7,uVar7);
      uVar8 = 0x36;
      goto LAB_0012479c;
    }
    *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
  }
switchD_00124b7c_caseD_1:
  uVar7 = FUN_00128910(param_1);
LAB_00124794:
  uVar8 = 0x36;
LAB_0012479c:
  piVar9 = (int *)FUN_00122ff4(param_1,uVar8,piVar9,uVar7);
  pcVar12 = *(char **)(param_1 + 0x18);
  cVar3 = *pcVar12;
  goto LAB_001247b0;
switchD_00124c64_caseD_1:
  cVar3 = *pcVar12;
  if (((cVar3 == 'm') || (cVar3 == 'p')) && (pcVar12[1] == cVar3)) {
    cVar3 = **(char **)(param_1 + 0x18);
    if (cVar3 != '_') {
      uVar7 = FUN_00128910(param_1,cVar3,pcVar12,0);
      uVar7 = FUN_00122ff4(param_1,0x38,uVar7,uVar7);
      goto LAB_00124850;
    }
    *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
  }
  goto switchD_00124bfc_caseD_1;
}



undefined8 FUN_001254a4(long param_1,char param_2)

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
    uVar5 = FUN_00122ff4(param_1,0x2e,0,0);
    return uVar5;
  }
  do {
    uVar1 = *(undefined4 *)(param_1 + 0x54);
    *(undefined4 *)(param_1 + 0x54) = 1;
    cVar2 = *pcVar10;
    if (cVar2 == 'L') {
      lVar6 = FUN_00128798(param_1);
LAB_00125668:
      *(undefined4 *)(param_1 + 0x54) = uVar1;
      if (lVar6 == 0) {
        return 0;
      }
    }
    else {
      if (cVar2 == 'T') {
        lVar6 = FUN_00123de0(param_1);
        goto LAB_00125668;
      }
      if (cVar2 == 's') {
        if (pcVar10[1] == 'r') {
          *(char **)(param_1 + 0x18) = pcVar10 + 2;
          uVar5 = FUN_00125bf8(param_1);
          uVar8 = FUN_001275a4(param_1);
          if (**(char **)(param_1 + 0x18) == 'I') {
            uVar9 = FUN_00123fb8(param_1);
            uVar8 = FUN_00122ff4(param_1,4,uVar8,uVar9);
          }
          lVar6 = FUN_00122ff4(param_1,1,uVar5,uVar8);
        }
        else {
          if (pcVar10[1] != 'p') goto LAB_00125558;
          *(char **)(param_1 + 0x18) = pcVar10 + 2;
          uVar5 = FUN_00128910(param_1);
          lVar6 = FUN_00122ff4(param_1,0x4a,uVar5,0);
        }
        goto LAB_00125668;
      }
      if (cVar2 == 'f') {
        if (pcVar10[1] != 'p') goto LAB_00125558;
        *(char **)(param_1 + 0x18) = pcVar10 + 2;
        if (pcVar10[2] == 'T') {
          lVar7 = 0;
          *(char **)(param_1 + 0x18) = pcVar10 + 3;
        }
        else {
          iVar3 = FUN_00123cb0(param_1);
          if (iVar3 + 1 == 0) goto switchD_001257fc_caseD_4;
          lVar7 = (long)(iVar3 + 1);
        }
        iVar3 = *(int *)(param_1 + 0x28);
        if (*(int *)(param_1 + 0x2c) <= iVar3) goto switchD_001257fc_caseD_4;
        *(int *)(param_1 + 0x28) = iVar3 + 1;
        lVar6 = *(long *)(param_1 + 0x20) + (long)iVar3 * 0x18;
        if (lVar6 == 0) goto switchD_001257fc_caseD_4;
        *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar3 * 0x18) = 6;
        *(long *)(lVar6 + 8) = lVar7;
      }
      else {
        if (9 < (byte)(cVar2 - 0x30U)) {
          if (cVar2 == 'o') {
            if (pcVar10[1] == 'n') {
              *(char **)(param_1 + 0x18) = pcVar10 + 2;
              goto LAB_001255cc;
            }
          }
          else if (((cVar2 == 't') || (cVar2 == 'i')) && (pcVar10[1] == 'l')) {
            uVar5 = 0;
            if (cVar2 == 't') {
              uVar5 = FUN_00125bf8(param_1);
              pcVar10 = *(char **)(param_1 + 0x18);
            }
            *(char **)(param_1 + 0x18) = pcVar10 + 2;
            uVar8 = FUN_001254a4(param_1,0x45);
            lVar6 = FUN_00122ff4(param_1,0x30,uVar5,uVar8);
            goto LAB_00125668;
          }
LAB_00125558:
          piVar4 = (int *)FUN_001273b0(param_1);
          if (piVar4 == (int *)0x0) goto switchD_001257fc_caseD_4;
          iVar3 = *piVar4;
          if (iVar3 == 0x31) {
            ppcVar12 = *(char ***)(piVar4 + 2);
            pcVar10 = *ppcVar12;
            *(int *)(param_1 + 0x50) = *(int *)(param_1 + 0x50) + *(int *)(ppcVar12 + 2) + -2;
            iVar3 = strcmp(pcVar10,"st");
            if (iVar3 != 0) {
              switch(*(undefined4 *)((long)ppcVar12 + 0x14)) {
              case 0:
                goto switchD_001257fc_caseD_0;
              case 1:
                goto switchD_00125824_caseD_1;
              case 2:
                goto switchD_00125824_caseD_2;
              case 3:
                goto switchD_00125824_caseD_3;
              default:
                goto switchD_001257fc_caseD_4;
              }
            }
            uVar5 = FUN_00125bf8(param_1);
          }
          else {
            if (iVar3 == 0x32) {
              switch(piVar4[2]) {
              case 0:
switchD_001257fc_caseD_0:
                lVar6 = FUN_00122ff4(param_1,0x35,piVar4,0);
                goto LAB_00125668;
              case 1:
                goto switchD_001257fc_caseD_1;
              case 2:
                pcVar10 = (char *)0x0;
switchD_00125824_caseD_2:
                if (((**(char ***)(piVar4 + 2))[1] == 'c') &&
                   ((cVar2 = ***(char ***)(piVar4 + 2), (byte)(cVar2 + 0x8eU) < 2 ||
                    ((byte)(cVar2 + 0x9dU) < 2)))) {
                  uVar5 = FUN_00125bf8(param_1);
                }
                else {
                  uVar5 = FUN_00128910(param_1);
                }
                iVar3 = strcmp(pcVar10,"cl");
                if (iVar3 == 0) {
                  uVar8 = FUN_001254a4(param_1,0x45);
                }
                else {
                  iVar3 = strcmp(pcVar10,"dt");
                  if ((iVar3 == 0) || (iVar3 = strcmp(pcVar10,"pt"), iVar3 == 0)) {
                    uVar8 = FUN_001275a4(param_1);
                    if (**(char **)(param_1 + 0x18) == 'I') {
                      uVar9 = FUN_00123fb8(param_1);
                      uVar8 = FUN_00122ff4(param_1,4,uVar8,uVar9);
                    }
                  }
                  else {
                    uVar8 = FUN_00128910(param_1);
                  }
                }
                uVar5 = FUN_00122ff4(param_1,0x38,uVar5,uVar8);
                lVar6 = FUN_00122ff4(param_1,0x37,piVar4,uVar5);
                goto LAB_00125668;
              case 3:
                pcVar10 = (char *)0x0;
switchD_00125824_caseD_3:
                iVar3 = strcmp(pcVar10,"qu");
                if (iVar3 == 0) {
                  uVar5 = FUN_00128910(param_1);
                  uVar8 = FUN_00128910(param_1);
                  uVar9 = FUN_00128910(param_1);
                }
                else {
                  if ((*pcVar10 != 'n') || ((pcVar10[1] != 'a' && (pcVar10[1] != 'w'))))
                  goto switchD_001257fc_caseD_4;
                  uVar5 = FUN_001254a4(param_1,0x5f);
                  uVar8 = FUN_00125bf8(param_1);
                  pcVar10 = *(char **)(param_1 + 0x18);
                  cVar2 = *pcVar10;
                  if (cVar2 == 'E') {
                    uVar9 = 0;
                    *(char **)(param_1 + 0x18) = pcVar10 + 1;
                  }
                  else if (cVar2 == 'p') {
                    if (pcVar10[1] != 'i') goto switchD_001257fc_caseD_4;
                    *(char **)(param_1 + 0x18) = pcVar10 + 2;
                    uVar9 = FUN_001254a4(param_1,0x45);
                  }
                  else {
                    if ((cVar2 != 'i') || (pcVar10[1] != 'l')) {
switchD_001257fc_caseD_4:
                      *(undefined4 *)(param_1 + 0x54) = uVar1;
                      return 0;
                    }
                    uVar9 = FUN_00128910(param_1);
                  }
                }
                uVar8 = FUN_00122ff4(param_1,0x3b,uVar8,uVar9);
                uVar5 = FUN_00122ff4(param_1,0x3a,uVar5,uVar8);
                lVar6 = FUN_00122ff4(param_1,0x39,piVar4,uVar5);
                goto LAB_00125668;
              default:
                goto switchD_001257fc_caseD_4;
              }
            }
            if (iVar3 != 0x33) goto switchD_001257fc_caseD_4;
            if (**(char **)(param_1 + 0x18) == '_') {
              *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
              uVar5 = FUN_001254a4(param_1,0x45);
              goto LAB_001255a0;
            }
switchD_001257fc_caseD_1:
            uVar5 = FUN_00128910(param_1);
          }
LAB_001255a0:
          lVar6 = FUN_00122ff4(param_1,0x36,piVar4,uVar5);
          goto LAB_00125668;
        }
LAB_001255cc:
        lVar6 = FUN_001275a4(param_1);
        if (lVar6 == 0) goto switchD_001257fc_caseD_4;
        if (**(char **)(param_1 + 0x18) == 'I') {
          uVar5 = FUN_00123fb8(param_1);
          lVar6 = FUN_00122ff4(param_1,4,lVar6,uVar5);
          goto LAB_00125668;
        }
      }
      *(undefined4 *)(param_1 + 0x54) = uVar1;
    }
    lVar6 = FUN_00122ff4(param_1,0x2e,lVar6,0);
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
switchD_00125824_caseD_1:
  cVar2 = *pcVar10;
  if (((cVar2 == 'm') || (cVar2 == 'p')) && (pcVar10[1] == cVar2)) {
    if (**(char **)(param_1 + 0x18) != '_') {
      uVar5 = FUN_00128910(param_1);
      uVar5 = FUN_00122ff4(param_1,0x38,uVar5,uVar5);
      goto LAB_001255a0;
    }
    *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
  }
  goto switchD_001257fc_caseD_1;
}



int * FUN_00125bf8(long param_1)

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
    ppiVar11 = (int **)FUN_001230f4(param_1,&local_8,0);
    if (ppiVar11 == (int **)0x0) {
      return (int *)0x0;
    }
    if (**(char **)(param_1 + 0x18) == 'F') {
      piVar12 = (int *)FUN_00128f78(param_1);
      *ppiVar11 = piVar12;
    }
    else {
      piVar12 = (int *)FUN_00125bf8();
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
    local_8 = (int *)FUN_00127b28(param_1);
    break;
  default:
    goto switchD_00125c74_caseD_3a;
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
        lVar14 = FUN_00123094(param_1,pbVar21,(int)pbVar23 - (int)pbVar21);
joined_r0x001266d0:
        if (lVar14 == 0) goto LAB_00125e1c;
        pbVar21 = *(byte **)(param_1 + 0x18);
      }
      else {
        uVar2 = *(undefined4 *)(param_1 + 0x54);
        *(undefined4 *)(param_1 + 0x54) = 1;
        bVar7 = pbVar22[1];
        if (bVar7 == 0x4c) {
          lVar14 = FUN_00128798(param_1);
LAB_001266cc:
          *(undefined4 *)(param_1 + 0x54) = uVar2;
          goto joined_r0x001266d0;
        }
        if (bVar7 == 0x54) {
          lVar14 = FUN_00123de0(param_1);
          goto LAB_001266cc;
        }
        if (bVar7 == 0x73) {
          if (pbVar22[2] == 0x72) {
            *(byte **)(param_1 + 0x18) = pbVar22 + 3;
            uVar13 = FUN_00125bf8(param_1);
            uVar17 = FUN_001275a4(param_1);
            if (**(char **)(param_1 + 0x18) == 'I') {
              uVar18 = FUN_00123fb8(param_1);
              uVar17 = FUN_00122ff4(param_1,4,uVar17,uVar18);
              lVar14 = FUN_00122ff4(param_1,1,uVar13,uVar17);
            }
            else {
              lVar14 = FUN_00122ff4(param_1,1,uVar13,uVar17);
            }
          }
          else {
            if (pbVar22[2] != 0x70) goto LAB_00126670;
            *(byte **)(param_1 + 0x18) = pbVar22 + 3;
            uVar13 = FUN_00128910(param_1);
            lVar14 = FUN_00122ff4(param_1,0x4a,uVar13,0);
          }
          goto LAB_001266cc;
        }
        if (bVar7 != 0x66) {
          if ((byte)(bVar7 - 0x30) < 10) {
LAB_00126744:
            lVar14 = FUN_001275a4(param_1);
            if (lVar14 != 0) {
              pbVar21 = *(byte **)(param_1 + 0x18);
              if (*pbVar21 != 0x49) {
                *(undefined4 *)(param_1 + 0x54) = uVar2;
                goto LAB_00125e0c;
              }
              uVar13 = FUN_00123fb8(param_1);
              lVar14 = FUN_00122ff4(param_1,4,lVar14,uVar13);
              goto LAB_001266cc;
            }
          }
          else {
            if (bVar7 == 0x6f) {
              if (pbVar22[2] == 0x6e) {
                *(byte **)(param_1 + 0x18) = pbVar22 + 3;
                goto LAB_00126744;
              }
            }
            else if (((bVar7 == 0x74) || (bVar7 == 0x69)) && (pbVar22[2] == 0x6c)) {
              uVar13 = 0;
              if (bVar7 == 0x74) {
                uVar13 = FUN_00125bf8(param_1);
              }
              *(long *)(param_1 + 0x18) = *(long *)(param_1 + 0x18) + 2;
              uVar17 = FUN_001254a4(param_1,0x45);
              lVar14 = FUN_00122ff4(param_1,0x30,uVar13,uVar17);
              goto LAB_001266cc;
            }
LAB_00126670:
            piVar12 = (int *)FUN_001273b0(param_1);
            if (piVar12 != (int *)0x0) {
              iVar10 = *piVar12;
              if (iVar10 == 0x31) {
                pcVar24 = **(char ***)(piVar12 + 2);
                *(int *)(param_1 + 0x50) =
                     *(int *)(param_1 + 0x50) + *(int *)(*(char ***)(piVar12 + 2) + 2) + -2;
                iVar10 = strcmp(pcVar24,"st");
                if (iVar10 == 0) {
                  uVar13 = FUN_00125bf8(param_1);
LAB_001266b8:
                  lVar14 = FUN_00122ff4(param_1,0x36,piVar12,uVar13);
                  goto LAB_001266cc;
                }
                switch(*(undefined4 *)(*(long *)(piVar12 + 2) + 0x14)) {
                case 0:
                  goto switchD_00126a08_caseD_0;
                case 1:
                  cVar8 = *pcVar24;
                  if (((cVar8 == 'm') || (cVar8 == 'p')) && (pcVar24[1] == cVar8)) {
                    if (**(char **)(param_1 + 0x18) != '_') {
                      uVar13 = FUN_00128910(param_1);
                      uVar13 = FUN_00122ff4(param_1,0x38,uVar13,uVar13);
                      goto LAB_001266b8;
                    }
                    *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
                  }
                  goto switchD_00126a08_caseD_1;
                case 2:
                  goto switchD_00126c34_caseD_2;
                case 3:
                  goto switchD_00126c34_caseD_3;
                }
              }
              else if (iVar10 == 0x32) {
                switch(piVar12[2]) {
                case 0:
switchD_00126a08_caseD_0:
                  lVar14 = FUN_00122ff4(param_1,0x35,piVar12,0);
                  goto LAB_001266cc;
                case 1:
                  goto switchD_00126a08_caseD_1;
                case 2:
                  pcVar24 = (char *)0x0;
switchD_00126c34_caseD_2:
                  if (((**(char ***)(piVar12 + 2))[1] == 'c') &&
                     ((cVar8 = ***(char ***)(piVar12 + 2), (byte)(cVar8 + 0x8eU) < 2 ||
                      ((byte)(cVar8 + 0x9dU) < 2)))) {
                    uVar13 = FUN_00125bf8(param_1);
                  }
                  else {
                    uVar13 = FUN_00128910(param_1);
                  }
                  iVar10 = strcmp(pcVar24,"cl");
                  if (iVar10 == 0) {
                    uVar17 = FUN_001254a4(param_1,0x45);
                  }
                  else {
                    iVar10 = strcmp(pcVar24,"dt");
                    if ((iVar10 == 0) || (iVar10 = strcmp(pcVar24,"pt"), iVar10 == 0)) {
                      uVar17 = FUN_001275a4(param_1);
                      if (**(char **)(param_1 + 0x18) == 'I') {
                        uVar18 = FUN_00123fb8(param_1);
                        uVar17 = FUN_00122ff4(param_1,4,uVar17,uVar18);
                      }
                    }
                    else {
                      uVar17 = FUN_00128910(param_1);
                    }
                  }
                  uVar13 = FUN_00122ff4(param_1,0x38,uVar13,uVar17);
                  lVar14 = FUN_00122ff4(param_1,0x37,piVar12,uVar13);
                  goto LAB_001266cc;
                case 3:
                  pcVar24 = (char *)0x0;
switchD_00126c34_caseD_3:
                  iVar10 = strcmp(pcVar24,"qu");
                  if (iVar10 == 0) {
                    uVar13 = FUN_00128910(param_1);
                    uVar17 = FUN_00128910(param_1);
                    uVar18 = FUN_00128910(param_1);
LAB_00126ab0:
                    uVar17 = FUN_00122ff4(param_1,0x3b,uVar17,uVar18);
                    uVar13 = FUN_00122ff4(param_1,0x3a,uVar13,uVar17);
                    lVar14 = FUN_00122ff4(param_1,0x39,piVar12,uVar13);
                    goto LAB_001266cc;
                  }
                  if ((*pcVar24 == 'n') && ((pcVar24[1] == 'a' || (pcVar24[1] == 'w')))) {
                    uVar13 = FUN_001254a4(param_1,0x5f);
                    uVar17 = FUN_00125bf8(param_1);
                    pcVar24 = *(char **)(param_1 + 0x18);
                    cVar8 = *pcVar24;
                    if (cVar8 == 'E') {
                      uVar18 = 0;
                      *(char **)(param_1 + 0x18) = pcVar24 + 1;
                      goto LAB_00126ab0;
                    }
                    if (cVar8 == 'p') {
                      if (pcVar24[1] == 'i') {
                        *(char **)(param_1 + 0x18) = pcVar24 + 2;
                        uVar18 = FUN_001254a4(param_1,0x45);
                        goto LAB_00126ab0;
                      }
                    }
                    else if ((cVar8 == 'i') && (pcVar24[1] == 'l')) {
                      uVar18 = FUN_00128910(param_1);
                      goto LAB_00126ab0;
                    }
                  }
                }
              }
              else if (iVar10 == 0x33) {
                if (**(char **)(param_1 + 0x18) == '_') {
                  *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
                  uVar13 = FUN_001254a4(param_1,0x45);
                  goto LAB_001266b8;
                }
switchD_00126a08_caseD_1:
                uVar13 = FUN_00128910(param_1);
                goto LAB_001266b8;
              }
            }
          }
switchD_00126a08_caseD_4:
          *(undefined4 *)(param_1 + 0x54) = uVar2;
          goto LAB_00125e1c;
        }
        if (pbVar22[2] != 0x70) goto LAB_00126670;
        *(byte **)(param_1 + 0x18) = pbVar22 + 3;
        if (pbVar22[3] == 0x54) {
          iVar10 = 0;
          *(byte **)(param_1 + 0x18) = pbVar22 + 4;
        }
        else {
          iVar10 = FUN_00123cb0(param_1);
          iVar10 = iVar10 + 1;
          if (iVar10 == 0) goto switchD_00126a08_caseD_4;
        }
        iVar6 = *(int *)(param_1 + 0x28);
        if (*(int *)(param_1 + 0x2c) <= iVar6) goto switchD_00126a08_caseD_4;
        *(int *)(param_1 + 0x28) = iVar6 + 1;
        lVar14 = *(long *)(param_1 + 0x20) + (long)iVar6 * 0x18;
        if (lVar14 == 0) goto switchD_00126a08_caseD_4;
        *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar6 * 0x18) = 6;
        *(long *)(lVar14 + 8) = (long)iVar10;
        *(undefined4 *)(param_1 + 0x54) = uVar2;
        pbVar21 = *(byte **)(param_1 + 0x18);
      }
LAB_00125e0c:
      if (*pbVar21 != 0x5f) goto LAB_00125e1c;
    }
    *(byte **)(param_1 + 0x18) = pbVar21 + 1;
    uVar13 = FUN_00125bf8(param_1);
    local_8 = (int *)FUN_00122ff4(param_1,0x2a,lVar14,uVar13);
    break;
  case 0x43:
    *(byte **)(param_1 + 0x18) = pbVar22 + 1;
    uVar13 = FUN_00125bf8(param_1);
    local_8 = (int *)FUN_00122ff4(param_1,0x25,uVar13,0);
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
        UNRECOVERED_JUMPTABLE_00 = (code *)SoftwareBreakpoint(1000,0x126730);
        piVar12 = (int *)(*UNRECOVERED_JUMPTABLE_00)();
        return piVar12;
      }
      *(int *)(param_1 + 0x28) = iVar10 + 1;
      local_8 = (int *)(*(long *)(param_1 + 0x20) + (long)iVar10 * 0x18);
      *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar10 * 0x18) = 0x2c;
      bVar1 = (byte)(pbVar22[2] - 0x30) < 10;
      *(ushort *)(local_8 + 4) = (ushort)bVar1;
      if (bVar1) {
        FUN_001236a8(param_1 + 0x18);
      }
      piVar12 = local_8;
      uVar13 = FUN_00125bf8(param_1);
      *(undefined8 *)(piVar12 + 2) = uVar13;
      if (*(long *)(local_8 + 2) == 0) {
        return (int *)0x0;
      }
      FUN_001236a8(param_1 + 0x18);
      pcVar24 = *(char **)(param_1 + 0x18);
      uVar19 = 0;
      if (*pcVar24 != '\0') {
        *(char **)(param_1 + 0x18) = pcVar24 + 1;
        uVar19 = (ushort)(*pcVar24 == 's');
      }
      *(ushort *)((long)local_8 + 0x12) = uVar19;
      return local_8;
    default:
      goto switchD_00125c74_caseD_3a;
    case 0x54:
    case 0x74:
      uVar2 = *(undefined4 *)(param_1 + 0x54);
      *(undefined4 *)(param_1 + 0x54) = 1;
      bVar7 = pbVar22[2];
      if (bVar7 == 0x4c) {
        lVar14 = FUN_00128798(param_1);
      }
      else if (bVar7 == 0x54) {
        lVar14 = FUN_00123de0(param_1);
      }
      else if (bVar7 == 0x73) {
        if (pbVar22[3] == 0x72) {
          *(byte **)(param_1 + 0x18) = pbVar22 + 4;
          uVar13 = FUN_00125bf8(param_1);
          uVar17 = FUN_001275a4(param_1);
          if (**(char **)(param_1 + 0x18) == 'I') {
            uVar18 = FUN_00123fb8(param_1);
            uVar17 = FUN_00122ff4(param_1,4,uVar17,uVar18);
            lVar14 = FUN_00122ff4(param_1,1,uVar13,uVar17);
          }
          else {
            lVar14 = FUN_00122ff4(param_1,1,uVar13,uVar17);
          }
        }
        else {
          if (pbVar22[3] != 0x70) goto LAB_00126454;
          *(byte **)(param_1 + 0x18) = pbVar22 + 4;
          uVar13 = FUN_00128910(param_1);
          lVar14 = FUN_00122ff4(param_1,0x4a,uVar13,0);
        }
      }
      else if (bVar7 == 0x66) {
        if (pbVar22[3] != 0x70) goto LAB_00126454;
        *(byte **)(param_1 + 0x18) = pbVar22 + 4;
        if (pbVar22[4] == 0x54) {
          iVar10 = 0;
          *(byte **)(param_1 + 0x18) = pbVar22 + 5;
        }
        else {
          iVar10 = FUN_00123cb0(param_1);
          iVar10 = iVar10 + 1;
          if (iVar10 == 0) goto LAB_00126cc4;
        }
        iVar6 = *(int *)(param_1 + 0x28);
        if (*(int *)(param_1 + 0x2c) <= iVar6) goto LAB_00126cc4;
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
LAB_0012685c:
          lVar14 = FUN_001275a4(param_1);
          if (lVar14 != 0) {
            if (**(char **)(param_1 + 0x18) == 'I') {
              uVar13 = FUN_00123fb8(param_1);
              lVar14 = FUN_00122ff4(param_1,4,lVar14,uVar13);
            }
            goto switchD_00126ec8_caseD_4;
          }
        }
        else {
          if (bVar7 == 0x6f) {
            if (pbVar22[3] == 0x6e) {
              *(byte **)(param_1 + 0x18) = pbVar22 + 4;
              goto LAB_0012685c;
            }
          }
          else if (((bVar7 == 0x74) || (bVar7 == 0x69)) && (pbVar22[3] == 0x6c)) {
            uVar13 = 0;
            if (bVar7 == 0x74) {
              uVar13 = FUN_00125bf8(param_1);
            }
            *(long *)(param_1 + 0x18) = *(long *)(param_1 + 0x18) + 2;
            uVar17 = FUN_001254a4(param_1,0x45);
            lVar14 = FUN_00122ff4(param_1,0x30,uVar13,uVar17);
            goto switchD_00126ec8_caseD_4;
          }
LAB_00126454:
          piVar12 = (int *)FUN_001273b0(param_1);
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
                  goto switchD_00126ec8_caseD_0;
                case 1:
                  goto switchD_00126cb0_caseD_1;
                case 2:
                  goto switchD_00126cb0_caseD_2;
                case 3:
                  goto switchD_00126cb0_caseD_3;
                default:
                  goto switchD_00126ec8_caseD_4;
                }
              }
              uVar13 = FUN_00125bf8(param_1);
            }
            else {
              if (iVar10 == 0x32) {
                lVar14 = 0;
                switch(piVar12[2]) {
                case 0:
switchD_00126ec8_caseD_0:
                  lVar14 = FUN_00122ff4(param_1,0x35,piVar12,0);
                  break;
                case 1:
                  goto switchD_00126ec8_caseD_1;
                case 2:
                  pcVar24 = (char *)0x0;
switchD_00126cb0_caseD_2:
                  if ((**(char ***)(piVar12 + 2))[1] == 'c') {
                    cVar8 = ***(char ***)(piVar12 + 2);
                    bVar7 = cVar8 + 0x8e;
                    if ((1 < bVar7) && (1 < (byte)(cVar8 + 0x9dU))) goto LAB_00126ef8;
                    uVar13 = FUN_00125bf8(param_1,bVar7,0);
                  }
                  else {
LAB_00126ef8:
                    uVar13 = FUN_00128910(param_1);
                  }
                  iVar10 = strcmp(pcVar24,"cl");
                  if (iVar10 == 0) {
                    uVar17 = FUN_001254a4(param_1,0x45);
                  }
                  else {
                    iVar10 = strcmp(pcVar24,"dt");
                    if ((iVar10 == 0) || (iVar10 = strcmp(pcVar24,"pt"), iVar10 == 0)) {
                      uVar17 = FUN_001275a4(param_1);
                      if (**(char **)(param_1 + 0x18) == 'I') {
                        uVar18 = FUN_00123fb8(param_1);
                        uVar17 = FUN_00122ff4(param_1,4,uVar17,uVar18);
                      }
                    }
                    else {
                      uVar17 = FUN_00128910(param_1);
                    }
                  }
                  uVar13 = FUN_00122ff4(param_1,0x38,uVar13,uVar17);
                  lVar14 = FUN_00122ff4(param_1,0x37,piVar12,uVar13);
                  break;
                case 3:
                  pcVar24 = (char *)0x0;
switchD_00126cb0_caseD_3:
                  iVar10 = strcmp(pcVar24,"qu");
                  if (iVar10 == 0) {
                    uVar13 = FUN_00128910(param_1);
                    uVar17 = FUN_00128910(param_1);
                    uVar18 = FUN_00128910(param_1);
                  }
                  else {
                    if ((*pcVar24 != 'n') || ((pcVar24[1] != 'a' && (pcVar24[1] != 'w'))))
                    goto LAB_00126cc4;
                    uVar13 = FUN_001254a4(param_1,0x5f);
                    uVar17 = FUN_00125bf8(param_1);
                    pcVar24 = *(char **)(param_1 + 0x18);
                    cVar8 = *pcVar24;
                    if (cVar8 != 'E') {
                      if (cVar8 == 'p') {
                        if (pcVar24[1] == 'i') {
                          *(char **)(param_1 + 0x18) = pcVar24 + 2;
                          uVar18 = FUN_001254a4(param_1,0x45);
                          goto LAB_00127068;
                        }
                      }
                      else if ((cVar8 == 'i') && (pcVar24[1] == 'l')) {
                        uVar18 = FUN_00128910(param_1);
                        goto LAB_00127068;
                      }
                      goto LAB_00126cc4;
                    }
                    uVar18 = 0;
                    *(char **)(param_1 + 0x18) = pcVar24 + 1;
                  }
LAB_00127068:
                  uVar17 = FUN_00122ff4(param_1,0x3b,uVar17,uVar18);
                  uVar13 = FUN_00122ff4(param_1,0x3a,uVar13,uVar17);
                  lVar14 = FUN_00122ff4(param_1,0x39,piVar12,uVar13);
                }
                goto switchD_00126ec8_caseD_4;
              }
              if (iVar10 != 0x33) goto LAB_00126cc4;
              if (**(char **)(param_1 + 0x18) == '_') {
                *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
                uVar13 = FUN_001254a4(param_1,0x45);
                goto LAB_0012649c;
              }
switchD_00126ec8_caseD_1:
              uVar13 = FUN_00128910(param_1);
            }
LAB_0012649c:
            lVar14 = FUN_00122ff4(param_1,0x36,piVar12,uVar13);
            goto switchD_00126ec8_caseD_4;
          }
        }
LAB_00126cc4:
        lVar14 = 0;
      }
switchD_00126ec8_caseD_4:
      *(undefined4 *)(param_1 + 0x54) = uVar2;
      local_8 = (int *)FUN_00122ff4(param_1,0x42,lVar14,0);
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
      goto LAB_00125d5c;
    case 0x61:
      piVar12 = (int *)FUN_00123094(param_1,&DAT_00138428,4);
      return piVar12;
    case 100:
      iVar10 = *(int *)(param_1 + 0x28);
      if (iVar10 < *(int *)(param_1 + 0x2c)) {
        *(int *)(param_1 + 0x28) = iVar10 + 1;
        piVar12 = (int *)(*(long *)(param_1 + 0x20) + (long)iVar10 * 0x18);
        if (piVar12 != (int *)0x0) {
          *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar10 * 0x18) = 0x27;
          *(undefined ***)(piVar12 + 2) = &PTR_s_decimal64_00140c20;
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
          *(undefined ***)(piVar12 + 2) = &PTR_s_decimal128_00140c40;
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
          *(undefined ***)(piVar12 + 2) = &PTR_s_decimal32_00140c00;
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
          *(undefined ***)(piVar12 + 2) = &PTR_DAT_00140c60;
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
          *(undefined ***)(piVar12 + 2) = &PTR_s_char32_t_00140ca0;
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
          *(undefined ***)(piVar12 + 2) = &PTR_s_decltype_nullptr__00140cc0;
          *(int *)(param_1 + 0x50) = *(int *)(param_1 + 0x50) + 0x11;
          return piVar12;
        }
      }
      break;
    case 0x70:
      uVar13 = FUN_00125bf8(param_1);
      local_8 = (int *)FUN_00122ff4(param_1,0x4a,uVar13,0);
      goto LAB_00125d58;
    case 0x73:
      iVar10 = *(int *)(param_1 + 0x28);
      if (iVar10 < *(int *)(param_1 + 0x2c)) {
        *(int *)(param_1 + 0x28) = iVar10 + 1;
        piVar12 = (int *)(*(long *)(param_1 + 0x20) + (long)iVar10 * 0x18);
        if (piVar12 != (int *)0x0) {
          *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar10 * 0x18) = 0x27;
          *(undefined ***)(piVar12 + 2) = &PTR_s_char16_t_00140c80;
          *(int *)(param_1 + 0x50) = *(int *)(param_1 + 0x50) + 8;
          return piVar12;
        }
      }
      break;
    case 0x76:
      local_8 = (int *)FUN_001290a8(param_1);
      goto LAB_00125d58;
    }
LAB_0012659c:
    local_8 = (int *)0x0;
                    // WARNING: Treating indirect jump as call
    UNRECOVERED_JUMPTABLE_00 = (code *)SoftwareBreakpoint(1000,0x1265ac);
    piVar12 = (int *)(*UNRECOVERED_JUMPTABLE_00)(uRam0000000000000008);
    return piVar12;
  case 0x46:
    local_8 = (int *)FUN_00128f78(param_1);
    break;
  case 0x47:
    *(byte **)(param_1 + 0x18) = pbVar22 + 1;
    uVar13 = FUN_00125bf8(param_1);
    local_8 = (int *)FUN_00122ff4(param_1,0x26,uVar13,0);
    break;
  case 0x4d:
    *(byte **)(param_1 + 0x18) = pbVar22 + 1;
    lVar14 = FUN_00125bf8(param_1);
    if ((lVar14 == 0) || (lVar15 = FUN_00125bf8(param_1), lVar15 == 0)) {
LAB_00125e1c:
      local_8 = (int *)0x0;
    }
    else {
      local_8 = (int *)FUN_00122ff4(param_1,0x2b,lVar14,lVar15);
    }
    break;
  case 0x4f:
    *(byte **)(param_1 + 0x18) = pbVar22 + 1;
    uVar13 = FUN_00125bf8(param_1);
    local_8 = (int *)FUN_00122ff4(param_1,0x24,uVar13,0);
    break;
  case 0x50:
    *(byte **)(param_1 + 0x18) = pbVar22 + 1;
    uVar13 = FUN_00125bf8(param_1);
    local_8 = (int *)FUN_00122ff4(param_1,0x22,uVar13,0);
    break;
  case 0x52:
    *(byte **)(param_1 + 0x18) = pbVar22 + 1;
    uVar13 = FUN_00125bf8(param_1);
    local_8 = (int *)FUN_00122ff4(param_1,0x23,uVar13,0);
    break;
  case 0x53:
    bVar7 = pbVar22[1];
    if (((9 < (byte)(bVar7 - 0x30)) && (bVar7 != 0x5f)) && (0x19 < (byte)(bVar7 + 0xbf))) {
      local_8 = (int *)FUN_00127b28(param_1);
      if (local_8 == (int *)0x0) {
        return (int *)0x0;
      }
      if (*local_8 == 0x18) {
        return local_8;
      }
      goto LAB_00125d5c;
    }
    local_8 = (int *)FUN_001232a4(param_1,0);
    if (**(char **)(param_1 + 0x18) != 'I') {
      return local_8;
    }
LAB_00126004:
    piVar12 = local_8;
    uVar13 = FUN_00123fb8(param_1);
    local_8 = (int *)FUN_00122ff4(param_1,4,piVar12,uVar13);
    break;
  case 0x54:
    local_8 = (int *)FUN_00123de0(param_1);
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
        goto LAB_00126004;
      }
      uVar2 = *(undefined4 *)(param_1 + 0x28);
      uVar3 = *(undefined4 *)(param_1 + 0x38);
      uVar4 = *(undefined4 *)(param_1 + 0x40);
      uVar5 = *(undefined4 *)(param_1 + 0x50);
      uVar13 = FUN_00123fb8(param_1);
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
        local_8 = (int *)FUN_00122ff4(param_1,4,local_8,uVar13);
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
    local_8 = (int *)FUN_00123c08(param_1);
    uVar13 = FUN_00125bf8(param_1);
    local_8 = (int *)FUN_00122ff4(param_1,0x21,uVar13,local_8);
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
        *(ulong *)(piVar12 + 2) = (long)&PTR_s_signed_char_001408c0 + uVar16;
        iVar10 = *(int *)(&DAT_001408c8 + uVar16);
        *(byte **)(param_1 + 0x18) = pbVar22 + 1;
        *(int *)(param_1 + 0x50) = *(int *)(param_1 + 0x50) + iVar10;
        return piVar12;
      }
    }
    goto LAB_0012659c;
  case 0x75:
    *(byte **)(param_1 + 0x18) = pbVar22 + 1;
    uVar13 = FUN_00123c08(param_1);
    local_8 = (int *)FUN_00122ff4(param_1,0x28,uVar13,0);
  }
LAB_00125d58:
  if (local_8 != (int *)0x0) {
LAB_00125d5c:
    iVar10 = *(int *)(param_1 + 0x38);
    if (iVar10 < *(int *)(param_1 + 0x3c)) {
      *(int **)(*(long *)(param_1 + 0x30) + (long)iVar10 * 8) = local_8;
      *(int *)(param_1 + 0x38) = iVar10 + 1;
      return local_8;
    }
  }
switchD_00125c74_caseD_3a:
  return (int *)0x0;
switchD_00126cb0_caseD_1:
  cVar8 = *pcVar24;
  if (((cVar8 == 'm') || (cVar8 == 'p')) && (pcVar24[1] == cVar8)) {
    cVar8 = **(char **)(param_1 + 0x18);
    if (cVar8 != '_') {
      uVar13 = FUN_00128910(param_1,cVar8,0);
      uVar13 = FUN_00122ff4(param_1,0x38,uVar13,uVar13);
      goto LAB_0012649c;
    }
    *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
  }
  goto switchD_00126ec8_caseD_1;
}



long FUN_001272a0(long param_1)

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
      lVar2 = FUN_00125bf8(param_1);
      if (lVar2 == 0) {
        return 0;
      }
      lVar2 = FUN_00122ff4(param_1,0x2e,lVar2,0);
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



long FUN_001273b0(long param_1)

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
          lVar7 = FUN_00123c08();
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
        uVar6 = FUN_00125bf8();
        if (*(int *)(param_1 + 0x58) == 0) {
          lVar7 = FUN_00122ff4(param_1,0x33,uVar6,0);
          *(undefined4 *)(param_1 + 0x58) = uVar3;
        }
        else {
          lVar7 = FUN_00122ff4(param_1,0x34,uVar6,0);
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
    bVar4 = *(&PTR_DAT_00140e68)[(long)iVar1 * 3];
    if (bVar11 == bVar4) {
      bVar4 = (&PTR_DAT_00140e68)[(long)iVar1 * 3][1];
      if (bVar12 == bVar4) {
        iVar9 = *(int *)(param_1 + 0x28);
        if (*(int *)(param_1 + 0x2c) <= iVar9) {
          return 0;
        }
        *(int *)(param_1 + 0x28) = iVar9 + 1;
        lVar7 = *(long *)(param_1 + 0x20) + (long)iVar9 * 0x18;
        if (lVar7 != 0) {
          *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar9 * 0x18) = 0x31;
          *(undefined ***)(lVar7 + 8) = &PTR_DAT_00140e68 + (long)iVar1 * 3;
          return lVar7;
        }
        return 0;
      }
      if (bVar4 <= bVar12) goto LAB_00127448;
    }
    else if (bVar4 <= bVar11) {
LAB_00127448:
      iVar9 = iVar1 + 1;
      iVar1 = iVar10;
    }
    iVar10 = iVar1;
    if (iVar9 == iVar10) {
      return 0;
    }
  } while( true );
}



int * FUN_001275a4(long param_1)

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
    local_8 = (int *)FUN_00123c08();
    pcVar7 = *(char **)(param_1 + 0x18);
    cVar10 = *pcVar7;
    goto joined_r0x001276fc;
  }
  if ((byte)(cVar10 + 0x9fU) < 0x1a) {
    local_8 = (int *)FUN_001273b0();
    if ((local_8 != (int *)0x0) && (*local_8 == 0x31)) {
      pcVar8 = **(char ***)(local_8 + 2);
      *(int *)(param_1 + 0x50) =
           *(int *)(param_1 + 0x50) + *(int *)(*(char ***)(local_8 + 2) + 2) + 7;
      iVar3 = strcmp(pcVar8,"li");
      if (iVar3 == 0) {
        uVar4 = FUN_00123c08(param_1);
        local_8 = (int *)FUN_00122ff4(param_1,0x36,local_8,uVar4);
      }
    }
    pcVar7 = *(char **)(param_1 + 0x18);
    cVar10 = *pcVar7;
    goto joined_r0x001276fc;
  }
  if (1 < (byte)(cVar10 + 0xbdU)) {
    if (cVar10 == 'L') {
      *(char **)(param_1 + 0x18) = pcVar8 + 1;
      local_8 = (int *)FUN_00123c08();
      if (local_8 == (int *)0x0) {
        return (int *)0x0;
      }
      iVar3 = FUN_00123d3c(param_1);
      if (iVar3 == 0) {
        return (int *)0x0;
      }
      cVar10 = **(char **)(param_1 + 0x18);
      pcVar7 = *(char **)(param_1 + 0x18);
      goto joined_r0x001276fc;
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
        lVar6 = FUN_001272a0();
        pcVar7 = *(char **)(param_1 + 0x18);
        if (lVar6 == 0) goto LAB_00127930;
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
            iVar3 = FUN_001236a8(param_1 + 0x18);
            pcVar7 = *(char **)(param_1 + 0x18);
            cVar10 = *pcVar7;
            if (cVar10 != '_') goto joined_r0x001276fc;
            iVar3 = iVar3 + 1;
            pcVar8 = pcVar7 + 1;
            *(char **)(param_1 + 0x18) = pcVar8;
            if (iVar3 < 0) {
              cVar10 = pcVar7[1];
              pcVar7 = pcVar8;
              local_8 = (int *)0x0;
              goto joined_r0x001276fc;
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
              if (iVar3 < *(int *)(param_1 + 0x3c)) goto LAB_00127884;
            }
          }
          cVar10 = *pcVar8;
          local_8 = (int *)0x0;
          pcVar7 = pcVar8;
          goto joined_r0x001276fc;
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
        lVar6 = FUN_00123cb0();
        if ((-1 < lVar6) && (iVar3 = *(int *)(param_1 + 0x28), iVar3 < *(int *)(param_1 + 0x2c))) {
          *(int *)(param_1 + 0x28) = iVar3 + 1;
          local_8 = (int *)(*(long *)(param_1 + 0x20) + (long)iVar3 * 0x18);
          if (local_8 != (int *)0x0) {
            *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar3 * 0x18) = 0x47;
            *(long *)(local_8 + 2) = lVar6;
            iVar3 = *(int *)(param_1 + 0x38);
            if (iVar3 < *(int *)(param_1 + 0x3c)) {
LAB_00127884:
              *(int **)(*(long *)(param_1 + 0x30) + (long)iVar3 * 8) = local_8;
              *(int *)(param_1 + 0x38) = iVar3 + 1;
              cVar10 = **(char **)(param_1 + 0x18);
              pcVar7 = *(char **)(param_1 + 0x18);
              goto joined_r0x001276fc;
            }
          }
        }
        pcVar7 = *(char **)(param_1 + 0x18);
LAB_00127930:
        cVar10 = *pcVar7;
        local_8 = (int *)0x0;
        goto joined_r0x001276fc;
      }
    }
    local_8 = (int *)0x0;
    goto joined_r0x001276fc;
  }
  piVar5 = *(int **)(param_1 + 0x48);
  if ((piVar5 == (int *)0x0) || ((*piVar5 != 0 && (*piVar5 != 0x18)))) {
    if (cVar10 == 'C') goto LAB_00127a74;
    if (cVar10 != 'D') {
      return (int *)0x0;
    }
LAB_00127960:
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
switchD_00127984_caseD_33:
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
        goto joined_r0x001276fc;
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
        goto joined_r0x001276fc;
      }
      goto LAB_00127960;
    }
LAB_00127a74:
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
      goto switchD_00127984_caseD_33;
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
        goto joined_r0x001276fc;
      }
    }
  }
  pcVar7 = pcVar8 + 2;
  cVar10 = *pcVar7;
  local_8 = (int *)0x0;
joined_r0x001276fc:
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
      if ((byte)(bVar2 - 0x30) < 10) goto LAB_0012765c;
LAB_0012772c:
      uVar4 = 0;
    }
    else {
      if (9 < (byte)(bVar2 - 0x30)) goto LAB_0012772c;
LAB_0012765c:
      pbVar11 = *(byte **)(param_1 + 0x18);
      lVar6 = 0;
      do {
        pbVar11 = pbVar11 + 1;
        uVar9 = (ulong)bVar2;
        *(byte **)(param_1 + 0x18) = pbVar11;
        bVar2 = *pbVar11;
        lVar6 = lVar6 * 10 + uVar9 + -0x30;
      } while ((byte)(bVar2 - 0x30) < 10);
      if ((lVar6 < 1) || (bVar12)) goto LAB_0012772c;
      uVar4 = FUN_001239e8(param_1);
      *(undefined8 *)(param_1 + 0x48) = uVar4;
    }
    local_8 = (int *)FUN_00122ff4(param_1,0x4b,local_8,uVar4);
    pcVar7 = *(char **)(param_1 + 0x18);
    if (*pcVar7 != 'B') {
      return local_8;
    }
  } while( true );
}



long FUN_00127b28(long param_1)

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
    plVar5 = (long *)FUN_001230f4(param_1,&local_8,1);
    if (plVar5 == (long *)0x0) {
      return 0;
    }
    pcVar4 = *(char **)(param_1 + 0x18);
    cVar13 = *pcVar4;
    if (cVar13 == 'O') {
      if (cVar13 == 'R') goto LAB_00127f84;
      uVar8 = 0x20;
      iVar1 = *(int *)(param_1 + 0x50) + 3;
    }
    else {
      lVar3 = 0;
      if (cVar13 != 'R') {
        lVar14 = 0;
        goto LAB_00127ca4;
      }
LAB_00127f84:
      uVar8 = 0x1f;
      iVar1 = *(int *)(param_1 + 0x50) + 2;
    }
    *(int *)(param_1 + 0x50) = iVar1;
    *(char **)(param_1 + 0x18) = pcVar4 + 1;
    lVar14 = 0;
    lVar3 = FUN_00122ff4(param_1,uVar8,0,0);
    pcVar4 = *(char **)(param_1 + 0x18);
    cVar13 = *pcVar4;
LAB_00127ca4:
    do {
      if (cVar13 == '\0') {
LAB_00127f2c:
        *plVar5 = 0;
        return 0;
      }
      pcVar9 = pcVar4;
      if (cVar13 == 'D') {
        if ((pcVar4[1] & 0xdfU) != 0x54) {
          lVar10 = FUN_001275a4(param_1);
          goto LAB_00127f14;
        }
        lVar10 = FUN_00125bf8();
        goto LAB_00127f14;
      }
      do {
        if ((((byte)(cVar13 - 0x30U) < 10) || ((byte)(cVar13 + 0x9fU) < 0x1a)) ||
           ((cVar13 == 'C' || cVar13 == 'U' || (cVar13 == 'L')))) {
          lVar10 = FUN_001275a4(param_1);
          if (lVar14 != 0) goto LAB_00127e90;
LAB_00127ea4:
          if (cVar13 == 'S') goto LAB_00127ee0;
        }
        else {
          if (cVar13 == 'S') {
            lVar10 = FUN_001232a4(param_1,1);
            if (lVar14 != 0) {
LAB_00127e90:
              uVar8 = 1;
LAB_00127e94:
              lVar10 = FUN_00122ff4(param_1,uVar8,lVar14,lVar10);
              goto LAB_00127ea4;
            }
            pcVar4 = *(char **)(param_1 + 0x18);
            cVar13 = *pcVar4;
            lVar14 = lVar10;
            goto LAB_00127ca4;
          }
          if (cVar13 == 'I') {
            if (lVar14 != 0) {
              lVar10 = FUN_00123fb8(param_1);
              uVar8 = 4;
              goto LAB_00127e94;
            }
            goto LAB_00127f2c;
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
            if ((cVar13 != 'M') || (lVar14 == 0)) goto LAB_00127f2c;
            pcVar4 = pcVar9 + 1;
            *(char **)(param_1 + 0x18) = pcVar4;
            cVar13 = pcVar9[1];
            goto LAB_00127ca4;
          }
          lVar10 = FUN_00123de0(param_1);
LAB_00127f14:
          if (lVar14 != 0) goto LAB_00127e90;
        }
        pcVar9 = *(char **)(param_1 + 0x18);
        cVar13 = *pcVar9;
        lVar14 = lVar10;
      } while (cVar13 == 'E');
      if ((lVar10 == 0) || (iVar1 = *(int *)(param_1 + 0x38), *(int *)(param_1 + 0x3c) <= iVar1))
      goto LAB_00127f2c;
      *(long *)(*(long *)(param_1 + 0x30) + (long)iVar1 * 8) = lVar10;
      *(int *)(param_1 + 0x38) = iVar1 + 1;
LAB_00127ee0:
      pcVar4 = *(char **)(param_1 + 0x18);
      cVar13 = *pcVar4;
      lVar14 = lVar10;
    } while( true );
  default:
    lVar3 = FUN_001275a4(param_1);
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
      uVar8 = FUN_00123fb8(param_1);
      lVar3 = FUN_00122ff4(param_1,4,lVar3,uVar8);
    }
    break;
  case 0x53:
    if (puVar12[1] == 't') {
      *(undefined **)(param_1 + 0x18) = puVar12 + 2;
      uVar8 = FUN_00123094(param_1,&DAT_00138448,3);
      uVar7 = FUN_001275a4(param_1);
      lVar3 = FUN_00122ff4(param_1,1,uVar8,uVar7);
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
      lVar3 = FUN_001232a4(param_1,0);
      if (**(char **)(param_1 + 0x18) != 'I') {
        return lVar3;
      }
    }
    uVar8 = FUN_00123fb8(param_1);
    lVar3 = FUN_00122ff4(param_1,4,lVar3,uVar8);
    break;
  case 0x55:
    lVar3 = FUN_001275a4(param_1);
    return lVar3;
  case 0x5a:
    *(undefined **)(param_1 + 0x18) = puVar12 + 1;
    uVar8 = FUN_001280d4(param_1,0);
    pcVar4 = *(char **)(param_1 + 0x18);
    if (*pcVar4 != 'E') {
      return 0;
    }
    *(char **)(param_1 + 0x18) = pcVar4 + 1;
    if (pcVar4[1] == 's') {
      *(char **)(param_1 + 0x18) = pcVar4 + 2;
      iVar1 = FUN_00123d3c(param_1);
      if (iVar1 == 0) {
        return 0;
      }
      piVar6 = (int *)FUN_00123094(param_1,"string literal",0xe);
    }
    else if (pcVar4[1] == 'd') {
      *(char **)(param_1 + 0x18) = pcVar4 + 2;
      iVar1 = FUN_00123cb0(param_1);
      if (iVar1 < 0) {
        return 0;
      }
      piVar11 = (int *)FUN_00127b28(param_1);
      if ((((piVar11 != (int *)0x0) && (*piVar11 != 0x45)) && (*piVar11 != 0x47)) &&
         (iVar2 = FUN_00123d3c(param_1), iVar2 == 0)) {
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
      piVar6 = (int *)FUN_00127b28(param_1);
      if (((piVar6 != (int *)0x0) && (*piVar6 != 0x45)) &&
         ((*piVar6 != 0x47 && (iVar1 = FUN_00123d3c(param_1), iVar1 == 0)))) {
        return 0;
      }
    }
    lVar3 = FUN_00122ff4(param_1,2,uVar8,piVar6);
    return lVar3;
  }
  return lVar3;
}



uint * FUN_001280d4(long param_1,int param_2)

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
    puVar6 = (uint *)FUN_00127b28();
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
        goto joined_r0x0012821c;
      }
    } while (((3 < uVar5) && (uVar5 - 0x1c < 5)) &&
            (ppuVar1 = (uint **)(puVar12 + 2), puVar12 = *ppuVar1, *ppuVar1 != (uint *)0x0));
LAB_00128170:
    if (cVar2 == 'J') goto LAB_001286c0;
    lVar11 = 0;
    goto LAB_00128260;
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
      lVar11 = FUN_00125bf8(param_1);
      lVar7 = FUN_001236a8(param_1 + 0x18);
      if (lVar7 < 0) {
        return (uint *)0x0;
      }
      if (**(char **)(param_1 + 0x18) != '_') {
        return (uint *)0x0;
      }
      *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
      puVar6 = (uint *)FUN_00125bf8(param_1);
      uVar9 = 0xb;
      *(int *)(param_1 + 0x50) = *(int *)(param_1 + 0x50) + 5;
      break;
    default:
      return (uint *)0x0;
    case 'F':
      puVar6 = (uint *)FUN_00125bf8(param_1);
      uVar9 = 0xe;
      lVar11 = 0;
      break;
    case 'H':
      puVar6 = (uint *)FUN_00127b28(param_1);
      uVar9 = 0x14;
      lVar11 = 0;
      break;
    case 'I':
      puVar6 = (uint *)FUN_00125bf8(param_1);
      uVar9 = 0xc;
      lVar11 = 0;
      break;
    case 'J':
      puVar6 = (uint *)FUN_00125bf8(param_1);
      uVar9 = 0x12;
      lVar11 = 0;
      break;
    case 'S':
      puVar6 = (uint *)FUN_00125bf8(param_1);
      uVar9 = 0xd;
      lVar11 = 0;
      break;
    case 'T':
      *(int *)(param_1 + 0x50) = iVar4 + 10;
      puVar6 = (uint *)FUN_00125bf8(param_1);
      uVar9 = 10;
      lVar11 = 0;
      break;
    case 'V':
      *(int *)(param_1 + 0x50) = iVar4 + 0xf;
      puVar6 = (uint *)FUN_00125bf8(param_1);
      uVar9 = 9;
      lVar11 = 0;
      break;
    case 'W':
      puVar6 = (uint *)FUN_00127b28(param_1);
      uVar9 = 0x15;
      lVar11 = 0;
      break;
    case 'c':
      iVar4 = FUN_00123ecc(param_1,0);
      if (iVar4 == 0) {
        return (uint *)0x0;
      }
      iVar4 = FUN_00123ecc(param_1,0);
      if (iVar4 == 0) {
        return (uint *)0x0;
      }
      puVar6 = (uint *)FUN_001280d4(param_1,0);
      uVar9 = 0x11;
      lVar11 = 0;
      break;
    case 'h':
      iVar4 = FUN_00123ecc(param_1,0x68);
      if (iVar4 == 0) {
        return (uint *)0x0;
      }
      puVar6 = (uint *)FUN_001280d4(param_1,0);
      uVar9 = 0xf;
      lVar11 = 0;
      break;
    case 'v':
      iVar4 = FUN_00123ecc(param_1,0x76);
      if (iVar4 == 0) {
        return (uint *)0x0;
      }
      puVar6 = (uint *)FUN_001280d4(param_1,0);
      uVar9 = 0x10;
      lVar11 = 0;
    }
    goto LAB_00128294;
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
    puVar6 = (uint *)FUN_001280d4(param_1,0);
    uVar9 = 0x17;
    lVar11 = 0;
    break;
  default:
    return (uint *)0x0;
  case 'R':
    puVar6 = (uint *)FUN_00127b28(param_1);
    iVar4 = *(int *)(param_1 + 0x28);
    if (iVar4 < *(int *)(param_1 + 0x2c)) {
      *(int *)(param_1 + 0x28) = iVar4 + 1;
      lVar11 = *(long *)(param_1 + 0x20) + (long)iVar4 * 0x18;
      if (lVar11 == 0) goto LAB_0012877c;
      *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar4 * 0x18) = 0x41;
      uVar9 = FUN_001236a8(param_1 + 0x18);
      *(undefined8 *)(lVar11 + 8) = uVar9;
    }
    else {
LAB_0012877c:
      lVar11 = 0;
    }
    uVar9 = 0x16;
    break;
  case 'T':
    if ((pcVar10[2] == '\0') || (*(char **)(param_1 + 0x18) = pcVar10 + 3, pcVar10[2] != 'n')) {
      puVar6 = (uint *)FUN_001280d4(param_1,0);
      uVar9 = 0x48;
      lVar11 = 0;
    }
    else {
      puVar6 = (uint *)FUN_001280d4(param_1,0);
      uVar9 = 0x49;
      lVar11 = 0;
    }
    break;
  case 'V':
    puVar6 = (uint *)FUN_00127b28(param_1);
    uVar9 = 0x13;
    lVar11 = 0;
    break;
  case 'r':
    lVar11 = FUN_001236a8(param_1 + 0x18);
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
LAB_00128784:
          *(long *)(param_1 + 0x18) = *(long *)(param_1 + 0x18) + 2;
          return (uint *)0x0;
        }
        *(int *)(param_1 + 0x28) = iVar4 + 1;
        puVar6 = (uint *)(*(long *)(param_1 + 0x20) + (long)iVar4 * 0x18);
        if (puVar6 == (uint *)0x0) goto LAB_00128784;
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
        puVar6 = (uint *)FUN_00123094(param_1,pcVar14,uVar13 & 0xffffffff);
        pcVar14 = (char *)(*(long *)(param_1 + 0x18) + uVar13);
        *(char **)(param_1 + 0x18) = pcVar14;
        if (puVar6 == (uint *)0x0) {
          return (uint *)0x0;
        }
      }
      lVar11 = lVar11 + lVar7;
      if ((puVar12 != (uint *)0x0) &&
         (puVar6 = (uint *)FUN_00122ff4(param_1,0x3f,puVar12), puVar6 == (uint *)0x0)) {
        return (uint *)0x0;
      }
      puVar12 = puVar6;
    } while (0 < lVar11);
    uVar9 = 0x3e;
    lVar11 = 0;
  }
  goto LAB_00128294;
joined_r0x0012821c:
  if (puVar12 == (uint *)0x0) goto LAB_00128248;
  uVar5 = *puVar12;
  if (8 < uVar5) {
    if (uVar5 == 0x34) goto LAB_00128170;
    goto LAB_00128248;
  }
  if (6 < uVar5) goto LAB_00128170;
  if (1 < uVar5 - 1) goto LAB_00128248;
  puVar12 = *(uint **)(puVar12 + 4);
  goto joined_r0x0012821c;
LAB_00128248:
  if (cVar2 == 'J') {
LAB_001286c0:
    *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
  }
  lVar11 = FUN_00125bf8(param_1);
  if (lVar11 == 0) {
LAB_00128774:
    lVar11 = 0;
  }
  else {
LAB_00128260:
    lVar7 = FUN_001272a0(param_1);
    if (lVar7 == 0) goto LAB_00128774;
    lVar11 = FUN_00122ff4(param_1,0x29,lVar11,lVar7);
  }
  uVar9 = 3;
LAB_00128294:
  puVar6 = (uint *)FUN_00122ff4(param_1,uVar9,puVar6,lVar11);
  return puVar6;
}



undefined8 FUN_00128798(long param_1)

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
    if (cVar1 == '_') goto LAB_001288c0;
  }
  else {
    if (cVar1 != '_') {
      piVar2 = (int *)FUN_00125bf8();
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
      uVar3 = FUN_00123094(param_1,pcVar7,iVar6);
      uVar8 = FUN_00122ff4(param_1,uVar8,piVar2,uVar3);
      pcVar5 = *(char **)(param_1 + 0x18);
      cVar4 = *pcVar5;
      goto LAB_00128870;
    }
LAB_001288c0:
    pcVar5 = pcVar7 + 2;
    *(char **)(param_1 + 0x18) = pcVar5;
    cVar4 = pcVar7[2];
  }
  uVar8 = 0;
  if (cVar4 == 'Z') {
    *(char **)(param_1 + 0x18) = pcVar5 + 1;
    uVar8 = FUN_001280d4(param_1,0);
    pcVar5 = *(char **)(param_1 + 0x18);
    cVar4 = *pcVar5;
  }
LAB_00128870:
  if (cVar4 != 'E') {
    return 0;
  }
  *(char **)(param_1 + 0x18) = pcVar5 + 1;
  return uVar8;
}



int * FUN_00128910(long param_1)

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
    piVar3 = (int *)FUN_00128798();
    return piVar3;
  }
  if (cVar1 == 'T') {
    piVar3 = (int *)FUN_00123de0();
    return piVar3;
  }
  if (cVar1 == 's') {
    if (pcVar7[1] == 'r') {
      *(char **)(param_1 + 0x18) = pcVar7 + 2;
      piVar3 = (int *)FUN_00125bf8();
      uVar4 = FUN_001275a4(param_1);
      if (**(char **)(param_1 + 0x18) == 'I') {
        uVar6 = FUN_00123fb8(param_1);
        uVar4 = FUN_00122ff4(param_1,4,uVar4,uVar6);
      }
      uVar6 = 1;
      goto LAB_00128a00;
    }
    if (pcVar7[1] == 'p') {
      *(char **)(param_1 + 0x18) = pcVar7 + 2;
      piVar3 = (int *)FUN_00128910();
      uVar6 = 0x4a;
      uVar4 = 0;
      goto LAB_00128b3c;
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
        iVar2 = FUN_00123cb0();
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
LAB_0012895c:
      piVar3 = (int *)FUN_001275a4(param_1);
      if (piVar3 == (int *)0x0) {
        return (int *)0x0;
      }
      if (**(char **)(param_1 + 0x18) != 'I') {
        return piVar3;
      }
      uVar4 = FUN_00123fb8(param_1);
      uVar6 = 4;
      goto LAB_00128b3c;
    }
    if (cVar1 == 'o') {
      if (pcVar7[1] == 'n') {
        *(char **)(param_1 + 0x18) = pcVar7 + 2;
        goto LAB_0012895c;
      }
    }
    else if (((cVar1 == 't') || (cVar1 == 'i')) && (pcVar7[1] == 'l')) {
      piVar3 = (int *)0x0;
      if (cVar1 == 't') {
        piVar3 = (int *)FUN_00125bf8(param_1);
        pcVar7 = *(char **)(param_1 + 0x18);
      }
      *(char **)(param_1 + 0x18) = pcVar7 + 2;
      uVar4 = FUN_001254a4(param_1,0x45);
      uVar6 = 0x30;
      goto LAB_00128b3c;
    }
  }
  piVar3 = (int *)FUN_001273b0(param_1);
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
        goto switchD_00128ba4_caseD_0;
      case 1:
        goto switchD_00128c28_caseD_1;
      case 2:
        goto switchD_00128c28_caseD_2;
      case 3:
        goto switchD_00128c28_caseD_3;
      default:
        goto switchD_00128ba4_caseD_4;
      }
    }
    uVar4 = FUN_00125bf8(param_1);
  }
  else {
    if (iVar2 == 0x32) {
      switch(piVar3[2]) {
      case 0:
switchD_00128ba4_caseD_0:
        uVar6 = 0x35;
        uVar4 = 0;
LAB_00128b3c:
        piVar3 = (int *)FUN_00122ff4(param_1,uVar6,piVar3,uVar4);
        return piVar3;
      case 1:
        goto switchD_00128ba4_caseD_1;
      case 2:
        pcVar7 = (char *)0x0;
switchD_00128c28_caseD_2:
        if (((**(char ***)(piVar3 + 2))[1] == 'c') &&
           ((cVar1 = ***(char ***)(piVar3 + 2), (byte)(cVar1 + 0x8eU) < 2 ||
            ((byte)(cVar1 + 0x9dU) < 2)))) {
          uVar4 = FUN_00125bf8(param_1);
        }
        else {
          uVar4 = FUN_00128910(param_1);
        }
        iVar2 = strcmp(pcVar7,"cl");
        if (iVar2 == 0) {
          uVar6 = FUN_001254a4(param_1,0x45);
        }
        else {
          iVar2 = strcmp(pcVar7,"dt");
          if ((iVar2 == 0) || (iVar2 = strcmp(pcVar7,"pt"), iVar2 == 0)) {
            uVar6 = FUN_001275a4(param_1);
            if (**(char **)(param_1 + 0x18) == 'I') {
              uVar5 = FUN_00123fb8(param_1);
              uVar6 = FUN_00122ff4(param_1,4,uVar6,uVar5);
            }
          }
          else {
            uVar6 = FUN_00128910(param_1);
          }
        }
        uVar4 = FUN_00122ff4(param_1,0x38,uVar4,uVar6);
        uVar6 = 0x37;
        goto LAB_00128a00;
      case 3:
        pcVar7 = (char *)0x0;
switchD_00128c28_caseD_3:
        iVar2 = strcmp(pcVar7,"qu");
        if (iVar2 == 0) {
          uVar4 = FUN_00128910(param_1);
          uVar6 = FUN_00128910(param_1);
          uVar5 = FUN_00128910(param_1);
        }
        else {
          if (*pcVar7 != 'n') {
            return (int *)0x0;
          }
          if ((pcVar7[1] != 'a') && (pcVar7[1] != 'w')) {
            return (int *)0x0;
          }
          uVar4 = FUN_001254a4(param_1,0x5f);
          uVar6 = FUN_00125bf8(param_1);
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
            uVar5 = FUN_001254a4(param_1,0x45);
          }
          else {
            if ((cVar1 != 'i') || (pcVar7[1] != 'l')) {
switchD_00128ba4_caseD_4:
              return (int *)0x0;
            }
            uVar5 = FUN_00128910(param_1);
          }
        }
        uVar6 = FUN_00122ff4(param_1,0x3b,uVar6,uVar5);
        uVar4 = FUN_00122ff4(param_1,0x3a,uVar4,uVar6);
        uVar6 = 0x39;
        goto LAB_00128a00;
      default:
        goto switchD_00128ba4_caseD_4;
      }
    }
    if (iVar2 != 0x33) {
      return (int *)0x0;
    }
    if (**(char **)(param_1 + 0x18) == '_') {
      *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
      uVar4 = FUN_001254a4(param_1,0x45);
      goto LAB_001289f4;
    }
switchD_00128ba4_caseD_1:
    uVar4 = FUN_00128910(param_1);
  }
LAB_001289f4:
  uVar6 = 0x36;
LAB_00128a00:
  piVar3 = (int *)FUN_00122ff4(param_1,uVar6,piVar3,uVar4);
  return piVar3;
switchD_00128c28_caseD_1:
  cVar1 = *pcVar7;
  if (((cVar1 == 'm') || (cVar1 == 'p')) && (pcVar7[1] == cVar1)) {
    if (**(char **)(param_1 + 0x18) != '_') {
      uVar4 = FUN_00128910(param_1);
      uVar4 = FUN_00122ff4(param_1,0x38,uVar4,uVar4);
      goto LAB_001289f4;
    }
    *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
  }
  goto switchD_00128ba4_caseD_1;
}



undefined8 FUN_00128f78(long param_1)

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
  lVar4 = FUN_00125bf8();
  if ((lVar4 == 0) || (lVar5 = FUN_001272a0(param_1), lVar5 == 0)) {
    uVar6 = 0;
  }
  else {
    uVar6 = FUN_00122ff4(param_1,0x29,lVar4,lVar5);
  }
  pcVar7 = *(char **)(param_1 + 0x18);
  cVar2 = *pcVar7;
  if (cVar2 == 'O') {
    if (cVar2 == 'R') goto LAB_00129090;
    uVar8 = 0x20;
    iVar3 = *(int *)(param_1 + 0x50) + 3;
  }
  else {
    if (cVar2 != 'R') {
      if (cVar2 != 'E') {
        return 0;
      }
      goto LAB_00129018;
    }
LAB_00129090:
    uVar8 = 0x1f;
    iVar3 = *(int *)(param_1 + 0x50) + 2;
  }
  *(int *)(param_1 + 0x50) = iVar3;
  *(char **)(param_1 + 0x18) = pcVar7 + 1;
  uVar6 = FUN_00122ff4(param_1,uVar8,uVar6,0);
  pcVar7 = *(char **)(param_1 + 0x18);
  if (*pcVar7 != 'E') {
    return 0;
  }
LAB_00129018:
  *(char **)(param_1 + 0x18) = pcVar7 + 1;
  return uVar6;
}


/*
Unable to decompile 'FUN_001290a8'
Cause: 
Low-level Error: Could not finish collapsing block structure
*/


// WARNING: Type propagation algorithm not settling

void FUN_0012b7dc(undefined *param_1,uint param_2,long *param_3)

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
  
  if (param_3 == (long *)0x0) goto LAB_0012b858;
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
                    goto LAB_0012ded8;
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
LAB_0012ded8:
        pbVar34 = pbVar35 + 1;
      }
    }
    break;
  case 1:
  case 2:
    FUN_0012b7dc(param_1,param_2,param_3[1]);
    lVar10 = *(long *)(param_1 + 0x100);
    if ((param_2 >> 2 & 1) == 0) {
      if (lVar10 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar18 = 1;
        *param_1 = 0x3a;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
LAB_0012b92c:
        lVar10 = lVar18 + 1;
      }
      else {
        lVar18 = lVar10 + 1;
        *(long *)(param_1 + 0x100) = lVar18;
        param_1[lVar10] = 0x3a;
        param_1[0x108] = 0x3a;
        if (lVar18 != 0xff) goto LAB_0012b92c;
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
      FUN_00123934(param_1,"{default arg#");
      FUN_00123b3c(param_1,(long)(piVar9[4] + 1));
      FUN_00123934(param_1,&DAT_00138460);
      piVar9 = *(int **)(piVar9 + 2);
    }
    FUN_0012b7dc(param_1,param_2,piVar9);
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
            goto LAB_0012ee48;
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
              goto LAB_0012ee48;
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
                goto LAB_0012ee48;
              }
            }
          }
        }
      }
      else {
        uVar39 = 1;
LAB_0012ee48:
        uVar37 = uVar39;
        if (iVar6 == 4) {
          *(long *****)(param_1 + 0x120) = &local_90;
          local_90 = ppplVar26;
          local_88 = plVar21;
LAB_0012ef68:
          FUN_0012b7dc(param_1,param_2,param_3[2]);
          if (*(int *)plVar21 == 4) {
            *(long ****)(param_1 + 0x120) = local_90;
          }
          iVar6 = (int)uVar37;
          uVar36 = iVar6 - 1;
          if (*(int *)(&local_70 + (ulong)uVar36 * 4) == 0) {
            FUN_00123630(param_1,0x20);
            FUN_0012f1e8(param_1,param_2,(&local_78)[(ulong)uVar36 * 4]);
          }
          if (uVar36 != 0) {
            uVar36 = iVar6 - 2;
            if (*(int *)(&local_70 + (ulong)uVar36 * 4) == 0) {
              FUN_00123630(param_1,0x20);
              FUN_0012f1e8(param_1,param_2,(&local_78)[(ulong)uVar36 * 4]);
            }
            if (uVar36 != 0) {
              uVar36 = iVar6 - 3;
              if (*(int *)(&local_70 + (ulong)uVar36 * 4) == 0) {
                FUN_00123630(param_1,0x20);
                FUN_0012f1e8(param_1,param_2,(&local_78)[(ulong)uVar36 * 4]);
              }
              if ((uVar36 != 0) && ((int)local_70 == 0)) {
                FUN_00123630(param_1,0x20);
                FUN_0012f1e8(param_1,param_2,local_78);
                *(undefined8 *)(param_1 + 0x128) = uVar38;
                return;
              }
            }
          }
          *(undefined8 *)(param_1 + 0x128) = uVar38;
          return;
        }
        if (iVar6 != 2) goto LAB_0012ef68;
        plVar25 = (long *)plVar21[2];
        if (*(int *)plVar25 == 0x46) {
          plVar25 = (long *)plVar25[1];
        }
        if (4 < *(int *)plVar25 - 0x1cU) goto LAB_0012ef68;
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
          if (4 < *(int *)plVar25 - 0x1cU) goto LAB_0012ef68;
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
            if (4 < *(int *)plVar25 - 0x1cU) goto LAB_0012ef68;
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
                goto LAB_0012ef68;
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
      FUN_0012b7dc(param_1,param_2,piVar9);
      if (param_1[0x108] == '<') {
        FUN_00123630(param_1,0x20);
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
      FUN_0012b7dc(param_1,param_2,param_3[2]);
      if (param_1[0x108] == '>') {
        FUN_00123630(param_1,0x20);
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
      FUN_0012b7dc(param_1,param_2,param_3[2]);
      FUN_00123934(param_1,&DAT_00138470);
    }
    *(undefined8 *)(param_1 + 0x128) = uVar40;
    *(undefined8 *)(param_1 + 0x160) = uVar38;
    break;
  case 5:
    piVar9 = (int *)FUN_00123730(param_1,param_3 + 1);
    if (piVar9 != (int *)0x0) {
      if (*piVar9 != 0x2f) {
LAB_0012c9f4:
        puVar32 = *(undefined8 **)(param_1 + 0x120);
        *(undefined8 *)(param_1 + 0x120) = *puVar32;
        FUN_0012b7dc(param_1,param_2);
        *(undefined8 **)(param_1 + 0x120) = puVar32;
        return;
      }
      iVar6 = *(int *)(param_1 + 0x134);
      while (0 < iVar6) {
        piVar9 = *(int **)(piVar9 + 4);
        iVar6 = iVar6 + -1;
        if ((piVar9 == (int *)0x0) || (*piVar9 != 0x2f)) goto LAB_0012b858;
      }
      if ((iVar6 == 0) && (*(long *)(piVar9 + 2) != 0)) goto LAB_0012c9f4;
    }
    goto LAB_0012b858;
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
LAB_0012d8d0:
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
LAB_0012d8ec:
          lVar7 = lVar12 + 1;
          *(long *)(param_1 + 0x100) = lVar7;
          param_1[lVar12] = 0x72;
          param_1[0x108] = 0x72;
          if (lVar7 != 0xff) goto LAB_0012d908;
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
          goto LAB_0012d8ec;
        }
        lVar10 = lVar10 + 2;
        *(long *)(param_1 + 0x100) = lVar10;
        param_1[lVar12] = 0x70;
        param_1[0x108] = 0x70;
        if (lVar10 != 0xff) goto LAB_0012d8d0;
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x61;
        lVar7 = 2;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        param_1[1] = 0x72;
LAB_0012d908:
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
          goto LAB_0012d928;
        }
      }
      lVar12 = lVar10 + 1;
LAB_0012d928:
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
LAB_0012c258:
      lVar18 = lVar10 + 1;
      *(long *)(param_1 + 0x100) = lVar18;
      param_1[lVar10] = 0x69;
      param_1[0x108] = 0x69;
      if (lVar18 != 0xff) goto LAB_0012c274;
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
        if (lVar10 != 0xff) goto LAB_0012c258;
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x69;
        lVar18 = 1;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
LAB_0012c274:
      lVar10 = lVar18 + 1;
    }
    *(long *)(param_1 + 0x100) = lVar10;
    param_1[lVar18] = 0x73;
    param_1[0x108] = 0x73;
    break;
  case 7:
    FUN_0012b7dc(param_1,param_2,param_3[2]);
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
    FUN_0012b7dc(param_1,param_2,param_3[2]);
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
    FUN_0012b7dc(param_1,param_2,param_3[1]);
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
    FUN_0012b7dc(param_1,param_2,param_3[1]);
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
    FUN_0012b7dc(param_1,param_2,param_3[1]);
    lVar10 = *(long *)(param_1 + 0x100);
    if (lVar10 == 0xff) {
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar10 = 2;
      *param_1 = 0x2d;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 0x69;
LAB_0012d6a4:
      lVar18 = lVar10 + 1;
      *(long *)(param_1 + 0x100) = lVar18;
      param_1[lVar10] = 0x6e;
      param_1[0x108] = 0x6e;
      if (lVar18 != 0xff) goto LAB_0012d6c0;
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
        if (lVar10 != 0xff) goto LAB_0012d6a4;
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x6e;
        lVar18 = 1;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
LAB_0012d6c0:
      lVar10 = lVar18 + 1;
    }
    *(long *)(param_1 + 0x100) = lVar10;
    param_1[lVar18] = 0x2d;
    param_1[0x108] = 0x2d;
    FUN_0012b7dc(param_1,param_2,param_3[2]);
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
    FUN_0012b7dc(param_1,param_2,param_3[1]);
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
    FUN_0012b7dc(param_1,param_2,param_3[1]);
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
    FUN_0012b7dc(param_1,param_2,param_3[1]);
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
    FUN_0012b7dc(param_1,param_2,param_3[1]);
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
    FUN_0012b7dc(param_1,param_2,param_3[1]);
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
    FUN_0012b7dc(param_1,param_2,param_3[1]);
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
    FUN_0012b7dc(param_1,param_2,param_3[1]);
    break;
  case 0x13:
    FUN_00123934(param_1,"guard variable for ");
    FUN_0012b7dc(param_1,param_2,param_3[1]);
    break;
  case 0x14:
    FUN_00123934(param_1,"TLS init function for ");
    FUN_0012b7dc(param_1,param_2,param_3[1]);
    break;
  case 0x15:
    FUN_00123934(param_1,"TLS wrapper function for ");
    FUN_0012b7dc(param_1,param_2,param_3[1]);
    break;
  case 0x16:
    FUN_00123934(param_1,"reference temporary #");
    FUN_0012b7dc(param_1,param_2,param_3[2]);
    FUN_00123934(param_1," for ");
    FUN_0012b7dc(param_1,param_2,param_3[1]);
    break;
  case 0x17:
    FUN_00123934(param_1,"hidden alias for ");
    FUN_0012b7dc(param_1,param_2,param_3[1]);
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
            FUN_0012b7dc(param_1,param_2,param_3[1]);
            return;
          }
        }
        pplVar27 = (long **)*pplVar27;
      } while (pplVar27 != (long **)0x0);
      bVar5 = false;
    }
    goto LAB_0012c0d8;
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
LAB_0012c0d8:
    local_68[0] = *(long ****)(param_1 + 0x120);
    *(long ****)(param_1 + 0x128) = &local_80;
    local_78 = param_3;
LAB_0012c0f4:
    lVar10 = local_78[1];
LAB_0012c0f8:
    plVar21 = local_78;
    local_70._0_4_ = 0;
    FUN_0012b7dc(param_1,param_2,lVar10);
    if ((int)local_70 == 0) {
      FUN_0012f1e8(param_1,param_2,plVar21);
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
LAB_0012dba0:
        if (*(int *)(param_1 + 0x14c) <= (int)uVar36) {
LAB_0012f0cc:
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
                goto LAB_0012dc24;
              }
              uVar39 = uVar39 + 0x10;
              puVar14 = puVar32;
              iVar31 = iVar15 + 1;
            } while (iVar15 + 1 != iVar6 + 1);
            *(int *)(param_1 + 0x158) = iVar15;
          }
          goto LAB_0012f0cc;
        }
LAB_0012dc24:
        *puVar32 = 0;
        bVar5 = false;
        plVar21 = (long *)FUN_00123730(param_1,plVar21 + 1);
        if (plVar21 == (long *)0x0) goto LAB_0012b858;
LAB_0012dde4:
        iVar6 = *(int *)plVar21;
        if (iVar6 != 0x2f) goto LAB_0012c134;
        iVar6 = *(int *)(param_1 + 0x134);
        while (0 < iVar6) {
          plVar21 = (long *)plVar21[2];
          iVar6 = iVar6 + -1;
          if ((plVar21 == (long *)0x0) || (*(int *)plVar21 != 0x2f)) goto LAB_0012b850;
        }
        if ((iVar6 == 0) && (plVar21 = (long *)plVar21[1], plVar21 != (long *)0x0)) {
          iVar6 = *(int *)plVar21;
          goto LAB_0012c134;
        }
LAB_0012b850:
        if (!bVar5) goto LAB_0012b858;
      }
      else {
        pplVar8 = pplVar27;
        if (plVar21 != *pplVar27) {
          do {
            pplVar8 = pplVar8 + 2;
            if (pplVar8 == pplVar27 + ((ulong)(uVar36 - 1) + 1) * 2) goto LAB_0012dba0;
          } while (plVar21 != *pplVar8);
        }
        unaff_x22 = *(undefined8 *)(param_1 + 0x120);
        *(long **)(param_1 + 0x120) = pplVar8[1];
        bVar5 = true;
        plVar21 = (long *)FUN_00123730(param_1,plVar21 + 1);
        if (plVar21 != (long *)0x0) goto LAB_0012dde4;
      }
      *(undefined8 *)(param_1 + 0x120) = unaff_x22;
LAB_0012b858:
      *(undefined4 *)(param_1 + 0x130) = 1;
      return;
    }
LAB_0012c134:
    if ((iVar6 == 0x23) || (*(int *)param_3 == iVar6)) {
      local_80 = *(long ***)(param_1 + 0x128);
      param_3 = plVar21;
      goto LAB_0012c0d8;
    }
    if (iVar6 != 0x24) {
      local_80 = *(long ***)(param_1 + 0x128);
      goto LAB_0012c0d8;
    }
    lVar10 = plVar21[1];
    local_80 = *(long ***)(param_1 + 0x128);
    local_68[0] = *(long ****)(param_1 + 0x120);
    *(long ****)(param_1 + 0x128) = &local_80;
    local_78 = param_3;
    if (lVar10 == 0) goto LAB_0012c0f4;
    goto LAB_0012c0f8;
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
    FUN_0012b7dc(param_1,param_2,param_3[1]);
    break;
  case 0x29:
    if ((param_2 >> 5 & 1) == 0) {
      if ((param_3[1] != 0) && ((param_2 >> 6 & 1) == 0)) {
        local_80 = *(long ***)(param_1 + 0x128);
        *(long ****)(param_1 + 0x128) = &local_80;
        local_68[0] = *(long ****)(param_1 + 0x120);
        local_70._0_4_ = 0;
        local_78 = param_3;
        FUN_0012b7dc(param_1,param_2 & 0xffffff9f,param_3[1]);
        *(long ***)(param_1 + 0x128) = local_80;
        if ((int)local_70 != 0) {
          return;
        }
        FUN_00123630(param_1,0x20);
      }
      FUN_00130044(param_1,param_2 & 0xffffff9f,param_3 + 2,*(undefined8 *)(param_1 + 0x128));
    }
    else {
      FUN_00130044(param_1,param_2 & 0xffffff9f,param_3 + 2,*(undefined8 *)(param_1 + 0x128));
      if (param_3[1] != 0) {
        FUN_0012b7dc(param_1,param_2 & 0xffffff9f);
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
      FUN_0012b7dc(param_1,param_2,param_3[2]);
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
      FUN_0012b7dc(param_1,param_2,param_3[2]);
      *(long ***)(param_1 + 0x128) = pplVar27;
      if ((int)local_70 != 0) {
        return;
      }
      if ((int)uVar37 != 1) {
        do {
          uVar36 = (int)uVar37 - 1;
          uVar37 = (ulong)uVar36;
          FUN_0012f1e8(param_1,param_2,(&local_78)[uVar37 * 4]);
        } while (uVar36 != 1);
        pplVar27 = *(long ***)(param_1 + 0x128);
      }
    }
    FUN_0012fd7c(param_1,param_2,param_3 + 1,pplVar27);
    break;
  case 0x2b:
  case 0x2d:
    local_80 = *(long ***)(param_1 + 0x128);
    *(long ****)(param_1 + 0x128) = &local_80;
    local_68[0] = *(long ****)(param_1 + 0x120);
    local_70._0_4_ = 0;
    local_78 = param_3;
    FUN_0012b7dc(param_1,param_2,param_3[2]);
    if ((int)local_70 == 0) {
      FUN_0012f1e8(param_1,param_2,param_3);
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
LAB_0012dadc:
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
          goto LAB_0012db14;
        }
LAB_0012daf8:
        lVar10 = lVar18 + 1;
        *(long *)(param_1 + 0x100) = lVar10;
        param_1[lVar18] = 0x74;
        param_1[0x108] = 0x74;
        if (lVar10 != 0xff) goto LAB_0012db14;
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
          goto LAB_0012daf8;
        }
        lVar10 = lVar10 + 2;
        *(long *)(param_1 + 0x100) = lVar10;
        param_1[lVar18] = 0x53;
        param_1[0x108] = 0x53;
        if (lVar10 != 0xff) goto LAB_0012dadc;
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x61;
        lVar10 = 2;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        param_1[1] = 0x74;
LAB_0012db14:
        lVar18 = lVar10 + 1;
      }
      *(long *)(param_1 + 0x100) = lVar18;
      param_1[lVar10] = 0x20;
      param_1[0x108] = 0x20;
    }
    if (*(undefined **)(param_3[1] + 8) == &UNK_001409c0) {
      lVar10 = *(long *)(param_1 + 0x100);
    }
    else {
      FUN_0012b7dc(param_1,param_2);
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
LAB_0012d7f8:
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
LAB_0012d814:
          lVar12 = lVar18 + 1;
          *(long *)(param_1 + 0x100) = lVar12;
          param_1[lVar18] = 0x61;
          param_1[0x108] = 0x61;
          if (lVar12 != 0xff) goto LAB_0012d830;
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
          goto LAB_0012d814;
        }
        lVar10 = lVar10 + 2;
        *(long *)(param_1 + 0x100) = lVar10;
        param_1[lVar18] = 0x46;
        param_1[0x108] = 0x46;
        if (lVar10 != 0xff) goto LAB_0012d7f8;
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x72;
        lVar12 = 2;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        param_1[1] = 0x61;
LAB_0012d830:
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
          goto LAB_0012d850;
        }
      }
      lVar18 = lVar10 + 1;
LAB_0012d850:
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
LAB_0012cd6c:
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
LAB_0012cd88:
        lVar12 = lVar18 + 1;
        *(long *)(param_1 + 0x100) = lVar12;
        param_1[lVar18] = 99;
        param_1[0x108] = 99;
        if (lVar12 != 0xff) goto LAB_0012cda4;
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x75;
        lVar10 = 1;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
LAB_0012cdc0:
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
        goto LAB_0012cd88;
      }
      lVar10 = lVar10 + 2;
      *(long *)(param_1 + 0x100) = lVar10;
      param_1[lVar18] = 0x41;
      param_1[0x108] = 0x41;
      if (lVar10 != 0xff) goto LAB_0012cd6c;
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      *param_1 = 99;
      lVar12 = 2;
      param_1[1] = 99;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
LAB_0012cda4:
      lVar10 = lVar12 + 1;
      *(long *)(param_1 + 0x100) = lVar10;
      param_1[lVar12] = 0x75;
      param_1[0x108] = 0x75;
      if (lVar10 != 0xff) goto LAB_0012cdc0;
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
      FUN_0012b7dc(param_1,param_2);
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
      FUN_0012b7dc(param_1,param_2,param_3[2]);
      if ((*(long *)(param_1 + 0x138) == lVar10) && (*(long *)(param_1 + 0x100) == uVar39 + 2)) {
        *(ulong *)(param_1 + 0x100) = uVar39;
      }
    }
    break;
  case 0x30:
    lVar10 = param_3[2];
    if (param_3[1] != 0) {
      FUN_0012b7dc(param_1,param_2);
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
    FUN_0012b7dc(param_1,param_2,lVar10);
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
    FUN_0012b7dc(param_1,param_2,param_3[2]);
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
      FUN_0012b7dc(param_1,param_2,*(undefined8 *)((int *)param_3[1] + 2));
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
      FUN_0012b7dc(param_1,param_2,*(undefined8 *)(param_3[1] + 0x10));
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
      FUN_0012b7dc(param_1,param_2);
      if (*(long *)(param_1 + 0x160) != 0) {
        *(long ***)(param_1 + 0x120) = local_80;
      }
    }
    break;
  case 0x35:
    FUN_001302f4(param_1,param_2,param_3[1]);
    break;
  case 0x36:
    piVar23 = (int *)param_3[1];
    piVar9 = (int *)param_3[2];
    if (*piVar23 == 0x31) {
      pcVar11 = **(char ***)(piVar23 + 2);
      iVar6 = strcmp(pcVar11,"ad");
      if (iVar6 == 0) {
        iVar6 = *piVar9;
        if (iVar6 != 3) goto LAB_0012dc6c;
        if ((**(int **)(piVar9 + 2) == 1) && (**(int **)(piVar9 + 4) == 0x29)) {
          piVar9 = *(int **)(piVar9 + 2);
        }
      }
      else {
        iVar6 = *piVar9;
LAB_0012dc6c:
        if (iVar6 == 0x38) {
          FUN_001303c8(param_1,param_2,*(undefined8 *)(piVar9 + 2));
          FUN_001302f4(param_1,param_2,piVar23);
          return;
        }
      }
      FUN_001302f4(param_1,param_2,piVar23);
      iVar6 = strcmp(pcVar11,"gs");
      if (iVar6 == 0) {
        FUN_0012b7dc(param_1,param_2,piVar9);
        return;
      }
      iVar6 = strcmp(pcVar11,"st");
      if (iVar6 == 0) {
        FUN_00123630(param_1,0x28);
        FUN_0012b7dc(param_1,param_2,piVar9);
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
      FUN_0012b7dc(param_1,param_2,*(undefined8 *)(piVar23 + 2));
      FUN_00123630(param_1,0x29);
    }
    else {
      FUN_001302f4(param_1,param_2,piVar23);
    }
    FUN_001303c8(param_1,param_2,piVar9);
    break;
  case 0x37:
    piVar9 = (int *)param_3[2];
    if (*piVar9 != 0x38) goto LAB_0012b858;
    ppcVar24 = *(char ***)((int *)param_3[1] + 2);
    pcVar11 = *ppcVar24;
    if ((pcVar11[1] == 'c') && (((byte)(*pcVar11 + 0x8eU) < 2 || ((byte)(*pcVar11 + 0x9dU) < 2)))) {
      FUN_001302f4(param_1,param_2);
      FUN_00123630(param_1,0x3c);
      FUN_0012b7dc(param_1,param_2,*(undefined8 *)(param_3[2] + 8));
      FUN_00123934(param_1,&DAT_00138710);
      FUN_0012b7dc(param_1,param_2,*(undefined8 *)(param_3[2] + 0x10));
      FUN_00123630(param_1,0x29);
    }
    else {
      if ((*(int *)param_3[1] == 0x31) && ((*(int *)(ppcVar24 + 2) == 1 && (*ppcVar24[1] == '>'))))
      {
        FUN_00123630(param_1,0x28);
        piVar9 = (int *)param_3[2];
        pcVar11 = **(char ***)(param_3[1] + 8);
      }
      iVar6 = strcmp(pcVar11,"cl");
      piVar9 = *(int **)(piVar9 + 2);
      if ((iVar6 == 0) && (*piVar9 == 3)) {
        if (**(int **)(piVar9 + 4) != 0x29) {
          *(undefined4 *)(param_1 + 0x130) = 1;
        }
        FUN_001303c8(param_1,param_2,*(undefined8 *)(piVar9 + 2));
      }
      else {
        FUN_001303c8(param_1,param_2);
      }
      lVar10 = param_3[1];
      pcVar11 = **(char ***)(lVar10 + 8);
      iVar6 = strcmp(pcVar11,"ix");
      if (iVar6 == 0) {
        FUN_00123630(param_1,0x5b);
        FUN_0012b7dc(param_1,param_2,*(undefined8 *)(param_3[2] + 0x10));
        FUN_00123630(param_1,0x5d);
      }
      else {
        iVar6 = strcmp(pcVar11,"cl");
        if (iVar6 != 0) {
          FUN_001302f4(param_1,param_2,lVar10);
        }
        FUN_001303c8(param_1,param_2,*(undefined8 *)(param_3[2] + 0x10));
      }
      if (((*(int *)param_3[1] == 0x31) &&
          (lVar10 = *(long *)((int *)param_3[1] + 2), *(int *)(lVar10 + 0x10) == 1)) &&
         (**(char **)(lVar10 + 8) == '>')) {
        FUN_00123630(param_1,0x29);
      }
    }
    break;
  case 0x38:
    *(undefined4 *)(param_1 + 0x130) = 1;
    break;
  case 0x39:
    piVar9 = (int *)param_3[2];
    if ((*piVar9 != 0x3a) || (piVar23 = *(int **)(piVar9 + 4), *piVar23 != 0x3b)) goto LAB_0012b858;
    lVar12 = param_3[1];
    lVar10 = *(long *)(piVar9 + 2);
    uVar38 = *(undefined8 *)(piVar23 + 2);
    lVar18 = *(long *)(piVar23 + 4);
    iVar6 = strcmp(**(char ***)(lVar12 + 8),"qu");
    if (iVar6 == 0) {
      FUN_001303c8(param_1,param_2);
      FUN_001302f4(param_1,param_2,lVar12);
      FUN_001303c8(param_1,param_2,uVar38);
      FUN_00123934(param_1,&DAT_00138648);
      FUN_001303c8(param_1,param_2,lVar18);
    }
    else {
      FUN_00123934(param_1,&DAT_00138650);
      if (*(long *)(lVar10 + 8) != 0) {
        FUN_001303c8(param_1,param_2);
        FUN_00123630(param_1,0x20);
      }
      FUN_0012b7dc(param_1,param_2,uVar38);
      if (lVar18 != 0) {
        FUN_001303c8(param_1,param_2,lVar18);
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
            FUN_00123630(param_1,0x2d);
          }
          FUN_0012b7dc(param_1,param_2,param_3[2]);
          switch(uVar36) {
          case 2:
            FUN_00123630(param_1,0x75);
            return;
          case 3:
            FUN_00123630(param_1,0x6c);
            return;
          case 4:
            FUN_00123934(param_1,&DAT_00138658);
            return;
          case 5:
            FUN_00123934(param_1,&DAT_00138660);
            return;
          case 6:
            FUN_00123934(param_1,"ull");
            return;
          default:
            return;
          }
        }
      }
      else if ((((uVar36 == 7) && (piVar9 = (int *)param_3[2], *piVar9 == 0)) && (piVar9[4] == 1))
              && (iVar6 == 0x3c)) {
        if (**(char **)(piVar9 + 2) == '0') {
          FUN_00123934(param_1,"false");
          return;
        }
        if (**(char **)(piVar9 + 2) == '1') {
          FUN_00123934(param_1,&DAT_00138670);
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
    FUN_0012b7dc(param_1,param_2,param_3[1]);
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
      FUN_00123630(param_1,0x2d);
    }
    if (uVar36 == 8) {
      FUN_00123630(param_1,0x5b);
      FUN_0012b7dc(param_1,param_2,param_3[2]);
      FUN_00123630(param_1,0x5d);
    }
    else {
      FUN_0012b7dc(param_1,param_2,param_3[2]);
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
    FUN_0012b7dc(param_1,param_2,param_3[1]);
    break;
  case 0x3f:
    FUN_0012b7dc(param_1,param_2,param_3[1]);
    FUN_0012b7dc(param_1,param_2,param_3[2]);
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
    FUN_0012b7dc(param_1,param_2,param_3[1]);
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
    FUN_0012b7dc(param_1,param_2,param_3[1]);
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
    FUN_0012b7dc(param_1,param_2,param_3[1]);
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
    FUN_0012b7dc(param_1,param_2,param_3[1]);
    lVar10 = *(long *)(param_1 + 0x100);
    if (lVar10 == 0xff) {
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar18 = 1;
      *param_1 = 0x29;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
LAB_0012d544:
      lVar10 = lVar18 + 1;
    }
    else {
      lVar18 = lVar10 + 1;
      *(long *)(param_1 + 0x100) = lVar18;
      param_1[lVar10] = 0x29;
      param_1[0x108] = 0x29;
      if (lVar18 != 0xff) goto LAB_0012d544;
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
    FUN_0012b7dc(param_1,param_2,param_3[1]);
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
    FUN_0012b7dc(param_1,param_2,param_3[1]);
    break;
  case 0x4a:
    iVar6 = 0;
    piVar9 = (int *)FUN_001237ac(param_1,param_3[1]);
    if (piVar9 == (int *)0x0) {
      FUN_001303c8(param_1,param_2,param_3[1]);
      FUN_00123934(param_1,&DAT_00138698);
    }
    else {
      do {
        if ((*piVar9 != 0x2f) || (*(long *)(piVar9 + 2) == 0)) {
          lVar10 = param_3[1];
          if (iVar6 == 0) {
            return;
          }
          goto LAB_0012c7ec;
        }
        piVar9 = *(int **)(piVar9 + 4);
        iVar6 = iVar6 + 1;
      } while (piVar9 != (int *)0x0);
      lVar10 = param_3[1];
LAB_0012c7ec:
      iVar31 = 0;
      do {
        *(int *)(param_1 + 0x134) = iVar31;
        FUN_0012b7dc(param_1,param_2,lVar10);
        if (iVar31 < iVar6 + -1) {
          lVar18 = *(long *)(param_1 + 0x100);
          if (lVar18 == 0xff) {
            param_1[0xff] = 0;
            (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
            *param_1 = 0x2c;
            lVar12 = 1;
            *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
LAB_0012c83c:
            lVar18 = lVar12 + 1;
          }
          else {
            lVar12 = lVar18 + 1;
            *(long *)(param_1 + 0x100) = lVar12;
            param_1[lVar18] = 0x2c;
            param_1[0x108] = 0x2c;
            if (lVar12 != 0xff) goto LAB_0012c83c;
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
    FUN_0012b7dc(param_1,param_2,param_3[1]);
    lVar10 = *(long *)(param_1 + 0x100);
    if (lVar10 == 0xff) {
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      *param_1 = 0x5b;
      lVar10 = 2;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 0x61;
LAB_0012c8b4:
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
        goto LAB_0012c8ec;
      }
LAB_0012c8d0:
      lVar10 = lVar18 + 1;
      *(long *)(param_1 + 0x100) = lVar10;
      param_1[lVar18] = 0x69;
      param_1[0x108] = 0x69;
      if (lVar10 != 0xff) goto LAB_0012c8ec;
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
        goto LAB_0012c8d0;
      }
      lVar10 = lVar10 + 2;
      *(long *)(param_1 + 0x100) = lVar10;
      param_1[lVar18] = 0x61;
      param_1[0x108] = 0x61;
      if (lVar10 != 0xff) goto LAB_0012c8b4;
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      *param_1 = 0x62;
      lVar10 = 2;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 0x69;
LAB_0012c8ec:
      lVar18 = lVar10 + 1;
    }
    *(long *)(param_1 + 0x100) = lVar18;
    param_1[lVar10] = 0x3a;
    param_1[0x108] = 0x3a;
    FUN_0012b7dc(param_1,param_2,param_3[2]);
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
    FUN_0012b7dc(param_1,param_2,param_3[1]);
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
    FUN_0012b7dc(param_1,param_2,param_3[2]);
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



void FUN_0012f1e8(undefined *param_1,uint param_2,undefined4 *param_3)

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
LAB_0012f224:
    FUN_0012b7dc(param_1,param_2,param_3);
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
LAB_0012f3f0:
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
LAB_0012f40c:
        lVar2 = lVar3 + 1;
        *(long *)(param_1 + 0x100) = lVar2;
        param_1[lVar3] = 0x6e;
        param_1[0x108] = 0x6e;
        if (lVar2 != 0xff) goto LAB_0012f428;
        uVar5 = 0x74;
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x73;
        lVar3 = 1;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
      goto LAB_0012f50c;
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
      goto LAB_0012f40c;
    }
    lVar2 = lVar2 + 2;
    *(long *)(param_1 + 0x100) = lVar2;
    param_1[lVar3] = 99;
    param_1[0x108] = 99;
    if (lVar2 != 0xff) goto LAB_0012f3f0;
    param_1[0xff] = 0;
    (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
    *param_1 = 0x6f;
    lVar2 = 2;
    *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    param_1[1] = 0x6e;
LAB_0012f428:
    lVar3 = lVar2 + 1;
    *(long *)(param_1 + 0x100) = lVar3;
    param_1[lVar2] = 0x73;
    param_1[0x108] = 0x73;
    uVar5 = 0x74;
    if (lVar3 != 0xff) goto LAB_0012f50c;
    goto LAB_0012f444;
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
    goto LAB_0012f494;
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
    goto LAB_0012f4e4;
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
    goto LAB_0012f224;
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
LAB_0012f494:
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
LAB_0012f4e4:
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
LAB_0012f444:
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,lVar3,*(undefined8 *)(param_1 + 0x118));
        lVar2 = 1;
        lVar3 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        goto LAB_0012f510;
      }
    }
LAB_0012f50c:
    lVar2 = lVar3 + 1;
LAB_0012f510:
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
    FUN_0012b7dc(param_1,param_2,*(undefined8 *)(param_3 + 2));
    lVar2 = *(long *)(param_1 + 0x100);
    if (lVar2 == 0xff) {
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar2 = 2;
      *param_1 = 0x3a;
      param_1[1] = 0x3a;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
LAB_0012f6f8:
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
        goto LAB_0012f6f8;
      }
      lVar2 = lVar2 + 2;
      *(long *)(param_1 + 0x100) = lVar2;
      param_1[lVar3] = 0x3a;
      param_1[0x108] = 0x3a;
      if (lVar2 != 0xff) goto LAB_0012f6f8;
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
    FUN_0012b7dc(param_1,param_2,*(undefined8 *)(param_3 + 2));
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



void FUN_0012fa68(undefined *param_1,uint param_2,undefined8 *param_3,int param_4)

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
            FUN_00130044(param_1,param_2,piVar5 + 4,*param_3);
            *(undefined8 *)(param_1 + 0x120) = uVar8;
            return;
          }
          if (iVar2 == 0x2a) {
            FUN_0012fd7c(param_1,param_2,piVar5 + 2,*param_3);
            *(undefined8 *)(param_1 + 0x120) = uVar8;
            return;
          }
          if (iVar2 == 2) {
            uVar6 = *(undefined8 *)(param_1 + 0x128);
            *(undefined8 *)(param_1 + 0x128) = 0;
            FUN_0012b7dc(param_1,param_2,*(undefined8 *)(piVar5 + 2));
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
              goto LAB_0012fbfc;
            }
            if (lVar3 == 0xff) {
              param_1[0xff] = 0;
              (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
              lVar4 = 1;
              *param_1 = 0x3a;
              *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
LAB_0012fbd0:
              lVar3 = lVar4 + 1;
            }
            else {
              lVar4 = lVar3 + 1;
              *(long *)(param_1 + 0x100) = lVar4;
              param_1[lVar3] = 0x3a;
              param_1[0x108] = 0x3a;
              if (lVar4 != 0xff) goto LAB_0012fbd0;
              param_1[0xff] = 0;
              (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
              lVar3 = 1;
              lVar4 = 0;
              *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
            }
            *(long *)(param_1 + 0x100) = lVar3;
            param_1[lVar4] = 0x3a;
            param_1[0x108] = 0x3a;
LAB_0012fbfc:
            piVar5 = *(int **)(param_3[1] + 0x10);
            iVar2 = *piVar5;
            if (iVar2 != 0x46) goto LAB_0012fc1c;
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
            FUN_00123b3c(param_1,(long)(piVar5[4] + 1));
            FUN_00123934(param_1,&DAT_00138460);
            do {
              piVar5 = *(int **)(piVar5 + 2);
              iVar2 = *piVar5;
LAB_0012fc1c:
            } while (iVar2 - 0x1cU < 5);
            FUN_0012b7dc(param_1,param_2,piVar5);
            *(undefined8 *)(param_1 + 0x120) = uVar8;
            return;
          }
          FUN_0012f1e8(param_1,param_2);
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



void FUN_0012fd7c(undefined *param_1,undefined4 param_2,long *param_3,long *param_4)

{
  long *plVar1;
  long lVar2;
  long lVar3;
  
  plVar1 = param_4;
  if (param_4 != (long *)0x0) {
    do {
      if (*(int *)(plVar1 + 2) == 0) {
        if (*(int *)plVar1[1] == 0x2a) {
          FUN_0012fa68(param_1,param_2,param_4,0);
          lVar3 = *(long *)(param_1 + 0x100);
          goto joined_r0x0012fee4;
        }
        lVar3 = *(long *)(param_1 + 0x100);
        if (lVar3 == 0xff) {
          param_1[0xff] = 0;
          (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
          lVar2 = 1;
          *param_1 = 0x20;
          *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
LAB_0012fe80:
          lVar3 = lVar2 + 1;
        }
        else {
          lVar2 = lVar3 + 1;
          *(long *)(param_1 + 0x100) = lVar2;
          param_1[lVar3] = 0x20;
          param_1[0x108] = 0x20;
          if (lVar2 != 0xff) goto LAB_0012fe80;
          param_1[0xff] = 0;
          (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
          lVar3 = 1;
          lVar2 = 0;
          *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        }
        *(long *)(param_1 + 0x100) = lVar3;
        param_1[lVar2] = 0x28;
        param_1[0x108] = 0x28;
        FUN_0012fa68(param_1,param_2,param_4,0);
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
        goto LAB_0012fdc8;
      }
      plVar1 = (long *)*plVar1;
    } while (plVar1 != (long *)0x0);
    FUN_0012fa68(param_1,param_2,param_4,0);
  }
  lVar2 = *(long *)(param_1 + 0x100);
LAB_0012fdc8:
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
joined_r0x0012fee4:
  if (lVar3 == 0xff) {
    param_1[0xff] = 0;
    (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
    *param_1 = 0x5b;
    param_1[0x108] = 0x5b;
    lVar2 = 1;
    lVar3 = *param_3;
    *(undefined8 *)(param_1 + 0x100) = 1;
    *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    if (lVar3 == 0) goto LAB_0012fe20;
LAB_0012fe08:
    FUN_0012b7dc(param_1,param_2);
    lVar2 = *(long *)(param_1 + 0x100);
  }
  else {
    lVar2 = lVar3 + 1;
    *(long *)(param_1 + 0x100) = lVar2;
    param_1[lVar3] = 0x5b;
    param_1[0x108] = 0x5b;
    if (*param_3 != 0) goto LAB_0012fe08;
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
LAB_0012fe20:
  *(long *)(param_1 + 0x100) = lVar2 + 1;
  param_1[lVar2] = 0x5d;
  param_1[0x108] = 0x5d;
  return;
}



void FUN_00130044(undefined *param_1,undefined4 param_2,long *param_3,long *param_4)

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
joined_r0x00130070:
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
LAB_00130154:
        if (bVar2 == 0x20) goto LAB_001301c0;
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
        if (lVar4 != 0xff) goto LAB_001301cc;
LAB_00130184:
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,lVar4,*(undefined8 *)(param_1 + 0x118));
        lVar5 = 1;
        lVar4 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        break;
      default:
        plVar3 = (long *)*plVar3;
        if (plVar3 != (long *)0x0) goto code_r0x001300ac;
        goto LAB_001300b4;
      case 0x22:
      case 0x23:
      case 0x24:
        bVar2 = param_1[0x108];
        if ((bVar2 & 0xfd) != 0x28) goto LAB_00130154;
LAB_001301c0:
        lVar4 = *(long *)(param_1 + 0x100);
        if (lVar4 == 0xff) goto LAB_00130184;
LAB_001301cc:
        lVar5 = lVar4 + 1;
      }
      *(long *)(param_1 + 0x100) = lVar5;
      param_1[lVar4] = 0x28;
      param_1[0x108] = 0x28;
      uVar6 = *(undefined8 *)(param_1 + 0x128);
      *(undefined8 *)(param_1 + 0x128) = 0;
      FUN_0012fa68(param_1,param_2,param_4,0);
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
      goto joined_r0x001300d8;
    }
  }
LAB_001300b4:
  uVar6 = *(undefined8 *)(param_1 + 0x128);
  *(undefined8 *)(param_1 + 0x128) = 0;
  FUN_0012fa68(param_1,param_2,param_4,0);
  lVar5 = *(long *)(param_1 + 0x100);
joined_r0x001300d8:
  if (lVar5 == 0xff) {
    param_1[0xff] = 0;
    (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
    *param_1 = 0x28;
    param_1[0x108] = 0x28;
    lVar4 = 1;
    lVar5 = *param_3;
    *(undefined8 *)(param_1 + 0x100) = 1;
    *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    if (lVar5 != 0) goto LAB_001300f8;
  }
  else {
    lVar4 = lVar5 + 1;
    *(long *)(param_1 + 0x100) = lVar4;
    param_1[lVar5] = 0x28;
    param_1[0x108] = 0x28;
    if (*param_3 != 0) {
LAB_001300f8:
      FUN_0012b7dc(param_1,param_2);
      lVar4 = *(long *)(param_1 + 0x100);
    }
    if (lVar4 == 0xff) {
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar5 = 1;
      lVar4 = 0;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      goto LAB_00130114;
    }
  }
  lVar5 = lVar4 + 1;
LAB_00130114:
  *(long *)(param_1 + 0x100) = lVar5;
  param_1[lVar4] = 0x29;
  param_1[0x108] = 0x29;
  FUN_0012fa68(param_1,param_2,param_4,1);
  *(undefined8 *)(param_1 + 0x128) = uVar6;
  return;
code_r0x001300ac:
  iVar1 = *(int *)(plVar3 + 2);
  goto joined_r0x00130070;
}



void FUN_001302f4(undefined *param_1,undefined8 param_2,int *param_3)

{
  undefined uVar1;
  long lVar2;
  long lVar3;
  long lVar4;
  long lVar5;
  
  if (*param_3 != 0x31) {
    FUN_0012b7dc();
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



void FUN_001303c8(long param_1,undefined4 param_2,uint *param_3)

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
    FUN_0012b7dc(param_1,param_2,param_3);
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
  FUN_0012b7dc(param_1);
  return;
}



bool FUN_001304d0(char *param_1,code *param_2,undefined8 param_3)

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
    lVar12 = FUN_001280d4(&local_1c8,1);
    if ((local_1b8 & 1) == 0) {
LAB_001308f0:
      cVar7 = *local_1b0;
    }
    else {
      while (pcVar1 = local_1b0, cVar7 = *local_1b0, cVar7 == '.') {
        cVar7 = local_1b0[1];
        if (((byte)(cVar7 + 0x9fU) < 0x1a) || (cVar7 == '_')) {
          cVar7 = local_1b0[2];
          pcVar14 = local_1b0 + 2;
          if (0x19 < (byte)(cVar7 + 0x9fU)) goto LAB_001308e4;
          do {
            do {
              pcVar14 = pcVar14 + 1;
              cVar7 = *pcVar14;
            } while ((byte)(cVar7 + 0x9fU) < 0x1a);
LAB_001308e4:
          } while (cVar7 == '_');
        }
        else {
          if (9 < (byte)(cVar7 - 0x30U)) goto LAB_001308f0;
          cVar7 = *local_1b0;
          pcVar14 = local_1b0;
        }
        while (cVar7 == '.') {
          while( true ) {
            if (9 < (byte)(pcVar14[1] - 0x30U)) goto LAB_00130874;
            cVar7 = pcVar14[2];
            pcVar14 = pcVar14 + 2;
            if (9 < (byte)(cVar7 - 0x30U)) break;
            do {
              pcVar14 = pcVar14 + 1;
            } while ((byte)(*pcVar14 - 0x30U) < 10);
            if (*pcVar14 != '.') goto LAB_00130874;
          }
        }
LAB_00130874:
        iVar8 = (int)local_1b0;
        local_1b0 = pcVar14;
        uVar11 = FUN_00123094(&local_1c8,pcVar1,(int)pcVar14 - iVar8);
        lVar12 = FUN_00122ff4(&local_1c8,0x4c,lVar12,uVar11);
      }
    }
  }
  else if (iVar9 == 0) {
    local_1b0 = param_1;
    local_1a8 = &stack0xfffffffffffffde0 + lVar3;
    local_198 = &stack0xfffffffffffffde0 + lVar4 + lVar3;
    lVar12 = FUN_00125bf8(&local_1c8);
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
      uVar11 = FUN_001280d4(&local_1c8,0);
    }
    else {
      local_1b0 = pcVar1;
      local_1a8 = &stack0xfffffffffffffde0 + lVar3;
      local_198 = &stack0xfffffffffffffde0 + lVar4 + lVar3;
      sVar10 = strlen(pcVar1);
      uVar11 = FUN_00123094(&local_1c8,pcVar1,sVar10);
    }
    lVar12 = FUN_00122ff4(&local_1c8,uVar13,uVar11,0);
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
    FUN_00123564(&local_c,&local_1c,lVar12);
    local_8 = 0;
    local_c = local_1c * local_c;
    lVar5 = -((-(ulong)(local_1c >> 0x1f) & 0xfffffff000000000 | (ulong)local_1c << 4) + 0x10);
    local_28 = &stack0xfffffffffffffde0 + lVar5 + lVar4 + lVar3;
    local_18 = &stack0xfffffffffffffde0 +
               ((lVar5 + lVar4 + lVar3) -
               ((-(ulong)(local_c >> 0x1f) & 0xfffffff000000000 | (ulong)local_c << 4) + 0x10));
    FUN_0012b7dc(auStack_168,0x11,lVar12);
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
    iVar1 = FUN_001304d0(param_1,FUN_00123844,&local_20);
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
    iVar1 = FUN_001304d0();
    uVar2 = 0xfffffffe;
    if (iVar1 != 0) {
      uVar2 = 0;
    }
  }
  return uVar2;
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



void FUN_00130adc(byte *param_1,ulong *param_2)

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



void FUN_00130b04(byte *param_1,ulong *param_2)

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



ulong ** FUN_00130b44(byte param_1,ulong **param_2,ulong **param_3,ulong **param_4)

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
      ppuVar1 = (ulong **)FUN_00130adc(param_3,&local_8);
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
      ppuVar1 = (ulong **)FUN_00130b04(param_3,&local_8);
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



void FUN_00130c34(void)

{
  DAT_00157fd0 = 8;
  DAT_00157fd1 = 8;
  DAT_00157fd2 = 8;
  DAT_00157fd3 = 8;
  DAT_00157fd4 = 8;
  DAT_00157fd5 = 8;
  DAT_00157fd6 = 8;
  DAT_00157fd7 = 8;
  DAT_00157fd8 = 8;
  DAT_00157fd9 = 8;
  DAT_00157fda = 8;
  DAT_00157fdb = 8;
  DAT_00157fdc = 8;
  DAT_00157fdd = 8;
  DAT_00157fde = 8;
  DAT_00157fdf = 8;
  DAT_00157fe0 = 8;
  DAT_00157fe1 = 8;
  DAT_00157fe2 = 8;
  DAT_00157fe3 = 8;
  DAT_00157fe4 = 8;
  DAT_00157fe5 = 8;
  DAT_00157fe6 = 8;
  DAT_00157fe7 = 8;
  DAT_00157fe8 = 8;
  DAT_00157fe9 = 8;
  DAT_00157fea = 8;
  DAT_00157feb = 8;
  DAT_00157fec = 8;
  DAT_00157fed = 8;
  DAT_00157fee = 8;
  DAT_00157fef = 8;
  DAT_00158010 = 8;
  DAT_00158011 = 8;
  DAT_00158012 = 8;
  DAT_00158013 = 8;
  DAT_00158014 = 8;
  DAT_00158015 = 8;
  DAT_00158016 = 8;
  DAT_00158017 = 8;
  DAT_00158018 = 8;
  DAT_00158019 = 8;
  DAT_0015801a = 8;
  DAT_0015801b = 8;
  DAT_0015801c = 8;
  DAT_0015801d = 8;
  DAT_0015801e = 8;
  DAT_0015801f = 8;
  DAT_00158020 = 8;
  DAT_00158021 = 8;
  DAT_00158022 = 8;
  DAT_00158023 = 8;
  DAT_00158024 = 8;
  DAT_00158025 = 8;
  DAT_00158026 = 8;
  DAT_00158027 = 8;
  DAT_00158028 = 8;
  DAT_00158029 = 8;
  DAT_0015802a = 8;
  DAT_0015802b = 8;
  DAT_0015802c = 8;
  DAT_0015802d = 8;
  DAT_0015802e = 8;
  DAT_0015802f = 8;
  DAT_00158030 = 8;
  return;
}



void FUN_00130d48(long param_1,undefined8 param_2,undefined8 *param_3)

{
  if (DAT_00157fef == '\b') {
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
      if ((&DAT_00157fd0)[param_2] != '\b') goto LAB_00130d94;
      puVar1 = (undefined8 *)*puVar1;
    }
    return puVar1;
  }
LAB_00130d94:
                    // WARNING: Subroutine does not return
  abort();
}



long FUN_00130ddc(long param_1,long param_2)

{
  void **__dest;
  void **__src;
  long lVar1;
  undefined auStack_8 [8];
  
  if ((((*(ulong *)(param_2 + 0x340) >> 0x3e & 1) == 0) || (*(char *)(param_2 + 0x377) == '\0')) &&
     (*(long *)(param_2 + 0xf8) == 0)) {
    FUN_00130d48(param_2,*(undefined8 *)(param_2 + 0x310),auStack_8);
  }
  lVar1 = 0;
  while( true ) {
    __dest = *(void ***)(param_1 + lVar1 * 8);
    __src = *(void ***)(param_2 + lVar1 * 8);
    if (*(char *)(param_1 + lVar1 + 0x358) != '\0') break;
    if ((*(char *)(param_2 + lVar1 + 0x358) == '\0') || (__dest == (void **)0x0)) {
      if ((__dest != (void **)0x0 && __src != (void **)0x0) && (__src != __dest)) {
        memcpy(__dest,__src,(ulong)(byte)(&DAT_00157fd0)[lVar1]);
      }
    }
    else {
      if ((&DAT_00157fd0)[lVar1] != '\b') break;
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
LAB_00130f00:
                    // WARNING: Subroutine does not return
    abort();
  }
  if (((*(ulong *)(param_1 + 0x340) >> 0x3e & 1) == 0) ||
     (*(char *)(param_1 + param_2 + 0x358) == '\0')) {
    if ((&DAT_00157fd0)[param_2] != '\b') goto LAB_00130f00;
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



undefined8 FUN_00130fb4(byte param_1,undefined8 param_2)

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
LAB_0013101c:
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
        goto LAB_0013101c;
      }
    }
  }
  return 0;
}



void FUN_0013102c(byte *param_1,byte *param_2,long param_3,void *param_4)

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
LAB_00131074:
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
    if (bVar1 != 0xc0) goto code_r0x001310f4;
    *(undefined4 *)((long)param_4 + (uVar10 & 0x3f) * 0x10 + 8) = 0;
  }
  local_18 = uVar10 & 0x3f;
  goto LAB_00131194;
code_r0x001310f4:
  switch(bVar2) {
  case 0:
    goto LAB_00131074;
  case 1:
    uVar3 = *(undefined *)((long)param_4 + 0x670);
    uVar8 = FUN_00130fb4(uVar3,param_3);
    param_1 = (byte *)FUN_00130b44(uVar3,uVar8,param_1,&local_8);
    *(long *)((long)param_4 + 0x648) = local_8;
    goto LAB_00131074;
  case 2:
    *(ulong *)((long)param_4 + 0x648) = uVar12 + (ulong)pbVar5[1] * *(long *)((long)param_4 + 0x660)
    ;
    param_1 = pbVar5 + 2;
    goto LAB_00131074;
  case 3:
    *(ulong *)((long)param_4 + 0x648) =
         uVar12 + (ulong)*(ushort *)(pbVar5 + 1) * *(long *)((long)param_4 + 0x660);
    param_1 = pbVar5 + 3;
    goto LAB_00131074;
  case 4:
    *(ulong *)((long)param_4 + 0x648) =
         uVar12 + (ulong)*(uint *)(pbVar5 + 1) * *(long *)((long)param_4 + 0x660);
    param_1 = pbVar5 + 5;
    goto LAB_00131074;
  case 5:
    param_1 = (byte *)FUN_00130adc(param_1,&local_18);
LAB_00131194:
    param_1 = (byte *)FUN_00130adc(param_1,&local_10);
    lVar11 = *(long *)((long)param_4 + 0x658);
    lVar9 = local_10;
    break;
  case 6:
  case 8:
    param_1 = (byte *)FUN_00130adc(param_1,&local_18);
    if (local_18 < 0x62) {
      *(undefined4 *)((long)param_4 + local_18 * 0x10 + 8) = 0;
    }
    goto LAB_00131074;
  case 7:
    param_1 = (byte *)FUN_00130adc(param_1,&local_18);
    if (local_18 < 0x62) {
      *(undefined4 *)((long)param_4 + local_18 * 0x10 + 8) = 6;
    }
    goto LAB_00131074;
  case 9:
    uVar8 = FUN_00130adc(param_1,&local_18);
    param_1 = (byte *)FUN_00130adc(uVar8,&local_8);
    if (0x61 < local_18) goto LAB_00131074;
    lVar7 = local_18 * 0x10;
    *(undefined4 *)((long)param_4 + lVar7 + 8) = 2;
    lVar9 = local_8;
    goto LAB_001314f0;
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
    goto LAB_00131074;
  case 0xb:
    puVar15 = *(undefined **)((long)param_4 + 0x620);
    memcpy(param_4,puVar15,0x648);
    *(undefined **)(puVar15 + 0x620) = puVar16;
    puVar16 = puVar15;
    goto LAB_00131074;
  case 0xc:
    uVar8 = FUN_00130adc(param_1,&local_10);
    *(long *)((long)param_4 + 0x630) = local_10;
    param_1 = (byte *)FUN_00130adc(uVar8,&local_10);
    *(long *)((long)param_4 + 0x628) = local_10;
    goto LAB_001312d8;
  case 0xd:
    param_1 = (byte *)FUN_00130adc(param_1,&local_10);
    *(long *)((long)param_4 + 0x630) = local_10;
LAB_001312d8:
    *(undefined4 *)((long)param_4 + 0x640) = 1;
    goto LAB_00131074;
  case 0xe:
    param_1 = (byte *)FUN_00130adc(param_1,&local_10);
    lVar9 = local_10;
    goto LAB_001313a4;
  case 0xf:
    *(byte **)((long)param_4 + 0x638) = param_1;
    *(undefined4 *)((long)param_4 + 0x640) = 2;
    goto LAB_00131454;
  case 0x10:
    param_1 = (byte *)FUN_00130adc(param_1,&local_18);
    if (0x61 < local_18) goto LAB_00131454;
    uVar14 = 3;
    goto LAB_0013144c;
  case 0x11:
    uVar8 = FUN_00130adc(param_1,&local_18);
    param_1 = (byte *)FUN_00130b04(uVar8,&local_8);
    lVar11 = *(long *)((long)param_4 + 0x658);
    lVar9 = local_8;
    break;
  case 0x12:
    uVar8 = FUN_00130adc(param_1,&local_10);
    *(long *)((long)param_4 + 0x630) = local_10;
    param_1 = (byte *)FUN_00130b04(uVar8,&local_8);
    *(undefined4 *)((long)param_4 + 0x640) = 1;
    goto LAB_00131398;
  case 0x13:
    param_1 = (byte *)FUN_00130b04(param_1,&local_8);
LAB_00131398:
    lVar9 = local_8 * *(long *)((long)param_4 + 0x658);
LAB_001313a4:
    *(long *)((long)param_4 + 0x628) = lVar9;
    goto LAB_00131074;
  case 0x14:
    uVar8 = FUN_00130adc(param_1,&local_18);
    param_1 = (byte *)FUN_00130adc(uVar8,&local_10);
    lVar11 = *(long *)((long)param_4 + 0x658);
    lVar9 = local_10;
    goto LAB_00131404;
  case 0x15:
    uVar8 = FUN_00130adc(param_1,&local_18);
    param_1 = (byte *)FUN_00130b04(uVar8,&local_8);
    lVar11 = *(long *)((long)param_4 + 0x658);
    lVar9 = local_8;
LAB_00131404:
    if (0x61 < local_18) goto LAB_00131074;
    lVar7 = local_18 * 0x10;
    *(undefined4 *)((long)param_4 + lVar7 + 8) = 4;
    lVar9 = lVar9 * lVar11;
    goto LAB_001314f0;
  case 0x16:
    param_1 = (byte *)FUN_00130adc(param_1,&local_18);
    if (0x61 < local_18) goto LAB_00131454;
    uVar14 = 5;
LAB_0013144c:
    *(undefined4 *)((long)param_4 + local_18 * 0x10 + 8) = uVar14;
    *(byte **)((long)param_4 + local_18 * 0x10) = param_1;
LAB_00131454:
    lVar9 = FUN_00130adc(param_1,&local_10);
    param_1 = (byte *)(lVar9 + local_10);
    goto LAB_00131074;
  default:
    goto switchD_00131100_caseD_17;
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
    goto LAB_00131074;
  case 0x2e:
    param_1 = (byte *)FUN_00130adc(param_1,&local_10);
    *(long *)(param_3 + 0x350) = local_10;
    goto LAB_00131074;
  case 0x2f:
    uVar8 = FUN_00130adc(param_1,&local_18);
    param_1 = (byte *)FUN_00130adc(uVar8,&local_10);
    lVar9 = *(long *)((long)param_4 + 0x658);
    if (0x61 < local_18) goto LAB_00131074;
    lVar7 = local_18 * 0x10;
    *(undefined4 *)((long)param_4 + lVar7 + 8) = 1;
    lVar9 = -(lVar9 * local_10);
    goto LAB_001314f0;
  }
  if (0x61 < local_18) goto LAB_00131074;
  lVar7 = local_18 * 0x10;
  *(undefined4 *)((long)param_4 + lVar7 + 8) = 1;
  lVar9 = lVar9 * lVar11;
LAB_001314f0:
  *(long *)((long)param_4 + lVar7) = lVar9;
  goto LAB_00131074;
switchD_00131100_caseD_17:
                    // WARNING: Subroutine does not return
  abort();
}



undefined8 FUN_00131524(long param_1,long *param_2)

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
LAB_00131920:
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
LAB_001316fc:
      uVar12 = FUN_00130adc(plVar7,&local_18);
      param_2[0xcc] = local_18;
      pbVar8 = (byte *)FUN_00130b04(uVar12,&local_10);
      param_2[0xcb] = local_10;
      if (*(char *)(puVar17 + 2) == '\x01') {
        pbVar9 = pbVar8 + 1;
        uVar13 = (ulong)*pbVar8;
      }
      else {
        pbVar9 = (byte *)FUN_00130adc(pbVar8,&local_18);
        uVar13 = local_18;
      }
      param_2[0xcd] = uVar13;
      *(undefined *)((long)param_2 + 0x671) = 0xff;
      pbVar8 = (byte *)0x0;
      if (*pcVar19 == 'z') {
        pcVar19 = pcVar19 + 1;
        pbVar9 = (byte *)FUN_00130adc(pbVar9,&local_18);
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
LAB_001317b8:
          pbVar9 = pbVar9 + 1;
        }
        else {
          if (cVar2 == 'R') {
            *(byte *)(param_2 + 0xce) = *pbVar9;
            goto LAB_001317b8;
          }
          if (cVar2 == 'P') {
            bVar1 = *pbVar9;
            uVar12 = FUN_00130fb4(bVar1,param_1);
            pbVar9 = (byte *)FUN_00130b44(bVar1,uVar12,pbVar9 + 1,&local_8);
            param_2[0xca] = local_8;
          }
          else {
            pbVar10 = pbVar8;
            if (cVar2 != 'S') goto LAB_00131828;
            *(undefined *)((long)param_2 + 0x673) = 1;
          }
        }
      }
      pbVar10 = pbVar9;
      if (pbVar8 != (byte *)0x0) {
        pbVar10 = pbVar8;
      }
LAB_00131828:
      if (pbVar10 != (byte *)0x0) {
        FUN_0013102c(pbVar10,(long)puVar17 + (ulong)*puVar17 + 4,param_1,param_2);
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
          lVar11 = FUN_00130adc(lVar11,&local_8);
          lVar4 = lVar11 + local_8;
        }
        cVar2 = *(char *)((long)param_2 + 0x671);
        if (cVar2 != -1) {
          uVar12 = FUN_00130fb4(cVar2,param_1);
          lVar11 = FUN_00130b44(cVar2,uVar12,lVar11,&local_8);
          *(long *)(param_1 + 800) = local_8;
        }
        if (lVar4 == 0) {
          lVar4 = lVar11;
        }
        FUN_0013102c(lVar4,(long)puVar3 + (ulong)*puVar3 + 4,param_1,param_2);
        goto LAB_00131920;
      }
    }
    else if ((*(char *)plVar7 == '\b') && (*(char *)((long)plVar7 + 1) == '\0')) {
      plVar7 = (long *)((long)plVar7 + 2);
      goto LAB_001316fc;
    }
    uVar12 = 3;
  }
  return uVar12;
}



// WARNING: Restarted to delay deadcode elimination for space: stack

ulong * FUN_00131948(byte *param_1,byte *param_2,undefined8 param_3,ulong *param_4)

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
LAB_00131998:
  pbVar10 = param_1;
  if (param_2 <= pbVar10) {
    if (uVar12 != 0) {
      return local_200[(int)(uVar12 - 1)];
    }
switchD_00131d54_caseD_3:
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
        param_1 = (byte *)FUN_00130adc(param_1,&local_218);
        puVar5 = local_218;
      }
      else if (uVar14 < 0x11) {
        if (uVar14 == 10) {
          puVar5 = (ulong *)(ulong)*(ushort *)(pbVar10 + 1);
LAB_00131ba4:
          param_1 = pbVar10 + 3;
        }
        else if (uVar14 < 0xb) {
          if (uVar13 == 6) goto LAB_00131ce0;
          if (uVar13 < 7) {
            if (bVar1 != 3) goto switchD_00131d54_caseD_3;
            param_1 = pbVar10 + 9;
            puVar5 = *(ulong **)(pbVar10 + 1);
          }
          else {
            param_1 = pbVar10 + 2;
            if (uVar13 == 8) {
              puVar5 = (ulong *)(ulong)pbVar10[1];
            }
            else {
              if (uVar13 != 9) goto switchD_00131d54_caseD_3;
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
                goto LAB_00131eb8;
              }
              goto switchD_00131d54_caseD_3;
            }
            if (bVar1 == 0xb) {
              puVar5 = (ulong *)(long)*(short *)(pbVar10 + 1);
              goto LAB_00131ba4;
            }
            if (bVar1 != 0xc) goto switchD_00131d54_caseD_3;
            puVar5 = (ulong *)(ulong)*(uint *)(pbVar10 + 1);
          }
          param_1 = pbVar10 + 5;
        }
      }
      else if (uVar14 == 0x15) {
        local_210 = (ulong)pbVar10[1];
        param_1 = pbVar10 + 2;
        if ((long)(int)(uVar12 - 1) <= (long)local_210) goto switchD_00131d54_caseD_3;
        puVar5 = local_200[(long)(int)(uVar12 - 1) - local_210];
      }
      else {
        if (0x15 < uVar14) {
          if (uVar14 == 0x19) goto LAB_00131ce0;
          if (0x19 < uVar14) goto LAB_00131da4;
          iVar4 = uVar12 - 1;
          iVar2 = uVar12 - 2;
          if (uVar14 == 0x16) {
            if ((int)uVar12 < 2) goto switchD_00131d54_caseD_3;
            puVar5 = local_200[iVar4];
            local_200[iVar4] = local_200[iVar2];
            local_200[iVar2] = puVar5;
          }
          else {
            if ((uVar14 != 0x17) || ((int)uVar12 < 3)) goto switchD_00131d54_caseD_3;
            puVar5 = local_200[iVar4];
            puVar11 = local_200[(int)(uVar12 - 3)];
            local_200[iVar4] = local_200[iVar2];
            local_200[iVar2] = puVar11;
            local_200[(int)(uVar12 - 3)] = puVar5;
          }
          goto LAB_00131998;
        }
        if (uVar14 == 0x12) {
          if (uVar12 == 0) goto switchD_00131d54_caseD_3;
          iVar4 = uVar12 - 1;
        }
        else {
          if (uVar14 < 0x12) {
            param_1 = (byte *)FUN_00130b04(param_1,&local_208);
            puVar5 = local_208;
            goto LAB_00131eb8;
          }
          if (uVar14 == 0x13) {
            if (uVar12 == 0) goto switchD_00131d54_caseD_3;
            uVar12 = uVar12 - 1;
            goto LAB_00131998;
          }
          if ((uVar14 != 0x14) || ((int)uVar12 < 2)) goto switchD_00131d54_caseD_3;
          iVar4 = uVar12 - 2;
        }
        puVar5 = local_200[iVar4];
      }
    }
    else {
LAB_00131ce0:
      if (uVar12 == 0) goto switchD_00131d54_caseD_3;
      uVar12 = uVar12 - 1;
      ppuVar9 = (ulong **)local_200[(int)uVar12];
      if (uVar13 == 0x1f) {
        puVar5 = (ulong *)-(long)ppuVar9;
      }
      else if (uVar13 < 0x20) {
        if (uVar13 == 6) {
switchD_00131d54_caseD_8:
          puVar5 = *ppuVar9;
        }
        else {
          if (bVar1 != 0x19) goto switchD_00131d54_caseD_3;
          puVar5 = (ulong *)(((ulong)ppuVar9 ^ (long)ppuVar9 >> 0x3f) - ((long)ppuVar9 >> 0x3f));
        }
      }
      else if (uVar13 == 0x23) {
        param_1 = (byte *)FUN_00130adc(param_1,&local_218);
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
          goto switchD_00131d54_caseD_3;
        case 4:
          puVar5 = (ulong *)(ulong)*(uint *)ppuVar9;
          break;
        case 8:
          goto switchD_00131d54_caseD_8;
        }
      }
      else {
        if (uVar13 != 0x20) goto switchD_00131d54_caseD_3;
        puVar5 = (ulong *)~(ulong)ppuVar9;
      }
    }
  }
  else if (uVar14 < 0x50) {
    if (0x2f < uVar13) {
      puVar5 = (ulong *)(ulong)(uVar13 - 0x30);
      goto LAB_00131eb8;
    }
    if (0x27 < uVar13) {
      if (uVar14 < 0x2f) {
        if (0x28 < uVar14) goto LAB_00131da4;
        if (uVar12 == 0) goto switchD_00131d54_caseD_3;
        uVar12 = uVar12 - 1;
        param_1 = pbVar10 + 3;
        if (local_200[(int)uVar12] != (ulong *)0x0) {
          param_1 = pbVar10 + 3 + *(short *)(pbVar10 + 1);
        }
      }
      else {
        param_1 = pbVar10 + (long)*(short *)(pbVar10 + 1) + 3;
      }
      goto LAB_00131998;
    }
    if ((uVar14 < 0x24) && (0x22 < uVar14)) goto LAB_00131ce0;
LAB_00131da4:
    if ((int)uVar12 < 2) goto switchD_00131d54_caseD_3;
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
      goto switchD_00131d54_caseD_3;
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
          goto LAB_00131c0c;
        }
        param_1 = (byte *)FUN_00130b04(param_1,&local_210);
        lVar7 = _Unwind_GetGR(param_3,uVar14 - 0x70);
      }
      else {
        if (uVar14 == 0x94) goto LAB_00131ce0;
        if (0x94 < uVar14) {
          if (uVar14 != 0x96) {
            if (uVar14 == 0xf1) {
              bVar1 = pbVar10[1];
              uVar6 = FUN_00130fb4(bVar1,param_3);
              param_1 = (byte *)FUN_00130b44(bVar1,uVar6,pbVar10 + 2,&local_208);
              puVar5 = local_208;
              goto LAB_00131eb8;
            }
            goto switchD_00131d54_caseD_3;
          }
          goto LAB_00131998;
        }
        if (bVar1 != 0x92) goto switchD_00131d54_caseD_3;
        uVar6 = FUN_00130adc(param_1,local_220);
        param_1 = (byte *)FUN_00130b04(uVar6,&local_210);
        lVar7 = _Unwind_GetGR(param_3,local_220[0]);
      }
      puVar5 = (ulong *)(lVar7 + local_210);
      goto LAB_00131eb8;
    }
    param_1 = (byte *)FUN_00130adc(param_1,local_220);
    iVar4 = local_220[0];
LAB_00131c0c:
    puVar5 = (ulong *)_Unwind_GetGR(param_3,iVar4);
  }
LAB_00131eb8:
  if (0x3f < uVar12) goto switchD_00131d54_caseD_3;
  local_200[(int)uVar12] = puVar5;
  uVar12 = uVar12 + 1;
  goto LAB_00131998;
}



void FUN_00131efc(void *param_1,long *param_2)

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
    FUN_00130d48(alStack_3c0,*(undefined8 *)((long)param_1 + 0x310),auStack_3d0);
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
LAB_00132044:
                    // WARNING: Subroutine does not return
      abort();
    }
    lVar3 = FUN_00130adc(param_2[199],&local_3c8);
    lVar3 = FUN_00131948(lVar3,lVar3 + local_3c8,alStack_3c0,0);
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
        goto LAB_00132034;
      }
      lVar4 = alStack_3c0[(int)*plVar7];
      break;
    case 3:
      lVar4 = FUN_00130adc(*plVar7,&local_3c8);
      lVar4 = FUN_00131948(lVar4,lVar4 + local_3c8,alStack_3c0,lVar3);
      break;
    case 4:
      lVar4 = lVar3 + *plVar7;
      goto LAB_00132034;
    case 5:
      lVar4 = FUN_00130adc(*plVar7,&local_3c8);
      lVar4 = FUN_00131948(lVar4,lVar4 + local_3c8,alStack_3c0,lVar3);
LAB_00132034:
      if ((byte)(&DAT_00157fd0)[lVar5] < 9) {
        *puVar6 = 1;
        goto LAB_001320b4;
      }
      goto LAB_00132044;
    default:
      goto switchD_0013200c_caseD_5;
    }
    if ((*(ulong *)((long)param_1 + 0x340) >> 0x3e & 1) != 0) {
      *puVar6 = 0;
    }
LAB_001320b4:
    *(long *)((long)param_1 + lVar5 * 8) = lVar4;
switchD_0013200c_caseD_5:
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



void FUN_00132108(void *param_1,undefined8 param_2,undefined8 param_3)

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
  iVar1 = FUN_00131524(param_1,auStack_680);
  if (iVar1 == 0) {
    iVar1 = pthread_once((pthread_once_t *)&DAT_00158034,FUN_00130c34);
    if ((iVar1 != 0) && (DAT_00157fd0 == '\0')) {
      FUN_00130c34();
    }
    FUN_00130d48(param_1,param_2,auStack_688);
    local_58 = 0;
    local_40 = 1;
    local_50 = 0x1f;
    FUN_00131efc(param_1,auStack_680);
    *(undefined8 *)((long)param_1 + 0x318) = param_3;
    return;
  }
                    // WARNING: Subroutine does not return
  abort();
}



void FUN_001321e4(long param_1,long param_2)

{
  undefined8 uVar1;
  
  FUN_00131efc();
  if (*(int *)(param_2 + *(long *)(param_2 + 0x668) * 0x10 + 8) == 6) {
    *(undefined8 *)(param_1 + 0x318) = 0;
  }
  else {
    uVar1 = _Unwind_GetGR(param_1);
    *(undefined8 *)(param_1 + 0x318) = uVar1;
  }
  return;
}



undefined8 FUN_00132230(undefined8 *param_1,long param_2)

{
  int iVar1;
  long lVar2;
  undefined8 uVar3;
  uint uVar4;
  undefined auStack_680 [1616];
  code *local_30;
  
  do {
    iVar1 = FUN_00131524(param_2,auStack_680);
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
    FUN_001321e4(param_2,auStack_680);
  } while( true );
}



undefined4 FUN_001322f0(undefined8 *param_1,undefined8 param_2)

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
    iVar1 = FUN_00131524(param_2,auStack_680);
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
    FUN_001321e4(param_2,auStack_680);
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
  iVar2 = FUN_00131524(auStack_a40,&local_680);
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



void FUN_001324d0(void)

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
  
  FUN_00132108(auStack_e00,&stack0x00000000);
  memcpy(auStack_a40,auStack_e00,0x3c0);
  do {
    iVar2 = FUN_00131524(auStack_a40,auStack_680);
    if ((iVar2 == 5) || (iVar2 != 0)) goto LAB_0013260c;
    if (local_30 != (code *)0x0) {
      iVar2 = (*local_30)(1,1,*param_1,param_1,auStack_a40);
      if (iVar2 == 6) {
        param_1[2] = 0;
        lVar3 = _Unwind_GetCFA(auStack_a40);
        param_1[3] = lVar3 + (local_700 >> 0x3f);
        memcpy(auStack_a40,auStack_e00,0x3c0);
        iVar2 = FUN_00132230(param_1,auStack_a40);
        if (iVar2 == 7) {
          FUN_00130ddc(auStack_e00,auStack_a40);
          FUN_001324d0(local_730,local_728);
        }
LAB_0013260c:
        auVar1._8_8_ = param_2;
        auVar1._0_8_ = param_1;
        return auVar1;
      }
      if (iVar2 != 8) goto LAB_0013260c;
    }
    FUN_001321e4(auStack_a40,auStack_680);
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
  
  FUN_00132108(auStack_780,&stack0x00000000);
  memcpy(auStack_3c0,auStack_780,0x3c0);
  *(undefined8 *)(param_1 + 0x10) = param_2;
  *(undefined8 *)(param_1 + 0x18) = param_3;
  iVar2 = FUN_001322f0(param_1,auStack_3c0);
  if (iVar2 == 7) {
    FUN_00130ddc(auStack_780,auStack_3c0);
    FUN_001324d0(local_b0,local_a8);
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
  
  FUN_00132108(auStack_780,&stack0x00000000);
  memcpy(auStack_3c0,auStack_780,0x3c0);
  if (*(long *)(param_1 + 0x10) == 0) {
    iVar2 = FUN_00132230(param_1,auStack_3c0);
  }
  else {
    iVar2 = FUN_001322f0(param_1,auStack_3c0);
  }
  if (iVar2 != 7) {
                    // WARNING: Subroutine does not return
    abort();
  }
  FUN_00130ddc(auStack_780,auStack_3c0);
  FUN_001324d0(local_b0,local_a8);
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
    FUN_00132108(auStack_780,&stack0x00000000);
    memcpy(auStack_3c0,auStack_780,0x3c0);
    iVar2 = FUN_001322f0(param_1,auStack_3c0);
    if (iVar2 != 7) {
                    // WARNING: Subroutine does not return
      abort();
    }
    FUN_00130ddc(auStack_780,auStack_3c0);
    FUN_001324d0(local_b0,local_a8);
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
  
  FUN_00132108(auStack_a40,&stack0x00000000);
  while (((iVar1 = FUN_00131524(auStack_a40,auStack_680), iVar1 == 5 || (iVar1 == 0)) &&
         (iVar2 = (*param_1)(auStack_a40,param_2), iVar2 == 0))) {
    if (iVar1 == 5) {
      return 5;
    }
    FUN_001321e4(auStack_a40,auStack_680);
  }
  return 3;
}



void FUN_00132a28(byte *param_1,ulong *param_2)

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



void FUN_00132a50(byte *param_1,ulong *param_2)

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



int FUN_00132a90(undefined8 param_1,long param_2,long param_3)

{
  int iVar1;
  
  iVar1 = -(uint)(*(ulong *)(param_2 + 8) < *(ulong *)(param_3 + 8));
  if (*(ulong *)(param_3 + 8) < *(ulong *)(param_2 + 8)) {
    iVar1 = 1;
  }
  return iVar1;
}



void FUN_00132aac(undefined8 param_1,code *param_2,long param_3,ulong param_4,int param_5)

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



void FUN_00132b6c(undefined8 param_1,undefined8 param_2,long param_3)

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
    FUN_00132aac(param_1,param_2,lVar2,uVar3,uVar6 & 0xffffffff);
  }
  lVar8 = 0;
  iVar5 = (int)uVar6 + -1;
  lVar1 = lVar2 + (long)iVar5 * 8;
  for (; 0 < iVar5; iVar5 = iVar5 + -1) {
    uVar4 = *(undefined8 *)(param_3 + 0x10);
    *(undefined8 *)(param_3 + 0x10) = *(undefined8 *)(lVar1 + lVar8);
    *(undefined8 *)(lVar1 + lVar8) = uVar4;
    lVar8 = lVar8 + -8;
    FUN_00132aac(param_1,param_2,lVar2,0,iVar5);
  }
  return;
}



undefined8 FUN_00132c20(byte param_1)

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



undefined8 FUN_00132c80(byte param_1,long param_2)

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



undefined8 FUN_00132ce0(byte param_1,long param_2)

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



ulong ** FUN_00132d40(byte param_1,ulong **param_2,ulong **param_3,ulong **param_4)

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
      ppuVar1 = (ulong **)FUN_00132a28(param_3,&local_8);
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
      ppuVar1 = (ulong **)FUN_00132a50(param_3,&local_8);
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



int FUN_00132e30(long param_1,long param_2,long param_3)

{
  int iVar1;
  ushort uVar2;
  undefined8 uVar3;
  ulong local_10;
  ulong local_8;
  
  uVar2 = *(ushort *)(param_1 + 0x20) >> 3 & 0xff;
  uVar3 = FUN_00132c80(uVar2,param_1);
  FUN_00132d40(uVar2,uVar3,param_2 + 8,&local_10);
  FUN_00132d40(*(ushort *)(param_1 + 0x20) >> 3,uVar3,param_3 + 8,&local_8);
  iVar1 = -(uint)(local_10 < local_8);
  if (local_8 < local_10) {
    iVar1 = 1;
  }
  return iVar1;
}



byte FUN_00132ec0(long param_1)

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
    uVar4 = FUN_00132a28(pcVar7,auStack_10);
    lVar5 = FUN_00132a50(uVar4,auStack_8);
    if (*(char *)(param_1 + 8) == '\x01') {
      lVar5 = lVar5 + 1;
    }
    else {
      lVar5 = FUN_00132a28(lVar5,auStack_10);
    }
    pbVar6 = (byte *)FUN_00132a28(lVar5,auStack_10);
    for (pcVar8 = (char *)(param_1 + 10); cVar1 = *pcVar8, cVar1 != 'R'; pcVar8 = pcVar8 + 1) {
      if (cVar1 == 'P') {
        pbVar6 = (byte *)FUN_00132d40(*pbVar6 & 0x7f,0,pbVar6 + 1,auStack_18);
      }
      else {
        if (cVar1 != 'L') goto LAB_00132f18;
        pbVar6 = pbVar6 + 1;
      }
    }
    bVar2 = *pbVar6;
  }
  else {
LAB_00132f18:
    bVar2 = 0;
  }
  return bVar2;
}



uint * FUN_00132fbc(long param_1,uint *param_2,long param_3)

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
  uVar2 = FUN_00132c80(uVar1,param_1);
  lVar3 = 0;
  do {
    if (*param_2 == 0) {
      return (uint *)0x0;
    }
    if (param_2[1] != 0) {
      lVar7 = lVar3;
      if (((*(byte *)(param_1 + 0x20) >> 2 & 1) != 0) &&
         (lVar7 = (long)param_2 + (4 - (long)(int)param_2[1]), lVar7 != lVar3)) {
        uVar4 = FUN_00132ec0(lVar7);
        uVar1 = uVar4 & 0xffffffff;
        uVar2 = FUN_00132c80(uVar4,param_1);
      }
      if ((uint)uVar1 == 0) {
        local_10 = *(ulong *)(param_2 + 2);
        local_8 = *(ulong *)(param_2 + 4);
        uVar4 = local_10;
      }
      else {
        uVar5 = FUN_00132d40(uVar1 & 0xff,uVar2,param_2 + 2,&local_10);
        FUN_00132d40((uint)uVar1 & 0xf,0,uVar5,&local_8);
        uVar4 = FUN_00132c20(uVar1 & 0xff);
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



void FUN_0013311c(long param_1)

{
  FUN_00132ec0((param_1 + 4) - (long)*(int *)(param_1 + 4));
  return;
}



undefined8 FUN_0013312c(ulong *param_1,ulong param_2,ulong *param_3)

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
    if ((param_1[4] == DAT_00146030) && (param_1[5] == DAT_00158040)) {
      puVar18 = DAT_00158048;
      puVar12 = (ulong *)0x0;
      puVar16 = (ulong *)0x0;
      while (puVar10 = puVar18, puVar10 != (ulong *)0x0) {
        if ((*puVar10 <= *param_3) && (*param_3 < puVar10[1])) {
          uVar17 = puVar10[2];
          piVar15 = (int *)puVar10[3];
          if (puVar10 != DAT_00158048) {
            puVar16[5] = puVar10[5];
            puVar10[5] = (ulong)DAT_00158048;
            DAT_00158048 = puVar10;
          }
          goto LAB_00133338;
        }
        puVar12 = puVar10;
        if ((*puVar10 | puVar10[1]) == 0) break;
        puVar18 = (ulong *)puVar10[5];
        if (puVar18 != (ulong *)0x0) {
          puVar16 = puVar10;
        }
      }
      goto LAB_00133254;
    }
    puVar11 = &DAT_00158080;
    DAT_00146030 = param_1[4];
    DAT_00158040 = param_1[5];
    do {
      puVar11[-6] = 0;
      puVar11[-5] = 0;
      puVar11[-1] = puVar11;
      puVar11 = puVar11 + 6;
    } while (puVar11 != (undefined8 *)0x158200);
    DAT_001581c8 = 0;
    DAT_00158048 = &DAT_00158050;
    *(undefined4 *)(param_3 + 5) = 0;
  }
  puVar16 = (ulong *)0x0;
  puVar12 = (ulong *)0x0;
LAB_00133254:
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
      puVar12[5] = (ulong)DAT_00158048;
      DAT_00158048 = puVar12;
    }
    puVar12 = DAT_00158048;
    DAT_00158048[2] = uVar17;
    puVar12[3] = (ulong)piVar15;
    puVar12[4] = (ulong)piVar20;
    *puVar12 = uVar19;
    puVar12[1] = uVar13;
  }
LAB_00133338:
  if (piVar15 == (int *)0x0) {
    return 0;
  }
  lVar1 = uVar17 + *(long *)(piVar15 + 4);
  if (*(char *)(uVar17 + *(long *)(piVar15 + 4)) != '\x01') {
    return 1;
  }
  uVar7 = *(undefined *)(lVar1 + 1);
  uVar8 = FUN_00132ce0(uVar7,param_3);
  uVar8 = FUN_00132d40(uVar7,uVar8,lVar1 + 4,&local_40);
  cVar3 = *(char *)(lVar1 + 2);
  if ((cVar3 != -1) && (*(char *)(lVar1 + 3) == ';')) {
    uVar9 = FUN_00132ce0(cVar3,param_3);
    piVar14 = (int *)FUN_00132d40(cVar3,uVar9,uVar8,&local_38);
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
      bVar6 = FUN_0013311c(uVar17);
      uVar13 = FUN_00132c20(bVar6);
      FUN_00132d40(bVar6 & 0xf,0,uVar17 + (uVar13 & 0xffffffff) + 8,&local_30);
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
  uVar17 = FUN_00132fbc(&local_30,local_40,*param_3);
  param_3[4] = uVar17;
  if (uVar17 != 0) {
    uVar7 = FUN_0013311c();
    uVar8 = FUN_00132ce0(uVar7,param_3);
    FUN_00132d40(uVar7,uVar8,param_3[4] + 8,&local_38);
    param_3[3] = local_38;
  }
  return 1;
}



int FUN_0013354c(undefined8 param_1,long param_2,long param_3)

{
  int iVar1;
  undefined uVar2;
  undefined8 uVar3;
  ulong local_10;
  ulong local_8;
  
  uVar2 = FUN_0013311c(param_2);
  uVar3 = FUN_00132c80(uVar2,param_1);
  FUN_00132d40(uVar2,uVar3,param_2 + 8,&local_10);
  uVar2 = FUN_0013311c(param_3);
  uVar3 = FUN_00132c80(uVar2,param_1);
  FUN_00132d40(uVar2,uVar3,param_3 + 8,&local_8);
  iVar1 = -(uint)(local_10 < local_8);
  if (local_8 < local_10) {
    iVar1 = 1;
  }
  return iVar1;
}



long FUN_001335e8(ulong *param_1,uint *param_2)

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
        uVar2 = FUN_00132ec0(lVar6);
        if (uVar2 == 0xff) {
          return -1;
        }
        uVar8 = FUN_00132c80((char)uVar2,param_1);
        uVar1 = *(ushort *)(param_1 + 4);
        lVar3 = lVar6;
        if ((uVar1 & 0x7f8) == 0x7f8) {
          *(ushort *)(param_1 + 4) = uVar1 & 0xf800 | uVar1 & 7 | (ushort)((uVar2 & 0xff) << 3);
        }
        else if ((uVar1 >> 3 & 0xff) != uVar2) {
          *(byte *)(param_1 + 4) = *(byte *)(param_1 + 4) | 4;
        }
      }
      FUN_00132d40(uVar2 & 0xff,uVar8,param_2 + 2,&local_8);
      uVar4 = FUN_00132c20(uVar2 & 0xff);
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



void FUN_00133748(long param_1,long *param_2,uint *param_3)

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
  uVar2 = FUN_00132c80(uVar1,param_1);
  lVar3 = 0;
  for (; *param_3 != 0; param_3 = (uint *)((long)param_3 + (ulong)*param_3 + 4)) {
    if (param_3[1] != 0) {
      lVar7 = lVar3;
      if (((*(byte *)(param_1 + 0x20) >> 2 & 1) != 0) &&
         (lVar7 = (long)param_3 + (4 - (long)(int)param_3[1]), lVar7 != lVar3)) {
        uVar4 = FUN_00132ec0(lVar7);
        uVar1 = uVar4 & 0xffffffff;
        uVar2 = FUN_00132c80(uVar4,param_1);
      }
      if ((int)uVar1 == 0) {
        uVar4 = *(ulong *)(param_3 + 2);
      }
      else {
        FUN_00132d40(uVar1 & 0xff,uVar2,param_3 + 2,&local_8);
        uVar5 = FUN_00132c20(uVar1 & 0xff);
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



long FUN_0013387c(ulong *param_1,ulong param_2)

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
  
  if ((*(byte *)(param_1 + 4) & 1) != 0) goto LAB_001338a8;
  uVar17 = (ulong)(*(uint *)(param_1 + 4) >> 0xb);
  if (uVar17 == 0) {
    if ((*(byte *)(param_1 + 4) >> 1 & 1) == 0) {
      uVar17 = FUN_001335e8(param_1,param_1[3]);
      if (uVar17 != 0xffffffffffffffff) goto LAB_00133920;
LAB_001338e0:
      param_1[4] = 0;
      *(undefined2 *)(param_1 + 4) = 0x7f8;
      param_1[3] = (ulong)&DAT_001581d8;
    }
    else {
      for (plVar12 = (long *)param_1[3]; *plVar12 != 0; plVar12 = plVar12 + 1) {
        lVar10 = FUN_001335e8(param_1);
        if (lVar10 == -1) goto LAB_001338e0;
        uVar17 = uVar17 + lVar10;
      }
LAB_00133920:
      uVar6 = (uint)uVar17 & 0x1fffff;
      if (uVar6 == uVar17) {
        uVar6 = *(uint *)(param_1 + 4) & 0x7ff | uVar6 << 0xb;
      }
      else {
        uVar6 = *(uint *)(param_1 + 4) & 0x7ff;
      }
      *(uint *)(param_1 + 4) = uVar6;
      if (uVar17 != 0) goto LAB_00133948;
    }
  }
  else {
LAB_00133948:
    __size = (uVar17 + 2) * 8;
    local_10 = (ulong *)malloc(__size);
    if (local_10 != (ulong *)0x0) {
      local_10[1] = 0;
      local_8 = malloc(__size);
      if (local_8 != (void *)0x0) {
        *(undefined8 *)((long)local_8 + 8) = 0;
      }
      if ((*(byte *)(param_1 + 4) >> 1 & 1) == 0) {
        FUN_00133748(param_1,&local_10,param_1[3]);
      }
      else {
        for (plVar12 = (long *)param_1[3]; *plVar12 != 0; plVar12 = plVar12 + 1) {
          FUN_00133748(param_1,&local_10);
        }
      }
      pvVar4 = local_8;
      puVar3 = local_10;
      if ((local_10 != (ulong *)0x0) && (local_10[1] != uVar17)) {
LAB_00133ca0:
                    // WARNING: Subroutine does not return
        abort();
      }
      if ((*(byte *)(param_1 + 4) >> 2 & 1) == 0) {
        if ((*(ushort *)(param_1 + 4) & 0x7f8) == 0) {
          pcVar16 = FUN_00132a90;
        }
        else {
          pcVar16 = FUN_00132e30;
        }
      }
      else {
        pcVar16 = FUN_0013354c;
      }
      if (local_8 == (void *)0x0) {
        FUN_00132b6c(param_1,pcVar16,local_10);
      }
      else {
        puVar18 = local_10 + 2;
        uVar20 = local_10[1];
        puVar14 = &DAT_001581d0;
        puVar21 = puVar18;
        for (uVar13 = 0; uVar13 != uVar20; uVar13 = uVar13 + 1) {
          while ((puVar14 != &DAT_001581d0 &&
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
        if (*(long *)((long)local_8 + 8) + local_10[1] != uVar17) goto LAB_00133ca0;
        FUN_00132b6c(param_1,pcVar16);
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
LAB_001338a8:
  bVar5 = *(byte *)(param_1 + 4);
  if ((bVar5 & 1) == 0) {
    if ((bVar5 >> 1 & 1) == 0) {
      lVar10 = FUN_00132fbc(param_1,param_1[3],param_2);
      return lVar10;
    }
    for (plVar12 = (long *)param_1[3]; *plVar12 != 0; plVar12 = plVar12 + 1) {
      lVar10 = FUN_00132fbc(param_1,*plVar12,param_2);
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
      uVar8 = FUN_00132c80(uVar2,param_1);
      uVar13 = *(ulong *)(uVar20 + 8);
      while (uVar11 = uVar13, uVar17 < uVar11) {
        uVar13 = uVar11 + uVar17 >> 1;
        lVar10 = *(long *)(uVar20 + (uVar13 + 2) * 8);
        uVar9 = FUN_00132d40(uVar2,uVar8,lVar10 + 8,&local_18);
        FUN_00132d40(uVar1 & 0xf,0,uVar9,&local_10);
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
      bVar5 = FUN_0013311c(lVar10);
      uVar8 = FUN_00132c80(bVar5,param_1);
      uVar8 = FUN_00132d40(bVar5,uVar8,lVar10 + 8,&local_18);
      FUN_00132d40(bVar5 & 0xf,0,uVar8,&local_10);
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
    pthread_mutex_lock((pthread_mutex_t *)&DAT_001581e0);
    param_2[5] = DAT_00158208;
    DAT_00158208 = param_2;
    uVar1 = pthread_mutex_unlock((pthread_mutex_t *)&DAT_001581e0);
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



// WARNING: Removing unreachable block (ram,0x00133f5c)

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
  pthread_mutex_lock((pthread_mutex_t *)&DAT_001581e0);
  param_2[5] = DAT_00158208;
  DAT_00158208 = param_2;
  iVar1 = pthread_mutex_unlock((pthread_mutex_t *)&DAT_001581e0);
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
  pthread_mutex_lock((pthread_mutex_t *)&DAT_001581e0);
  plVar1 = &DAT_00158208;
  for (lVar2 = DAT_00158208; lVar2 != 0; lVar2 = *(long *)(lVar2 + 0x28)) {
    if (*(int **)(lVar2 + 0x18) == param_1) goto LAB_00134030;
    plVar1 = (long *)(lVar2 + 0x28);
  }
  plVar1 = &DAT_00158210;
  while (lVar2 = *plVar1, lVar2 != 0) {
    if ((*(byte *)(lVar2 + 0x20) & 1) == 0) {
      if (*(int **)(lVar2 + 0x18) == param_1) goto LAB_00134030;
    }
    else if (**(int ***)(lVar2 + 0x18) == param_1) {
      *plVar1 = *(long *)(lVar2 + 0x28);
      free(*(void **)(lVar2 + 0x18));
      break;
    }
    plVar1 = (long *)(lVar2 + 0x28);
  }
LAB_00134070:
  pthread_mutex_unlock((pthread_mutex_t *)&DAT_001581e0);
  if (lVar2 != 0) {
    return lVar2;
  }
                    // WARNING: Subroutine does not return
  abort();
LAB_00134030:
  *plVar1 = *(long *)(lVar2 + 0x28);
  goto LAB_00134070;
}



long __deregister_frame_info(int *param_1)

{
  long *plVar1;
  long lVar2;
  
  if ((param_1 == (int *)0x0) || (*param_1 == 0)) {
    return 0;
  }
  pthread_mutex_lock((pthread_mutex_t *)&DAT_001581e0);
  plVar1 = &DAT_00158208;
  for (lVar2 = DAT_00158208; lVar2 != 0; lVar2 = *(long *)(lVar2 + 0x28)) {
    if (*(int **)(lVar2 + 0x18) == param_1) goto LAB_00134030;
    plVar1 = (long *)(lVar2 + 0x28);
  }
  plVar1 = &DAT_00158210;
  while (lVar2 = *plVar1, lVar2 != 0) {
    if ((*(byte *)(lVar2 + 0x20) & 1) == 0) {
      if (*(int **)(lVar2 + 0x18) == param_1) goto LAB_00134030;
    }
    else if (**(int ***)(lVar2 + 0x18) == param_1) {
      *plVar1 = *(long *)(lVar2 + 0x28);
      free(*(void **)(lVar2 + 0x18));
      break;
    }
    plVar1 = (long *)(lVar2 + 0x28);
  }
LAB_00134070:
  pthread_mutex_unlock((pthread_mutex_t *)&DAT_001581e0);
  if (lVar2 != 0) {
    return lVar2;
  }
                    // WARNING: Subroutine does not return
  abort();
LAB_00134030:
  *plVar1 = *(long *)(lVar2 + 0x28);
  goto LAB_00134070;
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



// WARNING: Removing unreachable block (ram,0x0013426c)

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
  
  pthread_mutex_lock((pthread_mutex_t *)&DAT_001581e0);
  for (puVar7 = DAT_00158210; puVar7 != (ulong *)0x0; puVar7 = (ulong *)puVar7[5]) {
    if (*puVar7 <= param_1) {
      local_10 = FUN_0013387c(puVar7,param_1);
      if (local_10 != 0) goto LAB_001341a4;
      break;
    }
  }
  do {
    puVar7 = DAT_00158208;
    if (DAT_00158208 == (ulong *)0x0) {
      local_10 = 0;
      break;
    }
    DAT_00158208 = (ulong *)DAT_00158208[5];
    local_10 = FUN_0013387c(puVar7,param_1);
    ppuVar4 = &DAT_00158210;
    for (puVar6 = DAT_00158210; (puVar6 != (ulong *)0x0 && (*puVar7 <= *puVar6));
        puVar6 = (ulong *)puVar6[5]) {
      ppuVar4 = (ulong **)(puVar6 + 5);
    }
    puVar7[5] = (ulong)puVar6;
    *ppuVar4 = puVar7;
  } while (local_10 == 0);
LAB_001341a4:
  pthread_mutex_unlock((pthread_mutex_t *)&DAT_001581e0);
  if (local_10 == 0) {
    local_8 = 1;
    local_28 = 0;
    local_20 = 0;
    local_18 = 0;
    local_10 = 0;
    local_30 = param_1;
    iVar3 = dl_iterate_phdr(FUN_0013312c,&local_30);
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
      uVar2 = FUN_0013311c(local_10);
    }
    uVar5 = FUN_00132c80(uVar2 & 0xff,puVar7);
    FUN_00132d40(uVar2 & 0xff,uVar5,local_10 + 8,&local_30);
  }
  param_2[2] = local_30;
  return local_10;
}


