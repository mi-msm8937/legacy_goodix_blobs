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

typedef union sem_t sem_t, *Psem_t;

union sem_t {
    char __size[32];
    long __align;
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

typedef struct _IO_FILE FILE;

typedef long __ssize_t;

typedef __ssize_t ssize_t;

typedef int __clockid_t;

typedef uint __mode_t;

typedef long __time_t;

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

typedef struct __dirstream __dirstream, *P__dirstream;

struct __dirstream {
};

typedef struct __dirstream DIR;

typedef __clockid_t clockid_t;

typedef struct timespec timespec, *Ptimespec;

struct timespec {
    __time_t tv_sec;
    long tv_nsec;
};

typedef struct st_fingerprint_hal_device_t st_fingerprint_hal_device_t, *Pst_fingerprint_hal_device_t;

struct st_fingerprint_hal_device_t { // PlaceHolder Structure
};

typedef struct FingerMSDeathNotifier FingerMSDeathNotifier, *PFingerMSDeathNotifier;

struct FingerMSDeathNotifier { // PlaceHolder Structure
};

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

typedef struct Parcel Parcel, *PParcel;

struct Parcel { // PlaceHolder Structure
};

typedef dword FpClientType;

typedef struct sp<android::IBinder> sp<android::IBinder>, *Psp<android::IBinder>;

struct sp<android::IBinder> { // PlaceHolder Structure
};

typedef struct String16 String16, *PString16;

struct String16 { // PlaceHolder Structure
};

typedef struct RefBase RefBase, *PRefBase;

struct RefBase { // PlaceHolder Structure
};

typedef struct sp sp, *Psp;

struct sp { // PlaceHolder Structure
};

typedef struct wp wp, *Pwp;

struct wp { // PlaceHolder Structure
};

typedef struct sp<FingerMSDeathNotifier> sp<FingerMSDeathNotifier>, *Psp<FingerMSDeathNotifier>;

struct sp<FingerMSDeathNotifier> { // PlaceHolder Structure
};

typedef struct BBinder BBinder, *PBBinder;

struct BBinder { // PlaceHolder Structure
};

typedef struct sp<android::GxFpDevice> sp<android::GxFpDevice>, *Psp<android::GxFpDevice>;

struct sp<android::GxFpDevice> { // PlaceHolder Structure
};

typedef struct GxFpDevice GxFpDevice, *PGxFpDevice;

struct GxFpDevice { // PlaceHolder Structure
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




void FUN_00107900(void)

{
  (*(code *)(undefined *)0x0)();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void android::Parcel::writeString16(String16 *param_1)

{
  writeString16(param_1);
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

FILE * fopen(char *__filename,char *__modes)

{
  FILE *pFVar1;
  
  pFVar1 = fopen(__filename,__modes);
  return pFVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void android::Fp::gx_Match(void *param_1)

{
  gx_Match(param_1);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void android::Parcel::readInt32(int *param_1)

{
  readInt32(param_1);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int sem_destroy(sem_t *__sem)

{
  int iVar1;
  
  iVar1 = sem_destroy(__sem);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

DIR * opendir(char *__name)

{
  DIR *pDVar1;
  
  pDVar1 = opendir(__name);
  return pDVar1;
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

void android::defaultServiceManager(void)

{
  defaultServiceManager();
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

void android::Parcel::writeInt32(int param_1)

{
  writeInt32(param_1);
  return;
}



void __system_property_get(void)

{
  __system_property_get();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int pthread_join(pthread_t __th,void **__thread_return)

{
  int iVar1;
  
  iVar1 = pthread_join(__th,__thread_return);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void android::RefBase::onLastWeakRef(void *param_1)

{
  onLastWeakRef(param_1);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int clock_gettime(clockid_t __clock_id,timespec *__tp)

{
  int iVar1;
  
  iVar1 = clock_gettime(__clock_id,__tp);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void free(void *__ptr)

{
  free(__ptr);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

size_t fread(void *__ptr,size_t __size,size_t __n,FILE *__stream)

{
  size_t sVar1;
  
  sVar1 = fread(__ptr,__size,__n,__stream);
  return sVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void android::Fp::gx_set_fpdb_to_ta(char *param_1)

{
  gx_set_fpdb_to_ta(param_1);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void android::Parcel::dataSize(void)

{
  dataSize();
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

int mkdir(char *__path,__mode_t __mode)

{
  int iVar1;
  
  iVar1 = mkdir(__path,__mode);
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

void android::Fp::gx_gfCmdM
               (int param_1,uchar *param_2,int param_3,uchar *param_4,int param_5,int *param_6)

{
  gx_gfCmdM(param_1,param_2,param_3,param_4,param_5,param_6);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void * malloc(size_t __size)

{
  void *pvVar1;
  
  pvVar1 = malloc(__size);
  return pvVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void android::Fp::gx_UnRegister(int param_1)

{
  gx_UnRegister(param_1);
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

int sem_post(sem_t *__sem)

{
  int iVar1;
  
  iVar1 = sem_post(__sem);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int rand(void)

{
  int iVar1;
  
  iVar1 = rand();
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

int pthread_once(pthread_once_t *__once_control,__init_routine *__init_routine)

{
  int iVar1;
  
  iVar1 = pthread_once(__once_control,__init_routine);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

size_t strlen(char *__s)

{
  size_t sVar1;
  
  sVar1 = strlen(__s);
  return sVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int fclose(FILE *__stream)

{
  int iVar1;
  
  iVar1 = fclose(__stream);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void * realloc(void *__ptr,size_t __size)

{
  void *pvVar1;
  
  pvVar1 = realloc(__ptr,__size);
  return pvVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void android::RefBase::decStrong(void *param_1)

{
  decStrong(param_1);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void android::Fp::gx_getFpTemplateList(uint *param_1,uint *param_2,char **param_3)

{
  gx_getFpTemplateList(param_1,param_2,param_3);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int strncmp(char *__s1,char *__s2,size_t __n)

{
  int iVar1;
  
  iVar1 = strncmp(__s1,__s2,__n);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void android::Fp::gx_set_user_id(ulong param_1)

{
  gx_set_user_id(param_1);
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

void android::Parcel::readDouble(double *param_1)

{
  readDouble(param_1);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int snprintf(char *__s,size_t __maxlen,char *__format,...)

{
  int iVar1;
  
  iVar1 = snprintf(__s,__maxlen,__format);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int pthread_attr_setdetachstate(pthread_attr_t *__attr,int __detachstate)

{
  int iVar1;
  
  iVar1 = pthread_attr_setdetachstate(__attr,__detachstate);
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

void android::Fp::remote(void)

{
  remote();
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

void android::Fp::connect(FpClientType param_1)

{
  connect(param_1);
  return;
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

int pthread_cond_wait(pthread_cond_t *__cond,pthread_mutex_t *__mutex)

{
  int iVar1;
  
  iVar1 = pthread_cond_wait(__cond,__mutex);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void android::Fp::gx_Register(void)

{
  gx_Register();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void android::Fp::gx_EngTest(int param_1)

{
  gx_EngTest(param_1);
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



// WARNING: Unknown calling convention -- yet parameter storage is locked

void pthread_exit(void *__retval)

{
                    // WARNING: Subroutine does not return
  pthread_exit(__retval);
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void android::Fp::gx_RegisterSave(int param_1)

{
  gx_RegisterSave(param_1);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void android::Fp::gx_setSafeClass(uint param_1)

{
  gx_setSafeClass(param_1);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void android::Fp::gx_MatchCancel(void)

{
  gx_MatchCancel();
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

void android::Fp::setListener(sp *param_1)

{
  setListener(param_1);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int pthread_cond_signal(pthread_cond_t *__cond)

{
  int iVar1;
  
  iVar1 = pthread_cond_signal(__cond);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int sem_init(sem_t *__sem,int __pshared,uint __value)

{
  int iVar1;
  
  iVar1 = sem_init(__sem,__pshared,__value);
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

void abort(void)

{
                    // WARNING: Subroutine does not return
  abort();
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

int atoi(char *__nptr)

{
  int iVar1;
  
  iVar1 = atoi(__nptr);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void android::Fp::gx_load_all_fpdata(void *param_1)

{
  gx_load_all_fpdata(param_1);
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



void __errno(void)

{
  __errno();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void android::Fp::gx_RegisterCancel(void)

{
  gx_RegisterCancel();
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



// WARNING: Unknown calling convention -- yet parameter storage is locked

void android::Fp::gx_enableFingerScreenUnlock(void)

{
  gx_enableFingerScreenUnlock();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int pthread_mutex_lock(pthread_mutex_t *__mutex)

{
  int iVar1;
  
  iVar1 = pthread_mutex_lock(__mutex);
  return iVar1;
}



void __cxa_finalize(void)

{
  __cxa_finalize();
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

void android::Parcel::readString16(void)

{
  readString16();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void android::RefBase::onFirstRef(void)

{
  onFirstRef();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void android::Parcel::readExceptionCode(void)

{
  readExceptionCode();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int pthread_attr_init(pthread_attr_t *__attr)

{
  int iVar1;
  
  iVar1 = pthread_attr_init(__attr);
  return iVar1;
}



void __stack_chk_fail(void)

{
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void android::Fp::gx_disableFingerScreenUnlock(void)

{
  gx_disableFingerScreenUnlock();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int puts(char *__s)

{
  int iVar1;
  
  iVar1 = puts(__s);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int fputs(char *__s,FILE *__stream)

{
  int iVar1;
  
  iVar1 = fputs(__s,__stream);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int pthread_cond_init(pthread_cond_t *__cond,pthread_condattr_t *__cond_attr)

{
  int iVar1;
  
  iVar1 = pthread_cond_init(__cond,__cond_attr);
  return iVar1;
}



void __thiscall android::BBinder::BBinder(BBinder *this)

{
  BBinder(this);
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

void android::Fp::gx_delFpTemplates(uint *param_1,uint param_2)

{
  gx_delFpTemplates(param_1,param_2);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int closedir(DIR *__dirp)

{
  int iVar1;
  
  iVar1 = closedir(__dirp);
  return iVar1;
}



void entry(void)

{
  __cxa_finalize(&DAT_0013c000);
  return;
}



void _INIT_0(void)

{
  sGxFpDevice = 0;
  __cxa_atexit(android::sp<>::~sp,&sGxFpDevice,&DAT_0013c000);
  return;
}



void _INIT_1(void)

{
  long *this;
  
  gFingerPrintMSBinder = 0;
  __cxa_atexit(android::sp<>::~sp,&gFingerPrintMSBinder,&DAT_0013c000);
  gFingerMSDeathNotifier = 0;
  __cxa_atexit(android::sp<>::~sp,&gFingerMSDeathNotifier,&DAT_0013c000);
  gPmsBinder = 0;
  __cxa_atexit(android::sp<>::~sp,&gPmsBinder,&DAT_0013c000);
  this = (long *)operator_new(0x28);
  android::BBinder::BBinder((BBinder *)this);
  gToken = this;
  android::RefBase::incStrong((BBinder *)((long)this + *(long *)(*this + -0x18)));
  __cxa_atexit(android::sp<>::~sp,&gToken,&DAT_0013c000);
  return;
}



void _INIT_2(void)

{
  DAT_0013e300 = 0;
  DAT_0013e308 = 0;
  DAT_0013e310 = 0;
  DAT_0013e318 = 0;
  DAT_0013e320 = 0;
  return;
}



void _INIT_3(void)

{
  int iVar1;
  
  DAT_0014e344 = 0;
  iVar1 = pthread_key_create(&DAT_0014e340,FUN_001107b4);
  DAT_0014e344 = iVar1 == 0;
  __cxa_atexit(FUN_00110798,&DAT_0014e340,&DAT_0013c000);
  return;
}



void FUN_001080bc(code *param_1)

{
  if (param_1 != (code *)0x0) {
    (*param_1)();
  }
  return;
}



undefined8 FUN_001080ec(long param_1)

{
  __android_log_print(3,"FingerGoodix","fpcode, fingerprint_get_auth_id(%p) = %lu",param_1,
                      *(undefined8 *)(param_1 + 0x1d8));
  return *(undefined8 *)(param_1 + 0x1d8);
}



undefined8 FUN_0010812c(long param_1)

{
  __android_log_print(3,"FingerGoodix","post_enroll");
  *(undefined8 *)(param_1 + 0x1c0) = 0;
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00108168(undefined8 param_1,undefined8 param_2,undefined8 *param_3)

{
  int iVar1;
  undefined4 *__s;
  undefined8 uVar2;
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
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","fpcode, fingerprint_open(), merged");
  if (param_3 == (undefined8 *)0x0) {
    __android_log_print(6,"FingerGoodix","NULL device on open");
    uVar2 = 0xffffffea;
  }
  else {
    __android_log_print(3,"FingerGoodix","fingerprint open");
    __s = (undefined4 *)malloc(0x210);
    memset(__s,0,0x210);
    *(undefined8 *)(__s + 2) = param_1;
    *__s = 0x48574454;
    __s[1] = 0x200;
    *(code **)(__s + 0x1c) = FUN_00108c54;
    *(code **)(__s + 0x22) = FUN_00108bc4;
    *(code **)(__s + 0x26) = FUN_0010812c;
    *(code **)(__s + 0x24) = FUN_00108a54;
    *(undefined8 *)(__s + 0x76) = 0xdeadbeef;
    *(code **)(__s + 0x28) = FUN_001080ec;
    local_18 = 0;
    *(code **)(__s + 0x30) = FUN_001089ec;
    local_10 = 0;
    *(code **)(__s + 0x32) = FUN_0010885c;
    *(code **)(__s + 0x2a) = FUN_00108780;
    *(code **)(__s + 0x2c) = FUN_00108534;
    *(code **)(__s + 0x2e) = FUN_001084a8;
    *(code **)(__s + 0x20) = FUN_0010842c;
    *(code **)(__s + 0x34) = FUN_0010839c;
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
    iVar1 = __system_property_get("ro.template.count",&local_68);
    if (iVar1 < 1) {
      iVar1 = 8;
    }
    else {
      iVar1 = atoi((char *)&local_68);
      if (iVar1 < 1) {
        iVar1 = 8;
      }
    }
    __s[0x6c] = iVar1;
    __android_log_print(3,"FingerGoodix","Max fp number: %d",iVar1);
    pthread_mutex_init((pthread_mutex_t *)(__s + 0x79),(pthread_mutexattr_t *)0x0);
    __s[0x4b] = 3;
    createListenerThread(__s);
    goodix_sensor_set_active_group(__s,0,"/data/system/users/0/fpdata/");
    *param_3 = __s;
    __android_log_print(3,"FingerGoodix","lichi reduce =====  checkConsistence");
    uVar2 = 0;
  }
  if (local_8 != ___stack_chk_guard) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail(uVar2);
  }
  return;
}



undefined8
FUN_0010839c(undefined8 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            undefined8 param_5,ulong param_6)

{
  __android_log_print(3,"FingerGoodix","fpcode, fingerprint_gxCmd(%d, %d, %d, %p, %d)",param_2,
                      param_3,param_4,param_5,param_6 & 0xffffffff);
  loadFingerPrintPlatformDataIfNeed(param_1);
  goodix_sensor_fp_gxCmd(param_2,param_3,param_4,param_5,param_6);
  return 0;
}



undefined8 FUN_0010842c(long param_1,undefined8 param_2)

{
  __android_log_print(3,"FingerGoodix","set_notify");
  __android_log_print(3,"FingerGoodix","fpcode, set_notify_callback(%p, %p)",param_1,param_2);
  pthread_mutex_lock((pthread_mutex_t *)(param_1 + 0x1e4));
  *(undefined8 *)(param_1 + 0x78) = param_2;
  pthread_mutex_unlock((pthread_mutex_t *)(param_1 + 0x1e4));
  return 0;
}



undefined4 FUN_001084a8(undefined8 param_1,undefined4 param_2,undefined4 param_3)

{
  undefined4 uVar1;
  
  loadFingerPrintPlatformDataIfNeed();
  pthread_mutex_lock((pthread_mutex_t *)&DAT_0013c140);
  __android_log_print(3,"FingerGoodix","fpcode, fingerprint_remove(%p, %d, %d)",param_1,param_2,
                      param_3);
  loadFingerPrintPlatformDataIfNeed(param_1);
  uVar1 = goodix_sensor_fp_remove(param_1,param_3,param_2);
  pthread_mutex_unlock((pthread_mutex_t *)&DAT_0013c140);
  return uVar1;
}



int FUN_00108534(undefined8 param_1)

{
  int iVar1;
  
  __android_log_print(3,"FingerGoodix","fpcode, fingerprint_enumerate N(%p)",param_1);
  if (DAT_0013c168 == 0) {
    iVar1 = gf_worker_thread_create(&DAT_0013c168);
    if (iVar1 != 0) {
      puts("creat worker threat fail");
      return iVar1;
    }
  }
  iVar1 = gf_send_callback_msg(DAT_0013c168,param_1,FUN_00108604);
  if (iVar1 != 0) {
    __android_log_print(3,"FingerGoodix","%s:send callback message error","fingerprint_enumerate");
    return iVar1;
  }
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00108604(long param_1)

{
  int iVar1;
  int iVar2;
  undefined8 uVar3;
  undefined4 *puVar4;
  uint local_8c;
  undefined4 local_88 [10];
  undefined8 local_60;
  undefined8 local_58;
  undefined8 local_50;
  undefined8 uStack_48;
  undefined8 local_40;
  undefined8 uStack_38;
  undefined8 local_30;
  undefined8 uStack_28;
  undefined8 local_20;
  undefined8 uStack_18;
  undefined8 local_10;
  long local_8;
  
  local_10 = 0;
  local_8 = ___stack_chk_guard;
  local_60 = 0;
  local_58 = 0;
  local_50 = 0;
  uStack_48 = 0;
  local_40 = 0;
  uStack_38 = 0;
  local_30 = 0;
  uStack_28 = 0;
  local_20 = 0;
  uStack_18 = 0;
  if (param_1 == 0) {
    __android_log_print(6,"FingerGoodix","%s:device point is null","enumerate_callback_func");
    uVar3 = 0xffffffff;
  }
  else {
    local_8c = 0x28;
    iVar2 = goodix_sensor_fp_enumerate(local_88,&local_8c);
    uVar3 = __android_log_print(3,"FingerGoodix","%s:ret=%d,array_size= %d",
                                "enumerate_callback_func",iVar2,local_8c);
    if (((iVar2 == 0) && (local_8c != 0)) && (local_8c >> 3 != 0)) {
      puVar4 = local_88 + 1;
      iVar2 = (local_8c >> 3) - 1;
      do {
        local_50 = CONCAT44(local_50._4_4_,iVar2);
        local_58 = CONCAT44(*puVar4,puVar4[-1]);
        local_60 = CONCAT44(local_60._4_4_,6);
        (**(code **)(param_1 + 0x78))(&local_60);
        iVar1 = iVar2 + -1;
        uVar3 = __android_log_print(3,"FingerGoodix","%s:remaining_templats=%d,fid=%d,gid=%d",
                                    "enumerate_callback_func",iVar2,*puVar4,puVar4[-1]);
        puVar4 = puVar4 + 2;
        iVar2 = iVar1;
      } while (iVar1 != -1);
    }
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar3);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00108780(long param_1)

{
  undefined8 local_60;
  undefined8 local_58;
  undefined8 local_50;
  undefined8 uStack_48;
  undefined8 local_40;
  undefined8 uStack_38;
  undefined8 local_30;
  undefined8 uStack_28;
  undefined8 local_20;
  undefined8 uStack_18;
  undefined8 local_10;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","fpcode, fingerprint_cancel()");
  pthread_mutex_lock((pthread_mutex_t *)&DAT_0013c140);
  __android_log_print(3,"FingerGoodix","fingerprint_cancel");
  local_10 = 0;
  local_60 = 0xffffffff;
  local_50 = 0;
  uStack_48 = 0;
  local_58 = 5;
  local_40 = 0;
  uStack_38 = 0;
  local_30 = 0;
  uStack_28 = 0;
  local_20 = 0;
  uStack_18 = 0;
  (**(code **)(param_1 + 0x78))(&local_60);
  goodix_sensor_fp_cancel(*(undefined4 *)(param_1 + 300));
  setListenerState(param_1,3);
  pthread_mutex_unlock((pthread_mutex_t *)&DAT_0013c140);
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(0);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0010885c(long param_1,undefined8 param_2,undefined4 param_3)

{
  int iVar1;
  undefined8 uVar2;
  undefined local_50;
  undefined7 uStack_4f;
  undefined uStack_48;
  undefined7 uStack_47;
  undefined local_40;
  undefined7 uStack_3f;
  undefined uStack_38;
  undefined4 local_37;
  undefined3 uStack_33;
  undefined8 local_30;
  undefined8 uStack_28;
  undefined8 local_20;
  undefined8 uStack_18;
  undefined4 local_10;
  undefined local_c;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix",
                      "fpcode, fingerprint_authenticate(%p, operation_id=%lud, gid=%d)",param_1,
                      param_2,param_3);
  iVar1 = goodix_sensor_init();
  if (iVar1 < 0) {
    __android_log_print(6,"FingerGoodix","Init goodix sensor failed!");
    uVar2 = 0xffffffea;
  }
  else {
    pthread_mutex_lock((pthread_mutex_t *)&DAT_0013c140);
    __android_log_print(3,"FingerGoodix","fingerprint_authenticate");
    set_fpdb_to_ta();
    loadFingerPrintPlatformDataIfNeed(param_1);
    checkConsistence(param_1);
    if (*(int *)(param_1 + 0x1a0) < 1) {
      __android_log_print(3,"FingerGoodix","no fingerprint, can not authenticate");
      pthread_mutex_unlock((pthread_mutex_t *)&DAT_0013c140);
      uVar2 = 0;
    }
    else {
      goodix_sensor_fp_cancel(*(undefined4 *)(param_1 + 300));
      setListenerState(param_1,3);
      pthread_mutex_lock((pthread_mutex_t *)(param_1 + 0x1e4));
      *(undefined8 *)(param_1 + 0x1b8) = param_2;
      pthread_mutex_unlock((pthread_mutex_t *)(param_1 + 0x1e4));
      setListenerState(param_1,2);
      local_10 = 0;
      uStack_33 = 0;
      local_50 = 0;
      local_37 = 0x2000000;
      uStack_4f = (undefined7)*(undefined8 *)(param_1 + 0x1b8);
      uStack_48 = (undefined)((ulong)*(undefined8 *)(param_1 + 0x1b8) >> 0x38);
      uStack_3f = (undefined7)*(undefined8 *)(param_1 + 0x1d8);
      uStack_38 = (undefined)((ulong)*(undefined8 *)(param_1 + 0x1d8) >> 0x38);
      uStack_47 = (undefined7)*(undefined8 *)(param_1 + 0x1c8);
      local_40 = (undefined)((ulong)*(undefined8 *)(param_1 + 0x1c8) >> 0x38);
      local_30 = 0;
      uStack_28 = 0;
      local_20 = 0;
      uStack_18 = 0;
      local_c = 0;
      goodix_sensor_fp_match(&local_50);
      pthread_mutex_unlock((pthread_mutex_t *)&DAT_0013c140);
      uVar2 = 0;
    }
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar2);
}



void FUN_001089ec(long param_1,uint param_2,undefined8 param_3)

{
  __android_log_print(3,"FingerGoodix","fpcode, fingerprint_set_active_group(%p, %d, %s)",param_1,
                      param_2,param_3);
  *(ulong *)(param_1 + 0x1d0) = (ulong)param_2;
  clear_check_when_set_active_group();
  goodix_sensor_set_active_group(param_1,param_2,param_3);
  return;
}



undefined8 FUN_00108a54(long param_1,char *param_2,undefined4 param_3,undefined4 param_4)

{
  int iVar1;
  undefined8 uVar2;
  
  __android_log_print(3,"FingerGoodix",
                      "fpcode, fingerprint_enroll(%p, hat=%p, gid=%d, timeout_sec=%d)",param_1,
                      param_2,param_3,param_4);
  iVar1 = goodix_sensor_init();
  if (iVar1 < 0) {
    __android_log_print(6,"FingerGoodix","Init goodix sensor failed!");
    uVar2 = 0xffffffea;
  }
  else {
    pthread_mutex_lock((pthread_mutex_t *)&DAT_0013c140);
    __android_log_print(3,"FingerGoodix","fingerprint_enroll");
    loadFingerPrintPlatformDataIfNeed(param_1);
    goodix_sensor_fp_cancel(*(undefined4 *)(param_1 + 300));
    setListenerState(param_1,3);
    if (((param_2 == (char *)0x0) || (*(long *)(param_2 + 1) == 0)) ||
       (*(long *)(param_2 + 1) != *(long *)(param_1 + 0x1c0))) {
      __android_log_print(6,"FingerGoodix","%s: invalid or null auth token","fingerprint_enroll");
    }
    else {
      *(undefined8 *)(param_1 + 0x1c8) = *(undefined8 *)(param_2 + 9);
    }
    if (*param_2 == '\0') {
      if ((*(long *)(param_2 + 1) == *(long *)(param_1 + 0x1c0)) ||
         ((*(uint *)(param_2 + 0x19) >> 1 & 1) != 0)) {
        goodix_sensor_fp_set_user_id(*(undefined8 *)(param_1 + 0x1c8));
        setListenerState(param_1,1);
        do {
          iVar1 = rand();
        } while (iVar1 < 1);
        goodix_sensor_fp_enroll();
        pthread_mutex_unlock((pthread_mutex_t *)&DAT_0013c140);
        uVar2 = 0;
      }
      else {
        pthread_mutex_unlock((pthread_mutex_t *)&DAT_0013c140);
        uVar2 = 0xffffffff;
      }
    }
    else {
      pthread_mutex_unlock((pthread_mutex_t *)&DAT_0013c140);
      uVar2 = 0xffffffa3;
    }
  }
  return uVar2;
}



undefined8 FUN_00108bc4(long param_1)

{
  undefined8 uVar1;
  long lVar2;
  
  __android_log_print(3,"FingerGoodix","pre_enroll");
  gCheckFingerprintidsConsistence_flag = 1;
  uVar1 = get_64bit_rand();
  *(undefined8 *)(param_1 + 0x1c0) = uVar1;
  set_fpdb_to_ta();
  loadFingerPrintPlatformDataIfNeed(param_1);
  lVar2 = *(long *)(param_1 + 0x1c0);
  while (lVar2 == 0) {
    lVar2 = get_64bit_rand();
    *(long *)(param_1 + 0x1c0) = lVar2;
  }
  __android_log_print(3,"FingerGoodix","fpcode, fingerprint_pre_enroll() = %lu",lVar2);
  checkConsistence(param_1);
  return *(undefined8 *)(param_1 + 0x1c0);
}



undefined8 FUN_00108c54(void *param_1)

{
  undefined8 uVar1;
  
  __android_log_print(3,"FingerGoodix","fpcode, fingerprint_close(%p)",param_1);
  if (param_1 == (void *)0x0) {
    uVar1 = 0xffffffff;
  }
  else {
    destroyListenerThread(param_1);
    free(param_1);
    uVar1 = 0;
  }
  return uVar1;
}



void FUN_00108cac(long param_1,undefined *param_2,int param_3)

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
  if (param_3 < 1) goto LAB_00108ec8;
  if (param_3 == 1) {
    uVar4 = 0;
LAB_00108ef8:
    uVar5 = 0;
LAB_00108efc:
    uVar6 = 0;
LAB_00108f00:
    uVar7 = 0;
LAB_00108f04:
    uVar3 = 0;
  }
  else {
    uVar4 = param_2[1];
    if (param_3 == 2) goto LAB_00108ef8;
    uVar5 = param_2[2];
    if (param_3 == 3) goto LAB_00108efc;
    uVar6 = param_2[3];
    if (param_3 == 4) goto LAB_00108f00;
    uVar7 = param_2[4];
    if (param_3 == 5) goto LAB_00108f04;
    uVar3 = param_2[5];
  }
  __android_log_print(3,"FingerGoodix",
                      " %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
                      *param_2,uVar4,uVar5,uVar6,uVar7,uVar3);
LAB_00108ec8:
  __android_log_print(3,"FingerGoodix","--------------------------------");
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00108f3c(long param_1,uint param_2)

{
  undefined8 local_60;
  ulong local_58;
  undefined8 local_50;
  undefined8 uStack_48;
  undefined8 local_40;
  undefined8 uStack_38;
  undefined8 local_30;
  undefined8 uStack_28;
  undefined8 local_20;
  undefined8 uStack_18;
  undefined8 local_10;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","notify acquired message:%d",param_2);
  local_10 = 0;
  local_58 = (ulong)param_2;
  local_50 = 0;
  uStack_48 = 0;
  local_40 = 0;
  uStack_38 = 0;
  local_30 = 0;
  uStack_28 = 0;
  local_20 = 0;
  uStack_18 = 0;
  local_60 = 1;
  (**(code **)(param_1 + 0x78))(&local_60);
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



void FUN_00108fd4(void)

{
  pthread_mutex_lock((pthread_mutex_t *)&DAT_0013c180);
  while (0 < DAT_0013c1a8) {
    __android_log_print(3,"FingerGoodix","fpcode, wait fp channel finish the last task.");
    pthread_mutex_unlock((pthread_mutex_t *)&DAT_0013c180);
    usleep(10000);
    pthread_mutex_lock((pthread_mutex_t *)&DAT_0013c180);
  }
  return;
}



ulong get_64bit_rand(void)

{
  uint uVar1;
  int iVar2;
  ulong uVar3;
  
  uVar1 = rand();
  iVar2 = rand();
  uVar3 = (long)iVar2 | (ulong)uVar1 << 0x20;
  __android_log_print(3,"FingerGoodix","fpcode, get_64bit_rand()=%lu",uVar3);
  return uVar3;
}



uint get_all_fingerprint_ids(int *param_1,uint param_2)

{
  int iVar1;
  long lVar2;
  uint uVar3;
  
  lVar2 = DAT_0013c1b0;
  if (DAT_0013c1b0 == 0) {
    return 0;
  }
  if (param_2 == 0) {
    uVar3 = 0;
  }
  else {
    iVar1 = *(int *)(DAT_0013c1b0 + 0x138);
    if (iVar1 != 0) {
      *param_1 = iVar1;
    }
    uVar3 = (uint)(iVar1 != 0);
    if (uVar3 < param_2) {
      if (*(int *)(lVar2 + 0x13c) != 0) {
        param_1[(int)uVar3] = *(int *)(lVar2 + 0x13c);
        uVar3 = uVar3 + 1;
        if (param_2 <= uVar3) {
          return uVar3;
        }
      }
      if (*(int *)(lVar2 + 0x140) != 0) {
        param_1[(int)uVar3] = *(int *)(lVar2 + 0x140);
        uVar3 = uVar3 + 1;
        if (param_2 <= uVar3) {
          return uVar3;
        }
      }
      if (*(int *)(lVar2 + 0x144) != 0) {
        param_1[(int)uVar3] = *(int *)(lVar2 + 0x144);
        uVar3 = uVar3 + 1;
        if (param_2 <= uVar3) {
          return uVar3;
        }
      }
      if (*(int *)(lVar2 + 0x148) != 0) {
        param_1[(int)uVar3] = *(int *)(lVar2 + 0x148);
        uVar3 = uVar3 + 1;
      }
    }
  }
  return uVar3;
}



undefined4 get_max_fp_num(void)

{
  if (DAT_0013c1b0 != 0) {
    return *(undefined4 *)(DAT_0013c1b0 + 0x1b0);
  }
  return 0;
}



int setListenerState(long param_1,undefined4 param_2)

{
  int iVar1;
  
  __android_log_print(3,"FingerGoodix","fpcode, setListenerState(%p, %d)",param_1,param_2);
  pthread_mutex_lock((pthread_mutex_t *)(param_1 + 0x100));
  *(undefined4 *)(param_1 + 300) = param_2;
  gSensorState = param_2;
  iVar1 = pthread_mutex_unlock((pthread_mutex_t *)(param_1 + 0x100));
  return iVar1;
}



undefined8 remove_fpdb_file(void)

{
  int iVar1;
  undefined8 uVar2;
  FILE *__stream;
  
  if (gFPExtDataFilePath == '\0') {
    uVar2 = __android_log_print(6,"FingerGoodix",
                                "fpcode, remove_fpdb_file(), gFPExtDataFilePath need init first!");
    return uVar2;
  }
  iVar1 = remove(&gFPExtDataFilePath);
  if (iVar1 != 0) {
    return 0;
  }
  __stream = fopen(&gFPExtDataFilePath,"a");
  fclose(__stream);
  return 1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void set_fpdb_to_ta(void)

{
  FILE *__stream;
  size_t sVar1;
  size_t sVar2;
  char acStack_808 [2048];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","set_fpdb_to_ta,gFPExtDataFilePath:%s",&gFPExtDataFilePath);
  __stream = fopen(&gFPExtDataFilePath,"r");
  memset(acStack_808,0,0x800);
  set_fpdb_path(&gFPExtDataFilePath);
  __android_log_print(3,"FingerGoodix","set_fpdb_to_ta,fp_stored:begin");
  DAT_0013c1b8 = 1;
  if (__stream != (FILE *)0x0) {
    __android_log_print(3,"FingerGoodix","set_fpdb_to_ta,fp_stored:%d");
    sVar1 = fread(acStack_808,1,0x800,__stream);
    sVar2 = strlen(acStack_808);
    __android_log_print(3,"FingerGoodix","set_fpdb_to_ta,count:%d",sVar2);
    if ((int)sVar1 < 1) {
      __android_log_print(3,"FingerGoodix","ss count <= 0");
      remove(&gFPExtDataFilePath);
    }
    else {
      goodix_set_fpdb_to_ta(acStack_808);
      remove(&gFPExtDataFilePath);
      fclose(__stream);
      DAT_0013c1bc = 0;
    }
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(0);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void loadFingerPrintPlatformDataIfNeed(long param_1)

{
  int iVar1;
  int iVar2;
  undefined8 uVar3;
  undefined8 uVar4;
  undefined8 *puVar5;
  undefined8 *puVar6;
  undefined8 *puVar7;
  undefined8 local_88;
  undefined8 local_80;
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
  if (((param_1 != 0) && (DAT_0013c1bc == 0)) && (DAT_0013c1b8 != 0)) {
    puVar5 = &local_88;
    *(undefined4 *)(param_1 + 0x1a0) = 0;
    local_88 = 0;
    local_80 = 0;
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
    iVar2 = load_all_fpdata(puVar5);
    if (iVar2 != -1) {
      puVar7 = (undefined8 *)(param_1 + 0x150);
      __android_log_print(3,"FingerGoodix","loadFingerPrintPlatformDataIfNeed-->current_num:%d",
                          local_10 & 0xffffffff);
      puVar6 = (undefined8 *)(param_1 + 0x138);
      pthread_mutex_lock((pthread_mutex_t *)&DAT_0013c1c0);
      *puVar6 = 0;
      *(undefined8 *)(param_1 + 0x140) = 0;
      *(undefined4 *)(param_1 + 0x148) = 0;
      *(undefined4 *)(param_1 + 0x1a0) = 0;
      do {
        __android_log_print(3,"FingerGoodix","loadFingerPrintPlatformDataIfNeed:%d,%llu,%llu\n",
                            *(int *)puVar5,puVar5[1],puVar5[2]);
        iVar2 = *(int *)puVar5;
        if (iVar2 < 1) {
          *(undefined4 *)puVar6 = 0;
          *puVar7 = 0;
          puVar7[5] = 0;
        }
        else {
          *(int *)puVar6 = iVar2;
          uVar3 = puVar5[1];
          iVar1 = *(int *)(param_1 + 0x1a0);
          uVar4 = puVar5[2];
          *puVar7 = uVar3;
          puVar7[5] = uVar4;
          *(undefined8 *)(param_1 + 0x1d8) = uVar4;
          *(undefined8 *)(param_1 + 0x1c8) = uVar3;
          *(int *)(param_1 + 0x130) = iVar2;
          *(int *)(param_1 + 0x1a0) = iVar1 + 1;
        }
        puVar6 = (undefined8 *)((long)puVar6 + 4);
        puVar5 = puVar5 + 3;
        puVar7 = puVar7 + 1;
      } while (puVar6 != (undefined8 *)(param_1 + 0x14c));
      pthread_mutex_unlock((pthread_mutex_t *)&DAT_0013c1c0);
      DAT_0013c1bc = 1;
    }
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00109554(long param_1)

{
  ulong uVar1;
  long lVar2;
  ulong uVar3;
  uint uVar4;
  bool bVar5;
  undefined8 uVar6;
  undefined8 uVar7;
  int *piVar8;
  undefined8 uVar9;
  int iVar10;
  int iVar11;
  int *local_c8;
  int local_9c;
  timespec local_90;
  undefined8 local_80;
  undefined8 local_78;
  undefined8 local_70;
  long local_68;
  ulong local_60;
  ulong local_58;
  undefined4 local_50;
  int iStack_4c;
  undefined local_48;
  undefined7 uStack_47;
  undefined local_40;
  undefined7 uStack_3f;
  undefined uStack_38;
  undefined4 local_37;
  undefined3 uStack_33;
  uint5 local_30;
  undefined3 uStack_2b;
  undefined5 uStack_28;
  undefined3 uStack_23;
  undefined5 local_20;
  undefined3 uStack_1b;
  undefined5 uStack_18;
  undefined3 uStack_13;
  undefined5 local_10;
  undefined3 uStack_b;
  long local_8;
  
  local_9c = -1;
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","fpcode, listenerFunction(%p)",param_1);
  pthread_mutex_init((pthread_mutex_t *)&DAT_0013c180,(pthread_mutexattr_t *)0x0);
  pthread_cond_init((pthread_cond_t *)&DAT_0013c1e8,(pthread_condattr_t *)0x0);
  pthread_mutex_lock((pthread_mutex_t *)&DAT_0013c180);
LAB_00109604:
  do {
    while( true ) {
      local_80 = 0;
      local_78 = 0;
      local_70 = 0;
      local_68 = 0;
      __android_log_print(3,"FingerGoodix","fpcode, recv_fp_scan_data(%p)",&local_80);
      __android_log_print(3,"FingerGoodix","fpcode, recv_fp_scan_data(), receiving");
      pthread_cond_wait((pthread_cond_t *)&DAT_0013c1e8,(pthread_mutex_t *)&DAT_0013c180);
      if (0 < DAT_0013c1a8) {
        DAT_0013c1a8 = DAT_0013c1a8 + -1;
      }
      __android_log_print(3,"FingerGoodix","fpcode, recv_fp_scan_data(), received");
      local_80._0_4_ = gSensorNotifyData;
      local_80._4_4_ = DAT_0013c33c;
      local_78._0_4_ = DAT_0013c340;
      local_78._4_4_ = DAT_0013c344;
      local_68 = DAT_0013c350;
      local_70 = CONCAT44(DAT_0013c34c,DAT_0013c348);
      if (DAT_0013c1b0 == 0) {
        __android_log_print(3,"FingerGoodix","listener exit");
        if (local_8 == ___stack_chk_guard) {
          return;
        }
                    // WARNING: Subroutine does not return
        __stack_chk_fail(0);
      }
      __android_log_print(3,"FingerGoodix",
                          "fpcode, recv_fp_scan_data(), result:{action=%d, msg_type=%d, custom_fp_id=%d, gx_fp_id=%d, arg1=%d, arg2=%d, data=%p}"
                         );
      uVar4 = local_70._4_4_;
      if ((int)local_80 != 3) break;
      local_9c = (int)local_78;
      if (local_78._4_4_ < 0) {
        __android_log_print(6,"FingerGoodix","finger id should be positive");
      }
      else if (((int)local_78 == 0) && (local_80._4_4_ == 5)) {
        local_50 = 0;
        iStack_4c = 0;
        local_48 = 0;
        uStack_47 = 0;
        local_40 = 0;
        uStack_3f = 0;
        uStack_38 = 0;
        local_37 = 0;
        uStack_33 = 0;
        local_30 = 0;
        uStack_2b = 0;
        uStack_28 = 0;
        uStack_23 = 0;
        local_20 = 0;
        uStack_1b = 0;
        uStack_18 = 0;
        uStack_13 = 0;
        local_10 = 0;
        uStack_b = 0;
        local_60 = 5;
        local_58 = (ulong)gCurrentActiveGroup;
        (**(code **)(param_1 + 0x78))(&local_60);
      }
      else if (local_80._4_4_ == 1) {
        __android_log_print(3,"FingerGoodix",
                            "fpcode, recv_fp_scan_data(), FINGERPRINT_ACQUIRED, acquired_info=%d",
                            local_70._4_4_);
        if ((*(int *)(param_1 + 300) == 2) && (4 < uVar4 - 1)) {
          __android_log_print(6,"FingerGoodix","can not recognize this acquired_info: %d",uVar4);
        }
        else {
          FUN_00108f3c(param_1,uVar4);
        }
      }
      else if ((local_80._4_4_ - 3 & 0xfffffffd) == 0) {
        *(undefined4 *)(param_1 + 0x1e0) = (undefined4)local_70;
        *(int *)(param_1 + 0x130) = local_78._4_4_;
        *(undefined4 *)(param_1 + 0x134) = 1;
        __android_log_print(3,"FingerGoodix","got finger %d",local_78._4_4_);
        __android_log_print(3,"FingerGoodix","fpcode, got gx_finger %d, verifyScore=%d",
                            local_78._4_4_,*(undefined4 *)(param_1 + 0x1e0));
        lVar2 = local_68;
        uVar4 = local_80._4_4_;
        __android_log_print(3,"FingerGoodix","fpcode, listener_send_notice(%p), listener state: %d",
                            param_1,*(undefined4 *)(param_1 + 300));
        FUN_00108f3c(param_1,0);
        __android_log_print(3,"FingerGoodix",
                            "fpcode, listener_send_notice, notified FINGERPRINT_ACQUIRED_GOOD, fid:%d"
                            ,*(undefined4 *)(param_1 + 0x130));
        pthread_mutex_lock((pthread_mutex_t *)(param_1 + 0x100));
        if (*(int *)(param_1 + 300) == 1) {
          iStack_4c = 0;
          local_48 = 0;
          uStack_47 = 0;
          local_50 = *(int *)(param_1 + 0x1e0);
          local_40 = 0;
          uStack_3f = 0;
          uStack_38 = 0;
          local_37 = 0;
          uStack_33 = 0;
          local_30 = 0;
          uStack_2b = 0;
          uStack_28 = 0;
          uStack_23 = 0;
          local_20 = 0;
          uStack_1b = 0;
          uStack_18 = 0;
          uStack_13 = 0;
          local_10 = 0;
          uStack_b = 0;
          local_60 = 3;
          local_58 = CONCAT44(*(undefined4 *)(param_1 + 0x130),gCurrentActiveGroup);
          (**(code **)(param_1 + 0x78))(&local_60);
          if (*(int *)(param_1 + 0x1e0) < 1) {
            uVar6 = get_64bit_rand();
            *(undefined8 *)(param_1 + 0x1d8) = uVar6;
            local_c8 = (int *)(param_1 + 0x138);
            __android_log_print(3,"FingerGoodix",
                                "fpcode, listener_send_notice(), new authenticator_id=%lu",uVar6);
            *(undefined4 *)(param_1 + 300) = 3;
            iVar11 = 0;
            piVar8 = local_c8;
            do {
              __android_log_print(3,"FingerGoodix",
                                  "fpcode, finger_already_enrolled, all_fingerids[%d]=%d",iVar11,
                                  *piVar8);
              if (*(int *)(param_1 + 0x130) == *piVar8) {
                *(undefined8 *)(param_1 + 0x1c8) =
                     *(undefined8 *)(param_1 + (long)iVar11 * 8 + 0x150);
                goto LAB_001099e0;
              }
              iVar11 = iVar11 + 1;
              piVar8 = piVar8 + 1;
            } while (iVar11 != 5);
            if (*(long *)(param_1 + 0x1a8) == 0) {
              loadFingerPrintPlatformDataIfNeed(param_1);
            }
            iVar11 = 0;
            do {
              __android_log_print(3,"FingerGoodix","%s,i=%d","add_current_fingerprint",iVar11);
              if (*local_c8 == 0) {
                iVar10 = iVar11 % 5;
                goto LAB_00109f90;
              }
              iVar11 = iVar11 + 1;
              local_c8 = local_c8 + 1;
            } while (iVar11 != 5);
            iVar10 = 0;
            iVar11 = 0;
LAB_00109f90:
            __android_log_print(3,"FingerGoodix","fpcode, add_current_fingerprint  new_index=%d",
                                iVar11);
            lVar2 = param_1 + (long)iVar10 * 8;
            uVar6 = *(undefined8 *)(param_1 + 0x1c8);
            *(undefined4 *)(param_1 + (long)iVar10 * 4 + 0x138) = *(undefined4 *)(param_1 + 0x130);
            *(undefined8 *)(lVar2 + 0x150) = uVar6;
            *(undefined8 *)(lVar2 + 0x178) = *(undefined8 *)(param_1 + 0x1d8);
            iVar11 = *(int *)(param_1 + 0x1a0) + 1;
            if (*(int *)(param_1 + 0x1a0) < 0) {
              iVar11 = 1;
            }
            *(int *)(param_1 + 0x1a0) = iVar11;
            __android_log_print(3,"FingerGoodix",
                                "fpcode, add_current_fingerprint  dev->listener.num_fingers_enrolled=%d"
                               );
          }
        }
        else if (0 < *(int *)(param_1 + 0x130)) {
          __android_log_print(3,"FingerGoodix","fpcode, listener_send_notice(), is_valid_finger=%d",
                              uVar4 != 3);
          local_10 = 0;
          uStack_b = 0;
          *(undefined4 *)(param_1 + 300) = 3;
          local_60 = 5;
          uStack_33 = 0;
          local_30 = 0;
          uStack_2b = 0;
          uStack_28 = 0;
          uStack_23 = 0;
          local_20 = 0;
          uStack_1b = 0;
          uStack_18 = 0;
          uStack_13 = 0;
          local_58 = (ulong)gCurrentActiveGroup;
          if (uVar4 != 3) {
            local_58 = CONCAT44(*(undefined4 *)(param_1 + 0x130),gCurrentActiveGroup);
            local_37 = *(undefined4 *)(lVar2 + 0x2b9);
            uVar6 = *(undefined8 *)(lVar2 + 0x2a1);
            local_50._1_3_ = (uint3)uVar6;
            local_50 = CONCAT31(local_50._1_3_,*(undefined *)(lVar2 + 0x2a0));
            iStack_4c = (int)((ulong)uVar6 >> 0x18);
            local_48 = (undefined)((ulong)uVar6 >> 0x38);
            uStack_3f = (undefined7)*(undefined8 *)(lVar2 + 0x2b1);
            uStack_38 = (undefined)((ulong)*(undefined8 *)(lVar2 + 0x2b1) >> 0x38);
            uStack_47 = (undefined7)*(undefined8 *)(lVar2 + 0x2a9);
            local_40 = (undefined)((ulong)*(undefined8 *)(lVar2 + 0x2a9) >> 0x38);
            uStack_33 = (undefined3)*(undefined8 *)(lVar2 + 0x2bd);
            local_30 = (uint5)((ulong)*(undefined8 *)(lVar2 + 0x2bd) >> 0x18);
            uStack_2b = (undefined3)*(undefined8 *)(lVar2 + 0x2c5);
            uStack_28 = (undefined5)((ulong)*(undefined8 *)(lVar2 + 0x2c5) >> 0x18);
            uStack_23 = (undefined3)*(undefined8 *)(lVar2 + 0x2cd);
            local_20 = (undefined5)((ulong)*(undefined8 *)(lVar2 + 0x2cd) >> 0x18);
            uStack_1b = (undefined3)*(undefined8 *)(lVar2 + 0x2d5);
            uStack_18 = (undefined5)((ulong)*(undefined8 *)(lVar2 + 0x2d5) >> 0x18);
            uStack_13 = (undefined3)*(undefined8 *)(lVar2 + 0x2dd);
            local_10 = (undefined5)((ulong)*(undefined8 *)(lVar2 + 0x2dd) >> 0x18);
          }
          else {
            uVar9 = *(undefined8 *)(param_1 + 0x1d8);
            uVar6 = *(undefined8 *)(param_1 + 0x1c8);
            uVar7 = *(undefined8 *)(param_1 + 0x1b8);
            local_50._1_3_ = (uint3)uVar7;
            local_50 = (uint)local_50._1_3_ << 8;
            iStack_4c = (int)((ulong)uVar7 >> 0x18);
            local_48 = (undefined)((ulong)uVar7 >> 0x38);
            local_37 = 0x2000000;
            uStack_3f = (undefined7)uVar9;
            uStack_38 = (undefined)((ulong)uVar9 >> 0x38);
            uStack_47 = (undefined7)uVar6;
            local_40 = (undefined)((ulong)uVar6 >> 0x38);
            __android_log_print(3,"FingerGoodix","listener_send_notice:final-->%llu,%llu\n",uVar9,
                                uVar6);
            clock_gettime(1,&local_90);
            uVar1 = local_90.tv_nsec / 1000000 + local_90.tv_sec * 1000;
            uVar1 = (uVar1 & 0xff00ff00ff00ff00) >> 8 | (uVar1 & 0xff00ff00ff00ff) << 8;
            uVar3 = uVar1 & 0xffff0000ffff;
            uVar1 = (uVar1 & 0xffff0000ffff0000) >> 0x10 | uVar3 << 0x10;
            local_30 = (uint5)(byte)(uVar3 >> 0x28) | (uint5)((uVar1 << 0x20) >> 0x18);
            uStack_33 = (undefined3)(uVar1 >> 0x20);
            FUN_00108cac("fp1, TEE auth token",&local_50,0x25);
            FUN_00108cac("fp1, TEE auth hmac",&uStack_2b,0x20);
            __android_log_print(3,"FingerGoodix","gen hmac, try, sid:0x%lx, uid:0x%lx, time=0x%lx",
                                CONCAT17(local_48,CONCAT43(iStack_4c,local_50._1_3_)),
                                CONCAT17(local_40,uStack_47),CONCAT53(local_30,uStack_33));
            goodix_sensor_fill_auth_token_hmac(&local_50);
            __android_log_print(3,"FingerGoodix",
                                "gen hmac, filled, sid:0x%lx, uid:0x%lx, time=0x%lx",
                                CONCAT17(local_48,CONCAT43(iStack_4c,local_50._1_3_)),
                                CONCAT17(local_40,uStack_47),CONCAT53(local_30,uStack_33));
            FUN_00108cac("fp2, TEE auth token",&local_50,0x25);
            FUN_00108cac("fp2, TEE auth hmac",&uStack_2b,0x20);
          }
          __android_log_print(3,"FingerGoodix","listener_send_notice:end");
          (**(code **)(param_1 + 0x78))(&local_60);
          __android_log_print(3,"FingerGoodix","listener_send_notice:end1");
        }
LAB_001099e0:
        pthread_mutex_unlock((pthread_mutex_t *)(param_1 + 0x100));
        __android_log_print(3,"FingerGoodix","send notice finger %d",local_78._4_4_);
      }
      else {
        __android_log_print(6,"FingerGoodix","invalid fingerprint message type: %d");
      }
    }
    if ((int)local_80 != 4) {
      if ((int)local_80 == 5) {
        if (local_80._4_4_ == 4) {
          __android_log_print(3,"FingerGoodix","fpcode, gx_fp_id=%d, FINGERPRINT_TEMPLATE_REMOVED",
                              local_78._4_4_);
          iVar11 = local_78._4_4_;
          __android_log_print(3,"FingerGoodix","fpcode, remove_fingerprint()");
          bVar5 = iVar11 == 0;
          if ((bVar5 || *(int *)(param_1 + 0x138) == 0) || (iVar11 != *(int *)(param_1 + 0x138))) {
            if ((!bVar5 && *(int *)(param_1 + 0x13c) != 0) && (iVar11 == *(int *)(param_1 + 0x13c)))
            {
              iVar11 = 1;
              goto LAB_0010a008;
            }
            if ((!bVar5 && *(int *)(param_1 + 0x140) != 0) && (iVar11 == *(int *)(param_1 + 0x140)))
            {
              iVar11 = 2;
              goto LAB_0010a008;
            }
            if ((!bVar5 && *(int *)(param_1 + 0x144) != 0) && (iVar11 == *(int *)(param_1 + 0x144)))
            {
              iVar11 = 3;
              goto LAB_0010a008;
            }
            if ((!bVar5 && *(int *)(param_1 + 0x148) != 0) && (iVar11 == *(int *)(param_1 + 0x148)))
            {
              iVar11 = 4;
              goto LAB_0010a008;
            }
            __android_log_print(3,"FingerGoodix","fpcode, remove_fingerprint  fp_index=%d",
                                0xffffffff);
          }
          else {
            iVar11 = 0;
LAB_0010a008:
            __android_log_print(3,"FingerGoodix","fpcode, remove_fingerprint  fp_index=%d",iVar11);
            lVar2 = param_1 + (long)iVar11 * 8;
            *(undefined4 *)(param_1 + (long)iVar11 * 4 + 0x138) = 0;
            *(undefined8 *)(lVar2 + 0x150) = 0;
            *(undefined8 *)(lVar2 + 0x178) = 0;
            iVar11 = *(int *)(param_1 + 0x1a0) + -1;
            *(int *)(param_1 + 0x1a0) = iVar11;
            if (iVar11 < 0) {
              *(undefined4 *)(param_1 + 0x1a0) = 0;
            }
            else {
              __android_log_print(3,"FingerGoodix",
                                  "fpcode, remove_fingerprint  dev->listener.num_fingers_enrolled=%d"
                                 );
            }
          }
          local_60 = 4;
          local_50 = 0;
          iStack_4c = 0;
          local_48 = 0;
          uStack_47 = 0;
          local_40 = 0;
          uStack_3f = 0;
          uStack_38 = 0;
          local_37 = 0;
          uStack_33 = 0;
          local_30 = 0;
          uStack_2b = 0;
          uStack_28 = 0;
          uStack_23 = 0;
          local_20 = 0;
          uStack_1b = 0;
          uStack_18 = 0;
          uStack_13 = 0;
          local_10 = 0;
          uStack_b = 0;
          local_58 = CONCAT44(local_78._4_4_,(int)*(undefined8 *)(param_1 + 0x1d0));
          (**(code **)(param_1 + 0x78))(&local_60);
        }
        else if (local_80._4_4_ == 0xffffffff) {
          __android_log_print(3,"FingerGoodix",
                              "fpcode, gx_fp_id=%d, fingerprint template removing error!",
                              local_78._4_4_);
          local_10 = 0;
          uStack_b = 0;
          local_58 = local_70 >> 0x20;
          local_50 = 0;
          iStack_4c = 0;
          local_48 = 0;
          uStack_47 = 0;
          local_40 = 0;
          uStack_3f = 0;
          uStack_38 = 0;
          local_37 = 0;
          uStack_33 = 0;
          local_30 = 0;
          uStack_2b = 0;
          uStack_28 = 0;
          uStack_23 = 0;
          local_20 = 0;
          uStack_1b = 0;
          uStack_18 = 0;
          uStack_13 = 0;
          local_60 = 0xffffffff;
          (**(code **)(param_1 + 0x78))(&local_60);
        }
        else {
          __android_log_print(3,"FingerGoodix",
                              "fpcode, gx_fp_id=%d, fingerprint template removing state cannot be recognized!"
                              ,local_78._4_4_);
        }
      }
      else if ((int)local_80 == 6) {
        local_50 = 0;
        iStack_4c = 0;
        local_48 = 0;
        uStack_47 = 0;
        local_40 = 0;
        uStack_3f = 0;
        uStack_38 = 0;
        local_37 = 0;
        uStack_33 = 0;
        local_30 = 0;
        uStack_2b = 0;
        uStack_28 = 0;
        uStack_23 = 0;
        local_20 = 0;
        uStack_1b = 0;
        uStack_18 = 0;
        uStack_13 = 0;
        local_10 = 0;
        uStack_b = 0;
        local_60 = 0xffffffff;
        local_58 = (ulong)local_70._4_4_;
        (**(code **)(param_1 + 0x78))(&local_60);
      }
      else if ((int)local_80 - 1U < 2) {
        DAT_0013c218 = (uint)((int)local_80 == 1);
        if (local_80._4_4_ == 1) {
          FUN_00108f3c(param_1,local_70 & 0xffffffff);
        }
      }
      else if ((int)local_80 == 7) {
        __android_log_print(3,"FingerGoodix","fpcode, GOODIX_SENSOR_MOTION_GX_CMD_RESULT, cmd=%d",
                            (int)local_78);
        local_10 = 0;
        uStack_b = 0;
        local_40 = 0;
        uStack_3f = 0;
        uStack_38 = 0;
        local_37 = 0;
        uStack_33 = 0;
        local_30 = 0;
        uStack_2b = 0;
        uStack_28 = 0;
        uStack_23 = 0;
        local_20 = 0;
        uStack_1b = 0;
        uStack_18 = 0;
        uStack_13 = 0;
        local_60 = (ulong)local_80._4_4_;
        local_58 = CONCAT44((undefined4)local_70,(int)local_78);
        local_50 = local_70._4_4_;
        iStack_4c = local_78._4_4_;
        local_48 = (undefined)local_68;
        uStack_47 = (undefined7)((ulong)local_68 >> 8);
        (**(code **)(param_1 + 0x78))(&local_60);
      }
      else {
        __android_log_print(6,"FingerGoodix","error: motion type:%d");
      }
      goto LAB_00109604;
    }
    *(undefined4 *)(param_1 + 0x134) = 0;
    __android_log_print(3,"FingerGoodix","finger off %d",local_9c);
    __android_log_print(3,"FingerGoodix","fpcode, finger off %d",local_9c);
  } while( true );
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined8 set_active_group_to_channel(int param_1,char *param_2)

{
  int iVar1;
  size_t sVar2;
  DIR *pDVar3;
  __mode_t __mode;
  
  if (param_2 == (char *)0x0) {
    __android_log_print(6,"FingerGoodix","fpcode, The dir for the new FP group is invalid!");
    return 0xffffffff;
  }
  if (((param_1 == gCurrentActiveGroup) && (gPlatformFPDataDirPath != '\0')) &&
     (iVar1 = strcmp(&gPlatformFPDataDirPath,param_2), iVar1 == 0)) {
    __android_log_print(3,"FingerGoodix","fpcode, the group %d has already been actived.",param_1);
    return 1;
  }
  DAT_0013c1bc = 0;
  DAT_0013c1b8 = 0;
  __android_log_print(3,"FingerGoodix","fpcode, set_active_group_to_channel(%d, \'%s\')",param_1,
                      param_2);
  _gPlatformFPDataDirPath = 0;
  DAT_0013c2b8 = 0;
  DAT_0013c2c0 = 0;
  DAT_0013c2c8 = 0;
  DAT_0013c2d0 = 0;
  DAT_0013c2d8 = 0;
  DAT_0013c2e0 = 0;
  DAT_0013c2e8 = 0;
  DAT_0013c2f0 = 0;
  DAT_0013c2f8 = 0;
  DAT_0013c300 = 0;
  DAT_0013c308 = 0;
  DAT_0013c310 = 0;
  DAT_0013c318 = 0;
  DAT_0013c320 = 0;
  DAT_0013c328 = 0;
  gCurrentActiveGroup = param_1;
  snprintf(&gPlatformFPDataDirPath,0x80,"%s",param_2);
  sVar2 = strlen(&gPlatformFPDataDirPath);
  iVar1 = (int)sVar2 + -1;
  if ((&gPlatformFPDataDirPath)[iVar1] == '/') {
    (&gPlatformFPDataDirPath)[iVar1] = 0;
    pDVar3 = opendir(&gPlatformFPDataDirPath);
  }
  else {
    pDVar3 = opendir(&gPlatformFPDataDirPath);
  }
  if (pDVar3 == (DIR *)0x0) {
    __android_log_print(3,"FingerGoodix","fpcode, data dir exist.");
    closedir((DIR *)0x0);
  }
  else {
    __android_log_print(3,"FingerGoodix","fpcode, create data dir.");
    mkdir(&gPlatformFPDataDirPath,__mode);
  }
  snprintf(&gFPExtDataFilePath,0x80,"%s/%s",&gPlatformFPDataDirPath,&DAT_00122ca8);
  pthread_mutex_lock((pthread_mutex_t *)&DAT_0013c1c0);
  if (*(FILE **)(DAT_0013c1b0 + 0x1a8) != (FILE *)0x0) {
    fclose(*(FILE **)(DAT_0013c1b0 + 0x1a8));
    *(undefined8 *)(DAT_0013c1b0 + 0x1a8) = 0;
  }
  pthread_mutex_unlock((pthread_mutex_t *)&DAT_0013c1c0);
  return 0;
}



int createListenerThread(void *param_1)

{
  int iVar1;
  
  __android_log_print(3,"FingerGoodix","createListenerThread");
  DAT_0013c1bc = 0;
  DAT_0013c1b8 = 0;
  pthread_mutex_init((pthread_mutex_t *)((long)param_1 + 0x100),(pthread_mutexattr_t *)0x0);
  iVar1 = pthread_create((pthread_t *)((long)param_1 + 0xf8),(pthread_attr_t *)0x0,FUN_00109554,
                         param_1);
  DAT_0013c1b0 = param_1;
  return iVar1;
}



undefined8
send_fp_gx_cmd_exed(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined8 param_4,
                   undefined4 param_5)

{
  __android_log_print(3,"FingerGoodix","fpcode, send_fp_gx_cmd_exed(%d, %d, %d, %p, %d ...)",param_1
                      ,param_2,param_3,param_4,param_5);
  FUN_00108fd4();
  DAT_0013c1a8 = DAT_0013c1a8 + 1;
  gSensorNotifyData = 7;
  DAT_0013c33c = 1000;
  DAT_0013c340 = param_1;
  DAT_0013c344 = param_5;
  DAT_0013c348 = param_2;
  DAT_0013c34c = param_3;
  DAT_0013c350 = param_4;
  pthread_cond_signal((pthread_cond_t *)&DAT_0013c1e8);
  pthread_mutex_unlock((pthread_mutex_t *)&DAT_0013c180);
  return 0;
}



undefined8
send_fp_scan_on(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
               undefined4 param_5,undefined8 param_6)

{
  __android_log_print(3,"FingerGoodix","fpcode, send_fp_scan_on(%d, %d, %d, %d, %d ...)",param_1,
                      param_2,param_3,param_4,param_5);
  FUN_00108fd4();
  DAT_0013c1a8 = DAT_0013c1a8 + 1;
  gSensorNotifyData = 3;
  sFingerId = param_2;
  DAT_0013c33c = param_1;
  DAT_0013c340 = param_2;
  DAT_0013c344 = param_3;
  DAT_0013c348 = param_4;
  DAT_0013c34c = param_5;
  DAT_0013c350 = param_6;
  pthread_cond_signal((pthread_cond_t *)&DAT_0013c1e8);
  pthread_mutex_unlock((pthread_mutex_t *)&DAT_0013c180);
  return 0;
}



undefined8 send_fp_scan_off(undefined4 param_1)

{
  __android_log_print(3,"FingerGoodix","fpcode, send_fp_scan_off()");
  FUN_00108fd4();
  DAT_0013c1a8 = DAT_0013c1a8 + 1;
  sFingerId = 0;
  gSensorNotifyData = 4;
  DAT_0013c33c = param_1;
  pthread_cond_signal((pthread_cond_t *)&DAT_0013c1e8);
  pthread_mutex_unlock((pthread_mutex_t *)&DAT_0013c180);
  return 0;
}



undefined8 send_fp_touch(void)

{
  __android_log_print(3,"FingerGoodix","fpcode, send_fp_touch()");
  FUN_00108fd4();
  DAT_0013c1a8 = DAT_0013c1a8 + 1;
  sFingerId = 0;
  gSensorNotifyData = 1;
  DAT_0013c33c = 1;
  DAT_0013c348 = 0x44e;
  pthread_cond_signal((pthread_cond_t *)&DAT_0013c1e8);
  pthread_mutex_unlock((pthread_mutex_t *)&DAT_0013c180);
  return 0;
}



int destroyListenerThread(long param_1)

{
  int iVar1;
  
  __android_log_print(3,"FingerGoodix","destroyListenerThread");
  DAT_0013c1b0 = 0;
  send_fp_touch();
  if (*(pthread_t *)(param_1 + 0xf8) != 0) {
    pthread_join(*(pthread_t *)(param_1 + 0xf8),(void **)0x0);
  }
  iVar1 = pthread_mutex_destroy((pthread_mutex_t *)(param_1 + 0x100));
  *(undefined8 *)(param_1 + 0xf8) = 0;
  return iVar1;
}



undefined8 send_fp_untouch(void)

{
  __android_log_print(3,"FingerGoodix","fpcode, send_fp_untouch()");
  FUN_00108fd4();
  sFingerId = 0;
  gSensorNotifyData = 2;
  DAT_0013c1a8 = DAT_0013c1a8 + 1;
  DAT_0013c33c = 1;
  DAT_0013c348 = 0x44f;
  pthread_cond_signal((pthread_cond_t *)&DAT_0013c1e8);
  pthread_mutex_unlock((pthread_mutex_t *)&DAT_0013c180);
  return 0;
}



undefined8
send_fp_error(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  __android_log_print(3,"FingerGoodix","fpcode, send_fp_error(%d, %d, %d, %d...)",param_1,param_2,
                      param_3,param_4);
  FUN_00108fd4();
  DAT_0013c1a8 = DAT_0013c1a8 + 1;
  gSensorNotifyData = 6;
  DAT_0013c33c = 0xffffffff;
  DAT_0013c350 = 0;
  sFingerId = param_1;
  DAT_0013c340 = param_1;
  DAT_0013c344 = param_2;
  DAT_0013c348 = param_3;
  DAT_0013c34c = param_4;
  pthread_cond_signal((pthread_cond_t *)&DAT_0013c1e8);
  pthread_mutex_unlock((pthread_mutex_t *)&DAT_0013c180);
  return 0;
}



undefined8
send_fp_removed(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
               undefined4 param_5)

{
  __android_log_print(3,"FingerGoodix","fpcode, send_fp_removed(%d, %d, %d, %d, %d...)",param_1,
                      param_2,param_3,param_4,param_5);
  FUN_00108fd4();
  DAT_0013c1a8 = DAT_0013c1a8 + 1;
  gSensorNotifyData = 5;
  DAT_0013c350 = 0;
  sFingerId = param_2;
  DAT_0013c33c = param_1;
  DAT_0013c340 = param_2;
  DAT_0013c344 = param_3;
  DAT_0013c348 = param_4;
  DAT_0013c34c = param_5;
  pthread_cond_signal((pthread_cond_t *)&DAT_0013c1e8);
  pthread_mutex_unlock((pthread_mutex_t *)&DAT_0013c180);
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// android::fpMGxCmd_send_int(void*, int, int)

void android::fpMGxCmd_send_int(void *param_1,int param_2,int param_3)

{
  int iVar1;
  undefined4 uVar2;
  int local_24 [4];
  undefined4 local_14;
  long *local_10;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  local_24[0] = param_3;
  local_10 = (long *)param_1;
  if (param_1 == (void *)0x0) {
    iVar1 = 0;
  }
  else {
                    // WARNING: Load size is inaccurate
    android::RefBase::incStrong((void *)((long)param_1 + *(long *)(*param_1 + -0x18)));
    iVar1 = (int)local_10;
  }
  local_14 = 0;
  uVar2 = android::Fp::gx_gfCmdM
                    (iVar1,(uchar *)(ulong)(uint)param_2,(int)local_24,(uchar *)0x4,0,(int *)0x0);
  if (local_10 != (long *)0x0) {
    android::RefBase::decStrong((void *)((long)local_10 + *(long *)(*local_10 + -0x18)));
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar2);
}



// android::sp<android::GxFpDevice>::~sp()

void __thiscall android::sp<>::~sp(sp<> *this)

{
  long *plVar1;
  
  plVar1 = *(long **)this;
  if (plVar1 != (long *)0x0) {
    android::RefBase::decStrong((void *)((long)plVar1 + *(long *)(*plVar1 + -0x18)));
    return;
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// android::GxFpDevice::notify(int, int, int)

void __thiscall android::GxFpDevice::notify(GxFpDevice *this,int param_1,int param_2,int param_3)

{
  undefined4 uVar1;
  long lVar2;
  int iVar3;
  int iVar4;
  long *plVar5;
  undefined8 uVar6;
  int iVar7;
  
  lVar2 = ___stack_chk_guard;
  uVar1 = sFingerId;
  __android_log_print(3,"FingerGoodix","fpcode, GxFpDevice::notify(), fingerid = %d",sFingerId);
  pthread_mutex_lock((pthread_mutex_t *)(this + 0x10));
  plVar5 = *(long **)(this + 8);
  if (plVar5 != (long *)0x0) {
    android::RefBase::incStrong((void *)((long)plVar5 + *(long *)(*plVar5 + -0x18)));
  }
  pthread_mutex_unlock((pthread_mutex_t *)(this + 0x10));
  __android_log_print(3,"FingerGoodix","fpcode, GxFpDevice::notify(), msgType=%d, ext1=%d, ext2=%d",
                      param_1,param_2,param_3);
  if (param_1 == 0x20) {
LAB_0010ad28:
    iVar7 = 2;
  }
  else {
    if (0x20 < param_1) {
      if (param_1 == 0x105) {
LAB_0010ac7c:
        uVar6 = 3;
      }
      else {
        if (param_1 < 0x106) {
          if (param_1 == 0x101) {
            __android_log_print(3,"FingerGoodix",
                                "fpcode, GxFpDevice::notify(), match, MSG_TYPE_RECONGNIZE_SUCCESS");
            __android_log_print(3,"FingerGoodix","fpcode, send authentication success message");
            send_fp_scan_on(5,param_3,param_3,param_2,0,0);
            android::Fp::gx_MatchCancel();
            goto LAB_0010aa7c;
          }
          if (param_1 < 0x102) {
            if (param_1 == 0x21) goto LAB_0010ad28;
            iVar7 = 2;
            if (param_1 != 0x22) goto LAB_0010ad10;
            goto LAB_0010aae4;
          }
          if (param_1 == 0x103) {
            send_fp_scan_on(5,0,0,0,0,0);
            goto LAB_0010aa7c;
          }
          if (param_1 < 0x104) {
            __android_log_print(6,"FingerGoodix",
                                "fpcode, GxFpDevice::notify(), MSG_TYPE_RECONGNIZE_TIMEOUT!!!");
            send_fp_error(1,param_3,param_2,3);
            goto LAB_0010aa7c;
          }
          goto LAB_0010ac7c;
        }
        if (param_1 == 0x1001) {
          __android_log_print(3,"FingerGoodix",
                              "fpcode, GxFpDevice::notify(), MSG_TYPE_DELETE_SUCCESS fingerprint has been removed."
                             );
LAB_0010ae14:
          send_fp_removed(4,0,0,0,0);
          goto LAB_0010aa7c;
        }
        if (0x1001 < param_1) {
          if (param_1 == 0x1003) {
            __android_log_print(6,"FingerGoodix",
                                "fpcode, GxFpDevice::notify(), MSG_TYPE_DELETE_TIMEOUT!!!");
            uVar6 = 3;
          }
          else {
            if (0x1002 < param_1) {
              if (param_1 == 0x1004) {
                __android_log_print(3,"FingerGoodix",
                                    "fpcode, GxFpDevice::notify(), MSG_TYPE_EACH_FP_DELETE_SUCCESS fingerprint has been removed."
                                   );
                send_fp_removed(4,param_3,param_3,param_2,0);
                goto LAB_0010aa7c;
              }
LAB_0010ad10:
              __android_log_print(6,"FingerGoodix",
                                  "fpcode, GxFpDevice::notify(), msgType is invalid!");
              goto LAB_0010aa7c;
            }
            __android_log_print(6,"FingerGoodix",
                                "fpcode, GxFpDevice::notify(), the fingerprint is not existed, can not remove!"
                               );
            uVar6 = 2;
          }
          send_fp_removed(0xffffffff,param_3,param_3,param_2,uVar6);
          goto LAB_0010ae14;
        }
        if (param_1 == 0x10c) {
          uVar6 = 1;
        }
        else if (param_1 == 0x10d) {
          uVar6 = 5;
        }
        else {
          if (param_1 != 0x10b) goto LAB_0010ad10;
          uVar6 = 2;
        }
      }
      __android_log_print(3,"FingerGoodix","fpcode, GxFpDevice::notify(), match, arg = %d",0);
      send_fp_scan_on(1,param_3,param_3,param_2,uVar6,0);
      goto LAB_0010aa7c;
    }
    if (param_1 == 0x15) {
      iVar7 = 3;
    }
    else if (param_1 < 0x16) {
      if (param_1 == 0x11) {
        iVar7 = 0;
      }
      else {
        if (param_1 < 0x12) {
          if (param_1 == 1) {
            if (gSensorState == 2) {
              send_fp_touch();
            }
            goto LAB_0010aa7c;
          }
          if (param_1 == 2) {
            if (gSensorState == 2) {
              send_fp_untouch();
            }
            goto LAB_0010aa7c;
          }
          goto LAB_0010ad10;
        }
        if (param_1 == 0x13) {
          iVar7 = 5;
        }
        else {
          iVar7 = 2;
          if (param_1 < 0x14) {
            iVar7 = 1;
          }
        }
      }
    }
    else {
      if (param_1 == 0x19) goto LAB_0010aa7c;
      if (param_1 < 0x1a) {
        if (param_1 == 0x17) {
          __android_log_print(6,"FingerGoodix",
                              "fpcode, GxFpDevice::notify(), MSG_TYPE_REGISTER_TIMEOUT!!!");
          send_fp_error(1,param_3,0,3);
          goto LAB_0010aa7c;
        }
        if (0x17 < param_1) {
          __android_log_print(3,"FingerGoodix",
                              "fpcode, GxFpDevice::notify(), register, MSG_TYPE_REGISTER_COMPLETE");
          goto LAB_0010aa7c;
        }
        iVar7 = 1;
      }
      else if (param_1 == 0x1e) {
        iVar7 = 0x452;
      }
      else {
        if (0x1e < param_1) {
          __android_log_print(6,"FingerGoodix",
                              "fpcode, GxFpDevice::notify(), FINGERPRINT_ERROR_NO_SPACE!!!");
          send_fp_error(1,param_3,0,4);
          goto LAB_0010aa7c;
        }
        if (param_1 != 0x1c) goto LAB_0010ad10;
        iVar7 = 0x451;
        __android_log_print(6,"FingerGoodix",
                            "fpcode, GxFpDevice::notify(), this fingerprint is already exist.");
      }
    }
  }
LAB_0010aae4:
  iVar3 = get_max_fp_num();
  iVar3 = ((100 - param_2) * iVar3) / 100;
  __android_log_print(3,"FingerGoodix","fpcode, GxFpDevice::notify(), register, arg = %d",iVar3);
  if (param_2 < 100) {
    if (iVar3 < 1) {
      iVar3 = 1;
    }
  }
  else {
    iVar4 = android::Fp::gx_RegisterSave((int)plVar5);
    __android_log_print(3,"FingerGoodix",
                        "fpcode, GxFpDevice::notify(), got result_fp_id:=%d, ext2=%d",iVar4,param_3)
    ;
    if (iVar4 < 1) {
      android::Fp::gx_RegisterCancel();
      send_fp_error(0,0,0,5);
      goto LAB_0010aa7c;
    }
    if (param_3 < 1) {
      param_3 = iVar4;
    }
  }
  if (DAT_0013c360 < iVar3) {
    DAT_0013c360 = get_max_fp_num();
  }
  if (iVar7 == 0) {
    __android_log_print(3,"FingerGoodix","fpcode, register progress increase %d",
                        DAT_0013c360 - iVar3);
    send_fp_scan_on(3,uVar1,param_3,iVar3,0,0);
    DAT_0013c360 = iVar3;
  }
  else {
    send_fp_scan_on(1,uVar1,param_3,iVar3,iVar7,0);
    DAT_0013c360 = iVar3;
  }
LAB_0010aa7c:
  if (plVar5 != (long *)0x0) {
    android::RefBase::decStrong((void *)((long)plVar5 + *(long *)(*plVar5 + -0x18)));
  }
  if (lVar2 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// android::GxFpDevice::notifyData(int, int, char*)

void __thiscall
android::GxFpDevice::notifyData(GxFpDevice *this,int param_1,int param_2,char *param_3)

{
  long lVar1;
  long *plVar2;
  undefined8 uVar3;
  
  lVar1 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","fpcode, GxFpDevice::notifyData(), fingerId = %d",sFingerId);
  pthread_mutex_lock((pthread_mutex_t *)(this + 0x10));
  plVar2 = *(long **)(this + 8);
  if (plVar2 != (long *)0x0) {
    android::RefBase::incStrong((void *)((long)plVar2 + *(long *)(*plVar2 + -0x18)));
  }
  pthread_mutex_unlock((pthread_mutex_t *)(this + 0x10));
  __android_log_print(3,"FingerGoodix",
                      "fpcode, GxFpDevice::notifyData(), msgType=%d, length=%d, data:%p",param_1,
                      param_2,param_3);
  if (param_1 == 0x18) {
    __android_log_print(3,"FingerGoodix",
                        "fpcode, GxFpDevice::notify(), register, MSG_TYPE_REGISTER_COMPLETE");
    goto joined_r0x0010b094;
  }
  if (param_1 < 0x19) {
    if (param_1 == 2) {
      if (gSensorState == 2) {
        send_fp_untouch();
      }
      goto joined_r0x0010b094;
    }
    if (param_1 < 3) {
      if (param_1 == 1) {
        if (gSensorState == 2) {
          send_fp_touch();
        }
        goto joined_r0x0010b094;
      }
    }
    else if (param_1 - 0x11U < 6) {
      __android_log_print(3,"FingerGoodix","fpcode, GxFpDevice::notifyData(), register");
      goto joined_r0x0010b094;
    }
  }
  else {
    if (param_1 == 0x103) {
      send_fp_scan_on(5,0,0,0,0,0);
      goto joined_r0x0010b094;
    }
    if (0x103 < param_1) {
      if (param_1 == 0x104) {
        uVar3 = 2;
      }
      else {
        uVar3 = 3;
        if (param_1 != 0x105) goto LAB_0010b1b0;
      }
      __android_log_print(3,"FingerGoodix",
                          "fpcode, GxFpDevice::notifyData(), matching, error msg: %d",param_1);
      send_fp_scan_on(1,0,0,0,uVar3,0);
      goto joined_r0x0010b094;
    }
    if (param_1 == 0x101) {
      __android_log_print(3,"FingerGoodix",
                          "fpcode, GxFpDevice::notifyData(), matched, MSG_TYPE_RECONGNIZE_SUCCESS");
      if (param_3 != (char *)0x0) {
        __android_log_print(3,"FingerGoodix",
                            "fpcode, GxFpDevice::notifyData(), matched, verifyIndex=%d, verifyScore=%d, verifyID=%d"
                            ,*(undefined4 *)param_3,*(undefined4 *)(param_3 + 4),
                            *(undefined4 *)(param_3 + 0x10));
        __android_log_print(3,"FingerGoodix","fpcode, send authentication success message");
        send_fp_scan_on(5,*(undefined4 *)(param_3 + 0x10),*(undefined4 *)(param_3 + 0x10),
                        *(undefined4 *)(param_3 + 4),param_2,param_3);
        android::Fp::gx_MatchCancel();
      }
      goto joined_r0x0010b094;
    }
    if (param_1 == 0x102) {
      __android_log_print(6,"FingerGoodix",
                          "fpcode, GxFpDevice::notifyData(), MSG_TYPE_REGISTER_TIMEOUT!!!");
      send_fp_error(1,0,0,3);
      goto joined_r0x0010b094;
    }
  }
LAB_0010b1b0:
  __android_log_print(6,"FingerGoodix","fpcode, GxFpDevice::notifyData(), msgType is invalid!");
joined_r0x0010b094:
  if (plVar2 != (long *)0x0) {
    android::RefBase::decStrong((void *)((long)plVar2 + *(long *)(*plVar2 + -0x18)));
  }
  if (lVar1 != ___stack_chk_guard) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail();
  }
  return;
}



// android::GxFpDevice::GxFpDevice(android::sp<android::Fp> const&)

void __thiscall android::GxFpDevice::GxFpDevice(GxFpDevice *this,sp *param_1)

{
  long *plVar1;
  long **in_x2;
  long lVar2;
  long *plVar3;
  
  lVar2 = *(long *)(param_1 + 8);
  *(long *)this = lVar2;
  *(undefined8 *)(this + *(long *)(lVar2 + -0x18)) = *(undefined8 *)(param_1 + 0x10);
  lVar2 = *(long *)param_1;
  *(long *)this = lVar2;
  *(undefined8 *)(this + *(long *)(lVar2 + -0x18)) = *(undefined8 *)(param_1 + 0x18);
  *(undefined8 *)(this + 8) = 0;
  pthread_mutex_init((pthread_mutex_t *)(this + 0x10),(pthread_mutexattr_t *)0x0);
  plVar3 = *in_x2;
  if (plVar3 != (long *)0x0) {
    android::RefBase::incStrong((void *)((long)plVar3 + *(long *)(*plVar3 + -0x18)));
  }
  plVar1 = *(long **)(this + 8);
  if (plVar1 != (long *)0x0) {
    android::RefBase::decStrong((void *)((long)plVar1 + *(long *)(*plVar1 + -0x18)));
  }
  *(long **)(this + 8) = plVar3;
  return;
}



// android::GxFpDevice::GxFpDevice(android::sp<android::Fp> const&)

void __thiscall android::GxFpDevice::GxFpDevice(GxFpDevice *this,sp *param_1)

{
  long *plVar1;
  long *plVar2;
  
  android::RefBase::RefBase((RefBase *)(this + 0x38));
  *(undefined8 *)(this + 8) = 0;
  *(undefined8 *)this = 0x13b498;
  *(undefined8 *)(this + 0x38) = 0x13b4f0;
  pthread_mutex_init((pthread_mutex_t *)(this + 0x10),(pthread_mutexattr_t *)0x0);
  plVar2 = *(long **)param_1;
  if (plVar2 != (long *)0x0) {
    android::RefBase::incStrong((void *)((long)plVar2 + *(long *)(*plVar2 + -0x18)));
  }
  plVar1 = *(long **)(this + 8);
  if (plVar1 != (long *)0x0) {
    android::RefBase::decStrong((void *)((long)plVar1 + *(long *)(*plVar1 + -0x18)));
  }
  *(long **)(this + 8) = plVar2;
  return;
}



// android::GxFpDevice::release()

void android::GxFpDevice::release(void)

{
  return;
}



// android::GxFpDevice::~GxFpDevice()

void __thiscall android::GxFpDevice::~GxFpDevice(GxFpDevice *this)

{
  long *plVar1;
  
  *(undefined8 *)this = 0x13b498;
  *(undefined8 *)(this + 0x38) = 0x13b4f0;
  release();
  pthread_mutex_destroy((pthread_mutex_t *)(this + 0x10));
  plVar1 = *(long **)(this + 8);
  if (plVar1 != (long *)0x0) {
    android::RefBase::decStrong((void *)((long)plVar1 + *(long *)(*plVar1 + -0x18)));
  }
  *(undefined **)(this + 0x38) = &DAT_0013b430;
  android::RefBase::~RefBase((RefBase *)(this + 0x38));
  return;
}



// virtual thunk to android::GxFpDevice::~GxFpDevice()

void __thiscall android::GxFpDevice::~GxFpDevice(GxFpDevice *this)

{
  ~GxFpDevice(this + *(long *)(*(long *)this + -0x18));
  return;
}



// android::GxFpDevice::~GxFpDevice()

void __thiscall android::GxFpDevice::~GxFpDevice(GxFpDevice *this)

{
  long *plVar1;
  
  *(undefined8 *)this = 0x13b498;
  *(undefined8 *)(this + 0x38) = 0x13b4f0;
  release();
  pthread_mutex_destroy((pthread_mutex_t *)(this + 0x10));
  plVar1 = *(long **)(this + 8);
  if (plVar1 != (long *)0x0) {
    android::RefBase::decStrong((void *)((long)plVar1 + *(long *)(*plVar1 + -0x18)));
  }
  *(undefined **)(this + 0x38) = &DAT_0013b430;
  android::RefBase::~RefBase((RefBase *)(this + 0x38));
  operator_delete(this);
  return;
}



// virtual thunk to android::GxFpDevice::~GxFpDevice()

void __thiscall android::GxFpDevice::~GxFpDevice(GxFpDevice *this)

{
  ~GxFpDevice(this + *(long *)(*(long *)this + -0x18));
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0010b434(uint **param_1)

{
  undefined8 local_20;
  undefined8 uStack_18;
  undefined4 local_10;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","init, g_need_clean_fp_data=%d",g_need_clean_fp_data);
  if (g_need_clean_fp_data != 0) {
    local_10 = 0;
    local_20 = 0;
    uStack_18 = 0;
    android::Fp::gx_delFpTemplates(*param_1,(uint)&local_20);
    g_need_clean_fp_data = 0;
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void goodix_sensor_init(void)

{
  pthread_mutex_t *__mutex;
  long *plVar1;
  int iVar2;
  undefined4 uVar3;
  undefined4 local_20;
  undefined4 local_1c;
  long *local_18;
  long *local_10;
  long local_8;
  
  plVar1 = sGxFpDevice;
  local_8 = ___stack_chk_guard;
  if (sGxFpDevice != (long *)0x0) {
    __mutex = (pthread_mutex_t *)(sGxFpDevice + 2);
    pthread_mutex_lock(__mutex);
    local_18 = (long *)plVar1[1];
    if (local_18 != (long *)0x0) {
      android::RefBase::incStrong((void *)((long)local_18 + *(long *)(*local_18 + -0x18)));
    }
    pthread_mutex_unlock(__mutex);
    if (local_18 != (long *)0x0) {
      android::Fp::remote();
      if (local_10 != (long *)0x0) {
        __android_log_print(3,"FingerGoodix","fpcode, goodix sensor has already been inited!");
        if (local_10 != (long *)0x0) {
          android::RefBase::decStrong((void *)((long)local_10 + *(long *)(*local_10 + -0x18)));
        }
        if (local_18 != (long *)0x0) {
          android::RefBase::decStrong((void *)((long)local_18 + *(long *)(*local_18 + -0x18)));
        }
        uVar3 = 0;
        goto LAB_0010b5ac;
      }
      if (local_18 != (long *)0x0) {
        android::RefBase::decStrong((void *)((long)local_18 + *(long *)(*local_18 + -0x18)));
      }
    }
  }
  __android_log_print(3,"FingerGoodix","fpcode, goodix sensor need to init. merged");
  android::Fp::connect(0);
  if (local_18 == (long *)0x0) {
    uVar3 = 0xffffffff;
    __android_log_print(3,"FingerGoodix","fpcode, goodix_sensor_init(), Fp::connect failed!");
  }
  else if (*(int *)(local_18 + 6) == 0) {
    __android_log_print(3,"FingerGoodix","fpcode, goodix_sensor_init() ok!");
    local_10 = (long *)operator_new(0x48);
    android::GxFpDevice::GxFpDevice((GxFpDevice *)local_10,(sp *)&local_18);
    android::RefBase::incStrong((GxFpDevice *)((long)local_10 + *(long *)(*local_10 + -0x18)));
    if (sGxFpDevice != (long *)0x0) {
      android::RefBase::decStrong
                ((GxFpDevice *)((long)sGxFpDevice + *(long *)(*sGxFpDevice + -0x18)));
    }
    plVar1 = local_18;
    sGxFpDevice = local_10;
    android::RefBase::incStrong((GxFpDevice *)((long)local_10 + *(long *)(*local_10 + -0x18)));
    android::Fp::setListener((sp *)plVar1);
    if (local_10 != (long *)0x0) {
      android::RefBase::decStrong((GxFpDevice *)((long)local_10 + *(long *)(*local_10 + -0x18)));
    }
    local_10 = local_18;
    if (local_18 == (long *)0x0) {
      iVar2 = 0;
    }
    else {
      android::RefBase::incStrong((void *)((long)local_18 + *(long *)(*local_18 + -0x18)));
      iVar2 = (int)local_10;
    }
    local_1c = 0;
    local_20 = gCurrentActiveGroup;
    android::Fp::gx_gfCmdM(iVar2,(uchar *)0x1,(int)&local_20,(uchar *)0x4,0,(int *)0x0);
    if (local_10 != (long *)0x0) {
      android::RefBase::decStrong((void *)((long)local_10 + *(long *)(*local_10 + -0x18)));
    }
    android::Fp::gx_EngTest((int)local_18);
    local_10 = local_18;
    if (local_18 != (long *)0x0) {
      android::RefBase::incStrong((void *)((long)local_18 + *(long *)(*local_18 + -0x18)));
    }
    FUN_0010b434(&local_10);
    uVar3 = 0;
    if (local_10 != (long *)0x0) {
      android::RefBase::decStrong((void *)((long)local_10 + *(long *)(*local_10 + -0x18)));
    }
  }
  else {
    uVar3 = 0xffffffff;
    __android_log_print(3,"FingerGoodix","FpService initialization failed");
  }
  if (local_18 != (long *)0x0) {
    android::RefBase::decStrong((void *)((long)local_18 + *(long *)(*local_18 + -0x18)));
  }
LAB_0010b5ac:
  if (local_8 != ___stack_chk_guard) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail(uVar3);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void load_all_fpdata(void)

{
  pthread_mutex_t *__mutex;
  long lVar1;
  long lVar2;
  undefined4 uVar3;
  long *plVar4;
  
  lVar2 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","load_all_fpdata");
  lVar1 = sGxFpDevice;
  if (sGxFpDevice == 0) {
    uVar3 = 0xffffffff;
  }
  else {
    __mutex = (pthread_mutex_t *)(sGxFpDevice + 0x10);
    pthread_mutex_lock(__mutex);
    plVar4 = *(long **)(lVar1 + 8);
    if (plVar4 != (long *)0x0) {
      android::RefBase::incStrong((void *)((long)plVar4 + *(long *)(*plVar4 + -0x18)));
    }
    pthread_mutex_unlock(__mutex);
    if (plVar4 == (long *)0x0) {
      uVar3 = 0xfffffffe;
      __android_log_print(6,"FingerGoodix","fpcode, sGxFpDevice->getFp(), return NULL!");
    }
    else {
      uVar3 = android::Fp::gx_load_all_fpdata(plVar4);
      android::RefBase::decStrong((void *)((long)plVar4 + *(long *)(*plVar4 + -0x18)));
    }
  }
  if (lVar2 != ___stack_chk_guard) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail(uVar3);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void goodix_sensor_fp_set_user_id(void)

{
  pthread_mutex_t *__mutex;
  long lVar1;
  long lVar2;
  undefined4 uVar3;
  long *plVar4;
  
  lVar2 = ___stack_chk_guard;
  lVar1 = sGxFpDevice;
  __mutex = (pthread_mutex_t *)(sGxFpDevice + 0x10);
  pthread_mutex_lock(__mutex);
  plVar4 = *(long **)(lVar1 + 8);
  if (plVar4 != (long *)0x0) {
    android::RefBase::incStrong((void *)((long)plVar4 + *(long *)(*plVar4 + -0x18)));
  }
  pthread_mutex_unlock(__mutex);
  if (plVar4 == (long *)0x0) {
    uVar3 = 0xfffffffe;
    __android_log_print(6,"FingerGoodix","fpcode, sGxFpDevice->getFp(), return NULL!");
  }
  else {
    uVar3 = android::Fp::gx_set_user_id((ulong)plVar4);
    android::RefBase::decStrong((void *)((long)plVar4 + *(long *)(*plVar4 + -0x18)));
  }
  if (lVar2 != ___stack_chk_guard) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail(uVar3);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void goodix_set_fpdb_to_ta(void)

{
  pthread_mutex_t *__mutex;
  long lVar1;
  long lVar2;
  undefined4 uVar3;
  long *plVar4;
  
  lVar2 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","goodix_set_fpdb_to_ta");
  lVar1 = sGxFpDevice;
  if (sGxFpDevice == 0) {
    uVar3 = 0xffffffff;
  }
  else {
    __mutex = (pthread_mutex_t *)(sGxFpDevice + 0x10);
    pthread_mutex_lock(__mutex);
    plVar4 = *(long **)(lVar1 + 8);
    if (plVar4 != (long *)0x0) {
      android::RefBase::incStrong((char *)((long)plVar4 + *(long *)(*plVar4 + -0x18)));
    }
    pthread_mutex_unlock(__mutex);
    if (plVar4 == (long *)0x0) {
      uVar3 = 0xfffffffe;
      __android_log_print(6,"FingerGoodix","fpcode, sGxFpDevice->getFp(), return NULL!");
    }
    else {
      uVar3 = android::Fp::gx_set_fpdb_to_ta((char *)plVar4);
      android::RefBase::decStrong((char *)((long)plVar4 + *(long *)(*plVar4 + -0x18)));
    }
  }
  if (lVar2 != ___stack_chk_guard) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail(uVar3);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void goodix_sensor_set_active_group(undefined8 param_1,undefined4 param_2,long param_3)

{
  pthread_mutex_t *__mutex;
  long lVar1;
  int iVar2;
  undefined4 local_20;
  undefined4 local_1c;
  long *local_18;
  long *local_10;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  if (param_3 == 0) {
    iVar2 = -1;
    __android_log_print(6,"FingerGoodix","fpcode, The dir for the new FP group is invalid!");
  }
  else {
    iVar2 = set_active_group_to_channel(param_2,param_3);
    if (iVar2 == 0) {
      iVar2 = goodix_sensor_init();
      lVar1 = sGxFpDevice;
      if (iVar2 == 0) {
        __mutex = (pthread_mutex_t *)(sGxFpDevice + 0x10);
        pthread_mutex_lock(__mutex);
        local_18 = *(long **)(lVar1 + 8);
        if (local_18 != (long *)0x0) {
          android::RefBase::incStrong((void *)((long)local_18 + *(long *)(*local_18 + -0x18)));
        }
        pthread_mutex_unlock(__mutex);
        if (local_18 == (long *)0x0) {
          iVar2 = -1;
          __android_log_print(6,"FingerGoodix","fpcode, sGxFpDevice->getFp(), return NULL!");
        }
        else {
          local_10 = local_18;
          android::RefBase::incStrong((void *)((long)local_18 + *(long *)(*local_18 + -0x18)));
          local_1c = 0;
          local_20 = gCurrentActiveGroup;
          android::Fp::gx_gfCmdM
                    ((int)local_10,(uchar *)0x1,(int)&local_20,(uchar *)0x4,0,(int *)0x0);
          if (local_10 != (long *)0x0) {
            android::RefBase::decStrong((void *)((long)local_10 + *(long *)(*local_10 + -0x18)));
          }
          loadFingerPrintPlatformDataIfNeed(param_1);
          local_10 = local_18;
          if (local_18 != (long *)0x0) {
            android::RefBase::incStrong((void *)((long)local_18 + *(long *)(*local_18 + -0x18)));
          }
          FUN_0010b434(&local_10);
          iVar2 = 0;
          if (local_10 != (long *)0x0) {
            android::RefBase::decStrong((void *)((long)local_10 + *(long *)(*local_10 + -0x18)));
          }
        }
        if (local_18 != (long *)0x0) {
          android::RefBase::decStrong((void *)((long)local_18 + *(long *)(*local_18 + -0x18)));
        }
      }
      else {
        iVar2 = -1;
        __android_log_print(6,"FingerGoodix","fpcode, sGxFpDevice has not been inited");
      }
    }
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(iVar2);
}



// WARNING: Removing unreachable block (ram,0x0010be00)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void goodix_sensor_fill_auth_token_hmac(long param_1)

{
  pthread_mutex_t *__mutex;
  long lVar1;
  int iVar2;
  long *plVar3;
  undefined8 local_50;
  undefined8 uStack_48;
  undefined8 local_40;
  undefined8 uStack_38;
  undefined8 local_30;
  undefined8 uStack_28;
  undefined8 local_20;
  undefined8 uStack_18;
  undefined4 local_10;
  undefined local_c;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  if (param_1 == 0) {
    iVar2 = -1;
    __android_log_print(6,"FingerGoodix","fpcode, params are invalid!");
  }
  else {
    iVar2 = goodix_sensor_init();
    lVar1 = sGxFpDevice;
    if (iVar2 == 0) {
      __mutex = (pthread_mutex_t *)(sGxFpDevice + 0x10);
      pthread_mutex_lock(__mutex);
      plVar3 = *(long **)(lVar1 + 8);
      if (plVar3 != (long *)0x0) {
        android::RefBase::incStrong((void *)((long)plVar3 + *(long *)(*plVar3 + -0x18)));
      }
      pthread_mutex_unlock(__mutex);
      if (plVar3 == (long *)0x0) {
        iVar2 = -1;
        __android_log_print(6,"FingerGoodix","fpcode, sGxFpDevice->getFp(), return NULL!");
      }
      else {
        android::RefBase::incStrong((void *)((long)plVar3 + *(long *)(*plVar3 + -0x18)));
        local_10 = 0;
        local_c = 0;
        local_50 = 0;
        uStack_48 = 0;
        local_40 = 0;
        uStack_38 = 0;
        local_30 = 0;
        uStack_28 = 0;
        local_20 = 0;
        uStack_18 = 0;
        iVar2 = android::Fp::gx_gfCmdM
                          ((int)plVar3,(uchar *)0x3,(int)param_1,(uchar *)0x45,(int)&local_50,
                           (int *)0x45);
        if (iVar2 == 0) {
          iVar2 = -2;
        }
        if (plVar3 != (long *)0x0) {
          android::RefBase::decStrong((void *)((long)plVar3 + *(long *)(*plVar3 + -0x18)));
        }
        __android_log_print(3,"FingerGoodix","fill hmac ret: %d",iVar2);
      }
      if (plVar3 != (long *)0x0) {
        android::RefBase::decStrong((void *)((long)plVar3 + *(long *)(*plVar3 + -0x18)));
      }
    }
    else {
      iVar2 = -1;
      __android_log_print(6,"FingerGoodix","fpcode, sGxFpDevice has not been inited");
    }
  }
  if (local_8 != ___stack_chk_guard) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail(iVar2);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void goodix_sensor_fp_enroll_verify(int param_1)

{
  pthread_mutex_t *__mutex;
  long lVar1;
  long lVar2;
  undefined4 uVar3;
  long *plVar4;
  
  lVar2 = ___stack_chk_guard;
  lVar1 = sGxFpDevice;
  __mutex = (pthread_mutex_t *)(sGxFpDevice + 0x10);
  pthread_mutex_lock(__mutex);
  plVar4 = *(long **)(lVar1 + 8);
  if (plVar4 != (long *)0x0) {
    android::RefBase::incStrong((void *)((long)plVar4 + *(long *)(*plVar4 + -0x18)));
  }
  pthread_mutex_unlock(__mutex);
  if (plVar4 == (long *)0x0) {
    uVar3 = 0xfffffffe;
    __android_log_print(6,"FingerGoodix","fpcode, sGxFpDevice->getFp(), return NULL!");
  }
  else {
    uVar3 = android::Fp::gx_gfCmdM((int)plVar4,(uchar *)0x4,param_1,(uchar *)0x45,0,(int *)0x0);
    android::RefBase::decStrong((void *)((long)plVar4 + *(long *)(*plVar4 + -0x18)));
  }
  if (lVar2 != ___stack_chk_guard) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail(uVar3);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void goodix_sensor_fp_enroll(undefined4 param_1)

{
  pthread_mutex_t *__mutex;
  long lVar1;
  undefined4 uVar2;
  long *plVar3;
  long *local_10;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","fpcode, goodix_sensor_fp_enroll(), fingerId = %d",param_1);
  lVar1 = sGxFpDevice;
  if (sGxFpDevice == 0) {
    uVar2 = 0xffffffff;
    goto LAB_0010c0ec;
  }
  __mutex = (pthread_mutex_t *)(sGxFpDevice + 0x10);
  sFingerId = param_1;
  pthread_mutex_lock(__mutex);
  plVar3 = *(long **)(lVar1 + 8);
  if (plVar3 != (long *)0x0) {
    android::RefBase::incStrong((void *)((long)plVar3 + *(long *)(*plVar3 + -0x18)));
  }
  pthread_mutex_unlock(__mutex);
  if (plVar3 == (long *)0x0) {
    uVar2 = 0xfffffffe;
    __android_log_print(6,"FingerGoodix","fpcode, sGxFpDevice->getFp(), return NULL!");
LAB_0010c164:
    if (plVar3 == (long *)0x0) goto LAB_0010c0ec;
  }
  else {
    if (DAT_0013c10c != 0) {
      local_10 = plVar3;
      android::RefBase::incStrong((void *)((long)plVar3 + *(long *)(*plVar3 + -0x18)));
      FUN_0010b434(&local_10);
      if (local_10 != (long *)0x0) {
        android::RefBase::decStrong((void *)((long)local_10 + *(long *)(*local_10 + -0x18)));
      }
      uVar2 = android::Fp::gx_Register();
      goto LAB_0010c164;
    }
    uVar2 = 0xfffffffd;
  }
  android::RefBase::decStrong((void *)((long)plVar3 + *(long *)(*plVar3 + -0x18)));
LAB_0010c0ec:
  if (local_8 != ___stack_chk_guard) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail(uVar2);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void goodix_sensor_fp_clear_enroll_env(void)

{
  pthread_mutex_t *__mutex;
  long lVar1;
  long lVar2;
  long *plVar3;
  
  lVar2 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","fpcode, clear_enroll_env");
  lVar1 = sGxFpDevice;
  __mutex = (pthread_mutex_t *)(sGxFpDevice + 0x10);
  pthread_mutex_lock(__mutex);
  plVar3 = *(long **)(lVar1 + 8);
  if (plVar3 != (long *)0x0) {
    android::RefBase::incStrong((void *)((long)plVar3 + *(long *)(*plVar3 + -0x18)));
  }
  pthread_mutex_unlock(__mutex);
  if (plVar3 == (long *)0x0) {
    __android_log_print(6,"FingerGoodix","fpcode, sGxFpDevice->getFp(), return NULL!");
  }
  android::Fp::gx_EngTest((int)plVar3);
  if (plVar3 != (long *)0x0) {
    android::RefBase::decStrong((void *)((long)plVar3 + *(long *)(*plVar3 + -0x18)));
  }
  if (lVar2 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



// WARNING: Removing unreachable block (ram,0x0010c38c)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void goodix_sensor_fp_set_session_id(void)

{
  pthread_mutex_t *__mutex;
  long lVar1;
  long lVar2;
  long *plVar3;
  undefined4 uVar4;
  
  lVar2 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","fpcode, set session id.");
  lVar1 = sGxFpDevice;
  if (sGxFpDevice == 0) {
    uVar4 = 0xffffffff;
  }
  else {
    __mutex = (pthread_mutex_t *)(sGxFpDevice + 0x10);
    pthread_mutex_lock(__mutex);
    plVar3 = *(long **)(lVar1 + 8);
    if (plVar3 != (long *)0x0) {
      android::RefBase::incStrong((void *)((long)plVar3 + *(long *)(*plVar3 + -0x18)));
    }
    pthread_mutex_unlock(__mutex);
    if (plVar3 == (long *)0x0) {
      uVar4 = 0xfffffffe;
      __android_log_print(6,"FingerGoodix","fpcode, sGxFpDevice->getFp(), return NULL!");
    }
    else {
      uVar4 = 0xfffffffd;
      if (DAT_0013c10c != 0) {
        uVar4 = 0;
      }
      android::RefBase::decStrong((void *)((long)plVar3 + *(long *)(*plVar3 + -0x18)));
    }
  }
  if (lVar2 != ___stack_chk_guard) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail(uVar4);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void goodix_sensor_fp_match(long param_1)

{
  pthread_mutex_t *__mutex;
  long lVar1;
  undefined4 uVar2;
  long *plVar3;
  long *local_10;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","fpcode, goodix_sensor_fp_match(), operation_id = %lud",
                      *(undefined4 *)(param_1 + 1));
  lVar1 = sGxFpDevice;
  if (sGxFpDevice == 0) {
    uVar2 = 0xffffffff;
    goto LAB_0010c454;
  }
  __mutex = (pthread_mutex_t *)(sGxFpDevice + 0x10);
  pthread_mutex_lock(__mutex);
  plVar3 = *(long **)(lVar1 + 8);
  if (plVar3 != (long *)0x0) {
    android::RefBase::incStrong((void *)((long)plVar3 + *(long *)(*plVar3 + -0x18)));
  }
  pthread_mutex_unlock(__mutex);
  if (plVar3 == (long *)0x0) {
    uVar2 = 0xfffffffe;
    __android_log_print(6,"FingerGoodix","fpcode, sGxFpDevice->getFp(), return NULL!");
LAB_0010c4d0:
    if (plVar3 == (long *)0x0) goto LAB_0010c454;
  }
  else {
    if (DAT_0013c10c != 0) {
      local_10 = plVar3;
      android::RefBase::incStrong((void *)((long)plVar3 + *(long *)(*plVar3 + -0x18)));
      FUN_0010b434(&local_10);
      if (local_10 != (long *)0x0) {
        android::RefBase::decStrong((void *)((long)local_10 + *(long *)(*local_10 + -0x18)));
      }
      uVar2 = android::Fp::gx_Match(plVar3);
      goto LAB_0010c4d0;
    }
    uVar2 = 0xfffffffd;
  }
  android::RefBase::decStrong((void *)((long)plVar3 + *(long *)(*plVar3 + -0x18)));
LAB_0010c454:
  if (local_8 != ___stack_chk_guard) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail(uVar2);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void goodix_sensor_fp_cancel(int param_1)

{
  pthread_mutex_t *__mutex;
  long lVar1;
  long lVar2;
  long *plVar3;
  undefined8 uVar4;
  
  lVar2 = ___stack_chk_guard;
  lVar1 = sGxFpDevice;
  if (sGxFpDevice != 0) {
    __mutex = (pthread_mutex_t *)(sGxFpDevice + 0x10);
    pthread_mutex_lock(__mutex);
    plVar3 = *(long **)(lVar1 + 8);
    if (plVar3 != (long *)0x0) {
      android::RefBase::incStrong((void *)((long)plVar3 + *(long *)(*plVar3 + -0x18)));
    }
    pthread_mutex_unlock(__mutex);
    if (plVar3 != (long *)0x0) {
      __android_log_print(3,"FingerGoodix","fpcode, fp cancel!");
      if (param_1 == 1) {
        android::Fp::gx_RegisterCancel();
      }
      else if (param_1 == 2) {
        android::Fp::gx_MatchCancel();
      }
      uVar4 = 0;
      if (plVar3 != (long *)0x0) {
        android::RefBase::decStrong((void *)((long)plVar3 + *(long *)(*plVar3 + -0x18)));
      }
      goto LAB_0010c5c4;
    }
  }
  uVar4 = 0xffffffff;
LAB_0010c5c4:
  if (lVar2 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar4);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// goodix_sensor_fp_save(int)

void goodix_sensor_fp_save(int param_1)

{
  pthread_mutex_t *__mutex;
  long lVar1;
  long lVar2;
  long *plVar3;
  undefined8 uVar4;
  
  lVar2 = ___stack_chk_guard;
  lVar1 = sGxFpDevice;
  if (sGxFpDevice != 0) {
    __mutex = (pthread_mutex_t *)(sGxFpDevice + 0x10);
    pthread_mutex_lock(__mutex);
    plVar3 = *(long **)(lVar1 + 8);
    if (plVar3 != (long *)0x0) {
      android::RefBase::incStrong((void *)((long)plVar3 + *(long *)(*plVar3 + -0x18)));
    }
    pthread_mutex_unlock(__mutex);
    if (plVar3 != (long *)0x0) {
      uVar4 = 0;
      android::Fp::gx_RegisterSave((int)plVar3);
      if (plVar3 != (long *)0x0) {
        android::RefBase::decStrong((void *)((long)plVar3 + *(long *)(*plVar3 + -0x18)));
      }
      goto LAB_0010c6b4;
    }
  }
  uVar4 = 0xffffffff;
LAB_0010c6b4:
  if (lVar2 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar4);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void goodix_sensor_fp_get_fp_list(uint *param_1,char **param_2)

{
  pthread_mutex_t *__mutex;
  long lVar1;
  long *plVar2;
  undefined8 uVar3;
  long *local_10;
  long local_8;
  
  lVar1 = sGxFpDevice;
  local_8 = ___stack_chk_guard;
  if (sGxFpDevice != 0) {
    __mutex = (pthread_mutex_t *)(sGxFpDevice + 0x10);
    pthread_mutex_lock(__mutex);
    plVar2 = *(long **)(lVar1 + 8);
    if (plVar2 != (long *)0x0) {
      android::RefBase::incStrong((void *)((long)plVar2 + *(long *)(*plVar2 + -0x18)));
    }
    pthread_mutex_unlock(__mutex);
    if (plVar2 != (long *)0x0) {
      local_10 = plVar2;
      android::RefBase::incStrong((void *)((long)plVar2 + *(long *)(*plVar2 + -0x18)));
      FUN_0010b434(&local_10);
      if (local_10 != (long *)0x0) {
        android::RefBase::decStrong((void *)((long)local_10 + *(long *)(*local_10 + -0x18)));
      }
      android::Fp::gx_getFpTemplateList((uint *)plVar2,param_1,param_2);
      if (plVar2 == (long *)0x0) {
        uVar3 = 0;
      }
      else {
        android::RefBase::decStrong((void *)((long)plVar2 + *(long *)(*plVar2 + -0x18)));
        uVar3 = 0;
      }
      goto LAB_0010c7e4;
    }
  }
  uVar3 = 0xffffffff;
LAB_0010c7e4:
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar3);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void goodix_sensor_fp_remove(long param_1,int param_2,int param_3)

{
  pthread_mutex_t *__mutex;
  undefined8 *puVar1;
  int iVar2;
  undefined4 uVar3;
  long *plVar4;
  undefined8 uVar5;
  int *piVar6;
  undefined8 local_20;
  undefined8 uStack_18;
  undefined4 local_10;
  long local_8;
  
  puVar1 = sGxFpDevice;
  local_8 = ___stack_chk_guard;
  if (sGxFpDevice == (undefined8 *)0x0) {
    uVar5 = 0xffffffff;
  }
  else {
    __mutex = (pthread_mutex_t *)(sGxFpDevice + 2);
    pthread_mutex_lock(__mutex);
    plVar4 = (long *)puVar1[1];
    if (plVar4 != (long *)0x0) {
      android::RefBase::incStrong((void *)((long)plVar4 + *(long *)(*plVar4 + -0x18)));
    }
    pthread_mutex_unlock(__mutex);
    if (plVar4 == (long *)0x0) {
      uVar5 = 0xfffffffe;
    }
    else {
      if (DAT_0013c10c == 0) {
        uVar5 = 0xfffffffd;
      }
      else {
        if ((param_2 == 0) && (param_3 == 0)) {
          piVar6 = (int *)(param_1 + 0x138);
          android::RefBase::incStrong((void *)((long)plVar4 + *(long *)(*plVar4 + -0x18)));
          __android_log_print(3,"FingerGoodix","init, clean_fp_data_if_need_from_settings");
          local_10 = 0;
          local_20 = 0;
          uStack_18 = 0;
          iVar2 = android::Fp::gx_delFpTemplates((uint *)plVar4,(uint)&local_20);
          if (iVar2 == 0) {
            do {
              if (0 < *piVar6) {
                __android_log_print(3,"FingerGoodix",
                                    "clean_fp_data_if_need_from_settings:remove up-->%d\n");
                (**(code **)*sGxFpDevice)(sGxFpDevice,0x1004,0,*piVar6);
              }
              piVar6 = piVar6 + 1;
            } while (piVar6 != (int *)(param_1 + 0x14c));
          }
          loadFingerPrintPlatformDataIfNeed(param_1);
          __android_log_print(3,"FingerGoodix",
                              "init, clean_fp_data_if_need_from_settings,result:%d\n",iVar2);
          if (plVar4 != (long *)0x0) {
            android::RefBase::decStrong((void *)((long)plVar4 + *(long *)(*plVar4 + -0x18)));
          }
        }
        else {
          uVar3 = android::Fp::gx_UnRegister((int)plVar4);
          __android_log_print(3,"FingerGoodix","fpcode, UnRegister result:%d",uVar3);
          (**(code **)*sGxFpDevice)(sGxFpDevice,0x1004,0,param_2);
        }
        uVar5 = 0;
        (**(code **)*sGxFpDevice)(sGxFpDevice,0x1001,0,0);
        if (plVar4 == (long *)0x0) goto LAB_0010c9fc;
      }
      android::RefBase::decStrong((void *)((long)plVar4 + *(long *)(*plVar4 + -0x18)));
    }
  }
LAB_0010c9fc:
  if (local_8 != ___stack_chk_guard) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail(uVar5);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void goodix_sensor_fp_gxCmd
               (uint param_1,int param_2,undefined4 param_3,undefined8 param_4,undefined8 param_5)

{
  pthread_mutex_t *__mutex;
  long lVar1;
  uint uVar2;
  uint uVar3;
  long *plVar4;
  long *local_18;
  uint local_10 [2];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,0,"goodix_sensor_fp_gxCmd(%d, %d, %d, %p, %d)",param_1,param_2,param_3,
                      param_4,param_5);
  lVar1 = sGxFpDevice;
  if (sGxFpDevice != 0) {
    __mutex = (pthread_mutex_t *)(sGxFpDevice + 0x10);
    pthread_mutex_lock(__mutex);
    plVar4 = *(long **)(lVar1 + 8);
    if (plVar4 != (long *)0x0) {
      android::RefBase::incStrong((void *)((long)plVar4 + *(long *)(*plVar4 + -0x18)));
    }
    pthread_mutex_unlock(__mutex);
    if (plVar4 != (long *)0x0) {
      if (param_1 < 0xb) {
        local_18 = plVar4;
        android::RefBase::incStrong((void *)((long)plVar4 + *(long *)(*plVar4 + -0x18)));
        FUN_0010b434(&local_18);
        if (local_18 != (long *)0x0) {
          android::RefBase::decStrong((void *)((long)local_18 + *(long *)(*local_18 + -0x18)));
        }
        uVar3 = 0xfffffffd;
        if (param_1 - 1 < 7) {
          uVar2 = (uint)plVar4;
          switch(param_1) {
          case 1:
            uVar3 = 0;
            android::Fp::gx_EngTest(uVar2);
            break;
          case 2:
            if (param_2 - 1U < 3) {
              DAT_0013c110 = *(undefined4 *)(&DAT_001234a0 + (ulong)(param_2 - 1U) * 4);
            }
            else {
              DAT_0013c110 = 0xffffffff;
            }
            uVar3 = 0;
            android::Fp::gx_EngTest(uVar2);
            break;
          case 3:
            uVar3 = 0;
            android::Fp::gx_enableFingerScreenUnlock();
            DAT_0013c10c = 1;
            break;
          case 4:
            uVar3 = 0;
            DAT_0013c10c = 0;
            android::Fp::gx_disableFingerScreenUnlock();
            break;
          case 5:
            uVar3 = 0;
            android::Fp::gx_MatchCancel();
            android::Fp::gx_EngTest(uVar2);
            break;
          case 6:
            uVar3 = 0;
            android::Fp::gx_EngTest(uVar2);
            break;
          case 7:
            uVar3 = android::Fp::gx_setSafeClass(uVar2);
          }
        }
        local_10[0] = uVar3;
        send_fp_gx_cmd_exed(param_1,param_2,param_3,local_10,4);
        if (plVar4 == (long *)0x0) goto LAB_0010cb5c;
      }
      else {
        uVar3 = 0xfffffffe;
      }
      android::RefBase::decStrong((void *)((long)plVar4 + *(long *)(*plVar4 + -0x18)));
      goto LAB_0010cb5c;
    }
  }
  uVar3 = 0xffffffff;
LAB_0010cb5c:
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar3);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void goodix_sensor_fp_enumerate(int param_1,uint *param_2)

{
  pthread_mutex_t *__mutex;
  long lVar1;
  long lVar2;
  int iVar3;
  long *plVar4;
  
  lVar2 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","goodix_sensor_fp_enumerate");
  lVar1 = sGxFpDevice;
  if (sGxFpDevice == 0) {
    iVar3 = -1;
    goto LAB_0010ce10;
  }
  __mutex = (pthread_mutex_t *)(sGxFpDevice + 0x10);
  pthread_mutex_lock(__mutex);
  plVar4 = *(long **)(lVar1 + 8);
  if (plVar4 != (long *)0x0) {
    android::RefBase::incStrong((void *)((long)plVar4 + *(long *)(*plVar4 + -0x18)));
  }
  pthread_mutex_unlock(__mutex);
  if (plVar4 == (long *)0x0) {
    iVar3 = -2;
    __android_log_print(6,"FingerGoodix","fpcode, sGxFpDevice->getFp(), return NULL!");
LAB_0010ce68:
    if (plVar4 == (long *)0x0) goto LAB_0010ce10;
  }
  else {
    iVar3 = -3;
    if (DAT_0013c10c != 0) {
      iVar3 = android::Fp::gx_gfCmdM
                        ((int)plVar4,(uchar *)0xa,0,(uchar *)0x0,param_1,(int *)(ulong)*param_2);
      if (iVar3 == 0) {
        iVar3 = 0;
        *param_2 = 0;
      }
      else {
        *param_2 = 0;
      }
      goto LAB_0010ce68;
    }
  }
  android::RefBase::decStrong((void *)((long)plVar4 + *(long *)(*plVar4 + -0x18)));
LAB_0010ce10:
  if (lVar2 != ___stack_chk_guard) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail(iVar3);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// fido_disptach_command(android::sp<android::Fp>, int, int, int, unsigned char const*, long)

void fido_disptach_command
               (sp param_1,int param_2,int param_3,int param_4,uchar *param_5,long param_6)

{
  undefined4 uVar1;
  void *pvVar2;
  undefined8 uVar3;
  int local_98;
  undefined4 local_94;
  undefined auStack_90 [128];
  int local_10;
  int local_c;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  if (param_2 == 8) {
    uVar3 = 1;
    __android_log_print(3,"FingerGoodix",
                        "FINGERPRINT_GX_CMD_FIDO_START, aaid_len = %d, chanllege_len = %d, reqLen=%d"
                        ,param_3,param_4);
    local_10 = param_4;
    local_c = param_3;
    pvVar2 = memcpy(auStack_90,param_5,param_6);
    local_94 = 4;
    uVar1 = android::Fp::gx_gfCmdM
                      ((int)*(undefined8 *)(ulong)(byte)param_1,(uchar *)0x96,(int)pvVar2,
                       (uchar *)0x88,(int)&local_98,(int *)0x4);
    __android_log_print(3,"FingerGoodix","gx_gfCmdM ret:%d, cmd:%d, command execute status:%d",uVar1
                        ,8,local_98);
    DAT_0013c378 = -(uint)(local_98 != 0);
  }
  else if (param_2 == 9) {
    memset(&DAT_0013c380,0,0x208);
    local_98 = 0;
    DAT_0013c584 = -2;
    local_94 = 0x208;
    uVar1 = android::Fp::gx_gfCmdM
                      ((int)*(undefined8 *)(ulong)(byte)param_1,(uchar *)0x97,(int)&local_98,
                       (uchar *)0x4,0x13c380,(int *)0x208);
    __android_log_print(3,"FingerGoodix","SendCmd ret:%d, cmd:%d, command execute status:%d",uVar1,9
                        ,DAT_0013c584);
    if (DAT_0013c584 == 0) {
      __android_log_print(3,"FingerGoodix","fido_uvt_len:%d",DAT_0013c380);
      send_fp_gx_cmd_exed(9,0,0,&DAT_0013c384,(long)DAT_0013c380);
      uVar3 = 1;
      goto LAB_0010cf20;
    }
    uVar3 = 1;
    DAT_0013c378 = -1;
  }
  else {
    uVar3 = 0;
  }
  send_fp_gx_cmd_exed(param_2,param_3,param_4,&DAT_0013c378,4);
LAB_0010cf20:
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar3);
}



// android::sp<android::IBinder>::~sp()

void __thiscall android::sp<>::~sp(sp<> *this)

{
  long *plVar1;
  
  plVar1 = *(long **)this;
  if (plVar1 != (long *)0x0) {
    android::RefBase::decStrong((void *)((long)plVar1 + *(long *)(*plVar1 + -0x18)));
    return;
  }
  return;
}



// android::sp<FingerMSDeathNotifier>::~sp()

void __thiscall android::sp<>::~sp(sp<> *this)

{
  long *plVar1;
  
  plVar1 = *(long **)this;
  if (plVar1 != (long *)0x0) {
    android::RefBase::decStrong((void *)((long)plVar1 + *(long *)(*plVar1 + -0x18)));
    return;
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0010d10c(void)

{
  long *plVar1;
  long lVar2;
  long **in_x8;
  int iVar3;
  code *pcVar4;
  long *local_20;
  String16 aSStack_18 [8];
  long *local_10;
  long local_8;
  
  plVar1 = gFingerPrintMSBinder;
  local_8 = ___stack_chk_guard;
  if (gFingerPrintMSBinder == (long *)0x0) {
    iVar3 = 0x1f;
    android::defaultServiceManager();
    while( true ) {
      pcVar4 = *(code **)(*local_20 + 0x28);
      android::String16::String16(aSStack_18,"fingerprint");
      (*pcVar4)(local_20,aSStack_18);
      if (gFingerPrintMSBinder != (long *)0x0) {
        android::RefBase::decStrong
                  ((void *)((long)gFingerPrintMSBinder + *(long *)(*gFingerPrintMSBinder + -0x18)));
      }
      gFingerPrintMSBinder = local_10;
      android::String16::~String16(aSStack_18);
      if (gFingerPrintMSBinder != (long *)0x0) {
        __android_log_print(3,"FingerGoodix","get FingerPrintService ,gFingerPrintMSBinder:%d.",1);
        if (gFingerMSDeathNotifier == (long *)0x0) {
          plVar1 = (long *)operator_new(0x18);
          android::RefBase::RefBase((RefBase *)(plVar1 + 1));
          *plVar1 = (long)&PTR_binderDied_0013b5f8;
          plVar1[1] = (long)&PTR__FingerMSDeathNotifier_0013b648;
          android::RefBase::incStrong(plVar1 + 1);
          if (gFingerMSDeathNotifier != (long *)0x0) {
            android::RefBase::decStrong
                      ((void *)((long)gFingerMSDeathNotifier +
                               *(long *)(*gFingerMSDeathNotifier + -0x18)));
          }
          pcVar4 = *(code **)(*gFingerPrintMSBinder + 0x30);
          gFingerMSDeathNotifier = plVar1;
        }
        else {
          pcVar4 = *(code **)(*gFingerPrintMSBinder + 0x30);
        }
        plVar1 = gFingerPrintMSBinder;
        local_10 = gFingerMSDeathNotifier;
        android::RefBase::incStrong
                  ((void *)((long)gFingerMSDeathNotifier +
                           *(long *)(*gFingerMSDeathNotifier + -0x18)));
        (*pcVar4)(plVar1,&local_10,0,0);
        if (local_10 != (long *)0x0) {
          android::RefBase::decStrong((void *)((long)local_10 + *(long *)(*local_10 + -0x18)));
        }
        plVar1 = gFingerPrintMSBinder;
        *in_x8 = gFingerPrintMSBinder;
        if (plVar1 != (long *)0x0) {
          android::RefBase::incStrong((void *)((long)plVar1 + *(long *)(*plVar1 + -0x18)));
        }
        goto LAB_0010d2d4;
      }
      iVar3 = iVar3 + -1;
      if (iVar3 == 0) break;
      usleep(500000);
    }
    __android_log_print(6,"FingerGoodix","get FingerPrintService ,failed:%d.",0x1f);
    *in_x8 = (long *)0x0;
LAB_0010d2d4:
    if (local_20 != (long *)0x0) {
      android::RefBase::decStrong((void *)((long)local_20 + *(long *)(*local_20 + -0x18)));
    }
  }
  else {
    lVar2 = *gFingerPrintMSBinder;
    *in_x8 = gFingerPrintMSBinder;
    android::RefBase::incStrong((void *)((long)plVar1 + *(long *)(lVar2 + -0x18)));
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



// FingerMSDeathNotifier::~FingerMSDeathNotifier()

void __thiscall FingerMSDeathNotifier::~FingerMSDeathNotifier(FingerMSDeathNotifier *this)

{
  android::RefBase::~RefBase((RefBase *)(this + 8));
  return;
}



// virtual thunk to FingerMSDeathNotifier::~FingerMSDeathNotifier()

void __thiscall FingerMSDeathNotifier::~FingerMSDeathNotifier(FingerMSDeathNotifier *this)

{
  ~FingerMSDeathNotifier(this + *(long *)(*(long *)this + -0x18));
  return;
}



// FingerMSDeathNotifier::~FingerMSDeathNotifier()

void __thiscall FingerMSDeathNotifier::~FingerMSDeathNotifier(FingerMSDeathNotifier *this)

{
  android::RefBase::~RefBase((RefBase *)(this + 8));
  operator_delete(this);
  return;
}



// virtual thunk to FingerMSDeathNotifier::~FingerMSDeathNotifier()

void __thiscall FingerMSDeathNotifier::~FingerMSDeathNotifier(FingerMSDeathNotifier *this)

{
  ~FingerMSDeathNotifier(this + *(long *)(*(long *)this + -0x18));
  return;
}



// FingerMSDeathNotifier::binderDied(android::wp<android::IBinder> const&)

void FingerMSDeathNotifier::binderDied(wp *param_1)

{
  __android_log_print(3,"FingerGoodix","FingerMSDeathNotifier binderDied");
  if (gFingerPrintMSBinder != (long *)0x0) {
    android::RefBase::decStrong
              ((void *)((long)gFingerPrintMSBinder + *(long *)(*gFingerPrintMSBinder + -0x18)));
  }
  gFingerPrintMSBinder = (long *)0x0;
  __android_log_print(3,"FingerGoodix","Fp server died!");
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked
// check_file_can_read()

undefined8 check_file_can_read(void)

{
  FILE *__stream;
  undefined4 *puVar1;
  
  if (gFpdbPath != '\0') {
    __stream = fopen(&gFpdbPath,"r");
    puVar1 = (undefined4 *)__errno();
    __android_log_print(3,"FingerGoodix","check_file_can_read errno:%d",*puVar1);
    if (__stream != (FILE *)0x0) {
      __android_log_print(3,"FingerGoodix","check_file_can_read OK");
      fclose(__stream);
      return 0;
    }
  }
  return 0xffffffff;
}



undefined8 set_fpdb_path(char *param_1)

{
  size_t sVar1;
  
  sVar1 = strlen(param_1);
  __android_log_print(3,"FingerGoodix","set_fpdb_path source path: %s",param_1);
  memset(&gFpdbPath,0,0x100);
  memcpy(&gFpdbPath,param_1,(long)((int)sVar1 + -0xb));
  sVar1 = strlen(&gFpdbPath);
  *(undefined8 *)(&DAT_0013c5b0 + sVar1) = 0x6c6d782e746e6972;
  (&DAT_0013c5b8)[sVar1] = '\0';
  *(undefined8 *)(&gFpdbPath + sVar1) = 0x73676e6974746573;
  *(undefined8 *)(&DAT_0013c5a8 + sVar1) = 0x707265676e69665f;
  __android_log_print(3,"FingerGoodix","set_fpdb_path %s",&gFpdbPath);
  return 0;
}



void wait_for_boot_complete(void)

{
  int iVar1;
  
  __android_log_print(3,"FingerGoodix","wait_for_boot_complete,%d",gIsBootCompleted);
  if (gIsBootCompleted != 1) {
    while( true ) {
      iVar1 = property_get_int32("sys.boot_completed",0);
      __android_log_print(3,"FingerGoodix","wait_for_boot_complete,boot_complete_value:%d",iVar1);
      if (iVar1 == 1) break;
      usleep(1000000);
    }
    __android_log_print(3,"FingerGoodix","wait_for_boot_complete OK");
    gIsBootCompleted = 1;
  }
  return;
}



undefined8 clear_check_when_set_active_group(void)

{
  DAT_0013c590 = 0;
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void checkConsistence(void *param_1)

{
  pthread_t local_48;
  pthread_attr_t pStack_40;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","gCheckFingerprintidsConsistence:%d",DAT_0013c590);
  if (DAT_0013c590 != 1) {
    pthread_attr_init(&pStack_40);
    pthread_attr_setdetachstate(&pStack_40,1);
    pthread_create(&local_48,&pStack_40,deleteThread,param_1);
    pthread_join(local_48,(void **)0x0);
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



// android::sp<android::IBinder>::TEMPNAMEPLACEHOLDERVALUE(android::sp<android::IBinder> const&)

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



// WARNING: Removing unreachable block (ram,0x0010d908)
// WARNING: Removing unreachable block (ram,0x0010d914)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// getFrameworkFingerID(int*, int)

void getFrameworkFingerID(int *param_1,int param_2)

{
  int iVar1;
  undefined8 uVar2;
  String16 aSStack_e0 [8];
  Parcel aPStack_d8 [104];
  long *local_70 [13];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  if (gPmsBinder == (long *)0x0) {
    FUN_0010d10c();
    android::sp<>::operator=((sp<> *)&gPmsBinder,(sp *)local_70);
    if (local_70[0] != (long *)0x0) {
      android::RefBase::decStrong((void *)((long)local_70[0] + *(long *)(*local_70[0] + -0x18)));
    }
  }
  if (gFingerPrintMSBinder == 0) {
    iVar1 = -1;
  }
  else {
    __android_log_print(3,"FingerGoodix","Check finger print");
    android::Parcel::Parcel(aPStack_d8);
    android::Parcel::Parcel((Parcel *)local_70);
    android::String16::String16(aSStack_e0,"android.hardware.fingerprint.IFingerprintService");
    android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
    android::String16::~String16(aSStack_e0);
    android::Parcel::writeInt32((int)aPStack_d8);
    android::String16::String16(aSStack_e0,"com.android.settings");
    android::Parcel::writeString16((String16 *)aPStack_d8);
    android::String16::~String16(aSStack_e0);
    (**(code **)(*gPmsBinder + 0x28))(gPmsBinder,7,aPStack_d8,local_70,0);
    uVar2 = android::Parcel::dataSize();
    __android_log_print(3,"FingerGoodix","getFrameworkFingerID reply size: %d",uVar2);
    iVar1 = android::Parcel::readExceptionCode();
    __android_log_print(3,"FingerGoodix","getFrameworkFingerID ret: %d",iVar1);
    if (iVar1 != 0) {
      android::Parcel::readString16();
      android::String16::~String16(aSStack_e0);
    }
    android::Parcel::readInt32((int *)local_70);
    __android_log_print(3,"FingerGoodix","final finger state: %d",iVar1);
    android::Parcel::~Parcel((Parcel *)local_70);
    android::Parcel::~Parcel(aPStack_d8);
  }
  if (local_8 != ___stack_chk_guard) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail(iVar1);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// removeSettingFingerprintId(int, int)

void removeSettingFingerprintId(int param_1,int param_2)

{
  int iVar1;
  int iVar2;
  String16 aSStack_f8 [8];
  undefined8 local_f0;
  undefined8 local_e8;
  int local_e0;
  Parcel aPStack_d8 [104];
  long *local_70 [13];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  local_f0 = 0;
  local_e8 = 0;
  local_e0 = 0;
  if (gPmsBinder == (long *)0x0) {
    FUN_0010d10c();
    android::sp<>::operator=((sp<> *)&gPmsBinder,(sp *)local_70);
    if (local_70[0] != (long *)0x0) {
      android::RefBase::decStrong((void *)((long)local_70[0] + *(long *)(*local_70[0] + -0x18)));
    }
  }
  if (gFingerPrintMSBinder != 0) {
    __android_log_print(3,"FingerGoodix","removeSettingFingerprintId");
    iVar2 = 4;
    android::Parcel::Parcel(aPStack_d8);
    android::Parcel::Parcel((Parcel *)local_70);
    android::String16::String16(aSStack_f8,"android.hardware.fingerprint.IFingerprintService");
    android::Parcel::writeInterfaceToken((String16 *)aPStack_d8);
    android::String16::~String16(aSStack_f8);
    android::Parcel::writeStrongBinder((sp *)aPStack_d8);
    iVar1 = (int)aPStack_d8;
    android::Parcel::writeInt32(iVar1);
    android::Parcel::writeInt32(iVar1);
    android::Parcel::writeInt32(iVar1);
    (**(code **)(*gPmsBinder + 0x28))(gPmsBinder,5,aPStack_d8,local_70,0);
    do {
      local_f0 = 0;
      local_e8 = 0;
      local_e0 = 0;
      iVar1 = getFrameworkFingerID((int *)&local_f0,gCurrentActiveGroup);
      if (iVar1 != -1) {
        if (((((int)local_f0 != param_1) && (local_f0._4_4_ != param_1)) &&
            ((int)local_e8 != param_1)) && ((local_e8._4_4_ != param_1 && (local_e0 != param_1)))) {
          __android_log_print(3,"FingerGoodix","removeSettingFingerprintId delete sucess");
          break;
        }
        __android_log_print(3,"FingerGoodix","removeSettingFingerprintId delete continue:%d",param_1
                           );
      }
      usleep(180000);
      iVar2 = iVar2 + -1;
    } while (iVar2 != 0);
    android::Parcel::~Parcel((Parcel *)local_70);
    android::Parcel::~Parcel(aPStack_d8);
  }
  if (local_8 != ___stack_chk_guard) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail(0);
  }
  return;
}



// checkFrameworkToHal(st_fingerprint_hal_device_t*)

int checkFrameworkToHal(st_fingerprint_hal_device_t *param_1)

{
  int iVar1;
  int iVar2;
  long lVar3;
  
  gCurrentFingeridsNum = *(undefined4 *)(param_1 + 0x1a0);
  lVar3 = 0;
  __android_log_print(3,"FingerGoodix","checkFrameworkToHal,check_consistence-->current_num:%d",
                      gCurrentFingeridsNum);
  do {
    iVar1 = *(int *)((long)&gIds + lVar3);
    __android_log_print(3,"FingerGoodix","checkFrameworkToHal,check_consistence:%d\n",iVar1);
    if (*(int *)((long)&gIds + lVar3) == 0) {
      return 0;
    }
    if ((((((iVar1 == *(int *)(param_1 + 0x138)) && (*(int *)(param_1 + 0x138) != 0)) ||
          ((iVar1 == *(int *)(param_1 + 0x13c) && (*(int *)(param_1 + 0x13c) != 0)))) ||
         ((iVar1 == *(int *)(param_1 + 0x140) && (*(int *)(param_1 + 0x140) != 0)))) ||
        ((iVar1 == *(int *)(param_1 + 0x144) && (*(int *)(param_1 + 0x144) != 0)))) ||
       ((iVar1 == *(int *)(param_1 + 0x148) && (*(int *)(param_1 + 0x148) != 0)))) {
      gIsConsistence = 1;
    }
    __android_log_print(3,"FingerGoodix","checkFrameworkToHal,is_consistence:%d",gIsConsistence);
    iVar2 = gIsConsistence;
    if (gIsConsistence == 0) {
      removeSettingFingerprintId(iVar1,gCurrentActiveGroup);
      iVar2 = usleep(180000);
    }
    lVar3 = lVar3 + 4;
    gIsConsistence = 0;
  } while (lVar3 != 0x14);
  gIsConsistence = 0;
  return iVar2;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// checkHalToFramework(st_fingerprint_hal_device_t*)

ulong checkHalToFramework(st_fingerprint_hal_device_t *param_1)

{
  int iVar1;
  ulong uVar2;
  int *piVar3;
  
  _gIds = 0;
  _DAT_0013c6b8 = 0;
  DAT_0013c6c0 = 0;
  uVar2 = getFrameworkFingerID(&gIds,gCurrentActiveGroup);
  if ((int)uVar2 != -1) {
    gCurrentFingeridsNum = *(undefined4 *)(param_1 + 0x1a0);
    piVar3 = (int *)(param_1 + 0x138);
    __android_log_print(3,"FingerGoodix","checkHalToFramework,check_consistence-->current_num:%d",
                        gCurrentFingeridsNum);
    do {
      iVar1 = *piVar3;
      uVar2 = __android_log_print(3,"FingerGoodix","checkHalToFramework,check_consistence:%d\n",
                                  iVar1);
      if (iVar1 != 0) {
        if ((((((iVar1 == gIds) && (gIds != 0)) || ((iVar1 == DAT_0013c6b4 && (DAT_0013c6b4 != 0))))
             || ((iVar1 == DAT_0013c6b8 && (DAT_0013c6b8 != 0)))) ||
            ((iVar1 == DAT_0013c6bc && (DAT_0013c6bc != 0)))) ||
           ((iVar1 == DAT_0013c6c0 && (DAT_0013c6c0 != 0)))) {
          gIsConsistence = 1;
        }
        __android_log_print(3,"FingerGoodix","checkHalToFramework,is_consistence:%d",gIsConsistence)
        ;
        if (gIsConsistence == 0) {
          removeSettingFingerprintId(iVar1,gCurrentActiveGroup);
          gIsConsistence = usleep(180000);
        }
        uVar2 = (ulong)gIsConsistence;
        gIsConsistence = 0;
      }
      piVar3 = piVar3 + 1;
    } while (piVar3 != (int *)(param_1 + 0x14c));
  }
  return uVar2;
}



// deleteThread(void*)

undefined8 deleteThread(void *param_1)

{
  int iVar1;
  
  __android_log_print(3,"FingerGoodix","createDeleteThread");
  wait_for_boot_complete();
  iVar1 = getFrameworkFingerID(&gIds,gCurrentActiveGroup);
  if (iVar1 != -1) {
    checkFrameworkToHal((st_fingerprint_hal_device_t *)param_1);
    checkHalToFramework((st_fingerprint_hal_device_t *)param_1);
    if (gCheckFingerprintidsConsistence_flag == 1) {
      DAT_0013c590 = 1;
    }
    __android_log_print(3,"FingerGoodix","check_consistence:end");
    return 0;
  }
  DAT_0013c590 = 1;
  return 0;
}



undefined8 msgqueue_open(undefined8 *param_1)

{
  undefined8 *puVar1;
  undefined8 uVar2;
  
  __android_log_print(3,"FingerGoodix","%s:start message queue open","msgqueue_open");
  puVar1 = (undefined8 *)malloc(0x58);
  if (puVar1 == (undefined8 *)0x0) {
    __android_log_print(6,"FingerGoodix","%s:alloc message manage queue struct error",
                        "msgqueue_open");
    uVar2 = 0xfffffff4;
  }
  else {
    *puVar1 = 0;
    puVar1[1] = 0;
    puVar1[2] = 0;
    puVar1[3] = 0;
    puVar1[4] = 0;
    puVar1[5] = 0;
    puVar1[6] = 0;
    puVar1[7] = 0;
    puVar1[8] = 0;
    puVar1[9] = 0;
    puVar1[10] = 0;
    pthread_mutex_init((pthread_mutex_t *)((long)puVar1 + 4),(pthread_mutexattr_t *)0x0);
    sem_init((sem_t *)((long)puVar1 + 0x2c),0,0);
    *param_1 = puVar1;
    *(undefined4 *)puVar1 = 0x4d414751;
    uVar2 = 0;
    puVar1[8] = 0;
    puVar1[9] = puVar1 + 8;
  }
  return uVar2;
}



undefined8 msg_send(int *param_1,undefined4 param_2,undefined4 param_3,void *param_4,int param_5)

{
  undefined4 *__ptr;
  void *__dest;
  long lVar1;
  void **ppvVar2;
  
  if ((0 < param_5 && param_4 == (void *)0x0) || (param_5 < 0)) {
    __android_log_print(6,"FingerGoodix","%s:message parameter error","msg_send");
    return 0xfffffff2;
  }
  if ((param_1 == (int *)0x0) || (*param_1 != 0x4d414751)) {
    __android_log_print(6,"FingerGoodix","%s:message queue handle = %p error","msg_send",param_1);
    return 0xfffffff2;
  }
  __ptr = (undefined4 *)malloc(0x28);
  if (__ptr == (undefined4 *)0x0) {
    __android_log_print(6,"FingerGoodix","%s:malloc message item error","msg_send");
    return 0xfffffff4;
  }
  *__ptr = param_2;
  __ptr[1] = param_3;
  if (param_5 == 0) {
    *(undefined8 *)(__ptr + 2) = 0;
    __ptr[4] = 0;
    pthread_mutex_lock((pthread_mutex_t *)(param_1 + 1));
    lVar1 = *(long *)(param_1 + 0x10);
  }
  else {
    __dest = malloc((long)param_5);
    if (__dest == (void *)0x0) {
      __android_log_print(6,"FingerGoodix","%s:malloc message buffer error","msg_send");
      free(__ptr);
      return 0xfffffff4;
    }
    memcpy(__dest,param_4,(long)param_5);
    *(void **)(__ptr + 2) = __dest;
    __ptr[4] = param_5;
    pthread_mutex_lock((pthread_mutex_t *)(param_1 + 1));
    lVar1 = *(long *)(param_1 + 0x10);
  }
  if (lVar1 == 0) {
    *(undefined8 *)(__ptr + 6) = 0;
    *(undefined4 **)(param_1 + 0x12) = __ptr + 6;
    *(undefined4 **)(param_1 + 0x10) = __ptr;
    *(int **)(__ptr + 8) = param_1 + 0x10;
  }
  else {
    do {
      if (*(int *)(lVar1 + 4) < (int)__ptr[1]) {
        *(undefined8 *)(__ptr + 8) = *(undefined8 *)(lVar1 + 0x20);
        *(long *)(__ptr + 6) = lVar1;
        **(void ***)(lVar1 + 0x20) = __ptr;
        *(undefined4 **)(lVar1 + 0x20) = __ptr + 6;
        goto LAB_0010e23c;
      }
      lVar1 = *(long *)(lVar1 + 0x18);
    } while (lVar1 != 0);
    ppvVar2 = *(void ***)(param_1 + 0x12);
    *(undefined8 *)(__ptr + 6) = 0;
    *(void ***)(__ptr + 8) = ppvVar2;
    *ppvVar2 = __ptr;
    *(undefined4 **)(param_1 + 0x12) = __ptr + 6;
  }
LAB_0010e23c:
  __android_log_print(3,"FingerGoodix","%s:add a message item to message queue","msg_send");
  param_1[0x14] = param_1[0x14] + 1;
  pthread_mutex_unlock((pthread_mutex_t *)(param_1 + 1));
  sem_post((sem_t *)(param_1 + 0xb));
  return 0;
}



int msg_receive(int *param_1,undefined4 *param_2,void *param_3,int param_4)

{
  pthread_mutex_t *__mutex;
  int iVar1;
  long lVar2;
  long *plVar3;
  char *pcVar4;
  undefined4 *__ptr;
  
  if ((param_3 == (void *)0x0) || (param_4 != 0)) {
    if (param_2 != (undefined4 *)0x0) {
      if ((param_1 == (int *)0x0) || (*param_1 != 0x4d414751)) {
        __android_log_print(6,"FingerGoodix","%s:message queue handle = %p error","msg_receive",
                            param_1);
        return -0xe;
      }
      __mutex = (pthread_mutex_t *)(param_1 + 1);
      __android_log_print(3,"FingerGoodix","%s:wait a message","msg_receive");
      sem_wait((sem_t *)(param_1 + 0xb));
      pthread_mutex_lock(__mutex);
      iVar1 = param_1[0x14];
      if ((0 < iVar1) && (__ptr = *(undefined4 **)(param_1 + 0x10), __ptr != (undefined4 *)0x0)) {
        lVar2 = *(long *)(__ptr + 6);
        plVar3 = *(long **)(__ptr + 8);
        if (lVar2 == 0) {
          *(long **)(param_1 + 0x12) = plVar3;
        }
        else {
          *(long **)(lVar2 + 0x20) = plVar3;
          plVar3 = *(long **)(__ptr + 8);
        }
        *plVar3 = lVar2;
        param_1[0x14] = iVar1 + -1;
        pthread_mutex_unlock(__mutex);
        __android_log_print(3,"FingerGoodix","%s:receive a message item from queue","msg_receive");
        if ((int)__ptr[4] < param_4) {
          param_4 = __ptr[4];
        }
        __android_log_print(3,"FingerGoodix","%s:message copy length = %d","msg_receive",param_4);
        if ((0 < param_4) && (param_3 != (void *)0x0)) {
          memcpy(param_3,*(void **)(__ptr + 2),(long)param_4);
        }
        if (*(void **)(__ptr + 2) != (void *)0x0) {
          free(*(void **)(__ptr + 2));
        }
        *param_2 = *__ptr;
        free(__ptr);
        return param_4;
      }
      __android_log_print(6,"FingerGoodix","%s:message queue error","msg_receive");
      pthread_mutex_unlock(__mutex);
      return -0x10;
    }
    pcVar4 = "%s:message type point is null";
  }
  else {
    pcVar4 = "%s:message buffer parameter error";
  }
  __android_log_print(6,"FingerGoodix",pcVar4,"msg_receive");
  return -0xe;
}



undefined8 msgqueue_close(int *param_1)

{
  int iVar1;
  long lVar2;
  long *plVar3;
  void *__ptr;
  
  if ((param_1 != (int *)0x0) && (*param_1 == 0x4d414751)) {
    while (__ptr = *(void **)(param_1 + 0x10), __ptr != (void *)0x0) {
      lVar2 = *(long *)((long)__ptr + 0x18);
      plVar3 = *(long **)((long)__ptr + 0x20);
      if (lVar2 == 0) {
        *(long **)(param_1 + 0x12) = plVar3;
      }
      else {
        *(long **)(lVar2 + 0x20) = plVar3;
        plVar3 = *(long **)((long)__ptr + 0x20);
      }
      iVar1 = *(int *)((long)__ptr + 0x10);
      *plVar3 = lVar2;
      if ((iVar1 != 0) && (*(void **)((long)__ptr + 8) != (void *)0x0)) {
        free(*(void **)((long)__ptr + 8));
      }
      free(__ptr);
    }
    sem_destroy((sem_t *)(param_1 + 0xb));
    pthread_mutex_destroy((pthread_mutex_t *)(param_1 + 1));
    free(param_1);
    return 0;
  }
  __android_log_print(6,"FingerGoodix","%s:message queue handle = %p error","msgqueue_close",param_1
                     );
  return 0xfffffff2;
}



undefined8 dump_msgqueue(int *param_1)

{
  undefined8 uVar1;
  undefined4 *puVar2;
  
  if ((param_1 == (int *)0x0) || (*param_1 != 0x4d414751)) {
    __android_log_print(6,"FingerGoodix","%s:message queue handle = %p error","dump_msgqueue",
                        param_1);
    uVar1 = 0xfffffff2;
  }
  else {
    uVar1 = __android_log_print(3,"FingerGoodix","%s:message queue item num is %d\n","dump_msgqueue"
                                ,param_1[0x14]);
    puVar2 = *(undefined4 **)(param_1 + 0x10);
    if (puVar2 != (undefined4 *)0x0) {
      do {
        __android_log_print(3,"FingerGoodix","%s:message  item addre =  %p\n","dump_msgqueue",puVar2
                           );
        __android_log_print(3,"FingerGoodix","%s:message  msg_type =  %d\n","dump_msgqueue",*puVar2)
        ;
        __android_log_print(3,"FingerGoodix","%s:message  msg_prio =  %d\n","dump_msgqueue",
                            puVar2[1]);
        __android_log_print(3,"FingerGoodix","%s:message  msg_param =  %p\n","dump_msgqueue",
                            *(undefined8 *)(puVar2 + 2));
        uVar1 = __android_log_print(3,"FingerGoodix","%s:message  param_size =  %d\n",
                                    "dump_msgqueue",puVar2[4]);
        puVar2 = *(undefined4 **)(puVar2 + 6);
      } while (puVar2 != (undefined4 *)0x0);
      return uVar1;
    }
  }
  return uVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0010e81c(int *param_1)

{
  int iVar1;
  undefined4 uVar2;
  undefined auStack_1c [4];
  long local_18;
  code *local_10;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  if ((param_1 != (int *)0x0) && (*param_1 == 0x574f524b)) {
    while( true ) {
      while( true ) {
        while( true ) {
          iVar1 = msg_receive(*(undefined8 *)(param_1 + 2),auStack_1c,&local_18,0x10);
          __android_log_print(3,"FingerGoodix","%s:receive a message msg_len = %d",
                              "worker_thread_loop",iVar1);
          if (iVar1 == 0x10) break;
          __android_log_print(6,"FingerGoodix","%s:receive message error msg_len = %d",
                              "worker_thread_loop",iVar1);
        }
        if (local_10 == (code *)0x0) break;
        uVar2 = (*local_10)(local_18);
        __android_log_print(3,"FingerGoodix","%s:callback func %p return value = %d",
                            "worker_thread_loop",local_10,uVar2);
      }
      if (local_18 == 0x45584954) break;
      __android_log_print(3,"FingerGoodix","%s:exec func is null","worker_thread_loop");
    }
    __android_log_print(3,"FingerGoodix","%s:worker thread exit","worker_thread_loop");
    msgqueue_close(*(undefined8 *)(param_1 + 2));
    free(param_1);
                    // WARNING: Subroutine does not return
    pthread_exit((void *)0x0);
  }
  __android_log_print(6,"FingerGoodix","%s:worker handle error,worker thread exit",
                      "worker_thread_loop");
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(0);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void gf_worker_thread_create(undefined8 *param_1)

{
  int iVar1;
  undefined4 *__ptr;
  undefined8 local_18;
  pthread_t local_10;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  __android_log_print(3,"FingerGoodix","%s:start worker thread create","gf_worker_thread_create");
  __ptr = (undefined4 *)malloc(0x18);
  if (__ptr == (undefined4 *)0x0) {
    __android_log_print(6,"FingerGoodix","%s:alloc worker  handle struct error",
                        "gf_worker_thread_create");
    iVar1 = -0xc;
  }
  else {
    *__ptr = 0x574f524b;
    iVar1 = msgqueue_open(&local_18);
    if (iVar1 < 0) {
      __android_log_print(6,"FingerGoodix","%s:creat message queue error %d",
                          "gf_worker_thread_create",iVar1);
      free(__ptr);
    }
    else {
      iVar1 = pthread_create(&local_10,(pthread_attr_t *)0x0,FUN_0010e81c,__ptr);
      if (iVar1 == 0) {
        iVar1 = 0;
        *(undefined8 *)(__ptr + 2) = local_18;
        *(pthread_t *)(__ptr + 4) = local_10;
        *param_1 = __ptr;
      }
      else {
        __android_log_print(6,"FingerGoodix","%s:Failed to create handle message loop thread.",
                            "gf_worker_thread_create");
        msgqueue_close(local_18);
        free(__ptr);
      }
    }
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(iVar1);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void gf_send_callback_msg(int *param_1,undefined8 param_2,undefined8 param_3)

{
  int iVar1;
  int iVar2;
  undefined8 local_18;
  undefined8 local_10;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  if ((param_1 == (int *)0x0) || (*param_1 != 0x574f524b)) {
    __android_log_print(6,"FingerGoodix","%s:worker thread not init,or worker thread is closed",
                        "gf_send_callback_msg");
    iVar2 = -1;
  }
  else {
    __android_log_print(3,"FingerGoodix","%s:param = %p,callback_func = %p\n","gf_send_callback_msg"
                        ,param_2,param_3);
    local_18 = param_2;
    local_10 = param_3;
    iVar1 = msg_send(*(undefined8 *)(param_1 + 2),0,0,&local_18,0x10);
    iVar2 = 0;
    if (iVar1 != 0) {
      __android_log_print(6,"FingerGoodix","%s:send exec message error\n","gf_send_callback_msg");
      iVar2 = iVar1;
    }
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(iVar2);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void gf_worker_thread_destroy(int *param_1)

{
  int iVar1;
  undefined8 local_18;
  undefined8 local_10;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  if ((param_1 == (int *)0x0) || (*param_1 != 0x574f524b)) {
    __android_log_print(6,"FingerGoodix","%s:worker thread not init,or worker thread is closed",
                        "gf_worker_thread_destroy");
    iVar1 = -1;
  }
  else {
    local_10 = 0;
    local_18 = 0x45584954;
    iVar1 = msg_send(*(undefined8 *)(param_1 + 2),0,1,&local_18,0x10);
    if (iVar1 != 0) {
      __android_log_print(6,"FingerGoodix","%s:send exec message error\n","gf_worker_thread_destroy"
                         );
    }
    __android_log_print(3,"FingerGoodix","%s:worker_thread exit ok\n","gf_worker_thread_destroy");
  }
  if (local_8 != ___stack_chk_guard) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail(iVar1);
  }
  return;
}



// operator delete(void*)

void operator_delete(void *param_1)

{
  free(param_1);
  return;
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
  *puVar3 = &PTR__bad_alloc_0013b6b0;
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
  *(undefined ***)this = &PTR__bad_alloc_0013b6b0;
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



char * FUN_0010ee58(void)

{
  return "__gnu_cxx::__concurrence_lock_error";
}



char * FUN_0010ee64(void)

{
  return "__gnu_cxx::__concurrence_unlock_error";
}



void FUN_0010ee70(undefined8 *param_1)

{
  *param_1 = &PTR_FUN_0013a7b0;
  std::exception::~exception((exception *)param_1);
  return;
}



void FUN_0010ee80(undefined8 *param_1)

{
  *param_1 = &PTR_FUN_0013a7e0;
  std::exception::~exception((exception *)param_1);
  return;
}



void FUN_0010ee90(undefined8 *param_1)

{
  *param_1 = &PTR_FUN_0013a7b0;
  std::exception::~exception((exception *)param_1);
  operator_delete(param_1);
  return;
}



void FUN_0010eec0(undefined8 *param_1)

{
  *param_1 = &PTR_FUN_0013a7e0;
  std::exception::~exception((exception *)param_1);
  operator_delete(param_1);
  return;
}



void FUN_0010eef0(void)

{
  undefined8 *puVar1;
  
  puVar1 = (undefined8 *)__cxa_allocate_exception(8);
  *puVar1 = &PTR_FUN_0013a7b0;
                    // WARNING: Subroutine does not return
  __cxa_throw(puVar1,&PTR_PTR____si_class_type_info_0013b6d0,FUN_0010ee70);
}



void FUN_0010ef20(void)

{
  undefined8 *puVar1;
  
  puVar1 = (undefined8 *)__cxa_allocate_exception(8);
  *puVar1 = &PTR_FUN_0013a7e0;
                    // WARNING: Subroutine does not return
  __cxa_throw(puVar1,&PTR_PTR____si_class_type_info_0013b6e8,FUN_0010ee80);
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
LAB_0010ef74:
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
                    // try { // try from 0010efbc to 0010efbf has its CatchHandler @ 0010f030
  iVar2 = pthread_mutex_lock((pthread_mutex_t *)&DAT_0013e300);
  if (iVar2 == 0) {
    if (param_1 + 0x80U < 0x401) {
      uVar5 = 0;
      uVar4 = DAT_0014e330;
      do {
        if ((uVar4 & 1) == 0) {
          DAT_0014e330 = 1L << (uVar5 & 0x3f) | DAT_0014e330;
          puVar3 = &DAT_0013e330 + uVar5 * 0x80;
                    // try { // try from 0010f024 to 0010f02f has its CatchHandler @ 0010f044
          iVar2 = pthread_mutex_unlock((pthread_mutex_t *)&DAT_0013e300);
          if (iVar2 == 0) goto LAB_0010ef74;
          FUN_0010ef20();
                    // catch() { ... } // from try @ 0010efbc with catch @ 0010f030
                    // catch() { ... } // from try @ 0010f03c with catch @ 0010f030
          if (extraout_x1 != -1) {
                    // WARNING: Subroutine does not return
            _Unwind_Resume();
          }
          goto LAB_0010f040;
        }
        uVar1 = (int)uVar5 + 1;
        uVar5 = (ulong)uVar1;
        uVar4 = uVar4 >> 1;
      } while (uVar1 != 0x40);
    }
                    // WARNING: Subroutine does not return
    std::terminate();
  }
                    // try { // try from 0010f03c to 0010f03f has its CatchHandler @ 0010f030
  FUN_0010eef0();
LAB_0010f040:
                    // WARNING: Subroutine does not return
  __cxa_call_unexpected();
}



// WARNING: Removing unreachable block (ram,0x0010f0d4)

void __cxa_free_exception(undefined8 *param_1)

{
  int iVar1;
  long extraout_x1;
  long lVar2;
  long extraout_x1_00;
  
  if ((param_1 < &DAT_0013e330) || ((undefined8 *)0x14e32f < param_1)) {
    free(param_1 + -0x10);
    return;
  }
                    // try { // try from 0010f08c to 0010f08f has its CatchHandler @ 0010f10c
  iVar1 = pthread_mutex_lock((pthread_mutex_t *)&DAT_0013e300);
  if (iVar1 == 0) {
    DAT_0014e330 = DAT_0014e330 &
                   (1L << ((ulong)(param_1 + -0x27c66) >> 10 & 0x3f) ^ 0xffffffffffffffffU);
                    // try { // try from 0010f0b0 to 0010f0fb has its CatchHandler @ 0010f0fc
    iVar1 = pthread_mutex_unlock((pthread_mutex_t *)&DAT_0013e300);
    if (iVar1 == 0) {
      return;
    }
    FUN_0010ef20();
    lVar2 = extraout_x1;
  }
  else {
                    // try { // try from 0010f108 to 0010f10b has its CatchHandler @ 0010f10c
    FUN_0010eef0();
    lVar2 = extraout_x1_00;
                    // catch() { ... } // from try @ 0010f08c with catch @ 0010f10c
                    // catch() { ... } // from try @ 0010f108 with catch @ 0010f10c
  }
                    // catch() { ... } // from try @ 0010f0b0 with catch @ 0010f0fc
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
LAB_0010f130:
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
                    // try { // try from 0010f170 to 0010f173 has its CatchHandler @ 0010f1f4
  iVar2 = pthread_mutex_lock((pthread_mutex_t *)&DAT_0013e300);
  if (iVar2 == 0) {
    uVar4 = 0;
    uVar5 = DAT_0013c6f0;
    while ((uVar5 & 1) != 0) {
      uVar1 = (int)uVar4 + 1;
      uVar4 = (ulong)uVar1;
      uVar5 = uVar5 >> 1;
      if (uVar1 == 0x40) {
                    // WARNING: Subroutine does not return
        std::terminate();
      }
    }
    DAT_0013c6f0 = 1L << (uVar4 & 0x3f) | DAT_0013c6f0;
    puVar3 = &DAT_0013c700 + uVar4 * 0xe;
                    // try { // try from 0010f1d8 to 0010f1e3 has its CatchHandler @ 0010f1e8
    iVar2 = pthread_mutex_unlock((pthread_mutex_t *)&DAT_0013e300);
    if (iVar2 == 0) goto LAB_0010f130;
    FUN_0010ef20();
  }
                    // try { // try from 0010f1e4 to 0010f1e7 has its CatchHandler @ 0010f1f4
  FUN_0010eef0();
                    // catch() { ... } // from try @ 0010f1d8 with catch @ 0010f1e8
  if (extraout_x1 == -1) {
                    // WARNING: Subroutine does not return
    __cxa_call_unexpected();
  }
                    // WARNING: Subroutine does not return
  _Unwind_Resume();
}



// WARNING: Removing unreachable block (ram,0x0010f29c)

void __cxa_free_dependent_exception(undefined8 *param_1)

{
  int iVar1;
  long extraout_x1;
  long lVar2;
  long extraout_x1_00;
  
  if ((param_1 < &DAT_0013c700) || ((undefined8 *)0x13e2ff < param_1)) {
    free(param_1);
    return;
  }
                    // try { // try from 0010f258 to 0010f25b has its CatchHandler @ 0010f2d4
  iVar1 = pthread_mutex_lock((pthread_mutex_t *)&DAT_0013e300);
  if (iVar1 == 0) {
    DAT_0013c6f0 = DAT_0013c6f0 &
                   (1L << (SUB168(ZEXT416((int)param_1 - 0x13c700U >> 4) *
                                  ZEXT816(0x2492492492492494),8) & 0x3f) ^ 0xffffffffffffffffU);
                    // try { // try from 0010f27c to 0010f2c3 has its CatchHandler @ 0010f2c4
    iVar1 = pthread_mutex_unlock((pthread_mutex_t *)&DAT_0013e300);
    if (iVar1 == 0) {
      return;
    }
    FUN_0010ef20();
    lVar2 = extraout_x1;
  }
  else {
                    // try { // try from 0010f2d0 to 0010f2d3 has its CatchHandler @ 0010f2d4
    FUN_0010eef0();
    lVar2 = extraout_x1_00;
                    // catch() { ... } // from try @ 0010f258 with catch @ 0010f2d4
                    // catch() { ... } // from try @ 0010f2d0 with catch @ 0010f2d4
  }
                    // catch() { ... } // from try @ 0010f27c with catch @ 0010f2c4
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
  *(undefined ***)this = &PTR__bad_exception_0013b790;
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



void FUN_0010f3a4(byte *param_1,ulong *param_2)

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



ulong * FUN_0010f3e4(byte param_1,ulong *param_2,ulong *param_3,ulong *param_4)

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
      puVar4 = (ulong *)FUN_0010f3a4(param_3,&local_8);
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



undefined8 FUN_0010f4f4(byte param_1,undefined8 param_2)

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



void FUN_0010f570(long param_1,char *param_2,undefined8 *param_3)

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
    uVar4 = FUN_0010f4f4(cVar2,param_1);
    pcVar5 = (char *)FUN_0010f3e4(cVar2,uVar4,param_2 + 1,param_3 + 1);
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



char FUN_0010f67c(long param_1,long *param_2,long **param_3,ulong param_4)

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
    FUN_0010f3e4(bVar1,*(undefined8 *)(param_1 + 0x10),*(long *)(param_1 + 0x18) + lVar7,&local_8);
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
    pbVar9 = (byte *)FUN_0010f570(param_5,local_60,&local_30);
    local_20 = FUN_0010f4f4(local_8,param_5);
    lVar13 = _Unwind_GetIPInfo(param_5,&local_4c);
    uVar17 = lVar13 - (ulong)(local_4c == 0);
    if (pbVar9 < local_10) {
      do {
        uVar4 = local_7;
        uVar10 = FUN_0010f4f4(local_7,0);
        uVar10 = FUN_0010f3e4(uVar4,uVar10,pbVar9,&local_48);
        uVar4 = local_7;
        uVar11 = FUN_0010f4f4(local_7,0);
        uVar10 = FUN_0010f3e4(uVar4,uVar11,uVar10,&local_40);
        uVar4 = local_7;
        uVar11 = FUN_0010f4f4(local_7,0);
        pbVar12 = (byte *)FUN_0010f3e4(uVar4,uVar11,uVar10,&local_38);
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
              goto LAB_0010fb14;
            }
          }
          iVar7 = 2;
          goto LAB_0010fa20;
        }
      } while (pbVar9 < local_10);
    }
    uVar17 = 0;
    iVar7 = 1;
LAB_0010fa20:
    local_68 = (ulong **)0x0;
    local_48 = 0;
    local_10 = (byte *)0x0;
    goto LAB_0010fa2c;
  }
  local_60 = param_4[-3];
  uVar17 = param_4[-2];
  local_48 = *(int *)((long)param_4 + -0x24);
  if (uVar17 == 0) {
    if ((param_2 >> 3 & 1) != 0) {
                    // WARNING: Subroutine does not return
      std::terminate();
    }
LAB_0010f854:
    FUN_001105f0(param_4);
  }
  if ((param_2 >> 3 & 1) == 0) {
LAB_0010f8c0:
    if (local_48 < 0) {
      FUN_0010f570(param_5,local_60,&local_30);
      local_20 = FUN_0010f4f4(local_8,param_5);
      uVar8 = FUN_0010f4f4(local_8,param_5);
      param_4[-2] = uVar8;
    }
    goto LAB_0010f864;
  }
  goto LAB_0010f860;
LAB_0010fb14:
  lVar13 = FUN_0010f3a4(local_10,&local_48);
  FUN_0010f3a4(lVar13,&local_40);
  uVar8 = CONCAT44(uStack_44,local_48);
  if (uVar8 == 0) {
    bVar2 = true;
  }
  else if ((long)uVar8 < 1) {
    if (bVar1 < (local_70 != (undefined **)0x0 && (param_2 & 8) == 0)) {
      bVar5 = FUN_0010f67c(&local_30,local_70,local_68);
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
LAB_0010fc78:
      iVar7 = 3;
      goto LAB_0010fa2c;
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
    FUN_0010f3e4(local_8,local_20,local_18 + lVar14,&local_38);
    ppuVar3 = local_38;
    if (local_38 == (ulong **)0x0) goto LAB_0010fc78;
    if (local_70 != (undefined **)0x0) {
      local_38 = local_68;
      cVar6 = (**(code **)(*local_70 + 0x10))(local_70);
      if (cVar6 != '\0') {
        local_38 = (ulong **)*local_38;
      }
      cVar6 = (*(code *)(*ppuVar3)[4])(ppuVar3,local_70,&local_38,1);
      if (cVar6 != '\0') {
        local_68 = local_38;
        goto LAB_0010fc78;
      }
    }
  }
  if (local_40 == 0) goto LAB_0010fccc;
  local_10 = (byte *)(lVar13 + local_40);
  goto LAB_0010fb14;
LAB_0010fccc:
  if (!bVar2) {
    return 8;
  }
  local_48 = 0;
  iVar7 = 2;
LAB_0010fa2c:
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
    if (iVar7 == 1) goto LAB_0010f854;
    goto LAB_0010f8c0;
  }
  if (iVar7 == 1) {
                    // WARNING: Subroutine does not return
    std::terminate();
  }
LAB_0010f860:
  if (local_48 < 0) {
                    // try { // try from 0010fcf4 to 0010fcf7 has its CatchHandler @ 0010fa80
    lVar13 = std::unexpected();
    __cxa_begin_catch();
                    // WARNING: Subroutine does not return
    __cxxabiv1::__unexpected(*(_func_void **)(lVar13 + -0x40));
  }
LAB_0010f864:
  _Unwind_SetGR(param_5,0,param_4);
  _Unwind_SetGR(param_5,1,(long)local_48);
  _Unwind_SetIP(param_5,uVar17);
  return 7;
}



void __cxa_call_unexpected(long param_1)

{
  __cxa_begin_catch();
                    // WARNING: Subroutine does not return
                    // try { // try from 0010fd2c to 0010fd2f has its CatchHandler @ 0010fd30
  __cxxabiv1::__unexpected(*(_func_void **)(param_1 + -0x40));
}



// __cxxabiv1::__terminate(void (*)())

void __cxxabiv1::__terminate(_func_void *param_1)

{
                    // try { // try from 0010fdf0 to 0010fdf7 has its CatchHandler @ 0010fdf8
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



void FUN_0010feac(uint param_1,long param_2)

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
  *(code **)(param_1 + -0x18) = FUN_0010feac;
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



// WARNING: Unknown calling convention -- yet parameter storage is locked
// std::set_new_handler(void (*)())

_func_void * std::set_new_handler(_func_void *param_1)

{
  char cVar1;
  bool bVar2;
  _func_void *p_Var3;
  
  do {
    p_Var3 = DAT_0014e338;
    cVar1 = '\x01';
    bVar2 = (bool)ExclusiveMonitorPass(0x14e338,0x10);
    if (bVar2) {
      cVar1 = ExclusiveMonitorsStatus();
      DAT_0014e338 = param_1;
    }
  } while (cVar1 != '\0');
  return p_Var3;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked
// std::get_new_handler()

undefined8 std::get_new_handler(void)

{
  return DAT_0014e338;
}



// __cxxabiv1::__si_class_type_info::~__si_class_type_info()

void __thiscall __cxxabiv1::__si_class_type_info::~__si_class_type_info(__si_class_type_info *this)

{
  *(undefined ***)this = &PTR____si_class_type_info_0013b840;
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
LAB_00110114:
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
      if (iVar3 == 0) goto LAB_00110114;
    }
    if (param_4 == param_6) {
      if (__s1 == *(char **)(param_5 + 8)) {
LAB_001101b0:
        *(__sub_kind *)(param_7 + 0xc) = param_2;
        return 0;
      }
      if (cVar1 != '*') {
        iVar3 = strcmp(__s1,*(char **)(param_5 + 8));
        if (iVar3 == 0) goto LAB_001101b0;
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



void FUN_001102bc(void)

{
  return;
}



undefined8 FUN_001102c0(void)

{
  return 0;
}



undefined8 FUN_001102c8(void)

{
  return 0;
}



undefined8 FUN_001102d0(void)

{
  return 0;
}



void operator_delete(void *param_1)

{
  free(param_1);
  return;
}



bool FUN_001102dc(long param_1,long param_2)

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
  *(undefined ***)this = &PTR____class_type_info_0013b8d0;
  FUN_001102bc();
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
      if (iVar1 == 0) goto LAB_00110420;
    }
    return 0;
  }
LAB_00110420:
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
LAB_001105cc:
      *(__sub_kind *)(param_7 + 0xc) = param_2;
      return 0;
    }
    if (*__s1 == '*') {
      if (__s1 != *(char **)(param_3 + 8)) {
        return 0;
      }
      goto LAB_001105ac;
    }
    iVar1 = strcmp(__s1,*(char **)(param_5 + 8));
    if (iVar1 == 0) goto LAB_001105cc;
    __s2 = *(char **)(param_3 + 8);
    if (__s1 == __s2) goto LAB_001105ac;
  }
  else {
    __s2 = *(char **)(param_3 + 8);
    if (__s1 == __s2) goto LAB_001105ac;
    if (*__s1 == '*') {
      return 0;
    }
  }
  iVar1 = strcmp(__s1,__s2);
  if (iVar1 != 0) {
    return 0;
  }
LAB_001105ac:
  *(void **)param_7 = param_4;
  *(__sub_kind *)(param_7 + 8) = param_2;
  *(undefined4 *)(param_7 + 0x10) = 1;
  return 0;
}



void FUN_001105f0(long *param_1)

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



pthread_key_t * FUN_00110798(pthread_key_t *param_1)

{
  code *UNRECOVERED_JUMPTABLE;
  uint uVar1;
  pthread_key_t *ppVar2;
  
  if (param_1 == (pthread_key_t *)0x0) {
                    // WARNING: Treating indirect jump as call
    UNRECOVERED_JUMPTABLE = (code *)SoftwareBreakpoint(1000,0x1107b4);
    ppVar2 = (pthread_key_t *)(*UNRECOVERED_JUMPTABLE)();
    return ppVar2;
  }
  if (*(char *)(param_1 + 1) == '\0') {
    return param_1;
  }
  uVar1 = pthread_key_delete(*param_1);
  return (pthread_key_t *)(ulong)uVar1;
}



void FUN_001107b4(long *param_1)

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
  
  if (DAT_0014e344 == '\0') {
    return &DAT_0014e348;
  }
                    // try { // try from 0011082c to 0011082f has its CatchHandler @ 00110838
  puVar1 = (undefined *)pthread_getspecific(DAT_0014e340);
  return puVar1;
}



undefined8 * __cxa_get_globals(void)

{
  int iVar1;
  undefined8 *__pointer;
  
  if (DAT_0014e344 == '\0') {
    __pointer = (undefined8 *)&DAT_0014e348;
  }
  else {
                    // try { // try from 00110880 to 001108a7 has its CatchHandler @ 001108bc
    __pointer = (undefined8 *)pthread_getspecific(DAT_0014e340);
    if (__pointer == (undefined8 *)0x0) {
      __pointer = (undefined8 *)malloc(0x10);
      if ((__pointer == (undefined8 *)0x0) ||
         (iVar1 = pthread_setspecific(DAT_0014e340,__pointer), iVar1 != 0)) {
                    // WARNING: Subroutine does not return
        std::terminate();
      }
      *__pointer = 0;
      *(undefined4 *)(__pointer + 1) = 0;
    }
  }
  return __pointer;
}



// WARNING: Removing unreachable block (ram,0x001109bc)
// WARNING: Removing unreachable block (ram,0x00110a50)
// WARNING: Removing unreachable block (ram,0x001109d0)
// __gnu_cxx::__verbose_terminate_handler()

void __gnu_cxx::__verbose_terminate_handler(void)

{
  long lVar1;
  char *pcVar2;
  char *__s;
  size_t __n;
  
  if (DAT_0014e358 == '\0') {
    DAT_0014e358 = '\x01';
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
        fwrite(&DAT_00124598,1,2,(FILE *)sem_init);
                    // try { // try from 00110984 to 00110987 has its CatchHandler @ 001109c8
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



long FUN_00110a5c(long param_1,undefined4 param_2,long param_3,long param_4)

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
switchD_00110a88_caseD_2a:
    if ((param_4 != 0) && (iVar2 = *(int *)(param_1 + 0x28), iVar2 < *(int *)(param_1 + 0x2c))) {
LAB_00110aa4:
      *(int *)(param_1 + 0x28) = iVar2 + 1;
      lVar1 = *(long *)(param_1 + 0x20) + (long)iVar2 * 0x18;
      if (lVar1 != 0) {
        *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar2 * 0x18) = param_2;
        *(long *)(lVar1 + 8) = param_3;
        *(long *)(lVar1 + 0x10) = param_4;
        return lVar1;
      }
    }
LAB_00110a6c:
    return 0;
  default:
    goto LAB_00110a6c;
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
    goto LAB_00110aa4;
  case 0x2a:
  case 0x30:
    goto switchD_00110a88_caseD_2a;
  }
}



long FUN_00110afc(long param_1,long param_2,int param_3)

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



int ** FUN_00110b5c(long param_1,int **param_2,int param_3)

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
        if (cVar2 != 'V') goto LAB_00110bc0;
        uVar5 = 0x1d;
        if (param_3 == 0) {
          uVar5 = 0x1a;
        }
        *(int *)(param_1 + 0x50) = *(int *)(param_1 + 0x50) + 9;
        goto LAB_00110bd4;
      }
      uVar5 = 0x1c;
      if (param_3 == 0) {
        uVar5 = 0x19;
      }
      *(int *)(param_1 + 0x50) = *(int *)(param_1 + 0x50) + 9;
      piVar3 = (int *)FUN_00110a5c(param_1,uVar5,0,0);
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
LAB_00110bc0:
      uVar5 = 0x1e;
      if (param_3 == 0) {
        uVar5 = 0x1b;
      }
      *(int *)(param_1 + 0x50) = *(int *)(param_1 + 0x50) + 6;
LAB_00110bd4:
      piVar3 = (int *)FUN_00110a5c(param_1,uVar5,0,0);
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



long FUN_00110d0c(long param_1,int param_2)

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
        goto LAB_00110e48;
      }
    }
    else if (0x19 < (byte)(bVar3 + 0xbf)) goto LAB_00110dd8;
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
        if (uVar6 == 0x5f) goto LAB_00110e44;
      }
      uVar14 = uVar6 - 0x30;
      uVar9 = uVar4;
    } while( true );
  }
  uVar6 = 0;
LAB_00110dd8:
  uVar14 = *(uint *)(param_1 + 0x10) >> 3 & 1;
  if (uVar14 < (param_2 != 0)) {
    uVar14 = (uint)((byte)(**(char **)(param_1 + 0x18) + 0xbdU) < 2);
  }
  if (uVar6 == 0x74) {
    puVar8 = &UNK_0013ac60;
  }
  else if (uVar6 == 0x61) {
    puVar8 = &UNK_0013ac98;
  }
  else if (uVar6 == 0x62) {
    puVar8 = &UNK_0013acd0;
  }
  else if (uVar6 == 0x73) {
    puVar8 = &UNK_0013ad08;
  }
  else if (uVar6 == 0x69) {
    puVar8 = &UNK_0013ad40;
  }
  else if (uVar6 == 0x6f) {
    puVar8 = &UNK_0013ad78;
  }
  else {
    if (uVar6 != 100) {
      return 0;
    }
    puVar8 = &UNK_0013adb0;
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
LAB_00110e44:
  uVar4 = uVar4 + 1;
LAB_00110e48:
  if (*(uint *)(param_1 + 0x38) <= uVar4) {
    return 0;
  }
  lVar5 = *(long *)(*(long *)(param_1 + 0x30) + (ulong)uVar4 * 8);
  *(int *)(param_1 + 0x40) = *(int *)(param_1 + 0x40) + 1;
  return lVar5;
}



void FUN_00110fcc(int *param_1,int *param_2,undefined4 *param_3)

{
  int *piVar1;
  
  if (param_3 == (undefined4 *)0x0) {
switchD_00111020_caseD_5:
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
switchD_00111020_caseD_1:
      piVar1 = *(int **)(param_3 + 2);
      break;
    case 4:
      *param_1 = *param_1 + 1;
      piVar1 = *(int **)(param_3 + 2);
      break;
    default:
      goto switchD_00111020_caseD_5;
    case 7:
    case 8:
    case 0x32:
      param_3 = *(undefined4 **)(param_3 + 4);
      goto joined_r0x00111040;
    case 0x23:
    case 0x24:
      piVar1 = *(int **)(param_3 + 2);
      if (*piVar1 == 5) {
        *param_2 = *param_2 + 1;
        goto switchD_00111020_caseD_1;
      }
      break;
    case 0x43:
    case 0x44:
    case 0x45:
    case 0x46:
      param_3 = *(undefined4 **)(param_3 + 2);
      goto joined_r0x00111040;
    }
    FUN_00110fcc(param_1,param_2,piVar1);
    param_3 = *(undefined4 **)(param_3 + 4);
joined_r0x00111040:
    if (param_3 == (undefined4 *)0x0) {
      return;
    }
  } while( true );
}



void FUN_00111098(undefined *param_1,undefined param_2)

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



long FUN_00111110(byte **param_1)

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



undefined8 FUN_00111198(long param_1,ulong *param_2)

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



int * FUN_00111214(undefined8 param_1,undefined4 *param_2)

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
        goto LAB_00111260;
      case 5:
        piVar1 = (int *)FUN_00111198(param_1,param_2 + 2);
        if ((piVar1 != (int *)0x0) && (*piVar1 == 0x2f)) {
          return piVar1;
        }
        goto LAB_00111260;
      case 7:
      case 8:
      case 0x32:
        goto switchD_0011127c_caseD_7;
      }
      piVar1 = (int *)FUN_00111214(param_1,*(undefined8 *)(param_2 + 2));
      if (piVar1 != (int *)0x0) {
        return piVar1;
      }
switchD_0011127c_caseD_7:
      param_2 = *(undefined4 **)(param_2 + 4);
    } while (param_2 != (undefined4 *)0x0);
  }
LAB_00111260:
  return (int *)0x0;
}



void FUN_001112ac(void *param_1,size_t param_2,void **param_3)

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



void FUN_0011139c(char *param_1,char *param_2)

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



long FUN_00111450(long param_1,int param_2)

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
      lVar3 = FUN_00110afc(param_1,"(anonymous namespace)",0x15);
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



void FUN_001115a4(char *param_1,undefined8 param_2)

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



undefined8 FUN_00111670(long param_1)

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
      uVar3 = FUN_00111450();
      *(undefined8 *)(param_1 + 0x48) = uVar3;
      return uVar3;
    }
  }
  return 0;
}



long FUN_00111718(long param_1)

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
      if (bVar1 == 0x5f) goto LAB_00111794;
    }
    return -1;
  }
  lVar3 = 0;
LAB_00111794:
  *(byte **)(param_1 + 0x18) = pbVar4 + 1;
  return lVar3;
}



ulong FUN_001117a4(long param_1)

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



long FUN_00111848(long param_1)

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



undefined8 FUN_00111934(long param_1,uint param_2)

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
      goto LAB_001119b4;
    }
  }
  else {
    if (param_2 != 0x76) {
      return 0;
    }
    FUN_00111110(param_1 + 0x18);
    if (**(char **)(param_1 + 0x18) != '_') {
      return 0;
    }
    *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
    FUN_00111110(param_1 + 0x18);
    pcVar2 = *(char **)(param_1 + 0x18);
  }
  cVar4 = *pcVar2;
LAB_001119b4:
  if (cVar4 != '_') {
    return 0;
  }
  *(char **)(param_1 + 0x18) = pcVar2 + 1;
  return 1;
}



long FUN_00111a20(long param_1)

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
    uVar14 = FUN_00110a5c(param_1,0x2f,0,0);
    return uVar14;
  }
  plVar13 = &local_8;
  local_8 = 0;
LAB_00111a90:
  switch(cVar3) {
  case 'I':
  case 'J':
    lVar5 = FUN_00111a20(param_1);
    break;
  default:
    lVar5 = FUN_00113660(param_1);
    break;
  case 'L':
    lVar5 = FUN_00116200(param_1);
    break;
  case 'X':
    pcVar12 = pcVar16 + 1;
    uVar1 = *(undefined4 *)(param_1 + 0x54);
    *(char **)(param_1 + 0x18) = pcVar12;
    *(undefined4 *)(param_1 + 0x54) = 1;
    cVar3 = pcVar16[1];
    if (cVar3 == 'L') {
      lVar5 = FUN_00116200(param_1);
      pcVar12 = *(char **)(param_1 + 0x18);
    }
    else if (cVar3 == 'T') {
      lVar5 = FUN_00111848(param_1);
      pcVar12 = *(char **)(param_1 + 0x18);
    }
    else if (cVar3 == 's') {
      if (pcVar16[2] == 'r') {
        *(char **)(param_1 + 0x18) = pcVar16 + 3;
        uVar7 = FUN_00113660(param_1);
        uVar8 = FUN_0011500c(param_1);
        if (**(char **)(param_1 + 0x18) == 'I') {
          uVar10 = FUN_00111a20(param_1);
          uVar8 = FUN_00110a5c(param_1,4,uVar8,uVar10);
        }
        lVar5 = FUN_00110a5c(param_1,1,uVar7,uVar8);
        pcVar12 = *(char **)(param_1 + 0x18);
      }
      else {
        if (pcVar16[2] != 'p') goto LAB_00111b7c;
        *(char **)(param_1 + 0x18) = pcVar16 + 3;
        uVar7 = FUN_00116378(param_1);
        lVar5 = FUN_00110a5c(param_1,0x4a,uVar7,0);
        pcVar12 = *(char **)(param_1 + 0x18);
      }
    }
    else {
      if (cVar3 == 'f') {
        if (pcVar16[2] != 'p') goto LAB_00111b7c;
        *(char **)(param_1 + 0x18) = pcVar16 + 3;
        if (pcVar16[3] == 'T') {
          lVar15 = 0;
          *(char **)(param_1 + 0x18) = pcVar16 + 4;
        }
        else {
          iVar4 = FUN_00111718(param_1);
          lVar15 = (long)(iVar4 + 1);
          if (iVar4 + 1 == 0) {
            pcVar12 = *(char **)(param_1 + 0x18);
            goto LAB_00111c88;
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
            goto LAB_00111c28;
          }
        }
        goto switchD_00111ee4_caseD_4;
      }
      if ((byte)(cVar3 - 0x30U) < 10) {
LAB_00111c08:
        lVar5 = FUN_0011500c(param_1);
        pcVar12 = *(char **)(param_1 + 0x18);
        if (lVar5 != 0) {
          if (*pcVar12 == 'I') {
            uVar7 = FUN_00111a20(param_1);
            lVar5 = FUN_00110a5c(param_1,4,lVar5,uVar7);
            pcVar12 = *(char **)(param_1 + 0x18);
          }
          goto LAB_00111c28;
        }
      }
      else {
        if (cVar3 == 'o') {
          if (pcVar16[2] == 'n') {
            *(char **)(param_1 + 0x18) = pcVar16 + 3;
            goto LAB_00111c08;
          }
        }
        else if (((cVar3 == 't') || (cVar3 == 'i')) && (pcVar16[2] == 'l')) {
          uVar7 = 0;
          if (cVar3 == 't') {
            uVar7 = FUN_00113660(param_1);
            pcVar12 = *(char **)(param_1 + 0x18);
          }
          *(char **)(param_1 + 0x18) = pcVar12 + 2;
          uVar8 = FUN_00112f0c(param_1,0x45);
          lVar5 = FUN_00110a5c(param_1,0x30,uVar7,uVar8);
          pcVar12 = *(char **)(param_1 + 0x18);
          goto LAB_00111c28;
        }
LAB_00111b7c:
        piVar6 = (int *)FUN_00114e18(param_1);
        if (piVar6 != (int *)0x0) {
          iVar4 = *piVar6;
          if (iVar4 == 0x31) {
            ppcVar17 = *(char ***)(piVar6 + 2);
            pcVar12 = *ppcVar17;
            *(int *)(param_1 + 0x50) = *(int *)(param_1 + 0x50) + *(int *)(ppcVar17 + 2) + -2;
            iVar4 = strcmp(pcVar12,"st");
            if (iVar4 == 0) {
              uVar7 = FUN_00113660(param_1);
LAB_00111f58:
              lVar5 = FUN_00110a5c(param_1,0x36,piVar6,uVar7);
              pcVar12 = *(char **)(param_1 + 0x18);
              goto LAB_00111c28;
            }
            switch(*(undefined4 *)((long)ppcVar17 + 0x14)) {
            case 0:
              goto switchD_00111ee4_caseD_0;
            case 1:
              cVar3 = *pcVar12;
              if (((cVar3 == 'm') || (cVar3 == 'p')) && (pcVar12[1] == cVar3)) {
                if (**(char **)(param_1 + 0x18) != '_') {
                  uVar7 = FUN_00116378(param_1);
                  uVar7 = FUN_00110a5c(param_1,0x38,uVar7,uVar7);
                  goto LAB_00111f58;
                }
                *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
              }
              goto switchD_00111ee4_caseD_1;
            case 2:
              goto switchD_00111dbc_caseD_2;
            case 3:
              goto switchD_00111dbc_caseD_3;
            }
          }
          else if (iVar4 == 0x32) {
            switch(piVar6[2]) {
            case 0:
switchD_00111ee4_caseD_0:
              lVar5 = FUN_00110a5c(param_1,0x35,piVar6,0);
              pcVar12 = *(char **)(param_1 + 0x18);
              goto LAB_00111c28;
            case 1:
              goto switchD_00111ee4_caseD_1;
            case 2:
              pcVar12 = (char *)0x0;
switchD_00111dbc_caseD_2:
              if (((**(char ***)(piVar6 + 2))[1] == 'c') &&
                 ((cVar3 = ***(char ***)(piVar6 + 2), (byte)(cVar3 + 0x8eU) < 2 ||
                  ((byte)(cVar3 + 0x9dU) < 2)))) {
                uVar7 = FUN_00113660(param_1);
              }
              else {
                uVar7 = FUN_00116378(param_1);
              }
              iVar4 = strcmp(pcVar12,"cl");
              if (iVar4 == 0) {
                uVar8 = FUN_00112f0c(param_1,0x45);
              }
              else {
                iVar4 = strcmp(pcVar12,"dt");
                if ((iVar4 == 0) || (iVar4 = strcmp(pcVar12,"pt"), iVar4 == 0)) {
                  uVar8 = FUN_0011500c(param_1);
                  if (**(char **)(param_1 + 0x18) == 'I') {
                    uVar10 = FUN_00111a20(param_1);
                    uVar8 = FUN_00110a5c(param_1,4,uVar8,uVar10);
                  }
                }
                else {
                  uVar8 = FUN_00116378(param_1);
                }
              }
              uVar7 = FUN_00110a5c(param_1,0x38,uVar7,uVar8);
              lVar5 = FUN_00110a5c(param_1,0x37,piVar6,uVar7);
              pcVar12 = *(char **)(param_1 + 0x18);
              goto LAB_00111c28;
            case 3:
              pcVar12 = (char *)0x0;
switchD_00111dbc_caseD_3:
              iVar4 = strcmp(pcVar12,"qu");
              if (iVar4 == 0) {
                local_18 = FUN_00116378(param_1);
                pcVar12 = *(char **)(param_1 + 0x18);
                cVar3 = *pcVar12;
                if (cVar3 == 'L') {
                  piVar9 = (int *)FUN_00116200(param_1);
                  pcVar12 = *(char **)(param_1 + 0x18);
                  cVar3 = *pcVar12;
LAB_00112218:
                  if (cVar3 == 'L') {
                    lVar5 = FUN_00116200(param_1);
                  }
                  else if (cVar3 == 'T') {
                    lVar5 = FUN_00111848(param_1);
                  }
                  else if (cVar3 == 's') {
                    if (pcVar12[1] == 'r') {
                      *(char **)(param_1 + 0x18) = pcVar12 + 2;
                      uVar7 = FUN_00113660(param_1);
                      uVar8 = FUN_0011500c(param_1);
                      if (**(char **)(param_1 + 0x18) == 'I') {
                        uVar10 = FUN_00111a20(param_1);
                        uVar8 = FUN_00110a5c(param_1,4,uVar8,uVar10);
                      }
                      lVar5 = FUN_00110a5c(param_1,1,uVar7,uVar8);
                    }
                    else {
                      if (pcVar12[1] != 'p') goto LAB_00112270;
                      *(char **)(param_1 + 0x18) = pcVar12 + 2;
                      uVar7 = FUN_00116378(param_1);
                      lVar5 = FUN_00110a5c(param_1,0x4a,uVar7,0);
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
                        iVar4 = FUN_00111718(param_1);
                        if (iVar4 + 1 == 0) goto LAB_001126d0;
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
LAB_00112270:
                      piVar11 = (int *)FUN_00114e18(param_1);
                      if (piVar11 == (int *)0x0) {
LAB_001126d0:
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
                              goto switchD_00112664_caseD_0;
                            case 1:
                              goto switchD_001126cc_caseD_1;
                            case 2:
                              goto switchD_001126cc_caseD_2;
                            case 3:
                              goto switchD_001126cc_caseD_3;
                            default:
                              goto switchD_00112664_caseD_4;
                            }
                          }
                          uVar7 = FUN_00113660(param_1);
                        }
                        else {
                          if (iVar4 == 0x32) {
                            lVar5 = 0;
                            switch(piVar11[2]) {
                            case 0:
switchD_00112664_caseD_0:
                              lVar5 = FUN_00110a5c(param_1,0x35,piVar11,0);
                              break;
                            case 1:
                              goto switchD_00112664_caseD_1;
                            case 2:
                              pcVar12 = (char *)0x0;
switchD_001126cc_caseD_2:
                              if ((**(char ***)(piVar11 + 2))[1] == 'c') {
                                cVar3 = ***(char ***)(piVar11 + 2);
                                bVar2 = cVar3 + 0x8e;
                                if ((1 < bVar2) && (1 < (byte)(cVar3 + 0x9dU))) goto LAB_00112988;
                                local_20 = FUN_00113660(param_1,bVar2,pcVar12,0);
                              }
                              else {
LAB_00112988:
                                local_20 = FUN_00116378(param_1);
                              }
                              iVar4 = strcmp(pcVar12,"cl");
                              if (iVar4 == 0) {
                                uVar7 = FUN_00112f0c(param_1,0x45);
                              }
                              else {
                                iVar4 = strcmp(pcVar12,"dt");
                                if ((iVar4 == 0) || (iVar4 = strcmp(pcVar12,"pt"), iVar4 == 0)) {
                                  uVar7 = FUN_0011500c(param_1);
                                  if (**(char **)(param_1 + 0x18) == 'I') {
                                    uVar8 = FUN_00111a20(param_1);
                                    uVar7 = FUN_00110a5c(param_1,4,uVar7,uVar8);
                                  }
                                }
                                else {
                                  uVar7 = FUN_00116378(param_1);
                                }
                              }
                              uVar7 = FUN_00110a5c(param_1,0x38,local_20,uVar7);
                              lVar5 = FUN_00110a5c(param_1,0x37,piVar11,uVar7);
                              break;
                            case 3:
                              pcVar12 = (char *)0x0;
switchD_001126cc_caseD_3:
                              iVar4 = strcmp(pcVar12,"qu");
                              if (iVar4 == 0) {
                                local_20 = FUN_00116378(param_1);
                                local_28 = FUN_00116378(param_1);
                                uVar7 = FUN_00116378(param_1);
                              }
                              else {
                                if ((*pcVar12 != 'n') ||
                                   ((pcVar12[1] != 'a' && (pcVar12[1] != 'w')))) goto LAB_001126d0;
                                local_20 = FUN_00112f0c(param_1,0x5f);
                                local_28 = FUN_00113660(param_1);
                                pcVar12 = *(char **)(param_1 + 0x18);
                                cVar3 = *pcVar12;
                                if (cVar3 != 'E') {
                                  if (cVar3 == 'p') {
                                    lVar5 = 0;
                                    if (pcVar12[1] == 'i') {
                                      *(char **)(param_1 + 0x18) = pcVar12 + 2;
                                      uVar7 = FUN_00112f0c(param_1,0x45);
                                      goto LAB_00112ac0;
                                    }
                                  }
                                  else {
                                    if (cVar3 != 'i') goto LAB_001126d0;
                                    lVar5 = 0;
                                    if (pcVar12[1] == 'l') {
                                      uVar7 = FUN_00116378(param_1);
                                      goto LAB_00112ac0;
                                    }
                                  }
                                  break;
                                }
                                uVar7 = 0;
                                *(char **)(param_1 + 0x18) = pcVar12 + 1;
                              }
LAB_00112ac0:
                              uVar7 = FUN_00110a5c(param_1,0x3b,local_28,uVar7);
                              uVar7 = FUN_00110a5c(param_1,0x3a,local_20,uVar7);
                              lVar5 = FUN_00110a5c(param_1,0x39,piVar11,uVar7);
                            }
                            goto switchD_00112664_caseD_4;
                          }
                          if (iVar4 != 0x33) goto LAB_001126d0;
                          if (**(char **)(param_1 + 0x18) == '_') {
                            *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
                            uVar7 = FUN_00112f0c(param_1,0x45);
                            goto LAB_001122b8;
                          }
switchD_00112664_caseD_1:
                          uVar7 = FUN_00116378(param_1);
                        }
LAB_001122b8:
                        lVar5 = FUN_00110a5c(param_1,0x36,piVar11,uVar7);
                      }
                    }
                  }
                  else {
                    if (9 < (byte)(cVar3 - 0x30U)) {
                      if (cVar3 != 'o') goto LAB_00112250;
                      if (pcVar12[1] != 'n') goto LAB_00112270;
                      *(char **)(param_1 + 0x18) = pcVar12 + 2;
                    }
                    lVar5 = FUN_0011500c(param_1);
                    if ((lVar5 != 0) && (**(char **)(param_1 + 0x18) == 'I')) {
                      uVar7 = FUN_00111a20(param_1);
                      lVar5 = FUN_00110a5c(param_1,4,lVar5,uVar7);
                    }
                  }
                }
                else {
                  if (cVar3 == 'T') {
                    piVar9 = (int *)FUN_00111848(param_1);
                    pcVar12 = *(char **)(param_1 + 0x18);
                    cVar3 = *pcVar12;
                    goto LAB_00112218;
                  }
                  if (cVar3 == 's') {
                    if (pcVar12[1] == 'r') {
                      *(char **)(param_1 + 0x18) = pcVar12 + 2;
                      piVar9 = (int *)FUN_00113660(param_1);
                      uVar7 = FUN_0011500c(param_1);
                      if (**(char **)(param_1 + 0x18) != 'I') {
                        piVar9 = (int *)FUN_00110a5c(param_1,1,piVar9,uVar7);
                        pcVar12 = *(char **)(param_1 + 0x18);
                        cVar3 = *pcVar12;
                        goto LAB_00112218;
                      }
                      uVar8 = FUN_00111a20(param_1);
                      uVar7 = FUN_00110a5c(param_1,4,uVar7,uVar8);
                      uVar8 = 1;
                      goto LAB_00112204;
                    }
                    if (pcVar12[1] != 'p') goto LAB_001121b4;
                    *(char **)(param_1 + 0x18) = pcVar12 + 2;
                    piVar9 = (int *)FUN_00116378(param_1);
                    uVar7 = 0x4a;
LAB_00112558:
                    piVar9 = (int *)FUN_00110a5c(param_1,uVar7,piVar9,0);
LAB_00112564:
                    pcVar12 = *(char **)(param_1 + 0x18);
LAB_00112568:
                    cVar3 = *pcVar12;
                    goto LAB_00112218;
                  }
                  if (cVar3 == 'f') {
                    if (pcVar12[1] != 'p') goto LAB_001121b4;
                    *(char **)(param_1 + 0x18) = pcVar12 + 2;
                    if (pcVar12[2] == 'T') {
                      pcVar12 = pcVar12 + 3;
                      lVar5 = 0;
                      *(char **)(param_1 + 0x18) = pcVar12;
                    }
                    else {
                      iVar4 = FUN_00111718(param_1);
                      pcVar12 = *(char **)(param_1 + 0x18);
                      if (iVar4 + 1 == 0) {
LAB_00112574:
                        piVar9 = (int *)0x0;
                        cVar3 = *pcVar12;
                        goto LAB_00112218;
                      }
                      lVar5 = (long)(iVar4 + 1);
                    }
                    iVar4 = *(int *)(param_1 + 0x28);
                    if (iVar4 < *(int *)(param_1 + 0x2c)) {
                      *(int *)(param_1 + 0x28) = iVar4 + 1;
                      piVar9 = (int *)(*(long *)(param_1 + 0x20) + (long)iVar4 * 0x18);
                      if (piVar9 == (int *)0x0) goto LAB_00112568;
                      *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar4 * 0x18) = 6;
                      *(long *)(piVar9 + 2) = lVar5;
                      cVar3 = *pcVar12;
                    }
                    else {
                      cVar3 = *pcVar12;
                      piVar9 = (int *)0x0;
                    }
                    goto LAB_00112218;
                  }
                  if ((byte)(cVar3 - 0x30U) < 10) {
LAB_001123cc:
                    piVar9 = (int *)FUN_0011500c(param_1);
                    pcVar12 = *(char **)(param_1 + 0x18);
                    cVar3 = *pcVar12;
                    if ((piVar9 != (int *)0x0) && (cVar3 == 'I')) {
                      uVar7 = FUN_00111a20(param_1);
                      uVar8 = 4;
                      goto LAB_00112204;
                    }
                    goto LAB_00112218;
                  }
                  if (cVar3 == 'o') {
                    if (pcVar12[1] == 'n') {
                      *(char **)(param_1 + 0x18) = pcVar12 + 2;
                      goto LAB_001123cc;
                    }
                  }
                  else if (((cVar3 == 't') || (cVar3 == 'i')) && (pcVar12[1] == 'l')) {
                    uVar7 = 0;
                    if (cVar3 == 't') {
                      uVar7 = FUN_00113660(param_1);
                      pcVar12 = *(char **)(param_1 + 0x18);
                    }
                    *(char **)(param_1 + 0x18) = pcVar12 + 2;
                    uVar8 = FUN_00112f0c(param_1,0x45);
                    piVar9 = (int *)FUN_00110a5c(param_1,0x30,uVar7,uVar8);
                    pcVar12 = *(char **)(param_1 + 0x18);
                    cVar3 = *pcVar12;
                    goto LAB_00112218;
                  }
LAB_001121b4:
                  piVar9 = (int *)FUN_00114e18(param_1);
                  if (piVar9 == (int *)0x0) goto LAB_00112564;
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
                        goto switchD_001125e4_caseD_0;
                      case 1:
                        goto switchD_00112750_caseD_1;
                      case 2:
                        goto switchD_00112750_caseD_2;
                      case 3:
                        goto switchD_00112750_caseD_3;
                      default:
                        goto switchD_001125e4_caseD_4;
                      }
                    }
                    uVar7 = FUN_00113660(param_1);
                    uVar8 = 0x36;
                    goto LAB_00112204;
                  }
                  if (iVar4 != 0x32) {
                    if (iVar4 == 0x33) {
                      if (**(char **)(param_1 + 0x18) != '_') goto switchD_001125e4_caseD_1;
                      *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
                      uVar7 = FUN_00112f0c(param_1,0x45);
                      goto LAB_001121fc;
                    }
switchD_001125e4_caseD_4:
                    pcVar12 = *(char **)(param_1 + 0x18);
                    goto LAB_00112574;
                  }
                  switch(piVar9[2]) {
                  case 0:
switchD_001125e4_caseD_0:
                    uVar7 = 0x35;
                    goto LAB_00112558;
                  case 1:
                    goto switchD_001125e4_caseD_1;
                  case 2:
                    pcVar12 = (char *)0x0;
switchD_00112750_caseD_2:
                    if (((**(char ***)(piVar9 + 2))[1] == 'c') &&
                       ((cVar3 = ***(char ***)(piVar9 + 2), (byte)(cVar3 + 0x8eU) < 2 ||
                        ((byte)(cVar3 + 0x9dU) < 2)))) {
                      local_20 = FUN_00113660(param_1);
                    }
                    else {
                      local_20 = FUN_00116378(param_1);
                    }
                    iVar4 = strcmp(pcVar12,"cl");
                    if (iVar4 == 0) {
                      uVar7 = FUN_00112f0c(param_1,0x45);
                    }
                    else {
                      iVar4 = strcmp(pcVar12,"dt");
                      if ((iVar4 == 0) || (iVar4 = strcmp(pcVar12,"pt"), iVar4 == 0)) {
                        uVar7 = FUN_0011500c(param_1);
                        if (**(char **)(param_1 + 0x18) == 'I') {
                          uVar8 = FUN_00111a20(param_1);
                          uVar7 = FUN_00110a5c(param_1,4,uVar7,uVar8);
                        }
                      }
                      else {
                        uVar7 = FUN_00116378(param_1);
                      }
                    }
                    uVar7 = FUN_00110a5c(param_1,0x38,local_20,uVar7);
                    uVar8 = 0x37;
                    goto LAB_00112204;
                  case 3:
                    pcVar12 = (char *)0x0;
switchD_00112750_caseD_3:
                    iVar4 = strcmp(pcVar12,"qu");
                    if (iVar4 == 0) {
                      local_20 = FUN_00116378(param_1);
                      uVar7 = FUN_00116378(param_1);
                      uVar8 = FUN_00116378(param_1);
LAB_00112938:
                      uVar7 = FUN_00110a5c(param_1,0x3b,uVar7,uVar8);
                      uVar7 = FUN_00110a5c(param_1,0x3a,local_20,uVar7);
                      uVar8 = 0x39;
                      goto LAB_00112204;
                    }
                    if ((*pcVar12 != 'n') || ((pcVar12[1] != 'a' && (pcVar12[1] != 'w'))))
                    goto switchD_001125e4_caseD_4;
                    local_20 = FUN_00112f0c(param_1,0x5f);
                    uVar7 = FUN_00113660(param_1);
                    pcVar12 = *(char **)(param_1 + 0x18);
                    cVar3 = *pcVar12;
                    if (cVar3 == 'E') {
                      uVar8 = 0;
                      *(char **)(param_1 + 0x18) = pcVar12 + 1;
                      goto LAB_00112938;
                    }
                    if (cVar3 == 'p') {
                      if (pcVar12[1] == 'i') {
                        *(char **)(param_1 + 0x18) = pcVar12 + 2;
                        uVar8 = FUN_00112f0c(param_1,0x45);
                        goto LAB_00112938;
                      }
                    }
                    else {
                      if (cVar3 != 'i') {
                        piVar9 = (int *)0x0;
                        goto LAB_00112218;
                      }
                      if (pcVar12[1] == 'l') {
                        uVar8 = FUN_00116378(param_1);
                        goto LAB_00112938;
                      }
                    }
                    piVar9 = (int *)0x0;
LAB_00112250:
                    if (((cVar3 != 't') && (cVar3 != 'i')) || (pcVar12[1] != 'l'))
                    goto LAB_00112270;
                    uVar7 = 0;
                    if (cVar3 == 't') {
                      uVar7 = FUN_00113660(param_1);
                    }
                    *(long *)(param_1 + 0x18) = *(long *)(param_1 + 0x18) + 2;
                    uVar8 = FUN_00112f0c(param_1,0x45);
                    lVar5 = FUN_00110a5c(param_1,0x30,uVar7,uVar8);
                    break;
                  default:
                    goto switchD_001125e4_caseD_4;
                  }
                }
              }
              else {
                if ((*pcVar12 != 'n') || ((pcVar12[1] != 'a' && (pcVar12[1] != 'w')))) break;
                local_18 = FUN_00112f0c(param_1,0x5f);
                piVar9 = (int *)FUN_00113660(param_1);
                pcVar12 = *(char **)(param_1 + 0x18);
                cVar3 = *pcVar12;
                if (cVar3 != 'E') {
                  if (cVar3 == 'p') {
                    lVar5 = 0;
                    if (pcVar12[1] == 'i') {
                      *(char **)(param_1 + 0x18) = pcVar12 + 2;
                      lVar5 = FUN_00112f0c(param_1,0x45);
                      goto switchD_00112664_caseD_4;
                    }
                  }
                  else {
                    lVar5 = 0;
                    if ((cVar3 == 'i') && (pcVar12[1] == 'l')) {
                      lVar5 = FUN_00116378(param_1);
                      goto switchD_00112664_caseD_4;
                    }
                  }
                  goto LAB_00111c28;
                }
                lVar5 = 0;
                *(char **)(param_1 + 0x18) = pcVar12 + 1;
              }
switchD_00112664_caseD_4:
              uVar7 = FUN_00110a5c(param_1,0x3b,piVar9,lVar5);
              uVar7 = FUN_00110a5c(param_1,0x3a,local_18,uVar7);
              lVar5 = FUN_00110a5c(param_1,0x39,piVar6,uVar7);
              pcVar12 = *(char **)(param_1 + 0x18);
              goto LAB_00111c28;
            }
          }
          else if (iVar4 == 0x33) {
            if (**(char **)(param_1 + 0x18) == '_') {
              *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
              uVar7 = FUN_00112f0c(param_1,0x45);
              goto LAB_00111f58;
            }
switchD_00111ee4_caseD_1:
            uVar7 = FUN_00116378(param_1);
            goto LAB_00111f58;
          }
        }
switchD_00111ee4_caseD_4:
        pcVar12 = *(char **)(param_1 + 0x18);
      }
LAB_00111c88:
      lVar5 = 0;
    }
LAB_00111c28:
    *(undefined4 *)(param_1 + 0x54) = uVar1;
    if (*pcVar12 != 'E') {
      return 0;
    }
    *(char **)(param_1 + 0x18) = pcVar12 + 1;
  }
  if (lVar5 == 0) {
    return 0;
  }
  lVar5 = FUN_00110a5c(param_1,0x2f,lVar5,0);
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
  goto LAB_00111a90;
switchD_00112750_caseD_1:
  cVar3 = *pcVar12;
  if (((cVar3 == 'm') || (cVar3 == 'p')) && (pcVar12[1] == cVar3)) {
    if (**(char **)(param_1 + 0x18) != '_') {
      uVar7 = FUN_00116378(param_1);
      uVar7 = FUN_00110a5c(param_1,0x38,uVar7,uVar7);
      uVar8 = 0x36;
      goto LAB_00112204;
    }
    *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
  }
switchD_001125e4_caseD_1:
  uVar7 = FUN_00116378(param_1);
LAB_001121fc:
  uVar8 = 0x36;
LAB_00112204:
  piVar9 = (int *)FUN_00110a5c(param_1,uVar8,piVar9,uVar7);
  pcVar12 = *(char **)(param_1 + 0x18);
  cVar3 = *pcVar12;
  goto LAB_00112218;
switchD_001126cc_caseD_1:
  cVar3 = *pcVar12;
  if (((cVar3 == 'm') || (cVar3 == 'p')) && (pcVar12[1] == cVar3)) {
    cVar3 = **(char **)(param_1 + 0x18);
    if (cVar3 != '_') {
      uVar7 = FUN_00116378(param_1,cVar3,pcVar12,0);
      uVar7 = FUN_00110a5c(param_1,0x38,uVar7,uVar7);
      goto LAB_001122b8;
    }
    *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
  }
  goto switchD_00112664_caseD_1;
}



undefined8 FUN_00112f0c(long param_1,char param_2)

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
    uVar5 = FUN_00110a5c(param_1,0x2e,0,0);
    return uVar5;
  }
  do {
    uVar1 = *(undefined4 *)(param_1 + 0x54);
    *(undefined4 *)(param_1 + 0x54) = 1;
    cVar2 = *pcVar10;
    if (cVar2 == 'L') {
      lVar6 = FUN_00116200(param_1);
LAB_001130d0:
      *(undefined4 *)(param_1 + 0x54) = uVar1;
      if (lVar6 == 0) {
        return 0;
      }
    }
    else {
      if (cVar2 == 'T') {
        lVar6 = FUN_00111848(param_1);
        goto LAB_001130d0;
      }
      if (cVar2 == 's') {
        if (pcVar10[1] == 'r') {
          *(char **)(param_1 + 0x18) = pcVar10 + 2;
          uVar5 = FUN_00113660(param_1);
          uVar8 = FUN_0011500c(param_1);
          if (**(char **)(param_1 + 0x18) == 'I') {
            uVar9 = FUN_00111a20(param_1);
            uVar8 = FUN_00110a5c(param_1,4,uVar8,uVar9);
          }
          lVar6 = FUN_00110a5c(param_1,1,uVar5,uVar8);
        }
        else {
          if (pcVar10[1] != 'p') goto LAB_00112fc0;
          *(char **)(param_1 + 0x18) = pcVar10 + 2;
          uVar5 = FUN_00116378(param_1);
          lVar6 = FUN_00110a5c(param_1,0x4a,uVar5,0);
        }
        goto LAB_001130d0;
      }
      if (cVar2 == 'f') {
        if (pcVar10[1] != 'p') goto LAB_00112fc0;
        *(char **)(param_1 + 0x18) = pcVar10 + 2;
        if (pcVar10[2] == 'T') {
          lVar7 = 0;
          *(char **)(param_1 + 0x18) = pcVar10 + 3;
        }
        else {
          iVar3 = FUN_00111718(param_1);
          if (iVar3 + 1 == 0) goto switchD_00113264_caseD_4;
          lVar7 = (long)(iVar3 + 1);
        }
        iVar3 = *(int *)(param_1 + 0x28);
        if (*(int *)(param_1 + 0x2c) <= iVar3) goto switchD_00113264_caseD_4;
        *(int *)(param_1 + 0x28) = iVar3 + 1;
        lVar6 = *(long *)(param_1 + 0x20) + (long)iVar3 * 0x18;
        if (lVar6 == 0) goto switchD_00113264_caseD_4;
        *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar3 * 0x18) = 6;
        *(long *)(lVar6 + 8) = lVar7;
      }
      else {
        if (9 < (byte)(cVar2 - 0x30U)) {
          if (cVar2 == 'o') {
            if (pcVar10[1] == 'n') {
              *(char **)(param_1 + 0x18) = pcVar10 + 2;
              goto LAB_00113034;
            }
          }
          else if (((cVar2 == 't') || (cVar2 == 'i')) && (pcVar10[1] == 'l')) {
            uVar5 = 0;
            if (cVar2 == 't') {
              uVar5 = FUN_00113660(param_1);
              pcVar10 = *(char **)(param_1 + 0x18);
            }
            *(char **)(param_1 + 0x18) = pcVar10 + 2;
            uVar8 = FUN_00112f0c(param_1,0x45);
            lVar6 = FUN_00110a5c(param_1,0x30,uVar5,uVar8);
            goto LAB_001130d0;
          }
LAB_00112fc0:
          piVar4 = (int *)FUN_00114e18(param_1);
          if (piVar4 == (int *)0x0) goto switchD_00113264_caseD_4;
          iVar3 = *piVar4;
          if (iVar3 == 0x31) {
            ppcVar12 = *(char ***)(piVar4 + 2);
            pcVar10 = *ppcVar12;
            *(int *)(param_1 + 0x50) = *(int *)(param_1 + 0x50) + *(int *)(ppcVar12 + 2) + -2;
            iVar3 = strcmp(pcVar10,"st");
            if (iVar3 != 0) {
              switch(*(undefined4 *)((long)ppcVar12 + 0x14)) {
              case 0:
                goto switchD_00113264_caseD_0;
              case 1:
                goto switchD_0011328c_caseD_1;
              case 2:
                goto switchD_0011328c_caseD_2;
              case 3:
                goto switchD_0011328c_caseD_3;
              default:
                goto switchD_00113264_caseD_4;
              }
            }
            uVar5 = FUN_00113660(param_1);
          }
          else {
            if (iVar3 == 0x32) {
              switch(piVar4[2]) {
              case 0:
switchD_00113264_caseD_0:
                lVar6 = FUN_00110a5c(param_1,0x35,piVar4,0);
                goto LAB_001130d0;
              case 1:
                goto switchD_00113264_caseD_1;
              case 2:
                pcVar10 = (char *)0x0;
switchD_0011328c_caseD_2:
                if (((**(char ***)(piVar4 + 2))[1] == 'c') &&
                   ((cVar2 = ***(char ***)(piVar4 + 2), (byte)(cVar2 + 0x8eU) < 2 ||
                    ((byte)(cVar2 + 0x9dU) < 2)))) {
                  uVar5 = FUN_00113660(param_1);
                }
                else {
                  uVar5 = FUN_00116378(param_1);
                }
                iVar3 = strcmp(pcVar10,"cl");
                if (iVar3 == 0) {
                  uVar8 = FUN_00112f0c(param_1,0x45);
                }
                else {
                  iVar3 = strcmp(pcVar10,"dt");
                  if ((iVar3 == 0) || (iVar3 = strcmp(pcVar10,"pt"), iVar3 == 0)) {
                    uVar8 = FUN_0011500c(param_1);
                    if (**(char **)(param_1 + 0x18) == 'I') {
                      uVar9 = FUN_00111a20(param_1);
                      uVar8 = FUN_00110a5c(param_1,4,uVar8,uVar9);
                    }
                  }
                  else {
                    uVar8 = FUN_00116378(param_1);
                  }
                }
                uVar5 = FUN_00110a5c(param_1,0x38,uVar5,uVar8);
                lVar6 = FUN_00110a5c(param_1,0x37,piVar4,uVar5);
                goto LAB_001130d0;
              case 3:
                pcVar10 = (char *)0x0;
switchD_0011328c_caseD_3:
                iVar3 = strcmp(pcVar10,"qu");
                if (iVar3 == 0) {
                  uVar5 = FUN_00116378(param_1);
                  uVar8 = FUN_00116378(param_1);
                  uVar9 = FUN_00116378(param_1);
                }
                else {
                  if ((*pcVar10 != 'n') || ((pcVar10[1] != 'a' && (pcVar10[1] != 'w'))))
                  goto switchD_00113264_caseD_4;
                  uVar5 = FUN_00112f0c(param_1,0x5f);
                  uVar8 = FUN_00113660(param_1);
                  pcVar10 = *(char **)(param_1 + 0x18);
                  cVar2 = *pcVar10;
                  if (cVar2 == 'E') {
                    uVar9 = 0;
                    *(char **)(param_1 + 0x18) = pcVar10 + 1;
                  }
                  else if (cVar2 == 'p') {
                    if (pcVar10[1] != 'i') goto switchD_00113264_caseD_4;
                    *(char **)(param_1 + 0x18) = pcVar10 + 2;
                    uVar9 = FUN_00112f0c(param_1,0x45);
                  }
                  else {
                    if ((cVar2 != 'i') || (pcVar10[1] != 'l')) {
switchD_00113264_caseD_4:
                      *(undefined4 *)(param_1 + 0x54) = uVar1;
                      return 0;
                    }
                    uVar9 = FUN_00116378(param_1);
                  }
                }
                uVar8 = FUN_00110a5c(param_1,0x3b,uVar8,uVar9);
                uVar5 = FUN_00110a5c(param_1,0x3a,uVar5,uVar8);
                lVar6 = FUN_00110a5c(param_1,0x39,piVar4,uVar5);
                goto LAB_001130d0;
              default:
                goto switchD_00113264_caseD_4;
              }
            }
            if (iVar3 != 0x33) goto switchD_00113264_caseD_4;
            if (**(char **)(param_1 + 0x18) == '_') {
              *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
              uVar5 = FUN_00112f0c(param_1,0x45);
              goto LAB_00113008;
            }
switchD_00113264_caseD_1:
            uVar5 = FUN_00116378(param_1);
          }
LAB_00113008:
          lVar6 = FUN_00110a5c(param_1,0x36,piVar4,uVar5);
          goto LAB_001130d0;
        }
LAB_00113034:
        lVar6 = FUN_0011500c(param_1);
        if (lVar6 == 0) goto switchD_00113264_caseD_4;
        if (**(char **)(param_1 + 0x18) == 'I') {
          uVar5 = FUN_00111a20(param_1);
          lVar6 = FUN_00110a5c(param_1,4,lVar6,uVar5);
          goto LAB_001130d0;
        }
      }
      *(undefined4 *)(param_1 + 0x54) = uVar1;
    }
    lVar6 = FUN_00110a5c(param_1,0x2e,lVar6,0);
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
switchD_0011328c_caseD_1:
  cVar2 = *pcVar10;
  if (((cVar2 == 'm') || (cVar2 == 'p')) && (pcVar10[1] == cVar2)) {
    if (**(char **)(param_1 + 0x18) != '_') {
      uVar5 = FUN_00116378(param_1);
      uVar5 = FUN_00110a5c(param_1,0x38,uVar5,uVar5);
      goto LAB_00113008;
    }
    *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
  }
  goto switchD_00113264_caseD_1;
}



int * FUN_00113660(long param_1)

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
    ppiVar11 = (int **)FUN_00110b5c(param_1,&local_8,0);
    if (ppiVar11 == (int **)0x0) {
      return (int *)0x0;
    }
    if (**(char **)(param_1 + 0x18) == 'F') {
      piVar12 = (int *)FUN_001169e0(param_1);
      *ppiVar11 = piVar12;
    }
    else {
      piVar12 = (int *)FUN_00113660();
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
    local_8 = (int *)FUN_00115590(param_1);
    break;
  default:
    goto switchD_001136dc_caseD_3a;
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
        lVar14 = FUN_00110afc(param_1,pbVar21,(int)pbVar23 - (int)pbVar21);
joined_r0x00114138:
        if (lVar14 == 0) goto LAB_00113884;
        pbVar21 = *(byte **)(param_1 + 0x18);
      }
      else {
        uVar2 = *(undefined4 *)(param_1 + 0x54);
        *(undefined4 *)(param_1 + 0x54) = 1;
        bVar7 = pbVar22[1];
        if (bVar7 == 0x4c) {
          lVar14 = FUN_00116200(param_1);
LAB_00114134:
          *(undefined4 *)(param_1 + 0x54) = uVar2;
          goto joined_r0x00114138;
        }
        if (bVar7 == 0x54) {
          lVar14 = FUN_00111848(param_1);
          goto LAB_00114134;
        }
        if (bVar7 == 0x73) {
          if (pbVar22[2] == 0x72) {
            *(byte **)(param_1 + 0x18) = pbVar22 + 3;
            uVar13 = FUN_00113660(param_1);
            uVar17 = FUN_0011500c(param_1);
            if (**(char **)(param_1 + 0x18) == 'I') {
              uVar18 = FUN_00111a20(param_1);
              uVar17 = FUN_00110a5c(param_1,4,uVar17,uVar18);
              lVar14 = FUN_00110a5c(param_1,1,uVar13,uVar17);
            }
            else {
              lVar14 = FUN_00110a5c(param_1,1,uVar13,uVar17);
            }
          }
          else {
            if (pbVar22[2] != 0x70) goto LAB_001140d8;
            *(byte **)(param_1 + 0x18) = pbVar22 + 3;
            uVar13 = FUN_00116378(param_1);
            lVar14 = FUN_00110a5c(param_1,0x4a,uVar13,0);
          }
          goto LAB_00114134;
        }
        if (bVar7 != 0x66) {
          if ((byte)(bVar7 - 0x30) < 10) {
LAB_001141ac:
            lVar14 = FUN_0011500c(param_1);
            if (lVar14 != 0) {
              pbVar21 = *(byte **)(param_1 + 0x18);
              if (*pbVar21 != 0x49) {
                *(undefined4 *)(param_1 + 0x54) = uVar2;
                goto LAB_00113874;
              }
              uVar13 = FUN_00111a20(param_1);
              lVar14 = FUN_00110a5c(param_1,4,lVar14,uVar13);
              goto LAB_00114134;
            }
          }
          else {
            if (bVar7 == 0x6f) {
              if (pbVar22[2] == 0x6e) {
                *(byte **)(param_1 + 0x18) = pbVar22 + 3;
                goto LAB_001141ac;
              }
            }
            else if (((bVar7 == 0x74) || (bVar7 == 0x69)) && (pbVar22[2] == 0x6c)) {
              uVar13 = 0;
              if (bVar7 == 0x74) {
                uVar13 = FUN_00113660(param_1);
              }
              *(long *)(param_1 + 0x18) = *(long *)(param_1 + 0x18) + 2;
              uVar17 = FUN_00112f0c(param_1,0x45);
              lVar14 = FUN_00110a5c(param_1,0x30,uVar13,uVar17);
              goto LAB_00114134;
            }
LAB_001140d8:
            piVar12 = (int *)FUN_00114e18(param_1);
            if (piVar12 != (int *)0x0) {
              iVar10 = *piVar12;
              if (iVar10 == 0x31) {
                pcVar24 = **(char ***)(piVar12 + 2);
                *(int *)(param_1 + 0x50) =
                     *(int *)(param_1 + 0x50) + *(int *)(*(char ***)(piVar12 + 2) + 2) + -2;
                iVar10 = strcmp(pcVar24,"st");
                if (iVar10 == 0) {
                  uVar13 = FUN_00113660(param_1);
LAB_00114120:
                  lVar14 = FUN_00110a5c(param_1,0x36,piVar12,uVar13);
                  goto LAB_00114134;
                }
                switch(*(undefined4 *)(*(long *)(piVar12 + 2) + 0x14)) {
                case 0:
                  goto switchD_00114470_caseD_0;
                case 1:
                  cVar8 = *pcVar24;
                  if (((cVar8 == 'm') || (cVar8 == 'p')) && (pcVar24[1] == cVar8)) {
                    if (**(char **)(param_1 + 0x18) != '_') {
                      uVar13 = FUN_00116378(param_1);
                      uVar13 = FUN_00110a5c(param_1,0x38,uVar13,uVar13);
                      goto LAB_00114120;
                    }
                    *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
                  }
                  goto switchD_00114470_caseD_1;
                case 2:
                  goto switchD_0011469c_caseD_2;
                case 3:
                  goto switchD_0011469c_caseD_3;
                }
              }
              else if (iVar10 == 0x32) {
                switch(piVar12[2]) {
                case 0:
switchD_00114470_caseD_0:
                  lVar14 = FUN_00110a5c(param_1,0x35,piVar12,0);
                  goto LAB_00114134;
                case 1:
                  goto switchD_00114470_caseD_1;
                case 2:
                  pcVar24 = (char *)0x0;
switchD_0011469c_caseD_2:
                  if (((**(char ***)(piVar12 + 2))[1] == 'c') &&
                     ((cVar8 = ***(char ***)(piVar12 + 2), (byte)(cVar8 + 0x8eU) < 2 ||
                      ((byte)(cVar8 + 0x9dU) < 2)))) {
                    uVar13 = FUN_00113660(param_1);
                  }
                  else {
                    uVar13 = FUN_00116378(param_1);
                  }
                  iVar10 = strcmp(pcVar24,"cl");
                  if (iVar10 == 0) {
                    uVar17 = FUN_00112f0c(param_1,0x45);
                  }
                  else {
                    iVar10 = strcmp(pcVar24,"dt");
                    if ((iVar10 == 0) || (iVar10 = strcmp(pcVar24,"pt"), iVar10 == 0)) {
                      uVar17 = FUN_0011500c(param_1);
                      if (**(char **)(param_1 + 0x18) == 'I') {
                        uVar18 = FUN_00111a20(param_1);
                        uVar17 = FUN_00110a5c(param_1,4,uVar17,uVar18);
                      }
                    }
                    else {
                      uVar17 = FUN_00116378(param_1);
                    }
                  }
                  uVar13 = FUN_00110a5c(param_1,0x38,uVar13,uVar17);
                  lVar14 = FUN_00110a5c(param_1,0x37,piVar12,uVar13);
                  goto LAB_00114134;
                case 3:
                  pcVar24 = (char *)0x0;
switchD_0011469c_caseD_3:
                  iVar10 = strcmp(pcVar24,"qu");
                  if (iVar10 == 0) {
                    uVar13 = FUN_00116378(param_1);
                    uVar17 = FUN_00116378(param_1);
                    uVar18 = FUN_00116378(param_1);
LAB_00114518:
                    uVar17 = FUN_00110a5c(param_1,0x3b,uVar17,uVar18);
                    uVar13 = FUN_00110a5c(param_1,0x3a,uVar13,uVar17);
                    lVar14 = FUN_00110a5c(param_1,0x39,piVar12,uVar13);
                    goto LAB_00114134;
                  }
                  if ((*pcVar24 == 'n') && ((pcVar24[1] == 'a' || (pcVar24[1] == 'w')))) {
                    uVar13 = FUN_00112f0c(param_1,0x5f);
                    uVar17 = FUN_00113660(param_1);
                    pcVar24 = *(char **)(param_1 + 0x18);
                    cVar8 = *pcVar24;
                    if (cVar8 == 'E') {
                      uVar18 = 0;
                      *(char **)(param_1 + 0x18) = pcVar24 + 1;
                      goto LAB_00114518;
                    }
                    if (cVar8 == 'p') {
                      if (pcVar24[1] == 'i') {
                        *(char **)(param_1 + 0x18) = pcVar24 + 2;
                        uVar18 = FUN_00112f0c(param_1,0x45);
                        goto LAB_00114518;
                      }
                    }
                    else if ((cVar8 == 'i') && (pcVar24[1] == 'l')) {
                      uVar18 = FUN_00116378(param_1);
                      goto LAB_00114518;
                    }
                  }
                }
              }
              else if (iVar10 == 0x33) {
                if (**(char **)(param_1 + 0x18) == '_') {
                  *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
                  uVar13 = FUN_00112f0c(param_1,0x45);
                  goto LAB_00114120;
                }
switchD_00114470_caseD_1:
                uVar13 = FUN_00116378(param_1);
                goto LAB_00114120;
              }
            }
          }
switchD_00114470_caseD_4:
          *(undefined4 *)(param_1 + 0x54) = uVar2;
          goto LAB_00113884;
        }
        if (pbVar22[2] != 0x70) goto LAB_001140d8;
        *(byte **)(param_1 + 0x18) = pbVar22 + 3;
        if (pbVar22[3] == 0x54) {
          iVar10 = 0;
          *(byte **)(param_1 + 0x18) = pbVar22 + 4;
        }
        else {
          iVar10 = FUN_00111718(param_1);
          iVar10 = iVar10 + 1;
          if (iVar10 == 0) goto switchD_00114470_caseD_4;
        }
        iVar6 = *(int *)(param_1 + 0x28);
        if (*(int *)(param_1 + 0x2c) <= iVar6) goto switchD_00114470_caseD_4;
        *(int *)(param_1 + 0x28) = iVar6 + 1;
        lVar14 = *(long *)(param_1 + 0x20) + (long)iVar6 * 0x18;
        if (lVar14 == 0) goto switchD_00114470_caseD_4;
        *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar6 * 0x18) = 6;
        *(long *)(lVar14 + 8) = (long)iVar10;
        *(undefined4 *)(param_1 + 0x54) = uVar2;
        pbVar21 = *(byte **)(param_1 + 0x18);
      }
LAB_00113874:
      if (*pbVar21 != 0x5f) goto LAB_00113884;
    }
    *(byte **)(param_1 + 0x18) = pbVar21 + 1;
    uVar13 = FUN_00113660(param_1);
    local_8 = (int *)FUN_00110a5c(param_1,0x2a,lVar14,uVar13);
    break;
  case 0x43:
    *(byte **)(param_1 + 0x18) = pbVar22 + 1;
    uVar13 = FUN_00113660(param_1);
    local_8 = (int *)FUN_00110a5c(param_1,0x25,uVar13,0);
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
        UNRECOVERED_JUMPTABLE_00 = (code *)SoftwareBreakpoint(1000,0x114198);
        piVar12 = (int *)(*UNRECOVERED_JUMPTABLE_00)();
        return piVar12;
      }
      *(int *)(param_1 + 0x28) = iVar10 + 1;
      local_8 = (int *)(*(long *)(param_1 + 0x20) + (long)iVar10 * 0x18);
      *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar10 * 0x18) = 0x2c;
      bVar1 = (byte)(pbVar22[2] - 0x30) < 10;
      *(ushort *)(local_8 + 4) = (ushort)bVar1;
      if (bVar1) {
        FUN_00111110(param_1 + 0x18);
      }
      piVar12 = local_8;
      uVar13 = FUN_00113660(param_1);
      *(undefined8 *)(piVar12 + 2) = uVar13;
      if (*(long *)(local_8 + 2) == 0) {
        return (int *)0x0;
      }
      FUN_00111110(param_1 + 0x18);
      pcVar24 = *(char **)(param_1 + 0x18);
      uVar19 = 0;
      if (*pcVar24 != '\0') {
        *(char **)(param_1 + 0x18) = pcVar24 + 1;
        uVar19 = (ushort)(*pcVar24 == 's');
      }
      *(ushort *)((long)local_8 + 0x12) = uVar19;
      return local_8;
    default:
      goto switchD_001136dc_caseD_3a;
    case 0x54:
    case 0x74:
      uVar2 = *(undefined4 *)(param_1 + 0x54);
      *(undefined4 *)(param_1 + 0x54) = 1;
      bVar7 = pbVar22[2];
      if (bVar7 == 0x4c) {
        lVar14 = FUN_00116200(param_1);
      }
      else if (bVar7 == 0x54) {
        lVar14 = FUN_00111848(param_1);
      }
      else if (bVar7 == 0x73) {
        if (pbVar22[3] == 0x72) {
          *(byte **)(param_1 + 0x18) = pbVar22 + 4;
          uVar13 = FUN_00113660(param_1);
          uVar17 = FUN_0011500c(param_1);
          if (**(char **)(param_1 + 0x18) == 'I') {
            uVar18 = FUN_00111a20(param_1);
            uVar17 = FUN_00110a5c(param_1,4,uVar17,uVar18);
            lVar14 = FUN_00110a5c(param_1,1,uVar13,uVar17);
          }
          else {
            lVar14 = FUN_00110a5c(param_1,1,uVar13,uVar17);
          }
        }
        else {
          if (pbVar22[3] != 0x70) goto LAB_00113ebc;
          *(byte **)(param_1 + 0x18) = pbVar22 + 4;
          uVar13 = FUN_00116378(param_1);
          lVar14 = FUN_00110a5c(param_1,0x4a,uVar13,0);
        }
      }
      else if (bVar7 == 0x66) {
        if (pbVar22[3] != 0x70) goto LAB_00113ebc;
        *(byte **)(param_1 + 0x18) = pbVar22 + 4;
        if (pbVar22[4] == 0x54) {
          iVar10 = 0;
          *(byte **)(param_1 + 0x18) = pbVar22 + 5;
        }
        else {
          iVar10 = FUN_00111718(param_1);
          iVar10 = iVar10 + 1;
          if (iVar10 == 0) goto LAB_0011472c;
        }
        iVar6 = *(int *)(param_1 + 0x28);
        if (*(int *)(param_1 + 0x2c) <= iVar6) goto LAB_0011472c;
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
LAB_001142c4:
          lVar14 = FUN_0011500c(param_1);
          if (lVar14 != 0) {
            if (**(char **)(param_1 + 0x18) == 'I') {
              uVar13 = FUN_00111a20(param_1);
              lVar14 = FUN_00110a5c(param_1,4,lVar14,uVar13);
            }
            goto switchD_00114930_caseD_4;
          }
        }
        else {
          if (bVar7 == 0x6f) {
            if (pbVar22[3] == 0x6e) {
              *(byte **)(param_1 + 0x18) = pbVar22 + 4;
              goto LAB_001142c4;
            }
          }
          else if (((bVar7 == 0x74) || (bVar7 == 0x69)) && (pbVar22[3] == 0x6c)) {
            uVar13 = 0;
            if (bVar7 == 0x74) {
              uVar13 = FUN_00113660(param_1);
            }
            *(long *)(param_1 + 0x18) = *(long *)(param_1 + 0x18) + 2;
            uVar17 = FUN_00112f0c(param_1,0x45);
            lVar14 = FUN_00110a5c(param_1,0x30,uVar13,uVar17);
            goto switchD_00114930_caseD_4;
          }
LAB_00113ebc:
          piVar12 = (int *)FUN_00114e18(param_1);
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
                  goto switchD_00114930_caseD_0;
                case 1:
                  goto switchD_00114718_caseD_1;
                case 2:
                  goto switchD_00114718_caseD_2;
                case 3:
                  goto switchD_00114718_caseD_3;
                default:
                  goto switchD_00114930_caseD_4;
                }
              }
              uVar13 = FUN_00113660(param_1);
            }
            else {
              if (iVar10 == 0x32) {
                lVar14 = 0;
                switch(piVar12[2]) {
                case 0:
switchD_00114930_caseD_0:
                  lVar14 = FUN_00110a5c(param_1,0x35,piVar12,0);
                  break;
                case 1:
                  goto switchD_00114930_caseD_1;
                case 2:
                  pcVar24 = (char *)0x0;
switchD_00114718_caseD_2:
                  if ((**(char ***)(piVar12 + 2))[1] == 'c') {
                    cVar8 = ***(char ***)(piVar12 + 2);
                    bVar7 = cVar8 + 0x8e;
                    if ((1 < bVar7) && (1 < (byte)(cVar8 + 0x9dU))) goto LAB_00114960;
                    uVar13 = FUN_00113660(param_1,bVar7,0);
                  }
                  else {
LAB_00114960:
                    uVar13 = FUN_00116378(param_1);
                  }
                  iVar10 = strcmp(pcVar24,"cl");
                  if (iVar10 == 0) {
                    uVar17 = FUN_00112f0c(param_1,0x45);
                  }
                  else {
                    iVar10 = strcmp(pcVar24,"dt");
                    if ((iVar10 == 0) || (iVar10 = strcmp(pcVar24,"pt"), iVar10 == 0)) {
                      uVar17 = FUN_0011500c(param_1);
                      if (**(char **)(param_1 + 0x18) == 'I') {
                        uVar18 = FUN_00111a20(param_1);
                        uVar17 = FUN_00110a5c(param_1,4,uVar17,uVar18);
                      }
                    }
                    else {
                      uVar17 = FUN_00116378(param_1);
                    }
                  }
                  uVar13 = FUN_00110a5c(param_1,0x38,uVar13,uVar17);
                  lVar14 = FUN_00110a5c(param_1,0x37,piVar12,uVar13);
                  break;
                case 3:
                  pcVar24 = (char *)0x0;
switchD_00114718_caseD_3:
                  iVar10 = strcmp(pcVar24,"qu");
                  if (iVar10 == 0) {
                    uVar13 = FUN_00116378(param_1);
                    uVar17 = FUN_00116378(param_1);
                    uVar18 = FUN_00116378(param_1);
                  }
                  else {
                    if ((*pcVar24 != 'n') || ((pcVar24[1] != 'a' && (pcVar24[1] != 'w'))))
                    goto LAB_0011472c;
                    uVar13 = FUN_00112f0c(param_1,0x5f);
                    uVar17 = FUN_00113660(param_1);
                    pcVar24 = *(char **)(param_1 + 0x18);
                    cVar8 = *pcVar24;
                    if (cVar8 != 'E') {
                      if (cVar8 == 'p') {
                        if (pcVar24[1] == 'i') {
                          *(char **)(param_1 + 0x18) = pcVar24 + 2;
                          uVar18 = FUN_00112f0c(param_1,0x45);
                          goto LAB_00114ad0;
                        }
                      }
                      else if ((cVar8 == 'i') && (pcVar24[1] == 'l')) {
                        uVar18 = FUN_00116378(param_1);
                        goto LAB_00114ad0;
                      }
                      goto LAB_0011472c;
                    }
                    uVar18 = 0;
                    *(char **)(param_1 + 0x18) = pcVar24 + 1;
                  }
LAB_00114ad0:
                  uVar17 = FUN_00110a5c(param_1,0x3b,uVar17,uVar18);
                  uVar13 = FUN_00110a5c(param_1,0x3a,uVar13,uVar17);
                  lVar14 = FUN_00110a5c(param_1,0x39,piVar12,uVar13);
                }
                goto switchD_00114930_caseD_4;
              }
              if (iVar10 != 0x33) goto LAB_0011472c;
              if (**(char **)(param_1 + 0x18) == '_') {
                *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
                uVar13 = FUN_00112f0c(param_1,0x45);
                goto LAB_00113f04;
              }
switchD_00114930_caseD_1:
              uVar13 = FUN_00116378(param_1);
            }
LAB_00113f04:
            lVar14 = FUN_00110a5c(param_1,0x36,piVar12,uVar13);
            goto switchD_00114930_caseD_4;
          }
        }
LAB_0011472c:
        lVar14 = 0;
      }
switchD_00114930_caseD_4:
      *(undefined4 *)(param_1 + 0x54) = uVar2;
      local_8 = (int *)FUN_00110a5c(param_1,0x42,lVar14,0);
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
      goto LAB_001137c4;
    case 0x61:
      piVar12 = (int *)FUN_00110afc(param_1,&DAT_00124ab0,4);
      return piVar12;
    case 100:
      iVar10 = *(int *)(param_1 + 0x28);
      if (iVar10 < *(int *)(param_1 + 0x2c)) {
        *(int *)(param_1 + 0x28) = iVar10 + 1;
        piVar12 = (int *)(*(long *)(param_1 + 0x20) + (long)iVar10 * 0x18);
        if (piVar12 != (int *)0x0) {
          *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar10 * 0x18) = 0x27;
          *(undefined ***)(piVar12 + 2) = &PTR_s_decimal64_0013aba0;
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
          *(undefined ***)(piVar12 + 2) = &PTR_s_decimal128_0013abc0;
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
          *(undefined ***)(piVar12 + 2) = &PTR_s_decimal32_0013ab80;
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
          *(undefined ***)(piVar12 + 2) = &PTR_DAT_0013abe0;
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
          *(undefined ***)(piVar12 + 2) = &PTR_s_char32_t_0013ac20;
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
          *(undefined ***)(piVar12 + 2) = &PTR_s_decltype_nullptr__0013ac40;
          *(int *)(param_1 + 0x50) = *(int *)(param_1 + 0x50) + 0x11;
          return piVar12;
        }
      }
      break;
    case 0x70:
      uVar13 = FUN_00113660(param_1);
      local_8 = (int *)FUN_00110a5c(param_1,0x4a,uVar13,0);
      goto LAB_001137c0;
    case 0x73:
      iVar10 = *(int *)(param_1 + 0x28);
      if (iVar10 < *(int *)(param_1 + 0x2c)) {
        *(int *)(param_1 + 0x28) = iVar10 + 1;
        piVar12 = (int *)(*(long *)(param_1 + 0x20) + (long)iVar10 * 0x18);
        if (piVar12 != (int *)0x0) {
          *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar10 * 0x18) = 0x27;
          *(undefined ***)(piVar12 + 2) = &PTR_s_char16_t_0013ac00;
          *(int *)(param_1 + 0x50) = *(int *)(param_1 + 0x50) + 8;
          return piVar12;
        }
      }
      break;
    case 0x76:
      local_8 = (int *)FUN_00116b10(param_1);
      goto LAB_001137c0;
    }
LAB_00114004:
    local_8 = (int *)0x0;
                    // WARNING: Treating indirect jump as call
    UNRECOVERED_JUMPTABLE_00 = (code *)SoftwareBreakpoint(1000,0x114014);
    piVar12 = (int *)(*UNRECOVERED_JUMPTABLE_00)(uRam0000000000000008);
    return piVar12;
  case 0x46:
    local_8 = (int *)FUN_001169e0(param_1);
    break;
  case 0x47:
    *(byte **)(param_1 + 0x18) = pbVar22 + 1;
    uVar13 = FUN_00113660(param_1);
    local_8 = (int *)FUN_00110a5c(param_1,0x26,uVar13,0);
    break;
  case 0x4d:
    *(byte **)(param_1 + 0x18) = pbVar22 + 1;
    lVar14 = FUN_00113660(param_1);
    if ((lVar14 == 0) || (lVar15 = FUN_00113660(param_1), lVar15 == 0)) {
LAB_00113884:
      local_8 = (int *)0x0;
    }
    else {
      local_8 = (int *)FUN_00110a5c(param_1,0x2b,lVar14,lVar15);
    }
    break;
  case 0x4f:
    *(byte **)(param_1 + 0x18) = pbVar22 + 1;
    uVar13 = FUN_00113660(param_1);
    local_8 = (int *)FUN_00110a5c(param_1,0x24,uVar13,0);
    break;
  case 0x50:
    *(byte **)(param_1 + 0x18) = pbVar22 + 1;
    uVar13 = FUN_00113660(param_1);
    local_8 = (int *)FUN_00110a5c(param_1,0x22,uVar13,0);
    break;
  case 0x52:
    *(byte **)(param_1 + 0x18) = pbVar22 + 1;
    uVar13 = FUN_00113660(param_1);
    local_8 = (int *)FUN_00110a5c(param_1,0x23,uVar13,0);
    break;
  case 0x53:
    bVar7 = pbVar22[1];
    if (((9 < (byte)(bVar7 - 0x30)) && (bVar7 != 0x5f)) && (0x19 < (byte)(bVar7 + 0xbf))) {
      local_8 = (int *)FUN_00115590(param_1);
      if (local_8 == (int *)0x0) {
        return (int *)0x0;
      }
      if (*local_8 == 0x18) {
        return local_8;
      }
      goto LAB_001137c4;
    }
    local_8 = (int *)FUN_00110d0c(param_1,0);
    if (**(char **)(param_1 + 0x18) != 'I') {
      return local_8;
    }
LAB_00113a6c:
    piVar12 = local_8;
    uVar13 = FUN_00111a20(param_1);
    local_8 = (int *)FUN_00110a5c(param_1,4,piVar12,uVar13);
    break;
  case 0x54:
    local_8 = (int *)FUN_00111848(param_1);
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
        goto LAB_00113a6c;
      }
      uVar2 = *(undefined4 *)(param_1 + 0x28);
      uVar3 = *(undefined4 *)(param_1 + 0x38);
      uVar4 = *(undefined4 *)(param_1 + 0x40);
      uVar5 = *(undefined4 *)(param_1 + 0x50);
      uVar13 = FUN_00111a20(param_1);
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
        local_8 = (int *)FUN_00110a5c(param_1,4,local_8,uVar13);
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
    local_8 = (int *)FUN_00111670(param_1);
    uVar13 = FUN_00113660(param_1);
    local_8 = (int *)FUN_00110a5c(param_1,0x21,uVar13,local_8);
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
        *(ulong *)(piVar12 + 2) = (long)&PTR_s_signed_char_0013a840 + uVar16;
        iVar10 = *(int *)(&DAT_0013a848 + uVar16);
        *(byte **)(param_1 + 0x18) = pbVar22 + 1;
        *(int *)(param_1 + 0x50) = *(int *)(param_1 + 0x50) + iVar10;
        return piVar12;
      }
    }
    goto LAB_00114004;
  case 0x75:
    *(byte **)(param_1 + 0x18) = pbVar22 + 1;
    uVar13 = FUN_00111670(param_1);
    local_8 = (int *)FUN_00110a5c(param_1,0x28,uVar13,0);
  }
LAB_001137c0:
  if (local_8 != (int *)0x0) {
LAB_001137c4:
    iVar10 = *(int *)(param_1 + 0x38);
    if (iVar10 < *(int *)(param_1 + 0x3c)) {
      *(int **)(*(long *)(param_1 + 0x30) + (long)iVar10 * 8) = local_8;
      *(int *)(param_1 + 0x38) = iVar10 + 1;
      return local_8;
    }
  }
switchD_001136dc_caseD_3a:
  return (int *)0x0;
switchD_00114718_caseD_1:
  cVar8 = *pcVar24;
  if (((cVar8 == 'm') || (cVar8 == 'p')) && (pcVar24[1] == cVar8)) {
    cVar8 = **(char **)(param_1 + 0x18);
    if (cVar8 != '_') {
      uVar13 = FUN_00116378(param_1,cVar8,0);
      uVar13 = FUN_00110a5c(param_1,0x38,uVar13,uVar13);
      goto LAB_00113f04;
    }
    *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
  }
  goto switchD_00114930_caseD_1;
}



long FUN_00114d08(long param_1)

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
      lVar2 = FUN_00113660(param_1);
      if (lVar2 == 0) {
        return 0;
      }
      lVar2 = FUN_00110a5c(param_1,0x2e,lVar2,0);
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



long FUN_00114e18(long param_1)

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
          lVar7 = FUN_00111670();
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
        uVar6 = FUN_00113660();
        if (*(int *)(param_1 + 0x58) == 0) {
          lVar7 = FUN_00110a5c(param_1,0x33,uVar6,0);
          *(undefined4 *)(param_1 + 0x58) = uVar3;
        }
        else {
          lVar7 = FUN_00110a5c(param_1,0x34,uVar6,0);
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
    bVar4 = *(&PTR_DAT_0013ade8)[(long)iVar1 * 3];
    if (bVar11 == bVar4) {
      bVar4 = (&PTR_DAT_0013ade8)[(long)iVar1 * 3][1];
      if (bVar12 == bVar4) {
        iVar9 = *(int *)(param_1 + 0x28);
        if (*(int *)(param_1 + 0x2c) <= iVar9) {
          return 0;
        }
        *(int *)(param_1 + 0x28) = iVar9 + 1;
        lVar7 = *(long *)(param_1 + 0x20) + (long)iVar9 * 0x18;
        if (lVar7 != 0) {
          *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar9 * 0x18) = 0x31;
          *(undefined ***)(lVar7 + 8) = &PTR_DAT_0013ade8 + (long)iVar1 * 3;
          return lVar7;
        }
        return 0;
      }
      if (bVar4 <= bVar12) goto LAB_00114eb0;
    }
    else if (bVar4 <= bVar11) {
LAB_00114eb0:
      iVar9 = iVar1 + 1;
      iVar1 = iVar10;
    }
    iVar10 = iVar1;
    if (iVar9 == iVar10) {
      return 0;
    }
  } while( true );
}



int * FUN_0011500c(long param_1)

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
    local_8 = (int *)FUN_00111670();
    pcVar7 = *(char **)(param_1 + 0x18);
    cVar10 = *pcVar7;
    goto joined_r0x00115164;
  }
  if ((byte)(cVar10 + 0x9fU) < 0x1a) {
    local_8 = (int *)FUN_00114e18();
    if ((local_8 != (int *)0x0) && (*local_8 == 0x31)) {
      pcVar8 = **(char ***)(local_8 + 2);
      *(int *)(param_1 + 0x50) =
           *(int *)(param_1 + 0x50) + *(int *)(*(char ***)(local_8 + 2) + 2) + 7;
      iVar3 = strcmp(pcVar8,"li");
      if (iVar3 == 0) {
        uVar4 = FUN_00111670(param_1);
        local_8 = (int *)FUN_00110a5c(param_1,0x36,local_8,uVar4);
      }
    }
    pcVar7 = *(char **)(param_1 + 0x18);
    cVar10 = *pcVar7;
    goto joined_r0x00115164;
  }
  if (1 < (byte)(cVar10 + 0xbdU)) {
    if (cVar10 == 'L') {
      *(char **)(param_1 + 0x18) = pcVar8 + 1;
      local_8 = (int *)FUN_00111670();
      if (local_8 == (int *)0x0) {
        return (int *)0x0;
      }
      iVar3 = FUN_001117a4(param_1);
      if (iVar3 == 0) {
        return (int *)0x0;
      }
      cVar10 = **(char **)(param_1 + 0x18);
      pcVar7 = *(char **)(param_1 + 0x18);
      goto joined_r0x00115164;
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
        lVar6 = FUN_00114d08();
        pcVar7 = *(char **)(param_1 + 0x18);
        if (lVar6 == 0) goto LAB_00115398;
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
            iVar3 = FUN_00111110(param_1 + 0x18);
            pcVar7 = *(char **)(param_1 + 0x18);
            cVar10 = *pcVar7;
            if (cVar10 != '_') goto joined_r0x00115164;
            iVar3 = iVar3 + 1;
            pcVar8 = pcVar7 + 1;
            *(char **)(param_1 + 0x18) = pcVar8;
            if (iVar3 < 0) {
              cVar10 = pcVar7[1];
              pcVar7 = pcVar8;
              local_8 = (int *)0x0;
              goto joined_r0x00115164;
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
              if (iVar3 < *(int *)(param_1 + 0x3c)) goto LAB_001152ec;
            }
          }
          cVar10 = *pcVar8;
          local_8 = (int *)0x0;
          pcVar7 = pcVar8;
          goto joined_r0x00115164;
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
        lVar6 = FUN_00111718();
        if ((-1 < lVar6) && (iVar3 = *(int *)(param_1 + 0x28), iVar3 < *(int *)(param_1 + 0x2c))) {
          *(int *)(param_1 + 0x28) = iVar3 + 1;
          local_8 = (int *)(*(long *)(param_1 + 0x20) + (long)iVar3 * 0x18);
          if (local_8 != (int *)0x0) {
            *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar3 * 0x18) = 0x47;
            *(long *)(local_8 + 2) = lVar6;
            iVar3 = *(int *)(param_1 + 0x38);
            if (iVar3 < *(int *)(param_1 + 0x3c)) {
LAB_001152ec:
              *(int **)(*(long *)(param_1 + 0x30) + (long)iVar3 * 8) = local_8;
              *(int *)(param_1 + 0x38) = iVar3 + 1;
              cVar10 = **(char **)(param_1 + 0x18);
              pcVar7 = *(char **)(param_1 + 0x18);
              goto joined_r0x00115164;
            }
          }
        }
        pcVar7 = *(char **)(param_1 + 0x18);
LAB_00115398:
        cVar10 = *pcVar7;
        local_8 = (int *)0x0;
        goto joined_r0x00115164;
      }
    }
    local_8 = (int *)0x0;
    goto joined_r0x00115164;
  }
  piVar5 = *(int **)(param_1 + 0x48);
  if ((piVar5 == (int *)0x0) || ((*piVar5 != 0 && (*piVar5 != 0x18)))) {
    if (cVar10 == 'C') goto LAB_001154dc;
    if (cVar10 != 'D') {
      return (int *)0x0;
    }
LAB_001153c8:
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
switchD_001153ec_caseD_33:
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
        goto joined_r0x00115164;
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
        goto joined_r0x00115164;
      }
      goto LAB_001153c8;
    }
LAB_001154dc:
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
      goto switchD_001153ec_caseD_33;
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
        goto joined_r0x00115164;
      }
    }
  }
  pcVar7 = pcVar8 + 2;
  cVar10 = *pcVar7;
  local_8 = (int *)0x0;
joined_r0x00115164:
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
      if ((byte)(bVar2 - 0x30) < 10) goto LAB_001150c4;
LAB_00115194:
      uVar4 = 0;
    }
    else {
      if (9 < (byte)(bVar2 - 0x30)) goto LAB_00115194;
LAB_001150c4:
      pbVar11 = *(byte **)(param_1 + 0x18);
      lVar6 = 0;
      do {
        pbVar11 = pbVar11 + 1;
        uVar9 = (ulong)bVar2;
        *(byte **)(param_1 + 0x18) = pbVar11;
        bVar2 = *pbVar11;
        lVar6 = lVar6 * 10 + uVar9 + -0x30;
      } while ((byte)(bVar2 - 0x30) < 10);
      if ((lVar6 < 1) || (bVar12)) goto LAB_00115194;
      uVar4 = FUN_00111450(param_1);
      *(undefined8 *)(param_1 + 0x48) = uVar4;
    }
    local_8 = (int *)FUN_00110a5c(param_1,0x4b,local_8,uVar4);
    pcVar7 = *(char **)(param_1 + 0x18);
    if (*pcVar7 != 'B') {
      return local_8;
    }
  } while( true );
}



long FUN_00115590(long param_1)

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
    plVar5 = (long *)FUN_00110b5c(param_1,&local_8,1);
    if (plVar5 == (long *)0x0) {
      return 0;
    }
    pcVar4 = *(char **)(param_1 + 0x18);
    cVar13 = *pcVar4;
    if (cVar13 == 'O') {
      if (cVar13 == 'R') goto LAB_001159ec;
      uVar8 = 0x20;
      iVar1 = *(int *)(param_1 + 0x50) + 3;
    }
    else {
      lVar3 = 0;
      if (cVar13 != 'R') {
        lVar14 = 0;
        goto LAB_0011570c;
      }
LAB_001159ec:
      uVar8 = 0x1f;
      iVar1 = *(int *)(param_1 + 0x50) + 2;
    }
    *(int *)(param_1 + 0x50) = iVar1;
    *(char **)(param_1 + 0x18) = pcVar4 + 1;
    lVar14 = 0;
    lVar3 = FUN_00110a5c(param_1,uVar8,0,0);
    pcVar4 = *(char **)(param_1 + 0x18);
    cVar13 = *pcVar4;
LAB_0011570c:
    do {
      if (cVar13 == '\0') {
LAB_00115994:
        *plVar5 = 0;
        return 0;
      }
      pcVar9 = pcVar4;
      if (cVar13 == 'D') {
        if ((pcVar4[1] & 0xdfU) != 0x54) {
          lVar10 = FUN_0011500c(param_1);
          goto LAB_0011597c;
        }
        lVar10 = FUN_00113660();
        goto LAB_0011597c;
      }
      do {
        if ((((byte)(cVar13 - 0x30U) < 10) || ((byte)(cVar13 + 0x9fU) < 0x1a)) ||
           ((cVar13 == 'C' || cVar13 == 'U' || (cVar13 == 'L')))) {
          lVar10 = FUN_0011500c(param_1);
          if (lVar14 != 0) goto LAB_001158f8;
LAB_0011590c:
          if (cVar13 == 'S') goto LAB_00115948;
        }
        else {
          if (cVar13 == 'S') {
            lVar10 = FUN_00110d0c(param_1,1);
            if (lVar14 != 0) {
LAB_001158f8:
              uVar8 = 1;
LAB_001158fc:
              lVar10 = FUN_00110a5c(param_1,uVar8,lVar14,lVar10);
              goto LAB_0011590c;
            }
            pcVar4 = *(char **)(param_1 + 0x18);
            cVar13 = *pcVar4;
            lVar14 = lVar10;
            goto LAB_0011570c;
          }
          if (cVar13 == 'I') {
            if (lVar14 != 0) {
              lVar10 = FUN_00111a20(param_1);
              uVar8 = 4;
              goto LAB_001158fc;
            }
            goto LAB_00115994;
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
            if ((cVar13 != 'M') || (lVar14 == 0)) goto LAB_00115994;
            pcVar4 = pcVar9 + 1;
            *(char **)(param_1 + 0x18) = pcVar4;
            cVar13 = pcVar9[1];
            goto LAB_0011570c;
          }
          lVar10 = FUN_00111848(param_1);
LAB_0011597c:
          if (lVar14 != 0) goto LAB_001158f8;
        }
        pcVar9 = *(char **)(param_1 + 0x18);
        cVar13 = *pcVar9;
        lVar14 = lVar10;
      } while (cVar13 == 'E');
      if ((lVar10 == 0) || (iVar1 = *(int *)(param_1 + 0x38), *(int *)(param_1 + 0x3c) <= iVar1))
      goto LAB_00115994;
      *(long *)(*(long *)(param_1 + 0x30) + (long)iVar1 * 8) = lVar10;
      *(int *)(param_1 + 0x38) = iVar1 + 1;
LAB_00115948:
      pcVar4 = *(char **)(param_1 + 0x18);
      cVar13 = *pcVar4;
      lVar14 = lVar10;
    } while( true );
  default:
    lVar3 = FUN_0011500c(param_1);
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
      uVar8 = FUN_00111a20(param_1);
      lVar3 = FUN_00110a5c(param_1,4,lVar3,uVar8);
    }
    break;
  case 0x53:
    if (puVar12[1] == 't') {
      *(undefined **)(param_1 + 0x18) = puVar12 + 2;
      uVar8 = FUN_00110afc(param_1,&DAT_00124ad0,3);
      uVar7 = FUN_0011500c(param_1);
      lVar3 = FUN_00110a5c(param_1,1,uVar8,uVar7);
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
      lVar3 = FUN_00110d0c(param_1,0);
      if (**(char **)(param_1 + 0x18) != 'I') {
        return lVar3;
      }
    }
    uVar8 = FUN_00111a20(param_1);
    lVar3 = FUN_00110a5c(param_1,4,lVar3,uVar8);
    break;
  case 0x55:
    lVar3 = FUN_0011500c(param_1);
    return lVar3;
  case 0x5a:
    *(undefined **)(param_1 + 0x18) = puVar12 + 1;
    uVar8 = FUN_00115b3c(param_1,0);
    pcVar4 = *(char **)(param_1 + 0x18);
    if (*pcVar4 != 'E') {
      return 0;
    }
    *(char **)(param_1 + 0x18) = pcVar4 + 1;
    if (pcVar4[1] == 's') {
      *(char **)(param_1 + 0x18) = pcVar4 + 2;
      iVar1 = FUN_001117a4(param_1);
      if (iVar1 == 0) {
        return 0;
      }
      piVar6 = (int *)FUN_00110afc(param_1,"string literal",0xe);
    }
    else if (pcVar4[1] == 'd') {
      *(char **)(param_1 + 0x18) = pcVar4 + 2;
      iVar1 = FUN_00111718(param_1);
      if (iVar1 < 0) {
        return 0;
      }
      piVar11 = (int *)FUN_00115590(param_1);
      if ((((piVar11 != (int *)0x0) && (*piVar11 != 0x45)) && (*piVar11 != 0x47)) &&
         (iVar2 = FUN_001117a4(param_1), iVar2 == 0)) {
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
      piVar6 = (int *)FUN_00115590(param_1);
      if (((piVar6 != (int *)0x0) && (*piVar6 != 0x45)) &&
         ((*piVar6 != 0x47 && (iVar1 = FUN_001117a4(param_1), iVar1 == 0)))) {
        return 0;
      }
    }
    lVar3 = FUN_00110a5c(param_1,2,uVar8,piVar6);
    return lVar3;
  }
  return lVar3;
}



uint * FUN_00115b3c(long param_1,int param_2)

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
    puVar6 = (uint *)FUN_00115590();
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
        goto joined_r0x00115c84;
      }
    } while (((3 < uVar5) && (uVar5 - 0x1c < 5)) &&
            (ppuVar1 = (uint **)(puVar12 + 2), puVar12 = *ppuVar1, *ppuVar1 != (uint *)0x0));
LAB_00115bd8:
    if (cVar2 == 'J') goto LAB_00116128;
    lVar11 = 0;
    goto LAB_00115cc8;
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
      lVar11 = FUN_00113660(param_1);
      lVar7 = FUN_00111110(param_1 + 0x18);
      if (lVar7 < 0) {
        return (uint *)0x0;
      }
      if (**(char **)(param_1 + 0x18) != '_') {
        return (uint *)0x0;
      }
      *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
      puVar6 = (uint *)FUN_00113660(param_1);
      uVar9 = 0xb;
      *(int *)(param_1 + 0x50) = *(int *)(param_1 + 0x50) + 5;
      break;
    default:
      return (uint *)0x0;
    case 'F':
      puVar6 = (uint *)FUN_00113660(param_1);
      uVar9 = 0xe;
      lVar11 = 0;
      break;
    case 'H':
      puVar6 = (uint *)FUN_00115590(param_1);
      uVar9 = 0x14;
      lVar11 = 0;
      break;
    case 'I':
      puVar6 = (uint *)FUN_00113660(param_1);
      uVar9 = 0xc;
      lVar11 = 0;
      break;
    case 'J':
      puVar6 = (uint *)FUN_00113660(param_1);
      uVar9 = 0x12;
      lVar11 = 0;
      break;
    case 'S':
      puVar6 = (uint *)FUN_00113660(param_1);
      uVar9 = 0xd;
      lVar11 = 0;
      break;
    case 'T':
      *(int *)(param_1 + 0x50) = iVar4 + 10;
      puVar6 = (uint *)FUN_00113660(param_1);
      uVar9 = 10;
      lVar11 = 0;
      break;
    case 'V':
      *(int *)(param_1 + 0x50) = iVar4 + 0xf;
      puVar6 = (uint *)FUN_00113660(param_1);
      uVar9 = 9;
      lVar11 = 0;
      break;
    case 'W':
      puVar6 = (uint *)FUN_00115590(param_1);
      uVar9 = 0x15;
      lVar11 = 0;
      break;
    case 'c':
      iVar4 = FUN_00111934(param_1,0);
      if (iVar4 == 0) {
        return (uint *)0x0;
      }
      iVar4 = FUN_00111934(param_1,0);
      if (iVar4 == 0) {
        return (uint *)0x0;
      }
      puVar6 = (uint *)FUN_00115b3c(param_1,0);
      uVar9 = 0x11;
      lVar11 = 0;
      break;
    case 'h':
      iVar4 = FUN_00111934(param_1,0x68);
      if (iVar4 == 0) {
        return (uint *)0x0;
      }
      puVar6 = (uint *)FUN_00115b3c(param_1,0);
      uVar9 = 0xf;
      lVar11 = 0;
      break;
    case 'v':
      iVar4 = FUN_00111934(param_1,0x76);
      if (iVar4 == 0) {
        return (uint *)0x0;
      }
      puVar6 = (uint *)FUN_00115b3c(param_1,0);
      uVar9 = 0x10;
      lVar11 = 0;
    }
    goto LAB_00115cfc;
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
    puVar6 = (uint *)FUN_00115b3c(param_1,0);
    uVar9 = 0x17;
    lVar11 = 0;
    break;
  default:
    return (uint *)0x0;
  case 'R':
    puVar6 = (uint *)FUN_00115590(param_1);
    iVar4 = *(int *)(param_1 + 0x28);
    if (iVar4 < *(int *)(param_1 + 0x2c)) {
      *(int *)(param_1 + 0x28) = iVar4 + 1;
      lVar11 = *(long *)(param_1 + 0x20) + (long)iVar4 * 0x18;
      if (lVar11 == 0) goto LAB_001161e4;
      *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar4 * 0x18) = 0x41;
      uVar9 = FUN_00111110(param_1 + 0x18);
      *(undefined8 *)(lVar11 + 8) = uVar9;
    }
    else {
LAB_001161e4:
      lVar11 = 0;
    }
    uVar9 = 0x16;
    break;
  case 'T':
    if ((pcVar10[2] == '\0') || (*(char **)(param_1 + 0x18) = pcVar10 + 3, pcVar10[2] != 'n')) {
      puVar6 = (uint *)FUN_00115b3c(param_1,0);
      uVar9 = 0x48;
      lVar11 = 0;
    }
    else {
      puVar6 = (uint *)FUN_00115b3c(param_1,0);
      uVar9 = 0x49;
      lVar11 = 0;
    }
    break;
  case 'V':
    puVar6 = (uint *)FUN_00115590(param_1);
    uVar9 = 0x13;
    lVar11 = 0;
    break;
  case 'r':
    lVar11 = FUN_00111110(param_1 + 0x18);
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
LAB_001161ec:
          *(long *)(param_1 + 0x18) = *(long *)(param_1 + 0x18) + 2;
          return (uint *)0x0;
        }
        *(int *)(param_1 + 0x28) = iVar4 + 1;
        puVar6 = (uint *)(*(long *)(param_1 + 0x20) + (long)iVar4 * 0x18);
        if (puVar6 == (uint *)0x0) goto LAB_001161ec;
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
        puVar6 = (uint *)FUN_00110afc(param_1,pcVar14,uVar13 & 0xffffffff);
        pcVar14 = (char *)(*(long *)(param_1 + 0x18) + uVar13);
        *(char **)(param_1 + 0x18) = pcVar14;
        if (puVar6 == (uint *)0x0) {
          return (uint *)0x0;
        }
      }
      lVar11 = lVar11 + lVar7;
      if ((puVar12 != (uint *)0x0) &&
         (puVar6 = (uint *)FUN_00110a5c(param_1,0x3f,puVar12), puVar6 == (uint *)0x0)) {
        return (uint *)0x0;
      }
      puVar12 = puVar6;
    } while (0 < lVar11);
    uVar9 = 0x3e;
    lVar11 = 0;
  }
  goto LAB_00115cfc;
joined_r0x00115c84:
  if (puVar12 == (uint *)0x0) goto LAB_00115cb0;
  uVar5 = *puVar12;
  if (8 < uVar5) {
    if (uVar5 == 0x34) goto LAB_00115bd8;
    goto LAB_00115cb0;
  }
  if (6 < uVar5) goto LAB_00115bd8;
  if (1 < uVar5 - 1) goto LAB_00115cb0;
  puVar12 = *(uint **)(puVar12 + 4);
  goto joined_r0x00115c84;
LAB_00115cb0:
  if (cVar2 == 'J') {
LAB_00116128:
    *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
  }
  lVar11 = FUN_00113660(param_1);
  if (lVar11 == 0) {
LAB_001161dc:
    lVar11 = 0;
  }
  else {
LAB_00115cc8:
    lVar7 = FUN_00114d08(param_1);
    if (lVar7 == 0) goto LAB_001161dc;
    lVar11 = FUN_00110a5c(param_1,0x29,lVar11,lVar7);
  }
  uVar9 = 3;
LAB_00115cfc:
  puVar6 = (uint *)FUN_00110a5c(param_1,uVar9,puVar6,lVar11);
  return puVar6;
}



undefined8 FUN_00116200(long param_1)

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
    if (cVar1 == '_') goto LAB_00116328;
  }
  else {
    if (cVar1 != '_') {
      piVar2 = (int *)FUN_00113660();
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
      uVar3 = FUN_00110afc(param_1,pcVar7,iVar6);
      uVar8 = FUN_00110a5c(param_1,uVar8,piVar2,uVar3);
      pcVar5 = *(char **)(param_1 + 0x18);
      cVar4 = *pcVar5;
      goto LAB_001162d8;
    }
LAB_00116328:
    pcVar5 = pcVar7 + 2;
    *(char **)(param_1 + 0x18) = pcVar5;
    cVar4 = pcVar7[2];
  }
  uVar8 = 0;
  if (cVar4 == 'Z') {
    *(char **)(param_1 + 0x18) = pcVar5 + 1;
    uVar8 = FUN_00115b3c(param_1,0);
    pcVar5 = *(char **)(param_1 + 0x18);
    cVar4 = *pcVar5;
  }
LAB_001162d8:
  if (cVar4 != 'E') {
    return 0;
  }
  *(char **)(param_1 + 0x18) = pcVar5 + 1;
  return uVar8;
}



int * FUN_00116378(long param_1)

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
    piVar3 = (int *)FUN_00116200();
    return piVar3;
  }
  if (cVar1 == 'T') {
    piVar3 = (int *)FUN_00111848();
    return piVar3;
  }
  if (cVar1 == 's') {
    if (pcVar7[1] == 'r') {
      *(char **)(param_1 + 0x18) = pcVar7 + 2;
      piVar3 = (int *)FUN_00113660();
      uVar4 = FUN_0011500c(param_1);
      if (**(char **)(param_1 + 0x18) == 'I') {
        uVar6 = FUN_00111a20(param_1);
        uVar4 = FUN_00110a5c(param_1,4,uVar4,uVar6);
      }
      uVar6 = 1;
      goto LAB_00116468;
    }
    if (pcVar7[1] == 'p') {
      *(char **)(param_1 + 0x18) = pcVar7 + 2;
      piVar3 = (int *)FUN_00116378();
      uVar6 = 0x4a;
      uVar4 = 0;
      goto LAB_001165a4;
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
        iVar2 = FUN_00111718();
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
LAB_001163c4:
      piVar3 = (int *)FUN_0011500c(param_1);
      if (piVar3 == (int *)0x0) {
        return (int *)0x0;
      }
      if (**(char **)(param_1 + 0x18) != 'I') {
        return piVar3;
      }
      uVar4 = FUN_00111a20(param_1);
      uVar6 = 4;
      goto LAB_001165a4;
    }
    if (cVar1 == 'o') {
      if (pcVar7[1] == 'n') {
        *(char **)(param_1 + 0x18) = pcVar7 + 2;
        goto LAB_001163c4;
      }
    }
    else if (((cVar1 == 't') || (cVar1 == 'i')) && (pcVar7[1] == 'l')) {
      piVar3 = (int *)0x0;
      if (cVar1 == 't') {
        piVar3 = (int *)FUN_00113660(param_1);
        pcVar7 = *(char **)(param_1 + 0x18);
      }
      *(char **)(param_1 + 0x18) = pcVar7 + 2;
      uVar4 = FUN_00112f0c(param_1,0x45);
      uVar6 = 0x30;
      goto LAB_001165a4;
    }
  }
  piVar3 = (int *)FUN_00114e18(param_1);
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
        goto switchD_0011660c_caseD_0;
      case 1:
        goto switchD_00116690_caseD_1;
      case 2:
        goto switchD_00116690_caseD_2;
      case 3:
        goto switchD_00116690_caseD_3;
      default:
        goto switchD_0011660c_caseD_4;
      }
    }
    uVar4 = FUN_00113660(param_1);
  }
  else {
    if (iVar2 == 0x32) {
      switch(piVar3[2]) {
      case 0:
switchD_0011660c_caseD_0:
        uVar6 = 0x35;
        uVar4 = 0;
LAB_001165a4:
        piVar3 = (int *)FUN_00110a5c(param_1,uVar6,piVar3,uVar4);
        return piVar3;
      case 1:
        goto switchD_0011660c_caseD_1;
      case 2:
        pcVar7 = (char *)0x0;
switchD_00116690_caseD_2:
        if (((**(char ***)(piVar3 + 2))[1] == 'c') &&
           ((cVar1 = ***(char ***)(piVar3 + 2), (byte)(cVar1 + 0x8eU) < 2 ||
            ((byte)(cVar1 + 0x9dU) < 2)))) {
          uVar4 = FUN_00113660(param_1);
        }
        else {
          uVar4 = FUN_00116378(param_1);
        }
        iVar2 = strcmp(pcVar7,"cl");
        if (iVar2 == 0) {
          uVar6 = FUN_00112f0c(param_1,0x45);
        }
        else {
          iVar2 = strcmp(pcVar7,"dt");
          if ((iVar2 == 0) || (iVar2 = strcmp(pcVar7,"pt"), iVar2 == 0)) {
            uVar6 = FUN_0011500c(param_1);
            if (**(char **)(param_1 + 0x18) == 'I') {
              uVar5 = FUN_00111a20(param_1);
              uVar6 = FUN_00110a5c(param_1,4,uVar6,uVar5);
            }
          }
          else {
            uVar6 = FUN_00116378(param_1);
          }
        }
        uVar4 = FUN_00110a5c(param_1,0x38,uVar4,uVar6);
        uVar6 = 0x37;
        goto LAB_00116468;
      case 3:
        pcVar7 = (char *)0x0;
switchD_00116690_caseD_3:
        iVar2 = strcmp(pcVar7,"qu");
        if (iVar2 == 0) {
          uVar4 = FUN_00116378(param_1);
          uVar6 = FUN_00116378(param_1);
          uVar5 = FUN_00116378(param_1);
        }
        else {
          if (*pcVar7 != 'n') {
            return (int *)0x0;
          }
          if ((pcVar7[1] != 'a') && (pcVar7[1] != 'w')) {
            return (int *)0x0;
          }
          uVar4 = FUN_00112f0c(param_1,0x5f);
          uVar6 = FUN_00113660(param_1);
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
            uVar5 = FUN_00112f0c(param_1,0x45);
          }
          else {
            if ((cVar1 != 'i') || (pcVar7[1] != 'l')) {
switchD_0011660c_caseD_4:
              return (int *)0x0;
            }
            uVar5 = FUN_00116378(param_1);
          }
        }
        uVar6 = FUN_00110a5c(param_1,0x3b,uVar6,uVar5);
        uVar4 = FUN_00110a5c(param_1,0x3a,uVar4,uVar6);
        uVar6 = 0x39;
        goto LAB_00116468;
      default:
        goto switchD_0011660c_caseD_4;
      }
    }
    if (iVar2 != 0x33) {
      return (int *)0x0;
    }
    if (**(char **)(param_1 + 0x18) == '_') {
      *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
      uVar4 = FUN_00112f0c(param_1,0x45);
      goto LAB_0011645c;
    }
switchD_0011660c_caseD_1:
    uVar4 = FUN_00116378(param_1);
  }
LAB_0011645c:
  uVar6 = 0x36;
LAB_00116468:
  piVar3 = (int *)FUN_00110a5c(param_1,uVar6,piVar3,uVar4);
  return piVar3;
switchD_00116690_caseD_1:
  cVar1 = *pcVar7;
  if (((cVar1 == 'm') || (cVar1 == 'p')) && (pcVar7[1] == cVar1)) {
    if (**(char **)(param_1 + 0x18) != '_') {
      uVar4 = FUN_00116378(param_1);
      uVar4 = FUN_00110a5c(param_1,0x38,uVar4,uVar4);
      goto LAB_0011645c;
    }
    *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
  }
  goto switchD_0011660c_caseD_1;
}



undefined8 FUN_001169e0(long param_1)

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
  lVar4 = FUN_00113660();
  if ((lVar4 == 0) || (lVar5 = FUN_00114d08(param_1), lVar5 == 0)) {
    uVar6 = 0;
  }
  else {
    uVar6 = FUN_00110a5c(param_1,0x29,lVar4,lVar5);
  }
  pcVar7 = *(char **)(param_1 + 0x18);
  cVar2 = *pcVar7;
  if (cVar2 == 'O') {
    if (cVar2 == 'R') goto LAB_00116af8;
    uVar8 = 0x20;
    iVar3 = *(int *)(param_1 + 0x50) + 3;
  }
  else {
    if (cVar2 != 'R') {
      if (cVar2 != 'E') {
        return 0;
      }
      goto LAB_00116a80;
    }
LAB_00116af8:
    uVar8 = 0x1f;
    iVar3 = *(int *)(param_1 + 0x50) + 2;
  }
  *(int *)(param_1 + 0x50) = iVar3;
  *(char **)(param_1 + 0x18) = pcVar7 + 1;
  uVar6 = FUN_00110a5c(param_1,uVar8,uVar6,0);
  pcVar7 = *(char **)(param_1 + 0x18);
  if (*pcVar7 != 'E') {
    return 0;
  }
LAB_00116a80:
  *(char **)(param_1 + 0x18) = pcVar7 + 1;
  return uVar6;
}


/*
Unable to decompile 'FUN_00116b10'
Cause: 
Low-level Error: Could not finish collapsing block structure
*/


// WARNING: Type propagation algorithm not settling

void FUN_00119244(undefined *param_1,uint param_2,long *param_3)

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
  
  if (param_3 == (long *)0x0) goto LAB_001192c0;
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
                    goto LAB_0011b940;
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
LAB_0011b940:
        pbVar34 = pbVar35 + 1;
      }
    }
    break;
  case 1:
  case 2:
    FUN_00119244(param_1,param_2,param_3[1]);
    lVar10 = *(long *)(param_1 + 0x100);
    if ((param_2 >> 2 & 1) == 0) {
      if (lVar10 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar18 = 1;
        *param_1 = 0x3a;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
LAB_00119394:
        lVar10 = lVar18 + 1;
      }
      else {
        lVar18 = lVar10 + 1;
        *(long *)(param_1 + 0x100) = lVar18;
        param_1[lVar10] = 0x3a;
        param_1[0x108] = 0x3a;
        if (lVar18 != 0xff) goto LAB_00119394;
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
      FUN_0011139c(param_1,"{default arg#");
      FUN_001115a4(param_1,(long)(piVar9[4] + 1));
      FUN_0011139c(param_1,&DAT_00124ae8);
      piVar9 = *(int **)(piVar9 + 2);
    }
    FUN_00119244(param_1,param_2,piVar9);
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
            goto LAB_0011c8b0;
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
              goto LAB_0011c8b0;
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
                goto LAB_0011c8b0;
              }
            }
          }
        }
      }
      else {
        uVar39 = 1;
LAB_0011c8b0:
        uVar37 = uVar39;
        if (iVar6 == 4) {
          *(long *****)(param_1 + 0x120) = &local_90;
          local_90 = ppplVar26;
          local_88 = plVar21;
LAB_0011c9d0:
          FUN_00119244(param_1,param_2,param_3[2]);
          if (*(int *)plVar21 == 4) {
            *(long ****)(param_1 + 0x120) = local_90;
          }
          iVar6 = (int)uVar37;
          uVar36 = iVar6 - 1;
          if (*(int *)(&local_70 + (ulong)uVar36 * 4) == 0) {
            FUN_00111098(param_1,0x20);
            FUN_0011cc50(param_1,param_2,(&local_78)[(ulong)uVar36 * 4]);
          }
          if (uVar36 != 0) {
            uVar36 = iVar6 - 2;
            if (*(int *)(&local_70 + (ulong)uVar36 * 4) == 0) {
              FUN_00111098(param_1,0x20);
              FUN_0011cc50(param_1,param_2,(&local_78)[(ulong)uVar36 * 4]);
            }
            if (uVar36 != 0) {
              uVar36 = iVar6 - 3;
              if (*(int *)(&local_70 + (ulong)uVar36 * 4) == 0) {
                FUN_00111098(param_1,0x20);
                FUN_0011cc50(param_1,param_2,(&local_78)[(ulong)uVar36 * 4]);
              }
              if ((uVar36 != 0) && ((int)local_70 == 0)) {
                FUN_00111098(param_1,0x20);
                FUN_0011cc50(param_1,param_2,local_78);
                *(undefined8 *)(param_1 + 0x128) = uVar38;
                return;
              }
            }
          }
          *(undefined8 *)(param_1 + 0x128) = uVar38;
          return;
        }
        if (iVar6 != 2) goto LAB_0011c9d0;
        plVar25 = (long *)plVar21[2];
        if (*(int *)plVar25 == 0x46) {
          plVar25 = (long *)plVar25[1];
        }
        if (4 < *(int *)plVar25 - 0x1cU) goto LAB_0011c9d0;
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
          if (4 < *(int *)plVar25 - 0x1cU) goto LAB_0011c9d0;
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
            if (4 < *(int *)plVar25 - 0x1cU) goto LAB_0011c9d0;
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
                goto LAB_0011c9d0;
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
      FUN_00119244(param_1,param_2,piVar9);
      if (param_1[0x108] == '<') {
        FUN_00111098(param_1,0x20);
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
      FUN_00119244(param_1,param_2,param_3[2]);
      if (param_1[0x108] == '>') {
        FUN_00111098(param_1,0x20);
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
      FUN_00119244(param_1,param_2,param_3[2]);
      FUN_0011139c(param_1,&DAT_00124af8);
    }
    *(undefined8 *)(param_1 + 0x128) = uVar40;
    *(undefined8 *)(param_1 + 0x160) = uVar38;
    break;
  case 5:
    piVar9 = (int *)FUN_00111198(param_1,param_3 + 1);
    if (piVar9 != (int *)0x0) {
      if (*piVar9 != 0x2f) {
LAB_0011a45c:
        puVar32 = *(undefined8 **)(param_1 + 0x120);
        *(undefined8 *)(param_1 + 0x120) = *puVar32;
        FUN_00119244(param_1,param_2);
        *(undefined8 **)(param_1 + 0x120) = puVar32;
        return;
      }
      iVar6 = *(int *)(param_1 + 0x134);
      while (0 < iVar6) {
        piVar9 = *(int **)(piVar9 + 4);
        iVar6 = iVar6 + -1;
        if ((piVar9 == (int *)0x0) || (*piVar9 != 0x2f)) goto LAB_001192c0;
      }
      if ((iVar6 == 0) && (*(long *)(piVar9 + 2) != 0)) goto LAB_0011a45c;
    }
    goto LAB_001192c0;
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
LAB_0011b338:
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
LAB_0011b354:
          lVar7 = lVar12 + 1;
          *(long *)(param_1 + 0x100) = lVar7;
          param_1[lVar12] = 0x72;
          param_1[0x108] = 0x72;
          if (lVar7 != 0xff) goto LAB_0011b370;
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
          goto LAB_0011b354;
        }
        lVar10 = lVar10 + 2;
        *(long *)(param_1 + 0x100) = lVar10;
        param_1[lVar12] = 0x70;
        param_1[0x108] = 0x70;
        if (lVar10 != 0xff) goto LAB_0011b338;
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x61;
        lVar7 = 2;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        param_1[1] = 0x72;
LAB_0011b370:
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
          goto LAB_0011b390;
        }
      }
      lVar12 = lVar10 + 1;
LAB_0011b390:
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
LAB_00119cc0:
      lVar18 = lVar10 + 1;
      *(long *)(param_1 + 0x100) = lVar18;
      param_1[lVar10] = 0x69;
      param_1[0x108] = 0x69;
      if (lVar18 != 0xff) goto LAB_00119cdc;
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
        if (lVar10 != 0xff) goto LAB_00119cc0;
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x69;
        lVar18 = 1;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
LAB_00119cdc:
      lVar10 = lVar18 + 1;
    }
    *(long *)(param_1 + 0x100) = lVar10;
    param_1[lVar18] = 0x73;
    param_1[0x108] = 0x73;
    break;
  case 7:
    FUN_00119244(param_1,param_2,param_3[2]);
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
    FUN_00119244(param_1,param_2,param_3[2]);
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
    FUN_00119244(param_1,param_2,param_3[1]);
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
    FUN_00119244(param_1,param_2,param_3[1]);
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
    FUN_00119244(param_1,param_2,param_3[1]);
    lVar10 = *(long *)(param_1 + 0x100);
    if (lVar10 == 0xff) {
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar10 = 2;
      *param_1 = 0x2d;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 0x69;
LAB_0011b10c:
      lVar18 = lVar10 + 1;
      *(long *)(param_1 + 0x100) = lVar18;
      param_1[lVar10] = 0x6e;
      param_1[0x108] = 0x6e;
      if (lVar18 != 0xff) goto LAB_0011b128;
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
        if (lVar10 != 0xff) goto LAB_0011b10c;
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x6e;
        lVar18 = 1;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
LAB_0011b128:
      lVar10 = lVar18 + 1;
    }
    *(long *)(param_1 + 0x100) = lVar10;
    param_1[lVar18] = 0x2d;
    param_1[0x108] = 0x2d;
    FUN_00119244(param_1,param_2,param_3[2]);
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
    FUN_00119244(param_1,param_2,param_3[1]);
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
    FUN_00119244(param_1,param_2,param_3[1]);
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
    FUN_00119244(param_1,param_2,param_3[1]);
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
    FUN_00119244(param_1,param_2,param_3[1]);
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
    FUN_00119244(param_1,param_2,param_3[1]);
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
    FUN_00119244(param_1,param_2,param_3[1]);
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
    FUN_00119244(param_1,param_2,param_3[1]);
    break;
  case 0x13:
    FUN_0011139c(param_1,"guard variable for ");
    FUN_00119244(param_1,param_2,param_3[1]);
    break;
  case 0x14:
    FUN_0011139c(param_1,"TLS init function for ");
    FUN_00119244(param_1,param_2,param_3[1]);
    break;
  case 0x15:
    FUN_0011139c(param_1,"TLS wrapper function for ");
    FUN_00119244(param_1,param_2,param_3[1]);
    break;
  case 0x16:
    FUN_0011139c(param_1,"reference temporary #");
    FUN_00119244(param_1,param_2,param_3[2]);
    FUN_0011139c(param_1," for ");
    FUN_00119244(param_1,param_2,param_3[1]);
    break;
  case 0x17:
    FUN_0011139c(param_1,"hidden alias for ");
    FUN_00119244(param_1,param_2,param_3[1]);
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
            FUN_00119244(param_1,param_2,param_3[1]);
            return;
          }
        }
        pplVar27 = (long **)*pplVar27;
      } while (pplVar27 != (long **)0x0);
      bVar5 = false;
    }
    goto LAB_00119b40;
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
LAB_00119b40:
    local_68[0] = *(long ****)(param_1 + 0x120);
    *(long ****)(param_1 + 0x128) = &local_80;
    local_78 = param_3;
LAB_00119b5c:
    lVar10 = local_78[1];
LAB_00119b60:
    plVar21 = local_78;
    local_70._0_4_ = 0;
    FUN_00119244(param_1,param_2,lVar10);
    if ((int)local_70 == 0) {
      FUN_0011cc50(param_1,param_2,plVar21);
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
LAB_0011b608:
        if (*(int *)(param_1 + 0x14c) <= (int)uVar36) {
LAB_0011cb34:
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
                goto LAB_0011b68c;
              }
              uVar39 = uVar39 + 0x10;
              puVar14 = puVar32;
              iVar31 = iVar15 + 1;
            } while (iVar15 + 1 != iVar6 + 1);
            *(int *)(param_1 + 0x158) = iVar15;
          }
          goto LAB_0011cb34;
        }
LAB_0011b68c:
        *puVar32 = 0;
        bVar5 = false;
        plVar21 = (long *)FUN_00111198(param_1,plVar21 + 1);
        if (plVar21 == (long *)0x0) goto LAB_001192c0;
LAB_0011b84c:
        iVar6 = *(int *)plVar21;
        if (iVar6 != 0x2f) goto LAB_00119b9c;
        iVar6 = *(int *)(param_1 + 0x134);
        while (0 < iVar6) {
          plVar21 = (long *)plVar21[2];
          iVar6 = iVar6 + -1;
          if ((plVar21 == (long *)0x0) || (*(int *)plVar21 != 0x2f)) goto LAB_001192b8;
        }
        if ((iVar6 == 0) && (plVar21 = (long *)plVar21[1], plVar21 != (long *)0x0)) {
          iVar6 = *(int *)plVar21;
          goto LAB_00119b9c;
        }
LAB_001192b8:
        if (!bVar5) goto LAB_001192c0;
      }
      else {
        pplVar8 = pplVar27;
        if (plVar21 != *pplVar27) {
          do {
            pplVar8 = pplVar8 + 2;
            if (pplVar8 == pplVar27 + ((ulong)(uVar36 - 1) + 1) * 2) goto LAB_0011b608;
          } while (plVar21 != *pplVar8);
        }
        unaff_x22 = *(undefined8 *)(param_1 + 0x120);
        *(long **)(param_1 + 0x120) = pplVar8[1];
        bVar5 = true;
        plVar21 = (long *)FUN_00111198(param_1,plVar21 + 1);
        if (plVar21 != (long *)0x0) goto LAB_0011b84c;
      }
      *(undefined8 *)(param_1 + 0x120) = unaff_x22;
LAB_001192c0:
      *(undefined4 *)(param_1 + 0x130) = 1;
      return;
    }
LAB_00119b9c:
    if ((iVar6 == 0x23) || (*(int *)param_3 == iVar6)) {
      local_80 = *(long ***)(param_1 + 0x128);
      param_3 = plVar21;
      goto LAB_00119b40;
    }
    if (iVar6 != 0x24) {
      local_80 = *(long ***)(param_1 + 0x128);
      goto LAB_00119b40;
    }
    lVar10 = plVar21[1];
    local_80 = *(long ***)(param_1 + 0x128);
    local_68[0] = *(long ****)(param_1 + 0x120);
    *(long ****)(param_1 + 0x128) = &local_80;
    local_78 = param_3;
    if (lVar10 == 0) goto LAB_00119b5c;
    goto LAB_00119b60;
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
    FUN_00119244(param_1,param_2,param_3[1]);
    break;
  case 0x29:
    if ((param_2 >> 5 & 1) == 0) {
      if ((param_3[1] != 0) && ((param_2 >> 6 & 1) == 0)) {
        local_80 = *(long ***)(param_1 + 0x128);
        *(long ****)(param_1 + 0x128) = &local_80;
        local_68[0] = *(long ****)(param_1 + 0x120);
        local_70._0_4_ = 0;
        local_78 = param_3;
        FUN_00119244(param_1,param_2 & 0xffffff9f,param_3[1]);
        *(long ***)(param_1 + 0x128) = local_80;
        if ((int)local_70 != 0) {
          return;
        }
        FUN_00111098(param_1,0x20);
      }
      FUN_0011daac(param_1,param_2 & 0xffffff9f,param_3 + 2,*(undefined8 *)(param_1 + 0x128));
    }
    else {
      FUN_0011daac(param_1,param_2 & 0xffffff9f,param_3 + 2,*(undefined8 *)(param_1 + 0x128));
      if (param_3[1] != 0) {
        FUN_00119244(param_1,param_2 & 0xffffff9f);
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
      FUN_00119244(param_1,param_2,param_3[2]);
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
      FUN_00119244(param_1,param_2,param_3[2]);
      *(long ***)(param_1 + 0x128) = pplVar27;
      if ((int)local_70 != 0) {
        return;
      }
      if ((int)uVar37 != 1) {
        do {
          uVar36 = (int)uVar37 - 1;
          uVar37 = (ulong)uVar36;
          FUN_0011cc50(param_1,param_2,(&local_78)[uVar37 * 4]);
        } while (uVar36 != 1);
        pplVar27 = *(long ***)(param_1 + 0x128);
      }
    }
    FUN_0011d7e4(param_1,param_2,param_3 + 1,pplVar27);
    break;
  case 0x2b:
  case 0x2d:
    local_80 = *(long ***)(param_1 + 0x128);
    *(long ****)(param_1 + 0x128) = &local_80;
    local_68[0] = *(long ****)(param_1 + 0x120);
    local_70._0_4_ = 0;
    local_78 = param_3;
    FUN_00119244(param_1,param_2,param_3[2]);
    if ((int)local_70 == 0) {
      FUN_0011cc50(param_1,param_2,param_3);
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
LAB_0011b544:
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
          goto LAB_0011b57c;
        }
LAB_0011b560:
        lVar10 = lVar18 + 1;
        *(long *)(param_1 + 0x100) = lVar10;
        param_1[lVar18] = 0x74;
        param_1[0x108] = 0x74;
        if (lVar10 != 0xff) goto LAB_0011b57c;
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
          goto LAB_0011b560;
        }
        lVar10 = lVar10 + 2;
        *(long *)(param_1 + 0x100) = lVar10;
        param_1[lVar18] = 0x53;
        param_1[0x108] = 0x53;
        if (lVar10 != 0xff) goto LAB_0011b544;
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x61;
        lVar10 = 2;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        param_1[1] = 0x74;
LAB_0011b57c:
        lVar18 = lVar10 + 1;
      }
      *(long *)(param_1 + 0x100) = lVar18;
      param_1[lVar10] = 0x20;
      param_1[0x108] = 0x20;
    }
    if (*(undefined **)(param_3[1] + 8) == &UNK_0013a940) {
      lVar10 = *(long *)(param_1 + 0x100);
    }
    else {
      FUN_00119244(param_1,param_2);
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
LAB_0011b260:
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
LAB_0011b27c:
          lVar12 = lVar18 + 1;
          *(long *)(param_1 + 0x100) = lVar12;
          param_1[lVar18] = 0x61;
          param_1[0x108] = 0x61;
          if (lVar12 != 0xff) goto LAB_0011b298;
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
          goto LAB_0011b27c;
        }
        lVar10 = lVar10 + 2;
        *(long *)(param_1 + 0x100) = lVar10;
        param_1[lVar18] = 0x46;
        param_1[0x108] = 0x46;
        if (lVar10 != 0xff) goto LAB_0011b260;
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x72;
        lVar12 = 2;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        param_1[1] = 0x61;
LAB_0011b298:
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
          goto LAB_0011b2b8;
        }
      }
      lVar18 = lVar10 + 1;
LAB_0011b2b8:
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
LAB_0011a7d4:
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
LAB_0011a7f0:
        lVar12 = lVar18 + 1;
        *(long *)(param_1 + 0x100) = lVar12;
        param_1[lVar18] = 99;
        param_1[0x108] = 99;
        if (lVar12 != 0xff) goto LAB_0011a80c;
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x75;
        lVar10 = 1;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
LAB_0011a828:
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
        goto LAB_0011a7f0;
      }
      lVar10 = lVar10 + 2;
      *(long *)(param_1 + 0x100) = lVar10;
      param_1[lVar18] = 0x41;
      param_1[0x108] = 0x41;
      if (lVar10 != 0xff) goto LAB_0011a7d4;
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      *param_1 = 99;
      lVar12 = 2;
      param_1[1] = 99;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
LAB_0011a80c:
      lVar10 = lVar12 + 1;
      *(long *)(param_1 + 0x100) = lVar10;
      param_1[lVar12] = 0x75;
      param_1[0x108] = 0x75;
      if (lVar10 != 0xff) goto LAB_0011a828;
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
      FUN_00119244(param_1,param_2);
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
      FUN_00119244(param_1,param_2,param_3[2]);
      if ((*(long *)(param_1 + 0x138) == lVar10) && (*(long *)(param_1 + 0x100) == uVar39 + 2)) {
        *(ulong *)(param_1 + 0x100) = uVar39;
      }
    }
    break;
  case 0x30:
    lVar10 = param_3[2];
    if (param_3[1] != 0) {
      FUN_00119244(param_1,param_2);
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
    FUN_00119244(param_1,param_2,lVar10);
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
    FUN_00119244(param_1,param_2,param_3[2]);
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
      FUN_00119244(param_1,param_2,*(undefined8 *)((int *)param_3[1] + 2));
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
      FUN_00119244(param_1,param_2,*(undefined8 *)(param_3[1] + 0x10));
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
      FUN_00119244(param_1,param_2);
      if (*(long *)(param_1 + 0x160) != 0) {
        *(long ***)(param_1 + 0x120) = local_80;
      }
    }
    break;
  case 0x35:
    FUN_0011dd5c(param_1,param_2,param_3[1]);
    break;
  case 0x36:
    piVar23 = (int *)param_3[1];
    piVar9 = (int *)param_3[2];
    if (*piVar23 == 0x31) {
      pcVar11 = **(char ***)(piVar23 + 2);
      iVar6 = strcmp(pcVar11,"ad");
      if (iVar6 == 0) {
        iVar6 = *piVar9;
        if (iVar6 != 3) goto LAB_0011b6d4;
        if ((**(int **)(piVar9 + 2) == 1) && (**(int **)(piVar9 + 4) == 0x29)) {
          piVar9 = *(int **)(piVar9 + 2);
        }
      }
      else {
        iVar6 = *piVar9;
LAB_0011b6d4:
        if (iVar6 == 0x38) {
          FUN_0011de30(param_1,param_2,*(undefined8 *)(piVar9 + 2));
          FUN_0011dd5c(param_1,param_2,piVar23);
          return;
        }
      }
      FUN_0011dd5c(param_1,param_2,piVar23);
      iVar6 = strcmp(pcVar11,"gs");
      if (iVar6 == 0) {
        FUN_00119244(param_1,param_2,piVar9);
        return;
      }
      iVar6 = strcmp(pcVar11,"st");
      if (iVar6 == 0) {
        FUN_00111098(param_1,0x28);
        FUN_00119244(param_1,param_2,piVar9);
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
      FUN_00119244(param_1,param_2,*(undefined8 *)(piVar23 + 2));
      FUN_00111098(param_1,0x29);
    }
    else {
      FUN_0011dd5c(param_1,param_2,piVar23);
    }
    FUN_0011de30(param_1,param_2,piVar9);
    break;
  case 0x37:
    piVar9 = (int *)param_3[2];
    if (*piVar9 != 0x38) goto LAB_001192c0;
    ppcVar24 = *(char ***)((int *)param_3[1] + 2);
    pcVar11 = *ppcVar24;
    if ((pcVar11[1] == 'c') && (((byte)(*pcVar11 + 0x8eU) < 2 || ((byte)(*pcVar11 + 0x9dU) < 2)))) {
      FUN_0011dd5c(param_1,param_2);
      FUN_00111098(param_1,0x3c);
      FUN_00119244(param_1,param_2,*(undefined8 *)(param_3[2] + 8));
      FUN_0011139c(param_1,&DAT_00124d90);
      FUN_00119244(param_1,param_2,*(undefined8 *)(param_3[2] + 0x10));
      FUN_00111098(param_1,0x29);
    }
    else {
      if ((*(int *)param_3[1] == 0x31) && ((*(int *)(ppcVar24 + 2) == 1 && (*ppcVar24[1] == '>'))))
      {
        FUN_00111098(param_1,0x28);
        piVar9 = (int *)param_3[2];
        pcVar11 = **(char ***)(param_3[1] + 8);
      }
      iVar6 = strcmp(pcVar11,"cl");
      piVar9 = *(int **)(piVar9 + 2);
      if ((iVar6 == 0) && (*piVar9 == 3)) {
        if (**(int **)(piVar9 + 4) != 0x29) {
          *(undefined4 *)(param_1 + 0x130) = 1;
        }
        FUN_0011de30(param_1,param_2,*(undefined8 *)(piVar9 + 2));
      }
      else {
        FUN_0011de30(param_1,param_2);
      }
      lVar10 = param_3[1];
      pcVar11 = **(char ***)(lVar10 + 8);
      iVar6 = strcmp(pcVar11,"ix");
      if (iVar6 == 0) {
        FUN_00111098(param_1,0x5b);
        FUN_00119244(param_1,param_2,*(undefined8 *)(param_3[2] + 0x10));
        FUN_00111098(param_1,0x5d);
      }
      else {
        iVar6 = strcmp(pcVar11,"cl");
        if (iVar6 != 0) {
          FUN_0011dd5c(param_1,param_2,lVar10);
        }
        FUN_0011de30(param_1,param_2,*(undefined8 *)(param_3[2] + 0x10));
      }
      if (((*(int *)param_3[1] == 0x31) &&
          (lVar10 = *(long *)((int *)param_3[1] + 2), *(int *)(lVar10 + 0x10) == 1)) &&
         (**(char **)(lVar10 + 8) == '>')) {
        FUN_00111098(param_1,0x29);
      }
    }
    break;
  case 0x38:
    *(undefined4 *)(param_1 + 0x130) = 1;
    break;
  case 0x39:
    piVar9 = (int *)param_3[2];
    if ((*piVar9 != 0x3a) || (piVar23 = *(int **)(piVar9 + 4), *piVar23 != 0x3b)) goto LAB_001192c0;
    lVar12 = param_3[1];
    lVar10 = *(long *)(piVar9 + 2);
    uVar38 = *(undefined8 *)(piVar23 + 2);
    lVar18 = *(long *)(piVar23 + 4);
    iVar6 = strcmp(**(char ***)(lVar12 + 8),"qu");
    if (iVar6 == 0) {
      FUN_0011de30(param_1,param_2);
      FUN_0011dd5c(param_1,param_2,lVar12);
      FUN_0011de30(param_1,param_2,uVar38);
      FUN_0011139c(param_1,&DAT_00124cc8);
      FUN_0011de30(param_1,param_2,lVar18);
    }
    else {
      FUN_0011139c(param_1,&DAT_00124cd0);
      if (*(long *)(lVar10 + 8) != 0) {
        FUN_0011de30(param_1,param_2);
        FUN_00111098(param_1,0x20);
      }
      FUN_00119244(param_1,param_2,uVar38);
      if (lVar18 != 0) {
        FUN_0011de30(param_1,param_2,lVar18);
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
            FUN_00111098(param_1,0x2d);
          }
          FUN_00119244(param_1,param_2,param_3[2]);
          switch(uVar36) {
          case 2:
            FUN_00111098(param_1,0x75);
            return;
          case 3:
            FUN_00111098(param_1,0x6c);
            return;
          case 4:
            FUN_0011139c(param_1,&DAT_00124cd8);
            return;
          case 5:
            FUN_0011139c(param_1,"ll");
            return;
          case 6:
            FUN_0011139c(param_1,&DAT_00124ce0);
            return;
          default:
            return;
          }
        }
      }
      else if ((((uVar36 == 7) && (piVar9 = (int *)param_3[2], *piVar9 == 0)) && (piVar9[4] == 1))
              && (iVar6 == 0x3c)) {
        if (**(char **)(piVar9 + 2) == '0') {
          FUN_0011139c(param_1,"false");
          return;
        }
        if (**(char **)(piVar9 + 2) == '1') {
          FUN_0011139c(param_1,&DAT_00124cf0);
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
    FUN_00119244(param_1,param_2,param_3[1]);
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
      FUN_00111098(param_1,0x2d);
    }
    if (uVar36 == 8) {
      FUN_00111098(param_1,0x5b);
      FUN_00119244(param_1,param_2,param_3[2]);
      FUN_00111098(param_1,0x5d);
    }
    else {
      FUN_00119244(param_1,param_2,param_3[2]);
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
    FUN_00119244(param_1,param_2,param_3[1]);
    break;
  case 0x3f:
    FUN_00119244(param_1,param_2,param_3[1]);
    FUN_00119244(param_1,param_2,param_3[2]);
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
    FUN_00119244(param_1,param_2,param_3[1]);
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
    FUN_00119244(param_1,param_2,param_3[1]);
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
    FUN_00119244(param_1,param_2,param_3[1]);
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
    FUN_00119244(param_1,param_2,param_3[1]);
    lVar10 = *(long *)(param_1 + 0x100);
    if (lVar10 == 0xff) {
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar18 = 1;
      *param_1 = 0x29;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
LAB_0011afac:
      lVar10 = lVar18 + 1;
    }
    else {
      lVar18 = lVar10 + 1;
      *(long *)(param_1 + 0x100) = lVar18;
      param_1[lVar10] = 0x29;
      param_1[0x108] = 0x29;
      if (lVar18 != 0xff) goto LAB_0011afac;
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
    FUN_00119244(param_1,param_2,param_3[1]);
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
    FUN_00119244(param_1,param_2,param_3[1]);
    break;
  case 0x4a:
    iVar6 = 0;
    piVar9 = (int *)FUN_00111214(param_1,param_3[1]);
    if (piVar9 == (int *)0x0) {
      FUN_0011de30(param_1,param_2,param_3[1]);
      FUN_0011139c(param_1,&DAT_00124d18);
    }
    else {
      do {
        if ((*piVar9 != 0x2f) || (*(long *)(piVar9 + 2) == 0)) {
          lVar10 = param_3[1];
          if (iVar6 == 0) {
            return;
          }
          goto LAB_0011a254;
        }
        piVar9 = *(int **)(piVar9 + 4);
        iVar6 = iVar6 + 1;
      } while (piVar9 != (int *)0x0);
      lVar10 = param_3[1];
LAB_0011a254:
      iVar31 = 0;
      do {
        *(int *)(param_1 + 0x134) = iVar31;
        FUN_00119244(param_1,param_2,lVar10);
        if (iVar31 < iVar6 + -1) {
          lVar18 = *(long *)(param_1 + 0x100);
          if (lVar18 == 0xff) {
            param_1[0xff] = 0;
            (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
            *param_1 = 0x2c;
            lVar12 = 1;
            *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
LAB_0011a2a4:
            lVar18 = lVar12 + 1;
          }
          else {
            lVar12 = lVar18 + 1;
            *(long *)(param_1 + 0x100) = lVar12;
            param_1[lVar18] = 0x2c;
            param_1[0x108] = 0x2c;
            if (lVar12 != 0xff) goto LAB_0011a2a4;
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
    FUN_00119244(param_1,param_2,param_3[1]);
    lVar10 = *(long *)(param_1 + 0x100);
    if (lVar10 == 0xff) {
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      *param_1 = 0x5b;
      lVar10 = 2;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 0x61;
LAB_0011a31c:
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
        goto LAB_0011a354;
      }
LAB_0011a338:
      lVar10 = lVar18 + 1;
      *(long *)(param_1 + 0x100) = lVar10;
      param_1[lVar18] = 0x69;
      param_1[0x108] = 0x69;
      if (lVar10 != 0xff) goto LAB_0011a354;
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
        goto LAB_0011a338;
      }
      lVar10 = lVar10 + 2;
      *(long *)(param_1 + 0x100) = lVar10;
      param_1[lVar18] = 0x61;
      param_1[0x108] = 0x61;
      if (lVar10 != 0xff) goto LAB_0011a31c;
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      *param_1 = 0x62;
      lVar10 = 2;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 0x69;
LAB_0011a354:
      lVar18 = lVar10 + 1;
    }
    *(long *)(param_1 + 0x100) = lVar18;
    param_1[lVar10] = 0x3a;
    param_1[0x108] = 0x3a;
    FUN_00119244(param_1,param_2,param_3[2]);
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
    FUN_00119244(param_1,param_2,param_3[1]);
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
    FUN_00119244(param_1,param_2,param_3[2]);
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



void FUN_0011cc50(undefined *param_1,uint param_2,undefined4 *param_3)

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
LAB_0011cc8c:
    FUN_00119244(param_1,param_2,param_3);
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
LAB_0011ce58:
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
LAB_0011ce74:
        lVar2 = lVar3 + 1;
        *(long *)(param_1 + 0x100) = lVar2;
        param_1[lVar3] = 0x6e;
        param_1[0x108] = 0x6e;
        if (lVar2 != 0xff) goto LAB_0011ce90;
        uVar5 = 0x74;
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x73;
        lVar3 = 1;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
      goto LAB_0011cf74;
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
      goto LAB_0011ce74;
    }
    lVar2 = lVar2 + 2;
    *(long *)(param_1 + 0x100) = lVar2;
    param_1[lVar3] = 99;
    param_1[0x108] = 99;
    if (lVar2 != 0xff) goto LAB_0011ce58;
    param_1[0xff] = 0;
    (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
    *param_1 = 0x6f;
    lVar2 = 2;
    *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    param_1[1] = 0x6e;
LAB_0011ce90:
    lVar3 = lVar2 + 1;
    *(long *)(param_1 + 0x100) = lVar3;
    param_1[lVar2] = 0x73;
    param_1[0x108] = 0x73;
    uVar5 = 0x74;
    if (lVar3 != 0xff) goto LAB_0011cf74;
    goto LAB_0011ceac;
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
    goto LAB_0011cefc;
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
    goto LAB_0011cf4c;
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
    goto LAB_0011cc8c;
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
LAB_0011cefc:
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
LAB_0011cf4c:
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
LAB_0011ceac:
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,lVar3,*(undefined8 *)(param_1 + 0x118));
        lVar2 = 1;
        lVar3 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        goto LAB_0011cf78;
      }
    }
LAB_0011cf74:
    lVar2 = lVar3 + 1;
LAB_0011cf78:
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
    FUN_00119244(param_1,param_2,*(undefined8 *)(param_3 + 2));
    lVar2 = *(long *)(param_1 + 0x100);
    if (lVar2 == 0xff) {
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar2 = 2;
      *param_1 = 0x3a;
      param_1[1] = 0x3a;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
LAB_0011d160:
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
        goto LAB_0011d160;
      }
      lVar2 = lVar2 + 2;
      *(long *)(param_1 + 0x100) = lVar2;
      param_1[lVar3] = 0x3a;
      param_1[0x108] = 0x3a;
      if (lVar2 != 0xff) goto LAB_0011d160;
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
    FUN_00119244(param_1,param_2,*(undefined8 *)(param_3 + 2));
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



void FUN_0011d4d0(undefined *param_1,uint param_2,undefined8 *param_3,int param_4)

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
            FUN_0011daac(param_1,param_2,piVar5 + 4,*param_3);
            *(undefined8 *)(param_1 + 0x120) = uVar8;
            return;
          }
          if (iVar2 == 0x2a) {
            FUN_0011d7e4(param_1,param_2,piVar5 + 2,*param_3);
            *(undefined8 *)(param_1 + 0x120) = uVar8;
            return;
          }
          if (iVar2 == 2) {
            uVar6 = *(undefined8 *)(param_1 + 0x128);
            *(undefined8 *)(param_1 + 0x128) = 0;
            FUN_00119244(param_1,param_2,*(undefined8 *)(piVar5 + 2));
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
              goto LAB_0011d664;
            }
            if (lVar3 == 0xff) {
              param_1[0xff] = 0;
              (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
              lVar4 = 1;
              *param_1 = 0x3a;
              *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
LAB_0011d638:
              lVar3 = lVar4 + 1;
            }
            else {
              lVar4 = lVar3 + 1;
              *(long *)(param_1 + 0x100) = lVar4;
              param_1[lVar3] = 0x3a;
              param_1[0x108] = 0x3a;
              if (lVar4 != 0xff) goto LAB_0011d638;
              param_1[0xff] = 0;
              (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
              lVar3 = 1;
              lVar4 = 0;
              *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
            }
            *(long *)(param_1 + 0x100) = lVar3;
            param_1[lVar4] = 0x3a;
            param_1[0x108] = 0x3a;
LAB_0011d664:
            piVar5 = *(int **)(param_3[1] + 0x10);
            iVar2 = *piVar5;
            if (iVar2 != 0x46) goto LAB_0011d684;
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
            FUN_001115a4(param_1,(long)(piVar5[4] + 1));
            FUN_0011139c(param_1,&DAT_00124ae8);
            do {
              piVar5 = *(int **)(piVar5 + 2);
              iVar2 = *piVar5;
LAB_0011d684:
            } while (iVar2 - 0x1cU < 5);
            FUN_00119244(param_1,param_2,piVar5);
            *(undefined8 *)(param_1 + 0x120) = uVar8;
            return;
          }
          FUN_0011cc50(param_1,param_2);
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



void FUN_0011d7e4(undefined *param_1,undefined4 param_2,long *param_3,long *param_4)

{
  long *plVar1;
  long lVar2;
  long lVar3;
  
  plVar1 = param_4;
  if (param_4 != (long *)0x0) {
    do {
      if (*(int *)(plVar1 + 2) == 0) {
        if (*(int *)plVar1[1] == 0x2a) {
          FUN_0011d4d0(param_1,param_2,param_4,0);
          lVar3 = *(long *)(param_1 + 0x100);
          goto joined_r0x0011d94c;
        }
        lVar3 = *(long *)(param_1 + 0x100);
        if (lVar3 == 0xff) {
          param_1[0xff] = 0;
          (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
          lVar2 = 1;
          *param_1 = 0x20;
          *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
LAB_0011d8e8:
          lVar3 = lVar2 + 1;
        }
        else {
          lVar2 = lVar3 + 1;
          *(long *)(param_1 + 0x100) = lVar2;
          param_1[lVar3] = 0x20;
          param_1[0x108] = 0x20;
          if (lVar2 != 0xff) goto LAB_0011d8e8;
          param_1[0xff] = 0;
          (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
          lVar3 = 1;
          lVar2 = 0;
          *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        }
        *(long *)(param_1 + 0x100) = lVar3;
        param_1[lVar2] = 0x28;
        param_1[0x108] = 0x28;
        FUN_0011d4d0(param_1,param_2,param_4,0);
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
        goto LAB_0011d830;
      }
      plVar1 = (long *)*plVar1;
    } while (plVar1 != (long *)0x0);
    FUN_0011d4d0(param_1,param_2,param_4,0);
  }
  lVar2 = *(long *)(param_1 + 0x100);
LAB_0011d830:
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
joined_r0x0011d94c:
  if (lVar3 == 0xff) {
    param_1[0xff] = 0;
    (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
    *param_1 = 0x5b;
    param_1[0x108] = 0x5b;
    lVar2 = 1;
    lVar3 = *param_3;
    *(undefined8 *)(param_1 + 0x100) = 1;
    *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    if (lVar3 == 0) goto LAB_0011d888;
LAB_0011d870:
    FUN_00119244(param_1,param_2);
    lVar2 = *(long *)(param_1 + 0x100);
  }
  else {
    lVar2 = lVar3 + 1;
    *(long *)(param_1 + 0x100) = lVar2;
    param_1[lVar3] = 0x5b;
    param_1[0x108] = 0x5b;
    if (*param_3 != 0) goto LAB_0011d870;
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
LAB_0011d888:
  *(long *)(param_1 + 0x100) = lVar2 + 1;
  param_1[lVar2] = 0x5d;
  param_1[0x108] = 0x5d;
  return;
}



void FUN_0011daac(undefined *param_1,undefined4 param_2,long *param_3,long *param_4)

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
joined_r0x0011dad8:
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
LAB_0011dbbc:
        if (bVar2 == 0x20) goto LAB_0011dc28;
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
        if (lVar4 != 0xff) goto LAB_0011dc34;
LAB_0011dbec:
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,lVar4,*(undefined8 *)(param_1 + 0x118));
        lVar5 = 1;
        lVar4 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        break;
      default:
        plVar3 = (long *)*plVar3;
        if (plVar3 != (long *)0x0) goto code_r0x0011db14;
        goto LAB_0011db1c;
      case 0x22:
      case 0x23:
      case 0x24:
        bVar2 = param_1[0x108];
        if ((bVar2 & 0xfd) != 0x28) goto LAB_0011dbbc;
LAB_0011dc28:
        lVar4 = *(long *)(param_1 + 0x100);
        if (lVar4 == 0xff) goto LAB_0011dbec;
LAB_0011dc34:
        lVar5 = lVar4 + 1;
      }
      *(long *)(param_1 + 0x100) = lVar5;
      param_1[lVar4] = 0x28;
      param_1[0x108] = 0x28;
      uVar6 = *(undefined8 *)(param_1 + 0x128);
      *(undefined8 *)(param_1 + 0x128) = 0;
      FUN_0011d4d0(param_1,param_2,param_4,0);
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
      goto joined_r0x0011db40;
    }
  }
LAB_0011db1c:
  uVar6 = *(undefined8 *)(param_1 + 0x128);
  *(undefined8 *)(param_1 + 0x128) = 0;
  FUN_0011d4d0(param_1,param_2,param_4,0);
  lVar5 = *(long *)(param_1 + 0x100);
joined_r0x0011db40:
  if (lVar5 == 0xff) {
    param_1[0xff] = 0;
    (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
    *param_1 = 0x28;
    param_1[0x108] = 0x28;
    lVar4 = 1;
    lVar5 = *param_3;
    *(undefined8 *)(param_1 + 0x100) = 1;
    *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    if (lVar5 != 0) goto LAB_0011db60;
  }
  else {
    lVar4 = lVar5 + 1;
    *(long *)(param_1 + 0x100) = lVar4;
    param_1[lVar5] = 0x28;
    param_1[0x108] = 0x28;
    if (*param_3 != 0) {
LAB_0011db60:
      FUN_00119244(param_1,param_2);
      lVar4 = *(long *)(param_1 + 0x100);
    }
    if (lVar4 == 0xff) {
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar5 = 1;
      lVar4 = 0;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      goto LAB_0011db7c;
    }
  }
  lVar5 = lVar4 + 1;
LAB_0011db7c:
  *(long *)(param_1 + 0x100) = lVar5;
  param_1[lVar4] = 0x29;
  param_1[0x108] = 0x29;
  FUN_0011d4d0(param_1,param_2,param_4,1);
  *(undefined8 *)(param_1 + 0x128) = uVar6;
  return;
code_r0x0011db14:
  iVar1 = *(int *)(plVar3 + 2);
  goto joined_r0x0011dad8;
}



void FUN_0011dd5c(undefined *param_1,undefined8 param_2,int *param_3)

{
  undefined uVar1;
  long lVar2;
  long lVar3;
  long lVar4;
  long lVar5;
  
  if (*param_3 != 0x31) {
    FUN_00119244();
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



void FUN_0011de30(long param_1,undefined4 param_2,uint *param_3)

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
    FUN_00119244(param_1,param_2,param_3);
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
  FUN_00119244(param_1);
  return;
}



bool FUN_0011df38(char *param_1,code *param_2,undefined8 param_3)

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
    lVar12 = FUN_00115b3c(&local_1c8,1);
    if ((local_1b8 & 1) == 0) {
LAB_0011e358:
      cVar7 = *local_1b0;
    }
    else {
      while (pcVar1 = local_1b0, cVar7 = *local_1b0, cVar7 == '.') {
        cVar7 = local_1b0[1];
        if (((byte)(cVar7 + 0x9fU) < 0x1a) || (cVar7 == '_')) {
          cVar7 = local_1b0[2];
          pcVar14 = local_1b0 + 2;
          if (0x19 < (byte)(cVar7 + 0x9fU)) goto LAB_0011e34c;
          do {
            do {
              pcVar14 = pcVar14 + 1;
              cVar7 = *pcVar14;
            } while ((byte)(cVar7 + 0x9fU) < 0x1a);
LAB_0011e34c:
          } while (cVar7 == '_');
        }
        else {
          if (9 < (byte)(cVar7 - 0x30U)) goto LAB_0011e358;
          cVar7 = *local_1b0;
          pcVar14 = local_1b0;
        }
        while (cVar7 == '.') {
          while( true ) {
            if (9 < (byte)(pcVar14[1] - 0x30U)) goto LAB_0011e2dc;
            cVar7 = pcVar14[2];
            pcVar14 = pcVar14 + 2;
            if (9 < (byte)(cVar7 - 0x30U)) break;
            do {
              pcVar14 = pcVar14 + 1;
            } while ((byte)(*pcVar14 - 0x30U) < 10);
            if (*pcVar14 != '.') goto LAB_0011e2dc;
          }
        }
LAB_0011e2dc:
        iVar8 = (int)local_1b0;
        local_1b0 = pcVar14;
        uVar11 = FUN_00110afc(&local_1c8,pcVar1,(int)pcVar14 - iVar8);
        lVar12 = FUN_00110a5c(&local_1c8,0x4c,lVar12,uVar11);
      }
    }
  }
  else if (iVar9 == 0) {
    local_1b0 = param_1;
    local_1a8 = &stack0xfffffffffffffde0 + lVar3;
    local_198 = &stack0xfffffffffffffde0 + lVar4 + lVar3;
    lVar12 = FUN_00113660(&local_1c8);
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
      uVar11 = FUN_00115b3c(&local_1c8,0);
    }
    else {
      local_1b0 = pcVar1;
      local_1a8 = &stack0xfffffffffffffde0 + lVar3;
      local_198 = &stack0xfffffffffffffde0 + lVar4 + lVar3;
      sVar10 = strlen(pcVar1);
      uVar11 = FUN_00110afc(&local_1c8,pcVar1,sVar10);
    }
    lVar12 = FUN_00110a5c(&local_1c8,uVar13,uVar11,0);
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
    FUN_00110fcc(&local_c,&local_1c,lVar12);
    local_8 = 0;
    local_c = local_1c * local_c;
    lVar5 = -((-(ulong)(local_1c >> 0x1f) & 0xfffffff000000000 | (ulong)local_1c << 4) + 0x10);
    local_28 = &stack0xfffffffffffffde0 + lVar5 + lVar4 + lVar3;
    local_18 = &stack0xfffffffffffffde0 +
               ((lVar5 + lVar4 + lVar3) -
               ((-(ulong)(local_c >> 0x1f) & 0xfffffff000000000 | (ulong)local_c << 4) + 0x10));
    FUN_00119244(auStack_168,0x11,lVar12);
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
    iVar1 = FUN_0011df38(param_1,FUN_001112ac,&local_20);
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
    iVar1 = FUN_0011df38();
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



void FUN_0011e544(byte *param_1,ulong *param_2)

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



void FUN_0011e56c(byte *param_1,ulong *param_2)

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



ulong ** FUN_0011e5ac(byte param_1,ulong **param_2,ulong **param_3,ulong **param_4)

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
      ppuVar1 = (ulong **)FUN_0011e544(param_3,&local_8);
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
      ppuVar1 = (ulong **)FUN_0011e56c(param_3,&local_8);
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



void FUN_0011e69c(void)

{
  DAT_0014e360 = 8;
  DAT_0014e361 = 8;
  DAT_0014e362 = 8;
  DAT_0014e363 = 8;
  DAT_0014e364 = 8;
  DAT_0014e365 = 8;
  DAT_0014e366 = 8;
  DAT_0014e367 = 8;
  DAT_0014e368 = 8;
  DAT_0014e369 = 8;
  DAT_0014e36a = 8;
  DAT_0014e36b = 8;
  DAT_0014e36c = 8;
  DAT_0014e36d = 8;
  DAT_0014e36e = 8;
  DAT_0014e36f = 8;
  DAT_0014e370 = 8;
  DAT_0014e371 = 8;
  DAT_0014e372 = 8;
  DAT_0014e373 = 8;
  DAT_0014e374 = 8;
  DAT_0014e375 = 8;
  DAT_0014e376 = 8;
  DAT_0014e377 = 8;
  DAT_0014e378 = 8;
  DAT_0014e379 = 8;
  DAT_0014e37a = 8;
  DAT_0014e37b = 8;
  DAT_0014e37c = 8;
  DAT_0014e37d = 8;
  DAT_0014e37e = 8;
  DAT_0014e37f = 8;
  DAT_0014e3a0 = 8;
  DAT_0014e3a1 = 8;
  DAT_0014e3a2 = 8;
  DAT_0014e3a3 = 8;
  DAT_0014e3a4 = 8;
  DAT_0014e3a5 = 8;
  DAT_0014e3a6 = 8;
  DAT_0014e3a7 = 8;
  DAT_0014e3a8 = 8;
  DAT_0014e3a9 = 8;
  DAT_0014e3aa = 8;
  DAT_0014e3ab = 8;
  DAT_0014e3ac = 8;
  DAT_0014e3ad = 8;
  DAT_0014e3ae = 8;
  DAT_0014e3af = 8;
  DAT_0014e3b0 = 8;
  DAT_0014e3b1 = 8;
  DAT_0014e3b2 = 8;
  DAT_0014e3b3 = 8;
  DAT_0014e3b4 = 8;
  DAT_0014e3b5 = 8;
  DAT_0014e3b6 = 8;
  DAT_0014e3b7 = 8;
  DAT_0014e3b8 = 8;
  DAT_0014e3b9 = 8;
  DAT_0014e3ba = 8;
  DAT_0014e3bb = 8;
  DAT_0014e3bc = 8;
  DAT_0014e3bd = 8;
  DAT_0014e3be = 8;
  DAT_0014e3bf = 8;
  DAT_0014e3c0 = 8;
  return;
}



void FUN_0011e7b0(long param_1,undefined8 param_2,undefined8 *param_3)

{
  if (DAT_0014e37f == '\b') {
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
      if ((&DAT_0014e360)[param_2] != '\b') goto LAB_0011e7fc;
      puVar1 = (undefined8 *)*puVar1;
    }
    return puVar1;
  }
LAB_0011e7fc:
                    // WARNING: Subroutine does not return
  abort();
}



long FUN_0011e844(long param_1,long param_2)

{
  void **__dest;
  void **__src;
  long lVar1;
  undefined auStack_8 [8];
  
  if ((((*(ulong *)(param_2 + 0x340) >> 0x3e & 1) == 0) || (*(char *)(param_2 + 0x377) == '\0')) &&
     (*(long *)(param_2 + 0xf8) == 0)) {
    FUN_0011e7b0(param_2,*(undefined8 *)(param_2 + 0x310),auStack_8);
  }
  lVar1 = 0;
  while( true ) {
    __dest = *(void ***)(param_1 + lVar1 * 8);
    __src = *(void ***)(param_2 + lVar1 * 8);
    if (*(char *)(param_1 + lVar1 + 0x358) != '\0') break;
    if ((*(char *)(param_2 + lVar1 + 0x358) == '\0') || (__dest == (void **)0x0)) {
      if ((__dest != (void **)0x0 && __src != (void **)0x0) && (__src != __dest)) {
        memcpy(__dest,__src,(ulong)(byte)(&DAT_0014e360)[lVar1]);
      }
    }
    else {
      if ((&DAT_0014e360)[lVar1] != '\b') break;
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
LAB_0011e968:
                    // WARNING: Subroutine does not return
    abort();
  }
  if (((*(ulong *)(param_1 + 0x340) >> 0x3e & 1) == 0) ||
     (*(char *)(param_1 + param_2 + 0x358) == '\0')) {
    if ((&DAT_0014e360)[param_2] != '\b') goto LAB_0011e968;
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



undefined8 FUN_0011ea1c(byte param_1,undefined8 param_2)

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
LAB_0011ea84:
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
        goto LAB_0011ea84;
      }
    }
  }
  return 0;
}



void FUN_0011ea94(byte *param_1,byte *param_2,long param_3,void *param_4)

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
LAB_0011eadc:
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
    if (bVar1 != 0xc0) goto code_r0x0011eb5c;
    *(undefined4 *)((long)param_4 + (uVar10 & 0x3f) * 0x10 + 8) = 0;
  }
  local_18 = uVar10 & 0x3f;
  goto LAB_0011ebfc;
code_r0x0011eb5c:
  switch(bVar2) {
  case 0:
    goto LAB_0011eadc;
  case 1:
    uVar3 = *(undefined *)((long)param_4 + 0x670);
    uVar8 = FUN_0011ea1c(uVar3,param_3);
    param_1 = (byte *)FUN_0011e5ac(uVar3,uVar8,param_1,&local_8);
    *(long *)((long)param_4 + 0x648) = local_8;
    goto LAB_0011eadc;
  case 2:
    *(ulong *)((long)param_4 + 0x648) = uVar12 + (ulong)pbVar5[1] * *(long *)((long)param_4 + 0x660)
    ;
    param_1 = pbVar5 + 2;
    goto LAB_0011eadc;
  case 3:
    *(ulong *)((long)param_4 + 0x648) =
         uVar12 + (ulong)*(ushort *)(pbVar5 + 1) * *(long *)((long)param_4 + 0x660);
    param_1 = pbVar5 + 3;
    goto LAB_0011eadc;
  case 4:
    *(ulong *)((long)param_4 + 0x648) =
         uVar12 + (ulong)*(uint *)(pbVar5 + 1) * *(long *)((long)param_4 + 0x660);
    param_1 = pbVar5 + 5;
    goto LAB_0011eadc;
  case 5:
    param_1 = (byte *)FUN_0011e544(param_1,&local_18);
LAB_0011ebfc:
    param_1 = (byte *)FUN_0011e544(param_1,&local_10);
    lVar11 = *(long *)((long)param_4 + 0x658);
    lVar9 = local_10;
    break;
  case 6:
  case 8:
    param_1 = (byte *)FUN_0011e544(param_1,&local_18);
    if (local_18 < 0x62) {
      *(undefined4 *)((long)param_4 + local_18 * 0x10 + 8) = 0;
    }
    goto LAB_0011eadc;
  case 7:
    param_1 = (byte *)FUN_0011e544(param_1,&local_18);
    if (local_18 < 0x62) {
      *(undefined4 *)((long)param_4 + local_18 * 0x10 + 8) = 6;
    }
    goto LAB_0011eadc;
  case 9:
    uVar8 = FUN_0011e544(param_1,&local_18);
    param_1 = (byte *)FUN_0011e544(uVar8,&local_8);
    if (0x61 < local_18) goto LAB_0011eadc;
    lVar7 = local_18 * 0x10;
    *(undefined4 *)((long)param_4 + lVar7 + 8) = 2;
    lVar9 = local_8;
    goto LAB_0011ef58;
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
    goto LAB_0011eadc;
  case 0xb:
    puVar15 = *(undefined **)((long)param_4 + 0x620);
    memcpy(param_4,puVar15,0x648);
    *(undefined **)(puVar15 + 0x620) = puVar16;
    puVar16 = puVar15;
    goto LAB_0011eadc;
  case 0xc:
    uVar8 = FUN_0011e544(param_1,&local_10);
    *(long *)((long)param_4 + 0x630) = local_10;
    param_1 = (byte *)FUN_0011e544(uVar8,&local_10);
    *(long *)((long)param_4 + 0x628) = local_10;
    goto LAB_0011ed40;
  case 0xd:
    param_1 = (byte *)FUN_0011e544(param_1,&local_10);
    *(long *)((long)param_4 + 0x630) = local_10;
LAB_0011ed40:
    *(undefined4 *)((long)param_4 + 0x640) = 1;
    goto LAB_0011eadc;
  case 0xe:
    param_1 = (byte *)FUN_0011e544(param_1,&local_10);
    lVar9 = local_10;
    goto LAB_0011ee0c;
  case 0xf:
    *(byte **)((long)param_4 + 0x638) = param_1;
    *(undefined4 *)((long)param_4 + 0x640) = 2;
    goto LAB_0011eebc;
  case 0x10:
    param_1 = (byte *)FUN_0011e544(param_1,&local_18);
    if (0x61 < local_18) goto LAB_0011eebc;
    uVar14 = 3;
    goto LAB_0011eeb4;
  case 0x11:
    uVar8 = FUN_0011e544(param_1,&local_18);
    param_1 = (byte *)FUN_0011e56c(uVar8,&local_8);
    lVar11 = *(long *)((long)param_4 + 0x658);
    lVar9 = local_8;
    break;
  case 0x12:
    uVar8 = FUN_0011e544(param_1,&local_10);
    *(long *)((long)param_4 + 0x630) = local_10;
    param_1 = (byte *)FUN_0011e56c(uVar8,&local_8);
    *(undefined4 *)((long)param_4 + 0x640) = 1;
    goto LAB_0011ee00;
  case 0x13:
    param_1 = (byte *)FUN_0011e56c(param_1,&local_8);
LAB_0011ee00:
    lVar9 = local_8 * *(long *)((long)param_4 + 0x658);
LAB_0011ee0c:
    *(long *)((long)param_4 + 0x628) = lVar9;
    goto LAB_0011eadc;
  case 0x14:
    uVar8 = FUN_0011e544(param_1,&local_18);
    param_1 = (byte *)FUN_0011e544(uVar8,&local_10);
    lVar11 = *(long *)((long)param_4 + 0x658);
    lVar9 = local_10;
    goto LAB_0011ee6c;
  case 0x15:
    uVar8 = FUN_0011e544(param_1,&local_18);
    param_1 = (byte *)FUN_0011e56c(uVar8,&local_8);
    lVar11 = *(long *)((long)param_4 + 0x658);
    lVar9 = local_8;
LAB_0011ee6c:
    if (0x61 < local_18) goto LAB_0011eadc;
    lVar7 = local_18 * 0x10;
    *(undefined4 *)((long)param_4 + lVar7 + 8) = 4;
    lVar9 = lVar9 * lVar11;
    goto LAB_0011ef58;
  case 0x16:
    param_1 = (byte *)FUN_0011e544(param_1,&local_18);
    if (0x61 < local_18) goto LAB_0011eebc;
    uVar14 = 5;
LAB_0011eeb4:
    *(undefined4 *)((long)param_4 + local_18 * 0x10 + 8) = uVar14;
    *(byte **)((long)param_4 + local_18 * 0x10) = param_1;
LAB_0011eebc:
    lVar9 = FUN_0011e544(param_1,&local_10);
    param_1 = (byte *)(lVar9 + local_10);
    goto LAB_0011eadc;
  default:
    goto switchD_0011eb68_caseD_17;
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
    goto LAB_0011eadc;
  case 0x2e:
    param_1 = (byte *)FUN_0011e544(param_1,&local_10);
    *(long *)(param_3 + 0x350) = local_10;
    goto LAB_0011eadc;
  case 0x2f:
    uVar8 = FUN_0011e544(param_1,&local_18);
    param_1 = (byte *)FUN_0011e544(uVar8,&local_10);
    lVar9 = *(long *)((long)param_4 + 0x658);
    if (0x61 < local_18) goto LAB_0011eadc;
    lVar7 = local_18 * 0x10;
    *(undefined4 *)((long)param_4 + lVar7 + 8) = 1;
    lVar9 = -(lVar9 * local_10);
    goto LAB_0011ef58;
  }
  if (0x61 < local_18) goto LAB_0011eadc;
  lVar7 = local_18 * 0x10;
  *(undefined4 *)((long)param_4 + lVar7 + 8) = 1;
  lVar9 = lVar9 * lVar11;
LAB_0011ef58:
  *(long *)((long)param_4 + lVar7) = lVar9;
  goto LAB_0011eadc;
switchD_0011eb68_caseD_17:
                    // WARNING: Subroutine does not return
  abort();
}



undefined8 FUN_0011ef8c(long param_1,long *param_2)

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
LAB_0011f388:
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
LAB_0011f164:
      uVar12 = FUN_0011e544(plVar7,&local_18);
      param_2[0xcc] = local_18;
      pbVar8 = (byte *)FUN_0011e56c(uVar12,&local_10);
      param_2[0xcb] = local_10;
      if (*(char *)(puVar17 + 2) == '\x01') {
        pbVar9 = pbVar8 + 1;
        uVar13 = (ulong)*pbVar8;
      }
      else {
        pbVar9 = (byte *)FUN_0011e544(pbVar8,&local_18);
        uVar13 = local_18;
      }
      param_2[0xcd] = uVar13;
      *(undefined *)((long)param_2 + 0x671) = 0xff;
      pbVar8 = (byte *)0x0;
      if (*pcVar19 == 'z') {
        pcVar19 = pcVar19 + 1;
        pbVar9 = (byte *)FUN_0011e544(pbVar9,&local_18);
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
LAB_0011f220:
          pbVar9 = pbVar9 + 1;
        }
        else {
          if (cVar2 == 'R') {
            *(byte *)(param_2 + 0xce) = *pbVar9;
            goto LAB_0011f220;
          }
          if (cVar2 == 'P') {
            bVar1 = *pbVar9;
            uVar12 = FUN_0011ea1c(bVar1,param_1);
            pbVar9 = (byte *)FUN_0011e5ac(bVar1,uVar12,pbVar9 + 1,&local_8);
            param_2[0xca] = local_8;
          }
          else {
            pbVar10 = pbVar8;
            if (cVar2 != 'S') goto LAB_0011f290;
            *(undefined *)((long)param_2 + 0x673) = 1;
          }
        }
      }
      pbVar10 = pbVar9;
      if (pbVar8 != (byte *)0x0) {
        pbVar10 = pbVar8;
      }
LAB_0011f290:
      if (pbVar10 != (byte *)0x0) {
        FUN_0011ea94(pbVar10,(long)puVar17 + (ulong)*puVar17 + 4,param_1,param_2);
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
          lVar11 = FUN_0011e544(lVar11,&local_8);
          lVar4 = lVar11 + local_8;
        }
        cVar2 = *(char *)((long)param_2 + 0x671);
        if (cVar2 != -1) {
          uVar12 = FUN_0011ea1c(cVar2,param_1);
          lVar11 = FUN_0011e5ac(cVar2,uVar12,lVar11,&local_8);
          *(long *)(param_1 + 800) = local_8;
        }
        if (lVar4 == 0) {
          lVar4 = lVar11;
        }
        FUN_0011ea94(lVar4,(long)puVar3 + (ulong)*puVar3 + 4,param_1,param_2);
        goto LAB_0011f388;
      }
    }
    else if ((*(char *)plVar7 == '\b') && (*(char *)((long)plVar7 + 1) == '\0')) {
      plVar7 = (long *)((long)plVar7 + 2);
      goto LAB_0011f164;
    }
    uVar12 = 3;
  }
  return uVar12;
}



// WARNING: Restarted to delay deadcode elimination for space: stack

ulong * FUN_0011f3b0(byte *param_1,byte *param_2,undefined8 param_3,ulong *param_4)

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
LAB_0011f400:
  pbVar10 = param_1;
  if (param_2 <= pbVar10) {
    if (uVar12 != 0) {
      return local_200[(int)(uVar12 - 1)];
    }
switchD_0011f7bc_caseD_3:
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
        param_1 = (byte *)FUN_0011e544(param_1,&local_218);
        puVar5 = local_218;
      }
      else if (uVar14 < 0x11) {
        if (uVar14 == 10) {
          puVar5 = (ulong *)(ulong)*(ushort *)(pbVar10 + 1);
LAB_0011f60c:
          param_1 = pbVar10 + 3;
        }
        else if (uVar14 < 0xb) {
          if (uVar13 == 6) goto LAB_0011f748;
          if (uVar13 < 7) {
            if (bVar1 != 3) goto switchD_0011f7bc_caseD_3;
            param_1 = pbVar10 + 9;
            puVar5 = *(ulong **)(pbVar10 + 1);
          }
          else {
            param_1 = pbVar10 + 2;
            if (uVar13 == 8) {
              puVar5 = (ulong *)(ulong)pbVar10[1];
            }
            else {
              if (uVar13 != 9) goto switchD_0011f7bc_caseD_3;
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
                goto LAB_0011f920;
              }
              goto switchD_0011f7bc_caseD_3;
            }
            if (bVar1 == 0xb) {
              puVar5 = (ulong *)(long)*(short *)(pbVar10 + 1);
              goto LAB_0011f60c;
            }
            if (bVar1 != 0xc) goto switchD_0011f7bc_caseD_3;
            puVar5 = (ulong *)(ulong)*(uint *)(pbVar10 + 1);
          }
          param_1 = pbVar10 + 5;
        }
      }
      else if (uVar14 == 0x15) {
        local_210 = (ulong)pbVar10[1];
        param_1 = pbVar10 + 2;
        if ((long)(int)(uVar12 - 1) <= (long)local_210) goto switchD_0011f7bc_caseD_3;
        puVar5 = local_200[(long)(int)(uVar12 - 1) - local_210];
      }
      else {
        if (0x15 < uVar14) {
          if (uVar14 == 0x19) goto LAB_0011f748;
          if (0x19 < uVar14) goto LAB_0011f80c;
          iVar4 = uVar12 - 1;
          iVar2 = uVar12 - 2;
          if (uVar14 == 0x16) {
            if ((int)uVar12 < 2) goto switchD_0011f7bc_caseD_3;
            puVar5 = local_200[iVar4];
            local_200[iVar4] = local_200[iVar2];
            local_200[iVar2] = puVar5;
          }
          else {
            if ((uVar14 != 0x17) || ((int)uVar12 < 3)) goto switchD_0011f7bc_caseD_3;
            puVar5 = local_200[iVar4];
            puVar11 = local_200[(int)(uVar12 - 3)];
            local_200[iVar4] = local_200[iVar2];
            local_200[iVar2] = puVar11;
            local_200[(int)(uVar12 - 3)] = puVar5;
          }
          goto LAB_0011f400;
        }
        if (uVar14 == 0x12) {
          if (uVar12 == 0) goto switchD_0011f7bc_caseD_3;
          iVar4 = uVar12 - 1;
        }
        else {
          if (uVar14 < 0x12) {
            param_1 = (byte *)FUN_0011e56c(param_1,&local_208);
            puVar5 = local_208;
            goto LAB_0011f920;
          }
          if (uVar14 == 0x13) {
            if (uVar12 == 0) goto switchD_0011f7bc_caseD_3;
            uVar12 = uVar12 - 1;
            goto LAB_0011f400;
          }
          if ((uVar14 != 0x14) || ((int)uVar12 < 2)) goto switchD_0011f7bc_caseD_3;
          iVar4 = uVar12 - 2;
        }
        puVar5 = local_200[iVar4];
      }
    }
    else {
LAB_0011f748:
      if (uVar12 == 0) goto switchD_0011f7bc_caseD_3;
      uVar12 = uVar12 - 1;
      ppuVar9 = (ulong **)local_200[(int)uVar12];
      if (uVar13 == 0x1f) {
        puVar5 = (ulong *)-(long)ppuVar9;
      }
      else if (uVar13 < 0x20) {
        if (uVar13 == 6) {
switchD_0011f7bc_caseD_8:
          puVar5 = *ppuVar9;
        }
        else {
          if (bVar1 != 0x19) goto switchD_0011f7bc_caseD_3;
          puVar5 = (ulong *)(((ulong)ppuVar9 ^ (long)ppuVar9 >> 0x3f) - ((long)ppuVar9 >> 0x3f));
        }
      }
      else if (uVar13 == 0x23) {
        param_1 = (byte *)FUN_0011e544(param_1,&local_218);
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
          goto switchD_0011f7bc_caseD_3;
        case 4:
          puVar5 = (ulong *)(ulong)*(uint *)ppuVar9;
          break;
        case 8:
          goto switchD_0011f7bc_caseD_8;
        }
      }
      else {
        if (uVar13 != 0x20) goto switchD_0011f7bc_caseD_3;
        puVar5 = (ulong *)~(ulong)ppuVar9;
      }
    }
  }
  else if (uVar14 < 0x50) {
    if (0x2f < uVar13) {
      puVar5 = (ulong *)(ulong)(uVar13 - 0x30);
      goto LAB_0011f920;
    }
    if (0x27 < uVar13) {
      if (uVar14 < 0x2f) {
        if (0x28 < uVar14) goto LAB_0011f80c;
        if (uVar12 == 0) goto switchD_0011f7bc_caseD_3;
        uVar12 = uVar12 - 1;
        param_1 = pbVar10 + 3;
        if (local_200[(int)uVar12] != (ulong *)0x0) {
          param_1 = pbVar10 + 3 + *(short *)(pbVar10 + 1);
        }
      }
      else {
        param_1 = pbVar10 + (long)*(short *)(pbVar10 + 1) + 3;
      }
      goto LAB_0011f400;
    }
    if ((uVar14 < 0x24) && (0x22 < uVar14)) goto LAB_0011f748;
LAB_0011f80c:
    if ((int)uVar12 < 2) goto switchD_0011f7bc_caseD_3;
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
      goto switchD_0011f7bc_caseD_3;
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
          goto LAB_0011f674;
        }
        param_1 = (byte *)FUN_0011e56c(param_1,&local_210);
        lVar7 = _Unwind_GetGR(param_3,uVar14 - 0x70);
      }
      else {
        if (uVar14 == 0x94) goto LAB_0011f748;
        if (0x94 < uVar14) {
          if (uVar14 != 0x96) {
            if (uVar14 == 0xf1) {
              bVar1 = pbVar10[1];
              uVar6 = FUN_0011ea1c(bVar1,param_3);
              param_1 = (byte *)FUN_0011e5ac(bVar1,uVar6,pbVar10 + 2,&local_208);
              puVar5 = local_208;
              goto LAB_0011f920;
            }
            goto switchD_0011f7bc_caseD_3;
          }
          goto LAB_0011f400;
        }
        if (bVar1 != 0x92) goto switchD_0011f7bc_caseD_3;
        uVar6 = FUN_0011e544(param_1,local_220);
        param_1 = (byte *)FUN_0011e56c(uVar6,&local_210);
        lVar7 = _Unwind_GetGR(param_3,local_220[0]);
      }
      puVar5 = (ulong *)(lVar7 + local_210);
      goto LAB_0011f920;
    }
    param_1 = (byte *)FUN_0011e544(param_1,local_220);
    iVar4 = local_220[0];
LAB_0011f674:
    puVar5 = (ulong *)_Unwind_GetGR(param_3,iVar4);
  }
LAB_0011f920:
  if (0x3f < uVar12) goto switchD_0011f7bc_caseD_3;
  local_200[(int)uVar12] = puVar5;
  uVar12 = uVar12 + 1;
  goto LAB_0011f400;
}



void FUN_0011f964(void *param_1,long *param_2)

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
    FUN_0011e7b0(alStack_3c0,*(undefined8 *)((long)param_1 + 0x310),auStack_3d0);
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
LAB_0011faac:
                    // WARNING: Subroutine does not return
      abort();
    }
    lVar3 = FUN_0011e544(param_2[199],&local_3c8);
    lVar3 = FUN_0011f3b0(lVar3,lVar3 + local_3c8,alStack_3c0,0);
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
        goto LAB_0011fa9c;
      }
      lVar4 = alStack_3c0[(int)*plVar7];
      break;
    case 3:
      lVar4 = FUN_0011e544(*plVar7,&local_3c8);
      lVar4 = FUN_0011f3b0(lVar4,lVar4 + local_3c8,alStack_3c0,lVar3);
      break;
    case 4:
      lVar4 = lVar3 + *plVar7;
      goto LAB_0011fa9c;
    case 5:
      lVar4 = FUN_0011e544(*plVar7,&local_3c8);
      lVar4 = FUN_0011f3b0(lVar4,lVar4 + local_3c8,alStack_3c0,lVar3);
LAB_0011fa9c:
      if ((byte)(&DAT_0014e360)[lVar5] < 9) {
        *puVar6 = 1;
        goto LAB_0011fb1c;
      }
      goto LAB_0011faac;
    default:
      goto switchD_0011fa74_caseD_5;
    }
    if ((*(ulong *)((long)param_1 + 0x340) >> 0x3e & 1) != 0) {
      *puVar6 = 0;
    }
LAB_0011fb1c:
    *(long *)((long)param_1 + lVar5 * 8) = lVar4;
switchD_0011fa74_caseD_5:
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



void FUN_0011fb70(void *param_1,undefined8 param_2,undefined8 param_3)

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
  iVar1 = FUN_0011ef8c(param_1,auStack_680);
  if (iVar1 == 0) {
    iVar1 = pthread_once((pthread_once_t *)&DAT_0014e3c4,FUN_0011e69c);
    if ((iVar1 != 0) && (DAT_0014e360 == '\0')) {
      FUN_0011e69c();
    }
    FUN_0011e7b0(param_1,param_2,auStack_688);
    local_58 = 0;
    local_40 = 1;
    local_50 = 0x1f;
    FUN_0011f964(param_1,auStack_680);
    *(undefined8 *)((long)param_1 + 0x318) = param_3;
    return;
  }
                    // WARNING: Subroutine does not return
  abort();
}



void FUN_0011fc4c(long param_1,long param_2)

{
  undefined8 uVar1;
  
  FUN_0011f964();
  if (*(int *)(param_2 + *(long *)(param_2 + 0x668) * 0x10 + 8) == 6) {
    *(undefined8 *)(param_1 + 0x318) = 0;
  }
  else {
    uVar1 = _Unwind_GetGR(param_1);
    *(undefined8 *)(param_1 + 0x318) = uVar1;
  }
  return;
}



undefined8 FUN_0011fc98(undefined8 *param_1,long param_2)

{
  int iVar1;
  long lVar2;
  undefined8 uVar3;
  uint uVar4;
  undefined auStack_680 [1616];
  code *local_30;
  
  do {
    iVar1 = FUN_0011ef8c(param_2,auStack_680);
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
    FUN_0011fc4c(param_2,auStack_680);
  } while( true );
}



undefined4 FUN_0011fd58(undefined8 *param_1,undefined8 param_2)

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
    iVar1 = FUN_0011ef8c(param_2,auStack_680);
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
    FUN_0011fc4c(param_2,auStack_680);
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
  iVar2 = FUN_0011ef8c(auStack_a40,&local_680);
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



void FUN_0011ff38(void)

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
  
  FUN_0011fb70(auStack_e00,&stack0x00000000);
  memcpy(auStack_a40,auStack_e00,0x3c0);
  do {
    iVar2 = FUN_0011ef8c(auStack_a40,auStack_680);
    if ((iVar2 == 5) || (iVar2 != 0)) goto LAB_00120074;
    if (local_30 != (code *)0x0) {
      iVar2 = (*local_30)(1,1,*param_1,param_1,auStack_a40);
      if (iVar2 == 6) {
        param_1[2] = 0;
        lVar3 = _Unwind_GetCFA(auStack_a40);
        param_1[3] = lVar3 + (local_700 >> 0x3f);
        memcpy(auStack_a40,auStack_e00,0x3c0);
        iVar2 = FUN_0011fc98(param_1,auStack_a40);
        if (iVar2 == 7) {
          FUN_0011e844(auStack_e00,auStack_a40);
          FUN_0011ff38(local_730,local_728);
        }
LAB_00120074:
        auVar1._8_8_ = param_2;
        auVar1._0_8_ = param_1;
        return auVar1;
      }
      if (iVar2 != 8) goto LAB_00120074;
    }
    FUN_0011fc4c(auStack_a40,auStack_680);
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
  
  FUN_0011fb70(auStack_780,&stack0x00000000);
  memcpy(auStack_3c0,auStack_780,0x3c0);
  *(undefined8 *)(param_1 + 0x10) = param_2;
  *(undefined8 *)(param_1 + 0x18) = param_3;
  iVar2 = FUN_0011fd58(param_1,auStack_3c0);
  if (iVar2 == 7) {
    FUN_0011e844(auStack_780,auStack_3c0);
    FUN_0011ff38(local_b0,local_a8);
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
  
  FUN_0011fb70(auStack_780,&stack0x00000000);
  memcpy(auStack_3c0,auStack_780,0x3c0);
  if (*(long *)(param_1 + 0x10) == 0) {
    iVar2 = FUN_0011fc98(param_1,auStack_3c0);
  }
  else {
    iVar2 = FUN_0011fd58(param_1,auStack_3c0);
  }
  if (iVar2 != 7) {
                    // WARNING: Subroutine does not return
    abort();
  }
  FUN_0011e844(auStack_780,auStack_3c0);
  FUN_0011ff38(local_b0,local_a8);
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
    FUN_0011fb70(auStack_780,&stack0x00000000);
    memcpy(auStack_3c0,auStack_780,0x3c0);
    iVar2 = FUN_0011fd58(param_1,auStack_3c0);
    if (iVar2 != 7) {
                    // WARNING: Subroutine does not return
      abort();
    }
    FUN_0011e844(auStack_780,auStack_3c0);
    FUN_0011ff38(local_b0,local_a8);
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
  
  FUN_0011fb70(auStack_a40,&stack0x00000000);
  while (((iVar1 = FUN_0011ef8c(auStack_a40,auStack_680), iVar1 == 5 || (iVar1 == 0)) &&
         (iVar2 = (*param_1)(auStack_a40,param_2), iVar2 == 0))) {
    if (iVar1 == 5) {
      return 5;
    }
    FUN_0011fc4c(auStack_a40,auStack_680);
  }
  return 3;
}



void FUN_00120490(byte *param_1,ulong *param_2)

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



void FUN_001204b8(byte *param_1,ulong *param_2)

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



int FUN_001204f8(undefined8 param_1,long param_2,long param_3)

{
  int iVar1;
  
  iVar1 = -(uint)(*(ulong *)(param_2 + 8) < *(ulong *)(param_3 + 8));
  if (*(ulong *)(param_3 + 8) < *(ulong *)(param_2 + 8)) {
    iVar1 = 1;
  }
  return iVar1;
}



void FUN_00120514(undefined8 param_1,code *param_2,long param_3,ulong param_4,int param_5)

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



void FUN_001205d4(undefined8 param_1,undefined8 param_2,long param_3)

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
    FUN_00120514(param_1,param_2,lVar2,uVar3,uVar6 & 0xffffffff);
  }
  lVar8 = 0;
  iVar5 = (int)uVar6 + -1;
  lVar1 = lVar2 + (long)iVar5 * 8;
  for (; 0 < iVar5; iVar5 = iVar5 + -1) {
    uVar4 = *(undefined8 *)(param_3 + 0x10);
    *(undefined8 *)(param_3 + 0x10) = *(undefined8 *)(lVar1 + lVar8);
    *(undefined8 *)(lVar1 + lVar8) = uVar4;
    lVar8 = lVar8 + -8;
    FUN_00120514(param_1,param_2,lVar2,0,iVar5);
  }
  return;
}



undefined8 FUN_00120688(byte param_1)

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



undefined8 FUN_001206e8(byte param_1,long param_2)

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



undefined8 FUN_00120748(byte param_1,long param_2)

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



ulong ** FUN_001207a8(byte param_1,ulong **param_2,ulong **param_3,ulong **param_4)

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
      ppuVar1 = (ulong **)FUN_00120490(param_3,&local_8);
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
      ppuVar1 = (ulong **)FUN_001204b8(param_3,&local_8);
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



int FUN_00120898(long param_1,long param_2,long param_3)

{
  int iVar1;
  ushort uVar2;
  undefined8 uVar3;
  ulong local_10;
  ulong local_8;
  
  uVar2 = *(ushort *)(param_1 + 0x20) >> 3 & 0xff;
  uVar3 = FUN_001206e8(uVar2,param_1);
  FUN_001207a8(uVar2,uVar3,param_2 + 8,&local_10);
  FUN_001207a8(*(ushort *)(param_1 + 0x20) >> 3,uVar3,param_3 + 8,&local_8);
  iVar1 = -(uint)(local_10 < local_8);
  if (local_8 < local_10) {
    iVar1 = 1;
  }
  return iVar1;
}



byte FUN_00120928(long param_1)

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
    uVar4 = FUN_00120490(pcVar7,auStack_10);
    lVar5 = FUN_001204b8(uVar4,auStack_8);
    if (*(char *)(param_1 + 8) == '\x01') {
      lVar5 = lVar5 + 1;
    }
    else {
      lVar5 = FUN_00120490(lVar5,auStack_10);
    }
    pbVar6 = (byte *)FUN_00120490(lVar5,auStack_10);
    for (pcVar8 = (char *)(param_1 + 10); cVar1 = *pcVar8, cVar1 != 'R'; pcVar8 = pcVar8 + 1) {
      if (cVar1 == 'P') {
        pbVar6 = (byte *)FUN_001207a8(*pbVar6 & 0x7f,0,pbVar6 + 1,auStack_18);
      }
      else {
        if (cVar1 != 'L') goto LAB_00120980;
        pbVar6 = pbVar6 + 1;
      }
    }
    bVar2 = *pbVar6;
  }
  else {
LAB_00120980:
    bVar2 = 0;
  }
  return bVar2;
}



uint * FUN_00120a24(long param_1,uint *param_2,long param_3)

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
  uVar2 = FUN_001206e8(uVar1,param_1);
  lVar3 = 0;
  do {
    if (*param_2 == 0) {
      return (uint *)0x0;
    }
    if (param_2[1] != 0) {
      lVar7 = lVar3;
      if (((*(byte *)(param_1 + 0x20) >> 2 & 1) != 0) &&
         (lVar7 = (long)param_2 + (4 - (long)(int)param_2[1]), lVar7 != lVar3)) {
        uVar4 = FUN_00120928(lVar7);
        uVar1 = uVar4 & 0xffffffff;
        uVar2 = FUN_001206e8(uVar4,param_1);
      }
      if ((uint)uVar1 == 0) {
        local_10 = *(ulong *)(param_2 + 2);
        local_8 = *(ulong *)(param_2 + 4);
        uVar4 = local_10;
      }
      else {
        uVar5 = FUN_001207a8(uVar1 & 0xff,uVar2,param_2 + 2,&local_10);
        FUN_001207a8((uint)uVar1 & 0xf,0,uVar5,&local_8);
        uVar4 = FUN_00120688(uVar1 & 0xff);
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



void FUN_00120b84(long param_1)

{
  FUN_00120928((param_1 + 4) - (long)*(int *)(param_1 + 4));
  return;
}



undefined8 FUN_00120b94(ulong *param_1,ulong param_2,ulong *param_3)

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
    if ((param_1[4] == DAT_0013c138) && (param_1[5] == DAT_0014e3d0)) {
      puVar18 = DAT_0014e3d8;
      puVar12 = (ulong *)0x0;
      puVar16 = (ulong *)0x0;
      while (puVar10 = puVar18, puVar10 != (ulong *)0x0) {
        if ((*puVar10 <= *param_3) && (*param_3 < puVar10[1])) {
          uVar17 = puVar10[2];
          piVar15 = (int *)puVar10[3];
          if (puVar10 != DAT_0014e3d8) {
            puVar16[5] = puVar10[5];
            puVar10[5] = (ulong)DAT_0014e3d8;
            DAT_0014e3d8 = puVar10;
          }
          goto LAB_00120da0;
        }
        puVar12 = puVar10;
        if ((*puVar10 | puVar10[1]) == 0) break;
        puVar18 = (ulong *)puVar10[5];
        if (puVar18 != (ulong *)0x0) {
          puVar16 = puVar10;
        }
      }
      goto LAB_00120cbc;
    }
    puVar11 = &DAT_0014e410;
    DAT_0013c138 = param_1[4];
    DAT_0014e3d0 = param_1[5];
    do {
      puVar11[-6] = 0;
      puVar11[-5] = 0;
      puVar11[-1] = puVar11;
      puVar11 = puVar11 + 6;
    } while (puVar11 != (undefined8 *)0x14e590);
    DAT_0014e558 = 0;
    DAT_0014e3d8 = &DAT_0014e3e0;
    *(undefined4 *)(param_3 + 5) = 0;
  }
  puVar16 = (ulong *)0x0;
  puVar12 = (ulong *)0x0;
LAB_00120cbc:
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
      puVar12[5] = (ulong)DAT_0014e3d8;
      DAT_0014e3d8 = puVar12;
    }
    puVar12 = DAT_0014e3d8;
    DAT_0014e3d8[2] = uVar17;
    puVar12[3] = (ulong)piVar15;
    puVar12[4] = (ulong)piVar20;
    *puVar12 = uVar19;
    puVar12[1] = uVar13;
  }
LAB_00120da0:
  if (piVar15 == (int *)0x0) {
    return 0;
  }
  lVar1 = uVar17 + *(long *)(piVar15 + 4);
  if (*(char *)(uVar17 + *(long *)(piVar15 + 4)) != '\x01') {
    return 1;
  }
  uVar7 = *(undefined *)(lVar1 + 1);
  uVar8 = FUN_00120748(uVar7,param_3);
  uVar8 = FUN_001207a8(uVar7,uVar8,lVar1 + 4,&local_40);
  cVar3 = *(char *)(lVar1 + 2);
  if ((cVar3 != -1) && (*(char *)(lVar1 + 3) == ';')) {
    uVar9 = FUN_00120748(cVar3,param_3);
    piVar14 = (int *)FUN_001207a8(cVar3,uVar9,uVar8,&local_38);
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
      bVar6 = FUN_00120b84(uVar17);
      uVar13 = FUN_00120688(bVar6);
      FUN_001207a8(bVar6 & 0xf,0,uVar17 + (uVar13 & 0xffffffff) + 8,&local_30);
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
  uVar17 = FUN_00120a24(&local_30,local_40,*param_3);
  param_3[4] = uVar17;
  if (uVar17 != 0) {
    uVar7 = FUN_00120b84();
    uVar8 = FUN_00120748(uVar7,param_3);
    FUN_001207a8(uVar7,uVar8,param_3[4] + 8,&local_38);
    param_3[3] = local_38;
  }
  return 1;
}



int FUN_00120fb4(undefined8 param_1,long param_2,long param_3)

{
  int iVar1;
  undefined uVar2;
  undefined8 uVar3;
  ulong local_10;
  ulong local_8;
  
  uVar2 = FUN_00120b84(param_2);
  uVar3 = FUN_001206e8(uVar2,param_1);
  FUN_001207a8(uVar2,uVar3,param_2 + 8,&local_10);
  uVar2 = FUN_00120b84(param_3);
  uVar3 = FUN_001206e8(uVar2,param_1);
  FUN_001207a8(uVar2,uVar3,param_3 + 8,&local_8);
  iVar1 = -(uint)(local_10 < local_8);
  if (local_8 < local_10) {
    iVar1 = 1;
  }
  return iVar1;
}



long FUN_00121050(ulong *param_1,uint *param_2)

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
        uVar2 = FUN_00120928(lVar6);
        if (uVar2 == 0xff) {
          return -1;
        }
        uVar8 = FUN_001206e8((char)uVar2,param_1);
        uVar1 = *(ushort *)(param_1 + 4);
        lVar3 = lVar6;
        if ((uVar1 & 0x7f8) == 0x7f8) {
          *(ushort *)(param_1 + 4) = uVar1 & 0xf800 | uVar1 & 7 | (ushort)((uVar2 & 0xff) << 3);
        }
        else if ((uVar1 >> 3 & 0xff) != uVar2) {
          *(byte *)(param_1 + 4) = *(byte *)(param_1 + 4) | 4;
        }
      }
      FUN_001207a8(uVar2 & 0xff,uVar8,param_2 + 2,&local_8);
      uVar4 = FUN_00120688(uVar2 & 0xff);
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



void FUN_001211b0(long param_1,long *param_2,uint *param_3)

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
  uVar2 = FUN_001206e8(uVar1,param_1);
  lVar3 = 0;
  for (; *param_3 != 0; param_3 = (uint *)((long)param_3 + (ulong)*param_3 + 4)) {
    if (param_3[1] != 0) {
      lVar7 = lVar3;
      if (((*(byte *)(param_1 + 0x20) >> 2 & 1) != 0) &&
         (lVar7 = (long)param_3 + (4 - (long)(int)param_3[1]), lVar7 != lVar3)) {
        uVar4 = FUN_00120928(lVar7);
        uVar1 = uVar4 & 0xffffffff;
        uVar2 = FUN_001206e8(uVar4,param_1);
      }
      if ((int)uVar1 == 0) {
        uVar4 = *(ulong *)(param_3 + 2);
      }
      else {
        FUN_001207a8(uVar1 & 0xff,uVar2,param_3 + 2,&local_8);
        uVar5 = FUN_00120688(uVar1 & 0xff);
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



long FUN_001212e4(ulong *param_1,ulong param_2)

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
  
  if ((*(byte *)(param_1 + 4) & 1) != 0) goto LAB_00121310;
  uVar17 = (ulong)(*(uint *)(param_1 + 4) >> 0xb);
  if (uVar17 == 0) {
    if ((*(byte *)(param_1 + 4) >> 1 & 1) == 0) {
      uVar17 = FUN_00121050(param_1,param_1[3]);
      if (uVar17 != 0xffffffffffffffff) goto LAB_00121388;
LAB_00121348:
      param_1[4] = 0;
      *(undefined2 *)(param_1 + 4) = 0x7f8;
      param_1[3] = (ulong)&DAT_0014e568;
    }
    else {
      for (plVar12 = (long *)param_1[3]; *plVar12 != 0; plVar12 = plVar12 + 1) {
        lVar10 = FUN_00121050(param_1);
        if (lVar10 == -1) goto LAB_00121348;
        uVar17 = uVar17 + lVar10;
      }
LAB_00121388:
      uVar6 = (uint)uVar17 & 0x1fffff;
      if (uVar6 == uVar17) {
        uVar6 = *(uint *)(param_1 + 4) & 0x7ff | uVar6 << 0xb;
      }
      else {
        uVar6 = *(uint *)(param_1 + 4) & 0x7ff;
      }
      *(uint *)(param_1 + 4) = uVar6;
      if (uVar17 != 0) goto LAB_001213b0;
    }
  }
  else {
LAB_001213b0:
    __size = (uVar17 + 2) * 8;
    local_10 = (ulong *)malloc(__size);
    if (local_10 != (ulong *)0x0) {
      local_10[1] = 0;
      local_8 = malloc(__size);
      if (local_8 != (void *)0x0) {
        *(undefined8 *)((long)local_8 + 8) = 0;
      }
      if ((*(byte *)(param_1 + 4) >> 1 & 1) == 0) {
        FUN_001211b0(param_1,&local_10,param_1[3]);
      }
      else {
        for (plVar12 = (long *)param_1[3]; *plVar12 != 0; plVar12 = plVar12 + 1) {
          FUN_001211b0(param_1,&local_10);
        }
      }
      pvVar4 = local_8;
      puVar3 = local_10;
      if ((local_10 != (ulong *)0x0) && (local_10[1] != uVar17)) {
LAB_00121708:
                    // WARNING: Subroutine does not return
        abort();
      }
      if ((*(byte *)(param_1 + 4) >> 2 & 1) == 0) {
        if ((*(ushort *)(param_1 + 4) & 0x7f8) == 0) {
          pcVar16 = FUN_001204f8;
        }
        else {
          pcVar16 = FUN_00120898;
        }
      }
      else {
        pcVar16 = FUN_00120fb4;
      }
      if (local_8 == (void *)0x0) {
        FUN_001205d4(param_1,pcVar16,local_10);
      }
      else {
        puVar18 = local_10 + 2;
        uVar20 = local_10[1];
        puVar14 = &DAT_0014e560;
        puVar21 = puVar18;
        for (uVar13 = 0; uVar13 != uVar20; uVar13 = uVar13 + 1) {
          while ((puVar14 != &DAT_0014e560 &&
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
        if (*(long *)((long)local_8 + 8) + local_10[1] != uVar17) goto LAB_00121708;
        FUN_001205d4(param_1,pcVar16);
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
LAB_00121310:
  bVar5 = *(byte *)(param_1 + 4);
  if ((bVar5 & 1) == 0) {
    if ((bVar5 >> 1 & 1) == 0) {
      lVar10 = FUN_00120a24(param_1,param_1[3],param_2);
      return lVar10;
    }
    for (plVar12 = (long *)param_1[3]; *plVar12 != 0; plVar12 = plVar12 + 1) {
      lVar10 = FUN_00120a24(param_1,*plVar12,param_2);
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
      uVar8 = FUN_001206e8(uVar2,param_1);
      uVar13 = *(ulong *)(uVar20 + 8);
      while (uVar11 = uVar13, uVar17 < uVar11) {
        uVar13 = uVar11 + uVar17 >> 1;
        lVar10 = *(long *)(uVar20 + (uVar13 + 2) * 8);
        uVar9 = FUN_001207a8(uVar2,uVar8,lVar10 + 8,&local_18);
        FUN_001207a8(uVar1 & 0xf,0,uVar9,&local_10);
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
      bVar5 = FUN_00120b84(lVar10);
      uVar8 = FUN_001206e8(bVar5,param_1);
      uVar8 = FUN_001207a8(bVar5,uVar8,lVar10 + 8,&local_18);
      FUN_001207a8(bVar5 & 0xf,0,uVar8,&local_10);
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
    pthread_mutex_lock((pthread_mutex_t *)&DAT_0014e570);
    param_2[5] = DAT_0014e598;
    DAT_0014e598 = param_2;
    uVar1 = pthread_mutex_unlock((pthread_mutex_t *)&DAT_0014e570);
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



// WARNING: Removing unreachable block (ram,0x001219c4)

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
  pthread_mutex_lock((pthread_mutex_t *)&DAT_0014e570);
  param_2[5] = DAT_0014e598;
  DAT_0014e598 = param_2;
  iVar1 = pthread_mutex_unlock((pthread_mutex_t *)&DAT_0014e570);
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
  pthread_mutex_lock((pthread_mutex_t *)&DAT_0014e570);
  plVar1 = &DAT_0014e598;
  for (lVar2 = DAT_0014e598; lVar2 != 0; lVar2 = *(long *)(lVar2 + 0x28)) {
    if (*(int **)(lVar2 + 0x18) == param_1) goto LAB_00121a98;
    plVar1 = (long *)(lVar2 + 0x28);
  }
  plVar1 = &DAT_0014e5a0;
  while (lVar2 = *plVar1, lVar2 != 0) {
    if ((*(byte *)(lVar2 + 0x20) & 1) == 0) {
      if (*(int **)(lVar2 + 0x18) == param_1) goto LAB_00121a98;
    }
    else if (**(int ***)(lVar2 + 0x18) == param_1) {
      *plVar1 = *(long *)(lVar2 + 0x28);
      free(*(void **)(lVar2 + 0x18));
      break;
    }
    plVar1 = (long *)(lVar2 + 0x28);
  }
LAB_00121ad8:
  pthread_mutex_unlock((pthread_mutex_t *)&DAT_0014e570);
  if (lVar2 != 0) {
    return lVar2;
  }
                    // WARNING: Subroutine does not return
  abort();
LAB_00121a98:
  *plVar1 = *(long *)(lVar2 + 0x28);
  goto LAB_00121ad8;
}



long __deregister_frame_info(int *param_1)

{
  long *plVar1;
  long lVar2;
  
  if ((param_1 == (int *)0x0) || (*param_1 == 0)) {
    return 0;
  }
  pthread_mutex_lock((pthread_mutex_t *)&DAT_0014e570);
  plVar1 = &DAT_0014e598;
  for (lVar2 = DAT_0014e598; lVar2 != 0; lVar2 = *(long *)(lVar2 + 0x28)) {
    if (*(int **)(lVar2 + 0x18) == param_1) goto LAB_00121a98;
    plVar1 = (long *)(lVar2 + 0x28);
  }
  plVar1 = &DAT_0014e5a0;
  while (lVar2 = *plVar1, lVar2 != 0) {
    if ((*(byte *)(lVar2 + 0x20) & 1) == 0) {
      if (*(int **)(lVar2 + 0x18) == param_1) goto LAB_00121a98;
    }
    else if (**(int ***)(lVar2 + 0x18) == param_1) {
      *plVar1 = *(long *)(lVar2 + 0x28);
      free(*(void **)(lVar2 + 0x18));
      break;
    }
    plVar1 = (long *)(lVar2 + 0x28);
  }
LAB_00121ad8:
  pthread_mutex_unlock((pthread_mutex_t *)&DAT_0014e570);
  if (lVar2 != 0) {
    return lVar2;
  }
                    // WARNING: Subroutine does not return
  abort();
LAB_00121a98:
  *plVar1 = *(long *)(lVar2 + 0x28);
  goto LAB_00121ad8;
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



// WARNING: Removing unreachable block (ram,0x00121cd4)

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
  
  pthread_mutex_lock((pthread_mutex_t *)&DAT_0014e570);
  for (puVar7 = DAT_0014e5a0; puVar7 != (ulong *)0x0; puVar7 = (ulong *)puVar7[5]) {
    if (*puVar7 <= param_1) {
      local_10 = FUN_001212e4(puVar7,param_1);
      if (local_10 != 0) goto LAB_00121c0c;
      break;
    }
  }
  do {
    puVar7 = DAT_0014e598;
    if (DAT_0014e598 == (ulong *)0x0) {
      local_10 = 0;
      break;
    }
    DAT_0014e598 = (ulong *)DAT_0014e598[5];
    local_10 = FUN_001212e4(puVar7,param_1);
    ppuVar4 = &DAT_0014e5a0;
    for (puVar6 = DAT_0014e5a0; (puVar6 != (ulong *)0x0 && (*puVar7 <= *puVar6));
        puVar6 = (ulong *)puVar6[5]) {
      ppuVar4 = (ulong **)(puVar6 + 5);
    }
    puVar7[5] = (ulong)puVar6;
    *ppuVar4 = puVar7;
  } while (local_10 == 0);
LAB_00121c0c:
  pthread_mutex_unlock((pthread_mutex_t *)&DAT_0014e570);
  if (local_10 == 0) {
    local_8 = 1;
    local_28 = 0;
    local_20 = 0;
    local_18 = 0;
    local_10 = 0;
    local_30 = param_1;
    iVar3 = dl_iterate_phdr(FUN_00120b94,&local_30);
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
      uVar2 = FUN_00120b84(local_10);
    }
    uVar5 = FUN_001206e8(uVar2 & 0xff,puVar7);
    FUN_001207a8(uVar2 & 0xff,uVar5,local_10 + 8,&local_30);
  }
  param_2[2] = local_30;
  return local_10;
}


