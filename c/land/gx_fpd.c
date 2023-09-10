typedef unsigned char   undefined;

typedef unsigned char    bool;
typedef unsigned char    byte;
typedef unsigned char    dwfenc;
typedef unsigned int    dword;
typedef long double    longdouble;
typedef unsigned long    qword;
typedef unsigned int    uint;
typedef unsigned long    ulong;
typedef unsigned char    undefined1;
typedef unsigned int    undefined4;
typedef unsigned long    undefined8;
typedef unsigned short    ushort;
typedef unsigned short    word;
typedef pointer pointer __((offset(0x10)));

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

typedef struct _IO_FILE FILE;

typedef long __ssize_t;

typedef __ssize_t ssize_t;

typedef uint pthread_key_t;

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

typedef int pthread_once_t;

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

typedef struct __vmi_class_type_info __vmi_class_type_info, *P__vmi_class_type_info;

struct __vmi_class_type_info { // PlaceHolder Structure
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

typedef struct type_info type_info, *Ptype_info;

struct type_info { // PlaceHolder Structure
};

typedef struct bad_cast bad_cast, *Pbad_cast;

struct bad_cast { // PlaceHolder Structure
};

typedef struct _Ios_Iostate _Ios_Iostate, *P_Ios_Iostate;

struct _Ios_Iostate { // PlaceHolder Structure
};

typedef struct bad_array_length bad_array_length, *Pbad_array_length;

struct bad_array_length { // PlaceHolder Structure
};

typedef struct bad_exception bad_exception, *Pbad_exception;

struct bad_exception { // PlaceHolder Structure
};

typedef struct bad_typeid bad_typeid, *Pbad_typeid;

struct bad_typeid { // PlaceHolder Structure
};

typedef struct bad_array_new_length bad_array_new_length, *Pbad_array_new_length;

struct bad_array_new_length { // PlaceHolder Structure
};

typedef struct exception_ptr exception_ptr, *Pexception_ptr;

struct exception_ptr { // PlaceHolder Structure
};

typedef struct FpService FpService, *PFpService;

struct FpService { // PlaceHolder Structure
};

typedef struct String16 String16, *PString16;

struct String16 { // PlaceHolder Structure
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

typedef struct Elf64_Rela Elf64_Rela, *PElf64_Rela;

struct Elf64_Rela {
    qword r_offset; // location to apply the relocation action
    qword r_info; // the symbol table index and the type of relocation
    qword r_addend; // a constant addend used to compute the relocatable field value
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




void FUN_00106f60(void)

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



// WARNING: Unknown calling convention -- yet parameter storage is locked

void free(void *__ptr)

{
  free(__ptr);
  return;
}



void __libc_init(void)

{
  __libc_init();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

double strtold(char *__nptr,char **__endptr)

{
  double dVar1;
  
  dVar1 = strtold(__nptr,__endptr);
  return dVar1;
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

int sprintf(char *__s,char *__format,...)

{
  int iVar1;
  
  iVar1 = sprintf(__s,__format);
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

int pthread_once(pthread_once_t *__once_control,__init_routine *__init_routine)

{
  int iVar1;
  
  iVar1 = pthread_once(__once_control,__init_routine);
  return iVar1;
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

void android::IPCThreadState::joinThreadPool(bool param_1)

{
  joinThreadPool(param_1);
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

double strtod(char *__nptr,char **__endptr)

{
  double dVar1;
  
  dVar1 = strtod(__nptr,__endptr);
  return dVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void android::RefBase::decStrong(void *param_1)

{
  decStrong(param_1);
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

int fputc(int __c,FILE *__stream)

{
  int iVar1;
  
  iVar1 = fputc(__c,__stream);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void android::ProcessState::startThreadPool(void)

{
  startThreadPool();
  return;
}



void __android_log_print(void)

{
  __android_log_print();
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

void check_sys_prop(void)

{
  check_sys_prop();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

size_t fwrite(void *__ptr,size_t __size,size_t __n,FILE *__s)

{
  size_t sVar1;
  
  sVar1 = fwrite(__ptr,__size,__n,__s);
  return sVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void android::IPCThreadState::self(void)

{
  self();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

long syscall(long __sysno,...)

{
  long lVar1;
  
  lVar1 = syscall(__sysno);
  return lVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void * memset(void *__s,int __c,size_t __n)

{
  void *pvVar1;
  
  pvVar1 = memset(__s,__c,__n);
  return pvVar1;
}



void __google_potentially_blocking_region_begin(void)

{
  __google_potentially_blocking_region_begin();
  return;
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



void __cxa_atexit(void)

{
  __cxa_atexit();
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



// WARNING: Unknown calling convention -- yet parameter storage is locked

int pthread_mutex_lock(pthread_mutex_t *__mutex)

{
  int iVar1;
  
  iVar1 = pthread_mutex_lock(__mutex);
  return iVar1;
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

void android::ProcessState::self(void)

{
  self();
  return;
}



void __stack_chk_fail(void)

{
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

float strtof(char *__nptr,char **__endptr)

{
  float fVar1;
  
  fVar1 = strtof(__nptr,__endptr);
  return fVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int fputs(char *__s,FILE *__stream)

{
  int iVar1;
  
  iVar1 = fputs(__s,__stream);
  return iVar1;
}



void __thiscall android::FpService::FpService(FpService *this)

{
  FpService(this);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

char * setlocale(int __category,char *__locale)

{
  char *pcVar1;
  
  pcVar1 = setlocale(__category,__locale);
  return pcVar1;
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



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void main(void)

{
  bool bVar1;
  int iVar2;
  FpService *this;
  undefined4 uVar3;
  code *pcVar4;
  long *local_30;
  String16 aSStack_28 [8];
  long *local_20;
  long *local_18;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  iVar2 = check_sys_prop();
  if (iVar2 == 0) {
    android::defaultServiceManager();
                    // try { // try from 001072a4 to 001072a7 has its CatchHandler @ 001073c0
    this = (FpService *)operator_new(0x2f8);
                    // try { // try from 001072ac to 001072af has its CatchHandler @ 001074a0
    android::FpService::FpService(this);
    pcVar4 = *(code **)(*local_30 + 0x30);
                    // try { // try from 001072cc to 001072cf has its CatchHandler @ 001074b8
    android::String16::String16(aSStack_28,"goodix.fp");
    local_20 = (long *)(this + 8);
                    // try { // try from 001072ec to 001072ef has its CatchHandler @ 001074ec
    android::RefBase::incStrong
              ((FpService *)((long)local_20 + *(long *)(*(long *)(this + 8) + -0x18)));
                    // try { // try from 00107300 to 00107303 has its CatchHandler @ 001074c0
    (*pcVar4)(local_30,aSStack_28,&local_20,0);
    if (local_20 != (long *)0x0) {
      android::RefBase::decStrong((FpService *)((long)local_20 + *(long *)(*local_20 + -0x18)));
    }
    android::String16::~String16(aSStack_28);
                    // try { // try from 00107330 to 00107333 has its CatchHandler @ 001074b8
    android::ProcessState::self();
                    // try { // try from 00107338 to 0010733b has its CatchHandler @ 0010745c
    android::ProcessState::startThreadPool();
    if (local_18 != (long *)0x0) {
      android::RefBase::decStrong((void *)((long)local_18 + *(long *)(*local_18 + -0x18)));
    }
                    // try { // try from 00107358 to 00107363 has its CatchHandler @ 001074b8
    bVar1 = (bool)android::IPCThreadState::self();
    android::IPCThreadState::joinThreadPool(bVar1);
    uVar3 = 0;
    if (local_30 != (long *)0x0) {
      android::RefBase::decStrong((void *)((long)local_30 + *(long *)(*local_30 + -0x18)));
    }
  }
  else {
    uVar3 = 0xffffffff;
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar3);
}



void FUN_001074f4(void)

{
  int iVar1;
  
  DAT_00136054 = 0;
  iVar1 = pthread_key_create(&__bss_start__,FUN_00107d1c);
  DAT_00136054 = iVar1 == 0;
  __cxa_atexit(FUN_00107d00,&__bss_start__,&DAT_00136000);
  return;
}



void FUN_00107548(void)

{
  DAT_00137ca0 = 0;
  DAT_00137ca8 = 0;
  DAT_00137cb0 = 0;
  DAT_00137cb8 = 0;
  DAT_00137cc0 = 0;
  return;
}



void FUN_00107560(void)

{
  __cxa_atexit(FUN_00109c6c,&PTR_PTR_FUN_00136030,&DAT_00136000);
  __cxa_atexit(FUN_00109c68,&PTR_PTR_FUN_00136038,&DAT_00136000);
  return;
}



void FUN_001075ac(void)

{
  if ((DAT_00147d40 & 1) == 0) {
    DAT_00147d40 = 1;
  }
  if ((DAT_00147d38 & 1) == 0) {
    DAT_00147d38 = 1;
  }
  if ((DAT_00147d30 & 1) == 0) {
    DAT_00147d30 = 1;
  }
  if ((DAT_00147d28 & 1) == 0) {
    DAT_00147d28 = 1;
  }
  if ((DAT_00147d20 & 1) == 0) {
    DAT_00147d20 = 1;
  }
  if ((DAT_00147d18 & 1) == 0) {
    DAT_00147d18 = 1;
  }
  if ((DAT_00147d10 & 1) == 0) {
    DAT_00147d10 = 1;
  }
  if ((DAT_00147d08 & 1) == 0) {
    DAT_00147d08 = 1;
  }
  if ((DAT_00147d00 & 1) == 0) {
    DAT_00147d00 = 1;
  }
  if ((DAT_00147cf8 & 1) == 0) {
    DAT_00147cf8 = 1;
  }
  if ((DAT_00147cf0 & 1) == 0) {
    DAT_00147cf0 = 1;
  }
  if ((DAT_00147ce8 & 1) == 0) {
    DAT_00147ce8 = 1;
  }
  return;
}



void FUN_001076a0(void)

{
  if ((DAT_00147da0 & 1) == 0) {
    DAT_00147da0 = 1;
  }
  if ((DAT_00147d98 & 1) == 0) {
    DAT_00147d98 = 1;
  }
  if ((DAT_00147d90 & 1) == 0) {
    DAT_00147d90 = 1;
  }
  if ((DAT_00147d88 & 1) == 0) {
    DAT_00147d88 = 1;
  }
  if ((DAT_00147d80 & 1) == 0) {
    DAT_00147d80 = 1;
  }
  if ((DAT_00147d78 & 1) == 0) {
    DAT_00147d78 = 1;
  }
  if ((DAT_00147d70 & 1) == 0) {
    DAT_00147d70 = 1;
  }
  if ((DAT_00147d68 & 1) == 0) {
    DAT_00147d68 = 1;
  }
  if ((DAT_00147d60 & 1) == 0) {
    DAT_00147d60 = 1;
  }
  if ((DAT_00147d58 & 1) == 0) {
    DAT_00147d58 = 1;
  }
  if ((DAT_00147d50 & 1) == 0) {
    DAT_00147d50 = 1;
  }
  if ((DAT_00147d48 & 1) == 0) {
    DAT_00147d48 = 1;
  }
  return;
}



void entry(void)

{
  FUN_001077b4(&stack0x00000000);
  return;
}



void FUN_0010779c(code *param_1)

{
  if (param_1 != (code *)0x0) {
    (*param_1)();
  }
  return;
}



void FUN_001077b4(undefined8 param_1)

{
  undefined8 uVar1;
  qword *local_18;
  qword *local_10;
  qword *local_8;
  
  local_18 = &__PREINIT_ARRAY__;
  local_10 = &__INIT_ARRAY__;
  local_8 = &__FINI_ARRAY__;
  uVar1 = __libc_init(param_1,0,main,&local_18);
  __cxa_atexit(FUN_0010779c,uVar1,&DAT_00136000);
  return;
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
  *(undefined ***)this = &PTR____class_type_info_00135550;
  FUN_00108d54();
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
      if (iVar1 == 0) goto LAB_00107900;
    }
    return 0;
  }
LAB_00107900:
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
LAB_00107aac:
      *(__sub_kind *)(param_7 + 0xc) = param_2;
      return 0;
    }
    if (*__s1 == '*') {
      if (__s1 != *(char **)(param_3 + 8)) {
        return 0;
      }
      goto LAB_00107a8c;
    }
    iVar1 = strcmp(__s1,*(char **)(param_5 + 8));
    if (iVar1 == 0) goto LAB_00107aac;
    __s2 = *(char **)(param_3 + 8);
    if (__s1 == __s2) goto LAB_00107a8c;
  }
  else {
    __s2 = *(char **)(param_3 + 8);
    if (__s1 == __s2) goto LAB_00107a8c;
    if (*__s1 == '*') {
      return 0;
    }
  }
  iVar1 = strcmp(__s1,__s2);
  if (iVar1 != 0) {
    return 0;
  }
LAB_00107a8c:
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
  plVar4 = *pplVar3;
  plVar5 = param_1 + -10;
  if (*param_1 + 0xb8b1aabcbcd4d500U < 2) {
    iVar2 = *(int *)(param_1 + -5);
    if (iVar2 < 0) {
      iVar2 = -iVar2;
    }
    iVar1 = *(int *)(pplVar3 + 1);
    *(int *)(param_1 + -5) = iVar2 + 1;
    *(int *)(pplVar3 + 1) = iVar1 + -1;
    if (plVar4 != plVar5) {
      param_1[-6] = (long)plVar4;
      *pplVar3 = plVar5;
    }
    return param_1[-1];
  }
  if (plVar4 == (long *)0x0) {
    *pplVar3 = plVar5;
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
  *(undefined ***)this = &PTR__bad_exception_00135620;
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



pthread_key_t * FUN_00107d00(pthread_key_t *param_1)

{
  code *UNRECOVERED_JUMPTABLE;
  uint uVar1;
  pthread_key_t *ppVar2;
  
  if (param_1 == (pthread_key_t *)0x0) {
                    // WARNING: Treating indirect jump as call
    UNRECOVERED_JUMPTABLE = (code *)SoftwareBreakpoint(1000,0x107d1c);
    ppVar2 = (pthread_key_t *)(*UNRECOVERED_JUMPTABLE)();
    return ppVar2;
  }
  if (*(char *)(param_1 + 1) == '\0') {
    return param_1;
  }
  uVar1 = pthread_key_delete(*param_1);
  return (pthread_key_t *)(ulong)uVar1;
}



void FUN_00107d1c(long *param_1)

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
  
  if (DAT_00136054 == '\0') {
    return &DAT_00136058;
  }
                    // try { // try from 00107d94 to 00107d97 has its CatchHandler @ 00107da0
  puVar1 = (undefined *)pthread_getspecific(__bss_start__);
  return puVar1;
}



undefined8 * __cxa_get_globals(void)

{
  int iVar1;
  undefined8 *__pointer;
  
  if (DAT_00136054 == '\0') {
    __pointer = (undefined8 *)&DAT_00136058;
  }
  else {
                    // try { // try from 00107de8 to 00107e0f has its CatchHandler @ 00107e24
    __pointer = (undefined8 *)pthread_getspecific(__bss_start__);
    if (__pointer == (undefined8 *)0x0) {
      __pointer = (undefined8 *)malloc(0x10);
      if ((__pointer == (undefined8 *)0x0) ||
         (iVar1 = pthread_setspecific(__bss_start__,__pointer), iVar1 != 0)) {
                    // WARNING: Subroutine does not return
        std::terminate();
      }
      *__pointer = 0;
      *(undefined4 *)(__pointer + 1) = 0;
    }
  }
  return __pointer;
}



void FUN_00107e34(byte *param_1,ulong *param_2)

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



void FUN_00107e74(long *param_1,long *param_2,undefined8 *param_3)

{
  char cVar1;
  undefined8 *local_8;
  
  local_8 = (undefined8 *)*param_3;
  cVar1 = (**(code **)(*param_2 + 0x10))(param_2);
  if (cVar1 != '\0') {
    local_8 = (undefined8 *)*local_8;
  }
  cVar1 = (**(code **)(*param_1 + 0x20))(param_1,param_2,&local_8,1);
  if (cVar1 != '\0') {
    *param_3 = local_8;
  }
  return;
}



ulong * FUN_00107ef0(byte param_1,ulong *param_2,ulong *param_3,ulong *param_4)

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
      puVar4 = (ulong *)FUN_00107e34(param_3,&local_8);
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



undefined8 FUN_00108000(long param_1,long param_2)

{
  byte bVar1;
  undefined8 local_8;
  
  bVar1 = *(byte *)(param_1 + 0x28);
  if (bVar1 == 0xff) {
    param_2 = 0;
  }
  else {
    switch(bVar1 & 7) {
    case 0:
    case 4:
      param_2 = param_2 * -8;
      break;
    default:
                    // WARNING: Subroutine does not return
      abort();
    case 2:
      param_2 = param_2 * -2;
      break;
    case 3:
      param_2 = param_2 * -4;
    }
  }
  FUN_00107ef0(bVar1,*(undefined8 *)(param_1 + 0x10),*(long *)(param_1 + 0x18) + param_2,&local_8);
  return local_8;
}



char FUN_00108080(long param_1,undefined8 param_2,undefined8 param_3,ulong param_4)

{
  byte bVar1;
  ulong uVar2;
  char cVar3;
  undefined8 uVar4;
  ulong uVar5;
  ulong uVar6;
  byte *pbVar7;
  undefined8 local_8;
  byte *pbVar8;
  
  pbVar7 = (byte *)(*(long *)(param_1 + 0x18) + ~param_4);
  local_8 = param_3;
  while( true ) {
    uVar5 = 0;
    uVar6 = 0;
    pbVar8 = pbVar7;
    do {
      pbVar7 = pbVar8 + 1;
      bVar1 = *pbVar8;
      uVar2 = uVar6 & 0x3f;
      uVar6 = (ulong)((int)uVar6 + 7);
      uVar5 = uVar5 | ((ulong)bVar1 & 0x7f) << uVar2;
      pbVar8 = pbVar7;
    } while ((char)bVar1 < '\0');
    if (uVar5 == 0) break;
    uVar4 = FUN_00108000(param_1);
    cVar3 = FUN_00107e74(uVar4,param_2,&local_8);
    if (cVar3 != '\0') {
      return cVar3;
    }
  }
  return '\0';
}



undefined8 FUN_00108110(byte param_1,undefined8 param_2)

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



void FUN_0010818c(long param_1,char *param_2,undefined8 *param_3)

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
    uVar4 = FUN_00108110(cVar2,param_1);
    pcVar5 = (char *)FUN_00107ef0(cVar2,uVar4,param_2 + 1,param_3 + 1);
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



undefined8
__gxx_personality_v0(int param_1,uint param_2,long param_3,ulong *param_4,undefined8 param_5)

{
  bool bVar1;
  bool bVar2;
  undefined uVar3;
  byte bVar4;
  int iVar5;
  ulong uVar6;
  long lVar7;
  byte *pbVar8;
  long lVar9;
  undefined8 uVar10;
  undefined8 uVar11;
  byte *pbVar12;
  pointer_____offset_0x10___ *ppuVar13;
  ulong uVar14;
  ulong uVar15;
  ulong uVar16;
  ulong uVar17;
  int local_54;
  ulong *local_50;
  long local_48;
  int local_40;
  undefined4 uStack_3c;
  long local_38;
  long local_30;
  long local_28;
  undefined8 local_20;
  long local_18;
  byte *local_10;
  undefined local_8;
  undefined local_7;
  
  local_50 = (ulong *)0x0;
  local_54 = 0;
  if (param_1 != 1) {
    return 3;
  }
  bVar1 = 1 < param_3 + 0xb8b1aabcbcd4d500U;
  if ((param_2 == 6) <= bVar1) {
    uVar6 = _Unwind_GetLanguageSpecificData(param_5);
    if (uVar6 == 0) {
      return 8;
    }
    pbVar8 = (byte *)FUN_0010818c(param_5,uVar6,&local_30);
    local_20 = FUN_00108110(local_8,param_5);
    lVar9 = _Unwind_GetIPInfo(param_5,&local_54);
    uVar17 = lVar9 - (ulong)(local_54 == 0);
    if (pbVar8 < local_10) {
      do {
        uVar3 = local_7;
        uVar10 = FUN_00108110(local_7,0);
        uVar10 = FUN_00107ef0(uVar3,uVar10,pbVar8,&local_48);
        uVar3 = local_7;
        uVar11 = FUN_00108110(local_7,0);
        uVar10 = FUN_00107ef0(uVar3,uVar11,uVar10,&local_40);
        uVar3 = local_7;
        uVar11 = FUN_00108110(local_7,0);
        pbVar12 = (byte *)FUN_00107ef0(uVar3,uVar11,uVar10,&local_38);
        uVar16 = 0;
        uVar15 = 0;
        do {
          pbVar8 = pbVar12 + 1;
          bVar4 = *pbVar12;
          uVar14 = uVar15 & 0x3f;
          uVar15 = (ulong)((int)uVar15 + 7);
          uVar16 = uVar16 | ((ulong)bVar4 & 0x7f) << uVar14;
          pbVar12 = pbVar8;
        } while ((char)bVar4 < '\0');
        if (uVar17 < (ulong)(local_48 + local_30)) break;
        if (uVar17 < (ulong)(local_48 + local_30 + CONCAT44(uStack_3c,local_40))) {
          if (local_38 == 0) {
            return 8;
          }
          uVar17 = local_38 + local_28;
          if (uVar16 == 0) {
            if (uVar17 == 0) {
              return 8;
            }
          }
          else {
            if (uVar17 == 0) {
              return 8;
            }
            local_10 = local_10 + (uVar16 - 1);
            if (local_10 != (byte *)0x0) {
              if ((param_2 >> 3 & 1) == 0) {
                if (bVar1) {
                  ppuVar13 = &__cxxabiv1::__foreign_exception::typeinfo;
                }
                else {
                  local_50 = param_4 + 4;
                  if ((*param_4 & 1) != 0) {
                    local_50 = (ulong *)param_4[-10];
                  }
                  ppuVar13 = (pointer_____offset_0x10___ *)local_50[-0xe];
                }
              }
              else {
                ppuVar13 = &__cxxabiv1::__forced_unwind::typeinfo;
              }
              bVar2 = false;
              goto LAB_00108610;
            }
          }
          iVar5 = 2;
          goto LAB_00108530;
        }
      } while (pbVar8 < local_10);
    }
    uVar17 = 0;
    iVar5 = 1;
LAB_00108530:
    local_40 = 0;
    local_10 = (byte *)0x0;
    goto joined_r0x001083c0;
  }
  uVar6 = param_4[-3];
  uVar17 = param_4[-2];
  local_40 = *(int *)((long)param_4 + -0x24);
  if (uVar17 == 0) {
    if ((param_2 >> 3 & 1) != 0) goto LAB_00108564;
LAB_0010834c:
    FUN_00109854(param_4);
  }
  if ((param_2 >> 3 & 1) == 0) {
LAB_001083d8:
    if (local_40 < 0) {
      FUN_0010818c(param_5,uVar6,&local_30);
      local_20 = FUN_00108110(local_8,param_5);
      uVar6 = FUN_00108110(local_8,param_5);
      param_4[-2] = uVar6;
    }
    goto LAB_0010835c;
  }
  goto LAB_00108358;
LAB_00108610:
  lVar9 = FUN_00107e34(local_10,&local_40);
  FUN_00107e34(lVar9,&local_38);
  uVar15 = CONCAT44(uStack_3c,local_40);
  if (uVar15 != 0) {
    if ((long)uVar15 < 1) {
      if (bVar1 < (ppuVar13 != (pointer_____offset_0x10___ *)0x0 && (param_2 & 8) == 0)) {
        bVar4 = FUN_00108080(&local_30,ppuVar13,local_50);
        bVar4 = bVar4 ^ 1;
      }
      else {
        uVar14 = 0;
        uVar16 = 0;
        pbVar8 = (byte *)(local_18 + ~uVar15);
        do {
          bVar4 = *pbVar8;
          uVar15 = uVar16 & 0x3f;
          uVar16 = (ulong)((int)uVar16 + 7);
          uVar14 = uVar14 | ((ulong)bVar4 & 0x7f) << uVar15;
          pbVar8 = pbVar8 + 1;
        } while ((char)bVar4 < '\0');
        bVar4 = uVar14 == 0;
      }
joined_r0x001083b4:
      if (bVar4 == 0) goto LAB_00108694;
    }
    else {
      lVar7 = FUN_00108000(&local_30,uVar15);
      if (lVar7 != 0) {
        if (ppuVar13 == (pointer_____offset_0x10___ *)0x0) goto LAB_00108694;
        bVar4 = FUN_00107e74(lVar7,ppuVar13,&local_50);
        goto joined_r0x001083b4;
      }
    }
    iVar5 = 3;
    goto joined_r0x001083c0;
  }
  bVar2 = true;
LAB_00108694:
  if (local_38 == 0) goto LAB_001086b0;
  local_10 = (byte *)(lVar9 + local_38);
  goto LAB_00108610;
LAB_001086b0:
  if (!bVar2) {
    return 8;
  }
  local_40 = 0;
  iVar5 = 2;
joined_r0x001083c0:
  if ((param_2 & 1) != 0) {
    if (iVar5 == 2) {
      return 8;
    }
    if (!bVar1) {
      *(int *)((long)param_4 + -0x24) = local_40;
      param_4[-4] = (ulong)local_10;
      param_4[-3] = uVar6;
      param_4[-1] = (ulong)local_50;
      param_4[-2] = uVar17;
      return 6;
    }
    return 6;
  }
  if (((param_2 >> 3 & 1) == 0) && (!bVar1)) {
    if (iVar5 == 1) goto LAB_0010834c;
    goto LAB_001083d8;
  }
  if (iVar5 == 1) {
LAB_00108564:
                    // WARNING: Subroutine does not return
    std::terminate();
  }
LAB_00108358:
  if (local_40 < 0) {
                    // try { // try from 00108700 to 00108703 has its CatchHandler @ 00108704
    std::unexpected();
                    // catch(type#1 @ 00000000) { ... } // from try @ 00108700 with catch @ 00108704
    __cxa_begin_catch();
                    // WARNING: Subroutine does not return
    std::terminate();
  }
LAB_0010835c:
  _Unwind_SetGR(param_5,0,param_4);
  _Unwind_SetGR(param_5,1,(long)local_40);
  _Unwind_SetIP(param_5,uVar17);
  return 7;
}



void __cxa_call_unexpected(long param_1)

{
  __cxa_begin_catch();
                    // WARNING: Subroutine does not return
                    // try { // try from 00108740 to 00108743 has its CatchHandler @ 00108744
  __cxxabiv1::__unexpected(*(_func_void **)(param_1 + -0x40));
}



// __cxxabiv1::__terminate(void (*)())

void __cxxabiv1::__terminate(_func_void *param_1)

{
                    // try { // try from 00108804 to 0010880b has its CatchHandler @ 0010880c
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



void FUN_001088c0(uint param_1,long param_2)

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
  *(code **)(param_1 + -0x18) = FUN_001088c0;
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
  *puVar3 = &PTR__bad_alloc_00135820;
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
  *(undefined ***)this = &PTR____si_class_type_info_001356d0;
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
LAB_00108bac:
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
      if (iVar3 == 0) goto LAB_00108bac;
    }
    if (param_4 == param_6) {
      if (__s1 == *(char **)(param_5 + 8)) {
LAB_00108c48:
        *(__sub_kind *)(param_7 + 0xc) = param_2;
        return 0;
      }
      if (cVar1 != '*') {
        iVar3 = strcmp(__s1,*(char **)(param_5 + 8));
        if (iVar3 == 0) goto LAB_00108c48;
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



void FUN_00108d54(void)

{
  return;
}



undefined8 FUN_00108d58(void)

{
  return 0;
}



undefined8 FUN_00108d60(void)

{
  return 0;
}



undefined8 FUN_00108d68(void)

{
  return 0;
}



void operator_delete(void *param_1)

{
  free(param_1);
  return;
}



bool FUN_00108d74(long param_1,long param_2)

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



undefined8 FUN_00108dc4(long param_1)

{
  return *(undefined8 *)(param_1 + 8);
}



undefined8 FUN_00108dcc(long param_1)

{
  return *(undefined8 *)(param_1 + 8);
}



void FUN_00108dd4(undefined8 *param_1)

{
  int iVar1;
  char cVar2;
  bool bVar3;
  undefined *puVar4;
  int *piVar5;
  
  *param_1 = &PTR_FUN_001346e0;
  puVar4 = (undefined *)(param_1[1] + -0x18);
  if (puVar4 != &DAT_00136070) {
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



void FUN_00108e44(undefined8 *param_1)

{
  *param_1 = &PTR_FUN_00134710;
  FUN_00108dd4();
  return;
}



void FUN_00108e54(undefined8 *param_1)

{
  *param_1 = &PTR_FUN_00134710;
  FUN_00108dd4();
  operator_delete(param_1);
  return;
}



void FUN_00108e84(undefined8 *param_1)

{
  *param_1 = &PTR_FUN_00134740;
  FUN_00108dd4();
  return;
}



void FUN_00108e94(undefined8 *param_1)

{
  *param_1 = &PTR_FUN_00134740;
  FUN_00108dd4();
  operator_delete(param_1);
  return;
}



void FUN_00108ec4(undefined8 *param_1)

{
  *param_1 = &PTR_FUN_00134770;
  FUN_00108dd4();
  return;
}



void FUN_00108ed4(undefined8 *param_1)

{
  *param_1 = &PTR_FUN_00134770;
  FUN_00108dd4();
  operator_delete(param_1);
  return;
}



void FUN_00108f04(undefined8 *param_1)

{
  *param_1 = &PTR_FUN_001347a0;
  FUN_00108dd4();
  return;
}



void FUN_00108f14(undefined8 *param_1)

{
  *param_1 = &PTR_FUN_001347a0;
  FUN_00108dd4();
  operator_delete(param_1);
  return;
}



void FUN_00108f44(void *param_1)

{
  FUN_00108dd4();
  operator_delete(param_1);
  return;
}



void FUN_00108f68(undefined8 *param_1)

{
  int iVar1;
  char cVar2;
  bool bVar3;
  undefined *puVar4;
  int *piVar5;
  
  *param_1 = &PTR_FUN_001347d0;
  puVar4 = (undefined *)(param_1[1] + -0x18);
  if (puVar4 != &DAT_00136070) {
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



void FUN_00108fd8(undefined8 *param_1)

{
  *param_1 = &PTR_FUN_00134800;
  FUN_00108f68();
  return;
}



void FUN_00108fe8(undefined8 *param_1)

{
  *param_1 = &PTR_FUN_00134800;
  FUN_00108f68();
  operator_delete(param_1);
  return;
}



void FUN_00109018(undefined8 *param_1)

{
  *param_1 = &PTR_FUN_00134830;
  FUN_00108f68();
  return;
}



void FUN_00109028(undefined8 *param_1)

{
  *param_1 = &PTR_FUN_00134830;
  FUN_00108f68();
  operator_delete(param_1);
  return;
}



void FUN_00109058(undefined8 *param_1)

{
  *param_1 = &PTR_FUN_00134860;
  FUN_00108f68();
  return;
}



void FUN_00109068(undefined8 *param_1)

{
  *param_1 = &PTR_FUN_00134860;
  FUN_00108f68();
  operator_delete(param_1);
  return;
}



void FUN_00109098(void *param_1)

{
  FUN_00108f68();
  operator_delete(param_1);
  return;
}



void FUN_001090bc(undefined8 *param_1)

{
  *param_1 = &PTR_FUN_001346e0;
                    // try { // try from 001090d8 to 001090db has its CatchHandler @ 001090e8
  FUN_00109270(param_1 + 1);
  return;
}



void FUN_001090fc(undefined8 *param_1)

{
  FUN_001090bc();
  *param_1 = &PTR_FUN_00134770;
  return;
}



void FUN_00109128(ulong param_1,ulong param_2)

{
  void *pvVar1;
  ulong uVar2;
  
  if (0x3ffffffffffffff9 < param_1) {
                    // WARNING: Subroutine does not return
    FUN_00109b60("basic_string::_S_create");
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



void operator_delete(void *param_1)

{
  free(param_1);
  return;
}



size_t * FUN_001091c4(size_t *param_1,undefined8 param_2,long param_3)

{
  size_t *psVar1;
  size_t *__dest;
  size_t __n;
  
  psVar1 = (size_t *)FUN_00109128(param_3 + *param_1,param_1[1],param_2);
  __n = *param_1;
  __dest = psVar1 + 3;
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
  if (psVar1 != (size_t *)&DAT_00136070) {
    *(undefined4 *)(psVar1 + 2) = 0;
    *psVar1 = __n;
    *(undefined *)((long)psVar1 + __n + 0x18) = 0;
    return __dest;
  }
  return __dest;
}



void FUN_00109270(long *param_1,long *param_2)

{
  char cVar1;
  bool bVar2;
  int *piVar3;
  long lVar4;
  undefined auStack_8 [8];
  
  lVar4 = *param_2;
  if (*(int *)(lVar4 + -8) < 0) {
    lVar4 = FUN_001091c4((undefined *)(lVar4 + -0x18),auStack_8,0);
    *param_1 = lVar4;
    return;
  }
  if ((undefined *)(lVar4 + -0x18) != &DAT_00136070) {
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



size_t * FUN_001092e8(undefined *param_1,undefined *param_2)

{
  size_t *psVar1;
  size_t *__dest;
  size_t __n;
  
  if (param_1 != param_2) {
    if ((param_1 == (undefined *)0x0) && (param_2 != (undefined *)0x0)) {
      FUN_00109aac("basic_string::_S_construct null not valid");
    }
    __n = (long)param_2 - (long)param_1;
    psVar1 = (size_t *)FUN_00109128(__n,0);
    __dest = psVar1 + 3;
    if (__n == 1) {
      *(undefined *)(psVar1 + 3) = *param_1;
    }
    else {
      __dest = (size_t *)memcpy(__dest,param_1,__n);
    }
    if (psVar1 != (size_t *)&DAT_00136070) {
      *(undefined4 *)(psVar1 + 2) = 0;
      *psVar1 = __n;
      *(undefined *)((long)psVar1 + __n + 0x18) = 0;
    }
    return __dest;
  }
  return (size_t *)&DAT_00136088;
}



void FUN_001093b0(undefined8 *param_1,char *param_2,undefined8 param_3)

{
  size_t sVar1;
  undefined8 uVar2;
  
  if (param_2 != (char *)0x0) {
    sVar1 = strlen(param_2);
    uVar2 = FUN_001092e8(param_2,param_2 + sVar1,param_3,0);
    *param_1 = uVar2;
    return;
  }
  uVar2 = FUN_001092e8(0,0xffffffffffffffff,param_3,0);
  *param_1 = uVar2;
  return;
}



// std::bad_alloc::what() const

char * std::bad_alloc::what(void)

{
  return "std::bad_alloc";
}



// std::bad_alloc::~bad_alloc()

void __thiscall std::bad_alloc::~bad_alloc(bad_alloc *this)

{
  *(undefined ***)this = &PTR__bad_alloc_00135820;
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



char * FUN_0010945c(void)

{
  return "__gnu_cxx::__concurrence_lock_error";
}



char * FUN_00109468(void)

{
  return "__gnu_cxx::__concurrence_unlock_error";
}



void FUN_00109474(undefined8 *param_1)

{
  *param_1 = &PTR_FUN_00134890;
  std::exception::~exception((exception *)param_1);
  return;
}



void FUN_00109484(undefined8 *param_1)

{
  *param_1 = &PTR_FUN_001348c0;
  std::exception::~exception((exception *)param_1);
  return;
}



void FUN_00109494(undefined8 *param_1)

{
  *param_1 = &PTR_FUN_00134890;
  std::exception::~exception((exception *)param_1);
  operator_delete(param_1);
  return;
}



void FUN_001094c4(undefined8 *param_1)

{
  *param_1 = &PTR_FUN_001348c0;
  std::exception::~exception((exception *)param_1);
  operator_delete(param_1);
  return;
}



void FUN_001094f4(void)

{
  undefined8 *puVar1;
  
  puVar1 = (undefined8 *)__cxa_allocate_exception(8);
  *puVar1 = &PTR_FUN_00134890;
                    // WARNING: Subroutine does not return
  __cxa_throw(puVar1,&PTR_PTR____si_class_type_info_00135840,FUN_00109474);
}



void FUN_00109524(void)

{
  undefined8 *puVar1;
  
  puVar1 = (undefined8 *)__cxa_allocate_exception(8);
  *puVar1 = &PTR_FUN_001348c0;
                    // WARNING: Subroutine does not return
  __cxa_throw(puVar1,&PTR_PTR____si_class_type_info_00135858,FUN_00109484);
}



undefined8 * __cxa_allocate_exception(long param_1)

{
  uint uVar1;
  int iVar2;
  undefined8 *puVar3;
  ulong uVar4;
  long extraout_x1;
  
  puVar3 = (undefined8 *)malloc(param_1 + 0x80U);
  if (puVar3 == (undefined8 *)0x0) {
                    // try { // try from 001095b4 to 001095b7 has its CatchHandler @ 0010962c
    iVar2 = pthread_mutex_lock((pthread_mutex_t *)&DAT_00137ca0);
    if (iVar2 != 0) {
                    // WARNING: Subroutine does not return
                    // try { // try from 00109634 to 00109637 has its CatchHandler @ 0010962c
      FUN_001094f4();
    }
    if (0x400 < param_1 + 0x80U) {
                    // WARNING: Subroutine does not return
      std::terminate();
    }
    uVar1 = 0;
    uVar4 = DAT_00147cd0;
    while ((uVar4 & 1) != 0) {
      uVar1 = uVar1 + 1;
      uVar4 = uVar4 >> 1;
      if (uVar1 == 0x40) {
                    // WARNING: Subroutine does not return
        std::terminate();
      }
    }
    DAT_00147cd0 = 1L << ((ulong)uVar1 & 0x3f) | DAT_00147cd0;
    puVar3 = (undefined8 *)(&DAT_00137cd0 + (ulong)uVar1 * 0x400);
                    // try { // try from 00109614 to 0010961f has its CatchHandler @ 00109620
    iVar2 = pthread_mutex_unlock((pthread_mutex_t *)&DAT_00137ca0);
    if (iVar2 != 0) {
      FUN_00109524();
                    // catch() { ... } // from try @ 00109614 with catch @ 00109620
      if (extraout_x1 != -1) {
                    // WARNING: Subroutine does not return
        _Unwind_Resume();
      }
                    // WARNING: Subroutine does not return
      __cxa_call_unexpected();
    }
  }
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



void __cxa_free_exception(undefined *param_1)

{
  int iVar1;
  long extraout_x1;
  
  if ((param_1 < &DAT_00137cd0) || ((undefined *)0x147ccf < param_1)) {
    free(param_1 + -0x80);
    return;
  }
                    // try { // try from 00109680 to 00109683 has its CatchHandler @ 001096bc
  iVar1 = pthread_mutex_lock((pthread_mutex_t *)&DAT_00137ca0);
  if (iVar1 != 0) {
                    // WARNING: Subroutine does not return
                    // try { // try from 001096b8 to 001096bb has its CatchHandler @ 001096bc
    FUN_001094f4();
  }
  DAT_00147cd0 = DAT_00147cd0 &
                 (1L << ((ulong)(param_1 + -0x137cd0) >> 10 & 0x3f) ^ 0xffffffffffffffffU);
                    // try { // try from 001096a4 to 001096a7 has its CatchHandler @ 001096cc
  iVar1 = pthread_mutex_unlock((pthread_mutex_t *)&DAT_00137ca0);
  if (iVar1 == 0) {
    return;
  }
                    // try { // try from 001096c8 to 001096cb has its CatchHandler @ 001096cc
  FUN_00109524();
                    // catch() { ... } // from try @ 00109680 with catch @ 001096bc
                    // catch() { ... } // from try @ 001096b8 with catch @ 001096bc
                    // catch() { ... } // from try @ 001096a4 with catch @ 001096cc
                    // catch() { ... } // from try @ 001096c8 with catch @ 001096cc
  if (extraout_x1 != -1) {
                    // WARNING: Subroutine does not return
    _Unwind_Resume();
  }
                    // WARNING: Subroutine does not return
  __cxa_call_unexpected();
}



undefined8 * __cxa_allocate_dependent_exception(void)

{
  uint uVar1;
  int iVar2;
  undefined8 *puVar3;
  ulong uVar4;
  
  puVar3 = (undefined8 *)malloc(0x70);
  if (puVar3 != (undefined8 *)0x0) {
LAB_001096f0:
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
                    // try { // try from 00109724 to 00109727 has its CatchHandler @ 0010979c
  iVar2 = pthread_mutex_lock((pthread_mutex_t *)&DAT_00137ca0);
  if (iVar2 == 0) {
    uVar1 = 0;
    uVar4 = DAT_00136090;
    while ((uVar4 & 1) != 0) {
      uVar1 = uVar1 + 1;
      uVar4 = uVar4 >> 1;
      if (uVar1 == 0x40) {
                    // WARNING: Subroutine does not return
        std::terminate();
      }
    }
    DAT_00136090 = 1L << ((ulong)uVar1 & 0x3f) | DAT_00136090;
    puVar3 = (undefined8 *)(&DAT_001360a0 + (ulong)uVar1 * 0x70);
                    // try { // try from 00109780 to 0010978b has its CatchHandler @ 00109790
    iVar2 = pthread_mutex_unlock((pthread_mutex_t *)&DAT_00137ca0);
    if (iVar2 == 0) goto LAB_001096f0;
    FUN_00109524();
  }
                    // WARNING: Subroutine does not return
                    // try { // try from 0010978c to 0010978f has its CatchHandler @ 0010979c
  FUN_001094f4();
}



void __cxa_free_dependent_exception(undefined *param_1)

{
  int iVar1;
  long extraout_x1;
  
  if ((param_1 < &DAT_001360a0) || ((undefined *)0x137c9f < param_1)) {
    free(param_1);
    return;
  }
                    // try { // try from 00109800 to 00109803 has its CatchHandler @ 0010983c
  iVar1 = pthread_mutex_lock((pthread_mutex_t *)&DAT_00137ca0);
  if (iVar1 != 0) {
                    // WARNING: Subroutine does not return
                    // try { // try from 00109838 to 0010983b has its CatchHandler @ 0010983c
    FUN_001094f4();
  }
  DAT_00136090 = DAT_00136090 &
                 (1L << (SUB168(ZEXT416((int)param_1 - 0x1360a0U >> 4) * ZEXT816(0x2492492492492494)
                                ,8) & 0x3f) ^ 0xffffffffffffffffU);
                    // try { // try from 00109824 to 00109827 has its CatchHandler @ 0010984c
  iVar1 = pthread_mutex_unlock((pthread_mutex_t *)&DAT_00137ca0);
  if (iVar1 == 0) {
    return;
  }
                    // try { // try from 00109848 to 0010984b has its CatchHandler @ 0010984c
  FUN_00109524();
                    // catch() { ... } // from try @ 00109800 with catch @ 0010983c
                    // catch() { ... } // from try @ 00109838 with catch @ 0010983c
                    // catch() { ... } // from try @ 00109824 with catch @ 0010984c
                    // catch() { ... } // from try @ 00109848 with catch @ 0010984c
  if (extraout_x1 != -1) {
                    // WARNING: Subroutine does not return
    _Unwind_Resume();
  }
                    // WARNING: Subroutine does not return
  __cxa_call_unexpected();
}



void FUN_00109854(long *param_1)

{
  if ((param_1 != (long *)0x0) && (__cxa_begin_catch(), *param_1 + 0xb8b1aabcbcd4d500U < 2)) {
                    // WARNING: Subroutine does not return
    __cxxabiv1::__terminate((_func_void *)param_1[-7]);
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
    p_Var3 = DAT_00147cd8;
    cVar1 = '\x01';
    bVar2 = (bool)ExclusiveMonitorPass(0x147cd8,0x10);
    if (bVar2) {
      cVar1 = ExclusiveMonitorsStatus();
      DAT_00147cd8 = param_1;
    }
  } while (cVar1 != '\0');
  return p_Var3;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked
// std::get_new_handler()

undefined8 std::get_new_handler(void)

{
  return DAT_00147cd8;
}



// WARNING: Removing unreachable block (ram,0x001099b4)
// WARNING: Removing unreachable block (ram,0x00109a48)
// WARNING: Removing unreachable block (ram,0x001099c8)
// __gnu_cxx::__verbose_terminate_handler()

void __gnu_cxx::__verbose_terminate_handler(void)

{
  long lVar1;
  char *pcVar2;
  char *__s;
  size_t __n;
  
  if (DAT_00147ce0 == '\0') {
    DAT_00147ce0 = '\x01';
    lVar1 = __cxa_current_exception_type();
    if (lVar1 != 0) {
      pcVar2 = *(char **)(lVar1 + 8);
      if (*pcVar2 == '*') {
        pcVar2 = pcVar2 + 1;
      }
      __s = (char *)__cxa_demangle(pcVar2,0,0);
      fwrite("terminate called after throwing an instance of \'",1,0x30,(FILE *)0x148188);
      fputs(pcVar2,(FILE *)0x148188);
      do {
        fwrite(&DAT_0011ee10,1,2,(FILE *)0x148188);
                    // try { // try from 0010997c to 0010997f has its CatchHandler @ 001099c0
        __cxa_rethrow();
        fputs(__s,(FILE *)0x148188);
      } while( true );
    }
    pcVar2 = "terminate called without an active exception\n";
    __n = 0x2d;
  }
  else {
    __n = 0x1d;
    pcVar2 = "terminate called recursively\n";
  }
  fwrite(pcVar2,1,__n,(FILE *)0x148188);
                    // WARNING: Subroutine does not return
  abort();
}



void FUN_00109a54(void *param_1)

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



void FUN_00109a78(void)

{
  undefined8 *puVar1;
  
  puVar1 = (undefined8 *)__cxa_allocate_exception(8);
  *puVar1 = &PTR__bad_alloc_00135820;
                    // WARNING: Subroutine does not return
  __cxa_throw(puVar1,&std::bad_alloc::typeinfo,std::bad_alloc::~bad_alloc);
}



void FUN_00109aac(undefined8 param_1)

{
  undefined8 uVar1;
  undefined auStack_18 [8];
  undefined auStack_10 [8];
  long local_8;
  
  uVar1 = __cxa_allocate_exception(0x10);
                    // try { // try from 00109ad8 to 00109adb has its CatchHandler @ 00109b24
  FUN_001093b0(&local_8,param_1,auStack_18);
                    // try { // try from 00109ae4 to 00109ae7 has its CatchHandler @ 00109b38
  FUN_001090bc(uVar1,&local_8);
  if ((undefined *)(local_8 + -0x18) != &DAT_00136070) {
    FUN_00109a54((undefined *)(local_8 + -0x18),auStack_10);
  }
                    // WARNING: Subroutine does not return
  __cxa_throw(uVar1,&PTR_PTR____si_class_type_info_00135730,FUN_00108dd4);
}



void FUN_00109b60(undefined8 param_1)

{
  undefined8 uVar1;
  undefined auStack_18 [8];
  undefined auStack_10 [8];
  long local_8;
  
  uVar1 = __cxa_allocate_exception(0x10);
                    // try { // try from 00109b8c to 00109b8f has its CatchHandler @ 00109bd8
  FUN_001093b0(&local_8,param_1,auStack_18);
                    // try { // try from 00109b98 to 00109b9b has its CatchHandler @ 00109bec
  FUN_001090fc(uVar1,&local_8);
  if ((undefined *)(local_8 + -0x18) != &DAT_00136070) {
    FUN_00109a54((undefined *)(local_8 + -0x18),auStack_10);
  }
                    // WARNING: Subroutine does not return
  __cxa_throw(uVar1,&PTR_PTR____si_class_type_info_00135778,FUN_00108ec4);
}



char * FUN_00109c14(void)

{
  return "generic";
}



char * FUN_00109c20(void)

{
  return "system";
}



undefined  [16] FUN_00109c2c(undefined8 param_1,ulong param_2)

{
  undefined auVar1 [16];
  
  auVar1._0_8_ = param_2 & 0xffffffff;
  auVar1._8_8_ = param_1;
  return auVar1;
}



bool FUN_00109c3c(long param_1,int *param_2,int param_3)

{
  if (*(long *)(param_2 + 2) != param_1) {
    return false;
  }
  return *param_2 == param_3;
}



void FUN_00109c68(void)

{
  return;
}



void FUN_00109c6c(void)

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



void FUN_00109c78(undefined8 param_1,int param_2)

{
  strerror(param_2);
  FUN_001093b0();
  return;
}



void FUN_00109cb0(undefined8 param_1,int param_2)

{
  strerror(param_2);
  FUN_001093b0();
  return;
}



bool FUN_00109ce8(long *param_1,int param_2,int *param_3)

{
  long extraout_x1;
  
  if (*(code **)(*param_1 + 0x20) == FUN_00109c2c) {
    if (*(long **)(param_3 + 2) == param_1) {
LAB_00109d48:
      return *param_3 == param_2;
    }
  }
  else {
    param_2 = (**(code **)(*param_1 + 0x20))();
    if (*(long *)(param_3 + 2) == extraout_x1) goto LAB_00109d48;
  }
  return false;
}



// std::bad_cast::what() const

char * std::bad_cast::what(void)

{
  return "std::bad_cast";
}



// std::bad_cast::~bad_cast()

void __thiscall std::bad_cast::~bad_cast(bad_cast *this)

{
  *(undefined ***)this = &PTR__bad_cast_001358e0;
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
  *(undefined ***)this = &PTR__bad_typeid_00135930;
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



long FUN_00109de4(long param_1,undefined4 param_2,long param_3,long param_4)

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
  case 0x35:
  case 0x36:
  case 0x37:
  case 0x38:
  case 0x39:
  case 0x3b:
  case 0x3c:
  case 0x3e:
  case 0x4a:
  case 0x4b:
    if (param_3 == 0) {
      return 0;
    }
    if (param_4 == 0) {
      return 0;
    }
    iVar2 = *(int *)(param_1 + 0x28);
    if (*(int *)(param_1 + 0x2c) <= iVar2) {
      return 0;
    }
    goto LAB_00109e2c;
  default:
    goto LAB_00109df4;
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
  case 0x3a:
  case 0x3d:
  case 0x41:
  case 0x42:
  case 0x43:
  case 0x47:
  case 0x48:
  case 0x49:
    if (param_3 == 0) {
      return 0;
    }
    break;
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
    break;
  case 0x2a:
  case 0x30:
    if (param_4 == 0) {
      return 0;
    }
  }
  iVar2 = *(int *)(param_1 + 0x28);
  if (iVar2 < *(int *)(param_1 + 0x2c)) {
LAB_00109e2c:
    *(int *)(param_1 + 0x28) = iVar2 + 1;
    lVar1 = *(long *)(param_1 + 0x20) + (long)iVar2 * 0x18;
    if (lVar1 != 0) {
      *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar2 * 0x18) = param_2;
      *(long *)(lVar1 + 8) = param_3;
      *(long *)(lVar1 + 0x10) = param_4;
      return lVar1;
    }
  }
LAB_00109df4:
  return 0;
}



long FUN_00109e98(long param_1,long param_2,int param_3)

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



int ** FUN_00109f00(long param_1,int **param_2,int param_3)

{
  int iVar1;
  char cVar2;
  int *piVar3;
  char *pcVar4;
  int **ppiVar5;
  undefined4 uVar6;
  
  pcVar4 = *(char **)(param_1 + 0x18);
  cVar2 = *pcVar4;
  ppiVar5 = param_2;
  do {
    if ((cVar2 == 'V') || (cVar2 == 'r')) {
      *(char **)(param_1 + 0x18) = pcVar4 + 1;
      if (cVar2 != 'r') {
        if (cVar2 != 'V') goto LAB_00109f64;
        uVar6 = 0x1d;
        if (param_3 == 0) {
          uVar6 = 0x1a;
        }
        *(int *)(param_1 + 0x50) = *(int *)(param_1 + 0x50) + 9;
        goto LAB_00109f78;
      }
      uVar6 = 0x1c;
      if (param_3 == 0) {
        uVar6 = 0x19;
      }
      *(int *)(param_1 + 0x50) = *(int *)(param_1 + 0x50) + 9;
      piVar3 = (int *)FUN_00109de4(param_1,uVar6,0,0);
      *ppiVar5 = piVar3;
    }
    else {
      if (cVar2 != 'K') {
        if (((param_3 == 0) && (cVar2 == 'F')) && (param_2 != ppiVar5)) {
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
          } while (param_2 != ppiVar5);
        }
        return ppiVar5;
      }
      *(char **)(param_1 + 0x18) = pcVar4 + 1;
LAB_00109f64:
      uVar6 = 0x1e;
      if (param_3 == 0) {
        uVar6 = 0x1b;
      }
      *(int *)(param_1 + 0x50) = *(int *)(param_1 + 0x50) + 6;
LAB_00109f78:
      piVar3 = (int *)FUN_00109de4(param_1,uVar6,0,0);
      *ppiVar5 = piVar3;
    }
    if (piVar3 == (int *)0x0) {
      return (int **)0x0;
    }
    pcVar4 = *(char **)(param_1 + 0x18);
    ppiVar5 = (int **)(piVar3 + 2);
    cVar2 = *pcVar4;
  } while( true );
}



undefined8 FUN_0010a0ac(long param_1,undefined8 param_2)

{
  char cVar1;
  undefined8 uVar2;
  char *pcVar3;
  
  pcVar3 = *(char **)(param_1 + 0x18);
  cVar1 = *pcVar3;
  if (cVar1 == 'O') {
    if (cVar1 != 'R') {
      *(char **)(param_1 + 0x18) = pcVar3 + 1;
      *(int *)(param_1 + 0x50) = *(int *)(param_1 + 0x50) + 3;
      uVar2 = FUN_00109de4(param_1,0x20,param_2,0);
      return uVar2;
    }
  }
  else if (cVar1 != 'R') {
    return param_2;
  }
  *(char **)(param_1 + 0x18) = pcVar3 + 1;
  *(int *)(param_1 + 0x50) = *(int *)(param_1 + 0x50) + 2;
  uVar2 = FUN_00109de4(param_1,0x1f,param_2,0);
  return uVar2;
}



long FUN_0010a118(long param_1,int param_2)

{
  long lVar1;
  undefined4 uVar2;
  byte bVar3;
  uint uVar4;
  long lVar5;
  uint uVar6;
  undefined *puVar7;
  uint uVar8;
  int iVar9;
  char *pcVar10;
  uint uVar11;
  int iVar12;
  byte *pbVar13;
  long lVar14;
  int iVar15;
  undefined8 uVar16;
  long lVar17;
  
  pcVar10 = *(char **)(param_1 + 0x18);
  if (*pcVar10 != 'S') {
    return 0;
  }
  *(char **)(param_1 + 0x18) = pcVar10 + 1;
  uVar6 = (uint)(byte)pcVar10[1];
  if (pcVar10[1] == 0) {
LAB_0010a1e8:
    uVar11 = *(uint *)(param_1 + 0x10) >> 3 & 1;
    if (uVar11 < (param_2 != 0)) {
      uVar11 = (uint)((byte)(**(char **)(param_1 + 0x18) + 0xbdU) < 2);
    }
    if (uVar6 == 0x74) {
      puVar7 = &UNK_00134da0;
    }
    else if (uVar6 == 0x61) {
      puVar7 = &UNK_00134dd8;
    }
    else if (uVar6 == 0x62) {
      puVar7 = &UNK_00134e10;
    }
    else if (uVar6 == 0x73) {
      puVar7 = &UNK_00134e48;
    }
    else if (uVar6 == 0x69) {
      puVar7 = &UNK_00134e80;
    }
    else if (uVar6 == 0x6f) {
      puVar7 = &UNK_00134eb8;
    }
    else {
      if (uVar6 != 100) {
        return 0;
      }
      puVar7 = &UNK_00134ef0;
    }
    lVar5 = *(long *)(puVar7 + 0x28);
    if (lVar5 == 0) {
      iVar15 = *(int *)(param_1 + 0x2c);
      iVar9 = *(int *)(param_1 + 0x28);
    }
    else {
      iVar9 = *(int *)(param_1 + 0x28);
      iVar15 = *(int *)(param_1 + 0x2c);
      uVar2 = *(undefined4 *)(puVar7 + 0x30);
      lVar17 = 0;
      if (iVar9 < iVar15) {
        lVar14 = (long)iVar9;
        iVar9 = iVar9 + 1;
        *(int *)(param_1 + 0x28) = iVar9;
        lVar1 = *(long *)(param_1 + 0x20) + lVar14 * 0x18;
        if (lVar1 != 0) {
          *(undefined4 *)(*(long *)(param_1 + 0x20) + lVar14 * 0x18) = 0x18;
          *(long *)(lVar1 + 8) = lVar5;
          *(undefined4 *)(lVar1 + 0x10) = uVar2;
          lVar17 = lVar1;
        }
      }
      *(long *)(param_1 + 0x48) = lVar17;
    }
    if (uVar11 == 0) {
      uVar16 = *(undefined8 *)(puVar7 + 8);
      iVar12 = *(int *)(puVar7 + 0x10);
    }
    else {
      uVar16 = *(undefined8 *)(puVar7 + 0x18);
      iVar12 = *(int *)(puVar7 + 0x20);
    }
    *(int *)(param_1 + 0x50) = *(int *)(param_1 + 0x50) + iVar12;
    if (iVar15 <= iVar9) {
      return 0;
    }
    *(int *)(param_1 + 0x28) = iVar9 + 1;
    lVar5 = *(long *)(param_1 + 0x20) + (long)iVar9 * 0x18;
    if (lVar5 != 0) {
      *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar9 * 0x18) = 0x18;
      *(undefined8 *)(lVar5 + 8) = uVar16;
      *(int *)(lVar5 + 0x10) = iVar12;
      return lVar5;
    }
    return 0;
  }
  *(char **)(param_1 + 0x18) = pcVar10 + 2;
  bVar3 = pcVar10[1];
  uVar6 = (uint)bVar3;
  uVar11 = bVar3 - 0x30;
  if (((uVar11 & 0xff) < 10) || (bVar3 == 0x5f)) {
    if (bVar3 == 0x5f) {
      uVar4 = 0;
      goto LAB_0010a258;
    }
  }
  else if (0x19 < (byte)(bVar3 + 0xbf)) goto LAB_0010a1e8;
  uVar8 = 0;
  do {
    uVar4 = (uVar6 + uVar8 * 0x24) - 0x37;
    if ((uVar11 & 0xff) < 10) {
      uVar4 = (uVar6 + uVar8 * 0x24) - 0x30;
    }
    else if (0x19 < (uVar6 - 0x41 & 0xff)) {
      return 0;
    }
    if (uVar4 < uVar8) {
      return 0;
    }
    pbVar13 = *(byte **)(param_1 + 0x18);
    uVar6 = (uint)*pbVar13;
    if (uVar6 != 0) {
      *(byte **)(param_1 + 0x18) = pbVar13 + 1;
      uVar6 = (uint)*pbVar13;
      if (uVar6 == 0x5f) break;
    }
    uVar11 = uVar6 - 0x30;
    uVar8 = uVar4;
  } while( true );
  uVar4 = uVar4 + 1;
LAB_0010a258:
  if (*(uint *)(param_1 + 0x38) <= uVar4) {
    return 0;
  }
  lVar5 = *(long *)(*(long *)(param_1 + 0x30) + (ulong)uVar4 * 8);
  *(int *)(param_1 + 0x40) = *(int *)(param_1 + 0x40) + 1;
  return lVar5;
}



void FUN_0010a3c8(int *param_1,int *param_2,undefined4 *param_3)

{
  int *piVar1;
  
  if (param_3 == (undefined4 *)0x0) {
switchD_0010a41c_caseD_5:
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
    case 0x41:
    case 0x47:
    case 0x48:
    case 0x49:
    case 0x4a:
    case 0x4b:
switchD_0010a41c_caseD_1:
      piVar1 = *(int **)(param_3 + 2);
      break;
    case 4:
      *param_1 = *param_1 + 1;
      piVar1 = *(int **)(param_3 + 2);
      break;
    default:
      goto switchD_0010a41c_caseD_5;
    case 7:
    case 8:
    case 0x32:
      param_3 = *(undefined4 **)(param_3 + 4);
      goto joined_r0x0010a43c;
    case 0x23:
    case 0x24:
      piVar1 = *(int **)(param_3 + 2);
      if (*piVar1 == 5) {
        *param_2 = *param_2 + 1;
        goto switchD_0010a41c_caseD_1;
      }
      break;
    case 0x42:
    case 0x43:
    case 0x44:
    case 0x45:
      param_3 = *(undefined4 **)(param_3 + 2);
      goto joined_r0x0010a43c;
    }
    FUN_0010a3c8(param_1,param_2,piVar1);
    param_3 = *(undefined4 **)(param_3 + 4);
joined_r0x0010a43c:
    if (param_3 == (undefined4 *)0x0) {
      return;
    }
  } while( true );
}



void FUN_0010a494(undefined *param_1,undefined param_2)

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



long FUN_0010a50c(byte **param_1)

{
  bool bVar1;
  byte *pbVar2;
  ulong uVar3;
  ulong uVar4;
  byte bVar5;
  ulong uVar6;
  
  pbVar2 = *param_1;
  bVar5 = *pbVar2;
  bVar1 = bVar5 == 0x6e;
  if (bVar1) {
    *param_1 = pbVar2 + 1;
    uVar6 = 0xffffffffffffffff;
    bVar5 = pbVar2[1];
  }
  else {
    uVar6 = 0;
  }
  uVar3 = 0;
  if ((byte)(bVar5 - 0x30) < 10) {
    pbVar2 = *param_1;
    uVar3 = 0;
    do {
      pbVar2 = pbVar2 + 1;
      *param_1 = pbVar2;
      uVar4 = (ulong)bVar5;
      bVar5 = *pbVar2;
      uVar3 = (uVar4 + uVar3 * 10) - 0x30;
    } while ((byte)(bVar5 - 0x30) < 10);
  }
  return (uVar3 ^ uVar6) + (ulong)bVar1;
}



long FUN_0010a590(long param_1)

{
  long lVar1;
  char *pcVar2;
  
  pcVar2 = *(char **)(param_1 + 0x18);
  if (*pcVar2 != '_') {
    if (*pcVar2 != 'n') {
      lVar1 = FUN_0010a50c(param_1 + 0x18);
      lVar1 = lVar1 + 1;
      pcVar2 = *(char **)(param_1 + 0x18);
      if (*pcVar2 == '_') goto LAB_0010a5e8;
    }
    return -1;
  }
  lVar1 = 0;
LAB_0010a5e8:
  *(char **)(param_1 + 0x18) = pcVar2 + 1;
  return lVar1;
}



long FUN_0010a5fc(long param_1)

{
  long lVar1;
  int iVar2;
  long lVar3;
  
  if (**(char **)(param_1 + 0x18) == 'T') {
    *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
    lVar3 = FUN_0010a590();
    if (-1 < lVar3) {
      iVar2 = *(int *)(param_1 + 0x28);
      *(int *)(param_1 + 0x40) = *(int *)(param_1 + 0x40) + 1;
      if (iVar2 < *(int *)(param_1 + 0x2c)) {
        *(int *)(param_1 + 0x28) = iVar2 + 1;
        lVar1 = *(long *)(param_1 + 0x20) + (long)iVar2 * 0x18;
        if (lVar1 != 0) {
          *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar2 * 0x18) = 5;
          *(long *)(lVar1 + 8) = lVar3;
          return lVar1;
        }
      }
    }
  }
  return 0;
}



ulong FUN_0010a69c(long param_1)

{
  ulong uVar1;
  
  if (**(char **)(param_1 + 0x18) != '_') {
    return 1;
  }
  *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
  uVar1 = FUN_0010a50c();
  return ~uVar1 >> 0x3f;
}



undefined8 FUN_0010a6e4(long param_1)

{
  char cVar1;
  int iVar2;
  int iVar3;
  ulong uVar4;
  undefined8 uVar5;
  long lVar6;
  void *__s1;
  
  uVar4 = FUN_0010a50c(param_1 + 0x18);
  if ((long)uVar4 < 1) {
    uVar5 = 0;
  }
  else {
    iVar2 = (int)uVar4;
    lVar6 = (long)iVar2;
    __s1 = *(void **)(param_1 + 0x18);
    if (*(long *)(param_1 + 8) - (long)__s1 < lVar6) {
      uVar5 = 0;
    }
    else {
      *(long *)(param_1 + 0x18) = (long)__s1 + lVar6;
      if (((*(uint *)(param_1 + 0x10) >> 2 & 1) != 0) && (*(char *)((long)__s1 + lVar6) == '$')) {
        *(long *)(param_1 + 0x18) = (long)__s1 + lVar6 + 1;
      }
      if ((((iVar2 < 10) || (iVar3 = memcmp(__s1,"_GLOBAL_",8), iVar3 != 0)) ||
          ((cVar1 = *(char *)((long)__s1 + 8), cVar1 != '_' && cVar1 != '.' && (cVar1 != '$')))) ||
         (*(char *)((long)__s1 + 9) != 'N')) {
        uVar5 = FUN_00109e98(param_1,__s1,uVar4 & 0xffffffff);
      }
      else {
        *(int *)(param_1 + 0x50) = (*(int *)(param_1 + 0x50) + 0x16) - iVar2;
        uVar5 = FUN_00109e98(param_1,"(anonymous namespace)",0x15);
      }
    }
    *(undefined8 *)(param_1 + 0x48) = uVar5;
  }
  return uVar5;
}



undefined8 FUN_0010a7f8(long param_1,uint param_2)

{
  byte *pbVar1;
  
  if (param_2 == 0) {
    pbVar1 = *(byte **)(param_1 + 0x18);
    if (*pbVar1 == 0) {
      return 0;
    }
    *(byte **)(param_1 + 0x18) = pbVar1 + 1;
    param_2 = (uint)*pbVar1;
  }
  if (param_2 == 0x68) {
    FUN_0010a50c(param_1 + 0x18);
  }
  else {
    if (param_2 != 0x76) {
      return 0;
    }
    FUN_0010a50c(param_1 + 0x18);
    if (**(char **)(param_1 + 0x18) != '_') {
      return 0;
    }
    *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
    FUN_0010a50c(param_1 + 0x18);
  }
  if (**(char **)(param_1 + 0x18) != '_') {
    return 0;
  }
  *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
  return 1;
}



int * FUN_0010a89c(long param_1,ulong *param_2)

{
  uint uVar1;
  ulong uVar2;
  int *piVar3;
  int iVar4;
  
  if (*(long *)(param_1 + 0x120) == 0) {
    *(undefined4 *)(param_1 + 0x130) = 1;
    piVar3 = (int *)0x0;
  }
  else {
    piVar3 = *(int **)(*(long *)(*(long *)(param_1 + 0x120) + 8) + 0x10);
    uVar2 = *param_2 & 0xffffffff;
    if (piVar3 != (int *)0x0) {
      if (*piVar3 != 0x2f) {
        return (int *)0x0;
      }
      iVar4 = (int)*param_2;
      if (iVar4 < 1) {
        if (iVar4 != 0) {
          return (int *)0x0;
        }
      }
      else {
        do {
          piVar3 = *(int **)(piVar3 + 4);
          uVar1 = (int)uVar2 - 1;
          uVar2 = (ulong)uVar1;
          if (piVar3 == (int *)0x0) {
            return (int *)0x0;
          }
          if (*piVar3 != 0x2f) {
            return (int *)0x0;
          }
        } while (uVar1 != 0);
      }
      return *(int **)(piVar3 + 2);
    }
  }
  return piVar3;
}



int * FUN_0010a924(undefined8 param_1,undefined4 *param_2)

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
      case 0x3f:
      case 0x44:
      case 0x46:
      case 0x49:
      case 0x4a:
        goto LAB_0010a970;
      case 5:
        piVar1 = (int *)FUN_0010a89c(param_1,param_2 + 2);
        if ((piVar1 != (int *)0x0) && (*piVar1 == 0x2f)) {
          return piVar1;
        }
        goto LAB_0010a970;
      case 7:
      case 8:
      case 0x32:
        goto switchD_0010a98c_caseD_7;
      }
      piVar1 = (int *)FUN_0010a924(param_1,*(undefined8 *)(param_2 + 2));
      if (piVar1 != (int *)0x0) {
        return piVar1;
      }
switchD_0010a98c_caseD_7:
      param_2 = *(undefined4 **)(param_2 + 4);
    } while (param_2 != (undefined4 *)0x0);
  }
LAB_0010a970:
  return (int *)0x0;
}



void FUN_0010a9bc(void *param_1,size_t param_2,void **param_3)

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



void FUN_0010aabc(char *param_1,char *param_2)

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



void FUN_0010ab68(char *param_1,undefined8 param_2)

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



int * FUN_0010ac34(long param_1)

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
  byte *pbVar20;
  byte *pbVar21;
  int *piVar22;
  byte *pbVar23;
  char *pcVar24;
  int *local_8;
  
  pbVar21 = *(byte **)(param_1 + 0x18);
  bVar7 = *pbVar21;
  if ((bVar7 == 0x56 || bVar7 == 0x72) || (uVar9 = (uint)bVar7, uVar9 == 0x4b)) {
    ppiVar11 = (int **)FUN_00109f00(param_1,&local_8,0);
    if (ppiVar11 == (int **)0x0) {
      return (int *)0x0;
    }
    if (**(char **)(param_1 + 0x18) == 'F') {
      piVar12 = (int *)FUN_0010c510(param_1);
      *ppiVar11 = piVar12;
    }
    else {
      piVar12 = (int *)FUN_0010ac34();
      *ppiVar11 = piVar12;
    }
    if (piVar12 == (int *)0x0) {
      return (int *)0x0;
    }
    if (*piVar12 - 0x1fU < 2) {
      piVar22 = *(int **)(piVar12 + 2);
      *(int **)(piVar12 + 2) = local_8;
      local_8 = *ppiVar11;
      *ppiVar11 = piVar22;
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
    local_8 = (int *)FUN_0010ed9c(param_1);
    break;
  default:
    goto switchD_0010acb0_caseD_3a;
  case 0x41:
    pbVar20 = pbVar21 + 1;
    *(byte **)(param_1 + 0x18) = pbVar20;
    if (pbVar21[1] == 0x5f) {
      lVar14 = 0;
    }
    else {
      if ((byte)(pbVar21[1] - 0x30) < 10) {
        pbVar21 = pbVar21 + 2;
        do {
          pbVar23 = pbVar21;
          *(byte **)(param_1 + 0x18) = pbVar23;
          pbVar21 = pbVar23 + 1;
        } while ((byte)(*pbVar23 - 0x30) < 10);
        lVar14 = FUN_00109e98(param_1,pbVar20,(int)pbVar23 - (int)pbVar20);
joined_r0x0010b788:
        if (lVar14 == 0) goto LAB_0010ae58;
        pbVar20 = *(byte **)(param_1 + 0x18);
      }
      else {
        uVar2 = *(undefined4 *)(param_1 + 0x54);
        *(undefined4 *)(param_1 + 0x54) = 1;
        bVar7 = pbVar21[1];
        if (bVar7 == 0x4c) {
          lVar14 = FUN_0010f980(param_1);
LAB_0010b784:
          *(undefined4 *)(param_1 + 0x54) = uVar2;
          goto joined_r0x0010b788;
        }
        if (bVar7 == 0x54) {
          lVar14 = FUN_0010a5fc(param_1);
          goto LAB_0010b784;
        }
        if (bVar7 == 0x73) {
          if (pbVar21[2] == 0x72) {
            *(byte **)(param_1 + 0x18) = pbVar21 + 3;
            uVar13 = FUN_0010ac34(param_1);
            uVar17 = FUN_0010c75c(param_1);
            if (**(char **)(param_1 + 0x18) == 'I') {
              uVar18 = FUN_0010cbec(param_1);
              uVar17 = FUN_00109de4(param_1,4,uVar17,uVar18);
              lVar14 = FUN_00109de4(param_1,1,uVar13,uVar17);
            }
            else {
              lVar14 = FUN_00109de4(param_1,1,uVar13,uVar17);
            }
          }
          else {
            if (pbVar21[2] != 0x70) goto LAB_0010b728;
            *(byte **)(param_1 + 0x18) = pbVar21 + 3;
            uVar13 = FUN_00111c88(param_1);
            lVar14 = FUN_00109de4(param_1,0x49,uVar13,0);
          }
          goto LAB_0010b784;
        }
        if (bVar7 != 0x66) {
          if ((byte)(bVar7 - 0x30) < 10) {
LAB_0010b7fc:
            lVar14 = FUN_0010c75c(param_1);
            if (lVar14 != 0) {
              pbVar20 = *(byte **)(param_1 + 0x18);
              if (*pbVar20 != 0x49) {
                *(undefined4 *)(param_1 + 0x54) = uVar2;
                goto LAB_0010ae48;
              }
              uVar13 = FUN_0010cbec(param_1);
              lVar14 = FUN_00109de4(param_1,4,lVar14,uVar13);
              goto LAB_0010b784;
            }
          }
          else {
            if (bVar7 == 0x6f) {
              if (pbVar21[2] == 0x6e) {
                *(byte **)(param_1 + 0x18) = pbVar21 + 3;
                goto LAB_0010b7fc;
              }
            }
            else if (((bVar7 == 0x74) || (bVar7 == 0x69)) && (pbVar21[2] == 0x6c)) {
              uVar13 = 0;
              if (bVar7 == 0x74) {
                uVar13 = FUN_0010ac34(param_1);
              }
              *(long *)(param_1 + 0x18) = *(long *)(param_1 + 0x18) + 2;
              uVar17 = FUN_0010fb04(param_1,0x45);
              lVar14 = FUN_00109de4(param_1,0x30,uVar13,uVar17);
              goto LAB_0010b784;
            }
LAB_0010b728:
            piVar12 = (int *)FUN_0010c598(param_1);
            if (piVar12 != (int *)0x0) {
              iVar10 = *piVar12;
              if (iVar10 == 0x31) {
                pcVar24 = **(char ***)(piVar12 + 2);
                *(int *)(param_1 + 0x50) =
                     *(int *)(param_1 + 0x50) + *(int *)(*(char ***)(piVar12 + 2) + 2) + -2;
                iVar10 = strcmp(pcVar24,"st");
                if (iVar10 == 0) {
                  uVar13 = FUN_0010ac34(param_1);
LAB_0010b770:
                  lVar14 = FUN_00109de4(param_1,0x35,piVar12,uVar13);
                  goto LAB_0010b784;
                }
                switch(*(undefined4 *)(*(long *)(piVar12 + 2) + 0x14)) {
                case 0:
                  goto switchD_0010baf0_caseD_0;
                case 1:
                  cVar8 = *pcVar24;
                  if (((cVar8 == 'm') || (cVar8 == 'p')) && (pcVar24[1] == cVar8)) {
                    if (**(char **)(param_1 + 0x18) != '_') {
                      uVar13 = FUN_00111c88(param_1);
                      uVar13 = FUN_00109de4(param_1,0x37,uVar13,uVar13);
                      goto LAB_0010b770;
                    }
                    *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
                  }
                  goto switchD_0010baf0_caseD_1;
                case 2:
                  goto switchD_0010bd1c_caseD_2;
                case 3:
                  goto switchD_0010bd1c_caseD_3;
                }
              }
              else if (iVar10 == 0x32) {
                switch(piVar12[2]) {
                case 0:
switchD_0010baf0_caseD_0:
                  lVar14 = FUN_00109de4(param_1,0x34,piVar12,0);
                  goto LAB_0010b784;
                case 1:
                  goto switchD_0010baf0_caseD_1;
                case 2:
                  pcVar24 = (char *)0x0;
switchD_0010bd1c_caseD_2:
                  if (((**(char ***)(piVar12 + 2))[1] == 'c') &&
                     ((cVar8 = ***(char ***)(piVar12 + 2), (byte)(cVar8 + 0x8eU) < 2 ||
                      ((byte)(cVar8 + 0x9dU) < 2)))) {
                    uVar13 = FUN_0010ac34(param_1);
                  }
                  else {
                    uVar13 = FUN_00111c88(param_1);
                  }
                  iVar10 = strcmp(pcVar24,"cl");
                  if (iVar10 == 0) {
                    uVar17 = FUN_0010fb04(param_1,0x45);
                  }
                  else {
                    iVar10 = strcmp(pcVar24,"dt");
                    if ((iVar10 == 0) || (iVar10 = strcmp(pcVar24,"pt"), iVar10 == 0)) {
                      uVar17 = FUN_0010c75c(param_1);
                      if (**(char **)(param_1 + 0x18) == 'I') {
                        uVar18 = FUN_0010cbec(param_1);
                        uVar17 = FUN_00109de4(param_1,4,uVar17,uVar18);
                      }
                    }
                    else {
                      uVar17 = FUN_00111c88(param_1);
                    }
                  }
                  uVar13 = FUN_00109de4(param_1,0x37,uVar13,uVar17);
                  lVar14 = FUN_00109de4(param_1,0x36,piVar12,uVar13);
                  goto LAB_0010b784;
                case 3:
                  pcVar24 = (char *)0x0;
switchD_0010bd1c_caseD_3:
                  iVar10 = strcmp(pcVar24,"qu");
                  if (iVar10 == 0) {
                    uVar13 = FUN_00111c88(param_1);
                    uVar17 = FUN_00111c88(param_1);
                    uVar18 = FUN_00111c88(param_1);
LAB_0010bb98:
                    uVar17 = FUN_00109de4(param_1,0x3a,uVar17,uVar18);
                    uVar13 = FUN_00109de4(param_1,0x39,uVar13,uVar17);
                    lVar14 = FUN_00109de4(param_1,0x38,piVar12,uVar13);
                    goto LAB_0010b784;
                  }
                  if ((*pcVar24 == 'n') && ((pcVar24[1] == 'a' || (pcVar24[1] == 'w')))) {
                    uVar13 = FUN_0010fb04(param_1,0x5f);
                    uVar17 = FUN_0010ac34(param_1);
                    pcVar24 = *(char **)(param_1 + 0x18);
                    cVar8 = *pcVar24;
                    if (cVar8 == 'E') {
                      uVar18 = 0;
                      *(char **)(param_1 + 0x18) = pcVar24 + 1;
                      goto LAB_0010bb98;
                    }
                    if (cVar8 == 'p') {
                      if (pcVar24[1] == 'i') {
                        *(char **)(param_1 + 0x18) = pcVar24 + 2;
                        uVar18 = FUN_0010fb04(param_1,0x45);
                        goto LAB_0010bb98;
                      }
                    }
                    else if ((cVar8 == 'i') && (pcVar24[1] == 'l')) {
                      uVar18 = FUN_00111c88(param_1);
                      goto LAB_0010bb98;
                    }
                  }
                }
              }
              else if (iVar10 == 0x33) {
                if (**(char **)(param_1 + 0x18) == '_') {
                  *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
                  uVar13 = FUN_0010fb04(param_1,0x45);
                  goto LAB_0010b770;
                }
switchD_0010baf0_caseD_1:
                uVar13 = FUN_00111c88(param_1);
                goto LAB_0010b770;
              }
            }
          }
switchD_0010baf0_caseD_4:
          *(undefined4 *)(param_1 + 0x54) = uVar2;
          goto LAB_0010ae58;
        }
        if (pbVar21[2] != 0x70) goto LAB_0010b728;
        *(byte **)(param_1 + 0x18) = pbVar21 + 3;
        if (pbVar21[3] == 0x54) {
          iVar10 = 0;
          *(byte **)(param_1 + 0x18) = pbVar21 + 4;
        }
        else {
          iVar10 = FUN_0010a590(param_1);
          iVar10 = iVar10 + 1;
          if (iVar10 == 0) goto switchD_0010baf0_caseD_4;
        }
        iVar6 = *(int *)(param_1 + 0x28);
        if (*(int *)(param_1 + 0x2c) <= iVar6) goto switchD_0010baf0_caseD_4;
        *(int *)(param_1 + 0x28) = iVar6 + 1;
        lVar14 = *(long *)(param_1 + 0x20) + (long)iVar6 * 0x18;
        if (lVar14 == 0) goto switchD_0010baf0_caseD_4;
        *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar6 * 0x18) = 6;
        *(long *)(lVar14 + 8) = (long)iVar10;
        *(undefined4 *)(param_1 + 0x54) = uVar2;
        pbVar20 = *(byte **)(param_1 + 0x18);
      }
LAB_0010ae48:
      if (*pbVar20 != 0x5f) goto LAB_0010ae58;
    }
    *(byte **)(param_1 + 0x18) = pbVar20 + 1;
    uVar13 = FUN_0010ac34(param_1);
    local_8 = (int *)FUN_00109de4(param_1,0x2a,lVar14,uVar13);
    break;
  case 0x43:
    *(byte **)(param_1 + 0x18) = pbVar21 + 1;
    uVar13 = FUN_0010ac34(param_1);
    local_8 = (int *)FUN_00109de4(param_1,0x25,uVar13,0);
    break;
  case 0x44:
    *(byte **)(param_1 + 0x18) = pbVar21 + 1;
    if (pbVar21[1] == 0) {
      return (int *)0x0;
    }
    *(byte **)(param_1 + 0x18) = pbVar21 + 2;
    switch(pbVar21[1]) {
    case 0x46:
      iVar10 = *(int *)(param_1 + 0x28);
      if (*(int *)(param_1 + 0x2c) <= iVar10) {
        uRam0000000000000000 = 0;
                    // WARNING: Treating indirect jump as call
        UNRECOVERED_JUMPTABLE_00 = (code *)SoftwareBreakpoint(1000,0x10b7e8);
        piVar12 = (int *)(*UNRECOVERED_JUMPTABLE_00)();
        return piVar12;
      }
      *(int *)(param_1 + 0x28) = iVar10 + 1;
      local_8 = (int *)(*(long *)(param_1 + 0x20) + (long)iVar10 * 0x18);
      *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar10 * 0x18) = 0x2c;
      bVar1 = (byte)(pbVar21[2] - 0x30) < 10;
      *(ushort *)(local_8 + 4) = (ushort)bVar1;
      if (bVar1) {
        FUN_0010a50c(param_1 + 0x18);
      }
      piVar12 = local_8;
      uVar13 = FUN_0010ac34(param_1);
      *(undefined8 *)(piVar12 + 2) = uVar13;
      if (*(long *)(local_8 + 2) == 0) {
        return (int *)0x0;
      }
      FUN_0010a50c(param_1 + 0x18);
      pcVar24 = *(char **)(param_1 + 0x18);
      uVar19 = 0;
      if (*pcVar24 != '\0') {
        *(char **)(param_1 + 0x18) = pcVar24 + 1;
        uVar19 = (ushort)(*pcVar24 == 's');
      }
      *(ushort *)((long)local_8 + 0x12) = uVar19;
      return local_8;
    default:
      goto switchD_0010acb0_caseD_3a;
    case 0x54:
    case 0x74:
      uVar2 = *(undefined4 *)(param_1 + 0x54);
      *(undefined4 *)(param_1 + 0x54) = 1;
      bVar7 = pbVar21[2];
      if (bVar7 == 0x4c) {
        lVar14 = FUN_0010f980(param_1);
      }
      else if (bVar7 == 0x54) {
        lVar14 = FUN_0010a5fc(param_1);
      }
      else if (bVar7 == 0x73) {
        if (pbVar21[3] == 0x72) {
          *(byte **)(param_1 + 0x18) = pbVar21 + 4;
          uVar13 = FUN_0010ac34(param_1);
          uVar17 = FUN_0010c75c(param_1);
          if (**(char **)(param_1 + 0x18) == 'I') {
            uVar18 = FUN_0010cbec(param_1);
            uVar17 = FUN_00109de4(param_1,4,uVar17,uVar18);
            lVar14 = FUN_00109de4(param_1,1,uVar13,uVar17);
          }
          else {
            lVar14 = FUN_00109de4(param_1,1,uVar13,uVar17);
          }
        }
        else {
          if (pbVar21[3] != 0x70) goto LAB_0010b50c;
          *(byte **)(param_1 + 0x18) = pbVar21 + 4;
          uVar13 = FUN_00111c88(param_1);
          lVar14 = FUN_00109de4(param_1,0x49,uVar13,0);
        }
      }
      else if (bVar7 == 0x66) {
        if (pbVar21[3] != 0x70) goto LAB_0010b50c;
        *(byte **)(param_1 + 0x18) = pbVar21 + 4;
        if (pbVar21[4] == 0x54) {
          iVar10 = 0;
          *(byte **)(param_1 + 0x18) = pbVar21 + 5;
        }
        else {
          iVar10 = FUN_0010a590(param_1);
          iVar10 = iVar10 + 1;
          if (iVar10 == 0) goto LAB_0010bde0;
        }
        iVar6 = *(int *)(param_1 + 0x28);
        if (*(int *)(param_1 + 0x2c) <= iVar6) goto LAB_0010bde0;
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
LAB_0010b914:
          lVar14 = FUN_0010c75c(param_1);
          if (lVar14 != 0) {
            if (**(char **)(param_1 + 0x18) == 'I') {
              uVar13 = FUN_0010cbec(param_1);
              lVar14 = FUN_00109de4(param_1,4,lVar14,uVar13);
            }
            goto switchD_0010bfa8_caseD_4;
          }
        }
        else {
          if (bVar7 == 0x6f) {
            if (pbVar21[3] == 0x6e) {
              *(byte **)(param_1 + 0x18) = pbVar21 + 4;
              goto LAB_0010b914;
            }
          }
          else if (((bVar7 == 0x74) || (bVar7 == 0x69)) && (pbVar21[3] == 0x6c)) {
            uVar13 = 0;
            if (bVar7 == 0x74) {
              uVar13 = FUN_0010ac34(param_1);
            }
            *(long *)(param_1 + 0x18) = *(long *)(param_1 + 0x18) + 2;
            uVar17 = FUN_0010fb04(param_1,0x45);
            lVar14 = FUN_00109de4(param_1,0x30,uVar13,uVar17);
            goto switchD_0010bfa8_caseD_4;
          }
LAB_0010b50c:
          piVar12 = (int *)FUN_0010c598(param_1);
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
                  goto switchD_0010bfa8_caseD_0;
                case 1:
                  goto switchD_0010bdcc_caseD_1;
                case 2:
                  goto switchD_0010bdcc_caseD_2;
                case 3:
                  goto switchD_0010bdcc_caseD_3;
                default:
                  goto switchD_0010bfa8_caseD_4;
                }
              }
              uVar13 = FUN_0010ac34(param_1);
            }
            else {
              if (iVar10 == 0x32) {
                lVar14 = 0;
                switch(piVar12[2]) {
                case 0:
switchD_0010bfa8_caseD_0:
                  lVar14 = FUN_00109de4(param_1,0x34,piVar12,0);
                  break;
                case 1:
                  goto switchD_0010bfa8_caseD_1;
                case 2:
                  pcVar24 = (char *)0x0;
switchD_0010bdcc_caseD_2:
                  if ((**(char ***)(piVar12 + 2))[1] == 'c') {
                    cVar8 = ***(char ***)(piVar12 + 2);
                    bVar7 = cVar8 + 0x8e;
                    if ((1 < bVar7) && (1 < (byte)(cVar8 + 0x9dU))) goto LAB_0010beac;
                    uVar13 = FUN_0010ac34(param_1,bVar7,0);
                  }
                  else {
LAB_0010beac:
                    uVar13 = FUN_00111c88(param_1);
                  }
                  iVar10 = strcmp(pcVar24,"cl");
                  if (iVar10 == 0) {
                    uVar17 = FUN_0010fb04(param_1,0x45);
                  }
                  else {
                    iVar10 = strcmp(pcVar24,"dt");
                    if ((iVar10 == 0) || (iVar10 = strcmp(pcVar24,"pt"), iVar10 == 0)) {
                      uVar17 = FUN_0010c75c(param_1);
                      if (**(char **)(param_1 + 0x18) == 'I') {
                        uVar18 = FUN_0010cbec(param_1);
                        uVar17 = FUN_00109de4(param_1,4,uVar17,uVar18);
                      }
                    }
                    else {
                      uVar17 = FUN_00111c88(param_1);
                    }
                  }
                  uVar13 = FUN_00109de4(param_1,0x37,uVar13,uVar17);
                  lVar14 = FUN_00109de4(param_1,0x36,piVar12,uVar13);
                  break;
                case 3:
                  pcVar24 = (char *)0x0;
switchD_0010bdcc_caseD_3:
                  iVar10 = strcmp(pcVar24,"qu");
                  if (iVar10 == 0) {
                    uVar13 = FUN_00111c88(param_1);
                    uVar17 = FUN_00111c88(param_1);
                    uVar18 = FUN_00111c88(param_1);
                  }
                  else {
                    if ((*pcVar24 != 'n') || ((pcVar24[1] != 'a' && (pcVar24[1] != 'w'))))
                    goto LAB_0010bde0;
                    uVar13 = FUN_0010fb04(param_1,0x5f);
                    uVar17 = FUN_0010ac34(param_1);
                    pcVar24 = *(char **)(param_1 + 0x18);
                    cVar8 = *pcVar24;
                    if (cVar8 != 'E') {
                      if (cVar8 == 'p') {
                        if (pcVar24[1] == 'i') {
                          *(char **)(param_1 + 0x18) = pcVar24 + 2;
                          uVar18 = FUN_0010fb04(param_1,0x45);
                          goto LAB_0010c16c;
                        }
                      }
                      else if ((cVar8 == 'i') && (pcVar24[1] == 'l')) {
                        uVar18 = FUN_00111c88(param_1);
                        goto LAB_0010c16c;
                      }
                      goto LAB_0010bde0;
                    }
                    uVar18 = 0;
                    *(char **)(param_1 + 0x18) = pcVar24 + 1;
                  }
LAB_0010c16c:
                  uVar17 = FUN_00109de4(param_1,0x3a,uVar17,uVar18);
                  uVar13 = FUN_00109de4(param_1,0x39,uVar13,uVar17);
                  lVar14 = FUN_00109de4(param_1,0x38,piVar12,uVar13);
                }
                goto switchD_0010bfa8_caseD_4;
              }
              if (iVar10 != 0x33) goto LAB_0010bde0;
              if (**(char **)(param_1 + 0x18) == '_') {
                *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
                uVar13 = FUN_0010fb04(param_1,0x45);
                goto LAB_0010b554;
              }
switchD_0010bfa8_caseD_1:
              uVar13 = FUN_00111c88(param_1);
            }
LAB_0010b554:
            lVar14 = FUN_00109de4(param_1,0x35,piVar12,uVar13);
            goto switchD_0010bfa8_caseD_4;
          }
        }
LAB_0010bde0:
        lVar14 = 0;
      }
switchD_0010bfa8_caseD_4:
      *(undefined4 *)(param_1 + 0x54) = uVar2;
      local_8 = (int *)FUN_00109de4(param_1,0x41,lVar14,0);
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
      goto LAB_0010ad98;
    case 0x61:
      piVar12 = (int *)FUN_00109e98(param_1,&DAT_0011f468,4);
      return piVar12;
    case 100:
      iVar10 = *(int *)(param_1 + 0x28);
      if (iVar10 < *(int *)(param_1 + 0x2c)) {
        *(int *)(param_1 + 0x28) = iVar10 + 1;
        piVar12 = (int *)(*(long *)(param_1 + 0x20) + (long)iVar10 * 0x18);
        if (piVar12 != (int *)0x0) {
          *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar10 * 0x18) = 0x27;
          *(undefined ***)(piVar12 + 2) = &PTR_s_decimal64_00134ce0;
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
          *(undefined ***)(piVar12 + 2) = &PTR_s_decimal128_00134d00;
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
          *(undefined ***)(piVar12 + 2) = &PTR_s_decimal32_00134cc0;
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
          *(undefined ***)(piVar12 + 2) = &PTR_DAT_00134d20;
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
          *(undefined ***)(piVar12 + 2) = &PTR_s_char32_t_00134d60;
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
          *(undefined ***)(piVar12 + 2) = &PTR_s_decltype_nullptr__00134d80;
          *(int *)(param_1 + 0x50) = *(int *)(param_1 + 0x50) + 0x11;
          return piVar12;
        }
      }
      break;
    case 0x70:
      uVar13 = FUN_0010ac34(param_1);
      local_8 = (int *)FUN_00109de4(param_1,0x49,uVar13,0);
      goto LAB_0010ad94;
    case 0x73:
      iVar10 = *(int *)(param_1 + 0x28);
      if (iVar10 < *(int *)(param_1 + 0x2c)) {
        *(int *)(param_1 + 0x28) = iVar10 + 1;
        piVar12 = (int *)(*(long *)(param_1 + 0x20) + (long)iVar10 * 0x18);
        if (piVar12 != (int *)0x0) {
          *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar10 * 0x18) = 0x27;
          *(undefined ***)(piVar12 + 2) = &PTR_s_char16_t_00134d40;
          *(int *)(param_1 + 0x50) = *(int *)(param_1 + 0x50) + 8;
          return piVar12;
        }
      }
      break;
    case 0x76:
      if (pbVar21[2] == 0x5f) {
        uVar2 = *(undefined4 *)(param_1 + 0x54);
        *(undefined4 *)(param_1 + 0x54) = 1;
        *(byte **)(param_1 + 0x18) = pbVar21 + 3;
        lVar14 = FUN_00111c88(param_1);
        *(undefined4 *)(param_1 + 0x54) = uVar2;
        if (lVar14 != 0) {
LAB_0010b318:
          if (**(char **)(param_1 + 0x18) == '_') {
            *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
            uVar13 = FUN_0010ac34(param_1);
            local_8 = (int *)FUN_00109de4(param_1,0x2d,lVar14,uVar13);
            goto LAB_0010ad94;
          }
        }
      }
      else {
        iVar10 = *(int *)(param_1 + 0x28);
        if (iVar10 < *(int *)(param_1 + 0x2c)) {
          *(int *)(param_1 + 0x28) = iVar10 + 1;
          lVar14 = *(long *)(param_1 + 0x20) + (long)iVar10 * 0x18;
          if (lVar14 != 0) {
            *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar10 * 0x18) = 0x40;
            uVar13 = FUN_0010a50c(param_1 + 0x18);
            *(undefined8 *)(lVar14 + 8) = uVar13;
            goto LAB_0010b318;
          }
        }
      }
LAB_0010ae58:
      local_8 = (int *)0x0;
      goto LAB_0010ad94;
    }
LAB_0010b654:
    local_8 = (int *)0x0;
                    // WARNING: Treating indirect jump as call
    UNRECOVERED_JUMPTABLE_00 = (code *)SoftwareBreakpoint(1000,0x10b664);
    piVar12 = (int *)(*UNRECOVERED_JUMPTABLE_00)(uRam0000000000000008);
    return piVar12;
  case 0x46:
    local_8 = (int *)FUN_0010c510(param_1);
    break;
  case 0x47:
    *(byte **)(param_1 + 0x18) = pbVar21 + 1;
    uVar13 = FUN_0010ac34(param_1);
    local_8 = (int *)FUN_00109de4(param_1,0x26,uVar13,0);
    break;
  case 0x4d:
    *(byte **)(param_1 + 0x18) = pbVar21 + 1;
    lVar14 = FUN_0010ac34(param_1);
    if ((lVar14 == 0) || (lVar15 = FUN_0010ac34(param_1), lVar15 == 0)) goto LAB_0010ae58;
    local_8 = (int *)FUN_00109de4(param_1,0x2b,lVar14,lVar15);
    break;
  case 0x4f:
    *(byte **)(param_1 + 0x18) = pbVar21 + 1;
    uVar13 = FUN_0010ac34(param_1);
    local_8 = (int *)FUN_00109de4(param_1,0x24,uVar13,0);
    break;
  case 0x50:
    *(byte **)(param_1 + 0x18) = pbVar21 + 1;
    uVar13 = FUN_0010ac34(param_1);
    local_8 = (int *)FUN_00109de4(param_1,0x22,uVar13,0);
    break;
  case 0x52:
    *(byte **)(param_1 + 0x18) = pbVar21 + 1;
    uVar13 = FUN_0010ac34(param_1);
    local_8 = (int *)FUN_00109de4(param_1,0x23,uVar13,0);
    break;
  case 0x53:
    bVar7 = pbVar21[1];
    if (((9 < (byte)(bVar7 - 0x30)) && (bVar7 != 0x5f)) && (0x19 < (byte)(bVar7 + 0xbf))) {
      local_8 = (int *)FUN_0010ed9c(param_1);
      if (local_8 == (int *)0x0) {
        return (int *)0x0;
      }
      if (*local_8 == 0x18) {
        return local_8;
      }
      goto LAB_0010ad98;
    }
    local_8 = (int *)FUN_0010a118(param_1,0);
    if (**(char **)(param_1 + 0x18) != 'I') {
      return local_8;
    }
LAB_0010b040:
    piVar12 = local_8;
    uVar13 = FUN_0010cbec(param_1);
    local_8 = (int *)FUN_00109de4(param_1,4,piVar12,uVar13);
    break;
  case 0x54:
    local_8 = (int *)FUN_0010a5fc(param_1);
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
        goto LAB_0010b040;
      }
      uVar2 = *(undefined4 *)(param_1 + 0x28);
      uVar3 = *(undefined4 *)(param_1 + 0x38);
      uVar4 = *(undefined4 *)(param_1 + 0x40);
      uVar5 = *(undefined4 *)(param_1 + 0x50);
      uVar13 = FUN_0010cbec(param_1);
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
        local_8 = (int *)FUN_00109de4(param_1,4,local_8,uVar13);
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
    *(byte **)(param_1 + 0x18) = pbVar21 + 1;
    local_8 = (int *)FUN_0010a6e4(param_1);
    uVar13 = FUN_0010ac34(param_1);
    local_8 = (int *)FUN_00109de4(param_1,0x21,uVar13,local_8);
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
        *(undefined **)(piVar12 + 2) = &UNK_00134980 + uVar16;
        iVar10 = *(int *)(&DAT_00134988 + uVar16);
        *(byte **)(param_1 + 0x18) = pbVar21 + 1;
        *(int *)(param_1 + 0x50) = *(int *)(param_1 + 0x50) + iVar10;
        return piVar12;
      }
    }
    goto LAB_0010b654;
  case 0x75:
    *(byte **)(param_1 + 0x18) = pbVar21 + 1;
    uVar13 = FUN_0010a6e4(param_1);
    local_8 = (int *)FUN_00109de4(param_1,0x28,uVar13,0);
  }
LAB_0010ad94:
  if (local_8 != (int *)0x0) {
LAB_0010ad98:
    iVar10 = *(int *)(param_1 + 0x38);
    if (iVar10 < *(int *)(param_1 + 0x3c)) {
      *(int **)(*(long *)(param_1 + 0x30) + (long)iVar10 * 8) = local_8;
      *(int *)(param_1 + 0x38) = iVar10 + 1;
      return local_8;
    }
  }
switchD_0010acb0_caseD_3a:
  return (int *)0x0;
switchD_0010bdcc_caseD_1:
  cVar8 = *pcVar24;
  if (((cVar8 == 'm') || (cVar8 == 'p')) && (pcVar24[1] == cVar8)) {
    cVar8 = **(char **)(param_1 + 0x18);
    if (cVar8 != '_') {
      uVar13 = FUN_00111c88(param_1,cVar8,0);
      uVar13 = FUN_00109de4(param_1,0x37,uVar13,uVar13);
      goto LAB_0010b554;
    }
    *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
  }
  goto switchD_0010bfa8_caseD_1;
}



long FUN_0010c388(long param_1)

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
      lVar2 = FUN_0010ac34(param_1);
      if (lVar2 == 0) {
        return 0;
      }
      lVar2 = FUN_00109de4(param_1,0x2e,lVar2,0);
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



undefined8 FUN_0010c498(long param_1,int param_2)

{
  long lVar1;
  undefined8 uVar2;
  long lVar3;
  
  if (**(char **)(param_1 + 0x18) == 'J') {
    *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
  }
  else {
    lVar3 = 0;
    if (param_2 == 0) goto LAB_0010c4c0;
  }
  lVar3 = FUN_0010ac34(param_1);
  if (lVar3 == 0) {
    return 0;
  }
LAB_0010c4c0:
  lVar1 = FUN_0010c388(param_1);
  if (lVar1 == 0) {
    return 0;
  }
  uVar2 = FUN_00109de4(param_1,0x29,lVar3,lVar1);
  return uVar2;
}



undefined8 FUN_0010c510(long param_1)

{
  undefined8 uVar1;
  char *pcVar2;
  
  pcVar2 = *(char **)(param_1 + 0x18);
  if (*pcVar2 == 'F') {
    *(char **)(param_1 + 0x18) = pcVar2 + 1;
    if (pcVar2[1] == 'Y') {
      *(char **)(param_1 + 0x18) = pcVar2 + 2;
    }
    uVar1 = FUN_0010c498(param_1,1);
    uVar1 = FUN_0010a0ac(param_1,uVar1);
    if (**(char **)(param_1 + 0x18) == 'E') {
      *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
      return uVar1;
    }
  }
  return 0;
}



long FUN_0010c598(long param_1)

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
    bVar11 = 0;
    bVar12 = 0;
  }
  else {
    *(byte **)(param_1 + 0x18) = pbVar8 + 1;
    bVar12 = pbVar8[1];
    bVar11 = *pbVar8;
    if (bVar12 != 0) {
      *(byte **)(param_1 + 0x18) = pbVar8 + 2;
      bVar12 = pbVar8[1];
      if (bVar11 == 0x76) {
        uVar5 = bVar12 - 0x30;
        if ((uVar5 & 0xff) < 10) {
          lVar7 = FUN_0010a6e4();
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
        uVar6 = FUN_0010ac34();
        *(undefined4 *)(param_1 + 0x58) = uVar3;
        lVar7 = FUN_00109de4(param_1,0x33,uVar6,0);
        return lVar7;
      }
    }
  }
  iVar10 = 0x3d;
  iVar9 = 0;
  do {
    iVar1 = iVar9 + (iVar10 - iVar9) / 2;
    bVar4 = *(&PTR_DAT_00134f28)[(long)iVar1 * 3];
    if (bVar11 == bVar4) {
      bVar4 = (&PTR_DAT_00134f28)[(long)iVar1 * 3][1];
      if (bVar12 == bVar4) {
        iVar9 = *(int *)(param_1 + 0x28);
        if (*(int *)(param_1 + 0x2c) <= iVar9) {
          return 0;
        }
        *(int *)(param_1 + 0x28) = iVar9 + 1;
        lVar7 = *(long *)(param_1 + 0x20) + (long)iVar9 * 0x18;
        if (lVar7 != 0) {
          *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar9 * 0x18) = 0x31;
          *(undefined ***)(lVar7 + 8) = &PTR_DAT_00134f28 + (long)iVar1 * 3;
          return lVar7;
        }
        return 0;
      }
      if (bVar4 <= bVar12) goto LAB_0010c62c;
    }
    else if (bVar4 <= bVar11) {
LAB_0010c62c:
      iVar9 = iVar1 + 1;
      iVar1 = iVar10;
    }
    iVar10 = iVar1;
    if (iVar9 == iVar10) {
      return 0;
    }
  } while( true );
}



int * FUN_0010c75c(long param_1)

{
  int iVar1;
  int iVar2;
  undefined8 uVar3;
  long lVar4;
  char *pcVar5;
  char cVar6;
  int *piVar7;
  char *pcVar8;
  int *piVar9;
  
  pcVar8 = *(char **)(param_1 + 0x18);
  cVar6 = *pcVar8;
  if ((byte)(cVar6 - 0x30U) < 10) {
    piVar9 = (int *)FUN_0010a6e4();
    pcVar5 = *(char **)(param_1 + 0x18);
    cVar6 = *pcVar5;
    goto joined_r0x0010c858;
  }
  if ((byte)(cVar6 + 0x9fU) < 0x1a) {
    piVar9 = (int *)FUN_0010c598();
    if ((piVar9 != (int *)0x0) && (*piVar9 == 0x31)) {
      pcVar8 = **(char ***)(piVar9 + 2);
      *(int *)(param_1 + 0x50) =
           *(int *)(param_1 + 0x50) + *(int *)(*(char ***)(piVar9 + 2) + 2) + 7;
      iVar2 = strcmp(pcVar8,"li");
      if (iVar2 == 0) {
        uVar3 = FUN_0010a6e4(param_1);
        piVar9 = (int *)FUN_00109de4(param_1,0x35,piVar9,uVar3);
      }
    }
  }
  else {
    if ((byte)(cVar6 + 0xbdU) < 2) {
      piVar7 = *(int **)(param_1 + 0x48);
      if ((piVar7 == (int *)0x0) || ((*piVar7 != 0 && (*piVar7 != 0x18)))) {
        if (cVar6 != 'C') {
          if (cVar6 != 'D') {
            return (int *)0x0;
          }
          goto LAB_0010c970;
        }
LAB_0010cb34:
        switch(pcVar8[1]) {
        case '1':
          iVar2 = 1;
          break;
        case '2':
          iVar2 = 2;
          break;
        case '3':
          iVar2 = 3;
          break;
        case '4':
          iVar2 = 4;
          break;
        case '5':
          iVar2 = 5;
          break;
        default:
switchD_0010c994_caseD_33:
          return (int *)0x0;
        }
        iVar1 = *(int *)(param_1 + 0x28);
        pcVar5 = pcVar8 + 2;
        *(char **)(param_1 + 0x18) = pcVar5;
        if (iVar1 < *(int *)(param_1 + 0x2c)) {
          *(int *)(param_1 + 0x28) = iVar1 + 1;
          piVar9 = (int *)(*(long *)(param_1 + 0x20) + (long)iVar1 * 0x18);
          if ((piVar9 != (int *)0x0) && (piVar7 != (int *)0x0)) {
            *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar1 * 0x18) = 7;
            piVar9[2] = iVar2;
            *(int **)(piVar9 + 4) = piVar7;
            cVar6 = pcVar8[2];
            goto joined_r0x0010c858;
          }
        }
      }
      else {
        *(int *)(param_1 + 0x50) = *(int *)(param_1 + 0x50) + piVar7[4];
        cVar6 = *pcVar8;
        if (cVar6 == 'C') goto LAB_0010cb34;
        if (cVar6 != 'D') {
          piVar9 = (int *)0x0;
          pcVar5 = pcVar8;
          goto joined_r0x0010c858;
        }
LAB_0010c970:
        switch(pcVar8[1]) {
        case '0':
          iVar2 = 1;
          break;
        case '1':
          iVar2 = 2;
          break;
        case '2':
          iVar2 = 3;
          break;
        default:
          goto switchD_0010c994_caseD_33;
        case '4':
          iVar2 = 4;
          break;
        case '5':
          iVar2 = 5;
        }
        iVar1 = *(int *)(param_1 + 0x28);
        pcVar5 = pcVar8 + 2;
        *(char **)(param_1 + 0x18) = pcVar5;
        if (iVar1 < *(int *)(param_1 + 0x2c)) {
          *(int *)(param_1 + 0x28) = iVar1 + 1;
          piVar9 = (int *)(*(long *)(param_1 + 0x20) + (long)iVar1 * 0x18);
          if ((piVar9 != (int *)0x0) && (piVar7 != (int *)0x0)) {
            *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar1 * 0x18) = 8;
            piVar9[2] = iVar2;
            *(int **)(piVar9 + 4) = piVar7;
            cVar6 = pcVar8[2];
            goto joined_r0x0010c858;
          }
        }
      }
      pcVar5 = pcVar8 + 2;
      cVar6 = *pcVar5;
      piVar9 = (int *)0x0;
      goto joined_r0x0010c858;
    }
    if (cVar6 != 'L') {
      if (cVar6 != 'U') {
        return (int *)0x0;
      }
      if (pcVar8[1] == 'l') {
        pcVar5 = pcVar8 + 1;
        *(char **)(param_1 + 0x18) = pcVar5;
        cVar6 = pcVar8[1];
        if (cVar6 == 'l') {
          *(char **)(param_1 + 0x18) = pcVar8 + 2;
          lVar4 = FUN_0010c388();
          pcVar5 = *(char **)(param_1 + 0x18);
          if (lVar4 == 0) {
            cVar6 = *pcVar5;
            piVar9 = (int *)0x0;
            goto joined_r0x0010c858;
          }
          cVar6 = *pcVar5;
          if (cVar6 == 'E') {
            *(char **)(param_1 + 0x18) = pcVar5 + 1;
            iVar2 = FUN_0010a590(param_1);
            if ((-1 < iVar2) && (iVar1 = *(int *)(param_1 + 0x28), iVar1 < *(int *)(param_1 + 0x2c))
               ) {
              *(int *)(param_1 + 0x28) = iVar1 + 1;
              piVar9 = (int *)(*(long *)(param_1 + 0x20) + (long)iVar1 * 0x18);
              if (piVar9 != (int *)0x0) {
                *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar1 * 0x18) = 0x44;
                *(long *)(piVar9 + 2) = lVar4;
                piVar9[4] = iVar2;
                iVar2 = *(int *)(param_1 + 0x38);
                if (iVar2 < *(int *)(param_1 + 0x3c)) goto LAB_0010ca20;
              }
            }
            goto LAB_0010c92c;
          }
        }
      }
      else {
        if (pcVar8[1] != 't') {
          return (int *)0x0;
        }
        pcVar5 = pcVar8 + 1;
        *(char **)(param_1 + 0x18) = pcVar5;
        cVar6 = pcVar8[1];
        if (cVar6 == 't') {
          *(char **)(param_1 + 0x18) = pcVar8 + 2;
          lVar4 = FUN_0010a590();
          if ((-1 < lVar4) && (iVar2 = *(int *)(param_1 + 0x28), iVar2 < *(int *)(param_1 + 0x2c)))
          {
            *(int *)(param_1 + 0x28) = iVar2 + 1;
            piVar9 = (int *)(*(long *)(param_1 + 0x20) + (long)iVar2 * 0x18);
            if (piVar9 != (int *)0x0) {
              *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar2 * 0x18) = 0x46;
              *(long *)(piVar9 + 2) = lVar4;
              iVar2 = *(int *)(param_1 + 0x38);
              if (iVar2 < *(int *)(param_1 + 0x3c)) {
LAB_0010ca20:
                *(int **)(*(long *)(param_1 + 0x30) + (long)iVar2 * 8) = piVar9;
                *(int *)(param_1 + 0x38) = iVar2 + 1;
                cVar6 = **(char **)(param_1 + 0x18);
                pcVar5 = *(char **)(param_1 + 0x18);
                goto joined_r0x0010c858;
              }
            }
          }
LAB_0010c92c:
          piVar9 = (int *)0x0;
          cVar6 = **(char **)(param_1 + 0x18);
          pcVar5 = *(char **)(param_1 + 0x18);
          goto joined_r0x0010c858;
        }
      }
      piVar9 = (int *)0x0;
      goto joined_r0x0010c858;
    }
    *(char **)(param_1 + 0x18) = pcVar8 + 1;
    piVar9 = (int *)FUN_0010a6e4();
    if (piVar9 == (int *)0x0) {
      return (int *)0x0;
    }
    iVar2 = FUN_0010a69c(param_1);
    if (iVar2 == 0) {
      return (int *)0x0;
    }
  }
  cVar6 = **(char **)(param_1 + 0x18);
  pcVar5 = *(char **)(param_1 + 0x18);
joined_r0x0010c858:
  if (cVar6 == 'B') {
    do {
      *(char **)(param_1 + 0x18) = pcVar5 + 1;
      uVar3 = FUN_0010a6e4(param_1);
      piVar9 = (int *)FUN_00109de4(param_1,0x4a,piVar9,uVar3);
      pcVar5 = *(char **)(param_1 + 0x18);
    } while (*pcVar5 == 'B');
    return piVar9;
  }
  return piVar9;
}



long FUN_0010cbec(long param_1)

{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  long lVar4;
  int *piVar5;
  undefined8 uVar6;
  undefined8 uVar7;
  int *piVar8;
  int *piVar9;
  undefined8 uVar10;
  int *piVar11;
  undefined8 uVar12;
  char cVar13;
  char *pcVar14;
  char *pcVar15;
  long lVar16;
  long *plVar17;
  undefined8 uVar18;
  char **ppcVar19;
  undefined8 local_18;
  long local_8;
  
  pcVar15 = *(char **)(param_1 + 0x18);
  uVar18 = *(undefined8 *)(param_1 + 0x48);
  if (1 < (byte)(*pcVar15 + 0xb7U)) {
    return 0;
  }
  pcVar14 = pcVar15 + 1;
  *(char **)(param_1 + 0x18) = pcVar14;
  cVar13 = pcVar15[1];
  if (cVar13 == 'E') {
    *(char **)(param_1 + 0x18) = pcVar15 + 2;
    uVar18 = FUN_00109de4(param_1,0x2f,0,0);
    return uVar18;
  }
  plVar17 = &local_8;
  local_8 = 0;
LAB_0010cc64:
  switch(cVar13) {
  case 'I':
  case 'J':
    lVar4 = FUN_0010cbec(param_1);
    break;
  default:
    lVar4 = FUN_0010ac34(param_1);
    break;
  case 'L':
    lVar4 = FUN_0010f980(param_1);
    break;
  case 'X':
    pcVar15 = pcVar14 + 1;
    uVar1 = *(undefined4 *)(param_1 + 0x54);
    *(char **)(param_1 + 0x18) = pcVar15;
    *(undefined4 *)(param_1 + 0x54) = 1;
    cVar13 = pcVar14[1];
    if (cVar13 == 'L') {
      lVar4 = FUN_0010f980(param_1);
      pcVar15 = *(char **)(param_1 + 0x18);
    }
    else if (cVar13 == 'T') {
      lVar4 = FUN_0010a5fc(param_1);
      pcVar15 = *(char **)(param_1 + 0x18);
    }
    else if (cVar13 == 's') {
      if (pcVar14[2] == 'r') {
        *(char **)(param_1 + 0x18) = pcVar14 + 3;
        uVar6 = FUN_0010ac34(param_1);
        uVar7 = FUN_0010c75c(param_1);
        if (**(char **)(param_1 + 0x18) == 'I') {
          uVar10 = FUN_0010cbec(param_1);
          uVar7 = FUN_00109de4(param_1,4,uVar7,uVar10);
        }
        lVar4 = FUN_00109de4(param_1,1,uVar6,uVar7);
        pcVar15 = *(char **)(param_1 + 0x18);
      }
      else {
        if (pcVar14[2] != 'p') goto LAB_0010cd38;
        *(char **)(param_1 + 0x18) = pcVar14 + 3;
        uVar6 = FUN_00111c88(param_1);
        lVar4 = FUN_00109de4(param_1,0x49,uVar6,0);
        pcVar15 = *(char **)(param_1 + 0x18);
      }
    }
    else if (cVar13 == 'f') {
      if (pcVar14[2] != 'p') goto LAB_0010cd38;
      *(char **)(param_1 + 0x18) = pcVar14 + 3;
      if (pcVar14[3] == 'T') {
        lVar16 = 0;
        *(char **)(param_1 + 0x18) = pcVar14 + 4;
      }
      else {
        iVar3 = FUN_0010a590(param_1);
        lVar16 = (long)(iVar3 + 1);
        if (iVar3 + 1 == 0) goto switchD_0010d0a8_caseD_4;
      }
      iVar3 = *(int *)(param_1 + 0x28);
      if (*(int *)(param_1 + 0x2c) <= iVar3) goto switchD_0010d0a8_caseD_4;
      *(int *)(param_1 + 0x28) = iVar3 + 1;
      lVar4 = *(long *)(param_1 + 0x20) + (long)iVar3 * 0x18;
      if (lVar4 != 0) {
        *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar3 * 0x18) = 6;
        *(long *)(lVar4 + 8) = lVar16;
        pcVar15 = *(char **)(param_1 + 0x18);
        goto LAB_0010cde4;
      }
LAB_0010d2c4:
      pcVar15 = *(char **)(param_1 + 0x18);
    }
    else {
      if ((byte)(cVar13 - 0x30U) < 10) {
LAB_0010cdc4:
        lVar4 = FUN_0010c75c(param_1);
        pcVar15 = *(char **)(param_1 + 0x18);
        if ((lVar4 != 0) && (*pcVar15 == 'I')) {
          uVar6 = FUN_0010cbec(param_1);
          lVar4 = FUN_00109de4(param_1,4,lVar4,uVar6);
          pcVar15 = *(char **)(param_1 + 0x18);
        }
        goto LAB_0010cde4;
      }
      if (cVar13 == 'o') {
        if (pcVar14[2] == 'n') {
          *(char **)(param_1 + 0x18) = pcVar14 + 3;
          goto LAB_0010cdc4;
        }
      }
      else if (((cVar13 == 't') || (cVar13 == 'i')) && (pcVar14[2] == 'l')) {
        uVar6 = 0;
        if (cVar13 == 't') {
          uVar6 = FUN_0010ac34(param_1);
          pcVar15 = *(char **)(param_1 + 0x18);
        }
        *(char **)(param_1 + 0x18) = pcVar15 + 2;
        uVar7 = FUN_0010fb04(param_1,0x45);
        lVar4 = FUN_00109de4(param_1,0x30,uVar6,uVar7);
        pcVar15 = *(char **)(param_1 + 0x18);
        goto LAB_0010cde4;
      }
LAB_0010cd38:
      piVar5 = (int *)FUN_0010c598(param_1);
      if (piVar5 != (int *)0x0) {
        iVar3 = *piVar5;
        if (iVar3 == 0x31) {
          ppcVar19 = *(char ***)(piVar5 + 2);
          pcVar15 = *ppcVar19;
          *(int *)(param_1 + 0x50) = *(int *)(param_1 + 0x50) + *(int *)(ppcVar19 + 2) + -2;
          iVar3 = strcmp(pcVar15,"st");
          if (iVar3 == 0) {
            uVar6 = FUN_0010ac34(param_1);
LAB_0010d124:
            lVar4 = FUN_00109de4(param_1,0x35,piVar5,uVar6);
            pcVar15 = *(char **)(param_1 + 0x18);
            goto LAB_0010cde4;
          }
          switch(*(undefined4 *)((long)ppcVar19 + 0x14)) {
          case 0:
            goto switchD_0010d0a8_caseD_0;
          case 1:
            cVar13 = *pcVar15;
            if (((cVar13 == 'm') || (cVar13 == 'p')) && (pcVar15[1] == cVar13)) {
              if (**(char **)(param_1 + 0x18) != '_') {
                uVar6 = FUN_00111c88(param_1);
                uVar6 = FUN_00109de4(param_1,0x37,uVar6,uVar6);
                goto LAB_0010d124;
              }
              *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
            }
            goto switchD_0010d0a8_caseD_1;
          case 2:
            goto switchD_0010cf80_caseD_2;
          case 3:
            goto switchD_0010cf80_caseD_3;
          }
        }
        else if (iVar3 == 0x32) {
          switch(piVar5[2]) {
          case 0:
switchD_0010d0a8_caseD_0:
            lVar4 = FUN_00109de4(param_1,0x34,piVar5,0);
            pcVar15 = *(char **)(param_1 + 0x18);
            goto LAB_0010cde4;
          case 1:
            goto switchD_0010d0a8_caseD_1;
          case 2:
            pcVar15 = (char *)0x0;
switchD_0010cf80_caseD_2:
            if (((**(char ***)(piVar5 + 2))[1] == 'c') &&
               ((cVar13 = ***(char ***)(piVar5 + 2), (byte)(cVar13 + 0x8eU) < 2 ||
                ((byte)(cVar13 + 0x9dU) < 2)))) {
              uVar6 = FUN_0010ac34(param_1);
            }
            else {
              uVar6 = FUN_00111c88(param_1);
            }
            iVar3 = strcmp(pcVar15,"cl");
            if (iVar3 == 0) {
              lVar4 = FUN_0010fb04(param_1,0x45);
            }
            else {
              iVar3 = strcmp(pcVar15,"dt");
              if ((iVar3 == 0) || (iVar3 = strcmp(pcVar15,"pt"), iVar3 == 0)) {
                lVar4 = FUN_0010c75c(param_1);
                cVar13 = **(char **)(param_1 + 0x18);
joined_r0x0010d690:
                if (cVar13 == 'I') {
                  uVar7 = FUN_0010cbec(param_1);
                  lVar4 = FUN_00109de4(param_1,4,lVar4,uVar7);
                }
              }
              else {
                pcVar15 = *(char **)(param_1 + 0x18);
                cVar13 = *pcVar15;
                if (cVar13 == 'L') {
                  lVar4 = FUN_0010f980(param_1);
                }
                else if (cVar13 == 'T') {
                  lVar4 = FUN_0010a5fc(param_1);
                }
                else if (cVar13 == 's') {
                  if (pcVar15[1] == 'r') {
                    *(char **)(param_1 + 0x18) = pcVar15 + 2;
                    uVar7 = FUN_0010ac34(param_1);
                    uVar10 = FUN_0010c75c(param_1);
                    if (**(char **)(param_1 + 0x18) == 'I') {
                      uVar12 = FUN_0010cbec(param_1);
                      uVar10 = FUN_00109de4(param_1,4,uVar10,uVar12);
                    }
                    lVar4 = FUN_00109de4(param_1,1,uVar7,uVar10);
                  }
                  else {
                    if (pcVar15[1] != 'p') goto LAB_0010d600;
                    *(char **)(param_1 + 0x18) = pcVar15 + 2;
                    uVar7 = FUN_00111c88(param_1);
                    lVar4 = FUN_00109de4(param_1,0x49,uVar7,0);
                  }
                }
                else if (cVar13 == 'f') {
                  if (pcVar15[1] != 'p') goto LAB_0010d600;
                  *(char **)(param_1 + 0x18) = pcVar15 + 2;
                  if (pcVar15[2] == 'T') {
                    iVar3 = 0;
                    *(char **)(param_1 + 0x18) = pcVar15 + 3;
                  }
                  else {
                    iVar3 = FUN_0010a590(param_1);
                    iVar3 = iVar3 + 1;
                    if (iVar3 == 0) goto LAB_0010db28;
                  }
                  iVar2 = *(int *)(param_1 + 0x28);
                  if (*(int *)(param_1 + 0x2c) <= iVar2) goto LAB_0010db28;
                  *(int *)(param_1 + 0x28) = iVar2 + 1;
                  lVar4 = *(long *)(param_1 + 0x20) + (long)iVar2 * 0x18;
                  if (lVar4 != 0) {
                    *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar2 * 0x18) = 6;
                    *(long *)(lVar4 + 8) = (long)iVar3;
                  }
                }
                else {
                  if ((byte)(cVar13 - 0x30U) < 10) {
LAB_0010d674:
                    lVar4 = FUN_0010c75c(param_1);
                    if (lVar4 != 0) {
                      cVar13 = **(char **)(param_1 + 0x18);
                      goto joined_r0x0010d690;
                    }
                  }
                  else {
                    if (cVar13 == 'o') {
                      if (pcVar15[1] == 'n') {
                        *(char **)(param_1 + 0x18) = pcVar15 + 2;
                        goto LAB_0010d674;
                      }
                    }
                    else if (((cVar13 == 't') || (cVar13 == 'i')) && (pcVar15[1] == 'l')) {
                      uVar7 = 0;
                      if (cVar13 == 't') {
                        uVar7 = FUN_0010ac34(param_1);
                        pcVar15 = *(char **)(param_1 + 0x18);
                      }
                      *(char **)(param_1 + 0x18) = pcVar15 + 2;
                      uVar10 = FUN_0010fb04(param_1,0x45);
                      lVar4 = FUN_00109de4(param_1,0x30,uVar7,uVar10);
                      goto switchD_0010e0f8_caseD_4;
                    }
LAB_0010d600:
                    piVar8 = (int *)FUN_0010c598(param_1);
                    if (piVar8 != (int *)0x0) {
                      iVar3 = *piVar8;
                      if (iVar3 == 0x31) {
                        ppcVar19 = *(char ***)(piVar8 + 2);
                        pcVar15 = *ppcVar19;
                        *(int *)(param_1 + 0x50) =
                             *(int *)(param_1 + 0x50) + *(int *)(ppcVar19 + 2) + -2;
                        iVar3 = strcmp(pcVar15,"st");
                        if (iVar3 != 0) {
                          lVar4 = 0;
                          switch(*(undefined4 *)((long)ppcVar19 + 0x14)) {
                          case 0:
                            goto switchD_0010e0f8_caseD_0;
                          case 1:
                            goto switchD_0010e160_caseD_1;
                          case 2:
                            goto switchD_0010e160_caseD_2;
                          case 3:
                            goto switchD_0010e160_caseD_3;
                          default:
                            goto switchD_0010e0f8_caseD_4;
                          }
                        }
                        uVar7 = FUN_0010ac34(param_1);
                      }
                      else {
                        if (iVar3 == 0x32) {
                          lVar4 = 0;
                          switch(piVar8[2]) {
                          case 0:
switchD_0010e0f8_caseD_0:
                            lVar4 = FUN_00109de4(param_1,0x34,piVar8,0);
                            break;
                          case 1:
                            goto switchD_0010e0f8_caseD_1;
                          case 2:
                            pcVar15 = (char *)0x0;
switchD_0010e160_caseD_2:
                            if (((**(char ***)(piVar8 + 2))[1] == 'c') &&
                               ((cVar13 = ***(char ***)(piVar8 + 2), (byte)(cVar13 + 0x8eU) < 2 ||
                                ((byte)(cVar13 + 0x9dU) < 2)))) {
                              uVar7 = FUN_0010ac34(param_1);
                            }
                            else {
                              uVar7 = FUN_00111c88(param_1);
                            }
                            iVar3 = strcmp(pcVar15,"cl");
                            if (iVar3 == 0) {
                              uVar10 = FUN_0010fb04(param_1,0x45);
                            }
                            else {
                              iVar3 = strcmp(pcVar15,"dt");
                              if ((iVar3 == 0) || (iVar3 = strcmp(pcVar15,"pt"), iVar3 == 0)) {
                                uVar10 = FUN_0010c75c(param_1);
                                if (**(char **)(param_1 + 0x18) == 'I') {
                                  uVar12 = FUN_0010cbec(param_1);
                                  uVar10 = FUN_00109de4(param_1,4,uVar10,uVar12);
                                }
                              }
                              else {
                                uVar10 = FUN_00111c88(param_1);
                              }
                            }
                            uVar7 = FUN_00109de4(param_1,0x37,uVar7,uVar10);
                            lVar4 = FUN_00109de4(param_1,0x36,piVar8,uVar7);
                            break;
                          case 3:
                            pcVar15 = (char *)0x0;
switchD_0010e160_caseD_3:
                            iVar3 = strcmp(pcVar15,"qu");
                            if (iVar3 == 0) {
                              uVar7 = FUN_00111c88(param_1);
                              uVar10 = FUN_00111c88(param_1);
                              uVar12 = FUN_00111c88(param_1);
                            }
                            else {
                              if ((*pcVar15 != 'n') || ((pcVar15[1] != 'a' && (pcVar15[1] != 'w'))))
                              goto LAB_0010db28;
                              uVar7 = FUN_0010fb04(param_1,0x5f);
                              uVar10 = FUN_0010ac34(param_1);
                              pcVar15 = *(char **)(param_1 + 0x18);
                              cVar13 = *pcVar15;
                              if (cVar13 != 'E') {
                                if (cVar13 == 'p') {
                                  if (pcVar15[1] == 'i') {
                                    *(char **)(param_1 + 0x18) = pcVar15 + 2;
                                    uVar12 = FUN_0010fb04(param_1,0x45);
                                    goto LAB_0010e798;
                                  }
                                }
                                else if ((cVar13 == 'i') && (pcVar15[1] == 'l')) {
                                  uVar12 = FUN_00111c88(param_1);
                                  goto LAB_0010e798;
                                }
                                goto LAB_0010db28;
                              }
                              uVar12 = 0;
                              *(char **)(param_1 + 0x18) = pcVar15 + 1;
                            }
LAB_0010e798:
                            uVar10 = FUN_00109de4(param_1,0x3a,uVar10,uVar12);
                            uVar7 = FUN_00109de4(param_1,0x39,uVar7,uVar10);
                            lVar4 = FUN_00109de4(param_1,0x38,piVar8,uVar7);
                          }
                          goto switchD_0010e0f8_caseD_4;
                        }
                        if (iVar3 != 0x33) goto LAB_0010db28;
                        if (**(char **)(param_1 + 0x18) == '_') {
                          *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
                          uVar7 = FUN_0010fb04(param_1,0x45);
                          goto LAB_0010d648;
                        }
switchD_0010e0f8_caseD_1:
                        uVar7 = FUN_00111c88(param_1);
                      }
LAB_0010d648:
                      lVar4 = FUN_00109de4(param_1,0x35,piVar8,uVar7);
                      goto switchD_0010e0f8_caseD_4;
                    }
                  }
LAB_0010db28:
                  lVar4 = 0;
                }
              }
            }
switchD_0010e0f8_caseD_4:
            uVar6 = FUN_00109de4(param_1,0x37,uVar6,lVar4);
            lVar4 = FUN_00109de4(param_1,0x36,piVar5,uVar6);
            pcVar15 = *(char **)(param_1 + 0x18);
            goto LAB_0010cde4;
          case 3:
            pcVar15 = (char *)0x0;
switchD_0010cf80_caseD_3:
            iVar3 = strcmp(pcVar15,"qu");
            if (iVar3 == 0) {
              pcVar15 = *(char **)(param_1 + 0x18);
              cVar13 = *pcVar15;
              if (cVar13 == 'L') {
                piVar8 = (int *)FUN_0010f980(param_1);
                pcVar15 = *(char **)(param_1 + 0x18);
                cVar13 = *pcVar15;
LAB_0010d3e4:
                if (cVar13 == 'L') {
                  piVar9 = (int *)FUN_0010f980(param_1);
                  pcVar15 = *(char **)(param_1 + 0x18);
                  cVar13 = *pcVar15;
                  goto LAB_0010d4a0;
                }
                if (cVar13 == 'T') {
                  piVar9 = (int *)FUN_0010a5fc(param_1);
                  pcVar15 = *(char **)(param_1 + 0x18);
                  cVar13 = *pcVar15;
                  goto LAB_0010d4a0;
                }
                if (cVar13 == 's') {
                  if (pcVar15[1] == 'r') {
                    *(char **)(param_1 + 0x18) = pcVar15 + 2;
                    piVar9 = (int *)FUN_0010ac34(param_1);
                    uVar6 = FUN_0010c75c(param_1);
                    if (**(char **)(param_1 + 0x18) == 'I') {
                      uVar7 = FUN_0010cbec(param_1);
                      uVar6 = FUN_00109de4(param_1,4,uVar6,uVar7);
                    }
                    uVar7 = 1;
                    goto LAB_0010d48c;
                  }
                  if (pcVar15[1] != 'p') goto LAB_0010d43c;
                  *(char **)(param_1 + 0x18) = pcVar15 + 2;
                  piVar9 = (int *)FUN_00111c88(param_1);
                  uVar6 = 0x49;
LAB_0010d96c:
                  piVar9 = (int *)FUN_00109de4(param_1,uVar6,piVar9,0);
                  pcVar15 = *(char **)(param_1 + 0x18);
                  cVar13 = *pcVar15;
                  goto LAB_0010d4a0;
                }
                if (cVar13 != 'f') {
                  if (9 < (byte)(cVar13 - 0x30U)) {
                    if (cVar13 != 'o') goto LAB_0010d41c;
                    if (pcVar15[1] != 'n') goto LAB_0010d43c;
                    *(char **)(param_1 + 0x18) = pcVar15 + 2;
                  }
                  piVar9 = (int *)FUN_0010c75c(param_1);
                  pcVar15 = *(char **)(param_1 + 0x18);
                  cVar13 = *pcVar15;
                  if ((piVar9 != (int *)0x0) && (cVar13 == 'I')) {
                    uVar6 = FUN_0010cbec(param_1);
                    uVar7 = 4;
                    goto LAB_0010d48c;
                  }
                  goto LAB_0010d4a0;
                }
                if (pcVar15[1] == 'p') {
                  *(char **)(param_1 + 0x18) = pcVar15 + 2;
                  if (pcVar15[2] == 'T') {
                    pcVar15 = pcVar15 + 3;
                    lVar4 = 0;
                    *(char **)(param_1 + 0x18) = pcVar15;
                  }
                  else {
                    iVar3 = FUN_0010a590(param_1);
                    pcVar15 = *(char **)(param_1 + 0x18);
                    if (iVar3 + 1 == 0) {
LAB_0010da4c:
                      piVar9 = (int *)0x0;
                      cVar13 = *pcVar15;
                      goto LAB_0010d4a0;
                    }
                    lVar4 = (long)(iVar3 + 1);
                  }
                  iVar3 = *(int *)(param_1 + 0x28);
                  if (iVar3 < *(int *)(param_1 + 0x2c)) {
                    *(int *)(param_1 + 0x28) = iVar3 + 1;
                    piVar9 = (int *)(*(long *)(param_1 + 0x20) + (long)iVar3 * 0x18);
                    if (piVar9 == (int *)0x0) goto LAB_0010d49c;
                    *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar3 * 0x18) = 6;
                    *(long *)(piVar9 + 2) = lVar4;
                    cVar13 = *pcVar15;
                  }
                  else {
                    cVar13 = *pcVar15;
                    piVar9 = (int *)0x0;
                  }
                  goto LAB_0010d4a0;
                }
LAB_0010d43c:
                piVar9 = (int *)FUN_0010c598(param_1);
                if (piVar9 == (int *)0x0) {
LAB_0010d498:
                  pcVar15 = *(char **)(param_1 + 0x18);
LAB_0010d49c:
                  cVar13 = *pcVar15;
                  goto LAB_0010d4a0;
                }
                iVar3 = *piVar9;
                if (iVar3 == 0x31) {
                  ppcVar19 = *(char ***)(piVar9 + 2);
                  pcVar15 = *ppcVar19;
                  *(int *)(param_1 + 0x50) = *(int *)(param_1 + 0x50) + *(int *)(ppcVar19 + 2) + -2;
                  iVar3 = strcmp(pcVar15,"st");
                  if (iVar3 != 0) {
                    switch(*(undefined4 *)((long)ppcVar19 + 0x14)) {
                    case 0:
                      goto switchD_0010dd20_caseD_0;
                    case 1:
                      goto switchD_0010dd84_caseD_1;
                    case 2:
                      goto switchD_0010dd84_caseD_2;
                    case 3:
                      goto switchD_0010dd84_caseD_3;
                    default:
                      goto switchD_0010dd20_caseD_4;
                    }
                  }
                  uVar6 = FUN_0010ac34(param_1);
                  uVar7 = 0x35;
                  goto LAB_0010d48c;
                }
                if (iVar3 != 0x32) {
                  if (iVar3 == 0x33) {
                    if (**(char **)(param_1 + 0x18) != '_') goto switchD_0010dd20_caseD_1;
                    *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
                    uVar6 = FUN_0010fb04(param_1,0x45);
                    goto LAB_0010d484;
                  }
switchD_0010dd20_caseD_4:
                  pcVar15 = *(char **)(param_1 + 0x18);
                  goto LAB_0010da4c;
                }
                switch(piVar9[2]) {
                case 0:
switchD_0010dd20_caseD_0:
                  uVar6 = 0x34;
                  goto LAB_0010d96c;
                case 1:
                  goto switchD_0010dd20_caseD_1;
                case 2:
                  pcVar15 = (char *)0x0;
switchD_0010dd84_caseD_2:
                  if (((**(char ***)(piVar9 + 2))[1] == 'c') &&
                     ((cVar13 = ***(char ***)(piVar9 + 2), (byte)(cVar13 + 0x8eU) < 2 ||
                      ((byte)(cVar13 + 0x9dU) < 2)))) {
                    uVar6 = FUN_0010ac34(param_1);
                  }
                  else {
                    uVar6 = FUN_00111c88(param_1);
                  }
                  iVar3 = strcmp(pcVar15,"cl");
                  if (iVar3 == 0) {
                    uVar7 = FUN_0010fb04(param_1,0x45);
                  }
                  else {
                    iVar3 = strcmp(pcVar15,"dt");
                    if ((iVar3 == 0) || (iVar3 = strcmp(pcVar15,"pt"), iVar3 == 0)) {
                      uVar7 = FUN_0010c75c(param_1);
                      if (**(char **)(param_1 + 0x18) == 'I') {
                        uVar10 = FUN_0010cbec(param_1);
                        uVar7 = FUN_00109de4(param_1,4,uVar7,uVar10);
                      }
                    }
                    else {
                      uVar7 = FUN_00111c88(param_1);
                    }
                  }
                  uVar6 = FUN_00109de4(param_1,0x37,uVar6,uVar7);
                  uVar7 = 0x36;
                  break;
                case 3:
                  pcVar15 = (char *)0x0;
switchD_0010dd84_caseD_3:
                  iVar3 = strcmp(pcVar15,"qu");
                  if (iVar3 == 0) {
                    uVar6 = FUN_00111c88(param_1);
                    uVar7 = FUN_00111c88(param_1);
                    uVar10 = FUN_00111c88(param_1);
LAB_0010df1c:
                    uVar7 = FUN_00109de4(param_1,0x3a,uVar7,uVar10);
                    uVar6 = FUN_00109de4(param_1,0x39,uVar6,uVar7);
                    uVar7 = 0x38;
                    break;
                  }
                  if ((*pcVar15 != 'n') || ((pcVar15[1] != 'a' && (pcVar15[1] != 'w'))))
                  goto switchD_0010dd20_caseD_4;
                  uVar6 = FUN_0010fb04(param_1,0x5f);
                  uVar7 = FUN_0010ac34(param_1);
                  pcVar15 = *(char **)(param_1 + 0x18);
                  cVar13 = *pcVar15;
                  if (cVar13 == 'E') {
                    uVar10 = 0;
                    *(char **)(param_1 + 0x18) = pcVar15 + 1;
                    goto LAB_0010df1c;
                  }
                  if (cVar13 == 'p') {
                    if (pcVar15[1] == 'i') {
                      *(char **)(param_1 + 0x18) = pcVar15 + 2;
                      uVar10 = FUN_0010fb04(param_1,0x45);
                      goto LAB_0010df1c;
                    }
                  }
                  else {
                    if (cVar13 != 'i') {
                      piVar9 = (int *)0x0;
                      goto LAB_0010d4a0;
                    }
                    if (pcVar15[1] == 'l') {
                      uVar10 = FUN_00111c88(param_1);
                      goto LAB_0010df1c;
                    }
                  }
                  piVar9 = (int *)0x0;
LAB_0010d4d8:
                  if (((cVar13 != 't') && (cVar13 != 'i')) || (pcVar15[1] != 'l'))
                  goto LAB_0010d4f8;
                  local_18 = 0;
                  if (cVar13 == 't') {
                    local_18 = FUN_0010ac34(param_1);
                  }
                  *(long *)(param_1 + 0x18) = *(long *)(param_1 + 0x18) + 2;
                  goto LAB_0010d26c;
                default:
                  goto switchD_0010dd20_caseD_4;
                }
                goto LAB_0010d48c;
              }
              if (cVar13 == 'T') {
                piVar8 = (int *)FUN_0010a5fc(param_1);
                pcVar15 = *(char **)(param_1 + 0x18);
                cVar13 = *pcVar15;
                goto LAB_0010d3e4;
              }
              if (cVar13 == 's') {
                if (pcVar15[1] == 'r') {
                  *(char **)(param_1 + 0x18) = pcVar15 + 2;
                  piVar8 = (int *)FUN_0010ac34(param_1);
                  uVar6 = FUN_0010c75c(param_1);
                  if (**(char **)(param_1 + 0x18) != 'I') {
                    piVar8 = (int *)FUN_00109de4(param_1,1,piVar8,uVar6);
                    pcVar15 = *(char **)(param_1 + 0x18);
                    cVar13 = *pcVar15;
                    goto LAB_0010d3e4;
                  }
                  uVar7 = FUN_0010cbec(param_1);
                  uVar6 = FUN_00109de4(param_1,4,uVar6,uVar7);
                  uVar7 = 1;
                  goto LAB_0010d3d0;
                }
                if (pcVar15[1] != 'p') goto LAB_0010d380;
                *(char **)(param_1 + 0x18) = pcVar15 + 2;
                piVar8 = (int *)FUN_00111c88(param_1);
                uVar6 = 0x49;
LAB_0010d924:
                piVar8 = (int *)FUN_00109de4(param_1,uVar6,piVar8,0);
LAB_0010d930:
                pcVar15 = *(char **)(param_1 + 0x18);
LAB_0010d934:
                cVar13 = *pcVar15;
                goto LAB_0010d3e4;
              }
              if (cVar13 == 'f') {
                if (pcVar15[1] != 'p') goto LAB_0010d380;
                *(char **)(param_1 + 0x18) = pcVar15 + 2;
                if (pcVar15[2] == 'T') {
                  pcVar15 = pcVar15 + 3;
                  lVar4 = 0;
                  *(char **)(param_1 + 0x18) = pcVar15;
                }
                else {
                  iVar3 = FUN_0010a590(param_1);
                  pcVar15 = *(char **)(param_1 + 0x18);
                  if (iVar3 + 1 == 0) {
LAB_0010da3c:
                    piVar8 = (int *)0x0;
                    cVar13 = *pcVar15;
                    goto LAB_0010d3e4;
                  }
                  lVar4 = (long)(iVar3 + 1);
                }
                iVar3 = *(int *)(param_1 + 0x28);
                if (iVar3 < *(int *)(param_1 + 0x2c)) {
                  *(int *)(param_1 + 0x28) = iVar3 + 1;
                  piVar8 = (int *)(*(long *)(param_1 + 0x20) + (long)iVar3 * 0x18);
                  if (piVar8 == (int *)0x0) goto LAB_0010d934;
                  *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar3 * 0x18) = 6;
                  *(long *)(piVar8 + 2) = lVar4;
                  cVar13 = *pcVar15;
                }
                else {
                  cVar13 = *pcVar15;
                  piVar8 = (int *)0x0;
                }
                goto LAB_0010d3e4;
              }
              if ((byte)(cVar13 - 0x30U) < 10) {
LAB_0010d74c:
                piVar8 = (int *)FUN_0010c75c(param_1);
                pcVar15 = *(char **)(param_1 + 0x18);
                cVar13 = *pcVar15;
                if ((piVar8 != (int *)0x0) && (cVar13 == 'I')) {
                  uVar6 = FUN_0010cbec(param_1);
                  uVar7 = 4;
                  goto LAB_0010d3d0;
                }
                goto LAB_0010d3e4;
              }
              if (cVar13 == 'o') {
                if (pcVar15[1] == 'n') {
                  *(char **)(param_1 + 0x18) = pcVar15 + 2;
                  goto LAB_0010d74c;
                }
              }
              else if (((cVar13 == 't') || (cVar13 == 'i')) && (pcVar15[1] == 'l')) {
                uVar6 = 0;
                if (cVar13 == 't') {
                  uVar6 = FUN_0010ac34(param_1);
                  pcVar15 = *(char **)(param_1 + 0x18);
                }
                *(char **)(param_1 + 0x18) = pcVar15 + 2;
                uVar7 = FUN_0010fb04(param_1,0x45);
                piVar8 = (int *)FUN_00109de4(param_1,0x30,uVar6,uVar7);
                pcVar15 = *(char **)(param_1 + 0x18);
                cVar13 = *pcVar15;
                goto LAB_0010d3e4;
              }
LAB_0010d380:
              piVar8 = (int *)FUN_0010c598(param_1);
              if (piVar8 == (int *)0x0) goto LAB_0010d930;
              iVar3 = *piVar8;
              if (iVar3 == 0x31) {
                ppcVar19 = *(char ***)(piVar8 + 2);
                pcVar15 = *ppcVar19;
                *(int *)(param_1 + 0x50) = *(int *)(param_1 + 0x50) + *(int *)(ppcVar19 + 2) + -2;
                iVar3 = strcmp(pcVar15,"st");
                if (iVar3 != 0) {
                  switch(*(undefined4 *)((long)ppcVar19 + 0x14)) {
                  case 0:
                    goto switchD_0010dcfc_caseD_0;
                  case 1:
                    goto switchD_0010db14_caseD_1;
                  case 2:
                    goto switchD_0010db14_caseD_2;
                  case 3:
                    goto switchD_0010db14_caseD_3;
                  default:
                    goto switchD_0010dcfc_caseD_4;
                  }
                }
                uVar6 = FUN_0010ac34(param_1);
                uVar7 = 0x35;
                goto LAB_0010d3d0;
              }
              if (iVar3 != 0x32) {
                if (iVar3 == 0x33) {
                  if (**(char **)(param_1 + 0x18) != '_') goto switchD_0010dcfc_caseD_1;
                  *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
                  uVar6 = FUN_0010fb04(param_1,0x45);
                  goto LAB_0010d3c8;
                }
switchD_0010dcfc_caseD_4:
                pcVar15 = *(char **)(param_1 + 0x18);
                goto LAB_0010da3c;
              }
              switch(piVar8[2]) {
              case 0:
switchD_0010dcfc_caseD_0:
                uVar6 = 0x34;
                goto LAB_0010d924;
              case 1:
                goto switchD_0010dcfc_caseD_1;
              case 2:
                pcVar15 = (char *)0x0;
switchD_0010db14_caseD_2:
                if (((**(char ***)(piVar8 + 2))[1] == 'c') &&
                   ((cVar13 = ***(char ***)(piVar8 + 2), (byte)(cVar13 + 0x8eU) < 2 ||
                    ((byte)(cVar13 + 0x9dU) < 2)))) {
                  uVar6 = FUN_0010ac34(param_1);
                }
                else {
                  uVar6 = FUN_00111c88(param_1);
                }
                iVar3 = strcmp(pcVar15,"cl");
                if (iVar3 == 0) {
                  uVar7 = FUN_0010fb04(param_1,0x45);
                }
                else {
                  iVar3 = strcmp(pcVar15,"dt");
                  if ((iVar3 == 0) || (iVar3 = strcmp(pcVar15,"pt"), iVar3 == 0)) {
                    uVar7 = FUN_0010c75c(param_1);
                    if (**(char **)(param_1 + 0x18) == 'I') {
                      uVar10 = FUN_0010cbec(param_1);
                      uVar7 = FUN_00109de4(param_1,4,uVar7,uVar10);
                    }
                  }
                  else {
                    uVar7 = FUN_00111c88(param_1);
                  }
                }
                uVar6 = FUN_00109de4(param_1,0x37,uVar6,uVar7);
                uVar7 = 0x36;
                goto LAB_0010d3d0;
              case 3:
                pcVar15 = (char *)0x0;
switchD_0010db14_caseD_3:
                iVar3 = strcmp(pcVar15,"qu");
                if (iVar3 == 0) {
                  uVar6 = FUN_00111c88(param_1);
                  uVar7 = FUN_00111c88(param_1);
                  uVar10 = FUN_00111c88(param_1);
LAB_0010e254:
                  uVar7 = FUN_00109de4(param_1,0x3a,uVar7,uVar10);
                  uVar6 = FUN_00109de4(param_1,0x39,uVar6,uVar7);
                  uVar7 = 0x38;
                  goto LAB_0010d3d0;
                }
                if ((*pcVar15 != 'n') || ((pcVar15[1] != 'a' && (pcVar15[1] != 'w'))))
                goto switchD_0010dcfc_caseD_4;
                uVar6 = FUN_0010fb04(param_1,0x5f);
                uVar7 = FUN_0010ac34(param_1);
                pcVar15 = *(char **)(param_1 + 0x18);
                cVar13 = *pcVar15;
                if (cVar13 == 'E') {
                  uVar10 = 0;
                  *(char **)(param_1 + 0x18) = pcVar15 + 1;
                  goto LAB_0010e254;
                }
                if (cVar13 == 'p') {
                  if (pcVar15[1] == 'i') {
                    *(char **)(param_1 + 0x18) = pcVar15 + 2;
                    uVar10 = FUN_0010fb04(param_1,0x45);
                    goto LAB_0010e254;
                  }
                }
                else {
                  if (cVar13 != 'i') {
                    piVar8 = (int *)0x0;
                    goto LAB_0010d3e4;
                  }
                  if (pcVar15[1] == 'l') {
                    uVar10 = FUN_00111c88(param_1);
                    goto LAB_0010e254;
                  }
                }
                piVar8 = (int *)0x0;
LAB_0010d41c:
                if (((cVar13 != 't') && (cVar13 != 'i')) || (pcVar15[1] != 'l')) goto LAB_0010d43c;
                uVar6 = 0;
                if (cVar13 == 't') {
                  uVar6 = FUN_0010ac34(param_1);
                }
                *(long *)(param_1 + 0x18) = *(long *)(param_1 + 0x18) + 2;
                uVar7 = FUN_0010fb04(param_1,0x45);
                piVar9 = (int *)FUN_00109de4(param_1,0x30,uVar6,uVar7);
                pcVar15 = *(char **)(param_1 + 0x18);
                cVar13 = *pcVar15;
LAB_0010d4a0:
                if (cVar13 == 'L') {
                  lVar4 = FUN_0010f980(param_1);
                }
                else if (cVar13 == 'T') {
                  lVar4 = FUN_0010a5fc(param_1);
                }
                else if (cVar13 == 's') {
                  if (pcVar15[1] == 'r') {
                    *(char **)(param_1 + 0x18) = pcVar15 + 2;
                    uVar6 = FUN_0010ac34(param_1);
                    uVar7 = FUN_0010c75c(param_1);
                    if (**(char **)(param_1 + 0x18) == 'I') {
                      uVar10 = FUN_0010cbec(param_1);
                      uVar7 = FUN_00109de4(param_1,4,uVar7,uVar10);
                    }
                    lVar4 = FUN_00109de4(param_1,1,uVar6,uVar7);
                  }
                  else {
                    if (pcVar15[1] != 'p') goto LAB_0010d4f8;
                    *(char **)(param_1 + 0x18) = pcVar15 + 2;
                    uVar6 = FUN_00111c88(param_1);
                    lVar4 = FUN_00109de4(param_1,0x49,uVar6,0);
                  }
                }
                else if (cVar13 == 'f') {
                  if (pcVar15[1] == 'p') {
                    *(char **)(param_1 + 0x18) = pcVar15 + 2;
                    if (pcVar15[2] == 'T') {
                      lVar16 = 0;
                      *(char **)(param_1 + 0x18) = pcVar15 + 3;
                    }
                    else {
                      iVar3 = FUN_0010a590(param_1);
                      if (iVar3 + 1 == 0) goto LAB_0010db8c;
                      lVar16 = (long)(iVar3 + 1);
                    }
                    iVar3 = *(int *)(param_1 + 0x28);
                    lVar4 = 0;
                    if (iVar3 < *(int *)(param_1 + 0x2c)) {
                      *(int *)(param_1 + 0x28) = iVar3 + 1;
                      lVar4 = *(long *)(param_1 + 0x20) + (long)iVar3 * 0x18;
                      if (lVar4 != 0) {
                        *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar3 * 0x18) = 6;
                        *(long *)(lVar4 + 8) = lVar16;
                      }
                    }
                  }
                  else {
LAB_0010d4f8:
                    piVar11 = (int *)FUN_0010c598(param_1);
                    if (piVar11 == (int *)0x0) {
                      lVar4 = 0;
                    }
                    else {
                      iVar3 = *piVar11;
                      if (iVar3 == 0x31) {
                        ppcVar19 = *(char ***)(piVar11 + 2);
                        pcVar15 = *ppcVar19;
                        *(int *)(param_1 + 0x50) =
                             *(int *)(param_1 + 0x50) + *(int *)(ppcVar19 + 2) + -2;
                        iVar3 = strcmp(pcVar15,"st");
                        if (iVar3 != 0) {
                          lVar4 = 0;
                          switch(*(undefined4 *)((long)ppcVar19 + 0x14)) {
                          case 0:
                            goto switchD_0010dcd8_caseD_0;
                          case 1:
                            cVar13 = *pcVar15;
                            if (((cVar13 == 'm') || (cVar13 == 'p')) && (pcVar15[1] == cVar13)) {
                              if (**(char **)(param_1 + 0x18) != '_') {
                                uVar6 = FUN_00111c88(param_1);
                                uVar6 = FUN_00109de4(param_1,0x37,uVar6,uVar6);
                                goto LAB_0010d540;
                              }
                              *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
                            }
                            goto switchD_0010dcd8_caseD_1;
                          case 2:
                            goto switchD_0010dcac_caseD_2;
                          case 3:
                            goto switchD_0010dcac_caseD_3;
                          }
                          break;
                        }
                        uVar6 = FUN_0010ac34(param_1);
                      }
                      else {
                        if (iVar3 == 0x32) {
                          lVar4 = 0;
                          switch(piVar11[2]) {
                          case 0:
switchD_0010dcd8_caseD_0:
                            lVar4 = FUN_00109de4(param_1,0x34,piVar11,0);
                            break;
                          case 1:
                            goto switchD_0010dcd8_caseD_1;
                          case 2:
                            pcVar15 = (char *)0x0;
switchD_0010dcac_caseD_2:
                            if (((**(char ***)(piVar11 + 2))[1] == 'c') &&
                               ((cVar13 = ***(char ***)(piVar11 + 2), (byte)(cVar13 + 0x8eU) < 2 ||
                                ((byte)(cVar13 + 0x9dU) < 2)))) {
                              uVar6 = FUN_0010ac34(param_1);
                            }
                            else {
                              uVar6 = FUN_00111c88(param_1);
                            }
                            iVar3 = strcmp(pcVar15,"cl");
                            if (iVar3 == 0) {
                              uVar7 = FUN_0010fb04(param_1,0x45);
                            }
                            else {
                              iVar3 = strcmp(pcVar15,"dt");
                              if ((iVar3 == 0) || (iVar3 = strcmp(pcVar15,"pt"), iVar3 == 0)) {
                                uVar7 = FUN_0010c75c(param_1);
                                if (**(char **)(param_1 + 0x18) == 'I') {
                                  uVar10 = FUN_0010cbec(param_1);
                                  uVar7 = FUN_00109de4(param_1,4,uVar7,uVar10);
                                }
                              }
                              else {
                                uVar7 = FUN_00111c88(param_1);
                              }
                            }
                            uVar6 = FUN_00109de4(param_1,0x37,uVar6,uVar7);
                            lVar4 = FUN_00109de4(param_1,0x36,piVar11,uVar6);
                            break;
                          case 3:
                            pcVar15 = (char *)0x0;
switchD_0010dcac_caseD_3:
                            iVar3 = strcmp(pcVar15,"qu");
                            if (iVar3 == 0) {
                              uVar6 = FUN_00111c88(param_1);
                              uVar7 = FUN_00111c88(param_1);
                              uVar10 = FUN_00111c88(param_1);
LAB_0010e51c:
                              uVar7 = FUN_00109de4(param_1,0x3a,uVar7,uVar10);
                              uVar6 = FUN_00109de4(param_1,0x39,uVar6,uVar7);
                              lVar4 = FUN_00109de4(param_1,0x38,piVar11,uVar6);
                            }
                            else if ((*pcVar15 == 'n') &&
                                    ((pcVar15[1] == 'a' || (pcVar15[1] == 'w')))) {
                              uVar6 = FUN_0010fb04(param_1,0x5f);
                              uVar7 = FUN_0010ac34(param_1);
                              pcVar15 = *(char **)(param_1 + 0x18);
                              cVar13 = *pcVar15;
                              if (cVar13 == 'E') {
                                uVar10 = 0;
                                *(char **)(param_1 + 0x18) = pcVar15 + 1;
                                goto LAB_0010e51c;
                              }
                              if (cVar13 == 'p') {
                                lVar4 = 0;
                                if (pcVar15[1] == 'i') {
                                  *(char **)(param_1 + 0x18) = pcVar15 + 2;
                                  uVar10 = FUN_0010fb04(param_1,0x45);
                                  goto LAB_0010e51c;
                                }
                              }
                              else {
                                if (cVar13 != 'i') goto LAB_0010db8c;
                                lVar4 = 0;
                                if (pcVar15[1] == 'l') {
                                  uVar10 = FUN_00111c88(param_1);
                                  goto LAB_0010e51c;
                                }
                              }
                            }
                            else {
LAB_0010db8c:
                              lVar4 = 0;
                            }
                          }
                          break;
                        }
                        if (iVar3 != 0x33) goto LAB_0010db8c;
                        if (**(char **)(param_1 + 0x18) == '_') {
                          *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
                          uVar6 = FUN_0010fb04(param_1,0x45);
                          goto LAB_0010d540;
                        }
switchD_0010dcd8_caseD_1:
                        uVar6 = FUN_00111c88(param_1);
                      }
LAB_0010d540:
                      lVar4 = FUN_00109de4(param_1,0x35,piVar11,uVar6);
                    }
                  }
                }
                else {
                  if (9 < (byte)(cVar13 - 0x30U)) {
                    if (cVar13 != 'o') goto LAB_0010d4d8;
                    if (pcVar15[1] != 'n') goto LAB_0010d4f8;
                    *(char **)(param_1 + 0x18) = pcVar15 + 2;
                  }
                  lVar4 = FUN_0010c75c(param_1);
                  if ((lVar4 != 0) && (**(char **)(param_1 + 0x18) == 'I')) {
                    uVar6 = FUN_0010cbec(param_1);
                    lVar4 = FUN_00109de4(param_1,4,lVar4,uVar6);
                  }
                }
                break;
              default:
                goto switchD_0010dcfc_caseD_4;
              }
            }
            else {
              if ((*pcVar15 != 'n') || ((pcVar15[1] != 'a' && (pcVar15[1] != 'w')))) break;
              piVar8 = (int *)FUN_0010fb04(param_1,0x5f);
              piVar9 = (int *)FUN_0010ac34(param_1);
              pcVar15 = *(char **)(param_1 + 0x18);
              cVar13 = *pcVar15;
              if (cVar13 == 'E') {
                lVar4 = 0;
                *(char **)(param_1 + 0x18) = pcVar15 + 1;
                goto switchD_0010dcd8_caseD_4;
              }
              if (cVar13 == 'p') {
                lVar4 = 0;
                if (pcVar15[1] == 'i') {
                  *(char **)(param_1 + 0x18) = pcVar15 + 2;
                  lVar4 = FUN_0010fb04(param_1,0x45);
                  goto switchD_0010dcd8_caseD_4;
                }
                goto LAB_0010cde4;
              }
              lVar4 = 0;
              if ((cVar13 != 'i') || (pcVar15[1] != 'l')) goto LAB_0010cde4;
              local_18 = 0;
              *(char **)(param_1 + 0x18) = pcVar15 + 2;
LAB_0010d26c:
              uVar6 = FUN_0010fb04(param_1,0x45);
              lVar4 = FUN_00109de4(param_1,0x30,local_18,uVar6);
            }
switchD_0010dcd8_caseD_4:
            uVar6 = FUN_00109de4(param_1,0x3a,piVar9,lVar4);
            uVar6 = FUN_00109de4(param_1,0x39,piVar8,uVar6);
            lVar4 = FUN_00109de4(param_1,0x38,piVar5,uVar6);
            goto LAB_0010d2c4;
          }
        }
        else if (iVar3 == 0x33) {
          if (**(char **)(param_1 + 0x18) == '_') {
            *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
            uVar6 = FUN_0010fb04(param_1,0x45);
            goto LAB_0010d124;
          }
switchD_0010d0a8_caseD_1:
          uVar6 = FUN_00111c88(param_1);
          goto LAB_0010d124;
        }
      }
switchD_0010d0a8_caseD_4:
      pcVar15 = *(char **)(param_1 + 0x18);
      lVar4 = 0;
    }
LAB_0010cde4:
    *(undefined4 *)(param_1 + 0x54) = uVar1;
    if (*pcVar15 != 'E') {
      return 0;
    }
    *(char **)(param_1 + 0x18) = pcVar15 + 1;
  }
  if (lVar4 == 0) {
    return 0;
  }
  lVar4 = FUN_00109de4(param_1,0x2f,lVar4,0);
  *plVar17 = lVar4;
  if (lVar4 == 0) {
    return 0;
  }
  pcVar14 = *(char **)(param_1 + 0x18);
  plVar17 = (long *)(lVar4 + 0x10);
  cVar13 = *pcVar14;
  if (cVar13 == 'E') {
    *(undefined8 *)(param_1 + 0x48) = uVar18;
    *(char **)(param_1 + 0x18) = pcVar14 + 1;
    return local_8;
  }
  goto LAB_0010cc64;
switchD_0010db14_caseD_1:
  cVar13 = *pcVar15;
  if (((cVar13 == 'm') || (cVar13 == 'p')) && (pcVar15[1] == cVar13)) {
    if (**(char **)(param_1 + 0x18) != '_') {
      uVar6 = FUN_00111c88(param_1);
      uVar6 = FUN_00109de4(param_1,0x37,uVar6,uVar6);
      uVar7 = 0x35;
      goto LAB_0010d3d0;
    }
    *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
  }
switchD_0010dcfc_caseD_1:
  uVar6 = FUN_00111c88(param_1);
LAB_0010d3c8:
  uVar7 = 0x35;
LAB_0010d3d0:
  piVar8 = (int *)FUN_00109de4(param_1,uVar7,piVar8,uVar6);
  pcVar15 = *(char **)(param_1 + 0x18);
  cVar13 = *pcVar15;
  goto LAB_0010d3e4;
switchD_0010dd84_caseD_1:
  cVar13 = *pcVar15;
  if (((cVar13 == 'm') || (cVar13 == 'p')) && (pcVar15[1] == cVar13)) {
    if (**(char **)(param_1 + 0x18) != '_') {
      uVar6 = FUN_00111c88(param_1);
      uVar6 = FUN_00109de4(param_1,0x37,uVar6,uVar6);
      uVar7 = 0x35;
      goto LAB_0010d48c;
    }
    *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
  }
switchD_0010dd20_caseD_1:
  uVar6 = FUN_00111c88(param_1);
LAB_0010d484:
  uVar7 = 0x35;
LAB_0010d48c:
  piVar9 = (int *)FUN_00109de4(param_1,uVar7,piVar9,uVar6);
  goto LAB_0010d498;
switchD_0010e160_caseD_1:
  cVar13 = *pcVar15;
  if (((cVar13 == 'm') || (cVar13 == 'p')) && (pcVar15[1] == cVar13)) {
    if (**(char **)(param_1 + 0x18) != '_') {
      uVar7 = FUN_00111c88(param_1);
      uVar7 = FUN_00109de4(param_1,0x37,uVar7,uVar7);
      goto LAB_0010d648;
    }
    *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
  }
  goto switchD_0010e0f8_caseD_1;
}



long FUN_0010ed9c(long param_1)

{
  int iVar1;
  int iVar2;
  long lVar3;
  long *plVar4;
  long lVar5;
  int *piVar6;
  undefined8 uVar7;
  undefined8 uVar8;
  long lVar9;
  int *piVar10;
  char *pcVar11;
  char *pcVar12;
  undefined *puVar13;
  char cVar14;
  long local_8;
  
  puVar13 = *(undefined **)(param_1 + 0x18);
  switch(*puVar13) {
  case 0x4e:
    *(undefined **)(param_1 + 0x18) = puVar13 + 1;
    plVar4 = (long *)FUN_00109f00(param_1,&local_8,1);
    if (plVar4 != (long *)0x0) {
      lVar5 = FUN_0010a0ac(param_1);
      pcVar11 = *(char **)(param_1 + 0x18);
      cVar14 = *pcVar11;
      lVar3 = 0;
LAB_0010ef10:
      if (cVar14 != '\0') {
        pcVar12 = pcVar11;
        if (cVar14 == 'D') {
          if ((pcVar11[1] & 0xdfU) != 0x54) {
            lVar9 = FUN_0010c75c(param_1);
            goto LAB_0010f180;
          }
          lVar9 = FUN_0010ac34();
          goto LAB_0010f180;
        }
        do {
          if ((((byte)(cVar14 - 0x30U) < 10) || ((byte)(cVar14 + 0x9fU) < 0x1a)) ||
             ((cVar14 == 'C' || cVar14 == 'U' || (cVar14 == 'L')))) {
            lVar9 = FUN_0010c75c(param_1);
            if (lVar3 != 0) goto LAB_0010f0fc;
LAB_0010f110:
            if (cVar14 == 'S') goto LAB_0010f14c;
          }
          else {
            if (cVar14 == 'S') {
              lVar9 = FUN_0010a118(param_1,1);
              if (lVar3 != 0) {
LAB_0010f0fc:
                uVar8 = 1;
LAB_0010f100:
                lVar9 = FUN_00109de4(param_1,uVar8,lVar3,lVar9);
                goto LAB_0010f110;
              }
              pcVar11 = *(char **)(param_1 + 0x18);
              cVar14 = *pcVar11;
              lVar3 = lVar9;
              goto LAB_0010ef10;
            }
            if (cVar14 == 'I') {
              if (lVar3 != 0) {
                lVar9 = FUN_0010cbec(param_1);
                uVar8 = 4;
                goto LAB_0010f100;
              }
              goto LAB_0010f198;
            }
            if (cVar14 != 'T') {
              if (cVar14 == 'E') {
                *plVar4 = lVar3;
                if (lVar3 == 0) {
                  return 0;
                }
                if (lVar5 != 0) {
                  *(long *)(lVar5 + 8) = local_8;
                  local_8 = lVar5;
                }
                if (**(char **)(param_1 + 0x18) == 'E') {
                  *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
                  return local_8;
                }
                return 0;
              }
              if ((cVar14 != 'M') || (lVar3 == 0)) goto LAB_0010f198;
              pcVar11 = pcVar12 + 1;
              *(char **)(param_1 + 0x18) = pcVar11;
              cVar14 = pcVar12[1];
              goto LAB_0010ef10;
            }
            lVar9 = FUN_0010a5fc(param_1);
LAB_0010f180:
            if (lVar3 != 0) goto LAB_0010f0fc;
          }
          pcVar12 = *(char **)(param_1 + 0x18);
          cVar14 = *pcVar12;
          lVar3 = lVar9;
        } while (cVar14 == 'E');
        if ((lVar9 == 0) || (iVar1 = *(int *)(param_1 + 0x38), *(int *)(param_1 + 0x3c) <= iVar1))
        goto LAB_0010f198;
        *(long *)(*(long *)(param_1 + 0x30) + (long)iVar1 * 8) = lVar9;
        *(int *)(param_1 + 0x38) = iVar1 + 1;
LAB_0010f14c:
        pcVar11 = *(char **)(param_1 + 0x18);
        cVar14 = *pcVar11;
        lVar3 = lVar9;
        goto LAB_0010ef10;
      }
LAB_0010f198:
      *plVar4 = 0;
    }
    break;
  default:
    lVar3 = FUN_0010c75c(param_1);
    if (**(char **)(param_1 + 0x18) != 'I') {
      return lVar3;
    }
    if (lVar3 != 0) {
      iVar1 = *(int *)(param_1 + 0x38);
      if (iVar1 < *(int *)(param_1 + 0x3c)) {
        *(long *)(*(long *)(param_1 + 0x30) + (long)iVar1 * 8) = lVar3;
        *(int *)(param_1 + 0x38) = iVar1 + 1;
        uVar8 = FUN_0010cbec(param_1);
        lVar3 = FUN_00109de4(param_1,4,lVar3,uVar8);
        return lVar3;
      }
      return 0;
    }
    return 0;
  case 0x53:
    if (puVar13[1] == 't') {
      *(undefined **)(param_1 + 0x18) = puVar13 + 2;
      uVar8 = FUN_00109e98(param_1,&DAT_0011f488,3);
      uVar7 = FUN_0010c75c(param_1);
      lVar3 = FUN_00109de4(param_1,1,uVar8,uVar7);
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
      lVar3 = FUN_0010a118(param_1,0);
      if (**(char **)(param_1 + 0x18) != 'I') {
        return lVar3;
      }
    }
    uVar8 = FUN_0010cbec(param_1);
    lVar3 = FUN_00109de4(param_1,4,lVar3,uVar8);
    return lVar3;
  case 0x55:
    lVar3 = FUN_0010c75c(param_1);
    return lVar3;
  case 0x5a:
    *(undefined **)(param_1 + 0x18) = puVar13 + 1;
    uVar8 = FUN_0010f2f0(param_1,0);
    pcVar11 = *(char **)(param_1 + 0x18);
    if (*pcVar11 == 'E') {
      *(char **)(param_1 + 0x18) = pcVar11 + 1;
      if (pcVar11[1] == 's') {
        *(char **)(param_1 + 0x18) = pcVar11 + 2;
        iVar1 = FUN_0010a69c(param_1);
        if (iVar1 != 0) {
          piVar6 = (int *)FUN_00109e98(param_1,"string literal",0xe);
          goto LAB_0010eff0;
        }
      }
      else if (pcVar11[1] == 'd') {
        *(char **)(param_1 + 0x18) = pcVar11 + 2;
        iVar1 = FUN_0010a590(param_1);
        if ((-1 < iVar1) &&
           ((((piVar10 = (int *)FUN_0010ed9c(param_1), piVar10 == (int *)0x0 || (*piVar10 == 0x44))
             || (*piVar10 == 0x46)) || (iVar2 = FUN_0010a69c(param_1), iVar2 != 0)))) {
          iVar2 = *(int *)(param_1 + 0x28);
          piVar6 = (int *)0x0;
          if (iVar2 < *(int *)(param_1 + 0x2c)) {
            *(int *)(param_1 + 0x28) = iVar2 + 1;
            piVar6 = (int *)(*(long *)(param_1 + 0x20) + (long)iVar2 * 0x18);
            if (piVar6 != (int *)0x0) {
              *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar2 * 0x18) = 0x45;
              piVar6[4] = iVar1;
              *(int **)(piVar6 + 2) = piVar10;
            }
          }
          goto LAB_0010eff0;
        }
      }
      else {
        piVar6 = (int *)FUN_0010ed9c(param_1);
        if (((piVar6 == (int *)0x0) || (*piVar6 == 0x44)) ||
           ((*piVar6 == 0x46 || (iVar1 = FUN_0010a69c(param_1), iVar1 != 0)))) {
LAB_0010eff0:
          lVar3 = FUN_00109de4(param_1,2,uVar8,piVar6);
          return lVar3;
        }
      }
    }
  }
  return 0;
}



uint * FUN_0010f2f0(long param_1,int param_2)

{
  uint **ppuVar1;
  char cVar2;
  int iVar3;
  uint *puVar4;
  long lVar5;
  long lVar6;
  uint uVar7;
  uint *puVar8;
  int *piVar9;
  undefined4 *puVar10;
  undefined8 uVar11;
  char *pcVar12;
  ulong uVar13;
  char *pcVar14;
  
  pcVar12 = *(char **)(param_1 + 0x18);
  if ((*pcVar12 == 'T') || (*pcVar12 == 'G')) {
    iVar3 = *(int *)(param_1 + 0x50);
    *(int *)(param_1 + 0x50) = iVar3 + 0x14;
    if (*pcVar12 == 'T') {
      *(char **)(param_1 + 0x18) = pcVar12 + 1;
      if (pcVar12[1] == '\0') {
        return (uint *)0x0;
      }
      *(char **)(param_1 + 0x18) = pcVar12 + 2;
      switch(pcVar12[1]) {
      case 'C':
        lVar5 = FUN_0010ac34(param_1);
        lVar6 = FUN_0010a50c(param_1 + 0x18);
        if (lVar6 < 0) {
          return (uint *)0x0;
        }
        if (**(char **)(param_1 + 0x18) != '_') {
          return (uint *)0x0;
        }
        *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
        puVar4 = (uint *)FUN_0010ac34(param_1);
        uVar11 = 0xb;
        *(int *)(param_1 + 0x50) = *(int *)(param_1 + 0x50) + 5;
        break;
      default:
        return (uint *)0x0;
      case 'F':
        puVar4 = (uint *)FUN_0010ac34(param_1);
        uVar11 = 0xe;
        lVar5 = 0;
        break;
      case 'H':
        puVar4 = (uint *)FUN_0010ed9c(param_1);
        uVar11 = 0x14;
        lVar5 = 0;
        break;
      case 'I':
        puVar4 = (uint *)FUN_0010ac34(param_1);
        uVar11 = 0xc;
        lVar5 = 0;
        break;
      case 'J':
        puVar4 = (uint *)FUN_0010ac34(param_1);
        uVar11 = 0x12;
        lVar5 = 0;
        break;
      case 'S':
        puVar4 = (uint *)FUN_0010ac34(param_1);
        uVar11 = 0xd;
        lVar5 = 0;
        break;
      case 'T':
        *(int *)(param_1 + 0x50) = iVar3 + 10;
        puVar4 = (uint *)FUN_0010ac34(param_1);
        uVar11 = 10;
        lVar5 = 0;
        break;
      case 'V':
        *(int *)(param_1 + 0x50) = iVar3 + 0xf;
        puVar4 = (uint *)FUN_0010ac34(param_1);
        uVar11 = 9;
        lVar5 = 0;
        break;
      case 'W':
        puVar4 = (uint *)FUN_0010ed9c(param_1);
        uVar11 = 0x15;
        lVar5 = 0;
        break;
      case 'c':
        iVar3 = FUN_0010a7f8(param_1,0);
        if (iVar3 == 0) {
          return (uint *)0x0;
        }
        iVar3 = FUN_0010a7f8(param_1,0);
        if (iVar3 == 0) {
          return (uint *)0x0;
        }
        puVar4 = (uint *)FUN_0010f2f0(param_1,0);
        uVar11 = 0x11;
        lVar5 = 0;
        break;
      case 'h':
        iVar3 = FUN_0010a7f8(param_1,0x68);
        if (iVar3 == 0) {
          return (uint *)0x0;
        }
        puVar4 = (uint *)FUN_0010f2f0(param_1,0);
        uVar11 = 0xf;
        lVar5 = 0;
        break;
      case 'v':
        iVar3 = FUN_0010a7f8(param_1,0x76);
        if (iVar3 == 0) {
          return (uint *)0x0;
        }
        puVar4 = (uint *)FUN_0010f2f0(param_1,0);
        uVar11 = 0x10;
        lVar5 = 0;
      }
    }
    else {
      if (*pcVar12 != 'G') {
        return (uint *)0x0;
      }
      *(char **)(param_1 + 0x18) = pcVar12 + 1;
      if (pcVar12[1] == '\0') {
        return (uint *)0x0;
      }
      *(char **)(param_1 + 0x18) = pcVar12 + 2;
      switch(pcVar12[1]) {
      case 'A':
        puVar4 = (uint *)FUN_0010f2f0(param_1,0);
        uVar11 = 0x17;
        lVar5 = 0;
        break;
      default:
        return (uint *)0x0;
      case 'R':
        puVar4 = (uint *)FUN_0010ed9c(param_1);
        iVar3 = *(int *)(param_1 + 0x28);
        if (iVar3 < *(int *)(param_1 + 0x2c)) {
          *(int *)(param_1 + 0x28) = iVar3 + 1;
          lVar5 = *(long *)(param_1 + 0x20) + (long)iVar3 * 0x18;
          if (lVar5 != 0) {
            *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar3 * 0x18) = 0x40;
            uVar11 = FUN_0010a50c(param_1 + 0x18);
            *(undefined8 *)(lVar5 + 8) = uVar11;
          }
        }
        else {
          lVar5 = 0;
        }
        uVar11 = 0x16;
        break;
      case 'T':
        if ((pcVar12[2] == '\0') || (*(char **)(param_1 + 0x18) = pcVar12 + 3, pcVar12[2] != 'n')) {
          puVar4 = (uint *)FUN_0010f2f0(param_1,0);
          uVar11 = 0x47;
          lVar5 = 0;
        }
        else {
          puVar4 = (uint *)FUN_0010f2f0(param_1,0);
          uVar11 = 0x48;
          lVar5 = 0;
        }
        break;
      case 'V':
        puVar4 = (uint *)FUN_0010ed9c(param_1);
        uVar11 = 0x13;
        lVar5 = 0;
        break;
      case 'r':
        lVar5 = FUN_0010a50c(param_1 + 0x18);
        if (lVar5 < 2) {
          return (uint *)0x0;
        }
        pcVar12 = *(char **)(param_1 + 0x18);
        if (*pcVar12 == '\0') {
          return (uint *)0x0;
        }
        pcVar14 = pcVar12 + 1;
        *(char **)(param_1 + 0x18) = pcVar14;
        if (*pcVar12 != '_') {
          return (uint *)0x0;
        }
        lVar5 = lVar5 + -1;
        puVar8 = (uint *)0x0;
        do {
          if (*pcVar14 == '\0') {
            return (uint *)0x0;
          }
          uVar13 = 0;
          if (*pcVar14 == '$') {
            cVar2 = pcVar14[1];
            if (cVar2 == 'S') {
              uVar7 = 0x2f;
            }
            else if (cVar2 == '_') {
              uVar7 = 0x2e;
            }
            else {
              if (cVar2 != '$') {
                return (uint *)0x0;
              }
              uVar7 = 0x24;
            }
            iVar3 = *(int *)(param_1 + 0x28);
            if (*(int *)(param_1 + 0x2c) <= iVar3) {
LAB_0010f95c:
              *(long *)(param_1 + 0x18) = *(long *)(param_1 + 0x18) + 2;
              return (uint *)0x0;
            }
            *(int *)(param_1 + 0x28) = iVar3 + 1;
            puVar4 = (uint *)(*(long *)(param_1 + 0x20) + (long)iVar3 * 0x18);
            if (puVar4 == (uint *)0x0) goto LAB_0010f95c;
            *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar3 * 0x18) = 0x3f;
            lVar6 = -2;
            puVar4[2] = uVar7;
            pcVar14 = (char *)(*(long *)(param_1 + 0x18) + 2);
            *(char **)(param_1 + 0x18) = pcVar14;
          }
          else {
            do {
              uVar13 = uVar13 + 1;
              if ((lVar5 <= (long)uVar13) || (pcVar14[uVar13] == '\0')) break;
            } while (pcVar14[uVar13] != '$');
            lVar6 = -uVar13;
            puVar4 = (uint *)FUN_00109e98(param_1,pcVar14,uVar13 & 0xffffffff);
            pcVar14 = (char *)(*(long *)(param_1 + 0x18) + uVar13);
            *(char **)(param_1 + 0x18) = pcVar14;
            if (puVar4 == (uint *)0x0) {
              return (uint *)0x0;
            }
          }
          lVar5 = lVar5 + lVar6;
          if ((puVar8 != (uint *)0x0) &&
             (puVar4 = (uint *)FUN_00109de4(param_1,0x3e,puVar8), puVar4 == (uint *)0x0)) {
            return (uint *)0x0;
          }
          puVar8 = puVar4;
        } while (0 < lVar5);
        uVar11 = 0x3d;
        lVar5 = 0;
      }
    }
    goto LAB_0010f4c0;
  }
  puVar4 = (uint *)FUN_0010ed9c();
  if ((puVar4 != (uint *)0x0) && ((param_2 != 0 && ((*(uint *)(param_1 + 0x10) & 1) == 0)))) {
    for (; *puVar4 - 0x1c < 5; puVar4 = *(uint **)(puVar4 + 2)) {
    }
    if (*puVar4 == 2) {
      piVar9 = *(int **)(puVar4 + 4);
      iVar3 = *piVar9;
      while (iVar3 - 0x1cU < 5) {
        piVar9 = *(int **)(piVar9 + 2);
        iVar3 = *piVar9;
      }
      *(int **)(puVar4 + 4) = piVar9;
    }
    return puVar4;
  }
  if (**(char **)(param_1 + 0x18) == 'E' || **(char **)(param_1 + 0x18) == '\0') {
    return puVar4;
  }
  puVar8 = puVar4;
  if (puVar4 == (uint *)0x0) {
    return (uint *)0x0;
  }
  do {
    uVar7 = *puVar8;
    if (uVar7 == 4) {
      puVar10 = *(undefined4 **)(puVar8 + 2);
      if (puVar10 != (undefined4 *)0x0) goto LAB_0010f438;
      goto switchD_0010f49c_caseD_3;
    }
    if ((uVar7 < 4) || (4 < uVar7 - 0x1c)) goto switchD_0010f49c_caseD_7;
    ppuVar1 = (uint **)(puVar8 + 2);
    puVar8 = *ppuVar1;
  } while (*ppuVar1 != (uint *)0x0);
  uVar11 = 0;
LAB_0010f4a4:
  lVar5 = FUN_0010c498(param_1,uVar11);
  uVar11 = 3;
LAB_0010f4c0:
  puVar4 = (uint *)FUN_00109de4(param_1,uVar11,puVar4,lVar5);
  return puVar4;
LAB_0010f438:
  switch(*puVar10) {
  case 1:
  case 2:
    goto switchD_0010f49c_caseD_1;
  default:
    break;
  case 7:
  case 8:
  case 0x33:
    goto switchD_0010f49c_caseD_7;
  }
switchD_0010f49c_caseD_3:
  uVar11 = 1;
  goto LAB_0010f4a4;
switchD_0010f49c_caseD_1:
  puVar10 = *(undefined4 **)(puVar10 + 4);
  if (puVar10 == (undefined4 *)0x0) goto code_r0x0010f51c;
  goto LAB_0010f438;
code_r0x0010f51c:
  uVar11 = 1;
  goto LAB_0010f4a4;
switchD_0010f49c_caseD_7:
  uVar11 = 0;
  goto LAB_0010f4a4;
}



undefined8 FUN_0010f980(long param_1)

{
  char cVar1;
  int *piVar2;
  undefined8 uVar3;
  char *pcVar4;
  char cVar5;
  int iVar6;
  char *pcVar7;
  undefined8 uVar8;
  
  pcVar7 = *(char **)(param_1 + 0x18);
  if (*pcVar7 != 'L') {
    return 0;
  }
  pcVar4 = pcVar7 + 1;
  *(char **)(param_1 + 0x18) = pcVar4;
  cVar1 = pcVar7[1];
  if (cVar1 == 'Z') {
    cVar5 = 'Z';
    if (cVar1 == '_') goto LAB_0010fab4;
  }
  else {
    if (cVar1 != '_') {
      piVar2 = (int *)FUN_0010ac34();
      if (piVar2 == (int *)0x0) {
        return 0;
      }
      if ((*piVar2 == 0x27) && (*(int *)(*(long *)(piVar2 + 2) + 0x1c) != 0)) {
        *(int *)(param_1 + 0x50) = *(int *)(param_1 + 0x50) - *(int *)(*(long *)(piVar2 + 2) + 8);
      }
      pcVar4 = *(char **)(param_1 + 0x18);
      uVar8 = 0x3b;
      cVar1 = *pcVar4;
      pcVar7 = pcVar4;
      if (cVar1 == 'n') {
        pcVar7 = pcVar4 + 1;
        *(char **)(param_1 + 0x18) = pcVar7;
        uVar8 = 0x3c;
        cVar1 = pcVar4[1];
      }
      pcVar4 = pcVar7;
      if (cVar1 == 'E') {
        iVar6 = 0;
      }
      else {
        do {
          if (cVar1 == '\0') {
            return 0;
          }
          pcVar4 = pcVar4 + 1;
          *(char **)(param_1 + 0x18) = pcVar4;
          cVar1 = *pcVar4;
        } while (cVar1 != 'E');
        iVar6 = (int)pcVar4 - (int)pcVar7;
      }
      uVar3 = FUN_00109e98(param_1,pcVar7,iVar6);
      uVar8 = FUN_00109de4(param_1,uVar8,piVar2,uVar3);
      pcVar4 = *(char **)(param_1 + 0x18);
      cVar5 = *pcVar4;
      goto LAB_0010fa5c;
    }
LAB_0010fab4:
    pcVar4 = pcVar7 + 2;
    *(char **)(param_1 + 0x18) = pcVar4;
    cVar5 = pcVar7[2];
  }
  uVar8 = 0;
  if (cVar5 == 'Z') {
    *(char **)(param_1 + 0x18) = pcVar4 + 1;
    uVar8 = FUN_0010f2f0(param_1);
    pcVar4 = *(char **)(param_1 + 0x18);
    cVar5 = *pcVar4;
  }
LAB_0010fa5c:
  if (cVar5 != 'E') {
    return 0;
  }
  *(char **)(param_1 + 0x18) = pcVar4 + 1;
  return uVar8;
}



long FUN_0010fb04(long param_1,char param_2)

{
  undefined4 uVar1;
  bool bVar2;
  int iVar3;
  int iVar4;
  int *piVar5;
  undefined8 uVar6;
  long lVar7;
  long lVar8;
  undefined8 uVar9;
  int *piVar10;
  int *piVar11;
  int *piVar12;
  undefined8 uVar13;
  char cVar14;
  char *pcVar15;
  long *plVar16;
  char **ppcVar17;
  long local_8;
  
  pcVar15 = *(char **)(param_1 + 0x18);
  plVar16 = &local_8;
  local_8 = 0;
  if (*pcVar15 == param_2) {
    *(char **)(param_1 + 0x18) = pcVar15 + 1;
    uVar6 = FUN_00109de4(param_1,0x2e,0,0);
    return uVar6;
  }
LAB_0010fb60:
  uVar1 = *(undefined4 *)(param_1 + 0x54);
  *(undefined4 *)(param_1 + 0x54) = 1;
  cVar14 = *pcVar15;
  if (cVar14 == 'L') {
    lVar7 = FUN_0010f980(param_1);
LAB_0010fcb8:
    *(undefined4 *)(param_1 + 0x54) = uVar1;
    if (lVar7 == 0) {
      return 0;
    }
  }
  else {
    if (cVar14 == 'T') {
      lVar7 = FUN_0010a5fc(param_1);
      goto LAB_0010fcb8;
    }
    if (cVar14 == 's') {
      if (pcVar15[1] == 'r') {
        *(char **)(param_1 + 0x18) = pcVar15 + 2;
        uVar6 = FUN_0010ac34(param_1);
        uVar9 = FUN_0010c75c(param_1);
        if (**(char **)(param_1 + 0x18) == 'I') {
          uVar13 = FUN_0010cbec(param_1);
          uVar9 = FUN_00109de4(param_1,4,uVar9,uVar13);
        }
        lVar7 = FUN_00109de4(param_1,1,uVar6,uVar9);
      }
      else {
        if (pcVar15[1] != 'p') goto LAB_0010fbc0;
        *(char **)(param_1 + 0x18) = pcVar15 + 2;
        uVar6 = FUN_00111c88(param_1);
        lVar7 = FUN_00109de4(param_1,0x49,uVar6,0);
      }
      goto LAB_0010fcb8;
    }
    if (cVar14 == 'f') {
      if (pcVar15[1] != 'p') goto LAB_0010fbc0;
      *(char **)(param_1 + 0x18) = pcVar15 + 2;
      if (pcVar15[2] == 'T') {
        lVar8 = 0;
        *(char **)(param_1 + 0x18) = pcVar15 + 3;
      }
      else {
        iVar3 = FUN_0010a590(param_1);
        if (iVar3 + 1 == 0) goto switchD_0010fe54_caseD_4;
        lVar8 = (long)(iVar3 + 1);
      }
      iVar3 = *(int *)(param_1 + 0x28);
      if (*(int *)(param_1 + 0x2c) <= iVar3) goto switchD_0010fe54_caseD_4;
      *(int *)(param_1 + 0x28) = iVar3 + 1;
      lVar7 = *(long *)(param_1 + 0x20) + (long)iVar3 * 0x18;
      if (lVar7 == 0) goto switchD_0010fe54_caseD_4;
      *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar3 * 0x18) = 6;
      *(long *)(lVar7 + 8) = lVar8;
    }
    else {
      if (9 < (byte)(cVar14 - 0x30U)) {
        if (cVar14 == 'o') {
          if (pcVar15[1] == 'n') {
            *(char **)(param_1 + 0x18) = pcVar15 + 2;
            goto LAB_0010fc34;
          }
        }
        else if (((cVar14 == 't') || (cVar14 == 'i')) && (pcVar15[1] == 'l')) {
          uVar6 = 0;
          if (cVar14 == 't') {
            uVar6 = FUN_0010ac34(param_1);
            pcVar15 = *(char **)(param_1 + 0x18);
          }
          *(char **)(param_1 + 0x18) = pcVar15 + 2;
          uVar9 = FUN_0010fb04(param_1,0x45);
          lVar7 = FUN_00109de4(param_1,0x30,uVar6,uVar9);
          goto LAB_0010fcb8;
        }
LAB_0010fbc0:
        piVar5 = (int *)FUN_0010c598(param_1);
        if (piVar5 == (int *)0x0) goto switchD_0010fe54_caseD_4;
        iVar3 = *piVar5;
        if (iVar3 == 0x31) {
          ppcVar17 = *(char ***)(piVar5 + 2);
          pcVar15 = *ppcVar17;
          *(int *)(param_1 + 0x50) = *(int *)(param_1 + 0x50) + *(int *)(ppcVar17 + 2) + -2;
          iVar3 = strcmp(pcVar15,"st");
          if (iVar3 != 0) {
            switch(*(undefined4 *)((long)ppcVar17 + 0x14)) {
            case 0:
              goto switchD_0010fe54_caseD_0;
            case 1:
              goto switchD_0010fe7c_caseD_1;
            case 2:
              goto switchD_0010fe7c_caseD_2;
            case 3:
              goto switchD_0010fe7c_caseD_3;
            default:
              goto switchD_0010fe54_caseD_4;
            }
          }
          uVar6 = FUN_0010ac34(param_1);
        }
        else {
          if (iVar3 == 0x32) {
            switch(piVar5[2]) {
            case 0:
switchD_0010fe54_caseD_0:
              lVar7 = FUN_00109de4(param_1,0x34,piVar5,0);
              goto LAB_0010fcb8;
            case 1:
              goto switchD_0010fe54_caseD_1;
            case 2:
              pcVar15 = (char *)0x0;
switchD_0010fe7c_caseD_2:
              if (((**(char ***)(piVar5 + 2))[1] == 'c') &&
                 ((cVar14 = ***(char ***)(piVar5 + 2), (byte)(cVar14 + 0x8eU) < 2 ||
                  ((byte)(cVar14 + 0x9dU) < 2)))) {
                uVar6 = FUN_0010ac34(param_1);
              }
              else {
                uVar6 = FUN_00111c88(param_1);
              }
              iVar3 = strcmp(pcVar15,"cl");
              if (iVar3 == 0) {
                uVar9 = FUN_0010fb04(param_1,0x45);
              }
              else {
                iVar3 = strcmp(pcVar15,"dt");
                if ((iVar3 == 0) || (iVar3 = strcmp(pcVar15,"pt"), iVar3 == 0)) {
                  uVar9 = FUN_0010c75c(param_1);
                  if (**(char **)(param_1 + 0x18) == 'I') {
                    uVar13 = FUN_0010cbec(param_1);
                    uVar9 = FUN_00109de4(param_1,4,uVar9,uVar13);
                  }
                }
                else {
                  uVar9 = FUN_00111c88(param_1);
                }
              }
              uVar6 = FUN_00109de4(param_1,0x37,uVar6,uVar9);
              lVar7 = FUN_00109de4(param_1,0x36,piVar5,uVar6);
              goto LAB_0010fcb8;
            case 3:
              pcVar15 = (char *)0x0;
switchD_0010fe7c_caseD_3:
              iVar3 = strcmp(pcVar15,"qu");
              if (iVar3 == 0) {
                pcVar15 = *(char **)(param_1 + 0x18);
                cVar14 = *pcVar15;
                if (cVar14 == 'L') {
                  piVar10 = (int *)FUN_0010f980(param_1);
                  pcVar15 = *(char **)(param_1 + 0x18);
                  cVar14 = *pcVar15;
LAB_00110194:
                  if (cVar14 == 'L') {
                    piVar11 = (int *)FUN_0010f980(param_1);
                    pcVar15 = *(char **)(param_1 + 0x18);
                    cVar14 = *pcVar15;
                    goto LAB_00110318;
                  }
                  if (cVar14 == 'T') {
                    piVar11 = (int *)FUN_0010a5fc(param_1);
                    pcVar15 = *(char **)(param_1 + 0x18);
                    cVar14 = *pcVar15;
                    goto LAB_00110318;
                  }
                  if (cVar14 == 's') {
                    if (pcVar15[1] == 'r') {
                      *(char **)(param_1 + 0x18) = pcVar15 + 2;
                      piVar11 = (int *)FUN_0010ac34(param_1);
                      lVar7 = FUN_0010c75c(param_1);
                      if (**(char **)(param_1 + 0x18) == 'I') {
                        uVar6 = FUN_0010cbec(param_1);
                        lVar7 = FUN_00109de4(param_1,4,lVar7,uVar6);
                      }
                      uVar6 = 1;
LAB_00110304:
                      piVar11 = (int *)FUN_00109de4(param_1,uVar6,piVar11,lVar7);
LAB_00110310:
                      pcVar15 = *(char **)(param_1 + 0x18);
                    }
                    else {
                      if (pcVar15[1] != 'p') goto LAB_001101ec;
                      *(char **)(param_1 + 0x18) = pcVar15 + 2;
                      piVar11 = (int *)FUN_00111c88(param_1);
                      uVar6 = 0x49;
LAB_00110700:
                      piVar11 = (int *)FUN_00109de4(param_1,uVar6,piVar11,0);
                      pcVar15 = *(char **)(param_1 + 0x18);
                    }
LAB_00110314:
                    cVar14 = *pcVar15;
                    goto LAB_00110318;
                  }
                  if (cVar14 != 'f') {
                    if (9 < (byte)(cVar14 - 0x30U)) {
                      if (cVar14 != 'o') goto LAB_001101cc;
                      if (pcVar15[1] != 'n') goto LAB_001101ec;
                      *(char **)(param_1 + 0x18) = pcVar15 + 2;
                    }
                    piVar11 = (int *)FUN_0010c75c(param_1);
                    pcVar15 = *(char **)(param_1 + 0x18);
                    cVar14 = *pcVar15;
                    if ((piVar11 != (int *)0x0) && (cVar14 == 'I')) {
                      lVar7 = FUN_0010cbec(param_1);
                      uVar6 = 4;
                      goto LAB_00110304;
                    }
                    goto LAB_00110318;
                  }
                  if (pcVar15[1] == 'p') {
                    *(char **)(param_1 + 0x18) = pcVar15 + 2;
                    if (pcVar15[2] == 'T') {
                      pcVar15 = pcVar15 + 3;
                      lVar7 = 0;
                      *(char **)(param_1 + 0x18) = pcVar15;
                    }
                    else {
                      iVar3 = FUN_0010a590(param_1);
                      pcVar15 = *(char **)(param_1 + 0x18);
                      if (iVar3 + 1 == 0) {
LAB_00110f34:
                        piVar11 = (int *)0x0;
                        goto LAB_00110314;
                      }
                      lVar7 = (long)(iVar3 + 1);
                    }
                    iVar3 = *(int *)(param_1 + 0x28);
                    if (iVar3 < *(int *)(param_1 + 0x2c)) {
                      *(int *)(param_1 + 0x28) = iVar3 + 1;
                      piVar11 = (int *)(*(long *)(param_1 + 0x20) + (long)iVar3 * 0x18);
                      if (piVar11 == (int *)0x0) goto LAB_00110314;
                      *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar3 * 0x18) = 6;
                      *(long *)(piVar11 + 2) = lVar7;
                      cVar14 = *pcVar15;
                    }
                    else {
                      cVar14 = *pcVar15;
                      piVar11 = (int *)0x0;
                    }
                    goto LAB_00110318;
                  }
LAB_001101ec:
                  piVar11 = (int *)FUN_0010c598(param_1);
                  if (piVar11 == (int *)0x0) goto LAB_00110310;
                  iVar3 = *piVar11;
                  if (iVar3 == 0x31) {
                    ppcVar17 = *(char ***)(piVar11 + 2);
                    pcVar15 = *ppcVar17;
                    *(int *)(param_1 + 0x50) =
                         *(int *)(param_1 + 0x50) + *(int *)(ppcVar17 + 2) + -2;
                    iVar4 = strcmp(pcVar15,"st");
                    if (iVar4 == 0) {
                      lVar7 = FUN_0010ac34(param_1);
                      uVar6 = 0x35;
                      goto LAB_00110304;
                    }
                    switch(*(undefined4 *)((long)ppcVar17 + 0x14)) {
                    case 0:
                      goto switchD_00110f5c_caseD_0;
                    case 1:
                      cVar14 = *pcVar15;
                      if (((cVar14 != 'm') && (cVar14 != 'p')) || (pcVar15[1] != cVar14))
                      goto switchD_00110f5c_caseD_1;
                      pcVar15 = *(char **)(param_1 + 0x18);
                      cVar14 = *pcVar15;
                      if (cVar14 == '_') {
                        pcVar15 = pcVar15 + 1;
                        *(char **)(param_1 + 0x18) = pcVar15;
                        goto LAB_00110fcc;
                      }
                      bVar2 = true;
                      break;
                    case 2:
                      goto switchD_00110ab0_caseD_2;
                    case 3:
                      goto switchD_00110ab0_caseD_3;
                    default:
                      goto switchD_00110f5c_caseD_4;
                    }
LAB_0011022c:
                    if (cVar14 == 'L') {
                      lVar7 = FUN_0010f980(param_1);
                    }
                    else if (cVar14 == 'T') {
                      lVar7 = FUN_0010a5fc(param_1);
                    }
                    else if (cVar14 == 's') {
                      if (pcVar15[1] == 'r') {
                        *(char **)(param_1 + 0x18) = pcVar15 + 2;
                        uVar6 = FUN_0010ac34(param_1);
                        uVar9 = FUN_0010c75c(param_1);
                        if (**(char **)(param_1 + 0x18) == 'I') {
                          uVar13 = FUN_0010cbec(param_1);
                          uVar9 = FUN_00109de4(param_1,4,uVar9,uVar13);
                        }
                        lVar7 = FUN_00109de4(param_1,1,uVar6,uVar9);
                      }
                      else {
                        if (pcVar15[1] != 'p') goto LAB_00110284;
                        *(char **)(param_1 + 0x18) = pcVar15 + 2;
                        uVar6 = FUN_00111c88(param_1);
                        lVar7 = FUN_00109de4(param_1,0x49,uVar6,0);
                      }
                    }
                    else if (cVar14 == 'f') {
                      if (pcVar15[1] != 'p') goto LAB_00110284;
                      *(char **)(param_1 + 0x18) = pcVar15 + 2;
                      if (pcVar15[2] == 'T') {
                        lVar8 = 0;
                        *(char **)(param_1 + 0x18) = pcVar15 + 3;
                      }
                      else {
                        iVar3 = FUN_0010a590(param_1);
                        if (iVar3 + 1 == 0) goto LAB_00111898;
                        lVar8 = (long)(iVar3 + 1);
                      }
                      iVar3 = *(int *)(param_1 + 0x28);
                      lVar7 = 0;
                      if (iVar3 < *(int *)(param_1 + 0x2c)) {
                        *(int *)(param_1 + 0x28) = iVar3 + 1;
                        lVar7 = *(long *)(param_1 + 0x20) + (long)iVar3 * 0x18;
                        if (lVar7 != 0) {
                          *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar3 * 0x18) = 6;
                          *(long *)(lVar7 + 8) = lVar8;
                        }
                      }
                    }
                    else if ((byte)(cVar14 - 0x30U) < 10) {
LAB_001113b0:
                      lVar7 = FUN_0010c75c(param_1);
                      if ((lVar7 != 0) && (**(char **)(param_1 + 0x18) == 'I')) {
                        uVar6 = FUN_0010cbec(param_1);
                        lVar7 = FUN_00109de4(param_1,4,lVar7,uVar6);
                      }
                    }
                    else {
                      if (cVar14 == 'o') {
                        if (pcVar15[1] == 'n') {
                          *(char **)(param_1 + 0x18) = pcVar15 + 2;
                          goto LAB_001113b0;
                        }
                      }
                      else if (((cVar14 == 't') || (cVar14 == 'i')) && (pcVar15[1] == 'l')) {
                        uVar6 = 0;
                        if (cVar14 == 't') {
                          uVar6 = FUN_0010ac34(param_1);
                          pcVar15 = *(char **)(param_1 + 0x18);
                        }
                        *(char **)(param_1 + 0x18) = pcVar15 + 2;
                        uVar9 = FUN_0010fb04(param_1,0x45);
                        lVar7 = FUN_00109de4(param_1,0x30,uVar6,uVar9);
                        goto switchD_001118c8_caseD_4;
                      }
LAB_00110284:
                      piVar12 = (int *)FUN_0010c598(param_1);
                      if (piVar12 == (int *)0x0) {
                        lVar7 = 0;
                      }
                      else {
                        iVar3 = *piVar12;
                        if (iVar3 == 0x31) {
                          ppcVar17 = *(char ***)(piVar12 + 2);
                          pcVar15 = *ppcVar17;
                          *(int *)(param_1 + 0x50) =
                               *(int *)(param_1 + 0x50) + *(int *)(ppcVar17 + 2) + -2;
                          iVar3 = strcmp(pcVar15,"st");
                          if (iVar3 != 0) {
                            lVar7 = 0;
                            switch(*(undefined4 *)((long)ppcVar17 + 0x14)) {
                            case 0:
                              goto switchD_001118c8_caseD_0;
                            case 1:
                              cVar14 = *pcVar15;
                              if (((cVar14 == 'm') || (cVar14 == 'p')) && (pcVar15[1] == cVar14)) {
                                if (**(char **)(param_1 + 0x18) != '_') {
                                  uVar6 = FUN_00111c88(param_1);
                                  uVar6 = FUN_00109de4(param_1,0x37,uVar6,uVar6);
                                  goto LAB_001102cc;
                                }
                                *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
                              }
                              goto switchD_001118c8_caseD_1;
                            case 2:
                              goto switchD_00111934_caseD_2;
                            case 3:
                              goto switchD_00111934_caseD_3;
                            }
                            goto switchD_001118c8_caseD_4;
                          }
                          uVar6 = FUN_0010ac34(param_1);
                        }
                        else {
                          if (iVar3 == 0x32) {
                            lVar7 = 0;
                            switch(piVar12[2]) {
                            case 0:
switchD_001118c8_caseD_0:
                              lVar7 = FUN_00109de4(param_1,0x34,piVar12,0);
                              break;
                            case 1:
                              goto switchD_001118c8_caseD_1;
                            case 2:
                              pcVar15 = (char *)0x0;
switchD_00111934_caseD_2:
                              if (((**(char ***)(piVar12 + 2))[1] == 'c') &&
                                 ((cVar14 = ***(char ***)(piVar12 + 2), (byte)(cVar14 + 0x8eU) < 2
                                  || ((byte)(cVar14 + 0x9dU) < 2)))) {
                                uVar6 = FUN_0010ac34(param_1);
                              }
                              else {
                                uVar6 = FUN_00111c88(param_1);
                              }
                              iVar3 = strcmp(pcVar15,"cl");
                              if (iVar3 == 0) {
                                uVar9 = FUN_0010fb04(param_1,0x45);
                              }
                              else {
                                iVar3 = strcmp(pcVar15,"dt");
                                if ((iVar3 == 0) || (iVar3 = strcmp(pcVar15,"pt"), iVar3 == 0)) {
                                  uVar9 = FUN_0010c75c(param_1);
                                  if (**(char **)(param_1 + 0x18) == 'I') {
                                    uVar13 = FUN_0010cbec(param_1);
                                    uVar9 = FUN_00109de4(param_1,4,uVar9,uVar13);
                                  }
                                }
                                else {
                                  uVar9 = FUN_00111c88(param_1);
                                }
                              }
                              uVar6 = FUN_00109de4(param_1,0x37,uVar6,uVar9);
                              lVar7 = FUN_00109de4(param_1,0x36,piVar12,uVar6);
                              break;
                            case 3:
                              pcVar15 = (char *)0x0;
switchD_00111934_caseD_3:
                              iVar3 = strcmp(pcVar15,"qu");
                              if (iVar3 == 0) {
                                uVar6 = FUN_00111c88(param_1);
                                uVar9 = FUN_00111c88(param_1);
                                uVar13 = FUN_00111c88(param_1);
LAB_00111bdc:
                                uVar9 = FUN_00109de4(param_1,0x3a,uVar9,uVar13);
                                uVar6 = FUN_00109de4(param_1,0x39,uVar6,uVar9);
                                lVar7 = FUN_00109de4(param_1,0x38,piVar12,uVar6);
                              }
                              else if ((*pcVar15 == 'n') &&
                                      ((pcVar15[1] == 'a' || (pcVar15[1] == 'w')))) {
                                uVar6 = FUN_0010fb04(param_1,0x5f);
                                uVar9 = FUN_0010ac34(param_1);
                                pcVar15 = *(char **)(param_1 + 0x18);
                                cVar14 = *pcVar15;
                                if (cVar14 == 'E') {
                                  uVar13 = 0;
                                  *(char **)(param_1 + 0x18) = pcVar15 + 1;
                                  goto LAB_00111bdc;
                                }
                                if (cVar14 == 'p') {
                                  lVar7 = 0;
                                  if (pcVar15[1] == 'i') {
                                    *(char **)(param_1 + 0x18) = pcVar15 + 2;
                                    uVar13 = FUN_0010fb04(param_1,0x45);
                                    goto LAB_00111bdc;
                                  }
                                }
                                else {
                                  if (cVar14 != 'i') goto LAB_00111898;
                                  lVar7 = 0;
                                  if (pcVar15[1] == 'l') {
                                    uVar13 = FUN_00111c88(param_1);
                                    goto LAB_00111bdc;
                                  }
                                }
                              }
                              else {
LAB_00111898:
                                lVar7 = 0;
                              }
                            }
                            goto switchD_001118c8_caseD_4;
                          }
                          if (iVar3 != 0x33) goto LAB_00111898;
                          if (**(char **)(param_1 + 0x18) == '_') {
                            *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
                            uVar6 = FUN_0010fb04(param_1,0x45);
                            goto LAB_001102cc;
                          }
switchD_001118c8_caseD_1:
                          uVar6 = FUN_00111c88(param_1);
                        }
LAB_001102cc:
                        lVar7 = FUN_00109de4(param_1,0x35,piVar12,uVar6);
                      }
                    }
switchD_001118c8_caseD_4:
                    if (bVar2) {
                      lVar7 = FUN_00109de4(param_1,0x37,lVar7);
                      uVar6 = 0x35;
                      goto LAB_00110304;
                    }
LAB_001112ec:
                    uVar6 = 0x35;
                    goto LAB_00110304;
                  }
                  if (iVar3 != 0x32) {
                    if (iVar3 != 0x33) {
LAB_00110f30:
                      pcVar15 = *(char **)(param_1 + 0x18);
                      goto LAB_00110f34;
                    }
                    pcVar15 = *(char **)(param_1 + 0x18);
LAB_0011021c:
                    cVar14 = *pcVar15;
                    bVar2 = false;
                    if (cVar14 != '_') goto LAB_0011022c;
                    *(char **)(param_1 + 0x18) = pcVar15 + 1;
                    lVar7 = FUN_0010fb04(param_1,0x45);
                    goto LAB_001112ec;
                  }
                  switch(piVar11[2]) {
                  case 0:
switchD_00110f5c_caseD_0:
                    uVar6 = 0x34;
                    goto LAB_00110700;
                  case 1:
switchD_00110f5c_caseD_1:
                    pcVar15 = *(char **)(param_1 + 0x18);
                    if (iVar3 != 0x33) {
LAB_00110fcc:
                      cVar14 = *pcVar15;
                      bVar2 = false;
                      goto LAB_0011022c;
                    }
                    goto LAB_0011021c;
                  case 2:
                    pcVar15 = (char *)0x0;
switchD_00110ab0_caseD_2:
                    if (((**(char ***)(piVar11 + 2))[1] == 'c') &&
                       ((cVar14 = ***(char ***)(piVar11 + 2), (byte)(cVar14 + 0x8eU) < 2 ||
                        ((byte)(cVar14 + 0x9dU) < 2)))) {
                      uVar6 = FUN_0010ac34(param_1);
                    }
                    else {
                      uVar6 = FUN_00111c88(param_1);
                    }
                    iVar3 = strcmp(pcVar15,"cl");
                    if (iVar3 == 0) {
                      uVar9 = FUN_0010fb04(param_1,0x45);
                    }
                    else {
                      iVar3 = strcmp(pcVar15,"dt");
                      if ((iVar3 == 0) || (iVar3 = strcmp(pcVar15,"pt"), iVar3 == 0)) {
                        uVar9 = FUN_0010c75c(param_1);
                        if (**(char **)(param_1 + 0x18) == 'I') {
                          uVar13 = FUN_0010cbec(param_1);
                          uVar9 = FUN_00109de4(param_1,4,uVar9,uVar13);
                        }
                      }
                      else {
                        uVar9 = FUN_00111c88(param_1);
                      }
                    }
                    lVar7 = FUN_00109de4(param_1,0x37,uVar6,uVar9);
                    uVar6 = 0x36;
                    goto LAB_00110304;
                  case 3:
                    pcVar15 = (char *)0x0;
switchD_00110ab0_caseD_3:
                    iVar3 = strcmp(pcVar15,"qu");
                    if (iVar3 == 0) {
                      uVar6 = FUN_00111c88(param_1);
                      uVar9 = FUN_00111c88(param_1);
                      uVar13 = FUN_00111c88(param_1);
LAB_00110c04:
                      uVar9 = FUN_00109de4(param_1,0x3a,uVar9,uVar13);
                      lVar7 = FUN_00109de4(param_1,0x39,uVar6,uVar9);
                      uVar6 = 0x38;
                      goto LAB_00110304;
                    }
                    if ((*pcVar15 != 'n') || ((pcVar15[1] != 'a' && (pcVar15[1] != 'w'))))
                    goto LAB_00110f30;
                    uVar6 = FUN_0010fb04(param_1,0x5f);
                    uVar9 = FUN_0010ac34(param_1);
                    pcVar15 = *(char **)(param_1 + 0x18);
                    cVar14 = *pcVar15;
                    if (cVar14 == 'E') {
                      uVar13 = 0;
                      *(char **)(param_1 + 0x18) = pcVar15 + 1;
                      goto LAB_00110c04;
                    }
                    if (cVar14 == 'p') {
                      if (pcVar15[1] == 'i') {
                        *(char **)(param_1 + 0x18) = pcVar15 + 2;
                        uVar13 = FUN_0010fb04(param_1,0x45);
                        goto LAB_00110c04;
                      }
                    }
                    else {
                      if (cVar14 != 'i') {
                        piVar11 = (int *)0x0;
                        goto LAB_00110318;
                      }
                      if (pcVar15[1] == 'l') {
                        uVar13 = FUN_00111c88(param_1);
                        goto LAB_00110c04;
                      }
                    }
                    piVar11 = (int *)0x0;
                    break;
                  default:
switchD_00110f5c_caseD_4:
                    pcVar15 = *(char **)(param_1 + 0x18);
                    piVar11 = (int *)0x0;
                    cVar14 = *pcVar15;
                    goto LAB_00110318;
                  }
LAB_00110350:
                  if (((cVar14 != 't') && (cVar14 != 'i')) || (pcVar15[1] != 'l'))
                  goto LAB_00110370;
                  uVar6 = 0;
                  if (cVar14 == 't') {
                    uVar6 = FUN_0010ac34(param_1);
                  }
                  *(long *)(param_1 + 0x18) = *(long *)(param_1 + 0x18) + 2;
                  uVar9 = FUN_0010fb04(param_1,0x45);
                  lVar7 = FUN_00109de4(param_1,0x30,uVar6,uVar9);
                }
                else {
                  if (cVar14 == 'T') {
                    piVar10 = (int *)FUN_0010a5fc(param_1);
                    pcVar15 = *(char **)(param_1 + 0x18);
                    cVar14 = *pcVar15;
                    goto LAB_00110194;
                  }
                  if (cVar14 == 's') {
                    if (pcVar15[1] == 'r') {
                      *(char **)(param_1 + 0x18) = pcVar15 + 2;
                      piVar10 = (int *)FUN_0010ac34(param_1);
                      uVar6 = FUN_0010c75c(param_1);
                      if (**(char **)(param_1 + 0x18) != 'I') {
                        piVar10 = (int *)FUN_00109de4(param_1,1,piVar10,uVar6);
                        pcVar15 = *(char **)(param_1 + 0x18);
                        cVar14 = *pcVar15;
                        goto LAB_00110194;
                      }
                      uVar9 = FUN_0010cbec(param_1);
                      uVar6 = FUN_00109de4(param_1,4,uVar6,uVar9);
                      uVar9 = 1;
                      goto LAB_001104e4;
                    }
                    if (pcVar15[1] != 'p') goto LAB_00110494;
                    *(char **)(param_1 + 0x18) = pcVar15 + 2;
                    piVar10 = (int *)FUN_00111c88(param_1);
                    uVar6 = 0x49;
LAB_001106b8:
                    piVar10 = (int *)FUN_00109de4(param_1,uVar6,piVar10,0);
LAB_001106c4:
                    pcVar15 = *(char **)(param_1 + 0x18);
LAB_001106c8:
                    cVar14 = *pcVar15;
                    goto LAB_00110194;
                  }
                  if (cVar14 == 'f') {
                    if (pcVar15[1] != 'p') goto LAB_00110494;
                    *(char **)(param_1 + 0x18) = pcVar15 + 2;
                    if (pcVar15[2] == 'T') {
                      pcVar15 = pcVar15 + 3;
                      lVar7 = 0;
                      *(char **)(param_1 + 0x18) = pcVar15;
                    }
                    else {
                      iVar3 = FUN_0010a590(param_1);
                      pcVar15 = *(char **)(param_1 + 0x18);
                      if (iVar3 + 1 == 0) {
LAB_001107f4:
                        piVar10 = (int *)0x0;
                        cVar14 = *pcVar15;
                        goto LAB_00110194;
                      }
                      lVar7 = (long)(iVar3 + 1);
                    }
                    iVar3 = *(int *)(param_1 + 0x28);
                    if (iVar3 < *(int *)(param_1 + 0x2c)) {
                      *(int *)(param_1 + 0x28) = iVar3 + 1;
                      piVar10 = (int *)(*(long *)(param_1 + 0x20) + (long)iVar3 * 0x18);
                      if (piVar10 == (int *)0x0) goto LAB_001106c8;
                      *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar3 * 0x18) = 6;
                      *(long *)(piVar10 + 2) = lVar7;
                      cVar14 = *pcVar15;
                    }
                    else {
                      cVar14 = *pcVar15;
                      piVar10 = (int *)0x0;
                    }
                    goto LAB_00110194;
                  }
                  if ((byte)(cVar14 - 0x30U) < 10) {
LAB_00110174:
                    piVar10 = (int *)FUN_0010c75c(param_1);
                    pcVar15 = *(char **)(param_1 + 0x18);
                    cVar14 = *pcVar15;
                    if ((piVar10 != (int *)0x0) && (cVar14 == 'I')) {
                      uVar6 = FUN_0010cbec(param_1);
                      uVar9 = 4;
                      goto LAB_001104e4;
                    }
                    goto LAB_00110194;
                  }
                  if (cVar14 == 'o') {
                    if (pcVar15[1] == 'n') {
                      *(char **)(param_1 + 0x18) = pcVar15 + 2;
                      goto LAB_00110174;
                    }
                  }
                  else if (((cVar14 == 't') || (cVar14 == 'i')) && (pcVar15[1] == 'l')) {
                    uVar6 = 0;
                    if (cVar14 == 't') {
                      uVar6 = FUN_0010ac34(param_1);
                      pcVar15 = *(char **)(param_1 + 0x18);
                    }
                    *(char **)(param_1 + 0x18) = pcVar15 + 2;
                    uVar9 = FUN_0010fb04(param_1,0x45);
                    piVar10 = (int *)FUN_00109de4(param_1,0x30,uVar6,uVar9);
                    pcVar15 = *(char **)(param_1 + 0x18);
                    cVar14 = *pcVar15;
                    goto LAB_00110194;
                  }
LAB_00110494:
                  piVar10 = (int *)FUN_0010c598(param_1);
                  if (piVar10 == (int *)0x0) goto LAB_001106c4;
                  iVar3 = *piVar10;
                  if (iVar3 == 0x31) {
                    ppcVar17 = *(char ***)(piVar10 + 2);
                    pcVar15 = *ppcVar17;
                    *(int *)(param_1 + 0x50) =
                         *(int *)(param_1 + 0x50) + *(int *)(ppcVar17 + 2) + -2;
                    iVar3 = strcmp(pcVar15,"st");
                    if (iVar3 != 0) {
                      switch(*(undefined4 *)((long)ppcVar17 + 0x14)) {
                      case 0:
                        goto switchD_00110f80_caseD_0;
                      case 1:
                        goto switchD_001108d8_caseD_1;
                      case 2:
                        goto switchD_001108d8_caseD_2;
                      case 3:
                        goto switchD_001108d8_caseD_3;
                      default:
                        goto switchD_00110f80_caseD_4;
                      }
                    }
                    uVar6 = FUN_0010ac34(param_1);
                    uVar9 = 0x35;
                    goto LAB_001104e4;
                  }
                  if (iVar3 != 0x32) {
                    if (iVar3 == 0x33) {
                      if (**(char **)(param_1 + 0x18) != '_') goto switchD_00110f80_caseD_1;
                      *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
                      uVar6 = FUN_0010fb04(param_1,0x45);
                      goto LAB_001104dc;
                    }
switchD_00110f80_caseD_4:
                    pcVar15 = *(char **)(param_1 + 0x18);
                    goto LAB_001107f4;
                  }
                  switch(piVar10[2]) {
                  case 0:
switchD_00110f80_caseD_0:
                    uVar6 = 0x34;
                    goto LAB_001106b8;
                  case 1:
                    goto switchD_00110f80_caseD_1;
                  case 2:
                    pcVar15 = (char *)0x0;
switchD_001108d8_caseD_2:
                    if (((**(char ***)(piVar10 + 2))[1] == 'c') &&
                       ((cVar14 = ***(char ***)(piVar10 + 2), (byte)(cVar14 + 0x8eU) < 2 ||
                        ((byte)(cVar14 + 0x9dU) < 2)))) {
                      uVar6 = FUN_0010ac34(param_1);
                    }
                    else {
                      uVar6 = FUN_00111c88(param_1);
                    }
                    iVar3 = strcmp(pcVar15,"cl");
                    if (iVar3 == 0) {
                      uVar9 = FUN_0010fb04(param_1,0x45);
                    }
                    else {
                      iVar3 = strcmp(pcVar15,"dt");
                      if ((iVar3 == 0) || (iVar3 = strcmp(pcVar15,"pt"), iVar3 == 0)) {
                        uVar9 = FUN_0010c75c(param_1);
                        if (**(char **)(param_1 + 0x18) == 'I') {
                          uVar13 = FUN_0010cbec(param_1);
                          uVar9 = FUN_00109de4(param_1,4,uVar9,uVar13);
                        }
                      }
                      else {
                        uVar9 = FUN_00111c88(param_1);
                      }
                    }
                    uVar6 = FUN_00109de4(param_1,0x37,uVar6,uVar9);
                    uVar9 = 0x36;
                    goto LAB_001104e4;
                  case 3:
                    pcVar15 = (char *)0x0;
switchD_001108d8_caseD_3:
                    iVar3 = strcmp(pcVar15,"qu");
                    if (iVar3 == 0) {
                      uVar6 = FUN_00111c88(param_1);
                      uVar9 = FUN_00111c88(param_1);
                      uVar13 = FUN_00111c88(param_1);
LAB_00110a10:
                      uVar9 = FUN_00109de4(param_1,0x3a,uVar9,uVar13);
                      uVar6 = FUN_00109de4(param_1,0x39,uVar6,uVar9);
                      uVar9 = 0x38;
                      goto LAB_001104e4;
                    }
                    if ((*pcVar15 != 'n') || ((pcVar15[1] != 'a' && (pcVar15[1] != 'w'))))
                    goto switchD_00110f80_caseD_4;
                    uVar6 = FUN_0010fb04(param_1,0x5f);
                    uVar9 = FUN_0010ac34(param_1);
                    pcVar15 = *(char **)(param_1 + 0x18);
                    cVar14 = *pcVar15;
                    if (cVar14 == 'E') {
                      uVar13 = 0;
                      *(char **)(param_1 + 0x18) = pcVar15 + 1;
                      goto LAB_00110a10;
                    }
                    if (cVar14 == 'p') {
                      if (pcVar15[1] == 'i') {
                        *(char **)(param_1 + 0x18) = pcVar15 + 2;
                        uVar13 = FUN_0010fb04(param_1,0x45);
                        goto LAB_00110a10;
                      }
                    }
                    else {
                      if (cVar14 != 'i') {
                        piVar10 = (int *)0x0;
                        goto LAB_00110194;
                      }
                      if (pcVar15[1] == 'l') {
                        uVar13 = FUN_00111c88(param_1);
                        goto LAB_00110a10;
                      }
                    }
                    piVar10 = (int *)0x0;
LAB_001101cc:
                    if (((cVar14 != 't') && (cVar14 != 'i')) || (pcVar15[1] != 'l'))
                    goto LAB_001101ec;
                    uVar6 = 0;
                    if (cVar14 == 't') {
                      uVar6 = FUN_0010ac34(param_1);
                    }
                    *(long *)(param_1 + 0x18) = *(long *)(param_1 + 0x18) + 2;
                    uVar9 = FUN_0010fb04(param_1,0x45);
                    piVar11 = (int *)FUN_00109de4(param_1,0x30,uVar6,uVar9);
                    pcVar15 = *(char **)(param_1 + 0x18);
                    cVar14 = *pcVar15;
LAB_00110318:
                    if (cVar14 == 'L') {
                      lVar7 = FUN_0010f980(param_1);
                    }
                    else if (cVar14 == 'T') {
                      lVar7 = FUN_0010a5fc(param_1);
                    }
                    else if (cVar14 == 's') {
                      if (pcVar15[1] == 'r') {
                        *(char **)(param_1 + 0x18) = pcVar15 + 2;
                        uVar6 = FUN_0010ac34(param_1);
                        uVar9 = FUN_0010c75c(param_1);
                        if (**(char **)(param_1 + 0x18) == 'I') {
                          uVar13 = FUN_0010cbec(param_1);
                          uVar9 = FUN_00109de4(param_1,4,uVar9,uVar13);
                        }
                        lVar7 = FUN_00109de4(param_1,1,uVar6,uVar9);
                      }
                      else {
                        if (pcVar15[1] != 'p') goto LAB_00110370;
                        *(char **)(param_1 + 0x18) = pcVar15 + 2;
                        uVar6 = FUN_00111c88(param_1);
                        lVar7 = FUN_00109de4(param_1,0x49,uVar6,0);
                      }
                    }
                    else if (cVar14 == 'f') {
                      if (pcVar15[1] == 'p') {
                        *(char **)(param_1 + 0x18) = pcVar15 + 2;
                        if (pcVar15[2] == 'T') {
                          lVar8 = 0;
                          *(char **)(param_1 + 0x18) = pcVar15 + 3;
                        }
                        else {
                          iVar3 = FUN_0010a590(param_1);
                          if (iVar3 + 1 == 0) goto LAB_00110e5c;
                          lVar8 = (long)(iVar3 + 1);
                        }
                        iVar3 = *(int *)(param_1 + 0x28);
                        lVar7 = 0;
                        if (iVar3 < *(int *)(param_1 + 0x2c)) {
                          *(int *)(param_1 + 0x28) = iVar3 + 1;
                          lVar7 = *(long *)(param_1 + 0x20) + (long)iVar3 * 0x18;
                          if (lVar7 != 0) {
                            *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar3 * 0x18) = 6;
                            *(long *)(lVar7 + 8) = lVar8;
                          }
                        }
                      }
                      else {
LAB_00110370:
                        piVar12 = (int *)FUN_0010c598(param_1);
                        if (piVar12 == (int *)0x0) {
                          lVar7 = 0;
                        }
                        else {
                          iVar3 = *piVar12;
                          if (iVar3 == 0x31) {
                            ppcVar17 = *(char ***)(piVar12 + 2);
                            pcVar15 = *ppcVar17;
                            *(int *)(param_1 + 0x50) =
                                 *(int *)(param_1 + 0x50) + *(int *)(ppcVar17 + 2) + -2;
                            iVar3 = strcmp(pcVar15,"st");
                            if (iVar3 != 0) {
                              lVar7 = 0;
                              switch(*(undefined4 *)((long)ppcVar17 + 0x14)) {
                              case 0:
                                goto switchD_00110fa4_caseD_0;
                              case 1:
                                cVar14 = *pcVar15;
                                if (((cVar14 == 'm') || (cVar14 == 'p')) && (pcVar15[1] == cVar14))
                                {
                                  if (**(char **)(param_1 + 0x18) != '_') {
                                    uVar6 = FUN_00111c88(param_1);
                                    uVar6 = FUN_00109de4(param_1,0x37,uVar6,uVar6);
                                    goto LAB_001103b8;
                                  }
                                  *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
                                }
                                goto switchD_00110fa4_caseD_1;
                              case 2:
                                goto switchD_00110ca4_caseD_2;
                              case 3:
                                goto switchD_00110ca4_caseD_3;
                              }
                              break;
                            }
                            uVar6 = FUN_0010ac34(param_1);
                          }
                          else {
                            if (iVar3 == 0x32) {
                              lVar7 = 0;
                              switch(piVar12[2]) {
                              case 0:
switchD_00110fa4_caseD_0:
                                lVar7 = FUN_00109de4(param_1,0x34,piVar12,0);
                                break;
                              case 1:
                                goto switchD_00110fa4_caseD_1;
                              case 2:
                                pcVar15 = (char *)0x0;
switchD_00110ca4_caseD_2:
                                if (((**(char ***)(piVar12 + 2))[1] == 'c') &&
                                   ((cVar14 = ***(char ***)(piVar12 + 2), (byte)(cVar14 + 0x8eU) < 2
                                    || ((byte)(cVar14 + 0x9dU) < 2)))) {
                                  uVar6 = FUN_0010ac34(param_1);
                                }
                                else {
                                  uVar6 = FUN_00111c88(param_1);
                                }
                                iVar3 = strcmp(pcVar15,"cl");
                                if (iVar3 == 0) {
                                  uVar9 = FUN_0010fb04(param_1,0x45);
                                }
                                else {
                                  iVar3 = strcmp(pcVar15,"dt");
                                  if ((iVar3 == 0) || (iVar3 = strcmp(pcVar15,"pt"), iVar3 == 0)) {
                                    uVar9 = FUN_0010c75c(param_1);
                                    if (**(char **)(param_1 + 0x18) == 'I') {
                                      uVar13 = FUN_0010cbec(param_1);
                                      uVar9 = FUN_00109de4(param_1,4,uVar9,uVar13);
                                    }
                                  }
                                  else {
                                    uVar9 = FUN_00111c88(param_1);
                                  }
                                }
                                uVar6 = FUN_00109de4(param_1,0x37,uVar6,uVar9);
                                lVar7 = FUN_00109de4(param_1,0x36,piVar12,uVar6);
                                break;
                              case 3:
                                pcVar15 = (char *)0x0;
switchD_00110ca4_caseD_3:
                                iVar3 = strcmp(pcVar15,"qu");
                                if (iVar3 == 0) {
                                  uVar6 = FUN_00111c88(param_1);
                                  uVar9 = FUN_00111c88(param_1);
                                  uVar13 = FUN_00111c88(param_1);
LAB_00110e18:
                                  uVar9 = FUN_00109de4(param_1,0x3a,uVar9,uVar13);
                                  uVar6 = FUN_00109de4(param_1,0x39,uVar6,uVar9);
                                  lVar7 = FUN_00109de4(param_1,0x38,piVar12,uVar6);
                                }
                                else if ((*pcVar15 == 'n') &&
                                        ((pcVar15[1] == 'a' || (pcVar15[1] == 'w')))) {
                                  uVar6 = FUN_0010fb04(param_1,0x5f);
                                  uVar9 = FUN_0010ac34(param_1);
                                  pcVar15 = *(char **)(param_1 + 0x18);
                                  cVar14 = *pcVar15;
                                  if (cVar14 == 'E') {
                                    uVar13 = 0;
                                    *(char **)(param_1 + 0x18) = pcVar15 + 1;
                                    goto LAB_00110e18;
                                  }
                                  if (cVar14 == 'p') {
                                    lVar7 = 0;
                                    if (pcVar15[1] == 'i') {
                                      *(char **)(param_1 + 0x18) = pcVar15 + 2;
                                      uVar13 = FUN_0010fb04(param_1,0x45);
                                      goto LAB_00110e18;
                                    }
                                  }
                                  else {
                                    if (cVar14 != 'i') goto LAB_00110e5c;
                                    lVar7 = 0;
                                    if (pcVar15[1] == 'l') {
                                      uVar13 = FUN_00111c88(param_1);
                                      goto LAB_00110e18;
                                    }
                                  }
                                }
                                else {
LAB_00110e5c:
                                  lVar7 = 0;
                                }
                              }
                              break;
                            }
                            if (iVar3 != 0x33) goto LAB_00110e5c;
                            if (**(char **)(param_1 + 0x18) == '_') {
                              *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
                              uVar6 = FUN_0010fb04(param_1,0x45);
                              goto LAB_001103b8;
                            }
switchD_00110fa4_caseD_1:
                            uVar6 = FUN_00111c88(param_1);
                          }
LAB_001103b8:
                          lVar7 = FUN_00109de4(param_1,0x35,piVar12,uVar6);
                        }
                      }
                    }
                    else {
                      if (9 < (byte)(cVar14 - 0x30U)) {
                        if (cVar14 != 'o') goto LAB_00110350;
                        if (pcVar15[1] != 'n') goto LAB_00110370;
                        *(char **)(param_1 + 0x18) = pcVar15 + 2;
                      }
                      lVar7 = FUN_0010c75c(param_1);
                      if ((lVar7 != 0) && (**(char **)(param_1 + 0x18) == 'I')) {
                        uVar6 = FUN_0010cbec(param_1);
                        lVar7 = FUN_00109de4(param_1,4,lVar7,uVar6);
                      }
                    }
                    break;
                  default:
                    goto switchD_00110f80_caseD_4;
                  }
                }
              }
              else {
                if ((*pcVar15 != 'n') || ((pcVar15[1] != 'a' && (pcVar15[1] != 'w'))))
                goto switchD_0010fe54_caseD_4;
                piVar10 = (int *)FUN_0010fb04(param_1,0x5f);
                piVar11 = (int *)FUN_0010ac34(param_1);
                pcVar15 = *(char **)(param_1 + 0x18);
                cVar14 = *pcVar15;
                if (cVar14 == 'E') {
                  lVar7 = 0;
                  *(char **)(param_1 + 0x18) = pcVar15 + 1;
                }
                else if (cVar14 == 'p') {
                  if (pcVar15[1] != 'i') goto switchD_0010fe54_caseD_4;
                  *(char **)(param_1 + 0x18) = pcVar15 + 2;
                  lVar7 = FUN_0010fb04(param_1,0x45);
                }
                else {
                  if ((cVar14 != 'i') || (pcVar15[1] != 'l')) {
switchD_0010fe54_caseD_4:
                    *(undefined4 *)(param_1 + 0x54) = uVar1;
                    return 0;
                  }
                  *(char **)(param_1 + 0x18) = pcVar15 + 2;
                  uVar6 = FUN_0010fb04(param_1,0x45);
                  lVar7 = FUN_00109de4(param_1,0x30,0,uVar6);
                }
              }
              uVar6 = FUN_00109de4(param_1,0x3a,piVar11,lVar7);
              uVar6 = FUN_00109de4(param_1,0x39,piVar10,uVar6);
              lVar7 = FUN_00109de4(param_1,0x38,piVar5,uVar6);
              goto LAB_0010fcb8;
            default:
              goto switchD_0010fe54_caseD_4;
            }
          }
          if (iVar3 != 0x33) goto switchD_0010fe54_caseD_4;
          if (**(char **)(param_1 + 0x18) == '_') {
            *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
            uVar6 = FUN_0010fb04(param_1,0x45);
            goto LAB_0010fc08;
          }
switchD_0010fe54_caseD_1:
          uVar6 = FUN_00111c88(param_1);
        }
LAB_0010fc08:
        lVar7 = FUN_00109de4(param_1,0x35,piVar5,uVar6);
        goto LAB_0010fcb8;
      }
LAB_0010fc34:
      lVar7 = FUN_0010c75c(param_1);
      if (lVar7 == 0) goto switchD_0010fe54_caseD_4;
      if (**(char **)(param_1 + 0x18) == 'I') {
        uVar6 = FUN_0010cbec(param_1);
        lVar7 = FUN_00109de4(param_1,4,lVar7,uVar6);
        goto LAB_0010fcb8;
      }
    }
    *(undefined4 *)(param_1 + 0x54) = uVar1;
  }
  lVar7 = FUN_00109de4(param_1,0x2e,lVar7,0);
  *plVar16 = lVar7;
  if (lVar7 == 0) {
    return 0;
  }
  pcVar15 = *(char **)(param_1 + 0x18);
  plVar16 = (long *)(lVar7 + 0x10);
  if (*pcVar15 == param_2) {
    *(char **)(param_1 + 0x18) = pcVar15 + 1;
    return local_8;
  }
  goto LAB_0010fb60;
switchD_0010fe7c_caseD_1:
  cVar14 = *pcVar15;
  if (((cVar14 == 'm') || (cVar14 == 'p')) && (pcVar15[1] == cVar14)) {
    if (**(char **)(param_1 + 0x18) != '_') {
      uVar6 = FUN_00111c88(param_1);
      uVar6 = FUN_00109de4(param_1,0x37,uVar6,uVar6);
      goto LAB_0010fc08;
    }
    *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
  }
  goto switchD_0010fe54_caseD_1;
switchD_001108d8_caseD_1:
  cVar14 = *pcVar15;
  if (((cVar14 == 'm') || (cVar14 == 'p')) && (pcVar15[1] == cVar14)) {
    if (**(char **)(param_1 + 0x18) != '_') {
      uVar6 = FUN_00111c88(param_1);
      uVar6 = FUN_00109de4(param_1,0x37,uVar6,uVar6);
      uVar9 = 0x35;
      goto LAB_001104e4;
    }
    *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
  }
switchD_00110f80_caseD_1:
  uVar6 = FUN_00111c88(param_1);
LAB_001104dc:
  uVar9 = 0x35;
LAB_001104e4:
  piVar10 = (int *)FUN_00109de4(param_1,uVar9,piVar10,uVar6);
  pcVar15 = *(char **)(param_1 + 0x18);
  cVar14 = *pcVar15;
  goto LAB_00110194;
}



long FUN_00111c88(long param_1)

{
  long lVar1;
  char cVar2;
  int iVar3;
  int *piVar4;
  long lVar5;
  undefined8 uVar6;
  undefined8 uVar7;
  undefined8 uVar8;
  char *pcVar9;
  char **ppcVar10;
  long local_8;
  
  pcVar9 = *(char **)(param_1 + 0x18);
  cVar2 = *pcVar9;
  if (cVar2 == 'L') {
    lVar5 = FUN_0010f980();
    return lVar5;
  }
  if (cVar2 == 'T') {
    lVar5 = FUN_0010a5fc();
    return lVar5;
  }
  if (cVar2 == 's') {
    if (pcVar9[1] == 'r') {
      *(char **)(param_1 + 0x18) = pcVar9 + 2;
      piVar4 = (int *)FUN_0010ac34();
      uVar6 = FUN_0010c75c(param_1);
      if (**(char **)(param_1 + 0x18) == 'I') {
        uVar8 = FUN_0010cbec(param_1);
        uVar6 = FUN_00109de4(param_1,4,uVar6,uVar8);
      }
      uVar8 = 1;
      goto LAB_00111f6c;
    }
    if (pcVar9[1] == 'p') {
      *(char **)(param_1 + 0x18) = pcVar9 + 2;
      piVar4 = (int *)FUN_00111c88();
      uVar6 = 0x49;
      goto LAB_00111e1c;
    }
  }
  else if (cVar2 == 'f') {
    if (pcVar9[1] == 'p') {
      *(char **)(param_1 + 0x18) = pcVar9 + 2;
      if (pcVar9[2] == 'T') {
        lVar5 = 0;
        *(char **)(param_1 + 0x18) = pcVar9 + 3;
      }
      else {
        iVar3 = FUN_0010a590();
        lVar5 = (long)(iVar3 + 1);
        if (iVar3 + 1 == 0) {
          return 0;
        }
      }
      iVar3 = *(int *)(param_1 + 0x28);
      if (*(int *)(param_1 + 0x2c) <= iVar3) {
        return 0;
      }
      *(int *)(param_1 + 0x28) = iVar3 + 1;
      lVar1 = *(long *)(param_1 + 0x20) + (long)iVar3 * 0x18;
      if (lVar1 == 0) {
        return 0;
      }
      *(undefined4 *)(*(long *)(param_1 + 0x20) + (long)iVar3 * 0x18) = 6;
      *(long *)(lVar1 + 8) = lVar5;
      return lVar1;
    }
  }
  else {
    if ((byte)(cVar2 - 0x30U) < 10) {
LAB_00111cd4:
      local_8 = FUN_0010c75c(param_1);
      if (local_8 == 0) {
        return 0;
      }
      if (**(char **)(param_1 + 0x18) != 'I') {
        return local_8;
      }
      uVar6 = FUN_0010cbec(param_1);
      uVar8 = 4;
LAB_00111eac:
      lVar5 = FUN_00109de4(param_1,uVar8,local_8,uVar6);
      return lVar5;
    }
    if (cVar2 == 'o') {
      if (pcVar9[1] == 'n') {
        *(char **)(param_1 + 0x18) = pcVar9 + 2;
        goto LAB_00111cd4;
      }
    }
    else if (((cVar2 == 't') || (cVar2 == 'i')) && (pcVar9[1] == 'l')) {
      local_8 = 0;
      if (cVar2 == 't') {
        local_8 = FUN_0010ac34(param_1);
        pcVar9 = *(char **)(param_1 + 0x18);
      }
      *(char **)(param_1 + 0x18) = pcVar9 + 2;
      uVar6 = FUN_0010fb04(param_1,0x45);
      uVar8 = 0x30;
      goto LAB_00111eac;
    }
  }
  piVar4 = (int *)FUN_0010c598(param_1);
  if (piVar4 == (int *)0x0) {
    return 0;
  }
  iVar3 = *piVar4;
  if (iVar3 == 0x31) {
    ppcVar10 = *(char ***)(piVar4 + 2);
    pcVar9 = *ppcVar10;
    *(int *)(param_1 + 0x50) = *(int *)(param_1 + 0x50) + *(int *)(ppcVar10 + 2) + -2;
    iVar3 = strcmp(pcVar9,"st");
    if (iVar3 != 0) {
      switch(*(undefined4 *)((long)ppcVar10 + 0x14)) {
      case 0:
        goto switchD_00111f18_caseD_0;
      case 1:
        goto switchD_00111fa4_caseD_1;
      case 2:
        goto switchD_00111fa4_caseD_2;
      case 3:
        goto switchD_00111fa4_caseD_3;
      default:
        goto switchD_00111f18_caseD_4;
      }
    }
    uVar6 = FUN_0010ac34(param_1);
  }
  else {
    if (iVar3 == 0x32) {
      switch(piVar4[2]) {
      case 0:
switchD_00111f18_caseD_0:
        uVar6 = 0x34;
LAB_00111e1c:
        lVar5 = FUN_00109de4(param_1,uVar6,piVar4,0);
        return lVar5;
      case 1:
        goto switchD_00111f18_caseD_1;
      case 2:
        pcVar9 = (char *)0x0;
switchD_00111fa4_caseD_2:
        if (((**(char ***)(piVar4 + 2))[1] == 'c') &&
           ((cVar2 = ***(char ***)(piVar4 + 2), (byte)(cVar2 + 0x8eU) < 2 ||
            ((byte)(cVar2 + 0x9dU) < 2)))) {
          uVar6 = FUN_0010ac34(param_1);
        }
        else {
          uVar6 = FUN_00111c88(param_1);
        }
        iVar3 = strcmp(pcVar9,"cl");
        if (iVar3 == 0) {
          uVar8 = FUN_0010fb04(param_1,0x45);
        }
        else {
          iVar3 = strcmp(pcVar9,"dt");
          if ((iVar3 == 0) || (iVar3 = strcmp(pcVar9,"pt"), iVar3 == 0)) {
            uVar8 = FUN_0010c75c(param_1);
            if (**(char **)(param_1 + 0x18) == 'I') {
              uVar7 = FUN_0010cbec(param_1);
              uVar8 = FUN_00109de4(param_1,4,uVar8,uVar7);
            }
          }
          else {
            uVar8 = FUN_00111c88(param_1);
          }
        }
        uVar6 = FUN_00109de4(param_1,0x37,uVar6,uVar8);
        uVar8 = 0x36;
        goto LAB_00111f6c;
      case 3:
        pcVar9 = (char *)0x0;
switchD_00111fa4_caseD_3:
        iVar3 = strcmp(pcVar9,"qu");
        if (iVar3 == 0) {
          uVar6 = FUN_00111c88(param_1);
          uVar8 = FUN_00111c88(param_1);
          uVar7 = FUN_00111c88(param_1);
        }
        else {
          if (*pcVar9 != 'n') {
            return 0;
          }
          if ((pcVar9[1] != 'a') && (pcVar9[1] != 'w')) {
            return 0;
          }
          uVar6 = FUN_0010fb04(param_1,0x5f);
          uVar8 = FUN_0010ac34(param_1);
          pcVar9 = *(char **)(param_1 + 0x18);
          cVar2 = *pcVar9;
          if (cVar2 == 'E') {
            uVar7 = 0;
            *(char **)(param_1 + 0x18) = pcVar9 + 1;
          }
          else if (cVar2 == 'p') {
            if (pcVar9[1] != 'i') {
              return 0;
            }
            *(char **)(param_1 + 0x18) = pcVar9 + 2;
            uVar7 = FUN_0010fb04(param_1,0x45);
          }
          else {
            if ((cVar2 != 'i') || (pcVar9[1] != 'l')) {
switchD_00111f18_caseD_4:
              return 0;
            }
            uVar7 = FUN_00111c88(param_1);
          }
        }
        uVar8 = FUN_00109de4(param_1,0x3a,uVar8,uVar7);
        uVar6 = FUN_00109de4(param_1,0x39,uVar6,uVar8);
        uVar8 = 0x38;
        goto LAB_00111f6c;
      default:
        goto switchD_00111f18_caseD_4;
      }
    }
    if (iVar3 != 0x33) {
      return 0;
    }
    if (**(char **)(param_1 + 0x18) == '_') {
      *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
      uVar6 = FUN_0010fb04(param_1,0x45);
      goto LAB_00111d6c;
    }
switchD_00111f18_caseD_1:
    uVar6 = FUN_00111c88(param_1);
  }
LAB_00111d6c:
  uVar8 = 0x35;
LAB_00111f6c:
  lVar5 = FUN_00109de4(param_1,uVar8,piVar4,uVar6);
  return lVar5;
switchD_00111fa4_caseD_1:
  cVar2 = *pcVar9;
  if (((cVar2 == 'm') || (cVar2 == 'p')) && (pcVar9[1] == cVar2)) {
    if (**(char **)(param_1 + 0x18) != '_') {
      uVar6 = FUN_00111c88(param_1);
      uVar6 = FUN_00109de4(param_1,0x37,uVar6,uVar6);
      goto LAB_00111d6c;
    }
    *(char **)(param_1 + 0x18) = *(char **)(param_1 + 0x18) + 1;
  }
  goto switchD_00111f18_caseD_1;
}



// WARNING: Type propagation algorithm not settling

void FUN_001122e8(undefined *param_1,uint param_2,long *param_3)

{
  int iVar1;
  char *pcVar2;
  byte *pbVar3;
  undefined uVar4;
  char cVar5;
  bool bVar6;
  int iVar7;
  size_t sVar8;
  int *piVar9;
  char *pcVar10;
  long lVar11;
  long lVar12;
  long lVar13;
  long **pplVar14;
  long lVar15;
  long lVar16;
  long *plVar17;
  long ***ppplVar18;
  undefined8 *puVar19;
  byte *pbVar20;
  long *plVar21;
  long ***ppplVar22;
  int *piVar23;
  char **ppcVar24;
  long ***ppplVar25;
  long **pplVar26;
  long ***ppplVar27;
  long *plVar28;
  ulong uVar29;
  byte bVar30;
  int iVar31;
  size_t sVar32;
  undefined8 *puVar33;
  byte *pbVar34;
  uint uVar35;
  ulong uVar36;
  ulong uVar37;
  undefined8 unaff_x23;
  undefined8 uVar38;
  undefined8 uVar39;
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
  
  if (param_3 == (long *)0x0) goto LAB_00112364;
  if (*(int *)(param_1 + 0x130) != 0) {
    return;
  }
  iVar7 = *(int *)param_3;
  switch(iVar7) {
  case 0:
    if ((param_2 >> 2 & 1) == 0) {
      iVar7 = *(int *)(param_3 + 2);
      lVar15 = param_3[1];
      if ((long)iVar7 != 0) {
        lVar12 = 0;
        lVar11 = *(long *)(param_1 + 0x100);
        do {
          uVar4 = *(undefined *)(lVar15 + lVar12);
          if (lVar11 == 0xff) {
            param_1[0xff] = 0;
            (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
            lVar16 = 1;
            lVar11 = 0;
            *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
          }
          else {
            lVar16 = lVar11 + 1;
          }
          *(long *)(param_1 + 0x100) = lVar16;
          lVar12 = lVar12 + 1;
          param_1[lVar11] = uVar4;
          param_1[0x108] = uVar4;
          lVar11 = lVar16;
        } while (iVar7 != lVar12);
      }
    }
    else {
      pbVar34 = (byte *)param_3[1];
      pbVar3 = pbVar34 + *(int *)(param_3 + 2);
      while (pbVar34 < pbVar3) {
        bVar30 = *pbVar34;
        if (((3 < (long)pbVar3 - (long)pbVar34) && (bVar30 == 0x5f)) &&
           ((pbVar34[1] == 0x5f &&
            ((bVar30 = 0x5f, pbVar34[2] == 0x55 && (pbVar20 = pbVar34 + 3, pbVar20 < pbVar3)))))) {
          uVar37 = 0;
          do {
            bVar30 = *pbVar20;
            uVar35 = bVar30 - 0x30;
            if (9 < (uVar35 & 0xff)) {
              uVar35 = (uint)bVar30;
              if ((bVar30 - 0x41 & 0xff) < 6) {
                uVar35 = uVar35 - 0x37;
              }
              else {
                if (5 < (uVar35 - 0x61 & 0xff)) {
                  if (((pbVar20 < pbVar3) && (uVar35 == 0x5f)) && (uVar37 < 0x100)) {
                    FUN_0010a494(param_1);
                    goto LAB_00114d28;
                  }
                  break;
                }
                uVar35 = uVar35 - 0x57;
              }
            }
            pbVar20 = pbVar20 + 1;
            uVar37 = (long)(int)uVar35 + uVar37 * 0x10;
          } while (pbVar20 != pbVar3);
          bVar30 = 0x5f;
        }
        lVar15 = *(long *)(param_1 + 0x100);
        if (lVar15 == 0xff) {
          param_1[0xff] = 0;
          (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
          lVar12 = 1;
          lVar15 = 0;
          *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        }
        else {
          lVar12 = lVar15 + 1;
        }
        *(long *)(param_1 + 0x100) = lVar12;
        param_1[lVar15] = bVar30;
        param_1[0x108] = bVar30;
        pbVar20 = pbVar34;
LAB_00114d28:
        pbVar34 = pbVar20 + 1;
      }
    }
    break;
  case 1:
  case 2:
    FUN_001122e8(param_1,param_2,param_3[1]);
    lVar15 = *(long *)(param_1 + 0x100);
    bVar30 = (byte)param_2 & 4;
    if ((param_2 >> 2 & 1) == 0) {
      if (lVar15 == 0xff) {
        param_1[0xff] = bVar30;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar12 = 1;
        *param_1 = 0x3a;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
LAB_0011243c:
        lVar15 = lVar12 + 1;
      }
      else {
        lVar12 = lVar15 + 1;
        *(long *)(param_1 + 0x100) = lVar12;
        param_1[lVar15] = 0x3a;
        param_1[0x108] = 0x3a;
        if (lVar12 != 0xff) goto LAB_0011243c;
        param_1[0xff] = bVar30;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar15 = 1;
        lVar12 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
      *(long *)(param_1 + 0x100) = lVar15;
      param_1[lVar12] = 0x3a;
      param_1[0x108] = 0x3a;
    }
    else {
      if (lVar15 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar12 = 1;
        lVar15 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
      else {
        lVar12 = lVar15 + 1;
      }
      *(long *)(param_1 + 0x100) = lVar12;
      param_1[lVar15] = 0x2e;
      param_1[0x108] = 0x2e;
    }
    piVar9 = (int *)param_3[2];
    if (*piVar9 == 0x45) {
      FUN_0010aabc(param_1,"{default arg#");
      FUN_0010ab68(param_1,(long)(piVar9[4] + 1));
      FUN_0010aabc(param_1,&DAT_0011f4a0);
      piVar9 = *(int **)(piVar9 + 2);
    }
    FUN_001122e8(param_1,param_2,piVar9);
    break;
  case 3:
    uVar38 = *(undefined8 *)(param_1 + 0x128);
    *(undefined8 *)(param_1 + 0x128) = 0;
    plVar21 = (long *)param_3[1];
    if (plVar21 != (long *)0x0) {
      iVar7 = *(int *)plVar21;
      ppplVar25 = *(long ****)(param_1 + 0x120);
      local_80 = (long **)0x0;
      *(long ****)(param_1 + 0x128) = &local_80;
      local_78 = plVar21;
      local_70._0_4_ = 0;
      local_68[0] = ppplVar25;
      if (iVar7 - 0x1cU < 5) {
        plVar21 = (long *)plVar21[1];
        if (plVar21 != (long *)0x0) {
          iVar7 = *(int *)plVar21;
          local_68[1] = &local_80;
          *(long *****)(param_1 + 0x128) = local_68 + 1;
          local_58 = plVar21;
          local_50._0_4_ = 0;
          local_48 = ppplVar25;
          if (4 < iVar7 - 0x1cU) {
            uVar37 = 2;
            goto LAB_00116b70;
          }
          plVar21 = (long *)plVar21[1];
          if (plVar21 != (long *)0x0) {
            iVar7 = *(int *)plVar21;
            local_40 = local_68 + 1;
            local_38 = plVar21;
            *(long ******)(param_1 + 0x128) = &local_40;
            local_30 = 0;
            local_28 = ppplVar25;
            if (4 < iVar7 - 0x1cU) {
              uVar37 = 3;
              goto LAB_00116b70;
            }
            plVar21 = (long *)plVar21[1];
            if (plVar21 != (long *)0x0) {
              iVar7 = *(int *)plVar21;
              local_20 = &local_40;
              local_18 = plVar21;
              *(long *****)(param_1 + 0x128) = &local_28 + 1;
              local_10 = local_10 & 0xffffffff00000000;
              local_8 = ppplVar25;
              if (4 < iVar7 - 0x1cU) {
                uVar37 = 4;
                goto LAB_00116b70;
              }
            }
          }
        }
      }
      else {
        uVar37 = 1;
LAB_00116b70:
        uVar36 = uVar37;
        if (iVar7 == 4) {
          *(long *****)(param_1 + 0x120) = &local_90;
          local_90 = ppplVar25;
          local_88 = plVar21;
LAB_00116c90:
          FUN_001122e8(param_1,param_2,param_3[2]);
          if (*(int *)plVar21 == 4) {
            *(long ****)(param_1 + 0x120) = local_90;
          }
          iVar7 = (int)uVar36;
          uVar35 = iVar7 - 1;
          if (*(int *)(&local_70 + (ulong)uVar35 * 4) == 0) {
            FUN_0010a494(param_1,0x20);
            FUN_00116e70(param_1,param_2,(&local_78)[(ulong)uVar35 * 4]);
          }
          if (uVar35 != 0) {
            uVar35 = iVar7 - 2;
            if (*(int *)(&local_70 + (ulong)uVar35 * 4) == 0) {
              FUN_0010a494(param_1,0x20);
              FUN_00116e70(param_1,param_2,(&local_78)[(ulong)uVar35 * 4]);
            }
            if (uVar35 != 0) {
              uVar35 = iVar7 - 3;
              if (*(int *)(&local_70 + (ulong)uVar35 * 4) == 0) {
                FUN_0010a494(param_1,0x20);
                FUN_00116e70(param_1,param_2,(&local_78)[(ulong)uVar35 * 4]);
              }
              if ((uVar35 != 0) && ((uint)local_70 == 0)) {
                FUN_0010a494(param_1,0x20);
                FUN_00116e70(param_1,param_2,local_78);
                *(undefined8 *)(param_1 + 0x128) = uVar38;
                return;
              }
            }
          }
          *(undefined8 *)(param_1 + 0x128) = uVar38;
          return;
        }
        if (iVar7 != 2) goto LAB_00116c90;
        plVar28 = (long *)plVar21[2];
        if (*(int *)plVar28 == 0x45) {
          plVar28 = (long *)plVar28[1];
        }
        if (4 < *(int *)plVar28 - 0x1cU) goto LAB_00116c90;
        iVar7 = (int)uVar37;
        if (iVar7 != 4) {
          uVar36 = (ulong)(iVar7 - 1);
          ppplVar27 = &local_80 + uVar37 * 4;
          *(long ****)(param_1 + 0x128) = ppplVar27;
          ppplVar22 = &local_80 + uVar36 * 4;
          uVar29 = (ulong)(iVar7 + 1U);
          plVar17 = (&local_78)[uVar36 * 4];
          *ppplVar27 = *ppplVar22;
          (&local_78)[uVar37 * 4] = plVar17;
          ppplVar18 = local_68[uVar36 * 4];
          (&local_70)[uVar37 * 4] = (&local_70)[uVar36 * 4];
          local_68[uVar37 * 4] = ppplVar18;
          (&local_80)[uVar37 * 4] = (long **)ppplVar22;
          (&local_78)[uVar36 * 4] = plVar28;
          *(undefined4 *)(&local_70 + uVar36 * 4) = 0;
          local_68[uVar36 * 4] = ppplVar25;
          plVar28 = (long *)plVar28[1];
          uVar36 = uVar29;
          if (4 < *(int *)plVar28 - 0x1cU) goto LAB_00116c90;
          if (iVar7 + 1U != 4) {
            uVar36 = (ulong)(iVar7 + 2U);
            ppplVar22 = &local_80 + uVar29 * 4;
            *(long ****)(param_1 + 0x128) = ppplVar22;
            plVar17 = (&local_78)[uVar37 * 4];
            *ppplVar22 = *ppplVar27;
            (&local_78)[uVar29 * 4] = plVar17;
            ppplVar22 = local_68[uVar37 * 4];
            (&local_70)[uVar29 * 4] = (&local_70)[uVar37 * 4];
            local_68[uVar29 * 4] = ppplVar22;
            (&local_80)[uVar29 * 4] = (long **)ppplVar27;
            (&local_78)[uVar37 * 4] = plVar28;
            *(undefined4 *)(&local_70 + uVar37 * 4) = 0;
            local_68[uVar37 * 4] = ppplVar25;
            plVar28 = (long *)plVar28[1];
            if (4 < *(int *)plVar28 - 0x1cU) goto LAB_00116c90;
            if (iVar7 + 2U != 4) {
              local_10 = CONCAT44(uStack_2c,local_30);
              local_18 = local_38;
              local_20 = &local_40;
              local_8 = local_28;
              *(long *****)(param_1 + 0x128) = &local_28 + 1;
              local_30 = 0;
              if (4 < *(int *)plVar28[1] - 0x1cU) {
                uVar36 = 4;
                local_38 = plVar28;
                local_28 = ppplVar25;
                goto LAB_00116c90;
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
    uVar39 = *(undefined8 *)(param_1 + 0x128);
    *(long **)(param_1 + 0x160) = param_3;
    *(undefined8 *)(param_1 + 0x128) = 0;
    piVar9 = (int *)param_3[1];
    if (((((param_2 >> 2 & 1) == 0) || (*piVar9 != 0)) || (piVar9[4] != 6)) ||
       (iVar7 = strncmp(*(char **)(piVar9 + 2),"JArray",6), iVar7 != 0)) {
      FUN_001122e8(param_1,param_2,piVar9);
      if (param_1[0x108] == '<') {
        FUN_0010a494(param_1,0x20);
      }
      lVar15 = *(long *)(param_1 + 0x100);
      if (lVar15 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar12 = 1;
        lVar15 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
      else {
        lVar12 = lVar15 + 1;
      }
      *(long *)(param_1 + 0x100) = lVar12;
      param_1[lVar15] = 0x3c;
      param_1[0x108] = 0x3c;
      FUN_001122e8(param_1,param_2,param_3[2]);
      if (param_1[0x108] == '>') {
        FUN_0010a494(param_1,0x20);
      }
      lVar15 = *(long *)(param_1 + 0x100);
      if (lVar15 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar12 = 1;
        lVar15 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
      else {
        lVar12 = lVar15 + 1;
      }
      *(long *)(param_1 + 0x100) = lVar12;
      param_1[lVar15] = 0x3e;
      param_1[0x108] = 0x3e;
    }
    else {
      FUN_001122e8(param_1,param_2,param_3[2]);
      FUN_0010aabc(param_1,&DAT_0011f4b0);
    }
    *(undefined8 *)(param_1 + 0x128) = uVar39;
    *(undefined8 *)(param_1 + 0x160) = uVar38;
    break;
  case 5:
    piVar9 = (int *)FUN_0010a89c(param_1,param_3 + 1);
    if (piVar9 != (int *)0x0) {
      if (*piVar9 != 0x2f) {
LAB_00113234:
        puVar33 = *(undefined8 **)(param_1 + 0x120);
        *(undefined8 *)(param_1 + 0x120) = *puVar33;
        FUN_001122e8(param_1,param_2);
        *(undefined8 **)(param_1 + 0x120) = puVar33;
        return;
      }
      iVar7 = *(int *)(param_1 + 0x134);
      while (0 < iVar7) {
        piVar9 = *(int **)(piVar9 + 4);
        iVar7 = iVar7 + -1;
        if ((piVar9 == (int *)0x0) || (*piVar9 != 0x2f)) goto LAB_00112364;
      }
      if ((iVar7 == 0) && (*(long *)(piVar9 + 2) != 0)) goto LAB_00113234;
    }
    goto LAB_00112364;
  case 6:
    lVar15 = param_3[1];
    if (lVar15 == 0) {
      FUN_0010aabc(param_1,&DAT_0011f678);
    }
    else {
      FUN_0010aabc(param_1,"{parm#");
      FUN_0010ab68(param_1,lVar15);
      FUN_0010a494(param_1,0x7d);
    }
    break;
  case 7:
    FUN_001122e8(param_1,param_2,param_3[2]);
    break;
  case 8:
    lVar15 = *(long *)(param_1 + 0x100);
    if (lVar15 == 0xff) {
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar12 = 1;
      lVar15 = 0;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    }
    else {
      lVar12 = lVar15 + 1;
    }
    *(long *)(param_1 + 0x100) = lVar12;
    param_1[lVar15] = 0x7e;
    param_1[0x108] = 0x7e;
    FUN_001122e8(param_1,param_2,param_3[2]);
    break;
  case 9:
    lVar15 = *(long *)(param_1 + 0x100);
    if (lVar15 == 0xff) {
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      *param_1 = 0x76;
      lVar15 = 2;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 0x74;
LAB_0011368c:
      lVar12 = lVar15 + 1;
      *(long *)(param_1 + 0x100) = lVar12;
      param_1[lVar15] = 0x61;
      param_1[0x108] = 0x61;
      if (lVar12 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x62;
        lVar15 = 2;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        param_1[1] = 0x6c;
        goto LAB_001136e0;
      }
LAB_001136a8:
      lVar11 = lVar12 + 1;
      *(long *)(param_1 + 0x100) = lVar11;
      param_1[lVar12] = 0x62;
      param_1[0x108] = 0x62;
      if (lVar11 != 0xff) goto LAB_001136c4;
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      *param_1 = 0x6c;
      lVar12 = 2;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 0x65;
LAB_001136fc:
      lVar15 = lVar12 + 1;
      *(long *)(param_1 + 0x100) = lVar15;
      param_1[lVar12] = 0x20;
      param_1[0x108] = 0x20;
      if (lVar15 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x66;
        lVar15 = 2;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        param_1[1] = 0x6f;
        goto LAB_00113750;
      }
LAB_00113718:
      lVar12 = lVar15 + 1;
      *(long *)(param_1 + 0x100) = lVar12;
      param_1[lVar15] = 0x66;
      param_1[0x108] = 0x66;
      if (lVar12 != 0xff) goto LAB_00113734;
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      *param_1 = 0x6f;
      lVar12 = 2;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 0x72;
LAB_0011376c:
      lVar15 = lVar12 + 1;
    }
    else {
      lVar12 = lVar15 + 1;
      *(long *)(param_1 + 0x100) = lVar12;
      param_1[lVar15] = 0x76;
      param_1[0x108] = 0x76;
      if (lVar12 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x74;
        lVar12 = 2;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        param_1[1] = 0x61;
        goto LAB_001136a8;
      }
      lVar15 = lVar15 + 2;
      *(long *)(param_1 + 0x100) = lVar15;
      param_1[lVar12] = 0x74;
      param_1[0x108] = 0x74;
      if (lVar15 != 0xff) goto LAB_0011368c;
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      *param_1 = 0x61;
      lVar11 = 2;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 0x62;
LAB_001136c4:
      lVar15 = lVar11 + 1;
      *(long *)(param_1 + 0x100) = lVar15;
      param_1[lVar11] = 0x6c;
      param_1[0x108] = 0x6c;
      if (lVar15 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x65;
        lVar15 = 2;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        param_1[1] = 0x20;
        goto LAB_00113718;
      }
LAB_001136e0:
      lVar12 = lVar15 + 1;
      *(long *)(param_1 + 0x100) = lVar12;
      param_1[lVar15] = 0x65;
      param_1[0x108] = 0x65;
      if (lVar12 != 0xff) goto LAB_001136fc;
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      *param_1 = 0x20;
      lVar12 = 2;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 0x66;
LAB_00113734:
      lVar15 = lVar12 + 1;
      *(long *)(param_1 + 0x100) = lVar15;
      param_1[lVar12] = 0x6f;
      param_1[0x108] = 0x6f;
      if (lVar15 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x72;
        lVar12 = 1;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        goto LAB_0011376c;
      }
LAB_00113750:
      lVar12 = lVar15 + 1;
      *(long *)(param_1 + 0x100) = lVar12;
      param_1[lVar15] = 0x72;
      param_1[0x108] = 0x72;
      if (lVar12 != 0xff) goto LAB_0011376c;
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar15 = 1;
      lVar12 = 0;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    }
    *(long *)(param_1 + 0x100) = lVar15;
    param_1[lVar12] = 0x20;
    param_1[0x108] = 0x20;
    FUN_001122e8(param_1,param_2,param_3[1]);
    break;
  case 10:
    lVar15 = *(long *)(param_1 + 0x100);
    if (lVar15 == 0xff) {
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar15 = 2;
      *param_1 = 0x56;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 0x54;
LAB_00113528:
      lVar12 = lVar15 + 1;
      *(long *)(param_1 + 0x100) = lVar12;
      param_1[lVar15] = 0x54;
      param_1[0x108] = 0x54;
      if (lVar12 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x20;
        lVar15 = 2;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        param_1[1] = 0x66;
        goto LAB_0011357c;
      }
LAB_00113544:
      lVar11 = lVar12 + 1;
      *(long *)(param_1 + 0x100) = lVar11;
      param_1[lVar12] = 0x20;
      param_1[0x108] = 0x20;
      if (lVar11 != 0xff) goto LAB_00113560;
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      *param_1 = 0x66;
      lVar12 = 2;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 0x6f;
LAB_00113598:
      lVar15 = lVar12 + 1;
      *(long *)(param_1 + 0x100) = lVar15;
      param_1[lVar12] = 0x72;
      param_1[0x108] = 0x72;
      if (lVar15 != 0xff) goto LAB_001135b4;
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar12 = 1;
      lVar15 = 0;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    }
    else {
      lVar12 = lVar15 + 1;
      *(long *)(param_1 + 0x100) = lVar12;
      param_1[lVar15] = 0x56;
      param_1[0x108] = 0x56;
      if (lVar12 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x54;
        lVar12 = 2;
        param_1[1] = 0x54;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        goto LAB_00113544;
      }
      lVar15 = lVar15 + 2;
      *(long *)(param_1 + 0x100) = lVar15;
      param_1[lVar12] = 0x54;
      param_1[0x108] = 0x54;
      if (lVar15 != 0xff) goto LAB_00113528;
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      *param_1 = 0x54;
      lVar11 = 2;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 0x20;
LAB_00113560:
      lVar15 = lVar11 + 1;
      *(long *)(param_1 + 0x100) = lVar15;
      param_1[lVar11] = 0x66;
      param_1[0x108] = 0x66;
      if (lVar15 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x6f;
        lVar15 = 2;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        param_1[1] = 0x72;
      }
      else {
LAB_0011357c:
        lVar12 = lVar15 + 1;
        *(long *)(param_1 + 0x100) = lVar12;
        param_1[lVar15] = 0x6f;
        param_1[0x108] = 0x6f;
        if (lVar12 != 0xff) goto LAB_00113598;
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x72;
        lVar15 = 1;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
LAB_001135b4:
      lVar12 = lVar15 + 1;
    }
    *(long *)(param_1 + 0x100) = lVar12;
    param_1[lVar15] = 0x20;
    param_1[0x108] = 0x20;
    FUN_001122e8(param_1,param_2,param_3[1]);
    break;
  case 0xb:
    lVar15 = 0;
    lVar12 = *(long *)(param_1 + 0x100);
    do {
      cVar5 = "construction vtable for "[lVar15];
      if (lVar12 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar11 = 1;
        lVar12 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
      else {
        lVar11 = lVar12 + 1;
      }
      *(long *)(param_1 + 0x100) = lVar11;
      lVar15 = lVar15 + 1;
      param_1[lVar12] = cVar5;
      param_1[0x108] = cVar5;
      lVar12 = lVar11;
    } while (lVar15 != 0x18);
    FUN_001122e8(param_1,param_2,param_3[1]);
    lVar15 = *(long *)(param_1 + 0x100);
    if (lVar15 == 0xff) {
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar15 = 2;
      *param_1 = 0x2d;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 0x69;
LAB_00114500:
      lVar12 = lVar15 + 1;
      *(long *)(param_1 + 0x100) = lVar12;
      param_1[lVar15] = 0x6e;
      param_1[0x108] = 0x6e;
      if (lVar12 != 0xff) goto LAB_0011451c;
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar15 = 1;
      lVar12 = 0;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    }
    else {
      lVar12 = lVar15 + 1;
      *(long *)(param_1 + 0x100) = lVar12;
      param_1[lVar15] = 0x2d;
      param_1[0x108] = 0x2d;
      if (lVar12 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x69;
        lVar12 = 2;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        param_1[1] = 0x6e;
      }
      else {
        lVar15 = lVar15 + 2;
        *(long *)(param_1 + 0x100) = lVar15;
        param_1[lVar12] = 0x69;
        param_1[0x108] = 0x69;
        if (lVar15 != 0xff) goto LAB_00114500;
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x6e;
        lVar12 = 1;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
LAB_0011451c:
      lVar15 = lVar12 + 1;
    }
    *(long *)(param_1 + 0x100) = lVar15;
    param_1[lVar12] = 0x2d;
    param_1[0x108] = 0x2d;
    FUN_001122e8(param_1,param_2,param_3[2]);
    break;
  case 0xc:
    lVar15 = *(long *)(param_1 + 0x100);
    if (lVar15 == 0xff) {
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      *param_1 = 0x74;
      lVar15 = 2;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 0x79;
LAB_001127a8:
      lVar12 = lVar15 + 1;
      *(long *)(param_1 + 0x100) = lVar12;
      param_1[lVar15] = 0x70;
      param_1[0x108] = 0x70;
      if (lVar12 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x65;
        lVar15 = 2;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        param_1[1] = 0x69;
        goto LAB_001127fc;
      }
LAB_001127c4:
      lVar11 = lVar12 + 1;
      *(long *)(param_1 + 0x100) = lVar11;
      param_1[lVar12] = 0x65;
      param_1[0x108] = 0x65;
      if (lVar11 != 0xff) goto LAB_001127e0;
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      *param_1 = 0x69;
      lVar12 = 2;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 0x6e;
LAB_00112818:
      lVar15 = lVar12 + 1;
      *(long *)(param_1 + 0x100) = lVar15;
      param_1[lVar12] = 0x66;
      param_1[0x108] = 0x66;
      if (lVar15 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x6f;
        lVar15 = 2;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        param_1[1] = 0x20;
        goto LAB_0011286c;
      }
LAB_00112834:
      lVar12 = lVar15 + 1;
      *(long *)(param_1 + 0x100) = lVar12;
      param_1[lVar15] = 0x6f;
      param_1[0x108] = 0x6f;
      if (lVar12 != 0xff) goto LAB_00112850;
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      *param_1 = 0x20;
      lVar12 = 2;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 0x66;
LAB_00112888:
      lVar15 = lVar12 + 1;
      *(long *)(param_1 + 0x100) = lVar15;
      param_1[lVar12] = 0x6f;
      param_1[0x108] = 0x6f;
      if (lVar15 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x72;
        lVar12 = 1;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        goto LAB_001128c0;
      }
LAB_001128a4:
      lVar12 = lVar15 + 1;
      *(long *)(param_1 + 0x100) = lVar12;
      param_1[lVar15] = 0x72;
      param_1[0x108] = 0x72;
      if (lVar12 != 0xff) goto LAB_001128c0;
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar15 = 1;
      lVar12 = 0;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    }
    else {
      lVar12 = lVar15 + 1;
      *(long *)(param_1 + 0x100) = lVar12;
      param_1[lVar15] = 0x74;
      param_1[0x108] = 0x74;
      if (lVar12 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x79;
        lVar12 = 2;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        param_1[1] = 0x70;
        goto LAB_001127c4;
      }
      lVar15 = lVar15 + 2;
      *(long *)(param_1 + 0x100) = lVar15;
      param_1[lVar12] = 0x79;
      param_1[0x108] = 0x79;
      if (lVar15 != 0xff) goto LAB_001127a8;
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      *param_1 = 0x70;
      lVar11 = 2;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 0x65;
LAB_001127e0:
      lVar15 = lVar11 + 1;
      *(long *)(param_1 + 0x100) = lVar15;
      param_1[lVar11] = 0x69;
      param_1[0x108] = 0x69;
      if (lVar15 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x6e;
        lVar15 = 2;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        param_1[1] = 0x66;
        goto LAB_00112834;
      }
LAB_001127fc:
      lVar12 = lVar15 + 1;
      *(long *)(param_1 + 0x100) = lVar12;
      param_1[lVar15] = 0x6e;
      param_1[0x108] = 0x6e;
      if (lVar12 != 0xff) goto LAB_00112818;
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      *param_1 = 0x66;
      lVar12 = 2;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 0x6f;
LAB_00112850:
      lVar15 = lVar12 + 1;
      *(long *)(param_1 + 0x100) = lVar15;
      param_1[lVar12] = 0x20;
      param_1[0x108] = 0x20;
      if (lVar15 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x66;
        lVar15 = 2;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        param_1[1] = 0x6f;
        goto LAB_001128a4;
      }
LAB_0011286c:
      lVar12 = lVar15 + 1;
      *(long *)(param_1 + 0x100) = lVar12;
      param_1[lVar15] = 0x66;
      param_1[0x108] = 0x66;
      if (lVar12 != 0xff) goto LAB_00112888;
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      *param_1 = 0x6f;
      lVar12 = 2;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 0x72;
LAB_001128c0:
      lVar15 = lVar12 + 1;
    }
    *(long *)(param_1 + 0x100) = lVar15;
    param_1[lVar12] = 0x20;
    param_1[0x108] = 0x20;
    FUN_001122e8(param_1,param_2,param_3[1]);
    break;
  case 0xd:
    lVar15 = 0;
    lVar12 = *(long *)(param_1 + 0x100);
    do {
      cVar5 = "typeinfo name for "[lVar15];
      if (lVar12 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar11 = 1;
        lVar12 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
      else {
        lVar11 = lVar12 + 1;
      }
      *(long *)(param_1 + 0x100) = lVar11;
      lVar15 = lVar15 + 1;
      param_1[lVar12] = cVar5;
      param_1[0x108] = cVar5;
      lVar12 = lVar11;
    } while (lVar15 != 0x12);
    FUN_001122e8(param_1,param_2,param_3[1]);
    break;
  case 0xe:
    lVar15 = 0;
    lVar12 = *(long *)(param_1 + 0x100);
    do {
      cVar5 = "typeinfo fn for "[lVar15];
      if (lVar12 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar11 = 1;
        lVar12 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
      else {
        lVar11 = lVar12 + 1;
      }
      *(long *)(param_1 + 0x100) = lVar11;
      lVar15 = lVar15 + 1;
      param_1[lVar12] = cVar5;
      param_1[0x108] = cVar5;
      lVar12 = lVar11;
    } while (lVar15 != 0x10);
    FUN_001122e8(param_1,param_2,param_3[1]);
    break;
  case 0xf:
    lVar15 = 0;
    lVar12 = *(long *)(param_1 + 0x100);
    do {
      cVar5 = "non-virtual thunk to "[lVar15];
      if (lVar12 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar11 = 1;
        lVar12 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
      else {
        lVar11 = lVar12 + 1;
      }
      *(long *)(param_1 + 0x100) = lVar11;
      lVar15 = lVar15 + 1;
      param_1[lVar12] = cVar5;
      param_1[0x108] = cVar5;
      lVar12 = lVar11;
    } while (lVar15 != 0x15);
    FUN_001122e8(param_1,param_2,param_3[1]);
    break;
  case 0x10:
    lVar15 = 0;
    lVar12 = *(long *)(param_1 + 0x100);
    do {
      cVar5 = "virtual thunk to "[lVar15];
      if (lVar12 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar11 = 1;
        lVar12 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
      else {
        lVar11 = lVar12 + 1;
      }
      *(long *)(param_1 + 0x100) = lVar11;
      lVar15 = lVar15 + 1;
      param_1[lVar12] = cVar5;
      param_1[0x108] = cVar5;
      lVar12 = lVar11;
    } while (lVar15 != 0x11);
    FUN_001122e8(param_1,param_2,param_3[1]);
    break;
  case 0x11:
    lVar15 = 0;
    lVar12 = *(long *)(param_1 + 0x100);
    do {
      cVar5 = "covariant return thunk to "[lVar15];
      if (lVar12 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar11 = 1;
        lVar12 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
      else {
        lVar11 = lVar12 + 1;
      }
      *(long *)(param_1 + 0x100) = lVar11;
      lVar15 = lVar15 + 1;
      param_1[lVar12] = cVar5;
      param_1[0x108] = cVar5;
      lVar12 = lVar11;
    } while (lVar15 != 0x1a);
    FUN_001122e8(param_1,param_2,param_3[1]);
    break;
  case 0x12:
    lVar15 = 0;
    lVar12 = *(long *)(param_1 + 0x100);
    do {
      cVar5 = "java Class for "[lVar15];
      if (lVar12 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar11 = 1;
        lVar12 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
      else {
        lVar11 = lVar12 + 1;
      }
      *(long *)(param_1 + 0x100) = lVar11;
      lVar15 = lVar15 + 1;
      param_1[lVar12] = cVar5;
      param_1[0x108] = cVar5;
      lVar12 = lVar11;
    } while (lVar15 != 0xf);
    FUN_001122e8(param_1,param_2,param_3[1]);
    break;
  case 0x13:
    lVar15 = 0;
    lVar12 = *(long *)(param_1 + 0x100);
    do {
      cVar5 = "guard variable for "[lVar15];
      if (lVar12 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar11 = 1;
        lVar12 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
      else {
        lVar11 = lVar12 + 1;
      }
      *(long *)(param_1 + 0x100) = lVar11;
      lVar15 = lVar15 + 1;
      param_1[lVar12] = cVar5;
      param_1[0x108] = cVar5;
      lVar12 = lVar11;
    } while (lVar15 != 0x13);
    FUN_001122e8(param_1,param_2,param_3[1]);
    break;
  case 0x14:
    lVar15 = 0;
    lVar12 = *(long *)(param_1 + 0x100);
    do {
      cVar5 = "TLS init function for "[lVar15];
      if (lVar12 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar11 = 1;
        lVar12 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
      else {
        lVar11 = lVar12 + 1;
      }
      *(long *)(param_1 + 0x100) = lVar11;
      lVar15 = lVar15 + 1;
      param_1[lVar12] = cVar5;
      param_1[0x108] = cVar5;
      lVar12 = lVar11;
    } while (lVar15 != 0x16);
    FUN_001122e8(param_1,param_2,param_3[1]);
    break;
  case 0x15:
    lVar15 = 0;
    lVar12 = *(long *)(param_1 + 0x100);
    do {
      cVar5 = "TLS wrapper function for "[lVar15];
      if (lVar12 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar11 = 1;
        lVar12 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
      else {
        lVar11 = lVar12 + 1;
      }
      *(long *)(param_1 + 0x100) = lVar11;
      lVar15 = lVar15 + 1;
      param_1[lVar12] = cVar5;
      param_1[0x108] = cVar5;
      lVar12 = lVar11;
    } while (lVar15 != 0x19);
    FUN_001122e8(param_1,param_2,param_3[1]);
    break;
  case 0x16:
    lVar15 = 0;
    lVar12 = *(long *)(param_1 + 0x100);
    do {
      cVar5 = "reference temporary #"[lVar15];
      if (lVar12 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar11 = 1;
        lVar12 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
      else {
        lVar11 = lVar12 + 1;
      }
      *(long *)(param_1 + 0x100) = lVar11;
      lVar15 = lVar15 + 1;
      param_1[lVar12] = cVar5;
      param_1[0x108] = cVar5;
      lVar12 = lVar11;
    } while (lVar15 != 0x15);
    FUN_001122e8(param_1,param_2,param_3[2]);
    lVar15 = *(long *)(param_1 + 0x100);
    if (lVar15 == 0xff) {
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      *param_1 = 0x20;
      lVar15 = 2;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 0x66;
LAB_00114614:
      lVar12 = lVar15 + 1;
      *(long *)(param_1 + 0x100) = lVar12;
      param_1[lVar15] = 0x6f;
      param_1[0x108] = 0x6f;
      if (lVar12 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x72;
        lVar15 = 1;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        goto LAB_0011464c;
      }
LAB_00114630:
      lVar15 = lVar12 + 1;
      *(long *)(param_1 + 0x100) = lVar15;
      param_1[lVar12] = 0x72;
      param_1[0x108] = 0x72;
      if (lVar15 != 0xff) goto LAB_0011464c;
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar12 = 1;
      lVar15 = 0;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    }
    else {
      lVar12 = lVar15 + 1;
      *(long *)(param_1 + 0x100) = lVar12;
      param_1[lVar15] = 0x20;
      param_1[0x108] = 0x20;
      if (lVar12 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x66;
        lVar12 = 2;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        param_1[1] = 0x6f;
        goto LAB_00114630;
      }
      lVar15 = lVar15 + 2;
      *(long *)(param_1 + 0x100) = lVar15;
      param_1[lVar12] = 0x66;
      param_1[0x108] = 0x66;
      if (lVar15 != 0xff) goto LAB_00114614;
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      *param_1 = 0x6f;
      lVar15 = 2;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 0x72;
LAB_0011464c:
      lVar12 = lVar15 + 1;
    }
    *(long *)(param_1 + 0x100) = lVar12;
    param_1[lVar15] = 0x20;
    param_1[0x108] = 0x20;
    FUN_001122e8(param_1,param_2,param_3[1]);
    break;
  case 0x17:
    lVar15 = 0;
    lVar12 = *(long *)(param_1 + 0x100);
    do {
      cVar5 = "hidden alias for "[lVar15];
      if (lVar12 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar11 = 1;
        lVar12 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
      else {
        lVar11 = lVar12 + 1;
      }
      *(long *)(param_1 + 0x100) = lVar11;
      lVar15 = lVar15 + 1;
      param_1[lVar12] = cVar5;
      param_1[0x108] = cVar5;
      lVar12 = lVar11;
    } while (lVar15 != 0x11);
    FUN_001122e8(param_1,param_2,param_3[1]);
    break;
  case 0x18:
    iVar7 = *(int *)(param_3 + 2);
    lVar15 = param_3[1];
    if ((long)iVar7 != 0) {
      lVar12 = 0;
      lVar11 = *(long *)(param_1 + 0x100);
      do {
        uVar4 = *(undefined *)(lVar15 + lVar12);
        if (lVar11 == 0xff) {
          param_1[0xff] = 0;
          (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
          lVar16 = 1;
          lVar11 = 0;
          *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        }
        else {
          lVar16 = lVar11 + 1;
        }
        *(long *)(param_1 + 0x100) = lVar16;
        lVar12 = lVar12 + 1;
        param_1[lVar11] = uVar4;
        param_1[0x108] = uVar4;
        lVar11 = lVar16;
      } while (iVar7 != lVar12);
    }
    break;
  case 0x19:
  case 0x1a:
  case 0x1b:
    local_80 = *(long ***)(param_1 + 0x128);
    pplVar26 = local_80;
    if (local_80 == (long **)0x0) {
      bVar6 = false;
    }
    else {
      do {
        if (*(int *)(pplVar26 + 2) == 0) {
          if (2 < *(int *)pplVar26[1] - 0x19U) {
            bVar6 = false;
            goto LAB_00112c94;
          }
          if (iVar7 == *(int *)pplVar26[1]) {
            FUN_001122e8(param_1,param_2,param_3[1]);
            return;
          }
        }
        pplVar26 = (long **)*pplVar26;
      } while (pplVar26 != (long **)0x0);
      bVar6 = false;
    }
    goto LAB_00112c94;
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
    bVar6 = false;
LAB_00112c94:
    local_68[0] = *(long ****)(param_1 + 0x120);
    *(long ****)(param_1 + 0x128) = &local_80;
    local_78 = param_3;
LAB_00112cb0:
    lVar15 = local_78[1];
LAB_00112cb4:
    plVar21 = local_78;
    local_70._0_4_ = 0;
    FUN_001122e8(param_1,param_2,lVar15);
    if ((uint)local_70 == 0) {
      FUN_00116e70(param_1,param_2,plVar21);
    }
    *(long ***)(param_1 + 0x128) = local_80;
    if (bVar6) {
      *(undefined8 *)(param_1 + 0x120) = unaff_x23;
    }
    break;
  case 0x23:
  case 0x24:
    plVar21 = (long *)param_3[1];
    bVar6 = false;
    iVar7 = *(int *)plVar21;
    if (iVar7 == 5) {
      uVar35 = *(uint *)(param_1 + 0x148);
      pplVar26 = *(long ***)(param_1 + 0x140);
      if ((int)uVar35 < 1) {
LAB_00114b0c:
        if (*(int *)(param_1 + 0x14c) <= (int)uVar35) {
LAB_00116dec:
          *(undefined4 *)(param_1 + 0x130) = 1;
          return;
        }
        uVar37 = -(ulong)(uVar35 >> 0x1f) & 0xfffffff000000000 | (ulong)uVar35 << 4;
        plVar28 = *(long **)(param_1 + 0x120);
        *(uint *)(param_1 + 0x148) = uVar35 + 1;
        *(long **)((long)pplVar26 + uVar37) = plVar21;
        puVar33 = (undefined8 *)((long)pplVar26 + uVar37 + 8);
        if (plVar28 != (long *)0x0) {
          uVar35 = *(uint *)(param_1 + 0x158);
          iVar7 = *(int *)(param_1 + 0x15c);
          if ((int)uVar35 < iVar7) {
            uVar37 = -(ulong)(uVar35 >> 0x1f) & 0xfffffff000000000 | (ulong)uVar35 << 4;
            puVar19 = puVar33;
            iVar31 = uVar35 + 1;
            do {
              iVar1 = iVar31;
              puVar33 = (undefined8 *)(*(long *)(param_1 + 0x150) + uVar37);
              puVar33[1] = plVar28[1];
              *puVar19 = puVar33;
              plVar28 = (long *)*plVar28;
              if (plVar28 == (long *)0x0) {
                *(int *)(param_1 + 0x158) = iVar1;
                goto LAB_00114b90;
              }
              uVar37 = uVar37 + 0x10;
              puVar19 = puVar33;
              iVar31 = iVar1 + 1;
            } while (iVar1 + 1 != iVar7 + 1);
            *(int *)(param_1 + 0x158) = iVar1;
          }
          goto LAB_00116dec;
        }
LAB_00114b90:
        *puVar33 = 0;
        bVar6 = false;
        plVar21 = (long *)FUN_0010a89c(param_1,plVar21 + 1);
        if (plVar21 == (long *)0x0) goto LAB_00112364;
LAB_00114c2c:
        iVar7 = *(int *)plVar21;
        if (iVar7 != 0x2f) goto LAB_00112cf0;
        iVar7 = *(int *)(param_1 + 0x134);
        while (0 < iVar7) {
          plVar21 = (long *)plVar21[2];
          iVar7 = iVar7 + -1;
          if ((plVar21 == (long *)0x0) || (*(int *)plVar21 != 0x2f)) goto LAB_0011235c;
        }
        if ((iVar7 == 0) && (plVar21 = (long *)plVar21[1], plVar21 != (long *)0x0)) {
          iVar7 = *(int *)plVar21;
          goto LAB_00112cf0;
        }
LAB_0011235c:
        if (!bVar6) goto LAB_00112364;
      }
      else {
        pplVar14 = pplVar26;
        if (plVar21 != *pplVar26) {
          do {
            pplVar14 = pplVar14 + 2;
            if (pplVar14 == pplVar26 + ((ulong)(uVar35 - 1) + 1) * 2) goto LAB_00114b0c;
          } while (plVar21 != *pplVar14);
        }
        unaff_x23 = *(undefined8 *)(param_1 + 0x120);
        *(long **)(param_1 + 0x120) = pplVar14[1];
        bVar6 = true;
        plVar21 = (long *)FUN_0010a89c(param_1,plVar21 + 1);
        if (plVar21 != (long *)0x0) goto LAB_00114c2c;
      }
      *(undefined8 *)(param_1 + 0x120) = unaff_x23;
LAB_00112364:
      *(undefined4 *)(param_1 + 0x130) = 1;
      return;
    }
LAB_00112cf0:
    if ((iVar7 == 0x23) || (*(int *)param_3 == iVar7)) {
      local_80 = *(long ***)(param_1 + 0x128);
      param_3 = plVar21;
      goto LAB_00112c94;
    }
    if (iVar7 != 0x24) {
      local_80 = *(long ***)(param_1 + 0x128);
      goto LAB_00112c94;
    }
    lVar15 = plVar21[1];
    local_68[0] = *(long ****)(param_1 + 0x120);
    local_80 = *(long ***)(param_1 + 0x128);
    *(long ****)(param_1 + 0x128) = &local_80;
    local_78 = param_3;
    if (lVar15 == 0) goto LAB_00112cb0;
    goto LAB_00112cb4;
  case 0x27:
    if ((param_2 >> 2 & 1) == 0) {
      lVar15 = (long)*(int *)((long *)param_3[1] + 1);
      lVar12 = *(long *)param_3[1];
      if (lVar15 != 0) {
        lVar11 = 0;
        lVar16 = *(long *)(param_1 + 0x100);
        do {
          uVar4 = *(undefined *)(lVar12 + lVar11);
          if (lVar16 == 0xff) {
            param_1[0xff] = 0;
            (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
            lVar13 = 1;
            lVar16 = 0;
            *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
          }
          else {
            lVar13 = lVar16 + 1;
          }
          *(long *)(param_1 + 0x100) = lVar13;
          lVar11 = lVar11 + 1;
          param_1[lVar16] = uVar4;
          param_1[0x108] = uVar4;
          lVar16 = lVar13;
        } while (lVar15 != lVar11);
      }
    }
    else {
      lVar15 = (long)*(int *)(param_3[1] + 0x18);
      lVar12 = *(long *)(param_3[1] + 0x10);
      if (lVar15 != 0) {
        lVar11 = 0;
        lVar16 = *(long *)(param_1 + 0x100);
        do {
          uVar4 = *(undefined *)(lVar12 + lVar11);
          if (lVar16 == 0xff) {
            param_1[0xff] = 0;
            (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
            lVar13 = 1;
            lVar16 = 0;
            *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
          }
          else {
            lVar13 = lVar16 + 1;
          }
          *(long *)(param_1 + 0x100) = lVar13;
          lVar11 = lVar11 + 1;
          param_1[lVar16] = uVar4;
          param_1[0x108] = uVar4;
          lVar16 = lVar13;
        } while (lVar15 != lVar11);
      }
    }
    break;
  case 0x28:
    FUN_001122e8(param_1,param_2,param_3[1]);
    break;
  case 0x29:
    if ((param_2 >> 5 & 1) == 0) {
      if (param_3[1] != 0) {
        if ((param_2 >> 6 & 1) == 0) {
          local_80 = *(long ***)(param_1 + 0x128);
          *(long ****)(param_1 + 0x128) = &local_80;
          local_68[0] = *(long ****)(param_1 + 0x120);
          local_78 = param_3;
          local_70._0_4_ = param_2 & 0x40;
          FUN_001122e8(param_1,param_2 & 0xffffff9f,param_3[1]);
          *(long ***)(param_1 + 0x128) = local_80;
          if ((uint)local_70 != 0) {
            return;
          }
          FUN_0010a494(param_1,0x20);
        }
      }
      FUN_00118d70(param_1,param_2 & 0xffffff9f,param_3 + 2,*(undefined8 *)(param_1 + 0x128));
    }
    else {
      FUN_00118d70(param_1,param_2 & 0xffffff9f,param_3 + 2,*(undefined8 *)(param_1 + 0x128));
      if (param_3[1] != 0) {
        FUN_001122e8(param_1,param_2 & 0xffffff9f);
      }
    }
    break;
  case 0x2a:
    pplVar26 = *(long ***)(param_1 + 0x128);
    local_68[0] = *(long ****)(param_1 + 0x120);
    *(long ****)(param_1 + 0x128) = &local_80;
    local_70._0_4_ = 0;
    local_80 = pplVar26;
    if ((pplVar26 == (long **)0x0) || (2 < *(int *)pplVar26[1] - 0x19U)) {
      local_78 = param_3;
      FUN_001122e8(param_1,param_2,param_3[2]);
      *(long ***)(param_1 + 0x128) = pplVar26;
      if ((uint)local_70 != 0) {
        return;
      }
    }
    else {
      pplVar14 = pplVar26;
      ppplVar25 = &local_80;
      uVar37 = 1;
      do {
        ppplVar27 = ppplVar25;
        uVar36 = uVar37;
        if (*(int *)(pplVar14 + 2) == 0) {
          if (3 < (uint)uVar37) {
            *(undefined4 *)(param_1 + 0x130) = 1;
            return;
          }
          uVar36 = (ulong)((uint)uVar37 + 1);
          ppplVar27 = &local_80 + uVar37 * 4;
          plVar21 = pplVar14[1];
          *ppplVar27 = (long **)*pplVar14;
          (&local_78)[uVar37 * 4] = plVar21;
          ppplVar22 = (long ***)pplVar14[3];
          (&local_70)[uVar37 * 4] = pplVar14[2];
          local_68[uVar37 * 4] = ppplVar22;
          (&local_80)[uVar37 * 4] = (long **)ppplVar25;
          *(long ****)(param_1 + 0x128) = ppplVar27;
          *(undefined4 *)(pplVar14 + 2) = 1;
        }
        pplVar14 = (long **)*pplVar14;
      } while ((pplVar14 != (long **)0x0) &&
              (ppplVar25 = ppplVar27, uVar37 = uVar36, *(int *)pplVar14[1] - 0x19U < 3));
      local_78 = param_3;
      FUN_001122e8(param_1,param_2,param_3[2]);
      *(long ***)(param_1 + 0x128) = pplVar26;
      if ((uint)local_70 != 0) {
        return;
      }
      if ((int)uVar36 != 1) {
        do {
          uVar35 = (int)uVar36 - 1;
          uVar36 = (ulong)uVar35;
          FUN_00116e70(param_1,param_2,(&local_78)[uVar36 * 4]);
        } while (uVar35 != 1);
        pplVar26 = *(long ***)(param_1 + 0x128);
      }
    }
    FUN_00118aa4(param_1,param_2,param_3 + 1,pplVar26);
    break;
  case 0x2b:
  case 0x2d:
    local_80 = *(long ***)(param_1 + 0x128);
    *(long ****)(param_1 + 0x128) = &local_80;
    local_68[0] = *(long ****)(param_1 + 0x120);
    local_70._0_4_ = 0;
    local_78 = param_3;
    FUN_001122e8(param_1,param_2,param_3[2]);
    if ((uint)local_70 == 0) {
      FUN_00116e70(param_1,param_2,param_3);
    }
    *(long ***)(param_1 + 0x128) = local_80;
    break;
  case 0x2c:
    if (*(short *)((long)param_3 + 0x12) != 0) {
      lVar15 = *(long *)(param_1 + 0x100);
      if (lVar15 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar15 = 2;
        *param_1 = 0x5f;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        param_1[1] = 0x53;
LAB_00114a48:
        lVar12 = lVar15 + 1;
        *(long *)(param_1 + 0x100) = lVar12;
        param_1[lVar15] = 0x61;
        param_1[0x108] = 0x61;
        if (lVar12 == 0xff) {
          param_1[0xff] = 0;
          (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
          *param_1 = 0x74;
          lVar15 = 1;
          *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
          goto LAB_00114a80;
        }
LAB_00114a64:
        lVar15 = lVar12 + 1;
        *(long *)(param_1 + 0x100) = lVar15;
        param_1[lVar12] = 0x74;
        param_1[0x108] = 0x74;
        if (lVar15 != 0xff) goto LAB_00114a80;
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar12 = 1;
        lVar15 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
      else {
        lVar12 = lVar15 + 1;
        *(long *)(param_1 + 0x100) = lVar12;
        param_1[lVar15] = 0x5f;
        param_1[0x108] = 0x5f;
        if (lVar12 == 0xff) {
          param_1[0xff] = 0;
          (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
          *param_1 = 0x53;
          lVar12 = 2;
          *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
          param_1[1] = 0x61;
          goto LAB_00114a64;
        }
        lVar15 = lVar15 + 2;
        *(long *)(param_1 + 0x100) = lVar15;
        param_1[lVar12] = 0x53;
        param_1[0x108] = 0x53;
        if (lVar15 != 0xff) goto LAB_00114a48;
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x61;
        lVar15 = 2;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        param_1[1] = 0x74;
LAB_00114a80:
        lVar12 = lVar15 + 1;
      }
      *(long *)(param_1 + 0x100) = lVar12;
      param_1[lVar15] = 0x20;
      param_1[0x108] = 0x20;
    }
    if (*(undefined **)(param_3[1] + 8) == &UNK_00134a80) {
      lVar15 = *(long *)(param_1 + 0x100);
    }
    else {
      FUN_001122e8(param_1,param_2);
      lVar12 = *(long *)(param_1 + 0x100);
      if (lVar12 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar15 = 1;
        lVar12 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
      else {
        lVar15 = lVar12 + 1;
      }
      *(long *)(param_1 + 0x100) = lVar15;
      param_1[lVar12] = 0x20;
      param_1[0x108] = 0x20;
    }
    if (*(short *)(param_3 + 2) == 0) {
      if (lVar15 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar15 = 2;
        *param_1 = 0x5f;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        param_1[1] = 0x46;
LAB_0011479c:
        lVar12 = lVar15 + 1;
        *(long *)(param_1 + 0x100) = lVar12;
        param_1[lVar15] = 0x72;
        param_1[0x108] = 0x72;
        if (lVar12 == 0xff) {
          param_1[0xff] = 0;
          (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
          *param_1 = 0x61;
          lVar15 = 2;
          *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
          param_1[1] = 99;
        }
        else {
LAB_001147b8:
          lVar11 = lVar12 + 1;
          *(long *)(param_1 + 0x100) = lVar11;
          param_1[lVar12] = 0x61;
          param_1[0x108] = 0x61;
          if (lVar11 != 0xff) goto LAB_001147d4;
          param_1[0xff] = 0;
          (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
          *param_1 = 99;
          lVar15 = 1;
          *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        }
      }
      else {
        lVar12 = lVar15 + 1;
        *(long *)(param_1 + 0x100) = lVar12;
        param_1[lVar15] = 0x5f;
        param_1[0x108] = 0x5f;
        if (lVar12 == 0xff) {
          param_1[0xff] = 0;
          (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
          *param_1 = 0x46;
          lVar12 = 2;
          *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
          param_1[1] = 0x72;
          goto LAB_001147b8;
        }
        lVar15 = lVar15 + 2;
        *(long *)(param_1 + 0x100) = lVar15;
        param_1[lVar12] = 0x46;
        param_1[0x108] = 0x46;
        if (lVar15 != 0xff) goto LAB_0011479c;
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x72;
        lVar11 = 2;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        param_1[1] = 0x61;
LAB_001147d4:
        lVar15 = lVar11 + 1;
        *(long *)(param_1 + 0x100) = lVar15;
        param_1[lVar11] = 99;
        param_1[0x108] = 99;
        if (lVar15 == 0xff) {
          param_1[0xff] = 0;
          (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
          lVar12 = 1;
          lVar15 = 0;
          *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
          goto LAB_001147f4;
        }
      }
      lVar12 = lVar15 + 1;
LAB_001147f4:
      *(long *)(param_1 + 0x100) = lVar12;
      param_1[lVar15] = 0x74;
      param_1[0x108] = 0x74;
      return;
    }
    if (lVar15 == 0xff) {
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar15 = 2;
      *param_1 = 0x5f;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 0x41;
LAB_00113a28:
      lVar12 = lVar15 + 1;
      *(long *)(param_1 + 0x100) = lVar12;
      param_1[lVar15] = 99;
      param_1[0x108] = 99;
      if (lVar12 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 99;
        lVar15 = 2;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        param_1[1] = 0x75;
      }
      else {
LAB_00113a44:
        lVar11 = lVar12 + 1;
        *(long *)(param_1 + 0x100) = lVar11;
        param_1[lVar12] = 99;
        param_1[0x108] = 99;
        if (lVar11 != 0xff) goto LAB_00113a60;
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x75;
        lVar15 = 1;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
LAB_00113a7c:
      lVar12 = lVar15 + 1;
    }
    else {
      lVar12 = lVar15 + 1;
      *(long *)(param_1 + 0x100) = lVar12;
      param_1[lVar15] = 0x5f;
      param_1[0x108] = 0x5f;
      if (lVar12 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x41;
        lVar12 = 2;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        param_1[1] = 99;
        goto LAB_00113a44;
      }
      lVar15 = lVar15 + 2;
      *(long *)(param_1 + 0x100) = lVar15;
      param_1[lVar12] = 0x41;
      param_1[0x108] = 0x41;
      if (lVar15 != 0xff) goto LAB_00113a28;
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      *param_1 = 99;
      lVar11 = 2;
      param_1[1] = 99;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
LAB_00113a60:
      lVar15 = lVar11 + 1;
      *(long *)(param_1 + 0x100) = lVar15;
      param_1[lVar11] = 0x75;
      param_1[0x108] = 0x75;
      if (lVar15 != 0xff) goto LAB_00113a7c;
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar12 = 1;
      lVar15 = 0;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    }
    *(long *)(param_1 + 0x100) = lVar12;
    param_1[lVar15] = 0x6d;
    param_1[0x108] = 0x6d;
    break;
  case 0x2e:
  case 0x2f:
    if (param_3[1] != 0) {
      FUN_001122e8(param_1,param_2);
    }
    if (param_3[2] != 0) {
      uVar36 = *(ulong *)(param_1 + 0x100);
      uVar37 = uVar36;
      if (0xfd < uVar36) {
        param_1[uVar36] = 0;
        uVar37 = 0;
        (**(code **)(param_1 + 0x110))(param_1,uVar36,*(undefined8 *)(param_1 + 0x118));
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
      param_1[uVar37] = 0x2c;
      *(ulong *)(param_1 + 0x100) = uVar37 + 2;
      param_1[uVar37 + 1] = 0x20;
      param_1[0x108] = 0x20;
      lVar15 = *(long *)(param_1 + 0x138);
      FUN_001122e8(param_1,param_2,param_3[2]);
      if ((*(long *)(param_1 + 0x138) == lVar15) && (*(long *)(param_1 + 0x100) == uVar37 + 2)) {
        *(ulong *)(param_1 + 0x100) = uVar37;
      }
    }
    break;
  case 0x30:
    lVar15 = param_3[2];
    if (param_3[1] != 0) {
      FUN_001122e8(param_1,param_2);
    }
    lVar12 = *(long *)(param_1 + 0x100);
    if (lVar12 == 0xff) {
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar11 = 1;
      lVar12 = 0;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    }
    else {
      lVar11 = lVar12 + 1;
    }
    *(long *)(param_1 + 0x100) = lVar11;
    param_1[lVar12] = 0x7b;
    param_1[0x108] = 0x7b;
    FUN_001122e8(param_1,param_2,lVar15);
    lVar15 = *(long *)(param_1 + 0x100);
    if (lVar15 == 0xff) {
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar12 = 1;
      lVar15 = 0;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    }
    else {
      lVar12 = lVar15 + 1;
    }
    *(long *)(param_1 + 0x100) = lVar12;
    param_1[lVar15] = 0x7d;
    param_1[0x108] = 0x7d;
    break;
  case 0x31:
    lVar15 = *(long *)(param_1 + 0x100);
    lVar12 = param_3[1];
    iVar7 = *(int *)(lVar12 + 0x10);
    if (lVar15 == 0xff) {
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      *param_1 = 0x6f;
      lVar15 = 2;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 0x70;
LAB_001132d8:
      lVar11 = lVar15 + 1;
      *(long *)(param_1 + 0x100) = lVar11;
      param_1[lVar15] = 0x65;
      param_1[0x108] = 0x65;
      if (lVar11 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x72;
        lVar15 = 2;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        param_1[1] = 0x61;
        goto LAB_0011332c;
      }
LAB_001132f4:
      lVar16 = lVar11 + 1;
      *(long *)(param_1 + 0x100) = lVar16;
      param_1[lVar11] = 0x72;
      param_1[0x108] = 0x72;
      if (lVar16 != 0xff) goto LAB_00113310;
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      *param_1 = 0x61;
      lVar11 = 2;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 0x74;
LAB_00113348:
      lVar15 = lVar11 + 1;
      *(long *)(param_1 + 0x100) = lVar15;
      param_1[lVar11] = 0x6f;
      param_1[0x108] = 0x6f;
      if (lVar15 != 0xff) goto LAB_00113364;
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      *param_1 = 0x72;
      param_1[0x108] = 0x72;
      lVar11 = 1;
      lVar15 = *(long *)(param_1 + 0x138);
      pcVar10 = *(char **)(lVar12 + 8);
LAB_001159b0:
      *(long *)(param_1 + 0x100) = lVar11;
      *(long *)(param_1 + 0x138) = lVar15 + 1;
      if ((byte)(*pcVar10 + 0x9fU) < 0x1a) goto LAB_00114908;
    }
    else {
      lVar11 = lVar15 + 1;
      *(long *)(param_1 + 0x100) = lVar11;
      param_1[lVar15] = 0x6f;
      param_1[0x108] = 0x6f;
      if (lVar11 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x70;
        lVar11 = 2;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        param_1[1] = 0x65;
        goto LAB_001132f4;
      }
      lVar15 = lVar15 + 2;
      *(long *)(param_1 + 0x100) = lVar15;
      param_1[lVar11] = 0x70;
      param_1[0x108] = 0x70;
      if (lVar15 != 0xff) goto LAB_001132d8;
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      *param_1 = 0x65;
      lVar16 = 2;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 0x72;
LAB_00113310:
      lVar15 = lVar16 + 1;
      *(long *)(param_1 + 0x100) = lVar15;
      param_1[lVar16] = 0x61;
      param_1[0x108] = 0x61;
      if (lVar15 != 0xff) {
LAB_0011332c:
        lVar11 = lVar15 + 1;
        *(long *)(param_1 + 0x100) = lVar11;
        param_1[lVar15] = 0x74;
        param_1[0x108] = 0x74;
        if (lVar11 != 0xff) goto LAB_00113348;
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x6f;
        param_1[1] = 0x72;
        param_1[0x108] = 0x72;
        lVar11 = 2;
        lVar15 = *(long *)(param_1 + 0x138);
        pcVar10 = *(char **)(lVar12 + 8);
        goto LAB_001159b0;
      }
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      *param_1 = 0x74;
      lVar15 = 2;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 0x6f;
LAB_00113364:
      lVar11 = lVar15 + 1;
      *(long *)(param_1 + 0x100) = lVar11;
      param_1[lVar15] = 0x72;
      param_1[0x108] = 0x72;
      pcVar10 = *(char **)(lVar12 + 8);
      if ((byte)(*pcVar10 + 0x9fU) < 0x1a) {
        if (lVar11 == 0xff) {
          param_1[0xff] = 0;
          (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
          lVar11 = 0;
          *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        }
LAB_00114908:
        *(long *)(param_1 + 0x100) = lVar11 + 1;
        param_1[lVar11] = 0x20;
        param_1[0x108] = 0x20;
        pcVar10 = *(char **)(lVar12 + 8);
      }
    }
    lVar15 = (long)iVar7;
    if (pcVar10[lVar15 + -1] == ' ') {
      lVar15 = (long)(iVar7 + -1);
    }
    if (lVar15 != 0) {
      pcVar2 = pcVar10 + lVar15;
      lVar15 = *(long *)(param_1 + 0x100);
      do {
        cVar5 = *pcVar10;
        if (lVar15 == 0xff) {
          param_1[0xff] = 0;
          (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
          lVar12 = 1;
          lVar15 = 0;
          *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        }
        else {
          lVar12 = lVar15 + 1;
        }
        *(long *)(param_1 + 0x100) = lVar12;
        pcVar10 = pcVar10 + 1;
        param_1[lVar15] = cVar5;
        param_1[0x108] = cVar5;
        lVar15 = lVar12;
      } while (pcVar10 != pcVar2);
    }
    break;
  case 0x32:
    lVar15 = *(long *)(param_1 + 0x100);
    if (lVar15 == 0xff) {
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      *param_1 = 0x6f;
      lVar15 = 2;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 0x70;
LAB_00114078:
      lVar12 = lVar15 + 1;
      *(long *)(param_1 + 0x100) = lVar12;
      param_1[lVar15] = 0x65;
      param_1[0x108] = 0x65;
      if (lVar12 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x72;
        lVar15 = 2;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        param_1[1] = 0x61;
        goto LAB_001140cc;
      }
LAB_00114094:
      lVar11 = lVar12 + 1;
      *(long *)(param_1 + 0x100) = lVar11;
      param_1[lVar12] = 0x72;
      param_1[0x108] = 0x72;
      if (lVar11 != 0xff) goto LAB_001140b0;
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      *param_1 = 0x61;
      lVar12 = 2;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 0x74;
LAB_001140e8:
      lVar15 = lVar12 + 1;
      *(long *)(param_1 + 0x100) = lVar15;
      param_1[lVar12] = 0x6f;
      param_1[0x108] = 0x6f;
      if (lVar15 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x72;
        lVar12 = 1;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        goto LAB_00114120;
      }
LAB_00114104:
      lVar12 = lVar15 + 1;
      *(long *)(param_1 + 0x100) = lVar12;
      param_1[lVar15] = 0x72;
      param_1[0x108] = 0x72;
      if (lVar12 != 0xff) goto LAB_00114120;
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar15 = 1;
      lVar12 = 0;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    }
    else {
      lVar12 = lVar15 + 1;
      *(long *)(param_1 + 0x100) = lVar12;
      param_1[lVar15] = 0x6f;
      param_1[0x108] = 0x6f;
      if (lVar12 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x70;
        lVar12 = 2;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        param_1[1] = 0x65;
        goto LAB_00114094;
      }
      lVar15 = lVar15 + 2;
      *(long *)(param_1 + 0x100) = lVar15;
      param_1[lVar12] = 0x70;
      param_1[0x108] = 0x70;
      if (lVar15 != 0xff) goto LAB_00114078;
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      *param_1 = 0x65;
      lVar11 = 2;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 0x72;
LAB_001140b0:
      lVar15 = lVar11 + 1;
      *(long *)(param_1 + 0x100) = lVar15;
      param_1[lVar11] = 0x61;
      param_1[0x108] = 0x61;
      if (lVar15 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x74;
        lVar15 = 2;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        param_1[1] = 0x6f;
        goto LAB_00114104;
      }
LAB_001140cc:
      lVar12 = lVar15 + 1;
      *(long *)(param_1 + 0x100) = lVar12;
      param_1[lVar15] = 0x74;
      param_1[0x108] = 0x74;
      if (lVar12 != 0xff) goto LAB_001140e8;
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      *param_1 = 0x6f;
      lVar12 = 2;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 0x72;
LAB_00114120:
      lVar15 = lVar12 + 1;
    }
    *(long *)(param_1 + 0x100) = lVar15;
    param_1[lVar12] = 0x20;
    param_1[0x108] = 0x20;
    FUN_001122e8(param_1,param_2,param_3[2]);
    break;
  case 0x33:
    lVar15 = *(long *)(param_1 + 0x100);
    if (lVar15 == 0xff) {
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      *param_1 = 0x6f;
      lVar15 = 2;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 0x70;
LAB_00113f64:
      lVar12 = lVar15 + 1;
      *(long *)(param_1 + 0x100) = lVar12;
      param_1[lVar15] = 0x65;
      param_1[0x108] = 0x65;
      if (lVar12 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x72;
        lVar15 = 2;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        param_1[1] = 0x61;
        goto LAB_00113fb8;
      }
LAB_00113f80:
      lVar11 = lVar12 + 1;
      *(long *)(param_1 + 0x100) = lVar11;
      param_1[lVar12] = 0x72;
      param_1[0x108] = 0x72;
      if (lVar11 != 0xff) goto LAB_00113f9c;
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      *param_1 = 0x61;
      lVar12 = 2;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 0x74;
LAB_00113fd4:
      lVar15 = lVar12 + 1;
      *(long *)(param_1 + 0x100) = lVar15;
      param_1[lVar12] = 0x6f;
      param_1[0x108] = 0x6f;
      if (lVar15 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x72;
        lVar12 = 1;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        goto LAB_0011400c;
      }
LAB_00113ff0:
      lVar12 = lVar15 + 1;
      *(long *)(param_1 + 0x100) = lVar12;
      param_1[lVar15] = 0x72;
      param_1[0x108] = 0x72;
      if (lVar12 != 0xff) goto LAB_0011400c;
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar15 = 1;
      lVar12 = 0;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    }
    else {
      lVar12 = lVar15 + 1;
      *(long *)(param_1 + 0x100) = lVar12;
      param_1[lVar15] = 0x6f;
      param_1[0x108] = 0x6f;
      if (lVar12 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x70;
        lVar12 = 2;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        param_1[1] = 0x65;
        goto LAB_00113f80;
      }
      lVar15 = lVar15 + 2;
      *(long *)(param_1 + 0x100) = lVar15;
      param_1[lVar12] = 0x70;
      param_1[0x108] = 0x70;
      if (lVar15 != 0xff) goto LAB_00113f64;
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      *param_1 = 0x65;
      lVar11 = 2;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 0x72;
LAB_00113f9c:
      lVar15 = lVar11 + 1;
      *(long *)(param_1 + 0x100) = lVar15;
      param_1[lVar11] = 0x61;
      param_1[0x108] = 0x61;
      if (lVar15 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x74;
        lVar15 = 2;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        param_1[1] = 0x6f;
        goto LAB_00113ff0;
      }
LAB_00113fb8:
      lVar12 = lVar15 + 1;
      *(long *)(param_1 + 0x100) = lVar12;
      param_1[lVar15] = 0x74;
      param_1[0x108] = 0x74;
      if (lVar12 != 0xff) goto LAB_00113fd4;
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      *param_1 = 0x6f;
      lVar12 = 2;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 0x72;
LAB_0011400c:
      lVar15 = lVar12 + 1;
    }
    *(long *)(param_1 + 0x100) = lVar15;
    param_1[lVar12] = 0x20;
    param_1[0x108] = 0x20;
    FUN_00119020(param_1,param_2,param_3 + 1);
    break;
  case 0x34:
    FUN_00119230(param_1,param_2,param_3[1]);
    break;
  case 0x35:
    piVar23 = (int *)param_3[1];
    piVar9 = (int *)param_3[2];
    if (*piVar23 == 0x31) {
      pcVar10 = **(char ***)(piVar23 + 2);
      iVar7 = strcmp(pcVar10,"ad");
      if (iVar7 == 0) {
        iVar7 = *piVar9;
        if (iVar7 != 3) goto LAB_0011497c;
        if ((**(int **)(piVar9 + 2) == 1) && (**(int **)(piVar9 + 4) == 0x29)) {
          piVar9 = *(int **)(piVar9 + 2);
        }
      }
      else {
        iVar7 = *piVar9;
LAB_0011497c:
        if (iVar7 == 0x37) {
          FUN_00119304(param_1,param_2,*(undefined8 *)(piVar9 + 2));
          FUN_00119230(param_1,param_2,piVar23);
          return;
        }
      }
      FUN_00119230(param_1,param_2,piVar23);
      iVar7 = strcmp(pcVar10,"gs");
      if (iVar7 == 0) {
        FUN_001122e8(param_1,param_2,piVar9);
        return;
      }
      iVar7 = strcmp(pcVar10,"st");
      if (iVar7 == 0) {
        lVar15 = *(long *)(param_1 + 0x100);
        if (lVar15 == 0xff) {
          param_1[0xff] = 0;
          (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
          lVar15 = 0;
          *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        }
        *(long *)(param_1 + 0x100) = lVar15 + 1;
        param_1[lVar15] = 0x28;
        param_1[0x108] = 0x28;
        FUN_001122e8(param_1,param_2,piVar9);
        FUN_0010a494(param_1,0x29);
        return;
      }
    }
    else if (*piVar23 == 0x33) {
      lVar15 = *(long *)(param_1 + 0x100);
      if (lVar15 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar15 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
      *(long *)(param_1 + 0x100) = lVar15 + 1;
      param_1[lVar15] = 0x28;
      param_1[0x108] = 0x28;
      FUN_00119020(param_1,param_2,piVar23 + 2);
      lVar15 = *(long *)(param_1 + 0x100);
      if (lVar15 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar15 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
      *(long *)(param_1 + 0x100) = lVar15 + 1;
      param_1[lVar15] = 0x29;
      param_1[0x108] = 0x29;
    }
    else {
      FUN_00119230(param_1,param_2,piVar23);
    }
    FUN_00119304(param_1,param_2,piVar9);
    break;
  case 0x36:
    piVar9 = (int *)param_3[2];
    if (*piVar9 != 0x37) goto LAB_00112364;
    ppcVar24 = *(char ***)((int *)param_3[1] + 2);
    pcVar10 = *ppcVar24;
    if ((pcVar10[1] == 'c') && (((byte)(*pcVar10 + 0x8eU) < 2 || ((byte)(*pcVar10 + 0x9dU) < 2)))) {
      FUN_00119230(param_1,param_2);
      FUN_0010a494(param_1,0x3c);
      FUN_001122e8(param_1,param_2,*(undefined8 *)(param_3[2] + 8));
      FUN_0010aabc(param_1,&DAT_0011f700);
      FUN_001122e8(param_1,param_2,*(undefined8 *)(param_3[2] + 0x10));
      FUN_0010a494(param_1,0x29);
    }
    else {
      if ((*(int *)param_3[1] == 0x31) && ((*(int *)(ppcVar24 + 2) == 1 && (*ppcVar24[1] == '>'))))
      {
        FUN_0010a494(param_1,0x28);
        piVar9 = (int *)param_3[2];
        pcVar10 = **(char ***)(param_3[1] + 8);
      }
      iVar7 = strcmp(pcVar10,"cl");
      piVar9 = *(int **)(piVar9 + 2);
      if ((iVar7 == 0) && (*piVar9 == 3)) {
        if (**(int **)(piVar9 + 4) != 0x29) {
          *(undefined4 *)(param_1 + 0x130) = 1;
        }
        FUN_00119304(param_1,param_2,*(undefined8 *)(piVar9 + 2));
      }
      else {
        FUN_00119304(param_1,param_2);
      }
      lVar15 = param_3[1];
      pcVar10 = **(char ***)(lVar15 + 8);
      iVar7 = strcmp(pcVar10,"ix");
      if (iVar7 == 0) {
        FUN_0010a494(param_1,0x5b);
        FUN_001122e8(param_1,param_2,*(undefined8 *)(param_3[2] + 0x10));
        FUN_0010a494(param_1,0x5d);
      }
      else {
        iVar7 = strcmp(pcVar10,"cl");
        if (iVar7 != 0) {
          FUN_00119230(param_1,param_2,lVar15);
        }
        FUN_00119304(param_1,param_2,*(undefined8 *)(param_3[2] + 0x10));
      }
      if (((*(int *)param_3[1] == 0x31) &&
          (lVar15 = *(long *)((int *)param_3[1] + 2), *(int *)(lVar15 + 0x10) == 1)) &&
         (**(char **)(lVar15 + 8) == '>')) {
        FUN_0010a494(param_1,0x29);
      }
    }
    break;
  case 0x37:
    *(undefined4 *)(param_1 + 0x130) = 1;
    break;
  case 0x38:
    piVar9 = (int *)param_3[2];
    if ((*piVar9 != 0x39) || (piVar23 = *(int **)(piVar9 + 4), *piVar23 != 0x3a)) goto LAB_00112364;
    lVar11 = param_3[1];
    lVar12 = *(long *)(piVar9 + 2);
    uVar38 = *(undefined8 *)(piVar23 + 2);
    lVar15 = *(long *)(piVar23 + 4);
    iVar7 = strcmp(**(char ***)(lVar11 + 8),"qu");
    if (iVar7 == 0) {
      FUN_00119304(param_1,param_2,lVar12);
      FUN_00119230(param_1,param_2,lVar11);
      FUN_00119304(param_1,param_2,uVar38);
      FUN_0010aabc(param_1,&DAT_0011f638);
      FUN_00119304(param_1,param_2,lVar15);
    }
    else {
      FUN_0010aabc(param_1,&DAT_0011f640);
      if (*(long *)(lVar12 + 8) != 0) {
        FUN_00119304(param_1,param_2,lVar12);
        FUN_0010a494(param_1,0x20);
      }
      FUN_001122e8(param_1,param_2,uVar38);
      if (lVar15 != 0) {
        FUN_00119304(param_1,param_2,lVar15);
      }
    }
    break;
  case 0x39:
  case 0x3a:
    *(undefined4 *)(param_1 + 0x130) = 1;
    break;
  case 0x3b:
  case 0x3c:
    uVar35 = 0;
    if ((*(int *)param_3[1] == 0x27) &&
       (uVar35 = *(uint *)(*(long *)((int *)param_3[1] + 2) + 0x1c), uVar35 != 0)) {
      if (uVar35 < 7) {
        if (*(int *)param_3[2] == 0) {
          if (iVar7 == 0x3c) {
            FUN_0010a494(param_1,0x2d);
          }
          FUN_001122e8(param_1,param_2,param_3[2]);
          switch(uVar35) {
          case 2:
            FUN_0010a494(param_1,0x75);
            return;
          case 3:
            FUN_0010a494(param_1,0x6c);
            return;
          case 4:
            FUN_0010aabc(param_1,&DAT_0011f648);
            return;
          case 5:
            FUN_0010aabc(param_1,&DAT_0011f650);
            return;
          case 6:
            FUN_0010aabc(param_1,&DAT_0011f658);
            return;
          default:
            return;
          }
        }
      }
      else if ((((uVar35 == 7) && (piVar9 = (int *)param_3[2], *piVar9 == 0)) && (piVar9[4] == 1))
              && (iVar7 == 0x3b)) {
        if (**(char **)(piVar9 + 2) == '0') {
          FUN_0010aabc(param_1,"false");
          return;
        }
        if (**(char **)(piVar9 + 2) == '1') {
          FUN_0010aabc(param_1,&DAT_0011f668);
          return;
        }
      }
    }
    lVar15 = *(long *)(param_1 + 0x100);
    if (lVar15 == 0xff) {
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar12 = 1;
      lVar15 = 0;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    }
    else {
      lVar12 = lVar15 + 1;
    }
    *(long *)(param_1 + 0x100) = lVar12;
    param_1[lVar15] = 0x28;
    param_1[0x108] = 0x28;
    FUN_001122e8(param_1,param_2,param_3[1]);
    lVar15 = *(long *)(param_1 + 0x100);
    if (lVar15 == 0xff) {
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar12 = 1;
      lVar15 = 0;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    }
    else {
      lVar12 = lVar15 + 1;
    }
    *(long *)(param_1 + 0x100) = lVar12;
    param_1[lVar15] = 0x29;
    param_1[0x108] = 0x29;
    if (*(int *)param_3 == 0x3c) {
      FUN_0010a494(param_1,0x2d);
    }
    if (uVar35 == 8) {
      FUN_0010a494(param_1,0x5b);
      FUN_001122e8(param_1,param_2,param_3[2]);
      FUN_0010a494(param_1,0x5d);
    }
    else {
      FUN_001122e8(param_1,param_2,param_3[2]);
    }
    break;
  case 0x3d:
    lVar15 = *(long *)(param_1 + 0x100);
    if (lVar15 == 0xff) {
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar15 = 2;
      *param_1 = 0x6a;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 0x61;
LAB_00112f08:
      lVar12 = lVar15 + 1;
      *(long *)(param_1 + 0x100) = lVar12;
      param_1[lVar15] = 0x76;
      param_1[0x108] = 0x76;
      if (lVar12 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x61;
        lVar15 = 2;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        param_1[1] = 0x20;
        goto LAB_00112f5c;
      }
LAB_00112f24:
      lVar11 = lVar12 + 1;
      *(long *)(param_1 + 0x100) = lVar11;
      param_1[lVar12] = 0x61;
      param_1[0x108] = 0x61;
      if (lVar11 != 0xff) goto LAB_00112f40;
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      *param_1 = 0x20;
      lVar12 = 2;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 0x72;
LAB_00112f78:
      lVar15 = lVar12 + 1;
      *(long *)(param_1 + 0x100) = lVar15;
      param_1[lVar12] = 0x65;
      param_1[0x108] = 0x65;
      if (lVar15 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x73;
        lVar15 = 2;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        param_1[1] = 0x6f;
        goto LAB_00112fcc;
      }
LAB_00112f94:
      lVar12 = lVar15 + 1;
      *(long *)(param_1 + 0x100) = lVar12;
      param_1[lVar15] = 0x73;
      param_1[0x108] = 0x73;
      if (lVar12 != 0xff) goto LAB_00112fb0;
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      *param_1 = 0x6f;
      lVar12 = 2;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 0x75;
LAB_00112fe8:
      lVar15 = lVar12 + 1;
      *(long *)(param_1 + 0x100) = lVar15;
      param_1[lVar12] = 0x72;
      param_1[0x108] = 0x72;
      if (lVar15 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 99;
        lVar15 = 2;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        param_1[1] = 0x65;
      }
      else {
LAB_00113004:
        lVar12 = lVar15 + 1;
        *(long *)(param_1 + 0x100) = lVar12;
        param_1[lVar15] = 99;
        param_1[0x108] = 99;
        if (lVar12 != 0xff) goto LAB_00113020;
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x65;
        lVar15 = 1;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
LAB_0011303c:
      lVar12 = lVar15 + 1;
    }
    else {
      lVar12 = lVar15 + 1;
      *(long *)(param_1 + 0x100) = lVar12;
      param_1[lVar15] = 0x6a;
      param_1[0x108] = 0x6a;
      if (lVar12 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x61;
        lVar12 = 2;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        param_1[1] = 0x76;
        goto LAB_00112f24;
      }
      lVar15 = lVar15 + 2;
      *(long *)(param_1 + 0x100) = lVar15;
      param_1[lVar12] = 0x61;
      param_1[0x108] = 0x61;
      if (lVar15 != 0xff) goto LAB_00112f08;
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      *param_1 = 0x76;
      lVar11 = 2;
      param_1[1] = 0x61;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
LAB_00112f40:
      lVar15 = lVar11 + 1;
      *(long *)(param_1 + 0x100) = lVar15;
      param_1[lVar11] = 0x20;
      param_1[0x108] = 0x20;
      if (lVar15 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x72;
        lVar15 = 2;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        param_1[1] = 0x65;
        goto LAB_00112f94;
      }
LAB_00112f5c:
      lVar12 = lVar15 + 1;
      *(long *)(param_1 + 0x100) = lVar12;
      param_1[lVar15] = 0x72;
      param_1[0x108] = 0x72;
      if (lVar12 != 0xff) goto LAB_00112f78;
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      *param_1 = 0x65;
      lVar12 = 2;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 0x73;
LAB_00112fb0:
      lVar15 = lVar12 + 1;
      *(long *)(param_1 + 0x100) = lVar15;
      param_1[lVar12] = 0x6f;
      param_1[0x108] = 0x6f;
      if (lVar15 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x75;
        lVar15 = 2;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        param_1[1] = 0x72;
        goto LAB_00113004;
      }
LAB_00112fcc:
      lVar12 = lVar15 + 1;
      *(long *)(param_1 + 0x100) = lVar12;
      param_1[lVar15] = 0x75;
      param_1[0x108] = 0x75;
      if (lVar12 != 0xff) goto LAB_00112fe8;
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      *param_1 = 0x72;
      lVar12 = 2;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 99;
LAB_00113020:
      lVar15 = lVar12 + 1;
      *(long *)(param_1 + 0x100) = lVar15;
      param_1[lVar12] = 0x65;
      param_1[0x108] = 0x65;
      if (lVar15 != 0xff) goto LAB_0011303c;
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar12 = 1;
      lVar15 = 0;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    }
    *(long *)(param_1 + 0x100) = lVar12;
    param_1[lVar15] = 0x20;
    param_1[0x108] = 0x20;
    FUN_001122e8(param_1,param_2,param_3[1]);
    break;
  case 0x3e:
    FUN_001122e8(param_1,param_2,param_3[1]);
    FUN_001122e8(param_1,param_2,param_3[2]);
    break;
  case 0x3f:
    lVar15 = *(long *)(param_1 + 0x100);
    uVar4 = *(undefined *)(param_3 + 1);
    if (lVar15 == 0xff) {
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar12 = 1;
      lVar15 = 0;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    }
    else {
      lVar12 = lVar15 + 1;
    }
    *(long *)(param_1 + 0x100) = lVar12;
    param_1[lVar15] = uVar4;
    param_1[0x108] = uVar4;
    break;
  case 0x40:
    sprintf((char *)&local_80,"%ld",param_3[1]);
    sVar8 = strlen((char *)&local_80);
    if (sVar8 != 0) {
      sVar32 = 0;
      lVar15 = *(long *)(param_1 + 0x100);
      do {
        cVar5 = *(char *)((long)&local_80 + sVar32);
        if (lVar15 == 0xff) {
          param_1[0xff] = 0;
          (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
          lVar12 = 1;
          lVar15 = 0;
          *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        }
        else {
          lVar12 = lVar15 + 1;
        }
        *(long *)(param_1 + 0x100) = lVar12;
        sVar32 = sVar32 + 1;
        param_1[lVar15] = cVar5;
        param_1[0x108] = cVar5;
        lVar15 = lVar12;
      } while (sVar32 != sVar8);
    }
    break;
  case 0x41:
    lVar15 = *(long *)(param_1 + 0x100);
    if (lVar15 == 0xff) {
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar15 = 2;
      *param_1 = 100;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 0x65;
LAB_00113bc8:
      lVar12 = lVar15 + 1;
      *(long *)(param_1 + 0x100) = lVar12;
      param_1[lVar15] = 99;
      param_1[0x108] = 99;
      if (lVar12 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x6c;
        lVar15 = 2;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        param_1[1] = 0x74;
        goto LAB_00113c1c;
      }
LAB_00113be4:
      lVar11 = lVar12 + 1;
      *(long *)(param_1 + 0x100) = lVar11;
      param_1[lVar12] = 0x6c;
      param_1[0x108] = 0x6c;
      if (lVar11 != 0xff) goto LAB_00113c00;
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      *param_1 = 0x74;
      lVar12 = 2;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 0x79;
LAB_00113c38:
      lVar15 = lVar12 + 1;
      *(long *)(param_1 + 0x100) = lVar15;
      param_1[lVar12] = 0x70;
      param_1[0x108] = 0x70;
      if (lVar15 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x65;
        lVar15 = 2;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        param_1[1] = 0x20;
      }
      else {
LAB_00113c54:
        lVar12 = lVar15 + 1;
        *(long *)(param_1 + 0x100) = lVar12;
        param_1[lVar15] = 0x65;
        param_1[0x108] = 0x65;
        if (lVar12 != 0xff) goto LAB_00113c70;
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x20;
        lVar15 = 1;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
LAB_00113c8c:
      lVar12 = lVar15 + 1;
    }
    else {
      lVar12 = lVar15 + 1;
      *(long *)(param_1 + 0x100) = lVar12;
      param_1[lVar15] = 100;
      param_1[0x108] = 100;
      if (lVar12 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x65;
        lVar12 = 2;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        param_1[1] = 99;
        goto LAB_00113be4;
      }
      lVar15 = lVar15 + 2;
      *(long *)(param_1 + 0x100) = lVar15;
      param_1[lVar12] = 0x65;
      param_1[0x108] = 0x65;
      if (lVar15 != 0xff) goto LAB_00113bc8;
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      *param_1 = 99;
      lVar11 = 2;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 0x6c;
LAB_00113c00:
      lVar15 = lVar11 + 1;
      *(long *)(param_1 + 0x100) = lVar15;
      param_1[lVar11] = 0x74;
      param_1[0x108] = 0x74;
      if (lVar15 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x79;
        lVar15 = 2;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        param_1[1] = 0x70;
        goto LAB_00113c54;
      }
LAB_00113c1c:
      lVar12 = lVar15 + 1;
      *(long *)(param_1 + 0x100) = lVar12;
      param_1[lVar15] = 0x79;
      param_1[0x108] = 0x79;
      if (lVar12 != 0xff) goto LAB_00113c38;
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      *param_1 = 0x70;
      lVar12 = 2;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 0x65;
LAB_00113c70:
      lVar15 = lVar12 + 1;
      *(long *)(param_1 + 0x100) = lVar15;
      param_1[lVar12] = 0x20;
      param_1[0x108] = 0x20;
      if (lVar15 != 0xff) goto LAB_00113c8c;
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar12 = 1;
      lVar15 = 0;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    }
    *(long *)(param_1 + 0x100) = lVar12;
    param_1[lVar15] = 0x28;
    param_1[0x108] = 0x28;
    FUN_001122e8(param_1,param_2,param_3[1]);
    lVar15 = *(long *)(param_1 + 0x100);
    if (lVar15 == 0xff) {
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar12 = 1;
      lVar15 = 0;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    }
    else {
      lVar12 = lVar15 + 1;
    }
    *(long *)(param_1 + 0x100) = lVar12;
    param_1[lVar15] = 0x29;
    param_1[0x108] = 0x29;
    break;
  case 0x42:
    FUN_0010aabc(param_1,"global constructors keyed to ");
    FUN_001122e8(param_1,param_2,param_3[1]);
    break;
  case 0x43:
    FUN_0010aabc(param_1,"global destructors keyed to ");
    FUN_001122e8(param_1,param_2,param_3[1]);
    break;
  case 0x44:
    FUN_0010aabc(param_1,"{lambda(");
    FUN_001122e8(param_1,param_2,param_3[1]);
    FUN_0010aabc(param_1,&DAT_0011f6d8);
    FUN_0010ab68(param_1,(long)(*(int *)(param_3 + 2) + 1));
    FUN_0010a494(param_1,0x7d);
    break;
  default:
    *(undefined4 *)(param_1 + 0x130) = 1;
    break;
  case 0x46:
    FUN_0010aabc(param_1,"{unnamed type#");
    FUN_0010ab68(param_1,param_3[1] + 1);
    FUN_0010a494(param_1,0x7d);
    break;
  case 0x47:
    lVar15 = 0;
    lVar12 = *(long *)(param_1 + 0x100);
    do {
      cVar5 = "transaction clone for "[lVar15];
      if (lVar12 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar11 = 1;
        lVar12 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
      else {
        lVar11 = lVar12 + 1;
      }
      *(long *)(param_1 + 0x100) = lVar11;
      lVar15 = lVar15 + 1;
      param_1[lVar12] = cVar5;
      param_1[0x108] = cVar5;
      lVar12 = lVar11;
    } while (lVar15 != 0x16);
    FUN_001122e8(param_1,param_2,param_3[1]);
    break;
  case 0x48:
    lVar15 = 0;
    lVar12 = *(long *)(param_1 + 0x100);
    do {
      cVar5 = "non-transaction clone for "[lVar15];
      if (lVar12 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar11 = 1;
        lVar12 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
      else {
        lVar11 = lVar12 + 1;
      }
      *(long *)(param_1 + 0x100) = lVar11;
      lVar15 = lVar15 + 1;
      param_1[lVar12] = cVar5;
      param_1[0x108] = cVar5;
      lVar12 = lVar11;
    } while (lVar15 != 0x1a);
    FUN_001122e8(param_1,param_2,param_3[1]);
    break;
  case 0x49:
    iVar7 = 0;
    piVar9 = (int *)FUN_0010a924(param_1,param_3[1]);
    if (piVar9 == (int *)0x0) {
      FUN_00119304(param_1,param_2,param_3[1]);
      FUN_0010aabc(param_1,&DAT_0011f670);
    }
    else {
      do {
        if ((*piVar9 != 0x2f) || (*(long *)(piVar9 + 2) == 0)) {
          lVar15 = param_3[1];
          if (iVar7 == 0) {
            return;
          }
          goto LAB_00113eac;
        }
        piVar9 = *(int **)(piVar9 + 4);
        iVar7 = iVar7 + 1;
      } while (piVar9 != (int *)0x0);
      lVar15 = param_3[1];
LAB_00113eac:
      iVar31 = 0;
      do {
        *(int *)(param_1 + 0x134) = iVar31;
        FUN_001122e8(param_1,param_2,lVar15);
        if (iVar31 < iVar7 + -1) {
          lVar12 = *(long *)(param_1 + 0x100);
          if (lVar12 == 0xff) {
            param_1[0xff] = 0;
            (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
            *param_1 = 0x2c;
            lVar11 = 1;
            *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
LAB_00113efc:
            lVar12 = lVar11 + 1;
          }
          else {
            lVar11 = lVar12 + 1;
            *(long *)(param_1 + 0x100) = lVar11;
            param_1[lVar12] = 0x2c;
            param_1[0x108] = 0x2c;
            if (lVar11 != 0xff) goto LAB_00113efc;
            param_1[0xff] = 0;
            (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
            lVar12 = 1;
            lVar11 = 0;
            *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
          }
          *(long *)(param_1 + 0x100) = lVar12;
          param_1[lVar11] = 0x20;
          param_1[0x108] = 0x20;
        }
        iVar31 = iVar31 + 1;
      } while (iVar31 != iVar7);
    }
    break;
  case 0x4a:
    FUN_001122e8(param_1,param_2,param_3[1]);
    lVar15 = *(long *)(param_1 + 0x100);
    if (lVar15 == 0xff) {
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      *param_1 = 0x5b;
      lVar15 = 2;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 0x61;
LAB_00113db8:
      lVar12 = lVar15 + 1;
      *(long *)(param_1 + 0x100) = lVar12;
      param_1[lVar15] = 0x62;
      param_1[0x108] = 0x62;
      if (lVar12 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x69;
        lVar15 = 1;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        goto LAB_00113df0;
      }
LAB_00113dd4:
      lVar15 = lVar12 + 1;
      *(long *)(param_1 + 0x100) = lVar15;
      param_1[lVar12] = 0x69;
      param_1[0x108] = 0x69;
      if (lVar15 != 0xff) goto LAB_00113df0;
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar12 = 1;
      lVar15 = 0;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    }
    else {
      lVar12 = lVar15 + 1;
      *(long *)(param_1 + 0x100) = lVar12;
      param_1[lVar15] = 0x5b;
      param_1[0x108] = 0x5b;
      if (lVar12 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x61;
        lVar12 = 2;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        param_1[1] = 0x62;
        goto LAB_00113dd4;
      }
      lVar15 = lVar15 + 2;
      *(long *)(param_1 + 0x100) = lVar15;
      param_1[lVar12] = 0x61;
      param_1[0x108] = 0x61;
      if (lVar15 != 0xff) goto LAB_00113db8;
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      *param_1 = 0x62;
      lVar15 = 2;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 0x69;
LAB_00113df0:
      lVar12 = lVar15 + 1;
    }
    *(long *)(param_1 + 0x100) = lVar12;
    param_1[lVar15] = 0x3a;
    param_1[0x108] = 0x3a;
    FUN_001122e8(param_1,param_2,param_3[2]);
    lVar15 = *(long *)(param_1 + 0x100);
    if (lVar15 == 0xff) {
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar12 = 1;
      lVar15 = 0;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    }
    else {
      lVar12 = lVar15 + 1;
    }
    *(long *)(param_1 + 0x100) = lVar12;
    param_1[lVar15] = 0x5d;
    param_1[0x108] = 0x5d;
    break;
  case 0x4b:
    FUN_001122e8(param_1,param_2,param_3[1]);
    FUN_0010aabc(param_1," [clone ");
    FUN_001122e8(param_1,param_2,param_3[2]);
    FUN_0010a494(param_1,0x5d);
  }
  return;
}



void FUN_00116e70(undefined *param_1,uint param_2,undefined4 *param_3)

{
  long lVar1;
  long lVar2;
  undefined8 uVar3;
  code *pcVar4;
  long lVar5;
  undefined uVar6;
  undefined uVar7;
  
  switch(*param_3) {
  case 3:
    param_3 = *(undefined4 **)(param_3 + 2);
  default:
LAB_00116eac:
    FUN_001122e8(param_1,param_2,param_3);
    return;
  case 0x19:
  case 0x1c:
    lVar2 = *(long *)(param_1 + 0x100);
    if (lVar2 == 0xff) {
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar2 = 2;
      *param_1 = 0x20;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 0x72;
LAB_00117080:
      lVar1 = lVar2 + 1;
      *(long *)(param_1 + 0x100) = lVar1;
      param_1[lVar2] = 0x65;
      param_1[0x108] = 0x65;
      if (lVar1 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x73;
        lVar2 = 2;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        param_1[1] = 0x74;
        goto LAB_001170d4;
      }
LAB_0011709c:
      lVar5 = lVar1 + 1;
      *(long *)(param_1 + 0x100) = lVar5;
      param_1[lVar1] = 0x73;
      param_1[0x108] = 0x73;
      if (lVar5 != 0xff) goto LAB_001170b8;
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      *param_1 = 0x74;
      lVar1 = 2;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 0x72;
LAB_001170f0:
      lVar5 = lVar1 + 1;
      *(long *)(param_1 + 0x100) = lVar5;
      param_1[lVar1] = 0x69;
      param_1[0x108] = 0x69;
      uVar7 = 99;
joined_r0x001172b4:
      if (lVar5 == 0xff) {
        pcVar4 = *(code **)(param_1 + 0x110);
        uVar3 = *(undefined8 *)(param_1 + 0x118);
        uVar6 = 0x74;
        param_1[0xff] = 0;
        goto LAB_001174d8;
      }
      goto LAB_001172b8;
    }
    lVar1 = lVar2 + 1;
    *(long *)(param_1 + 0x100) = lVar1;
    param_1[lVar2] = 0x20;
    param_1[0x108] = 0x20;
    if (lVar1 == 0xff) {
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      *param_1 = 0x72;
      lVar1 = 2;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 0x65;
      goto LAB_0011709c;
    }
    lVar2 = lVar2 + 2;
    *(long *)(param_1 + 0x100) = lVar2;
    param_1[lVar1] = 0x72;
    param_1[0x108] = 0x72;
    if (lVar2 != 0xff) goto LAB_00117080;
    param_1[0xff] = 0;
    (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
    *param_1 = 0x65;
    lVar5 = 2;
    *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    param_1[1] = 0x73;
LAB_001170b8:
    lVar2 = lVar5 + 1;
    *(long *)(param_1 + 0x100) = lVar2;
    param_1[lVar5] = 0x74;
    param_1[0x108] = 0x74;
    if (lVar2 == 0xff) {
      uVar7 = 99;
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      *param_1 = 0x72;
      lVar5 = 2;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 0x69;
      goto LAB_001172b8;
    }
LAB_001170d4:
    lVar1 = lVar2 + 1;
    *(long *)(param_1 + 0x100) = lVar1;
    param_1[lVar2] = 0x72;
    param_1[0x108] = 0x72;
    if (lVar1 != 0xff) goto LAB_001170f0;
    param_1[0xff] = 0;
    uVar6 = 0x74;
    (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
    *param_1 = 0x69;
    lVar2 = 2;
    *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    param_1[1] = 99;
    break;
  case 0x1a:
  case 0x1d:
    lVar2 = *(long *)(param_1 + 0x100);
    if (lVar2 == 0xff) {
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar2 = 2;
      *param_1 = 0x20;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 0x76;
LAB_0011716c:
      lVar1 = lVar2 + 1;
      *(long *)(param_1 + 0x100) = lVar1;
      param_1[lVar2] = 0x6f;
      param_1[0x108] = 0x6f;
      if (lVar1 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x6c;
        lVar2 = 2;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        param_1[1] = 0x61;
        goto LAB_001171c0;
      }
LAB_00117188:
      lVar5 = lVar1 + 1;
      *(long *)(param_1 + 0x100) = lVar5;
      param_1[lVar1] = 0x6c;
      param_1[0x108] = 0x6c;
      if (lVar5 != 0xff) goto LAB_001171a4;
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      *param_1 = 0x61;
      lVar1 = 2;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 0x74;
LAB_001171dc:
      lVar5 = lVar1 + 1;
      *(long *)(param_1 + 0x100) = lVar5;
      param_1[lVar1] = 0x69;
      param_1[0x108] = 0x69;
      uVar7 = 0x6c;
      if (lVar5 != 0xff) goto LAB_001171f8;
      pcVar4 = *(code **)(param_1 + 0x110);
      uVar3 = *(undefined8 *)(param_1 + 0x118);
      uVar6 = 0x65;
      param_1[0xff] = 0;
LAB_001174d8:
      (*pcVar4)(param_1,0xff,uVar3);
      *param_1 = uVar7;
      lVar2 = 1;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      break;
    }
    lVar1 = lVar2 + 1;
    *(long *)(param_1 + 0x100) = lVar1;
    param_1[lVar2] = 0x20;
    param_1[0x108] = 0x20;
    if (lVar1 == 0xff) {
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      *param_1 = 0x76;
      lVar1 = 2;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 0x6f;
      goto LAB_00117188;
    }
    lVar2 = lVar2 + 2;
    *(long *)(param_1 + 0x100) = lVar2;
    param_1[lVar1] = 0x76;
    param_1[0x108] = 0x76;
    if (lVar2 != 0xff) goto LAB_0011716c;
    param_1[0xff] = 0;
    (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
    *param_1 = 0x6f;
    lVar5 = 2;
    *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    param_1[1] = 0x6c;
LAB_001171a4:
    lVar2 = lVar5 + 1;
    *(long *)(param_1 + 0x100) = lVar2;
    param_1[lVar5] = 0x61;
    param_1[0x108] = 0x61;
    if (lVar2 != 0xff) {
LAB_001171c0:
      lVar1 = lVar2 + 1;
      *(long *)(param_1 + 0x100) = lVar1;
      param_1[lVar2] = 0x74;
      param_1[0x108] = 0x74;
      if (lVar1 == 0xff) {
        param_1[0xff] = 0;
        uVar6 = 0x65;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x69;
        lVar2 = 2;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        param_1[1] = 0x6c;
        break;
      }
      goto LAB_001171dc;
    }
    param_1[0xff] = 0;
    (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
    *param_1 = 0x74;
    lVar5 = 2;
    *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    param_1[1] = 0x69;
LAB_001171f8:
    lVar2 = lVar5 + 1;
    *(long *)(param_1 + 0x100) = lVar2;
    param_1[lVar5] = 0x6c;
    param_1[0x108] = 0x6c;
    uVar6 = 0x65;
    if (lVar2 != 0xff) break;
    goto LAB_001172d4;
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
LAB_00117280:
      lVar1 = lVar2 + 1;
      *(long *)(param_1 + 0x100) = lVar1;
      param_1[lVar2] = 0x6f;
      param_1[0x108] = 0x6f;
      if (lVar1 == 0xff) {
        param_1[0xff] = 0;
        uVar6 = 0x74;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x6e;
        lVar2 = 2;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        param_1[1] = 0x73;
        break;
      }
LAB_0011729c:
      lVar5 = lVar1 + 1;
      *(long *)(param_1 + 0x100) = lVar5;
      param_1[lVar1] = 0x6e;
      param_1[0x108] = 0x6e;
      uVar7 = 0x73;
      goto joined_r0x001172b4;
    }
    lVar1 = lVar2 + 1;
    *(long *)(param_1 + 0x100) = lVar1;
    param_1[lVar2] = 0x20;
    param_1[0x108] = 0x20;
    if (lVar1 == 0xff) {
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      *param_1 = 99;
      lVar1 = 2;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 0x6f;
      goto LAB_0011729c;
    }
    lVar2 = lVar2 + 2;
    *(long *)(param_1 + 0x100) = lVar2;
    param_1[lVar1] = 99;
    param_1[0x108] = 99;
    if (lVar2 != 0xff) goto LAB_00117280;
    uVar7 = 0x73;
    param_1[0xff] = 0;
    (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
    *param_1 = 0x6f;
    lVar5 = 2;
    *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    param_1[1] = 0x6e;
LAB_001172b8:
    lVar2 = lVar5 + 1;
    *(long *)(param_1 + 0x100) = lVar2;
    param_1[lVar5] = uVar7;
    param_1[0x108] = uVar7;
    uVar6 = 0x74;
    if (lVar2 == 0xff) goto LAB_001172d4;
    break;
  case 0x1f:
    lVar1 = *(long *)(param_1 + 0x100);
    if (lVar1 == 0xff) {
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar2 = 1;
      lVar1 = 0;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    }
    else {
      lVar2 = lVar1 + 1;
    }
    *(long *)(param_1 + 0x100) = lVar2;
    param_1[lVar1] = 0x20;
    param_1[0x108] = 0x20;
    goto LAB_00117324;
  case 0x20:
    lVar2 = *(long *)(param_1 + 0x100);
    if (lVar2 == 0xff) {
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar1 = 1;
      lVar2 = 0;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    }
    else {
      lVar1 = lVar2 + 1;
    }
    *(long *)(param_1 + 0x100) = lVar1;
    param_1[lVar2] = 0x20;
    param_1[0x108] = 0x20;
    goto LAB_00117374;
  case 0x21:
    lVar2 = *(long *)(param_1 + 0x100);
    if (lVar2 == 0xff) {
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar1 = 1;
      lVar2 = 0;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    }
    else {
      lVar1 = lVar2 + 1;
    }
    *(long *)(param_1 + 0x100) = lVar1;
    param_1[lVar2] = 0x20;
    param_1[0x108] = 0x20;
    param_3 = *(undefined4 **)(param_3 + 4);
    goto LAB_00116eac;
  case 0x22:
    if ((param_2 >> 2 & 1) == 0) {
      lVar2 = *(long *)(param_1 + 0x100);
      if (lVar2 == 0xff) {
        param_1[0xff] = (byte)param_2 & 4;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar1 = 1;
        lVar2 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
      else {
        lVar1 = lVar2 + 1;
      }
      *(long *)(param_1 + 0x100) = lVar1;
      param_1[lVar2] = 0x2a;
      param_1[0x108] = 0x2a;
      return;
    }
    return;
  case 0x23:
    lVar2 = *(long *)(param_1 + 0x100);
LAB_00117324:
    if (lVar2 == 0xff) {
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar1 = 1;
      lVar2 = 0;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    }
    else {
      lVar1 = lVar2 + 1;
    }
    *(long *)(param_1 + 0x100) = lVar1;
    param_1[lVar2] = 0x26;
    param_1[0x108] = 0x26;
    return;
  case 0x24:
    lVar1 = *(long *)(param_1 + 0x100);
LAB_00117374:
    if (lVar1 == 0xff) {
      uVar6 = 0x26;
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar2 = 1;
      *param_1 = 0x26;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    }
    else {
      lVar2 = lVar1 + 1;
      *(long *)(param_1 + 0x100) = lVar2;
      param_1[lVar1] = 0x26;
      param_1[0x108] = 0x26;
      uVar6 = 0x26;
      if (lVar2 == 0xff) {
        lVar2 = 0xff;
LAB_001172d4:
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,lVar2,*(undefined8 *)(param_1 + 0x118));
        lVar1 = 1;
        lVar2 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        goto LAB_00117218;
      }
    }
    break;
  case 0x25:
    lVar2 = *(long *)(param_1 + 0x100);
    if (lVar2 == 0xff) {
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      *param_1 = 99;
      lVar2 = 2;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 0x6f;
LAB_00117454:
      lVar1 = lVar2 + 1;
      *(long *)(param_1 + 0x100) = lVar1;
      param_1[lVar2] = 0x6d;
      param_1[0x108] = 0x6d;
      if (lVar1 != 0xff) {
LAB_00117470:
        lVar2 = lVar1 + 1;
        *(long *)(param_1 + 0x100) = lVar2;
        param_1[lVar1] = 0x70;
        param_1[0x108] = 0x70;
        if (lVar2 == 0xff) {
          uVar7 = 0x78;
          param_1[0xff] = 0;
          (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
          *param_1 = 0x6c;
          lVar1 = 2;
          *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
          param_1[1] = 0x65;
          goto LAB_001175e4;
        }
        goto LAB_0011748c;
      }
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      *param_1 = 0x70;
      lVar5 = 2;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 0x6c;
    }
    else {
      lVar1 = lVar2 + 1;
      *(long *)(param_1 + 0x100) = lVar1;
      param_1[lVar2] = 99;
      param_1[0x108] = 99;
      if (lVar1 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x6f;
        lVar1 = 2;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        param_1[1] = 0x6d;
        goto LAB_00117470;
      }
      lVar2 = lVar2 + 2;
      *(long *)(param_1 + 0x100) = lVar2;
      param_1[lVar1] = 0x6f;
      param_1[0x108] = 0x6f;
      if (lVar2 != 0xff) goto LAB_00117454;
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      *param_1 = 0x6d;
      lVar2 = 2;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 0x70;
LAB_0011748c:
      lVar5 = lVar2 + 1;
      *(long *)(param_1 + 0x100) = lVar5;
      param_1[lVar2] = 0x6c;
      param_1[0x108] = 0x6c;
      if (lVar5 == 0xff) {
        param_1[0xff] = 0;
        uVar6 = 0x20;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x65;
        lVar2 = 2;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        param_1[1] = 0x78;
        break;
      }
    }
    lVar1 = lVar5 + 1;
    *(long *)(param_1 + 0x100) = lVar1;
    param_1[lVar5] = 0x65;
    param_1[0x108] = 0x65;
    uVar7 = 0x78;
joined_r0x001175e0:
    if (lVar1 == 0xff) {
      pcVar4 = *(code **)(param_1 + 0x110);
      uVar3 = *(undefined8 *)(param_1 + 0x118);
      uVar6 = 0x20;
      param_1[0xff] = 0;
      goto LAB_001174d8;
    }
    goto LAB_001175e4;
  case 0x26:
    lVar2 = *(long *)(param_1 + 0x100);
    if (lVar2 == 0xff) {
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      *param_1 = 0x69;
      lVar2 = 2;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 0x6d;
LAB_0011753c:
      lVar1 = lVar2 + 1;
      *(long *)(param_1 + 0x100) = lVar1;
      param_1[lVar2] = 0x61;
      param_1[0x108] = 0x61;
      if (lVar1 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x67;
        lVar2 = 2;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        param_1[1] = 0x69;
        goto LAB_00117590;
      }
LAB_00117558:
      lVar5 = lVar1 + 1;
      *(long *)(param_1 + 0x100) = lVar5;
      param_1[lVar1] = 0x67;
      param_1[0x108] = 0x67;
      if (lVar5 != 0xff) goto LAB_00117574;
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      *param_1 = 0x69;
      lVar1 = 2;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 0x6e;
LAB_001175ac:
      lVar2 = lVar1 + 1;
      *(long *)(param_1 + 0x100) = lVar2;
      param_1[lVar1] = 0x61;
      param_1[0x108] = 0x61;
      if (lVar2 == 0xff) {
        param_1[0xff] = 0;
        uVar6 = 0x20;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x72;
        lVar2 = 2;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        param_1[1] = 0x79;
        break;
      }
LAB_001175c8:
      lVar1 = lVar2 + 1;
      *(long *)(param_1 + 0x100) = lVar1;
      param_1[lVar2] = 0x72;
      param_1[0x108] = 0x72;
      uVar7 = 0x79;
      goto joined_r0x001175e0;
    }
    lVar1 = lVar2 + 1;
    *(long *)(param_1 + 0x100) = lVar1;
    param_1[lVar2] = 0x69;
    param_1[0x108] = 0x69;
    if (lVar1 == 0xff) {
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      *param_1 = 0x6d;
      lVar1 = 2;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 0x61;
      goto LAB_00117558;
    }
    lVar2 = lVar2 + 2;
    *(long *)(param_1 + 0x100) = lVar2;
    param_1[lVar1] = 0x6d;
    param_1[0x108] = 0x6d;
    if (lVar2 != 0xff) goto LAB_0011753c;
    param_1[0xff] = 0;
    (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
    *param_1 = 0x61;
    lVar5 = 2;
    *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    param_1[1] = 0x67;
LAB_00117574:
    lVar2 = lVar5 + 1;
    *(long *)(param_1 + 0x100) = lVar2;
    param_1[lVar5] = 0x69;
    param_1[0x108] = 0x69;
    if (lVar2 == 0xff) {
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      *param_1 = 0x6e;
      lVar2 = 2;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 0x61;
      goto LAB_001175c8;
    }
LAB_00117590:
    lVar1 = lVar2 + 1;
    *(long *)(param_1 + 0x100) = lVar1;
    param_1[lVar2] = 0x6e;
    param_1[0x108] = 0x6e;
    if (lVar1 != 0xff) goto LAB_001175ac;
    uVar7 = 0x79;
    param_1[0xff] = 0;
    (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
    *param_1 = 0x61;
    lVar1 = 2;
    *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    param_1[1] = 0x72;
LAB_001175e4:
    lVar2 = lVar1 + 1;
    *(long *)(param_1 + 0x100) = lVar2;
    param_1[lVar1] = uVar7;
    param_1[0x108] = uVar7;
    uVar6 = 0x20;
    if (lVar2 != 0xff) break;
    lVar2 = 0xff;
    goto LAB_001172d4;
  case 0x2b:
    if (param_1[0x108] != '(') {
      lVar2 = *(long *)(param_1 + 0x100);
      if (lVar2 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar1 = 1;
        lVar2 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
      else {
        lVar1 = lVar2 + 1;
      }
      *(long *)(param_1 + 0x100) = lVar1;
      param_1[lVar2] = 0x20;
      param_1[0x108] = 0x20;
    }
    FUN_001122e8(param_1,param_2,*(undefined8 *)(param_3 + 2));
    lVar2 = *(long *)(param_1 + 0x100);
    if (lVar2 == 0xff) {
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar2 = 2;
      *param_1 = 0x3a;
      param_1[1] = 0x3a;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    }
    else {
      lVar1 = lVar2 + 1;
      *(long *)(param_1 + 0x100) = lVar1;
      param_1[lVar2] = 0x3a;
      param_1[0x108] = 0x3a;
      if (lVar1 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x3a;
        lVar2 = 1;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
      else {
        lVar2 = lVar2 + 2;
        *(long *)(param_1 + 0x100) = lVar2;
        param_1[lVar1] = 0x3a;
        param_1[0x108] = 0x3a;
        if (lVar2 == 0xff) {
          param_1[0xff] = 0;
          (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
          lVar1 = 1;
          lVar2 = 0;
          *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
          goto LAB_00117688;
        }
      }
    }
    lVar1 = lVar2 + 1;
LAB_00117688:
    *(long *)(param_1 + 0x100) = lVar1;
    param_1[lVar2] = 0x2a;
    param_1[0x108] = 0x2a;
    return;
  case 0x2d:
    lVar2 = *(long *)(param_1 + 0x100);
    if (lVar2 == 0xff) {
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar2 = 2;
      *param_1 = 0x20;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 0x5f;
LAB_00116f20:
      lVar1 = lVar2 + 1;
      *(long *)(param_1 + 0x100) = lVar1;
      param_1[lVar2] = 0x5f;
      param_1[0x108] = 0x5f;
      if (lVar1 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x76;
        lVar2 = 2;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        param_1[1] = 0x65;
        goto LAB_00116f74;
      }
LAB_00116f3c:
      lVar5 = lVar1 + 1;
      *(long *)(param_1 + 0x100) = lVar5;
      param_1[lVar1] = 0x76;
      param_1[0x108] = 0x76;
      if (lVar5 != 0xff) goto LAB_00116f58;
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      *param_1 = 0x65;
      lVar1 = 2;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 99;
LAB_00116f90:
      lVar2 = lVar1 + 1;
      *(long *)(param_1 + 0x100) = lVar2;
      param_1[lVar1] = 0x74;
      param_1[0x108] = 0x74;
      if (lVar2 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x6f;
        lVar2 = 2;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        param_1[1] = 0x72;
      }
      else {
LAB_00116fac:
        lVar1 = lVar2 + 1;
        *(long *)(param_1 + 0x100) = lVar1;
        param_1[lVar2] = 0x6f;
        param_1[0x108] = 0x6f;
        if (lVar1 != 0xff) goto LAB_00116fc8;
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x72;
        lVar2 = 1;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      }
    }
    else {
      lVar1 = lVar2 + 1;
      *(long *)(param_1 + 0x100) = lVar1;
      param_1[lVar2] = 0x20;
      param_1[0x108] = 0x20;
      if (lVar1 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 0x5f;
        lVar1 = 2;
        param_1[1] = 0x5f;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        goto LAB_00116f3c;
      }
      lVar2 = lVar2 + 2;
      *(long *)(param_1 + 0x100) = lVar2;
      param_1[lVar1] = 0x5f;
      param_1[0x108] = 0x5f;
      if (lVar2 != 0xff) goto LAB_00116f20;
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      *param_1 = 0x5f;
      lVar5 = 2;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 0x76;
LAB_00116f58:
      lVar2 = lVar5 + 1;
      *(long *)(param_1 + 0x100) = lVar2;
      param_1[lVar5] = 0x65;
      param_1[0x108] = 0x65;
      if (lVar2 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        *param_1 = 99;
        lVar2 = 2;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        param_1[1] = 0x74;
        goto LAB_00116fac;
      }
LAB_00116f74:
      lVar1 = lVar2 + 1;
      *(long *)(param_1 + 0x100) = lVar1;
      param_1[lVar2] = 99;
      param_1[0x108] = 99;
      if (lVar1 != 0xff) goto LAB_00116f90;
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      *param_1 = 0x74;
      lVar1 = 2;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      param_1[1] = 0x6f;
LAB_00116fc8:
      lVar2 = lVar1 + 1;
      *(long *)(param_1 + 0x100) = lVar2;
      param_1[lVar1] = 0x72;
      param_1[0x108] = 0x72;
      if (lVar2 == 0xff) {
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
        lVar1 = 1;
        lVar2 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        goto LAB_00116fe8;
      }
    }
    lVar1 = lVar2 + 1;
LAB_00116fe8:
    *(long *)(param_1 + 0x100) = lVar1;
    param_1[lVar2] = 0x28;
    param_1[0x108] = 0x28;
    FUN_001122e8(param_1,param_2,*(undefined8 *)(param_3 + 2));
    lVar2 = *(long *)(param_1 + 0x100);
    if (lVar2 == 0xff) {
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar1 = 1;
      lVar2 = 0;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    }
    else {
      lVar1 = lVar2 + 1;
    }
    *(long *)(param_1 + 0x100) = lVar1;
    param_1[lVar2] = 0x29;
    param_1[0x108] = 0x29;
    return;
  }
  lVar1 = lVar2 + 1;
LAB_00117218:
  *(long *)(param_1 + 0x100) = lVar1;
  param_1[lVar2] = uVar6;
  param_1[0x108] = uVar6;
  return;
}



void FUN_00118244(undefined *param_1,uint param_2,undefined8 *param_3,int param_4)

{
  char cVar1;
  byte bVar2;
  int iVar3;
  size_t sVar4;
  long lVar5;
  int *piVar6;
  long lVar7;
  long lVar8;
  undefined8 uVar9;
  undefined8 uVar10;
  size_t sVar11;
  char local_20 [32];
  
  if (param_3 != (undefined8 *)0x0) {
    iVar3 = *(int *)(param_1 + 0x130);
    while (iVar3 == 0) {
      if (*(int *)(param_3 + 2) == 0) {
        piVar6 = (int *)param_3[1];
        iVar3 = *piVar6;
        if ((param_4 != 0) || (4 < iVar3 - 0x1cU)) {
          *(undefined4 *)(param_3 + 2) = 1;
          uVar9 = *(undefined8 *)(param_1 + 0x120);
          *(undefined8 *)(param_1 + 0x120) = param_3[3];
          if (iVar3 == 0x29) {
            FUN_00118d70(param_1,param_2,piVar6 + 4,*param_3);
            *(undefined8 *)(param_1 + 0x120) = uVar9;
            return;
          }
          if (iVar3 == 0x2a) {
            FUN_00118aa4(param_1,param_2,piVar6 + 2,*param_3);
            *(undefined8 *)(param_1 + 0x120) = uVar9;
            return;
          }
          if (iVar3 == 2) {
            uVar10 = *(undefined8 *)(param_1 + 0x128);
            *(undefined8 *)(param_1 + 0x128) = 0;
            FUN_001122e8(param_1,param_2,*(undefined8 *)(piVar6 + 2));
            *(undefined8 *)(param_1 + 0x128) = uVar10;
            lVar5 = *(long *)(param_1 + 0x100);
            bVar2 = (byte)param_2 & 4;
            if ((param_2 >> 2 & 1) == 0) {
              if (lVar5 == 0xff) {
                param_1[0xff] = bVar2;
                (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
                lVar7 = 1;
                *param_1 = 0x3a;
                *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
LAB_001183b0:
                lVar5 = lVar7 + 1;
              }
              else {
                lVar7 = lVar5 + 1;
                *(long *)(param_1 + 0x100) = lVar7;
                param_1[lVar5] = 0x3a;
                param_1[0x108] = 0x3a;
                if (lVar7 != 0xff) goto LAB_001183b0;
                param_1[0xff] = bVar2;
                (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
                lVar5 = 1;
                lVar7 = 0;
                *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
              }
              *(long *)(param_1 + 0x100) = lVar5;
              param_1[lVar7] = 0x3a;
              param_1[0x108] = 0x3a;
            }
            else {
              if (lVar5 == 0xff) {
                param_1[0xff] = 0;
                (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
                lVar7 = 1;
                lVar5 = 0;
                *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
              }
              else {
                lVar7 = lVar5 + 1;
              }
              *(long *)(param_1 + 0x100) = lVar7;
              param_1[lVar5] = 0x2e;
              param_1[0x108] = 0x2e;
            }
            piVar6 = *(int **)(param_3[1] + 0x10);
            iVar3 = *piVar6;
            if (iVar3 != 0x45) goto LAB_001183fc;
            lVar5 = *(long *)(param_1 + 0x100);
            if (lVar5 == 0xff) {
              param_1[0xff] = 0;
              (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
              lVar5 = 2;
              *param_1 = 0x7b;
              *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
              param_1[1] = 100;
LAB_0011850c:
              lVar7 = lVar5 + 1;
              *(long *)(param_1 + 0x100) = lVar7;
              param_1[lVar5] = 0x65;
              param_1[0x108] = 0x65;
              if (lVar7 == 0xff) {
                param_1[0xff] = 0;
                (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
                *param_1 = 0x66;
                lVar5 = 2;
                *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
                param_1[1] = 0x61;
                goto LAB_00118560;
              }
LAB_00118528:
              lVar8 = lVar7 + 1;
              *(long *)(param_1 + 0x100) = lVar8;
              param_1[lVar7] = 0x66;
              param_1[0x108] = 0x66;
              if (lVar8 != 0xff) goto LAB_00118544;
              param_1[0xff] = 0;
              (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
              *param_1 = 0x61;
              lVar7 = 2;
              *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
              param_1[1] = 0x75;
LAB_0011857c:
              lVar5 = lVar7 + 1;
              *(long *)(param_1 + 0x100) = lVar5;
              param_1[lVar7] = 0x6c;
              param_1[0x108] = 0x6c;
              if (lVar5 == 0xff) {
                param_1[0xff] = 0;
                (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
                *param_1 = 0x74;
                lVar5 = 2;
                *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
                param_1[1] = 0x20;
                goto LAB_001185d0;
              }
LAB_00118598:
              lVar7 = lVar5 + 1;
              *(long *)(param_1 + 0x100) = lVar7;
              param_1[lVar5] = 0x74;
              param_1[0x108] = 0x74;
              if (lVar7 != 0xff) goto LAB_001185b4;
              param_1[0xff] = 0;
              (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
              *param_1 = 0x20;
              lVar7 = 2;
              *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
              param_1[1] = 0x61;
LAB_001185ec:
              lVar5 = lVar7 + 1;
              *(long *)(param_1 + 0x100) = lVar5;
              param_1[lVar7] = 0x72;
              param_1[0x108] = 0x72;
              if (lVar5 == 0xff) {
                param_1[0xff] = 0;
                (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
                *param_1 = 0x67;
                lVar7 = 1;
                *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
                goto LAB_00118624;
              }
LAB_00118608:
              lVar7 = lVar5 + 1;
              *(long *)(param_1 + 0x100) = lVar7;
              param_1[lVar5] = 0x67;
              param_1[0x108] = 0x67;
              if (lVar7 != 0xff) goto LAB_00118624;
              param_1[0xff] = 0;
              (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
              lVar5 = 1;
              lVar7 = 0;
              *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
            }
            else {
              lVar7 = lVar5 + 1;
              *(long *)(param_1 + 0x100) = lVar7;
              param_1[lVar5] = 0x7b;
              param_1[0x108] = 0x7b;
              if (lVar7 == 0xff) {
                param_1[0xff] = 0;
                (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
                *param_1 = 100;
                lVar7 = 2;
                *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
                param_1[1] = 0x65;
                goto LAB_00118528;
              }
              lVar5 = lVar5 + 2;
              *(long *)(param_1 + 0x100) = lVar5;
              param_1[lVar7] = 100;
              param_1[0x108] = 100;
              if (lVar5 != 0xff) goto LAB_0011850c;
              param_1[0xff] = 0;
              (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
              *param_1 = 0x65;
              lVar8 = 2;
              *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
              param_1[1] = 0x66;
LAB_00118544:
              lVar5 = lVar8 + 1;
              *(long *)(param_1 + 0x100) = lVar5;
              param_1[lVar8] = 0x61;
              param_1[0x108] = 0x61;
              if (lVar5 == 0xff) {
                param_1[0xff] = 0;
                (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
                *param_1 = 0x75;
                lVar5 = 2;
                *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
                param_1[1] = 0x6c;
                goto LAB_00118598;
              }
LAB_00118560:
              lVar7 = lVar5 + 1;
              *(long *)(param_1 + 0x100) = lVar7;
              param_1[lVar5] = 0x75;
              param_1[0x108] = 0x75;
              if (lVar7 != 0xff) goto LAB_0011857c;
              param_1[0xff] = 0;
              (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
              *param_1 = 0x6c;
              lVar7 = 2;
              *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
              param_1[1] = 0x74;
LAB_001185b4:
              lVar5 = lVar7 + 1;
              *(long *)(param_1 + 0x100) = lVar5;
              param_1[lVar7] = 0x20;
              param_1[0x108] = 0x20;
              if (lVar5 == 0xff) {
                param_1[0xff] = 0;
                (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
                *param_1 = 0x61;
                lVar5 = 2;
                *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
                param_1[1] = 0x72;
                goto LAB_00118608;
              }
LAB_001185d0:
              lVar7 = lVar5 + 1;
              *(long *)(param_1 + 0x100) = lVar7;
              param_1[lVar5] = 0x61;
              param_1[0x108] = 0x61;
              if (lVar7 != 0xff) goto LAB_001185ec;
              param_1[0xff] = 0;
              (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
              *param_1 = 0x72;
              lVar7 = 2;
              *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
              param_1[1] = 0x67;
LAB_00118624:
              lVar5 = lVar7 + 1;
            }
            *(long *)(param_1 + 0x100) = lVar5;
            param_1[lVar7] = 0x23;
            param_1[0x108] = 0x23;
            sVar11 = 0;
            sprintf(local_20,"%ld",(long)(piVar6[4] + 1));
            sVar4 = strlen(local_20);
            lVar5 = *(long *)(param_1 + 0x100);
            lVar7 = lVar5;
            if (sVar4 != 0) {
              do {
                cVar1 = local_20[sVar11];
                if (lVar7 == 0xff) {
                  param_1[0xff] = 0;
                  (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
                  lVar5 = 1;
                  lVar7 = 0;
                  *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
                }
                else {
                  lVar5 = lVar7 + 1;
                }
                *(long *)(param_1 + 0x100) = lVar5;
                sVar11 = sVar11 + 1;
                param_1[lVar7] = cVar1;
                param_1[0x108] = cVar1;
                lVar7 = lVar5;
              } while (sVar11 != sVar4);
            }
            if (lVar5 == 0xff) {
              param_1[0xff] = 0;
              (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
              *param_1 = 0x7d;
              param_1[1] = 0x3a;
              *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
              lVar5 = 2;
            }
            else {
              lVar7 = lVar5 + 1;
              *(long *)(param_1 + 0x100) = lVar7;
              param_1[lVar5] = 0x7d;
              param_1[0x108] = 0x7d;
              if (lVar7 == 0xff) {
                param_1[0xff] = 0;
                (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
                *param_1 = 0x3a;
                lVar5 = 1;
                *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
              }
              else {
                lVar5 = lVar5 + 2;
                *(long *)(param_1 + 0x100) = lVar5;
                param_1[lVar7] = 0x3a;
                param_1[0x108] = 0x3a;
                if (lVar5 == 0xff) {
                  param_1[0xff] = 0;
                  (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
                  lVar7 = 1;
                  lVar5 = 0;
                  *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
                  goto LAB_00118740;
                }
              }
            }
            lVar7 = lVar5 + 1;
LAB_00118740:
            *(long *)(param_1 + 0x100) = lVar7;
            param_1[lVar5] = 0x3a;
            param_1[0x108] = 0x3a;
            do {
              piVar6 = *(int **)(piVar6 + 2);
              iVar3 = *piVar6;
LAB_001183fc:
            } while (iVar3 - 0x1cU < 5);
            FUN_001122e8(param_1,param_2,piVar6);
            *(undefined8 *)(param_1 + 0x120) = uVar9;
            return;
          }
          FUN_00116e70(param_1,param_2);
          *(undefined8 *)(param_1 + 0x120) = uVar9;
        }
      }
      param_3 = (undefined8 *)*param_3;
      if (param_3 == (undefined8 *)0x0) {
        return;
      }
      iVar3 = *(int *)(param_1 + 0x130);
    }
  }
  return;
}



void FUN_00118aa4(undefined *param_1,undefined4 param_2,long *param_3,long *param_4)

{
  long lVar1;
  long lVar2;
  long *plVar3;
  
  plVar3 = param_4;
  if (param_4 != (long *)0x0) {
    do {
      if (*(int *)(plVar3 + 2) == 0) {
        if (*(int *)plVar3[1] == 0x2a) {
          FUN_00118244(param_1,param_2,param_4,0);
          lVar2 = *(long *)(param_1 + 0x100);
          goto joined_r0x00118c0c;
        }
        lVar2 = *(long *)(param_1 + 0x100);
        if (lVar2 == 0xff) {
          param_1[0xff] = 0;
          (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
          lVar1 = 1;
          *param_1 = 0x20;
          *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
LAB_00118ba8:
          lVar2 = lVar1 + 1;
        }
        else {
          lVar1 = lVar2 + 1;
          *(long *)(param_1 + 0x100) = lVar1;
          param_1[lVar2] = 0x20;
          param_1[0x108] = 0x20;
          if (lVar1 != 0xff) goto LAB_00118ba8;
          param_1[0xff] = 0;
          (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
          lVar2 = 1;
          lVar1 = 0;
          *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        }
        *(long *)(param_1 + 0x100) = lVar2;
        param_1[lVar1] = 0x28;
        param_1[0x108] = 0x28;
        FUN_00118244(param_1,param_2,param_4,0);
        lVar2 = *(long *)(param_1 + 0x100);
        lVar1 = lVar2 + 1;
        if (lVar2 == 0xff) {
          param_1[0xff] = 0;
          (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
          lVar1 = 1;
          lVar2 = 0;
          *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        }
        *(long *)(param_1 + 0x100) = lVar1;
        param_1[lVar2] = 0x29;
        param_1[0x108] = 0x29;
        goto LAB_00118af0;
      }
      plVar3 = (long *)*plVar3;
    } while (plVar3 != (long *)0x0);
    FUN_00118244(param_1,param_2,param_4,0);
  }
  lVar1 = *(long *)(param_1 + 0x100);
LAB_00118af0:
  if (lVar1 == 0xff) {
    param_1[0xff] = 0;
    (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
    lVar2 = 1;
    lVar1 = 0;
    *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
  }
  else {
    lVar2 = lVar1 + 1;
  }
  *(long *)(param_1 + 0x100) = lVar2;
  param_1[lVar1] = 0x20;
  param_1[0x108] = 0x20;
joined_r0x00118c0c:
  if (lVar2 == 0xff) {
    param_1[0xff] = 0;
    (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
    *param_1 = 0x5b;
    param_1[0x108] = 0x5b;
    lVar1 = 1;
    lVar2 = *param_3;
    *(undefined8 *)(param_1 + 0x100) = 1;
    *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    if (lVar2 == 0) goto LAB_00118b48;
LAB_00118b30:
    FUN_001122e8(param_1,param_2);
    lVar1 = *(long *)(param_1 + 0x100);
  }
  else {
    lVar1 = lVar2 + 1;
    *(long *)(param_1 + 0x100) = lVar1;
    param_1[lVar2] = 0x5b;
    param_1[0x108] = 0x5b;
    if (*param_3 != 0) goto LAB_00118b30;
  }
  if (lVar1 == 0xff) {
    param_1[0xff] = 0;
    (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
    *(undefined8 *)(param_1 + 0x100) = 1;
    *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    *param_1 = 0x5d;
    param_1[0x108] = 0x5d;
    return;
  }
LAB_00118b48:
  *(long *)(param_1 + 0x100) = lVar1 + 1;
  param_1[lVar1] = 0x5d;
  param_1[0x108] = 0x5d;
  return;
}



void FUN_00118d70(undefined *param_1,undefined4 param_2,long *param_3,long *param_4)

{
  int iVar1;
  byte bVar2;
  long lVar3;
  long lVar4;
  long *plVar5;
  undefined8 uVar6;
  
  if (param_4 != (long *)0x0) {
    iVar1 = *(int *)(param_4 + 2);
    plVar5 = param_4;
joined_r0x00118d9c:
    if (iVar1 == 0) {
      switch(*(undefined4 *)plVar5[1]) {
      case 0x19:
      case 0x1a:
      case 0x1b:
      case 0x21:
      case 0x25:
      case 0x26:
      case 0x2b:
        bVar2 = param_1[0x108];
LAB_00118e80:
        if (bVar2 == 0x20) goto LAB_00118eec;
        lVar4 = *(long *)(param_1 + 0x100);
        if (lVar4 == 0xff) {
          param_1[0xff] = 0;
          (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
          lVar3 = 1;
          lVar4 = 0;
          *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        }
        else {
          lVar3 = lVar4 + 1;
        }
        *(long *)(param_1 + 0x100) = lVar3;
        param_1[lVar4] = 0x20;
        param_1[0x108] = 0x20;
        if (lVar3 != 0xff) goto LAB_00118ef8;
LAB_00118eb0:
        param_1[0xff] = 0;
        (**(code **)(param_1 + 0x110))(param_1,lVar3,*(undefined8 *)(param_1 + 0x118));
        lVar4 = 1;
        lVar3 = 0;
        *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
        break;
      default:
        plVar5 = (long *)*plVar5;
        if (plVar5 != (long *)0x0) goto code_r0x00118dd8;
        goto LAB_00118de0;
      case 0x22:
      case 0x23:
      case 0x24:
        bVar2 = param_1[0x108];
        if ((bVar2 & 0xfd) != 0x28) goto LAB_00118e80;
LAB_00118eec:
        lVar3 = *(long *)(param_1 + 0x100);
        if (lVar3 == 0xff) goto LAB_00118eb0;
LAB_00118ef8:
        lVar4 = lVar3 + 1;
      }
      *(long *)(param_1 + 0x100) = lVar4;
      param_1[lVar3] = 0x28;
      param_1[0x108] = 0x28;
      uVar6 = *(undefined8 *)(param_1 + 0x128);
      *(undefined8 *)(param_1 + 0x128) = 0;
      FUN_00118244(param_1,param_2,param_4,0);
      lVar3 = *(long *)(param_1 + 0x100);
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
      param_1[lVar3] = 0x29;
      param_1[0x108] = 0x29;
      goto joined_r0x00118e04;
    }
  }
LAB_00118de0:
  uVar6 = *(undefined8 *)(param_1 + 0x128);
  *(undefined8 *)(param_1 + 0x128) = 0;
  FUN_00118244(param_1,param_2,param_4,0);
  lVar4 = *(long *)(param_1 + 0x100);
joined_r0x00118e04:
  if (lVar4 == 0xff) {
    param_1[0xff] = 0;
    (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
    *param_1 = 0x28;
    param_1[0x108] = 0x28;
    lVar3 = 1;
    lVar4 = *param_3;
    *(undefined8 *)(param_1 + 0x100) = 1;
    *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    if (lVar4 != 0) goto LAB_00118e24;
  }
  else {
    lVar3 = lVar4 + 1;
    *(long *)(param_1 + 0x100) = lVar3;
    param_1[lVar4] = 0x28;
    param_1[0x108] = 0x28;
    if (*param_3 != 0) {
LAB_00118e24:
      FUN_001122e8(param_1,param_2);
      lVar3 = *(long *)(param_1 + 0x100);
    }
    if (lVar3 == 0xff) {
      param_1[0xff] = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar4 = 1;
      lVar3 = 0;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
      goto LAB_00118e40;
    }
  }
  lVar4 = lVar3 + 1;
LAB_00118e40:
  *(long *)(param_1 + 0x100) = lVar4;
  param_1[lVar3] = 0x29;
  param_1[0x108] = 0x29;
  FUN_00118244(param_1,param_2,param_4,1);
  *(undefined8 *)(param_1 + 0x128) = uVar6;
  return;
code_r0x00118dd8:
  iVar1 = *(int *)(plVar5 + 2);
  goto joined_r0x00118d9c;
}



void FUN_00119020(long param_1,undefined4 param_2,int **param_3)

{
  long lVar1;
  long lVar2;
  undefined8 local_10;
  long local_8;
  
  if (*(long *)(param_1 + 0x160) != 0) {
    local_10 = *(undefined8 *)(param_1 + 0x120);
    *(undefined8 **)(param_1 + 0x120) = &local_10;
    local_8 = *(long *)(param_1 + 0x160);
  }
  if (**param_3 != 4) {
    FUN_001122e8(param_1,param_2);
    if (*(long *)(param_1 + 0x160) != 0) {
      *(undefined8 *)(param_1 + 0x120) = local_10;
    }
    return;
  }
  FUN_001122e8(param_1,param_2,*(undefined8 *)(*param_3 + 2));
  if (*(long *)(param_1 + 0x160) != 0) {
    *(undefined8 *)(param_1 + 0x120) = local_10;
  }
  if (*(char *)(param_1 + 0x108) == '<') {
    lVar1 = *(long *)(param_1 + 0x100);
    if (lVar1 == 0xff) {
      *(undefined *)(param_1 + 0xff) = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar2 = 1;
      lVar1 = 0;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    }
    else {
      lVar2 = lVar1 + 1;
    }
    *(long *)(param_1 + 0x100) = lVar2;
    *(undefined *)(param_1 + lVar1) = 0x20;
    *(undefined *)(param_1 + 0x108) = 0x20;
  }
  else {
    lVar2 = *(long *)(param_1 + 0x100);
  }
  if (lVar2 == 0xff) {
    *(undefined *)(param_1 + 0xff) = 0;
    (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
    lVar1 = 1;
    lVar2 = 0;
    *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
  }
  else {
    lVar1 = lVar2 + 1;
  }
  *(long *)(param_1 + 0x100) = lVar1;
  *(undefined *)(param_1 + lVar2) = 0x3c;
  *(undefined *)(param_1 + 0x108) = 0x3c;
  FUN_001122e8(param_1,param_2,*(undefined8 *)(*param_3 + 4));
  if (*(char *)(param_1 + 0x108) == '>') {
    lVar1 = *(long *)(param_1 + 0x100);
    if (lVar1 == 0xff) {
      *(undefined *)(param_1 + 0xff) = 0;
      (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
      lVar2 = 1;
      lVar1 = 0;
      *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
    }
    else {
      lVar2 = lVar1 + 1;
    }
    *(long *)(param_1 + 0x100) = lVar2;
    *(undefined *)(param_1 + lVar1) = 0x20;
    *(undefined *)(param_1 + 0x108) = 0x20;
  }
  else {
    lVar2 = *(long *)(param_1 + 0x100);
  }
  if (lVar2 == 0xff) {
    *(undefined *)(param_1 + 0xff) = 0;
    (**(code **)(param_1 + 0x110))(param_1,0xff,*(undefined8 *)(param_1 + 0x118));
    lVar1 = 1;
    lVar2 = 0;
    *(long *)(param_1 + 0x138) = *(long *)(param_1 + 0x138) + 1;
  }
  else {
    lVar1 = lVar2 + 1;
  }
  *(long *)(param_1 + 0x100) = lVar1;
  *(undefined *)(param_1 + lVar2) = 0x3e;
  *(undefined *)(param_1 + 0x108) = 0x3e;
  return;
}



void FUN_00119230(undefined *param_1,undefined8 param_2,int *param_3)

{
  undefined uVar1;
  long lVar2;
  long lVar3;
  long lVar4;
  long lVar5;
  
  if (*param_3 != 0x31) {
    FUN_001122e8();
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



void FUN_00119304(long param_1,undefined4 param_2,uint *param_3)

{
  uint uVar1;
  long lVar2;
  long lVar3;
  
  uVar1 = *param_3;
  if (uVar1 != 0x30 && 1 < uVar1) {
    if (uVar1 != 6) {
      lVar3 = *(long *)(param_1 + 0x100);
      if (lVar3 == 0xff) {
        *(bool *)(param_1 + 0xff) = uVar1 == 6;
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
      FUN_001122e8(param_1,param_2,param_3);
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
  }
  FUN_001122e8(param_1);
  return;
}



bool FUN_00119410(char *param_1,code *param_2,undefined8 param_3)

{
  char *pcVar1;
  char cVar2;
  long lVar3;
  long lVar4;
  long lVar5;
  code *pcVar6;
  int iVar7;
  int iVar8;
  size_t sVar9;
  undefined8 uVar10;
  long lVar11;
  undefined4 uVar12;
  char *pcVar13;
  char cVar14;
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
  
  cVar14 = *param_1;
  if ((cVar14 == '_') && (param_1[1] == 'Z')) {
    iVar8 = 1;
  }
  else {
    iVar8 = 0;
    iVar7 = strncmp(param_1,"_GLOBAL_",8);
    if ((iVar7 == 0) && ((cVar2 = param_1[8], cVar2 == '_' || cVar2 == '.' || (cVar2 == '$')))) {
      cVar2 = param_1[9];
      if (((cVar2 == 'I') || (iVar8 = 0, cVar2 == 'D')) &&
         ((iVar8 = 0, param_1[10] == '_' && (iVar8 = 2, cVar2 != 'I')))) {
        iVar8 = 3;
      }
    }
  }
  sVar9 = strlen(param_1);
  local_18c = (int)sVar9;
  local_19c = local_18c << 1;
  local_1c0 = param_1 + sVar9;
  lVar3 = -((long)local_19c * 0x18 + 0x10);
  local_1a8 = &stack0xfffffffffffffde0 + lVar3;
  lVar4 = -((-(sVar9 >> 0x1f & 1) & 0xfffffff800000000 | (sVar9 & 0xffffffff) << 3) + 0x16 &
           0xfffffffffffffff0);
  local_198 = &stack0xfffffffffffffde0 + lVar4 + lVar3;
  local_1b8 = 0x11;
  local_1a0 = 0;
  local_190 = 0;
  local_188 = 0;
  local_180 = 0;
  local_178 = 0;
  local_174 = 0;
  local_170 = 0;
  local_1c8 = param_1;
  if (iVar8 == 1) {
    if (cVar14 != '_') {
      return false;
    }
    if (param_1[1] != 'Z') {
      return false;
    }
    local_1b0 = param_1 + 2;
    lVar11 = FUN_0010f2f0(&local_1c8,1);
    if ((local_1b8 & 1) == 0) {
LAB_00119830:
      cVar14 = *local_1b0;
    }
    else {
      while (pcVar1 = local_1b0, cVar14 = *local_1b0, cVar14 == '.') {
        cVar14 = local_1b0[1];
        if (((byte)(cVar14 + 0x9fU) < 0x1a) || (cVar14 == '_')) {
          cVar14 = local_1b0[2];
          pcVar13 = local_1b0 + 2;
          if (0x19 < (byte)(cVar14 + 0x9fU)) goto LAB_00119824;
          do {
            do {
              pcVar13 = pcVar13 + 1;
              cVar14 = *pcVar13;
            } while ((byte)(cVar14 + 0x9fU) < 0x1a);
LAB_00119824:
          } while (cVar14 == '_');
        }
        else {
          if (9 < (byte)(cVar14 - 0x30U)) goto LAB_00119830;
          cVar14 = *local_1b0;
          pcVar13 = local_1b0;
        }
        while (cVar14 == '.') {
          while( true ) {
            if (9 < (byte)(pcVar13[1] - 0x30U)) goto LAB_001197b4;
            cVar14 = pcVar13[2];
            pcVar13 = pcVar13 + 2;
            if (9 < (byte)(cVar14 - 0x30U)) break;
            do {
              pcVar13 = pcVar13 + 1;
            } while ((byte)(*pcVar13 - 0x30U) < 10);
            if (*pcVar13 != '.') goto LAB_001197b4;
          }
        }
LAB_001197b4:
        iVar8 = (int)local_1b0;
        local_1b0 = pcVar13;
        uVar10 = FUN_00109e98(&local_1c8,pcVar1,(int)pcVar13 - iVar8);
        lVar11 = FUN_00109de4(&local_1c8,0x4b,lVar11,uVar10);
      }
    }
  }
  else if (iVar8 == 0) {
    local_1b0 = param_1;
    local_1a8 = &stack0xfffffffffffffde0 + lVar3;
    local_198 = &stack0xfffffffffffffde0 + lVar4 + lVar3;
    lVar11 = FUN_0010ac34(&local_1c8);
    cVar14 = *local_1b0;
  }
  else {
    pcVar1 = param_1 + 0xb;
    uVar12 = 0x42;
    if (iVar8 != 2) {
      uVar12 = 0x43;
    }
    if ((param_1[0xb] == '_') && (param_1[0xc] == 'Z')) {
      local_1b0 = param_1 + 0xd;
      local_1a8 = &stack0xfffffffffffffde0 + lVar3;
      local_198 = &stack0xfffffffffffffde0 + lVar4 + lVar3;
      uVar10 = FUN_0010f2f0(&local_1c8,0);
    }
    else {
      local_1b0 = pcVar1;
      local_1a8 = &stack0xfffffffffffffde0 + lVar3;
      local_198 = &stack0xfffffffffffffde0 + lVar4 + lVar3;
      sVar9 = strlen(pcVar1);
      uVar10 = FUN_00109e98(&local_1c8,pcVar1,sVar9);
    }
    lVar11 = FUN_00109de4(&local_1c8,uVar12,uVar10,0);
    pcVar1 = local_1b0;
    sVar9 = strlen(local_1b0);
    local_1b0 = pcVar1 + sVar9;
    cVar14 = pcVar1[sVar9];
  }
  if ((cVar14 == '\0') && (lVar11 != 0)) {
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
    FUN_0010a3c8(&local_c,&local_1c,lVar11);
    local_8 = 0;
    local_c = local_1c * local_c;
    lVar5 = -((-(ulong)(local_1c >> 0x1f) & 0xfffffff000000000 | (ulong)local_1c << 4) + 0x10);
    local_28 = &stack0xfffffffffffffde0 + lVar5 + lVar4 + lVar3;
    local_18 = &stack0xfffffffffffffde0 +
               ((lVar5 + lVar4 + lVar3) -
               ((-(ulong)(local_c >> 0x1f) & 0xfffffff000000000 | (ulong)local_c << 4) + 0x10));
    FUN_001122e8(auStack_168,0x11,lVar11);
    uVar10 = local_50;
    pcVar6 = local_58;
    lVar3 = local_68;
    auStack_168[local_68] = 0;
    (*pcVar6)(auStack_168,lVar3,uVar10);
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
    iVar1 = FUN_00119410(param_1,FUN_0010a9bc,&local_20);
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
    iVar1 = FUN_00119410();
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



void FUN_001199e4(uint param_1,long param_2)

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
  code *pcVar1;
  
  pcVar1 = *(code **)this;
  if (pcVar1 != (_func_void *)0x0) {
    pcVar1 = _M_safe_bool_dummy;
  }
  return pcVar1;
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
  plVar4[0xb] = (long)FUN_001199e4;
  _Unwind_RaiseException(plVar4 + 10);
  __cxa_begin_catch(plVar4 + 10);
                    // WARNING: Subroutine does not return
  terminate();
}



long * __cxa_current_exception_type(void)

{
  long **pplVar1;
  long *plVar2;
  
  pplVar1 = (long **)__cxa_get_globals();
  plVar2 = *pplVar1;
  if (plVar2 != (long *)0x0) {
    if ((plVar2[10] & 1U) != 0) {
      plVar2 = (long *)(*plVar2 + -0x70);
    }
    plVar2 = (long *)*plVar2;
  }
  return plVar2;
}



undefined8 __cxa_guard_acquire(uint *param_1)

{
  uint uVar1;
  uint uVar2;
  char cVar3;
  bool bVar4;
  undefined8 uVar5;
  
  __google_potentially_blocking_region_begin();
  if (*(char *)param_1 != '\0') {
LAB_00119ddc:
    uVar5 = 0;
LAB_00119d4c:
    __google_potentially_blocking_region_end();
    return uVar5;
  }
LAB_00119d30:
  uVar1 = *param_1;
  if (uVar1 == 0) goto code_r0x00119d3c;
  goto LAB_00119d44;
code_r0x00119d3c:
  cVar3 = '\x01';
  bVar4 = (bool)ExclusiveMonitorPass(param_1,0x10);
  if (bVar4) {
    *param_1 = 0x100;
    cVar3 = ExclusiveMonitorsStatus();
  }
  if (cVar3 == '\0') {
LAB_00119d44:
    if (uVar1 == 0) {
      uVar5 = 1;
      goto LAB_00119d4c;
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
          if (uVar2 == 1) goto LAB_00119ddc;
          if (uVar2 == 0) goto LAB_00119d30;
        }
      }
                    // try { // try from 00119da0 to 00119da3 has its CatchHandler @ 00119de4
      syscall(0x62,param_1,0,(ulong)uVar1,0);
      goto LAB_00119d30;
    }
    goto LAB_00119ddc;
  }
  goto LAB_00119d30;
}



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
  if ((uVar1 & 0x10000) == 0) {
    return;
  }
                    // try { // try from 00119e40 to 00119e43 has its CatchHandler @ 00119e4c
  syscall(0x62,param_1,1,0x7fffffff);
  return;
}



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
  if ((uVar1 & 0x10000) == 0) {
    return;
  }
                    // try { // try from 00119ea0 to 00119ea3 has its CatchHandler @ 00119eac
  syscall(0x62,param_1,1,0x7fffffff);
  return;
}



// operator delete[](void*)

void operator_delete__(void *param_1)

{
  free(param_1);
  return;
}



long __dynamic_cast(long *param_1,undefined8 param_2,long *param_3,long param_4)

{
  uint uVar1;
  long *plVar2;
  long local_18;
  uint local_10;
  uint local_c;
  uint local_8;
  undefined4 local_4;
  
  plVar2 = *(long **)(*param_1 + -8);
  local_18 = 0;
  local_10 = 0;
  local_c = 0;
  local_8 = 0;
  local_4 = 0x10;
  (**(code **)(*plVar2 + 0x38))
            (plVar2,param_4,6,param_3,(long)param_1 + *(long *)(*param_1 + -0x10),param_2,param_1,
             &local_18);
  if (local_18 != 0) {
    if ((local_8 & 6) == 6) {
      return local_18;
    }
    if ((local_c & local_10 & 6) == 6) {
      return local_18;
    }
    if (((local_c & 5) != 4) && (local_8 == 0)) {
      if (param_4 < 0) {
        if (param_4 == -2) {
          return 0;
        }
        uVar1 = (**(code **)(*param_3 + 0x40))(param_3,param_4,local_18,param_2,param_1);
        if ((uVar1 & 6) != 6) {
          return 0;
        }
      }
      else if (param_1 != (long *)(local_18 + param_4)) {
        return 0;
      }
      return local_18;
    }
  }
  return 0;
}



void __cxa_bad_cast(void)

{
  undefined8 *puVar1;
  
  puVar1 = (undefined8 *)__cxa_allocate_exception(8);
  *puVar1 = &PTR__bad_cast_001358e0;
                    // WARNING: Subroutine does not return
  __cxa_throw(puVar1,&std::bad_cast::typeinfo,std::bad_cast::~bad_cast);
}



void __cxa_bad_typeid(void)

{
  undefined8 *puVar1;
  
  puVar1 = (undefined8 *)__cxa_allocate_exception(8);
  *puVar1 = &PTR__bad_typeid_00135930;
                    // WARNING: Subroutine does not return
  __cxa_throw(puVar1,&std::bad_typeid::typeinfo,std::bad_typeid::~bad_typeid);
}



void __cxa_throw_bad_array_new_length(void)

{
  undefined8 *puVar1;
  
  puVar1 = (undefined8 *)__cxa_allocate_exception(8);
  *puVar1 = &PTR__bad_array_new_length_00135a50;
                    // WARNING: Subroutine does not return
  __cxa_throw(puVar1,&std::bad_array_new_length::typeinfo,
              std::bad_array_new_length::~bad_array_new_length);
}



void __cxa_throw_bad_array_length(void)

{
  undefined8 *puVar1;
  
  puVar1 = (undefined8 *)__cxa_allocate_exception(8);
  *puVar1 = &PTR__bad_array_length_00135a00;
                    // WARNING: Subroutine does not return
  __cxa_throw(puVar1,&std::bad_array_length::typeinfo,std::bad_array_length::~bad_array_length);
}



// operator new[](unsigned long)

void * operator_new__(ulong param_1)

{
  void *pvVar1;
  
                    // try { // try from 0011a0c8 to 0011a0cb has its CatchHandler @ 0011a0d4
  pvVar1 = operator_new(param_1);
  return pvVar1;
}



// __cxxabiv1::__vmi_class_type_info::~__vmi_class_type_info()

void __thiscall
__cxxabiv1::__vmi_class_type_info::~__vmi_class_type_info(__vmi_class_type_info *this)

{
  *(undefined ***)this = &PTR____vmi_class_type_info_00135980;
  __class_type_info::~__class_type_info((__class_type_info *)this);
  return;
}



// __cxxabiv1::__vmi_class_type_info::~__vmi_class_type_info()

void __thiscall
__cxxabiv1::__vmi_class_type_info::~__vmi_class_type_info(__vmi_class_type_info *this)

{
  ~__vmi_class_type_info(this);
  operator_delete(this);
  return;
}



// __cxxabiv1::__vmi_class_type_info::__do_find_public_src(long, void const*,
// __cxxabiv1::__class_type_info const*, void const*) const

uint __thiscall
__cxxabiv1::__vmi_class_type_info::__do_find_public_src
          (__vmi_class_type_info *this,long param_1,void *param_2,__class_type_info *param_3,
          void *param_4)

{
  bool bVar1;
  uint uVar2;
  int iVar3;
  char *__s1;
  long lVar4;
  ulong uVar5;
  __vmi_class_type_info *p_Var6;
  ulong uVar7;
  ulong uVar8;
  
  if (param_2 == param_4) {
    __s1 = *(char **)(this + 8);
    if (__s1 == *(char **)(param_3 + 8)) {
      return 6;
    }
    if ((*__s1 != '*') && (iVar3 = strcmp(__s1,*(char **)(param_3 + 8)), iVar3 == 0)) {
      return 6;
    }
  }
  uVar8 = (ulong)*(uint *)(this + 0x14);
  uVar7 = 1;
  p_Var6 = this + uVar8 * 0x10;
  if (uVar8 != 0) {
    do {
      uVar5 = *(ulong *)(p_Var6 + 0x10);
      if (((uint)uVar5 >> 1 & 1) != 0) {
        lVar4 = (long)uVar5 >> 8;
        if (((uVar5 & 1) == 0) || (param_1 != -3)) {
          if ((uVar5 & 1) != 0) {
                    // WARNING: Load size is inaccurate
            lVar4 = *(long *)(*param_2 + lVar4);
          }
          uVar2 = (**(code **)(**(long **)(p_Var6 + 8) + 0x40))
                            (*(long **)(p_Var6 + 8),param_1,(long)param_2 + lVar4,param_3,param_4);
          if (3 < (int)uVar2) {
            return uVar2 | (uint)(uVar5 & 1);
          }
        }
      }
      bVar1 = uVar7 != uVar8;
      p_Var6 = p_Var6 + -0x10;
      uVar7 = uVar7 + 1;
    } while (bVar1);
  }
  return 1;
}



// __cxxabiv1::__vmi_class_type_info::__do_dyncast(long, __cxxabiv1::__class_type_info::__sub_kind,
// __cxxabiv1::__class_type_info const*, void const*, __cxxabiv1::__class_type_info const*, void
// const*, __cxxabiv1::__class_type_info::__dyncast_result&) const

char __thiscall
__cxxabiv1::__vmi_class_type_info::__do_dyncast
          (__vmi_class_type_info *this,long param_1,__sub_kind param_2,__class_type_info *param_3,
          void *param_4,__class_type_info *param_5,void *param_6,__dyncast_result *param_7)

{
  byte bVar1;
  char cVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  undefined4 uVar7;
  char *__s2;
  ulong uVar8;
  uint uVar9;
  long lVar10;
  ulong uVar11;
  ulong uVar12;
  char *__s1;
  char cVar13;
  ulong uVar14;
  __vmi_class_type_info *p_Var15;
  bool bVar16;
  byte bVar17;
  long local_18;
  uint local_10;
  uint local_c;
  uint local_8;
  uint local_4;
  
  if ((*(uint *)(param_7 + 0x14) >> 4 & 1) != 0) {
    *(undefined4 *)(param_7 + 0x14) = *(undefined4 *)(this + 0x10);
  }
  __s1 = *(char **)(this + 8);
  if (param_4 == param_6) {
    if (__s1 == *(char **)(param_5 + 8)) {
LAB_0011a57c:
      *(__sub_kind *)(param_7 + 0xc) = param_2;
      return '\0';
    }
    if (*__s1 == '*') {
      if (__s1 != *(char **)(param_3 + 8)) goto LAB_0011a2c4;
      goto LAB_0011a614;
    }
    iVar3 = strcmp(__s1,*(char **)(param_5 + 8));
    if (iVar3 == 0) goto LAB_0011a57c;
    __s2 = *(char **)(param_3 + 8);
    if (__s1 == __s2) goto LAB_0011a614;
  }
  else {
    __s2 = *(char **)(param_3 + 8);
    if (__s2 == __s1) goto LAB_0011a614;
    if (*__s1 == '*') goto LAB_0011a2c4;
  }
  iVar3 = strcmp(__s1,__s2);
  if (iVar3 != 0) {
LAB_0011a2c4:
    cVar13 = '\0';
    bVar17 = 0;
    uVar12 = (long)param_6 - param_1;
    if (param_1 < 0) {
      uVar12 = 0;
    }
    bVar16 = true;
    do {
      uVar14 = 0;
      uVar8 = (ulong)*(uint *)(this + 0x14);
      p_Var15 = this + uVar8 * 0x10;
      if (uVar8 != 0) {
        do {
          local_4 = *(uint *)(param_7 + 0x14);
          uVar11 = *(ulong *)(p_Var15 + 0x10);
          local_18 = 0;
          local_10 = 0;
          lVar10 = (long)uVar11 >> 8;
          local_c = 0;
          local_8 = 0;
          uVar9 = param_2;
          if ((uVar11 & 1) != 0) {
                    // WARNING: Load size is inaccurate
            lVar10 = *(long *)(*param_4 + lVar10);
            uVar9 = param_2 | 1;
          }
          if ((uVar12 == 0) || (uVar12 < (ulong)((long)param_4 + lVar10) != bVar16)) {
            if (((uint)uVar11 >> 1 & 1) == 0) {
              if ((param_1 == -2) && ((local_4 & 3) == 0)) goto LAB_0011a3e8;
              uVar9 = uVar9 & 0xfffffffd;
            }
            cVar2 = (**(code **)(**(long **)(p_Var15 + 8) + 0x38))
                              (*(long **)(p_Var15 + 8),param_1,uVar9,param_3,(long)param_4 + lVar10,
                               param_5,param_6,&local_18);
            uVar5 = local_8;
            uVar9 = local_c | *(uint *)(param_7 + 0xc);
            *(uint *)(param_7 + 0xc) = uVar9;
            if ((local_8 & 0xfffffffb) == 2) {
              *(long *)param_7 = local_18;
              *(uint *)(param_7 + 8) = local_10;
              *(uint *)(param_7 + 0x10) = local_8;
              return cVar2;
            }
            lVar10 = *(long *)param_7;
            if (cVar13 == '\0') {
              if (lVar10 == 0) {
                *(long *)param_7 = local_18;
                *(uint *)(param_7 + 8) = local_10;
                if (((uVar9 != 0) && (local_18 != 0)) && ((*(uint *)(this + 0x10) & 1) == 0)) {
                  return cVar2;
                }
              }
              else {
LAB_0011a3cc:
                if (lVar10 == local_18) {
                  *(uint *)(param_7 + 8) = *(uint *)(param_7 + 8) | local_10;
                  cVar2 = cVar13;
                }
                else if ((cVar2 != '\0') || (cVar2 = cVar13, local_18 != 0)) goto LAB_0011a444;
              }
            }
            else {
              if (lVar10 != 0) goto LAB_0011a3cc;
              cVar2 = cVar13;
              if (local_18 == 0) goto LAB_0011a3e0;
LAB_0011a444:
              uVar6 = *(uint *)(param_7 + 0x10);
              if (((int)uVar9 < 4) ||
                 (((uVar9 & 1) != 0 && ((*(uint *)(param_7 + 0x14) >> 1 & 1) != 0)))) {
                if (0 < (int)uVar6) {
LAB_0011a46c:
                  if (0 < (int)uVar5) {
LAB_0011a474:
                    uVar9 = uVar6 ^ uVar5;
                    local_8 = uVar5;
                    goto joined_r0x0011a500;
                  }
                  if ((3 < (int)uVar6) &&
                     (((uVar6 & 1) == 0 || ((*(uint *)(this + 0x10) >> 1 & 1) == 0)))) {
                    if (3 < (int)(uVar6 ^ 1)) {
                      uVar9 = uVar6 & 2;
                      uVar5 = uVar6;
                      goto LAB_0011a48c;
                    }
                    goto LAB_0011a510;
                  }
                  if (param_1 < 0) {
                    if (param_1 == -2) goto LAB_0011a534;
                    uVar5 = (**(code **)(*(long *)param_3 + 0x40))
                                      (param_3,param_1,local_18,param_5,param_6);
                    goto LAB_0011a474;
                  }
                  if (param_6 != (void *)(local_18 + param_1)) {
                    uVar4 = uVar6 ^ 1;
                    goto LAB_0011a538;
                  }
                  local_8 = uVar6 & 6;
                  if (3 < (int)(uVar6 ^ 6)) goto LAB_0011a778;
LAB_0011a508:
                  if (3 < (int)local_8) {
                    *(undefined8 *)param_7 = 0;
                    *(undefined4 *)(param_7 + 0x10) = 2;
                    return '\x01';
                  }
                  goto LAB_0011a510;
                }
                if (((int)local_8 < 4) ||
                   (((local_8 & 1) != 0 && ((*(uint *)(this + 0x10) >> 1 & 1) != 0)))) {
                  if (param_1 < 0) {
                    if (param_1 != -2) {
                      uVar6 = (**(code **)(*(long *)param_3 + 0x40))
                                        (param_3,param_1,lVar10,param_5,param_6);
                      goto LAB_0011a46c;
                    }
                    if ((int)local_8 < 1) goto LAB_0011a514;
LAB_0011a694:
                    uVar6 = 1;
                    goto LAB_0011a474;
                  }
                  if (param_6 == (void *)(lVar10 + param_1)) {
                    uVar6 = 6;
                    if (0 < (int)local_8) goto LAB_0011a474;
                    goto LAB_0011a488;
                  }
                  if (0 < (int)local_8) goto LAB_0011a694;
                  if (param_6 != (void *)(local_18 + param_1)) {
                    uVar6 = 1;
                    uVar4 = 0;
                    goto LAB_0011a538;
                  }
LAB_0011a778:
                  uVar5 = 0;
                  uVar9 = 2;
                  local_8 = 6;
                }
                else {
                  uVar6 = 1;
                  if ((int)(local_8 ^ 1) < 4) goto LAB_0011a504;
LAB_0011a4c0:
                  uVar9 = local_8 & 2;
                  uVar5 = local_8;
                }
                *(long *)param_7 = local_18;
                cVar13 = '\0';
                *(uint *)(param_7 + 8) = local_10;
                uVar6 = local_8;
LAB_0011a48c:
                *(uint *)(param_7 + 0x10) = uVar6;
                if (uVar9 != 0) {
                  return '\0';
                }
                if ((uVar5 & 1) == 0) {
                  return '\0';
                }
                uVar9 = *(uint *)(param_7 + 0xc);
                cVar2 = cVar13;
              }
              else {
                if (uVar6 == 0) {
                  if (local_8 != 0) {
                    uVar6 = 1;
LAB_0011a4f0:
                    uVar9 = uVar6 ^ local_8;
joined_r0x0011a500:
                    if (3 < (int)uVar9) {
                      if (3 < (int)local_8) goto LAB_0011a4c0;
LAB_0011a488:
                      uVar9 = uVar6 & 2;
                      uVar5 = uVar6;
                      goto LAB_0011a48c;
                    }
LAB_0011a504:
                    local_8 = uVar6 & local_8;
                    goto LAB_0011a508;
                  }
                }
                else {
                  if (local_8 != 0) goto LAB_0011a4f0;
LAB_0011a534:
                  uVar4 = uVar6 ^ 1;
LAB_0011a538:
                  uVar9 = uVar6 & 2;
                  uVar5 = uVar6;
                  if (3 < (int)uVar4) goto LAB_0011a48c;
LAB_0011a510:
                  uVar9 = *(uint *)(param_7 + 0xc);
                }
LAB_0011a514:
                *(undefined8 *)param_7 = 0;
                *(undefined4 *)(param_7 + 0x10) = 1;
                cVar2 = '\x01';
              }
            }
LAB_0011a3e0:
            cVar13 = cVar2;
            if (uVar9 == 4) {
              return cVar2;
            }
          }
          else {
            bVar17 = 1;
          }
LAB_0011a3e8:
          uVar14 = uVar14 + 1;
          p_Var15 = p_Var15 + -0x10;
        } while (uVar8 != uVar14);
      }
      bVar1 = bVar17 & bVar16;
      bVar17 = 1;
      bVar16 = false;
      if (bVar1 == 0) {
        return cVar13;
      }
    } while( true );
  }
LAB_0011a614:
  *(void **)param_7 = param_4;
  *(__sub_kind *)(param_7 + 8) = param_2;
  if (param_1 < 0) {
    if (param_1 == -2) {
      *(undefined4 *)(param_7 + 0x10) = 1;
    }
  }
  else {
    uVar7 = 6;
    if (param_6 != (void *)((long)param_4 + param_1)) {
      uVar7 = 1;
    }
    *(undefined4 *)(param_7 + 0x10) = uVar7;
  }
  return '\0';
}



// __cxxabiv1::__vmi_class_type_info::__do_upcast(__cxxabiv1::__class_type_info const*, void const*,
// __cxxabiv1::__class_type_info::__upcast_result&) const

char __thiscall
__cxxabiv1::__vmi_class_type_info::__do_upcast
          (__vmi_class_type_info *this,__class_type_info *param_1,void *param_2,
          __upcast_result *param_3)

{
  uint uVar1;
  char cVar2;
  int iVar3;
  char *__s1;
  ulong uVar4;
  long lVar5;
  __vmi_class_type_info *p_Var6;
  ulong uVar7;
  uint uVar8;
  ulong uVar9;
  long local_18;
  uint local_10;
  uint local_c;
  long local_8;
  
  cVar2 = __class_type_info::__do_upcast((__class_type_info *)this,param_1,param_2,param_3);
  if (cVar2 == '\0') {
    uVar8 = *(uint *)(param_3 + 0xc);
    if ((uVar8 >> 4 & 1) != 0) {
      uVar8 = *(uint *)(this + 0x10);
    }
    uVar7 = 0;
    uVar9 = (ulong)*(uint *)(this + 0x14);
    p_Var6 = this + uVar9 * 0x10;
    if (uVar9 != 0) {
      do {
        uVar4 = *(ulong *)(p_Var6 + 0x10);
        local_18 = 0;
        local_10 = 0;
        local_8 = 0;
        if (((uVar4 >> 1 & 1) != 0) || ((uVar8 & 1) != 0)) {
          if (param_2 == (void *)0x0) {
            lVar5 = 0;
          }
          else {
            lVar5 = (long)uVar4 >> 8;
            if ((uVar4 & 1) != 0) {
                    // WARNING: Load size is inaccurate
              lVar5 = *(long *)(*param_2 + lVar5);
            }
            lVar5 = (long)param_2 + lVar5;
          }
          local_c = uVar8;
          cVar2 = (**(code **)(**(long **)(p_Var6 + 8) + 0x30))
                            (*(long **)(p_Var6 + 8),param_1,lVar5,&local_18);
          if (cVar2 != '\0') {
            if (((uVar4 & 1) != 0) && (local_8 == 0x10)) {
              local_8 = *(long *)(p_Var6 + 8);
            }
            if (((uVar4 >> 1 & 1) == 0) && (3 < (int)local_10)) {
              local_10 = local_10 & 0xfffffffd;
            }
            lVar5 = *(long *)(param_3 + 0x10);
            if (lVar5 == 0) {
              *(long *)param_3 = local_18;
              *(ulong *)(param_3 + 8) = CONCAT44(local_c,local_10);
              *(long *)(param_3 + 0x10) = local_8;
              uVar1 = *(uint *)(param_3 + 8);
              if ((int)uVar1 < 4) {
                return cVar2;
              }
              if ((uVar1 >> 1 & 1) == 0) {
                if ((uVar1 & 1) == 0) {
                  return cVar2;
                }
                uVar1 = *(uint *)(this + 0x10) >> 1;
              }
              else {
                uVar1 = *(uint *)(this + 0x10);
              }
              if ((uVar1 & 1) == 0) {
                return cVar2;
              }
            }
            else {
              if (*(long *)param_3 != local_18) {
                *(undefined8 *)param_3 = 0;
                *(undefined4 *)(param_3 + 8) = 2;
                return cVar2;
              }
              if (*(long *)param_3 == 0) {
                if ((local_8 == 0x10) || (lVar5 == 0x10)) {
LAB_0011a9c4:
                  *(undefined4 *)(param_3 + 8) = 2;
                  return cVar2;
                }
                __s1 = *(char **)(local_8 + 8);
                if ((__s1 != *(char **)(lVar5 + 8)) &&
                   ((*__s1 == '*' || (iVar3 = strcmp(__s1,*(char **)(lVar5 + 8)), iVar3 != 0))))
                goto LAB_0011a9c4;
              }
              *(uint *)(param_3 + 8) = *(uint *)(param_3 + 8) | local_10;
            }
          }
        }
        uVar7 = uVar7 + 1;
        p_Var6 = p_Var6 + -0x10;
      } while (uVar9 != uVar7);
    }
    cVar2 = *(int *)(param_3 + 8) != 0;
  }
  return cVar2;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked
// void std::__convert_to_v<float>(char const*, float&, std::_Ios_Iostate&, int* const&)

void std::__convert_to_v<float>(char *param_1,float *param_2,_Ios_Iostate *param_3,int **param_4)

{
  char *__s;
  size_t sVar1;
  char *__locale;
  float fVar2;
  float fVar3;
  char *local_8;
  
  __s = setlocale(6,(char *)0x0);
  if (__s == (char *)0x0) {
    __locale = (char *)0x0;
  }
  else {
    sVar1 = strlen(__s);
                    // try { // try from 0011aa48 to 0011aa77 has its CatchHandler @ 0011ab0c
    __locale = (char *)operator_new__(sVar1 + 1);
    memcpy(__locale,__s,sVar1 + 1);
    setlocale(6,"C");
  }
  fVar2 = strtof(param_1,&local_8);
  *param_2 = fVar2;
  if ((local_8 == param_1) || (*local_8 != '\0')) {
    *param_2 = 0.0;
    *(undefined4 *)param_3 = 4;
  }
  else {
    fVar3 = 3.402823e+38;
    if ((3.402823e+38 < fVar2) || (fVar2 < -3.402823e+38)) {
      if (fVar2 <= 0.0) {
        fVar3 = -3.402823e+38;
      }
      *param_2 = fVar3;
      *(undefined4 *)param_3 = 4;
    }
  }
  setlocale(6,__locale);
  if (__locale != (char *)0x0) {
    operator_delete__(__locale);
  }
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked
// void std::__convert_to_v<double>(char const*, double&, std::_Ios_Iostate&, int* const&)

void std::__convert_to_v<double>(char *param_1,double *param_2,_Ios_Iostate *param_3,int **param_4)

{
  char *__s;
  size_t sVar1;
  char *__locale;
  double dVar2;
  double dVar3;
  char *local_8;
  
  __s = setlocale(6,(char *)0x0);
  if (__s == (char *)0x0) {
    __locale = (char *)0x0;
  }
  else {
    sVar1 = strlen(__s);
                    // try { // try from 0011ab68 to 0011ab6b has its CatchHandler @ 0011ac2c
    __locale = (char *)operator_new__(sVar1 + 1);
    memcpy(__locale,__s,sVar1 + 1);
    setlocale(6,"C");
  }
  dVar2 = strtod(param_1,&local_8);
  *param_2 = dVar2;
  if ((local_8 == param_1) || (*local_8 != '\0')) {
    *param_2 = 0.0;
    *(undefined4 *)param_3 = 4;
  }
  else {
    dVar3 = 1.797693134862316e+308;
    if ((1.797693134862316e+308 < dVar2) || (dVar2 < -1.797693134862316e+308)) {
      if (dVar2 <= 0.0) {
        dVar3 = -1.797693134862316e+308;
      }
      *param_2 = dVar3;
      *(undefined4 *)param_3 = 4;
    }
  }
  setlocale(6,__locale);
  if (__locale != (char *)0x0) {
    operator_delete__(__locale);
  }
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked
// void std::__convert_to_v<long double>(char const*, long double&, std::_Ios_Iostate&, int* const&)

void std::__convert_to_v<>(char *param_1,longdouble *param_2,_Ios_Iostate *param_3,int **param_4)

{
  int iVar1;
  char *__s;
  size_t sVar2;
  char *__locale;
  double dVar3;
  longdouble in_register_00005008;
  longdouble lVar4;
  char *local_8;
  
  __s = setlocale(6,(char *)0x0);
  if (__s == (char *)0x0) {
    __locale = (char *)0x0;
  }
  else {
    sVar2 = strlen(__s);
                    // try { // try from 0011ac90 to 0011acbf has its CatchHandler @ 0011ad84
    __locale = (char *)operator_new__(sVar2 + 1);
    memcpy(__locale,__s,sVar2 + 1);
    setlocale(6,"C");
  }
  dVar3 = strtold(param_1,&local_8);
  param_2[1] = in_register_00005008;
  *param_2 = (longdouble)dVar3;
  if ((local_8 == param_1) || (*local_8 != '\0')) {
    param_2[1] = 0.0;
    *param_2 = 0.0;
    *(undefined4 *)param_3 = 4;
  }
  else {
    lVar4 = NAN;
    iVar1 = __getf2();
    if (iVar1 < 1) {
      iVar1 = __lttf2(dVar3,0xffffffffffffffff);
      if (-1 < iVar1) goto LAB_0011ace8;
    }
    iVar1 = __getf2(dVar3,0);
    if (iVar1 < 1) {
      lVar4 = -NAN;
    }
    param_2[1] = lVar4;
    *param_2 = -NAN;
    *(undefined4 *)param_3 = 4;
  }
LAB_0011ace8:
  setlocale(6,__locale);
  if (__locale != (char *)0x0) {
    operator_delete__(__locale);
  }
  return;
}



// std::bad_array_length::what() const

char * std::bad_array_length::what(void)

{
  return "std::bad_array_length";
}



// std::bad_array_length::~bad_array_length()

void __thiscall std::bad_array_length::~bad_array_length(bad_array_length *this)

{
  *(undefined ***)this = &PTR__bad_array_length_00135a00;
  bad_alloc::~bad_alloc((bad_alloc *)this);
  return;
}



// std::bad_array_length::~bad_array_length()

void __thiscall std::bad_array_length::~bad_array_length(bad_array_length *this)

{
  ~bad_array_length(this);
  operator_delete(this);
  return;
}



// std::bad_array_new_length::what() const

char * std::bad_array_new_length::what(void)

{
  return "std::bad_array_new_length";
}



// std::bad_array_new_length::~bad_array_new_length()

void __thiscall std::bad_array_new_length::~bad_array_new_length(bad_array_new_length *this)

{
  *(undefined ***)this = &PTR__bad_array_new_length_00135a50;
  bad_alloc::~bad_alloc((bad_alloc *)this);
  return;
}



// std::bad_array_new_length::~bad_array_new_length()

void __thiscall std::bad_array_new_length::~bad_array_new_length(bad_array_new_length *this)

{
  ~bad_array_new_length(this);
  operator_delete(this);
  return;
}



undefined4 __getf2(ulong param_1,ulong param_2)

{
  undefined8 uVar1;
  ulong uVar2;
  ulong uVar3;
  ulong uVar4;
  bool bVar5;
  bool bVar6;
  undefined4 uVar7;
  ulong uVar8;
  ulong uVar9;
  ulong in_register_00005008;
  ulong in_register_00005028;
  
  uVar1 = fpcr;
  uVar8 = in_register_00005008 >> 0x30 & 0x7fff;
  uVar3 = in_register_00005008 & 0xffffffffffff;
  uVar4 = in_register_00005028 & 0xffffffffffff;
  uVar9 = in_register_00005028 >> 0x30 & 0x7fff;
  if (uVar8 == 0x7fff) {
    if ((uVar3 | param_1) != 0) goto LAB_0011af70;
    bVar5 = false;
    if (uVar9 == 0x7fff) goto LAB_0011aeb8;
  }
  else {
    if (uVar9 == 0x7fff) {
LAB_0011aeb8:
      if ((uVar4 | param_2) != 0) {
LAB_0011af70:
        __sfp_handle_exceptions(1);
        return 0xfffffffe;
      }
    }
    bVar5 = false;
    if (uVar8 == 0) {
      bVar5 = (uVar3 | param_1) == 0;
    }
  }
  bVar6 = false;
  if (uVar9 == 0) {
    bVar6 = (uVar4 | param_2) == 0;
  }
  if ((bool)(bVar6 & bVar5)) {
    return 0;
  }
  uVar2 = in_register_00005028 >> 0x3f;
  if (!bVar5) {
    uVar2 = -((long)in_register_00005008 >> 0x3f);
    if (((bVar6) || (uVar2 != in_register_00005028 >> 0x3f)) || (uVar9 < uVar8)) {
LAB_0011af34:
      if (uVar2 == 0) {
        return 1;
      }
      return 0xffffffff;
    }
    if (uVar9 <= uVar8) {
      if ((uVar4 < uVar3) || ((uVar3 == uVar4 && (param_2 < param_1)))) goto LAB_0011af34;
      if ((uVar4 <= uVar3) && ((uVar3 != uVar4 || (param_2 <= param_1)))) {
        return 0;
      }
    }
  }
  uVar7 = 0xffffffff;
  if (uVar2 != 0) {
    uVar7 = 1;
  }
  return uVar7;
}



undefined4 __lttf2(ulong param_1,ulong param_2)

{
  undefined8 uVar1;
  ulong uVar2;
  ulong uVar3;
  ulong uVar4;
  bool bVar5;
  bool bVar6;
  undefined4 uVar7;
  ulong uVar8;
  ulong uVar9;
  ulong in_register_00005008;
  ulong in_register_00005028;
  
  uVar1 = fpcr;
  uVar8 = in_register_00005008 >> 0x30 & 0x7fff;
  uVar3 = in_register_00005008 & 0xffffffffffff;
  uVar4 = in_register_00005028 & 0xffffffffffff;
  uVar9 = in_register_00005028 >> 0x30 & 0x7fff;
  if (uVar8 == 0x7fff) {
    if ((uVar3 | param_1) != 0) goto LAB_0011b0ac;
    bVar5 = false;
    if (uVar9 == 0x7fff) goto LAB_0011aff4;
  }
  else {
    if (uVar9 == 0x7fff) {
LAB_0011aff4:
      if ((uVar4 | param_2) != 0) {
LAB_0011b0ac:
        __sfp_handle_exceptions(1);
        return 2;
      }
    }
    bVar5 = false;
    if (uVar8 == 0) {
      bVar5 = (uVar3 | param_1) == 0;
    }
  }
  bVar6 = false;
  if (uVar9 == 0) {
    bVar6 = (uVar4 | param_2) == 0;
  }
  if ((bool)(bVar6 & bVar5)) {
    return 0;
  }
  uVar2 = in_register_00005028 >> 0x3f;
  if (!bVar5) {
    uVar2 = -((long)in_register_00005008 >> 0x3f);
    if (((bVar6) || (uVar2 != in_register_00005028 >> 0x3f)) || (uVar9 < uVar8)) {
LAB_0011b070:
      if (uVar2 == 0) {
        return 1;
      }
      return 0xffffffff;
    }
    if (uVar9 <= uVar8) {
      if ((uVar4 < uVar3) || ((uVar3 == uVar4 && (param_2 < param_1)))) goto LAB_0011b070;
      if ((uVar4 <= uVar3) && ((uVar3 != uVar4 || (param_2 <= param_1)))) {
        return 0;
      }
    }
  }
  uVar7 = 0xffffffff;
  if (uVar2 != 0) {
    uVar7 = 1;
  }
  return uVar7;
}



void FUN_0011b0d0(byte *param_1,ulong *param_2)

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



void FUN_0011b0f8(byte *param_1,ulong *param_2)

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



ulong ** FUN_0011b138(byte param_1,ulong **param_2,ulong **param_3,ulong **param_4)

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
      ppuVar1 = (ulong **)FUN_0011b0d0(param_3,&local_8);
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
      ppuVar1 = (ulong **)FUN_0011b0f8(param_3,&local_8);
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



void FUN_0011b228(void)

{
  DAT_00147db0 = 8;
  DAT_00147db1 = 8;
  DAT_00147db2 = 8;
  DAT_00147db3 = 8;
  DAT_00147db4 = 8;
  DAT_00147db5 = 8;
  DAT_00147db6 = 8;
  DAT_00147db7 = 8;
  DAT_00147db8 = 8;
  DAT_00147db9 = 8;
  DAT_00147dba = 8;
  DAT_00147dbb = 8;
  DAT_00147dbc = 8;
  DAT_00147dbd = 8;
  DAT_00147dbe = 8;
  DAT_00147dbf = 8;
  DAT_00147dc0 = 8;
  DAT_00147dc1 = 8;
  DAT_00147dc2 = 8;
  DAT_00147dc3 = 8;
  DAT_00147dc4 = 8;
  DAT_00147dc5 = 8;
  DAT_00147dc6 = 8;
  DAT_00147dc7 = 8;
  DAT_00147dc8 = 8;
  DAT_00147dc9 = 8;
  DAT_00147dca = 8;
  DAT_00147dcb = 8;
  DAT_00147dcc = 8;
  DAT_00147dcd = 8;
  DAT_00147dce = 8;
  DAT_00147dcf = 8;
  DAT_00147df0 = 8;
  DAT_00147df1 = 8;
  DAT_00147df2 = 8;
  DAT_00147df3 = 8;
  DAT_00147df4 = 8;
  DAT_00147df5 = 8;
  DAT_00147df6 = 8;
  DAT_00147df7 = 8;
  DAT_00147df8 = 8;
  DAT_00147df9 = 8;
  DAT_00147dfa = 8;
  DAT_00147dfb = 8;
  DAT_00147dfc = 8;
  DAT_00147dfd = 8;
  DAT_00147dfe = 8;
  DAT_00147dff = 8;
  DAT_00147e00 = 8;
  DAT_00147e01 = 8;
  DAT_00147e02 = 8;
  DAT_00147e03 = 8;
  DAT_00147e04 = 8;
  DAT_00147e05 = 8;
  DAT_00147e06 = 8;
  DAT_00147e07 = 8;
  DAT_00147e08 = 8;
  DAT_00147e09 = 8;
  DAT_00147e0a = 8;
  DAT_00147e0b = 8;
  DAT_00147e0c = 8;
  DAT_00147e0d = 8;
  DAT_00147e0e = 8;
  DAT_00147e0f = 8;
  DAT_00147e10 = 8;
  return;
}



void FUN_0011b33c(long param_1,undefined8 param_2,undefined8 *param_3)

{
  if (DAT_00147dcf == '\b') {
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
      if ((&DAT_00147db0)[param_2] != '\b') goto LAB_0011b388;
      puVar1 = (undefined8 *)*puVar1;
    }
    return puVar1;
  }
LAB_0011b388:
                    // WARNING: Subroutine does not return
  abort();
}



long FUN_0011b3d0(long param_1,long param_2)

{
  void **__dest;
  void **__src;
  long lVar1;
  undefined auStack_8 [8];
  
  if ((((*(ulong *)(param_2 + 0x340) >> 0x3e & 1) == 0) || (*(char *)(param_2 + 0x377) == '\0')) &&
     (*(long *)(param_2 + 0xf8) == 0)) {
    FUN_0011b33c(param_2,*(undefined8 *)(param_2 + 0x310),auStack_8);
  }
  lVar1 = 0;
  while( true ) {
    __dest = *(void ***)(param_1 + lVar1 * 8);
    __src = *(void ***)(param_2 + lVar1 * 8);
    if (*(char *)(param_1 + lVar1 + 0x358) != '\0') break;
    if ((*(char *)(param_2 + lVar1 + 0x358) == '\0') || (__dest == (void **)0x0)) {
      if ((__dest != (void **)0x0 && __src != (void **)0x0) && (__src != __dest)) {
        memcpy(__dest,__src,(ulong)(byte)(&DAT_00147db0)[lVar1]);
      }
    }
    else {
      if ((&DAT_00147db0)[lVar1] != '\b') break;
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
LAB_0011b4f4:
                    // WARNING: Subroutine does not return
    abort();
  }
  if (((*(ulong *)(param_1 + 0x340) >> 0x3e & 1) == 0) ||
     (*(char *)(param_1 + param_2 + 0x358) == '\0')) {
    if ((&DAT_00147db0)[param_2] != '\b') goto LAB_0011b4f4;
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



undefined8 FUN_0011b5a8(byte param_1,undefined8 param_2)

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
LAB_0011b610:
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
        goto LAB_0011b610;
      }
    }
  }
  return 0;
}



void FUN_0011b620(byte *param_1,byte *param_2,long param_3,void *param_4)

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
  long *plVar12;
  undefined4 uVar13;
  undefined *puVar14;
  ulong uVar15;
  undefined *puVar16;
  ulong local_18;
  long local_10;
  long local_8;
  
  *(undefined8 *)((long)param_4 + 0x620) = 0;
  puVar4 = &stack0xffffffffffffff70;
  puVar16 = (undefined *)0x0;
LAB_0011b668:
  while( true ) {
    while( true ) {
      pbVar5 = param_1;
      if ((param_2 <= pbVar5) ||
         (uVar10 = *(ulong *)((long)param_4 + 0x648),
         (ulong)(*(long *)(param_3 + 0x318) - (*(long *)(param_3 + 0x340) >> 0x3f)) <= uVar10)) {
        return;
      }
      bVar2 = *pbVar5;
      uVar15 = (ulong)bVar2;
      param_1 = pbVar5 + 1;
      bVar1 = bVar2 & 0xc0;
      if (bVar1 != 0x40) break;
      *(ulong *)((long)param_4 + 0x648) =
           uVar10 + (uVar15 & 0x3f) * *(long *)((long)param_4 + 0x660);
    }
    if (bVar1 == 0x80) break;
    if (bVar1 != 0xc0) goto code_r0x0011b6e8;
    *(undefined4 *)((long)param_4 + (uVar15 & 0x3f) * 0x10 + 8) = 0;
  }
  local_18 = uVar15 & 0x3f;
  goto LAB_0011b788;
code_r0x0011b6e8:
  switch(bVar2) {
  case 0:
    goto LAB_0011b668;
  case 1:
    uVar3 = *(undefined *)((long)param_4 + 0x670);
    uVar8 = FUN_0011b5a8(uVar3,param_3);
    param_1 = (byte *)FUN_0011b138(uVar3,uVar8,param_1,&local_8);
    *(long *)((long)param_4 + 0x648) = local_8;
    goto LAB_0011b668;
  case 2:
    *(ulong *)((long)param_4 + 0x648) = uVar10 + (ulong)pbVar5[1] * *(long *)((long)param_4 + 0x660)
    ;
    param_1 = pbVar5 + 2;
    goto LAB_0011b668;
  case 3:
    *(ulong *)((long)param_4 + 0x648) =
         uVar10 + (ulong)*(ushort *)(pbVar5 + 1) * *(long *)((long)param_4 + 0x660);
    param_1 = pbVar5 + 3;
    goto LAB_0011b668;
  case 4:
    *(ulong *)((long)param_4 + 0x648) =
         uVar10 + (ulong)*(uint *)(pbVar5 + 1) * *(long *)((long)param_4 + 0x660);
    param_1 = pbVar5 + 5;
    goto LAB_0011b668;
  case 5:
    param_1 = (byte *)FUN_0011b0d0(param_1,&local_18);
LAB_0011b788:
    param_1 = (byte *)FUN_0011b0d0(param_1,&local_10);
    lVar11 = *(long *)((long)param_4 + 0x658);
    lVar9 = local_10;
    break;
  case 6:
  case 8:
    param_1 = (byte *)FUN_0011b0d0(param_1,&local_18);
    if (local_18 < 0x62) {
      *(undefined4 *)((long)param_4 + local_18 * 0x10 + 8) = 0;
    }
    goto LAB_0011b668;
  case 7:
    param_1 = (byte *)FUN_0011b0d0(param_1,&local_18);
    if (local_18 < 0x62) {
      *(undefined4 *)((long)param_4 + local_18 * 0x10 + 8) = 6;
    }
    goto LAB_0011b668;
  case 9:
    uVar8 = FUN_0011b0d0(param_1,&local_18);
    param_1 = (byte *)FUN_0011b0d0(uVar8,&local_8);
    if (0x61 < local_18) goto LAB_0011b668;
    lVar7 = local_18 * 0x10;
    *(undefined4 *)((long)param_4 + lVar7 + 8) = 2;
    lVar9 = local_8;
    goto LAB_0011bae4;
  case 10:
    if (puVar16 == (undefined *)0x0) {
      puVar14 = puVar4 + -0x660;
      puVar4 = puVar4 + -0x660;
    }
    else {
      puVar14 = puVar4;
      puVar4 = puVar16;
      puVar16 = *(undefined **)(puVar16 + 0x620);
    }
    pvVar6 = memcpy(puVar4,param_4,0x648);
    *(void **)((long)param_4 + 0x620) = pvVar6;
    puVar4 = puVar14;
    goto LAB_0011b668;
  case 0xb:
    puVar14 = *(undefined **)((long)param_4 + 0x620);
    memcpy(param_4,puVar14,0x648);
    *(undefined **)(puVar14 + 0x620) = puVar16;
    puVar16 = puVar14;
    goto LAB_0011b668;
  case 0xc:
    uVar8 = FUN_0011b0d0(param_1,&local_10);
    *(long *)((long)param_4 + 0x630) = local_10;
    param_1 = (byte *)FUN_0011b0d0(uVar8,&local_10);
    *(long *)((long)param_4 + 0x628) = local_10;
    goto LAB_0011b8cc;
  case 0xd:
    param_1 = (byte *)FUN_0011b0d0(param_1,&local_10);
    *(long *)((long)param_4 + 0x630) = local_10;
LAB_0011b8cc:
    *(undefined4 *)((long)param_4 + 0x640) = 1;
    goto LAB_0011b668;
  case 0xe:
    param_1 = (byte *)FUN_0011b0d0(param_1,&local_10);
    lVar9 = local_10;
    goto LAB_0011b998;
  case 0xf:
    *(byte **)((long)param_4 + 0x638) = param_1;
    *(undefined4 *)((long)param_4 + 0x640) = 2;
    goto LAB_0011ba48;
  case 0x10:
    param_1 = (byte *)FUN_0011b0d0(param_1,&local_18);
    if (0x61 < local_18) goto LAB_0011ba48;
    uVar13 = 3;
    goto LAB_0011ba40;
  case 0x11:
    uVar8 = FUN_0011b0d0(param_1,&local_18);
    param_1 = (byte *)FUN_0011b0f8(uVar8,&local_8);
    lVar11 = *(long *)((long)param_4 + 0x658);
    lVar9 = local_8;
    break;
  case 0x12:
    uVar8 = FUN_0011b0d0(param_1,&local_10);
    *(long *)((long)param_4 + 0x630) = local_10;
    param_1 = (byte *)FUN_0011b0f8(uVar8,&local_8);
    *(undefined4 *)((long)param_4 + 0x640) = 1;
    goto LAB_0011b98c;
  case 0x13:
    param_1 = (byte *)FUN_0011b0f8(param_1,&local_8);
LAB_0011b98c:
    lVar9 = local_8 * *(long *)((long)param_4 + 0x658);
LAB_0011b998:
    *(long *)((long)param_4 + 0x628) = lVar9;
    goto LAB_0011b668;
  case 0x14:
    uVar8 = FUN_0011b0d0(param_1,&local_18);
    param_1 = (byte *)FUN_0011b0d0(uVar8,&local_10);
    lVar11 = *(long *)((long)param_4 + 0x658);
    lVar9 = local_10;
    goto LAB_0011b9f8;
  case 0x15:
    uVar8 = FUN_0011b0d0(param_1,&local_18);
    param_1 = (byte *)FUN_0011b0f8(uVar8,&local_8);
    lVar11 = *(long *)((long)param_4 + 0x658);
    lVar9 = local_8;
LAB_0011b9f8:
    if (0x61 < local_18) goto LAB_0011b668;
    lVar7 = local_18 * 0x10;
    *(undefined4 *)((long)param_4 + lVar7 + 8) = 4;
    lVar9 = lVar9 * lVar11;
    goto LAB_0011bae4;
  case 0x16:
    param_1 = (byte *)FUN_0011b0d0(param_1,&local_18);
    if (0x61 < local_18) goto LAB_0011ba48;
    uVar13 = 5;
LAB_0011ba40:
    *(undefined4 *)((long)param_4 + local_18 * 0x10 + 8) = uVar13;
    *(byte **)((long)param_4 + local_18 * 0x10) = param_1;
LAB_0011ba48:
    lVar9 = FUN_0011b0d0(param_1,&local_10);
    param_1 = (byte *)(lVar9 + local_10);
    goto LAB_0011b668;
  default:
    goto switchD_0011b6f4_caseD_17;
  case 0x2d:
    lVar9 = 0x10;
    local_18 = 0x10;
    lVar7 = 0;
    plVar12 = (long *)((long)param_4 + 0x100);
    do {
      *(undefined4 *)(plVar12 + 1) = 1;
      lVar9 = lVar9 + 1;
      *plVar12 = lVar7;
      lVar7 = lVar7 + 8;
      plVar12 = plVar12 + 2;
    } while (lVar9 != 0x20);
    goto LAB_0011b668;
  case 0x2e:
    param_1 = (byte *)FUN_0011b0d0(param_1,&local_10);
    *(long *)(param_3 + 0x350) = local_10;
    goto LAB_0011b668;
  case 0x2f:
    uVar8 = FUN_0011b0d0(param_1,&local_18);
    param_1 = (byte *)FUN_0011b0d0(uVar8,&local_10);
    lVar9 = *(long *)((long)param_4 + 0x658);
    if (0x61 < local_18) goto LAB_0011b668;
    lVar7 = local_18 * 0x10;
    *(undefined4 *)((long)param_4 + lVar7 + 8) = 1;
    lVar9 = -(lVar9 * local_10);
    goto LAB_0011bae4;
  }
  if (0x61 < local_18) goto LAB_0011b668;
  lVar7 = local_18 * 0x10;
  *(undefined4 *)((long)param_4 + lVar7 + 8) = 1;
  lVar9 = lVar9 * lVar11;
LAB_0011bae4:
  *(long *)((long)param_4 + lVar7) = lVar9;
  goto LAB_0011b668;
switchD_0011b6f4_caseD_17:
                    // WARNING: Subroutine does not return
  abort();
}



undefined4 FUN_0011bb18(long param_1,long *param_2)

{
  byte bVar1;
  char cVar2;
  uint *puVar3;
  long *plVar4;
  long *plVar5;
  size_t sVar6;
  undefined8 uVar7;
  byte *pbVar8;
  byte *pbVar9;
  byte *pbVar10;
  long lVar11;
  ulong uVar12;
  int *piVar13;
  long lVar14;
  int iVar15;
  char *pcVar16;
  uint *puVar17;
  long lVar18;
  char *pcVar19;
  ulong local_18;
  long local_10;
  long local_8;
  
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
    lVar11 = *(long *)(param_1 + 0x310);
    param_2[0xc6] = 0x1f;
    lVar18 = lVar11 + 0x130;
    param_2[0xc5] = 0x130;
    *(undefined4 *)(param_2 + 200) = 1;
    lVar14 = 8;
    plVar5 = param_2;
    do {
      *(undefined4 *)(plVar5 + 1) = 1;
      plVar4 = plVar5 + 2;
      *plVar5 = lVar14;
      lVar14 = lVar14 + 8;
      plVar5 = plVar4;
    } while (plVar4 != param_2 + 0x3e);
    for (piVar13 = (int *)(lVar11 + 0x250); *piVar13 != 0;
        piVar13 = (int *)((long)piVar13 + (ulong)(uint)piVar13[1])) {
      if (*piVar13 == 0x46508001) {
        plVar5 = param_2 + 0x81;
        do {
          *(undefined4 *)plVar5 = 1;
          plVar4 = plVar5 + 2;
          plVar5[-1] = (long)piVar13 + ((-0x3f8 - lVar18) - (long)param_2) + (long)plVar5;
          plVar5 = plVar4;
        } while (plVar4 != param_2 + 0xc1);
      }
    }
    *(undefined *)((long)param_2 + 0x673) = 1;
    param_2[0x3e] = (lVar11 + 0x230) - lVar18;
    *(undefined4 *)(param_2 + 0xc1) = 4;
    lVar14 = *(long *)(lVar11 + 0x238);
    *(undefined4 *)(param_2 + 0x3f) = 1;
    param_2[0xc0] = lVar14 - lVar18;
    param_2[0xcd] = 0x60;
    return 0;
  }
  param_2[0xc9] = *(long *)(param_1 + 0x338);
  puVar17 = (uint *)((long)puVar3 + (4 - (long)(int)puVar3[1]));
  pcVar16 = (char *)((long)puVar17 + 9);
  sVar6 = strlen(pcVar16);
  plVar4 = (long *)(pcVar16 + sVar6 + 1);
  plVar5 = plVar4;
  if ((*(char *)((long)puVar17 + 9) == 'e') && (*(char *)((long)puVar17 + 10) == 'h')) {
    plVar5 = plVar4 + 1;
    pcVar16 = (char *)((long)puVar17 + 0xb);
    param_2[0xcf] = *plVar4;
  }
  if (3 < *(byte *)(puVar17 + 2)) {
    if (*(char *)plVar5 != '\b') {
      return 3;
    }
    if (*(char *)((long)plVar5 + 1) != '\0') {
      return 3;
    }
    plVar5 = (long *)((long)plVar5 + 2);
  }
  uVar7 = FUN_0011b0d0(plVar5,&local_18);
  param_2[0xcc] = local_18;
  pbVar8 = (byte *)FUN_0011b0f8(uVar7,&local_10);
  param_2[0xcb] = local_10;
  if (*(char *)(puVar17 + 2) == '\x01') {
    pbVar9 = pbVar8 + 1;
    uVar12 = (ulong)*pbVar8;
  }
  else {
    pbVar9 = (byte *)FUN_0011b0d0(pbVar8,&local_18);
    uVar12 = local_18;
  }
  param_2[0xcd] = uVar12;
  *(undefined *)((long)param_2 + 0x671) = 0xff;
  pbVar8 = (byte *)0x0;
  if (*pcVar16 == 'z') {
    pcVar16 = pcVar16 + 1;
    pbVar9 = (byte *)FUN_0011b0d0(pbVar9,&local_18);
    *(undefined *)((long)param_2 + 0x672) = 1;
    pbVar8 = pbVar9 + local_18;
  }
  while( true ) {
    pcVar19 = pcVar16 + 1;
    cVar2 = *pcVar16;
    if (cVar2 == '\0') break;
    pcVar16 = pcVar19;
    if (cVar2 == 'L') {
      *(byte *)((long)param_2 + 0x671) = *pbVar9;
LAB_0011bdb0:
      pbVar9 = pbVar9 + 1;
    }
    else {
      if (cVar2 == 'R') {
        *(byte *)(param_2 + 0xce) = *pbVar9;
        goto LAB_0011bdb0;
      }
      if (cVar2 == 'P') {
        bVar1 = *pbVar9;
        uVar7 = FUN_0011b5a8(bVar1,param_1);
        pbVar9 = (byte *)FUN_0011b138(bVar1,uVar7,pbVar9 + 1,&local_8);
        param_2[0xca] = local_8;
      }
      else {
        pbVar10 = pbVar8;
        if (cVar2 != 'S') goto LAB_0011be18;
        *(undefined *)((long)param_2 + 0x673) = 1;
      }
    }
  }
  pbVar10 = pbVar9;
  if (pbVar8 != (byte *)0x0) {
    pbVar10 = pbVar8;
  }
LAB_0011be18:
  if (pbVar10 == (byte *)0x0) {
    return 3;
  }
  FUN_0011b620(pbVar10,(long)puVar17 + (ulong)*puVar17 + 4,param_1,param_2);
  if (*(byte *)(param_2 + 0xce) == 0xff) {
    iVar15 = 0;
  }
  else {
    switch(*(byte *)(param_2 + 0xce) & 7) {
    case 0:
    case 4:
      iVar15 = 8;
      break;
    default:
                    // WARNING: Subroutine does not return
      abort();
    case 2:
      iVar15 = 2;
      break;
    case 3:
      iVar15 = 4;
    }
  }
  lVar18 = 0;
  lVar14 = (long)puVar3 + (ulong)(uint)(iVar15 << 1) + 8;
  if (*(char *)((long)param_2 + 0x672) != '\0') {
    lVar14 = FUN_0011b0d0(lVar14,&local_8);
    lVar18 = lVar14 + local_8;
  }
  cVar2 = *(char *)((long)param_2 + 0x671);
  if (cVar2 != -1) {
    uVar7 = FUN_0011b5a8(cVar2,param_1);
    lVar14 = FUN_0011b138(cVar2,uVar7,lVar14,&local_8);
    *(long *)(param_1 + 800) = local_8;
  }
  if (lVar18 == 0) {
    lVar18 = lVar14;
  }
  FUN_0011b620(lVar18,(long)puVar3 + (ulong)*puVar3 + 4,param_1,param_2);
  return 0;
}



ulong * FUN_0011bf34(byte *param_1,byte *param_2,undefined8 param_3,ulong *param_4)

{
  byte bVar1;
  int iVar2;
  ulong uVar3;
  int iVar4;
  ulong *puVar5;
  undefined8 uVar6;
  long lVar7;
  ulong *puVar8;
  byte *pbVar9;
  ulong *puVar10;
  ulong **ppuVar11;
  uint uVar12;
  uint uVar13;
  uint uVar14;
  int local_220 [2];
  ulong *local_218;
  ulong local_210;
  ulong *local_208;
  ulong *local_200 [64];
  uint uVar15;
  
  local_200[0] = param_4;
  uVar12 = 1;
LAB_0011bf88:
  pbVar9 = param_1;
  if (param_2 <= pbVar9) {
    if (uVar12 != 0) {
      return local_200[(int)(uVar12 - 1)];
    }
switchD_0011c330_caseD_3:
                    // WARNING: Subroutine does not return
    abort();
  }
  bVar1 = *pbVar9;
  param_1 = pbVar9 + 1;
  uVar14 = (uint)bVar1;
  uVar15 = (uint)bVar1;
  uVar13 = uVar12;
  if (bVar1 < 0x21) {
    if (bVar1 < 0x1f) {
      if (uVar15 == 0x10) {
        param_1 = (byte *)FUN_0011b0d0(param_1,&local_218);
        puVar5 = local_218;
      }
      else if (uVar15 < 0x11) {
        if (uVar15 == 10) {
          puVar5 = (ulong *)(ulong)*(ushort *)(pbVar9 + 1);
LAB_0011c188:
          param_1 = pbVar9 + 3;
        }
        else if (uVar15 < 0xb) {
          if (uVar14 == 6) goto LAB_0011c2bc;
          if (uVar14 < 7) {
            if (bVar1 != 3) goto switchD_0011c330_caseD_3;
            param_1 = pbVar9 + 9;
            puVar5 = *(ulong **)(pbVar9 + 1);
          }
          else {
            param_1 = pbVar9 + 2;
            if (uVar14 == 8) {
              puVar5 = (ulong *)(ulong)pbVar9[1];
            }
            else {
              if (uVar14 != 9) goto switchD_0011c330_caseD_3;
              puVar5 = (ulong *)(long)(char)pbVar9[1];
            }
          }
        }
        else {
          if (uVar15 == 0xd) {
            puVar5 = (ulong *)(long)*(int *)(pbVar9 + 1);
          }
          else {
            if (0xd < uVar15) {
              param_1 = pbVar9 + 9;
              if ((bVar1 == 0xe) || (bVar1 == 0xf)) {
                puVar5 = *(ulong **)(pbVar9 + 1);
                goto LAB_0011c484;
              }
              goto switchD_0011c330_caseD_3;
            }
            if (bVar1 == 0xb) {
              puVar5 = (ulong *)(long)*(short *)(pbVar9 + 1);
              goto LAB_0011c188;
            }
            if (bVar1 != 0xc) goto switchD_0011c330_caseD_3;
            puVar5 = (ulong *)(ulong)*(uint *)(pbVar9 + 1);
          }
          param_1 = pbVar9 + 5;
        }
      }
      else if (uVar15 == 0x15) {
        local_210 = (ulong)pbVar9[1];
        param_1 = pbVar9 + 2;
        if ((long)(int)(uVar12 - 1) <= (long)local_210) goto switchD_0011c330_caseD_3;
        puVar5 = local_200[(long)(int)(uVar12 - 1) - local_210];
      }
      else {
        if (0x15 < uVar15) {
          if (uVar15 == 0x19) goto LAB_0011c2bc;
          if (0x19 < uVar15) goto LAB_0011c370;
          iVar4 = uVar12 - 1;
          iVar2 = uVar12 - 2;
          if (uVar15 == 0x16) {
            if ((int)uVar12 < 2) goto switchD_0011c330_caseD_3;
            puVar5 = local_200[iVar4];
            local_200[iVar4] = local_200[iVar2];
            local_200[iVar2] = puVar5;
          }
          else {
            if ((uVar15 != 0x17) || ((int)uVar12 < 3)) goto switchD_0011c330_caseD_3;
            puVar5 = local_200[iVar4];
            puVar10 = local_200[(int)(uVar12 - 3)];
            local_200[iVar4] = local_200[iVar2];
            local_200[iVar2] = puVar10;
            local_200[(int)(uVar12 - 3)] = puVar5;
          }
          goto LAB_0011bf88;
        }
        if (uVar15 == 0x12) {
          if (uVar12 == 0) goto switchD_0011c330_caseD_3;
          iVar4 = uVar12 - 1;
        }
        else {
          if (uVar15 < 0x12) {
            param_1 = (byte *)FUN_0011b0f8(param_1,&local_208);
            goto LAB_0011c1cc;
          }
          if (uVar15 == 0x13) {
            if (uVar12 == 0) goto switchD_0011c330_caseD_3;
            uVar12 = uVar12 - 1;
            goto LAB_0011bf88;
          }
          if ((uVar15 != 0x14) || ((int)uVar12 < 2)) goto switchD_0011c330_caseD_3;
          iVar4 = uVar12 - 2;
        }
        puVar5 = local_200[iVar4];
      }
    }
    else {
LAB_0011c2bc:
      if (uVar12 == 0) goto switchD_0011c330_caseD_3;
      uVar13 = uVar12 - 1;
      ppuVar11 = (ulong **)local_200[(int)uVar13];
      if (uVar14 == 0x1f) {
        puVar5 = (ulong *)-(long)ppuVar11;
      }
      else {
        uVar12 = uVar13;
        if (uVar14 < 0x20) {
          if (uVar14 == 6) {
switchD_0011c330_caseD_8:
            puVar5 = *ppuVar11;
            uVar13 = uVar12;
          }
          else {
            if (bVar1 != 0x19) goto switchD_0011c330_caseD_3;
            puVar5 = (ulong *)(((ulong)ppuVar11 ^ (long)ppuVar11 >> 0x3f) - ((long)ppuVar11 >> 0x3f)
                              );
          }
        }
        else if (uVar14 == 0x23) {
          param_1 = (byte *)FUN_0011b0d0(param_1,&local_218);
          puVar5 = (ulong *)((long)ppuVar11 + (long)local_218);
        }
        else if (uVar14 == 0x94) {
          param_1 = pbVar9 + 2;
          switch(pbVar9[1]) {
          case 1:
            puVar5 = (ulong *)(ulong)*(byte *)ppuVar11;
            break;
          case 2:
            puVar5 = (ulong *)(ulong)*(ushort *)ppuVar11;
            break;
          default:
            goto switchD_0011c330_caseD_3;
          case 4:
            puVar5 = (ulong *)(ulong)*(uint *)ppuVar11;
            break;
          case 8:
            goto switchD_0011c330_caseD_8;
          }
        }
        else {
          if (uVar14 != 0x20) goto switchD_0011c330_caseD_3;
          puVar5 = (ulong *)~(ulong)ppuVar11;
        }
      }
    }
  }
  else if (uVar15 < 0x50) {
    if (0x2f < uVar14) {
      puVar5 = (ulong *)(ulong)(uVar14 - 0x30);
      goto LAB_0011c484;
    }
    if (0x27 < uVar14) {
      if (uVar15 < 0x2f) {
        if (0x28 < uVar15) goto LAB_0011c370;
        if (uVar12 == 0) goto switchD_0011c330_caseD_3;
        uVar12 = uVar12 - 1;
        param_1 = pbVar9 + 3;
        if (local_200[(int)uVar12] != (ulong *)0x0) {
          param_1 = pbVar9 + 3 + *(short *)(pbVar9 + 1);
        }
      }
      else {
        param_1 = pbVar9 + (long)*(short *)(pbVar9 + 1) + 3;
      }
      goto LAB_0011bf88;
    }
    if ((uVar15 < 0x24) && (0x22 < uVar15)) goto LAB_0011c2bc;
LAB_0011c370:
    if ((int)uVar12 < 2) goto switchD_0011c330_caseD_3;
    uVar13 = uVar12 - 2;
    puVar10 = local_200[(int)uVar13];
    puVar8 = local_200[(int)(uVar12 - 1)];
    switch(bVar1) {
    case 0x1a:
      puVar5 = (ulong *)((ulong)puVar8 & (ulong)puVar10);
      break;
    case 0x1b:
      puVar5 = (ulong *)0x0;
      if (puVar8 != (ulong *)0x0) {
        puVar5 = (ulong *)((long)puVar10 / (long)puVar8);
      }
      break;
    case 0x1c:
      puVar5 = (ulong *)((long)puVar10 - (long)puVar8);
      break;
    case 0x1d:
      uVar3 = 0;
      if (puVar8 != (ulong *)0x0) {
        uVar3 = (ulong)puVar10 / (ulong)puVar8;
      }
      puVar5 = (ulong *)((long)puVar10 - uVar3 * (long)puVar8);
      break;
    case 0x1e:
      puVar5 = (ulong *)((long)puVar8 * (long)puVar10);
      break;
    default:
      goto switchD_0011c330_caseD_3;
    case 0x21:
      puVar5 = (ulong *)((ulong)puVar8 | (ulong)puVar10);
      break;
    case 0x22:
      puVar5 = (ulong *)((long)puVar8 + (long)puVar10);
      break;
    case 0x24:
      puVar5 = (ulong *)((long)puVar10 << ((ulong)puVar8 & 0x3f));
      break;
    case 0x25:
      puVar5 = (ulong *)((ulong)puVar10 >> ((ulong)puVar8 & 0x3f));
      break;
    case 0x26:
      puVar5 = (ulong *)((long)puVar10 >> ((ulong)puVar8 & 0x3f));
      break;
    case 0x27:
      puVar5 = (ulong *)((ulong)puVar8 ^ (ulong)puVar10);
      break;
    case 0x29:
      puVar5 = (ulong *)(ulong)(puVar10 == puVar8);
      break;
    case 0x2a:
      puVar5 = (ulong *)(ulong)((long)puVar8 <= (long)puVar10);
      break;
    case 0x2b:
      puVar5 = (ulong *)(ulong)((long)puVar8 < (long)puVar10);
      break;
    case 0x2c:
      puVar5 = (ulong *)(ulong)((long)puVar10 <= (long)puVar8);
      break;
    case 0x2d:
      puVar5 = (ulong *)(ulong)((long)puVar10 < (long)puVar8);
      break;
    case 0x2e:
      puVar5 = (ulong *)(ulong)(puVar10 != puVar8);
    }
  }
  else {
    if (uVar15 != 0x90) {
      if (uVar15 < 0x91) {
        if (bVar1 < 0x70) {
          iVar4 = uVar14 - 0x50;
          goto LAB_0011c1f0;
        }
        param_1 = (byte *)FUN_0011b0f8(param_1,&local_210);
        iVar4 = uVar15 - 0x70;
      }
      else {
        if (uVar15 == 0x94) goto LAB_0011c2bc;
        if (0x94 < uVar15) {
          if (uVar15 != 0x96) {
            if (uVar15 == 0xf1) {
              bVar1 = pbVar9[1];
              uVar6 = FUN_0011b5a8(bVar1,param_3);
              param_1 = (byte *)FUN_0011b138(bVar1,uVar6,pbVar9 + 2);
LAB_0011c1cc:
              ppuVar11 = &local_208;
              goto switchD_0011c330_caseD_8;
            }
            goto switchD_0011c330_caseD_3;
          }
          goto LAB_0011bf88;
        }
        if (bVar1 != 0x92) goto switchD_0011c330_caseD_3;
        uVar6 = FUN_0011b0d0(param_1,local_220);
        param_1 = (byte *)FUN_0011b0f8(uVar6,&local_210);
        iVar4 = local_220[0];
      }
      lVar7 = _Unwind_GetGR(param_3,iVar4);
      puVar5 = (ulong *)(lVar7 + local_210);
      goto LAB_0011c484;
    }
    param_1 = (byte *)FUN_0011b0d0(param_1,local_220);
    iVar4 = local_220[0];
LAB_0011c1f0:
    puVar5 = (ulong *)_Unwind_GetGR(param_3,iVar4);
  }
LAB_0011c484:
  if (0x3f < uVar13) goto switchD_0011c330_caseD_3;
  local_200[(int)uVar13] = puVar5;
  uVar12 = uVar13 + 1;
  goto LAB_0011bf88;
}



void FUN_0011c4cc(void *param_1,long *param_2)

{
  ulong uVar1;
  int iVar2;
  long lVar3;
  long lVar4;
  undefined8 uVar5;
  long lVar6;
  undefined *puVar7;
  long *plVar8;
  undefined auStack_3d0 [8];
  long local_3c8;
  undefined8 auStack_3c0 [31];
  long local_2c8;
  ulong local_80;
  char acStack_68 [31];
  char local_49;
  
  memcpy(auStack_3c0,param_1,0x3c0);
  if ((((local_80 >> 0x3e & 1) == 0) || (local_49 == '\0')) && (local_2c8 == 0)) {
    FUN_0011b33c(auStack_3c0,*(undefined8 *)((long)param_1 + 0x310),auStack_3d0);
  }
  if ((*(ulong *)((long)param_1 + 0x340) >> 0x3e & 1) != 0) {
    *(undefined *)((long)param_1 + 0x377) = 0;
  }
  iVar2 = *(int *)(param_2 + 200);
  *(undefined8 *)((long)param_1 + 0xf8) = 0;
  if (iVar2 == 1) {
    lVar3 = _Unwind_GetGR(auStack_3c0,*(undefined4 *)(param_2 + 0xc6));
    lVar3 = lVar3 + param_2[0xc5];
  }
  else {
    if (iVar2 != 2) {
LAB_0011c618:
                    // WARNING: Subroutine does not return
      abort();
    }
    lVar3 = FUN_0011b0d0(param_2[199],&local_3c8);
    lVar3 = FUN_0011bf34(lVar3,lVar3 + local_3c8,auStack_3c0,0);
  }
  *(long *)((long)param_1 + 0x310) = lVar3;
  puVar7 = (undefined *)((long)param_1 + 0x358);
  lVar6 = 0;
  plVar8 = param_2;
  do {
    switch(*(undefined4 *)(plVar8 + 1)) {
    case 1:
      lVar4 = lVar3 + *plVar8;
      goto LAB_0011c654;
    case 2:
      if (acStack_68[(int)*plVar8] != '\0') {
        lVar4 = _Unwind_GetGR(auStack_3c0);
        goto LAB_0011c608;
      }
      uVar5 = auStack_3c0[(int)*plVar8];
      if ((*(ulong *)((long)param_1 + 0x340) >> 0x3e & 1) != 0) {
        *puVar7 = 0;
      }
      *(undefined8 *)((long)param_1 + lVar6 * 8) = uVar5;
      break;
    case 3:
      lVar4 = FUN_0011b0d0(*plVar8,&local_3c8);
      lVar4 = FUN_0011bf34(lVar4,lVar4 + local_3c8,auStack_3c0,lVar3);
LAB_0011c654:
      if ((*(ulong *)((long)param_1 + 0x340) >> 0x3e & 1) != 0) {
        *puVar7 = 0;
      }
LAB_0011c698:
      *(long *)((long)param_1 + lVar6 * 8) = lVar4;
      break;
    case 4:
      lVar4 = lVar3 + *plVar8;
      goto LAB_0011c608;
    case 5:
      lVar4 = FUN_0011b0d0(*plVar8,&local_3c8);
      lVar4 = FUN_0011bf34(lVar4,lVar4 + local_3c8,auStack_3c0,lVar3);
LAB_0011c608:
      if ((byte)(&DAT_00147db0)[lVar6] < 9) {
        *puVar7 = 1;
        goto LAB_0011c698;
      }
      goto LAB_0011c618;
    }
    lVar6 = lVar6 + 1;
    plVar8 = plVar8 + 2;
    puVar7 = puVar7 + 1;
    if (lVar6 == 0x62) {
      uVar1 = *(ulong *)((long)param_1 + 0x340) & 0x7fffffffffffffff;
      if (*(char *)((long)param_2 + 0x673) != '\0') {
        uVar1 = *(ulong *)((long)param_1 + 0x340) | 0x8000000000000000;
      }
      *(ulong *)((long)param_1 + 0x340) = uVar1;
      return;
    }
  } while( true );
}



void FUN_0011c6f0(void *param_1,undefined8 param_2,undefined8 param_3)

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
  iVar1 = FUN_0011bb18(param_1,auStack_680);
  if (iVar1 != 0) {
                    // WARNING: Subroutine does not return
    abort();
  }
  iVar1 = pthread_once((pthread_once_t *)&DAT_00147e14,FUN_0011b228);
  if ((iVar1 != 0) && (DAT_00147db0 == '\0')) {
    FUN_0011b228();
  }
  FUN_0011b33c(param_1,param_2,auStack_688);
  local_58 = 0;
  local_40 = 1;
  local_50 = 0x1f;
  FUN_0011c4cc(param_1,auStack_680);
  *(undefined8 *)((long)param_1 + 0x318) = param_3;
  return;
}



void FUN_0011c7bc(long param_1,long param_2)

{
  undefined8 uVar1;
  
  FUN_0011c4cc();
  if (*(int *)(param_2 + *(long *)(param_2 + 0x668) * 0x10 + 8) == 6) {
    *(undefined8 *)(param_1 + 0x318) = 0;
  }
  else {
    uVar1 = _Unwind_GetGR(param_1);
    *(undefined8 *)(param_1 + 0x318) = uVar1;
  }
  return;
}



undefined8 FUN_0011c808(undefined8 *param_1,long param_2)

{
  int iVar1;
  long lVar2;
  undefined8 uVar3;
  uint uVar4;
  undefined auStack_680 [1616];
  code *local_30;
  
  do {
    iVar1 = FUN_0011bb18(param_2,auStack_680);
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
    FUN_0011c7bc(param_2,auStack_680);
  } while( true );
}



undefined4 FUN_0011c8c8(undefined8 *param_1,undefined8 param_2)

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
    iVar1 = FUN_0011bb18(param_2,auStack_680);
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
    FUN_0011c7bc(param_2,auStack_680);
  }
  return 2;
}



long __frame_state_for(long param_1,long param_2)

{
  char cVar1;
  int iVar2;
  undefined8 *puVar3;
  char *pcVar4;
  long lVar5;
  undefined auStack_a40 [792];
  long local_728;
  undefined8 local_700;
  undefined8 local_6f0;
  undefined8 local_680;
  char local_678 [1568];
  undefined8 local_58;
  undefined2 local_50;
  int local_40;
  undefined2 local_18;
  undefined8 local_8;
  
  local_728 = param_1 + 1;
  memset(auStack_a40,0,0x3c0);
  local_700 = 0x4000000000000000;
  iVar2 = FUN_0011bb18(auStack_a40,&local_680);
  lVar5 = 0;
  if ((iVar2 == 0) && (local_40 != 2)) {
    pcVar4 = (char *)(param_2 + 0x334);
    puVar3 = (undefined8 *)(param_2 + 0x20);
    lVar5 = 0;
    do {
      cVar1 = local_678[lVar5];
      *pcVar4 = cVar1;
      if ((cVar1 == '\x01') || (cVar1 == '\x02')) {
        *puVar3 = *(undefined8 *)((long)&local_680 + lVar5);
      }
      else {
        *puVar3 = 0;
      }
      lVar5 = lVar5 + 0x10;
      pcVar4 = pcVar4 + 1;
      puVar3 = puVar3 + 1;
    } while (lVar5 != 0x620);
    *(undefined8 *)(param_2 + 0x10) = local_58;
    *(undefined2 *)(param_2 + 0x330) = local_50;
    *(undefined2 *)(param_2 + 0x332) = local_18;
    *(undefined8 *)(param_2 + 0x18) = local_6f0;
    *(undefined8 *)(param_2 + 8) = local_8;
    lVar5 = param_2;
  }
  return lVar5;
}



void FUN_0011caa8(void)

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
  
  FUN_0011c6f0(auStack_e00,&stack0x00000000);
  memcpy(auStack_a40,auStack_e00,0x3c0);
  do {
    iVar2 = FUN_0011bb18(auStack_a40,auStack_680);
    if ((iVar2 == 5) || (iVar2 != 0)) goto LAB_0011cbf4;
    if (local_30 != (code *)0x0) {
      iVar2 = (*local_30)(1,1,*param_1,param_1,auStack_a40);
      if (iVar2 == 6) {
        param_1[2] = 0;
        lVar3 = _Unwind_GetCFA(auStack_a40);
        param_1[3] = lVar3 + (local_700 >> 0x3f);
        memcpy(auStack_a40,auStack_e00,0x3c0);
        iVar2 = FUN_0011c808(param_1,auStack_a40);
        if (iVar2 == 7) {
          FUN_0011b3d0(auStack_e00,auStack_a40,7);
          FUN_0011caa8(local_730,local_728);
        }
LAB_0011cbf4:
        auVar1._8_8_ = param_2;
        auVar1._0_8_ = param_1;
        return auVar1;
      }
      if (iVar2 != 8) goto LAB_0011cbf4;
    }
    FUN_0011c7bc(auStack_a40,auStack_680);
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
  
  FUN_0011c6f0(auStack_780,&stack0x00000000);
  memcpy(auStack_3c0,auStack_780,0x3c0);
  *(undefined8 *)(param_1 + 0x10) = param_2;
  *(undefined8 *)(param_1 + 0x18) = param_3;
  iVar2 = FUN_0011c8c8(param_1,auStack_3c0);
  if (iVar2 == 7) {
    FUN_0011b3d0(auStack_780,auStack_3c0);
    FUN_0011caa8(local_b0,local_a8);
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
  
  FUN_0011c6f0(auStack_780,&stack0x00000000);
  memcpy(auStack_3c0,auStack_780,0x3c0);
  if (*(long *)(param_1 + 0x10) == 0) {
    iVar2 = FUN_0011c808(param_1,auStack_3c0);
  }
  else {
    iVar2 = FUN_0011c8c8(param_1,auStack_3c0);
  }
  if (iVar2 != 7) {
                    // WARNING: Subroutine does not return
    abort();
  }
  FUN_0011b3d0(auStack_780,auStack_3c0);
  FUN_0011caa8(local_b0,local_a8);
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
    FUN_0011c6f0(auStack_780,&stack0x00000000);
    memcpy(auStack_3c0,auStack_780,0x3c0);
    iVar2 = FUN_0011c8c8(param_1,auStack_3c0);
    if (iVar2 != 7) {
                    // WARNING: Subroutine does not return
      abort();
    }
    FUN_0011b3d0(auStack_780,auStack_3c0);
    FUN_0011caa8(local_b0,local_a8);
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
  
  FUN_0011c6f0(auStack_a40,&stack0x00000000);
  while (((iVar1 = FUN_0011bb18(auStack_a40,auStack_680), iVar1 == 5 || (iVar1 == 0)) &&
         (iVar2 = (*param_1)(auStack_a40,param_2), iVar2 == 0))) {
    if (iVar1 == 5) {
      return 5;
    }
    FUN_0011c7bc(auStack_a40,auStack_680);
  }
  return 3;
}



void FUN_0011d014(byte *param_1,ulong *param_2)

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



void FUN_0011d03c(byte *param_1,ulong *param_2)

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



int FUN_0011d07c(undefined8 param_1,long param_2,long param_3)

{
  int iVar1;
  
  iVar1 = 1;
  if (*(ulong *)(param_2 + 8) <= *(ulong *)(param_3 + 8)) {
    iVar1 = -(uint)(*(ulong *)(param_2 + 8) < *(ulong *)(param_3 + 8));
  }
  return iVar1;
}



void FUN_0011d098(undefined8 param_1,code *param_2,long param_3,ulong param_4,int param_5)

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



void FUN_0011d158(undefined8 param_1,undefined8 param_2,long param_3)

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
    FUN_0011d098(param_1,param_2,lVar2,uVar3,uVar6 & 0xffffffff);
  }
  lVar8 = 0;
  iVar5 = (int)uVar6 + -1;
  lVar1 = lVar2 + (long)iVar5 * 8;
  for (; 0 < iVar5; iVar5 = iVar5 + -1) {
    uVar4 = *(undefined8 *)(param_3 + 0x10);
    *(undefined8 *)(param_3 + 0x10) = *(undefined8 *)(lVar1 + lVar8);
    *(undefined8 *)(lVar1 + lVar8) = uVar4;
    lVar8 = lVar8 + -8;
    FUN_0011d098(param_1,param_2,lVar2,0,iVar5);
  }
  return;
}



undefined8 FUN_0011d20c(byte param_1)

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



undefined8 FUN_0011d26c(byte param_1,long param_2)

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



undefined8 FUN_0011d2cc(byte param_1,long param_2)

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



ulong ** FUN_0011d32c(byte param_1,ulong **param_2,ulong **param_3,ulong **param_4)

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
      ppuVar1 = (ulong **)FUN_0011d014(param_3,&local_8);
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
      ppuVar1 = (ulong **)FUN_0011d03c(param_3,&local_8);
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



int FUN_0011d41c(long param_1,long param_2,long param_3)

{
  ushort uVar1;
  int iVar2;
  undefined8 uVar3;
  ulong local_10;
  ulong local_8;
  
  uVar1 = *(ushort *)(param_1 + 0x20) >> 3 & 0xff;
  uVar3 = FUN_0011d26c(uVar1,param_1);
  FUN_0011d32c(uVar1,uVar3,param_2 + 8,&local_10);
  FUN_0011d32c(*(ushort *)(param_1 + 0x20) >> 3,uVar3,param_3 + 8,&local_8);
  iVar2 = 1;
  if (local_10 <= local_8) {
    iVar2 = -(uint)(local_10 < local_8);
  }
  return iVar2;
}



byte FUN_0011d4ac(long param_1)

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
    uVar4 = FUN_0011d014(pcVar7,auStack_10);
    lVar5 = FUN_0011d03c(uVar4,auStack_8);
    if (*(char *)(param_1 + 8) == '\x01') {
      lVar5 = lVar5 + 1;
    }
    else {
      lVar5 = FUN_0011d014(lVar5,auStack_10);
    }
    pbVar6 = (byte *)FUN_0011d014(lVar5,auStack_10);
    for (pcVar8 = (char *)(param_1 + 10); cVar1 = *pcVar8, cVar1 != 'R'; pcVar8 = pcVar8 + 1) {
      if (cVar1 == 'P') {
        pbVar6 = (byte *)FUN_0011d32c(*pbVar6 & 0x7f,0,pbVar6 + 1,auStack_18);
      }
      else {
        if (cVar1 != 'L') goto LAB_0011d504;
        pbVar6 = pbVar6 + 1;
      }
    }
    bVar2 = *pbVar6;
  }
  else {
LAB_0011d504:
    bVar2 = 0;
  }
  return bVar2;
}



uint * FUN_0011d5a8(long param_1,uint *param_2,long param_3)

{
  ulong uVar1;
  undefined8 uVar2;
  ulong uVar3;
  undefined8 uVar4;
  ulong uVar5;
  long lVar6;
  long lVar7;
  ulong local_10;
  ulong local_8;
  
  uVar1 = (ulong)(*(ushort *)(param_1 + 0x20) >> 3) & 0xff;
  uVar2 = FUN_0011d26c(uVar1,param_1);
  lVar6 = 0;
  do {
    if (*param_2 == 0) {
      return (uint *)0x0;
    }
    if (param_2[1] != 0) {
      lVar7 = lVar6;
      if (((*(byte *)(param_1 + 0x20) >> 2 & 1) != 0) &&
         (lVar7 = (long)param_2 + (4 - (long)(int)param_2[1]), lVar7 != lVar6)) {
        uVar3 = FUN_0011d4ac(lVar7);
        uVar1 = uVar3 & 0xffffffff;
        uVar2 = FUN_0011d26c(uVar3,param_1);
      }
      if ((uint)uVar1 == 0) {
        local_10 = *(ulong *)(param_2 + 2);
        local_8 = *(ulong *)(param_2 + 4);
        uVar3 = local_10;
      }
      else {
        uVar4 = FUN_0011d32c(uVar1 & 0xff,uVar2,param_2 + 2,&local_10);
        FUN_0011d32c((uint)uVar1 & 0xf,0,uVar4,&local_8);
        uVar5 = FUN_0011d20c(uVar1 & 0xff);
        uVar3 = 0xffffffffffffffff;
        if ((uVar5 & 0xffffffff) < 8) {
          uVar3 = (1L << ((uVar5 & 7) << 3)) - 1;
        }
        uVar3 = uVar3 & local_10;
      }
      lVar6 = lVar7;
      if ((uVar3 != 0) && (param_3 - local_10 < local_8)) {
        return param_2;
      }
    }
    param_2 = (uint *)((long)param_2 + (ulong)*param_2 + 4);
  } while( true );
}



void FUN_0011d708(long param_1)

{
  FUN_0011d4ac((param_1 + 4) - (long)*(int *)(param_1 + 4));
  return;
}



undefined8 FUN_0011d718(ulong *param_1,ulong param_2,ulong *param_3)

{
  undefined8 *puVar1;
  long lVar2;
  ulong uVar3;
  char cVar4;
  int iVar5;
  bool bVar6;
  byte bVar7;
  undefined uVar8;
  undefined8 uVar9;
  undefined8 uVar10;
  ulong uVar11;
  ulong *puVar12;
  undefined8 *puVar13;
  ulong *puVar14;
  int *piVar15;
  int *piVar16;
  ulong *puVar17;
  ulong uVar18;
  ulong *puVar19;
  ulong uVar20;
  int *piVar21;
  int *piVar22;
  ulong uVar23;
  undefined8 local_40;
  ulong local_38;
  long local_30;
  ulong local_28;
  ulong local_20;
  undefined8 local_18;
  undefined8 local_10;
  
  piVar15 = (int *)param_1[2];
  uVar18 = *param_1;
  if ((param_2 < 0x30) || (*(int *)(param_3 + 5) == 0)) {
    if (param_2 < 0x1a) {
      return 0xffffffff;
    }
  }
  else {
    if ((param_1[4] == DAT_00136048) && (param_1[5] == DAT_00147e20)) {
      puVar19 = DAT_00147e28;
      puVar14 = (ulong *)0x0;
      puVar17 = (ulong *)0x0;
      while (puVar12 = puVar19, puVar12 != (ulong *)0x0) {
        if ((*puVar12 <= *param_3) && (*param_3 < puVar12[1])) {
          uVar18 = puVar12[2];
          piVar16 = (int *)puVar12[3];
          if (puVar12 != DAT_00147e28) {
            puVar17[5] = puVar12[5];
            puVar12[5] = (ulong)DAT_00147e28;
            DAT_00147e28 = puVar12;
          }
          goto LAB_0011d928;
        }
        puVar14 = puVar12;
        if ((*puVar12 | puVar12[1]) == 0) break;
        puVar19 = (ulong *)puVar12[5];
        if (puVar19 != (ulong *)0x0) {
          puVar17 = puVar12;
        }
      }
      goto LAB_0011d844;
    }
    puVar13 = &DAT_00147e30;
    DAT_00136048 = param_1[4];
    DAT_00147e20 = param_1[5];
    do {
      *puVar13 = 0;
      puVar13[1] = 0;
      puVar1 = puVar13 + 6;
      puVar13[5] = puVar1;
      puVar13 = puVar1;
    } while (puVar1 != &DAT_00147fb0);
    DAT_00147fa8 = 0;
    DAT_00147e28 = &DAT_00147e30;
    *(undefined4 *)(param_3 + 5) = 0;
  }
  puVar17 = (ulong *)0x0;
  puVar14 = (ulong *)0x0;
LAB_0011d844:
  uVar23 = (ulong)*(ushort *)(param_1 + 3);
  uVar11 = 0;
  uVar20 = 0;
  bVar6 = false;
  piVar21 = (int *)0x0;
  piVar16 = (int *)0x0;
  while (uVar23 = uVar23 - 1, uVar23 != 0xffffffffffffffff) {
    iVar5 = *piVar15;
    piVar22 = piVar16;
    if (iVar5 == 1) {
      uVar3 = uVar18 + *(long *)(piVar15 + 4);
      if ((uVar3 <= *param_3) && (*param_3 < uVar3 + *(long *)(piVar15 + 10))) {
        bVar6 = true;
        uVar11 = uVar3 + *(long *)(piVar15 + 10);
        uVar20 = uVar3;
      }
    }
    else {
      piVar22 = piVar15;
      if ((iVar5 != 0x6474e550) && (piVar22 = piVar16, iVar5 == 2)) {
        piVar21 = piVar15;
      }
    }
    piVar15 = piVar15 + 0xe;
    piVar16 = piVar22;
  }
  if (!bVar6) {
    return 0;
  }
  if (param_2 >= 0x30) {
    if ((puVar17 != (ulong *)0x0) && (puVar14 != (ulong *)0x0)) {
      puVar17[5] = puVar14[5];
      puVar14[5] = (ulong)DAT_00147e28;
      DAT_00147e28 = puVar14;
    }
    puVar14 = DAT_00147e28;
    DAT_00147e28[2] = uVar18;
    puVar14[3] = (ulong)piVar16;
    puVar14[4] = (ulong)piVar21;
    *puVar14 = uVar20;
    puVar14[1] = uVar11;
  }
LAB_0011d928:
  if (piVar16 == (int *)0x0) {
    return 0;
  }
  lVar2 = uVar18 + *(long *)(piVar16 + 4);
  if (*(char *)(uVar18 + *(long *)(piVar16 + 4)) != '\x01') {
    return 1;
  }
  uVar8 = *(undefined *)(lVar2 + 1);
  uVar9 = FUN_0011d2cc(uVar8,param_3);
  uVar9 = FUN_0011d32c(uVar8,uVar9,lVar2 + 4,&local_40);
  cVar4 = *(char *)(lVar2 + 2);
  if ((cVar4 != -1) && (*(char *)(lVar2 + 3) == ';')) {
    uVar10 = FUN_0011d2cc(cVar4,param_3);
    piVar15 = (int *)FUN_0011d32c(cVar4,uVar10,uVar9,&local_38);
    if (local_38 == 0) {
      return 1;
    }
    if (((ulong)piVar15 & 3) == 0) {
      uVar18 = *param_3;
      if (uVar18 < (ulong)(lVar2 + *piVar15)) {
        return 1;
      }
      local_38 = local_38 - 1;
      uVar11 = 0;
      uVar20 = local_38;
      if (uVar18 < (ulong)(lVar2 + piVar15[local_38 * 2])) {
        do {
          uVar23 = uVar20;
          if (uVar23 <= uVar11) {
                    // WARNING: Subroutine does not return
            abort();
          }
          uVar3 = uVar23 + uVar11;
          local_38 = uVar3 >> 1;
          uVar20 = local_38;
        } while ((uVar18 < (ulong)(lVar2 + piVar15[uVar3 & 0xfffffffffffffffe])) ||
                (uVar11 = local_38 + 1, uVar20 = uVar23,
                (ulong)(lVar2 + piVar15[(uVar3 & 0xfffffffffffffffe) + 2]) <= uVar18));
      }
      uVar18 = lVar2 + piVar15[local_38 * 2 + 1];
      bVar7 = FUN_0011d708(uVar18);
      uVar11 = FUN_0011d20c(bVar7);
      FUN_0011d32c(bVar7 & 0xf,0,uVar18 + (uVar11 & 0xffffffff) + 8,&local_30);
      iVar5 = piVar15[local_38 * 2];
      if (*param_3 < (ulong)(lVar2 + iVar5 + local_30)) {
        param_3[4] = uVar18;
      }
      param_3[3] = lVar2 + iVar5;
      return 1;
    }
  }
  local_28 = param_3[1];
  local_20 = param_3[2];
  local_10 = 4;
  local_30 = 0;
  local_18 = local_40;
  uVar18 = FUN_0011d5a8(&local_30,local_40,*param_3);
  param_3[4] = uVar18;
  if (uVar18 != 0) {
    uVar8 = FUN_0011d708();
    uVar9 = FUN_0011d2cc(uVar8,param_3);
    FUN_0011d32c(uVar8,uVar9,param_3[4] + 8,&local_38);
    param_3[3] = local_38;
  }
  return 1;
}



int FUN_0011db2c(undefined8 param_1,long param_2,long param_3)

{
  undefined uVar1;
  int iVar2;
  undefined8 uVar3;
  ulong local_10;
  ulong local_8;
  
  uVar1 = FUN_0011d708(param_2);
  uVar3 = FUN_0011d26c(uVar1,param_1);
  FUN_0011d32c(uVar1,uVar3,param_2 + 8,&local_10);
  uVar1 = FUN_0011d708(param_3);
  uVar3 = FUN_0011d26c(uVar1,param_1);
  FUN_0011d32c(uVar1,uVar3,param_3 + 8,&local_8);
  iVar2 = 1;
  if (local_10 <= local_8) {
    iVar2 = -(uint)(local_10 < local_8);
  }
  return iVar2;
}



long FUN_0011dbc8(ulong *param_1,uint *param_2)

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
        uVar2 = FUN_0011d4ac(lVar6);
        if (uVar2 == 0xff) {
          return -1;
        }
        uVar8 = FUN_0011d26c((char)uVar2,param_1);
        uVar1 = *(ushort *)(param_1 + 4);
        lVar3 = lVar6;
        if ((uVar1 & 0x7f8) == 0x7f8) {
          *(ushort *)(param_1 + 4) = uVar1 & 0xf800 | uVar1 & 7 | (ushort)((uVar2 & 0xff) << 3);
        }
        else if ((uVar1 >> 3 & 0xff) != uVar2) {
          *(byte *)(param_1 + 4) = *(byte *)(param_1 + 4) | 4;
        }
      }
      FUN_0011d32c(uVar2 & 0xff,uVar8,param_2 + 2,&local_8);
      uVar4 = FUN_0011d20c(uVar2 & 0xff);
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



void FUN_0011dd28(long param_1,long *param_2,uint *param_3)

{
  ulong uVar1;
  undefined8 uVar2;
  ulong uVar3;
  ulong uVar4;
  long lVar5;
  long lVar6;
  long lVar7;
  ulong local_8;
  
  uVar1 = (ulong)(*(ushort *)(param_1 + 0x20) >> 3) & 0xff;
  uVar2 = FUN_0011d26c(uVar1,param_1);
  lVar5 = 0;
  for (; *param_3 != 0; param_3 = (uint *)((long)param_3 + (ulong)*param_3 + 4)) {
    if (param_3[1] != 0) {
      lVar7 = lVar5;
      if (((*(byte *)(param_1 + 0x20) >> 2 & 1) != 0) &&
         (lVar7 = (long)param_3 + (4 - (long)(int)param_3[1]), lVar7 != lVar5)) {
        uVar3 = FUN_0011d4ac(lVar7);
        uVar1 = uVar3 & 0xffffffff;
        uVar2 = FUN_0011d26c(uVar3,param_1);
      }
      if ((int)uVar1 == 0) {
        uVar3 = *(ulong *)(param_3 + 2);
      }
      else {
        FUN_0011d32c(uVar1 & 0xff,uVar2,param_3 + 2,&local_8);
        uVar4 = FUN_0011d20c(uVar1 & 0xff);
        uVar3 = 0xffffffffffffffff;
        if ((uVar4 & 0xffffffff) < 8) {
          uVar3 = (1L << ((uVar4 & 7) << 3)) - 1;
        }
        uVar3 = uVar3 & local_8;
      }
      lVar5 = lVar7;
      if ((uVar3 != 0) && (lVar7 = *param_2, lVar7 != 0)) {
        lVar6 = *(long *)(lVar7 + 8);
        *(long *)(lVar7 + 8) = lVar6 + 1;
        *(uint **)(lVar7 + (lVar6 + 2) * 8) = param_3;
      }
    }
  }
  return;
}



long FUN_0011de5c(ulong *param_1,ulong param_2)

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
  ulong uVar12;
  long *plVar13;
  size_t __size;
  ulong uVar14;
  ulong *puVar15;
  ulong *puVar16;
  code *pcVar17;
  ulong uVar18;
  ulong *puVar19;
  ulong uVar20;
  long lVar21;
  ulong *puVar22;
  ulong local_18;
  ulong *local_10;
  void *local_8;
  
  if ((*(byte *)(param_1 + 4) & 1) != 0) goto LAB_0011de8c;
  uVar18 = (ulong)(*(uint *)(param_1 + 4) >> 0xb);
  if (uVar18 == 0) {
    if ((*(byte *)(param_1 + 4) >> 1 & 1) == 0) {
      uVar18 = FUN_0011dbc8(param_1,param_1[3]);
      if (uVar18 != 0xffffffffffffffff) goto LAB_0011df04;
LAB_0011dec4:
      param_1[4] = 0;
      *(undefined2 *)(param_1 + 4) = 0x7f8;
      param_1[3] = (ulong)&DAT_00147fb8;
    }
    else {
      for (plVar13 = (long *)param_1[3]; *plVar13 != 0; plVar13 = plVar13 + 1) {
        lVar10 = FUN_0011dbc8(param_1);
        if (lVar10 == -1) goto LAB_0011dec4;
        uVar18 = uVar18 + lVar10;
      }
LAB_0011df04:
      uVar6 = (uint)uVar18 & 0x1fffff;
      if (uVar6 == uVar18) {
        uVar6 = *(uint *)(param_1 + 4) & 0x7ff | uVar6 << 0xb;
      }
      else {
        uVar6 = *(uint *)(param_1 + 4) & 0x7ff;
      }
      *(uint *)(param_1 + 4) = uVar6;
      if (uVar18 != 0) goto LAB_0011df2c;
    }
  }
  else {
LAB_0011df2c:
    __size = (uVar18 + 2) * 8;
    local_10 = (ulong *)malloc(__size);
    if (local_10 != (ulong *)0x0) {
      local_10[1] = 0;
      local_8 = malloc(__size);
      if (local_8 != (void *)0x0) {
        *(undefined8 *)((long)local_8 + 8) = 0;
      }
      if ((*(byte *)(param_1 + 4) >> 1 & 1) == 0) {
        FUN_0011dd28(param_1,&local_10,param_1[3]);
      }
      else {
        for (plVar13 = (long *)param_1[3]; *plVar13 != 0; plVar13 = plVar13 + 1) {
          FUN_0011dd28(param_1,&local_10);
        }
      }
      pvVar4 = local_8;
      puVar3 = local_10;
      if ((local_10 != (ulong *)0x0) && (local_10[1] != uVar18)) {
LAB_0011e284:
                    // WARNING: Subroutine does not return
        abort();
      }
      if ((*(byte *)(param_1 + 4) >> 2 & 1) == 0) {
        if ((*(ushort *)(param_1 + 4) & 0x7f8) == 0) {
          pcVar17 = FUN_0011d07c;
        }
        else {
          pcVar17 = FUN_0011d41c;
        }
      }
      else {
        pcVar17 = FUN_0011db2c;
      }
      if (local_8 == (void *)0x0) {
        FUN_0011d158(param_1,pcVar17,local_10);
      }
      else {
        puVar19 = local_10 + 2;
        uVar20 = local_10[1];
        puVar15 = &DAT_00147fb0;
        puVar22 = puVar19;
        for (uVar14 = 0; uVar14 != uVar20; uVar14 = uVar14 + 1) {
          while ((puVar15 != &DAT_00147fb0 &&
                 (iVar7 = (*pcVar17)(param_1,*puVar22,*puVar15), iVar7 < 0))) {
            puVar16 = *(ulong **)((long)pvVar4 + (long)puVar15 + (0x10 - (long)puVar19));
            *(undefined8 *)((long)pvVar4 + (long)puVar15 + (0x10 - (long)puVar19)) = 0;
            puVar15 = puVar16;
          }
          *(ulong **)((long)pvVar4 + uVar14 * 8 + 0x10) = puVar15;
          puVar15 = puVar22;
          puVar22 = puVar22 + 1;
        }
        uVar11 = 0;
        uVar14 = uVar11;
        for (uVar12 = uVar11; uVar12 != uVar20; uVar12 = uVar12 + 1) {
          if (*(long *)((long)pvVar4 + uVar12 * 8 + 0x10) == 0) {
            lVar10 = uVar11 + 2;
            uVar11 = uVar11 + 1;
            *(ulong *)((long)pvVar4 + lVar10 * 8) = *puVar19;
          }
          else {
            lVar10 = uVar14 + 2;
            uVar14 = uVar14 + 1;
            puVar3[lVar10] = *puVar19;
          }
          puVar19 = puVar19 + 1;
        }
        puVar3[1] = uVar14;
        *(ulong *)((long)pvVar4 + 8) = uVar11;
        if (*(long *)((long)local_8 + 8) + local_10[1] != uVar18) goto LAB_0011e284;
        FUN_0011d158(param_1,pcVar17);
        pvVar4 = local_8;
        puVar3 = local_10;
        lVar10 = *(long *)((long)local_8 + 8);
        if (lVar10 != 0) {
          uVar18 = local_10[1];
          lVar21 = lVar10 << 3;
          do {
            lVar10 = lVar10 + -1;
            uVar14 = *(ulong *)((long)pvVar4 + lVar21 + 8);
            puVar19 = puVar3 + uVar18;
            while (uVar18 != 0) {
              iVar7 = (*pcVar17)(param_1,puVar19[1],uVar14);
              if (iVar7 < 1) break;
              *(ulong *)((long)(puVar19 + -1) + lVar21 + 0x10) = puVar19[1];
              uVar18 = uVar18 - 1;
              puVar19 = puVar19 + -1;
            }
            lVar21 = lVar21 + -8;
            puVar3[uVar18 + lVar10 + 2] = uVar14;
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
LAB_0011de8c:
  bVar5 = *(byte *)(param_1 + 4);
  if ((bVar5 & 1) == 0) {
    if ((bVar5 >> 1 & 1) == 0) {
      lVar10 = FUN_0011d5a8(param_1,param_1[3],param_2);
      return lVar10;
    }
    for (plVar13 = (long *)param_1[3]; *plVar13 != 0; plVar13 = plVar13 + 1) {
      lVar10 = FUN_0011d5a8(param_1,*plVar13,param_2);
      if (lVar10 != 0) {
        return lVar10;
      }
    }
  }
  else if ((bVar5 >> 2 & 1) == 0) {
    if ((*(ushort *)(param_1 + 4) & 0x7f8) == 0) {
      uVar18 = 0;
      uVar14 = *(ulong *)(param_1[3] + 8);
      while (uVar20 = uVar14, uVar18 < uVar20) {
        uVar14 = uVar20 + uVar18 >> 1;
        lVar10 = *(long *)(param_1[3] + (uVar14 + 2) * 8);
        if (*(ulong *)(lVar10 + 8) <= param_2) {
          if (param_2 < *(ulong *)(lVar10 + 8) + *(long *)(lVar10 + 0x10)) {
            return lVar10;
          }
          uVar18 = uVar14 + 1;
          uVar14 = uVar20;
        }
      }
    }
    else {
      uVar1 = *(ushort *)(param_1 + 4) >> 3;
      uVar2 = uVar1 & 0xff;
      uVar20 = param_1[3];
      uVar18 = 0;
      uVar8 = FUN_0011d26c(uVar2,param_1);
      uVar14 = *(ulong *)(uVar20 + 8);
      while (uVar12 = uVar14, uVar18 < uVar12) {
        uVar14 = uVar12 + uVar18 >> 1;
        lVar10 = *(long *)(uVar20 + (uVar14 + 2) * 8);
        uVar9 = FUN_0011d32c(uVar2,uVar8,lVar10 + 8,&local_18);
        FUN_0011d32c(uVar1 & 0xf,0,uVar9,&local_10);
        if (local_18 <= param_2) {
          if (param_2 < local_18 + (long)local_10) {
            return lVar10;
          }
          uVar18 = uVar14 + 1;
          uVar14 = uVar12;
        }
      }
    }
  }
  else {
    uVar20 = param_1[3];
    uVar18 = 0;
    uVar14 = *(ulong *)(uVar20 + 8);
    while (uVar12 = uVar14, uVar18 < uVar12) {
      uVar14 = uVar12 + uVar18 >> 1;
      lVar10 = *(long *)(uVar20 + (uVar14 + 2) * 8);
      bVar5 = FUN_0011d708(lVar10);
      uVar8 = FUN_0011d26c(bVar5,param_1);
      uVar8 = FUN_0011d32c(bVar5,uVar8,lVar10 + 8,&local_18);
      FUN_0011d32c(bVar5 & 0xf,0,uVar8,&local_10);
      if (local_18 <= param_2) {
        if (param_2 < local_18 + (long)local_10) {
          return lVar10;
        }
        uVar18 = uVar14 + 1;
        uVar14 = uVar12;
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
    param_2[3] = param_1;
    param_2[4] = 0;
    *param_2 = 0xffffffffffffffff;
    param_2[1] = param_3;
    param_2[2] = param_4;
    *(undefined2 *)(param_2 + 4) = 0x7f8;
    pthread_mutex_lock((pthread_mutex_t *)&DAT_00147fc0);
    param_2[5] = DAT_00147fe8;
    DAT_00147fe8 = param_2;
    uVar1 = pthread_mutex_unlock((pthread_mutex_t *)&DAT_00147fc0);
    return (int *)(ulong)uVar1;
  }
  return param_1;
}



void __register_frame_info(void)

{
  __register_frame_info_bases();
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



int __register_frame_info_table_bases
              (undefined8 param_1,undefined8 *param_2,undefined8 param_3,undefined8 param_4)

{
  undefined8 *puVar1;
  int iVar2;
  
  param_2[4] = 0;
  param_2[3] = param_1;
  *(undefined *)(param_2 + 4) = 2;
  *param_2 = 0xffffffffffffffff;
  param_2[1] = param_3;
  param_2[2] = param_4;
  *(ushort *)(param_2 + 4) = *(ushort *)(param_2 + 4) | 0x7f8;
  pthread_mutex_lock((pthread_mutex_t *)&DAT_00147fc0);
  puVar1 = param_2;
  param_2[5] = DAT_00147fe8;
  DAT_00147fe8 = puVar1;
  iVar2 = pthread_mutex_unlock((pthread_mutex_t *)&DAT_00147fc0);
  return iVar2;
}



void __register_frame_info_table(void)

{
  __register_frame_info_table_bases();
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
  undefined8 *puVar3;
  
  if (param_1 == (int *)0x0) {
    lVar2 = 0;
  }
  else if (*param_1 == 0) {
    lVar2 = 0;
  }
  else {
    puVar3 = &DAT_00147fe8;
    pthread_mutex_lock((pthread_mutex_t *)&DAT_00147fc0);
    for (lVar2 = DAT_00147fe8; lVar2 != 0; lVar2 = *(long *)(lVar2 + 0x28)) {
      if (*(int **)(lVar2 + 0x18) == param_1) {
        *puVar3 = *(undefined8 *)(lVar2 + 0x28);
        goto LAB_0011e608;
      }
      puVar3 = (undefined8 *)(lVar2 + 0x28);
    }
    plVar1 = &DAT_00147ff0;
    while (lVar2 = *plVar1, lVar2 != 0) {
      if ((*(byte *)(lVar2 + 0x20) & 1) == 0) {
        if (*(int **)(lVar2 + 0x18) == param_1) {
          *plVar1 = *(long *)(lVar2 + 0x28);
          break;
        }
      }
      else if (**(int ***)(lVar2 + 0x18) == param_1) {
        *plVar1 = *(long *)(lVar2 + 0x28);
        free(*(void **)(lVar2 + 0x18));
        break;
      }
      plVar1 = (long *)(lVar2 + 0x28);
    }
LAB_0011e608:
    pthread_mutex_unlock((pthread_mutex_t *)&DAT_00147fc0);
    if (lVar2 == 0) {
                    // WARNING: Subroutine does not return
      abort();
    }
  }
  return lVar2;
}



long __deregister_frame_info(int *param_1)

{
  long *plVar1;
  long lVar2;
  undefined8 *puVar3;
  
  if (param_1 == (int *)0x0) {
    lVar2 = 0;
  }
  else if (*param_1 == 0) {
    lVar2 = 0;
  }
  else {
    puVar3 = &DAT_00147fe8;
    pthread_mutex_lock((pthread_mutex_t *)&DAT_00147fc0);
    for (lVar2 = DAT_00147fe8; lVar2 != 0; lVar2 = *(long *)(lVar2 + 0x28)) {
      if (*(int **)(lVar2 + 0x18) == param_1) {
        *puVar3 = *(undefined8 *)(lVar2 + 0x28);
        goto LAB_0011e608;
      }
      puVar3 = (undefined8 *)(lVar2 + 0x28);
    }
    plVar1 = &DAT_00147ff0;
    while (lVar2 = *plVar1, lVar2 != 0) {
      if ((*(byte *)(lVar2 + 0x20) & 1) == 0) {
        if (*(int **)(lVar2 + 0x18) == param_1) {
          *plVar1 = *(long *)(lVar2 + 0x28);
          break;
        }
      }
      else if (**(int ***)(lVar2 + 0x18) == param_1) {
        *plVar1 = *(long *)(lVar2 + 0x28);
        free(*(void **)(lVar2 + 0x18));
        break;
      }
      plVar1 = (long *)(lVar2 + 0x28);
    }
LAB_0011e608:
    pthread_mutex_unlock((pthread_mutex_t *)&DAT_00147fc0);
    if (lVar2 == 0) {
                    // WARNING: Subroutine does not return
      abort();
    }
  }
  return lVar2;
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



ulong _Unwind_Find_FDE(ulong param_1,ulong *param_2)

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
  ulong local_10;
  undefined4 local_8;
  
  pthread_mutex_lock((pthread_mutex_t *)&DAT_00147fc0);
  for (puVar7 = DAT_00147ff0; puVar7 != (ulong *)0x0; puVar7 = (ulong *)puVar7[5]) {
    if (*puVar7 <= param_1) {
      local_10 = FUN_0011de5c(puVar7,param_1);
      if (local_10 != 0) goto LAB_0011e724;
      break;
    }
  }
  do {
    puVar7 = DAT_00147fe8;
    if (DAT_00147fe8 == (ulong *)0x0) {
      local_10 = 0;
      break;
    }
    DAT_00147fe8 = (ulong *)DAT_00147fe8[5];
    local_10 = FUN_0011de5c(puVar7,param_1);
    ppuVar4 = &DAT_00147ff0;
    for (puVar6 = DAT_00147ff0; (puVar6 != (ulong *)0x0 && (*puVar7 <= *puVar6));
        puVar6 = (ulong *)puVar6[5]) {
      ppuVar4 = (ulong **)(puVar6 + 5);
    }
    puVar7[5] = (ulong)puVar6;
    *ppuVar4 = puVar7;
  } while (local_10 == 0);
LAB_0011e724:
  pthread_mutex_unlock((pthread_mutex_t *)&DAT_00147fc0);
  if (local_10 == 0) {
    local_8 = 1;
    local_30 = param_1;
    local_28 = local_10;
    local_20 = local_10;
    local_18 = local_10;
    iVar3 = dl_iterate_phdr(FUN_0011d718,&local_30);
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
      uVar2 = FUN_0011d708(local_10);
    }
    uVar5 = FUN_0011d26c(uVar2 & 0xff,puVar7);
    FUN_0011d32c(uVar2 & 0xff,uVar5,local_10 + 8,&local_30);
  }
  param_2[2] = local_30;
  return local_10;
}



undefined  [16] __sfp_handle_exceptions(ulong param_1,undefined8 param_2)

{
  uint uVar1;
  undefined auVar2 [16];
  
  uVar1 = (uint)param_1;
  if ((param_1 & 1) != 0) {
    param_2 = fpsr;
  }
  if ((uVar1 >> 1 & 1) != 0) {
    param_2 = fpsr;
  }
  if ((uVar1 >> 2 & 1) != 0) {
    param_2 = fpsr;
  }
  if ((uVar1 >> 3 & 1) != 0) {
    param_2 = fpsr;
  }
  if ((uVar1 >> 4 & 1) != 0) {
    param_1 = fpsr;
  }
  auVar2._8_8_ = param_2;
  auVar2._0_8_ = param_1;
  return auVar2;
}


