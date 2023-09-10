typedef unsigned char   undefined;

typedef unsigned char    byte;
typedef unsigned char    dwfenc;
typedef unsigned int    dword;
typedef unsigned long    qword;
typedef unsigned long    ulong;
typedef unsigned char    undefined1;
typedef unsigned int    undefined4;
typedef unsigned long    undefined8;
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

typedef ulong size_t;




void FUN_00100550(void)

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



void __cxa_finalize(void)

{
  __cxa_finalize();
  return;
}



void __stack_chk_fail(void)

{
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



void __cxa_atexit(void)

{
  __cxa_atexit();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void * memset(void *__s,int __c,size_t __n)

{
  void *pvVar1;
  
  pvVar1 = memset(__s,__c,__n);
  return pvVar1;
}



void entry(void)

{
  __cxa_finalize(&DAT_00112000);
  return;
}



void FUN_001005cc(code *param_1)

{
  if (param_1 != (code *)0x0) {
    (*param_1)();
  }
  return;
}



void ChooseData(long param_1,undefined8 *param_2,int param_3,uint param_4,int param_5,int param_6,
               int param_7)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  undefined8 *puVar9;
  uint uVar10;
  long lVar11;
  undefined8 *puVar12;
  int iVar13;
  undefined8 *puVar14;
  ulong uVar15;
  ulong uVar16;
  ulong uVar17;
  ulong uVar18;
  ulong uVar19;
  ulong uVar20;
  ulong uVar21;
  undefined8 uVar22;
  
  puVar9 = (undefined8 *)(param_1 + ((long)param_6 + (long)(param_5 * 0x6c)) * 2);
  if (0 < param_3) {
    uVar1 = (param_4 - 8 >> 3) + 1;
    iVar13 = 0;
    uVar8 = uVar1 * 8;
    uVar7 = uVar8;
    if (param_4 - 1 < 7) {
      uVar7 = 0;
    }
    uVar2 = uVar7 + 1;
    uVar15 = -(ulong)(uVar7 >> 0x1f) & 0xfffffffe00000000 | (ulong)uVar7 << 1;
    uVar3 = uVar7 + 2;
    uVar21 = -(ulong)(uVar2 >> 0x1f) & 0xfffffffe00000000 | (ulong)uVar2 << 1;
    uVar4 = uVar7 + 3;
    uVar20 = -(ulong)(uVar3 >> 0x1f) & 0xfffffffe00000000 | (ulong)uVar3 << 1;
    uVar5 = uVar7 + 4;
    uVar19 = -(ulong)(uVar4 >> 0x1f) & 0xfffffffe00000000 | (ulong)uVar4 << 1;
    uVar6 = uVar7 + 5;
    uVar18 = -(ulong)(uVar5 >> 0x1f) & 0xfffffffe00000000 | (ulong)uVar5 << 1;
    uVar7 = uVar7 + 6;
    uVar17 = -(ulong)(uVar6 >> 0x1f) & 0xfffffffe00000000 | (ulong)uVar6 << 1;
    uVar16 = -(ulong)(uVar7 >> 0x1f) & 0xfffffffe00000000 | (ulong)uVar7 << 1;
    do {
      if (0 < (int)param_4) {
        if ((puVar9 < param_2 + 2 && param_2 < puVar9 + 2) || (param_4 < 10)) {
          lVar11 = 0;
          do {
            *(undefined2 *)((long)param_2 + lVar11 * 2) = *(undefined2 *)((long)puVar9 + lVar11 * 2)
            ;
            lVar11 = lVar11 + 1;
          } while ((int)lVar11 < (int)param_4);
        }
        else {
          if (6 < param_4 - 1) {
            uVar10 = 0;
            puVar12 = param_2;
            puVar14 = puVar9;
            do {
              uVar22 = *puVar14;
              uVar10 = uVar10 + 1;
              puVar12[1] = puVar14[1];
              *puVar12 = uVar22;
              puVar12 = puVar12 + 2;
              puVar14 = puVar14 + 2;
            } while (uVar10 < uVar1);
            if (param_4 == uVar8) goto LAB_00100754;
          }
          *(undefined2 *)((long)param_2 + uVar15) = *(undefined2 *)((long)puVar9 + uVar15);
          if (((((int)uVar2 < (int)param_4) &&
               (*(undefined2 *)((long)param_2 + uVar21) = *(undefined2 *)((long)puVar9 + uVar21),
               (int)uVar3 < (int)param_4)) &&
              (*(undefined2 *)((long)param_2 + uVar20) = *(undefined2 *)((long)puVar9 + uVar20),
              (int)uVar4 < (int)param_4)) &&
             (((*(undefined2 *)((long)param_2 + uVar19) = *(undefined2 *)((long)puVar9 + uVar19),
               (int)uVar5 < (int)param_4 &&
               (*(undefined2 *)((long)param_2 + uVar18) = *(undefined2 *)((long)puVar9 + uVar18),
               (int)uVar6 < (int)param_4)) &&
              (*(undefined2 *)((long)param_2 + uVar17) = *(undefined2 *)((long)puVar9 + uVar17),
              (int)uVar7 < (int)param_4)))) {
            *(undefined2 *)((long)param_2 + uVar16) = *(undefined2 *)((long)puVar9 + uVar16);
          }
        }
      }
LAB_00100754:
      iVar13 = iVar13 + 1;
      param_2 = (undefined8 *)
                ((long)param_2 +
                (-(ulong)(param_4 >> 0x1f) & 0xfffffffe00000000 | (ulong)param_4 << 1));
      puVar9 = (undefined8 *)
               ((long)puVar9 +
               (-(ulong)((uint)(param_7 * 0x6c) >> 0x1f) & 0xfffffffe00000000 |
               (ulong)(uint)(param_7 * 0x6c) << 1));
    } while (iVar13 != param_3);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void Navigation(ushort *param_1,int *param_2,ushort *param_3,int param_4,ulong param_5,
               undefined8 param_6,undefined8 param_7,int param_8,char param_9)

{
  undefined8 *puVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  ushort uVar5;
  uint uVar6;
  uint uVar7;
  undefined8 uVar8;
  undefined8 uVar9;
  undefined auVar10 [16];
  undefined auVar11 [16];
  int iVar12;
  uint uVar13;
  long lVar14;
  long lVar15;
  uint uVar16;
  int iVar17;
  ushort uVar18;
  int iVar19;
  long lVar20;
  uint uVar21;
  int iVar22;
  int iVar23;
  int iVar24;
  int iVar25;
  undefined2 *puVar26;
  int iVar27;
  int iVar28;
  ushort *puVar29;
  ulong uVar30;
  int iVar31;
  ushort *puVar32;
  int iVar33;
  undefined *puVar34;
  undefined2 *puVar35;
  long lVar36;
  int iVar37;
  uint uVar38;
  undefined uVar39;
  undefined uVar40;
  undefined uVar41;
  undefined uVar42;
  byte bVar43;
  byte bVar44;
  byte bVar45;
  undefined auVar46 [16];
  undefined auVar47 [16];
  int iVar48;
  undefined auVar49 [16];
  byte bVar50;
  byte bVar51;
  byte bVar52;
  undefined2 local_4a48 [9504];
  long local_8;
  
  puVar35 = local_4a48;
  local_8 = ___stack_chk_guard;
  memset(puVar35,0,0x4a40);
  if ((param_3 == (ushort *)0x0 || param_2 == (int *)0x0) || (param_1 == (ushort *)0x0)) {
    *param_2 = 0;
    goto LAB_00100b9c;
  }
  uVar21 = (uint)param_5;
  if (param_4 < 1) {
LAB_00100f64:
    iVar33 = 0;
    iVar37 = 0;
    iVar17 = 0;
    iVar48 = 0;
  }
  else {
    uVar38 = (uVar21 - 8 >> 3) + 1;
    lVar36 = (long)(int)(uVar21 << 1);
    uVar6 = uVar38 * 8;
    uVar30 = -(param_5 >> 0x1f & 1) & 0xfffffffe00000000 | (param_5 & 0xffffffff) << 1;
    iVar37 = 0;
    do {
      if (0 < (int)uVar21) {
        if (uVar21 - 1 < 7) {
          puVar26 = puVar35;
          puVar29 = param_1;
          puVar32 = param_3;
          uVar16 = 0;
        }
        else {
          lVar14 = 0;
          uVar16 = 0;
          do {
            puVar1 = (undefined8 *)((long)puVar35 + lVar14);
            uVar16 = uVar16 + 1;
            auVar46 = *(undefined (*) [16])((long)param_1 + lVar14);
            uVar9 = ((undefined8 *)((long)param_3 + lVar14))[1];
            uVar8 = *(undefined8 *)((long)param_3 + lVar14);
            lVar14 = lVar14 + 0x10;
            iVar23 = (uint)(ushort)uVar8 - (uint)auVar46._0_2_;
            iVar22 = (uint)(ushort)((ulong)uVar8 >> 0x10) - (uint)auVar46._2_2_;
            bVar50 = (byte)((uint)iVar22 >> 8);
            iVar25 = (uint)(ushort)((ulong)uVar8 >> 0x20) - (uint)auVar46._4_2_;
            bVar51 = (byte)((uint)iVar25 >> 8);
            iVar12 = (uint)(ushort)((ulong)uVar8 >> 0x30) - (uint)auVar46._6_2_;
            bVar52 = (byte)((uint)iVar12 >> 8);
            iVar33 = (uint)(ushort)uVar9 - (uint)auVar46._8_2_;
            iVar48 = (uint)(ushort)((ulong)uVar9 >> 0x10) - (uint)auVar46._10_2_;
            bVar43 = (byte)((uint)iVar48 >> 8);
            iVar17 = (uint)(ushort)((ulong)uVar9 >> 0x20) - (uint)auVar46._12_2_;
            bVar44 = (byte)((uint)iVar17 >> 8);
            iVar19 = (uint)(ushort)((ulong)uVar9 >> 0x30) - (uint)auVar46._14_2_;
            bVar45 = (byte)((uint)iVar19 >> 8);
            auVar49._8_4_ = 200;
            auVar49._0_8_ = 0xc8000000c8;
            auVar49._12_4_ = 200;
            auVar11[4] = (byte)iVar22;
            auVar11._0_4_ = iVar23;
            auVar11[5] = bVar50;
            auVar11[6] = (char)((uint)iVar22 >> 0x10);
            auVar11[7] = (char)((uint)iVar22 >> 0x18);
            auVar11[8] = (byte)iVar25;
            auVar11[9] = bVar51;
            auVar11[10] = (char)((uint)iVar25 >> 0x10);
            auVar11[11] = (char)((uint)iVar25 >> 0x18);
            auVar11[12] = (byte)iVar12;
            auVar11[13] = bVar52;
            auVar11[14] = (char)((uint)iVar12 >> 0x10);
            auVar11[15] = (char)((uint)iVar12 >> 0x18);
            auVar49 = NEON_cmgt(auVar11,auVar49,4);
            auVar46[4] = (byte)iVar48;
            auVar46._0_4_ = iVar33;
            auVar46[5] = bVar43;
            auVar46[6] = (char)((uint)iVar48 >> 0x10);
            auVar46[7] = (char)((uint)iVar48 >> 0x18);
            auVar46[8] = (byte)iVar17;
            auVar46[9] = bVar44;
            auVar46[10] = (char)((uint)iVar17 >> 0x10);
            auVar46[11] = (char)((uint)iVar17 >> 0x18);
            auVar46[12] = (byte)iVar19;
            auVar46[13] = bVar45;
            auVar46[14] = (char)((uint)iVar19 >> 0x10);
            auVar46[15] = (char)((uint)iVar19 >> 0x18);
            auVar10._8_4_ = 200;
            auVar10._0_8_ = 0xc8000000c8;
            auVar10._12_4_ = 200;
            auVar46 = NEON_cmgt(auVar46,auVar10,4);
            auVar47._0_8_ =
                 CONCAT26(CONCAT11(auVar49[13] & bVar52,auVar49[12] & (byte)iVar12),
                          CONCAT24(CONCAT11(auVar49[9] & bVar51,auVar49[8] & (byte)iVar25),
                                   CONCAT22(CONCAT11(auVar49[5] & bVar50,auVar49[4] & (byte)iVar22),
                                            CONCAT11(auVar49[1] & (byte)((uint)iVar23 >> 8),
                                                     auVar49[0] & (byte)iVar23))));
            auVar47[9] = auVar46[1] & (byte)((uint)iVar33 >> 8);
            auVar47[8] = auVar46[0] & (byte)iVar33;
            auVar47[11] = auVar46[5] & bVar43;
            auVar47[10] = auVar46[4] & (byte)iVar48;
            auVar47[13] = auVar46[9] & bVar44;
            auVar47[12] = auVar46[8] & (byte)iVar17;
            auVar47[15] = auVar46[13] & bVar45;
            auVar47[14] = auVar46[12] & (byte)iVar19;
            puVar1[1] = auVar47._8_8_;
            *puVar1 = auVar47._0_8_;
          } while (uVar16 < uVar38);
          puVar32 = param_3 + uVar6;
          puVar29 = param_1 + uVar6;
          puVar26 = puVar35 + uVar6;
          uVar16 = uVar6;
          if (uVar6 == uVar21) goto LAB_001009f4;
        }
        iVar33 = (uint)*puVar32 - (uint)*puVar29;
        if (iVar33 < 0xc9) {
          iVar33 = 0;
        }
        *puVar26 = (short)iVar33;
        if ((int)(uVar16 + 1) < (int)uVar21) {
          iVar33 = (uint)puVar32[1] - (uint)puVar29[1];
          if (iVar33 < 0xc9) {
            iVar33 = 0;
          }
          puVar26[1] = (short)iVar33;
          if ((int)(uVar16 + 2) < (int)uVar21) {
            iVar33 = (uint)puVar32[2] - (uint)puVar29[2];
            if (iVar33 < 0xc9) {
              iVar33 = 0;
            }
            puVar26[2] = (short)iVar33;
            if ((int)(uVar16 + 3) < (int)uVar21) {
              iVar33 = (uint)puVar32[3] - (uint)puVar29[3];
              if (iVar33 < 0xc9) {
                iVar33 = 0;
              }
              puVar26[3] = (short)iVar33;
              if ((int)(uVar16 + 4) < (int)uVar21) {
                iVar33 = (uint)puVar32[4] - (uint)puVar29[4];
                if (iVar33 < 0xc9) {
                  iVar33 = 0;
                }
                puVar26[4] = (short)iVar33;
                if ((int)(uVar16 + 5) < (int)uVar21) {
                  iVar33 = (uint)puVar32[5] - (uint)puVar29[5];
                  if (iVar33 < 0xc9) {
                    iVar33 = 0;
                  }
                  puVar26[5] = (short)iVar33;
                  if ((int)(uVar16 + 6) < (int)uVar21) {
                    iVar33 = (uint)puVar32[6] - (uint)puVar29[6];
                    if (iVar33 < 0xc9) {
                      iVar33 = 0;
                    }
                    puVar26[6] = (short)iVar33;
                  }
                }
              }
            }
          }
        }
      }
LAB_001009f4:
      iVar37 = iVar37 + 1;
      puVar35 = puVar35 + lVar36;
      param_3 = (ushort *)((long)param_3 + uVar30);
      param_1 = (ushort *)((long)param_1 + uVar30);
    } while (iVar37 != param_4);
    lVar14 = (long)local_4a48 + uVar30;
    if (1 < param_4) {
      iVar37 = 1;
      do {
        lVar15 = 0;
        if (0 < (int)uVar21) {
          do {
            while( true ) {
              uVar18 = *(ushort *)
                        (lVar14 + lVar15 * 2 +
                                  (-(ulong)(-uVar21 >> 0x1f) & 0xfffffffe00000000 |
                                  (ulong)-uVar21 << 1));
              if (uVar18 != 0) break;
LAB_00100a48:
              *(ushort *)(lVar14 + lVar15 * 2) = uVar18;
              lVar15 = lVar15 + 1;
              if ((int)uVar21 <= (int)lVar15) goto LAB_00100a80;
            }
            uVar5 = *(ushort *)(lVar14 + lVar15 * 2 + uVar30);
            if (uVar5 != 0) {
              uVar18 = (ushort)((uint)uVar18 + (uint)uVar5 >> 1);
              goto LAB_00100a48;
            }
            *(ushort *)(lVar14 + lVar15 * 2) = uVar5;
            lVar15 = lVar15 + 1;
          } while ((int)lVar15 < (int)uVar21);
        }
LAB_00100a80:
        iVar37 = iVar37 + 1;
        lVar14 = lVar14 + lVar36 * 2;
      } while (iVar37 < param_4);
      if (param_4 < 1) goto LAB_00100f64;
    }
    iVar33 = 0;
    iVar17 = 0;
    iVar23 = 0;
    iVar19 = 0;
    iVar37 = 0;
    puVar35 = local_4a48;
    do {
      lVar14 = 0;
      iVar48 = iVar17;
      if (0 < (int)uVar21) {
        do {
          uVar18 = puVar35[lVar14];
          iVar22 = (int)lVar14;
          lVar14 = lVar14 + 1;
          iVar19 = iVar19 + (uint)uVar18;
          if (uVar18 != 0) {
            iVar37 = iVar37 + 1;
          }
          iVar17 = iVar48 + iVar33;
          iVar22 = iVar23 + iVar22;
          if (uVar18 == 0) {
            iVar17 = iVar48;
            iVar22 = iVar23;
          }
          iVar23 = iVar22;
          iVar48 = iVar17;
        } while ((int)lVar14 < (int)uVar21);
      }
      iVar33 = iVar33 + 1;
      puVar35 = puVar35 + lVar36;
    } while (iVar33 < param_4);
    if (iVar37 == 0) {
      iVar48 = 0;
      iVar17 = 0;
      iVar33 = 0;
    }
    else {
      iVar22 = iVar37 >> 1;
      iVar48 = 0;
      if (iVar37 != 0) {
        iVar48 = (iVar22 + iVar23) / iVar37;
      }
      iVar33 = 0;
      if (iVar37 != 0) {
        iVar33 = (iVar22 + iVar17) / iVar37;
      }
      iVar48 = iVar48 << 1;
      iVar17 = 0;
      if (iVar37 != 0) {
        iVar17 = (iVar22 + iVar19) / iVar37;
      }
      iVar33 = param_8 * iVar33;
    }
  }
  if (__bss_start__ == 0) {
    if ((DAT_00112034 < 0xb) && (10 < iVar37)) {
      __bss_start__ = 1;
      if (0x2ff < iVar37) {
        DAT_00112040 = DAT_00112040 + 1;
      }
      DAT_00112038 = iVar48;
      DAT_0011203c = iVar33;
      memcpy(&DAT_00112050,local_4a48,0x4a40);
      DAT_00116a90 = iVar17;
    }
    DAT_00112034 = iVar37;
    *param_2 = 0;
    goto LAB_00100b9c;
  }
  if (param_9 == '\0') {
    if (__bss_start__ < 0x1e) {
      if (10 < iVar37) {
        uVar38 = 0xffffffec;
        lVar36 = (long)(int)(uVar21 * -0x14);
        uVar30 = -(ulong)(uVar21 * 3 >> 0x1f) & 0xfffffffe00000000 | (ulong)(uVar21 * 3) << 1;
        iVar19 = 0x7fffffff;
        iVar23 = 0;
        uVar40 = 0;
        uVar41 = 0;
        uVar42 = 0;
        uVar39 = 0;
        do {
          uVar6 = uVar38;
          if ((int)uVar38 < 0) {
            uVar6 = 0;
          }
          uVar16 = uVar38;
          if (0 < (int)uVar38) {
            uVar16 = 0;
          }
          iVar12 = 0x14 - ((uVar38 ^ (int)uVar38 >> 0x1f) - ((int)uVar38 >> 0x1f));
          iVar25 = param_4 * 2 + -1 + uVar16;
          iVar22 = iVar12 * -2;
          lVar14 = (lVar36 + iVar22) * 2;
          do {
            iVar3 = iVar22;
            if (iVar22 < 0) {
              iVar3 = 0;
            }
            iVar4 = iVar22;
            if (0 < iVar22) {
              iVar4 = 0;
            }
            if ((int)uVar6 < iVar25) {
              lVar15 = ((long)(int)(uVar21 * uVar6) + (long)iVar3) * 2;
              iVar28 = 0;
              iVar31 = 0;
              puVar34 = &DAT_00112050 + lVar15;
              lVar15 = (long)local_4a48 + (lVar15 - lVar14);
              uVar16 = uVar6;
              do {
                if (iVar3 < (int)(uVar21 + iVar4)) {
                  lVar20 = 0;
                  iVar27 = iVar28;
                  iVar24 = iVar3;
                  do {
                    puVar32 = (ushort *)(puVar34 + lVar20);
                    iVar24 = iVar24 + 6;
                    puVar29 = (ushort *)(lVar15 + lVar20);
                    lVar20 = lVar20 + 0xc;
                    uVar7 = (uint)*puVar29 - (uint)*puVar32;
                    uVar2 = (uint)(*puVar29 != 0 && *puVar32 != 0);
                    uVar13 = (int)uVar7 >> 0x1f;
                    iVar31 = uVar2 + iVar31;
                    iVar28 = iVar27 + ((uVar7 ^ uVar13) - uVar13);
                    if (uVar2 == 0) {
                      iVar28 = iVar27;
                    }
                    iVar27 = iVar28;
                  } while (iVar24 < (int)(uVar21 + iVar4));
                }
                uVar16 = uVar16 + 3;
                puVar34 = puVar34 + uVar30;
                lVar15 = lVar15 + uVar30;
              } while ((int)uVar16 < iVar25);
              if (0xf < iVar31) {
                iVar3 = 0;
                if (iVar31 != 0) {
                  iVar3 = (iVar28 << 10) / iVar31;
                }
                if (iVar3 < iVar19) {
                  uVar39 = (undefined)uVar38;
                  uVar40 = (undefined)(uVar38 >> 8);
                  uVar41 = (undefined)(uVar38 >> 0x10);
                  uVar42 = (undefined)(uVar38 >> 0x18);
                  iVar19 = iVar3;
                  iVar23 = iVar22;
                }
              }
            }
            iVar22 = iVar22 + 1;
            lVar14 = lVar14 + 2;
          } while (iVar22 != iVar12 * 2 + 1);
          uVar38 = uVar38 + 1;
          lVar36 = lVar36 + (int)uVar21;
        } while (uVar38 != 0x15);
        uVar21 = iVar23 * 2;
        uVar38 = param_8 * CONCAT13(uVar42,CONCAT12(uVar41,CONCAT11(uVar40,uVar39)));
        iVar25 = (uVar21 ^ (int)uVar21 >> 0x1f) - ((int)uVar21 >> 0x1f);
        iVar22 = (uVar38 ^ (int)uVar38 >> 0x1f) - ((int)uVar38 >> 0x1f);
        iVar23 = (iVar17 + DAT_00116a90) * 0x107 + -0x12770;
        if (iVar25 < iVar22) {
          if (iVar19 < (iVar23 * (iVar22 * 5 + 800)) / 1000) {
            if ((int)uVar38 < 5) {
              if ((int)(uVar38 + 4) < 0 == SCARRY4(uVar38,4)) goto LAB_0010115c;
              DAT_00116ab8 = uVar38 + DAT_00116ab8;
              _DAT_00116aa0 = CONCAT44(_DAT_00116aa4 + 1,DAT_00116aa0);
            }
            else {
              DAT_00116ab8 = uVar38 + DAT_00116ab8;
              _DAT_00116aa8 = CONCAT44(DAT_00116aac,DAT_00116aa8 + 1);
            }
          }
        }
        else if (iVar19 < (iVar23 * (iVar25 * 5 + 800)) / 1000) {
          if ((int)uVar21 < 5) {
            if ((int)(uVar21 + 4) < 0 == SCARRY4(uVar21,4)) {
LAB_0010115c:
              _DAT_00116aa0 = CONCAT44(_DAT_00116aa4,DAT_00116aa0 + 1);
            }
            else {
              DAT_00116ab4 = uVar21 + DAT_00116ab4;
              DAT_00116ab0 = DAT_00116ab0 + 1;
            }
          }
          else {
            DAT_00116ab4 = uVar21 + DAT_00116ab4;
            _DAT_00116aa8 = CONCAT44(DAT_00116aac + 1,DAT_00116aa8);
          }
        }
        __bss_start__ = __bss_start__ + 1;
        if (0x2ff < iVar37) {
          DAT_00112040 = DAT_00112040 + 1;
        }
        DAT_00116abc = iVar48;
        DAT_00116ac0 = iVar33;
        memcpy(&DAT_00112050,local_4a48,0x4a40);
        DAT_00112034 = iVar37;
        DAT_00116a90 = iVar17;
        *param_2 = 0;
        goto LAB_00100b9c;
      }
      goto LAB_00100ec8;
    }
LAB_00100f1c:
    iVar33 = 5;
    if (((DAT_00116aa0 + 1 < __bss_start__) &&
        ((__bss_start__ < 7 ||
         ((DAT_00116aa0 + 2 < __bss_start__ &&
          ((__bss_start__ < 10 || (DAT_00116aa0 + 3 < __bss_start__)))))))) &&
       ((DAT_00116aa0 < 4 || ((1 < DAT_00112040 || (iVar33 = 5, DAT_00116aa0 + 5 < __bss_start__))))
       )) {
      if (DAT_00116aac < DAT_00116aa8) {
        lVar36 = 3;
        lVar14 = 2;
        iVar33 = DAT_00116aa8;
        DAT_00116aa8 = DAT_00116aac;
      }
      else {
        lVar36 = 2;
        lVar14 = 3;
        iVar33 = DAT_00116aac;
      }
      if (iVar33 < DAT_00116ab0) {
        lVar15 = 4;
        lVar36 = lVar14;
        iVar48 = DAT_00116ab0;
        DAT_00116aa8 = iVar33;
      }
      else {
        lVar15 = lVar14;
        iVar48 = iVar33;
        if (DAT_00116aa8 < DAT_00116ab0) {
          lVar36 = 4;
          DAT_00116aa8 = DAT_00116ab0;
        }
      }
      if (iVar48 < _DAT_00116aa4) {
        if (_DAT_00116aa4 < 2) goto LAB_00101040;
        iVar33 = 1;
      }
      else {
        if (DAT_00116aa8 < _DAT_00116aa4) {
          lVar36 = 1;
          DAT_00116aa8 = _DAT_00116aa4;
        }
        iVar17 = (int)lVar15;
        iVar33 = 2;
        if ((iVar17 == 2) && (iVar33 = 2, iVar48 != DAT_00116aa8)) {
          iVar33 = 1;
        }
        if (iVar33 < iVar48) {
          iVar19 = (int)lVar36;
          iVar33 = iVar17;
          if ((iVar19 != iVar17) && (iVar48 <= DAT_00116aa8)) {
            if (((&DAT_00116aa0)[lVar15] <= (&DAT_00116aa0)[lVar36]) &&
               (iVar33 = iVar19, (&DAT_00116aa0)[lVar36] <= (&DAT_00116aa0)[lVar15])) {
              iVar33 = iVar17;
              if (((&DAT_00116aa0)[lVar15] <= (&DAT_00116aa0)[lVar36]) &&
                 (iVar33 = iVar19, (&DAT_00116aa0)[lVar36] <= (&DAT_00116aa0)[lVar15]))
              goto LAB_00101040;
            }
          }
        }
        else {
LAB_00101040:
          iVar33 = 7;
        }
      }
    }
    *param_2 = iVar33;
  }
  else {
LAB_00100ec8:
    if (2 < __bss_start__) goto LAB_00100f1c;
    *param_2 = 7;
  }
  __bss_start__ = 0;
  DAT_00112040 = 0;
  _DAT_00116aa0 = 0;
  _DAT_00116aa8 = 0;
  DAT_00116ab0 = 0;
  DAT_00116ab4 = 0;
  DAT_00116ab8 = 0;
  DAT_00112038 = 0;
  DAT_0011203c = 0;
  DAT_00116abc = 0;
  DAT_00116ac0 = 0;
  DAT_00112034 = iVar37;
LAB_00100b9c:
  if (local_8 != ___stack_chk_guard) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail();
  }
  return;
}



char * getNavigationVersion(void)

{
  return s_MilanF_Navigation_v_1_01_08_00112010;
}


