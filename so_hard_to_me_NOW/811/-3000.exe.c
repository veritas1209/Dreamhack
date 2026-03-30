typedef unsigned char   undefined;

typedef unsigned long long    GUID;
typedef pointer32 ImageBaseOffset32;

typedef unsigned char    bool;
typedef unsigned char    byte;
typedef unsigned int    dword;
typedef long long    longlong;
typedef unsigned long long    qword;
typedef unsigned char    uchar;
typedef unsigned int    uint;
typedef unsigned long    ulong;
typedef unsigned long long    ulonglong;
typedef unsigned char    undefined1;
typedef unsigned short    undefined2;
typedef unsigned int    undefined4;
typedef unsigned long long    undefined8;
typedef unsigned short    ushort;
typedef unsigned short    wchar16;
typedef short    wchar_t;
typedef unsigned short    word;
typedef struct _s__RTTIBaseClassDescriptor _s__RTTIBaseClassDescriptor, *P_s__RTTIBaseClassDescriptor;

typedef struct _s__RTTIBaseClassDescriptor RTTIBaseClassDescriptor;

typedef RTTIBaseClassDescriptor * RTTIBaseClassDescriptor *32 __((image-base-relative));

typedef RTTIBaseClassDescriptor *32 __((image-base-relative)) * RTTIBaseClassDescriptor *32 __((image-base-relative)) *32 __((image-base-relative));

typedef struct PMD PMD, *PPMD;

struct PMD {
    int mdisp;
    int pdisp;
    int vdisp;
};

struct _s__RTTIBaseClassDescriptor {
    ImageBaseOffset32 pTypeDescriptor; // ref to TypeDescriptor (RTTI 0) for class
    dword numContainedBases; // count of extended classes in BaseClassArray (RTTI 2)
    struct PMD where; // member displacement structure
    dword attributes; // bit flags
    ImageBaseOffset32 pClassHierarchyDescriptor; // ref to ClassHierarchyDescriptor (RTTI 3) for class
};

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion;

typedef struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct;

struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct {
    dword OffsetToDirectory;
    dword DataIsDirectory;
};

union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion {
    dword OffsetToData;
    struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct;
};

typedef struct _s__RTTIClassHierarchyDescriptor _s__RTTIClassHierarchyDescriptor, *P_s__RTTIClassHierarchyDescriptor;

struct _s__RTTIClassHierarchyDescriptor {
    dword signature;
    dword attributes; // bit flags
    dword numBaseClasses; // number of base classes (i.e. rtti1Count)
    RTTIBaseClassDescriptor *32 __((image-base-relative)) *32 __((image-base-relative)) pBaseClassArray; // ref to BaseClassArray (RTTI 2)
};

typedef struct _s__RTTICompleteObjectLocator _s__RTTICompleteObjectLocator, *P_s__RTTICompleteObjectLocator;

struct _s__RTTICompleteObjectLocator {
    dword signature;
    dword offset; // offset of vbtable within class
    dword cdOffset; // constructor displacement offset
    ImageBaseOffset32 pTypeDescriptor; // ref to TypeDescriptor (RTTI 0) for class
    ImageBaseOffset32 pClassDescriptor; // ref to ClassHierarchyDescriptor (RTTI 3)
};

typedef struct _IMAGE_RUNTIME_FUNCTION_ENTRY _IMAGE_RUNTIME_FUNCTION_ENTRY, *P_IMAGE_RUNTIME_FUNCTION_ENTRY;

struct _IMAGE_RUNTIME_FUNCTION_ENTRY {
    ImageBaseOffset32 BeginAddress;
    ImageBaseOffset32 EndAddress;
    ImageBaseOffset32 UnwindInfoAddressOrData;
};

typedef struct CLIENT_ID CLIENT_ID, *PCLIENT_ID;

struct CLIENT_ID {
    void * UniqueProcess;
    void * UniqueThread;
};

typedef struct _s__RTTIClassHierarchyDescriptor RTTIClassHierarchyDescriptor;

typedef ulonglong __uint64;

typedef struct _s__RTTICompleteObjectLocator RTTICompleteObjectLocator;

typedef struct exception exception, *Pexception;

struct exception { // PlaceHolder Class Structure
};

typedef struct bad_alloc bad_alloc, *Pbad_alloc;

struct bad_alloc { // PlaceHolder Class Structure
};

typedef struct bad_array_new_length bad_array_new_length, *Pbad_array_new_length;

struct bad_array_new_length { // PlaceHolder Class Structure
};

typedef struct _SECURITY_ATTRIBUTES _SECURITY_ATTRIBUTES, *P_SECURITY_ATTRIBUTES;

typedef ulong DWORD;

typedef void * LPVOID;

typedef int BOOL;

struct _SECURITY_ATTRIBUTES {
    DWORD nLength;
    LPVOID lpSecurityDescriptor;
    BOOL bInheritHandle;
};

typedef struct _OVERLAPPED _OVERLAPPED, *P_OVERLAPPED;

typedef ulonglong ULONG_PTR;

typedef union _union_540 _union_540, *P_union_540;

typedef void * HANDLE;

typedef struct _struct_541 _struct_541, *P_struct_541;

typedef void * PVOID;

struct _struct_541 {
    DWORD Offset;
    DWORD OffsetHigh;
};

union _union_540 {
    struct _struct_541 s;
    PVOID Pointer;
};

struct _OVERLAPPED {
    ULONG_PTR Internal;
    ULONG_PTR InternalHigh;
    union _union_540 u;
    HANDLE hEvent;
};

typedef struct _OVERLAPPED * LPOVERLAPPED;

typedef long LONG;

typedef struct _EXCEPTION_POINTERS _EXCEPTION_POINTERS, *P_EXCEPTION_POINTERS;

typedef LONG (* PTOP_LEVEL_EXCEPTION_FILTER)(struct _EXCEPTION_POINTERS *);

typedef struct _EXCEPTION_RECORD _EXCEPTION_RECORD, *P_EXCEPTION_RECORD;

typedef struct _EXCEPTION_RECORD EXCEPTION_RECORD;

typedef EXCEPTION_RECORD * PEXCEPTION_RECORD;

typedef struct _CONTEXT _CONTEXT, *P_CONTEXT;

typedef struct _CONTEXT * PCONTEXT;

typedef ulonglong DWORD64;

typedef ushort WORD;

typedef union _union_54 _union_54, *P_union_54;

typedef struct _M128A _M128A, *P_M128A;

typedef struct _M128A M128A;

typedef struct _XSAVE_FORMAT _XSAVE_FORMAT, *P_XSAVE_FORMAT;

typedef struct _XSAVE_FORMAT XSAVE_FORMAT;

typedef XSAVE_FORMAT XMM_SAVE_AREA32;

typedef struct _struct_55 _struct_55, *P_struct_55;

typedef ulonglong ULONGLONG;

typedef longlong LONGLONG;

typedef uchar BYTE;

struct _M128A {
    ULONGLONG Low;
    LONGLONG High;
};

struct _XSAVE_FORMAT {
    WORD ControlWord;
    WORD StatusWord;
    BYTE TagWord;
    BYTE Reserved1;
    WORD ErrorOpcode;
    DWORD ErrorOffset;
    WORD ErrorSelector;
    WORD Reserved2;
    DWORD DataOffset;
    WORD DataSelector;
    WORD Reserved3;
    DWORD MxCsr;
    DWORD MxCsr_Mask;
    M128A FloatRegisters[8];
    M128A XmmRegisters[16];
    BYTE Reserved4[96];
};

struct _struct_55 {
    M128A Header[2];
    M128A Legacy[8];
    M128A Xmm0;
    M128A Xmm1;
    M128A Xmm2;
    M128A Xmm3;
    M128A Xmm4;
    M128A Xmm5;
    M128A Xmm6;
    M128A Xmm7;
    M128A Xmm8;
    M128A Xmm9;
    M128A Xmm10;
    M128A Xmm11;
    M128A Xmm12;
    M128A Xmm13;
    M128A Xmm14;
    M128A Xmm15;
};

union _union_54 {
    XMM_SAVE_AREA32 FltSave;
    struct _struct_55 s;
};

struct _CONTEXT {
    DWORD64 P1Home;
    DWORD64 P2Home;
    DWORD64 P3Home;
    DWORD64 P4Home;
    DWORD64 P5Home;
    DWORD64 P6Home;
    DWORD ContextFlags;
    DWORD MxCsr;
    WORD SegCs;
    WORD SegDs;
    WORD SegEs;
    WORD SegFs;
    WORD SegGs;
    WORD SegSs;
    DWORD EFlags;
    DWORD64 Dr0;
    DWORD64 Dr1;
    DWORD64 Dr2;
    DWORD64 Dr3;
    DWORD64 Dr6;
    DWORD64 Dr7;
    DWORD64 Rax;
    DWORD64 Rcx;
    DWORD64 Rdx;
    DWORD64 Rbx;
    DWORD64 Rsp;
    DWORD64 Rbp;
    DWORD64 Rsi;
    DWORD64 Rdi;
    DWORD64 R8;
    DWORD64 R9;
    DWORD64 R10;
    DWORD64 R11;
    DWORD64 R12;
    DWORD64 R13;
    DWORD64 R14;
    DWORD64 R15;
    DWORD64 Rip;
    union _union_54 u;
    M128A VectorRegister[26];
    DWORD64 VectorControl;
    DWORD64 DebugControl;
    DWORD64 LastBranchToRip;
    DWORD64 LastBranchFromRip;
    DWORD64 LastExceptionToRip;
    DWORD64 LastExceptionFromRip;
};

struct _EXCEPTION_RECORD {
    DWORD ExceptionCode;
    DWORD ExceptionFlags;
    struct _EXCEPTION_RECORD * ExceptionRecord;
    PVOID ExceptionAddress;
    DWORD NumberParameters;
    ULONG_PTR ExceptionInformation[15];
};

struct _EXCEPTION_POINTERS {
    PEXCEPTION_RECORD ExceptionRecord;
    PCONTEXT ContextRecord;
};

typedef struct _SECURITY_ATTRIBUTES * LPSECURITY_ATTRIBUTES;

typedef PTOP_LEVEL_EXCEPTION_FILTER LPTOP_LEVEL_EXCEPTION_FILTER;

typedef struct _RUNTIME_FUNCTION _RUNTIME_FUNCTION, *P_RUNTIME_FUNCTION;

struct _RUNTIME_FUNCTION {
    DWORD BeginAddress;
    DWORD EndAddress;
    DWORD UnwindData;
};

typedef struct _RUNTIME_FUNCTION * PRUNTIME_FUNCTION;

typedef struct _UNWIND_HISTORY_TABLE_ENTRY _UNWIND_HISTORY_TABLE_ENTRY, *P_UNWIND_HISTORY_TABLE_ENTRY;

typedef struct _UNWIND_HISTORY_TABLE_ENTRY UNWIND_HISTORY_TABLE_ENTRY;

struct _UNWIND_HISTORY_TABLE_ENTRY {
    DWORD64 ImageBase;
    PRUNTIME_FUNCTION FunctionEntry;
};

typedef union _union_61 _union_61, *P_union_61;

typedef struct _M128A * PM128A;

typedef struct _struct_62 _struct_62, *P_struct_62;

struct _struct_62 {
    PM128A Xmm0;
    PM128A Xmm1;
    PM128A Xmm2;
    PM128A Xmm3;
    PM128A Xmm4;
    PM128A Xmm5;
    PM128A Xmm6;
    PM128A Xmm7;
    PM128A Xmm8;
    PM128A Xmm9;
    PM128A Xmm10;
    PM128A Xmm11;
    PM128A Xmm12;
    PM128A Xmm13;
    PM128A Xmm14;
    PM128A Xmm15;
};

union _union_61 {
    PM128A FloatingContext[16];
    struct _struct_62 s;
};

typedef union _union_63 _union_63, *P_union_63;

typedef ulonglong * PDWORD64;

typedef struct _struct_64 _struct_64, *P_struct_64;

struct _struct_64 {
    PDWORD64 Rax;
    PDWORD64 Rcx;
    PDWORD64 Rdx;
    PDWORD64 Rbx;
    PDWORD64 Rsp;
    PDWORD64 Rbp;
    PDWORD64 Rsi;
    PDWORD64 Rdi;
    PDWORD64 R8;
    PDWORD64 R9;
    PDWORD64 R10;
    PDWORD64 R11;
    PDWORD64 R12;
    PDWORD64 R13;
    PDWORD64 R14;
    PDWORD64 R15;
};

union _union_63 {
    PDWORD64 IntegerContext[16];
    struct _struct_64 s;
};

typedef enum _EXCEPTION_DISPOSITION {
    ExceptionContinueExecution=0,
    ExceptionContinueSearch=1,
    ExceptionNestedException=2,
    ExceptionCollidedUnwind=3
} _EXCEPTION_DISPOSITION;

typedef enum _EXCEPTION_DISPOSITION EXCEPTION_DISPOSITION;

typedef EXCEPTION_DISPOSITION (EXCEPTION_ROUTINE)(struct _EXCEPTION_RECORD *, PVOID, struct _CONTEXT *, PVOID);

typedef struct _UNWIND_HISTORY_TABLE _UNWIND_HISTORY_TABLE, *P_UNWIND_HISTORY_TABLE;

struct _UNWIND_HISTORY_TABLE {
    DWORD Count;
    BYTE LocalHint;
    BYTE GlobalHint;
    BYTE Search;
    BYTE Once;
    DWORD64 LowAddress;
    DWORD64 HighAddress;
    UNWIND_HISTORY_TABLE_ENTRY Entry[12];
};

typedef wchar_t WCHAR;

typedef struct _KNONVOLATILE_CONTEXT_POINTERS _KNONVOLATILE_CONTEXT_POINTERS, *P_KNONVOLATILE_CONTEXT_POINTERS;

struct _KNONVOLATILE_CONTEXT_POINTERS {
    union _union_61 u;
    union _union_63 u2;
};

typedef union _LARGE_INTEGER _LARGE_INTEGER, *P_LARGE_INTEGER;

typedef struct _struct_19 _struct_19, *P_struct_19;

typedef struct _struct_20 _struct_20, *P_struct_20;

struct _struct_20 {
    DWORD LowPart;
    LONG HighPart;
};

struct _struct_19 {
    DWORD LowPart;
    LONG HighPart;
};

union _LARGE_INTEGER {
    struct _struct_19 s;
    struct _struct_20 u;
    LONGLONG QuadPart;
};

typedef union _LARGE_INTEGER LARGE_INTEGER;

typedef WCHAR * LPCWSTR;

typedef struct _UNWIND_HISTORY_TABLE * PUNWIND_HISTORY_TABLE;

typedef struct _KNONVOLATILE_CONTEXT_POINTERS * PKNONVOLATILE_CONTEXT_POINTERS;

typedef EXCEPTION_ROUTINE * PEXCEPTION_ROUTINE;

typedef struct IMAGE_DOS_HEADER IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

struct IMAGE_DOS_HEADER {
    char e_magic[2]; // Magic number
    word e_cblp; // Bytes of last page
    word e_cp; // Pages in file
    word e_crlc; // Relocations
    word e_cparhdr; // Size of header in paragraphs
    word e_minalloc; // Minimum extra paragraphs needed
    word e_maxalloc; // Maximum extra paragraphs needed
    word e_ss; // Initial (relative) SS value
    word e_sp; // Initial SP value
    word e_csum; // Checksum
    word e_ip; // Initial IP value
    word e_cs; // Initial (relative) CS value
    word e_lfarlc; // File address of relocation table
    word e_ovno; // Overlay number
    word e_res[4][4]; // Reserved words
    word e_oemid; // OEM identifier (for e_oeminfo)
    word e_oeminfo; // OEM information; e_oemid specific
    word e_res2[10][10]; // Reserved words
    dword e_lfanew; // File address of new exe header
    byte e_program[64]; // Actual DOS program
};

typedef struct _FILETIME _FILETIME, *P_FILETIME;

typedef struct _FILETIME * LPFILETIME;

struct _FILETIME {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
};

typedef DWORD * LPDWORD;

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

struct HINSTANCE__ {
    int unused;
};

typedef struct HINSTANCE__ * HINSTANCE;

typedef void * LPCVOID;

typedef HINSTANCE HMODULE;

typedef struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct;

struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct {
    dword NameOffset;
    dword NameIsString;
};

typedef struct IMAGE_LOAD_CONFIG_CODE_INTEGRITY IMAGE_LOAD_CONFIG_CODE_INTEGRITY, *PIMAGE_LOAD_CONFIG_CODE_INTEGRITY;

struct IMAGE_LOAD_CONFIG_CODE_INTEGRITY {
    word Flags;
    word Catalog;
    dword CatalogOffset;
    dword Reserved;
};

typedef struct IMAGE_DEBUG_DIRECTORY IMAGE_DEBUG_DIRECTORY, *PIMAGE_DEBUG_DIRECTORY;

struct IMAGE_DEBUG_DIRECTORY {
    dword Characteristics;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    dword Type;
    dword SizeOfData;
    dword AddressOfRawData;
    dword PointerToRawData;
};

typedef struct IMAGE_FILE_HEADER IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

struct IMAGE_FILE_HEADER {
    word Machine; // 34404
    word NumberOfSections;
    dword TimeDateStamp;
    dword PointerToSymbolTable;
    dword NumberOfSymbols;
    word SizeOfOptionalHeader;
    word Characteristics;
};

typedef struct IMAGE_LOAD_CONFIG_DIRECTORY64 IMAGE_LOAD_CONFIG_DIRECTORY64, *PIMAGE_LOAD_CONFIG_DIRECTORY64;

typedef enum IMAGE_GUARD_FLAGS {
    IMAGE_GUARD_CF_INSTRUMENTED=256,
    IMAGE_GUARD_CFW_INSTRUMENTED=512,
    IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT=1024,
    IMAGE_GUARD_SECURITY_COOKIE_UNUSED=2048,
    IMAGE_GUARD_PROTECT_DELAYLOAD_IAT=4096,
    IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION=8192,
    IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT=16384,
    IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION=32768,
    IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT=65536,
    IMAGE_GUARD_RF_INSTRUMENTED=131072,
    IMAGE_GUARD_RF_ENABLE=262144,
    IMAGE_GUARD_RF_STRICT=524288,
    IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK_1=268435456,
    IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK_2=536870912,
    IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK_4=1073741824,
    IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK_8=2147483648
} IMAGE_GUARD_FLAGS;

struct IMAGE_LOAD_CONFIG_DIRECTORY64 {
    dword Size;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    dword GlobalFlagsClear;
    dword GlobalFlagsSet;
    dword CriticalSectionDefaultTimeout;
    qword DeCommitFreeBlockThreshold;
    qword DeCommitTotalFreeThreshold;
    pointer64 LockPrefixTable;
    qword MaximumAllocationSize;
    qword VirtualMemoryThreshold;
    qword ProcessAffinityMask;
    dword ProcessHeapFlags;
    word CsdVersion;
    word DependentLoadFlags;
    pointer64 EditList;
    pointer64 SecurityCookie;
    pointer64 SEHandlerTable;
    qword SEHandlerCount;
    pointer64 GuardCFCCheckFunctionPointer;
    pointer64 GuardCFDispatchFunctionPointer;
    pointer64 GuardCFFunctionTable;
    qword GuardCFFunctionCount;
    enum IMAGE_GUARD_FLAGS GuardFlags;
    struct IMAGE_LOAD_CONFIG_CODE_INTEGRITY CodeIntegrity;
    pointer64 GuardAddressTakenIatEntryTable;
    qword GuardAddressTakenIatEntryCount;
    pointer64 GuardLongJumpTargetTable;
    qword GuardLongJumpTargetCount;
    pointer64 DynamicValueRelocTable;
    pointer64 CHPEMetadataPointer;
    pointer64 GuardRFFailureRoutine;
    pointer64 GuardRFFailureRoutineFunctionPointer;
    dword DynamicValueRelocTableOffset;
    word DynamicValueRelocTableSection;
    word Reserved1;
    pointer64 GuardRFVerifyStackPointerFunctionPointer;
    dword HotPatchTableOffset;
    dword Reserved2;
    qword Reserved3;
};

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY IMAGE_RESOURCE_DIRECTORY_ENTRY, *PIMAGE_RESOURCE_DIRECTORY_ENTRY;

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion;

union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion {
    struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct;
    dword Name;
    word Id;
};

union IMAGE_RESOURCE_DIRECTORY_ENTRY {
    union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion NameUnion;
    union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion DirectoryUnion;
};

typedef struct IMAGE_OPTIONAL_HEADER64 IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

typedef struct IMAGE_DATA_DIRECTORY IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

struct IMAGE_DATA_DIRECTORY {
    ImageBaseOffset32 VirtualAddress;
    dword Size;
};

struct IMAGE_OPTIONAL_HEADER64 {
    word Magic;
    byte MajorLinkerVersion;
    byte MinorLinkerVersion;
    dword SizeOfCode;
    dword SizeOfInitializedData;
    dword SizeOfUninitializedData;
    ImageBaseOffset32 AddressOfEntryPoint;
    ImageBaseOffset32 BaseOfCode;
    pointer64 ImageBase;
    dword SectionAlignment;
    dword FileAlignment;
    word MajorOperatingSystemVersion;
    word MinorOperatingSystemVersion;
    word MajorImageVersion;
    word MinorImageVersion;
    word MajorSubsystemVersion;
    word MinorSubsystemVersion;
    dword Win32VersionValue;
    dword SizeOfImage;
    dword SizeOfHeaders;
    dword CheckSum;
    word Subsystem;
    word DllCharacteristics;
    qword SizeOfStackReserve;
    qword SizeOfStackCommit;
    qword SizeOfHeapReserve;
    qword SizeOfHeapCommit;
    dword LoaderFlags;
    dword NumberOfRvaAndSizes;
    struct IMAGE_DATA_DIRECTORY DataDirectory[16];
};

typedef struct IMAGE_SECTION_HEADER IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

typedef union Misc Misc, *PMisc;

typedef enum SectionFlags {
    IMAGE_SCN_TYPE_NO_PAD=8,
    IMAGE_SCN_RESERVED_0001=16,
    IMAGE_SCN_CNT_CODE=32,
    IMAGE_SCN_CNT_INITIALIZED_DATA=64,
    IMAGE_SCN_CNT_UNINITIALIZED_DATA=128,
    IMAGE_SCN_LNK_OTHER=256,
    IMAGE_SCN_LNK_INFO=512,
    IMAGE_SCN_RESERVED_0040=1024,
    IMAGE_SCN_LNK_REMOVE=2048,
    IMAGE_SCN_LNK_COMDAT=4096,
    IMAGE_SCN_GPREL=32768,
    IMAGE_SCN_MEM_16BIT=131072,
    IMAGE_SCN_MEM_PURGEABLE=131072,
    IMAGE_SCN_MEM_LOCKED=262144,
    IMAGE_SCN_MEM_PRELOAD=524288,
    IMAGE_SCN_ALIGN_1BYTES=1048576,
    IMAGE_SCN_ALIGN_2BYTES=2097152,
    IMAGE_SCN_ALIGN_4BYTES=3145728,
    IMAGE_SCN_ALIGN_8BYTES=4194304,
    IMAGE_SCN_ALIGN_16BYTES=5242880,
    IMAGE_SCN_ALIGN_32BYTES=6291456,
    IMAGE_SCN_ALIGN_64BYTES=7340032,
    IMAGE_SCN_ALIGN_128BYTES=8388608,
    IMAGE_SCN_ALIGN_256BYTES=9437184,
    IMAGE_SCN_ALIGN_512BYTES=10485760,
    IMAGE_SCN_ALIGN_1024BYTES=11534336,
    IMAGE_SCN_ALIGN_2048BYTES=12582912,
    IMAGE_SCN_ALIGN_4096BYTES=13631488,
    IMAGE_SCN_ALIGN_8192BYTES=14680064,
    IMAGE_SCN_LNK_NRELOC_OVFL=16777216,
    IMAGE_SCN_MEM_DISCARDABLE=33554432,
    IMAGE_SCN_MEM_NOT_CACHED=67108864,
    IMAGE_SCN_MEM_NOT_PAGED=134217728,
    IMAGE_SCN_MEM_SHARED=268435456,
    IMAGE_SCN_MEM_EXECUTE=536870912,
    IMAGE_SCN_MEM_READ=1073741824,
    IMAGE_SCN_MEM_WRITE=2147483648
} SectionFlags;

union Misc {
    dword PhysicalAddress;
    dword VirtualSize;
};

struct IMAGE_SECTION_HEADER {
    char Name[8];
    union Misc Misc;
    ImageBaseOffset32 VirtualAddress;
    dword SizeOfRawData;
    dword PointerToRawData;
    dword PointerToRelocations;
    dword PointerToLinenumbers;
    word NumberOfRelocations;
    word NumberOfLinenumbers;
    enum SectionFlags Characteristics;
};

typedef struct IMAGE_NT_HEADERS64 IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

struct IMAGE_NT_HEADERS64 {
    char Signature[4];
    struct IMAGE_FILE_HEADER FileHeader;
    struct IMAGE_OPTIONAL_HEADER64 OptionalHeader;
};

typedef struct IMAGE_RESOURCE_DATA_ENTRY IMAGE_RESOURCE_DATA_ENTRY, *PIMAGE_RESOURCE_DATA_ENTRY;

struct IMAGE_RESOURCE_DATA_ENTRY {
    dword OffsetToData;
    dword Size;
    dword CodePage;
    dword Reserved;
};

typedef struct IMAGE_RESOURCE_DIRECTORY IMAGE_RESOURCE_DIRECTORY, *PIMAGE_RESOURCE_DIRECTORY;

struct IMAGE_RESOURCE_DIRECTORY {
    dword Characteristics;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    word NumberOfNamedEntries;
    word NumberOfIdEntries;
};

typedef int PMFN;

typedef struct _s_ThrowInfo _s_ThrowInfo, *P_s_ThrowInfo;

typedef struct _s_ThrowInfo ThrowInfo;

struct _s_ThrowInfo {
    uint attributes;
    PMFN pmfnUnwind;
    int pForwardCompat;
    int pCatchableTypeArray;
};

typedef struct TypeDescriptor TypeDescriptor, *PTypeDescriptor;

struct TypeDescriptor {
    void * pVFTable;
    void * spare;
    char name[0];
};

typedef struct fpos<struct__Mbstatet> fpos<struct__Mbstatet>, *Pfpos<struct__Mbstatet>;

struct fpos<struct__Mbstatet> { // PlaceHolder Structure
};

typedef struct basic_ostream<wchar_t,struct_std::char_traits<wchar_t>_> basic_ostream<wchar_t,struct_std::char_traits<wchar_t>_>, *Pbasic_ostream<wchar_t,struct_std::char_traits<wchar_t>_>;

struct basic_ostream<wchar_t,struct_std::char_traits<wchar_t>_> { // PlaceHolder Structure
};

typedef struct basic_streambuf<wchar_t,struct_std::char_traits<wchar_t>_> basic_streambuf<wchar_t,struct_std::char_traits<wchar_t>_>, *Pbasic_streambuf<wchar_t,struct_std::char_traits<wchar_t>_>;

struct basic_streambuf<wchar_t,struct_std::char_traits<wchar_t>_> { // PlaceHolder Structure
};

typedef struct locale locale, *Plocale;

struct locale { // PlaceHolder Structure
};

typedef struct ios_base ios_base, *Pios_base;

struct ios_base { // PlaceHolder Structure
};

typedef struct basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>, *Pbasic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>;

struct basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> { // PlaceHolder Structure
};

typedef struct basic_ios<wchar_t,struct_std::char_traits<wchar_t>_> basic_ios<wchar_t,struct_std::char_traits<wchar_t>_>, *Pbasic_ios<wchar_t,struct_std::char_traits<wchar_t>_>;

struct basic_ios<wchar_t,struct_std::char_traits<wchar_t>_> { // PlaceHolder Structure
};

typedef struct basic_stringstream<char,struct_std::char_traits<char>,class_std::allocator<char>_> basic_stringstream<char,struct_std::char_traits<char>,class_std::allocator<char>_>, *Pbasic_stringstream<char,struct_std::char_traits<char>,class_std::allocator<char>_>;

struct basic_stringstream<char,struct_std::char_traits<char>,class_std::allocator<char>_> { // PlaceHolder Structure
};

typedef struct basic_iostream<wchar_t,struct_std::char_traits<wchar_t>_> basic_iostream<wchar_t,struct_std::char_traits<wchar_t>_>, *Pbasic_iostream<wchar_t,struct_std::char_traits<wchar_t>_>;

struct basic_iostream<wchar_t,struct_std::char_traits<wchar_t>_> { // PlaceHolder Structure
};

typedef struct integral_constant<bool,1> integral_constant<bool,1>, *Pintegral_constant<bool,1>;

struct integral_constant<bool,1> { // PlaceHolder Structure
};

typedef struct bool_<1> bool_<1>, *Pbool_<1>;

struct bool_<1> { // PlaceHolder Structure
};

typedef int (* _onexit_t)(void);

typedef ulonglong size_t;

typedef int errno_t;




undefined8 FUN_140001030(undefined8 param_1,undefined8 param_2)

{
  return param_2;
}



undefined FUN_140001040(void)

{
  return 0;
}



// Library Function - Single Match
//  wmemset
// 
// Library: Visual Studio

wchar_t * __cdecl wmemset(wchar_t *_S,wchar_t _C,size_t _N)

{
  size_t local_res18;
  wchar_t *local_18;
  
  local_18 = _S;
  for (local_res18 = _N; local_res18 != 0; local_res18 = local_res18 - 1) {
    *local_18 = _C;
    local_18 = local_18 + 1;
  }
  return _S;
}



undefined8 FUN_1400010b0(void)

{
  return 0x7fffffffffffffff;
}



// Library Function - Single Match
//  public: __cdecl std::exception::exception(char const * __ptr64 const,int) __ptr64
// 
// Libraries: Visual Studio 2015 Debug, Visual Studio 2017 Debug, Visual Studio 2019 Debug, Visual
// Studio 2019 Release

exception * __thiscall std::exception::exception(exception *this,char *param_1,int param_2)

{
  longlong lVar1;
  exception *peVar2;
  
  *(undefined ***)this = vftable;
  peVar2 = this + 8;
  for (lVar1 = 0x10; lVar1 != 0; lVar1 = lVar1 + -1) {
    *peVar2 = (exception)0x0;
    peVar2 = peVar2 + 1;
  }
  *(char **)(this + 8) = param_1;
  return this;
}



undefined8 * FUN_140001110(undefined8 *param_1,longlong param_2)

{
  longlong lVar1;
  undefined8 *puVar2;
  
  *param_1 = std::exception::vftable;
  puVar2 = param_1 + 1;
  for (lVar1 = 0x10; lVar1 != 0; lVar1 = lVar1 + -1) {
    *(undefined *)puVar2 = 0;
    puVar2 = (undefined8 *)((longlong)puVar2 + 1);
  }
  __std_exception_copy(param_2 + 8,param_1 + 1);
  return param_1;
}



void FUN_140001170(undefined8 *param_1)

{
  *param_1 = std::exception::vftable;
  __std_exception_destroy(param_1 + 1);
  return;
}



char * FUN_1400011a0(longlong param_1)

{
  char *local_18;
  
  if (*(longlong *)(param_1 + 8) == 0) {
    local_18 = "Unknown exception";
  }
  else {
    local_18 = *(char **)(param_1 + 8);
  }
  return local_18;
}



undefined8 * FUN_1400011e0(undefined8 *param_1,uint param_2)

{
  FUN_140001170(param_1);
  if ((param_2 & 1) != 0) {
    free(param_1);
  }
  return param_1;
}



// Library Function - Single Match
//  private: __cdecl std::bad_alloc::bad_alloc(char const * __ptr64 const) __ptr64
// 
// Libraries: Visual Studio 2015 Debug, Visual Studio 2017 Debug, Visual Studio 2019 Debug, Visual
// Studio 2019 Release

bad_alloc * __thiscall std::bad_alloc::bad_alloc(bad_alloc *this,char *param_1)

{
  exception::exception((exception *)this,param_1,1);
  *(undefined ***)this = vftable;
  return this;
}



undefined8 * FUN_140001260(undefined8 *param_1,uint param_2)

{
  FUN_1400012a0(param_1);
  if ((param_2 & 1) != 0) {
    free(param_1);
  }
  return param_1;
}



void FUN_1400012a0(undefined8 *param_1)

{
  FUN_140001170(param_1);
  return;
}



// Library Function - Single Match
//  public: __cdecl std::bad_array_new_length::bad_array_new_length(void) __ptr64
// 
// Libraries: Visual Studio 2015 Debug, Visual Studio 2017 Debug, Visual Studio 2019 Debug, Visual
// Studio 2019 Release

bad_array_new_length * __thiscall
std::bad_array_new_length::bad_array_new_length(bad_array_new_length *this)

{
  bad_alloc::bad_alloc((bad_alloc *)this,"bad array new length");
  *(undefined ***)this = vftable;
  return this;
}



undefined8 * FUN_140001300(undefined8 *param_1,uint param_2)

{
  FUN_140001340(param_1);
  if ((param_2 & 1) != 0) {
    free(param_1);
  }
  return param_1;
}



void FUN_140001340(undefined8 *param_1)

{
  FUN_1400012a0(param_1);
  return;
}



void * FUN_140001360(void *param_1)

{
  __ExceptionPtrCreate(param_1);
  return param_1;
}



void FUN_140001380(void *param_1)

{
  __ExceptionPtrDestroy(param_1);
  return;
}



void * FUN_1400013a0(void *param_1,void *param_2)

{
  __ExceptionPtrCopy(param_1,param_2);
  return param_1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_1400013d0(void *param_1)

{
  undefined auStack_48 [32];
  undefined local_28 [16];
  ulonglong local_18;
  
  local_18 = _FLOAT_14000d008 ^ (ulonglong)auStack_48;
  FUN_140001440(local_28,0x10);
  FUN_140001360(local_28);
  __ExceptionPtrCurrentException(local_28);
  FUN_1400013a0(param_1,local_28);
  FUN_140001380(local_28);
  FUN_140005b50(local_18 ^ (ulonglong)auStack_48);
  return;
}



void FUN_140001440(undefined *param_1,longlong param_2)

{
  for (; param_2 != 0; param_2 = param_2 + -1) {
    *param_1 = 0;
    param_1 = param_1 + 1;
  }
  return;
}



void * FUN_140001460(void *param_1)

{
  FUN_1400013d0(param_1);
  return param_1;
}



void FUN_140001480(void *param_1)

{
  __ExceptionPtrRethrow(param_1);
  FUN_140001380(param_1);
  return;
}



void FUN_1400014b0(void)

{
  bad_array_new_length local_28 [40];
  
  std::bad_array_new_length::bad_array_new_length(local_28);
                    // WARNING: Subroutine does not return
  _CxxThrowException(local_28,(ThrowInfo *)&DAT_14000aab0);
}



undefined8 * FUN_1400014e0(undefined8 *param_1,longlong param_2)

{
  FUN_140001520(param_1,param_2);
  *param_1 = std::bad_array_new_length::vftable;
  return param_1;
}



undefined8 * FUN_140001520(undefined8 *param_1,longlong param_2)

{
  FUN_140001110(param_1,param_2);
  *param_1 = std::bad_alloc::vftable;
  return param_1;
}



undefined8 FUN_140001560(undefined8 param_1)

{
  return param_1;
}



void FUN_140001570(__uint64 param_1)

{
  operator_new(param_1);
  return;
}



void FUN_140001590(longlong *param_1,longlong *param_2)

{
  ulonglong uVar1;
  
  *param_2 = *param_2 + 0x27;
  uVar1 = *param_1 - *(longlong *)(*param_1 + -8);
  if ((7 < uVar1) && (uVar1 < 0x28)) {
    *param_1 = *(longlong *)(*param_1 + -8);
    return;
  }
                    // WARNING: Subroutine does not return
  _invalid_parameter_noinfo_noreturn();
}



void FUN_140001630(void)

{
  return;
}



void FUN_140001640(void)

{
  return;
}



void FUN_140001650(void)

{
  std::_Xlength_error("string too long");
  return;
}



ios_base * FUN_140001670(ios_base *param_1)

{
  std::ios_base::setf(param_1,0x800,0xe00);
  return param_1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_1400016a0(undefined8 *param_1,undefined8 param_2)

{
  undefined auStack_38 [32];
  undefined8 local_18;
  ulonglong local_10;
  
  local_10 = _FLOAT_14000d008 ^ (ulonglong)auStack_38;
  FUN_140001700(&local_18);
  *param_1 = param_2;
  local_18 = param_2;
  FUN_140005b50(local_10 ^ (ulonglong)auStack_38);
  return;
}



undefined8 * FUN_140001700(undefined8 *param_1)

{
  *param_1 = 0;
  return param_1;
}



undefined FUN_140001720(void)

{
  return 0;
}



ushort FUN_140001730(undefined8 param_1,ushort param_2,short param_3)

{
  ushort local_res10;
  ushort local_18;
  
  local_18 = 0;
  for (local_res10 = param_2; local_res10 != 0;
      local_res10 = local_res10 ^ local_res10 & -local_res10) {
    local_18 = local_18 ^ (local_res10 & -local_res10) * param_3;
  }
  return local_18;
}



int FUN_1400017a0(undefined8 param_1,ushort param_2)

{
  ushort uVar1;
  
  uVar1 = param_2 | (short)param_2 >> 1;
  uVar1 = uVar1 | (short)uVar1 >> 2;
  uVar1 = uVar1 | (short)uVar1 >> 4;
  return (short)(uVar1 | (short)uVar1 >> 8) + 1 >> 1;
}



ushort FUN_140001810(undefined8 param_1,ushort param_2,ushort param_3)

{
  ushort uVar1;
  int iVar2;
  int iVar3;
  ushort uVar4;
  ushort local_res10;
  
  uVar4 = 0;
  for (local_res10 = param_2; (short)param_3 < (short)local_res10;
      local_res10 = local_res10 ^ param_3 * uVar1) {
    iVar2 = FUN_1400017a0(param_1,local_res10);
    iVar3 = FUN_1400017a0(param_1,param_3);
    uVar1 = (short)iVar2 / (short)iVar3;
    uVar4 = uVar4 | uVar1;
  }
  return uVar4;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_1400018b0(undefined8 param_1,short param_2,undefined2 param_3)

{
  ushort uVar1;
  short *psVar2;
  longlong lVar3;
  undefined8 uVar4;
  short local_res10 [4];
  undefined2 local_res18 [8];
  undefined auStack_b8 [32];
  ushort local_98;
  undefined4 local_94;
  undefined4 local_90;
  undefined4 local_8c;
  undefined4 local_88;
  uint local_84;
  uint local_80;
  uint local_7c;
  uint local_78;
  uint local_74;
  uint local_70 [2];
  ushort *local_68;
  ushort *local_60;
  undefined2 local_58 [4];
  short *local_50;
  short *local_48;
  short *local_40;
  short *local_38;
  undefined2 local_30 [4];
  undefined2 local_28 [4];
  undefined2 local_20 [4];
  undefined2 local_18 [4];
  ulonglong local_10;
  
  local_10 = _FLOAT_14000d008 ^ (ulonglong)auStack_b8;
  local_res10[0] = param_2;
  local_res18[0] = param_3;
  if (param_2 != 0) {
    local_90 = 1;
    local_94 = 0;
    FUN_140004540(local_18,&local_90,&local_94,local_res18);
    local_88 = 0;
    local_8c = 1;
    FUN_140004540(local_30,&local_88,&local_8c,local_res10);
    while (psVar2 = (short *)FUN_140001fa0(local_30), 1 < *psVar2) {
      FUN_140001e10(local_28,local_18);
      lVar3 = FUN_140001fa0(local_28);
      local_50 = (short *)FUN_1400045d0(lVar3);
      lVar3 = FUN_140001fa0(local_28);
      local_40 = (short *)FUN_1400045e0(lVar3);
      uVar4 = FUN_140001fa0(local_28);
      local_68 = (ushort *)FUN_140001fa0(uVar4);
      FUN_140001e10(local_20,local_30);
      lVar3 = FUN_140001fa0(local_20);
      local_48 = (short *)FUN_1400045d0(lVar3);
      lVar3 = FUN_140001fa0(local_20);
      local_38 = (short *)FUN_1400045e0(lVar3);
      uVar4 = FUN_140001fa0(local_20);
      local_60 = (ushort *)FUN_140001fa0(uVar4);
      local_98 = FUN_140001810(param_1,*local_68,*local_60);
      FUN_140004660((longlong)local_18,(longlong)local_30);
      local_84 = (uint)*local_50;
      uVar1 = FUN_140001730(param_1,local_98,*local_48);
      local_70[0] = local_84 ^ (int)(short)uVar1;
      local_80 = (uint)*local_40;
      uVar1 = FUN_140001730(param_1,local_98,*local_38);
      local_74 = local_80 ^ (int)(short)uVar1;
      local_7c = (uint)(short)*local_68;
      uVar1 = FUN_140001730(param_1,local_98,*local_60);
      local_78 = local_7c ^ (int)(short)uVar1;
      FUN_140004540(local_58,local_70,&local_74,&local_78);
      FUN_1400045f0((longlong)local_30,(longlong)local_58);
    }
    FUN_1400045e0((longlong)local_30);
  }
  FUN_140005b50(local_10 ^ (ulonglong)auStack_b8);
  return;
}



void FUN_140001b60(undefined8 param_1,undefined *param_2)

{
  undefined uVar1;
  
  uVar1 = *param_2;
  *param_2 = param_2[0xc];
  param_2[0xc] = param_2[8];
  param_2[8] = param_2[4];
  param_2[4] = uVar1;
  return;
}



void FUN_140001c10(undefined8 param_1,undefined2 *param_2)

{
  undefined2 uVar1;
  
  uVar1 = *param_2;
  *param_2 = param_2[6];
  param_2[6] = param_2[4];
  param_2[4] = param_2[2];
  param_2[2] = uVar1;
  return;
}



undefined8 * FUN_140001cc0(undefined8 param_1,undefined8 *param_2)

{
  undefined8 *puVar1;
  longlong local_10 [2];
  
  puVar1 = (undefined8 *)FUN_1400031d0(local_10,param_1);
  FUN_140001dd0(param_2,*puVar1);
  return param_2;
}



// Library Function - Single Match
//  public: __cdecl boost::integral_constant<bool,1>::operator struct
// boost::mpl::bool_<1>(void)const __ptr64
// 
// Libraries: Visual Studio 2017 Debug, Visual Studio 2017 Release, Visual Studio 2019 Debug, Visual
// Studio 2019 Release

bool_<1> __thiscall
boost::integral_constant<bool,1>::operator_struct_boost__mpl__bool_<1>
          (integral_constant<bool,1> *this)

{
  longlong lVar1;
  undefined *in_RDX;
  undefined *puVar2;
  
  puVar2 = in_RDX;
  for (lVar1 = 1; lVar1 != 0; lVar1 = lVar1 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  return SUB81(in_RDX,0);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_140001d40(void)

{
  undefined auStack_a8 [96];
  undefined *local_48;
  void *local_40;
  undefined local_38 [32];
  ulonglong local_18;
  
  local_18 = _FLOAT_14000d008 ^ (ulonglong)auStack_a8;
  local_48 = local_38;
  local_40 = FUN_140001460(local_48);
  FUN_140001480(local_40);
  FUN_140005b50(local_18 ^ (ulonglong)auStack_a8);
  return;
}



undefined8 * FUN_140001db0(undefined8 *param_1,undefined8 *param_2)

{
  *param_2 = *param_1;
  return param_2;
}



undefined8 * FUN_140001dd0(undefined8 *param_1,undefined8 param_2)

{
  *param_1 = param_2;
  return param_1;
}



void FUN_140001df0(longlong *param_1)

{
  FUN_140003130(param_1);
  return;
}



undefined2 * FUN_140001e10(undefined2 *param_1,undefined2 *param_2)

{
  FUN_140001e50(param_1,param_2);
  param_1[2] = param_2[2];
  return param_1;
}



undefined2 * FUN_140001e50(undefined2 *param_1,undefined2 *param_2)

{
  FUN_140001e90(param_1,param_2);
  param_1[1] = param_2[1];
  return param_1;
}



undefined2 * FUN_140001e90(undefined2 *param_1,undefined2 *param_2)

{
  FUN_140001560(param_1);
  *param_1 = *param_2;
  return param_1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_140001ed0(undefined8 param_1,undefined8 param_2,undefined2 param_3)

{
  undefined8 *puVar1;
  longlong lVar2;
  undefined auStack_48 [32];
  undefined8 local_28;
  undefined8 local_20;
  longlong local_18;
  ulonglong local_10;
  
  local_10 = _FLOAT_14000d008 ^ (ulonglong)auStack_48;
  FUN_1400046b0(&local_18,param_2);
  puVar1 = FUN_140001db0(&local_18,&local_28);
  lVar2 = FUN_1400031c0(puVar1);
  *(undefined2 *)(lVar2 + 0x1c) = param_3;
  puVar1 = FUN_140001db0(&local_18,&local_20);
  FUN_140003180(puVar1);
  FUN_140001df0(&local_18);
  FUN_140005b50(local_10 ^ (ulonglong)auStack_48);
  return;
}



undefined * FUN_140001f60(undefined *param_1,undefined *param_2,undefined4 param_3)

{
  longlong lVar1;
  undefined *puVar2;
  
  *(undefined4 *)(param_1 + 0x10) = param_3;
  puVar2 = param_1;
  for (lVar1 = 0x10; lVar1 != 0; lVar1 = lVar1 + -1) {
    *puVar2 = *param_2;
    param_2 = param_2 + 1;
    puVar2 = puVar2 + 1;
  }
  return param_1;
}



undefined8 FUN_140001fa0(undefined8 param_1)

{
  return param_1;
}



void FUN_140001fb0(ulonglong *param_1,ulonglong *param_2)

{
  int local_18;
  
  for (local_18 = 1; local_18 <= *(int *)(param_1 + 2); local_18 = local_18 + 1) {
    *param_2 = *param_2 ^ *param_1;
    param_2[1] = param_2[1] ^ param_1[1];
    FUN_140001ed0(param_1,param_2,4);
    FUN_140001ed0(param_1,param_2,6);
    if (local_18 != *(int *)(param_1 + 2)) {
      FUN_140001ed0(param_1,param_2,8);
    }
    FUN_140001ed0(param_1,param_1,10);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_1400020d0(undefined8 param_1,longlong *param_2)

{
  basic_string<> bVar1;
  ulonglong uVar2;
  size_t _Count;
  ulonglong *_Memory;
  basic_ostream<> *pbVar3;
  longlong lVar4;
  __uint64 *p_Var5;
  undefined7 extraout_var;
  LPCWSTR lpFileName;
  HANDLE hFile;
  longlong *plVar6;
  undefined7 extraout_var_00;
  ulonglong uVar7;
  undefined *puVar8;
  ulonglong *puVar9;
  undefined auStackY_248 [32];
  ulonglong *local_208;
  ulonglong local_1f8;
  void *local_170 [4];
  void *local_150 [5];
  longlong local_128 [2];
  basic_ostream<> local_118 [240];
  ulonglong local_28;
  
  local_28 = _FLOAT_14000d008 ^ (ulonglong)auStackY_248;
  local_1f8 = 0xffffffffffffffff;
  uVar7 = local_1f8;
  do {
    local_1f8 = uVar7;
    uVar7 = local_1f8 + 1;
  } while (*(char *)(*param_2 + uVar7) != '\0');
  uVar2 = (local_1f8 >> 1 & 0xfffffffffffffff8) * 2;
  _Count = uVar2 + 0x10;
  if (0xffffffffffffffef < uVar2) {
    _Count = 0xffffffffffffffff;
  }
  _Memory = (ulonglong *)calloc(_Count,1);
  if (_Memory == (ulonglong *)0x0) {
    pbVar3 = (basic_ostream<> *)FUN_140004780((longlong *)wcout_exref,L"Allocation failed.");
    std::basic_ostream<>::operator<<(pbVar3,FUN_140004bc0);
  }
  else {
    puVar8 = (undefined *)*param_2;
    puVar9 = _Memory;
    for (; local_208 = _Memory, uVar7 != 0; uVar7 = uVar7 - 1) {
      *(undefined *)puVar9 = *puVar8;
      puVar8 = puVar8 + 1;
      puVar9 = (ulonglong *)((longlong)puVar9 + 1);
    }
    for (; local_208 != _Memory + ((local_1f8 >> 4) + 1) * 2; local_208 = local_208 + 2) {
      FUN_140001fb0((ulonglong *)&DAT_14000d9e8,local_208);
      FUN_140001440((undefined *)local_128,0xf8);
      FUN_140003040(local_128,1);
      pbVar3 = std::basic_ostream<>::operator<<(local_118,FUN_140001670);
      lVar4 = FUN_140001fa0(&DAT_14000d9e8);
      pbVar3 = std::basic_ostream<>::operator<<(pbVar3,*(__uint64 *)(lVar4 + 8));
      p_Var5 = (__uint64 *)FUN_140001fa0(&DAT_14000d9e8);
      std::basic_ostream<>::operator<<(pbVar3,*p_Var5);
      bVar1 = std::basic_stringstream<>::str((basic_stringstream<> *)local_128);
      lpFileName = (LPCWSTR)FUN_140003250((undefined8 *)CONCAT71(extraout_var,bVar1));
      hFile = CreateFileW(lpFileName,0x40000000,1,(LPSECURITY_ATTRIBUTES)0x0,2,0x80,(HANDLE)0x0);
      ~basic_string<>(local_170);
      if (hFile == (HANDLE)0xffffffffffffffff) {
        plVar6 = (longlong *)FUN_140004780((longlong *)wcout_exref,L"Error on file: ");
        bVar1 = std::basic_stringstream<>::str((basic_stringstream<> *)local_128);
        pbVar3 = (basic_ostream<> *)
                 FUN_140004c20(plVar6,(undefined8 *)CONCAT71(extraout_var_00,bVar1));
        std::basic_ostream<>::operator<<(pbVar3,FUN_140004bc0);
        ~basic_string<>(local_150);
        FUN_1400024a0((longlong)local_128);
      }
      else {
        WriteFile(hFile,local_208,0x10,(LPDWORD)0x0,(LPOVERLAPPED)0x0);
        CloseHandle(hFile);
        FUN_1400024a0((longlong)local_128);
      }
    }
    free(_Memory);
    pbVar3 = (basic_ostream<> *)FUN_140004780((longlong *)wcout_exref,L"Done!");
    std::basic_ostream<>::operator<<(pbVar3,FUN_140004bc0);
  }
  FUN_140005b50(local_28 ^ (ulonglong)auStackY_248);
  return;
}



void FUN_1400024a0(longlong param_1)

{
  FUN_140002fb0(param_1 + 0x98);
  std::basic_ios<>::~basic_ios<>((basic_ios<> *)(param_1 + 0x98));
  return;
}



fpos<> * FUN_1400024e0(basic_streambuf<> *param_1,fpos<> *param_2,longlong *param_3,uint param_4)

{
  ulonglong uVar1;
  wchar_t *pwVar2;
  wchar_t *pwVar3;
  wchar_t *local_30;
  
  uVar1 = FUN_140003560(param_3);
  pwVar2 = std::basic_streambuf<>::gptr(param_1);
  if ((*(uint *)(param_1 + 0x70) & 2) == 0) {
    local_30 = std::basic_streambuf<>::pptr(param_1);
  }
  else {
    local_30 = (wchar_t *)0x0;
  }
  if ((local_30 != (wchar_t *)0x0) && (*(wchar_t **)(param_1 + 0x68) < local_30)) {
    *(wchar_t **)(param_1 + 0x68) = local_30;
  }
  pwVar3 = std::basic_streambuf<>::eback(param_1);
  if ((ulonglong)(*(longlong *)(param_1 + 0x68) - (longlong)pwVar3 >> 1) < uVar1) {
    std::fpos<>::fpos<>(param_2,-1);
  }
  else if ((uVar1 == 0) ||
          ((((param_4 & 1) == 0 || (pwVar2 != (wchar_t *)0x0)) &&
           (((param_4 & 2) == 0 || (local_30 != (wchar_t *)0x0)))))) {
    if (((param_4 & 1) != 0) && (pwVar2 != (wchar_t *)0x0)) {
      std::basic_streambuf<>::setg(param_1,pwVar3,pwVar3 + uVar1,*(wchar_t **)(param_1 + 0x68));
    }
    if (((param_4 & 2) != 0) && (local_30 != (wchar_t *)0x0)) {
      pwVar2 = std::basic_streambuf<>::epptr(param_1);
      std::basic_streambuf<>::setp(param_1,pwVar3,pwVar3 + uVar1,pwVar2);
    }
    std::fpos<>::fpos<>(param_2,uVar1);
  }
  else {
    std::fpos<>::fpos<>(param_2,-1);
  }
  return param_2;
}



fpos<> * FUN_1400026b0(basic_streambuf<> *param_1,fpos<> *param_2,longlong param_3,int param_4,
                      uint param_5)

{
  wchar_t *pwVar1;
  wchar_t *pwVar2;
  ulonglong uVar3;
  longlong lVar4;
  ulonglong local_40;
  wchar_t *local_30;
  
  pwVar1 = std::basic_streambuf<>::gptr(param_1);
  if ((*(uint *)(param_1 + 0x70) & 2) == 0) {
    local_30 = std::basic_streambuf<>::pptr(param_1);
  }
  else {
    local_30 = (wchar_t *)0x0;
  }
  if ((local_30 != (wchar_t *)0x0) && (*(wchar_t **)(param_1 + 0x68) < local_30)) {
    *(wchar_t **)(param_1 + 0x68) = local_30;
  }
  pwVar2 = std::basic_streambuf<>::eback(param_1);
  uVar3 = *(longlong *)(param_1 + 0x68) - (longlong)pwVar2 >> 1;
  if (param_4 == 0) {
    local_40 = 0;
LAB_14000285c:
    if (uVar3 < param_3 + local_40) {
      std::fpos<>::fpos<>(param_2,-1);
    }
    else {
      lVar4 = param_3 + local_40;
      if ((lVar4 == 0) ||
         ((((param_5 & 1) == 0 || (pwVar1 != (wchar_t *)0x0)) &&
          (((param_5 & 2) == 0 || (local_30 != (wchar_t *)0x0)))))) {
        if (((param_5 & 1) != 0) && (pwVar1 != (wchar_t *)0x0)) {
          std::basic_streambuf<>::setg(param_1,pwVar2,pwVar2 + lVar4,*(wchar_t **)(param_1 + 0x68));
        }
        if (((param_5 & 2) != 0) && (local_30 != (wchar_t *)0x0)) {
          pwVar1 = std::basic_streambuf<>::epptr(param_1);
          std::basic_streambuf<>::setp(param_1,pwVar2,pwVar2 + lVar4,pwVar1);
        }
        std::fpos<>::fpos<>(param_2,lVar4);
      }
      else {
        std::fpos<>::fpos<>(param_2,-1);
      }
    }
  }
  else {
    if (param_4 == 1) {
      if ((param_5 & 3) != 3) {
        if ((param_5 & 1) == 0) {
          if (((param_5 & 2) != 0) && ((local_30 != (wchar_t *)0x0 || (pwVar2 == (wchar_t *)0x0))))
          {
            local_40 = (longlong)local_30 - (longlong)pwVar2 >> 1;
            goto LAB_14000285c;
          }
        }
        else if ((pwVar1 != (wchar_t *)0x0) || (pwVar2 == (wchar_t *)0x0)) {
          local_40 = (longlong)pwVar1 - (longlong)pwVar2 >> 1;
          goto LAB_14000285c;
        }
      }
    }
    else {
      local_40 = uVar3;
      if (param_4 == 2) goto LAB_14000285c;
    }
    std::fpos<>::fpos<>(param_2,-1);
  }
  return param_2;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_1400029c0(basic_streambuf<> *param_1)

{
  wchar_t *pwVar1;
  wchar_t **ppwVar2;
  undefined auStack_58 [32];
  wchar_t *local_38;
  wchar_t *local_30;
  wchar_t *local_28;
  wchar_t *local_20;
  wchar_t *local_18;
  ulonglong local_10;
  
  local_10 = _FLOAT_14000d008 ^ (ulonglong)auStack_58;
  local_38 = std::basic_streambuf<>::gptr(param_1);
  if (local_38 == (wchar_t *)0x0) {
    FUN_140003b20();
  }
  else {
    pwVar1 = std::basic_streambuf<>::egptr(param_1);
    if (local_38 < pwVar1) {
      FUN_140003be0(local_38);
    }
    else {
      local_18 = std::basic_streambuf<>::pptr(param_1);
      if ((local_18 == (wchar_t *)0x0) || ((*(uint *)(param_1 + 0x70) & 4) != 0)) {
        FUN_140003b20();
      }
      else {
        ppwVar2 = (wchar_t **)_Max_value<>((ulonglong *)(param_1 + 0x68),(ulonglong *)&local_18);
        local_30 = *ppwVar2;
        if (local_38 < local_30) {
          *(wchar_t **)(param_1 + 0x68) = local_30;
          local_28 = std::basic_streambuf<>::gptr(param_1);
          local_20 = std::basic_streambuf<>::eback(param_1);
          std::basic_streambuf<>::setg(param_1,local_20,local_28,local_30);
          pwVar1 = std::basic_streambuf<>::gptr(param_1);
          FUN_140003be0(pwVar1);
        }
        else {
          FUN_140003b20();
        }
      }
    }
  }
  FUN_140005b50(local_10 ^ (ulonglong)auStack_58);
  return;
}



void FUN_140002af0(basic_streambuf<> *param_1,ushort param_2)

{
  bool bVar1;
  wchar_t *pwVar2;
  undefined8 uVar3;
  ushort local_res10 [12];
  short local_18;
  short local_16;
  short local_14;
  wchar_t local_12;
  wchar_t *local_10;
  
  local_res10[0] = param_2;
  local_10 = std::basic_streambuf<>::gptr(param_1);
  if ((local_10 != (wchar_t *)0x0) &&
     (pwVar2 = std::basic_streambuf<>::eback(param_1), pwVar2 < local_10)) {
    uVar3 = FUN_140003b20();
    local_18 = (short)uVar3;
    bVar1 = eq_int_type(&local_18,(short *)local_res10);
    if (!bVar1) {
      local_16 = FUN_140003be0(local_res10);
      bVar1 = eq_int_type(&local_16,local_10 + -1);
      if ((!bVar1) && ((*(uint *)(param_1 + 0x70) & 2) != 0)) goto LAB_140002b8e;
    }
    std::basic_streambuf<>::gbump(param_1,-1);
    uVar3 = FUN_140003b20();
    local_14 = (short)uVar3;
    bVar1 = eq_int_type(&local_14,(short *)local_res10);
    if (!bVar1) {
      local_12 = FUN_140003be0(local_res10);
      pwVar2 = std::basic_streambuf<>::gptr(param_1);
      *pwVar2 = local_12;
    }
    not_eof(local_res10);
    return;
  }
LAB_140002b8e:
  FUN_140003b20();
  return;
}



ulonglong FUN_140002c00(basic_streambuf<> *param_1,ushort param_2)

{
  bool bVar1;
  ushort uVar2;
  ulonglong uVar3;
  undefined8 uVar4;
  undefined6 extraout_var;
  wchar_t *pwVar5;
  wchar_t *pwVar6;
  void *pvVar7;
  ushort local_res10 [12];
  ulonglong local_60;
  short local_58;
  wchar_t local_56;
  wchar_t local_54;
  wchar_t *local_50;
  __uint64 local_48;
  wchar_t *local_40;
  wchar_t *local_38;
  wchar_t *local_30;
  basic_streambuf<> *local_28;
  wchar_t *local_20;
  wchar_t *local_18;
  basic_streambuf<> *local_10;
  
  local_res10[0] = param_2;
  if ((*(uint *)(param_1 + 0x70) & 2) == 0) {
    uVar4 = FUN_140003b20();
    local_58 = (short)uVar4;
    bVar1 = eq_int_type(&local_58,(short *)local_res10);
    if (bVar1) {
      uVar2 = not_eof(local_res10);
      uVar3 = CONCAT62(extraout_var,uVar2);
    }
    else {
      local_50 = std::basic_streambuf<>::pptr(param_1);
      local_38 = std::basic_streambuf<>::epptr(param_1);
      if ((local_50 == (wchar_t *)0x0) || (local_38 <= local_50)) {
        local_60 = 0;
        local_40 = std::basic_streambuf<>::eback(param_1);
        if (local_50 != (wchar_t *)0x0) {
          local_60 = (longlong)local_38 - (longlong)local_40 >> 1;
        }
        if (local_60 < 0x20) {
          local_48 = 0x20;
        }
        else if (local_60 < 0x3fffffff) {
          local_48 = local_60 * 2;
        }
        else {
          if (0x7ffffffe < local_60) {
            uVar3 = FUN_140003b20();
            return uVar3;
          }
          local_48 = 0x7fffffff;
        }
        local_28 = param_1 + 0x74;
        uVar4 = allocate(local_28,local_48);
        pwVar5 = (wchar_t *)FUN_140001fa0(uVar4);
        FUN_140003bf0((undefined *)pwVar5,(undefined *)local_40,local_60);
        local_30 = pwVar5 + local_60;
        *(wchar_t **)(param_1 + 0x68) = local_30 + 1;
        std::basic_streambuf<>::setp(param_1,pwVar5,local_30,pwVar5 + local_48);
        if ((*(uint *)(param_1 + 0x70) & 4) == 0) {
          local_20 = *(wchar_t **)(param_1 + 0x68);
          pwVar6 = std::basic_streambuf<>::gptr(param_1);
          local_18 = pwVar5 + ((longlong)pwVar6 - (longlong)local_40 >> 1);
          std::basic_streambuf<>::setg(param_1,pwVar5,local_18,local_20);
        }
        else {
          std::basic_streambuf<>::setg(param_1,pwVar5,(wchar_t *)0x0,pwVar5);
        }
        if ((*(uint *)(param_1 + 0x70) & 1) != 0) {
          local_10 = param_1 + 0x74;
          pvVar7 = (void *)FUN_140003540(local_40);
          deallocate(local_10,pvVar7,local_60);
        }
        *(uint *)(param_1 + 0x70) = *(uint *)(param_1 + 0x70) | 1;
        local_54 = FUN_140003be0(local_res10);
        pwVar5 = std::basic_streambuf<>::_Pninc(param_1);
        *pwVar5 = local_54;
        uVar3 = (ulonglong)local_res10[0];
      }
      else {
        local_56 = FUN_140003be0(local_res10);
        pwVar5 = std::basic_streambuf<>::_Pninc(param_1);
        *pwVar5 = local_56;
        *(wchar_t **)(param_1 + 0x68) = local_50 + 1;
        uVar3 = (ulonglong)local_res10[0];
      }
    }
  }
  else {
    uVar3 = FUN_140003b20();
  }
  return uVar3;
}



void FUN_140002f20(undefined8 *param_1)

{
  *param_1 = std::basic_stringbuf<>::vftable;
  FUN_1400035d0((basic_streambuf<> *)param_1);
  std::basic_streambuf<>::~basic_streambuf<>((basic_streambuf<> *)param_1);
  return;
}



// Library Function - Single Match
//  public: class std::basic_string<char,struct std::char_traits<char>,class std::allocator<char> >
// __cdecl std::basic_stringstream<char,struct std::char_traits<char>,class std::allocator<char>
// >::str(void)const __ptr64
// 
// Libraries: Visual Studio 2017 Debug, Visual Studio 2017 Release, Visual Studio 2019 Debug, Visual
// Studio 2019 Release

basic_string<> __thiscall std::basic_stringstream<>::str(basic_stringstream<> *this)

{
  undefined8 *in_RDX;
  
  FUN_1400036c0((basic_streambuf<> *)(this + 0x18),in_RDX);
  return SUB81(in_RDX,0);
}



void FUN_140002fb0(longlong param_1)

{
  *(undefined ***)(param_1 + -0x98 + (longlong)*(int *)(*(longlong *)(param_1 + -0x98) + 4)) =
       std::basic_stringstream<>::vftable;
  *(int *)(param_1 + -0x9c + (longlong)*(int *)(*(longlong *)(param_1 + -0x98) + 4)) =
       *(int *)(*(longlong *)(param_1 + -0x98) + 4) + -0x98;
  FUN_140002f20((undefined8 *)(param_1 + -0x80));
  std::basic_iostream<>::~basic_iostream<>((basic_iostream<> *)(param_1 + -0x78));
  return;
}



longlong * FUN_140003040(longlong *param_1,int param_2)

{
  basic_streambuf<> *pbVar1;
  
  if (param_2 != 0) {
    *param_1 = (longlong)&DAT_140009568;
    param_1[2] = (longlong)&DAT_140009570;
    std::basic_ios<>::basic_ios<>((basic_ios<> *)(param_1 + 0x13));
  }
  pbVar1 = (basic_streambuf<> *)FUN_140001fa0(param_1 + 3);
  std::basic_iostream<>::basic_iostream<>((basic_iostream<> *)param_1,pbVar1);
  *(undefined ***)((longlong)param_1 + (longlong)*(int *)(*param_1 + 4)) =
       std::basic_stringstream<>::vftable;
  *(int *)((longlong)param_1 + (longlong)*(int *)(*param_1 + 4) + -4) =
       *(int *)(*param_1 + 4) + -0x98;
  FUN_140003770(param_1 + 3,3);
  return param_1;
}



void FUN_140003130(longlong *param_1)

{
  (**(code **)(*param_1 + 8))(*param_1);
  return;
}



void FUN_140003180(undefined8 *param_1)

{
  (**(code **)*param_1)(*param_1);
  return;
}



undefined8 FUN_1400031c0(undefined8 *param_1)

{
  return *param_1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_1400031d0(longlong *param_1,undefined8 param_2)

{
  undefined auStack_48 [32];
  longlong local_28;
  longlong local_20;
  longlong local_18;
  ulonglong local_10;
  
  local_10 = _FLOAT_14000d008 ^ (ulonglong)auStack_48;
  local_28 = FUN_140001fa0(param_2);
  local_20 = local_28 + -0x10;
  FUN_140001700(&local_18);
  local_18 = local_20;
  *param_1 = local_20;
  FUN_140005b50(local_10 ^ (ulonglong)auStack_48);
  return;
}



void FUN_140003250(undefined8 *param_1)

{
  Myptr(param_1);
  return;
}



// Library Function - Multiple Matches With Same Base Name
//  public: __cdecl std::basic_string<char,struct std::char_traits<char>,class std::allocator<char>
// >::~basic_string<char,struct std::char_traits<char>,class std::allocator<char> >(void) __ptr64
//  public: __cdecl std::basic_string<unsigned short,struct std::char_traits<unsigned short>,class
// std::allocator<unsigned short> >::~basic_string<unsigned short,struct std::char_traits<unsigned
// short>,class std::allocator<unsigned short> >(void) __ptr64
//  public: __cdecl std::basic_string<wchar_t,struct std::char_traits<wchar_t>,class
// std::allocator<wchar_t> >::~basic_string<wchar_t,struct std::char_traits<wchar_t>,class
// std::allocator<wchar_t> >(void) __ptr64
// 
// Library: Visual Studio 2019 Release

void ~basic_string<>(void **param_1)

{
  FUN_140003800(param_1);
  FUN_1400032a0();
  return;
}



void FUN_1400032a0(void)

{
  FUN_1400032c0();
  return;
}



void FUN_1400032c0(void)

{
  FUN_140001630();
  return;
}



undefined8 * FUN_1400032e0(undefined8 *param_1,undefined8 *param_2)

{
  undefined8 uVar1;
  byte local_27;
  
  uVar1 = FUN_1400037e0(param_2);
  uVar1 = FUN_140001fa0(uVar1);
  FUN_140004cc0(param_1,(ulonglong)local_27,uVar1);
  FUN_140001640();
  FUN_140003910((undefined *)param_1,param_2);
  return param_1;
}



undefined8 * FUN_140003360(undefined8 *param_1,uint param_2)

{
  FUN_140002f20(param_1);
  if ((param_2 & 1) != 0) {
    free(param_1);
  }
  return param_1;
}



// Library Function - Single Match
//  public: virtual void * __ptr64 __cdecl std::basic_stringstream<char,struct
// std::char_traits<char>,class std::allocator<char> >::`scalar deleting destructor'(unsigned int)
// __ptr64
// 
// Libraries: Visual Studio 2017 Debug, Visual Studio 2017 Release, Visual Studio 2019 Debug, Visual
// Studio 2019 Release

void * __thiscall
std::basic_stringstream<>::_scalar_deleting_destructor_(basic_stringstream<> *this,uint param_1)

{
  FUN_1400024a0((longlong)(this + -0x98));
  if ((param_1 & 1) != 0) {
    free(this + -0x98);
  }
  return this + -0x98;
}



undefined FUN_140003400(longlong param_1)

{
  return *(undefined *)(param_1 + 8);
}



void FUN_140003410(longlong **param_1)

{
  int iVar1;
  
  iVar1 = std::uncaught_exceptions();
  if (iVar1 == 0) {
    std::basic_ostream<>::_Osfx((basic_ostream<> *)*param_1);
  }
  FUN_140003c80(param_1);
  return;
}



longlong ** FUN_140003460(longlong **param_1,longlong *param_2)

{
  bool bVar1;
  longlong *this;
  
  FUN_140003ce0(param_1,param_2);
  bVar1 = std::ios_base::good((ios_base *)((longlong)param_2 + (longlong)*(int *)(*param_2 + 4)));
  if (bVar1) {
    this = (longlong *)
           std::basic_ios<>::tie
                     ((basic_ios<> *)((longlong)param_2 + (longlong)*(int *)(*param_2 + 4)));
    if ((this == (longlong *)0x0) || (this == param_2)) {
      *(undefined *)(param_1 + 1) = 1;
    }
    else {
      std::basic_ostream<>::flush((basic_ostream<> *)this);
      bVar1 = std::ios_base::good((ios_base *)((longlong)param_2 + (longlong)*(int *)(*param_2 + 4))
                                 );
      *(bool *)(param_1 + 1) = bVar1;
    }
  }
  else {
    *(undefined *)(param_1 + 1) = 0;
  }
  return param_1;
}



void FUN_140003540(undefined8 param_1)

{
  FUN_140001fa0(param_1);
  return;
}



longlong FUN_140003560(longlong *param_1)

{
  return *param_1 + param_1[1];
}



// Library Function - Single Match
//  public: __cdecl std::fpos<struct _Mbstatet>::fpos<struct _Mbstatet>(__int64) __ptr64
// 
// Libraries: Visual Studio 2015, Visual Studio 2017, Visual Studio 2019

fpos<> * __thiscall std::fpos<>::fpos<>(fpos<> *this,__int64 param_1)

{
  longlong lVar1;
  fpos<> *pfVar2;
  
  *(__int64 *)this = param_1;
  *(undefined8 *)(this + 8) = 0;
  pfVar2 = this + 0x10;
  for (lVar1 = 8; lVar1 != 0; lVar1 = lVar1 + -1) {
    *pfVar2 = (fpos<>)0x0;
    pfVar2 = pfVar2 + 1;
  }
  return this;
}



void FUN_1400035d0(basic_streambuf<> *param_1)

{
  wchar_t *pwVar1;
  wchar_t *pwVar2;
  void *pvVar3;
  wchar_t *local_28;
  
  if ((*(uint *)(param_1 + 0x70) & 1) != 0) {
    pwVar1 = std::basic_streambuf<>::pptr(param_1);
    if (pwVar1 == (wchar_t *)0x0) {
      local_28 = std::basic_streambuf<>::egptr(param_1);
    }
    else {
      local_28 = std::basic_streambuf<>::epptr(param_1);
    }
    pwVar1 = std::basic_streambuf<>::eback(param_1);
    pwVar2 = std::basic_streambuf<>::eback(param_1);
    pvVar3 = (void *)FUN_140003540(pwVar2);
    deallocate(param_1 + 0x74,pvVar3,(longlong)local_28 - (longlong)pwVar1 >> 1);
  }
  std::basic_streambuf<>::setg(param_1,(wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0);
  std::basic_streambuf<>::setp(param_1,(wchar_t *)0x0,(wchar_t *)0x0);
  *(undefined8 *)(param_1 + 0x68) = 0;
  *(uint *)(param_1 + 0x70) = *(uint *)(param_1 + 0x70) & 0xfffffffe;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_1400036c0(basic_streambuf<> *param_1,undefined8 *param_2)

{
  undefined auStack_78 [32];
  uint local_58;
  undefined *local_50;
  void *local_48;
  void *local_38 [4];
  ulonglong local_18;
  
  local_18 = _FLOAT_14000d008 ^ (ulonglong)auStack_78;
  local_58 = 0;
  FUN_140004190(local_38,param_1 + 0x74);
  FUN_140003dc0(param_1,(undefined *)&local_50);
  if (local_50 != (undefined *)0x0) {
    FID_conflict_assign(local_38,local_50,local_48);
  }
  FUN_1400032e0(param_2,local_38);
  local_58 = local_58 | 1;
  ~basic_string<>(local_38);
  FUN_140005b50(local_18 ^ (ulonglong)auStack_78);
  return;
}



undefined8 * FUN_140003770(undefined8 *param_1,int param_2)

{
  int iVar1;
  
  std::basic_streambuf<>::basic_streambuf<>((basic_streambuf<> *)param_1);
  *param_1 = std::basic_stringbuf<>::vftable;
  param_1[0xd] = 0;
  iVar1 = std::basic_stringbuf<>::_Getstate(param_2);
  *(int *)(param_1 + 0xe) = iVar1;
  FUN_140001fa0((longlong)param_1 + 0x74);
  return param_1;
}



void FUN_1400037e0(undefined8 param_1)

{
  FUN_140001fa0(param_1);
  return;
}



void FUN_140003800(void **param_1)

{
  bool bVar1;
  char cVar2;
  undefined2 local_28 [4];
  void **local_20;
  void *local_18;
  undefined8 local_10;
  
  local_20 = param_1;
  FUN_140001630();
  bVar1 = FUN_1400041f0((longlong)local_20);
  if (bVar1) {
    local_18 = *local_20;
    local_10 = FUN_1400037e0(param_1);
    FUN_140001630();
    cVar2 = FUN_140001040();
    if (cVar2 != '\0') {
      FUN_140004d00(local_20);
    }
    deallocate(local_10,local_18,(longlong)local_20[3] + 1);
  }
  local_20[2] = (void *)0x0;
  cVar2 = FUN_140001040();
  if (cVar2 == '\0') {
    local_20[3] = (void *)0x7;
    local_28[0] = 0;
    FUN_140004240((undefined2 *)local_20,local_28);
  }
  else {
    local_20[3] = (void *)0x0;
  }
  return;
}



undefined8 FUN_140003900(longlong param_1)

{
  return *(undefined8 *)(param_1 + 0x10);
}



void FUN_140003910(undefined *param_1,undefined8 *param_2)

{
  char cVar1;
  bool bVar2;
  
  cVar1 = FUN_140001040();
  if (cVar1 == '\0') {
    FUN_140004140(param_1,param_2);
    FUN_140003f70(param_2);
  }
  else {
    bVar2 = FUN_1400041f0((longlong)param_2);
    if (bVar2) {
      FUN_140004d60(param_1,param_2);
      *param_2 = 0;
      FUN_140003f40();
    }
    else {
      cVar1 = FUN_140001040();
      if (cVar1 != '\0') {
        FUN_140004d00(param_1);
      }
      FUN_140003bf0(param_1,(undefined *)param_2,param_2[2] + 1);
      FUN_140001630();
    }
    *(undefined8 *)(param_1 + 0x10) = param_2[2];
    *(undefined8 *)(param_1 + 0x18) = param_2[3];
    FUN_140003f70(param_2);
  }
  return;
}



// Library Function - Multiple Matches With Same Base Name
//  public: unsigned short * __ptr64 __cdecl std::_String_val<struct std::_Simple_types<unsigned
// short> >::_Myptr(void) __ptr64
//  public: wchar_t * __ptr64 __cdecl std::_String_val<struct std::_Simple_types<wchar_t>
// >::_Myptr(void) __ptr64
// 
// Library: Visual Studio 2019 Release

undefined8 * Myptr(undefined8 *param_1)

{
  bool bVar1;
  undefined8 *local_18;
  
  bVar1 = FUN_1400041f0((longlong)param_1);
  local_18 = param_1;
  if (bVar1) {
    local_18 = (undefined8 *)FUN_140001fa0(*param_1);
  }
  return local_18;
}



// Library Function - Multiple Matches With Same Base Name
//  public: unsigned short * __ptr64 __cdecl std::allocator<unsigned short>::allocate(unsigned
// __int64) __ptr64
//  public: wchar_t * __ptr64 __cdecl std::allocator<wchar_t>::allocate(unsigned __int64) __ptr64
// 
// Libraries: Visual Studio 2019 Debug, Visual Studio 2019 Release

void allocate(undefined8 param_1,__uint64 param_2)

{
  __uint64 _Var1;
  
  _Var1 = std::_Get_size_of_n<2>(param_2);
  FUN_140004e30(_Var1);
  return;
}



// Library Function - Multiple Matches With Same Base Name
//  char * __ptr64 const & __ptr64 __cdecl std::_Max_value<char * __ptr64>(char * __ptr64 const &
// __ptr64,char * __ptr64 const & __ptr64)
//  unsigned __int64 const & __ptr64 __cdecl std::_Max_value<unsigned __int64>(unsigned __int64
// const & __ptr64,unsigned __int64 const & __ptr64)
// 
// Libraries: Visual Studio 2017 Debug, Visual Studio 2017 Release, Visual Studio 2019 Debug, Visual
// Studio 2019 Release

ulonglong * _Max_value<>(ulonglong *param_1,ulonglong *param_2)

{
  ulonglong *local_18;
  
  local_18 = param_1;
  if (*param_1 < *param_2) {
    local_18 = param_2;
  }
  return local_18;
}



// Library Function - Multiple Matches With Same Base Name
//  public: void __cdecl std::allocator<unsigned short>::deallocate(unsigned short * __ptr64
// const,unsigned __int64) __ptr64
//  public: void __cdecl std::allocator<wchar_t>::deallocate(wchar_t * __ptr64 const,unsigned
// __int64) __ptr64
// 
// Libraries: Visual Studio 2017 Debug, Visual Studio 2017 Release, Visual Studio 2019 Debug, Visual
// Studio 2019 Release

void deallocate(undefined8 param_1,void *param_2,longlong param_3)

{
  FUN_140004e80(param_2,param_3 << 1);
  return;
}



undefined8 FUN_140003b20(void)

{
  return 0xffff;
}



// Library Function - Multiple Matches With Same Base Name
//  public: static unsigned short __cdecl std::_WChar_traits<unsigned short>::not_eof(unsigned short
// const & __ptr64)
//  public: static unsigned short __cdecl std::_WChar_traits<wchar_t>::not_eof(unsigned short const
// & __ptr64)
// 
// Libraries: Visual Studio 2017 Debug, Visual Studio 2017 Release, Visual Studio 2019 Debug, Visual
// Studio 2019 Release

ushort not_eof(ushort *param_1)

{
  ushort uVar1;
  undefined8 uVar2;
  ulonglong uVar3;
  ushort local_18;
  ushort local_16;
  
  uVar1 = *param_1;
  uVar2 = FUN_140003b20();
  if ((uint)uVar1 == ((uint)uVar2 & 0xffff)) {
    uVar3 = FUN_140003b20();
    local_18 = (ushort)((uVar3 & 0xffff) == 0);
    local_16 = local_18;
  }
  else {
    local_16 = *param_1;
  }
  return local_16;
}



// Library Function - Multiple Matches With Same Base Name
//  public: static bool __cdecl std::_WChar_traits<unsigned short>::eq_int_type(unsigned short const
// & __ptr64,unsigned short const & __ptr64)
//  public: static bool __cdecl std::_WChar_traits<wchar_t>::eq_int_type(unsigned short const &
// __ptr64,unsigned short const & __ptr64)
//  public: static bool __cdecl std::char_traits<unsigned short>::eq_int_type(unsigned short const &
// __ptr64,unsigned short const & __ptr64)
//  public: static bool __cdecl std::char_traits<wchar_t>::eq_int_type(unsigned short const &
// __ptr64,unsigned short const & __ptr64)
// 
// Library: Visual Studio

bool eq_int_type(short *param_1,short *param_2)

{
  return *param_1 == *param_2;
}



undefined2 FUN_140003be0(undefined2 *param_1)

{
  return *param_1;
}



undefined * FUN_140003bf0(undefined *param_1,undefined *param_2,longlong param_3)

{
  char cVar1;
  longlong lVar2;
  undefined *puVar3;
  longlong local_28;
  
  cVar1 = FUN_140001040();
  if (cVar1 == '\0') {
    puVar3 = param_1;
    for (lVar2 = param_3 << 1; lVar2 != 0; lVar2 = lVar2 + -1) {
      *puVar3 = *param_2;
      param_2 = param_2 + 1;
      puVar3 = puVar3 + 1;
    }
  }
  else {
    for (local_28 = 0; local_28 != param_3; local_28 = local_28 + 1) {
      *(undefined2 *)(param_1 + local_28 * 2) = *(undefined2 *)(param_2 + local_28 * 2);
    }
  }
  return param_1;
}



void FUN_140003c80(longlong **param_1)

{
  longlong *plVar1;
  
  plVar1 = (longlong *)
           std::basic_ios<>::rdbuf
                     ((basic_ios<> *)((longlong)*param_1 + (longlong)*(int *)(**param_1 + 4)));
  if (plVar1 != (longlong *)0x0) {
    (**(code **)(*plVar1 + 0x10))(plVar1);
  }
  return;
}



longlong ** FUN_140003ce0(longlong **param_1,longlong *param_2)

{
  longlong *plVar1;
  
  *param_1 = param_2;
  plVar1 = (longlong *)
           std::basic_ios<>::rdbuf
                     ((basic_ios<> *)((longlong)*param_1 + (longlong)*(int *)(**param_1 + 4)));
  if (plVar1 != (longlong *)0x0) {
    (**(code **)(*plVar1 + 8))(plVar1);
  }
  return param_1;
}



// Library Function - Single Match
//  private: static int __cdecl std::basic_stringbuf<char,struct std::char_traits<char>,class
// std::allocator<char> >::_Getstate(int)
// 
// Libraries: Visual Studio 2017 Debug, Visual Studio 2017 Release, Visual Studio 2019 Debug, Visual
// Studio 2019 Release

int __cdecl std::basic_stringbuf<>::_Getstate(int param_1)

{
  uint local_18;
  
  local_18 = 0;
  if ((param_1 & 1U) == 0) {
    local_18 = 4;
  }
  if ((param_1 & 2U) == 0) {
    local_18 = local_18 | 2;
  }
  if ((param_1 & 8U) != 0) {
    local_18 = local_18 | 8;
  }
  if ((param_1 & 4U) != 0) {
    local_18 = local_18 | 0x10;
  }
  return local_18;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_140003dc0(basic_streambuf<> *param_1,undefined *param_2)

{
  wchar_t *pwVar1;
  ulonglong *puVar2;
  longlong lVar3;
  wchar_t **ppwVar4;
  undefined auStack_78 [32];
  wchar_t *local_58;
  wchar_t *local_50;
  wchar_t *local_48;
  wchar_t *local_40;
  longlong local_38;
  longlong local_30;
  ulonglong local_28;
  
  local_28 = _FLOAT_14000d008 ^ (ulonglong)auStack_78;
  ppwVar4 = &local_40;
  for (lVar3 = 0x18; lVar3 != 0; lVar3 = lVar3 + -1) {
    *(undefined *)ppwVar4 = 0;
    ppwVar4 = (wchar_t **)((longlong)ppwVar4 + 1);
  }
  if (((*(uint *)(param_1 + 0x70) & 2) == 0) || ((*(uint *)(param_1 + 0x70) & 0x20) != 0)) {
    pwVar1 = std::basic_streambuf<>::pptr(param_1);
    if (pwVar1 != (wchar_t *)0x0) {
      local_58 = std::basic_streambuf<>::pbase(param_1);
      local_40 = local_58;
      local_48 = std::basic_streambuf<>::pptr(param_1);
      puVar2 = _Max_value<>((ulonglong *)&local_48,(ulonglong *)(param_1 + 0x68));
      local_38 = (longlong)(*puVar2 - (longlong)local_58) >> 1;
      pwVar1 = std::basic_streambuf<>::epptr(param_1);
      local_30 = (longlong)pwVar1 - (longlong)local_58 >> 1;
      goto LAB_140003f0b;
    }
  }
  if ((*(uint *)(param_1 + 0x70) & 4) == 0) {
    pwVar1 = std::basic_streambuf<>::gptr(param_1);
    if (pwVar1 != (wchar_t *)0x0) {
      local_50 = std::basic_streambuf<>::eback(param_1);
      local_40 = local_50;
      pwVar1 = std::basic_streambuf<>::egptr(param_1);
      local_38 = (longlong)pwVar1 - (longlong)local_50 >> 1;
      local_30 = local_38;
    }
  }
LAB_140003f0b:
  ppwVar4 = &local_40;
  for (lVar3 = 0x18; lVar3 != 0; lVar3 = lVar3 + -1) {
    *param_2 = *(undefined *)ppwVar4;
    ppwVar4 = (wchar_t **)((longlong)ppwVar4 + 1);
    param_2 = param_2 + 1;
  }
  FUN_140005b50(local_28 ^ (ulonglong)auStack_78);
  return;
}



void FUN_140003f40(void)

{
  FUN_140001640();
  return;
}



void FUN_140003f70(undefined8 *param_1)

{
  char cVar1;
  undefined2 local_38 [4];
  undefined8 *local_30;
  undefined8 local_28;
  undefined8 local_20;
  wchar_t *local_18;
  
  param_1[2] = 0;
  local_30 = param_1;
  cVar1 = FUN_140001040();
  if (cVar1 == '\0') {
    local_30[3] = 7;
    local_38[0] = 0;
    FUN_140004240((undefined2 *)local_30,local_38);
  }
  else {
    local_30[3] = 8;
    local_20 = FUN_1400037e0(param_1);
    local_28 = allocate(local_20,9);
    *local_30 = local_28;
    local_18 = (wchar_t *)FUN_140001fa0(local_28);
    FUN_1400042c0(local_18,9,L'\0');
  }
  return;
}



// Library Function - Multiple Matches With Different Base Names
//  public: class std::basic_string<unsigned short,struct std::char_traits<unsigned short>,class
// std::allocator<unsigned short> > & __ptr64 __cdecl std::basic_string<unsigned short,struct
// std::char_traits<unsigned short>,class std::allocator<unsigned short> >::assign(unsigned short
// const * __ptr64 const,unsigned __int64) __ptr64
//  public: class std::basic_string<wchar_t,struct std::char_traits<wchar_t>,class
// std::allocator<wchar_t> > & __ptr64 __cdecl std::basic_string<wchar_t,struct
// std::char_traits<wchar_t>,class std::allocator<wchar_t> >::assign(wchar_t const * __ptr64
// const,unsigned __int64) __ptr64
// 
// Library: Visual Studio 2019 Release

void ** FID_conflict_assign(void **param_1,undefined *param_2,void *param_3)

{
  undefined local_18;
  undefined2 local_16 [3];
  undefined8 *local_10;
  
  if (param_1[3] < param_3) {
    param_1 = (void **)FUN_140004ee0(param_1,param_3,local_18,param_2);
  }
  else {
    local_10 = Myptr(param_1);
    param_1[2] = param_3;
    FUN_140004360(local_10,param_2,(longlong)param_3);
    local_16[0] = 0;
    FUN_140004240((undefined2 *)((longlong)local_10 + (longlong)param_3 * 2),local_16);
  }
  return param_1;
}



void FUN_1400040e0(undefined8 param_1,undefined *param_2,longlong param_3,undefined *param_4)

{
  undefined2 local_18 [12];
  
  FUN_140003bf0(param_2,param_4,param_3);
  local_18[0] = 0;
  FUN_140004240((undefined2 *)(param_2 + param_3 * 2),local_18);
  return;
}



void FUN_140004140(undefined8 param_1,undefined8 param_2)

{
  undefined *puVar1;
  undefined *puVar2;
  longlong lVar3;
  
  puVar1 = (undefined *)FUN_140001fa0(param_1);
  puVar2 = (undefined *)FUN_140001fa0(param_2);
  for (lVar3 = 0x20; lVar3 != 0; lVar3 = lVar3 + -1) {
    *puVar1 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar1 = puVar1 + 1;
  }
  return;
}



undefined8 * FUN_140004190(undefined8 *param_1,undefined8 param_2)

{
  byte local_28;
  
  FUN_140004cc0(param_1,(ulonglong)local_28,param_2);
  FUN_140001640();
  FUN_140003f70(param_1);
  return param_1;
}



bool FUN_1400041f0(longlong param_1)

{
  char cVar1;
  bool bVar2;
  
  cVar1 = FUN_140001040();
  if (cVar1 == '\0') {
    bVar2 = 7 < *(ulonglong *)(param_1 + 0x18);
  }
  else {
    bVar2 = true;
  }
  return bVar2;
}



void FUN_140004240(undefined2 *param_1,undefined2 *param_2)

{
  char cVar1;
  
  cVar1 = FUN_140001040();
  if (cVar1 == '\0') {
    *param_1 = *param_2;
  }
  else {
    FUN_140004310(param_1,param_2);
  }
  return;
}



// Library Function - Single Match
//  public: static unsigned __int64 __cdecl std::_WChar_traits<wchar_t>::length(wchar_t const *
// __ptr64)
// 
// Libraries: Visual Studio 2017 Debug, Visual Studio 2017 Release, Visual Studio 2019 Debug, Visual
// Studio 2019 Release

__uint64 __cdecl std::_WChar_traits<wchar_t>::length(wchar_t *param_1)

{
  __uint64 local_18;
  
  local_18 = 0xffffffffffffffff;
  do {
    local_18 = local_18 + 1;
  } while (param_1[local_18] != L'\0');
  return local_18;
}



void FUN_1400042c0(wchar_t *param_1,size_t param_2,wchar_t param_3)

{
  char cVar1;
  
  cVar1 = FUN_140001040();
  if (cVar1 == '\0') {
    wmemset(param_1,param_3,param_2);
  }
  else {
    FUN_140004490(param_1,param_2,param_3);
  }
  return;
}



void FUN_140004310(undefined2 *param_1,undefined2 *param_2)

{
  char cVar1;
  undefined8 uVar2;
  
  cVar1 = FUN_140001040();
  if (cVar1 == '\0') {
    *param_1 = *param_2;
  }
  else {
    uVar2 = FUN_140001fa0(param_1);
    FUN_140005060(uVar2,param_2);
  }
  return;
}



void * FUN_140004360(void *param_1,void *param_2,longlong param_3)

{
  bool bVar1;
  char cVar2;
  longlong local_20;
  longlong local_18;
  void *local_10;
  
  cVar2 = FUN_140001040();
  if (cVar2 == '\0') {
    memmove(param_1,param_2,param_3 << 1);
  }
  else {
    bVar1 = true;
    for (local_10 = param_2; local_10 != (void *)((longlong)param_2 + param_3 * 2);
        local_10 = (void *)((longlong)local_10 + 2)) {
      if (param_1 == local_10) {
        bVar1 = false;
        break;
      }
    }
    local_18 = param_3;
    if (bVar1) {
      for (local_20 = 0; local_20 != param_3; local_20 = local_20 + 1) {
        *(undefined2 *)((longlong)param_1 + local_20 * 2) =
             *(undefined2 *)((longlong)param_2 + local_20 * 2);
      }
    }
    else {
      for (; local_18 != 0; local_18 = local_18 + -1) {
        *(undefined2 *)((longlong)param_1 + local_18 * 2 + -2) =
             *(undefined2 *)((longlong)param_2 + local_18 * 2 + -2);
      }
    }
  }
  return param_1;
}



undefined2 * FUN_140004490(undefined2 *param_1,longlong param_2,undefined2 param_3)

{
  char cVar1;
  longlong local_res10;
  undefined2 local_res18 [8];
  undefined2 *local_18;
  undefined2 *local_10;
  
  local_res18[0] = param_3;
  cVar1 = FUN_140001040();
  local_res10 = param_2;
  local_18 = param_1;
  local_10 = param_1;
  if (cVar1 == '\0') {
    for (; local_res10 != 0; local_res10 = local_res10 + -1) {
      *local_10 = local_res18[0];
      local_10 = local_10 + 1;
    }
  }
  else {
    for (; local_res10 != 0; local_res10 = local_res10 + -1) {
      FUN_140005060(local_18,local_res18);
      local_18 = local_18 + 1;
    }
  }
  return param_1;
}



undefined2 *
FUN_140004540(undefined2 *param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4)

{
  undefined8 uVar1;
  undefined8 uVar2;
  undefined8 uVar3;
  byte local_25;
  
  uVar1 = FUN_140001fa0(param_4);
  uVar2 = FUN_140001fa0(param_3);
  uVar3 = FUN_140001fa0(param_2);
  FUN_1400052c0(param_1,(ulonglong)local_25,uVar3,uVar2,uVar1);
  return param_1;
}



longlong FUN_1400045d0(longlong param_1)

{
  return param_1 + 4;
}



longlong FUN_1400045e0(longlong param_1)

{
  return param_1 + 2;
}



longlong FUN_1400045f0(longlong param_1,longlong param_2)

{
  undefined2 *puVar1;
  undefined8 uVar2;
  longlong lVar3;
  longlong lVar4;
  
  puVar1 = (undefined2 *)FUN_140001fa0(param_2 + 4);
  *(undefined2 *)(param_1 + 4) = *puVar1;
  uVar2 = FUN_140001fa0(param_2);
  lVar3 = FUN_140001fa0(uVar2);
  lVar4 = FUN_140001fa0(param_1);
  FUN_140005350(lVar4,lVar3);
  return param_1;
}



longlong FUN_140004660(longlong param_1,longlong param_2)

{
  longlong lVar1;
  longlong lVar2;
  
  *(undefined2 *)(param_1 + 4) = *(undefined2 *)(param_2 + 4);
  lVar1 = FUN_140001fa0(param_2);
  lVar2 = FUN_140001fa0(param_1);
  FUN_1400053c0(lVar2,lVar1);
  return param_1;
}



// WARNING: Removing unreachable block (ram,0x0001400046c7)
// WARNING: Removing unreachable block (ram,0x0001400046ff)

undefined8 * FUN_1400046b0(undefined8 *param_1,undefined8 param_2)

{
  int local_1b0 [2];
  undefined **local_1a8;
  
  local_1a8 = (undefined **)operator_new(400);
  local_1b0[0] = 0;
  FUN_140006900(local_1b0,local_1a8,param_1,param_2);
  return param_1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_140004780(longlong *param_1,wchar_t *param_2)

{
  char cVar1;
  bool bVar2;
  __int64 _Var3;
  undefined8 uVar4;
  undefined auStack_d8 [32];
  uint local_b8;
  wchar_t local_b4;
  wchar_t local_b2;
  ushort local_b0;
  ushort local_ae;
  short local_ac;
  wchar_t local_aa;
  wchar_t local_a8;
  ushort local_a6;
  ushort local_a4;
  short local_a2;
  longlong local_a0;
  __uint64 local_98;
  uint local_90;
  longlong local_88;
  basic_streambuf<> *local_80;
  basic_streambuf<> *local_78;
  basic_streambuf<> *local_70;
  basic_streambuf<> *local_68;
  __uint64 local_60;
  basic_streambuf<> *local_58;
  basic_streambuf<> *local_50;
  ios_base *local_48;
  basic_ios<> *local_38;
  longlong *local_30;
  longlong *local_28 [2];
  ulonglong local_18;
  
  local_18 = _FLOAT_14000d008 ^ (ulonglong)auStack_d8;
  local_b8 = 0;
  local_98 = std::_WChar_traits<wchar_t>::length(param_2);
  _Var3 = std::ios_base::width((ios_base *)((longlong)param_1 + (longlong)*(int *)(*param_1 + 4)));
  if ((_Var3 < 1) ||
     (_Var3 = std::ios_base::width
                        ((ios_base *)((longlong)param_1 + (longlong)*(int *)(*param_1 + 4))),
     _Var3 <= (longlong)local_98)) {
    local_88 = 0;
  }
  else {
    _Var3 = std::ios_base::width((ios_base *)((longlong)param_1 + (longlong)*(int *)(*param_1 + 4)))
    ;
    local_88 = _Var3 - local_98;
  }
  local_a0 = local_88;
  FUN_140003460(local_28,param_1);
  cVar1 = FUN_140003400((longlong)local_28);
  if (cVar1 == '\0') {
    local_b8 = local_b8 | 4;
  }
  else {
    local_90 = std::ios_base::flags
                         ((ios_base *)((longlong)param_1 + (longlong)*(int *)(*param_1 + 4)));
    if ((local_90 & 0x1c0) != 0x40) {
      for (; 0 < local_a0; local_a0 = local_a0 + -1) {
        local_80 = std::basic_ios<>::rdbuf
                             ((basic_ios<> *)((longlong)param_1 + (longlong)*(int *)(*param_1 + 4)))
        ;
        local_78 = local_80;
        local_b4 = std::basic_ios<>::fill
                             ((basic_ios<> *)((longlong)param_1 + (longlong)*(int *)(*param_1 + 4)))
        ;
        local_b2 = local_b4;
        local_b0 = std::basic_streambuf<>::sputc(local_78,local_b4);
        local_ae = local_b0;
        uVar4 = FUN_140003b20();
        local_ac = (short)uVar4;
        bVar2 = eq_int_type(&local_ac,(short *)&local_ae);
        if (bVar2) {
          local_b8 = local_b8 | 4;
          break;
        }
      }
    }
    if (local_b8 == 0) {
      local_70 = std::basic_ios<>::rdbuf
                           ((basic_ios<> *)((longlong)param_1 + (longlong)*(int *)(*param_1 + 4)));
      local_68 = local_70;
      local_60 = std::basic_streambuf<>::sputn(local_70,param_2,local_98);
      if (local_60 != local_98) {
        local_b8 = local_b8 | 4;
      }
    }
    if (local_b8 == 0) {
      for (; 0 < local_a0; local_a0 = local_a0 + -1) {
        local_58 = std::basic_ios<>::rdbuf
                             ((basic_ios<> *)((longlong)param_1 + (longlong)*(int *)(*param_1 + 4)))
        ;
        local_50 = local_58;
        local_aa = std::basic_ios<>::fill
                             ((basic_ios<> *)((longlong)param_1 + (longlong)*(int *)(*param_1 + 4)))
        ;
        local_a8 = local_aa;
        local_a6 = std::basic_streambuf<>::sputc(local_50,local_aa);
        local_a4 = local_a6;
        uVar4 = FUN_140003b20();
        local_a2 = (short)uVar4;
        bVar2 = eq_int_type(&local_a2,(short *)&local_a4);
        if (bVar2) {
          local_b8 = local_b8 | 4;
          break;
        }
      }
    }
    local_48 = (ios_base *)((longlong)param_1 + (longlong)*(int *)(*param_1 + 4));
    std::ios_base::width(local_48,0);
  }
  local_38 = (basic_ios<> *)((longlong)param_1 + (longlong)*(int *)(*param_1 + 4));
  std::basic_ios<>::setstate(local_38,local_b8,false);
  local_30 = param_1;
  FUN_140003410(local_28);
  FUN_140005b50(local_18 ^ (ulonglong)auStack_d8);
  return;
}



longlong * FUN_140004bc0(longlong *param_1)

{
  wchar_t wVar1;
  
  wVar1 = std::basic_ios<>::widen
                    ((basic_ios<> *)((longlong)param_1 + (longlong)*(int *)(*param_1 + 4)),'\n');
  std::basic_ostream<>::put((basic_ostream<> *)param_1,wVar1);
  std::basic_ostream<>::flush((basic_ostream<> *)param_1);
  return param_1;
}



void FUN_140004c20(longlong *param_1,undefined8 *param_2)

{
  ulonglong uVar1;
  wchar_t *pwVar2;
  
  uVar1 = FUN_140003900((longlong)param_2);
  pwVar2 = (wchar_t *)FUN_140003250(param_2);
  FUN_140005410(param_1,pwVar2,uVar1);
  return;
}



// Library Function - Single Match
//  unsigned __int64 const & __ptr64 __cdecl std::_Min_value<unsigned __int64>(unsigned __int64
// const & __ptr64,unsigned __int64 const & __ptr64)
// 
// Libraries: Visual Studio 2017 Debug, Visual Studio 2017 Release, Visual Studio 2019 Debug, Visual
// Studio 2019 Release

__uint64 * __cdecl std::_Min_value<>(__uint64 *param_1,__uint64 *param_2)

{
  __uint64 *local_18;
  
  local_18 = param_1;
  if (*param_2 < *param_1) {
    local_18 = param_2;
  }
  return local_18;
}



undefined8 * FUN_140004cc0(undefined8 *param_1,undefined8 param_2,undefined8 param_3)

{
  FUN_140001fa0(param_3);
  _String_val<>(param_1);
  return param_1;
}



void FUN_140004d00(undefined8 param_1)

{
  char cVar1;
  undefined8 uVar2;
  undefined8 *puVar3;
  
  cVar1 = FUN_140001040();
  if (cVar1 == '\0') {
    uVar2 = FUN_140001fa0(param_1);
    uVar2 = FUN_140001fa0(uVar2);
    puVar3 = (undefined8 *)FUN_140001030(0x10,uVar2);
    FUN_140001700(puVar3);
  }
  else {
    uVar2 = FUN_140001fa0(param_1);
    FUN_140005830(uVar2);
  }
  return;
}



void FUN_140004d60(undefined8 param_1,undefined8 param_2)

{
  char cVar1;
  undefined8 uVar2;
  undefined8 uVar3;
  undefined8 *puVar4;
  undefined8 *puVar5;
  
  cVar1 = FUN_140001040();
  if (cVar1 == '\0') {
    uVar2 = FUN_140001fa0(param_1);
    uVar2 = FUN_140001fa0(uVar2);
    puVar4 = (undefined8 *)FUN_140001030(8,uVar2);
    puVar5 = (undefined8 *)FUN_140001fa0(param_2);
    *puVar4 = *puVar5;
  }
  else {
    uVar2 = FUN_140001fa0(param_2);
    uVar3 = FUN_140001fa0(param_1);
    FUN_140005870(uVar3,uVar2);
  }
  return;
}



// Library Function - Single Match
//  unsigned __int64 __cdecl std::_Get_size_of_n<2>(unsigned __int64)
// 
// Libraries: Visual Studio 2019 Debug, Visual Studio 2019 Release

__uint64 __cdecl std::_Get_size_of_n<2>(__uint64 param_1)

{
  if (0x7fffffffffffffff < param_1) {
    FUN_1400014b0();
  }
  return param_1 << 1;
}



ulonglong FUN_140004e30(ulonglong param_1)

{
  char cVar1;
  ulonglong uVar2;
  
  cVar1 = FUN_140001040();
  if ((cVar1 == '\0') && (0xfff < param_1)) {
    uVar2 = FUN_1400058c0(param_1);
  }
  else if (param_1 == 0) {
    uVar2 = 0;
  }
  else {
    uVar2 = FUN_140001570(param_1);
  }
  return uVar2;
}



void FUN_140004e80(void *param_1,ulonglong param_2)

{
  char cVar1;
  void *local_res8;
  ulonglong local_res10 [3];
  
  local_res8 = param_1;
  local_res10[0] = param_2;
  cVar1 = FUN_140001040();
  if (cVar1 == '\0') {
    if (0xfff < local_res10[0]) {
      FUN_140001590((longlong *)&local_res8,(longlong *)local_res10);
    }
    free(local_res8);
  }
  else {
    free(local_res8);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_140004ee0(void **param_1,void *param_2,undefined param_3,undefined *param_4)

{
  char cVar1;
  void *pvVar2;
  __uint64 _Var3;
  wchar_t *pwVar4;
  undefined *puVar5;
  undefined local_res18 [8];
  undefined *local_res20;
  undefined auStack_58 [32];
  void *local_38;
  void *local_30;
  undefined8 local_28;
  size_t local_20;
  void *local_18;
  ulonglong local_10;
  
  local_10 = _FLOAT_14000d008 ^ (ulonglong)auStack_58;
  local_res18[0] = param_3;
  local_res20 = param_4;
  pvVar2 = (void *)FUN_140005130(param_1);
  if (pvVar2 < param_2) {
    FUN_140001650();
  }
  local_30 = param_1[3];
  local_38 = (void *)FUN_1400050e0((longlong)param_1,(ulonglong)param_2);
  local_28 = FUN_1400037e0(param_1);
  _Var3 = (longlong)local_38 + 1;
  if (local_38 == (void *)0xffffffffffffffff) {
    _Var3 = 0xffffffffffffffff;
  }
  local_18 = (void *)allocate(local_28,_Var3);
  cVar1 = FUN_140001040();
  if (cVar1 != '\0') {
    local_20 = (longlong)local_38 + 1;
    pwVar4 = (wchar_t *)FUN_140001fa0(local_18);
    FUN_1400042c0(pwVar4,local_20,L'\0');
  }
  FUN_140001630();
  param_1[2] = param_2;
  param_1[3] = local_38;
  puVar5 = (undefined *)FUN_140001fa0(local_18);
  FUN_1400040e0(local_res18,puVar5,(longlong)param_2,local_res20);
  if (local_30 < (void *)0x8) {
    FUN_140004d60(param_1,&local_18);
  }
  else {
    deallocate(local_28,*param_1,(longlong)local_30 + 1);
    *param_1 = local_18;
  }
  FUN_140005b50(local_10 ^ (ulonglong)auStack_58);
  return;
}



undefined2 * FUN_140005060(undefined8 param_1,undefined8 param_2)

{
  undefined8 uVar1;
  undefined2 *puVar2;
  undefined2 *puVar3;
  
  uVar1 = FUN_140001fa0(param_1);
  puVar2 = (undefined2 *)FUN_140001030(2,uVar1);
  puVar3 = (undefined2 *)FUN_140001fa0(param_2);
  *puVar2 = *puVar3;
  return puVar2;
}



undefined8 * FUN_1400050b0(undefined8 *param_1,undefined8 *param_2)

{
  FUN_1400016a0(param_2,*param_1);
  return param_2;
}



void FUN_1400050e0(longlong param_1,ulonglong param_2)

{
  ulonglong uVar1;
  
  uVar1 = FUN_140005130(param_1);
  FUN_140005200(param_2,*(ulonglong *)(param_1 + 0x18),uVar1);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_140005130(undefined8 param_1)

{
  ulonglong *puVar1;
  undefined auStack_58 [32];
  ulonglong local_38;
  ulonglong local_30;
  __uint64 local_28;
  __uint64 local_20;
  ulonglong local_18;
  ulonglong local_10;
  
  local_10 = _FLOAT_14000d008 ^ (ulonglong)auStack_58;
  FUN_1400037e0(param_1);
  local_18 = FUN_1400052b0();
  local_38 = 8;
  puVar1 = _Max_value<>(&local_18,&local_38);
  local_30 = *puVar1;
  local_28 = local_30 - 1;
  local_20 = FUN_1400010b0();
  std::_Min_value<>(&local_20,&local_28);
  FUN_140005b50(local_10 ^ (ulonglong)auStack_58);
  return;
}



// Library Function - Multiple Matches With Same Base Name
//  public: __cdecl std::_String_val<struct std::_Simple_types<char> >::_String_val<struct
// std::_Simple_types<char> >(void) __ptr64
//  public: __cdecl std::_String_val<struct std::_Simple_types<unsigned short> >::_String_val<struct
// std::_Simple_types<unsigned short> >(void) __ptr64
//  public: __cdecl std::_String_val<struct std::_Simple_types<wchar_t> >::_String_val<struct
// std::_Simple_types<wchar_t> >(void) __ptr64
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

undefined8 * _String_val<>(undefined8 *param_1)

{
  FUN_140001700(param_1);
  param_1[2] = 0;
  param_1[3] = 0;
  return param_1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_140005200(ulonglong param_1,ulonglong param_2,ulonglong param_3)

{
  undefined auStack_48 [32];
  ulonglong local_28;
  ulonglong local_20;
  ulonglong local_18;
  
  local_18 = _FLOAT_14000d008 ^ (ulonglong)auStack_48;
  local_20 = param_1 | 7;
  if ((local_20 <= param_3) && (param_2 <= param_3 - param_2 / 2)) {
    local_28 = param_2 + param_2 / 2;
    _Max_value<>(&local_20,&local_28);
  }
  FUN_140005b50(local_18 ^ (ulonglong)auStack_48);
  return;
}



undefined8 FUN_1400052b0(void)

{
  return 0x7fffffffffffffff;
}



undefined2 *
FUN_1400052c0(undefined2 *param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
             undefined8 param_5)

{
  undefined8 uVar1;
  undefined8 uVar2;
  byte local_26;
  
  uVar1 = FUN_140001fa0(param_5);
  uVar2 = FUN_140001fa0(param_4);
  FUN_140005950(param_1,(ulonglong)local_26,uVar2,uVar1);
  uVar1 = FUN_140001fa0(param_3);
  FUN_1400059d0(param_1 + 2,uVar1);
  return param_1;
}



longlong FUN_140005350(longlong param_1,longlong param_2)

{
  undefined2 *puVar1;
  undefined8 uVar2;
  
  puVar1 = (undefined2 *)FUN_140001fa0(param_2 + 2);
  *(undefined2 *)(param_1 + 2) = *puVar1;
  uVar2 = FUN_140001fa0(param_2);
  uVar2 = FUN_140001fa0(uVar2);
  puVar1 = (undefined2 *)FUN_140001fa0(param_1);
  FUN_140005a00(puVar1,uVar2);
  return param_1;
}



longlong FUN_1400053c0(longlong param_1,longlong param_2)

{
  undefined2 *puVar1;
  undefined2 *puVar2;
  
  *(undefined2 *)(param_1 + 2) = *(undefined2 *)(param_2 + 2);
  puVar1 = (undefined2 *)FUN_140001fa0(param_2);
  puVar2 = (undefined2 *)FUN_140001fa0(param_1);
  FUN_140005a50(puVar2,puVar1);
  return param_1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_140005410(longlong *param_1,wchar_t *param_2,ulonglong param_3)

{
  char cVar1;
  bool bVar2;
  __int64 _Var3;
  ulonglong uVar4;
  undefined8 uVar5;
  undefined auStack_c8 [32];
  uint local_a8;
  wchar_t local_a4;
  wchar_t local_a2;
  ushort local_a0;
  ushort local_9e;
  short local_9c;
  wchar_t local_9a;
  wchar_t local_98;
  ushort local_96;
  ushort local_94;
  short local_92;
  longlong local_90;
  uint local_88;
  basic_streambuf<> *local_80;
  basic_streambuf<> *local_78;
  basic_streambuf<> *local_70;
  basic_streambuf<> *local_68;
  ulonglong local_60;
  basic_streambuf<> *local_58;
  basic_streambuf<> *local_50;
  ios_base *local_48;
  basic_ios<> *local_38;
  longlong *local_30;
  longlong *local_28 [2];
  ulonglong local_18;
  
  local_18 = _FLOAT_14000d008 ^ (ulonglong)auStack_c8;
  local_a8 = 0;
  _Var3 = std::ios_base::width((ios_base *)((longlong)param_1 + (longlong)*(int *)(*param_1 + 4)));
  if ((_Var3 < 1) ||
     (uVar4 = std::ios_base::width
                        ((ios_base *)((longlong)param_1 + (longlong)*(int *)(*param_1 + 4))),
     uVar4 <= param_3)) {
    local_90 = 0;
  }
  else {
    _Var3 = std::ios_base::width((ios_base *)((longlong)param_1 + (longlong)*(int *)(*param_1 + 4)))
    ;
    local_90 = _Var3 - param_3;
  }
  FUN_140003460(local_28,param_1);
  cVar1 = FUN_140003400((longlong)local_28);
  if (cVar1 == '\0') {
    local_a8 = local_a8 | 4;
    goto LAB_1400057ae;
  }
  local_88 = std::ios_base::flags
                       ((ios_base *)((longlong)param_1 + (longlong)*(int *)(*param_1 + 4)));
  if ((local_88 & 0x1c0) != 0x40) {
    for (; local_90 != 0; local_90 = local_90 + -1) {
      local_80 = std::basic_ios<>::rdbuf
                           ((basic_ios<> *)((longlong)param_1 + (longlong)*(int *)(*param_1 + 4)));
      local_78 = local_80;
      local_a4 = std::basic_ios<>::fill
                           ((basic_ios<> *)((longlong)param_1 + (longlong)*(int *)(*param_1 + 4)));
      local_a2 = local_a4;
      local_a0 = std::basic_streambuf<>::sputc(local_78,local_a4);
      local_9e = local_a0;
      uVar5 = FUN_140003b20();
      local_9c = (short)uVar5;
      bVar2 = eq_int_type(&local_9c,(short *)&local_9e);
      if (bVar2) {
        local_a8 = local_a8 | 4;
        break;
      }
    }
  }
  if (local_a8 == 0) {
    local_70 = std::basic_ios<>::rdbuf
                         ((basic_ios<> *)((longlong)param_1 + (longlong)*(int *)(*param_1 + 4)));
    local_68 = local_70;
    local_60 = std::basic_streambuf<>::sputn(local_70,param_2,param_3);
    if (local_60 == param_3) goto LAB_1400056af;
    local_a8 = local_a8 | 4;
  }
  else {
LAB_1400056af:
    for (; local_90 != 0; local_90 = local_90 + -1) {
      local_58 = std::basic_ios<>::rdbuf
                           ((basic_ios<> *)((longlong)param_1 + (longlong)*(int *)(*param_1 + 4)));
      local_50 = local_58;
      local_9a = std::basic_ios<>::fill
                           ((basic_ios<> *)((longlong)param_1 + (longlong)*(int *)(*param_1 + 4)));
      local_98 = local_9a;
      local_96 = std::basic_streambuf<>::sputc(local_50,local_9a);
      local_94 = local_96;
      uVar5 = FUN_140003b20();
      local_92 = (short)uVar5;
      bVar2 = eq_int_type(&local_92,(short *)&local_94);
      if (bVar2) {
        local_a8 = local_a8 | 4;
        break;
      }
    }
  }
  local_48 = (ios_base *)((longlong)param_1 + (longlong)*(int *)(*param_1 + 4));
  std::ios_base::width(local_48,0);
LAB_1400057ae:
  local_38 = (basic_ios<> *)((longlong)param_1 + (longlong)*(int *)(*param_1 + 4));
  std::basic_ios<>::setstate(local_38,local_a8,false);
  local_30 = param_1;
  FUN_140003410(local_28);
  FUN_140005b50(local_18 ^ (ulonglong)auStack_c8);
  return;
}



void FUN_140005830(undefined8 param_1)

{
  undefined8 uVar1;
  undefined8 *puVar2;
  
  uVar1 = FUN_140001fa0(param_1);
  puVar2 = (undefined8 *)FUN_140001030(0x10,uVar1);
  FUN_140001700(puVar2);
  return;
}



undefined8 * FUN_140005870(undefined8 param_1,undefined8 param_2)

{
  undefined8 uVar1;
  undefined8 *puVar2;
  undefined8 *puVar3;
  
  uVar1 = FUN_140001fa0(param_1);
  puVar2 = (undefined8 *)FUN_140001030(8,uVar1);
  puVar3 = (undefined8 *)FUN_140001fa0(param_2);
  *puVar2 = *puVar3;
  return puVar2;
}



ulonglong FUN_1400058c0(ulonglong param_1)

{
  longlong lVar1;
  ulonglong uVar2;
  
  if (param_1 + 0x27 <= param_1) {
    FUN_1400014b0();
  }
  lVar1 = FUN_140001570(param_1 + 0x27);
  if (lVar1 != 0) {
    uVar2 = lVar1 + 0x27U & 0xffffffffffffffe0;
    *(longlong *)(uVar2 - 8) = lVar1;
    return uVar2;
  }
                    // WARNING: Subroutine does not return
  _invalid_parameter_noinfo_noreturn();
}



undefined2 *
FUN_140005950(undefined2 *param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4)

{
  undefined8 uVar1;
  byte local_27;
  
  uVar1 = FUN_140001fa0(param_4);
  FUN_140005a90(param_1,(ulonglong)local_27,uVar1);
  uVar1 = FUN_140001fa0(param_3);
  FUN_1400059d0(param_1 + 1,uVar1);
  return param_1;
}



undefined2 * FUN_1400059d0(undefined2 *param_1,undefined8 param_2)

{
  undefined2 *puVar1;
  
  puVar1 = (undefined2 *)FUN_140001fa0(param_2);
  *param_1 = *puVar1;
  return param_1;
}



undefined2 * FUN_140005a00(undefined2 *param_1,undefined8 param_2)

{
  undefined2 *puVar1;
  undefined8 uVar2;
  
  puVar1 = (undefined2 *)FUN_140001fa0(param_2);
  *param_1 = *puVar1;
  uVar2 = FUN_140001fa0(param_2);
  FUN_140001fa0(uVar2);
  FUN_140001fa0(param_1);
  return param_1;
}



undefined2 * FUN_140005a50(undefined2 *param_1,undefined2 *param_2)

{
  *param_1 = *param_2;
  FUN_140001fa0(param_2);
  FUN_140001fa0(param_1);
  return param_1;
}



undefined2 * FUN_140005a90(undefined2 *param_1,undefined8 param_2,undefined8 param_3)

{
  undefined8 uVar1;
  
  FUN_140005ae0(param_1);
  uVar1 = FUN_140001fa0(param_3);
  FUN_1400059d0(param_1,uVar1);
  return param_1;
}



undefined8 FUN_140005ae0(undefined8 param_1)

{
  return param_1;
}



void FUN_140005af0(longlong param_1,uint param_2)

{
  std::basic_stringstream<>::_scalar_deleting_destructor_
            ((basic_stringstream<> *)(param_1 - *(int *)(param_1 + -4)),param_2);
  return;
}



void __thiscall std::basic_streambuf<>::_Lock(basic_streambuf<> *this)

{
                    // WARNING: Could not recover jumptable at 0x000140005afc. Too many branches
                    // WARNING: Treating indirect jump as call
  _Lock(this);
  return;
}



void __thiscall std::basic_streambuf<>::_Unlock(basic_streambuf<> *this)

{
                    // WARNING: Could not recover jumptable at 0x000140005b02. Too many branches
                    // WARNING: Treating indirect jump as call
  _Unlock(this);
  return;
}



__int64 __thiscall std::basic_streambuf<>::showmanyc(basic_streambuf<> *this)

{
  __int64 _Var1;
  
                    // WARNING: Could not recover jumptable at 0x000140005b08. Too many branches
                    // WARNING: Treating indirect jump as call
  _Var1 = showmanyc(this);
  return _Var1;
}



ushort __thiscall std::basic_streambuf<>::uflow(basic_streambuf<> *this)

{
  ushort uVar1;
  
                    // WARNING: Could not recover jumptable at 0x000140005b0e. Too many branches
                    // WARNING: Treating indirect jump as call
  uVar1 = uflow(this);
  return uVar1;
}



__int64 __thiscall
std::basic_streambuf<>::xsgetn(basic_streambuf<> *this,wchar_t *param_1,__int64 param_2)

{
  __int64 _Var1;
  
                    // WARNING: Could not recover jumptable at 0x000140005b14. Too many branches
                    // WARNING: Treating indirect jump as call
  _Var1 = xsgetn(this,param_1,param_2);
  return _Var1;
}



__int64 __thiscall
std::basic_streambuf<>::xsputn(basic_streambuf<> *this,wchar_t *param_1,__int64 param_2)

{
  __int64 _Var1;
  
                    // WARNING: Could not recover jumptable at 0x000140005b1a. Too many branches
                    // WARNING: Treating indirect jump as call
  _Var1 = xsputn(this,param_1,param_2);
  return _Var1;
}



basic_streambuf<> * __thiscall
std::basic_streambuf<>::setbuf(basic_streambuf<> *this,wchar_t *param_1,__int64 param_2)

{
  basic_streambuf<> *pbVar1;
  
                    // WARNING: Could not recover jumptable at 0x000140005b20. Too many branches
                    // WARNING: Treating indirect jump as call
  pbVar1 = setbuf(this,param_1,param_2);
  return pbVar1;
}



int __thiscall std::basic_streambuf<>::sync(basic_streambuf<> *this)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x000140005b26. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = sync(this);
  return iVar1;
}



void __thiscall std::basic_streambuf<>::imbue(basic_streambuf<> *this,locale *param_1)

{
                    // WARNING: Could not recover jumptable at 0x000140005b2c. Too many branches
                    // WARNING: Treating indirect jump as call
  imbue(this,param_1);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_140005b50(longlong param_1)

{
  if ((param_1 == _FLOAT_14000d008) && ((short)((ulonglong)param_1 >> 0x30) == 0)) {
    return;
  }
  FUN_140005e90();
  return;
}



// Library Function - Single Match
//  void * __ptr64 __cdecl operator new(unsigned __int64)
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void * __cdecl operator_new(__uint64 param_1)

{
  code *pcVar1;
  int iVar2;
  void *pvVar3;
  
  do {
    pvVar3 = malloc(param_1);
    if (pvVar3 != (void *)0x0) {
      return pvVar3;
    }
    iVar2 = _callnewh(param_1);
  } while (iVar2 != 0);
  if (param_1 == 0xffffffffffffffff) {
    FUN_140006018();
    pcVar1 = (code *)swi(3);
    pvVar3 = (void *)(*pcVar1)();
    return pvVar3;
  }
  FUN_140005ff8();
  pcVar1 = (code *)swi(3);
  pvVar3 = (void *)(*pcVar1)();
  return pvVar3;
}



void __cdecl free(void *_Memory)

{
                    // WARNING: Could not recover jumptable at 0x00014000682a. Too many branches
                    // WARNING: Treating indirect jump as call
  free(_Memory);
  return;
}



void __cdecl free(void *_Memory)

{
                    // WARNING: Could not recover jumptable at 0x00014000682a. Too many branches
                    // WARNING: Treating indirect jump as call
  free(_Memory);
  return;
}



undefined8 * FUN_140005bbc(undefined8 *param_1,ulonglong param_2)

{
  *param_1 = type_info::vftable;
  if ((param_2 & 1) != 0) {
    free(param_1);
  }
  return param_1;
}



void FUN_140005be8(void)

{
  code *pcVar1;
  bool bVar2;
  char cVar3;
  int iVar4;
  undefined8 uVar5;
  undefined4 *puVar6;
  ulonglong uVar7;
  undefined7 extraout_var;
  
  _set_app_type(1);
  uVar5 = FUN_140006340();
  _set_fmode((int)uVar5);
  uVar5 = FUN_140006334();
  puVar6 = (undefined4 *)__p__commode();
  *puVar6 = (int)uVar5;
  uVar5 = __scrt_initialize_onexit_tables(1);
  if ((char)uVar5 != '\0') {
    FUN_1400065c4();
    atexit((_func_5014 *)&LAB_140006600);
    uVar7 = FUN_140006338();
    iVar4 = _configure_narrow_argv(uVar7 & 0xffffffff);
    if (iVar4 == 0) {
      FUN_140006348();
      bVar2 = FUN_14000638c();
      if ((int)CONCAT71(extraout_var,bVar2) != 0) {
        __setusermatherr(FUN_140006334);
      }
      _guard_check_icall();
      _guard_check_icall();
      uVar5 = FUN_140006334();
      _configthreadlocale((int)uVar5);
      cVar3 = FUN_140006358();
      if (cVar3 != '\0') {
        _initialize_narrow_environment();
      }
      FUN_140006334();
      uVar5 = thunk_FUN_140006334();
      if ((int)uVar5 == 0) {
        return;
      }
    }
  }
  FUN_1400063b0(7);
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



undefined8 FUN_140005ca0(void)

{
  FUN_140006370();
  return 0;
}



// WARNING: Function: _guard_dispatch_icall replaced with injection: guard_dispatch_icall

int FUN_140005ccc(void)

{
  bool bVar1;
  int iVar2;
  undefined8 uVar3;
  ulonglong uVar4;
  code **ppcVar5;
  longlong *plVar6;
  longlong **pplVar7;
  uint *puVar8;
  ulonglong uVar9;
  undefined8 unaff_RBX;
  undefined8 in_R9;
  undefined uVar10;
  
  iVar2 = (int)unaff_RBX;
  uVar3 = __scrt_initialize_crt(1);
  if ((char)uVar3 == '\0') {
    FUN_1400063b0(7);
  }
  else {
    bVar1 = false;
    uVar10 = 0;
    uVar4 = __scrt_acquire_startup_lock();
    iVar2 = (int)CONCAT71((int7)((ulonglong)unaff_RBX >> 8),(char)uVar4);
    if (DAT_14000d970 != 1) {
      if (DAT_14000d970 == 0) {
        DAT_14000d970 = 1;
        iVar2 = _initterm_e(&DAT_140009400,&DAT_140009418);
        if (iVar2 != 0) {
          return 0xff;
        }
        _initterm(&DAT_1400093e0,&DAT_1400093f8);
        DAT_14000d970 = 2;
      }
      else {
        bVar1 = true;
        uVar10 = 1;
      }
      __scrt_release_startup_lock((char)uVar4);
      ppcVar5 = (code **)FUN_140006398();
      if ((*ppcVar5 != (code *)0x0) &&
         (uVar4 = FUN_14000614c((longlong)ppcVar5), (char)uVar4 != '\0')) {
        (**ppcVar5)(0,2,0,in_R9,uVar10);
      }
      plVar6 = (longlong *)FUN_1400063a0();
      if ((*plVar6 != 0) && (uVar4 = FUN_14000614c((longlong)plVar6), (char)uVar4 != '\0')) {
        _register_thread_local_exe_atexit_callback(*plVar6);
      }
      _get_initial_narrow_environment();
      pplVar7 = (longlong **)__p___argv();
      plVar6 = *pplVar7;
      puVar8 = (uint *)__p___argc();
      uVar9 = (ulonglong)*puVar8;
      iVar2 = FUN_1400020d0(uVar9,plVar6);
      uVar4 = FUN_140006504();
      if ((char)uVar4 != '\0') {
        if (!bVar1) {
          _cexit();
        }
        __scrt_uninitialize_crt(CONCAT71((int7)(uVar9 >> 8),1),'\0');
        return iVar2;
      }
      goto LAB_140005e38;
    }
  }
  FUN_1400063b0(7);
LAB_140005e38:
                    // WARNING: Subroutine does not return
  exit(iVar2);
}



void entry(void)

{
  __security_init_cookie();
  FUN_140005ccc();
  return;
}



// Library Function - Single Match
//  __raise_securityfailure
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void __raise_securityfailure(_EXCEPTION_POINTERS *param_1)

{
  HANDLE pvVar1;
  
  SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)0x0);
  UnhandledExceptionFilter(param_1);
  pvVar1 = GetCurrentProcess();
                    // WARNING: Could not recover jumptable at 0x000140005e89. Too many branches
                    // WARNING: Treating indirect jump as call
  TerminateProcess(pvVar1,0xc0000409);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_140005e90(void)

{
  code *pcVar1;
  BOOL BVar2;
  undefined *puVar3;
  undefined auStack_38 [8];
  undefined auStack_30 [48];
  
  puVar3 = auStack_38;
  BVar2 = IsProcessorFeaturePresent(0x17);
  if (BVar2 != 0) {
    pcVar1 = (code *)swi(0x29);
    (*pcVar1)(2);
    puVar3 = auStack_30;
  }
  *(undefined8 *)(puVar3 + -8) = 0x140005ebb;
  capture_previous_context((PCONTEXT)&DAT_14000d4a0);
  _DAT_14000d410 = *(undefined8 *)(puVar3 + 0x38);
  _DAT_14000d538 = puVar3 + 0x40;
  _DAT_14000d520 = *(undefined8 *)(puVar3 + 0x40);
  _DAT_14000d400 = 0xc0000409;
  _DAT_14000d404 = 1;
  _DAT_14000d418 = 1;
  DAT_14000d420 = 2;
  *(undefined8 *)(puVar3 + 0x20) = _FLOAT_14000d008;
  *(undefined8 *)(puVar3 + 0x28) = DAT_14000d000;
  *(undefined8 *)(puVar3 + -8) = 0x140005f5d;
  DAT_14000d598 = _DAT_14000d410;
  __raise_securityfailure((_EXCEPTION_POINTERS *)&PTR_DAT_140009450);
  return;
}



// Library Function - Single Match
//  capture_previous_context
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void capture_previous_context(PCONTEXT param_1)

{
  DWORD64 ControlPc;
  PRUNTIME_FUNCTION FunctionEntry;
  int iVar1;
  DWORD64 local_res8;
  ulonglong local_res10;
  PVOID local_res18 [2];
  
  RtlCaptureContext();
  ControlPc = param_1->Rip;
  iVar1 = 0;
  do {
    FunctionEntry = RtlLookupFunctionEntry(ControlPc,&local_res8,(PUNWIND_HISTORY_TABLE)0x0);
    if (FunctionEntry == (PRUNTIME_FUNCTION)0x0) {
      return;
    }
    RtlVirtualUnwind(0,local_res8,ControlPc,FunctionEntry,param_1,local_res18,&local_res10,
                     (PKNONVOLATILE_CONTEXT_POINTERS)0x0);
    iVar1 = iVar1 + 1;
  } while (iVar1 < 2);
  return;
}



undefined8 * FUN_140005fd8(undefined8 *param_1)

{
  param_1[2] = 0;
  param_1[1] = "bad allocation";
  *param_1 = std::bad_alloc::vftable;
  return param_1;
}



void FUN_140005ff8(void)

{
  undefined8 local_28 [5];
  
  FUN_140005fd8(local_28);
                    // WARNING: Subroutine does not return
  _CxxThrowException(local_28,(ThrowInfo *)&DAT_14000a860);
}



void FUN_140006018(void)

{
  bad_array_new_length local_28 [40];
  
  std::bad_array_new_length::bad_array_new_length(local_28);
                    // WARNING: Subroutine does not return
  _CxxThrowException(local_28,(ThrowInfo *)&DAT_14000aab0);
}



// Library Function - Single Match
//  __scrt_acquire_startup_lock
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

ulonglong __scrt_acquire_startup_lock(void)

{
  bool bVar1;
  undefined7 extraout_var;
  ulonglong uVar3;
  void *pvVar2;
  
  bVar1 = __scrt_is_ucrt_dll_in_use();
  pvVar2 = (void *)CONCAT71(extraout_var,bVar1);
  if ((int)pvVar2 == 0) {
LAB_140006066:
    uVar3 = (ulonglong)pvVar2 & 0xffffffffffffff00;
  }
  else {
    do {
      LOCK();
      bVar1 = DAT_14000d978 == 0;
      DAT_14000d978 = DAT_14000d978 ^ (ulonglong)bVar1 * (DAT_14000d978 ^ (ulonglong)StackBase);
      pvVar2 = (void *)(!bVar1 * DAT_14000d978);
      UNLOCK();
      if (bVar1) goto LAB_140006066;
    } while (StackBase != pvVar2);
    uVar3 = CONCAT71((int7)((ulonglong)pvVar2 >> 8),1);
  }
  return uVar3;
}



// Library Function - Single Match
//  __scrt_initialize_crt
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

ulonglong __scrt_initialize_crt(int param_1)

{
  ulonglong uVar1;
  undefined8 uVar2;
  
  if (param_1 == 0) {
    DAT_14000d980 = 1;
  }
  FUN_14000663c();
  uVar1 = FUN_140006358();
  if ((char)uVar1 != '\0') {
    uVar2 = FUN_140006358();
    if ((char)uVar2 != '\0') {
      return CONCAT71((int7)((ulonglong)uVar2 >> 8),1);
    }
    uVar1 = FUN_140006358();
  }
  return uVar1 & 0xffffffffffffff00;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __scrt_initialize_onexit_tables
// 
// Library: Visual Studio 2019 Release

undefined8 __scrt_initialize_onexit_tables(uint param_1)

{
  code *pcVar1;
  bool bVar2;
  ulonglong in_RAX;
  undefined7 extraout_var;
  undefined8 uVar3;
  
  if (DAT_14000d981 == '\0') {
    if (1 < param_1) {
      FUN_1400063b0(5);
      pcVar1 = (code *)swi(3);
      uVar3 = (*pcVar1)();
      return uVar3;
    }
    bVar2 = __scrt_is_ucrt_dll_in_use();
    if (((int)CONCAT71(extraout_var,bVar2) == 0) || (param_1 != 0)) {
      in_RAX = 0xffffffffffffffff;
      _DAT_14000d988 = 0xffffffff;
      uRam000000014000d98c = 0xffffffff;
      uRam000000014000d990 = 0xffffffff;
      uRam000000014000d994 = 0xffffffff;
      _DAT_14000d998 = 0xffffffffffffffff;
      _DAT_14000d9a0 = 0xffffffff;
      uRam000000014000d9a4 = 0xffffffff;
      uRam000000014000d9a8 = 0xffffffff;
      uRam000000014000d9ac = 0xffffffff;
      _DAT_14000d9b0 = 0xffffffffffffffff;
    }
    else {
      in_RAX = _initialize_onexit_table(&DAT_14000d988);
      if (((int)in_RAX != 0) ||
         (in_RAX = _initialize_onexit_table(&DAT_14000d9a0), (int)in_RAX != 0)) {
        return in_RAX & 0xffffffffffffff00;
      }
    }
    DAT_14000d981 = '\x01';
  }
  return CONCAT71((int7)(in_RAX >> 8),1);
}



// WARNING: Removing unreachable block (ram,0x0001400061d9)

ulonglong FUN_14000614c(longlong param_1)

{
  ulonglong uVar1;
  uint7 uVar2;
  IMAGE_SECTION_HEADER *pIVar3;
  
  uVar1 = 0;
  for (pIVar3 = &IMAGE_SECTION_HEADER_140000208; pIVar3 != (IMAGE_SECTION_HEADER *)&DAT_1400002f8;
      pIVar3 = pIVar3 + 1) {
    if (((ulonglong)(uint)pIVar3->VirtualAddress <= param_1 - 0x140000000U) &&
       (uVar1 = (ulonglong)((pIVar3->Misc).PhysicalAddress + pIVar3->VirtualAddress),
       param_1 - 0x140000000U < uVar1)) goto LAB_1400061c2;
  }
  pIVar3 = (IMAGE_SECTION_HEADER *)0x0;
LAB_1400061c2:
  if (pIVar3 == (IMAGE_SECTION_HEADER *)0x0) {
    uVar1 = uVar1 & 0xffffffffffffff00;
  }
  else {
    uVar2 = (uint7)(uVar1 >> 8);
    if ((int)pIVar3->Characteristics < 0) {
      uVar1 = (ulonglong)uVar2 << 8;
    }
    else {
      uVar1 = CONCAT71(uVar2,1);
    }
  }
  return uVar1;
}



// Library Function - Single Match
//  __scrt_release_startup_lock
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void __scrt_release_startup_lock(char param_1)

{
  bool bVar1;
  undefined3 extraout_var;
  
  bVar1 = __scrt_is_ucrt_dll_in_use();
  if ((CONCAT31(extraout_var,bVar1) != 0) && (param_1 == '\0')) {
    LOCK();
    DAT_14000d978 = 0;
    UNLOCK();
  }
  return;
}



// Library Function - Single Match
//  __scrt_uninitialize_crt
// 
// Library: Visual Studio 2019 Release

undefined __scrt_uninitialize_crt(undefined8 param_1,char param_2)

{
  if ((DAT_14000d980 == '\0') || (param_2 == '\0')) {
    FUN_140006358();
    FUN_140006358();
  }
  return 1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  _onexit
// 
// Library: Visual Studio 2019 Release

_onexit_t __cdecl _onexit(_onexit_t _Func)

{
  int iVar1;
  _onexit_t p_Var2;
  
  if (_DAT_14000d988 == -1) {
    iVar1 = _crt_atexit();
  }
  else {
    iVar1 = _register_onexit_function(&DAT_14000d988);
  }
  p_Var2 = (_onexit_t)0x0;
  if (iVar1 == 0) {
    p_Var2 = _Func;
  }
  return p_Var2;
}



// Library Function - Single Match
//  atexit
// 
// Library: Visual Studio 2019 Release

int __cdecl atexit(_func_5014 *param_1)

{
  _onexit_t p_Var1;
  
  p_Var1 = _onexit((_onexit_t)param_1);
  return (p_Var1 != (_onexit_t)0x0) - 1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __security_init_cookie
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void __cdecl __security_init_cookie(void)

{
  DWORD DVar1;
  _FILETIME local_res8;
  _FILETIME local_res10;
  LARGE_INTEGER local_res18;
  
  if (_FLOAT_14000d008 == 0x2b992ddfa232) {
    local_res10.dwLowDateTime = 0;
    local_res10.dwHighDateTime = 0;
    GetSystemTimeAsFileTime(&local_res10);
    local_res8 = local_res10;
    DVar1 = GetCurrentThreadId();
    local_res8 = (_FILETIME)((ulonglong)local_res8 ^ (ulonglong)DVar1);
    DVar1 = GetCurrentProcessId();
    local_res8 = (_FILETIME)((ulonglong)local_res8 ^ (ulonglong)DVar1);
    QueryPerformanceCounter(&local_res18);
    _FLOAT_14000d008 =
         ((ulonglong)local_res18.s.LowPart << 0x20 ^
          CONCAT44(local_res18.s.HighPart,local_res18.s.LowPart) ^ (ulonglong)local_res8 ^
         (ulonglong)&local_res8) & 0xffffffffffff;
    if (_FLOAT_14000d008 == 0x2b992ddfa232) {
      _FLOAT_14000d008 = 0x2b992ddfa233;
    }
  }
  DAT_14000d000 = ~_FLOAT_14000d008;
  return;
}



undefined8 FUN_140006334(void)

{
  return 0;
}



undefined8 FUN_140006338(void)

{
  return 1;
}



undefined8 FUN_140006340(void)

{
  return 0x4000;
}



void FUN_140006348(void)

{
                    // WARNING: Could not recover jumptable at 0x00014000634f. Too many branches
                    // WARNING: Treating indirect jump as call
  InitializeSListHead(&DAT_14000d9c0);
  return;
}



undefined FUN_140006358(void)

{
  return 1;
}



void _guard_check_icall(void)

{
  return;
}



undefined * FUN_140006360(void)

{
  return &DAT_14000d9d0;
}



undefined * FUN_140006368(void)

{
  return &DAT_14000d9d8;
}



void FUN_140006370(void)

{
  ulonglong *puVar1;
  
  puVar1 = (ulonglong *)FUN_140006360();
  *puVar1 = *puVar1 | 0x24;
  puVar1 = (ulonglong *)FUN_140006368();
  *puVar1 = *puVar1 | 2;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

bool FUN_14000638c(void)

{
  return _DAT_14000d014 == 0;
}



undefined * FUN_140006398(void)

{
  return &DAT_14000da08;
}



undefined * FUN_1400063a0(void)

{
  return &DAT_14000da00;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_1400063a8(void)

{
  _DAT_14000d9e0 = 0;
  return;
}



void FUN_1400063b0(undefined4 param_1)

{
  code *pcVar1;
  BOOL BVar2;
  LONG LVar3;
  PRUNTIME_FUNCTION FunctionEntry;
  undefined *puVar4;
  undefined8 unaff_retaddr;
  DWORD64 local_res10;
  undefined local_res18 [8];
  undefined local_res20 [8];
  undefined auStack_5c8 [8];
  undefined auStack_5c0 [232];
  undefined local_4d8 [152];
  undefined *local_440;
  DWORD64 local_3e0;
  
  puVar4 = auStack_5c8;
  BVar2 = IsProcessorFeaturePresent(0x17);
  if (BVar2 != 0) {
    pcVar1 = (code *)swi(0x29);
    (*pcVar1)(param_1);
    puVar4 = auStack_5c0;
  }
  *(undefined8 *)(puVar4 + -8) = 0x1400063e4;
  FUN_1400063a8();
  *(undefined8 *)(puVar4 + -8) = 0x1400063f5;
  memset(local_4d8,0,0x4d0);
  *(undefined8 *)(puVar4 + -8) = 0x1400063ff;
  RtlCaptureContext(local_4d8);
  *(undefined8 *)(puVar4 + -8) = 0x140006419;
  FunctionEntry = RtlLookupFunctionEntry(local_3e0,&local_res10,(PUNWIND_HISTORY_TABLE)0x0);
  if (FunctionEntry != (PRUNTIME_FUNCTION)0x0) {
    *(undefined8 *)(puVar4 + 0x38) = 0;
    *(undefined **)(puVar4 + 0x30) = local_res18;
    *(undefined **)(puVar4 + 0x28) = local_res20;
    *(undefined **)(puVar4 + 0x20) = local_4d8;
    *(undefined8 *)(puVar4 + -8) = 0x14000645a;
    RtlVirtualUnwind(0,local_res10,local_3e0,FunctionEntry,*(PCONTEXT *)(puVar4 + 0x20),
                     *(PVOID **)(puVar4 + 0x28),*(PDWORD64 *)(puVar4 + 0x30),
                     *(PKNONVOLATILE_CONTEXT_POINTERS *)(puVar4 + 0x38));
  }
  local_440 = &stack0x00000008;
  *(undefined8 *)(puVar4 + -8) = 0x14000648c;
  memset(puVar4 + 0x50,0,0x98);
  *(undefined8 *)(puVar4 + 0x60) = unaff_retaddr;
  *(undefined4 *)(puVar4 + 0x50) = 0x40000015;
  *(undefined4 *)(puVar4 + 0x54) = 1;
  *(undefined8 *)(puVar4 + -8) = 0x1400064ae;
  BVar2 = IsDebuggerPresent();
  *(undefined **)(puVar4 + 0x40) = puVar4 + 0x50;
  *(undefined **)(puVar4 + 0x48) = local_4d8;
  *(undefined8 *)(puVar4 + -8) = 0x1400064cf;
  SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)0x0);
  *(undefined8 *)(puVar4 + -8) = 0x1400064da;
  LVar3 = UnhandledExceptionFilter((_EXCEPTION_POINTERS *)(puVar4 + 0x40));
  if ((LVar3 == 0) && (BVar2 != 1)) {
    *(undefined8 *)(puVar4 + -8) = 0x1400064ea;
    FUN_1400063a8();
  }
  return;
}



undefined8 thunk_FUN_140006334(void)

{
  return 0;
}



ulonglong FUN_140006504(void)

{
  HMODULE pHVar1;
  ulonglong uVar2;
  int *piVar3;
  
  pHVar1 = GetModuleHandleW((LPCWSTR)0x0);
  if ((((pHVar1 == (HMODULE)0x0) || (*(short *)&pHVar1->unused != 0x5a4d)) ||
      (piVar3 = (int *)((longlong)&pHVar1->unused + (longlong)pHVar1[0xf].unused), *piVar3 != 0x4550
      )) || ((pHVar1 = (HMODULE)0x20b, *(short *)(piVar3 + 6) != 0x20b || ((uint)piVar3[0x21] < 0xf)
             ))) {
    uVar2 = (ulonglong)pHVar1 & 0xffffffffffffff00;
  }
  else {
    uVar2 = CONCAT71(2,piVar3[0x3e] != 0);
  }
  return uVar2;
}



void FUN_140006558(void)

{
                    // WARNING: Could not recover jumptable at 0x00014000655f. Too many branches
                    // WARNING: Treating indirect jump as call
  SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)&LAB_140006568);
  return;
}



// WARNING: Function: _guard_dispatch_icall replaced with injection: guard_dispatch_icall

void FUN_1400065c4(void)

{
  code **ppcVar1;
  
  for (ppcVar1 = (code **)&DAT_14000a218; ppcVar1 < &DAT_14000a218; ppcVar1 = ppcVar1 + 1) {
    if (*ppcVar1 != (code *)0x0) {
      (**ppcVar1)();
    }
  }
  return;
}



// WARNING: Removing unreachable block (ram,0x000140006706)
// WARNING: Removing unreachable block (ram,0x000140006676)
// WARNING: Removing unreachable block (ram,0x00014000664f)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined8 FUN_14000663c(void)

{
  int *piVar1;
  uint *puVar2;
  longlong lVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  byte in_XCR0;
  
  piVar1 = (int *)cpuid_basic_info(0);
  uVar6 = 0;
  puVar2 = (uint *)cpuid_Version_info(1);
  uVar4 = puVar2[3];
  if ((piVar1[2] ^ 0x49656e69U | piVar1[3] ^ 0x6c65746eU | piVar1[1] ^ 0x756e6547U) == 0) {
    _DAT_14000d028 = 0xffffffffffffffff;
    uVar5 = *puVar2 & 0xfff3ff0;
    _DAT_14000d020 = 0x8000;
    if ((((uVar5 == 0x106c0) || (uVar5 == 0x20660)) || (uVar5 == 0x20670)) ||
       ((uVar5 - 0x30650 < 0x21 &&
        ((0x100010001U >> ((ulonglong)(uVar5 - 0x30650) & 0x3f) & 1) != 0)))) {
      DAT_14000d9e4 = DAT_14000d9e4 | 1;
    }
  }
  if (6 < *piVar1) {
    lVar3 = cpuid_Extended_Feature_Enumeration_info(7);
    uVar6 = *(uint *)(lVar3 + 4);
    if ((uVar6 >> 9 & 1) != 0) {
      DAT_14000d9e4 = DAT_14000d9e4 | 2;
    }
  }
  _DAT_14000d018 = 1;
  DAT_14000d01c = 2;
  if ((uVar4 >> 0x14 & 1) != 0) {
    _DAT_14000d018 = 2;
    DAT_14000d01c = 6;
    if ((((uVar4 >> 0x1b & 1) != 0) && ((uVar4 >> 0x1c & 1) != 0)) && ((in_XCR0 & 6) == 6)) {
      DAT_14000d01c = 0xe;
      _DAT_14000d018 = 3;
      if ((uVar6 & 0x20) != 0) {
        _DAT_14000d018 = 5;
        DAT_14000d01c = 0x2e;
        if (((uVar6 & 0xd0030000) == 0xd0030000) && ((in_XCR0 & 0xe0) == 0xe0)) {
          DAT_14000d01c = 0x6e;
          _DAT_14000d018 = 6;
        }
      }
    }
  }
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __scrt_is_ucrt_dll_in_use
// 
// Library: Visual Studio 2019 Release

bool __scrt_is_ucrt_dll_in_use(void)

{
  return _DAT_14000d030 != 0;
}



void __CxxFrameHandler4(void)

{
                    // WARNING: Could not recover jumptable at 0x000140006800. Too many branches
                    // WARNING: Treating indirect jump as call
  __CxxFrameHandler4();
  return;
}



void __stdcall _CxxThrowException(void *pExceptionObject,ThrowInfo *pThrowInfo)

{
                    // WARNING: Could not recover jumptable at 0x00014000680c. Too many branches
                    // WARNING: Subroutine does not return
                    // WARNING: Treating indirect jump as call
  _CxxThrowException(pExceptionObject,pThrowInfo);
  return;
}



void __current_exception(void)

{
                    // WARNING: Could not recover jumptable at 0x000140006812. Too many branches
                    // WARNING: Treating indirect jump as call
  __current_exception();
  return;
}



void __current_exception_context(void)

{
                    // WARNING: Could not recover jumptable at 0x000140006818. Too many branches
                    // WARNING: Treating indirect jump as call
  __current_exception_context();
  return;
}



void * __cdecl memset(void *_Dst,int _Val,size_t _Size)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x00014000681e. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = memset(_Dst,_Val,_Size);
  return pvVar1;
}



void __cdecl exit(int _Code)

{
                    // WARNING: Could not recover jumptable at 0x000140006824. Too many branches
                    // WARNING: Subroutine does not return
                    // WARNING: Treating indirect jump as call
  exit(_Code);
  return;
}



void __cdecl free(void *_Memory)

{
                    // WARNING: Could not recover jumptable at 0x00014000682a. Too many branches
                    // WARNING: Treating indirect jump as call
  free(_Memory);
  return;
}



int __cdecl _callnewh(size_t _Size)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x000140006830. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = _callnewh(_Size);
  return iVar1;
}



void * __cdecl malloc(size_t _Size)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x000140006836. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = malloc(_Size);
  return pvVar1;
}



void _seh_filter_exe(void)

{
                    // WARNING: Could not recover jumptable at 0x00014000683c. Too many branches
                    // WARNING: Treating indirect jump as call
  _seh_filter_exe();
  return;
}



void _set_app_type(void)

{
                    // WARNING: Could not recover jumptable at 0x000140006842. Too many branches
                    // WARNING: Treating indirect jump as call
  _set_app_type();
  return;
}



void __setusermatherr(void)

{
                    // WARNING: Could not recover jumptable at 0x000140006848. Too many branches
                    // WARNING: Treating indirect jump as call
  __setusermatherr();
  return;
}



void _configure_narrow_argv(void)

{
                    // WARNING: Could not recover jumptable at 0x00014000684e. Too many branches
                    // WARNING: Treating indirect jump as call
  _configure_narrow_argv();
  return;
}



void _initialize_narrow_environment(void)

{
                    // WARNING: Could not recover jumptable at 0x000140006854. Too many branches
                    // WARNING: Treating indirect jump as call
  _initialize_narrow_environment();
  return;
}



void _get_initial_narrow_environment(void)

{
                    // WARNING: Could not recover jumptable at 0x00014000685a. Too many branches
                    // WARNING: Treating indirect jump as call
  _get_initial_narrow_environment();
  return;
}



void _initterm(void)

{
                    // WARNING: Could not recover jumptable at 0x000140006860. Too many branches
                    // WARNING: Treating indirect jump as call
  _initterm();
  return;
}



void _initterm_e(void)

{
                    // WARNING: Could not recover jumptable at 0x000140006866. Too many branches
                    // WARNING: Treating indirect jump as call
  _initterm_e();
  return;
}



void __cdecl _exit(int _Code)

{
                    // WARNING: Could not recover jumptable at 0x00014000686c. Too many branches
                    // WARNING: Subroutine does not return
                    // WARNING: Treating indirect jump as call
  _exit(_Code);
  return;
}



errno_t __cdecl _set_fmode(int _Mode)

{
  errno_t eVar1;
  
                    // WARNING: Could not recover jumptable at 0x000140006872. Too many branches
                    // WARNING: Treating indirect jump as call
  eVar1 = _set_fmode(_Mode);
  return eVar1;
}



void __p___argc(void)

{
                    // WARNING: Could not recover jumptable at 0x000140006878. Too many branches
                    // WARNING: Treating indirect jump as call
  __p___argc();
  return;
}



void __p___argv(void)

{
                    // WARNING: Could not recover jumptable at 0x00014000687e. Too many branches
                    // WARNING: Treating indirect jump as call
  __p___argv();
  return;
}



void __cdecl _cexit(void)

{
                    // WARNING: Could not recover jumptable at 0x000140006884. Too many branches
                    // WARNING: Treating indirect jump as call
  _cexit();
  return;
}



void _register_thread_local_exe_atexit_callback(void)

{
                    // WARNING: Could not recover jumptable at 0x000140006890. Too many branches
                    // WARNING: Treating indirect jump as call
  _register_thread_local_exe_atexit_callback();
  return;
}



int __cdecl _configthreadlocale(int _Flag)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x000140006896. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = _configthreadlocale(_Flag);
  return iVar1;
}



void __p__commode(void)

{
                    // WARNING: Could not recover jumptable at 0x0001400068a2. Too many branches
                    // WARNING: Treating indirect jump as call
  __p__commode();
  return;
}



void _initialize_onexit_table(void)

{
                    // WARNING: Could not recover jumptable at 0x0001400068a8. Too many branches
                    // WARNING: Treating indirect jump as call
  _initialize_onexit_table();
  return;
}



void _register_onexit_function(void)

{
                    // WARNING: Could not recover jumptable at 0x0001400068ae. Too many branches
                    // WARNING: Treating indirect jump as call
  _register_onexit_function();
  return;
}



void _crt_atexit(void)

{
                    // WARNING: Could not recover jumptable at 0x0001400068b4. Too many branches
                    // WARNING: Treating indirect jump as call
  _crt_atexit();
  return;
}



void terminate(void)

{
                    // WARNING: Could not recover jumptable at 0x0001400068ba. Too many branches
                    // WARNING: Subroutine does not return
                    // WARNING: Treating indirect jump as call
  terminate();
  return;
}



void FUN_140006900(int *param_1,undefined **param_2,undefined8 *param_3,undefined8 param_4)

{
  char cVar1;
  undefined8 *puVar2;
  int local_68;
  undefined8 local_30;
  undefined8 local_28 [5];
  
  param_2[1] = &LAB_1400068c0;
  *param_2 = FUN_140006a70;
  FUN_140001dd0((undefined8 *)((longlong)param_2 + 0x12),param_4);
  if (*param_1 == 0) {
    local_68 = 0x10000;
  }
  else {
    local_68 = 0;
  }
  *(int *)((longlong)param_2 + 0x1c) = local_68 + 2;
  FUN_140001cc0(param_2 + 2,param_3);
  boost::integral_constant<bool,1>::operator_struct_boost__mpl__bool_<1>
            ((integral_constant<bool,1> *)(param_2 + 2));
  cVar1 = FUN_140001720();
  if (cVar1 == '\0') {
    puVar2 = (undefined8 *)FUN_1400016a0(&local_30,param_2);
    FUN_1400050b0(puVar2,local_28);
    FUN_140001640();
  }
  else {
    FUN_140006a70(param_2);
  }
  return;
}



// WARNING: Removing unreachable block (ram,0x00014000799f)

void FUN_140006a70(undefined8 *param_1)

{
  code *pcVar1;
  bool_<1> bVar2;
  char cVar3;
  undefined7 extraout_var;
  undefined8 *puVar4;
  undefined in_DL;
  undefined in_R8B;
  undefined in_R9B;
  undefined in_stack_fffffffffffffc00;
  undefined in_stack_fffffffffffffc08;
  undefined in_stack_fffffffffffffc10;
  undefined in_stack_fffffffffffffc18;
  undefined in_stack_fffffffffffffc20;
  undefined in_stack_fffffffffffffc28;
  undefined8 local_308 [15];
  undefined8 *local_290;
  undefined8 *local_288;
  undefined8 local_280 [15];
  undefined8 *local_208;
  undefined8 *local_200;
  undefined8 local_1f8 [15];
  undefined8 *local_180;
  undefined8 *local_178;
  undefined8 local_170 [15];
  undefined8 *local_f8;
  undefined8 *local_f0;
  undefined8 *local_e0;
  undefined8 *local_d8;
  undefined8 *local_d0;
  undefined8 local_c8;
  undefined8 *local_c0;
  undefined8 *local_b8;
  undefined8 *local_b0;
  undefined8 *local_a8;
  undefined8 *local_a0;
  undefined8 *local_98;
  undefined8 local_90;
  undefined2 *local_88;
  undefined8 *local_80;
  undefined8 *local_78;
  undefined8 local_70;
  undefined8 *local_60;
  undefined8 in_stack_ffffffffffffffa8;
  undefined8 in_stack_ffffffffffffffb0;
  undefined8 in_stack_ffffffffffffffb8;
  undefined8 in_stack_ffffffffffffffc0;
  undefined8 in_stack_ffffffffffffffc8;
  undefined8 in_stack_ffffffffffffffd0;
  undefined8 in_stack_ffffffffffffffd8;
  undefined8 in_stack_ffffffffffffffe0;
  undefined8 in_stack_ffffffffffffffe8;
  undefined8 in_stack_fffffffffffffff0;
  
  switch(*(undefined2 *)((longlong)param_1 + 0x1c)) {
  default:
    pcVar1 = (code *)swi(3);
    (*pcVar1)();
    return;
  case 1:
    switchD_140006adb::caseD_ffff
              (0,in_DL,in_R8B,in_R9B,in_stack_fffffffffffffc00,in_stack_fffffffffffffc08,
               in_stack_fffffffffffffc10,in_stack_fffffffffffffc18,in_stack_fffffffffffffc20,
               in_stack_fffffffffffffc28,in_stack_ffffffffffffffa8,in_stack_ffffffffffffffb0,
               in_stack_ffffffffffffffb8,in_stack_ffffffffffffffc0,in_stack_ffffffffffffffc8,
               in_stack_ffffffffffffffd0,in_stack_ffffffffffffffd8,in_stack_ffffffffffffffe0,
               in_stack_ffffffffffffffe8,in_stack_fffffffffffffff0,param_1);
    return;
  case 2:
    FUN_140001630();
                    // WARNING: Subroutine does not return
    exit(1);
  case 3:
    switchD_140006adb::caseD_ffff
              (0,in_DL,in_R8B,in_R9B,in_stack_fffffffffffffc00,in_stack_fffffffffffffc08,
               in_stack_fffffffffffffc10,in_stack_fffffffffffffc18,in_stack_fffffffffffffc20,
               in_stack_fffffffffffffc28,in_stack_ffffffffffffffa8,in_stack_ffffffffffffffb0,
               in_stack_ffffffffffffffb8,in_stack_ffffffffffffffc0,in_stack_ffffffffffffffc8,
               in_stack_ffffffffffffffd0,in_stack_ffffffffffffffd8,in_stack_ffffffffffffffe0,
               in_stack_ffffffffffffffe8,in_stack_fffffffffffffff0,param_1);
    return;
  case 4:
    *(undefined4 *)(param_1 + 0x1e) = 0;
    FUN_140001630();
    local_308[0] = *(undefined8 *)((longlong)param_1 + 0x12);
                    // WARNING: Subroutine does not return
    _CxxThrowException(local_308,(ThrowInfo *)&DAT_14000a930);
  case 5:
    switchD_140006adb::caseD_ffff
              (0,in_DL,in_R8B,in_R9B,in_stack_fffffffffffffc00,in_stack_fffffffffffffc08,
               in_stack_fffffffffffffc10,in_stack_fffffffffffffc18,in_stack_fffffffffffffc20,
               in_stack_fffffffffffffc28,in_stack_ffffffffffffffa8,in_stack_ffffffffffffffb0,
               in_stack_ffffffffffffffb8,in_stack_ffffffffffffffc0,in_stack_ffffffffffffffc8,
               in_stack_ffffffffffffffd0,in_stack_ffffffffffffffd8,in_stack_ffffffffffffffe0,
               in_stack_ffffffffffffffe8,in_stack_fffffffffffffff0,param_1);
    return;
  case 6:
    local_290 = param_1 + 0x20;
    *(undefined4 *)local_290 = 0;
    local_288 = param_1 + 9;
    FUN_140001630();
    local_280[0] = *(undefined8 *)((longlong)param_1 + 0x12);
                    // WARNING: Subroutine does not return
    _CxxThrowException(local_280,(ThrowInfo *)&DAT_14000aa68);
  case 7:
    switchD_140006adb::caseD_ffff
              (0,in_DL,in_R8B,in_R9B,in_stack_fffffffffffffc00,in_stack_fffffffffffffc08,
               in_stack_fffffffffffffc10,in_stack_fffffffffffffc18,in_stack_fffffffffffffc20,
               in_stack_fffffffffffffc28,in_stack_ffffffffffffffa8,in_stack_ffffffffffffffb0,
               in_stack_ffffffffffffffb8,in_stack_ffffffffffffffc0,in_stack_ffffffffffffffc8,
               in_stack_ffffffffffffffd0,in_stack_ffffffffffffffd8,in_stack_ffffffffffffffe0,
               in_stack_ffffffffffffffe8,in_stack_fffffffffffffff0,param_1);
    return;
  case 8:
    local_208 = param_1 + 0x22;
    *(undefined4 *)local_208 = 0;
    local_200 = param_1 + 0xe;
    FUN_140001630();
    local_1f8[0] = *(undefined8 *)((longlong)param_1 + 0x12);
                    // WARNING: Subroutine does not return
    _CxxThrowException(local_1f8,(ThrowInfo *)&DAT_14000a8e8);
  case 9:
    switchD_140006adb::caseD_ffff
              (0,in_DL,in_R8B,in_R9B,in_stack_fffffffffffffc00,in_stack_fffffffffffffc08,
               in_stack_fffffffffffffc10,in_stack_fffffffffffffc18,in_stack_fffffffffffffc20,
               in_stack_fffffffffffffc28,in_stack_ffffffffffffffa8,in_stack_ffffffffffffffb0,
               in_stack_ffffffffffffffb8,in_stack_ffffffffffffffc0,in_stack_ffffffffffffffc8,
               in_stack_ffffffffffffffd0,in_stack_ffffffffffffffd8,in_stack_ffffffffffffffe0,
               in_stack_ffffffffffffffe8,in_stack_fffffffffffffff0,param_1);
    return;
  case 10:
    local_180 = param_1 + 0x24;
    *(undefined4 *)local_180 = 0;
    local_178 = param_1 + 0x13;
    FUN_140001630();
    local_170[0] = *(undefined8 *)((longlong)param_1 + 0x12);
                    // WARNING: Subroutine does not return
    _CxxThrowException(local_170,(ThrowInfo *)&DAT_14000aad0);
  case 0xb:
    switchD_140006adb::caseD_ffff
              (0,in_DL,in_R8B,in_R9B,in_stack_fffffffffffffc00,in_stack_fffffffffffffc08,
               in_stack_fffffffffffffc10,in_stack_fffffffffffffc18,in_stack_fffffffffffffc20,
               in_stack_fffffffffffffc28,in_stack_ffffffffffffffa8,in_stack_ffffffffffffffb0,
               in_stack_ffffffffffffffb8,in_stack_ffffffffffffffc0,in_stack_ffffffffffffffc8,
               in_stack_ffffffffffffffd0,in_stack_ffffffffffffffd8,in_stack_ffffffffffffffe0,
               in_stack_ffffffffffffffe8,in_stack_fffffffffffffff0,param_1);
    return;
  case 0xc:
    local_f8 = param_1 + 0x26;
    *(undefined4 *)local_f8 = 0;
    local_f0 = param_1 + 0x18;
    FUN_140001630();
    FUN_140001630();
    local_d8 = param_1 + 2;
    local_e0 = param_1 + 0x28;
    bVar2 = boost::integral_constant<bool,1>::operator_struct_boost__mpl__bool_<1>
                      ((integral_constant<bool,1> *)local_d8);
    local_c8 = CONCAT71(extraout_var,bVar2);
    local_d0 = param_1 + 0x1d;
    *local_d0 = local_c8;
    local_c0 = param_1 + 0x1d;
    cVar3 = FUN_140001720();
    if (cVar3 == '\0') {
      local_b0 = param_1 + 0x29;
      local_a0 = (undefined8 *)FUN_1400016a0(local_b0,param_1);
      local_a8 = param_1 + 0x2a;
      puVar4 = FUN_1400050b0(local_a0,local_a8);
      local_98 = param_1 + 0x2b;
      local_90 = *puVar4;
      *local_98 = local_90;
      local_88 = (undefined2 *)((longlong)param_1 + 0x1c);
      *local_88 = 0;
      *param_1 = 0;
      local_80 = param_1 + 0x2b;
      local_70 = *local_80;
      local_78 = param_1 + 0x1d;
      FUN_140001640();
      FUN_140007a86();
      return;
    }
    local_b8 = param_1 + 0x2c;
    *(undefined4 *)local_b8 = 0;
    local_60 = param_1 + 0x1d;
    FUN_140001630();
code_r0x00014000794b:
    if (*(short *)((longlong)param_1 + 10) != 0) {
      param_1[0x30] = 400;
      param_1[0x2e] = param_1;
      free((void *)param_1[0x2e]);
    }
    FUN_140007a86();
    return;
  case 0xd:
    switchD_140006adb::caseD_ffff
              (0,in_DL,in_R8B,in_R9B,in_stack_fffffffffffffc00,in_stack_fffffffffffffc08,
               in_stack_fffffffffffffc10,in_stack_fffffffffffffc18,in_stack_fffffffffffffc20,
               in_stack_fffffffffffffc28,in_stack_ffffffffffffffa8,in_stack_ffffffffffffffb0,
               in_stack_ffffffffffffffb8,in_stack_ffffffffffffffc0,in_stack_ffffffffffffffc8,
               in_stack_ffffffffffffffd0,in_stack_ffffffffffffffd8,in_stack_ffffffffffffffe0,
               in_stack_ffffffffffffffe8,in_stack_fffffffffffffff0,param_1);
    return;
  case 0xffff:
    goto code_r0x00014000794b;
  }
}



// WARNING: Removing unreachable block (ram,0x00014000799f)

void switchD_140006adb::caseD_ffff
               (undefined param_1,undefined param_2,undefined param_3,undefined param_4,
               undefined param_5,undefined param_6,undefined param_7,undefined param_8,
               undefined param_9,undefined param_10,undefined8 param_11,undefined8 param_12,
               undefined8 param_13,undefined8 param_14,undefined8 param_15,undefined8 param_16,
               undefined8 param_17,undefined8 param_18,undefined8 param_19,undefined8 param_20,
               longlong param_21)

{
  if (*(short *)(param_21 + 10) != 0) {
    *(undefined8 *)(param_21 + 0x180) = 400;
    *(longlong *)(param_21 + 0x170) = param_21;
    free(*(void **)(param_21 + 0x170));
  }
  FUN_140007a86();
  return;
}



void FUN_140007a86(void)

{
  return;
}



// Library Function - Single Match
//  __GSHandlerCheckCommon
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void __GSHandlerCheckCommon(ulonglong param_1,longlong param_2,uint *param_3)

{
  ulonglong uVar1;
  ulonglong uVar2;
  
  uVar2 = param_1;
  if ((*(byte *)param_3 & 4) != 0) {
    uVar2 = (longlong)(int)param_3[1] + param_1 & (longlong)(int)-param_3[2];
  }
  uVar1 = (ulonglong)*(uint *)(*(longlong *)(param_2 + 0x10) + 8);
  if ((*(byte *)(uVar1 + 3 + *(longlong *)(param_2 + 8)) & 0xf) != 0) {
    param_1 = param_1 + (*(byte *)(uVar1 + 3 + *(longlong *)(param_2 + 8)) & 0xfffffff0);
  }
  FUN_140005b50(param_1 ^ *(ulonglong *)((longlong)(int)(*param_3 & 0xfffffff8) + uVar2));
  return;
}



void * __cdecl memmove(void *_Dst,void *_Src,size_t _Size)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x000140007bc7. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = memmove(_Dst,_Src,_Size);
  return pvVar1;
}



// WARNING: This is an inlined function

void _guard_dispatch_icall(void)

{
  code *UNRECOVERED_JUMPTABLE;
  
                    // WARNING: Could not recover jumptable at 0x000140007bf0. Too many branches
                    // WARNING: Treating indirect jump as call
  (*UNRECOVERED_JUMPTABLE)();
  return;
}



void FUN_140007c20(undefined8 param_1,longlong param_2)

{
  FUN_140001380(*(void **)(param_2 + 0x30));
  return;
}



undefined8 FUN_140007c40(undefined8 param_1,longlong param_2)

{
  undefined uVar1;
  
  *(undefined4 *)(param_2 + 0x20) = 0;
  while (*(int *)(param_2 + 0x20) < 0x10) {
    uVar1 = FUN_1400018b0(*(undefined8 *)(param_2 + 0xb0),
                          (ushort)*(byte *)(*(longlong *)(param_2 + 0x30) +
                                           (longlong)*(int *)(param_2 + 0x20)),0x11b);
    *(undefined *)(*(longlong *)(param_2 + 0x30) + (longlong)*(int *)(param_2 + 0x20)) = uVar1;
    *(byte *)(*(longlong *)(param_2 + 0x30) + (longlong)*(int *)(param_2 + 0x20)) =
         *(byte *)(*(longlong *)(param_2 + 0x30) + (longlong)*(int *)(param_2 + 0x20)) ^
         *(char *)(*(longlong *)(param_2 + 0x30) + (longlong)*(int *)(param_2 + 0x20)) << 2;
    *(byte *)(*(longlong *)(param_2 + 0x30) + (longlong)*(int *)(param_2 + 0x20)) =
         *(byte *)(*(longlong *)(param_2 + 0x30) + (longlong)*(int *)(param_2 + 0x20)) ^
         *(char *)(*(longlong *)(param_2 + 0x30) + (longlong)*(int *)(param_2 + 0x20)) << 2;
    *(byte *)(*(longlong *)(param_2 + 0x30) + (longlong)*(int *)(param_2 + 0x20)) =
         *(byte *)(*(longlong *)(param_2 + 0x30) + (longlong)*(int *)(param_2 + 0x20)) ^
         (byte)((int)(uint)*(byte *)(*(longlong *)(param_2 + 0x30) +
                                    (longlong)*(int *)(param_2 + 0x20)) >> 2);
    *(byte *)(*(longlong *)(param_2 + 0x30) + (longlong)*(int *)(param_2 + 0x20)) =
         *(byte *)(*(longlong *)(param_2 + 0x30) + (longlong)*(int *)(param_2 + 0x20)) ^
         (byte)((int)(uint)*(byte *)(*(longlong *)(param_2 + 0x30) +
                                    (longlong)*(int *)(param_2 + 0x20)) >> 1);
    *(byte *)(*(longlong *)(param_2 + 0x30) + (longlong)*(int *)(param_2 + 0x20)) =
         *(byte *)(*(longlong *)(param_2 + 0x30) + (longlong)*(int *)(param_2 + 0x20)) ^ 99;
    *(int *)(param_2 + 0x20) = *(int *)(param_2 + 0x20) + 1;
  }
  return 0x140001d90;
}



void FUN_140007fe0(undefined8 param_1,longlong param_2)

{
  FUN_140001df0((longlong *)(param_2 + 0x30));
  return;
}



void FUN_140008000(undefined8 param_1,longlong param_2)

{
  FUN_1400024a0(param_2 + 0x120);
  return;
}



void FUN_140008040(undefined8 param_1,longlong param_2)

{
  if ((*(uint *)(param_2 + 0x20) & 1) != 0) {
    *(uint *)(param_2 + 0x20) = *(uint *)(param_2 + 0x20) & 0xfffffffe;
    std::basic_ios<>::~basic_ios<>((basic_ios<> *)(*(longlong *)(param_2 + 0x40) + 0x98));
  }
  return;
}



void FUN_140008090(undefined8 param_1,longlong param_2)

{
  FUN_140003c80(*(longlong ***)(param_2 + 0x40));
  return;
}



void FUN_1400080b0(undefined8 param_1,longlong param_2)

{
  ~basic_string<>((void **)(param_2 + 0x40));
  return;
}



void FUN_1400080d0(undefined8 param_1,longlong param_2)

{
  std::basic_streambuf<>::~basic_streambuf<>(*(basic_streambuf<> **)(param_2 + 0x30));
  return;
}



void FUN_1400080f0(undefined8 param_1,longlong param_2)

{
  FUN_140003410((longlong **)(param_2 + 0xb0));
  return;
}



void FUN_140008160(undefined8 param_1,longlong param_2)

{
  FUN_140003410((longlong **)(param_2 + 0xa0));
  return;
}



void FUN_1400081ce(undefined8 *param_1)

{
  _seh_filter_exe(*(undefined4 *)*param_1,param_1);
  return;
}



// WARNING: Removing unreachable block (ram,0x00014000823c)

void FUN_140008210(undefined8 param_1,longlong param_2)

{
  if (*(short *)(*(longlong *)(param_2 + 0x98) + 10) != 0) {
    *(undefined8 *)(param_2 + 0x70) = 0;
    *(undefined8 *)(param_2 + 0x78) = *(undefined8 *)(param_2 + 0x98);
    free(*(void **)(param_2 + 0x78));
  }
  return;
}



undefined8 FUN_1400082a0(undefined8 param_1,longlong param_2)

{
  **(undefined8 **)(param_2 + 0x430) = 0;
  *(longlong *)(param_2 + 0x340) = *(longlong *)(param_2 + 0x430) + 0x1c;
  *(undefined2 *)(param_2 + 0x2e) = 0xffff;
  **(undefined2 **)(param_2 + 0x340) = *(undefined2 *)(param_2 + 0x2e);
  FUN_140001d40();
  return 0x1400076d9;
}


