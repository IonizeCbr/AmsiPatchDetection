using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace AmsiPatchDetection
{
    public class Program
    {
        const string amsiPath = @"c:\windows\system32\amsi.dll";
        public static void Main(string[] args)
        {
            Console.WriteLine("Running AMSI patch detection ({0}-bit only)", IntPtr.Size == 8 ? 64 : 32);
            var processes = Process.GetProcesses();
            var amsiModuleAddr = LoadLibrary(amsiPath);
            var amsiAddr = GetProcAddress(amsiModuleAddr, "AmsiScanBuffer");
            foreach (var process in processes)
            {
                if (process.Id == Process.GetCurrentProcess().Id)
                {
                    continue;
                }
                if (RunAmsiCheck(process, amsiAddr))
                {
                    Console.WriteLine("*** Potential AMSI bypass detected: {0} ({1}) ***", process.ProcessName, process.Id);
                }
            }
        }

        private static bool RunAmsiCheck(Process process, IntPtr amsiAddr)
        {
            var psapi_info = new PSAPI_WORKING_SET_EX_INFORMATION[1];
            psapi_info[0].VirtualAddress = amsiAddr;
            
            var fullHandle = OpenProcess(ProcessAccessFlags.All, false, process.Id);
            if (fullHandle == IntPtr.Zero)
            {
                return false;
            }

            // Force the memory into RAM
            IntPtr numBytesRead;
            var data = new byte[10];
            ReadProcessMemory(fullHandle, amsiAddr, data, 10, out numBytesRead);
            var size = (uint)Marshal.SizeOf(typeof(PSAPI_WORKING_SET_EX_INFORMATION));

            // Check "is it shared?"
            bool success = QueryWorkingSetEx(fullHandle, psapi_info, size);
            if (psapi_info[0].VirtualAttributes.IsValid)
            {
                Console.WriteLine("{0} ({1}) uses AMSI", process.ProcessName, process.Id);
                return !psapi_info[0].VirtualAttributes.IsShareable;
            }
            return false;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(ProcessAccessFlags processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32")]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32")]
        public static extern IntPtr LoadLibrary(string name);

        // Initial source: https://github.com/K2/Scripting/blob/master/Test-AllVirtualMemory.ps1
        [DllImport("psapi.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool QueryWorkingSetEx(IntPtr hProcess, [In, Out] PSAPI_WORKING_SET_EX_INFORMATION[] pv, uint cb);

        [StructLayout(LayoutKind.Sequential)]
        public struct PSAPI_WORKING_SET_EX_INFORMATION
        {
            public IntPtr VirtualAddress;
            public BLOCK_EX VirtualAttributes;
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
        public struct BLOCK_EX
        {
            public IntPtr Bits;
            private long BitsLong { get { return Bits.ToInt64(); } } // To be able to perform bitwise operations in any bitness
            const int Valid = 1;
            const int ShareCount = 3; // # up to 7 of shared usage
            const int Win32Protection = 11;
            const int Shareable = 1;
            const int Node = 6;
            const int Locked = 1;
            const int LargePage = 1;
            const int Reserved = 7;
            const int Bad = 1;
            const int ReservedUlong = 32;
            public bool IsValid { get { return (BitsLong & 1) != 0; } }
            public int ShareCnt { get { return (int)(BitsLong >> Valid) & 0x7; } }
            public int Protection { get { return (int)(BitsLong >> ShareCount + Valid) & 0x7FF; } }
            public bool IsShareable { get { return (BitsLong >> (Win32Protection + ShareCount + Valid) & 1) != 0; } }
            public int NodeId { get { return (int)(BitsLong >> Shareable + Win32Protection + ShareCount + Valid) & 0x3f; } }
            public bool IsLocked { get { return (BitsLong >> (Node + Shareable + Win32Protection + ShareCount + Valid) & 1) != 0; } }
            public bool IsLargePage { get { return BitsLong >> (Locked + Node + Shareable + Win32Protection + ShareCount + Valid) != 0; } }
            public int ReservedBits { get { return (int)BitsLong >> (LargePage + Locked + Node + Shareable + Win32Protection + ShareCount + Valid); } }
            public bool IsBad { get { return BitsLong >> (Reserved + LargePage + Locked + Node + Shareable + Win32Protection + ShareCount + Valid) != 0; } }
            public int ReservedUlongBits { get { return (int)(BitsLong >> 32); } }
        }
    }
}
