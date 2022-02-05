using System;
using System.Text;
using System.Runtime.InteropServices;
using System.Diagnostics;

namespace MemoryEdit
{
    class Memory
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
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

        public enum Protection : uint
        {
            PAGE_NOACCESS = 0x01,
            PAGE_READONLY = 0x02,
            PAGE_READWRITE = 0x04,
            PAGE_WRITECOPY = 0x08,
            PAGE_EXECUTE = 0x10,
            PAGE_EXECUTE_READ = 0x20,
            PAGE_EXECUTE_READWRITE = 0x40,
            PAGE_EXECUTE_WRITECOPY = 0x80,
            PAGE_GUARD = 0x100,
            PAGE_NOCACHE = 0x200,
            PAGE_WRITECOMBINE = 0x400
        }

        [DllImport("kernel32.dll")]
        static extern IntPtr OpenProcess(ProcessAccessFlags dwDesiredAccess, bool bInheritHandle,
            uint dwProcessId);

        [DllImport("kernel32.dll")]
        static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
            byte[] lpBuffer, UIntPtr nSize, uint lpNumberOfBytesWritten);
        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
            byte[] lpBuffer, UIntPtr nSize, uint lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress,
            out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength); 
        [DllImport("kernel32.dll")]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress,
            uint dwSize, Protection flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess,
           IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress,
           IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
        [DllImport("kernel32.dll")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress,
           uint dwSize, uint flAllocationType, uint flProtect);

        /*public enum AllocationType : uint
        {
            Commit = 0x1000,
            Reserve = 0x2000,
            Decommit = 0x4000,
            Release = 0x8000,
            Reset = 0x80000,
            Physical = 0x400000,
            TopDown = 0x100000,
            WriteWatch = 0x200000,
            LargePages = 0x20000000
        }*/

        [DllImport("kernel32.dll")]
        static extern bool CloseHandle(IntPtr hObject);

        [DllImport("user32.dll")]
        static extern IntPtr GetForegroundWindow();
        [DllImport("user32.dll")]
        static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

        //Create handle
        IntPtr Handle;
        uint Pid;

        public bool IsFocused()
        {
            uint id;
            GetWindowThreadProcessId(GetForegroundWindow(), out id);
            return Pid == id;
        }

        public bool Attach(string sprocess, ProcessAccessFlags access)
        {
            //Get the specific process
            Process[] Processes = Process.GetProcessesByName(sprocess);
            if (Processes.Length < 1) return false;
            Process nProcess = Processes[0];
            Attach((uint)nProcess.Id, access);
            return true;
        }

        public bool Attach(uint pid, ProcessAccessFlags access)
        {
            Pid = pid;
            Handle = OpenProcess(access, false, Pid);
            return true;
        }

        public void Detach()
        {
            if (Handle != IntPtr.Zero)
                CloseHandle(Handle);
        }

        //Memory reading

        //Byte array
        public byte[] ReadBytes(uint pointer, int blen)
        {
            byte[] bytes = new byte[blen];

            //Reading the specific address within the process
            ReadProcessMemory(Handle, (IntPtr)pointer, bytes, (UIntPtr)blen, 0);
            return bytes;
        }

        //Byte
        public byte ReadByte(uint pointer)
        {
            byte[] bytes = new byte[1];

            //Reading the specific address within the process
            ReadProcessMemory(Handle, (IntPtr)pointer, bytes, (UIntPtr)1, 0);
            return bytes[0];
        }

        //Float
        public float ReadFloat(uint pointer)
        {
            byte[] bytes = new byte[4];

            //Reading the specific address within the process
            ReadProcessMemory(Handle, (IntPtr)pointer, bytes, (UIntPtr)4, 0);
            return BitConverter.ToSingle(bytes, 0);
        }

        //Double
        public double ReadDouble(uint pointer)
        {
            byte[] bytes = new byte[8];

            //Reading the specific address within the process
            ReadProcessMemory(Handle, (IntPtr)pointer, bytes, (UIntPtr)8, 0);
            return BitConverter.ToDouble(bytes, 0);
        }

        //String
        public string ReadString(uint pointer, int blen)
        {
            byte[] bytes = new byte[blen];

            //Reading the specific address within the process
            ReadProcessMemory(Handle, (IntPtr)pointer, bytes, (UIntPtr)blen, 0);
            return BitConverter.ToString(bytes, 0);
        }

        //Int32
        public int Read(uint pointer)
        {
            byte[] bytes = new byte[4];

            //Reading the specific address within the process
            ReadProcessMemory(Handle, (IntPtr)pointer, bytes, (UIntPtr)4, 0);
            //Return the result as 4 byte int
            return BitConverter.ToInt32(bytes, 0);
        }

        //Memory writing

        public void WriteBytes(uint pointer, byte[] Buffer, int blen)
        {
            WriteProcessMemory(Handle, (IntPtr)pointer, Buffer, (UIntPtr)blen, 0);
        }

        //Memory protection

        public MEMORY_BASIC_INFORMATION GetProtection(uint pointer, uint length)
        {
            MEMORY_BASIC_INFORMATION lpBuffer;
            VirtualQueryEx(Handle, (IntPtr)pointer, out lpBuffer, length);
            return lpBuffer;
        }

        public bool SetProtection(uint dwAddress, uint dwSize, Protection flNewProtect, out uint lpflOldProtect)
        {
            return !VirtualProtectEx(Handle, (IntPtr)dwAddress, dwSize, flNewProtect, out lpflOldProtect);
        }

        //Calling functions

        public IntPtr ThreadCall(IntPtr address)
        {
            uint tid;
            return CreateRemoteThread(Handle, IntPtr.Zero, 0, address, IntPtr.Zero, 0, out tid);
        }

        public void ThreadClose(IntPtr address)
        {
            CloseHandle(address);
        }

        //Allocate memory

        public IntPtr Allocate(uint length)
        {
            return VirtualAllocEx(Handle, IntPtr.Zero, length, 0x1000, 0x40);
        }
    }
}