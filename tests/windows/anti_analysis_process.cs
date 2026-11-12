using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Vmkek.Lab
{
    public sealed class ProcessJob : SafeHandleZeroOrMinusOneIsInvalid
    {
        private const int ExtendedLimitInformation = 9;
        private const uint KillOnJobClose = 0x2000;

        private ProcessJob() : base(true) { }

        public static ProcessJob Create()
        {
            ProcessJob job = CreateJobObject(IntPtr.Zero, null);
            if (job.IsInvalid)
            {
                int error = Marshal.GetLastWin32Error();
                job.Dispose();
                throw new Win32Exception(error);
            }

            JobLimits limits = new JobLimits();
            limits.Basic.Flags = KillOnJobClose;
            if (!SetInformationJobObject(job, ExtendedLimitInformation, ref limits,
                (uint)Marshal.SizeOf<JobLimits>()))
            {
                int error = Marshal.GetLastWin32Error();
                job.Dispose();
                throw new Win32Exception(error);
            }
            return job;
        }

        public void Assign(SafeProcessHandle process)
        {
            if (!AssignProcessToJobObject(this, process))
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        public static bool HasWindowTitle(SafeProcessHandle process, string token)
        {
            uint expectedOwner = GetProcessId(process);
            if (expectedOwner == 0) return false;
            bool found = false;
            EnumWindows((window, _) =>
            {
                GetWindowThreadProcessId(window, out uint owner);
                if (owner != expectedOwner) return true;
                StringBuilder title = new StringBuilder(256);
                if (GetWindowText(window, title, title.Capacity) > 0 &&
                    title.ToString().Contains(token, StringComparison.OrdinalIgnoreCase))
                {
                    found = true;
                    return false;
                }
                return true;
            }, IntPtr.Zero);
            return found;
        }

        private delegate bool EnumWindow(IntPtr window, IntPtr parameter);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint GetProcessId(SafeProcessHandle process);

        [DllImport("user32.dll")]
        private static extern bool EnumWindows(EnumWindow callback, IntPtr parameter);

        [DllImport("user32.dll")]
        private static extern uint GetWindowThreadProcessId(IntPtr window, out uint process);

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        private static extern int GetWindowText(IntPtr window, StringBuilder title, int limit);

        protected override bool ReleaseHandle() => CloseHandle(handle);

        [StructLayout(LayoutKind.Sequential)]
        private struct BasicLimits
        {
            public long ProcessTime;
            public long JobTime;
            public uint Flags;
            public UIntPtr WorkingSetMin;
            public UIntPtr WorkingSetMax;
            public uint ActiveProcesses;
            public UIntPtr Affinity;
            public uint PriorityClass;
            public uint SchedulingClass;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JobLimits
        {
            public BasicLimits Basic;
            public ulong ReadOperations, WriteOperations, OtherOperations;
            public ulong ReadBytes, WriteBytes, OtherBytes;
            public UIntPtr ProcessMemory, JobMemory, PeakProcessMemory, PeakJobMemory;
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern ProcessJob CreateJobObject(IntPtr security, string name);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetInformationJobObject(
            ProcessJob job, int kind, ref JobLimits limits, uint length);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool AssignProcessToJobObject(ProcessJob job, SafeProcessHandle process);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);
    }
}
