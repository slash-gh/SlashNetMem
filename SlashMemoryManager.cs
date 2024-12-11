using Serilog;
using Serilog.Core;
using Serilog.Events;
using System;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace SlashNetMem
{
    public class SlashMemoryManager
    {
        // Add a logger
        private readonly ILogger _logger;

        private Process _process;
        private IntPtr _processHandle;

        // Importing necessary WinAPI functions
        [DllImport("kernel32.dll")]
        private static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll")]
        private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr hObject);

        private const int PROCESS_ALL_ACCESS = 0x1F0FFF;
        bool DebugEnable = false;

        public SlashMemoryManager(bool debug=false)
        {
            this.DebugEnable = debug;
            if (debug)
            {
                _logger = new LoggerConfiguration()
                       .WriteTo.Console()
                       .WriteTo.File("memory_manager.log", rollingInterval: RollingInterval.Day)
                       .CreateLogger();

                _logger.Information("MemoryManager initialized.");
            }
        }

        // Attach process by name
        public bool AttachProcess(string processName)
        {
            try
            {
                var processes = Process.GetProcessesByName(processName);
                if (processes.Length == 0)
                {
                    if (this.DebugEnable)
                    {
                        _logger.Warning("Process {ProcessName} not found.", processName);
                    }
                    return false;
                }

                _process = processes[0];
                _processHandle = OpenProcess(PROCESS_ALL_ACCESS, false, _process.Id);
                if (this.DebugEnable)
                {
                    _logger.Information("Attached to process {ProcessName} (PID: {PID})", processName, _process.Id);
                }
                return _processHandle != IntPtr.Zero;
            }
            catch (Exception ex)
            {
                if (this.DebugEnable)
                {
                    _logger.Error(ex, "Failed to attach to process {ProcessName}.", processName);
                }
                return false;
            }
        }

        // Attach process by PID
        public bool AttachProcess(int pid)
        {
            _process = Process.GetProcessById(pid);
            if (_process == null)
            {
                if (this.DebugEnable)
                {
                    _logger.Warning("Process {PId} not found.", pid);
                }
                return false;
            }

            _processHandle = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
            if (this.DebugEnable)
            {
                _logger.Information("Attached to process {ProcessName} (PID: {PID})", _process.ProcessName, _process.Id);
            }
            return _processHandle != IntPtr.Zero;
        }

        // Get the base address of the attached process
        public IntPtr GetBaseAddress()
        {
            if (_process == null)
            {
                _logger.Warning("No process attached.");
                return IntPtr.Zero;
            }

            try
            {
                return _process.MainModule.BaseAddress;
            }
            catch (Exception ex)
            {
                _logger.Warning("Error getting base address: {msg}", ex.Message);
                return IntPtr.Zero;
            }
        }

        // Read memory
        public T ReadMemory<T>(IntPtr address, int[] offsets = null) where T : struct
        {
            try
            {
                var targetAddress = ResolvePointer(address, offsets);

                if (!IsAddressValid(targetAddress))
                {
                    if (this.DebugEnable)
                    {
                        _logger.Warning("Attempted to read from an invalid address {Address}.", targetAddress.ToString("X"));
                    }
                    throw new InvalidOperationException($"Invalid memory address: {targetAddress.ToString("X")}");
                }

                var size = Marshal.SizeOf<T>();
                var buffer = new byte[size];

                if (ReadProcessMemory(_processHandle, targetAddress, buffer, (uint)size, out _))
                {
                    if (this.DebugEnable)
                    {
                        _logger.Information("Read memory from address {Address}.", targetAddress.ToString("X"));
                    }
                    return ByteArrayToStructure<T>(buffer);
                }
                throw new InvalidOperationException("Failed to read memory.");
            }
            catch (Exception ex)
            {
                if (this.DebugEnable)
                {
                    _logger.Error(ex, "Failed to read memory from address {Address}.", address.ToString("X"));
                }                
                throw;
            }
        }

        // Write memory
        public void WriteMemory<T>(IntPtr address, T value, int[] offsets = null) where T : struct
        {
            try { 
                var targetAddress = ResolvePointer(address, offsets);

                if (!IsAddressValid(targetAddress))
                {
                    if (this.DebugEnable)
                    {
                        _logger.Warning("Attempted to write to an invalid address {Address}.", targetAddress.ToString("X"));
                    }
                    throw new InvalidOperationException($"Invalid memory address: {targetAddress.ToString("X")}");
                }

                var buffer = StructureToByteArray(value);

                if (!WriteProcessMemory(_processHandle, targetAddress, buffer, (uint)buffer.Length, out _))
                {
                    throw new InvalidOperationException("Failed to write memory.");
                }
                else
                {
                    if (this.DebugEnable)
                    {
                        _logger.Information("Write memory to address {Address}.", targetAddress.ToString("X"));
                    }
                }
            }
            catch (Exception ex)
            {
                if (this.DebugEnable)
                {
                    _logger.Error(ex, "Failed to write memory to address {Address}.", address.ToString("X"));
                }
                throw;
            }
        }

        // Read string
        public string ReadString(IntPtr address, int length, int[] offsets = null)
        {
            try { 
                var targetAddress = ResolvePointer(address, offsets);
                if (!IsAddressValid(targetAddress))
                {
                    if (this.DebugEnable)
                    {
                        _logger.Warning("Attempted to read string from an invalid address {Address}.", targetAddress.ToString("X"));
                    }
                    throw new InvalidOperationException($"Invalid memory address: {targetAddress.ToString("X")}");
                }
                var buffer = new byte[length];

                if (ReadProcessMemory(_processHandle, targetAddress, buffer, (uint)length, out _))
                {
                    if (this.DebugEnable)
                    {
                        _logger.Information("Read memory from address {Address}.", targetAddress.ToString("X"));
                    }
                    return Encoding.UTF8.GetString(buffer).TrimEnd('\0');
                }
                throw new InvalidOperationException("Failed to read string.");
            }
            catch (Exception ex)
            {
                if (this.DebugEnable)
                {
                    _logger.Error(ex, "Failed to read string memory from address {Address}.", address.ToString("X"));
                }
                throw;
            }
        }

        // Write string
        public void WriteString(IntPtr address, string value, int[] offsets = null)
        {
            try { 
                var targetAddress = ResolvePointer(address, offsets);
                if (!IsAddressValid(targetAddress))
                {
                    if (this.DebugEnable)
                    {
                        _logger.Warning("Attempted to write string to an invalid address {Address}.", targetAddress.ToString("X"));
                    }
                    throw new InvalidOperationException($"Invalid memory address: {targetAddress.ToString("X")}");
                }
                var buffer = Encoding.UTF8.GetBytes(value + "\0");

                if (!WriteProcessMemory(_processHandle, targetAddress, buffer, (uint)buffer.Length, out _))
                {
                    throw new InvalidOperationException("Failed to write string.");
                }
            }
            catch (Exception ex)
            {
                if (this.DebugEnable)
                {
                    _logger.Error(ex, "Failed to write string memory to address {Address}.", address.ToString("X"));
                }
                throw;
            }
        }

        // Resolve pointer with offsets
        private IntPtr ResolvePointer(IntPtr baseAddress, int[] offsets)
        {
            if (offsets == null || offsets.Length == 0)
                return baseAddress;

            var buffer = new byte[IntPtr.Size];
            var address = baseAddress;

            foreach (var offset in offsets)
            {
                if (!IsAddressValid(address))
                {
                    if (this.DebugEnable)
                    {
                        _logger.Warning("Invalid pointer address {Address} during resolution.", address.ToString("X"));
                    }
                    throw new InvalidOperationException($"Invalid pointer address: {address.ToString("X")}");
                }

                if (!ReadProcessMemory(_processHandle, address, buffer, (uint)buffer.Length, out _))
                    throw new InvalidOperationException("Failed to resolve pointer.");

                address = IntPtr.Add(new IntPtr(BitConverter.ToInt64(buffer, 0)), offset);
            }

            return address;
        }

        // Convert byte array to structure
        private T ByteArrayToStructure<T>(byte[] bytes) where T : struct
        {
            var handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            try
            {
                return Marshal.PtrToStructure<T>(handle.AddrOfPinnedObject());
            }
            finally
            {
                handle.Free();
            }
        }

        // Convert structure to byte array
        private byte[] StructureToByteArray<T>(T value) where T : struct
        {
            var size = Marshal.SizeOf(value);
            var array = new byte[size];
            var ptr = Marshal.AllocHGlobal(size);

            try
            {
                Marshal.StructureToPtr(value, ptr, true);
                Marshal.Copy(ptr, array, 0, size);
            }
            finally
            {
                Marshal.FreeHGlobal(ptr);
            }

            return array;
        }

        //Capture the state of a specific memory region for analysis.
        public byte[] TakeSnapshot(IntPtr baseAddress, uint size)
        {
            try
            {
                if (!IsAddressValid(baseAddress))
                {
                    if (this.DebugEnable)
                    {
                        _logger.Warning("Attempted to take a snapshot from an invalid address {Address}.", baseAddress.ToString("X"));
                    }
                    throw new InvalidOperationException($"Invalid memory address: {baseAddress.ToString("X")}");
                }

                var buffer = new byte[size];
                if (ReadProcessMemory(_processHandle, baseAddress, buffer, size, out _))
                {
                    if (this.DebugEnable)
                    {
                        _logger.Information("Snapshot taken from address {Address}, size {Size} bytes.", baseAddress.ToString("X"), size);
                    }                    
                    return buffer;
                }

                throw new InvalidOperationException("Failed to take memory snapshot.");
            }
            catch (Exception ex)
            {
                if (this.DebugEnable)
                {
                    _logger.Error(ex, "Failed to take snapshot from address {Address}.", baseAddress.ToString("X"));
                }
                throw;
            }
        }

        public IntPtr AoBSearch(IntPtr startAddress, uint size, byte[] pattern, string mask)
        {
            if (pattern.Length != mask.Length)
            {
                if (this.DebugEnable)
                {
                    _logger.Warning("Pattern and mask lengths must match.");
                }
                throw new ArgumentException("Pattern and mask lengths must match.");
            }

            // Read memory region
            var buffer = new byte[size];
            if (!ReadProcessMemory(_processHandle, startAddress, buffer, size, out _))
            {
                if (this.DebugEnable)
                {
                    _logger.Warning("Failed to read memory for AoB search.");
                }
                throw new InvalidOperationException("Failed to read memory for AoB search.");
            }

            // Search for the pattern
            for (uint i = 0; i < size - pattern.Length; i++)
            {
                if (PatternMatches(buffer, i, pattern, mask))
                {
                    if (this.DebugEnable)
                    {
                        _logger.Information("AoB found at address {Address}.", IntPtr.Add(startAddress, (int)i).ToString("X"));
                    }
                    return IntPtr.Add(startAddress, (int)i); // Return the absolute address of the match
                }
            }
            if (this.DebugEnable)
            {
                _logger.Warning("AoB not found.");
            }
            return IntPtr.Zero; // Return null pointer if no match is found
        }

        private bool PatternMatches(byte[] buffer, uint offset, byte[] pattern, string mask)
        {
            for (int i = 0; i < pattern.Length; i++)
            {
                if (mask[i] == '?' || buffer[offset + i] == pattern[i])
                    continue;

                return false; // Mismatch found
            }
            return true; // All bytes match
        }

        //Validate addresses before performing memory operations
        private bool IsAddressValid(IntPtr address)
        {
            try
            {
                var buffer = new byte[1];
                return ReadProcessMemory(_processHandle, address, buffer, 1, out _);
            }
            catch
            {
                _logger.Warning("Invalid memory address {Address} accessed.", address.ToString("X"));
                return false;
            }
        }

        // Dispose and clean up
        public void Dispose()
        {
            if (_processHandle != IntPtr.Zero)
            {
                CloseHandle(_processHandle);
                _processHandle = IntPtr.Zero;
            }
        }
    }
}
