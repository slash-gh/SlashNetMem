# SlashNetMem

## How To Use

```C#
using System;
using SlashNetMem;

namespace SlashNetMemTest
{
    internal class Program
    {
        static void Main(string[] args)
        {
            //true for enable debug
            SlashMemoryManager memoryManager = new SlashMemoryManager(true);

            //Attach to process
            memoryManager.AttachProcess("notepad");

            //Notepad.exe+15C008
            var targetAddress = IntPtr.Add(memoryManager.GetBaseAddress(), 0x15C008);
            var targetStringAddress = IntPtr.Add(memoryManager.GetBaseAddress(), 0x15C8EE);

            //Read original value
            var a = memoryManager.ReadMemory<int>(targetAddress);
            Console.WriteLine($"Value at Notepad.exe+15C008: {a}");

            //Write modified value
            memoryManager.WriteMemory<int>(targetAddress,6);

            //Read modified value
            a = memoryManager.ReadMemory<int>(targetAddress);
            Console.WriteLine($"Value after write at Notepad.exe+15C008: {a}");

            //Read Original String
            var b = memoryManager.ReadString(targetStringAddress,10);
            Console.WriteLine($"Value at Notepad.exe+0x15C8EE: {b}");

            memoryManager.WriteString(targetStringAddress, "astaga");

            //Read Modified String
            b = memoryManager.ReadString(targetStringAddress, 10);
            Console.WriteLine($"Value at Notepad.exe+0x15C8EE: {b}");


            //Search Pattern
            // Define the AoB pattern
            var pattern = new byte[] { 0x61, 0x73, 0x74, 0x61, 0x67, 0x61 }; // Example pattern
            var mask = "xxxxxx"; // Mask with wildcards for 0x?? bytes

            // Search the memory
            var resultAddress = memoryManager.AoBSearch(memoryManager.GetBaseAddress(), 0x16C008, pattern, mask);

            if (resultAddress != IntPtr.Zero)
            {
                Console.WriteLine($"Pattern found at: {resultAddress.ToString("X")}");
            }
            else
            {
                Console.WriteLine("Pattern not found.");
            }

            //Read String
            Console.ReadLine();
        }
    }
}
```

## Features

##### Read Memory
##### Write Memory
##### AoB Search
