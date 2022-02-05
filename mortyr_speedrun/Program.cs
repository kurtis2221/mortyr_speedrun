//Alternative address check on register
//#define ALT_ADDR
using System;
using System.IO;
using System.Diagnostics;
using MemoryEdit;

namespace mortyr_speedrun
{
    class Program
    {
        const string game_exe = "Mortyr.exe";

        static void Main()
        {
            if (!File.Exists(game_exe))
            {
                System.Windows.Forms.MessageBox.Show("Mortyr.exe not found!", "Mortyr Speedrun Loader");
                return;
            }
            //Start game, attach
            Process proc = Process.Start(game_exe);
            Memory mem = new Memory();
            mem.Attach((uint)proc.Id, Memory.ProcessAccessFlags.All);
            //
            byte[] crash_jmp;
            byte[] crash_code;
            uint address;
            uint newmem;
            uint oldproct;
            //-----------------------------------------------------------------------------------------
            //Crash injection 1
            address = 0x0046307C;
            newmem = (uint)mem.Allocate(0x100);
            crash_jmp = new byte[]
            {
                0xE9, 0x00, 0x00, 0x00, 0x00 //jmp newmem
            };
            InsertJMPAddress(crash_jmp, address, newmem, 1);
            //
            crash_code = new byte[]
            {
#if ALT_ADDR
                0x81, 0xF9, 0xDA, 0xEF, 0x41, 0x10, //cmp ecx,1041EFDA
#else
                0x81, 0xF9, 0xFC, 0x2F, 0x05, 0x10, //cmp ecx,10052FFC 
#endif
                0x0F, 0x8D, 0x00, 0x00, 0x00, 0x00, //jnl 004630AC
                0x8B, 0x01, //mov eax,[ecx]
                0x29, 0xF0, //sub eax,esi
                0x99, //cdq
                0xE9, 0x00, 0x00, 0x00, 0x00 //jmp address
            };
            InsertJMPAddress(crash_code, newmem, 0x004630AC, 8);
            InsertJMPAddress(crash_code, newmem, address + (uint)crash_jmp.Length, 18);
            //Make writable protection
            mem.SetProtection(address, 0x100, Memory.Protection.PAGE_EXECUTE_READWRITE, out oldproct);
            //Write to memory
            mem.WriteBytes(newmem, crash_code, crash_code.Length);
            mem.WriteBytes(address, crash_jmp, crash_jmp.Length);
            //Reset protection
            mem.SetProtection(address, 0x100, (Memory.Protection)oldproct, out oldproct);
            //-----------------------------------------------------------------------------------------
            //Crash injection 2
            address = 0x00447E5F;
            newmem = (uint)mem.Allocate(0x100);
            crash_jmp = new byte[]
            {
                0xE9, 0x00, 0x00, 0x00, 0x00, //jmp newmem
                0x90 //nop
            };
            InsertJMPAddress(crash_jmp, address, newmem, 1);
            //
            crash_code = new byte[]
            {
#if ALT_ADDR
                0x81, 0xFF, 0xDA, 0xEF, 0x41, 0x10, //cmp edi,1041EFDA
#else
                0x81, 0xFF, 0xFC, 0x2F, 0x05, 0x10, //cmp edi,10052FFC
#endif
                0x0F, 0x8D, 0x00, 0x00, 0x00, 0x00, //jnl 00447EB0
                0x66, 0x8B, 0x07, //mov ax,[edi]
                0x66, 0x85, 0xC0, //test ax,ax
                0xE9, 0x00, 0x00, 0x00, 0x00 //jmp address
            };
            InsertJMPAddress(crash_code, newmem, 0x00447EB0, 8);
            InsertJMPAddress(crash_code, newmem, address + (uint)crash_jmp.Length, 19);
            //Make writable protection
            mem.SetProtection(address, 0x100, Memory.Protection.PAGE_EXECUTE_READWRITE, out oldproct);
            //Write to memory
            mem.WriteBytes(newmem, crash_code, crash_code.Length);
            mem.WriteBytes(address, crash_jmp, crash_jmp.Length);
            //Reset protection
            mem.SetProtection(address, 0x100, (Memory.Protection)oldproct, out oldproct);
            //-----------------------------------------------------------------------------------------
            //Crash injection 3
            address = 0x00447DE5;
            newmem = (uint)mem.Allocate(0x100);
            crash_jmp = new byte[]
            {
                0xE9, 0x00, 0x00, 0x00, 0x00 //jmp newmem
            };
            InsertJMPAddress(crash_jmp, address, newmem, 1);
            //
            crash_code = new byte[]
            {
#if ALT_ADDR
                0x81, 0xF9, 0xDA, 0xEF, 0x41, 0x10, //cmp ecx,1041EFDA
#else
                0x81, 0xF9, 0xFC, 0x2F, 0x05, 0x10, //cmp ecx,10052FFC
#endif
                0x0F, 0x8D, 0x00, 0x00, 0x00, 0x00, //jnl 00447E17
                0x2B, 0x01, //sub eax,[ecx]
                0x99, //cdq
                0x31, 0xD0, //xor eax,edx
                0xE9, 0x00, 0x00, 0x00, 0x00 //jmp address
            };
            InsertJMPAddress(crash_code, newmem, 0x00447E17, 8);
            InsertJMPAddress(crash_code, newmem, address + (uint)crash_jmp.Length, 18);
            //Make writable protection
            mem.SetProtection(address, 0x100, Memory.Protection.PAGE_EXECUTE_READWRITE, out oldproct);
            //Write to memory
            mem.WriteBytes(newmem, crash_code, crash_code.Length);
            mem.WriteBytes(address, crash_jmp, crash_jmp.Length);
            //Reset protection
            mem.SetProtection(address, 0x100, (Memory.Protection)oldproct, out oldproct);
        }

        static void InsertJMPAddress(byte[] code, uint fromaddress, uint toaddress, uint idx)
        {
            byte[] jmp_addr = BitConverter.GetBytes(toaddress - (fromaddress + idx + 4));
            Array.Copy(jmp_addr, 0, code, idx, 4);
        }
    }
}
