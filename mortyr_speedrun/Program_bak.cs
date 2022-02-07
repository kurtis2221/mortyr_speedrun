using System;
using System.IO;
using System.Diagnostics;
using MemoryEdit;

namespace mortyr_speedrun
{
    class Program
    {
        const string TITLE = "Mortyr Speedrun Loader";
        const string GAME_EXE = "Mortyr.exe";
        const string CONFIG_FILE = "mortyr_speedrun.ini";
        const string DLL_FILE = "memchk.dll";

        static void Main()
        {
            try
            {
                if (!File.Exists(GAME_EXE))
                {
                    MsgBox(GAME_EXE + " not found!");
                    return;
                }
                if (!File.Exists(DLL_FILE))
                {
                    MsgBox(DLL_FILE + " not found!");
                    return;
                }
                Inject();
            }
            catch (Exception ex)
            {
                MsgBox("An error occured\n" + ex.Message);
            }
        }

        static void Inject()
        {
            //Start game, attach
            Process proc = Process.Start(GAME_EXE);
            Memory mem = new Memory();
            mem.Attach((uint)proc.Id, Memory.ProcessAccessFlags.All);
            //
            byte[] crash_jmp;
            byte[] crash_code;
            uint address;
            uint newmem;
            uint dllfunc;
            mem.InjectDLL(DLL_FILE);
            dllfunc = (uint)mem.GetModule(DLL_FILE) + 0x1000;
            Memory.Protection oldproct;
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
                0x50, //push eax
                0x51, //push ecx
                0xE8, 0x00, 0x00, 0x00, 0x00, //call memchk.checkaccess(int)
                0x85, 0xC0, //test eax,eax
                0x59, //pop ecx
                0x58, //pop eax
                0x0F, 0x84, 0x00, 0x00, 0x00, 0x00, //je 004630AC
                0x8B, 0x01, //mov eax,[ecx]
                0x29, 0xF0, //sub eax,esi
                0x99, //cdq
                0xE9, 0x00, 0x00, 0x00, 0x00 //jmp address
            };
            InsertJMPAddress(crash_code, newmem, dllfunc, 3);
            InsertJMPAddress(crash_code, newmem, 0x004630AC, 13);
            InsertJMPAddress(crash_code, newmem, address + (uint)crash_jmp.Length, 23);
            //Make writable protection
            mem.SetProtection(address, 0x100, Memory.Protection.PAGE_EXECUTE_READWRITE, out oldproct);
            //Write to memory
            mem.WriteBytes(newmem, crash_code);
            mem.WriteBytes(address, crash_jmp);
            //Reset protection
            mem.SetProtection(address, 0x100, oldproct, out oldproct);
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
                0x50, //push eax
                0x51, //push ecx
                0x57, //push edi
                0xE8, 0x00, 0x00, 0x00, 0x00, //call memchk.checkaccess(int)
                0x85, 0xC0, //test eax,eax
                0x5F, //pop edi
                0x59, //pop ecx
                0x58, //pop eax
                0x0F, 0x84, 0x00, 0x00, 0x00, 0x00, //je 00447EB0
                0x66, 0x8B, 0x07, //mov ax,[edi]
                0x66, 0x85, 0xC0, //test ax,ax
                0xE9, 0x00, 0x00, 0x00, 0x00 //jmp address
            };
            InsertJMPAddress(crash_code, newmem, dllfunc, 4);
            InsertJMPAddress(crash_code, newmem, 0x00447EB0, 15);
            InsertJMPAddress(crash_code, newmem, address + (uint)crash_jmp.Length, 26);
            //Make writable protection
            mem.SetProtection(address, 0x100, Memory.Protection.PAGE_EXECUTE_READWRITE, out oldproct);
            //Write to memory
            mem.WriteBytes(newmem, crash_code);
            mem.WriteBytes(address, crash_jmp);
            //Reset protection
            mem.SetProtection(address, 0x100, oldproct, out oldproct);
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
                0x50, //push eax
                0x51, //push ecx
                0xE8, 0x00, 0x00, 0x00, 0x00, //call memchk.checkaccess(int)
                0x85, 0xC0, //test eax,eax
                0x59, //pop ecx
                0x58, //pop eax
                0x0F, 0x84, 0x00, 0x00, 0x00, 0x00, //je 00447E17
                0x2B, 0x01, //sub eax,[ecx]
                0x99, //cdq
                0x31, 0xD0, //xor eax,edx
                0xE9, 0x00, 0x00, 0x00, 0x00 //jmp address
            };
            InsertJMPAddress(crash_code, newmem, dllfunc, 3);
            InsertJMPAddress(crash_code, newmem, 0x00447E17, 13);
            InsertJMPAddress(crash_code, newmem, address + (uint)crash_jmp.Length, 23);
            //Make writable protection
            mem.SetProtection(address, 0x100, Memory.Protection.PAGE_EXECUTE_READWRITE, out oldproct);
            //Write to memory
            mem.WriteBytes(newmem, crash_code);
            mem.WriteBytes(address, crash_jmp);
            //Reset protection
            mem.SetProtection(address, 0x100, oldproct, out oldproct);
            //-----------------------------------------------------------------------------------------
            //Crash injection 4
            address = 0x0044AF51;
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
                0x50, //push eax
                0x01, 0xD0, //add eax,edx
                0x83, 0xC0, 0x38, //add eax,38
                0x51, //push ecx
                0x50, //push eax
                0xE8, 0x00, 0x00, 0x00, 0x00, //call memchk.checkaccess(int)
                0x85, 0xC0, //test eax,eax
                0x58, //pop eax
                0x59, //pop ecx
                0x58, //pop eax
                0x74, 0x08, //je +0x08
                0x0F, 0x1F, 0x40, 0x00, //nop dword ptr [eax+00]
                0x8B, 0x44, 0x10, 0x38, //mov eax,[eax+edx+38]
                0x85, 0xC0, //test eax,eax
                0xE9, 0x00, 0x00, 0x00, 0x00 //jmp address
            };
            InsertJMPAddress(crash_code, newmem, dllfunc, 9);
            InsertJMPAddress(crash_code, newmem, address + (uint)crash_jmp.Length, 31);
            //Make writable protection
            mem.SetProtection(address, 0x100, Memory.Protection.PAGE_EXECUTE_READWRITE, out oldproct);
            //Write to memory
            mem.WriteBytes(newmem, crash_code);
            mem.WriteBytes(address, crash_jmp);
            //Reset protection
            mem.SetProtection(address, 0x100, oldproct, out oldproct);
            mem.Detach();
        }

        static void InsertJMPAddress(byte[] code, uint fromaddress, uint toaddress, uint idx)
        {
            byte[] jmp_addr = BitConverter.GetBytes(toaddress - (fromaddress + idx + 4));
            Array.Copy(jmp_addr, 0, code, idx, 4);
        }

        static void MsgBox(string text)
        {
            System.Windows.Forms.MessageBox.Show(text, TITLE);
        }
    }
}
