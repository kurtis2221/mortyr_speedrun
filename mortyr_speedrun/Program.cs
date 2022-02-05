using System;
using System.IO;
using System.Diagnostics;
using MemoryEdit;
using FileConfigManager;
using System.Globalization;

namespace mortyr_speedrun
{
    class Program
    {
        const string TITLE = "Mortyr Speedrun Loader";
        const string GAME_EXE = "Mortyr.exe";
        const string CONFIG_FILE = "mortyr_speedrun.ini";

        static uint ADDRESSHI = 0;
        static uint ADDRESSLO = 0;

        static void Main()
        {
            try
            {
                if (!File.Exists(GAME_EXE))
                {
                    MsgBox(GAME_EXE + " not found!");
                    return;
                }
                if (!LoadConfig()) return;
                Inject();
            }
            catch (Exception ex)
            {
                MsgBox("An error occured\n" + ex.Message);
            }
        }

        static bool LoadConfig()
        {
            //Load config
            if (!File.Exists(CONFIG_FILE))
            {
                MsgBox(CONFIG_FILE + " not found!");
                return false;
            }
            string[] data, data2;
            try
            {
                FCM cfg = new FCM();
                cfg.ReadAllData(CONFIG_FILE, out data, out data2);
                for (int i = 0; i < data.Length; i++)
                {
                    if (data[i] == "ADDRESSHI")
                    {
                        uint.TryParse(data2[i], NumberStyles.HexNumber, null, out ADDRESSHI);
                    }
                    else if (data[i] == "ADDRESSLO")
                    {
                        uint.TryParse(data2[i], NumberStyles.HexNumber, null, out ADDRESSLO);
                    }
                }
            }
            catch (Exception ex)
            {
                MsgBox("Failed to load addresses, using default values.\n" + ex.Message);
            }
            return true;
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
                0x81, 0xF9, 0xFC, 0x2F, 0x05, 0x10, //cmp ecx,10052FFC
                0x0F, 0x8D, 0x00, 0x00, 0x00, 0x00, //jnl 004630AC
                0x8B, 0x01, //mov eax,[ecx]
                0x29, 0xF0, //sub eax,esi
                0x99, //cdq
                0xE9, 0x00, 0x00, 0x00, 0x00 //jmp address
            };
            InsertJMPAddress(crash_code, newmem, 0x004630AC, 8);
            InsertJMPAddress(crash_code, newmem, address + (uint)crash_jmp.Length, 18);
            InsertUInt(crash_code, ADDRESSHI, 2);
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
                0x81, 0xFF, 0xFC, 0x2F, 0x05, 0x10, //cmp edi,10052FFC
                0x0F, 0x8D, 0x00, 0x00, 0x00, 0x00, //jnl 00447EB0
                0x66, 0x8B, 0x07, //mov ax,[edi]
                0x66, 0x85, 0xC0, //test ax,ax
                0xE9, 0x00, 0x00, 0x00, 0x00 //jmp address
            };
            InsertJMPAddress(crash_code, newmem, 0x00447EB0, 8);
            InsertJMPAddress(crash_code, newmem, address + (uint)crash_jmp.Length, 19);
            InsertUInt(crash_code, ADDRESSHI, 2);
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
                0x81, 0xF9, 0xFC, 0x2F, 0x05, 0x10, //cmp ecx,10052FFC
                0x0F, 0x8D, 0x00, 0x00, 0x00, 0x00, //jnl 00447E17
                0x2B, 0x01, //sub eax,[ecx]
                0x99, //cdq
                0x31, 0xD0, //xor eax,edx
                0xE9, 0x00, 0x00, 0x00, 0x00 //jmp address
            };
            InsertJMPAddress(crash_code, newmem, 0x00447E17, 8);
            InsertJMPAddress(crash_code, newmem, address + (uint)crash_jmp.Length, 18);
            InsertUInt(crash_code, ADDRESSHI, 2);
            //Make writable protection
            mem.SetProtection(address, 0x100, Memory.Protection.PAGE_EXECUTE_READWRITE, out oldproct);
            //Write to memory
            mem.WriteBytes(newmem, crash_code, crash_code.Length);
            mem.WriteBytes(address, crash_jmp, crash_jmp.Length);
            //Reset protection
            mem.SetProtection(address, 0x100, (Memory.Protection)oldproct, out oldproct);
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
                0x3D, 0x00, 0x00, 0x40, 0x00, //cmp eax,00400000
                0x58, //pop eax
                0x7C, 0x08, //jl +0x08
                0x0F, 0x1F, 0x40, 0x00, //nop dword ptr [eax+00]
                0x8B, 0x44, 0x10, 0x38, //mov eax,[eax+edx+38]
                0x85, 0xC0, //test eax,eax
                0xE9, 0x00, 0x00, 0x00, 0x00 //jmp address
            };
            InsertJMPAddress(crash_code, newmem, address + (uint)crash_jmp.Length, 25);
            InsertUInt(crash_code, ADDRESSLO, 7);
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

        static void InsertUInt(byte[] code, uint val, uint idx)
        {
            if (val == 0) return;
            byte[] tmp = BitConverter.GetBytes(val);
            Array.Copy(tmp, 0, code, idx, 4);
        }

        static void MsgBox(string text)
        {
            System.Windows.Forms.MessageBox.Show(text, TITLE);
        }
    }
}
