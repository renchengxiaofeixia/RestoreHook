using Binarysharp.Assemblers.Fasm;
using Binarysharp.MemoryManagement;
using PeNet;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Linq;

public class ProcessHook
{
    /// <summary>
    /// 恢复Hook
    /// </summary>
    /// <param name="tp">目标进程</param>
    /// <param name="mods">检查可能被Hook的模块</param>
    public static void RestoreInlineHook(Process targetProcess, params string[] modules)
    {
        var targetMemorySharp = new MemorySharp(targetProcess);
        var currentMemorySharp = new MemorySharp(Process.GetCurrentProcess());
        var targetMods = targetProcess.Modules.Cast<ProcessModule>().Where(m=> modules.Any(md => md == m.ModuleName)).ToList();

        targetMods.ForEach(tm => {
            var targetModAddress = tm.BaseAddress;
            var pe = new PeFile(tm.FileName);
            pe.ExportedFunctions.ToList().ForEach(f => {
                var targetFuncTop5Bytes = targetMemorySharp.Read<byte>(new IntPtr((int)tm.BaseAddress + f.Address), 5, false);
                var funcTop5Bytes = currentMemorySharp.Read<byte>(new IntPtr((int)tm.BaseAddress + f.Address), 5, false);
                if (targetFuncTop5Bytes[0] == 233) // E9
                {
                    targetMemorySharp.Write(new IntPtr((int)tm.BaseAddress + f.Address)
                        , funcTop5Bytes
                        , false);
                }
            });
        });
    }
}