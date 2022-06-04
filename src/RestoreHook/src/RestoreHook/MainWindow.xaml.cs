using Binarysharp.MemoryManagement;
using PeNet;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Drawing;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
namespace RestoreHook
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public int _processId;
        public MainWindow()
        {
            InitializeComponent();
        }

        private void btnScan_Click(object sender, RoutedEventArgs e)
        {
            SelectProcessWnd.SelectProcess(p =>
            {
                _processId = p.ProcessId;
                ScanHooks();
            });
        }

        private void btnRestore_Click(object sender, RoutedEventArgs e)
        {
            var hookinfo = dg.SelectedItem as HookInfo;
            RestoreHook(hookinfo);
            ScanHooks();
        }

        async void ScanHooks()
        {
            pgWaiting.Visibility = Visibility.Visible;
            try
            {
                dg.ItemsSource = null;
                var hooks = new List<HookInfo>();
                await Task.Run(() => {
                    var process = Process.GetProcessById(_processId);
                    var pm = new MemorySharp(_processId);
                    var mods = process.Modules.Cast<ProcessModule>().Where(m => m.FileName.ToLower().StartsWith(@"c:\windows")).ToList();
                    hooks = mods.SelectMany(mod => ScanModuleHooks(pm, mod)).ToList();
                });
                dg.ItemsSource = hooks;
            }catch (Exception ex) { }
            finally
            {
                pgWaiting.Visibility = Visibility.Collapsed;
            }
        }


        public void RestoreHook(HookInfo hi)
        {
            var toMs = new MemorySharp(hi.ProcessId);
            var ms = new MemorySharp(Process.GetCurrentProcess());
            var source5Bytes = ms.Read<byte>(new IntPtr(hi.SourceAddress.ToIntFromHexString()), 5, false);
            toMs.Write(new IntPtr(hi.SourceAddress.ToIntFromHexString()), source5Bytes, false);
        }

        public List<HookInfo> ScanModuleHooks(MemorySharp toMs, ProcessModule module)
        {
            var hooks = new List<HookInfo>();
            var pe = new PeFile(module.FileName);
            var process = Process.GetCurrentProcess();
            var ms = new MemorySharp(process);
            if (!process.Modules.Cast<ProcessModule>().Any(m => m.ModuleName == module.ModuleName))
            {
                ms.Modules.Inject(module.FileName);
            }
            var injectModule = process.Modules.Cast<ProcessModule>().FirstOrDefault(m => m.ModuleName.ToLower() == module.ModuleName.ToLower());
            if (injectModule.BaseAddress != module.BaseAddress) return hooks;
            if (pe.ExportedFunctions == null) return hooks;
            pe.ExportedFunctions.ToList().ForEach(f =>
            {
                var funcAddress = new IntPtr((int)module.BaseAddress + f.Address);
                var toFunc = Read5Bytes(toMs, module, funcAddress);
                var fromFunc = Read5Bytes(ms, module, funcAddress);
                if (fromFunc != null 
                    && toFunc != null
                    && toFunc[0] == 0xE9 
                    && fromFunc.Any(ff=> !toFunc.Contains(ff)))
                {
                    var toMod = FindToModule(toMs, funcAddress, toFunc);
                    hooks.Add(new HookInfo { 
                        ProcessName = Process.GetProcessById(toMs.Pid).ProcessName,
                        ProcessId = toMs.Pid,
                        SourceModule = module.ModuleName + "!" + f.Name,                        
                        SourceAddress = ((ulong)funcAddress).ToHexString(),
                        TargetModule = toMod.Item1,
                        TargetAddress = toMod.Item2,
                    });
                }
            });
            return hooks;
        }

        private byte[] Read5Bytes(MemorySharp ms, ProcessModule module, IntPtr address)
        {
            if((module.BaseAddress.ToInt64() + module.ModuleMemorySize) < (long)(address.ToInt64()+5)) return null;
            return ms.Read<byte>(address, 5, false);
        }

        public (string,string) FindToModule(MemorySharp toMs, IntPtr funcAddress, byte[] toFunc)
        {
            var modules = Process.GetProcessById(toMs.Pid).Modules.Cast<ProcessModule>().ToList();
            var jmpAddress = $"0x{string.Join("", toFunc.Skip(1).Reverse().Select(b => b.ToString("X2")))}".ToIntFromHexString();
            var toAddress = (ulong)(jmpAddress + funcAddress.ToInt32() + 5);
            var toMod = modules.FirstOrDefault(module=> (ulong)module.BaseAddress.ToInt64() < toAddress && toAddress < (ulong)(module.BaseAddress.ToInt64()
            + module.ModuleMemorySize));
            var moduleName = toMod == null ? string.Empty : toMod.ModuleName;
            return (moduleName, toAddress.ToHexString());
        }

    }

    public class HookInfo {
        public string ProcessName { get; set; }
        public int ProcessId { get; set; }
        public string SourceModule { get; set; }
        public string SourceAddress { get; set; }
        public string TargetModule { get; set; }
        public string TargetAddress { get; set; }
    }
}
