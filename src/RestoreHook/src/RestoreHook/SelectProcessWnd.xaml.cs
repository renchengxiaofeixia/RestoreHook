using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;

namespace RestoreHook
{
    /// <summary>
    /// SelectProcessWnd.xaml 的交互逻辑
    /// </summary>
    public partial class SelectProcessWnd : Window
    {
        public SelectProcessWnd()
        {
            InitializeComponent();
            Loaded += SelectProcessWnd_Loaded;
        }

        private void SelectProcessWnd_Loaded(object sender, RoutedEventArgs e)
        {
            var pis = Process.GetProcesses().Where(p=>p.SessionId == 1 && p.MainWindowHandle.ToInt32() > 0).ToList().Select(p =>
			{ 
                  try
                  {
					  var excutePath = GetExecutablePath(p);
					  if (excutePath == null) return null;
					  var icon = System.Drawing.Icon.ExtractAssociatedIcon(excutePath);
                      var pi = new ProcessInfo
                      {
                          ProcessId = p.Id,
                          ProcessName = p.ProcessName,
                          Icon = Imaging.CreateBitmapSourceFromHIcon(icon.Handle, Int32Rect.Empty, BitmapSizeOptions.FromEmptyOptions())
                      };
                      return pi;
                  }
                  catch (Exception ex)
                  {
					  return null;
                  }
            }).ToList();
            processView.ItemsSource = pis;
        }

		public static void SelectProcess(Action<ProcessInfo> cb)
		{
			var wnd = new SelectProcessWnd();
			var rt = wnd.ShowDialog();
			if (rt.HasValue && rt.Value)
			{
				cb(wnd.processView.SelectedItem as ProcessInfo);
			}
		}

		private void btnOk_Click(object sender, RoutedEventArgs e)
		{
			DialogResult = true;
		}

		private void btnClose_Click(object sender, RoutedEventArgs e)
		{
			Close();
		}

		[Flags]
		enum ProcessAccessFlags : uint
		{
			All = 0x001F0FFF,
			Terminate = 0x00000001,
			CreateThread = 0x00000002,
			VMOperation = 0x00000008,
			VMRead = 0x00000010,
			VMWrite = 0x00000020,
			DupHandle = 0x00000040,
			SetInformation = 0x00000200,
			QueryInformation = 0x00000400,
			QueryLimitedInformation = 0x1000,
			Synchronize = 0x00100000
		}

		private static string GetExecutablePath(Process Process)
		{
			if (Environment.OSVersion.Version.Major >= 6)
			{
				return GetExecutablePathAboveVista(Process.Id);
			}

			return Process.MainModule.FileName;
		}

		private static string GetExecutablePathAboveVista(int ProcessId)
		{
			var buffer = new StringBuilder(1024);
			IntPtr hprocess = OpenProcess(ProcessAccessFlags.QueryLimitedInformation,
										  false, ProcessId);
			if (hprocess != IntPtr.Zero)
			{
				try
				{
					int size = buffer.Capacity;
					if (QueryFullProcessImageName(hprocess, 0, buffer, out size))
					{
						return buffer.ToString();
					}
				}
				finally
				{
					CloseHandle(hprocess);
				}
			}
			return string.Empty;
		}

		[DllImport("kernel32.dll")]
		private static extern bool QueryFullProcessImageName(IntPtr hprocess, int dwFlags,
					   StringBuilder lpExeName, out int size);
		[DllImport("kernel32.dll")]
		private static extern IntPtr OpenProcess(ProcessAccessFlags dwDesiredAccess,
					   bool bInheritHandle, int dwProcessId);

		[DllImport("kernel32.dll", SetLastError = true)]
		private static extern bool CloseHandle(IntPtr hHandle);

		public class ProcessInfo {
            public int ProcessId { get; set; }
            public string ProcessName { get; set; }
            public BitmapSource Icon { get; set; }
        }

    }
}
