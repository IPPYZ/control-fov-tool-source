using System;
using System.IO;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Windows.Forms;

[assembly: AssemblyTitle("Control FOV Tool")]
[assembly: AssemblyProduct("Control FOV Tool")]
[assembly: AssemblyCompany("Khalid Alsahari")]
[assembly: AssemblyDescription("Bilingual live field-of-view controller for Control")]
[assembly: AssemblyCopyright("Copyright © Khalid Alsahari")]
[assembly: AssemblyVersion("1.0.0.0")]
[assembly: AssemblyFileVersion("1.0.0.0")]

internal static class ControlFOVLauncher
{
    [STAThread]
    private static int Main()
    {
        try
        {
            Thread.CurrentThread.Name = "Control FOV UI";
            string script;
            Assembly assembly = Assembly.GetExecutingAssembly();
            using (Stream resource = assembly.GetManifestResourceStream("ControlFOVTool.ps1"))
            {
                if (resource == null)
                    throw new InvalidOperationException("The embedded Control FOV interface could not be found.");
                using (StreamReader reader = new StreamReader(resource, Encoding.UTF8, true))
                    script = reader.ReadToEnd();
            }

            InitialSessionState state = InitialSessionState.CreateDefault();
            using (Runspace runspace = RunspaceFactory.CreateRunspace(state))
            {
                runspace.ApartmentState = ApartmentState.STA;
                runspace.Open();
                using (PowerShell shell = PowerShell.Create())
                {
                    shell.Runspace = runspace;
                    shell.AddScript(script);
                    shell.Invoke();
                    if (shell.InvocationStateInfo.State == PSInvocationState.Failed && shell.InvocationStateInfo.Reason != null)
                        throw shell.InvocationStateInfo.Reason;
                }
            }
            return 0;
        }
        catch (Exception error)
        {
            MessageBox.Show(
                "Control FOV Tool could not start.\r\n\r\n" + error.Message,
                "Control FOV Tool",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
            return 1;
        }
    }
}
