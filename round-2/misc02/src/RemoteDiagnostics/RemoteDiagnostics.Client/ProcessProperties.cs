using RemoteDiagnostics.Contract;
using System;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace RemoteDiagnostics.Client
{
    public partial class ProcessProperties : Form
    {
        ProcessObject processObject;
        ProcessSecurityObject processSecurityObject;

        public TaskCompletionSource<bool> simSecurityLoaded = new TaskCompletionSource<bool>();

        public ProcessProperties(ProcessObject process)
        {
            InitializeComponent();
            processObject = process;
            Text = process.ProcessName;
            propertiesTable.Rows.Add("Id", process.Id.ToString());
            propertiesTable.Rows.Add("Name", process.ProcessName);
            propertiesTable.Rows.Add("Running", process.Running.ToString());
            propertiesTable.Rows.Add("Session ID", process.SessionId.ToString());
            propertiesTable.Rows.Add("Window title", process.MainWindowTitle);
            propertiesTable.Rows.Add("Virtual memory size", process.VirtualMemorySize.ToString());
            propertiesTable.Rows.Add("Physical memory size", process.PhysicalMemorySize.ToString());
            propertiesTable.Rows.Add("Nonpaged system memory size", process.NonpagedSystemMemorySize.ToString());
            propertiesTable.Rows.Add("Paged memory size", process.PagedMemorySize.ToString());
            propertiesTable.Rows.Add("Paged system memory size", process.PagedSystemMemorySize.ToString());
            propertiesTable.Rows.Add("Private memory size", process.PrivateMemorySize.ToString());
        }

        private async void tabControl1_Selected(object sender, TabControlEventArgs e)
        {

            if (e.TabPage == securityTab)
            {
                if (processSecurityObject == null)
                {
                    try
                    {
                        loadingBar.Visible = true;

                        processSecurityObject = await Task.Run(() =>
                        {
                            return DiagnosticsClient.client.GetProcessSecurity(processObject.Id);
                        });

                        userLabel.Text = processSecurityObject.Name;
                        sidLabel.Text = processSecurityObject.PrimarySid;

                        foreach (Privilege privilege in processSecurityObject.Privileges)
                        {
                            privilegeTable.Rows.Add(privilege.Name, privilege.Attributes.ToString());
                        }

                        foreach (GroupObject group in processSecurityObject.Groups)
                        {
                            groupTable.Rows.Add(group.Name, group.Sid);
                        }
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show(ex.Message, "Failed to get process security information", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    } finally
                    {
                        loadingBar.Visible = false;
                        simSecurityLoaded.TrySetResult(true);
                    }
                }
            }
        }

        private void ProcessProperties_Shown(object sender, EventArgs e)
        {
            if (Program.simulation == true)
            {
                tabControl1.SelectTab(securityTab);
            }
        }
    }
}
