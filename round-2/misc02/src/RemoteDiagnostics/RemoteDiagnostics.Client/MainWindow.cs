using RemoteDiagnostics.Contract;
using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using static System.Windows.Forms.VisualStyles.VisualStyleElement.StartPanel;

namespace RemoteDiagnostics.Client
{
    public partial class MainWindow : Form
    {
        private HostInformationObject hostInformation = null;
        private NetworkInformationObject networkInformation = null;
        private DiskInformationObject diskInformation = null;
        private ProcessObject[] processObjects = null;

        private string selectedNetworkInterfaceName = null;
        private string selectedDisk = null;
        private int selectedProcessId = 0;

        public TaskCompletionSource<bool> simMainWindowDone = new TaskCompletionSource<bool>();
        private TaskCompletionSource<bool> simHostInfoLoaded = new TaskCompletionSource<bool>();
        private TaskCompletionSource<bool> simNetworkInfoLoaded = new TaskCompletionSource<bool>();
        private TaskCompletionSource<bool> simDiskInfoLoaded = new TaskCompletionSource<bool>();
        private TaskCompletionSource<bool> simProcessInfoLoaded = new TaskCompletionSource<bool>();

        public MainWindow()
        {
            InitializeComponent();
        }

        private async Task LoadWhoAmI()
        {
            try
            {
                WhoAmIObject whoAmI = await Task.Run(() =>
                {
                    return DiagnosticsClient.client.WhoAmI();
                });

                string username = whoAmI.Identity.Name;
                string administratorsSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null).ToString();

                bool isAdministrator = whoAmI.Identity.Claims.Any(claim =>
                {
                    return claim.Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid" && claim.Value == administratorsSid;
                });

                string title = string.Format("Remote Diagnostics: {0}@{1}", username, DiagnosticsClient.host);
                if (isAdministrator)
                {
                    title += " (Administrator)";
                }

                Text = title;
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "Failed to get current user identity", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private async Task LoadHostInformation()
        {
            try
            {
                hostInformation = await Task.Run(() =>
                {
                    return DiagnosticsClient.client.GetHostInformation();
                });
                hostInformationTable.Rows.Add("Machine name", hostInformation.MachineName);
                hostInformationTable.Rows.Add("OS version", hostInformation.OSVersion.ToString());
                hostInformationTable.Rows.Add("Processor count", hostInformation.ProcessorCount.ToString());
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "Failed to load host information", MessageBoxButtons.OK, MessageBoxIcon.Error);
            } finally
            {
                simHostInfoLoaded.TrySetResult(true);
            }
        }

        private async Task LoadNetworkInformation()
        {
            try
            {
                networkInformation = await Task.Run(() =>
                {
                    return DiagnosticsClient.client.GetNetworkInformation();
                });

                foreach (Interface ni in networkInformation.Interfaces)
                {
                    networkTable.Rows.Add(ni.Name, ni.Description, ni.Status.ToString());
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "Failed to load network information", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                simNetworkInfoLoaded.TrySetResult(true);
            }
        }


        private async Task LoadDiskInformation()
        {
            try
            {
                diskInformation = await Task.Run(() =>
                {
                    return DiagnosticsClient.client.GetDiskInformation();
                });

                foreach (DriveInfo di in diskInformation.Drives)
                {
                    diskInformationTable.Rows.Add(di.Name, di.VolumeLabel, di.DriveFormat, di.RootDirectory.FullName, di.AvailableFreeSpace.ToString(), di.TotalSize.ToString());
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "Failed to load disk information", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                simDiskInfoLoaded.TrySetResult(true);
            }
        }

        private async Task LoadProcessInformation()
        {
            try
            {
                processObjects = await Task.Run(() =>
                {
                    return DiagnosticsClient.client.GetProcesses();
                });

                foreach (ProcessObject proc in processObjects)
                {
                    processTable.Rows.Add(proc.Id.ToString(), proc.ProcessName, proc.SessionId.ToString(), proc.PrivateMemorySize.ToString());
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "Failed to load disk information", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                simProcessInfoLoaded.TrySetResult(true);
            }
        }


        private async void MainWindow_Load(object sender, EventArgs e)
        {
            await LoadWhoAmI();
        }

        private void MainWindow_FormClosed(object sender, FormClosedEventArgs e)
        {
            DiagnosticsClient.Close();
            Program.connectWindow.Show();
        }

        private void disconnectToolStripMenuItem_Click(object sender, EventArgs e)
        {
            Close();
        }

        private async void hostInformationTab_Paint(object sender, PaintEventArgs e)
        {
            if (hostInformation == null)
            {
                loadingBar.Visible = true;
                await LoadHostInformation();
                loadingBar.Visible = false;
            }
        }

        private async void tabControl1_Selected(object sender, TabControlEventArgs e)
        {
            loadingBar.Visible = true;
            if (e.TabPage == hostInformationTab)
            {
                if (hostInformation == null)
                {
                    await LoadHostInformation();
                }
            }
            if (e.TabPage == networkInformationTab)
            {
                if (networkInformation == null)
                {
                    await LoadNetworkInformation();
                }
            }
            if (e.TabPage == diskInformationTab)
            {
                if (diskInformation == null)
                {
                    await LoadDiskInformation();
                }
            }
            if (e.TabPage == processInformationTab)
            {
                await LoadProcessInformation();
            }
            loadingBar.Visible = false;
        }

        private void networkTable_MouseClick(object sender, MouseEventArgs e)
        {
            if (e.Button == MouseButtons.Right)
            {
                networkInformationContextMenu.Show(Cursor.Position.X, Cursor.Position.Y);
            }
        }

        private void networkTable_CellMouseDown(object sender, DataGridViewCellMouseEventArgs e)
        {
            if (e.RowIndex < 0 || e.ColumnIndex < 0) return;
            networkTable.CurrentCell = networkTable.Rows[e.RowIndex].Cells[e.ColumnIndex];
            networkTable.Rows[e.RowIndex].Selected = true;
            networkTable.Focus();
            selectedNetworkInterfaceName = networkTable.Rows[e.RowIndex].Cells[0].Value.ToString();
        }

        private void propertiesToolStripMenuItem_Click(object sender, EventArgs e)
        {
            Interface networkInterface = Array.Find(networkInformation.Interfaces, ni => ni.Name == selectedNetworkInterfaceName);
            NetworkInterfaceProperties window = new NetworkInterfaceProperties(networkInterface);
            window.Show();
        }

        private void networkTable_CellDoubleClick(object sender, DataGridViewCellEventArgs e)
        {
            if (e.RowIndex < 0 || e.ColumnIndex < 0) return;
            networkTable.CurrentCell = networkTable.Rows[e.RowIndex].Cells[e.ColumnIndex];
            openNetworkInterfaceProperties(e.RowIndex);
        }

        private NetworkInterfaceProperties openNetworkInterfaceProperties(int rowIndex)
        {
            networkTable.Rows[rowIndex].Selected = true;
            networkTable.Focus();
            selectedNetworkInterfaceName = networkTable.Rows[rowIndex].Cells[0].Value.ToString();
            Interface networkInterface = Array.Find(networkInformation.Interfaces, ni => ni.Name == selectedNetworkInterfaceName);
            NetworkInterfaceProperties window = new NetworkInterfaceProperties(networkInterface);
            window.Show();
            return window;
        }

        private void diskInformationTable_MouseClick(object sender, MouseEventArgs e)
        {
            if (e.Button == MouseButtons.Right)
            {
                fileSystemContextMenu.Show(Cursor.Position.X, Cursor.Position.Y);
            }
        }

        private void diskInformationTable_CellMouseDown(object sender, DataGridViewCellMouseEventArgs e)
        {
            if (e.RowIndex < 0 || e.ColumnIndex < 0) return;
            diskInformationTable.CurrentCell = diskInformationTable.Rows[e.RowIndex].Cells[e.ColumnIndex];
            diskInformationTable.Rows[e.RowIndex].Selected = true;
            diskInformationTable.Focus();
            selectedDisk = diskInformationTable.Rows[e.RowIndex].Cells[0].Value.ToString();
        }

        private void diskInformationTable_CellDoubleClick(object sender, DataGridViewCellEventArgs e)
        {
            if (e.RowIndex < 0 || e.ColumnIndex < 0) return;
            diskInformationTable.CurrentCell = diskInformationTable.Rows[e.RowIndex].Cells[e.ColumnIndex];
            openFileSystemBrowse(e.RowIndex);
        }

        private FileSystemBrowse openFileSystemBrowse(int rowIndex)
        {
            diskInformationTable.Rows[rowIndex].Selected = true;
            diskInformationTable.Focus();
            selectedDisk = diskInformationTable.Rows[rowIndex].Cells[0].Value.ToString();
            DriveInfo drive = Array.Find(diskInformation.Drives, di => di.Name == selectedDisk);
            FileSystemBrowse window = new FileSystemBrowse(drive);
            window.Show();
            return window;
        }

        private void toolStripMenuItem1_Click(object sender, EventArgs e)
        {
            DriveInfo drive = Array.Find(diskInformation.Drives, di => di.Name == selectedDisk);
            FileSystemBrowse window = new FileSystemBrowse(drive);
            window.Show();
        }

        private void processTable_MouseClick(object sender, MouseEventArgs e)
        {
            if (e.Button == MouseButtons.Right)
            {
                processContextMenu.Show(Cursor.Position.X, Cursor.Position.Y);
            }
        }

        private void processTable_CellMouseDown(object sender, DataGridViewCellMouseEventArgs e)
        {
            if (e.RowIndex < 0 || e.ColumnIndex < 0) return;
            processTable.CurrentCell = processTable.Rows[e.RowIndex].Cells[e.ColumnIndex];
            processTable.Rows[e.RowIndex].Selected = true;
            processTable.Focus();
            selectedProcessId = int.Parse(processTable.Rows[e.RowIndex].Cells[0].Value.ToString());
        }

        private void processTable_CellDoubleClick(object sender, DataGridViewCellEventArgs e)
        {
            if (e.RowIndex < 0 || e.ColumnIndex < 0) return;
            processTable.CurrentCell = processTable.Rows[e.RowIndex].Cells[e.ColumnIndex];
            openProcessProperties(e.RowIndex);
        }

        private ProcessProperties openProcessProperties(int rowIndex)
        {
            processTable.Rows[rowIndex].Selected = true;
            processTable.Focus();
            selectedProcessId = int.Parse(processTable.Rows[rowIndex].Cells[0].Value.ToString());
            ProcessObject process = Array.Find(processObjects, proc => proc.Id == selectedProcessId);
            ProcessProperties window = new ProcessProperties(process);
            window.Show();
            return window;
        }

        private void toolStripMenuItem2_Click(object sender, EventArgs e)
        {
            ProcessObject process = Array.Find(processObjects, proc => proc.Id == selectedProcessId);
            ProcessProperties window = new ProcessProperties(process);
            window.Show();
        }

        private async void MainWindow_Shown(object sender, EventArgs e)
        {
            if (Program.simulation == true)
            {
                await simHostInfoLoaded.Task;
                await Task.Delay(500);
                tabControl1.SelectTab(networkInformationTab);
                await simNetworkInfoLoaded.Task;
                await Task.Delay(500);
                if (networkTable.Rows.Count > 0)
                {
                    var window = openNetworkInterfaceProperties(0);
                    await window.simWindowLoaded.Task;
                    await Task.Delay(500);
                    window.Close();
                }
                tabControl1.SelectTab(diskInformationTab);
                await simDiskInfoLoaded.Task;
                await Task.Delay(500);
                if (diskInformationTable.Rows.Count > 0)
                {
                    var window = openFileSystemBrowse(0);
                    await window.simDirectoryLoaded.Task;
                    await Task.Delay(500);
                    window.Close();
                }
                tabControl1.SelectTab(processInformationTab);
                await simProcessInfoLoaded.Task;
                if (processTable.Rows.Count > 0)
                {
                    var window = openProcessProperties(0);
                    await window.simSecurityLoaded.Task;
                    await Task.Delay(500);
                    window.Close();
                }
                simMainWindowDone.TrySetResult(true);
            }
        }
    }
}
