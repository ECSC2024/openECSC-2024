using System;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace RemoteDiagnostics.Client
{
    public partial class Connect : Form
    {
        private MainWindow mainWindow = null;
        private TaskCompletionSource<bool> simConnectDone = new TaskCompletionSource<bool>();

        public Connect()
        {
            InitializeComponent();
        }

        private void useCurrentCredentials_CheckedChanged(object sender, EventArgs e)
        {
            bool enabled = !useCurrentCredentials.Checked;
            username.Enabled = enabled;
            password.Enabled = enabled;
        }

        private void hasPermission_CheckedChanged(object sender, EventArgs e)
        {
            bool enabled = hasPermission.Checked && host.Text.Trim().Length > 0;
            connectBtn.Enabled = enabled;
        }

        private void host_TextChanged(object sender, EventArgs e)
        {
            bool enabled = hasPermission.Checked && host.Text.Trim().Length > 0;
            connectBtn.Enabled = enabled;
        }

        private async void connectBtn_Click(object sender, EventArgs e)
        {
            Connecting connecting = new Connecting();
            connecting.Show();

            string username = null;
            string password = null;
            if (useCurrentCredentials.Checked == false)
            {
                username = this.username.Text;
                password = this.password.Text;
            }

            try
            {
                await DiagnosticsClient.Connect(host.Text.Trim(), username, password);
                connecting.Close();
                Hide();
                mainWindow = new MainWindow();
                mainWindow.Show();
                if (Program.simulation == true)
                {
                    await mainWindow.simMainWindowDone.Task;
                }
            }
            catch (Exception ex)
            {
                connecting.Close();
                MessageBox.Show(ex.Message, "Failed to connect", MessageBoxButtons.OK, MessageBoxIcon.Error);
            } finally
            {
                simConnectDone.TrySetResult(true);
            }

        }

        private async void Connect_Shown(object sender, EventArgs e)
        {
            if (Program.simulation == true)
            {
                host.Text = Program.host;
                username.Text = Program.username;
                password.Text = Program.password;
                useCurrentCredentials.Checked = Program.username == null;
                hasPermission.Checked = true;
                connectBtn.PerformClick();
                await simConnectDone.Task;
                await Task.Delay(500);
                Close();
            }
        }
    }
}
