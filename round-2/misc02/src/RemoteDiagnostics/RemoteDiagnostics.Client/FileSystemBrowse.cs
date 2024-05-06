using RemoteDiagnostics.Contract;
using System;
using System.IO;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace RemoteDiagnostics.Client
{
    public partial class FileSystemBrowse : Form
    {
        private DirectoryInformationObject currentDir = null;
        private readonly DriveInfo di;

        public TaskCompletionSource<bool> simDirectoryLoaded = new TaskCompletionSource<bool>();

        public FileSystemBrowse(DriveInfo di)
        {
            InitializeComponent();
            Text = di.Name;
            this.di = di;
        }

        private async Task LoadDirectory(string path)
        {
            loader.Visible = true;
            try
            {
                currentDir = await Task.Run(() =>
                {
                    return DiagnosticsClient.client.GetDirectoryInformation(path);
                });

                pathLabel.Text = currentDir.Current.FullName;
                Text = currentDir.Current.FullName;

                fileTable.Rows.Clear();
                if (currentDir.Current != null && currentDir.Current.CreationTime != null)
                {
                    fileTable.Rows.Add(".", "Directory", currentDir.Current.CreationTime.ToString(), currentDir.Current.LastAccessTime.ToString());
                }
                if (currentDir.Parent != null && currentDir.Parent.CreationTime != null)
                {
                    fileTable.Rows.Add("..", "Directory", currentDir.Parent.CreationTime.ToString(), currentDir.Parent.LastAccessTime.ToString());
                }

                foreach (FileSystemInfo fi in currentDir.Children)
                {
                    string type = "File";
                    if (fi.Attributes.HasFlag(FileAttributes.Directory))
                    {
                        type = "Directory";
                    }
                    fileTable.Rows.Add(fi.Name, type, fi.CreationTime.ToString(), fi.LastWriteTime.ToString());
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "Failed to load directory information", MessageBoxButtons.OK, MessageBoxIcon.Error);
            } finally
            {
                simDirectoryLoaded.TrySetResult(true);
            }
            loader.Visible = false;
        }

        private async void FileSystemBrowse_Paint(object sender, PaintEventArgs e)
        {
            if (currentDir == null)
            {
                await LoadDirectory(di.RootDirectory.FullName);
            }
        }

        private async void fileTable_CellDoubleClick(object sender, DataGridViewCellEventArgs e)
        {
            string selectedType = fileTable.Rows[e.RowIndex].Cells[1].Value.ToString();
            if (selectedType != "Directory")
            {
                return;
            }
            string selectedName = fileTable.Rows[e.RowIndex].Cells[0].Value.ToString();
            string fullPath = Path.Combine(currentDir.Current.FullName, selectedName);
            await LoadDirectory(fullPath);
        }
    }
}
