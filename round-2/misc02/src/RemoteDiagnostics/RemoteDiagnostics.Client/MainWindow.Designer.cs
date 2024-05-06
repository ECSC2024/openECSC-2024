namespace RemoteDiagnostics.Client
{
    partial class MainWindow
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.components = new System.ComponentModel.Container();
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(MainWindow));
            this.tableLayoutPanel1 = new System.Windows.Forms.TableLayoutPanel();
            this.menuStrip1 = new System.Windows.Forms.MenuStrip();
            this.connectionToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.disconnectToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.statusStrip1 = new System.Windows.Forms.StatusStrip();
            this.loadingBar = new System.Windows.Forms.ToolStripProgressBar();
            this.tabControl1 = new System.Windows.Forms.TabControl();
            this.hostInformationTab = new System.Windows.Forms.TabPage();
            this.hostInformationTable = new System.Windows.Forms.DataGridView();
            this.HINameCol = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.HIValueCol = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.networkInformationTab = new System.Windows.Forms.TabPage();
            this.networkTable = new System.Windows.Forms.DataGridView();
            this.diskInformationTab = new System.Windows.Forms.TabPage();
            this.diskInformationTable = new System.Windows.Forms.DataGridView();
            this.DINameCol = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.DIVolLabCol = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.DIDriveFormat = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.DIRootDir = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.DIFreeSpace = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.DITotalSize = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.processInformationTab = new System.Windows.Forms.TabPage();
            this.processTable = new System.Windows.Forms.DataGridView();
            this.PIIdCol = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.PINameCol = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.PISessionIDCol = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.PIMemorySize = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.networkInformationContextMenu = new System.Windows.Forms.ContextMenuStrip(this.components);
            this.propertiesToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.fileSystemContextMenu = new System.Windows.Forms.ContextMenuStrip(this.components);
            this.toolStripMenuItem1 = new System.Windows.Forms.ToolStripMenuItem();
            this.processContextMenu = new System.Windows.Forms.ContextMenuStrip(this.components);
            this.toolStripMenuItem2 = new System.Windows.Forms.ToolStripMenuItem();
            this.NameCol = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.DescriptionCol = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.StatusCol = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.tableLayoutPanel1.SuspendLayout();
            this.menuStrip1.SuspendLayout();
            this.statusStrip1.SuspendLayout();
            this.tabControl1.SuspendLayout();
            this.hostInformationTab.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.hostInformationTable)).BeginInit();
            this.networkInformationTab.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.networkTable)).BeginInit();
            this.diskInformationTab.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.diskInformationTable)).BeginInit();
            this.processInformationTab.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.processTable)).BeginInit();
            this.networkInformationContextMenu.SuspendLayout();
            this.fileSystemContextMenu.SuspendLayout();
            this.processContextMenu.SuspendLayout();
            this.SuspendLayout();
            // 
            // tableLayoutPanel1
            // 
            this.tableLayoutPanel1.ColumnCount = 1;
            this.tableLayoutPanel1.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 100F));
            this.tableLayoutPanel1.Controls.Add(this.menuStrip1, 0, 0);
            this.tableLayoutPanel1.Controls.Add(this.statusStrip1, 0, 2);
            this.tableLayoutPanel1.Controls.Add(this.tabControl1, 0, 1);
            this.tableLayoutPanel1.Dock = System.Windows.Forms.DockStyle.Fill;
            this.tableLayoutPanel1.Location = new System.Drawing.Point(0, 0);
            this.tableLayoutPanel1.Name = "tableLayoutPanel1";
            this.tableLayoutPanel1.RowCount = 3;
            this.tableLayoutPanel1.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Absolute, 23F));
            this.tableLayoutPanel1.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Percent, 100F));
            this.tableLayoutPanel1.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Absolute, 23F));
            this.tableLayoutPanel1.Size = new System.Drawing.Size(962, 603);
            this.tableLayoutPanel1.TabIndex = 0;
            // 
            // menuStrip1
            // 
            this.menuStrip1.ImageScalingSize = new System.Drawing.Size(24, 24);
            this.menuStrip1.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.connectionToolStripMenuItem});
            this.menuStrip1.Location = new System.Drawing.Point(0, 0);
            this.menuStrip1.Name = "menuStrip1";
            this.menuStrip1.Size = new System.Drawing.Size(962, 23);
            this.menuStrip1.TabIndex = 0;
            this.menuStrip1.Text = "menuStrip1";
            // 
            // connectionToolStripMenuItem
            // 
            this.connectionToolStripMenuItem.DropDownItems.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.disconnectToolStripMenuItem});
            this.connectionToolStripMenuItem.Name = "connectionToolStripMenuItem";
            this.connectionToolStripMenuItem.Size = new System.Drawing.Size(81, 19);
            this.connectionToolStripMenuItem.Text = "Connection";
            // 
            // disconnectToolStripMenuItem
            // 
            this.disconnectToolStripMenuItem.Name = "disconnectToolStripMenuItem";
            this.disconnectToolStripMenuItem.Size = new System.Drawing.Size(133, 22);
            this.disconnectToolStripMenuItem.Text = "Disconnect";
            this.disconnectToolStripMenuItem.Click += new System.EventHandler(this.disconnectToolStripMenuItem_Click);
            // 
            // statusStrip1
            // 
            this.statusStrip1.ImageScalingSize = new System.Drawing.Size(24, 24);
            this.statusStrip1.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.loadingBar});
            this.statusStrip1.Location = new System.Drawing.Point(0, 581);
            this.statusStrip1.Name = "statusStrip1";
            this.statusStrip1.Size = new System.Drawing.Size(962, 22);
            this.statusStrip1.TabIndex = 1;
            this.statusStrip1.Text = "statusStrip1";
            // 
            // loadingBar
            // 
            this.loadingBar.Name = "loadingBar";
            this.loadingBar.Size = new System.Drawing.Size(100, 16);
            this.loadingBar.Style = System.Windows.Forms.ProgressBarStyle.Marquee;
            // 
            // tabControl1
            // 
            this.tabControl1.Controls.Add(this.hostInformationTab);
            this.tabControl1.Controls.Add(this.networkInformationTab);
            this.tabControl1.Controls.Add(this.diskInformationTab);
            this.tabControl1.Controls.Add(this.processInformationTab);
            this.tabControl1.Dock = System.Windows.Forms.DockStyle.Fill;
            this.tabControl1.Location = new System.Drawing.Point(3, 26);
            this.tabControl1.Name = "tabControl1";
            this.tabControl1.SelectedIndex = 0;
            this.tabControl1.Size = new System.Drawing.Size(956, 551);
            this.tabControl1.TabIndex = 2;
            this.tabControl1.Selected += new System.Windows.Forms.TabControlEventHandler(this.tabControl1_Selected);
            // 
            // hostInformationTab
            // 
            this.hostInformationTab.Controls.Add(this.hostInformationTable);
            this.hostInformationTab.Location = new System.Drawing.Point(4, 22);
            this.hostInformationTab.Name = "hostInformationTab";
            this.hostInformationTab.Size = new System.Drawing.Size(948, 525);
            this.hostInformationTab.TabIndex = 0;
            this.hostInformationTab.Text = "Host information";
            this.hostInformationTab.UseVisualStyleBackColor = true;
            this.hostInformationTab.Paint += new System.Windows.Forms.PaintEventHandler(this.hostInformationTab_Paint);
            // 
            // hostInformationTable
            // 
            this.hostInformationTable.AllowUserToAddRows = false;
            this.hostInformationTable.AllowUserToDeleteRows = false;
            this.hostInformationTable.AllowUserToOrderColumns = true;
            this.hostInformationTable.AllowUserToResizeRows = false;
            this.hostInformationTable.AutoSizeColumnsMode = System.Windows.Forms.DataGridViewAutoSizeColumnsMode.Fill;
            this.hostInformationTable.BackgroundColor = System.Drawing.SystemColors.Window;
            this.hostInformationTable.BorderStyle = System.Windows.Forms.BorderStyle.None;
            this.hostInformationTable.ColumnHeadersHeightSizeMode = System.Windows.Forms.DataGridViewColumnHeadersHeightSizeMode.AutoSize;
            this.hostInformationTable.Columns.AddRange(new System.Windows.Forms.DataGridViewColumn[] {
            this.HINameCol,
            this.HIValueCol});
            this.hostInformationTable.Dock = System.Windows.Forms.DockStyle.Fill;
            this.hostInformationTable.Location = new System.Drawing.Point(0, 0);
            this.hostInformationTable.Margin = new System.Windows.Forms.Padding(0);
            this.hostInformationTable.Name = "hostInformationTable";
            this.hostInformationTable.ReadOnly = true;
            this.hostInformationTable.RowHeadersVisible = false;
            this.hostInformationTable.SelectionMode = System.Windows.Forms.DataGridViewSelectionMode.FullRowSelect;
            this.hostInformationTable.Size = new System.Drawing.Size(948, 525);
            this.hostInformationTable.TabIndex = 2;
            // 
            // HINameCol
            // 
            this.HINameCol.HeaderText = "Name";
            this.HINameCol.Name = "HINameCol";
            this.HINameCol.ReadOnly = true;
            // 
            // HIValueCol
            // 
            this.HIValueCol.HeaderText = "Value";
            this.HIValueCol.Name = "HIValueCol";
            this.HIValueCol.ReadOnly = true;
            // 
            // networkInformationTab
            // 
            this.networkInformationTab.Controls.Add(this.networkTable);
            this.networkInformationTab.Location = new System.Drawing.Point(4, 22);
            this.networkInformationTab.Name = "networkInformationTab";
            this.networkInformationTab.Size = new System.Drawing.Size(948, 525);
            this.networkInformationTab.TabIndex = 1;
            this.networkInformationTab.Text = "Network information";
            this.networkInformationTab.UseVisualStyleBackColor = true;
            // 
            // networkTable
            // 
            this.networkTable.AllowUserToAddRows = false;
            this.networkTable.AllowUserToDeleteRows = false;
            this.networkTable.AllowUserToOrderColumns = true;
            this.networkTable.AllowUserToResizeRows = false;
            this.networkTable.AutoSizeColumnsMode = System.Windows.Forms.DataGridViewAutoSizeColumnsMode.Fill;
            this.networkTable.BackgroundColor = System.Drawing.SystemColors.Window;
            this.networkTable.BorderStyle = System.Windows.Forms.BorderStyle.None;
            this.networkTable.ColumnHeadersHeightSizeMode = System.Windows.Forms.DataGridViewColumnHeadersHeightSizeMode.AutoSize;
            this.networkTable.Columns.AddRange(new System.Windows.Forms.DataGridViewColumn[] {
            this.NameCol,
            this.DescriptionCol,
            this.StatusCol});
            this.networkTable.Dock = System.Windows.Forms.DockStyle.Fill;
            this.networkTable.Location = new System.Drawing.Point(0, 0);
            this.networkTable.Margin = new System.Windows.Forms.Padding(0);
            this.networkTable.Name = "networkTable";
            this.networkTable.ReadOnly = true;
            this.networkTable.RowHeadersVisible = false;
            this.networkTable.SelectionMode = System.Windows.Forms.DataGridViewSelectionMode.FullRowSelect;
            this.networkTable.Size = new System.Drawing.Size(948, 525);
            this.networkTable.TabIndex = 1;
            this.networkTable.CellDoubleClick += new System.Windows.Forms.DataGridViewCellEventHandler(this.networkTable_CellDoubleClick);
            this.networkTable.CellMouseDown += new System.Windows.Forms.DataGridViewCellMouseEventHandler(this.networkTable_CellMouseDown);
            this.networkTable.MouseClick += new System.Windows.Forms.MouseEventHandler(this.networkTable_MouseClick);
            // 
            // diskInformationTab
            // 
            this.diskInformationTab.Controls.Add(this.diskInformationTable);
            this.diskInformationTab.Location = new System.Drawing.Point(4, 22);
            this.diskInformationTab.Name = "diskInformationTab";
            this.diskInformationTab.Size = new System.Drawing.Size(948, 525);
            this.diskInformationTab.TabIndex = 2;
            this.diskInformationTab.Text = "Disk information";
            this.diskInformationTab.UseVisualStyleBackColor = true;
            // 
            // diskInformationTable
            // 
            this.diskInformationTable.AllowUserToAddRows = false;
            this.diskInformationTable.AllowUserToDeleteRows = false;
            this.diskInformationTable.AllowUserToOrderColumns = true;
            this.diskInformationTable.AllowUserToResizeRows = false;
            this.diskInformationTable.AutoSizeColumnsMode = System.Windows.Forms.DataGridViewAutoSizeColumnsMode.Fill;
            this.diskInformationTable.BackgroundColor = System.Drawing.SystemColors.Window;
            this.diskInformationTable.BorderStyle = System.Windows.Forms.BorderStyle.None;
            this.diskInformationTable.ColumnHeadersHeightSizeMode = System.Windows.Forms.DataGridViewColumnHeadersHeightSizeMode.AutoSize;
            this.diskInformationTable.Columns.AddRange(new System.Windows.Forms.DataGridViewColumn[] {
            this.DINameCol,
            this.DIVolLabCol,
            this.DIDriveFormat,
            this.DIRootDir,
            this.DIFreeSpace,
            this.DITotalSize});
            this.diskInformationTable.Dock = System.Windows.Forms.DockStyle.Fill;
            this.diskInformationTable.Location = new System.Drawing.Point(0, 0);
            this.diskInformationTable.Margin = new System.Windows.Forms.Padding(0);
            this.diskInformationTable.Name = "diskInformationTable";
            this.diskInformationTable.ReadOnly = true;
            this.diskInformationTable.RowHeadersVisible = false;
            this.diskInformationTable.SelectionMode = System.Windows.Forms.DataGridViewSelectionMode.FullRowSelect;
            this.diskInformationTable.Size = new System.Drawing.Size(948, 525);
            this.diskInformationTable.TabIndex = 3;
            this.diskInformationTable.CellDoubleClick += new System.Windows.Forms.DataGridViewCellEventHandler(this.diskInformationTable_CellDoubleClick);
            this.diskInformationTable.CellMouseDown += new System.Windows.Forms.DataGridViewCellMouseEventHandler(this.diskInformationTable_CellMouseDown);
            this.diskInformationTable.MouseClick += new System.Windows.Forms.MouseEventHandler(this.diskInformationTable_MouseClick);
            // 
            // DINameCol
            // 
            this.DINameCol.HeaderText = "Name";
            this.DINameCol.Name = "DINameCol";
            this.DINameCol.ReadOnly = true;
            // 
            // DIVolLabCol
            // 
            this.DIVolLabCol.HeaderText = "Volume label";
            this.DIVolLabCol.Name = "DIVolLabCol";
            this.DIVolLabCol.ReadOnly = true;
            // 
            // DIDriveFormat
            // 
            this.DIDriveFormat.HeaderText = "Drive format";
            this.DIDriveFormat.Name = "DIDriveFormat";
            this.DIDriveFormat.ReadOnly = true;
            // 
            // DIRootDir
            // 
            this.DIRootDir.HeaderText = "Root directory";
            this.DIRootDir.Name = "DIRootDir";
            this.DIRootDir.ReadOnly = true;
            // 
            // DIFreeSpace
            // 
            this.DIFreeSpace.HeaderText = "Free space";
            this.DIFreeSpace.Name = "DIFreeSpace";
            this.DIFreeSpace.ReadOnly = true;
            // 
            // DITotalSize
            // 
            this.DITotalSize.HeaderText = "Total size";
            this.DITotalSize.Name = "DITotalSize";
            this.DITotalSize.ReadOnly = true;
            // 
            // processInformationTab
            // 
            this.processInformationTab.Controls.Add(this.processTable);
            this.processInformationTab.Location = new System.Drawing.Point(4, 22);
            this.processInformationTab.Name = "processInformationTab";
            this.processInformationTab.Size = new System.Drawing.Size(948, 525);
            this.processInformationTab.TabIndex = 3;
            this.processInformationTab.Text = "Process information";
            this.processInformationTab.UseVisualStyleBackColor = true;
            // 
            // processTable
            // 
            this.processTable.AllowUserToAddRows = false;
            this.processTable.AllowUserToDeleteRows = false;
            this.processTable.AllowUserToOrderColumns = true;
            this.processTable.AllowUserToResizeRows = false;
            this.processTable.AutoSizeColumnsMode = System.Windows.Forms.DataGridViewAutoSizeColumnsMode.Fill;
            this.processTable.BackgroundColor = System.Drawing.SystemColors.Window;
            this.processTable.BorderStyle = System.Windows.Forms.BorderStyle.None;
            this.processTable.ColumnHeadersHeightSizeMode = System.Windows.Forms.DataGridViewColumnHeadersHeightSizeMode.AutoSize;
            this.processTable.Columns.AddRange(new System.Windows.Forms.DataGridViewColumn[] {
            this.PIIdCol,
            this.PINameCol,
            this.PISessionIDCol,
            this.PIMemorySize});
            this.processTable.Dock = System.Windows.Forms.DockStyle.Fill;
            this.processTable.Location = new System.Drawing.Point(0, 0);
            this.processTable.Margin = new System.Windows.Forms.Padding(0);
            this.processTable.Name = "processTable";
            this.processTable.ReadOnly = true;
            this.processTable.RowHeadersVisible = false;
            this.processTable.SelectionMode = System.Windows.Forms.DataGridViewSelectionMode.FullRowSelect;
            this.processTable.Size = new System.Drawing.Size(948, 525);
            this.processTable.TabIndex = 4;
            this.processTable.CellDoubleClick += new System.Windows.Forms.DataGridViewCellEventHandler(this.processTable_CellDoubleClick);
            this.processTable.CellMouseDown += new System.Windows.Forms.DataGridViewCellMouseEventHandler(this.processTable_CellMouseDown);
            this.processTable.MouseClick += new System.Windows.Forms.MouseEventHandler(this.processTable_MouseClick);
            // 
            // PIIdCol
            // 
            this.PIIdCol.HeaderText = "ID";
            this.PIIdCol.Name = "PIIdCol";
            this.PIIdCol.ReadOnly = true;
            // 
            // PINameCol
            // 
            this.PINameCol.HeaderText = "Name";
            this.PINameCol.Name = "PINameCol";
            this.PINameCol.ReadOnly = true;
            // 
            // PISessionIDCol
            // 
            this.PISessionIDCol.HeaderText = "Session ID";
            this.PISessionIDCol.Name = "PISessionIDCol";
            this.PISessionIDCol.ReadOnly = true;
            // 
            // PIMemorySize
            // 
            this.PIMemorySize.HeaderText = "Memory size";
            this.PIMemorySize.Name = "PIMemorySize";
            this.PIMemorySize.ReadOnly = true;
            // 
            // networkInformationContextMenu
            // 
            this.networkInformationContextMenu.ImageScalingSize = new System.Drawing.Size(24, 24);
            this.networkInformationContextMenu.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.propertiesToolStripMenuItem});
            this.networkInformationContextMenu.Name = "networkInformationContextMenu";
            this.networkInformationContextMenu.Size = new System.Drawing.Size(128, 26);
            // 
            // propertiesToolStripMenuItem
            // 
            this.propertiesToolStripMenuItem.Name = "propertiesToolStripMenuItem";
            this.propertiesToolStripMenuItem.Size = new System.Drawing.Size(127, 22);
            this.propertiesToolStripMenuItem.Text = "Properties";
            this.propertiesToolStripMenuItem.Click += new System.EventHandler(this.propertiesToolStripMenuItem_Click);
            // 
            // fileSystemContextMenu
            // 
            this.fileSystemContextMenu.ImageScalingSize = new System.Drawing.Size(24, 24);
            this.fileSystemContextMenu.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.toolStripMenuItem1});
            this.fileSystemContextMenu.Name = "networkInformationContextMenu";
            this.fileSystemContextMenu.Size = new System.Drawing.Size(113, 26);
            // 
            // toolStripMenuItem1
            // 
            this.toolStripMenuItem1.Name = "toolStripMenuItem1";
            this.toolStripMenuItem1.Size = new System.Drawing.Size(112, 22);
            this.toolStripMenuItem1.Text = "Browse";
            this.toolStripMenuItem1.Click += new System.EventHandler(this.toolStripMenuItem1_Click);
            // 
            // processContextMenu
            // 
            this.processContextMenu.ImageScalingSize = new System.Drawing.Size(24, 24);
            this.processContextMenu.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.toolStripMenuItem2});
            this.processContextMenu.Name = "networkInformationContextMenu";
            this.processContextMenu.Size = new System.Drawing.Size(128, 26);
            // 
            // toolStripMenuItem2
            // 
            this.toolStripMenuItem2.Name = "toolStripMenuItem2";
            this.toolStripMenuItem2.Size = new System.Drawing.Size(127, 22);
            this.toolStripMenuItem2.Text = "Properties";
            this.toolStripMenuItem2.Click += new System.EventHandler(this.toolStripMenuItem2_Click);
            // 
            // NameCol
            // 
            this.NameCol.HeaderText = "Name";
            this.NameCol.Name = "NameCol";
            this.NameCol.ReadOnly = true;
            // 
            // DescriptionCol
            // 
            this.DescriptionCol.HeaderText = "Description";
            this.DescriptionCol.Name = "DescriptionCol";
            this.DescriptionCol.ReadOnly = true;
            // 
            // StatusCol
            // 
            this.StatusCol.HeaderText = "Status";
            this.StatusCol.Name = "StatusCol";
            this.StatusCol.ReadOnly = true;
            // 
            // MainWindow
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(962, 603);
            this.Controls.Add(this.tableLayoutPanel1);
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.MainMenuStrip = this.menuStrip1;
            this.Name = "MainWindow";
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
            this.Text = "Remote Diagnostics";
            this.FormClosed += new System.Windows.Forms.FormClosedEventHandler(this.MainWindow_FormClosed);
            this.Load += new System.EventHandler(this.MainWindow_Load);
            this.Shown += new System.EventHandler(this.MainWindow_Shown);
            this.tableLayoutPanel1.ResumeLayout(false);
            this.tableLayoutPanel1.PerformLayout();
            this.menuStrip1.ResumeLayout(false);
            this.menuStrip1.PerformLayout();
            this.statusStrip1.ResumeLayout(false);
            this.statusStrip1.PerformLayout();
            this.tabControl1.ResumeLayout(false);
            this.hostInformationTab.ResumeLayout(false);
            ((System.ComponentModel.ISupportInitialize)(this.hostInformationTable)).EndInit();
            this.networkInformationTab.ResumeLayout(false);
            ((System.ComponentModel.ISupportInitialize)(this.networkTable)).EndInit();
            this.diskInformationTab.ResumeLayout(false);
            ((System.ComponentModel.ISupportInitialize)(this.diskInformationTable)).EndInit();
            this.processInformationTab.ResumeLayout(false);
            ((System.ComponentModel.ISupportInitialize)(this.processTable)).EndInit();
            this.networkInformationContextMenu.ResumeLayout(false);
            this.fileSystemContextMenu.ResumeLayout(false);
            this.processContextMenu.ResumeLayout(false);
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.TableLayoutPanel tableLayoutPanel1;
        private System.Windows.Forms.MenuStrip menuStrip1;
        private System.Windows.Forms.ToolStripMenuItem connectionToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem disconnectToolStripMenuItem;
        private System.Windows.Forms.StatusStrip statusStrip1;
        private System.Windows.Forms.ToolStripProgressBar loadingBar;
        private System.Windows.Forms.TabControl tabControl1;
        private System.Windows.Forms.TabPage hostInformationTab;
        private System.Windows.Forms.DataGridView hostInformationTable;
        private System.Windows.Forms.DataGridViewTextBoxColumn HINameCol;
        private System.Windows.Forms.DataGridViewTextBoxColumn HIValueCol;
        private System.Windows.Forms.TabPage networkInformationTab;
        private System.Windows.Forms.TabPage diskInformationTab;
        private System.Windows.Forms.TabPage processInformationTab;
        private System.Windows.Forms.DataGridView networkTable;
        private System.Windows.Forms.DataGridView diskInformationTable;
        private System.Windows.Forms.DataGridViewTextBoxColumn DINameCol;
        private System.Windows.Forms.DataGridViewTextBoxColumn DIVolLabCol;
        private System.Windows.Forms.DataGridViewTextBoxColumn DIDriveFormat;
        private System.Windows.Forms.DataGridViewTextBoxColumn DIRootDir;
        private System.Windows.Forms.DataGridViewTextBoxColumn DIFreeSpace;
        private System.Windows.Forms.DataGridViewTextBoxColumn DITotalSize;
        private System.Windows.Forms.DataGridView processTable;
        private System.Windows.Forms.DataGridViewTextBoxColumn PIIdCol;
        private System.Windows.Forms.DataGridViewTextBoxColumn PINameCol;
        private System.Windows.Forms.DataGridViewTextBoxColumn PISessionIDCol;
        private System.Windows.Forms.DataGridViewTextBoxColumn PIMemorySize;
        private System.Windows.Forms.ContextMenuStrip networkInformationContextMenu;
        private System.Windows.Forms.ToolStripMenuItem propertiesToolStripMenuItem;
        private System.Windows.Forms.ContextMenuStrip fileSystemContextMenu;
        private System.Windows.Forms.ToolStripMenuItem toolStripMenuItem1;
        private System.Windows.Forms.ContextMenuStrip processContextMenu;
        private System.Windows.Forms.ToolStripMenuItem toolStripMenuItem2;
        private System.Windows.Forms.DataGridViewTextBoxColumn NameCol;
        private System.Windows.Forms.DataGridViewTextBoxColumn DescriptionCol;
        private System.Windows.Forms.DataGridViewTextBoxColumn StatusCol;
    }
}