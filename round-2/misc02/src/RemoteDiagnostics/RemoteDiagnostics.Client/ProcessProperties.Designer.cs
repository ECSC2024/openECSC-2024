namespace RemoteDiagnostics.Client
{
    partial class ProcessProperties
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
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(ProcessProperties));
            this.tableLayoutPanel1 = new System.Windows.Forms.TableLayoutPanel();
            this.statusStrip1 = new System.Windows.Forms.StatusStrip();
            this.loadingBar = new System.Windows.Forms.ToolStripProgressBar();
            this.tabControl1 = new System.Windows.Forms.TabControl();
            this.propertiesTab = new System.Windows.Forms.TabPage();
            this.securityTab = new System.Windows.Forms.TabPage();
            this.propertiesTable = new System.Windows.Forms.DataGridView();
            this.PNameCol = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.PValueCol = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.tableLayoutPanel2 = new System.Windows.Forms.TableLayoutPanel();
            this.panel1 = new System.Windows.Forms.Panel();
            this.panel2 = new System.Windows.Forms.Panel();
            this.panel3 = new System.Windows.Forms.Panel();
            this.label1 = new System.Windows.Forms.Label();
            this.label2 = new System.Windows.Forms.Label();
            this.sidLabel = new System.Windows.Forms.Label();
            this.userLabel = new System.Windows.Forms.Label();
            this.groupTable = new System.Windows.Forms.DataGridView();
            this.dataGridViewTextBoxColumn3 = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.GroupSidCol = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.privilegeTable = new System.Windows.Forms.DataGridView();
            this.PrivilegeCol = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.FlagsCol = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.tableLayoutPanel1.SuspendLayout();
            this.statusStrip1.SuspendLayout();
            this.tabControl1.SuspendLayout();
            this.propertiesTab.SuspendLayout();
            this.securityTab.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.propertiesTable)).BeginInit();
            this.tableLayoutPanel2.SuspendLayout();
            this.panel1.SuspendLayout();
            this.panel2.SuspendLayout();
            this.panel3.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.groupTable)).BeginInit();
            ((System.ComponentModel.ISupportInitialize)(this.privilegeTable)).BeginInit();
            this.SuspendLayout();
            // 
            // tableLayoutPanel1
            // 
            this.tableLayoutPanel1.ColumnCount = 1;
            this.tableLayoutPanel1.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 100F));
            this.tableLayoutPanel1.Controls.Add(this.statusStrip1, 0, 1);
            this.tableLayoutPanel1.Controls.Add(this.tabControl1, 0, 0);
            this.tableLayoutPanel1.Dock = System.Windows.Forms.DockStyle.Fill;
            this.tableLayoutPanel1.Location = new System.Drawing.Point(0, 0);
            this.tableLayoutPanel1.Name = "tableLayoutPanel1";
            this.tableLayoutPanel1.RowCount = 2;
            this.tableLayoutPanel1.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Percent, 100F));
            this.tableLayoutPanel1.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Absolute, 23F));
            this.tableLayoutPanel1.Size = new System.Drawing.Size(800, 450);
            this.tableLayoutPanel1.TabIndex = 0;
            // 
            // statusStrip1
            // 
            this.statusStrip1.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.loadingBar});
            this.statusStrip1.Location = new System.Drawing.Point(0, 428);
            this.statusStrip1.Name = "statusStrip1";
            this.statusStrip1.Size = new System.Drawing.Size(800, 22);
            this.statusStrip1.TabIndex = 0;
            this.statusStrip1.Text = "statusStrip1";
            // 
            // loadingBar
            // 
            this.loadingBar.Name = "loadingBar";
            this.loadingBar.Size = new System.Drawing.Size(100, 16);
            this.loadingBar.Style = System.Windows.Forms.ProgressBarStyle.Marquee;
            this.loadingBar.Visible = false;
            // 
            // tabControl1
            // 
            this.tabControl1.Controls.Add(this.propertiesTab);
            this.tabControl1.Controls.Add(this.securityTab);
            this.tabControl1.Dock = System.Windows.Forms.DockStyle.Fill;
            this.tabControl1.Location = new System.Drawing.Point(3, 3);
            this.tabControl1.Name = "tabControl1";
            this.tabControl1.SelectedIndex = 0;
            this.tabControl1.Size = new System.Drawing.Size(794, 421);
            this.tabControl1.TabIndex = 1;
            this.tabControl1.Selected += new System.Windows.Forms.TabControlEventHandler(this.tabControl1_Selected);
            // 
            // propertiesTab
            // 
            this.propertiesTab.Controls.Add(this.propertiesTable);
            this.propertiesTab.Location = new System.Drawing.Point(4, 22);
            this.propertiesTab.Name = "propertiesTab";
            this.propertiesTab.Padding = new System.Windows.Forms.Padding(3);
            this.propertiesTab.Size = new System.Drawing.Size(786, 395);
            this.propertiesTab.TabIndex = 0;
            this.propertiesTab.Text = "Properties";
            this.propertiesTab.UseVisualStyleBackColor = true;
            // 
            // securityTab
            // 
            this.securityTab.Controls.Add(this.tableLayoutPanel2);
            this.securityTab.Location = new System.Drawing.Point(4, 22);
            this.securityTab.Name = "securityTab";
            this.securityTab.Padding = new System.Windows.Forms.Padding(3);
            this.securityTab.Size = new System.Drawing.Size(786, 395);
            this.securityTab.TabIndex = 1;
            this.securityTab.Text = "Security";
            this.securityTab.UseVisualStyleBackColor = true;
            // 
            // propertiesTable
            // 
            this.propertiesTable.AllowUserToAddRows = false;
            this.propertiesTable.AllowUserToDeleteRows = false;
            this.propertiesTable.AllowUserToResizeRows = false;
            this.propertiesTable.AutoSizeColumnsMode = System.Windows.Forms.DataGridViewAutoSizeColumnsMode.Fill;
            this.propertiesTable.BackgroundColor = System.Drawing.SystemColors.Window;
            this.propertiesTable.BorderStyle = System.Windows.Forms.BorderStyle.None;
            this.propertiesTable.ColumnHeadersHeightSizeMode = System.Windows.Forms.DataGridViewColumnHeadersHeightSizeMode.AutoSize;
            this.propertiesTable.Columns.AddRange(new System.Windows.Forms.DataGridViewColumn[] {
            this.PNameCol,
            this.PValueCol});
            this.propertiesTable.Dock = System.Windows.Forms.DockStyle.Fill;
            this.propertiesTable.Location = new System.Drawing.Point(3, 3);
            this.propertiesTable.Margin = new System.Windows.Forms.Padding(0);
            this.propertiesTable.Name = "propertiesTable";
            this.propertiesTable.ReadOnly = true;
            this.propertiesTable.RowHeadersVisible = false;
            this.propertiesTable.SelectionMode = System.Windows.Forms.DataGridViewSelectionMode.FullRowSelect;
            this.propertiesTable.Size = new System.Drawing.Size(780, 389);
            this.propertiesTable.TabIndex = 1;
            // 
            // PNameCol
            // 
            this.PNameCol.HeaderText = "Name";
            this.PNameCol.Name = "PNameCol";
            this.PNameCol.ReadOnly = true;
            // 
            // PValueCol
            // 
            this.PValueCol.HeaderText = "Value";
            this.PValueCol.Name = "PValueCol";
            this.PValueCol.ReadOnly = true;
            // 
            // tableLayoutPanel2
            // 
            this.tableLayoutPanel2.ColumnCount = 1;
            this.tableLayoutPanel2.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 100F));
            this.tableLayoutPanel2.Controls.Add(this.panel1, 0, 0);
            this.tableLayoutPanel2.Controls.Add(this.panel2, 0, 1);
            this.tableLayoutPanel2.Controls.Add(this.panel3, 0, 2);
            this.tableLayoutPanel2.Dock = System.Windows.Forms.DockStyle.Fill;
            this.tableLayoutPanel2.Location = new System.Drawing.Point(3, 3);
            this.tableLayoutPanel2.Name = "tableLayoutPanel2";
            this.tableLayoutPanel2.RowCount = 3;
            this.tableLayoutPanel2.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Absolute, 64F));
            this.tableLayoutPanel2.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Percent, 50F));
            this.tableLayoutPanel2.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Percent, 50F));
            this.tableLayoutPanel2.Size = new System.Drawing.Size(780, 389);
            this.tableLayoutPanel2.TabIndex = 0;
            // 
            // panel1
            // 
            this.panel1.Controls.Add(this.sidLabel);
            this.panel1.Controls.Add(this.userLabel);
            this.panel1.Controls.Add(this.label2);
            this.panel1.Controls.Add(this.label1);
            this.panel1.Dock = System.Windows.Forms.DockStyle.Fill;
            this.panel1.Location = new System.Drawing.Point(3, 3);
            this.panel1.Name = "panel1";
            this.panel1.Size = new System.Drawing.Size(774, 58);
            this.panel1.TabIndex = 0;
            // 
            // panel2
            // 
            this.panel2.BorderStyle = System.Windows.Forms.BorderStyle.FixedSingle;
            this.panel2.Controls.Add(this.groupTable);
            this.panel2.Dock = System.Windows.Forms.DockStyle.Fill;
            this.panel2.Location = new System.Drawing.Point(3, 67);
            this.panel2.Name = "panel2";
            this.panel2.Size = new System.Drawing.Size(774, 156);
            this.panel2.TabIndex = 1;
            // 
            // panel3
            // 
            this.panel3.BorderStyle = System.Windows.Forms.BorderStyle.FixedSingle;
            this.panel3.Controls.Add(this.privilegeTable);
            this.panel3.Dock = System.Windows.Forms.DockStyle.Fill;
            this.panel3.Location = new System.Drawing.Point(3, 229);
            this.panel3.Name = "panel3";
            this.panel3.Size = new System.Drawing.Size(774, 157);
            this.panel3.TabIndex = 2;
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(10, 10);
            this.label1.Margin = new System.Windows.Forms.Padding(10);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(32, 13);
            this.label1.TabIndex = 0;
            this.label1.Text = "User:";
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.Location = new System.Drawing.Point(10, 33);
            this.label2.Margin = new System.Windows.Forms.Padding(10, 0, 10, 10);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(28, 13);
            this.label2.TabIndex = 1;
            this.label2.Text = "SID:";
            // 
            // sidLabel
            // 
            this.sidLabel.AutoSize = true;
            this.sidLabel.Location = new System.Drawing.Point(52, 33);
            this.sidLabel.Margin = new System.Windows.Forms.Padding(10, 0, 10, 10);
            this.sidLabel.Name = "sidLabel";
            this.sidLabel.Size = new System.Drawing.Size(0, 13);
            this.sidLabel.TabIndex = 3;
            // 
            // userLabel
            // 
            this.userLabel.AutoSize = true;
            this.userLabel.Location = new System.Drawing.Point(52, 10);
            this.userLabel.Margin = new System.Windows.Forms.Padding(10);
            this.userLabel.Name = "userLabel";
            this.userLabel.Size = new System.Drawing.Size(0, 13);
            this.userLabel.TabIndex = 2;
            // 
            // groupTable
            // 
            this.groupTable.AllowUserToAddRows = false;
            this.groupTable.AllowUserToDeleteRows = false;
            this.groupTable.AllowUserToResizeRows = false;
            this.groupTable.AutoSizeColumnsMode = System.Windows.Forms.DataGridViewAutoSizeColumnsMode.Fill;
            this.groupTable.BackgroundColor = System.Drawing.SystemColors.Window;
            this.groupTable.BorderStyle = System.Windows.Forms.BorderStyle.None;
            this.groupTable.ColumnHeadersHeightSizeMode = System.Windows.Forms.DataGridViewColumnHeadersHeightSizeMode.AutoSize;
            this.groupTable.Columns.AddRange(new System.Windows.Forms.DataGridViewColumn[] {
            this.dataGridViewTextBoxColumn3,
            this.GroupSidCol});
            this.groupTable.Dock = System.Windows.Forms.DockStyle.Fill;
            this.groupTable.Location = new System.Drawing.Point(0, 0);
            this.groupTable.Name = "groupTable";
            this.groupTable.ReadOnly = true;
            this.groupTable.RowHeadersVisible = false;
            this.groupTable.SelectionMode = System.Windows.Forms.DataGridViewSelectionMode.FullRowSelect;
            this.groupTable.Size = new System.Drawing.Size(772, 154);
            this.groupTable.TabIndex = 3;
            // 
            // dataGridViewTextBoxColumn3
            // 
            this.dataGridViewTextBoxColumn3.HeaderText = "Group";
            this.dataGridViewTextBoxColumn3.Name = "dataGridViewTextBoxColumn3";
            this.dataGridViewTextBoxColumn3.ReadOnly = true;
            // 
            // GroupSidCol
            // 
            this.GroupSidCol.HeaderText = "SID";
            this.GroupSidCol.Name = "GroupSidCol";
            this.GroupSidCol.ReadOnly = true;
            // 
            // privilegeTable
            // 
            this.privilegeTable.AllowUserToAddRows = false;
            this.privilegeTable.AllowUserToDeleteRows = false;
            this.privilegeTable.AllowUserToResizeRows = false;
            this.privilegeTable.AutoSizeColumnsMode = System.Windows.Forms.DataGridViewAutoSizeColumnsMode.Fill;
            this.privilegeTable.BackgroundColor = System.Drawing.SystemColors.Window;
            this.privilegeTable.BorderStyle = System.Windows.Forms.BorderStyle.None;
            this.privilegeTable.ColumnHeadersHeightSizeMode = System.Windows.Forms.DataGridViewColumnHeadersHeightSizeMode.AutoSize;
            this.privilegeTable.Columns.AddRange(new System.Windows.Forms.DataGridViewColumn[] {
            this.PrivilegeCol,
            this.FlagsCol});
            this.privilegeTable.Dock = System.Windows.Forms.DockStyle.Fill;
            this.privilegeTable.Location = new System.Drawing.Point(0, 0);
            this.privilegeTable.Name = "privilegeTable";
            this.privilegeTable.ReadOnly = true;
            this.privilegeTable.RowHeadersVisible = false;
            this.privilegeTable.SelectionMode = System.Windows.Forms.DataGridViewSelectionMode.FullRowSelect;
            this.privilegeTable.Size = new System.Drawing.Size(772, 155);
            this.privilegeTable.TabIndex = 1;
            // 
            // PrivilegeCol
            // 
            this.PrivilegeCol.HeaderText = "Privilege";
            this.PrivilegeCol.Name = "PrivilegeCol";
            this.PrivilegeCol.ReadOnly = true;
            // 
            // FlagsCol
            // 
            this.FlagsCol.HeaderText = "Flags";
            this.FlagsCol.Name = "FlagsCol";
            this.FlagsCol.ReadOnly = true;
            // 
            // ProcessProperties
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(800, 450);
            this.Controls.Add(this.tableLayoutPanel1);
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.Name = "ProcessProperties";
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
            this.Text = "ProcessProperties";
            this.Shown += new System.EventHandler(this.ProcessProperties_Shown);
            this.tableLayoutPanel1.ResumeLayout(false);
            this.tableLayoutPanel1.PerformLayout();
            this.statusStrip1.ResumeLayout(false);
            this.statusStrip1.PerformLayout();
            this.tabControl1.ResumeLayout(false);
            this.propertiesTab.ResumeLayout(false);
            this.securityTab.ResumeLayout(false);
            ((System.ComponentModel.ISupportInitialize)(this.propertiesTable)).EndInit();
            this.tableLayoutPanel2.ResumeLayout(false);
            this.panel1.ResumeLayout(false);
            this.panel1.PerformLayout();
            this.panel2.ResumeLayout(false);
            this.panel3.ResumeLayout(false);
            ((System.ComponentModel.ISupportInitialize)(this.groupTable)).EndInit();
            ((System.ComponentModel.ISupportInitialize)(this.privilegeTable)).EndInit();
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.TableLayoutPanel tableLayoutPanel1;
        private System.Windows.Forms.StatusStrip statusStrip1;
        private System.Windows.Forms.ToolStripProgressBar loadingBar;
        private System.Windows.Forms.TabControl tabControl1;
        private System.Windows.Forms.TabPage propertiesTab;
        private System.Windows.Forms.DataGridView propertiesTable;
        private System.Windows.Forms.DataGridViewTextBoxColumn PNameCol;
        private System.Windows.Forms.DataGridViewTextBoxColumn PValueCol;
        private System.Windows.Forms.TabPage securityTab;
        private System.Windows.Forms.TableLayoutPanel tableLayoutPanel2;
        private System.Windows.Forms.Panel panel1;
        private System.Windows.Forms.Label sidLabel;
        private System.Windows.Forms.Label userLabel;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.Panel panel2;
        private System.Windows.Forms.DataGridView groupTable;
        private System.Windows.Forms.DataGridViewTextBoxColumn dataGridViewTextBoxColumn3;
        private System.Windows.Forms.DataGridViewTextBoxColumn GroupSidCol;
        private System.Windows.Forms.Panel panel3;
        private System.Windows.Forms.DataGridView privilegeTable;
        private System.Windows.Forms.DataGridViewTextBoxColumn PrivilegeCol;
        private System.Windows.Forms.DataGridViewTextBoxColumn FlagsCol;
    }
}