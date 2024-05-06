namespace RemoteDiagnostics.Client
{
    partial class FileSystemBrowse
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
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(FileSystemBrowse));
            this.tableLayoutPanel1 = new System.Windows.Forms.TableLayoutPanel();
            this.statusStrip1 = new System.Windows.Forms.StatusStrip();
            this.pathLabel = new System.Windows.Forms.ToolStripStatusLabel();
            this.loader = new System.Windows.Forms.ToolStripProgressBar();
            this.fileTable = new System.Windows.Forms.DataGridView();
            this.NameCol = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.TypeCol = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.CreationCol = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.ModCol = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.tableLayoutPanel1.SuspendLayout();
            this.statusStrip1.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.fileTable)).BeginInit();
            this.SuspendLayout();
            // 
            // tableLayoutPanel1
            // 
            this.tableLayoutPanel1.ColumnCount = 1;
            this.tableLayoutPanel1.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 100F));
            this.tableLayoutPanel1.Controls.Add(this.fileTable, 0, 0);
            this.tableLayoutPanel1.Controls.Add(this.statusStrip1, 0, 1);
            this.tableLayoutPanel1.Dock = System.Windows.Forms.DockStyle.Fill;
            this.tableLayoutPanel1.Location = new System.Drawing.Point(0, 0);
            this.tableLayoutPanel1.Name = "tableLayoutPanel1";
            this.tableLayoutPanel1.RowCount = 2;
            this.tableLayoutPanel1.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Percent, 100F));
            this.tableLayoutPanel1.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Absolute, 23F));
            this.tableLayoutPanel1.Size = new System.Drawing.Size(1025, 321);
            this.tableLayoutPanel1.TabIndex = 0;
            // 
            // statusStrip1
            // 
            this.statusStrip1.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.pathLabel,
            this.loader});
            this.statusStrip1.Location = new System.Drawing.Point(0, 299);
            this.statusStrip1.Name = "statusStrip1";
            this.statusStrip1.Size = new System.Drawing.Size(1025, 22);
            this.statusStrip1.TabIndex = 0;
            this.statusStrip1.Text = "statusStrip1";
            // 
            // pathLabel
            // 
            this.pathLabel.Name = "pathLabel";
            this.pathLabel.Size = new System.Drawing.Size(23, 17);
            this.pathLabel.Text = "C:\\";
            // 
            // loader
            // 
            this.loader.Name = "loader";
            this.loader.Size = new System.Drawing.Size(100, 16);
            this.loader.Style = System.Windows.Forms.ProgressBarStyle.Marquee;
            // 
            // fileTable
            // 
            this.fileTable.AllowUserToAddRows = false;
            this.fileTable.AllowUserToDeleteRows = false;
            this.fileTable.AllowUserToOrderColumns = true;
            this.fileTable.AllowUserToResizeRows = false;
            this.fileTable.AutoSizeColumnsMode = System.Windows.Forms.DataGridViewAutoSizeColumnsMode.Fill;
            this.fileTable.BackgroundColor = System.Drawing.SystemColors.Window;
            this.fileTable.BorderStyle = System.Windows.Forms.BorderStyle.None;
            this.fileTable.ColumnHeadersHeightSizeMode = System.Windows.Forms.DataGridViewColumnHeadersHeightSizeMode.AutoSize;
            this.fileTable.Columns.AddRange(new System.Windows.Forms.DataGridViewColumn[] {
            this.NameCol,
            this.TypeCol,
            this.CreationCol,
            this.ModCol});
            this.fileTable.Dock = System.Windows.Forms.DockStyle.Fill;
            this.fileTable.Location = new System.Drawing.Point(0, 0);
            this.fileTable.Margin = new System.Windows.Forms.Padding(0);
            this.fileTable.Name = "fileTable";
            this.fileTable.ReadOnly = true;
            this.fileTable.RowHeadersVisible = false;
            this.fileTable.SelectionMode = System.Windows.Forms.DataGridViewSelectionMode.FullRowSelect;
            this.fileTable.Size = new System.Drawing.Size(1025, 298);
            this.fileTable.TabIndex = 2;
            this.fileTable.CellDoubleClick += new System.Windows.Forms.DataGridViewCellEventHandler(this.fileTable_CellDoubleClick);
            // 
            // NameCol
            // 
            this.NameCol.HeaderText = "Name";
            this.NameCol.Name = "NameCol";
            this.NameCol.ReadOnly = true;
            // 
            // TypeCol
            // 
            this.TypeCol.HeaderText = "Type";
            this.TypeCol.Name = "TypeCol";
            this.TypeCol.ReadOnly = true;
            // 
            // CreationCol
            // 
            this.CreationCol.HeaderText = "Creation";
            this.CreationCol.Name = "CreationCol";
            this.CreationCol.ReadOnly = true;
            // 
            // ModCol
            // 
            this.ModCol.HeaderText = "Modification";
            this.ModCol.Name = "ModCol";
            this.ModCol.ReadOnly = true;
            // 
            // FileSystemBrowse
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(1025, 321);
            this.Controls.Add(this.tableLayoutPanel1);
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.Name = "FileSystemBrowse";
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
            this.Text = "FileSystemBrowse";
            this.Paint += new System.Windows.Forms.PaintEventHandler(this.FileSystemBrowse_Paint);
            this.tableLayoutPanel1.ResumeLayout(false);
            this.tableLayoutPanel1.PerformLayout();
            this.statusStrip1.ResumeLayout(false);
            this.statusStrip1.PerformLayout();
            ((System.ComponentModel.ISupportInitialize)(this.fileTable)).EndInit();
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.TableLayoutPanel tableLayoutPanel1;
        private System.Windows.Forms.StatusStrip statusStrip1;
        private System.Windows.Forms.ToolStripStatusLabel pathLabel;
        private System.Windows.Forms.ToolStripProgressBar loader;
        private System.Windows.Forms.DataGridView fileTable;
        private System.Windows.Forms.DataGridViewTextBoxColumn NameCol;
        private System.Windows.Forms.DataGridViewTextBoxColumn TypeCol;
        private System.Windows.Forms.DataGridViewTextBoxColumn CreationCol;
        private System.Windows.Forms.DataGridViewTextBoxColumn ModCol;
    }
}