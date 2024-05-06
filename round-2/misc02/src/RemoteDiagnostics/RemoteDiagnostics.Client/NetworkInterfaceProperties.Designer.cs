namespace RemoteDiagnostics.Client
{
    partial class NetworkInterfaceProperties
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
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(NetworkInterfaceProperties));
            this.interfacePropertiesTable = new System.Windows.Forms.DataGridView();
            this.NameCol = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.ValueCol = new System.Windows.Forms.DataGridViewTextBoxColumn();
            ((System.ComponentModel.ISupportInitialize)(this.interfacePropertiesTable)).BeginInit();
            this.SuspendLayout();
            // 
            // interfacePropertiesTable
            // 
            this.interfacePropertiesTable.AllowUserToAddRows = false;
            this.interfacePropertiesTable.AllowUserToDeleteRows = false;
            this.interfacePropertiesTable.AutoSizeColumnsMode = System.Windows.Forms.DataGridViewAutoSizeColumnsMode.Fill;
            this.interfacePropertiesTable.BackgroundColor = System.Drawing.SystemColors.Window;
            this.interfacePropertiesTable.BorderStyle = System.Windows.Forms.BorderStyle.None;
            this.interfacePropertiesTable.ColumnHeadersHeightSizeMode = System.Windows.Forms.DataGridViewColumnHeadersHeightSizeMode.AutoSize;
            this.interfacePropertiesTable.Columns.AddRange(new System.Windows.Forms.DataGridViewColumn[] {
            this.NameCol,
            this.ValueCol});
            this.interfacePropertiesTable.Dock = System.Windows.Forms.DockStyle.Fill;
            this.interfacePropertiesTable.Location = new System.Drawing.Point(0, 0);
            this.interfacePropertiesTable.Margin = new System.Windows.Forms.Padding(0);
            this.interfacePropertiesTable.Name = "interfacePropertiesTable";
            this.interfacePropertiesTable.ReadOnly = true;
            this.interfacePropertiesTable.RowHeadersVisible = false;
            this.interfacePropertiesTable.SelectionMode = System.Windows.Forms.DataGridViewSelectionMode.FullRowSelect;
            this.interfacePropertiesTable.Size = new System.Drawing.Size(800, 225);
            this.interfacePropertiesTable.TabIndex = 1;
            // 
            // NameCol
            // 
            this.NameCol.HeaderText = "Name";
            this.NameCol.Name = "NameCol";
            this.NameCol.ReadOnly = true;
            // 
            // ValueCol
            // 
            this.ValueCol.HeaderText = "Value";
            this.ValueCol.Name = "ValueCol";
            this.ValueCol.ReadOnly = true;
            // 
            // NetworkInterfaceProperties
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(800, 225);
            this.Controls.Add(this.interfacePropertiesTable);
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.Name = "NetworkInterfaceProperties";
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
            this.Text = "Network Interface Properties";
            this.Shown += new System.EventHandler(this.NetworkInterfaceProperties_Shown);
            ((System.ComponentModel.ISupportInitialize)(this.interfacePropertiesTable)).EndInit();
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.DataGridView interfacePropertiesTable;
        private System.Windows.Forms.DataGridViewTextBoxColumn NameCol;
        private System.Windows.Forms.DataGridViewTextBoxColumn ValueCol;
    }
}