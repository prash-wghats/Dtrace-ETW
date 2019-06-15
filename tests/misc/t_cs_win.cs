
//resgen /compile TextEditor.resx,TextEditor.TextEditor.resources
//csc Program.cs TextEditor.cs /resource:TextEditor.TextEditor.resources
// /platform:x86 /errorreport:prompt /warn:4 /define:DEBUG;TRACE
// /platform:x64
// /nostdlib+ /platform:AnyCPU /target:winexe /target:library /utf8output  /debug+ /debug:full /filealign:512 /optimize- /out:
//csc /platform:x64 /target:winexe /debug+ /debug:full  /optimize- /define: /out:
//Program.cs

//resgen /compile ..\..\internal\TextEditor.resx,TextEditor.TextEditor.resources
//csc /debug /platform:x64 ..\..\internal\TextEditorS.cs /define:MAIN /resource:TextEditor.TextEditor.resources

using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows.Forms;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Drawing.Text;
using System.Linq;
using System.Text;
using System.Windows.Forms;

namespace TextEditor
{
    static class Program
    {
        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        [STAThread]
        static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new TextEditor());
        }
    }
}

//TextEditor.cs



namespace TextEditor
{
    public partial class TextEditor : Form
    {
        public TextEditor()
        {
            InitializeComponent();
        }



        /// <summary>
        /// FOR THE TUTORIAL GO TO HTTP://WWW.THECODINGUYS.NET/C-SHARP OR HTTP://WWW.THECODINGGUYS.NET/DOWNLOADS
        /// THIS WORK IS LICNESED UNDER CCL 3.0 UNPORTED http://creativecommons.org/licenses/by/3.0/ YOU CAN USE THE PROGRAM
        /// COMMERCIALLY PROVIDING YOU CREDIT ME IN SOME WAY! 
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>

        #region Editor and General

        private void Document_LinkClicked(object sender, LinkClickedEventArgs e)
        {
            System.Diagnostics.Process.Start(e.LinkText);
        }

        private void TextEditor_Load(object sender, EventArgs e)
        {
            FontSize();
            InstalledFonts();

  

        }

        private void Timer_Tick_1(object sender, EventArgs e)
        {
            charCount.Text = "Characters in the current document: " + Document.TextLength.ToString();

            status_ZoomFactor.Text = Document.ZoomFactor.ToString();
        }



        #endregion



        #region MainMenu

        //FILE

        private void file_New_Click(object sender, EventArgs e)
        {
            New();
        }

        private void file_Open_Click(object sender, EventArgs e)
        {
            Open();
        }

        private void file_Save_Click(object sender, EventArgs e)
        {
            Save();
        }

        private void file_Exit_Click(object sender, EventArgs e)
        {
            Exit();
        }


        // EDIT MENU

        private void edit_Undo_Click(object sender, EventArgs e)
        {
            Undo();

        }

        private void edit_Redo_Click(object sender, EventArgs e)
        {
            Redo();
        }

        private void edit_Cut_Click(object sender, EventArgs e)
        {
            Cut();
        }

        private void edit_Copy_Click(object sender, EventArgs e)
        {
            Copy();
        }

        private void edit_Paste_Click(object sender, EventArgs e)
        {
            Paste();
        }

        private void edit_SelectAll_Click(object sender, EventArgs e)
        {
            SelectAll();
        }

        private void clearAllToolStripMenuItem_Click(object sender, EventArgs e)
        {
            ClearAll();
        }


        //TOOLS MENU

        private void tools_Customise_Click(object sender, EventArgs e)
        {
            customise();
        }

        #endregion



        #region Toolbar

        private void tb_New_Click(object sender, EventArgs e)
        {
            New();
        }

        private void tb_Open_Click(object sender, EventArgs e)
        {
            Open();
        }

        private void tb_Save_Click(object sender, EventArgs e)
        {
            Save();
        }

        private void tb_Cut_Click(object sender, EventArgs e)
        {
            Cut();
        }

        private void tb_Copy_Click(object sender, EventArgs e)
        {
            Copy();
        }

        private void tb_Paste_Click(object sender, EventArgs e)
        {
            Paste();
        }

        private void tb_ZoomIn_Click(object sender, EventArgs e)
        {
            if (Document.ZoomFactor == 63)
            {

                return;

            }
            else
                Document.ZoomFactor = Document.ZoomFactor + 1;
        }

        private void tb_ZoomOut_Click(object sender, EventArgs e)
        {
            if (Document.ZoomFactor == 1)
            {

                return;


            }
            else
                Document.ZoomFactor = Document.ZoomFactor - 1;
        }



        private void tb_Bold_Click(object sender, EventArgs e)
        {
            Font bfont = new Font(Document.Font, FontStyle.Bold);
            Font rfont = new Font(Document.Font, FontStyle.Regular);

            if (Document.SelectedText.Length == 0)
                return;
            if (Document.SelectionFont.Bold)
            {
                Document.SelectionFont = rfont;
            }
            else
            {
                Document.SelectionFont = bfont;
            }
        }

        private void tb_Italic_Click(object sender, EventArgs e)
        {
            Font Ifont = new Font(Document.Font, FontStyle.Italic);
            Font rfont = new Font(Document.Font, FontStyle.Regular);

            if (Document.SelectedText.Length == 0)
                return;
            if (Document.SelectionFont.Italic)
            {
                Document.SelectionFont = rfont;
            }
            else
            {
                Document.SelectionFont = Ifont;
            }
        }

        private void tb_UnderLine_Click(object sender, EventArgs e)
        {
            Font Ufont = new Font(Document.Font, FontStyle.Underline);
            Font rfont = new Font(Document.Font, FontStyle.Regular);

            if (Document.SelectedText.Length == 0)
                return;
            if (Document.SelectionFont.Underline)
            {
                Document.SelectionFont = rfont;
            }
            else
            {
                Document.SelectionFont = Ufont;
            }
        }

        private void tb_Strike_Click(object sender, EventArgs e)
        {
            Font Sfont = new Font(Document.Font, FontStyle.Strikeout);
            Font rfont = new Font(Document.Font, FontStyle.Regular);


            if (Document.SelectedText.Length == 0)
                return;
            if (Document.SelectionFont.Strikeout)
            {
                Document.SelectionFont = rfont;
            }
            else
            {
                Document.SelectionFont = Sfont;
            }
        }

        private void tb_AlignLeft_Click(object sender, EventArgs e)
        {
            Document.SelectionAlignment = HorizontalAlignment.Left;
        }

        private void tb_AlignCenter_Click(object sender, EventArgs e)
        {
            Document.SelectionAlignment = HorizontalAlignment.Center;
        }

        private void tb_AlignRight_Click(object sender, EventArgs e)
        {
            Document.SelectionAlignment = HorizontalAlignment.Right;
        }

        private void tb_UpperCase_Click(object sender, EventArgs e)
        {
            Document.SelectedText = Document.SelectedText.ToUpper();
        }

        private void tb_LowerCase_Click(object sender, EventArgs e)
        {
            Document.SelectedText = Document.SelectedText.ToLower();
        }



        private void tb_Font_SelectedIndexChanged(object sender, EventArgs e)
        {
            System.Drawing.Font ComboFonts = null;

            try
            {
                ComboFonts = Document.SelectionFont;
                Document.SelectionFont = new System.Drawing.Font(tb_Font.Text, Document.SelectionFont.Size, Document.SelectionFont.Style);
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
        }

        private void tb_FontSize_SelectedIndexChanged(object sender, EventArgs e)
        {

            Document.SelectionFont = new Font(tb_FontSize.SelectedItem.ToString(), int.Parse(tb_FontSize.SelectedItem.ToString()), Document.SelectionFont.Style);
        }

        #endregion


        #region contextmenu

        private void rc_Undo_Click(object sender, EventArgs e)
        {
            Undo();
        }

        private void rc_Redo_Click(object sender, EventArgs e)
        {
            Redo();
        }

        private void rc_Cut_Click(object sender, EventArgs e)
        {
            Cut();
        }

        private void rc_Copy_Click(object sender, EventArgs e)
        {
            Copy();
        }

        private void rc_Paste_Click(object sender, EventArgs e)
        {
            Paste();
        }

        #endregion


        /* ALL CODE BELOW HERE!  */
        #region Methods

        #region file

        void New()
        {

            Document.Clear();
        }


        void Open()
        {
            if (openWork.ShowDialog() == DialogResult.OK)
            {
                Document.LoadFile(openWork.FileName, RichTextBoxStreamType.PlainText);
            }
        }



        void Save()
        {

            if (saveWork.ShowDialog() == DialogResult.OK)
            {
                try
                {

                    Document.SaveFile(saveWork.FileName, RichTextBoxStreamType.PlainText);
                }

                catch (Exception ex)
                {
                    MessageBox.Show(ex.Message);
                }
            }
        }



        void Exit()
        {
            Application.Exit();
        }



        #endregion


        #region edit

        void Undo()
        {
            Document.Undo();
        }

        void Redo()
        {
            Document.Redo();
        }

        void Cut()
        {
            Document.Cut();
        }

        void Copy()
        {
            Document.Copy();
        }

        void Paste()
        {
            Document.Paste();
        }

        void SelectAll()
        {
            Document.SelectAll();
        }

        void ClearAll()
        {
            Document.Clear();
        }



        #endregion


        #region tools

        void customise()
        {
            ColorDialog myDialog = new ColorDialog();
            if (myDialog.ShowDialog() == DialogResult.OK)
            {

                mainMenu.BackColor = myDialog.Color;
                Status.BackColor = myDialog.Color;
                Tools.BackColor = myDialog.Color;
            }

        }


        #endregion




        #endregion


        void FontSize()
        {

            for (int fntSize = 10; fntSize <= 75; fntSize++)
            {
                tb_FontSize.Items.Add(fntSize.ToString());
            }


        }

        void InstalledFonts()
        {

            InstalledFontCollection fonts = new InstalledFontCollection();

            for (int i = 0; i < fonts.Families.Length; i++)
            {
                tb_Font.Items.Add(fonts.Families[i].Name);
            }


        }

        

     

      
    }

}   

//TextEditor.Designer.cs
namespace TextEditor
{
    partial class TextEditor
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
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(TextEditor));
            this.mainMenu = new System.Windows.Forms.MenuStrip();
            this.mM_File = new System.Windows.Forms.ToolStripMenuItem();
            this.file_New = new System.Windows.Forms.ToolStripMenuItem();
            this.file_Open = new System.Windows.Forms.ToolStripMenuItem();
            this.toolStripSeparator11 = new System.Windows.Forms.ToolStripSeparator();
            this.file_Save = new System.Windows.Forms.ToolStripMenuItem();
            this.toolStripSeparator13 = new System.Windows.Forms.ToolStripSeparator();
            this.file_Exit = new System.Windows.Forms.ToolStripMenuItem();
            this.mM_Edit = new System.Windows.Forms.ToolStripMenuItem();
            this.edit_Undo = new System.Windows.Forms.ToolStripMenuItem();
            this.edit_Redo = new System.Windows.Forms.ToolStripMenuItem();
            this.toolStripSeparator14 = new System.Windows.Forms.ToolStripSeparator();
            this.edit_Cut = new System.Windows.Forms.ToolStripMenuItem();
            this.edit_Copy = new System.Windows.Forms.ToolStripMenuItem();
            this.edit_Paste = new System.Windows.Forms.ToolStripMenuItem();
            this.toolStripSeparator15 = new System.Windows.Forms.ToolStripSeparator();
            this.edit_SelectAll = new System.Windows.Forms.ToolStripMenuItem();
            this.mM_Tools = new System.Windows.Forms.ToolStripMenuItem();
            this.tools_Customise = new System.Windows.Forms.ToolStripMenuItem();
            this.Tools = new System.Windows.Forms.ToolStrip();
            this.tb_New = new System.Windows.Forms.ToolStripButton();
            this.tb_Open = new System.Windows.Forms.ToolStripButton();
            this.tb_Save = new System.Windows.Forms.ToolStripButton();
            this.toolStripSeparator = new System.Windows.Forms.ToolStripSeparator();
            this.tb_Cut = new System.Windows.Forms.ToolStripButton();
            this.tb_Copy = new System.Windows.Forms.ToolStripButton();
            this.tb_Paste = new System.Windows.Forms.ToolStripButton();
            this.toolStripSeparator1 = new System.Windows.Forms.ToolStripSeparator();
            this.tb_Bold = new System.Windows.Forms.ToolStripButton();
            this.tb_Italic = new System.Windows.Forms.ToolStripButton();
            this.tb_UnderLine = new System.Windows.Forms.ToolStripButton();
            this.tb_Strike = new System.Windows.Forms.ToolStripButton();
            this.toolStripSeparator3 = new System.Windows.Forms.ToolStripSeparator();
            this.tb_AlignLeft = new System.Windows.Forms.ToolStripButton();
            this.tb_AlignCenter = new System.Windows.Forms.ToolStripButton();
            this.tb_AlignRight = new System.Windows.Forms.ToolStripButton();
            this.toolStripSeparator7 = new System.Windows.Forms.ToolStripSeparator();
            this.tb_UpperCase = new System.Windows.Forms.ToolStripButton();
            this.tb_LowerCase = new System.Windows.Forms.ToolStripButton();
            this.toolStripSeparator8 = new System.Windows.Forms.ToolStripSeparator();
            this.tb_ZoomIn = new System.Windows.Forms.ToolStripButton();
            this.tb_ZoomOut = new System.Windows.Forms.ToolStripButton();
            this.toolStripSeparator9 = new System.Windows.Forms.ToolStripSeparator();
            this.tb_Font = new System.Windows.Forms.ToolStripComboBox();
            this.tb_FontSize = new System.Windows.Forms.ToolStripComboBox();
            this.toolStripSeparator2 = new System.Windows.Forms.ToolStripSeparator();
            this.Status = new System.Windows.Forms.StatusStrip();
            this.charCount = new System.Windows.Forms.ToolStripStatusLabel();
            this.toolStripStatusLabel2 = new System.Windows.Forms.ToolStripStatusLabel();
            this.status_ZoomFactor = new System.Windows.Forms.ToolStripStatusLabel();
            this.Document = new System.Windows.Forms.RichTextBox();
            this.rcMenu = new System.Windows.Forms.ContextMenuStrip(this.components);
            this.rc_Undo = new System.Windows.Forms.ToolStripMenuItem();
            this.rc_Redo = new System.Windows.Forms.ToolStripMenuItem();
            this.toolStripSeparator10 = new System.Windows.Forms.ToolStripSeparator();
            this.rc_Cut = new System.Windows.Forms.ToolStripMenuItem();
            this.rc_Copy = new System.Windows.Forms.ToolStripMenuItem();
            this.rc_Paste = new System.Windows.Forms.ToolStripMenuItem();
            this.Timer = new System.Windows.Forms.Timer(this.components);
            this.openWork = new System.Windows.Forms.OpenFileDialog();
            this.saveWork = new System.Windows.Forms.SaveFileDialog();
            this.mainMenu.SuspendLayout();
            this.Tools.SuspendLayout();
            this.Status.SuspendLayout();
            this.rcMenu.SuspendLayout();
            this.SuspendLayout();
            // 
            // mainMenu
            // 
            this.mainMenu.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.mM_File,
            this.mM_Edit,
            this.mM_Tools});
            this.mainMenu.Location = new System.Drawing.Point(0, 0);
            this.mainMenu.Name = "mainMenu";
            this.mainMenu.Size = new System.Drawing.Size(732, 24);
            this.mainMenu.TabIndex = 0;
            this.mainMenu.Text = "menuStrip1";
            // 
            // mM_File
            // 
            this.mM_File.DropDownItems.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.file_New,
            this.file_Open,
            this.toolStripSeparator11,
            this.file_Save,
            this.toolStripSeparator13,
            this.file_Exit});
            this.mM_File.Name = "mM_File";
            this.mM_File.Size = new System.Drawing.Size(37, 20);
            this.mM_File.Text = "&File";
            // 
            // file_New
            // 
            this.file_New.Image = ((System.Drawing.Image)(resources.GetObject("file_New.Image")));
            this.file_New.ImageTransparentColor = System.Drawing.Color.Magenta;
            this.file_New.Name = "file_New";
            this.file_New.ShortcutKeys = ((System.Windows.Forms.Keys)((System.Windows.Forms.Keys.Control | System.Windows.Forms.Keys.N)));
            this.file_New.Size = new System.Drawing.Size(146, 22);
            this.file_New.Text = "&New";
            this.file_New.Click += new System.EventHandler(this.file_New_Click);
            // 
            // file_Open
            // 
            this.file_Open.Image = ((System.Drawing.Image)(resources.GetObject("file_Open.Image")));
            this.file_Open.ImageTransparentColor = System.Drawing.Color.Magenta;
            this.file_Open.Name = "file_Open";
            this.file_Open.ShortcutKeys = ((System.Windows.Forms.Keys)((System.Windows.Forms.Keys.Control | System.Windows.Forms.Keys.O)));
            this.file_Open.Size = new System.Drawing.Size(146, 22);
            this.file_Open.Text = "&Open";
            this.file_Open.Click += new System.EventHandler(this.file_Open_Click);
            // 
            // toolStripSeparator11
            // 
            this.toolStripSeparator11.Name = "toolStripSeparator11";
            this.toolStripSeparator11.Size = new System.Drawing.Size(143, 6);
            // 
            // file_Save
            // 
            this.file_Save.Image = ((System.Drawing.Image)(resources.GetObject("file_Save.Image")));
            this.file_Save.ImageTransparentColor = System.Drawing.Color.Magenta;
            this.file_Save.Name = "file_Save";
            this.file_Save.ShortcutKeys = ((System.Windows.Forms.Keys)((System.Windows.Forms.Keys.Control | System.Windows.Forms.Keys.S)));
            this.file_Save.Size = new System.Drawing.Size(146, 22);
            this.file_Save.Text = "&Save";
            this.file_Save.Click += new System.EventHandler(this.file_Save_Click);
            // 
            // toolStripSeparator13
            // 
            this.toolStripSeparator13.Name = "toolStripSeparator13";
            this.toolStripSeparator13.Size = new System.Drawing.Size(143, 6);
            // 
            // file_Exit
            // 
            this.file_Exit.Name = "file_Exit";
            this.file_Exit.Size = new System.Drawing.Size(146, 22);
            this.file_Exit.Text = "E&xit";
            this.file_Exit.Click += new System.EventHandler(this.file_Exit_Click);
            // 
            // mM_Edit
            // 
            this.mM_Edit.DropDownItems.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.edit_Undo,
            this.edit_Redo,
            this.toolStripSeparator14,
            this.edit_Cut,
            this.edit_Copy,
            this.edit_Paste,
            this.toolStripSeparator15,
            this.edit_SelectAll});
            this.mM_Edit.Name = "mM_Edit";
            this.mM_Edit.Size = new System.Drawing.Size(39, 20);
            this.mM_Edit.Text = "&Edit";
            // 
            // edit_Undo
            // 
            this.edit_Undo.Name = "edit_Undo";
            this.edit_Undo.ShortcutKeys = ((System.Windows.Forms.Keys)((System.Windows.Forms.Keys.Control | System.Windows.Forms.Keys.Z)));
            this.edit_Undo.Size = new System.Drawing.Size(144, 22);
            this.edit_Undo.Text = "&Undo";
            this.edit_Undo.Click += new System.EventHandler(this.edit_Undo_Click);
            // 
            // edit_Redo
            // 
            this.edit_Redo.Name = "edit_Redo";
            this.edit_Redo.ShortcutKeys = ((System.Windows.Forms.Keys)((System.Windows.Forms.Keys.Control | System.Windows.Forms.Keys.Y)));
            this.edit_Redo.Size = new System.Drawing.Size(144, 22);
            this.edit_Redo.Text = "&Redo";
            this.edit_Redo.Click += new System.EventHandler(this.edit_Redo_Click);
            // 
            // toolStripSeparator14
            // 
            this.toolStripSeparator14.Name = "toolStripSeparator14";
            this.toolStripSeparator14.Size = new System.Drawing.Size(141, 6);
            // 
            // edit_Cut
            // 
            this.edit_Cut.Image = ((System.Drawing.Image)(resources.GetObject("edit_Cut.Image")));
            this.edit_Cut.ImageTransparentColor = System.Drawing.Color.Magenta;
            this.edit_Cut.Name = "edit_Cut";
            this.edit_Cut.ShortcutKeys = ((System.Windows.Forms.Keys)((System.Windows.Forms.Keys.Control | System.Windows.Forms.Keys.X)));
            this.edit_Cut.Size = new System.Drawing.Size(144, 22);
            this.edit_Cut.Text = "Cu&t";
            this.edit_Cut.Click += new System.EventHandler(this.edit_Cut_Click);
            // 
            // edit_Copy
            // 
            this.edit_Copy.Image = ((System.Drawing.Image)(resources.GetObject("edit_Copy.Image")));
            this.edit_Copy.ImageTransparentColor = System.Drawing.Color.Magenta;
            this.edit_Copy.Name = "edit_Copy";
            this.edit_Copy.ShortcutKeys = ((System.Windows.Forms.Keys)((System.Windows.Forms.Keys.Control | System.Windows.Forms.Keys.C)));
            this.edit_Copy.Size = new System.Drawing.Size(144, 22);
            this.edit_Copy.Text = "&Copy";
            this.edit_Copy.Click += new System.EventHandler(this.edit_Copy_Click);
            // 
            // edit_Paste
            // 
            this.edit_Paste.Image = ((System.Drawing.Image)(resources.GetObject("edit_Paste.Image")));
            this.edit_Paste.ImageTransparentColor = System.Drawing.Color.Magenta;
            this.edit_Paste.Name = "edit_Paste";
            this.edit_Paste.ShortcutKeys = ((System.Windows.Forms.Keys)((System.Windows.Forms.Keys.Control | System.Windows.Forms.Keys.V)));
            this.edit_Paste.Size = new System.Drawing.Size(144, 22);
            this.edit_Paste.Text = "&Paste";
            this.edit_Paste.Click += new System.EventHandler(this.edit_Paste_Click);
            // 
            // toolStripSeparator15
            // 
            this.toolStripSeparator15.Name = "toolStripSeparator15";
            this.toolStripSeparator15.Size = new System.Drawing.Size(141, 6);
            // 
            // edit_SelectAll
            // 
            this.edit_SelectAll.Name = "edit_SelectAll";
            this.edit_SelectAll.Size = new System.Drawing.Size(144, 22);
            this.edit_SelectAll.Text = "Select &All";
            this.edit_SelectAll.Click += new System.EventHandler(this.edit_SelectAll_Click);
            // 
            // mM_Tools
            // 
            this.mM_Tools.DropDownItems.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.tools_Customise});
            this.mM_Tools.Name = "mM_Tools";
            this.mM_Tools.Size = new System.Drawing.Size(48, 20);
            this.mM_Tools.Text = "&Tools";
            // 
            // tools_Customise
            // 
            this.tools_Customise.Name = "tools_Customise";
            this.tools_Customise.Size = new System.Drawing.Size(130, 22);
            this.tools_Customise.Text = "&Customize";
            this.tools_Customise.Click += new System.EventHandler(this.tools_Customise_Click);
            // 
            // Tools
            // 
            this.Tools.GripStyle = System.Windows.Forms.ToolStripGripStyle.Hidden;
            this.Tools.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.tb_New,
            this.tb_Open,
            this.tb_Save,
            this.toolStripSeparator,
            this.tb_Cut,
            this.tb_Copy,
            this.tb_Paste,
            this.toolStripSeparator1,
            this.tb_Bold,
            this.tb_Italic,
            this.tb_UnderLine,
            this.tb_Strike,
            this.toolStripSeparator3,
            this.tb_AlignLeft,
            this.tb_AlignCenter,
            this.tb_AlignRight,
            this.toolStripSeparator7,
            this.tb_UpperCase,
            this.tb_LowerCase,
            this.toolStripSeparator8,
            this.tb_ZoomIn,
            this.tb_ZoomOut,
            this.toolStripSeparator9,
            this.tb_Font,
            this.tb_FontSize,
            this.toolStripSeparator2});
            this.Tools.Location = new System.Drawing.Point(0, 24);
            this.Tools.Name = "Tools";
            this.Tools.Size = new System.Drawing.Size(732, 25);
            this.Tools.TabIndex = 1;
            this.Tools.Text = "toolStrip1";
            // 
            // tb_New
            // 
            this.tb_New.DisplayStyle = System.Windows.Forms.ToolStripItemDisplayStyle.Image;
            this.tb_New.Image = ((System.Drawing.Image)(resources.GetObject("tb_New.Image")));
            this.tb_New.ImageTransparentColor = System.Drawing.Color.Magenta;
            this.tb_New.Name = "tb_New";
            this.tb_New.Size = new System.Drawing.Size(23, 22);
            this.tb_New.Text = "&New";
            this.tb_New.Click += new System.EventHandler(this.tb_New_Click);
            // 
            // tb_Open
            // 
            this.tb_Open.DisplayStyle = System.Windows.Forms.ToolStripItemDisplayStyle.Image;
            this.tb_Open.Image = ((System.Drawing.Image)(resources.GetObject("tb_Open.Image")));
            this.tb_Open.ImageTransparentColor = System.Drawing.Color.Magenta;
            this.tb_Open.Name = "tb_Open";
            this.tb_Open.Size = new System.Drawing.Size(23, 22);
            this.tb_Open.Text = "&Open";
            this.tb_Open.Click += new System.EventHandler(this.tb_Open_Click);
            // 
            // tb_Save
            // 
            this.tb_Save.DisplayStyle = System.Windows.Forms.ToolStripItemDisplayStyle.Image;
            this.tb_Save.Image = ((System.Drawing.Image)(resources.GetObject("tb_Save.Image")));
            this.tb_Save.ImageTransparentColor = System.Drawing.Color.Magenta;
            this.tb_Save.Name = "tb_Save";
            this.tb_Save.Size = new System.Drawing.Size(23, 22);
            this.tb_Save.Text = "&Save";
            this.tb_Save.Click += new System.EventHandler(this.tb_Save_Click);
            // 
            // toolStripSeparator
            // 
            this.toolStripSeparator.Name = "toolStripSeparator";
            this.toolStripSeparator.Size = new System.Drawing.Size(6, 25);
            // 
            // tb_Cut
            // 
            this.tb_Cut.DisplayStyle = System.Windows.Forms.ToolStripItemDisplayStyle.Image;
            this.tb_Cut.Image = ((System.Drawing.Image)(resources.GetObject("tb_Cut.Image")));
            this.tb_Cut.ImageTransparentColor = System.Drawing.Color.Magenta;
            this.tb_Cut.Name = "tb_Cut";
            this.tb_Cut.Size = new System.Drawing.Size(23, 22);
            this.tb_Cut.Text = "C&ut";
            this.tb_Cut.Click += new System.EventHandler(this.tb_Cut_Click);
            // 
            // tb_Copy
            // 
            this.tb_Copy.DisplayStyle = System.Windows.Forms.ToolStripItemDisplayStyle.Image;
            this.tb_Copy.Image = ((System.Drawing.Image)(resources.GetObject("tb_Copy.Image")));
            this.tb_Copy.ImageTransparentColor = System.Drawing.Color.Magenta;
            this.tb_Copy.Name = "tb_Copy";
            this.tb_Copy.Size = new System.Drawing.Size(23, 22);
            this.tb_Copy.Text = "&Copy";
            this.tb_Copy.Click += new System.EventHandler(this.tb_Copy_Click);
            // 
            // tb_Paste
            // 
            this.tb_Paste.DisplayStyle = System.Windows.Forms.ToolStripItemDisplayStyle.Image;
            this.tb_Paste.Image = ((System.Drawing.Image)(resources.GetObject("tb_Paste.Image")));
            this.tb_Paste.ImageTransparentColor = System.Drawing.Color.Magenta;
            this.tb_Paste.Name = "tb_Paste";
            this.tb_Paste.Size = new System.Drawing.Size(23, 22);
            this.tb_Paste.Text = "&Paste";
            this.tb_Paste.Click += new System.EventHandler(this.tb_Paste_Click);
            // 
            // toolStripSeparator1
            // 
            this.toolStripSeparator1.Name = "toolStripSeparator1";
            this.toolStripSeparator1.Size = new System.Drawing.Size(6, 25);
            // 
            // tb_Bold
            // 
            this.tb_Bold.DisplayStyle = System.Windows.Forms.ToolStripItemDisplayStyle.Text;
            this.tb_Bold.Font = new System.Drawing.Font("Arial Rounded MT Bold", 9F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.tb_Bold.Image = ((System.Drawing.Image)(resources.GetObject("tb_Bold.Image")));
            this.tb_Bold.ImageTransparentColor = System.Drawing.Color.Magenta;
            this.tb_Bold.Name = "tb_Bold";
            this.tb_Bold.Size = new System.Drawing.Size(23, 22);
            this.tb_Bold.Text = "B";
            this.tb_Bold.ToolTipText = "Bold";
            this.tb_Bold.Click += new System.EventHandler(this.tb_Bold_Click);
            // 
            // tb_Italic
            // 
            this.tb_Italic.DisplayStyle = System.Windows.Forms.ToolStripItemDisplayStyle.Text;
            this.tb_Italic.Font = new System.Drawing.Font("Arial Rounded MT Bold", 9F, System.Drawing.FontStyle.Italic, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.tb_Italic.Image = ((System.Drawing.Image)(resources.GetObject("tb_Italic.Image")));
            this.tb_Italic.ImageTransparentColor = System.Drawing.Color.Magenta;
            this.tb_Italic.Name = "tb_Italic";
            this.tb_Italic.Size = new System.Drawing.Size(23, 22);
            this.tb_Italic.Text = "I";
            this.tb_Italic.ToolTipText = "Italic";
            this.tb_Italic.Click += new System.EventHandler(this.tb_Italic_Click);
            // 
            // tb_UnderLine
            // 
            this.tb_UnderLine.DisplayStyle = System.Windows.Forms.ToolStripItemDisplayStyle.Text;
            this.tb_UnderLine.Font = new System.Drawing.Font("Arial Rounded MT Bold", 9F, System.Drawing.FontStyle.Underline, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.tb_UnderLine.Image = ((System.Drawing.Image)(resources.GetObject("tb_UnderLine.Image")));
            this.tb_UnderLine.ImageTransparentColor = System.Drawing.Color.Magenta;
            this.tb_UnderLine.Name = "tb_UnderLine";
            this.tb_UnderLine.Size = new System.Drawing.Size(23, 22);
            this.tb_UnderLine.Text = "U";
            this.tb_UnderLine.ToolTipText = "Underline";
            this.tb_UnderLine.Click += new System.EventHandler(this.tb_UnderLine_Click);
            // 
            // tb_Strike
            // 
            this.tb_Strike.DisplayStyle = System.Windows.Forms.ToolStripItemDisplayStyle.Text;
            this.tb_Strike.Font = new System.Drawing.Font("Arial Rounded MT Bold", 9F, System.Drawing.FontStyle.Strikeout, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.tb_Strike.Image = ((System.Drawing.Image)(resources.GetObject("tb_Strike.Image")));
            this.tb_Strike.ImageTransparentColor = System.Drawing.Color.Magenta;
            this.tb_Strike.Name = "tb_Strike";
            this.tb_Strike.Size = new System.Drawing.Size(23, 22);
            this.tb_Strike.Text = "S";
            this.tb_Strike.ToolTipText = "Strikethrough";
            this.tb_Strike.Click += new System.EventHandler(this.tb_Strike_Click);
            // 
            // toolStripSeparator3
            // 
            this.toolStripSeparator3.Name = "toolStripSeparator3";
            this.toolStripSeparator3.Size = new System.Drawing.Size(6, 25);
            // 
            // tb_AlignLeft
            // 
            this.tb_AlignLeft.DisplayStyle = System.Windows.Forms.ToolStripItemDisplayStyle.Text;
            this.tb_AlignLeft.Font = new System.Drawing.Font("Arial Rounded MT Bold", 9F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.tb_AlignLeft.Image = ((System.Drawing.Image)(resources.GetObject("tb_AlignLeft.Image")));
            this.tb_AlignLeft.ImageTransparentColor = System.Drawing.Color.Magenta;
            this.tb_AlignLeft.Name = "tb_AlignLeft";
            this.tb_AlignLeft.Size = new System.Drawing.Size(23, 22);
            this.tb_AlignLeft.Text = "L";
            this.tb_AlignLeft.ToolTipText = "Align Left";
            this.tb_AlignLeft.Click += new System.EventHandler(this.tb_AlignLeft_Click);
            // 
            // tb_AlignCenter
            // 
            this.tb_AlignCenter.DisplayStyle = System.Windows.Forms.ToolStripItemDisplayStyle.Text;
            this.tb_AlignCenter.Font = new System.Drawing.Font("Arial Rounded MT Bold", 9F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.tb_AlignCenter.Image = ((System.Drawing.Image)(resources.GetObject("tb_AlignCenter.Image")));
            this.tb_AlignCenter.ImageTransparentColor = System.Drawing.Color.Magenta;
            this.tb_AlignCenter.Name = "tb_AlignCenter";
            this.tb_AlignCenter.Size = new System.Drawing.Size(23, 22);
            this.tb_AlignCenter.Text = "C";
            this.tb_AlignCenter.ToolTipText = "Align Center";
            this.tb_AlignCenter.Click += new System.EventHandler(this.tb_AlignCenter_Click);
            // 
            // tb_AlignRight
            // 
            this.tb_AlignRight.DisplayStyle = System.Windows.Forms.ToolStripItemDisplayStyle.Text;
            this.tb_AlignRight.Font = new System.Drawing.Font("Arial Rounded MT Bold", 9F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.tb_AlignRight.Image = ((System.Drawing.Image)(resources.GetObject("tb_AlignRight.Image")));
            this.tb_AlignRight.ImageTransparentColor = System.Drawing.Color.Magenta;
            this.tb_AlignRight.Name = "tb_AlignRight";
            this.tb_AlignRight.Size = new System.Drawing.Size(23, 22);
            this.tb_AlignRight.Text = "R";
            this.tb_AlignRight.ToolTipText = "Align Right";
            this.tb_AlignRight.Click += new System.EventHandler(this.tb_AlignRight_Click);
            // 
            // toolStripSeparator7
            // 
            this.toolStripSeparator7.Name = "toolStripSeparator7";
            this.toolStripSeparator7.Size = new System.Drawing.Size(6, 25);
            // 
            // tb_UpperCase
            // 
            this.tb_UpperCase.DisplayStyle = System.Windows.Forms.ToolStripItemDisplayStyle.Text;
            this.tb_UpperCase.Font = new System.Drawing.Font("Arial Rounded MT Bold", 9F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.tb_UpperCase.Image = ((System.Drawing.Image)(resources.GetObject("tb_UpperCase.Image")));
            this.tb_UpperCase.ImageTransparentColor = System.Drawing.Color.Magenta;
            this.tb_UpperCase.Name = "tb_UpperCase";
            this.tb_UpperCase.Size = new System.Drawing.Size(23, 22);
            this.tb_UpperCase.Text = "A";
            this.tb_UpperCase.ToolTipText = "Uppercase";
            this.tb_UpperCase.Click += new System.EventHandler(this.tb_UpperCase_Click);
            // 
            // tb_LowerCase
            // 
            this.tb_LowerCase.DisplayStyle = System.Windows.Forms.ToolStripItemDisplayStyle.Text;
            this.tb_LowerCase.Font = new System.Drawing.Font("Arial Rounded MT Bold", 9F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.tb_LowerCase.Image = ((System.Drawing.Image)(resources.GetObject("tb_LowerCase.Image")));
            this.tb_LowerCase.ImageTransparentColor = System.Drawing.Color.Magenta;
            this.tb_LowerCase.Name = "tb_LowerCase";
            this.tb_LowerCase.Size = new System.Drawing.Size(23, 22);
            this.tb_LowerCase.Text = "a";
            this.tb_LowerCase.ToolTipText = "Lowercase";
            this.tb_LowerCase.Click += new System.EventHandler(this.tb_LowerCase_Click);
            // 
            // toolStripSeparator8
            // 
            this.toolStripSeparator8.Name = "toolStripSeparator8";
            this.toolStripSeparator8.Size = new System.Drawing.Size(6, 25);
            // 
            // tb_ZoomIn
            // 
            this.tb_ZoomIn.DisplayStyle = System.Windows.Forms.ToolStripItemDisplayStyle.Text;
            this.tb_ZoomIn.Font = new System.Drawing.Font("Arial Rounded MT Bold", 9F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.tb_ZoomIn.Image = ((System.Drawing.Image)(resources.GetObject("tb_ZoomIn.Image")));
            this.tb_ZoomIn.ImageTransparentColor = System.Drawing.Color.Magenta;
            this.tb_ZoomIn.Name = "tb_ZoomIn";
            this.tb_ZoomIn.Size = new System.Drawing.Size(23, 22);
            this.tb_ZoomIn.Text = "+";
            this.tb_ZoomIn.ToolTipText = "Zoom In";
            this.tb_ZoomIn.Click += new System.EventHandler(this.tb_ZoomIn_Click);
            // 
            // tb_ZoomOut
            // 
            this.tb_ZoomOut.DisplayStyle = System.Windows.Forms.ToolStripItemDisplayStyle.Text;
            this.tb_ZoomOut.Font = new System.Drawing.Font("Arial Rounded MT Bold", 9F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.tb_ZoomOut.Image = ((System.Drawing.Image)(resources.GetObject("tb_ZoomOut.Image")));
            this.tb_ZoomOut.ImageTransparentColor = System.Drawing.Color.Magenta;
            this.tb_ZoomOut.Name = "tb_ZoomOut";
            this.tb_ZoomOut.Size = new System.Drawing.Size(23, 22);
            this.tb_ZoomOut.Text = "-";
            this.tb_ZoomOut.ToolTipText = "Zoom Out";
            this.tb_ZoomOut.Click += new System.EventHandler(this.tb_ZoomOut_Click);
            // 
            // toolStripSeparator9
            // 
            this.toolStripSeparator9.Name = "toolStripSeparator9";
            this.toolStripSeparator9.Size = new System.Drawing.Size(6, 25);
            // 
            // tb_Font
            // 
            this.tb_Font.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.tb_Font.FlatStyle = System.Windows.Forms.FlatStyle.Standard;
            this.tb_Font.Name = "tb_Font";
            this.tb_Font.Size = new System.Drawing.Size(200, 25);
            this.tb_Font.SelectedIndexChanged += new System.EventHandler(this.tb_Font_SelectedIndexChanged);
            // 
            // tb_FontSize
            // 
            this.tb_FontSize.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.tb_FontSize.FlatStyle = System.Windows.Forms.FlatStyle.Standard;
            this.tb_FontSize.Name = "tb_FontSize";
            this.tb_FontSize.Size = new System.Drawing.Size(75, 25);
            this.tb_FontSize.SelectedIndexChanged += new System.EventHandler(this.tb_FontSize_SelectedIndexChanged);
            // 
            // toolStripSeparator2
            // 
            this.toolStripSeparator2.Name = "toolStripSeparator2";
            this.toolStripSeparator2.Size = new System.Drawing.Size(6, 25);
            // 
            // Status
            // 
            this.Status.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.charCount,
            this.toolStripStatusLabel2,
            this.status_ZoomFactor});
            this.Status.Location = new System.Drawing.Point(0, 413);
            this.Status.Name = "Status";
            this.Status.Size = new System.Drawing.Size(732, 22);
            this.Status.TabIndex = 2;
            this.Status.Text = "statusStrip1";
            // 
            // charCount
            // 
            this.charCount.Name = "charCount";
            this.charCount.Size = new System.Drawing.Size(63, 17);
            this.charCount.Text = "charCount";
            // 
            // toolStripStatusLabel2
            // 
            this.toolStripStatusLabel2.Name = "toolStripStatusLabel2";
            this.toolStripStatusLabel2.Size = new System.Drawing.Size(615, 17);
            this.toolStripStatusLabel2.Spring = true;
            // 
            // status_ZoomFactor
            // 
            this.status_ZoomFactor.Name = "status_ZoomFactor";
            this.status_ZoomFactor.Size = new System.Drawing.Size(39, 17);
            this.status_ZoomFactor.Text = "Zoom";
            // 
            // Document
            // 
            this.Document.ContextMenuStrip = this.rcMenu;
            this.Document.Dock = System.Windows.Forms.DockStyle.Fill;
            this.Document.Location = new System.Drawing.Point(0, 49);
            this.Document.Name = "Document";
            this.Document.Size = new System.Drawing.Size(732, 364);
            this.Document.TabIndex = 3;
            this.Document.Text = "";
            this.Document.LinkClicked += new System.Windows.Forms.LinkClickedEventHandler(this.Document_LinkClicked);
            // 
            // rcMenu
            // 
            this.rcMenu.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.rc_Undo,
            this.rc_Redo,
            this.toolStripSeparator10,
            this.rc_Cut,
            this.rc_Copy,
            this.rc_Paste});
            this.rcMenu.Name = "rcMenu";
            this.rcMenu.Size = new System.Drawing.Size(104, 120);
            // 
            // rc_Undo
            // 
            this.rc_Undo.Name = "rc_Undo";
            this.rc_Undo.Size = new System.Drawing.Size(103, 22);
            this.rc_Undo.Text = "Undo";
            this.rc_Undo.Click += new System.EventHandler(this.rc_Undo_Click);
            // 
            // rc_Redo
            // 
            this.rc_Redo.Name = "rc_Redo";
            this.rc_Redo.Size = new System.Drawing.Size(103, 22);
            this.rc_Redo.Text = "Redo";
            this.rc_Redo.Click += new System.EventHandler(this.rc_Redo_Click);
            // 
            // toolStripSeparator10
            // 
            this.toolStripSeparator10.Name = "toolStripSeparator10";
            this.toolStripSeparator10.Size = new System.Drawing.Size(100, 6);
            // 
            // rc_Cut
            // 
            this.rc_Cut.Name = "rc_Cut";
            this.rc_Cut.Size = new System.Drawing.Size(103, 22);
            this.rc_Cut.Text = "Cut";
            this.rc_Cut.Click += new System.EventHandler(this.rc_Cut_Click);
            // 
            // rc_Copy
            // 
            this.rc_Copy.Name = "rc_Copy";
            this.rc_Copy.Size = new System.Drawing.Size(103, 22);
            this.rc_Copy.Text = "Copy";
            this.rc_Copy.Click += new System.EventHandler(this.rc_Copy_Click);
            // 
            // rc_Paste
            // 
            this.rc_Paste.Name = "rc_Paste";
            this.rc_Paste.Size = new System.Drawing.Size(103, 22);
            this.rc_Paste.Text = "Paste";
            this.rc_Paste.Click += new System.EventHandler(this.rc_Paste_Click);
            // 
            // Timer
            // 
            this.Timer.Enabled = true;
            this.Timer.Interval = 1;
            this.Timer.Tick += new System.EventHandler(this.Timer_Tick_1);
            // 
            // openWork
            // 
            this.openWork.Filter = "Text Files|*.txt|RTF Files|*.rtf";
            this.openWork.Title = "Open Work";
            // 
            // saveWork
            // 
            this.saveWork.Filter = "Text Files|*.txt|RTF Files|*.rtf";
            this.saveWork.Title = "Save Work";
            // 
            // TextEditor
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(732, 435);
            this.Controls.Add(this.Document);
            this.Controls.Add(this.Status);
            this.Controls.Add(this.Tools);
            this.Controls.Add(this.mainMenu);
            this.MainMenuStrip = this.mainMenu;
            this.MinimumSize = new System.Drawing.Size(748, 473);
            this.Name = "TextEditor";
            this.ShowIcon = false;
            this.Text = "TextEditor";
            this.Load += new System.EventHandler(this.TextEditor_Load);
            this.mainMenu.ResumeLayout(false);
            this.mainMenu.PerformLayout();
            this.Tools.ResumeLayout(false);
            this.Tools.PerformLayout();
            this.Status.ResumeLayout(false);
            this.Status.PerformLayout();
            this.rcMenu.ResumeLayout(false);
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.MenuStrip mainMenu;
        private System.Windows.Forms.ToolStrip Tools;
        private System.Windows.Forms.ToolStripButton tb_New;
        private System.Windows.Forms.ToolStripButton tb_Open;
        private System.Windows.Forms.ToolStripButton tb_Save;
        private System.Windows.Forms.ToolStripSeparator toolStripSeparator;
        private System.Windows.Forms.ToolStripButton tb_Cut;
        private System.Windows.Forms.ToolStripButton tb_Copy;
        private System.Windows.Forms.ToolStripButton tb_Paste;
        private System.Windows.Forms.ToolStripSeparator toolStripSeparator1;
        private System.Windows.Forms.ToolStripComboBox tb_Font;
        private System.Windows.Forms.ToolStripComboBox tb_FontSize;
        private System.Windows.Forms.ToolStripSeparator toolStripSeparator2;
        private System.Windows.Forms.ToolStripButton tb_Bold;
        private System.Windows.Forms.ToolStripButton tb_Strike;
        private System.Windows.Forms.ToolStripSeparator toolStripSeparator3;
        private System.Windows.Forms.StatusStrip Status;
        private System.Windows.Forms.ToolStripStatusLabel charCount;
        private System.Windows.Forms.ToolStripStatusLabel toolStripStatusLabel2;
        private System.Windows.Forms.ToolStripStatusLabel status_ZoomFactor;
        private System.Windows.Forms.RichTextBox Document;
        private System.Windows.Forms.ToolStripButton tb_Italic;
        private System.Windows.Forms.ToolStripButton tb_UnderLine;
        private System.Windows.Forms.ToolStripButton tb_AlignLeft;
        private System.Windows.Forms.ToolStripButton tb_AlignCenter;
        private System.Windows.Forms.ToolStripButton tb_AlignRight;
        private System.Windows.Forms.ToolStripSeparator toolStripSeparator7;
        private System.Windows.Forms.ToolStripButton tb_UpperCase;
        private System.Windows.Forms.ToolStripButton tb_LowerCase;
        private System.Windows.Forms.ToolStripSeparator toolStripSeparator8;
        private System.Windows.Forms.ToolStripButton tb_ZoomIn;
        private System.Windows.Forms.ToolStripButton tb_ZoomOut;
        private System.Windows.Forms.ToolStripSeparator toolStripSeparator9;
        private System.Windows.Forms.ContextMenuStrip rcMenu;
        private System.Windows.Forms.ToolStripMenuItem rc_Undo;
        private System.Windows.Forms.ToolStripMenuItem rc_Redo;
        private System.Windows.Forms.ToolStripSeparator toolStripSeparator10;
        private System.Windows.Forms.ToolStripMenuItem rc_Cut;
        private System.Windows.Forms.ToolStripMenuItem rc_Copy;
        private System.Windows.Forms.ToolStripMenuItem rc_Paste;
        private System.Windows.Forms.ToolStripMenuItem mM_Edit;
        private System.Windows.Forms.ToolStripMenuItem edit_Undo;
        private System.Windows.Forms.ToolStripMenuItem edit_Redo;
        private System.Windows.Forms.ToolStripSeparator toolStripSeparator14;
        private System.Windows.Forms.ToolStripMenuItem edit_Cut;
        private System.Windows.Forms.ToolStripMenuItem edit_Copy;
        private System.Windows.Forms.ToolStripMenuItem edit_Paste;
        private System.Windows.Forms.ToolStripSeparator toolStripSeparator15;
        private System.Windows.Forms.ToolStripMenuItem edit_SelectAll;
        private System.Windows.Forms.ToolStripMenuItem mM_Tools;
        private System.Windows.Forms.ToolStripMenuItem tools_Customise;
        private System.Windows.Forms.ToolStripMenuItem mM_File;
        private System.Windows.Forms.ToolStripMenuItem file_New;
        private System.Windows.Forms.ToolStripMenuItem file_Open;
        private System.Windows.Forms.ToolStripSeparator toolStripSeparator11;
        private System.Windows.Forms.ToolStripMenuItem file_Save;
        private System.Windows.Forms.ToolStripSeparator toolStripSeparator13;
        private System.Windows.Forms.ToolStripMenuItem file_Exit;
        private System.Windows.Forms.Timer Timer;
        private System.Windows.Forms.OpenFileDialog openWork;
        private System.Windows.Forms.SaveFileDialog saveWork;
        private System.Windows.Forms.ToolStripButton toolStripButton1;
    }
}




        