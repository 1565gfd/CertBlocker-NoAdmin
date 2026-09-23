// CertBlocker - утилита блокировки (недоверия) сертификатов в Windows.
// Версия без оформления: стандартный интерфейс WinForms.
//
// Блокировка = добавление сертификата в хранилище недоверенных
// "Untrusted Certificates" (StoreName.Disallowed, StoreLocation.CurrentUser).
// Работает БЕЗ прав администратора, для текущего пользователя. После этого
// Windows и программы (Edge, Chrome, IE, .NET) перестают доверять сертификату.
//
// Все действия выполняются ТОЛЬКО по команде пользователя.
//
// Меры безопасности:
//   * защита от подмены DLL (DLL hijacking / binary planting);
//   * при загрузке файла берётся только публичная часть сертификата
//     (приватный ключ из .pfx не сохраняется на диск);
//   * освобождение объектов сертификатов (без утечки дескрипторов).
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Windows.Forms;

namespace CertBlocker
{
    internal static class Program
    {
        // --- Защита от подмены DLL (binary planting / DLL hijacking) ---
        // Критично для приложения с правами администратора, запускаемого из
        // каталога вроде Downloads: без этого Windows может подгрузить чужую
        // библиотеку из папки запуска. Ограничиваем поиск DLL только System32.
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool SetDefaultDllDirectories(uint DirectoryFlags);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool SetDllDirectory(string lpPathName);

        const uint LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800;

        [STAThread]
        static void Main()
        {
            // Выполняем в самом начале, до загрузки прочих библиотек.
            try { SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32); } catch { }
            try { SetDllDirectory(string.Empty); } catch { }

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm());
        }
    }

    internal class FoundCert
    {
        public X509Certificate2 Cert;
        public string Location;
        public string Store;
    }

    internal static class CertOps
    {
        public static string DisplayName(X509Certificate2 c)
        {
            if (!string.IsNullOrEmpty(c.FriendlyName)) return c.FriendlyName;
            var cn = c.GetNameInfo(X509NameType.SimpleName, false);
            if (!string.IsNullOrEmpty(cn)) return cn;
            return c.Subject;
        }

        public static string IssuerShort(X509Certificate2 c)
        {
            var s = c.GetNameInfo(X509NameType.SimpleName, true);
            return string.IsNullOrEmpty(s) ? c.Issuer : s;
        }

        // Заблокировать: добавить в CurrentUser\Disallowed (без прав администратора).
        // "ok" | "already" | "error:<msg>"
        public static string Block(X509Certificate2 cert)
        {
            var store = new X509Store(StoreName.Disallowed, StoreLocation.CurrentUser);
            try
            {
                store.Open(OpenFlags.ReadWrite);
                foreach (var c in store.Certificates)
                    if (c.Thumbprint == cert.Thumbprint) return "already";
                store.Add(cert);
                return "ok";
            }
            catch (Exception ex) { return "error:" + ex.Message; }
            finally { store.Close(); }
        }

        public static bool Unblock(string thumbprint)
        {
            var store = new X509Store(StoreName.Disallowed, StoreLocation.CurrentUser);
            try
            {
                store.Open(OpenFlags.ReadWrite);
                var toRemove = store.Certificates.Cast<X509Certificate2>()
                    .Where(c => c.Thumbprint == thumbprint).ToList();
                if (toRemove.Count == 0) return false;
                foreach (var c in toRemove) store.Remove(c);
                return true;
            }
            catch { return false; }
            finally { store.Close(); }
        }

        public static List<X509Certificate2> GetBlocked()
        {
            var store = new X509Store(StoreName.Disallowed, StoreLocation.CurrentUser);
            var result = new List<X509Certificate2>();
            try
            {
                store.Open(OpenFlags.ReadOnly);
                foreach (var c in store.Certificates) result.Add(c);
            }
            catch { }
            finally { store.Close(); }
            return result;
        }

        public static List<FoundCert> FindInstalled(string query)
        {
            var locations = new[] { StoreLocation.LocalMachine, StoreLocation.CurrentUser };
            var names = new[] { StoreName.Root, StoreName.CertificateAuthority, StoreName.AuthRoot, StoreName.My };
            var found = new List<FoundCert>();
            foreach (var loc in locations)
            {
                foreach (var sn in names)
                {
                    var store = new X509Store(sn, loc);
                    try
                    {
                        store.Open(OpenFlags.ReadOnly);
                        foreach (var c in store.Certificates)
                        {
                            bool match = string.IsNullOrEmpty(query)
                                || (c.Subject != null && c.Subject.IndexOf(query, StringComparison.OrdinalIgnoreCase) >= 0)
                                || (!string.IsNullOrEmpty(c.FriendlyName) && c.FriendlyName.IndexOf(query, StringComparison.OrdinalIgnoreCase) >= 0);
                            if (match)
                                found.Add(new FoundCert { Cert = c, Location = loc.ToString(), Store = sn.ToString() });
                        }
                    }
                    catch { }
                    finally { store.Close(); }
                }
            }
            return found.GroupBy(f => f.Cert.Thumbprint).Select(g => g.First()).ToList();
        }
    }

    internal class MainForm : Form
    {
        private ListView lstFound;
        private ListView lstBlocked;
        private TextBox txtSearch;
        private Label lblStatus;

        public MainForm()
        {
            Text = "CertBlocker — блокировка сертификатов Windows";
            Size = new Size(820, 600);
            MinimumSize = new Size(700, 500);
            StartPosition = FormStartPosition.CenterScreen;
            Font = new Font("Segoe UI", 9F);

            var lblHeader = new Label
            {
                Text = "Добавьте сертификат в список НЕДОВЕРЕННЫХ (для текущего пользователя). После этого Windows и браузеры перестанут ему доверять. Права администратора не требуются. Действие — только по вашей команде.",
                Location = new Point(12, 10),
                Size = new Size(786, 34),
                Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right
            };
            Controls.Add(lblHeader);

            var btnFromFile = new Button { Text = "Заблокировать из файла (.cer/.crt/.pem)…", Location = new Point(12, 50), Size = new Size(260, 30) };
            btnFromFile.Click += BtnFromFile_Click;
            Controls.Add(btnFromFile);

            var btnRefresh = new Button { Text = "Обновить список", Location = new Point(282, 50), Size = new Size(150, 30) };
            btnRefresh.Click += (s, e) => { UpdateBlocked(); SetStatus("Список обновлён.", false); };
            Controls.Add(btnRefresh);

            var btnExport = new Button { Text = "Экспорт выбранного (.cer)", Location = new Point(442, 50), Size = new Size(200, 30) };
            btnExport.Click += (s, e) => ExportSelectedFound();
            Controls.Add(btnExport);

            var lblSearch = new Label { Text = "Поиск установленных:", Location = new Point(12, 92), Size = new Size(150, 20) };
            Controls.Add(lblSearch);

            txtSearch = new TextBox { Location = new Point(166, 90), Size = new Size(190, 24) };
            txtSearch.KeyDown += (s, e) => { if (e.KeyCode == Keys.Enter) { DoSearch(txtSearch.Text.Trim()); e.SuppressKeyPress = true; } };
            Controls.Add(txtSearch);

            var btnSearch = new Button { Text = "Искать", Location = new Point(362, 89), Size = new Size(80, 26) };
            btnSearch.Click += (s, e) => DoSearch(txtSearch.Text.Trim());
            Controls.Add(btnSearch);

            var btnBlockSel = new Button { Text = "Заблокировать выбранный", Location = new Point(448, 89), Size = new Size(200, 26) };
            btnBlockSel.Click += (s, e) => BlockSelectedFound();
            Controls.Add(btnBlockSel);

            lstFound = new ListView
            {
                Location = new Point(12, 122),
                Size = new Size(786, 170),
                View = View.Details,
                FullRowSelect = true,
                GridLines = true,
                MultiSelect = false,
                Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right
            };
            lstFound.Columns.Add("Имя", 300);
            lstFound.Columns.Add("Издатель / Хранилище", 250);
            lstFound.Columns.Add("Действует до", 110);
            lstFound.Columns.Add("Отпечаток", 300);
            lstFound.DoubleClick += (s, e) => BlockSelectedFound();
            Controls.Add(lstFound);

            var lblBlocked = new Label
            {
                Text = "Заблокированные сертификаты (Untrusted / Disallowed):",
                Location = new Point(12, 302),
                Size = new Size(500, 20),
                Font = new Font("Segoe UI", 9F, FontStyle.Bold),
                Anchor = AnchorStyles.Top | AnchorStyles.Left
            };
            Controls.Add(lblBlocked);

            lstBlocked = new ListView
            {
                Location = new Point(12, 326),
                Size = new Size(786, 170),
                View = View.Details,
                FullRowSelect = true,
                GridLines = true,
                MultiSelect = false,
                Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right
            };
            lstBlocked.Columns.Add("Имя", 320);
            lstBlocked.Columns.Add("Действует до", 120);
            lstBlocked.Columns.Add("Отпечаток", 320);
            Controls.Add(lstBlocked);

            var btnUnblock = new Button
            {
                Text = "Разблокировать выбранный (вернуть доверие)",
                Location = new Point(12, 506),
                Size = new Size(300, 32),
                Anchor = AnchorStyles.Bottom | AnchorStyles.Left
            };
            btnUnblock.Click += (s, e) => UnblockSelected();
            Controls.Add(btnUnblock);

            lblStatus = new Label
            {
                Text = "Готово. Выберите действие.",
                Location = new Point(325, 512),
                Size = new Size(473, 24),
                Anchor = AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right,
                ForeColor = Color.FromArgb(0, 100, 0)
            };
            Controls.Add(lblStatus);

            UpdateBlocked();
        }

        private void SetStatus(string text, bool error)
        {
            lblStatus.Text = text;
            lblStatus.ForeColor = error ? Color.FromArgb(160, 0, 0) : Color.FromArgb(0, 100, 0);
        }

        private void UpdateBlocked()
        {
            lstBlocked.Items.Clear();
            foreach (var c in CertOps.GetBlocked())
            {
                var item = new ListViewItem(CertOps.DisplayName(c));
                item.SubItems.Add(c.NotAfter.ToString("yyyy-MM-dd"));
                item.SubItems.Add(c.Thumbprint);
                item.Tag = c.Thumbprint;   // храним только отпечаток, не сам объект
                lstBlocked.Items.Add(item);
                c.Dispose();               // объект сертификата больше не нужен
            }
        }

        private void FillFound(List<FoundCert> results)
        {
            // Освобождаем сертификаты предыдущего поиска, чтобы не копить дескрипторы.
            foreach (ListViewItem it in lstFound.Items)
            {
                var old = it.Tag as X509Certificate2;
                if (old != null) old.Dispose();
            }
            lstFound.Items.Clear();
            foreach (var r in results)
            {
                var item = new ListViewItem(CertOps.DisplayName(r.Cert));
                item.SubItems.Add(CertOps.IssuerShort(r.Cert) + "  [" + r.Location + "\\" + r.Store + "]");
                item.SubItems.Add(r.Cert.NotAfter.ToString("yyyy-MM-dd"));
                item.SubItems.Add(r.Cert.Thumbprint);
                item.Tag = r.Cert;
                lstFound.Items.Add(item);
            }
            if (lstFound.Items.Count > 0) lstFound.Items[0].Selected = true;
        }

        private void DoSearch(string query)
        {
            if (string.IsNullOrEmpty(query)) { SetStatus("Введите текст для поиска.", true); return; }
            SetStatus("Поиск: " + query + " …", false);
            var found = CertOps.FindInstalled(query);
            FillFound(found);
            if (found.Count == 0)
                SetStatus("Ничего не найдено.", true);
            else
                SetStatus("Найдено: " + found.Count + ". Выберите и нажмите «Заблокировать выбранный».", false);
        }

        private void DoBlock(X509Certificate2 cert)
        {
            var name = CertOps.DisplayName(cert);
            var res = CertOps.Block(cert);
            if (res == "ok") { SetStatus("Заблокировано: " + name, false); UpdateBlocked(); }
            else if (res == "already") SetStatus("Уже заблокирован: " + name, false);
            else SetStatus("Ошибка: " + res.Substring(6), true);
        }

        private void BtnFromFile_Click(object sender, EventArgs e)
        {
            using (var dlg = new OpenFileDialog())
            {
                dlg.Filter = "Сертификаты (*.cer;*.crt;*.der;*.pem)|*.cer;*.crt;*.der;*.pem|Все файлы (*.*)|*.*";
                dlg.Title = "Выберите файл сертификата для блокировки";
                if (dlg.ShowDialog() == DialogResult.OK)
                {
                    X509Certificate2 pub = null;
                    try
                    {
                        // Берём ТОЛЬКО публичную часть (RawData), чтобы не сохранять
                        // на диск приватный ключ из возможного .pfx.
                        using (var loaded = new X509Certificate2(dlg.FileName))
                            pub = new X509Certificate2(loaded.RawData);
                        DoBlock(pub);
                    }
                    catch (Exception ex) { SetStatus("Ошибка чтения файла: " + ex.Message, true); }
                    finally { if (pub != null) pub.Dispose(); }
                }
            }
        }

        private void ExportSelectedFound()
        {
            if (lstFound.SelectedItems.Count == 0) { SetStatus("Сначала выберите сертификат в верхнем списке.", true); return; }
            var cert = (X509Certificate2)lstFound.SelectedItems[0].Tag;
            using (var dlg = new SaveFileDialog())
            {
                dlg.Filter = "Сертификат (*.cer)|*.cer";
                var nm = CertOps.DisplayName(cert);
                foreach (var ch in System.IO.Path.GetInvalidFileNameChars()) nm = nm.Replace(ch, '_');
                dlg.FileName = (nm.Length > 60 ? nm.Substring(0, 60) : nm) + ".cer";
                if (dlg.ShowDialog() != DialogResult.OK) return;
                try
                {
                    System.IO.File.WriteAllBytes(dlg.FileName, cert.Export(X509ContentType.Cert));
                    SetStatus("Сохранено: " + dlg.FileName, false);
                }
                catch (Exception ex) { SetStatus("Ошибка экспорта: " + ex.Message, true); }
            }
        }

        private void BlockSelectedFound()
        {
            if (lstFound.SelectedItems.Count == 0) { SetStatus("Сначала выберите сертификат в верхнем списке.", true); return; }
            DoBlock((X509Certificate2)lstFound.SelectedItems[0].Tag);
        }

        private void UnblockSelected()
        {
            if (lstBlocked.SelectedItems.Count == 0) { SetStatus("Выберите сертификат в списке заблокированных.", true); return; }
            var thumb = (string)lstBlocked.SelectedItems[0].Tag;
            var name = lstBlocked.SelectedItems[0].Text;
            var r = MessageBox.Show("Вернуть доверие сертификату:\n" + name + "\n\nОн будет удалён из списка недоверенных.",
                "Подтверждение", MessageBoxButtons.YesNo, MessageBoxIcon.Question);
            if (r == DialogResult.Yes)
            {
                if (CertOps.Unblock(thumb)) { SetStatus("Разблокировано: " + name, false); UpdateBlocked(); }
                else SetStatus("Не удалось разблокировать: " + name, true);
            }
        }
    }
}
