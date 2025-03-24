using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Net.Http;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Policy;
using System.Text;
using System.Threading.Tasks;
using System.Web.UI.WebControls;
using System.Windows.Forms;
using Label = System.Windows.Forms.Label;

namespace RSAModel
{
    public partial class EncryptForm : Form
    {
        string p;
        string q;
        string n;
        string N;
        string e;
        string d;
        private byte[] fileInput;
        private string folderInput;
        private string pathOutput;
        private string KeyPrivate;
        RSAHelper rsa;
        Dictionary<string, string> lib;
        private static readonly HttpClient client = new HttpClient();
        public EncryptForm()
        {
            InitializeComponent();
            lib = new Dictionary<string, string>();
            cbSizeKey.DataSource = new List<int>()
            {
                512,
                1024,
                2048
            };
            

        }

        private void btnCreate_Click(object sender, EventArgs e)
        {
            rsa = new RSAHelper(cbSizeKey.Text);
            rsa.SaveKeys();
            rsa.LoadPrivateKey("C:\\Users\\giaba\\source\\repos\\3\\Ky2\\Network Security\\Test\\KEY\\publicKey.pem");
            rsa.LoadPublicKey("C:\\Users\\giaba\\source\\repos\\3\\Ky2\\Network Security\\Test\\KEY\\publicKey.pem");
            cbType.DataSource = new List<string>()
            {
                "Folder",
                "File"
            };
           
        }

        private async Task<string> GeneratePrimeNumber(string number)
        {
            string baseUrl = "https://localhost:7183/api/MyRSA/Generate";

            string url = $"{baseUrl}?primeNumber={number}";
            HttpResponseMessage response = await client.GetAsync(url);
            if (response.IsSuccessStatusCode)
            {
                return await response.Content.ReadAsStringAsync();
            }
            else
            {
                return "Lỗi khi gọi API!";
            }
        }
        private async Task<string> GenerateEAsync(string number)
        {
            string result;
            string responseString;
            do
            {
                result = await GeneratePrimeNumber(cbSizeKey.Text);

                string baseUrl = "https://localhost:7183/basic";

                string url = $"{baseUrl}?number1={e}&number2={n}";
                HttpResponseMessage response = await client.GetAsync(url);
                if (response.IsSuccessStatusCode)
                {

                    responseString = await response.Content.ReadAsStringAsync();
                }
                else
                {
                    return "Lỗi khi gọi API!";
                }
            } while (responseString.Equals("1"));
            return result;


        }
        private async Task<string> GenerateDAsync(string number)
        {
            string result;
            string responseString;
            do
            {
                result = await GeneratePrimeNumber(cbSizeKey.Text);

                string baseUrl = "https://localhost:7183/Extend";

                string url = $"{baseUrl}?a={result}&b={n}";
                HttpResponseMessage response = await client.GetAsync(url);
                if (response.IsSuccessStatusCode)
                {

                    responseString = await response.Content.ReadAsStringAsync();
                }
                else
                {
                    return "Lỗi khi gọi API!";
                }
            } while (responseString.Equals("1"));
            return result;


        }
        private void lbDatep_Click(object sender, EventArgs e)
        {
            Label label = sender as Label;
            MessageBox.Show(lib[label.Name]);
        }

        private void guna2Panel8_Paint(object sender, PaintEventArgs e)
        {

        }

        private void btnBrowseIntputPath_Click(object sender, EventArgs e)
        {
            if (cbType.Text.Equals("File"))
            {
                if (fileInputPath.ShowDialog() == DialogResult.OK)
                {
                    txtInputPath.Text = fileInputPath.FileName;
                    fileInput = File.ReadAllBytes(fileInputPath.FileName);
                }
            }
            else
            {
                if (folderInputDialog.ShowDialog() == DialogResult.OK)
                {
                    txtInputPath.Text = folderInputDialog.SelectedPath;
                    folderInput = folderInputDialog.SelectedPath;
                }
            }
        }

        private void btnBrowseOutputPath_Click(object sender, EventArgs e)
        {
            if (folderOutputDialog.ShowDialog() == DialogResult.OK)
            {
                txtOutputPath.Text = folderOutputDialog.SelectedPath;
                pathOutput = folderOutputDialog.SelectedPath;
            }
        }

        private void btnExcute_Click(object sender, EventArgs e)
        {
            rsa.LoadPublicKey("C:\\Users\\giaba\\source\\repos\\3\\Ky2\\Network Security\\Test\\KEY\\publicKey.pem");
            rsa.EncryptFile
            (
                txtInputPath.Text,
                Path.Combine
                (
                    txtOutputPath.Text,
                    Path.GetFileNameWithoutExtension(new Uri(txtInputPath.Text).LocalPath) + ".dat"
                 )

             );
        }

        private void BgWorker_DoWork(object sender, DoWorkEventArgs e)
        {
            try
            {
                dynamic args = e.Argument;
                BigInteger nBig = args.nBig;
                BigInteger eBig = args.eBig;

                if (args.type == "File")
                {
                    EncryptFile(txtInputPath.Text, args.encryptedFolder, eBig, nBig);
                }
                else
                {
                    string[] files = Directory.GetFiles(args.sourceFolder);
                    int totalFiles = files.Length;
                    int processedFiles = 0;

                    foreach (var file in files)
                    {
                        EncryptFile(file, args.encryptedFolder, eBig, nBig);
                        processedFiles++;

                        // Báo cáo tiến trình
                        int percent = (int)((processedFiles / (double)totalFiles) * 100);
                        backgroundWorker1.ReportProgress(percent);
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Lỗi: {ex.Message}", "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
        private void BgWorker_ProgressChanged(object sender, ProgressChangedEventArgs e)
        {
            guna2ProgressBar1.Value = e.ProgressPercentage;
        }
        private void BgWorker_RunWorkerCompleted(object sender, RunWorkerCompletedEventArgs e)
        {
            guna2ProgressBar1.Value = 100;
            MessageBox.Show("Quá trình mã hóa đã hoàn tất!", "Thông báo", MessageBoxButtons.OK, MessageBoxIcon.Information);
            guna2ProgressBar1.Value = 0;
        }

        static void EncryptDirectory(string sourceDir, string destDir, BigInteger e, BigInteger n)
        {
            if (!Directory.Exists(destDir))
                Directory.CreateDirectory(destDir);
            foreach (string file in Directory.GetFiles(sourceDir))
            {
                EncryptFile(file, destDir, e, n);
            }
            foreach (string subDir in Directory.GetDirectories(sourceDir))
            {
                string subDirName = Path.GetFileName(subDir);
                string newDestDir = Path.Combine(destDir, subDirName);
                EncryptDirectory(subDir, newDestDir, e, n);
            }
        }

        public static void EncryptFile(string sourceFile, string destDir, BigInteger e, BigInteger n)
        {
            Directory.CreateDirectory(destDir);

            string filename = Path.GetFileName(sourceFile);
            string encryptedFile = Path.Combine(destDir, filename + ".enc");

            byte[] fileBytes = File.ReadAllBytes(sourceFile);

            using (StreamWriter writer = new StreamWriter(encryptedFile))
            {
                writer.WriteLine($"RSA ENCRYPTED FILE - Original: {filename}");

                for (int i = 0; i < fileBytes.Length; i += 2)  // Mã hóa theo khối 2 byte
                {
                    BigInteger block = (i + 1 < fileBytes.Length)
                        ? (fileBytes[i] << 8) | fileBytes[i + 1]
                        : fileBytes[i];

                    BigInteger encryptedBlock = BigInteger.ModPow(block, e, n);
                    writer.WriteLine(encryptedBlock.ToString());
                }
            }
        }
        static BigInteger ModPow(BigInteger baseValue, BigInteger exponent, BigInteger modulus)
        {
            BigInteger result = 1;
            while (exponent > 0)
            {
                if ((exponent & 1) == 1)
                    result = (result * baseValue) % modulus;

                baseValue = (baseValue * baseValue) % modulus;
                exponent >>= 1;
            }
            return result;
        }

        private void btnChosseKey_Click(object sender, EventArgs e)
        {
            if (ofdKey.ShowDialog() == DialogResult.OK)
            {
                txtKeyPath.Text = ofdKey.FileName;
            }            
        }

        private void btnUse_Click(object sender, EventArgs e)
        {
            rsa.LoadPrivateKey(txtKeyPath.Text);
        }

        private void btnChosseInputFile_Click(object sender, EventArgs e)
        {
            if (fileInputPath.ShowDialog() == DialogResult.OK)
            {
                txtInputFileDencrypt.Text = fileInputPath.FileName;
            }
        }

        private void btnChosseOutputFiles_Click(object sender, EventArgs e)
        {
            if (folderOutputDialog.ShowDialog() == DialogResult.OK)
            {
                txtOutputFileDencrypt .Text = folderOutputDialog.SelectedPath;
            }
        }

        private void btnExcuteDencrypt_Click(object sender, EventArgs e)
        {
            rsa.DecryptFile(txtInputFileDencrypt.Text, Path.Combine(txtOutputFileDencrypt.Text, "a.txt"));
        }

        private void guna2Panel13_Paint(object sender, PaintEventArgs e)
        {

        }
    }
}
