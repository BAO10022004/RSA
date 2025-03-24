using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace RSAModel
{
    public partial class DencryptForm : Form
    {
        private BigInteger N;
        private BigInteger d;
        private string pathKey;
        public DencryptForm()
        {
            InitializeComponent();
        }
        private static (BigInteger, BigInteger) ReadKey(string filePath)
        {
            string[] lines = File.ReadAllLines(filePath);
            BigInteger N = BigInteger.Parse(lines[0].Split('=')[1]);
            BigInteger value = BigInteger.Parse(lines[1].Split('=')[1]);
            return (N, value);
        }

        private void guna2Button1_Click(object sender, EventArgs e)
        {
            if (ofdKey.ShowDialog() == DialogResult.OK)
            {
                txtKeyPath.Text = ofdKey.FileName;
                pathKey = fileInputPath.FileName;
            }
        }

        private void btnBrowseIntputPath_Click(object sender, EventArgs e)
        {
            if (fileInputPath.ShowDialog() == DialogResult.OK)
            {
                txtInputPath.Text = fileInputPath.FileName;
            }
        }

        private void btnBrowseOutputPath_Click(object sender, EventArgs e)
        {
            if (folderOutputDialog.ShowDialog() == DialogResult.OK)
            {
                txtOutputPath.Text = folderOutputDialog.SelectedPath;
            }
        }

        private void btnUse_Click(object sender, EventArgs e)
        {
            (N, d) = ReadKey(txtKeyPath.Text);
            lbDataN.Text =  N.ToString();
            lbDatad.Text = d.ToString();
        }
     
        

        private void btnDecrypt_Click(object sender, EventArgs e)
        {
            RSAHelper rsa = new RSAHelper(512);
            
           
        }

        private void BgWorker2_DoWork(object sender, DoWorkEventArgs e)
        {
            dynamic args = e.Argument;
            BigInteger nBig = args.nBig;
            BigInteger dBig = args.dBig;
            DecryptFile(args.fileInput, args.decryptedFolder, dBig, nBig);
        }

        private void BgWorker2_ProgressChanged(object sender, ProgressChangedEventArgs e)
        {
            guna2ProgressBar1.Value = e.ProgressPercentage;
        }

        private void BgWorker2_RunWorkerCompleted(object sender, RunWorkerCompletedEventArgs e)
        {
            guna2ProgressBar1.Value = 100;
            MessageBox.Show("Quá trình giải mã đã hoàn tất!", "Thông báo", MessageBoxButtons.OK, MessageBoxIcon.Information);
            guna2ProgressBar1.Value = 0;
        }

         void DecryptDirectory(string sourceDir, string destDir, BigInteger d, BigInteger n)
        {
            if (!Directory.Exists(destDir))
                Directory.CreateDirectory(destDir);
            foreach (string file in Directory.GetFiles(sourceDir))
            {
                if (file.EndsWith(".enc"))
                {
                    DecryptFile(file, destDir, d, n);
                }
            }
            foreach (string subDir in Directory.GetDirectories(sourceDir))
            {
                string subDirName = Path.GetFileName(subDir);
                string newDestDir = Path.Combine(destDir, subDirName);
                DecryptDirectory(subDir, newDestDir, d, n);
            }
            
        }

        public static void DecryptFile(string encryptedFile, string destDir, BigInteger d, BigInteger n)
        {
            Directory.CreateDirectory(destDir);

            string filename = Path.GetFileNameWithoutExtension(encryptedFile);
            string decryptedFile = Path.Combine(destDir, filename);

            string[] encryptedLines = File.ReadAllLines(encryptedFile);
            encryptedLines = encryptedLines.Skip(1).ToArray(); // Bỏ header

            List<byte> decryptedBytes = new List<byte>();

            foreach (string line in encryptedLines)
            {
                if (BigInteger.TryParse(line.Trim(), out BigInteger encryptedValue))
                {
                    BigInteger decryptedBlock = BigInteger.ModPow(encryptedValue, d, n);

                    // Tách thành 2 byte
                    byte highByte = (byte)(decryptedBlock >> 8);
                    byte lowByte = (byte)(decryptedBlock & 0xFF);

                    decryptedBytes.Add(highByte);
                    if (lowByte != 0) decryptedBytes.Add(lowByte);  // Nếu lowByte = 0, có thể đó là padding
                }
            }

            File.WriteAllBytes(decryptedFile, decryptedBytes.ToArray());
        }

        public static int Clamp(int value, int min, int max)
        {
            return (value < min) ? min : (value > max) ? max : value;
        }

        static string GetDecryptedContent(string encryptedFile, BigInteger d, BigInteger n)
        {
            StringBuilder content = new StringBuilder();

            try
            {
                using (StreamReader reader = new StreamReader(encryptedFile))
                {
                    string line;
                    while ((line = reader.ReadLine()) != null)
                    {
                        if (!string.IsNullOrWhiteSpace(line))
                        {
                            try
                            {
                                BigInteger encryptedValue = BigInteger.Parse(line.Trim());
                                BigInteger decryptedValue = BigInteger.ModPow(encryptedValue, d, n);

                                if (decryptedValue >= 0 && decryptedValue <= 255)
                                {
                                    byte b = (byte)decryptedValue;
                                    content.Append((char)b); // Chuyển byte thành ký tự
                                }
                            }
                            catch
                            {
                                // Bỏ qua các dòng lỗi
                            }
                        }
                    }
                }

                return content.ToString();
            }
            catch (Exception ex)
            {
                return $"Lỗi: {ex.Message}";
            }
        }
        static BigInteger ModPow(BigInteger value, BigInteger exponent, BigInteger modulus)
        {
            return BigInteger.ModPow(value, exponent, modulus);
        }
        private void btnExcute_Click(object sender, EventArgs e)
        {
            DecryptFile(txtInputPath.Text, txtOutputPath.Text, d, N);
        }
    }

    
}
