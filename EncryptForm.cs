using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Numerics;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Windows.Forms;

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
        private byte [] fileInput;
        private string folderInput;
        private string pathOutput;
        private string KeyPrivate;
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
        
        private async void btnCreate_Click(object sender, EventArgs e)
        {
            // Step 1
            p =await GeneratePrimeNumber(cbSizeKey.Text);
            q = await GeneratePrimeNumber(cbSizeKey.Text);
            do
            {
                q = await GeneratePrimeNumber(cbSizeKey.Text);
            }while(q.Equals(p));
            N = BigInteger.Parse(p) * BigInteger.Parse(q) + "";
            lbDatep.Text = p.Substring(0, Math.Min(10, p.Length)) + "..."; ;
            lbDataq.Text = q.Substring(0, Math.Min(10, q.Length)) + "..."; ;
            lbDataN.Text = N.Substring(0, Math.Min(10, N.Length)) + "..."; ;
            lib[lbDatep.Name] = p;
            lib[lbDataq.Name] =q;
            lib[lbDataN.Name] =N;
            // Step 2
            BigInteger nInteger = (BigInteger.Parse(p) - 1) * (BigInteger.Parse(q) - 1);
            n = nInteger.ToString();
            lbDataan.Text = n.Substring(0, Math.Min(10, n.Length)) + "...";
            lib[lbDataan.Name] = n;
            // Step 3
            this.e = await GenerateEAsync(cbSizeKey.Text); 
            lbDatae.Text = this.e.Substring(0, Math.Min(10, this.e.Length)) + "...";
            lib[lbDatae.Name] = this.e;
            // Step 4
            this.d = await GenerateDAsync(cbSizeKey.Text); 
            lbDatad.Text = this.d.Substring(0, Math.Min(10, this.e.Length)) + "...";
            lib[lbDatad.Name] = this.d;
            // Step 5
            lbKU.Text = $"({lbDatae.Text},{lbDataN.Text})";
            lbKR.Text = $"({lbDatad.Text},{lbDataN.Text})";
            cbType.DataSource = new List<string>()
            {
                "Folder",
                "File"
            };
            // Save Key private and Send Key public 
           
            string publicKeyPath = "C:\\Users\\giaba\\source\\repos\\3\\Ky2\\Network Security\\Test\\KEY\\publicKey.pem";
            string privateKeyPath = "C:\\Users\\giaba\\source\\repos\\3\\Ky2\\Network Security\\Test\\KEY\\privateKey.pem";

            // Xuất Public Key
            File.WriteAllText(publicKeyPath,N+this.e);

            // Xuất Private Key
            File.WriteAllText(privateKeyPath,N+d);

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
                    pathOutput= folderInputDialog.SelectedPath;
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
            BigInteger nBig = BigInteger.Parse(n);
            BigInteger eBig = BigInteger.Parse(this.e);
            if (cbType.Text.Equals("File"))
            {
                
                byte[] sourchBytes = fileInput;
                BigInteger plaintext = new BigInteger(sourchBytes);
                BigInteger ciphertext = ModPow(plaintext, eBig, nBig);
                File.WriteAllBytes($"{pathOutput}\\output.bin", ciphertext.ToByteArray());
            }
            else
            {
                string sourceFolder = txtInputPath.Text;
                string encryptedFolder = txtOutputPath.Text;
                EncryptDirectory(sourceFolder, 
                                encryptedFolder, 
                                eBig, 
                                nBig
                                );
            }
            
        }
        static void EncryptDirectory(string sourceDir, string destDir, BigInteger e, BigInteger n)
        {
            if (!Directory.Exists(destDir))
                Directory.CreateDirectory(destDir);
            foreach (string file in Directory.GetFiles(sourceDir))
            {
                string fileName = Path.GetFileName(file);
                string encryptedFilePath = Path.Combine(destDir, fileName + ".enc");
                byte[] fileBytes = File.ReadAllBytes(file);
                BigInteger plaintext = new BigInteger(fileBytes);
                BigInteger ciphertext = ModPow(plaintext, e, n);
                File.WriteAllBytes(encryptedFilePath, ciphertext.ToByteArray());
            }
            foreach (string subDir in Directory.GetDirectories(sourceDir))
            {
                string subDirName = Path.GetFileName(subDir);
                string newDestDir = Path.Combine(destDir, subDirName);
                EncryptDirectory(subDir, newDestDir, e, n);
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
    }
}
