using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;
namespace RSAModel
{

    class RSAHelper {
        private RSA rsa;
        private  RSAParameters rsaParams;

        public RSAHelper(int keySize)
        {
           
            rsa = RSA.Create();
            rsa.KeySize = keySize;
            rsaParams = rsa.ExportParameters(true);
            if (rsa is RSACryptoServiceProvider rsaCsp)
            {
                rsaCsp.PersistKeyInCsp = false;
            }
        }
        public RSAHelper(string  keySize)
        {
            rsa = RSA.Create();
            rsa.KeySize = int.Parse(keySize);
        }

        public void SaveKeys()
        {
            File.WriteAllText("C:\\Users\\giaba\\source\\repos\\3\\Ky2\\Network Security\\Test\\KEY\\publicKey.pem", rsa.ToXmlString(false)); 
            File.WriteAllText("C:\\Users\\giaba\\source\\repos\\3\\Ky2\\Network Security\\Test\\KEY\\privateKey.pem", rsa.ToXmlString(true)); 
        }

        public void LoadPublicKey(String path)
        {
            rsa.FromXmlString(File.ReadAllText(path));
        }

        public void LoadPrivateKey(String path)
        {
            rsa.FromXmlString(File.ReadAllText(path));
        }


        public void EncryptFile(string inputFile, string outputFile)
        {
            byte[] fileBytes = File.ReadAllBytes(inputFile);
            byte[] encryptedBytes = rsa.Encrypt(fileBytes, RSAEncryptionPadding.Pkcs1);
            File.WriteAllBytes(outputFile, encryptedBytes);
            MessageBox.Show("Success");
        }
        public void DecryptFile(string inputFile, string outputFile)
        {
            byte[] encryptedBytes = File.ReadAllBytes(inputFile);
            byte[] decryptedBytes = rsa.Decrypt(encryptedBytes, RSAEncryptionPadding.Pkcs1);
            File.WriteAllBytes(outputFile, decryptedBytes);
        }
      
    }


}
