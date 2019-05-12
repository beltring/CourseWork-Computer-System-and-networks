using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Server
{
    class Server
    {
        private const int port = 11000;
        private const int keySize = 128;
        private const int IV_Size = 16;
        private const int textSize = 1024;

        static void Main(string[] args)
        {
            TcpListener server = null;
            try
            {
                server = new TcpListener(port);
                server.Start();

                while (true)
                {
                    Console.WriteLine("Ожидание подключений... ");

                    TcpClient client = server.AcceptTcpClient();
                    Console.WriteLine("Подключен клиент. Выполнение запроса...");

                    RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();

                    byte[] privateKey = RSA.ExportCspBlob(true);
                    byte[] publicKey = RSA.ExportCspBlob(false);

                    StringBuilder response = new StringBuilder();

                    NetworkStream stream = client.GetStream();
                    byte[] encryptKey = new byte[keySize]; // буфер для ответа
                    byte[] IV = new byte[IV_Size];
                    byte[] encryptText = new byte[textSize];

                    // отправка публичного ключа rsa
                    stream.Write(publicKey, 0, publicKey.Length);

                    // получение данных
                    stream.Read(encryptKey, 0, encryptKey.Length);
                    stream.Read(IV, 0, IV.Length);
                    int bytes = stream.Read(encryptText, 0, encryptText.Length);
                    
                    byte[] aesKey = RSA_Decrypt.RSADecrypt(encryptKey, privateKey, false);

                    byte[] text = new byte[bytes];
                    for(int i = 0; i < bytes; i++)
                    {
                        text[i] = encryptText[i];
                    }

                    string decryptText = AES_Decrypt.DecryptStringFromBytes_Aes(text, aesKey, IV);

                    byte[] dataSend = Encoding.UTF8.GetBytes(decryptText);
                    stream.Write(dataSend, 0, dataSend.Length);
                    
                    stream.Close();
                    client.Close();
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
            finally
            {
                if (server != null)
                    server.Stop();
            }
        }
    }
}
