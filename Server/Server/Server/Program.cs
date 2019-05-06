using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Server
{
    class Program
    {
        static void Main(string[] args)
        {
            TcpListener server = null;
            try
            {
                server = new TcpListener(11000);
                server.Start();

                while (true)
                {
                    Console.WriteLine("Ожидание подключений... ");

                    TcpClient client = server.AcceptTcpClient();
                    Console.WriteLine("Подключен клиент. Выполнение запроса...");

                    RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();

                    byte[] privateKey = RSA.ExportCspBlob(true);
                    byte[] publicKey = RSA.ExportCspBlob(false);
                    //Console.WriteLine(Encoding.UTF8.GetString(publicKey));
                    


                    byte[] data = new byte[256];
                    StringBuilder response = new StringBuilder();

                    NetworkStream stream = client.GetStream();
                    byte[] encryptKey = new byte[128]; // буфер для ответа
                    byte[] IV = new byte[16];
                    byte[] encryptText = new byte[256];

                    // отправка публичного ключа rsa
                    stream.Write(publicKey, 0, publicKey.Length);

                    stream.Read(encryptKey, 0, encryptKey.Length);
                    //Console.WriteLine(Encoding.ASCII.GetString(encryptKey));
                    stream.Read(IV, 0, IV.Length);
                    int bytes = stream.Read(encryptText, 0, encryptText.Length);
                    //Console.WriteLine(Encoding.ASCII.GetString(IV));

                    byte[] aesKey = RSA_Decrypt.RSADecrypt(encryptKey, privateKey, false);
                    byte[] text = new byte[bytes];
                    for(int i = 0; i < bytes; i++)
                    {
                        text[i] = encryptText[i];
                    }

                    string decryptText = AES_Decrypt.DecryptStringFromBytes_Aes(text, aesKey, IV);

                    byte[] dataSend = Encoding.UTF8.GetBytes(decryptText);
                    stream.Write(dataSend, 0, dataSend.Length);
                    //Console.WriteLine("Сообщение полученное от клиента: {0}", response);

                    /*string responseClient = "Привет клиент!!!";
                    byte[] dataClient = Encoding.UTF8.GetBytes(responseClient);

                    stream.Write(dataClient, 0, dataClient.Length);
                    Console.WriteLine("Отправлено сообщение: {0}", responseClient);*/


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
