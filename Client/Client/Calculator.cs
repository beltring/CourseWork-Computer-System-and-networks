using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Client
{
    class Calculator
    {
        private Aes myAes;
        private byte[] key;
        private byte[] IV;
        private Form1 form1;
        public Calculator(Form1 form)
        {
            myAes = Aes.Create();
            key = myAes.Key;
            IV = myAes.IV;
            form1 = form;
        }

        public Aes MyAes { get => myAes;}
        public byte[] Key { get => key;}
        public byte[] IV1 { get => IV;}

        public byte[] EncryptText(string text)
        {
            byte[] encryptText = AES_Encrypt.EncryptStringToBytes_Aes(text, key, IV);
            return encryptText;
        }

        public void ConnectServer(string dnsName)
        {
            try
            {
                TcpClient client = new TcpClient(dnsName, 11000);

                NetworkStream stream = client.GetStream();
                byte[] publicKey = new byte[148];

                do
                {
                    stream.Read(publicKey, 0, publicKey.Length);   
                }
                while (stream.DataAvailable);
              

                byte[] encryptKey = RSA_Encrypt.RSAEncrypt(key, publicKey, false);
                
                byte[] encryptText = AES_Encrypt.EncryptStringToBytes_Aes(form1.textBox1.Text, key, IV);
                form1.textBox1.Text = Encoding.ASCII.GetString(encryptText);
                System.IO.File.WriteAllText(@"d:\Study\COURSE_TWO\КСиС\курсач\dataClient.txt", form1.textBox1.Text);

                stream.Write(encryptKey, 0, encryptKey.Length);
                stream.Write(IV, 0, IV.Length);
                stream.Write(encryptText, 0, encryptText.Length);
                /*string dataSend = "Привет сервер!!!";
                byte[] data = Encoding.UTF8.GetBytes(dataSend);
                stream.Write(data, 0, data.Length);*/


                byte[] data = new byte[256];
                StringBuilder response = new StringBuilder();

                do
                {
                    int bytes = stream.Read(data, 0, data.Length);
                    response.Append(Encoding.UTF8.GetString(data, 0, bytes));
                }
                while (stream.DataAvailable);

                form1.textBox2.Text = response.ToString();


                stream.Close();
                client.Close();
            }
            catch (SocketException e)
            {
                MessageBox.Show(e.Message);
            }
            catch (Exception e)
            {
                MessageBox.Show(e.Message);
            }
        }
    }
}
