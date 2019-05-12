using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Server
{
    class RSA_Decrypt
    {
        public static byte[] RSADecrypt(byte[] DataToDecrypt, byte[] privateKey, bool DoOAEPPadding)
        {
            try
            {
                byte[] decryptedData;
                //Создание объекта RSACryptoServiceProvider.
                using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
                {
                    //Импорт ключа
                    RSA.ImportCspBlob(privateKey);

                    //Расшифровка данных 
                    decryptedData = RSA.Decrypt(DataToDecrypt, DoOAEPPadding);
                }
                return decryptedData;
            }
            catch (CryptographicException e)
            {
                Console.WriteLine(e.ToString());

                return null;
            }

        }
    }
}
