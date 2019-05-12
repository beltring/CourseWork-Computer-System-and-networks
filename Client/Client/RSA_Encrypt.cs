using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Client
{
    class RSA_Encrypt
    {
        public static byte[] RSAEncrypt(byte[] DataToEncrypt, byte[] publicKey, bool DoOAEPPadding)
        {
            try
            {
                byte[] encryptedData;
                //Создание объекта RSACryptoServiceProvider.
                using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
                {

                    //Импорт ключа
                    RSA.ImportCspBlob(publicKey);

                    //Шифрование данных
                    encryptedData = RSA.Encrypt(DataToEncrypt, DoOAEPPadding);
                }
                return encryptedData;
            }

            catch (CryptographicException e)
            {
                Console.WriteLine(e.Message);

                return null;
            }

        }
    }
}
