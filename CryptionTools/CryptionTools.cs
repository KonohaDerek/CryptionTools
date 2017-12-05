using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.IO;

namespace CryptionTools
{
  public  class CryptionTools
    {  
        public  const int Bit_128 = 128;
        public const int Bit_256 = 256;
        public const int Bit_512 = 512;
        public const int Bit_1024 = 1024;


        /// <summary>
        /// 將輸入的Key值做轉換
        /// Author By Derek
        /// Create Time : 2014/01/08
        /// UpdateTime : 2014/01/08
        /// Set the Key 
        /// </summary>
        /// <param name="key"></param>
        /// <returns>key hash by System.Security.Cryptography.MD5</returns>
        public byte[] SetEncryKey(string key, int EncryptLenth)
        {
            StringBuilder st = new StringBuilder();
            st.Append(key);
            while (st.Length < (EncryptLenth / 8))
            {
                st.Append(st);
            }
            key = st.ToString().Substring(0, EncryptLenth / 8);
            System.Security.Cryptography.MD5 md5 = new System.Security.Cryptography.MD5CryptoServiceProvider();
            byte[] myHash = md5.ComputeHash(System.Text.Encoding.Default.GetBytes(key));
            //sKey = BitConverter.ToString(myHash);
            //sKey = sKey.Replace("-", "");

            return myHash;
        }

        /// <summary>
        /// 將輸入的IV值做轉換
        /// Author By Derek
        /// Create Time : 2014/01/08
        /// UpdateTime : 2014/01/08
        /// Set the IV 
        /// </summary>
        /// <param name="IV"></param>
        /// <returns>IV hash by System.Security.Cryptography.MD5</returns>
        public byte[] SetEncryIV(String IV, int EncryptLenth)
        {
            StringBuilder st = new StringBuilder();
            st.Append(IV);
            while (st.Length < (EncryptLenth / 8))
            {
                st.Append(IV);
            }
            IV = st.ToString().Substring(0, EncryptLenth / 8);
            System.Security.Cryptography.MD5 md5 = new System.Security.Cryptography.MD5CryptoServiceProvider();
            byte[] myHash = md5.ComputeHash(System.Text.Encoding.Default.GetBytes(IV));
            //sIV = BitConverter.ToString(myHash, 0, EncryptLenth / 8);
            //sIV = sKey.Replace("-", "");
            return myHash;
        }

        public string Get_MD5_String(string strSource)
        {
            //new
            System.Security.Cryptography.MD5 md5 = new System.Security.Cryptography.MD5CryptoServiceProvider();

            //獲取密文字節數組
            byte[] bytResult = md5.ComputeHash(System.Text.Encoding.Default.GetBytes(strSource));

            //轉換成字符串，并取9到25位
            //string strResult = BitConverter.ToString(bytResult, 4, 8);
            //轉換成字符串，32位
            string strResult = BitConverter.ToString(bytResult);

            //BitConverter轉換出來的字符串會在每個字符中間產生一個分隔符，需要去除掉
            strResult = strResult.Replace("-", "");
            return strResult;
        }


        #region public string TripleDESEncryptString(string Value, String Key, String IV, CipherMode ciphermode, PaddingMode paddingmode)
        /// <summary>
        /// TripleDES加密字符串
        /// Author By Derek
        /// Create Time : 2014/01/08
        /// UpdateTime : 2014/01/08
        /// </summary>
        /// <param name="Value">输入的字符串</param>
        /// <returns>加密后的字符串</returns>
        public string TripleDESEncryptString(string Value, String Key, String IV, CipherMode ciphermode, PaddingMode paddingmode, int EncryptLenth)
        {
            ICryptoTransform ct;
            MemoryStream ms;
            CryptoStream cs;
            byte[] byt;
            byte [] iv=SetEncryIV(IV,EncryptLenth/8);
            byte[] skey = new byte[8];
             using( SymmetricAlgorithm mCSP = new TripleDESCryptoServiceProvider()){
                 
                 mCSP.Key = SetEncryKey(Key, EncryptLenth);
                 for (int i = 0; i < 8;i++ )
                 {
                     skey[i] = iv[i];
                     
                 }
                 mCSP.IV = skey;
                //指定加密的运算模式
                 mCSP.Mode = ciphermode;
                //获取或设置加密算法的填充模式
                 mCSP.Padding = paddingmode;
                ct = mCSP.CreateEncryptor(mCSP.Key, mCSP.IV);
                byt = Encoding.UTF8.GetBytes(Value);
                ms = new MemoryStream();
                cs = new CryptoStream(ms, ct, CryptoStreamMode.Write);
                cs.Write(byt, 0, byt.Length);
                cs.FlushFinalBlock();
                cs.Close();
             }
            return Convert.ToBase64String(ms.ToArray());
        }
        #endregion

        #region public string TripleDESDecryptString(string Value, String Key, String IV, CipherMode ciphermode, PaddingMode paddingmode)
        /// <summary>
        /// TripleDES解密字符串
        /// Author By Derek
        /// Create Time : 2014/01/08
        /// UpdateTime : 2014/01/08
        /// </summary>
        /// <param name="Value">加过密的字符串</param>
        /// <returns>解密后的字符串</returns>
        public string TripleDESDecryptString(string Value, String Key, String IV, CipherMode ciphermode, PaddingMode paddingmode, int EncryptLenth)
        {
            ICryptoTransform ct;
            MemoryStream ms;
            CryptoStream cs;
            byte[] byt;
            byte[] iv = SetEncryIV(IV, EncryptLenth / 8);
            byte[] skey = new byte[8];
             using( SymmetricAlgorithm mCSP = new TripleDESCryptoServiceProvider()){
                mCSP.Key = SetEncryKey(Key, EncryptLenth);
                for (int i = 0; i < 8; i++)
                {
                    skey[i] = iv[i];

                }
                mCSP.IV = skey;
                mCSP.Mode = ciphermode;
                mCSP.Padding = paddingmode;
                ct = mCSP.CreateDecryptor(mCSP.Key, mCSP.IV);
                byt = Convert.FromBase64String(Value);
                ms = new MemoryStream();
                cs = new CryptoStream(ms, ct, CryptoStreamMode.Write);
                cs.Write(byt, 0, byt.Length);
                cs.FlushFinalBlock();
                cs.Close();
             }
            return Encoding.UTF8.GetString(ms.ToArray());
        }
        #endregion

        #region public string EncryptStringAES(String Key, String IV, String Value, CipherMode mode, int EncryptLenth, PaddingMode Padding)
        /// <summary>
        /// AES解密字符串
        /// Author By Derek
        /// Create Time : 2014/01/08
        /// UpdateTime : 2014/01/08
        /// </summary>
        /// <param name="Key"></param>
        /// <param name="IV"></param>
        /// <param name="Value">輸入的字串</param>
        /// <param name="mode">指定加密運算式</param>
        /// <param name="EncryptLenth">加密長度</param>
        /// <param name="Padding">填充模式</param>
        /// <returns>加密後的字串</returns>
        public String EncryptStringAES(String Key, String IV, String Value, CipherMode mode, int EncryptLenth, PaddingMode Padding)
        {
            String result = "";
            ICryptoTransform ct;
            using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
            {
                //aes.BlockSize = EncryptLenth/8;
                //aes.KeySize = EncryptLenth/8;
                //aes.FeedbackSize = EncryptLenth/8;
                aes.Mode = mode;
                aes.Padding = Padding;
                ct = aes.CreateEncryptor( SetEncryKey(Key, EncryptLenth),SetEncryIV(IV, EncryptLenth));
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, ct, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {

                            //Write all data to the stream.
                            swEncrypt.Write(Value);
                        }
                        result = Convert.ToBase64String(msEncrypt.ToArray());
                    }
                }
            }
            return result;
        }
        #endregion

        #region public string DecryptStringAES(String Key, String IV, String Value, CipherMode mode, int EncryptLenth, PaddingMode Padding)
        /// <summary>
        /// AES解密字符串
        /// Author By Derek
        /// Create Time : 2014/01/08
        /// UpdateTime : 2014/01/08
        /// </summary>
        /// <param name="Key"></param>
        /// <param name="IV"></param>
        /// <param name="Value">要解密的字串</param>
        /// <param name="mode">指定解密運算式</param>
        /// <param name="EncryptLenth">解密長度</param>
        /// <param name="Padding">填充模式</param>
        /// <returns>解密後的字串</returns>
        public String DecryptStringAES(String Key, String IV, String Value, CipherMode mode, int EncryptLenth, PaddingMode Padding)
        {
            String result = "";
            using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
            {
                //aes.BlockSize = EncryptLenth;
                //aes.KeySize = EncryptLenth;
                aes.Mode = mode;
                aes.Padding = Padding;
                ICryptoTransform decryptor = aes.CreateDecryptor(SetEncryKey(Key, EncryptLenth), SetEncryIV(IV, EncryptLenth));

                // Create the streams used for decryption. 
                using (MemoryStream msDecrypt = new MemoryStream(Convert.FromBase64String(Value)))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            // Read the decrypted bytes from the decrypting stream 
                            // and place them in a string.
                            result = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
            return result;
        }
        #endregion
    }
}
