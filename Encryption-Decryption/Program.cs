using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;
using System.Configuration;

public class rfc2898test
{
	public static void Main(string[] passwordargs)
	{
		string data, encData, encKey, encAlgoKey, saltString, deData;
		encKey = "onek kothin ekta chabi banailam, onek mojbut";
		data = "Tomorrow a secret meeting will be held, don't compromise.";

		Encrypt(data, encKey, out encData, out encAlgoKey, out saltString);
		deData = Decrypt(encData, encKey, encAlgoKey, saltString);
	}
	public static void Encrypt(string data, string encKey, out string encData, out string encAlgoIvString, out string saltString)
	{
		int myIterations = 1000;

		byte[] salt = new byte[8];
		using (RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider())
		{
			// Fill the array with a random value.
			rngCsp.GetBytes(salt);
		}

		Rfc2898DeriveBytes k1 = new Rfc2898DeriveBytes(encKey, salt, myIterations);
		// Encrypt the data.
		TripleDES encAlg = TripleDES.Create();
		encAlg.Key = k1.GetBytes(16);
		MemoryStream encryptionStream = new MemoryStream();
		CryptoStream encrypt = new CryptoStream(encryptionStream,
encAlg.CreateEncryptor(), CryptoStreamMode.Write);
		byte[] utfD1 = new System.Text.UTF8Encoding(false).GetBytes(
data);

		encrypt.Write(utfD1, 0, utfD1.Length);
		encrypt.FlushFinalBlock();
		encrypt.Close();
		byte[] edata = encryptionStream.ToArray();

		encAlgoIvString = Convert.ToBase64String(encAlg.IV);
		encData = Convert.ToBase64String(edata);
		saltString = Convert.ToBase64String(salt);
		k1.Reset();
	}

	public static string Decrypt(string edata, string encKey, string encAlgoIvString, string saltString)
	{
		byte[] ddata = Convert.FromBase64String(edata);
		byte[] encAlgoIv = Convert.FromBase64String(encAlgoIvString);
		byte[] salt = Convert.FromBase64String(saltString);
		
		Rfc2898DeriveBytes k2 = new Rfc2898DeriveBytes(encKey, salt);

		// Try to decrypt, thus showing it can be round-tripped.
		TripleDES decAlg = TripleDES.Create();
		decAlg.Key = k2.GetBytes(16);
		decAlg.IV = encAlgoIv;
		MemoryStream decryptionStreamBacking = new MemoryStream();
		CryptoStream decrypt = new CryptoStream(decryptionStreamBacking, 
			decAlg.CreateDecryptor(), CryptoStreamMode.Write);
		
		decrypt.Write(ddata, 0, ddata.Length);
		decrypt.Flush();
		decrypt.Close();
		k2.Reset();
		string origData = new UTF8Encoding(false).GetString(
decryptionStreamBacking.ToArray());

		return origData;
	}
}
