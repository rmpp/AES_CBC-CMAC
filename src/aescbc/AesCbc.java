package aescbc;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import cmac.CmacKeys;

public class AesCbc {

	public static byte[] cipher(byte[] iv, byte[] data,CmacKeys keys){

		byte[] returnSPacket = null;

		try {

			//Encrypt IV ( Nopadding-> IV.lenght must equal to BLOCK_SIZE)
			SecretKeySpec aesKey = new SecretKeySpec(keys.getKey1(),"AES");
			Cipher encryptIV = Cipher.getInstance("AES/ECB/NoPadding");
			encryptIV.init(Cipher.ENCRYPT_MODE, aesKey);
			byte[] encryptedIV = encryptIV.doFinal(iv);


			//------------------CBC
			//////////////////////////////////////////////////////////////
			aesKey= new SecretKeySpec(keys.getCbcKey(),"AES");
			//Cbc IV = encryptedIV
			IvParameterSpec ivparam = new IvParameterSpec(encryptedIV);
			Cipher cbc = Cipher.getInstance("AES/CBC/PKCS5Padding");

			cbc.init(Cipher.ENCRYPT_MODE,aesKey, ivparam);
			byte[] encriptedPayload = cbc.doFinal(data);

			returnSPacket = encriptedPayload;

		} catch (Exception  e) {
			
			e.printStackTrace();
		}

		return returnSPacket;
	}

	
	public static byte[] deCipher(byte[] iv, byte[] payload, CmacKeys keys) {

		byte[] retPacket = null;

		try{

			//Encrypt IV Nopadding-> IV.lenght must equal to BLOCK_SIZE)
			SecretKeySpec aesKey = new SecretKeySpec(keys.getKey1(),"AES");
			Cipher encryptIV = Cipher.getInstance("AES/ECB/NoPadding");
			encryptIV.init(Cipher.ENCRYPT_MODE, aesKey);
			byte[] encryptedIV = encryptIV.doFinal(iv);

			//					CBC
			aesKey= new SecretKeySpec(keys.getCbcKey(),"AES");
			IvParameterSpec ivparam = new IvParameterSpec(encryptedIV);
			Cipher dCbc = Cipher.getInstance("AES/CBC/PKCS5Padding");

			dCbc.init(Cipher.DECRYPT_MODE,aesKey, ivparam);
			byte[] decriptedPayload = dCbc.doFinal(payload);

			retPacket = decriptedPayload;

		}catch(Exception e){
			e.printStackTrace();
		}

		return retPacket;
	}
	 
}
