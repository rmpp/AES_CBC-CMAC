package cmac;

import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;


public class Cmac {

	public Cmac() {
		this.mac = null;
	}

	byte[] mac;

	public byte[] getMac() {
		return mac;
	}

	public void setMac(byte[] mac) {
		this.mac = mac;
	}

	public static Cmac compute(byte[] iv, byte[] data, CmacKeys keys){

		Cmac cMac = new Cmac();
		
		try {

			//Encrypt IV ( Nopadding-> IV.lenght must equal to BLOCK_SIZE)
			SecretKeySpec aesKey = new SecretKeySpec(keys.getKey1(),"AES");
			Cipher encryptIV = Cipher.getInstance("AES/ECB/NoPadding");
			encryptIV.init(Cipher.ENCRYPT_MODE, aesKey);
			byte[] encryptedIV = encryptIV.doFinal(iv);
			
			int  nBlocks = data.length/16;

			int  lastBlen = data.length%16;

			byte[] lastState;
			byte[] lastBData;

			boolean padding=false;

			if(lastBlen> 0){
				padding = true;
				nBlocks++;
			}


			if(nBlocks > 1){

				byte[] cbcdata =  Arrays.copyOf(data, (nBlocks-1)*16);

				//CBC
				aesKey= new SecretKeySpec(keys.getCbcKey(),"AES");
				IvParameterSpec ivparam = new IvParameterSpec(encryptedIV);
				Cipher cbc = Cipher.getInstance("AES/CBC/NoPadding");
				cbc.init(Cipher.ENCRYPT_MODE,aesKey,ivparam);

				byte[] cbcCt = cbc.doFinal(cbcdata);

				//get cbc last state
				lastState = Arrays.copyOfRange(cbcCt,(nBlocks-2)*16, (nBlocks-1)*16);

				lastBData = Arrays.copyOfRange(data,(nBlocks-1)*16 ,(nBlocks)*16);

			}else{

				if(data.length==0){
					lastState = encryptedIV;
					lastBData = DatatypeConverter.parseHexBinary("00000000000000000000000000000000");
					padding=true;

				}else{

					lastState = encryptedIV;
					lastBData = Arrays.copyOfRange(data,(nBlocks-1)*16 ,(nBlocks)*16);
				}
			}


			//Add Padding if needed
			if(lastBlen!=0 ||padding){
				lastBData[lastBlen]= (byte) 128;
			}


			if(padding){
				for (int i = 0; i < 16; i++) {
					lastBData[i] = (byte) ( (lastBData[i]) ^ ( keys.getKey2()[i]));
				}
			}else{
				for (int i = 0; i < 16; i++) {
					lastBData[i] = (byte) ( (lastBData[i]) ^ ( keys.getKey1()[i]));
				}

			}

			aesKey= new SecretKeySpec(keys.getCbcKey(),"AES");
			IvParameterSpec ivparam = new IvParameterSpec(lastState);
			Cipher cbc = Cipher.getInstance("AES/CBC/NoPadding");
			cbc.init(Cipher.ENCRYPT_MODE,aesKey, ivparam);

			cMac.setMac(cbc.doFinal(lastBData));

		} catch (Exception  e) {
			e.printStackTrace();
		}

		return cMac;
	}

}
