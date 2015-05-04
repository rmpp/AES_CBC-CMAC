package test;

import static org.junit.Assert.*;

import javax.xml.bind.DatatypeConverter;

import org.junit.Test;

import aescbc.AesCbc;
import cmac.Cmac;
import cmac.CmacKeys;

public class AesCbcCmacTest {


	@Test
	public void testM0() {

		byte[] cbcKey =  DatatypeConverter.parseHexBinary("2b7e151628aed2a6abf7158809cf4f3c");
		byte[] key1 =  DatatypeConverter.parseHexBinary("fbeed618357133667c85e08f7236a8de");
		byte[] key2 =  DatatypeConverter.parseHexBinary("f7ddac306ae266ccf90bc11ee46d513b");

		byte[] iv = DatatypeConverter.parseHexBinary("00000000000000000000000000000000");

		byte[] text= DatatypeConverter.parseHexBinary("");

		CmacKeys keys = new CmacKeys(key1,key2,cbcKey);

		byte[] encPayload = AesCbc.cipher(iv, text, keys);
		
		assertArrayEquals(text, AesCbc.deCipher(iv, encPayload, keys));
		
		Cmac mac = Cmac.compute(iv, text, keys);
			
		assertArrayEquals(mac.getMac(), Cmac.compute(iv, AesCbc.deCipher(iv, encPayload, keys), keys).getMac());
	}


	@Test
	public void testM1() {

		byte[] cbcKey =  DatatypeConverter.parseHexBinary("2b7e151628aed2a6abf7158809cf4f3c");
		byte[] key1 =  DatatypeConverter.parseHexBinary("fbeed618357133667c85e08f7236a8de");
		byte[] key2 =  DatatypeConverter.parseHexBinary("f7ddac306ae266ccf90bc11ee46d513b");

		byte[] iv = DatatypeConverter.parseHexBinary("00000000000000000000000000000000");

		byte[] text= DatatypeConverter.parseHexBinary("6bc1bee22e409f96e93d7e117393172a");

		CmacKeys keys = new CmacKeys(key1,key2,cbcKey);

		byte[] encPayload = AesCbc.cipher(iv, text, keys);
		
		assertArrayEquals(text, AesCbc.deCipher(iv, encPayload, keys));
		
		Cmac mac = Cmac.compute(iv, text, keys);
		
		assertArrayEquals(mac.getMac(), Cmac.compute(iv, AesCbc.deCipher(iv, encPayload, keys), keys).getMac());
	}



	@Test
	public void testM2() {

		byte[] cbcKey =  DatatypeConverter.parseHexBinary("2b7e151628aed2a6abf7158809cf4f3c");
		byte[] key1 =  DatatypeConverter.parseHexBinary("fbeed618357133667c85e08f7236a8de");
		byte[] key2 =  DatatypeConverter.parseHexBinary("f7ddac306ae266ccf90bc11ee46d513b");

		byte[] iv = DatatypeConverter.parseHexBinary("00000000000000000000000000000000");
		byte[] text= DatatypeConverter.parseHexBinary("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411");

		CmacKeys keys = new CmacKeys(key1,key2,cbcKey);

		byte[] encPayload = AesCbc.cipher(iv, text, keys);
		
		assertArrayEquals(text, AesCbc.deCipher(iv, encPayload, keys));
		
		Cmac mac = Cmac.compute(iv, text, keys);
		
		assertArrayEquals(mac.getMac(), Cmac.compute(iv, AesCbc.deCipher(iv, encPayload, keys), keys).getMac());
		
	}



	@Test
	public void testM3() {

		byte[] cbcKey =  DatatypeConverter.parseHexBinary("2b7e151628aed2a6abf7158809cf4f3c");
		byte[] key1 =  DatatypeConverter.parseHexBinary("fbeed618357133667c85e08f7236a8de");
		byte[] key2 =  DatatypeConverter.parseHexBinary("f7ddac306ae266ccf90bc11ee46d513b");

		byte[] iv = DatatypeConverter.parseHexBinary("00000000000000000000000000000000");

		byte[] text= DatatypeConverter.parseHexBinary("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");

		CmacKeys keys = new CmacKeys(key1,key2,cbcKey);

		byte[] encPayload = AesCbc.cipher(iv, text, keys);
		
		assertArrayEquals(text, AesCbc.deCipher(iv, encPayload, keys));
		
		Cmac mac = Cmac.compute(iv, text, keys);
		
		assertArrayEquals(mac.getMac(), Cmac.compute(iv, AesCbc.deCipher(iv, encPayload, keys), keys).getMac());
	}

}
