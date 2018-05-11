package fcm;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.KeyFactory;
import java.security.Security;
import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Random;
import java.security.spec.ECGenParameterSpec;
import javax.crypto.KeyAgreement;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Base64;

public class ECDH_BC
{

	public static byte [] savePublicKey (PublicKey key) throws Exception
	{
		//return key.getEncoded();

		ECPublicKey eckey = (ECPublicKey)key;
		return eckey.getQ().getEncoded(false);
	}

	public static PublicKey loadPublicKey (byte [] data) throws Exception
	{
		Security.addProvider(new BouncyCastleProvider());
		/*KeyFactory kf = KeyFactory.getInstance("ECDH", "BC");
		return kf.generatePublic(new X509EncodedKeySpec(data));*/

		ECParameterSpec params = ECNamedCurveTable.getParameterSpec("prime256v1");
		ECPublicKeySpec pubKey = new ECPublicKeySpec(
				params.getCurve().decodePoint(data), params);
		KeyFactory kf = KeyFactory.getInstance("ECDH", "BC");
		return kf.generatePublic(pubKey);
	}

	public static byte [] savePrivateKey (PrivateKey key) throws Exception
	{
		//return key.getEncoded();

		ECPrivateKey eckey = (ECPrivateKey)key;
		return eckey.getD().toByteArray();
	}

	public static PrivateKey loadPrivateKey (byte [] data) throws Exception
	{
		Security.addProvider(new BouncyCastleProvider());
		//KeyFactory kf = KeyFactory.getInstance("ECDH", "BC");
		//return kf.generatePrivate(new PKCS8EncodedKeySpec(data));

		ECParameterSpec params = ECNamedCurveTable.getParameterSpec("prime256v1");
		ECPrivateKeySpec prvkey = new ECPrivateKeySpec(new BigInteger(data), params);
		KeyFactory kf = KeyFactory.getInstance("ECDH", "BC");
		return kf.generatePrivate(prvkey);
	}
	
	public static KeyPair makeKeyPair() throws Exception{
		Security.addProvider(new BouncyCastleProvider());
		
		KeyPairGenerator kpgen = KeyPairGenerator.getInstance("ECDH", "BC");
		kpgen.initialize(new ECGenParameterSpec("prime256v1"), new SecureRandom());
		
		return kpgen.generateKeyPair();
	}

	public static void main (String [] args) throws Exception
	{
		Random r = new Random();
		
		byte[] bRandom = new byte[16];
		r.nextBytes(bRandom);
		String s = Base64.toBase64String(bRandom);
		
		KeyPair pairA = ECDH_BC.makeKeyPair();
		
		byte [] dataPrvA = savePrivateKey(pairA.getPrivate());
		byte [] dataPubA = savePublicKey(pairA.getPublic());
		byte [] aaa = pairA.getPublic().getEncoded();
		
		System.out.println(pairA.getPublic().getAlgorithm());
		System.out.println(pairA.getPublic().getFormat());
		System.out.println("Alice Prv: " + Base64.toBase64String(dataPrvA).replaceAll("=", ""));
		System.out.println("Alice Pub: " + Base64.toBase64String(aaa, aaa.length-65, 65).replaceAll("=", ""));
		System.out.println("Alice Pub: " + Base64.toBase64String(pairA.getPublic().getEncoded()).replaceAll("=", ""));
		System.out.println("Alice Pub: " + Base64.toBase64String(dataPubA).replaceAll("=", ""));
		System.out.println("authSecret: " + Base64.toBase64String(bRandom).replaceAll("=", ""));
		
		PublicKey pkk = loadPublicKey(dataPubA);
		System.out.println("Alice Pub: " + Base64.toBase64String(pkk.getEncoded()).replaceAll("=", ""));
		
		byte[] ttt = new byte[65];
		byte [] dest = pairA.getPublic().getEncoded();
		System.arraycopy(dest, dest.length-65, ttt, 0, 65);
		System.out.println("Alice Prv: " + Base64.toBase64String(ttt).replaceAll("=", ""));

	}
}
