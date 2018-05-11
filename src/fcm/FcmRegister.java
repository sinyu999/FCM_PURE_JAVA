package fcm;

import java.io.BufferedInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.UUID;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.bouncycastle.util.encoders.Base64;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.mozilla.httpece.HttpEce;

import checkin_proto.AndroidCheckin.AndroidCheckinProto;
import checkin_proto.AndroidCheckin.ChromeBuildProto;
import checkin_proto.AndroidCheckin.ChromeBuildProto.Channel;
import checkin_proto.AndroidCheckin.ChromeBuildProto.Platform;
import checkin_proto.AndroidCheckin.DeviceType;
import checkin_proto.Checkin.AndroidCheckinRequest;
import checkin_proto.Checkin.AndroidCheckinResponse;
import mcs_proto.Mcs.AppData;
import mcs_proto.Mcs.DataMessageStanza;
import mcs_proto.Mcs.LoginRequest;
import mcs_proto.Mcs.LoginRequest.AuthService;
import mcs_proto.Mcs.Setting;
public class FcmRegister extends Thread{
	private final String URL_GOOGLE_CHECKIN = "https://android.clients.google.com/checkin";
	private final String URL_GOOGLE_GCM_REGISTER = "https://android.clients.google.com/c2dm/register3";
	private final String URL_GOOGLE_FCM_REGISTER = "https://fcm.googleapis.com/fcm/connect/subscribe";
	private final String URL_GOOGLE_FCM_ENDPOINT = "https://fcm.googleapis.com/fcm/send";
	private final String DOMAIN_GOOGLE_MTALK = "mtalk.google.com";
	private final int PORT_GOOGLE_MTALK = 5228;
	private final String CHROME_VERSION = "63.0.3234.0";
	
	private String senderId = null;
	private FcmMessageListener listener = null;
	private boolean listenStop = false;
	private JSONObject credentials;
	private ArrayList<String> persistent_ids = new ArrayList<String>();
	public FcmRegister(String senderId){
		this.senderId = senderId;
	}
	
	public void setListener(FcmMessageListener listener){
		this.listener = listener;
	}
	
	public void setPersistentIds(ArrayList<String> persistent_ids){
		try{
			this.persistent_ids.addAll(persistent_ids);
		}catch(Exception e){
			
		}
	}
	
	public void listen(JSONObject credentials) throws Exception{
		if(credentials != null){}
		else{
		JSONParser jsonParser = new JSONParser();
		credentials = (JSONObject) jsonParser.parse("{\"gcm\":{\"securityToken\":2245100093084439068,\"appId\":\"wp:receiver.push.com#256f53eb-9d64-4129-bdb3-0d9eab30723a\",\"androidId\":4810723990713834544,\"token\":\"c4vijMZM5MU:APA91bFLUAo34cRWF0whaRBEiGgHisKfE2Yojpy1PHiyjES5o6Hya7VDkF4ZZhMXGng6NMsndFtBlSNtBNZjm2J67C1htDTzJnLUMd1U8IVwGmntBImWqDSYP28Y0l-VvvFFHESsMlHo\"},\"fcm\":{\"pushSet\":\"fyRoIJc4Aao:APA91bFfwlelzc8iTdIhWEuz7ABbv46QpjYYGbw1G__EvAwBAlH45oPPseEg1rh9bOPbGuLp9g7zE-njRIBqOJrN-Ue7ZpFCIOmlsMlS19UapBk4g68oJduDGifh-le8cKqzWECtVpUT\",\"token\":\"dpTpIxWPyKo:APA91bEAP3N8nusCGRYpJSUtyLJJtdRBWuuUaIn73lGslz1rJJkQ4dbbfF0rMWzd4T3ca0cKkAO4WlVqZT2spFKJt_p0YSkvHv0h0ENxWti-E9bxoaMzzLjFlQXVdBjV0bYejvrgt9q1\"},\"keys\":{\"privateKey\":\"c/fJHJRnZrpiCR2hkomMwDBhxWgJdqlY1e/yeav+ygY=\",\"authSecret\":\"3Wkz3/npLa5zVKL2a3MaAw==\",\"publicKey\":\"BMsD/Ht1Q+V2helgV/PjLWXLPmxZIK+v2sV49KsDBwYiAByS9UtKHa6XL7aintKHTvpjEDiRWDYBFgAxeNGOtNE=\"}}");
		}
		this.credentials = credentials;
		Long androidId = new Long(((JSONObject)credentials.get("gcm")).get("androidId").toString());
		Long securityToken = new Long(((JSONObject)credentials.get("gcm")).get("securityToken").toString());
		checkIn(androidId, securityToken);
		connectListenSocket();
		start();
	}
	
	private SSLSocket sslSock = null;
	
	private void connectListenSocket() throws Exception{
		try{sslSock.close();}catch(Exception e){}
		
		JSONObject jsonGcm = (JSONObject)credentials.get("gcm");
		LoginRequest.Builder loginRequest = LoginRequest.newBuilder();
		loginRequest.setAdaptiveHeartbeat(false);
		loginRequest.setAuthService(AuthService.ANDROID_ID);
		loginRequest.setAuthToken(jsonGcm.get("securityToken").toString());
		loginRequest.setId("chrome-"+CHROME_VERSION);
		loginRequest.setDomain("mcs.android.com");
		loginRequest.setDeviceId("android-"+Long.toHexString(new Long(jsonGcm.get("androidId").toString())));
		loginRequest.setNetworkType(1);
		loginRequest.setResource(jsonGcm.get("androidId").toString());
		loginRequest.setUser(jsonGcm.get("androidId").toString());
		loginRequest.setUseRmq2(true);
		loginRequest.addSetting(Setting.newBuilder().setName("new_vc").setValue("1").build());
		LoginRequest request = loginRequest.build();
		byte[] bRequest = request.toByteArray();
		
		byte[] preB = new byte[]{(byte)41,(byte)2,(byte)149,(byte)1};
		
		ByteBuffer bb = ByteBuffer.allocate(bRequest.length+preB.length);
		bb.put(preB);
		bb.put(bRequest);

		OutputStream os = null;
		SSLContext ctx = SSLContext.getInstance("TLS");
		ctx.init(null, null, null);
		SSLSocketFactory sf = ctx.getSocketFactory();
		sslSock = (SSLSocket)sf.createSocket(DOMAIN_GOOGLE_MTALK, PORT_GOOGLE_MTALK);
		sslSock.setSoTimeout(1000*60*5);
		os = sslSock.getOutputStream();
		
		os.write(bb.array());
		os.flush();
	}
	
	public void run(){
		while(!listenStop){
			InputStream is = null;
			try{
				byte[] bReads = new byte[1024*1024];
				int read = -1;
				is = sslSock.getInputStream();
				java.io.BufferedInputStream bis = new BufferedInputStream(is);
				java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
		
				while(!listenStop && (read = bis.read(bReads)) != -1){
					if(bReads[0] == 8){
						baos.reset();
		
						try{
							baos.write(bReads, 0, read);
							byte[] tb = baos.toByteArray();
							DataMessageStanza message = DataMessageStanza.parseFrom(tb);
							baos.reset();
							handleResponse(message);
						}catch(Exception e){
							//e.printStackTrace();
						}
					}else{
		
						try{
							baos.write(bReads, 0, read);
							byte[] tb = baos.toByteArray();
							DataMessageStanza message = DataMessageStanza.parseFrom(tb);
							baos.reset();
							handleResponse(message);
						}catch(Exception e){
							//e.printStackTrace();
						}
					}
					
				}
			}catch(Exception e){
				try{is.close();}catch(Exception ee){}
				//e.printStackTrace();
				if(!listenStop){
					try{
						sleep(1000);
						connectListenSocket();
					}catch(Exception ee){
						try{sleep(20000);}catch(Exception eee){eee.printStackTrace();}
					}
				}
			}
		}
		try{sslSock.close();}catch(Exception e){}
	}
	public void stopListen(){
		this.listenStop = true;
	}
	public void handleResponse(DataMessageStanza message) throws Exception{
		if(persistent_ids.contains(message.getPersistentId())) return;
		List<AppData> list = message.getAppDataList();
		String hexCryptoKey = null;
		String hexSalt = null;
		AppData temp = null;
		for(int i = 0; i < list.size(); i++){
			temp = list.get(i);
			if("encryption".equals(temp.getKey())){
				hexSalt = temp.getValue().substring(5).replaceAll("_", "/").replaceAll("-", "+");
			}else if("crypto-key".equals(temp.getKey())){
				hexCryptoKey = temp.getValue().substring(3).replaceAll("_", "/").replaceAll("-", "+");
			}
		}
		JSONObject jsonKey = (JSONObject) credentials.get("keys");
		
		if(hexCryptoKey != null && hexSalt != null){

	        HttpEce httpEce = new HttpEce();
	        HttpEce.Params params = new HttpEce.Params();
	        byte[] payload = message.getRawData().toByteArray();
	        PrivateKey receiverPrivate = ECDH_BC.loadPrivateKey(Base64.decode(jsonKey.get("privateKey").toString()));
	        PublicKey receiverPublic = ECDH_BC.loadPublicKey(Base64.decode(jsonKey.get("publicKey").toString()));
	        httpEce.saveKey("keyid", new KeyPair(receiverPublic, receiverPrivate), "P-256");
	        params.salt = Base64.decode(hexSalt);
	        params.dh = ECDH_BC.loadPublicKey(Base64.decode(hexCryptoKey));
	        params.keyId = "keyid";
	        params.authSecret = Base64.decode(jsonKey.get("authSecret").toString());

	        byte[] cipherText = httpEce.decrypt(payload, params);
	        
	        JSONParser jsonParser = new JSONParser();
			JSONObject jsonMessage = (JSONObject) jsonParser.parse(new String(cipherText));
			listener.receiveMessage((JSONObject) jsonMessage.get("data"), message.getPersistentId());
			this.persistent_ids.add(message.getPersistentId());
		}else{
			JSONObject jsonMessage = new JSONObject();
			AppData tempAppData = null;
			List<AppData> listAppData = message.getAppDataList();
			for(int i = 0; listAppData != null && i < listAppData.size(); i++){
				tempAppData = listAppData.get(i);
				jsonMessage.put(tempAppData.getKey(), tempAppData.getValue());
			}
			listener.receiveMessage(jsonMessage, message.getPersistentId());
			this.persistent_ids.add(message.getPersistentId());
		}
		
	}
	
	public JSONObject register() throws Exception{
		String appId = "wp:receiver.push.com#"+UUID.randomUUID().toString();
		JSONObject subscription = registerGCM(appId);
		JSONObject result = registerFCM(subscription);
		JSONObject credentials = null;
		if(result != null){
			credentials = new JSONObject();
			JSONObject jsonKeys = new JSONObject();
			jsonKeys.put("privateKey", result.get("privateKey"));
			jsonKeys.put("publicKey", result.get("publicKey"));
			jsonKeys.put("authSecret", result.get("authSecret"));
			JSONObject jsonFcm = new JSONObject();
			jsonFcm.put("token", result.get("token"));
			jsonFcm.put("pushSet", result.get("pushSet"));
			JSONObject jsonGcm = new JSONObject();
			jsonGcm.put("token", subscription.get("token"));
			jsonGcm.put("androidId", subscription.get("androidId"));
			jsonGcm.put("securityToken", subscription.get("securityToken"));
			jsonGcm.put("appId", appId);
			
			credentials.put("keys", jsonKeys);
			credentials.put("fcm", jsonFcm);
			credentials.put("gcm", jsonGcm);
			
			
		}
		return credentials;
	}
	
	public JSONObject registerGCM(String appId) throws Exception{
		JSONObject credentials = null;
		JSONObject options = checkIn(null, null);
		credentials = doRegisterGCM(options, appId);
		
		return credentials;
	}
	
	public JSONObject doRegisterGCM(JSONObject options, String appId) throws Exception{
		JSONObject credentials = null;
		java.net.HttpURLConnection httpConn = null;
		try{

			JSONObject body = new JSONObject();
			body.put("app", "org.chromium.linux");
			body.put("X-subtype", appId);
			body.put("device", options.get("androidId"));
			body.put("sender", senderId);
			

			URL url = new URL(URL_GOOGLE_GCM_REGISTER);
			httpConn = (HttpURLConnection) url.openConnection();
			httpConn.setRequestMethod("POST");
			httpConn.setRequestProperty("Authorization", "AidLogin "+options.get("androidId")+":"+options.get("securityToken"));
			httpConn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
			httpConn.setDoOutput(true);
			httpConn.setDoInput(true);
			
			String param = "";
			param += "app="+URLEncoder.encode("org.chromium.linux");
			param += "&X-subtype="+URLEncoder.encode(appId);
			param += "&device="+URLEncoder.encode(""+options.get("androidId"));
			param += "&sender="+URLEncoder.encode(senderId);

			OutputStream os = httpConn.getOutputStream();
			os.write(param.getBytes());
			os.flush();
			InputStream is = httpConn.getInputStream();
			byte rb[] = new byte[1024];
			int ri  = -1;

			java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
			while((ri = is.read(rb)) != -1){
				baos.write(rb, 0, ri);
			}
			String retmsg = new String(baos.toByteArray());
			os.close();
			is.close();
			String token = null;
			if(retmsg != null && retmsg.startsWith("token=")){
				credentials = new JSONObject();
				token = retmsg.split("=",2)[1];

				credentials.put("token", token);
				credentials.put("androidId", options.get("androidId"));
				credentials.put("securityToken", options.get("securityToken"));
				credentials.put("appId", appId);
				
			}
		}catch(Exception e){
			throw e;
		}finally{
			try{httpConn.disconnect();}catch(Exception e){}
		}
		return credentials;
	}
	
	public JSONObject registerFCM(JSONObject credentials) throws Exception{
		JSONObject jsonRet = null;
		java.net.HttpURLConnection httpConn = null;
		URL url = null;
		try{
			
			byte[] bAuthSecret = new byte[16];
			new Random().nextBytes(bAuthSecret);
			KeyPair keyPair = ECDH_BC.makeKeyPair();
			
			byte[] bPublicKey = ECDH_BC.savePublicKey(keyPair.getPublic());
			byte[] bPrivateKey = ECDH_BC.savePrivateKey(keyPair.getPrivate());
			String publicKey = Base64.toBase64String(bPublicKey);
			String privateKey = Base64.toBase64String(bPrivateKey);
			String authSecret = Base64.toBase64String(bAuthSecret);


			String param = "";
			param += "authorized_entity="+URLEncoder.encode(senderId);
			param += "&endpoint="+URLEncoder.encode(URL_GOOGLE_FCM_ENDPOINT+"/"+credentials.get("token"));
			param += "&encryption_key="+URLEncoder.encode(publicKey.replaceAll("=", "").replaceAll("\\+", "-").replaceAll("/", "_"));
			param += "&encryption_auth="+URLEncoder.encode(authSecret.replaceAll("=", "").replaceAll("\\+", "-").replaceAll("/", "_"));
			
			
			
			url = new URL(URL_GOOGLE_FCM_REGISTER);
			httpConn = (HttpURLConnection) url.openConnection();
			httpConn.setRequestMethod("POST");
			httpConn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
			httpConn.setDoOutput(true);
			httpConn.setDoInput(true);

			OutputStream os = httpConn.getOutputStream();
			os.write(param.getBytes());
			os.flush();
			InputStream is = httpConn.getInputStream();
			byte rb[] = new byte[1024*1024];
			int ri  = -1;

			java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
			while((ri = is.read(rb)) != -1){
				baos.write(rb, 0, ri);
			}
			JSONParser jsonParser = new JSONParser();
			jsonRet = (JSONObject) jsonParser.parse(new String(baos.toByteArray()));
			jsonRet.put("publicKey", publicKey);
			jsonRet.put("privateKey", privateKey);
			jsonRet.put("authSecret", authSecret);
			
			os.close();
			is.close();
			httpConn.disconnect();
		}catch(Exception e){
			throw e;
		}finally{
			try{httpConn.disconnect();}catch(Exception e){}
		}
		return jsonRet;
		
	}
	
	public JSONObject checkIn(Long androidId, Long securityToken) throws Exception{
		JSONObject options = null;

		java.net.HttpURLConnection httpConn = null;
		try{
			ChromeBuildProto.Builder chrome = ChromeBuildProto.newBuilder();
			chrome.setPlatform(Platform.PLATFORM_MAC);
			chrome.setChromeVersion(CHROME_VERSION);
			chrome.setChannel(Channel.CHANNEL_STABLE);
			AndroidCheckinProto.Builder checkin = AndroidCheckinProto.newBuilder();
			checkin.setType(DeviceType.DEVICE_CHROME_BROWSER);
			checkin.setChromeBuild(chrome);
			AndroidCheckinRequest.Builder request = AndroidCheckinRequest.newBuilder();
			request.setUserSerialNumber(0);
			request.setCheckin(checkin);
			request.setVersion(3);
			if(androidId != null) request.setId(androidId.longValue());
			if(securityToken != null) request.setSecurityToken(securityToken.longValue());
	

			URL url = new URL(URL_GOOGLE_CHECKIN);
			httpConn = (HttpURLConnection) url.openConnection();
			httpConn.setRequestMethod("POST");
			httpConn.setRequestProperty("Content-Type", "application/x-protobuf");
			httpConn.setDoOutput(true);
			httpConn.setDoInput(true);
			OutputStream os = httpConn.getOutputStream();
			request.build().writeTo(os);
			os.flush();
			
			InputStream is = httpConn.getInputStream();
			byte rb[] = new byte[1024];
			int ri  = -1;

			java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
			while((ri = is.read(rb)) != -1){
				baos.write(rb, 0, ri);
			}
			AndroidCheckinResponse response = AndroidCheckinResponse.parseFrom(baos.toByteArray());

			options = new JSONObject();
			options.put("statsOk", response.getStatsOk());
			options.put("timeMsec", response.getTimeMsec());
			options.put("androidId", response.getAndroidId());
			options.put("securityToken", response.getSecurityToken());
			options.put("versionInfo", response.getVersionInfo());
			
			os.close();
			is.close();
		}catch(Exception e){
			throw e;
		}finally{
			try{httpConn.disconnect();}catch(Exception e){}
		}
		return options;
	}
}
