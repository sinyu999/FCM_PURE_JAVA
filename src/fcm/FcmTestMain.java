package fcm;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.net.URLDecoder;
import java.util.ArrayList;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

public class FcmTestMain {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		new FcmTestMain().test();
	}
	
	public void test(){
		String senderId = "387701834168";
		FcmMessageListener listener = new FcmMessageListener(){
			public void receiveMessage(JSONObject message, String persistent_id){
				try{
					System.out.println(message.toJSONString());
					System.out.println(URLDecoder.decode(message.get("msg").toString(), "utf8"));
					savePersistentId(persistent_id);
				}catch(Exception e){
					e.printStackTrace();
				}
			}
			public void savePersistentId(String persistent_id){
				FileOutputStream fos = null;
				try{
					fos = new FileOutputStream("persistentIds.dat", true);
					fos.write((persistent_id+"\n").getBytes());
					fos.flush();
				}catch(Exception e){
					e.printStackTrace();
				}finally{
					try{fos.close();}catch(Exception e){}
				}
				
			}
		};
		

		ArrayList<String> persistent_ids = new ArrayList<String>();
		JSONObject credentials = null;
		try{
			File f1 = new File("credentials.dat");
			if(f1.exists() && f1.isFile()){
				FileInputStream fis = null;
				try{
					byte[] b = new byte[2048];
					int read = -1;
					fis = new FileInputStream(f1);
					read = fis.read(b);
					JSONParser jsonParser = new JSONParser();
					credentials = (JSONObject) jsonParser.parse(new String(b, 0, read));
				}catch(Exception e){
					
				}finally{
					try{fis.close();}catch(Exception e){}
				}
			}
			

			FcmRegister fr = new FcmRegister(senderId);
			fr.setListener(listener);
			if(credentials != null){
				System.out.println(credentials.toJSONString());
				File f2 = new File("persistentIds.dat");
				if(f2.exists() && f2.isFile()){
					java.io.BufferedReader br = null;
					try{
						br = new BufferedReader(new FileReader("persistentIds.dat"));
						String line = null;
						while((line = br.readLine()) != null){
							if(line.length() > 10){
								persistent_ids.add(line);
							}
						}
					}catch(Exception e){
						
					}finally{
						try{br.close();}catch(Exception e){}
					}
				}
				fr.setPersistentIds(persistent_ids);
				fr.listen(credentials);
				
			}else{
				System.out.println("credentials is null.");
				credentials = fr.register();
				if(credentials != null){
					FileOutputStream fos = new FileOutputStream("credentials.dat", false);
					fos.write(credentials.toJSONString().getBytes());
					fos.flush();
					fos.close();
					fos = new FileOutputStream("persistentIds.dat", false);
					fos.write("".getBytes());
					fos.flush();
					fos.close();
					JSONObject gcmInfo = (JSONObject) credentials.get("gcm");
					JSONObject fcmInfo = (JSONObject) credentials.get("fcm");
					String gcmToken = gcmInfo.get("token").toString();
					String fcmToken = fcmInfo.get("token").toString();
					System.out.println("gcm_token:"+gcmToken);
					System.out.println("fcm_token:"+fcmToken);
					fr.listen(credentials);
				}
				
			}
		}catch(Exception e){
			e.printStackTrace();
		}
	}

}
