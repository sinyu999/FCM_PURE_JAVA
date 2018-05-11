package fcm;

import java.util.ArrayList;

import org.json.simple.JSONObject;

public interface FcmMessageListener {
	public void savePersistentId(String persistent_id);
	public void receiveMessage(JSONObject message, String persistent_id);
}
