package org.forgerock.am.tn.p1verify;

public class Constants {

	protected enum GovId {

		DEFAULT("DEFAULT"), 
		DRIVING_LICENSE("DRIVING_LICENSE"), 
		PASSPORT("PASSPORT"), 
		ID_CARD("ID_CARD");

		private final String val;

		GovId(String val) {
			this.val = val;
		}

		public String getVal() {
			return val;
		}
	}
	
	protected enum UserNotification {
		QR("QR"), 
		SMS("SMS"), 
		EMAIL("eMail");
		
		private final String val;
		
		
		UserNotification(String val){
			this.val = val;
		}
		
		public int getDeliveryMethod() {	
			if (val.equalsIgnoreCase("QR")) 
				return 0;
			 else if (val.equalsIgnoreCase("SMS")) 
				return 1;
			 else
				return 2;
		}
	}
	
	
	protected static final String FAIL = "FAIL";
	protected static final String SUCCESS = "SUCCESS";
	protected static final String ERROR = "ERROR";
	protected static final String AGEFAILED = "AGEFAILED";

}
