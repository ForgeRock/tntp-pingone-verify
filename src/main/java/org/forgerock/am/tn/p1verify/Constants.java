package org.forgerock.am.tn.p1verify;

import javax.security.auth.callback.ConfirmationCallback;

public class Constants {
	
	
	protected final static String ANY = "ANY";
	protected final static String DRIVING_LICENSE = "DRIVING_LICENSE";
	protected final static String PASSPORT = "PASSPORT";
	protected final static String ID_CARD = "ID_CARD";
	protected final static String RESIDENCE_PERMIT = "RESIDENCE_PERMIT";

	protected enum GovId {
		ANY(Constants.ANY), 
		DRIVING_LICENSE(Constants.DRIVING_LICENSE), 
		PASSPORT(Constants.PASSPORT), 
		ID_CARD(Constants.ID_CARD),
		RESIDENCE_PERMIT(Constants.RESIDENCE_PERMIT);

		private final String val;

		GovId(String val) {
			this.val = val;
		}

		public String getVal() {
			return val;
		}
	}
	
	
	
	protected enum Mapper {
		
		
		givenName(Constants.givenName),
		sn(Constants.sn),
		address(Constants.address),
		cn(Constants.cn),
		birthDateAttribute(Constants.birthDateAttribute);
		
		private final String val;
		Mapper(String val){
			this.val = val;
		}
		
		public String getDSVal() {
			return val;
		}
		
	}
	
	
	protected final static String givenName = "givenName";
	protected final static String sn = "sn";
	
	//am
	protected final static String postalAddress = "postalAddress";
	
	protected final static String address = "address";
	protected final static String cn = "cn";
	protected final static String birthDateAttribute = "birthDateAttribute";
	

	

	
	//shared state variables
	protected final static String VerifyNeedPatch = "VerifyNeedPatch";
	protected final static String VerifyAuthnChoice = "VerifyAuthnChoice";
	protected final static String VerifyAuthnInit = "VerifyAuthnInit";
	protected final static String VerifyUsersChoice = "VerifyUsersChoice";
	protected final static String VerifyDS = "VerifyDS";
	protected final static String VerifyTransactionID = "VerifyTransactionID";
	
	protected final static String VerifyProofID = "VerifyProofID";
	
	
	protected final static String VerifyProofChoice = "VerifyProofChoice";
	
	
	//shared state var don't remove
	protected final static String VerifedFailedReason = "VerifedFailedReason";
	protected final static String VerifyMetadataResult = "VerifyMetadataResult";
	protected final static String VerifyClaimResult = "VerifyClaimResult";
	
	
	protected final static String telephoneNumber = "telephoneNumber";
	protected final static String mail = "mail";
	protected final static String objectAttributes = "objectAttributes";
	
	
	
	
	protected final static String webVerificationUrl = "webVerificationUrl";
	protected final static String webVerificationCode = "webVerificationCode";
	
	protected final static String transactionStatus = "transactionStatus";
	protected final static String overallStatus = "status";
	
	protected final static String REQUESTED = "REQUESTED";
	protected final static String PARTIAL = "PARTIAL";
	protected final static String INITIATED = "INITIATED";
	protected final static String IN_PROGRESS = "IN_PROGRESS";
	protected final static String THESUCCESS = "SUCCESS";
	protected final static String NOT_REQUIRED = "NOT_REQUIRED";
	protected final static String THEFAIL = "FAIL";
	protected final static String APPROVED_NO_REQUEST = "APPROVED_NO_REQUEST";
	protected final static String APPROVED_MANUALLY = "APPROVED_MANUALLY";
	
	
	
	protected static final ConfirmationCallback confirmationCancelCallback = new ConfirmationCallback(ConfirmationCallback.INFORMATION, new String[] { "Cancel" }, 0);
	
	protected final static String endpoint = "https://api.pingone";
	
	
	
	protected final static String QR = "QR";
	protected final static String SMS = "SMS";
	protected final static String eMail = "eMail";
	protected final static int QRNum = 0;
	protected final static int SMSNum = 1;
	protected final static int eMailNum = 2;
	
	protected enum UserNotification {
		QR(Constants.QR), 
		SMS(Constants.SMS), 
		EMAIL(Constants.eMail);
		
		private final String val;
		
		
		UserNotification(String val){
			this.val = val;
		}
		
		public int getDeliveryMethod() {	
			if (val.equalsIgnoreCase(Constants.QR)) 
				return Constants.QRNum;
			 else if (val.equalsIgnoreCase(Constants.SMS)) 
				return Constants.SMSNum;
			 else
				return Constants.eMailNum;
		}
		
		public String getDeliveryMethodName() {
			return val;
		}
	}
	
	//outcomes
	protected static final String SUCCESS = "SUCCESS";
	protected static final String SUCCESSPATCH = "SUCCESPATCH";
	protected static final String FAIL = "FAIL";
	protected static final String FAILPATCH = "FAILPATCH";
	protected static final String ERROR = "ERROR";
	protected static final String CANCEL = "CANCEL";
}
