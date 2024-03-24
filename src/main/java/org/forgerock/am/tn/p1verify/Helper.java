package org.forgerock.am.tn.p1verify;

import static org.forgerock.json.JsonValue.json;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.REALM;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;

import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.UUID;

import javax.inject.Inject;
import javax.inject.Singleton;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.ConfirmationCallback;
import javax.security.auth.callback.TextOutputCallback;

import org.forgerock.http.HttpApplicationException;
import org.forgerock.http.handler.HttpClientHandler;
import org.forgerock.http.header.AuthorizationHeader;
import org.forgerock.http.header.MalformedHeaderException;
import org.forgerock.http.header.authorization.BearerToken;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.json.JsonValue;
import org.forgerock.oauth2.core.AccessToken;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.NodeState;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.auth.service.marketplace.TNTPPingOneConfig;
import org.forgerock.openam.auth.service.marketplace.TNTPPingOneUtility;
import org.forgerock.openam.core.CoreWrapper;
import org.forgerock.openam.core.realms.Realm;
import org.forgerock.openam.http.HttpConstants;
import org.forgerock.openam.utils.qr.GenerationUtils;
import org.forgerock.services.context.RootContext;
import org.forgerock.util.thread.listener.ShutdownManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.sun.identity.authentication.callbacks.ScriptTextOutputCallback;
import com.sun.identity.idm.AMIdentity;

@Singleton
public class Helper {
	private final Logger logger = LoggerFactory.getLogger(Proofing.class);
	private final String loggerPrefix = "[PingOne Verify Helper]" + PingOneVerifyPlugin.logAppender;
	private AMIdentity identity = null;
	private final HttpClientHandler handler;
	
	@Inject
	public Helper(ShutdownManager shutdownManager) throws HttpApplicationException{
	    this.handler = new HttpClientHandler();
	    shutdownManager.addShutdownListener(() -> {
	      try {
	        handler.close();
	      } catch (IOException e) {
	        logger.error(loggerPrefix + " Could not close HTTP client", e);
	      }
	    });
	}
	

	protected static Action getChoiceCallback(String deliveryMess) throws Exception {
		List<Callback> callbacks = new ArrayList<>();

		String[] options = { Constants.UserNotification.QR.name(), Constants.UserNotification.SMS.name(), Constants.UserNotification.EMAIL.name() };
		TextOutputCallback textOutputCallback = new TextOutputCallback(TextOutputCallback.INFORMATION, deliveryMess);
		callbacks.add(textOutputCallback);
		ConfirmationCallback deliveryChoiceCallback = new ConfirmationCallback(deliveryMess, ConfirmationCallback.INFORMATION, options, 0);
		callbacks.add(deliveryChoiceCallback);
		return Action.send(callbacks).build();
	}

	protected String createPingUID(TNTPPingOneUtility tntpP1U, String theURI, Realm realm, TNTPPingOneConfig tntpPingOneConfig) throws Exception {
		String retVal = null;
		JsonValue createUidBody = new JsonValue(new LinkedHashMap<String, Object>(1));
		createUidBody.put("username", UUID.randomUUID().toString());

		AccessToken accessToken = tntpP1U.getAccessToken(realm, tntpPingOneConfig);

		JsonValue response = makeHTTPClientCall(accessToken, theURI, HttpConstants.Methods.POST, createUidBody);

		JsonValue theID = response.get("id");
		if (theID.isNotNull() && theID.isString())
			retVal = theID.asString();// hoping it's a string?
		else
			retVal = theID.toString();// not good if here, because it probably looks like a key/val pair?

		return retVal;
	}

	protected JsonValue makeHTTPClientCall(AccessToken accessToken, String theURI, String method, JsonValue body) throws Exception {
		Request request = null;
		try {
			URI uri = URI.create(theURI);

			request = new Request();
			request.setUri(uri).setMethod(method);
			if (body != null && body.isNotNull())
				request.getEntity().setJson(body);
			addAuthorizationHeader(request, accessToken);
			Response response = handler.handle(new RootContext(), request).getOrThrow();

			if (response.getStatus().isSuccessful()) {
				return json(response.getEntity().getJson());
			} else {
				throw new Exception("PingOne Verify verifyTransaction response with error." + response.getStatus() + "-" + response.getEntity().getString());
			}
		} catch (Exception e) {
			throw new Exception("Failed PingOne Verify", e);
		}

	}
	
	protected static boolean cancelPushed(TreeContext context, NodeState ns) {
		boolean retVal = false;
		for (Iterator<? extends Callback> thisIt = context.getAllCallbacks().iterator(); thisIt.hasNext();) {
			Callback thisCallback = thisIt.next();
			if (thisCallback instanceof ConfirmationCallback) {
				ConfirmationCallback cc = (ConfirmationCallback) thisCallback;
				int theSelection = cc.getSelectedIndex();
				if (theSelection == 100)// means cancel was not hit
					return false;
				else
					return true;
			}
		}
		return retVal;
	}
	
	
	protected static void cleanUpSS(NodeState ns, boolean needPatch) throws Exception {
		if (!needPatch)
			ns.remove(Constants.VerifyNeedPatch);
		ns.remove(Constants.VerifyAuthnChoice);
		ns.remove(Constants.VerifyAuthnInit);
		ns.remove(Constants.VerifyUsersChoice);	
		ns.remove(Constants.VerifyTransactionID);	
		ns.remove(Constants.VerifyDS);
	}
	
	protected static Callback generateQRCallback(String text) {
		return new ScriptTextOutputCallback(GenerationUtils.getQRCodeGenerationJavascriptForAuthenticatorAppRegistration("callback_0", text));
	}

	protected static void addAuthorizationHeader(Request request, AccessToken accessToken) throws MalformedHeaderException {
		AuthorizationHeader header = new AuthorizationHeader();
		BearerToken bearerToken = new BearerToken(accessToken.getTokenId());
		header.setRawValue(BearerToken.NAME + " " + bearerToken);
		request.addHeaders(header);
	}
	
	
	
	protected String getInfo(NodeState ns, String det, CoreWrapper coreWrapper, boolean onObjectAttribute) throws Exception{
    	if (onObjectAttribute && ns.isDefined(Constants.objectAttributes)) {
    		JsonValue jv = ns.get(Constants.objectAttributes);
    		if (jv.isDefined(det))
    			return jv.get(det).asString();
    	}
    	else if (!onObjectAttribute && ns.isDefined(det)) {
    		return ns.get(det).asString();
    	}
    	
    	AMIdentity thisIdentity = getUser(ns, coreWrapper);
        /* no identifier in sharedState, fetch from DS */
        if (thisIdentity != null && !thisIdentity.getAttribute(det).isEmpty())
        	return thisIdentity.getAttribute(det).iterator().next();
        
        return null;
    }
	
	protected AMIdentity getUser(NodeState ns, CoreWrapper coreWrapper) throws Exception{
		if (this.identity==null) {
			String userName = ns.get(USERNAME).asString();
			String realm = ns.get(REALM).asString();
			this.identity = coreWrapper.getIdentityOrElseSearchUsingAuthNUserAlias(userName,realm);
		}
        return this.identity;
	}
	
	protected String getPingUID(NodeState ns, TNTPPingOneConfig tntpPingOneConfig, Realm realm, String userIDAttribute, CoreWrapper coreWrapper) throws Exception{
		String pingUID = getInfo(ns, userIDAttribute, coreWrapper, false);
		
        String theURI = Constants.endpoint + tntpPingOneConfig.environmentRegion().getDomainSuffix() + "/v1/environments/" + tntpPingOneConfig.environmentId() + "/users";
        TNTPPingOneUtility tntpP1U = TNTPPingOneUtility.getInstance();
		if (pingUID == null || pingUID.isBlank()) {
			//create a new one	          
			pingUID = createPingUID(tntpP1U, theURI, realm, tntpPingOneConfig);
			ns.putShared(Constants.VerifyNeedPatch, pingUID);
		}
		else {
			//check it exists
			AccessToken accessToken = tntpP1U.getAccessToken(realm, tntpPingOneConfig);
			try {
				JsonValue response = makeHTTPClientCall(accessToken, theURI + "/" + pingUID, HttpConstants.Methods.GET, null);
				JsonValue theID = response.get("id");
		        if (theID.isNotNull() && theID.isString())
		        	pingUID = theID.asString();//hoping it's a string?
		        else
		        	pingUID = theID.toString();
			}
			catch (Exception e) {
				//if this failed, then create new user because the id stored, couldn't be found in pingone
				pingUID = createPingUID(tntpP1U, theURI, realm, tntpPingOneConfig);
				ns.putShared(Constants.VerifyNeedPatch, pingUID);
			}			
		}
		return pingUID;
	}
	
	protected JsonValue init(AccessToken accessToken, TNTPPingOneConfig worker, JsonValue body, String userID) throws Exception {
		String theURI = Constants.endpoint + worker.environmentRegion().getDomainSuffix() + "/v1/environments/" + worker.environmentId() + "/users/" + userID + "/verifyTransactions";
		return makeHTTPClientCall(accessToken, theURI, HttpConstants.Methods.POST, body);
	}
	
	protected static JsonValue getInitializeBody(String policyId, String telephoneNumber, String emailAddress, String selfie) {
		
		JsonValue body = new JsonValue(new LinkedHashMap<String, Object>(1));
		
		//Verify Policy ID section
		JsonValue theID = new JsonValue(new LinkedHashMap<String, Object>(1));
		theID.put("id", policyId);
		body.put("verifyPolicy", theID);
		
		//sendNotification section
		if ((telephoneNumber!=null && !telephoneNumber.isEmpty()) || (emailAddress!=null && !emailAddress.isEmpty())) {
			JsonValue sendNotification = new JsonValue(new LinkedHashMap<String, Object>(1));
			sendNotification.putIfNotNull("phone", telephoneNumber);
			sendNotification.putIfNotNull("email", emailAddress);
			body.put("sendNotification", sendNotification);
		}
		
		//selfie section
		if (selfie != null) {
			JsonValue value = new JsonValue(new LinkedHashMap<String, Object>(1));
			value.put("value", selfie);

			JsonValue refSelfie = new JsonValue(new LinkedHashMap<String, Object>(1));
			refSelfie.put("referenceSelfie", value);

			body.put("requirements", refSelfie);
		}
		

		return body;
	}

	protected static String getFuzzyVal(String val) {
		switch(val) {
		case Constants.givenName:
			return "given_name";
		case Constants.sn:
			return "family_name";
		case Constants.address:
			return Constants.address;
		case Constants.cn:
			return "name";
		case Constants.birthDateAttribute:
			return "birth_date";
		}
		return val;
	}
	

	public static void main(String[] args) {

		 //JsonValue ja = normalizeClaims(true, "PingOneIdentityProviderHandlerNode", null);
		
	 //System.out.println(ja.toString());

	}

}
