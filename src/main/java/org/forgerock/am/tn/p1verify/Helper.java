package org.forgerock.am.tn.p1verify;

import static org.forgerock.json.JsonValue.json;

import java.net.URI;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.UUID;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.ConfirmationCallback;
import javax.security.auth.callback.TextOutputCallback;

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
import org.forgerock.openam.core.realms.Realm;
import org.forgerock.openam.http.HttpConstants;
import org.forgerock.openam.utils.qr.GenerationUtils;
import org.forgerock.services.context.RootContext;

import com.sun.identity.authentication.callbacks.ScriptTextOutputCallback;


public class Helper {

	protected static Action getChoiceCallback(String deliveryMess) throws Exception {
		List<Callback> callbacks = new ArrayList<>();

		String[] options = { Constants.UserNotification.QR.name(), Constants.UserNotification.SMS.name(), Constants.UserNotification.EMAIL.name() };
		TextOutputCallback textOutputCallback = new TextOutputCallback(TextOutputCallback.INFORMATION, deliveryMess);
		callbacks.add(textOutputCallback);
		ConfirmationCallback deliveryChoiceCallback = new ConfirmationCallback(deliveryMess, ConfirmationCallback.INFORMATION, options, 0);
		callbacks.add(deliveryChoiceCallback);
		return Action.send(callbacks).build();
	}

	protected static String createPingUID(TNTPPingOneUtility tntpP1U, String theURI, Realm realm, TNTPPingOneConfig tntpPingOneConfig) throws Exception {
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

	protected static JsonValue makeHTTPClientCall(AccessToken accessToken, String theURI, String method, JsonValue body) throws Exception {
		Request request = null;
		HttpClientHandler handler = null;
		try {
			URI uri = URI.create(theURI);

			request = new Request();
			request.setUri(uri).setMethod(method);
			if (body != null && body.isNotNull())
				request.getEntity().setJson(body);
			addAuthorizationHeader(request, accessToken);
			handler = new HttpClientHandler();
			Response response = handler.handle(new RootContext(), request).getOrThrow();

			if (response.getStatus().isSuccessful()) {
				return json(response.getEntity().getJson());
			} else {
				throw new Exception("PingOne Verify verifyTransaction response with error." + response.getStatus() + "-" + response.getEntity().getString());
			}
		} catch (Exception e) {
			throw new Exception("Failed PingOne Verify", e);
		} finally {
			if (handler != null) {
				try {
					handler.close();
				} catch (Exception e) {
					// DO NOTHING
				}
			}

			if (request != null) {
				try {
					request.close();
				} catch (Exception e) {
					// DO NOTHING
				}
			}
		}

	}
	
	protected static boolean cancelPushed(TreeContext context, NodeState ns) {
		boolean retVal = false;
		//JsonValue jv = ns.get("confirmationCB");
		for (Iterator<? extends Callback> thisIt = context.getAllCallbacks().iterator(); thisIt.hasNext();) {
			Callback thisCallback = thisIt.next();
			if (thisCallback instanceof ConfirmationCallback) {
				ConfirmationCallback cc = (ConfirmationCallback) thisCallback;
				int theSelection = cc.getSelectedIndex();
				if (theSelection == 100)// means cancel was not hit
					return false;
				else
					return true;
				//	break;
				//String buttonPushed = (String) jv.asList().get(cc.getSelectedIndex());
				//if (buttonPushed.equalsIgnoreCase("cancel")) {
				//	retVal = true;
				//}
				//break;
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

	public static void main(String[] args) {

		// JsonValue ja = getInitializeBody("thepoicyid", null, "j@j.com", "this is a
		// pic");
		// System.out.println(ja.toString());

	}

}
