/*
 * This code is to be used exclusively in connection with Ping Identity Corporation software or services. 
 * Ping Identity Corporation only offers such software or services to legal entities who have entered into 
 * a binding license agreement with Ping Identity Corporation.
 *
 * Copyright 2024 Ping Identity Corporation. All Rights Reserved
 */

package org.forgerock.am.tn.p1verify;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.Set;
import java.util.UUID;

import javax.inject.Inject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.ConfirmationCallback;

import org.forgerock.json.JsonValue;
import org.forgerock.oauth2.core.AccessToken;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeState;
import org.forgerock.openam.auth.node.api.OutcomeProvider;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.auth.service.marketplace.TNTPPingOneConfig;
import org.forgerock.openam.auth.service.marketplace.TNTPPingOneConfigChoiceValues;
import org.forgerock.openam.auth.service.marketplace.TNTPPingOneUtility;
import org.forgerock.openam.authentication.callbacks.PollingWaitCallback;
import org.forgerock.openam.core.CoreWrapper;
import org.forgerock.openam.core.realms.Realm;
import org.forgerock.openam.http.HttpConstants;
import org.forgerock.util.i18n.PreferredLocales;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.inject.assistedinject.Assisted;


@Node.Metadata(
		outcomeProvider = Proofing.ProofingOutcomeProvider.class, 
		configClass = Proofing.Config.class, 
		tags = {"marketplace", "trustnetwork" })
public class Proofing implements Node {

	private final Config config;
	private final Realm realm;
	private TNTPPingOneConfig tntpPingOneConfig;
	private final CoreWrapper coreWrapper;
	
	private final Logger logger = LoggerFactory.getLogger(Proofing.class);
	private final String loggerPrefix = "[PingOne Verify Proofing Node]" + PingOneVerifyPlugin.logAppender;
	
	public static final String BUNDLE = Proofing.class.getName();
	private final Helper client;

	/**
	 * Configuration for the node.
	 */
	public interface Config {

		/**
		 * The Configured service
		 */
		@Attribute(order = 100, choiceValuesClass = TNTPPingOneConfigChoiceValues.class)
		default String tntpPingOneConfigName() {
			return TNTPPingOneConfigChoiceValues.createTNTPPingOneConfigName("Global Default");
		};

		@Attribute(order = 200)
		default String verifyPolicyId() {
			return "";
		}

		@Attribute(order = 300)
		default Constants.UserNotification userNotification() {
			return Constants.UserNotification.QR;
		}

		@Attribute(order = 400)
		default boolean userNotificationChoice() {
			return false;
		}
		
		@Attribute(order = 500)
		default String userNotificationChoiceMessage() {
			return "Choose your Delivery Method";
		}	
		
		@Attribute(order = 600)
		default Constants.GovId govId() {
			return Constants.GovId.ANY;
		}

		@Attribute(order = 700)
		default String userIdAttribute() {
			return "";
		}
		
        @Attribute(order = 800)
        default int dobVerification() {
        	return 0;
        }
		
		@Attribute(order = 900)
		default Map<String, String> attributeMappingConfiguration() {
			return new HashMap<String, String>() {
				{
					/*
					 * key is DS attribute name, value is the claim name in PingOneVerify verified
					 * claims
					 */
					put("givenName", "firstName");
					put("sn", "lastName");
					put("cn", "fullName");
					put("postalAddress", "address");
					put("country", "country");
					put("birthDateAttribute", "birthDate");
					put("idNumberAttribute", "idNumber");
					put("idTypeAttribute", "idType");
					put("expirationDateAttribute", "expirationDate");
				}
			};
		}

		@Attribute(order = 1000)
		default Map<String, String> fuzzyMatchingConfiguration() {
			return new HashMap<String, String>() {
				{
					/*
					 * key is DS attribute name, value is the confidence level required for success
					 */					
	                put(Constants.givenName, "LOW");
	                put(Constants.sn, "HIGH");
	                put(Constants.address, "MEDIUM");
	                put(Constants.cn, "LOW");
	                put(Constants.birthDateAttribute, "EXACT");
				}
			};
		}


		@Attribute(order = 1100)
		default boolean failExpired() {
			return false;
		}

		@Attribute(order = 1200)
		default int timeOut() {
			return 270;
		}

		@Attribute(order = 1300)
		default String pollWaitMessage() {
			return "Waiting for completion";
		}
		
		@Attribute(order = 1400)
		default boolean saveVerifiedClaims() {
			return false;
		}

		@Attribute(order = 1500)
		default boolean saveMetadata() {
			return false;
		}

		@Attribute(order = 1600)
		default boolean tsAccessToken() {
			return false;
		}

		@Attribute(order = 1700)
		default boolean tsTransactionId() {
			return false;
		}

		@Attribute(order = 1800)
		default boolean demoMode() {
			return false;
		}

	}

	/**
	 * Create the node using Guice injection. Just-in-time bindings can be used to
	 * obtain instances of other classes from the plugin.
	 *
	 * @param config The service config.
	 * @param realm  The realm the node is in.
	 */
	@Inject
	public Proofing(@Assisted Config config, @Assisted Realm realm, CoreWrapper coreWrapper, Helper client) {
		this.coreWrapper = coreWrapper;
		this.config = config;
		this.realm = realm;
		this.tntpPingOneConfig = TNTPPingOneConfigChoiceValues.getTNTPPingOneConfig(config.tntpPingOneConfigName());
		this.client = client;
	}

	@Override
	public Action process(TreeContext context) {
		try {
			logger.debug(loggerPrefix + "Started");
				
			NodeState ns = context.getStateFor(this);
			
			//check if choice exists
			if (!ns.isDefined(Constants.VerifyAuthnChoice)) {
				ns.putShared(Constants.VerifyAuthnChoice, UUID.randomUUID());
				if  (config.userNotificationChoice()){
					return Helper.getChoiceCallback(config.userNotificationChoiceMessage());
				}				
			}
			
			
			//if we are here, we are ready to init on choice made, or pre-set for user
			if (!ns.isDefined(Constants.VerifyAuthnInit)){
				//if here then the user choose, or the admin choose for them how to verify - SMS, EMAIL, or QR
				ns.putShared(Constants.VerifyAuthnInit, UUID.randomUUID());
				int userChoice = 0;
				if (config.userNotificationChoice()) {
					//get the users choice
					userChoice = context.getCallback(ConfirmationCallback.class).get().getSelectedIndex();
				}
				else {
					//take the choice picked for them
					userChoice = config.userNotification().getDeliveryMethod();
				}
				ns.putShared(Constants.VerifyUsersChoice, Integer.valueOf(userChoice));
				
				//perform init on choice
								
				//we need to get the phone number, email or we gen a qr code
				String phone = null;
				String email = null;
				switch(userChoice) {
				case Constants.SMSNum:
					phone = client.getInfo(ns, Constants.telephoneNumber, coreWrapper, true);
					break;
				case Constants.eMailNum:
					email = client.getInfo(ns, Constants.mail, coreWrapper, true);
					break;
				}
				
				JsonValue body = getInitBody(config.verifyPolicyId(), phone, email, ns);
				
				//need to get the user id
				String pingUID = client.getPingUID(ns, tntpPingOneConfig, realm, config.userIdAttribute(), coreWrapper);
				
				TNTPPingOneUtility tntpP1U = TNTPPingOneUtility.getInstance();
				AccessToken accessToken = tntpP1U.getAccessToken(realm, tntpPingOneConfig);
				
				JsonValue response = client.init(accessToken, tntpPingOneConfig, body, pingUID);
				
				ns.putShared(Constants.VerifyTransactionID, response.get("id").asString());
				List<Callback> callbacks = new ArrayList<>();
				//if we need to get a QR code, add it now
				if (userChoice == Constants.QRNum) {
					String webURL = response.get(Constants.webVerificationUrl).asString();
					callbacks.add(Helper.generateQRCallback(webURL));
				}
				
				String webVerCode = response.get(Constants.webVerificationCode).asString();
				PollingWaitCallback pwc = new PollingWaitCallback("5000", String.format(config.pollWaitMessage(), webVerCode));
				callbacks.add(pwc);
				Constants.confirmationCancelCallback.setSelectedIndex(100);// so cancel doesnt looked pressed by default
				callbacks.add(Constants.confirmationCancelCallback);
				
				long now = (new Date().getTime())/1000;
				ns.putShared(Constants.VerifyDS, now);
				
				return Action.send(callbacks).build();
				
			}
			
			
			//if here, then the communication path has been decided, and init already happened. 
			//we are checking if done and result
			
			//first check if cancelled hit
			if (Helper.cancelPushed(context, ns)) {
				Helper.cleanUpSS(ns, false);
				return Action.goTo(Constants.CANCEL).build();
			}
			
			//check if timeout reached
			long startTime = ns.get(Constants.VerifyDS).asLong();
			long now = (new Date().getTime())/1000;			
			if((now-config.timeOut()) >= startTime) {
				throw new Exception("Submission timeout reached");
			}
			
			
			String transactionID = ns.get(Constants.VerifyTransactionID).asString();
			String pingOneUID = null;
			
			if (ns.isDefined(Constants.VerifyNeedPatch))
				pingOneUID = ns.get(Constants.VerifyNeedPatch).asString();
			else {
				pingOneUID = client.getInfo(ns, config.userIdAttribute(), coreWrapper, false);
			}
			
			String theURI = Constants.endpoint + tntpPingOneConfig.environmentRegion().getDomainSuffix() + "/v1/environments/" + tntpPingOneConfig.environmentId() + "/users/" + pingOneUID + "/verifyTransactions/" + transactionID;
			TNTPPingOneUtility tntpP1U = TNTPPingOneUtility.getInstance();
			AccessToken accessToken = tntpP1U.getAccessToken(realm, tntpPingOneConfig);
			JsonValue response = client.makeHTTPClientCall(accessToken, theURI, HttpConstants.Methods.GET, null);
			
			String result = response.get(Constants.transactionStatus).get(Constants.overallStatus).asString();
			return returnFinalStep(result, ns, response);
			

		} catch (Exception ex) {
			String stackTrace = org.apache.commons.lang.exception.ExceptionUtils.getStackTrace(ex);
			logger.error(loggerPrefix + "Exception occurred: " + stackTrace);
			context.getStateFor(this).putTransient(loggerPrefix + "Exception", ex.getMessage());
			context.getStateFor(this).putTransient(loggerPrefix + "StackTrace", stackTrace);
			return Action.goTo(Constants.ERROR).build();
		}
	}
	
	
	private JsonValue getInitBody(String policyId, String telephoneNumber, String emailAddress, NodeState ns) throws Exception{
		
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
		
		//BIOGRAPHIC_MATCHER
		if (config.fuzzyMatchingConfiguration() != null && !config.fuzzyMatchingConfiguration().isEmpty()) {
			Set<String> keys = config.fuzzyMatchingConfiguration().keySet();
			JsonValue thisJVKey = new JsonValue(new LinkedHashMap<String, Object>(1));
			for(Iterator<String> i = keys.iterator(); i.hasNext();) {
				String thisKey = i.next();
				//get the value for the key from shared state or user
				String thisVal = client.getInfo(ns, thisKey, coreWrapper, true);
				if (thisVal!=null) {
					JsonValue value = new JsonValue(new LinkedHashMap<String, Object>(1));
					value.put("value", thisVal);

					thisJVKey.put(Helper.getFuzzyVal(thisKey), value);
				}
				else {
					throw new Exception(thisKey + " was not found on the Journey state or on the user.");
				}
			}
			body.put("requirements", thisJVKey);
			
			
		}
		return body;
	}
	
	
	private Action returnFinalStep(String result, NodeState ns, JsonValue response) throws Exception {

		switch (result) {
		case Constants.REQUESTED:
		case Constants.PARTIAL:
		case Constants.INITIATED:
		case Constants.IN_PROGRESS:
			List<Callback> callbacks = new ArrayList<>();
			// if we need to get a QR code, add it now
			if (ns.get(Constants.VerifyUsersChoice).asInteger().intValue() == Constants.QRNum) {
				String webURL = response.get(Constants.webVerificationUrl).asString();
				callbacks.add(Helper.generateQRCallback(webURL));
			}

			String webVerCode = response.get(Constants.webVerificationCode).asString();
			PollingWaitCallback pwc = new PollingWaitCallback("5000", String.format(config.pollWaitMessage(), webVerCode));
			callbacks.add(pwc);
			Constants.confirmationCancelCallback.setSelectedIndex(100);// so cancel doesnt looked pressed by default
			callbacks.add(Constants.confirmationCancelCallback);

			return Action.send(callbacks).build();
			
			//success outcomes
		case Constants.THESUCCESS:
		case Constants.NOT_REQUIRED:
		case Constants.APPROVED_NO_REQUEST:
		case Constants.APPROVED_MANUALLY:
			Action successRetVal = null;
			if (ns.isDefined(Constants.VerifyNeedPatch))
				successRetVal = Action.goTo(Constants.SUCCESSPATCH).build();
			else
				successRetVal = Action.goTo(Constants.SUCCESS).build();
			
			
			//gov ID check needed?
			successRetVal = govIDCheck(successRetVal);
			
			//fuzzy matching check
			successRetVal = fuzzyMatchCheck(successRetVal);
			
			//failed expired check
			successRetVal = expiredDocCheck(successRetVal);
			
			
			
			
			//cleanup SS
			Helper.cleanUpSS(ns, ns.isDefined(Constants.VerifyNeedPatch));
			return successRetVal;
			
			//fail outcome
		case Constants.THEFAIL:
			Action failRetVal = null;
			if (ns.isDefined(Constants.VerifyNeedPatch))
				failRetVal = Action.goTo(Constants.FAILPATCH).build();
			else
				failRetVal = Action.goTo(Constants.FAIL).build();
			
			//if demo mode, then send to success
			if (config.demoMode())
				failRetVal = Action.goTo(Constants.SUCCESS).build();
			//cleanup SS
			Helper.cleanUpSS(ns, ns.isDefined(Constants.VerifyNeedPatch));
			return failRetVal;
		}
		/* if we're here, something went wrong */
		return Action.goTo(Constants.ERROR).build();
	}
	
	
	//govID check
	private Action govIDCheck(Action currentAction) throws Exception{
		//TODO
		
		switch(config.govId().getVal()) {
			case Constants.DRIVING_LICENSE:
				
				
			case Constants.ID_CARD:
				
			
			case Constants.RESIDENCE_PERMIT:
				
			case Constants.PASSPORT:
				
			case Constants.ANY:
		
		}
		
		return currentAction;
	}

	
	private Action fuzzyMatchCheck(Action currentAction) throws Exception{
		return currentAction;
//TODO
	}

	private Action expiredDocCheck(Action currentAction) throws Exception{
		return currentAction;
//TODO
	}
	
	public static class ProofingOutcomeProvider implements OutcomeProvider {
		@Override
		public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {
			ResourceBundle bundle = locales.getBundleInPreferredLocale(Proofing.BUNDLE,
					OutcomeProvider.class.getClassLoader());
			List<Outcome> results = new ArrayList<>();
			results.add(new Outcome(Constants.SUCCESS, bundle.getString("successOutcome")));
			results.add(new Outcome(Constants.SUCCESSPATCH, bundle.getString("successOutcomePatch")));
			results.add(new Outcome(Constants.FAIL, bundle.getString("failOutcome")));
			results.add(new Outcome(Constants.FAILPATCH, bundle.getString("failOutcomePatch")));
			results.add(new Outcome(Constants.CANCEL, bundle.getString("cancelOutcome")));
			results.add(new Outcome(Constants.ERROR, bundle.getString("errorOutcome")));
			return Collections.unmodifiableList(results);
		}
	}
}
