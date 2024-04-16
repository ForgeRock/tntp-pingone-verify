/*
 * This code is to be used exclusively in connection with Ping Identity Corporation software or services. 
 * Ping Identity Corporation only offers such software or services to legal entities who have entered into 
 * a binding license agreement with Ping Identity Corporation.
 *
 * Copyright 2024 Ping Identity Corporation. All Rights Reserved
 */

package org.forgerock.am.tn.p1verify;

import static org.forgerock.openam.auth.node.api.SharedStateConstants.REALM;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.ResourceBundle;
import java.util.UUID;

import javax.inject.Inject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.ConfirmationCallback;
import javax.security.auth.callback.TextOutputCallback;

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
import com.sun.identity.idm.AMIdentity;


@Node.Metadata(
		outcomeProvider = PingOneVerifyAuthentication.AuthenticationOutcomeProvider.class, 
		configClass = PingOneVerifyAuthentication.Config.class, 
		tags = {"marketplace", "trustnetwork" })
public class PingOneVerifyAuthentication implements Node {

	private final Config config;
	private final Realm realm;
	private TNTPPingOneConfig tntpPingOneConfig;
	private final CoreWrapper coreWrapper;
	
	private final Logger logger = LoggerFactory.getLogger(PingOneVerifyAuthentication.class);
	private final String loggerPrefix = "[PingOne Verify Authentication Node]" + PingOneVerifyPlugin.logAppender;
	
	public static final String BUNDLE = PingOneVerifyAuthentication.class.getName();
	private final Helper client;
	private AMIdentity identity = null;
	
	
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
        default String pictureAttribute() {
            return "";
        }
		
		@Attribute(order = 700)
		default String userIdAttribute() {
			return "";
		}
		
		@Attribute(order = 800)
		default int timeOut() {
			return 270;
		}
		
		@Attribute(order = 900)
		default String pollWaitMessage() {
			return "Waiting for completion.  Here is the code you will see on your device: %s";
		}

		@Attribute(order = 1000)
		default boolean demoMode() {
			return false;
		}

		@Attribute(order = 1200)
		default boolean saveMetadata() {
			return false;
		}

		@Attribute(order = 1300)
		default boolean tsAccessToken() {
			return false;
		}

		@Attribute(order = 1400)
		default boolean tsTransactionId() {
			return false;
		}

	}

	@Inject
	public PingOneVerifyAuthentication(@Assisted Config config, @Assisted Realm realm, CoreWrapper coreWrapper, Helper client) {
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
				
				//we need to get the selfie
				String selfie = getInfo(ns, config.pictureAttribute(), coreWrapper, false);
				
				//we need to get the phone number, email or we gen a qr code
				String phone = null;
				String email = null;
				switch(userChoice) {
				case Constants.SMSNum:
					phone = getInfo(ns, Constants.telephoneNumber, coreWrapper, true);
					break;
				case Constants.eMailNum:
					email = getInfo(ns, Constants.mail, coreWrapper, true);
					break;
				}
				
				JsonValue body = Helper.getInitializeBody(config.verifyPolicyId(), phone, email, selfie);
				
				//need to get the user id
				String pingUIDLocal = getInfo(ns, config.userIdAttribute(), coreWrapper, false);
				String pingUID = client.getPingUID(ns, tntpPingOneConfig, realm, config.userIdAttribute(), pingUIDLocal);
				

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
				callbacks.add(new TextOutputCallback(TextOutputCallback.INFORMATION,  String.format(config.pollWaitMessage(), webVerCode)));
				PollingWaitCallback pwc = new PollingWaitCallback("5000","");
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
				Helper.cleanUpSS(ns, false, false);
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
				
				pingOneUID = getInfo(ns, config.userIdAttribute(), coreWrapper, false);
			}
			
			String theURI = Constants.endpoint + tntpPingOneConfig.environmentRegion().getDomainSuffix() + "/v1/environments/" + tntpPingOneConfig.environmentId() + "/users/" + pingOneUID + "/verifyTransactions/" + transactionID;
			TNTPPingOneUtility tntpP1U = TNTPPingOneUtility.getInstance();
			AccessToken accessToken = tntpP1U.getAccessToken(realm, tntpPingOneConfig);
			JsonValue response = client.makeHTTPClientCall(accessToken, theURI, HttpConstants.Methods.GET, null);
			
			String result = response.get(Constants.transactionStatus).get(Constants.overallStatus).asString();
			return returnFinalStep(result, ns, response, pingOneUID);
			
		} catch (Exception ex) {
			String stackTrace = org.apache.commons.lang.exception.ExceptionUtils.getStackTrace(ex);
			logger.error(loggerPrefix + "Exception occurred: ", ex);
			context.getStateFor(this).putTransient(loggerPrefix + "Exception", ex.getMessage());
			context.getStateFor(this).putTransient(loggerPrefix + "StackTrace", stackTrace);
			return Action.goTo(Constants.ERROR).build();
		}
	}
	
	private Action returnFinalStep(String result, NodeState ns, JsonValue response, String pingOneUID) throws Exception {

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
			callbacks.add(new TextOutputCallback(TextOutputCallback.INFORMATION,  String.format(config.pollWaitMessage(), webVerCode)));
			PollingWaitCallback pwc = new PollingWaitCallback("5000","");
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
			
			//if save metadata to transient state
			if(config.saveMetadata()) {
				TNTPPingOneUtility tntpP1U = TNTPPingOneUtility.getInstance();
				AccessToken accessToken = tntpP1U.getAccessToken(realm, tntpPingOneConfig);
				
				String txID = ns.get(Constants.VerifyTransactionID).asString();
				
				String theURI = Constants.endpoint + tntpPingOneConfig.environmentRegion().getDomainSuffix() + "/v1/environments/" + tntpPingOneConfig.environmentId() + "/users/" + pingOneUID + "/verifyTransactions/" + txID + "/metaData";

				JsonValue metadata = client.makeHTTPClientCall(accessToken, theURI, HttpConstants.Methods.GET, null);
				ns.putTransient(Constants.VerifyMetadataResult, metadata);
				
			}
			
			//cleanup SS
			Helper.cleanUpSS(ns, ns.isDefined(Constants.VerifyNeedPatch), config.tsTransactionId());
			
			//save AccessToken?
			if(config.tsAccessToken()) {
				TNTPPingOneUtility tntpP1U = TNTPPingOneUtility.getInstance();
				AccessToken accessToken = tntpP1U.getAccessToken(realm, tntpPingOneConfig);
				ns.putTransient(Constants.VerifyAT, accessToken);
			}
			
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
			
			//if save metadata to transient state
			if(config.saveMetadata()) {
				TNTPPingOneUtility tntpP1U = TNTPPingOneUtility.getInstance();
				AccessToken accessToken = tntpP1U.getAccessToken(realm, tntpPingOneConfig);
				
				String txID = ns.get(Constants.VerifyTransactionID).asString();
				
				String theURI = Constants.endpoint + tntpPingOneConfig.environmentRegion().getDomainSuffix() + "/v1/environments/" + tntpPingOneConfig.environmentId() + "/users/" + pingOneUID + "/verifyTransactions/" + txID + "/metaData";

				JsonValue metadata = client.makeHTTPClientCall(accessToken, theURI, HttpConstants.Methods.GET, null);
				ns.putTransient(Constants.VerifyMetadataResult, metadata);
				
			}

			//cleanup SS
			Helper.cleanUpSS(ns, ns.isDefined(Constants.VerifyNeedPatch), config.tsTransactionId());
			
			//save AccessToken?
			if(config.tsAccessToken()) {
				TNTPPingOneUtility tntpP1U = TNTPPingOneUtility.getInstance();
				AccessToken accessToken = tntpP1U.getAccessToken(realm, tntpPingOneConfig);
				ns.putTransient(Constants.VerifyAT, accessToken);
			}
			
			return failRetVal;
		}
		/* if we're here, something went wrong */
		return Action.goTo(Constants.ERROR).build();
	}
	
	
	
	private AMIdentity getUser(NodeState ns, CoreWrapper coreWrapper) throws Exception{
		if (this.identity==null || 
			!(identity.getName().equalsIgnoreCase(ns.get(USERNAME).asString()))) {
			String userName = ns.get(USERNAME).asString();
			String realm = ns.get(REALM).asString();
			this.identity = coreWrapper.getIdentityOrElseSearchUsingAuthNUserAlias(userName,realm);
		}
        return this.identity;
	}
	
	
	private String getInfo(NodeState ns, String det, CoreWrapper coreWrapper, boolean onObjectAttribute) throws Exception{
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
	
	public static class AuthenticationOutcomeProvider implements OutcomeProvider {
		@Override
		public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {
			ResourceBundle bundle = locales.getBundleInPreferredLocale(PingOneVerifyAuthentication.BUNDLE, OutcomeProvider.class.getClassLoader());
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
