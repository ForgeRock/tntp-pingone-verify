/*
 * This code is to be used exclusively in connection with Ping Identity Corporation software or services. 
 * Ping Identity Corporation only offers such software or services to legal entities who have entered into 
 * a binding license agreement with Ping Identity Corporation.
 *
 * Copyright 2024 Ping Identity Corporation. All Rights Reserved
 */

package org.forgerock.am.tn.p1verify;

import static org.forgerock.am.tn.p1verify.Constants.PINGONE_VERIFY_REDIRECT_FLOW_CODE_KEY;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.REALM;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;

import java.net.URISyntaxException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.ResourceBundle;
import java.util.Set;
import java.util.UUID;

import javax.inject.Inject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.ConfirmationCallback;
import javax.security.auth.callback.TextOutputCallback;

import com.sun.identity.authentication.spi.RedirectCallback;
import org.forgerock.json.JsonValue;
import org.forgerock.http.MutableUri;
import org.forgerock.http.protocol.Form;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.*;
import org.forgerock.openam.auth.nodes.helpers.IdmIntegrationHelper;
import org.forgerock.openam.auth.service.marketplace.TNTPPingOneConfig;
import org.forgerock.openam.auth.service.marketplace.TNTPPingOneConfigChoiceValues;
import org.forgerock.openam.auth.service.marketplace.TNTPPingOneUtility;
import org.forgerock.openam.authentication.callbacks.PollingWaitCallback;
import org.forgerock.openam.core.CoreWrapper;
import org.forgerock.openam.core.realms.Realm;
import org.forgerock.openam.http.HttpConstants;
import org.forgerock.openam.integration.idm.IdmIntegrationService;
import org.forgerock.util.i18n.PreferredLocales;
import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.inject.assistedinject.Assisted;
import com.sun.identity.idm.AMIdentity;

@Node.Metadata(
		outcomeProvider = PingOneVerifyProofing.ProofingOutcomeProvider.class, 
		configClass = PingOneVerifyProofing.Config.class, 
		tags = {"marketplace", "trustnetwork" })
public class PingOneVerifyProofing implements Node {

	private final Config config;
	private final Realm realm;
	private TNTPPingOneConfig tntpPingOneConfig;
	private final CoreWrapper coreWrapper;
	
	private final Logger logger = LoggerFactory.getLogger(PingOneVerifyProofing.class);
	private final String loggerPrefix = "[PingOne Verify Proofing Node]" + PingOneVerifyPlugin.logAppender;
	
	public static final String BUNDLE = PingOneVerifyProofing.class.getName();
	private final Helper client;
	private AMIdentity identity = null;
	private final IdmIntegrationService idmIntegrationService;

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
					put("postalAddress", "addressStreet");
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
			return "Waiting for completion.  Here is the code you will see on your device: %s";
		}

		@Attribute(order = 1350)
		default String redirectMessage() {
			return "Redirecting back to AIC.";
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
	public PingOneVerifyProofing(@Assisted Config config, @Assisted Realm realm, CoreWrapper coreWrapper, Helper client, IdmIntegrationService idmIntegrationService) {
		this.coreWrapper = coreWrapper;
		this.config = config;
		this.realm = realm;
		this.tntpPingOneConfig = TNTPPingOneConfigChoiceValues.getTNTPPingOneConfig(config.tntpPingOneConfigName());
		this.client = client;
		this.idmIntegrationService = idmIntegrationService;
	}

	@Override
	public Action process(TreeContext context) {
		try {
			logger.debug(loggerPrefix + "Started");
				
			NodeState ns = context.getStateFor(this);
			
			// check if choice exists
			if (!ns.isDefined(Constants.VerifyAuthnChoice)) {
				ns.putShared(Constants.VerifyAuthnChoice, UUID.randomUUID());
				if  (config.userNotificationChoice()){
					return Helper.getChoiceCallback(config.userNotificationChoiceMessage());
				}				
			}

			// if we are here, we are ready to init on choice made, or pre-set for user
			if (!ns.isDefined(Constants.VerifyAuthnInit)){
				// if here then the user choose, or the admin choose for them how to verify - SMS, EMAIL, or QR
				ns.putShared(Constants.VerifyAuthnInit, UUID.randomUUID());
				int userChoice = 0;
				if (config.userNotificationChoice()) {
					// get the users choice
					userChoice = context.getCallback(ConfirmationCallback.class).get().getSelectedIndex();
				}
				else {
					// take the choice picked for them
					userChoice = config.userNotification().getDeliveryMethod();
				}
				ns.putShared(Constants.VerifyUsersChoice, Integer.valueOf(userChoice));
				
				// perform init on choice

				// we need to get the phone number, email, or generate a qr code
				String phone = null;
				String email = null;
				switch(userChoice) {
				case Constants.SMSNum:
					phone = getInfo(Constants.telephoneNumber, context, true);
					break;
				case Constants.eMailNum:
					email = getInfo(Constants.mail, context, true);
					break;
				}
				
				JsonValue body = getInitBody(config.verifyPolicyId(), phone, email, context);

				// Setting PingOne Verify redirect callback url
				if (userChoice == Constants.redirectNum) {
					JsonValue redirect = new JsonValue(new LinkedHashMap<String, Object>(1));
					String redirectUri = getRedirectUri(context);
					redirect.put("url", redirectUri);
					redirect.put("message", config.redirectMessage());
					body.put("redirect", redirect);
				}

				// need to get the user id
				String pingUIDLocal = getInfo(config.userIdAttribute(), context, false);
				String pingUID = client.getPingUID(ns, tntpPingOneConfig, realm, config.userIdAttribute(), pingUIDLocal);
				
				ns.putShared(Constants.VerifyProofID, pingUID);
				
				TNTPPingOneUtility tntpP1U = TNTPPingOneUtility.getInstance();
				String accessToken = tntpP1U.getAccessToken(realm, tntpPingOneConfig);
				
				JsonValue response = client.init(accessToken, tntpPingOneConfig, body, pingUID);
				String webURL = response.get(Constants.webVerificationUrl).asString();
				String webVerCode = response.get(Constants.webVerificationCode).asString();
				long now = (new Date().getTime())/1000;

				// Setting shared state for redirect callback and polling callback
				ns.putShared(Constants.VerifyTransactionID, response.get("id").asString());
				ns.putShared(Constants.VerifyDS, now);

				// building list of callbacks
				List<Callback> callbacks = new ArrayList<>();
				// if we need to get a QR code, add it now
				if (userChoice == Constants.QRNum) {
					callbacks.add(Helper.generateQRCallback(webURL));
				} else if (userChoice == Constants.redirectNum) {
					// Building and executing the redirect URL
					RedirectCallback redirectCallback = new RedirectCallback(
							webURL + "&dt=1",
							null,
							"GET"
					);
					redirectCallback.setTrackingCookie(true);
					return Action.send(redirectCallback).build();
				}

				callbacks.add(new TextOutputCallback(TextOutputCallback.INFORMATION,  String.format(config.pollWaitMessage(), webVerCode)));
				PollingWaitCallback pwc = new PollingWaitCallback("5000","");
				callbacks.add(pwc);
				Constants.confirmationCancelCallback.setSelectedIndex(100);// so cancel doesnt looked pressed by default
				callbacks.add(Constants.confirmationCancelCallback);
				
				return Action.send(callbacks).build();
			}

			// Check if it should handle a redirect flow
			if (ns.isDefined(PINGONE_VERIFY_REDIRECT_FLOW_CODE_KEY)) {
				logger.debug("Handling redirect flow.");
				if (context.request.parameters.containsKey("code")) {
					String code = context.request.parameters.get("code").get(0);
					if (code.equals(ns.get(PINGONE_VERIFY_REDIRECT_FLOW_CODE_KEY).asString())) {
						logger.debug("Code found in request, completing the Identity Verification process.");
						ns.remove(PINGONE_VERIFY_REDIRECT_FLOW_CODE_KEY);
					} else {
						throw new Exception("Redirect code mismatch");
					}
				} else {
					throw new Exception("Redirect code missing");
				}
			}

			// if here, then the communication path has been decided, and init already happened.
			// we are checking if done and result
			
			// first check if cancelled hit
			if (Helper.cancelPushed(context, ns)) {
				Helper.cleanUpSS(ns, false, false);
				return Action.goTo(Constants.CANCEL).build();
			}
			
			// check if timeout reached
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
				pingOneUID = getInfo(config.userIdAttribute(), context, false);
			}
			
			String theURI = Constants.endpoint + tntpPingOneConfig.environmentRegion().getDomainSuffix() +
					"/v1/environments/" + tntpPingOneConfig.environmentId() + "/users/" + pingOneUID +
					"/verifyTransactions/" + transactionID;
			TNTPPingOneUtility tntpP1U = TNTPPingOneUtility.getInstance();
			String accessToken = tntpP1U.getAccessToken(realm, tntpPingOneConfig);
			JsonValue response = client.makeHTTPClientCall(accessToken, theURI, HttpConstants.Methods.GET, null);

			String result = response.get(Constants.transactionStatus).get(Constants.overallStatus).asString();

			return returnFinalStep(result, context, response, transactionID, pingOneUID, accessToken);

		} catch (Exception ex) {
			String stackTrace = org.apache.commons.lang.exception.ExceptionUtils.getStackTrace(ex);
			logger.error(loggerPrefix + "Exception occurred: ", ex);
			context.getStateFor(this).putTransient(loggerPrefix + "Exception", ex.getMessage());
			context.getStateFor(this).putTransient(loggerPrefix + "StackTrace", stackTrace);
			return Action.goTo(Constants.ERROR).build();
		}
	}

	String getRedirectUri(TreeContext context) throws NodeProcessException {
		// Get server URL
		String serverUrl = context.request.serverUrl;

		// Get query parameters and add code
		Map<String, List<String>> requestQueryParameters = context.request.parameters;
		Form redirectQuery = new Form();
		redirectQuery.putAll(requestQueryParameters);

		NodeState nodeState = context.getStateFor(this);
		String code = UUID.randomUUID().toString();
		nodeState.putShared(PINGONE_VERIFY_REDIRECT_FLOW_CODE_KEY, code);
		redirectQuery.put("code", Collections.singletonList(code));

		// Create resume URI
		MutableUri resumeUri;
		try {
			resumeUri = new MutableUri(serverUrl);
			resumeUri.setPath(resumeUri.getPath());
			resumeUri.setRawQuery(redirectQuery.toQueryString());
		} catch (URISyntaxException e) {
			throw new NodeProcessException(String.format("Failed to create Tree resume URI for server '%s'", serverUrl));
		}

		return resumeUri.toASCIIString();
	}
	
	private JsonValue getInitBody(String policyId, String telephoneNumber, String emailAddress, TreeContext context) throws Exception{
		
		JsonValue body = new JsonValue(new LinkedHashMap<String, Object>(1));


		// Verify Policy ID section
		JsonValue theID = new JsonValue(new LinkedHashMap<String, Object>(1));
		theID.put("id", policyId);
		body.put("verifyPolicy", theID);
		
		// sendNotification section
		if ((telephoneNumber!=null && !telephoneNumber.isEmpty()) || (emailAddress!=null && !emailAddress.isEmpty())) {
			JsonValue sendNotification = new JsonValue(new LinkedHashMap<String, Object>(1));
			sendNotification.putIfNotNull("phone", telephoneNumber);
			sendNotification.putIfNotNull("email", emailAddress);
			body.put("sendNotification", sendNotification);
		}
		
		// BIOGRAPHIC_MATCHER
		if (config.fuzzyMatchingConfiguration() != null && !config.fuzzyMatchingConfiguration().isEmpty()) {
			Set<String> keys = config.fuzzyMatchingConfiguration().keySet();
			JsonValue thisJVKey = new JsonValue(new LinkedHashMap<String, Object>(1));
			for(Iterator<String> i = keys.iterator(); i.hasNext();) {
				String thisKey = i.next();
				// get the value for the key from shared state or user
				String thisVal = getInfo(thisKey, context, true);
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

	private Action returnFinalStep(String result, TreeContext context, JsonValue response,
								   String transactionID, String pingOneUID, String accessToken) throws Exception {
		NodeState ns = context.getStateFor(this);

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
			
			// success outcomes
		case Constants.THESUCCESS:
		case Constants.NOT_REQUIRED:
		case Constants.APPROVED_NO_REQUEST:
		case Constants.APPROVED_MANUALLY:
			Action successRetVal = null;
			if (ns.isDefined(Constants.VerifyNeedPatch))
				successRetVal = Action.goTo(Constants.SUCCESSPATCH).build();
			else
				successRetVal = Action.goTo(Constants.SUCCESS).build();
			
			// retrieve verified data
			JsonValue userData = retrieveUserData(ns);
			
			// ensure map complete
			mapClaims(context, userData);

			// Process gov ID check if gov ID dropdown does not equal ANY
			if (!config.govId().equals(Constants.GovId.ANY)) {
				if (!govIDCheckPass(ns, userData)) {
					successRetVal = Action.goTo(Constants.FAIL).build();
				}
			}

			// failed expired check
			if (config.failExpired()) {
				if (!expiredDocCheck(ns, userData)) {
					successRetVal = Action.goTo(Constants.FAIL).build();
				}
			}

			// age threshold check
			if (!dobCheck(ns, userData)) {
				successRetVal = Action.goTo(Constants.FAIL).build();
			}
			
			// fuzzy matching check
			if (!fuzzyMatchCheck(context, userData, transactionID, pingOneUID, accessToken)) {
				successRetVal = Action.goTo(Constants.FAIL).build();
			}

			// save AccessToken?
			if(config.tsAccessToken()) {
				ns.putTransient(Constants.VerifyAT, accessToken);
			}
					
			// cleanup SS
			Helper.cleanUpSS(ns, ns.isDefined(Constants.VerifyNeedPatch), config.tsTransactionId());
			return successRetVal;
			
			// fail outcome
		case Constants.THEFAIL:
			// save PingOne UID
			ns.putShared(Constants.VerifyProofID, pingOneUID);

			// save AccessToken?
			if(config.tsAccessToken()) {
				ns.putTransient(Constants.VerifyAT, accessToken);
			}

			// save metadata
			if (config.saveMetadata()) {

				// if here, we need to get the metadata
				String theURI = Constants.endpoint + tntpPingOneConfig.environmentRegion().getDomainSuffix() +
						"/v1/environments/" + tntpPingOneConfig.environmentId() + "/users/" + pingOneUID +
						"/verifyTransactions/" + transactionID + "/metaData";

				JsonValue metadata = client.makeHTTPClientCall(accessToken, theURI, HttpConstants.Methods.GET, null);

				ns.putTransient(Constants.VerifyMetadataResult, metadata);
			}

			Action failRetVal = null;
			if (ns.isDefined(Constants.VerifyNeedPatch))
				failRetVal = Action.goTo(Constants.FAILPATCH).build();
			else
				failRetVal = Action.goTo(Constants.FAIL).build();
			
			// if demo mode, then send to success
			if (config.demoMode())
				failRetVal = Action.goTo(Constants.SUCCESS).build();
			// cleanup SS
			
			// message on why failed
			JsonValue failedReason = response.get(Constants.transactionStatus).get("verificationStatus");
			ns.putTransient(Constants.VerifedFailedReason, failedReason);
			
			Helper.cleanUpSS(ns, ns.isDefined(Constants.VerifyNeedPatch), config.tsTransactionId());
			return failRetVal;
		}
		/* if we're here, something went wrong */
		return Action.goTo(Constants.ERROR).build();
	}

	// fetch user data
	private JsonValue retrieveUserData(NodeState ns) throws Exception{
		JsonValue retVal = null;
		
		String pingUID = ns.get(Constants.VerifyProofID).asString();
		String txID = ns.get(Constants.VerifyTransactionID).asString();
		
		String theURI = Constants.endpoint + tntpPingOneConfig.environmentRegion().getDomainSuffix() + "/v1/environments/" + tntpPingOneConfig.environmentId() + "/users/" + pingUID + "/verifyTransactions/" + txID + "/verifiedData?type=GOVERNMENT_ID";
		
		TNTPPingOneUtility tntpP1U = TNTPPingOneUtility.getInstance();
		String accessToken = tntpP1U.getAccessToken(realm, tntpPingOneConfig);
		
		retVal = client.makeHTTPClientCall(accessToken, theURI, HttpConstants.Methods.GET, null);
		
		retVal = retVal.get("_embedded").get("verifiedData").get(0).get("data");
		
		if (config.saveVerifiedClaims())
			ns.putTransient(Constants.VerifyClaimResult, retVal);

		return retVal;
	}
	
	// govID check
	private boolean govIDCheckPass(NodeState ns, JsonValue claimData) throws Exception{
		boolean retVal = false;
		String thisGovIDCheck = claimData.get("idType").toString();
		
		thisGovIDCheck = thisGovIDCheck.toLowerCase();
		
		String cardToCompare = "";
		
		switch(config.govId().getVal()) {
			case Constants.DRIVING_LICENSE:
				cardToCompare = "DriversLicense";
				break;
			case Constants.ID_CARD:
				cardToCompare = "IdentificationCard";
				break;				
			case Constants.RESIDENCE_PERMIT:
				cardToCompare = "ResidencePermit";
				break;					
			case Constants.PASSPORT:
				cardToCompare = "Passport";
				break;					
			case Constants.ANY:
		}
		
		if (thisGovIDCheck.contains(cardToCompare.toLowerCase()) || config.govId().getVal().equalsIgnoreCase(Constants.ANY)) {
			retVal = true;
		}
		else {
			ns.putShared(Constants.VerifedFailedReason, "Document type required - failed");
		}
		
		return retVal;
	}

	// run a fuzzy match check against attribute confidence map
	private boolean fuzzyMatchCheck(TreeContext context, JsonValue claimData,
									String transactionID, String pingOneUID, String accessToken) throws Exception{
		NodeState ns = context.getStateFor(this);
		
		Map<String, String> fuzzyMap = config.fuzzyMatchingConfiguration();
		
		// if nothing in fuzzy mapping, and we don't need to save the metadata - return true
		if ((fuzzyMap==null || fuzzyMap.isEmpty()) && !config.saveMetadata())
			return true;
		
		String theURI = Constants.endpoint + tntpPingOneConfig.environmentRegion().getDomainSuffix() +
				"/v1/environments/" + tntpPingOneConfig.environmentId() + "/users/" + pingOneUID +
				"/verifyTransactions/" + transactionID + "/metaData";
		
		JsonValue metadata = client.makeHTTPClientCall(accessToken, theURI, HttpConstants.Methods.GET, null);

		// save metadata
		if (config.saveMetadata()) {
			ns.putTransient(Constants.VerifyMetadataResult, metadata);
			
			// if nothing in fuzzy mapping - return true
			if (fuzzyMap==null || fuzzyMap.isEmpty())
				return true;
		}

		// if here, we need to compare the biographic_match_results
		for (Iterator<JsonValue> i = metadata.get("_embedded").get("metaData").iterator(); i.hasNext(); ) {
			JsonValue thisOne = i.next();
			if (thisOne.get("type").asString().equalsIgnoreCase("BIOGRAPHIC_MATCH") && thisOne.get("status").asString().equalsIgnoreCase("SUCCESS")) {
				// last check do the levels match?  If exact, compare manually
				for (Iterator<JsonValue> innerIt = thisOne.get("data").get("biographic_match_results").iterator(); innerIt.hasNext(); ) {
					JsonValue thisInnerOne = innerIt.next();
					// Identifier can be different for onprem vs cloud TODO
					String thisAttr = thisInnerOne.get("identifier").asString();
					String thisConf = thisInnerOne.get("match").asString();

					String expectedConf = fuzzyMap.get(Helper.getFRVal(thisAttr));

					switch (expectedConf) {
						case "EXACT":
							String expectedAttr = getInfo(Helper.getFRVal(thisAttr), context, true);
							String claimAttr = claimData.get(Helper.getClaimVal(thisAttr)).asString();
							if (!expectedAttr.equalsIgnoreCase(claimAttr)) {
								ns.putShared(Constants.VerifedFailedReason, "Attribute match confidence map - failed");
								return false;
							}
							break;
						case "HIGH":
							if (!thisConf.equalsIgnoreCase("HIGH")) {
								ns.putShared(Constants.VerifedFailedReason, "Attribute match confidence map - failed");
								return false;
							}
							break;
						case "MEDIUM":
							if (thisConf.equalsIgnoreCase("LOW") || thisConf.equalsIgnoreCase("NOT_APPLICABLE")) {
								ns.putShared(Constants.VerifedFailedReason, "Attribute match confidence map - failed");
								return false;
							}
							break;
						case "LOW":
							if (thisConf.equalsIgnoreCase("NOT_APPLICABLE")) {
								ns.putShared(Constants.VerifedFailedReason, "Attribute match confidence map - failed");
								return false;
							}
							break;
					}
				}
				return true;
			}
		}
		ns.putShared(Constants.VerifedFailedReason, "Attribute match confidence map - failed");
		return false;
	}

	private boolean expiredDocCheck(NodeState ns, JsonValue claimData) throws Exception {
		String expirationDateClaim = claimData.get("expirationDate").asString();
		
        String toParse = expirationDateClaim + " 00:00:01.000-00:00";
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSSXXX");
        OffsetDateTime dateTime = OffsetDateTime.parse(toParse, formatter);
        Instant now = Instant.now();
        long days = ChronoUnit.DAYS.between(now, dateTime.toInstant());
        if(days<0) {
        	ns.putShared(Constants.VerifedFailedReason, "Fail expired documents - failed");
            return false;
        } else {
            return true;
        }
	}
	
	
	private void mapClaims(TreeContext context, JsonValue returnedClaims) throws Exception {
		
        JSONObject attributeMap = new JSONObject(config.attributeMappingConfiguration());
        JSONArray keys = attributeMap.names();
        
        if (keys==null || keys.isEmpty())
        	return;
        
        JsonValue objectAttributes = context.sharedState.get("objectAttributes");
        
        if (objectAttributes==null || objectAttributes.isNull()) {
        	objectAttributes = new JsonValue(new LinkedHashMap<String, Object>(1));
        }
        
        for (int i = 0; i < keys.length(); i++) {
            String key = keys.getString(i);
            String value = attributeMap.getString (key);
            if(returnedClaims.isDefined(value)){
            	objectAttributes.put(key, returnedClaims.get(value).getObject());
            }
        }
        NodeState ns = context.getStateFor(this);
        ns.putShared("objectAttributes",objectAttributes);
	}
	
	private boolean dobCheck(NodeState ns, JsonValue claimData) throws Exception {
		
		String dobClaim = claimData.get("birthDate").asString();
		
        String toParse = dobClaim + " 00:00:01.000-00:00";
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSSXXX");
        OffsetDateTime dobTime = OffsetDateTime.parse(toParse, formatter);
        OffsetDateTime limitTime = OffsetDateTime.now();
        limitTime = limitTime.minusYears(config.dobVerification());
        if (dobTime.isBefore(limitTime)) {
        	return true;
        }
        ns.putShared(Constants.VerifedFailedReason, "Age threshold - failed");
        return false;		
	}	
	
	private Optional<JsonValue> getUser(TreeContext context, String detail) throws Exception {
		
		if (idmIntegrationService.isEnabled()) {
			
			Optional<String> identity = IdmIntegrationHelper.stringAttribute(IdmIntegrationHelper.getUsernameFromContext(idmIntegrationService, context));
			
			Optional<JsonValue> user = IdmIntegrationHelper.getObject(idmIntegrationService, realm,
					context.request.locales, context.identityResource, "userName", identity, USERNAME, detail);
		
			return user;
		} else {
			if (this.identity==null || 
					!(identity.getName().equalsIgnoreCase(context.getStateFor(this).get(USERNAME).asString())) ||
					!(identity.getRealm().equalsIgnoreCase(context.getStateFor(this).get(REALM).asString()))) {
					String userName = context.getStateFor(this).get(USERNAME).asString();
					String realm = context.getStateFor(this).get(REALM).asString();
					this.identity = coreWrapper.getIdentityOrElseSearchUsingAuthNUserAlias(userName,realm);
			}

			
			JsonValue jv = new JsonValue(new LinkedHashMap<String, Object>(1));
			if (this.identity.getAttribute(detail)!=null && !this.identity.getAttribute(detail).isEmpty()) {
				jv.add(detail, this.identity.getAttribute(detail).iterator().next());
			}			
			return Optional.ofNullable(jv);
		}
	}
	
	
	private String getInfo(String det, TreeContext context, boolean onObjectAttribute) throws Exception {
		NodeState ns = context.getStateFor(this);
    	if (onObjectAttribute && ns.isDefined(Constants.objectAttributes)) {
    		
    		JsonValue objectAttributesTS = context.getTransientState(Constants.objectAttributes);
    		JsonValue objectAttributesSecured = context.getSecureState(Constants.objectAttributes);
    		JsonValue objectAttributes = context.sharedState.get(Constants.objectAttributes);
    		
    		if(objectAttributesTS!=null && objectAttributesTS.isNotNull() && objectAttributesTS.isDefined(det)) {
    			return objectAttributesTS.get(det).asString();
    		}
    		else if(objectAttributesSecured!=null && objectAttributesSecured.isNotNull() && objectAttributesSecured.isDefined(det)) {
    			return objectAttributesSecured.get(det).asString();
    		}
    		else if(objectAttributes!=null && objectAttributes.isNotNull() && objectAttributes.isDefined(det)) {
    			return objectAttributes.get(det).asString();
    		}
    	}
    	else if (!onObjectAttribute && ns.isDefined(det)) {
    		return ns.get(det).asString();
    	}
    	
    	// AMIdentity thisIdentity = getUser(ns);
    	
    	Optional<JsonValue> theInfo = getUser(context, det);
    	
        /* no identifier in sharedState, fetch from DS */
        if (theInfo != null && theInfo.isPresent()) {
        	
        	if (theInfo.get().isString())
        		return theInfo.get().asString();
        	else if (theInfo.get().isMap() && theInfo.get().iterator().hasNext())
        		return theInfo.get().get(det).asString();
        		// return theInfo.get().iterator().next().asString();
        }
        
        return null;
    }
	
	public static class ProofingOutcomeProvider implements OutcomeProvider {
		@Override
		public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {
			ResourceBundle bundle = locales.getBundleInPreferredLocale(PingOneVerifyProofing.BUNDLE,
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
