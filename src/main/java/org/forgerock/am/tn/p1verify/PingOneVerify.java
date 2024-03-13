/*
 * This code is to be used exclusively in connection with Ping Identity Corporation software or services. 
 * Ping Identity Corporation only offers such software or services to legal entities who have entered into 
 * a binding license agreement with Ping Identity Corporation.
 *
 * Copyright 2024 Ping Identity Corporation. All Rights Reserved
 */

package org.forgerock.am.tn.p1verify;

import static org.forgerock.openam.auth.node.api.Action.send;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.REALM;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.ResourceBundle;
import java.util.Set;
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
import org.forgerock.util.i18n.PreferredLocales;
import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.inject.assistedinject.Assisted;
import com.iplanet.sso.SSOException;
import com.sun.identity.authentication.callbacks.ScriptTextOutputCallback;
import com.sun.identity.idm.IdRepoException;


/**
 * A node that checks to see if zero-page login headers have specified username and whether that username is in a group
 * permitted to use zero-page login headers.
 */
@Node.Metadata(outcomeProvider  = PingOneVerify.PingOneVerifyOutcomeProvider.class,
        configClass      = PingOneVerify.Config.class, tags = {"marketplace", "trustnetwork" })
public class PingOneVerify implements Node {

    private final Logger logger = LoggerFactory.getLogger(PingOneVerify.class);
    private final Config config;
    private final String loggerPrefix = "[PingOneVerify Node]" + PingOneVerifyPlugin.logAppender;
    public static final String BUNDLE = PingOneVerify.class.getName();
    private final Realm realm;
    private TNTPPingOneConfig tntpPingOneConfig;
    public enum UserNotification { QR, SMS, EMAIL }
    public enum FlowType { REGISTRATION, VERIFICATION, AUTHENTICATION }
	public enum GovId { DEFAULT, DRIVING_LICENSE, PASSPORT, ID_CARD }

    public String getGovId(GovId govId) {
        if (govId == GovId.DEFAULT) {return "DEFAULT";}
        else if(govId == GovId.DRIVING_LICENSE) {return "DRIVING_LICENSE";}
        else if(govId == GovId.ID_CARD) {return "ID_CARD";}
        else return "PASSPORT";
    }
    public String getFlowType(FlowType flowType) {
        if (flowType == FlowType.REGISTRATION) {return "REGISTRATION";}
		else if(flowType == FlowType.AUTHENTICATION) {return "AUTHENTICATION";}
        else return "VERIFICATION";
    }
    public int getDeliveryMethod(UserNotification userNotification) {
        if (userNotification == UserNotification.EMAIL) {return 0;}
        else if (userNotification == UserNotification.SMS) {return 1;}
        else return 2;
    }
    public String txId;
    public String verificationCode;
    public String verificationUrl;
    public String verifiedClaims;
    public String verifyStatus;
    public String verifyMetadata;
    public String selfie = "";
    public String docFront = "";
    public String docPic = "";
    public String docType;
    public JSONObject userAttributesDsJson = new JSONObject();
    private final CoreWrapper coreWrapper;
    private static final String FAIL = "FAIL";
	private static final String SUCCESS = "SUCCESS";
	private static final String ERROR = "ERROR";
    private static final String IDNOMATCH = "IDNOMATCH";
    private static final String AGEFAILED = "AGEFAILED";


    public String ping2pingAttributeMap = "{\n" +
            "  \"firstName\":\"given_name\",\n" +
            "  \"lastName\" : \"family_name\",\n" +
            "  \"fullName\" : \"name\",\n" +
            "  \"address\" : \"address\",\n" +
            "  \"birthDate\" : \"birth_date\"\n" +
            "}";
    public String verifiedClaimsDemo = "{\n" +
            "                    \"address\": \"123 HILLCREST VIEW, NOTTINGHAM\",\n" +
            "                    \"birthDate\": \"1985-04-01\",\n" +
            "                    \"country\": \"GBR\",\n" +
            "                    \"expirationDate\": \"2045-12-31\",\n" +
            "                    \"firstName\": \"MR JOHN\",\n" +
            "                    \"fullName\": \"MR JOHN DOE\",\n" +
            "                    \"idNumber\": \"DOE654546HJ7TF34\",\n" +
            "                    \"idType\": \"[DriversLicenseFront, DriversLicenseBack]\",\n" +
            "                    \"issueDate\": \"2000-10-15\",\n" +
            "                    \"lastName\": \"DOE\"\n" +
            "                }";
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
		
        @Attribute(order = 130)
        default FlowType flowType() {
            return FlowType.REGISTRATION;
        }
    	
        @Attribute(order = 140)
        default String userIdAttribute() {
            return "";
        }
        
        @Attribute(order = 145)
        default String pictureAttribute() {
            return "";
        }
        
        
        
        @Attribute(order = 150)
        default String verifyPolicyId() {
            return "";
        }
        @Attribute(order = 160)
        default UserNotification userNotification() {
            return UserNotification.QR;
        }
        @Attribute(order = 170)
        default boolean userNotificationChoice() { return false; }

        @Attribute(order = 190)
        default int dobVerification() {return 0;}
        @Attribute(order = 200)
        default boolean failExpired() {return false;}
        @Attribute(order = 205)
        default GovId govId() {
            return GovId.DEFAULT;
        }
        @Attribute(order = 210)
        default int timeOut() {
            return 270;
        }
        @Attribute(order = 220)
        default boolean saveVerifiedClaims() { return false; }
        @Attribute(order = 230)
        default boolean saveMetadata() { return false; }
        @Attribute(order = 240)
        default Map<String, String> attributeMappingConfiguration() {
            return new HashMap<String, String>() {{
                /* key is DS attribute name,
                value is the claim name in PingOneVerify verified claims */
                put("givenName", "firstName");
                put("sn", "lastName");
                put("cn", "fullName");
                put("postalAddress", "address");
                put("country", "country");
                put("birthDateAttribute", "birthDate");
                put("idNumberAttribute", "idNumber");
                put("idTypeAttribute", "idType");
                put("expirationDateAttribute", "expirationDate");
            }};
        }
        @Attribute(order = 250)
        List<String> attributesToMatch();
        @Attribute(order = 260)
        default boolean preserveAttributes() { return true; }
        @Attribute(order = 270)
        default Map<String, String> fuzzyMatchingConfiguration() {
            return new HashMap<String, String>() {{
                /* key is DS attribute name,
                value is the confidence level required for success */
                put("givenName", "LOW");
                put("sn", "HIGH");
                put("address", "LOW");
                put("cn", "MEDIUM");
                put("birthDateAttribute", "MEDIUM");
            }};
        }
        @Attribute(order = 280)
        default boolean attributeLookup() { return false; }
        @Attribute(order = 290)
        default boolean tsAccessToken() { return false; }
        @Attribute(order = 300)
        default boolean tsTransactionId() { return false; }
        @Attribute(order = 310)
        default boolean demoMode() { return false; }

    }


    /**
     * Create the node using Guice injection. Just-in-time bindings can be used to obtain instances of other classes
     * from the plugin.
     *
     * @param config The service config.
     * @param realm The realm the node is in.
     */
    @Inject
    public PingOneVerify(@Assisted Config config, @Assisted Realm realm, CoreWrapper coreWrapper) {
        this.coreWrapper = coreWrapper;
        this.config = config;
        this.realm = realm;
		this.tntpPingOneConfig = TNTPPingOneConfigChoiceValues.getTNTPPingOneConfig(config.tntpPingOneConfigName());        
    }

    @Override
    public Action process(TreeContext context) {
        NodeState ns = context.getStateFor(this);
        try {
            logger.debug(loggerPrefix + "Started");

            /* check if we have PingOne Verify User ID attribute in config */
            if(config.userIdAttribute() == null) {
                /* cannot continue without */
                ns.putShared("PingOneVerifyError","PingOne UserID attribute (node config) needs to be defined");
                return Action.goTo(ERROR).build();
            }

            if (!ns.isDefined("verifyStage")) {
                ns.putShared("verifyStage", 0);
                ns.putShared("counter", 0);
            }

            if (config.userNotificationChoice() && ns.get("verifyStage").asInteger() < 2) {
                /* user is allowed to choose delivery method*/
                if (ns.get("verifyStage").asInteger() == 0) {
                    /* we haven't asked the user yet */
                    String[] options = {"Email", "SMS", "QR Code"};
                    TextOutputCallback textOutputCallback = new TextOutputCallback(TextOutputCallback.INFORMATION, "Choose delivery method");
                    ConfirmationCallback deliveryChoiceCallback =
                            new ConfirmationCallback("aaa", ConfirmationCallback.INFORMATION, options, 0);
                    Callback[] callbacks = new Callback[]{textOutputCallback, deliveryChoiceCallback};
                    ns.putShared("verifyStage", 1);
                    return send(callbacks).build();
                } else {
                    /* we have asked the user - fetch the choice */
                    int userChoice = context.getCallback(ConfirmationCallback.class).get().getSelectedIndex();
                    ns.putShared("PingOneVerifySelection", userChoice);
                    ns.putShared("verifyStage", 2);
                }
            } else if (ns.get("verifyStage").asInteger() < 2) {
                /* config determines delivery method */
                ns.putShared("PingOneVerifySelection", getDeliveryMethod(config.userNotification()));
                ns.putShared("verifyStage", 2);
            }
            if (ns.get("verifyStage").asInteger() == 2) {
                /* starting the verification procedure */
                String telephoneNumber = null;
                String emailAddress = null;
                
                TNTPPingOneUtility tntpP1U = TNTPPingOneUtility.getInstance();
				AccessToken accessToken = tntpP1U.getAccessToken(realm, tntpPingOneConfig);
                
                /* Check what flow type we're using and set/get a UUID for a user in PingOne */
                String p1vUserName = "";
                String p1vUserId = "";
                if(Objects.equals(getFlowType(config.flowType()),"REGISTRATION")) {
                    UUID uuid = UUID.randomUUID();
                    /* creating a random UUID for a new user */
                    p1vUserName = uuid.toString();
                    p1vUserId = createPingOneUser(accessToken,getUserEndpointUrl(),p1vUserName);
                    putP1vUseridToObjectAttributes(ns,config.userIdAttribute(),p1vUserId);
                } else {
                    /* get the id from sharedState */
                    if(ns.isDefined(config.userIdAttribute())) {
                        p1vUserId = ns.get(config.userIdAttribute()).toString();
                    } else {
                        /* sharedState missing PingOne Verify userId attribute */
                        p1vUserId = getP1uidFromDS(ns);
                        //ns.putShared("debug-id",p1vUserId);
                    }
                    if(p1vUserId.isEmpty()) {
                        /* something went wrong - we don't have user attribute */
                        return Action.goTo(IDNOMATCH).build();
                    }
                }
                ns.putShared("p1vUserId",p1vUserId);

                int verifyDeliveryMethod = ns.get("PingOneVerifySelection").asInteger();
                if (verifyDeliveryMethod == 0) {
                    /* email */
                    if(ns.get("objectAttributes").get("mail").asString()!=null &&
                            !Objects.equals(ns.get("objectAttributes").get("mail").asString(),"")) {
                        emailAddress = ns.get("objectAttributes").get("mail").asString();
                        ns.putShared("verifyStage", 3);
                    }
                    else {
                        ns.putShared("PingOneVerify-Error","mail attribute missing in sharedState objectAttributes");
                        return Action.goTo(ERROR).build();
                    }
                } else if (verifyDeliveryMethod == 1) {
                    /* sms */
                    if(ns.get("objectAttributes").get("telephoneNumber").asString()!=null &&
                            !Objects.equals(ns.get("objectAttributes").get("telephoneNumber").asString(),"")) {
                        telephoneNumber = ns.get("objectAttributes").get("telephoneNumber").asString();
                        ns.putShared("verifyStage", 3);
                    }
                    else {
                        ns.putShared("PingOneVerify-Error","Telephone number attribute missing in sharedState objectAttributes");
                        return Action.goTo(ERROR).build();
                    }
                } else if (verifyDeliveryMethod == 2) {
                    /* qr */
                    ns.putShared("verifyStage", 4);
                }
                if(Objects.equals(getFlowType(config.flowType()), "VERIFICATION")) {
                    /* pull all required attributes from objectAttributes or DS */
                    if(config.attributeLookup()) {
                        getUserAttributesFromDS(ns);
                    } else {
                        boolean result = getUserAttributesFromOA(ns);
                        if(!result) {
                            ns.putShared("PingOneVerifyMissingAttributesInSharedState","true");
                            return Action.goTo(ERROR).build();
                        }
                    }
                } else {
                    /* for REGISTRATION flow check if we want to verify attributes */
                    if(!config.fuzzyMatchingConfiguration().isEmpty()) {
                        /* we want to match attributes in REGISTRATION */
                        boolean result = getUserAttributesFromOA(ns);
                        if (!result) {
                            ns.putShared("PingOneVerifyMissingAttributesInSharedState", "true");
                            return Action.goTo(ERROR).build();
                        }
                    }
                }
                /* create PingOne Verify transaction */
                String verifyTxBody = createTransactionCallBody(config.verifyPolicyId(), telephoneNumber, emailAddress, createFuzzyMatchingAttributeMapObject(), ns);
                String verifyTxResponse = createVerifyTransaction(accessToken, getVerifyEndpointUrl(p1vUserId), verifyTxBody);
                if (verifyTxResponse.indexOf("error")==0) {
                    ns.putShared("PingOneTransactionError", verifyTxResponse);
                    if(Objects.equals(getFlowType(config.flowType()), "VERIFICATION")) {
                        if(verifyTxResponse.indexOf("404")>0) {
                            return Action.goTo(IDNOMATCH).build();
                        } else {
                            return Action.goTo(ERROR).build();
                        }
                    } else {
                        return Action.goTo(ERROR).build();
                    }

                }
                JSONObject obj = new JSONObject(verifyTxResponse);

                txId = obj.getString("id");
                ns.putShared("PingOneVerifyTxId",txId);
                verificationCode = obj.getString("webVerificationCode");
                ns.putShared("PingOneVerificationCode",verificationCode);
                verificationUrl = obj.getString("webVerificationUrl");
            }
            if (ns.get("verifyStage").asInteger() == 3) {
                /* sms and email */
            	
            	TNTPPingOneUtility tntpP1U = TNTPPingOneUtility.getInstance();
				AccessToken accessToken = tntpP1U.getAccessToken(realm, tntpPingOneConfig);
                String verifyTxId = ns.get("PingOneVerifyTxId").asString();
                String p1vUserId = ns.get("p1vUserId").asString();

                int count = ns.get("counter").asInteger();
                int timeOutCount = config.timeOut()/5;

                ns.putShared("counter", ++count);
                String message = "Interval: " + count;
                int verifyResult = 2;
                if(count>3) {
                    /* wait for 15 seconds before we start checking for result */
                    String sResult = getVerifyResult(accessToken.getTokenId(), getVerifyEndpointUrl(p1vUserId),verifyTxId);
                    if (sResult.indexOf("error")!=0) {
                        verifyResult = checkVerifyResult(sResult);
                    }
                }

                if (count < timeOutCount && verifyResult==2) {
                    /* waiting for verification success/fail for as long as configured */
                    verificationCode = ns.get("PingOneVerificationCode").asString();
                    TextOutputCallback textOutputCallback = new TextOutputCallback(TextOutputCallback.INFORMATION, "Please continue verification on your mobile device. Your verification code is: " + verificationCode);
                    PollingWaitCallback waitCallback =
                            new PollingWaitCallback("5000", message);
                    Callback[] callbacks = new Callback[]{textOutputCallback, waitCallback};
                    return send(callbacks).build();
                } else {
                    /* clean sharedState */
                    ns.putShared("counter",0);
                    if((config.saveMetadata() || createFuzzyMatchingAttributeMapObject()!=null) && !config.demoMode() ) {
                        /* we need metadata for either processing or to save in sharedState, demoMode is off */
                        verifyMetadata = getVerifyTransactionMetadata(accessToken.getTokenId(), getVerifyEndpointUrl(p1vUserId), verifyTxId);
                        if(config.saveMetadata()) {
                        	ns.putTransient("PingOneVerifyMetadata",verifyMetadata);
                        }
                    }
                    /* Leaving token and transaction id behind in transientState if needed */
                    transientStateResidue(ns, accessToken.getTokenId(), verifyTxId);

                    if(verifyResult==1) {
                        /* PingOne Verify returned SUCCESS */
                        /* We need to fetch the verifiedData claims */
                        if(!config.demoMode()) {
                            if(!Objects.equals(getFlowType(config.flowType()),"AUTHENTICATION")) {
                                /* not fetching claims for AUTHENTICATION flow */
                                verifiedClaims = getVerifiedData(accessToken.getTokenId(), getVerifyEndpointUrl(p1vUserId), verifyTxId);
                            }
                        } else {
                            /*we are in demo mode, returning example dataset*/
                            verifiedClaims = verifiedClaimsDemo;
                        }
                        if(verifiedClaims!=null && verifiedClaims.indexOf("error")==0) {
                            /* failed to fetch the verifiedData from PingOne Verify */
                            ns.putShared("PingOneVerifyFailedToGetVerifiedData","true");
                            ns.putShared("PingOneAccessToken","");
                            return Action.goTo(FAIL).build();
                        }
                        if(config.saveMetadata() || createFuzzyMatchingAttributeMapObject()!=null) {
                            verifyMetadata = getVerifyTransactionMetadata(accessToken.getTokenId(), getVerifyEndpointUrl(p1vUserId), verifyTxId);
                            if(config.saveMetadata()) {
                            	ns.putTransient("PingOneVerifyMetadata",verifyMetadata);
                            }
                        }
                        if(onResultSuccess(ns)){
                            if(!Objects.equals(getFlowType(config.flowType()),"AUTHENTICATION")) {

                                JSONObject claims = new JSONObject(verifiedClaims);
                                ns.putShared("userAttributesDsJson", "");
                                ns.putShared("PingOneAccessToken", "");

                                if (config.failExpired()) {
                                    /* check expiration date */
                                    if (claims.has("expirationDate")) {
                                        /* there is expiration date in the verified claims */
                                        if (!validateDocumentExpiration(claims.getString("expirationDate"))) {
                                            /* document expired */
                                            ns.putShared("PingOneVerifyDocumentExpired", "true");
                                            return Action.goTo(FAIL).build();
                                        }
                                    }
                                }
                                if (config.dobVerification() > 0 && Objects.equals(getFlowType(config.flowType()), "REGISTRATION")) {
                                    if (calculateAge(ns, claims.getString("birthDate")) >= config.dobVerification()) {
                                        //return Action.goTo(SUCCESS).build();
                                    } else {
                                        return Action.goTo(AGEFAILED).build();
                                    }
                                }
                                if (!Objects.equals(getGovId(config.govId()), "DEFAULT")) {
                                    /* a specific document type was required */
                                    if (claims.has("idType")) {
                                        String documentType = claims.getString("idType");
                                        if (Objects.equals(getGovId(config.govId()), "DRIVING_LICENSE")) {
                                            /* drivers license was required */
                                            if (!documentType.contains("DriversLicenseFront")) {
                                                /* no drivers license found in verifiedClaims */
                                                ns.putShared("PingOneVerifyDocumentTypeMismatch", "true");
                                                return Action.goTo(FAIL).build();
                                            }
                                        } else if (Objects.equals(getGovId(config.govId()), "PASSPORT")) {
                                            /* passport was required */
                                            if (!documentType.contains("PassportPicturePage")) {
                                                /* no passport found in verifiedClaims */
                                                ns.putShared("PingOneVerifyDocumentTypeMismatch", "true");
                                                return Action.goTo(FAIL).build();
                                            }
                                        } else {
                                            if (!documentType.contains("IdentificationCardFront")) {
                                                /* no id card found in verifiedClaims */
                                                ns.putShared("PingOneVerifyDocumentTypeMismatch", "true");
                                                return Action.goTo(FAIL).build();
                                            }
                                        }
                                    } else {
                                        /* cannot determine document type */
                                        ns.putShared("PingOneVerifyDocumentTypeUndetermined", "true");
                                        return Action.goTo(FAIL).build();
                                    }
                                }
                            }
                            return Action.goTo(SUCCESS).build();

                        } else {
                            ns.putShared("userAttributesDsJson","");
                            ns.putShared("PingOneAccessToken","");
                            return Action.goTo(FAIL).build();
                        }
                    } else {
                        /* Time out */
                        ns.putShared("userAttributesDsJson","");
                        ns.putShared("PingOneAccessToken","");
                        ns.putShared("PingOneVerifyClaims",verifiedClaims);
                        ns.putShared("PingOneVerifyStatus",verifyStatus);
                        return Action.goTo(FAIL).build();
                    }
                }
            }
            if (ns.get("verifyStage").asInteger() == 4) {
                /*qr code*/
            	TNTPPingOneUtility tntpP1U = TNTPPingOneUtility.getInstance();
				AccessToken accessToken = tntpP1U.getAccessToken(realm, tntpPingOneConfig);
                String verifyTxId = ns.get("PingOneVerifyTxId").asString();
                String p1vUserId = ns.get("p1vUserId").asString();

                int count = ns.get("counter").asInteger();
                int timeOutCount = config.timeOut()/5;

                ns.putShared("counter", ++count);
                String message = "Interval: " + count;
                int verifyResult = 2;

                if(count>3) {
                    /*wait for 15 seconds before we start checking for result*/
                    String sResult = getVerifyResult(accessToken.getTokenId(), getVerifyEndpointUrl(p1vUserId),verifyTxId );
                    if (sResult.indexOf("error")!=0) {
                        verifyResult = checkVerifyResult(sResult);
                    }
                }
                if (count < timeOutCount && verifyResult==2) {
                    /* waiting for verification success/fail for as long as configured */
                    verificationCode = ns.get("PingOneVerificationCode").asString();
                    String clientSideScriptExecutorFunction = createQrCodeScript(verificationUrl);
                    TextOutputCallback textOutputCallback = new TextOutputCallback(TextOutputCallback.INFORMATION, "Please scan the QR code to continue verification process. Your verification code is: " + verificationCode);
                    PollingWaitCallback waitCallback =
                            new PollingWaitCallback("5000", message);
                    ScriptTextOutputCallback scriptAndSelfSubmitCallback =
                            new ScriptTextOutputCallback(clientSideScriptExecutorFunction);
                    Callback[] callbacks = new Callback[]{textOutputCallback, waitCallback, scriptAndSelfSubmitCallback};
                    return send(callbacks).build();
                } else {
                    /* clean sharedState */
                    ns.putShared("counter",0);
                    if((config.saveMetadata() || createFuzzyMatchingAttributeMapObject()!=null) && !config.demoMode() ) {
                        /* we need metadata for either processing or to save in sharedState, demoMode is off */
                        verifyMetadata = getVerifyTransactionMetadata(accessToken.getTokenId(), getVerifyEndpointUrl(p1vUserId), verifyTxId);
                        if(config.saveMetadata()) {
                        	ns.putTransient("PingOneVerifyMetadata",verifyMetadata);
                        }
                    }
                    /* Leaving token and transaction id behind in transientState if needed */
                    transientStateResidue(ns, accessToken.getTokenId(), verifyTxId);

                    if(verifyResult==1) {
                        /* PingOne Verify returned SUCCESS */
                        /* We need to fetch the verifiedData claims */
                        if(!config.demoMode()) {
                            if(!Objects.equals(getFlowType(config.flowType()),"AUTHENTICATION")) {
                                /* not fetching claims for AUTHENTICATION flow */
                                verifiedClaims = getVerifiedData(accessToken.getTokenId(), getVerifyEndpointUrl(p1vUserId), verifyTxId);
                            }
                        } else {
                            /*we are in demo mode, returning example dataset*/
                           verifiedClaims = verifiedClaimsDemo;
                        }
                        if(verifiedClaims!=null && verifiedClaims.indexOf("error")==0) {
                            /* failed to fetch the verifiedData from PingOne Verify */
                            ns.putShared("PingOneVerifyFailedToGetVerifiedData","true");
                            ns.putShared("PingOneAccessToken","");
                            return Action.goTo(FAIL).build();
                        }
                        if(config.saveMetadata() || createFuzzyMatchingAttributeMapObject()!=null) {
                            verifyMetadata = getVerifyTransactionMetadata(accessToken.getTokenId(), getVerifyEndpointUrl(p1vUserId), verifyTxId);
                            if(config.saveMetadata()) {
                            	ns.putTransient("PingOneVerifyMetadata",verifyMetadata);
                            }
                        }


                        if(onResultSuccess(ns)) {
                            if(!Objects.equals(getFlowType(config.flowType()),"AUTHENTICATION")) {
                                /* we are only doing checks for REGISTRATION and VERIFICATIO */
                                JSONObject claims = new JSONObject(verifiedClaims);
                                ns.putShared("userAttributesDsJson", "");
                                ns.putShared("PingOneAccessToken", "");

                                if (config.failExpired()) {
                                    /* check expiration date */
                                    if (claims.has("expirationDate")) {
                                        /* there is expiration date in the verified claims */
                                        if (!validateDocumentExpiration(claims.getString("expirationDate"))) {
                                            /* document expired */
                                            ns.putShared("PingOneVerifyDocumentExpired", "true");
                                            return Action.goTo(FAIL).build();
                                        }
                                    }
                                }
                                if (config.dobVerification() > 0 && Objects.equals(getFlowType(config.flowType()), "REGISTRATION")) {
                                    if (calculateAge(ns, claims.getString("birthDate")) >= config.dobVerification()) {
                                        //return Action.goTo(SUCCESS).build();
                                    } else {
                                        return Action.goTo(AGEFAILED).build();
                                    }
                                }
                                if (!Objects.equals(getGovId(config.govId()), "DEFAULT")) {
                                    /* a specific document type was required */
                                    if (claims.has("idType")) {
                                        String documentType = claims.getString("idType");
                                        if (Objects.equals(getGovId(config.govId()), "DRIVING_LICENSE")) {
                                            /* drivers license was required */
                                            if (!documentType.contains("DriversLicenseFront")) {
                                                /* no drivers license found in verifiedClaims */
                                                ns.putShared("PingOneVerifyDocumentTypeMismatch", "true");
                                                return Action.goTo(FAIL).build();
                                            }
                                        } else if (Objects.equals(getGovId(config.govId()), "PASSPORT")) {
                                            /* passport was required */
                                            if (!documentType.contains("PassportPicturePage")) {
                                                /* no passport found in verifiedClaims */
                                                ns.putShared("PingOneVerifyDocumentTypeMismatch", "true");
                                                return Action.goTo(FAIL).build();
                                            }
                                        } else {
                                            if (!documentType.contains("IdentificationCardFront")) {
                                                /* no id card found in verifiedClaims */
                                                ns.putShared("PingOneVerifyDocumentTypeMismatch", "true");
                                                return Action.goTo(FAIL).build();
                                            }
                                        }
                                    } else {
                                        /* cannot determine document type */
                                        ns.putShared("PingOneVerifyDocumentTypeUndetermined", "true");
                                        return Action.goTo(FAIL).build();
                                    }
                                }
                            }
                            return Action.goTo(SUCCESS).build();
                        }
                        else {
                            ns.putShared("userAttributesDsJson","");
                            ns.putShared("PingOneAccessToken","");
                            return Action.goTo(FAIL).build();
                        }
                    }
                    else {
                        /* Time out */
                        ns.putShared("userAttributesDsJson","");
                        ns.putShared("PingOneAccessToken","");
                        ns.putShared("PingOneVerifyClaims",verifiedClaims);
                        ns.putShared("PingOneVerifyStatus",verifyStatus);
                        return Action.goTo(FAIL).build();
                    }
                }
            }
            /* if we're here, something went wrong */
            return Action.goTo(ERROR).build();
        }
        catch (Exception ex) {
            String stackTrace = org.apache.commons.lang.exception.ExceptionUtils.getStackTrace(ex);
            logger.error(loggerPrefix + "Exception occurred: " + stackTrace);
            context.getStateFor(this).putShared(loggerPrefix + "Exception", ex.getMessage());
            context.getStateFor(this).putShared(loggerPrefix + "StackTrace", stackTrace);
            return Action.goTo(ERROR).build();
        }
    }
    
    
	private boolean onResultSuccess(NodeState ns) throws IdRepoException, SSOException {
        if(config.saveVerifiedClaims()) {
            /* save verified claims to SharedState (config) */
            ns.putShared("PingOneVerifyClaims",verifiedClaims);
        }
        if(Objects.equals(getFlowType(config.flowType()), "VERIFICATION")) {
            /* checking if the objectAttributes match the verified claims */
            /* check successful */
            /* checks failed */
            return validateVerifiedClaims(ns, verifiedClaims);
        } else if (Objects.equals(getFlowType(config.flowType()), "REGISTRATION")){
            /* for REGISTRATION checks are only needed if configured
            but we are mapping claims to objectAttributes */
            verifiedClaimsToSharedState(ns,verifiedClaims);
            if(!config.attributesToMatch().isEmpty()) {
                /*  attribute matching required*/
                return validateVerifiedClaims(ns, verifiedClaims);
            } else {
                /* attribute matching not required */
                return true;
            }
        } else {
            /* no additional tasks for AUTHENTICATION flow */
            return true;
        }
    }
    private void transientStateResidue(NodeState ns, String p1AccessToken, String txId) {
        if(p1AccessToken!=null && !Objects.equals(p1AccessToken,"") && config.tsAccessToken()) {
            ns.putTransient("p1AccessToken",p1AccessToken);
        }
        if(txId!=null && !Objects.equals(p1AccessToken,"") && config.tsTransactionId()) {
            ns.putTransient("p1VtxId",txId);
        }
    }
    private String dsAttributeToVerifiedClaim (String dsAttribute) {
        JSONObject attributeMap = new JSONObject(config.attributeMappingConfiguration());
        return attributeMap.get(dsAttribute).toString();
    }
    private String verifiedClaimAttributeToRequirementsAttribute (String vcAttribute) {
        JSONObject attributeMap = new JSONObject(ping2pingAttributeMap);
        return attributeMap.get(vcAttribute).toString();
    }
    private String dsAttributeToRequirementsAttribute (String dsAttribute) {
        return verifiedClaimAttributeToRequirementsAttribute(dsAttributeToVerifiedClaim(dsAttribute));
    }
    private JSONObject createFuzzyMatchingAttributeMapObject () {
        JSONObject attributeMapping = new JSONObject();
        if(config.fuzzyMatchingConfiguration().isEmpty()) {
            attributeMapping = null;
            return attributeMapping;
        }
        JSONObject fuzzyMatchJSONConfig = new JSONObject(config.fuzzyMatchingConfiguration());
        JSONArray keys = fuzzyMatchJSONConfig.names();
        JSONObject attributeMap = new JSONObject(config.attributeMappingConfiguration());
        for(int i = 0; i < keys.length(); i++) {
            String attrNameDS = "";
            String attrNameVC = "";
            String attrValue = "";
            attrNameDS = keys.get(i).toString();
            if(attributeMap.has(attrNameDS)) {
                attrNameVC = attributeMap.getString(attrNameDS);
                if(userAttributesDsJson.has(attrNameDS)) {
                    attrValue = userAttributesDsJson.getString(attrNameDS);
                }
            }
            if(!Objects.equals(attrNameVC,"") && !Objects.equals(attrValue,"")) {
                attributeMapping.put(verifiedClaimAttributeToRequirementsAttribute(attrNameVC),attrValue);
            }
        }
        return attributeMapping;
    }
    private boolean getUserAttributesFromOA (NodeState ns) {
        JsonValue objectAttributes =  ns.get("objectAttributes");
        List<String> requiredAttributes = config.attributesToMatch();
        for (int i = 0; i < requiredAttributes.size(); i++) {
            String attribute = objectAttributes.get(requiredAttributes.get(i)).asString();
            if(attribute==null || Objects.equals(attribute,"")) {
                return false;
            } else {
                userAttributesDsJson.put(requiredAttributes.get(i),attribute);
            }
        }
        ns.putShared("userAttributesDsJson",userAttributesDsJson.toString());
        return true;
    }
    private String getSelfie (NodeState ns) throws IdRepoException, SSOException {
        if(ns.isDefined(config.pictureAttribute())) {
            return ns.get(config.pictureAttribute()).toString();
        }
        /* no identifier in sharedState, fetch from DS */
        String userName = ns.get(USERNAME).asString();
        String realm = ns.get(REALM).asString();
        /* get user attribute from ds */
        String userIdentifier = "";
        userIdentifier = coreWrapper.getIdentityOrElseSearchUsingAuthNUserAlias(userName,realm).getAttribute(config.pictureAttribute()).toString();

        userIdentifier = userIdentifier.replaceAll("[\\[\\]\\\"]", "");
        return userIdentifier;
    }
    private String getP1uidFromDS (NodeState ns) throws IdRepoException, SSOException {
        if(ns.isDefined(config.userIdAttribute())) {
            return ns.get(config.userIdAttribute()).toString();
        }
        /* no identifier in sharedState, fetch from DS */
        String userName = ns.get(USERNAME).asString();
        String realm = ns.get(REALM).asString();
        /* get user attribute from ds */
        String userIdentifier = "";
        userIdentifier = coreWrapper.getIdentityOrElseSearchUsingAuthNUserAlias(userName,realm).getAttribute(config.userIdAttribute()).toString();

        userIdentifier = userIdentifier.replaceAll("[\\[\\]\\\"]", "");
        return userIdentifier;

        //return coreWrapper.getIdentityOrElseSearchUsingAuthNUserAlias(userName,realm).getAttribute(config.userIdAttribute()).toString();
    }
    private long calculateAge(NodeState ns, String dobClaim) {
        String toParse = dobClaim + " 00:00:01.000-00:00";
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSSXXX");
        OffsetDateTime dateTime = OffsetDateTime.parse(toParse, formatter);
        Instant now = Instant.now();
        ns.putShared("Age",ChronoUnit.DAYS.between(dateTime.toInstant(), now)/365);
        return ChronoUnit.DAYS.between(dateTime.toInstant(), now)/365;
    }
    private boolean validateDocumentExpiration(String expirationDateClaim) {
        String toParse = expirationDateClaim + " 00:00:01.000-00:00";
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSSXXX");
        OffsetDateTime dateTime = OffsetDateTime.parse(toParse, formatter);
        Instant now = Instant.now();
        long days = ChronoUnit.DAYS.between(now, dateTime.toInstant());
        if(days<0) {
            return false;
        } else {
            return true;
        }

    }

    private void getUserAttributesFromDS (NodeState ns) throws IdRepoException, SSOException {
        List<String> requiredAttributes = config.attributesToMatch();
        String userName = ns.get(USERNAME).asString();
        String realm = ns.get(REALM).asString();
        /* make a map for all required attributes (names) */
        Set<String> uas = new HashSet<String>();
        for (int i = 0; i < requiredAttributes.size(); i++) {
            uas.add(requiredAttributes.get(i));
        }
        /* get user attributes from ds */
        Map dsAttributesMap = null;
        dsAttributesMap = coreWrapper.getIdentityOrElseSearchUsingAuthNUserAlias(userName,realm).getAttributes(uas);
        JSONObject dsMapTempJson = new JSONObject(dsAttributesMap);
        /* attributes are returned as array, need to transform */
        for (int i = 0; i < requiredAttributes.size(); i++) {
            String value = dsMapTempJson.get(requiredAttributes.get(i)).toString();
            value = value.replaceAll("[\\[\\]\\\"]", "");
            userAttributesDsJson.put(requiredAttributes.get(i),value);
        }
        ns.putShared("userAttributesDsJson",userAttributesDsJson.toString());
    }
    private int levelToNumber(String level) {
        if(Objects.equals(level,"LOW")) {
            return 0;
        } else if (Objects.equals(level,"MEDIUM")) {
            return 1;
        } else {
            return 2;
        }
    }
    private boolean validateVerifiedClaims(NodeState ns, String claims) throws IdRepoException, SSOException {
        /* verification procedure here */

        if(config.demoMode()) {
            /* always successful in demo mode */
            return true;
        }

        List<String> requiredAttributes = config.attributesToMatch();
        userAttributesDsJson = new JSONObject(ns.get("userAttributesDsJson").asString());

        if(!config.fuzzyMatchingConfiguration().isEmpty()) {
            /* get biographic data from metaData */
            String biographicData = getVerifyBiographicMetadata(verifyMetadata);
            if(biographicData.indexOf("error")==0) {
                ns.putShared("PingOneVerifyFailedToFetchBiographicResult",biographicData);
                return false;
            }
            JSONObject biographicDataJSON = new JSONObject(biographicData);
            JSONArray biographicDataJSONArray = biographicDataJSON.getJSONArray("biographic_match_results");
            /*get attribute confidence map from config */
            JSONObject attributeConfidenceMap = new JSONObject(config.fuzzyMatchingConfiguration());
            JSONArray keys = attributeConfidenceMap.names();

            for (int i = 0; i < keys.length(); i++) {
                String configAttribute = keys.getString(i);
                int configAttributeConfidence = levelToNumber(attributeConfidenceMap.get(configAttribute).toString());
                configAttribute = dsAttributeToRequirementsAttribute(configAttribute);
                for (int y = 0; y < biographicDataJSONArray.length(); y++) {
                    JSONObject entry = biographicDataJSONArray.getJSONObject(y);
                    if(Objects.equals(configAttribute,entry.get("identifier").toString())) {
                        int bioAttributeConfidence = levelToNumber(entry.getString("match"));
                        if (bioAttributeConfidence < configAttributeConfidence) {
                            ns.putShared("PingOneVerifyBiographicMatch", "below set confidence level");
                            ns.putShared("PingOneVerifyBiographicResult",biographicData);
                            return false;
                        } else {
                            y  = biographicDataJSONArray.length();
                        }
                    }
                }
            }
        }
        int matchedAttributes = 0;
        /* compare the attributes */
        JSONObject userAttributesVcJson = new JSONObject(claims);
        for(int i=0; i<requiredAttributes.size(); i++) {
            String dsAttr, vcAttr = "";
            dsAttr = userAttributesDsJson.get(requiredAttributes.get(i)).toString();
            vcAttr = userAttributesVcJson.get(dsAttributeToVerifiedClaim(requiredAttributes.get(i))).toString();
            if(Objects.equals(dsAttr.toUpperCase(), vcAttr.toUpperCase())) {
                matchedAttributes++;
            } else {
                if(!config.fuzzyMatchingConfiguration().isEmpty()) {
                    JSONObject attributeConfidenceMap = new JSONObject(config.fuzzyMatchingConfiguration());
                    JSONArray keys = attributeConfidenceMap.names();
                    for (int y = 0; y < keys.length(); y++) {
                        if (Objects.equals(keys.get(y).toString(), requiredAttributes.get(i))) {
                            // this attribute is on a fuzzy match list
                            matchedAttributes++;
                            y = keys.length();
                        }
                    }
                }
            }
        }
        return requiredAttributes.size() == matchedAttributes;
    }
    private boolean verifiedClaimsToSharedState(NodeState ns, String verifiedClaims) {
        /* Mapping verified claims (based on the map in config to objectAttributes */
        JSONObject attributeMap = new JSONObject(config.attributeMappingConfiguration());
        JSONArray keys = attributeMap.names();
        JsonValue objectAttributes;
        objectAttributes = ns.get("objectAttributes");
        JSONObject dataJson = new JSONObject(verifiedClaims);
        for (int i = 0; i < keys.length (); i++) {
            String key = keys.getString (i);
            String value = attributeMap.getString (key);
            if(dataJson.has(value)){
                if(!config.preserveAttributes()) {
                    /* we are putting all claims if we're not preserving original attributes */
                    objectAttributes.put(key, dataJson.get(value));
                }
                else {
                    /* we are preserving existing user attributes in objectAttributes */
                    if(!objectAttributes.isDefined(key)) {
                        objectAttributes.put(key, dataJson.get(value));
                    }
                }
            }
        }


        ns.putShared("objectAttributes",objectAttributes);
        return true;
    }

    private boolean putP1vUseridToObjectAttributes(NodeState ns, String p1vUserIdAttribute, String p1vUserId) {
        /* Mapping verified claims (based on the map in config to objectAttributes */
        JsonValue objectAttributes;
        objectAttributes = ns.get("objectAttributes");
        objectAttributes.put(p1vUserIdAttribute, p1vUserId);
        ns.putShared("objectAttributes",objectAttributes);
        return true;
    }

    private String createQrCodeScript(String url) {
        return  "var div = document.createElement('div'); \n" +
                "div.id = 'QRCode';  \n" +
                "div.innerHTML = '<div class=\"container\">' \n" +
                "'<h2>QR Code Authentication</h2>' \n" +
                "'<span style=\"font-size:20px;\">' + \n" +
                "'Please scan this QR Code with a registered device' + \n" +
                "'</span>' + \n" +
                "'<div id=\"qr\">QRCode</div>' +\n" +
                "'</div>'; \n" +
                "window.QRCodeReader.createCode({id: 'qr',text: '" + url + "',version: '20',code: 'L'});\n" +
                "document.getElementsByClassName(\"polling-spinner-container\")[0].hidden = true;\n" +
                "document.getElementsByClassName(\"btn mt-2 btn-link\")[0].hidden = true;\n";
    }

    private String getUserEndpointUrl() {
        return  "https://api.pingone." + tntpPingOneConfig.environmentRegion().getDomainSuffix() + "/v1/environments/" + tntpPingOneConfig.environmentId() + "/users";
    }

    private String getVerifyEndpointUrl(String p1vUid) {
        return  "https://api.pingone." + tntpPingOneConfig.environmentRegion().getDomainSuffix() + "/v1/environments/" + tntpPingOneConfig.environmentId() + "/users/" + p1vUid + "/verifyTransactions";
    }

    private String createVerifyTransaction(AccessToken accessToken, String endpoint, String body) {
        StringBuffer response = new StringBuffer();
        HttpURLConnection conn = null;
        try {
            URL url = new URL(endpoint);
            conn = (HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(4000);
            conn.setDoOutput(true);
            conn.setDoInput(true);
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("Authorization", "Bearer " + accessToken);
            conn.setRequestMethod("POST");
            OutputStream os = conn.getOutputStream();
            os.write(body.getBytes(StandardCharsets.UTF_8));
            os.close();
            if(conn.getResponseCode()==201) {
                BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
                String inputLine;
                while ((inputLine = in.readLine()) != null) {
                    response.append(inputLine);
                }
                in.close();
                return response.toString();
            } else {
                String responseError = "error:" + conn.getResponseCode();
                return responseError;
            }
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        finally {
            if(conn!=null) {
                conn.disconnect();
            }
        }
        return "error";
    }

    private String createPingOneUser(AccessToken accessToken, String endpoint, String userName) {
        StringBuffer response = new StringBuffer();
        HttpURLConnection conn = null;
        String body = "{\"username\":\"" + userName + "\"}";
        try {
            URL url = new URL(endpoint);
            conn = (HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(4000);
            conn.setDoOutput(true);
            conn.setDoInput(true);
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("Authorization", "Bearer " + accessToken);
            conn.setRequestMethod("POST");
            OutputStream os = conn.getOutputStream();
            os.write(body.getBytes(StandardCharsets.UTF_8));
            os.close();
            if(conn.getResponseCode()==201){
                BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
                String inputLine;
                while ((inputLine = in.readLine()) != null) {
                    response.append(inputLine);
                }
                in.close();
                JSONObject responseJSON = new JSONObject(response.toString());
                return responseJSON.getString("id");
            } else {
                String responseError = "error:" + conn.getResponseCode();
                return responseError;
            }
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        finally {
            if(conn!=null) {
                conn.disconnect();
            }
        }
        return "error";
    }
    private int checkVerifyResult(String verifyResponse) {
        try {
            JSONObject obj = new JSONObject(verifyResponse);
            String result = "";
            result = obj.getJSONObject("transactionStatus").getString("status");
            if (Objects.equals(result, "SUCCESS")) {
                return 1; /*success*/
            } else if (Objects.equals(result, "FAIL")) {
                verifyStatus = obj.getJSONObject("transactionStatus").getJSONObject("verificationStatus").toString();
                if(config.demoMode()) {
                    return 1; /*always successful in demo mode*/
                } else {
                    return 0; /*failed*/
                }
            }
            else {
                return 2; /*pending*/
            }
        } catch (Exception ex) {
            return 2; /*pending*/
        }
    }
    String verifyApiBase64ToJpeg(String apiResponse) {
        try {
            JSONObject obj = new JSONObject(apiResponse);
            JSONArray jsonArray;
            String result = "";
            jsonArray = obj.getJSONObject("_embedded").getJSONArray("verifiedData");

            JSONObject obj2 = new JSONObject(jsonArray.getJSONObject(0).toString());
            result = obj2.getJSONObject("data").getString("IMAGE");
            return result;
        } catch (Exception ex) {
            return "error";
        }
    }

    private String getVerifiedData(String accessToken, String endpoint, String vTxId) {
        String resultEndpoint = endpoint + "/" + vTxId + "/verifiedData?type=GOVERNMENT_ID";
        StringBuffer response = new StringBuffer();
        HttpURLConnection conn = null;
		try {
            URL url = new URL(resultEndpoint);
            conn = (HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(4000);
            conn.setDoOutput(true);
            conn.setDoInput(true);
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("Authorization", "Bearer " + accessToken);
            conn.setRequestMethod("GET");
            if(conn.getResponseCode()==200){
                BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
                String inputLine;
                while ((inputLine = in.readLine()) != null) {
                    response.append(inputLine);
                }
                in.close();
                JSONObject responseJSON = new JSONObject(response.toString());
                String verifiedData = responseJSON.getJSONObject("_embedded").getJSONArray("verifiedData").get(0).toString();
                responseJSON = new JSONObject(verifiedData);
                verifiedData = responseJSON.getJSONObject("data").toString();
                return verifiedData;
            } else {
                String responseError = "error:" + conn.getResponseCode();
                return responseError;
            }
        } catch (MalformedURLException e) {
        	String stackTrace = org.apache.commons.lang.exception.ExceptionUtils.getStackTrace(e);
        	logger.error(loggerPrefix + "Exception occurred: " + stackTrace);
        } catch (IOException e) {
        	String stackTrace = org.apache.commons.lang.exception.ExceptionUtils.getStackTrace(e);
        	logger.error(loggerPrefix + "Exception occurred: " + stackTrace);
        }
        finally {
            if(conn!=null) {
            	try {
                conn.disconnect();
            	}
            	catch (Exception e) {
            		//DO NOTHING
            	}
            }
        }
        return "error";
    }
    private String getVerifyResult(String accessToken, String endpoint, String vTxId) {
        String resultEndpoint = endpoint + "/" + vTxId;
        StringBuffer response = new StringBuffer();
        HttpURLConnection conn = null;
        try {
            URL url = new URL(resultEndpoint);
            conn = (HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(4000);
            conn.setDoOutput(true);
            conn.setDoInput(true);
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("Authorization", "Bearer " + accessToken);
            conn.setRequestMethod("GET");
            if(conn.getResponseCode()==200){
                BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
                String inputLine;
                while ((inputLine = in.readLine()) != null) {
                    response.append(inputLine);
                }
                in.close();
                return response.toString();
            } else {
                String responseError = "error:" + conn.getResponseCode();
                return responseError;
            }
        } catch (MalformedURLException e) {
        	String stackTrace = org.apache.commons.lang.exception.ExceptionUtils.getStackTrace(e);
        	logger.error(loggerPrefix + "Exception occurred: " + stackTrace);
        } catch (IOException e) {
        	String stackTrace = org.apache.commons.lang.exception.ExceptionUtils.getStackTrace(e);
        	logger.error(loggerPrefix + "Exception occurred: " + stackTrace);
        }
        finally {
            if(conn!=null) {
                conn.disconnect();
            }
        }
        return "error";
    }

    private String getVerifyTransactionMetadata(String accessToken, String endpoint, String vTxId) {
        String resultEndpoint = endpoint + "/" + vTxId + "/metaData";
        StringBuffer response = new StringBuffer();
        HttpURLConnection conn = null;
        try {
            URL url = new URL(resultEndpoint);
            conn = (HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(4000);
            conn.setDoOutput(true);
            conn.setDoInput(true);
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("Authorization", "Bearer " + accessToken);
            conn.setRequestMethod("GET");
            if(conn.getResponseCode()==200){
                BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
                String inputLine;
                while ((inputLine = in.readLine()) != null) {
                    response.append(inputLine);
                }
                in.close();
                JSONObject responseJSON = new JSONObject(response.toString());
                JSONArray metaDataArray = responseJSON.getJSONObject("_embedded").getJSONArray("metaData");
                return metaDataArray.toString();
            } else {
                String responseError = "error:" + conn.getResponseCode();
                return responseError;
            }
        } catch (MalformedURLException e) {
        	String stackTrace = org.apache.commons.lang.exception.ExceptionUtils.getStackTrace(e);
        	logger.error(loggerPrefix + "Exception occurred: " + stackTrace);
        } catch (IOException e) {
        	String stackTrace = org.apache.commons.lang.exception.ExceptionUtils.getStackTrace(e);
        	logger.error(loggerPrefix + "Exception occurred: " + stackTrace);
        }
        finally {
            if(conn!=null) {
                conn.disconnect();
            }
        }
        return "error";
    }
    private String getVerifyBiographicMetadata(String metadata) {
        String biographicMetaData = "";
        JSONArray metaDataArray = new JSONArray(metadata);
        for(int i=0; i<metaDataArray.length(); i++) {
            String entry = "";
            entry = metaDataArray.get(i).toString();
            JSONObject entryJSON = new JSONObject(entry);
            if(Objects.equals(entryJSON.get("type"),"BIOGRAPHIC_MATCH")) {
                biographicMetaData = entryJSON.getJSONObject("data").toString();
                i = metaDataArray.length();
            }
        }
        return biographicMetaData;
    }

    private String createTransactionCallBody (String policyId, String telephoneNumber, String emailAddress, JSONObject fuzzyMatchingAttributes, NodeState ns) throws IdRepoException, SSOException {
        String body ="{\"verifyPolicy\": {\"id\":\"" + policyId + "\"}";
        if(telephoneNumber!="" && telephoneNumber!=null) {
            body = body + ",\"sendNotification\": {\"phone\": \"" + telephoneNumber + "\"}";
        }
        else if(emailAddress!="" && emailAddress!=null) {
            body = body + ",\"sendNotification\": {\"email\": \"" + emailAddress + "\"}";
        }

        /* requirements go here */
        body = body + ",\"requirements\": {";

        if(Objects.equals(getFlowType(config.flowType()),"AUTHENTICATION") && config.pictureAttribute()!=null) {
            String selfie = getSelfie(ns);
            if(!Objects.equals(selfie,"")) {
                body = body + "\"referenceSelfie\": { \"value\": \"" + selfie +"\"}";
            }
        }

        if(fuzzyMatchingAttributes !=null && !Objects.equals(getFlowType(config.flowType()), "AUTHENTICATION")){
            /* fuzzy matching only happens on REGISTRATION and VERIFICATION */
            JSONArray keys = fuzzyMatchingAttributes.names();
            for (int i = 0; i < keys.length (); i++) {
                String key = keys.getString (i);
                String value = fuzzyMatchingAttributes.getString (key);
                if(i>0) {
                    body = body + ",";
                }
                body = body + "\"" + key + "\":{ \"value\":\"" + value + "\"}";
            }
        }
        body = body + "}";



        body = body + "}";
        return body;
    }

    public static class PingOneVerifyOutcomeProvider implements OutcomeProvider {
        @Override
        public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {
            ResourceBundle bundle = locales.getBundleInPreferredLocale(PingOneVerify.BUNDLE,
                    OutcomeProvider.class.getClassLoader());
            List<Outcome> results = new ArrayList<>();
            results.add(new Outcome(SUCCESS,  bundle.getString("successOutcome")));
            results.add(new Outcome(FAIL, bundle.getString("failOutcome")));

            /* Add ID NO MATCH outcome to VERIFICATION flow */
            if (Objects.equals(nodeAttributes.get("flowType").toString(),"\"VERIFICATION\"")) {
                results.add(new Outcome(IDNOMATCH, bundle.getString("idnomatch")));
            }

            /* Add AGE FAIL outcome to REGISTRATION flow (only) if using age verification*/
            if (!Objects.equals(nodeAttributes.get("dobVerification").toString(),"0") && Objects.equals(nodeAttributes.get("flowType").toString(),"\"REGISTRATION\"")) {
                results.add(new Outcome(AGEFAILED, bundle.getString("ageFail")));
            }

            results.add(new Outcome(ERROR, bundle.getString("errorOutcome")));
            return Collections.unmodifiableList(results);
        }
    }
}
