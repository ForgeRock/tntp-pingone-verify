/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2017-2022 ForgeRock AS.
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
import java.util.*;

import javax.inject.Inject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.ConfirmationCallback;
import javax.security.auth.callback.TextOutputCallback;

import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.*;
import org.forgerock.openam.authentication.callbacks.PollingWaitCallback;
import org.forgerock.openam.core.CoreWrapper;
import org.forgerock.openam.core.realms.Realm;
import org.forgerock.openam.sm.annotations.adapters.Password;
import org.forgerock.util.i18n.PreferredLocales;
import org.forgerock.openam.auth.node.api.OutcomeProvider;

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
    private final String loggerPrefix = "[Web3Auth Node]" + PingOneVerifyPlugin.logAppender;
    public static final String BUNDLE = PingOneVerify.class.getName();
    public enum VerifyRegion { EU, US, APAC, CANADA }
    public String getVerifyRegion(VerifyRegion verifyRegion) {
        if (verifyRegion == VerifyRegion.EU) { return "eu";}
        else if (verifyRegion == VerifyRegion.APAC) { return "asia";}
        else if (verifyRegion == VerifyRegion.CANADA) { return "ca";}
        else return "com";
    }
    public enum UserNotification { QR, SMS, EMAIL }
    public enum FlowType { REGISTRATION, VERIFICATION }
    public String getFlowType(FlowType flowType) {
        if (flowType == FlowType.REGISTRATION) {return "REGISTRATION";}
        else return "VERIFICATION";
    }
    public int getDeliveryMethod(UserNotification userNotification) {
        if (userNotification == UserNotification.EMAIL) {return 0;}
        else if (userNotification == UserNotification.SMS) {return 1;}
        else return 2;
    }
    public String txId;
    public String verificationCode;
    public String p1AccessToken;
    public String verificationUrl;
    public String verifiedClaims;
    public String verifyStatus;
    public JSONObject userAttributesDsJson = new JSONObject();
    private final CoreWrapper coreWrapper;
    private static final String FAIL = "FAIL";
	private static final String SUCCESS = "SUCCESS";
	private static final String ERROR = "ERROR";
    private static final String LOW_CONFIDENCE = "LOW_CONFIDENCE";
    private static final String MEDIUM_CONFIDENCE = "MEDIUM_CONFIDENCE";
    private static final String HIGH_CONFIDENCE = "HIGH_CONFIDENCE";



    /**
     * Configuration for the node.
     */
    public interface Config {
        /**
         * The header name for zero-page login that will contain the identity's username.
         */
        @Attribute(order = 100)
        default String envId() {
            return "";
        }
        @Attribute(order = 120)
        default String clientId() {
            return "";
        }
        @Attribute(order = 140)
        @Password
        char[] clientSecret();
        @Attribute(order = 160)
        default VerifyRegion verifyRegion() {
            return VerifyRegion.EU;
        }
        @Attribute(order = 180)
        default String verifyPolicyId() {
            return "";
        }
        @Attribute(order = 200)
        default String userId() {
            return "";
        }
        @Attribute(order = 220)
        default UserNotification userNotification() {
            return UserNotification.QR;
        }
        @Attribute(order = 240)
        default boolean userNotificationChoice() { return false; }
        @Attribute(order = 260)
        default FlowType flowType() {
            return FlowType.REGISTRATION;
        }
        @Attribute(order = 280)
        default boolean saveVerifiedClaims() { return true; }

        @Attribute(order = 300)
        default Map<String, String> attributeMappingConfiguration() {
            return new HashMap<String, String>() {{
                /*key is id_token key value is ldap attribute name,
                value is the claim name in PingOneVerify verified claims*/
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
        @Attribute(order = 320)
        List<String> attributesToMatch();
        @Attribute(order = 340)
        List<String> attributesToFuzzyMatch();
        @Attribute(order = 360)
        default String firstNameAttribute() {
            return "givenName";
        }

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
    }

    @Override
    public Action process(TreeContext context) {
        NodeState ns = context.getStateFor(this);
        try {
            logger.debug(loggerPrefix + "Started");

            if (!ns.isDefined("verifyStage")) {
                ns.putShared("verifyStage", 0);
                ns.putShared("counter", 0);
            }

            int a=2;
            if(a==1) {
                String syntheticData = "{\n" +
                        "    \"_links\": {\n" +
                        "        \"self\": {\n" +
                        "            \"href\": \"https://api.pingone.eu/v1/environments/5c603a56-c941-42a1-9fcd-2f63213e999e/users/8c38b5d4-028d-44dc-8502-6bf40fd86bc3/verifyTransactions/e6f63006-84f8-4556-857c-c3798c1a335c/verifiedData\"\n" +
                        "        },\n" +
                        "        \"user\": {\n" +
                        "            \"href\": \"https://api.pingone.eu/v1/environments/5c603a56-c941-42a1-9fcd-2f63213e999e/users/8c38b5d4-028d-44dc-8502-6bf40fd86bc3\"\n" +
                        "        },\n" +
                        "        \"environment\": {\n" +
                        "            \"href\": \"https://api.pingone.eu/v1/environments/5c603a56-c941-42a1-9fcd-2f63213e999e\"\n" +
                        "        },\n" +
                        "        \"verifyTransaction\": {\n" +
                        "            \"href\": \"https://api.pingone.eu/v1/environments/5c603a56-c941-42a1-9fcd-2f63213e999e/users/8c38b5d4-028d-44dc-8502-6bf40fd86bc3/verifyTransactions/e6f63006-84f8-4556-857c-c3798c1a335c\"\n" +
                        "        }\n" +
                        "    },\n" +
                        "    \"_embedded\": {\n" +
                        "        \"verifiedData\": [\n" +
                        "            {\n" +
                        "                \"_links\": {\n" +
                        "                    \"self\": {\n" +
                        "                        \"href\": \"https://api.pingone.eu/v1/environments/5c603a56-c941-42a1-9fcd-2f63213e999e/users/8c38b5d4-028d-44dc-8502-6bf40fd86bc3/verifyTransactions/e6f63006-84f8-4556-857c-c3798c1a335c/verifiedData/3b7fab64-1fb5-4197-b9d6-65ebd69e33c9\"\n" +
                        "                    }\n" +
                        "                },\n" +
                        "                \"id\": \"3b7fab64-1fb5-4197-b9d6-65ebd69e33c9\",\n" +
                        "                \"type\": \"GOVERNMENT_ID\",\n" +
                        "                \"data\": {\n" +
                        "                    \"address\": \"70 WEBB STREET, NEWSTEAD VILLAGE, NOTTINGHAM, NG15 0BH\",\n" +
                        "                    \"birthDate\": \"1978-04-03\",\n" +
                        "                    \"country\": \"GBR\",\n" +
                        "                    \"expirationDate\": \"2029-12-19\",\n" +
                        "                    \"firstName\": \"MR MARCIN JERZY\",\n" +
                        "                    \"fullName\": \"MR MARCIN JERZY ZIMNY\",\n" +
                        "                    \"idNumber\": \"ZIMNY704038MJ9YD12\",\n" +
                        "                    \"idType\": \"[DriversLicenseFront, DriversLicenseBack]\",\n" +
                        "                    \"issueDate\": \"2019-12-20\",\n" +
                        "                    \"lastName\": \"ZIMNY\"\n" +
                        "                },\n" +
                        "                \"createdAt\": \"2023-11-29T20:47:55.855Z\"\n" +
                        "            }\n" +
                        "        ]\n" +
                        "    },\n" +
                        "    \"size\": 1\n" +
                        "}";
                JSONObject myJSON = new JSONObject(syntheticData);
                String myString = myJSON.getJSONObject("_embedded").getJSONArray("verifiedData").get(0).toString();
                myJSON = new JSONObject(myString);
                myString = myJSON.getJSONObject("data").toString();
                ns.putShared("debug-myString",myString);

                //String realm = context.sharedState.get(SharedStateConstants.REALM).asString();
                //getUserAttributesFromDS(ns);
                //JSONObject myJsonObj = createFuzzyMatchingAttributeMapObject();
                //String verifyTxBody = createTransactionCallBody(config.verifyPolicyId(), "+447990560059", "", createFuzzyMatchingAttributeMapObject());
                //ns.putShared("debug-verifyTxBody", verifyTxBody);
                /*
                ns.putShared("username","marcin");
                String vcs = "{\"lastName\": \"ZIMNY\",\"firstName\": \"MR MARCIN\",\"country\": \"PL\"}";
                boolean res = validateVerifiedClaims(ns, vcs);
                ns.putShared("result_bool",res);*/
                return Action.goTo(ERROR).build();
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
                /*config determines delivery method*/
                ns.putShared("PingOneVerifySelection", getDeliveryMethod(config.userNotification()));
                ns.putShared("verifyStage", 2);
            }
            if (ns.get("verifyStage").asInteger() == 2) {
                /*starting the verification procedure*/
                String telephoneNumber = null;
                String emailAddress = null;
                String clientSecret = new String(config.clientSecret());
                p1AccessToken = getAccessToken(getTokenEndpointUrl(), config.clientId(), clientSecret);
                if (Objects.equals(p1AccessToken.substring(0, 4),"error")) {
                    logger.debug(loggerPrefix + "Failed to obtain PingOne service access token");
                    ns.putShared("PingOneVerifyTokenError", "Failed to obtain access token for PingOne Verify");
                    ns.putShared("PingOneVerifyTokenErrorDebugResponseCode", p1AccessToken);
                    return Action.goTo(ERROR).build();
                } else {
                    ns.putShared("PingOneAccessToken",p1AccessToken);
                }

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
                    //qr
                    ns.putShared("verifyStage", 4);
                }
                if(Objects.equals(getFlowType(config.flowType()), "VERIFICATION")) {
                    /* pull all required attributes from DS */
                    getUserAttributesFromDS(ns);
                }
                /* create PingOne Verify transaction */
                String verifyTxBody = createTransactionCallBody(config.verifyPolicyId(), telephoneNumber, emailAddress, createFuzzyMatchingAttributeMapObject());
                String verifyTxResponse = createVerifyTransaction(p1AccessToken, getVerifyEndpointUrl(), verifyTxBody);
                if (Objects.equals(verifyTxResponse.substring(0,4), "error")) {
                    ns.putShared("PingOneTransactionError", verifyTxResponse);
                    return Action.goTo(ERROR).build();
                }
                JSONObject obj = new JSONObject(verifyTxResponse);
                //txId = "0e3eb07c-d418-490a-8c36-e04b6fd39a15";
                //verificationCode  = "122345";
                txId = obj.getString("id");
                ns.putShared("PingOneVerifyTxId",txId);
                verificationCode = obj.getString("webVerificationCode");
                ns.putShared("PingOneVerificationCode",verificationCode);
                /* this could be derived from API response (webVerificationUrl) */
                verificationUrl = "https://apps.pingone.eu/" + config.envId() + "/verify/verify-webapp/v2/index.html?txnid=" +
                        txId + "&url=https://api.pingone.eu/v1/idValidations/webVerifications&code=" + verificationCode +
                        "&envId=" + config.envId();
            }
            if (ns.get("verifyStage").asInteger() == 3) {
                /*sms and email*/
                String accessToken = ns.get("PingOneAccessToken").asString();
                String verifyTxId = ns.get("PingOneVerifyTxId").asString();

                int count = ns.get("counter").asInteger();
                ns.putShared("counter", ++count);
                String message = "Interval: " + count;
                int verifyResult = 2;
                if(count>3) {
                    /*wait for 15 seconds before we start checking for result*/
                    String sResult = getVerifyResult(accessToken, getVerifyEndpointUrl(),verifyTxId);
                    if (!Objects.equals(sResult.substring(0,4), "error")) {
                        verifyResult = checkVerifyResult(sResult);
                    }
                }

                if (count < 45 && verifyResult==2) {
                    verificationCode = ns.get("PingOneVerificationCode").asString();
                    TextOutputCallback textOutputCallback = new TextOutputCallback(TextOutputCallback.INFORMATION, "Please continue verification on your mobile device. Your verification code is: " + verificationCode);
                    PollingWaitCallback waitCallback =
                            new PollingWaitCallback("5000", message);
                    Callback[] callbacks = new Callback[]{textOutputCallback, waitCallback};
                    return send(callbacks).build();
                } else {
                    if(verifyResult==1) {
                        /* PingOne Verify returned SUCCESS */
                        /* We need to fetch the verifiedData claims */
                        verifiedClaims = getVerifiedData(accessToken, getVerifyEndpointUrl(),verifyTxId);
                        if(Objects.equals(verifiedClaims.substring(0,4),"error")) {
                            /* failed to fetch the verifiedData from PingOne Verify */
                            ns.putShared("PingOneVerifyFailedToGetVerifiedData","true");
                            return Action.goTo(FAIL).build();
                        }
                        if(onResultSuccess(ns)){
                            ns.putShared("PingOneAccessToken","");
                            ns.putShared("counter",0);
                            return Action.goTo(SUCCESS).build();
                        }
                        else {
                            ns.putShared("PingOneAccessToken","");
                            ns.putShared("counter",0);
                            return Action.goTo(FAIL).build();
                        }
                    }
                    else {
                        /* Time out */
                        ns.putShared("PingOneAccessToken","");
                        ns.putShared("PingOneVerifyClaims",verifiedClaims);
                        ns.putShared("PingOneVerifyStatus",verifyStatus);
                        return Action.goTo(FAIL).build();
                    }
                }
            }
            if (ns.get("verifyStage").asInteger() == 4) {
                /*qr code*/
                String accessToken = ns.get("PingOneAccessToken").asString();
                String verifyTxId = ns.get("PingOneVerifyTxId").asString();

                int count = ns.get("counter").asInteger();
                ns.putShared("counter", ++count);
                String message = "Interval: " + count;
                int verifyResult = 2;

                if(count>3) {
                    /*wait for 15 seconds before we start checking for result*/
                    //String verifyTxId = "bc706a80-df9e-4fa9-8ce1-8e567f8fc22e";
                    String sResult = getVerifyResult(accessToken, getVerifyEndpointUrl(),verifyTxId );
                    if (!Objects.equals(sResult.substring(0,4), "error")) {
                        verifyResult = checkVerifyResult(sResult);
                    }
                }
                if (count < 45 && verifyResult==2) {
                    /* waiting for verification success/fail for 5 mins (just under) */
                    verificationCode = ns.get("PingOneVerificationCode").asString();
                    String clientSideScriptExecutorFunction = createQrCodeScript(verificationUrl);
                    TextOutputCallback textOutputCallback = new TextOutputCallback(TextOutputCallback.INFORMATION, "Please scan the QR code to continue verification process. Your verification code is: " + verificationCode + ", txId:" + txId);
                    PollingWaitCallback waitCallback =
                            new PollingWaitCallback("5000", message);
                    ScriptTextOutputCallback scriptAndSelfSubmitCallback =
                            new ScriptTextOutputCallback(clientSideScriptExecutorFunction);
                    Callback[] callbacks = new Callback[]{textOutputCallback, waitCallback, scriptAndSelfSubmitCallback};
                    return send(callbacks).build();
                } else {
                    if(verifyResult==1) {
                        /* PingOne Verify returned SUCCESS */
                        /* We need to fetch the verifiedData claims */
                        verifiedClaims = getVerifiedData(accessToken, getVerifyEndpointUrl(),verifyTxId);
                        if(Objects.equals(verifiedClaims.substring(0,4),"error")) {
                            /* failed to fetch the verifiedData from PingOne Verify */
                            ns.putShared("PingOneVerifyFailedToGetVerifiedData","true");
                            return Action.goTo(FAIL).build();
                        }
                        if(onResultSuccess(ns)){
                            ns.putShared("PingOneAccessToken","");
                            ns.putShared("counter",0);
                            return Action.goTo(SUCCESS).build();
                        }
                        else {
                            ns.putShared("PingOneAccessToken","");
                            ns.putShared("counter",0);
                            return Action.goTo(FAIL).build();
                        }
                    }
                    else {
                        /* Time out */
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
    public boolean onResultSuccess(NodeState ns) throws IdRepoException, SSOException {
        if(config.saveVerifiedClaims()) {
            /* save verified claims to SharedState (config) */
            ns.putShared("PingOneVerifyClaims",verifiedClaims);
        }
        if(Objects.equals(getFlowType(config.flowType()), "VERIFICATION")) {
            /* checking if the objectAttributes match the verified claims*/
            /* check successful*/
            /* checks failed*/
            return validateVerifiedClaims(ns, verifiedClaims);
        } else {
            /* for REGISTRATION no checks are needed
            but we are mapping claims to objectAttributes */
            verifiedClaimsToSharedState(ns,verifiedClaims);
            return true;
        }
    }
    public String dsAttributeToVerifiedClaim (String dsAttribute) {
        JSONObject attributeMap = new JSONObject(config.attributeMappingConfiguration());
        return attributeMap.get(dsAttribute).toString();
    }
    public JSONObject createFuzzyMatchingAttributeMapObject () {
        JSONObject attributeMapping = new JSONObject();
        if(config.attributesToFuzzyMatch().isEmpty()) {
            attributeMapping = null;
            return attributeMapping;
        }
        List<String> fuzzyMatchAttributes = config.attributesToFuzzyMatch();
        JSONObject attributeMap = new JSONObject(config.attributeMappingConfiguration());

        for(int i=0; i<fuzzyMatchAttributes.size(); i++) {
            String attrNameDS = "";
            String attrNameVC = "";
            String attrValue = "";
            attrNameDS = fuzzyMatchAttributes.get(i);
            if(attributeMap.has(attrNameDS)) {
                attrNameVC = attributeMap.getString(attrNameDS);
                if(userAttributesDsJson.has(attrNameDS)) {
                    attrValue = userAttributesDsJson.getString(attrNameDS);
                }
            }
            if(!Objects.equals(attrNameVC,"") && !Objects.equals(attrValue,"")) {
                attributeMapping.put(attrNameVC,attrValue);
            }
        }
        return attributeMapping;
    }
    public void getUserAttributesFromDS (NodeState ns) throws IdRepoException, SSOException {
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
        //JSONObject userAttributesDsJson = new JSONObject();
        /* attributes are returned as array, need to transform */
        for (int i = 0; i < requiredAttributes.size(); i++) {
            String value = dsMapTempJson.get(requiredAttributes.get(i)).toString();
            value = value.replaceAll("[\\[\\]\\\"]", "");
            userAttributesDsJson.put(requiredAttributes.get(i),value);
        }
    }
    public boolean validateVerifiedClaims(NodeState ns, String claims) throws IdRepoException, SSOException {
        /* verification procedure here */
        List<String> requiredAttributes = config.attributesToMatch();
        List<String> fuzzyMatchAttributes = config.attributesToFuzzyMatch();

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
                boolean fuzzyMatch = false;
                for (int y = 0; y < fuzzyMatchAttributes.size(); y++) {
                    if(Objects.equals(fuzzyMatchAttributes.get(y),requiredAttributes.get(i))) {
                        /* this attribute is on a fuzzy match list */
                        fuzzyMatch = true;
                        y = fuzzyMatchAttributes.size();
                    }
                }
                if(fuzzyMatch) {
                    /* ignoring the comparison, as it comes from PingOne Verify */
                    matchedAttributes++;
                }
            }
        }
        return requiredAttributes.size() == matchedAttributes;
    }
    public boolean verifiedClaimsToSharedState(NodeState ns, String verifiedClaims) {
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
                objectAttributes.put(key, dataJson.get(value));
            }
        }
        ns.putShared("objectAttributes",objectAttributes);
        return true;
    }

    public static String createQrCodeScript(String url) {
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

    public String getTokenEndpointUrl() {
        return  "https://auth.pingone." + getVerifyRegion(config.verifyRegion()) + "/" + config.envId() + "/as/token/";
    }

    public String getVerifyEndpointUrl() {
        return  "https://api.pingone." + getVerifyRegion(config.verifyRegion()) + "/v1/environments/" + config.envId() + "/users/" + config.userId() + "/verifyTransactions";
    }

    public static String createVerifyTransaction(String accessToken, String endpoint, String body) {
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
            if(conn.getResponseCode()==201){
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

    public int checkVerifyResult(String verifyResponse) {
        try {
            JSONObject obj = new JSONObject(verifyResponse);
            String result = "";
            result = obj.getJSONObject("transactionStatus").getString("status");
            if (Objects.equals(result, "SUCCESS")) {
                /*
                if(obj.has("verifiedUserData")) {
                    verifiedClaims = obj.getJSONObject("verifiedUserData").toString();
                }*/
                return 1; /*success*/
            } else if (Objects.equals(result, "FAIL")) {
                /*if(obj.has("verifiedUserData")) {
                    verifiedClaims = obj.getJSONObject("verifiedUserData").toString();
                    verifyStatus = obj.getJSONObject("transactionStatus").getJSONObject("verificationStatus").toString();
                }*/
                verifyStatus = obj.getJSONObject("transactionStatus").getJSONObject("verificationStatus").toString();
                return 0; /*failed*/
            }
            else {
                return 2; /*pending*/
            }
        } catch (Exception ex) {
            return 2; /*pending*/
        }
    }
    public static String getVerifiedData(String accessToken, String endpoint, String vTxId) {
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
    public static String getVerifyResult(String accessToken, String endpoint, String vTxId) {
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
    public static String createTransactionCallBody (String policyId, String telephoneNumber, String emailAddress, JSONObject fuzzyMatchingAttributes) {
        String body ="{\"verifyPolicy\": {\"id\":\"" + policyId + "\"}";
        if(telephoneNumber!="" && telephoneNumber!=null) {
            body = body + ",\"sendNotification\": {\"phone\": \"" + telephoneNumber + "\"}";
        }
        else if(emailAddress!="" && emailAddress!=null) {
            body = body + ",\"sendNotification\": {\"email\": \"" + emailAddress + "\"}";
        }

        if(fuzzyMatchingAttributes !=null){
            body = body + ",\"requirements\": {";
            JSONArray keys = fuzzyMatchingAttributes.names();
            for (int i = 0; i < keys.length (); i++) {
                String key = keys.getString (i);
                String value = fuzzyMatchingAttributes.getString (key);
                if(i>0) {
                    body = body + ",";
                }
                body = body + "\"" + key + "\":{ \"value\":\"" + value + "\"}";
            }
            body = body + "}";
        }

        body = body + "}";
        return body;
    }
    public static String getAccessToken(String endpoint, String client_id, String client_secret) {
        HttpURLConnection conn = null;
        try {
            URL url = new URL(endpoint);
            conn = (HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(4000);
            conn.setDoOutput(true);
            conn.setDoInput(true);
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            conn.setRequestMethod("POST");
            String body = "grant_type=client_credentials&client_id=" + client_id +
                    "&client_secret=" + client_secret + "&scope=default";
            OutputStream os = conn.getOutputStream();
            os.write(body.getBytes(StandardCharsets.UTF_8));
            os.close();

            if(conn.getResponseCode()==200) {
                BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
                String inputLine;
                StringBuffer response = new StringBuffer();
                while ((inputLine = in.readLine()) != null) {
                    response.append(inputLine);
                }
                in.close();
                JSONObject obj = new JSONObject(response.toString());
                String accessToken = obj.getString("access_token");
                return accessToken;
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
    public static class PingOneVerifyOutcomeProvider implements OutcomeProvider {
        @Override
        public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {

            ResourceBundle bundle = locales.getBundleInPreferredLocale(PingOneVerify.BUNDLE,
                    OutcomeProvider.class.getClassLoader());

            List<Outcome> results = new ArrayList<>();
            if(nodeAttributes.get("attributesToFuzzyMatch").required().asList(String.class).isEmpty()) {
                results.add(new Outcome(SUCCESS,  bundle.getString("successOutcome")));
            }
            else {
                results.add(new Outcome(HIGH_CONFIDENCE,  bundle.getString("confidenceHighOutcome")));
                results.add(new Outcome(MEDIUM_CONFIDENCE,  bundle.getString("confidenceMediumOutcome")));
                results.add(new Outcome(LOW_CONFIDENCE,  bundle.getString("confidenceLowOutcome")));
            }
            results.add(new Outcome(FAIL, bundle.getString("failOutcome")));
            results.add(new Outcome(ERROR, bundle.getString("errorOutcome")));

            return Collections.unmodifiableList(results);
        }
    }
}
