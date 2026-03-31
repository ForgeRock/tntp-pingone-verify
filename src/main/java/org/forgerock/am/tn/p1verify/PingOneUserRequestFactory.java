package org.forgerock.am.tn.p1verify;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.iplanet.sso.SSOException;
import com.sun.identity.idm.AMIdentity;

import com.sun.identity.idm.IdRepoException;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.NodeState;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.forgerock.am.tn.p1verify.UserHelper.*;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;

/**
 * Utility for constructing PingOne user creation request bodies.
 */
public final class PingOneUserRequestFactory {

    private static final Logger logger = LoggerFactory.getLogger(PingOneUserRequestFactory.class);

    private PingOneUserRequestFactory() {}

    /** Holds the built request body and chosen PingOne username. */
    public static final class BuildResult {
        private final JsonValue requestBody;

        public BuildResult(JsonValue requestBody) {
            this.requestBody = requestBody;
        }

        public JsonValue requestBody() { return requestBody; }
    }

    /**
     * Build the PingOne user creation request using attributes from the shared state objectAttributes object
     */
    public static BuildResult fromObjectAttributes(
            JsonValue objectAttributes,
            boolean anonymizedPingOneUser,
            String populationId,
            UserHelper userHelper) throws IdRepoException, SSOException, JsonProcessingException
    {

        logger.error("+++++++++++ Inside fromObjectAttributes method +++++++++++");

        // Retrieve username
        String objectAttributesUsername = objectAttributes.get(USERNAME).asString();
        logger.error("Object Attributes Username: {}", objectAttributesUsername);

        // Only populate minimal/anonymized fields
        if (anonymizedPingOneUser) {
            logger.error("fromObjectAttributes - anonymizedPingOneUser");

            String preferredLanguage = objectAttributes.get(AM_PREFERRED_LANGUAGE).asString();
            JsonValue requestBody = userHelper.getAnonymizedRequestBody(
                    populationId,
                    objectAttributesUsername,
                    preferredLanguage
            );
            return new BuildResult(requestBody);
        } else {

            logger.error("fromObjectAttributes - Full user details");

            // Populate full user details from shared state
            String email = objectAttributes.get(AM_EMAIL).asString();
            String phone = objectAttributes.get(AM_PHONE).asString();
            String givenName = objectAttributes.get(AM_GIVEN_NAME).asString();
            String familyName = objectAttributes.get(AM_FAMILY_NAME).asString();
            String commonName = objectAttributes.get(AM_COMMON_NAME).asString();
            String street = objectAttributes.get(AM_STREET).asString();
            String city = objectAttributes.get(AM_CITY).asString();
            String state = objectAttributes.get(AM_STATE).asString();
            String postalCode = objectAttributes.get(AM_POSTAL_CODE).asString();
            String country = objectAttributes.get(AM_COUNTRY).asString();
            String preferredLanguage = objectAttributes.get(AM_PREFERRED_LANGUAGE).asString();

            JsonValue requestBody = userHelper.getFullRequestBody(
                    populationId,
                    objectAttributesUsername,
                    email,
                    phone,
                    givenName,
                    familyName,
                    commonName,
                    street,
                    city,
                    state,
                    postalCode,
                    country,
                    preferredLanguage
            );

            logger.error("fromObjectAttributes - Request Body: {}", requestBody);

            return new BuildResult(requestBody);
        }
    }

    /**
     * Build the PingOne user creation request using attributes looked up from an AM identity object (profile stored in AM).
     */
    public static BuildResult fromAmIdentity(
            AMIdentity amIdentity,
            boolean anonymizedPingOneUser,
            String populationId,
            String amIdentityUsername,
            UserHelper userHelper) throws IdRepoException, SSOException, JsonProcessingException
    {

        logger.error("+++++++++++ Inside fromAmIdentity method +++++++++++");

        // Only populate minimal/anonymized fields
        if (anonymizedPingOneUser) {

            logger.error("fromAmIdentity - anonymizedPingOneUser");

            String preferredLanguage = userHelper.getUserAttribute(amIdentity, AM_PREFERRED_LANGUAGE);
            JsonValue requestBody = userHelper.getAnonymizedRequestBody(
                    populationId,
                    amIdentityUsername,
                    preferredLanguage
            );
            return new BuildResult(requestBody);
        } else {

            logger.error("fromAmIdentity - full user details");

            // Populate full user details from AM identity profile
            String email = userHelper.getUserAttribute(amIdentity, AM_EMAIL);
            String phone = userHelper.getUserAttribute(amIdentity, AM_PHONE);
            String givenName = userHelper.getUserAttribute(amIdentity, AM_GIVEN_NAME);
            String familyName = userHelper.getUserAttribute(amIdentity, AM_FAMILY_NAME);
            String commonName = userHelper.getUserAttribute(amIdentity, AM_COMMON_NAME);
            String street = userHelper.getUserAttribute(amIdentity, AM_STREET); // postalAddress = AM user address
            String city = userHelper.getUserAttribute(amIdentity, AM_CITY);
            String state = userHelper.getUserAttribute(amIdentity, AM_STATE);
            String postalCode = userHelper.getUserAttribute(amIdentity, AM_POSTAL_CODE);
            String country = userHelper.getUserAttribute(amIdentity, AM_COUNTRY);
            String preferredLanguage = userHelper.getUserAttribute(amIdentity, AM_PREFERRED_LANGUAGE);

            // ++++++ ATTRIBUTE KEY NAME TEST ++++++
//            logger.error("[AM RAW] email             = {}", email);       // WORKS -> 'mail'
//            logger.error("[AM RAW] phone             = {}", phone);       // WORKS -> 'telephoneNumber'
//            logger.error("[AM RAW] givenName         = {}", givenName);   // WORKS -> 'givenName'
//            logger.error("[AM RAW] familyName        = {}", familyName);  // WORKS -> 'sn'
//            logger.error("[AM RAW] commonName        = {}", commonName);  // WORKS -> 'cn'
//            logger.error("[AM RAW] preferredLocale   = {}", userHelper.getUserAttribute(amIdentity, "preferredLocale"));  // NOT FOUND
//            logger.error("[AM RAW] city (l)          = {}", city);                                                        // NOT FOUND
//            logger.error("[AM RAW] city              = {}", userHelper.getUserAttribute(amIdentity, "city"));             // NOT FOUND
//            logger.error("[AM RAW] state             = {}", state);                                                       // NOT FOUND
//            logger.error("[AM RAW] stateProvince     = {}", userHelper.getUserAttribute(amIdentity, "stateProvince"));    // NOT FOUND
//            logger.error("[AM RAW] zip               = {}", userHelper.getUserAttribute(amIdentity, "zip"));              // NOT FOUND
//            logger.error("[AM RAW] country (co)      = {}", country);                                                     // NOT FOUND
//            logger.error("[AM RAW] country           = {}", userHelper.getUserAttribute(amIdentity, "country"));          // NOT FOUND
//            logger.error("[AM RAW] preferredLanguage = {}", preferredLanguage);                                           // NOT FOUND

            JsonValue requestBody = userHelper.getFullRequestBody(
                    populationId,
                    amIdentityUsername,
                    email,
                    phone,
                    givenName,
                    familyName,
                    commonName,
                    street,
                    city,
                    state,
                    postalCode,
                    country,
                    preferredLanguage
            );

            logger.error("AM Identity request body: {}", requestBody);

            return new BuildResult(requestBody);
        }
    }
}
