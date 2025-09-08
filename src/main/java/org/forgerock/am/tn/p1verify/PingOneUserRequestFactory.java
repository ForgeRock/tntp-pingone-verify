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
     * Build the PingOne user creation request using attributes from the shared state (values passed through the journey).
     */
    public static BuildResult fromSharedState(
            NodeState nodeState,
            boolean anonymizedUser,
            String populationId,
            String sharedStateUsername,
            UserHelper userHelper) throws IdRepoException, SSOException, JsonProcessingException
    {

        logger.error("+++++++++++ Inside fromSharedState method +++++++++++");

        // Only populate minimal/anonymized fields
        if (anonymizedUser) {

            logger.error("fromSharedState - anonymizedUser");

            String preferredLanguage = nodeState.get(AM_PREFERRED_LANGUAGE).asString();
            JsonValue requestBody = userHelper.getAnonymizedRequestBody(
                    populationId,
                    sharedStateUsername,
                    preferredLanguage
            );
            return new BuildResult(requestBody);
        } else {

            logger.error("fromSharedState - Full user details");

            // Populate full user details from shared state
            String email = nodeState.get(AM_EMAIL).asString();
            String phone = nodeState.get(AM_PHONE).asString();
            String givenName = nodeState.get(AM_GIVEN_NAME).asString();
            String familyName = nodeState.get(AM_FAMILY_NAME).asString();
            String commonName = nodeState.get(AM_COMMON_NAME).asString();
            String street = nodeState.get(AM_STREET).asString();
            String city = nodeState.get(AM_CITY).asString();
            String state = nodeState.get(AM_STATE).asString();
            String postalCode = nodeState.get(AM_POSTAL_CODE).asString();
            String country = nodeState.get(AM_COUNTRY).asString();
            String preferredLanguage = nodeState.get(AM_PREFERRED_LANGUAGE).asString();

            JsonValue requestBody = userHelper.getFullRequestBody(
                    populationId,
                    sharedStateUsername,
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

            logger.error("Shared State request body: {}", requestBody);

            return new BuildResult(requestBody);
        }
    }

    /**
     * Build the PingOne user creation request using attributes looked up from an AM identity object (profile stored in AM).
     */
    public static BuildResult fromAmIdentity(
            AMIdentity amIdentity,
            boolean anonymizedUser,
            String populationId,
            String amIdentityUsername,
            UserHelper userHelper) throws IdRepoException, SSOException, JsonProcessingException
    {

        logger.error("+++++++++++ Inside fromAmIdentity method +++++++++++");

        // Only populate minimal/anonymized fields
        if (anonymizedUser) {

            logger.error("fromAmIdentity - anonymizedUser");

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

//            logger.error("[AM RAW] email             = {}", email);       // YES
//            logger.error("[AM RAW] phone             = {}", phone);       // YES
//            logger.error("[AM RAW] givenName         = {}", givenName);   // YES
//            logger.error("[AM RAW] familyName        = {}", familyName);  // YES
//            logger.error("[AM RAW] commonName        = {}", commonName);  // YES
//            logger.error("[AM RAW] preferredLocale   = {}", userHelper.getUserAttribute(amIdentity, "preferredLocale"));  // NO
//            logger.error("[AM RAW] city (l)          = {}", city);                                                        // NO
//            logger.error("[AM RAW] city              = {}", userHelper.getUserAttribute(amIdentity, "city"));             // NO
//            logger.error("[AM RAW] state             = {}", state);                                                       // NO
//            logger.error("[AM RAW] stateProvince     = {}", userHelper.getUserAttribute(amIdentity, "stateProvince"));    // NO
//            logger.error("[AM RAW] zip               = {}", userHelper.getUserAttribute(amIdentity, "zip"));              // NO
//            logger.error("[AM RAW] country (co)      = {}", country);                                                     // NO
//            logger.error("[AM RAW] country           = {}", userHelper.getUserAttribute(amIdentity, "country"));          // NO
//            logger.error("[AM RAW] preferredLanguage = {}", preferredLanguage);                                           // NO

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
