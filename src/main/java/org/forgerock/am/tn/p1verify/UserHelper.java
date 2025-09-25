
package org.forgerock.am.tn.p1verify;

import static org.forgerock.am.tn.p1verify.Constants.OBJECT_ATTRIBUTES;
import static org.forgerock.am.tn.p1verify.Constants.RESPONSE_EMBEDDED;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.REALM;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;

import java.util.Set;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.google.inject.Inject;
import com.iplanet.sso.SSOException;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdRepoException;
import org.forgerock.am.identity.application.IdentityNotFoundException;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.NodeState;
import org.forgerock.openam.core.CoreWrapper;
import org.forgerock.openam.utils.CollectionUtils;
import org.forgerock.openam.utils.JsonValueBuilder;
import org.forgerock.openam.utils.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class UserHelper {

    private static final Logger logger = LoggerFactory.getLogger(UserHelper.class);

    private static final String RESPONSE_COUNT = "count";
    private static final String RESPONSE_ID = "id";
    private static final String RESPONSE_USERS = "users";

    public static final String DEFAULT_AM_IDENTITY_ATTRIBUTE = "uid";
    public static final String DEFAULT_PING_IDENTITY_ATTRIBUTE = "username";
    public static final String AM_PHONE = "telephoneNumber";
    public static final String AM_EMAIL = "mail";
    public static final String AM_GIVEN_NAME = "givenName";
    public static final String AM_FAMILY_NAME = "sn";
    public static final String AM_COMMON_NAME = "cn";
    public static final String AM_POSTAL_CODE = "postalCode";
    public static final String AM_STREET = "postalAddress"; // "street";
    public static final String AM_COUNTRY = "co";
    public static final String AM_CITY = "l";
    public static final String AM_STATE = "st";
    public static final String AM_PREFERRED_LANGUAGE = "preferredLanguage";

    @Inject
    public UserHelper(CoreWrapper coreWrapper) {
        this.coreWrapper = coreWrapper;
    }

    /**
     * Retrieves the specified attribute value from the AMIdentity object.
     *
     * @param userIdentity The user's AM identity object.
     * @param attribute    The name of the attribute to retrieve.
     *
     * @return The first value of the attribute, or null if not present.
     */
    public String getUserAttribute(AMIdentity userIdentity, String attribute) throws IdRepoException, SSOException {

        // Get all values for the requested attribute
        Set<String> attributes = userIdentity.getAttribute(attribute);
        logger.error("getUserAttribute - Attributes Set: {}", attributes);

        // Return the first value if available
        if (CollectionUtils.isNotEmpty(attributes)) {
            logger.error("getUserAttribute - Returning First Attribute: {}", attributes.iterator().next());
            return attributes.iterator().next();
        } else {
            // Log and return null if attribute is missing or empty
            logger.debug("User attribute {} is empty", attribute);
            return null;
        }
    }

    @Inject
    CoreWrapper coreWrapper;

    /**
     * Retrieves the AMIdentity object for a user based on username and realm in the node state.
     *
     * @param nodeState The current node state.
     *
     * @return The user's AMIdentity object.
     */
    public AMIdentity getIdentity(NodeState nodeState) throws IdentityNotFoundException {

        // Extract username from node state; if username not found in shared state, fallback to objectAttributes
        String username = null;

        if (nodeState.isDefined(USERNAME)) {
            username = nodeState.get(USERNAME).asString();

        } else if (nodeState.isDefined(OBJECT_ATTRIBUTES)) {
            JsonValue attrs = nodeState.get(OBJECT_ATTRIBUTES);

            if (attrs != null && attrs.isDefined(USERNAME)) {
                username = attrs.get(USERNAME).asString();
                logger.debug("Resolved username from objectAttributes.USERNAME fallback");
            }
        }

        // Extract realm from node state; default realm to "/"
        String realm = nodeState.isDefined(REALM) ? nodeState.get(REALM).asString() : "/";

        // Throw if username is not present
        if (StringUtils.isBlank(username)) {
            throw new IdentityNotFoundException("Username not present (expected 'username' in shared state or objectAttributes).");
        }

        // Retrieve the user's AMIdentity using CoreWrapper
        AMIdentity identity = coreWrapper.getIdentityOrElseSearchUsingAuthNUserAlias(username, realm);

        if (identity == null) {
            throw new IdentityNotFoundException("Identity not found for username: " + username + " in realm: " + realm);
        }

        return identity;
    }

    /**
     * Builds a full user creation request body for PingOne, using attributes from the AMIdentity.
     *
     * @param populationId    The PingOne population ID.
     * @param pingOneUsername The unique user key (usually username or uid).
     *
     * @return A JsonValue representing the full user creation request body.
     */
    public JsonValue getFullRequestBody(String populationId, String pingOneUsername, String email, String phone, String givenName, String familyName, String commonName, String street, String city, String state, String postalCode, String country, String preferredLanguage) throws JsonProcessingException, IdRepoException, SSOException {

        // Initialize request body and set username
        UserRequestBody requestBody = new UserRequestBody();
        requestBody.setUsername(pingOneUsername);

        // Set population ID if provided
        if (StringUtils.isNotEmpty(populationId)) {
            requestBody.setPopulation(new UserRequestBody.Population(populationId));
        }

        // Set email if available
        if (StringUtils.isNotEmpty(email)) {
            requestBody.setEmail(email);
        }

        // Set primary phone number if available
        if (StringUtils.isNotEmpty(phone)) {
            requestBody.setPrimaryPhone(phone);
        }

        // Set name fields if any are present
        if (StringUtils.isNotEmpty(givenName) || StringUtils.isNotEmpty(familyName) || StringUtils.isNotEmpty(commonName)) {
            requestBody.setName(new UserRequestBody.Name(commonName, givenName, familyName));
        }

        // Set address fields if any are present
        if (StringUtils.isNotEmpty(street) || StringUtils.isNotEmpty(city) || StringUtils.isNotEmpty(state) || StringUtils.isNotEmpty(postalCode) || StringUtils.isNotEmpty(country)) {
            requestBody.setAddress(new UserRequestBody.Address(street, city, state, postalCode, country));
        }

        // Set preferred language if available
        if (StringUtils.isNotEmpty(preferredLanguage)) {
            requestBody.setPreferredLanguage(preferredLanguage);
        }

        // Convert the request body to JsonValue for transmission
        return JsonValueBuilder.toJsonValue(JsonValueBuilder.getObjectMapper().writeValueAsString(requestBody));
    }

    /**
     * Builds a minimal PingOne user creation request body with anonymized data.
     *
     * @param populationId      The PingOne population ID (optional).
     * @param pingOneUsername   The value to use as the PingOne username.
     * @param preferredLanguage The user's preferred language.
     *
     * @return A JsonValue representing the request body.
     */
    public JsonValue getAnonymizedRequestBody(String populationId, String pingOneUsername, String preferredLanguage) throws JsonProcessingException, IdRepoException, SSOException {

        // Create a new user request body and set the username
        UserRequestBody requestBody = new UserRequestBody();
        requestBody.setUsername(pingOneUsername);

        // If population ID is provided, set it in the request body
        if (StringUtils.isNotEmpty(populationId)) {
            requestBody.setPopulation(new UserRequestBody.Population(populationId));
        }

        // If preferred language is available, include it in the request
        if (StringUtils.isNotEmpty(preferredLanguage)) {
            requestBody.setPreferredLanguage(preferredLanguage);
        }

        // Convert the request body to a JSON string and wrap it in a JsonValue
        return JsonValueBuilder.toJsonValue(JsonValueBuilder.getObjectMapper().writeValueAsString(requestBody));
    }

    /**
     * Extracts the PingOne user ID from the API response.
     *
     * @param response The PingOne API response.
     *
     * @return The user ID as a string.
     */
    public String getUserIdFromResponse(JsonValue response) {
        if (response.isDefined(RESPONSE_EMBEDDED)) {
            return response.get(RESPONSE_EMBEDDED).get(RESPONSE_USERS).get(0).get(RESPONSE_ID).asString();
        } else {
            return response.get(RESPONSE_ID).asString();
        }
    }

    /**
     * Retrieves the number of users returned in the API response.
     *
     * @param response The PingOne API response.
     *
     * @return The user count, or 0 if the response is null.
     */
    public int userCount(JsonValue response) {
        if (response == null) {
            return 0;
        }
        return response.get(RESPONSE_COUNT).asInteger();
    }
}