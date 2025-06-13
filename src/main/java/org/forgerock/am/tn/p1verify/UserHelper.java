
package org.forgerock.am.tn.p1verify;

import static org.forgerock.am.tn.p1verify.Constants.RESPONSE_EMBEDDED;

import java.util.Optional;
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
    public static final String AM_USERNAME = "uid";
    public static final String AM_POSTAL_CODE = "postalCode";
    public static final String AM_COUNTRY = "co";
    public static final String AM_STREET = "street";
    public static final String AM_CITY = "l";
    public static final String AM_STATE = "st";
    public static final String AM_PREFERRED_LANGUAGE = "preferredLanguage";

    @Inject
    public UserHelper(CoreWrapper coreWrapper) {
        this.coreWrapper = coreWrapper;
    }

    public String getUserAttribute(AMIdentity userIdentity, String attribute) throws IdRepoException, SSOException {
        logger.error("++++++++++++++ Inside UserHelper / getUserAttribute ++++++++++++++");
        Set<String> attributes = userIdentity.getAttribute(attribute);
        if (CollectionUtils.isNotEmpty(attributes)) {
            return attributes.iterator().next();
        } else {
            logger.debug("User attribute {} is empty", attribute);
            return null;
        }
    }

    @Inject
    CoreWrapper coreWrapper;
    public AMIdentity getIdentity(NodeState nodeState) throws IdentityNotFoundException {
        logger.error("++++++++++++++ Inside UserHelper / getIdentity ++++++++++++++");
        String username = nodeState.isDefined("username") ? nodeState.get("username").asString() : null;
        String realm = nodeState.isDefined("realm") ? nodeState.get("realm").asString() : "/";

        logger.error("UserHelper / getIdentity - username: {}", username);
        logger.error("UserHelper / getIdentity - realm: {}", realm);

        if (StringUtils.isBlank(username)) {
            throw new IdentityNotFoundException("Username not present in node state.");
        }

        AMIdentity identity = coreWrapper.getIdentityOrElseSearchUsingAuthNUserAlias(username, realm);
        if (identity == null) {
            throw new IdentityNotFoundException("Identity not found for username: " + username + " in realm: " + realm);
        }

        logger.error("UserHelper / getIdentity - identity: {}", identity);

        return identity;
    }

    public JsonValue getFullRequestBody(AMIdentity amIdentity, String populationId, String amUserKey) throws JsonProcessingException, IdRepoException, SSOException {
        logger.error("++++++++++++++ Inside UserHelper / getFullRequestBody ++++++++++++++");
        logger.error("UserHelper / getIdentity - amIdentity: {}", amIdentity);
        logger.error("UserHelper / getIdentity - populationId: {}", populationId);
        logger.error("UserHelper / getIdentity - amUserKey: {}", amUserKey);

        UserRequestBody requestBody = new UserRequestBody();
        requestBody.setUsername(amUserKey);

        if (StringUtils.isNotEmpty(populationId)) {
            requestBody.setPopulation(new UserRequestBody.Population(populationId));
        }

        String email = getUserAttribute(amIdentity, AM_EMAIL);
        logger.error("UserHelper / getIdentity - email: {}", email);

        if (StringUtils.isNotEmpty(email)) {
            requestBody.setEmail(email);
        }

        String primaryPhone = getUserAttribute(amIdentity, AM_PHONE);
        logger.error("UserHelper / getIdentity - primaryPhone: {}", primaryPhone);

        if (StringUtils.isNotEmpty(primaryPhone)) {
            requestBody.setPrimaryPhone(primaryPhone);
        }

        String givenName = getUserAttribute(amIdentity, AM_GIVEN_NAME);
        String familyName = getUserAttribute(amIdentity, AM_FAMILY_NAME);
        String commonName = getUserAttribute(amIdentity, AM_COMMON_NAME);
        logger.error("UserHelper / getIdentity - givenName: {}", givenName);
        logger.error("UserHelper / getIdentity - familyName: {}", familyName);
        logger.error("UserHelper / getIdentity - commonName: {}", commonName);

        if (StringUtils.isNotEmpty(givenName) || StringUtils.isNotEmpty(familyName) || StringUtils.isNotEmpty(commonName)) {
            requestBody.setName(new UserRequestBody.Name(commonName, givenName, familyName));
        }

        String street = getUserAttribute(amIdentity, AM_STREET);
        String city = getUserAttribute(amIdentity, AM_CITY);
        String state = getUserAttribute(amIdentity, AM_STATE);
        String postalCode = getUserAttribute(amIdentity, AM_POSTAL_CODE);
        String country = getUserAttribute(amIdentity, AM_COUNTRY);
        logger.error("UserHelper / getIdentity - street: {}", street);
        logger.error("UserHelper / getIdentity - city: {}", city);
        logger.error("UserHelper / getIdentity - state: {}", state);
        logger.error("UserHelper / getIdentity - postalCode: {}", postalCode);
        logger.error("UserHelper / getIdentity - country: {}", country);

        if (StringUtils.isNotEmpty(street) || StringUtils.isNotEmpty(city) || StringUtils.isNotEmpty(state) || StringUtils.isNotEmpty(postalCode) || StringUtils.isNotEmpty(country)) {
            requestBody.setAddress(new UserRequestBody.Address(street, city, state, postalCode, country));
        }

        String preferredLanguage = getUserAttribute(amIdentity, AM_PREFERRED_LANGUAGE);
        logger.error("UserHelper / getIdentity - preferredLanguage: {}", preferredLanguage);

        if (StringUtils.isNotEmpty(preferredLanguage)) {
            requestBody.setPreferredLanguage(preferredLanguage);
        }
        return JsonValueBuilder.toJsonValue(JsonValueBuilder.getObjectMapper().writeValueAsString(requestBody));
    }

    public JsonValue getAnonymizedRequestBody(AMIdentity amIdentity, String populationId, String amUserKey) throws JsonProcessingException, IdRepoException, SSOException {
        logger.error("++++++++++++++ Inside UserHelper / getAnonymizedRequestBody ++++++++++++++");
        logger.error("UserHelper / getAnonymizedRequestBody - amIdentity: {}", amIdentity);
        logger.error("UserHelper / getAnonymizedRequestBody - populationId: {}", populationId);
        logger.error("UserHelper / getAnonymizedRequestBody - amUserKey: {}", amUserKey);

        UserRequestBody requestBody = new UserRequestBody();
        requestBody.setUsername(amUserKey);

        if (StringUtils.isNotEmpty(populationId)) {
            requestBody.setPopulation(new UserRequestBody.Population(populationId));
        }

        String preferredLanguage = getUserAttribute(amIdentity, AM_PREFERRED_LANGUAGE);
        logger.error("UserHelper / getAnonymizedRequestBody - preferredLanguage: {}", preferredLanguage);

        if (StringUtils.isNotEmpty(preferredLanguage)) {
            requestBody.setPreferredLanguage(preferredLanguage);
        }

        return JsonValueBuilder.toJsonValue(JsonValueBuilder.getObjectMapper().writeValueAsString(requestBody));
    }

    public String getUserIdFromResponse(JsonValue response) {
        logger.error("++++++++++++++ Inside UserHelper / getUserIdFromResponse ++++++++++++++");
        logger.error("UserHelper / getUserIdFromResponse - response: {}", response);
        if (response.isDefined(RESPONSE_EMBEDDED)) {
            return response.get(RESPONSE_EMBEDDED).get(RESPONSE_USERS).get(0).get(RESPONSE_ID).asString();
        } else {
            return response.get(RESPONSE_ID).asString();
        }
    }

    public int userCount(JsonValue response) {
        if (response == null) {
            return 0;
        }
        return response.get(RESPONSE_COUNT).asInteger();
    }
}