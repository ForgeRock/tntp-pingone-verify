package org.forgerock.am.tn.p1verify;

import com.google.inject.Inject;
import com.google.inject.assistedinject.Assisted;
import com.sun.identity.idm.AMIdentity;
import org.forgerock.am.identity.application.IdentityNotFoundException;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.*;
import org.forgerock.openam.auth.service.marketplace.TNTPPingOneConfig;
import org.forgerock.openam.auth.service.marketplace.TNTPPingOneConfigChoiceValues;
import org.forgerock.openam.auth.service.marketplace.TNTPPingOneUtility;
import org.forgerock.openam.core.realms.Realm;
import org.forgerock.openam.utils.StringUtils;
import org.forgerock.util.annotations.VisibleForTesting;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static java.util.Collections.singletonMap;
import static org.forgerock.am.tn.p1verify.FailureReason.getFailureJson;
import static org.forgerock.am.tn.p1verify.PingOneConstants.PINGONE_CREATE_USER_FAILURE_REASON_KEY;
import static org.forgerock.am.tn.p1verify.PingOneConstants.PINGONE_USER_ID_KEY;
import static org.forgerock.am.tn.p1verify.UserHelper.*;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;

/**
 * A node that creates a user in PingOne and stores the PingOne User ID on the shared state. It can also
 * store the PingOne User ID on the user's profile.
 */
@Node.Metadata(outcomeProvider = AbstractDecisionNode.OutcomeProvider.class,
        configClass = PingOneCreateUserNode.Config.class,
        tags = {"marketplace", "trustnetwork"})
public class PingOneCreateUserNode extends AbstractDecisionNode {

    private final Logger logger = LoggerFactory.getLogger(PingOneCreateUserNode.class);

    private final Config config;
    private final Realm realm;
    private final UserHelper userHelper;
    private final Helper client;
    private final TNTPPingOneConfig tntpPingOneConfig;

    public interface Config {

        /**
         * Reference to the PingOne Worker App.
         *
         * @return The PingOne Worker App.
         */
        @Attribute(order = 100, choiceValuesClass = TNTPPingOneConfigChoiceValues.class)
        default String tntpPingOneConfigName() {
            return TNTPPingOneConfigChoiceValues.createTNTPPingOneConfigName("Global Default");
        }

        /**
         * The PingOne population ID to assign the user to when creating a new PingOne user.
         * If not specified, the environment's default population is used.
         *
         * @return the PingOne population ID.
         */
        @Attribute(order = 200)
        default String populationId() {
            return "";
        }

        /**
         * Whether the created PingOne user should be anonymized.
         * An anonymized user only stores minimal identifying information (username and language).
         *
         * @return true if the created user should be anonymized, false otherwise.
         */
        @Attribute(order = 300)
        default boolean anonymizedUser() {
            return true;
        }

        /**
         * Whether to build the PingOne user from shared state attributes instead of
         * retrieving attributes from an AM identity profile.
         * Only applies when {@code createPingOneUser} is enabled.
         *
         * @return true if attributes come from shared state, false otherwise.
         */
        @Attribute(order = 400)
        default boolean userAttributesFromSharedState() {
            return true;
        }

        /**
         * The AM identity attribute used as the key when looking up an existing AM identity
         * (for example: uid, mail, or another attribute).
         * Only applies when {@code userAttributesFromSharedState} is false.
         *
         * @return the AM identity attribute to use as the lookup key.
         */
        @Attribute(order = 500)
        default String amIdentityAttribute() {
            return DEFAULT_AM_IDENTITY_ATTRIBUTE;
        }

        /**
         * If the node fail, the error detail will be provided in the shared state for analysis by later nodes.
         *
         * @return true if the failure will be captured.
         */
        @Attribute(order = 600)
        default boolean captureFailure() {
            return false;
        }
    }

    @Inject
    public PingOneCreateUserNode(@Assisted Config config,
                                 @Assisted Realm realm,
                                 UserHelper userHelper,
                                 Helper client) {
        this.config = config;
        this.realm = realm;
        this.userHelper = userHelper;
        this.client = client;
        this.tntpPingOneConfig = TNTPPingOneConfigChoiceValues.getTNTPPingOneConfig(config.tntpPingOneConfigName());
    }

    @Override
    public Action process(TreeContext context) {
        logger.debug("PingOneCreateUserNode started.");

        // Access the current node state (shared/transient attributes for this journey)
        NodeState nodeState = context.getStateFor(this);

        try {
            // Fail if username is not available in shared state
            if (!nodeState.isDefined(USERNAME)) {
                return handleFailure(nodeState, FailureReason.MISSING_USERNAME, null);
            }

            String username = nodeState.get(USERNAME).asString();

            // Retrieve an access token for PingOne API calls
            TNTPPingOneUtility utility = TNTPPingOneUtility.getInstance();
            String accessToken = utility.getAccessToken(realm, tntpPingOneConfig);
            if (accessToken == null) {
                return handleFailure(nodeState, FailureReason.ACCESS_TOKEN, null);
            }

            // Build the request payload depending on whether attributes come from shared state or AM identity
            PingOneUserRequestFactory.BuildResult build;
            if (config.userAttributesFromSharedState()) {
                build = PingOneUserRequestFactory.fromSharedState(
                        nodeState,
                        config.anonymizedUser(),
                        config.populationId(),
                        username,
                        userHelper
                );
            } else {
                // If not using shared state, look up an existing AM identity
                AMIdentity amIdentity = getIdentity(context);
                logger.debug("AMIdentity found: {} for user: {}.", amIdentity.getUniversalId(), username);

                // Validate required attribute exists in AM identity
                String pingOneUsername = userHelper.getUserAttribute(amIdentity, config.amIdentityAttribute());
                if (StringUtils.isEmpty(pingOneUsername)) {
                    return handleFailure(nodeState, FailureReason.MISSING_ATTRIBUTE_FROM_PROFILE, null);
                }

                build = PingOneUserRequestFactory.fromAmIdentity(
                        amIdentity,
                        config.anonymizedUser(),
                        config.populationId(),
                        pingOneUsername,
                        userHelper
                );
            }

            // Final API request body
            JsonValue requestBody = build.requestBody();

            // Build target URI
            String uri = Constants.endpoint + tntpPingOneConfig.environmentRegion().getDomainSuffix()
                    + "/v1/environments/" + tntpPingOneConfig.environmentId()
                    + "/users";

            // Call PingOne API to create the user
            JsonValue response = client.makeHTTPClientCall(accessToken, uri, "POST", requestBody);

            // Extract and store the PingOne User ID in shared state
            String pingOneUserId = userHelper.getUserIdFromResponse(response);
            nodeState.putShared(PINGONE_USER_ID_KEY, pingOneUserId);

            return goTo(true).build();

        } catch (IdentityNotFoundException e) {
            return handleFailure(nodeState, FailureReason.IDENTITY_NOT_FOUND, e);
        } catch (Exception e) {
            return handleFailure(nodeState, FailureReason.UNEXPECTED_ERROR, e);
        }
    }

    private Action handleFailure(NodeState nodeState, FailureReason reason, Exception e) {
        logger.error(reason.getMessage(), e);
        if (config.captureFailure()) {
            nodeState.putShared(PINGONE_CREATE_USER_FAILURE_REASON_KEY, getFailureJson(reason, e));
        }
        return goTo(false).build();
    }

    @VisibleForTesting
    AMIdentity getIdentity(TreeContext context) throws IdentityNotFoundException {
        return userHelper.getIdentity(context.getStateFor(this));
    }

    @Override
    public InputState[] getInputs() {
        return new InputState[] {
                new InputState(USERNAME, true),
                new InputState(AM_EMAIL, false),
                new InputState(AM_PHONE, false),
                new InputState(AM_GIVEN_NAME, false),
                new InputState(AM_FAMILY_NAME, false),
                new InputState(AM_COMMON_NAME, false),
                new InputState(AM_STREET, false),
                new InputState(AM_CITY, false),
                new InputState(AM_STATE, false),
                new InputState(AM_POSTAL_CODE, false),
                new InputState(AM_COUNTRY, false),
                new InputState(AM_PREFERRED_LANGUAGE, false)
        };
    }

    @Override
    public OutputState[] getOutputs() {
        return new OutputState[]{
                new OutputState(PINGONE_USER_ID_KEY, singletonMap(TRUE_OUTCOME_ID, true)),
                new OutputState(PINGONE_CREATE_USER_FAILURE_REASON_KEY, singletonMap(FALSE_OUTCOME_ID, true))
        };
    }
}
