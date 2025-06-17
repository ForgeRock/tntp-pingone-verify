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
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;
import static org.forgerock.am.tn.p1verify.UserHelper.DEFAULT_AM_IDENTITY_ATTRIBUTE;

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
        @Attribute(order = 100, choiceValuesClass = TNTPPingOneConfigChoiceValues.class)
        default String tntpPingOneConfigName() {
            return TNTPPingOneConfigChoiceValues.createTNTPPingOneConfigName("Global Default");
        }

        @Attribute(order = 200)
        default String populationId() {
            return "";
        }

        @Attribute(order = 300)
        default boolean anonymizedUser() {
            return true;
        }

        @Attribute(order = 400)
        default String amIdentityAttribute() {
            return DEFAULT_AM_IDENTITY_ATTRIBUTE;
        }

        @Attribute(order = 500)
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

        NodeState nodeState = context.getStateFor(this);

        try {
            if (!nodeState.isDefined(USERNAME)) {
                return handleFailure(nodeState, FailureReason.MISSING_USERNAME, null);
            }

            String username = nodeState.get(USERNAME).asString();
            AMIdentity amIdentity = getIdentity(context);
            logger.debug("AMIdentity found: {} for user: {}.", amIdentity.getUniversalId(), username);

            TNTPPingOneUtility utility = TNTPPingOneUtility.getInstance();
            String accessToken = utility.getAccessToken(realm, tntpPingOneConfig);
            if (accessToken == null) {
                return handleFailure(nodeState, FailureReason.ACCESS_TOKEN, null);
            }

            String amUserKey = userHelper.getUserAttribute(amIdentity, config.amIdentityAttribute());
            if (StringUtils.isEmpty(amUserKey)) {
                return handleFailure(nodeState, FailureReason.MISSING_ATTRIBUTE_FROM_PROFILE, null);
            }

            // Build request body
            JsonValue requestBody = config.anonymizedUser()
                    ? userHelper.getAnonymizedRequestBody(amIdentity, config.populationId(), amUserKey)
                    : userHelper.getFullRequestBody(amIdentity, config.populationId(), amUserKey);

            // Build target URI
            String uri = Constants.endpoint + tntpPingOneConfig.environmentRegion().getDomainSuffix()
                    + "/v1/environments/" + tntpPingOneConfig.environmentId()
                    + "/users";

            JsonValue response = client.makeHTTPClientCall(accessToken, uri, "POST", requestBody);
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
        return new InputState[]{ new InputState(USERNAME, true) };
    }

    @Override
    public OutputState[] getOutputs() {
        return new OutputState[]{
                new OutputState(PINGONE_USER_ID_KEY, singletonMap(TRUE_OUTCOME_ID, true)),
                new OutputState(PINGONE_CREATE_USER_FAILURE_REASON_KEY, singletonMap(FALSE_OUTCOME_ID, true))
        };
    }
}
