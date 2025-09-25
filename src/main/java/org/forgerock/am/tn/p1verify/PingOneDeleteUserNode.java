package org.forgerock.am.tn.p1verify;

import com.google.inject.Inject;
import com.google.inject.assistedinject.Assisted;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.*;
import org.forgerock.openam.auth.service.marketplace.TNTPPingOneConfig;
import org.forgerock.openam.auth.service.marketplace.TNTPPingOneConfigChoiceValues;
import org.forgerock.openam.auth.service.marketplace.TNTPPingOneUtility;
import org.forgerock.openam.core.realms.Realm;
import org.forgerock.openam.utils.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static java.util.Collections.singletonMap;
import static org.forgerock.am.tn.p1verify.FailureReason.getFailureJson;
import static org.forgerock.am.tn.p1verify.PingOneConstants.PINGONE_DELETE_USER_FAILURE_REASON_KEY;
import static org.forgerock.am.tn.p1verify.PingOneConstants.PINGONE_USER_ID_KEY;

/**
 * A node that deletes a user in PingOne using the PingOne User ID from the shared state.
 */
@Node.Metadata(
        outcomeProvider = AbstractDecisionNode.OutcomeProvider.class,
        configClass = PingOneDeleteUserNode.Config.class,
        tags = {"marketplace", "trustnetwork"}
)
public class PingOneDeleteUserNode extends AbstractDecisionNode {

    private static final Logger logger = LoggerFactory.getLogger(PingOneDeleteUserNode.class);

    private final Config config;
    private final Realm realm;
    private final Helper client;
    private final TNTPPingOneConfig tntpPingOneConfig;

    /**
     * Node configuration.
     */
    public interface Config {

        @Attribute(order = 100, choiceValuesClass = TNTPPingOneConfigChoiceValues.class)
        default String tntpPingOneConfigName() {
            return TNTPPingOneConfigChoiceValues.createTNTPPingOneConfigName("Global Default");
        }

        @Attribute(order = 200)
        default boolean captureFailure() {
            return false;
        }
    }

    /**
     * Constructs the PingOneDeleteUserNode.
     */
    @Inject
    public PingOneDeleteUserNode(@Assisted Config config,
                                 @Assisted Realm realm,
                                 Helper client) {
        this.config = config;
        this.realm = realm;
        this.client = client;
        this.tntpPingOneConfig = TNTPPingOneConfigChoiceValues.getTNTPPingOneConfig(config.tntpPingOneConfigName());
    }

    @Override
    public Action process(TreeContext context) {
        logger.debug("PingOneDeleteUserNode started.");

        NodeState nodeState = context.getStateFor(this);

        try {
            // Retrieve the PingOne User ID from shared state
            String pingOneUserId = nodeState.isDefined(PINGONE_USER_ID_KEY)
                    ? nodeState.get(PINGONE_USER_ID_KEY).asString()
                    : null;

            if (StringUtils.isBlank(pingOneUserId)) {
                return handleFailure(nodeState, FailureReason.MISSING_PINGONE_USER_ID, null);
            }

            // Retrieve PingOne access token
            String accessToken = TNTPPingOneUtility.getInstance().getAccessToken(realm, tntpPingOneConfig);
            if (StringUtils.isBlank(accessToken)) {
                return handleFailure(nodeState, FailureReason.ACCESS_TOKEN, null);
            }

            // Build the PingOne DELETE URI
            String uri = Constants.endpoint
                    + tntpPingOneConfig.environmentRegion().getDomainSuffix()
                    + "/v1/environments/" + tntpPingOneConfig.environmentId()
                    + "/users/" + pingOneUserId;

            // Perform the DELETE request
            client.makeHTTPClientCall(accessToken, uri, "DELETE", null);
            return goTo(true).build();

        } catch (Exception e) {
            return handleFailure(nodeState, FailureReason.UNEXPECTED_ERROR, e);
        }
    }

    private Action handleFailure(NodeState nodeState, FailureReason failureReason, Exception exception) {
        logger.error(failureReason.getMessage(), exception);
        if (config.captureFailure()) {
            nodeState.putShared(PINGONE_DELETE_USER_FAILURE_REASON_KEY, getFailureJson(failureReason, exception));
        }
        return goTo(false).build();
    }

    @Override
    public InputState[] getInputs() {
        return new InputState[]{
                new InputState(PINGONE_USER_ID_KEY, true)
        };
    }

    @Override
    public OutputState[] getOutputs() {
        return new OutputState[]{
                new OutputState(PINGONE_DELETE_USER_FAILURE_REASON_KEY, singletonMap(FALSE_OUTCOME_ID, true))
        };
    }
}
