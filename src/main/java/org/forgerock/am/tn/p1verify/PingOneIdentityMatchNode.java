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

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Collections;

import static org.forgerock.am.tn.p1verify.FailureReason.getFailureJson;
import static org.forgerock.am.tn.p1verify.PingOneConstants.PINGONE_IDENTITY_MATCH_FAILURE_REASON_KEY;
import static org.forgerock.am.tn.p1verify.PingOneConstants.PINGONE_USER_ID_KEY;
import static org.forgerock.am.tn.p1verify.UserHelper.DEFAULT_AM_IDENTITY_ATTRIBUTE;
import static org.forgerock.am.tn.p1verify.UserHelper.DEFAULT_PING_IDENTITY_ATTRIBUTE;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;

@Node.Metadata(
        outcomeProvider = AbstractDecisionNode.OutcomeProvider.class,
        configClass = PingOneIdentityMatchNode.Config.class,
        tags = {"marketplace", "trustnetwork"}
)
public class PingOneIdentityMatchNode extends AbstractDecisionNode {

    private final Logger logger = LoggerFactory.getLogger(PingOneIdentityMatchNode.class);

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
        default String amIdentityAttribute() {
            return DEFAULT_AM_IDENTITY_ATTRIBUTE;
        }

        @Attribute(order = 300)
        default String pingIdentityAttribute() {
            return DEFAULT_PING_IDENTITY_ATTRIBUTE;
        }

        @Attribute(order = 400)
        default boolean captureFailure() {
            return false;
        }
    }

    @Inject
    public PingOneIdentityMatchNode(@Assisted Config config,
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
        logger.debug("PingOneIdentityMatchNode started");

        NodeState nodeState = context.getStateFor(this);

        try {
            if (!nodeState.isDefined(USERNAME)) {
                return handleFailure(nodeState, FailureReason.MISSING_USERNAME, null);
            }

            String username = nodeState.get(USERNAME).asString();
            AMIdentity amIdentity = getIdentity(context);
            logger.debug("AMIdentity found: {} for user: {}", amIdentity.getUniversalId(), username);

            TNTPPingOneUtility utility = TNTPPingOneUtility.getInstance();
            String accessToken = utility.getAccessToken(realm, tntpPingOneConfig);
            if (accessToken == null) {
                return handleFailure(nodeState, FailureReason.ACCESS_TOKEN, null);
            }

            String amAttr = config.amIdentityAttribute();
            String pingAttr = config.pingIdentityAttribute();
            String amAttrValue = userHelper.getUserAttribute(amIdentity, amAttr);
            if (StringUtils.isEmpty(amAttrValue)) {
                return handleFailure(nodeState, FailureReason.INVALID_ATTRIBUTE_CONFIGURATION, null);
            }

            String rawFilter = pingAttr + " eq \"" + amAttrValue + "\"";
            String encodedFilter = URLEncoder.encode(rawFilter, StandardCharsets.UTF_8).replace("+","%20");
            String uri = Constants.endpoint + tntpPingOneConfig.environmentRegion().getDomainSuffix()
                    + "/v1/environments/" + tntpPingOneConfig.environmentId()
                    + "/users?filter=" + encodedFilter;

            JsonValue response = client.makeHTTPClientCall(accessToken, uri, "GET", null);

            int count = userHelper.userCount(response);

            if (count > 1) {
                return handleFailure(nodeState, FailureReason.MULTIPLE_ENTRIES_FOUND, null);
            } else if (count == 1) {
                String pingOneUserId = userHelper.getUserIdFromResponse(response);
                nodeState.putShared(PINGONE_USER_ID_KEY, pingOneUserId);
                logger.debug("User matched in PingOne with ID: {}", pingOneUserId);
                return goTo(true).build();
            } else {
                logger.debug("No PingOne user matched. Outcome: false");
                return goTo(false).build();
            }

        } catch (IdentityNotFoundException e) {
            return handleFailure(nodeState, FailureReason.IDENTITY_NOT_FOUND, e);
        } catch (Exception e) {
            return handleFailure(nodeState, FailureReason.UNEXPECTED_ERROR, e);
        }
    }

    private Action handleFailure(NodeState nodeState, FailureReason reason, Exception e) {
        logger.error(reason.getMessage(), e);
        if (config.captureFailure()) {
            nodeState.putShared(PINGONE_IDENTITY_MATCH_FAILURE_REASON_KEY, getFailureJson(reason, e));
        }
        return goTo(false).build();
    }

    @VisibleForTesting
    AMIdentity getIdentity(TreeContext context) throws IdentityNotFoundException {
        return userHelper.getIdentity(context.getStateFor(this));
    }

    @Override
    public InputState[] getInputs() {
        return new InputState[]{
                new InputState(USERNAME, true)
        };
    }

    @Override
    public OutputState[] getOutputs() {
        return new OutputState[]{
                new OutputState(PINGONE_USER_ID_KEY, Collections.singletonMap(TRUE_OUTCOME_ID, true)),
                new OutputState(PINGONE_IDENTITY_MATCH_FAILURE_REASON_KEY, Collections.singletonMap(FALSE_OUTCOME_ID, true))
        };
    }
}
