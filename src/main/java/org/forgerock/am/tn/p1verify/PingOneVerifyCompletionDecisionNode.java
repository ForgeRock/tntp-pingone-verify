/*
 * Copyright 2024-2025 Ping Identity Corporation. All Rights Reserved
 *
 * This code is to be used exclusively in connection with Ping Identity
 * Corporation software or services. Ping Identity Corporation only offers
 * such software or services to legal entities who have entered into a
 * binding license agreement with Ping Identity Corporation.
 */

package org.forgerock.am.tn.p1verify;

import com.google.common.collect.ImmutableList;
import com.google.inject.assistedinject.Assisted;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.*;
import org.forgerock.openam.auth.nodes.script.ActionWrapper;
import org.forgerock.openam.core.realms.Realm;
import org.forgerock.openam.scripting.domain.Script;
import org.forgerock.openam.utils.StringUtils;
import org.forgerock.util.i18n.PreferredLocales;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.SimpleBindings;
import javax.inject.Inject;
import javax.script.ScriptException;
import java.util.List;
import java.util.ResourceBundle;
import java.util.stream.Collectors;

import static java.util.Collections.singletonMap;
import static org.forgerock.am.tn.p1verify.FailureReason.ACCESS_TOKEN;
import static org.forgerock.am.tn.p1verify.FailureReason.UNEXPECTED_ERROR;
import static org.forgerock.openam.auth.node.api.AuthScriptUtilities.*;
import static org.forgerock.am.tn.p1verify.PingOneConstants.*;
import static org.forgerock.am.tn.p1verify.PingOneVerifyEvaluationNode.OutcomeProvider.FAILURE_OUTCOME_ID;
import static org.forgerock.am.tn.p1verify.Constants.RESPONSE_TRANSACTION_STATUS;
import static org.forgerock.am.tn.p1verify.Constants.RESPONSE_STATUS;
import static org.forgerock.am.tn.p1verify.Constants.RESPONSE_VERIFICATION_STATUS;
import static org.forgerock.am.tn.p1verify.Constants.RESPONSE_TRANSACTION_TIMED_OUT;
import static org.forgerock.am.tn.p1verify.Constants.RESPONSE_TRANSACTION_ID;
import org.forgerock.openam.auth.service.marketplace.TNTPPingOneConfig;
import org.forgerock.openam.auth.service.marketplace.TNTPPingOneConfigChoiceValues;
import org.forgerock.openam.auth.service.marketplace.TNTPPingOneUtility;

/**
 * The PingOne Verify Completion Decision node allows to determinate the transactions status of the
 * Identify Verification for the user on the PingOne platform.
 */
@Node.Metadata(
        outcomeProvider = PingOneVerifyCompletionDecisionNode.OutcomeProvider.class,
        configClass = PingOneVerifyCompletionDecisionNode.Config.class,
        tags = {"marketplace", "trustnetwork" }
)
public class PingOneVerifyCompletionDecisionNode implements Node {

    private static final Logger logger = LoggerFactory.getLogger(PingOneVerifyCompletionDecisionNode.class);
    private static final String BUNDLE = PingOneVerifyCompletionDecisionNode.class.getName();

    private final Helper client;
    private final TNTPPingOneConfig tntpPingOneConfig;
    private final Config config;
    private final Realm realm;
    private final ScriptEngineManager scriptEngineManager = new ScriptEngineManager();

    /**
     * Configuration for the node.
     */
    public interface Config {
        /**
         * Reference to the Configured PingOne Worker Service.
         *
         * @return The Configured PingOne Worker Service.
         */
        @Attribute(order = 100, choiceValuesClass = TNTPPingOneConfigChoiceValues.class)
        default String tntpPingOneConfigName() {
            return TNTPPingOneConfigChoiceValues.createTNTPPingOneConfigName("Global Default");
        }

        /**
         * Use a Decision Node Script to filter the Verify Transactions to be evaluated.
         *
         * @return true to use Decision Node script, false to use last transaction.
         */
        @Attribute(order = 200)
        default boolean useFilterScript() {
            return false;
        }

        /**
         * The script configuration.
         *
         * @return The script configuration.
         */
        @Attribute(order = 300)
        default Script script() {
            return Script.EMPTY_SCRIPT;
        }

        /**
         * The script inputs configuration.
         *
         * @return The script inputs configuration.
         */
        @Attribute(order = 400)
        default List<String> scriptInputs() {
            return List.of(WILDCARD);
        }

        /**
         * If the node fail, the error detail will be provided in the shared state for analysis by later nodes.
         *
         * @return true if the failure will be captured.
         */
        @Attribute(order = 500)
        default boolean captureFailure() {
            return false;
        }
    }

    /**
     * The PingOne Verify Completion Decision node constructor.
     *
     * @param config                 the node configuration.
     * @param realm                  the realm.
     */
    @Inject
    PingOneVerifyCompletionDecisionNode(Helper client,
                                        @Assisted Config config,
                                        @Assisted Realm realm) {
        this.config = config;
        this.realm = realm;
        this.client = client;
        this.tntpPingOneConfig = TNTPPingOneConfigChoiceValues.getTNTPPingOneConfig(config.tntpPingOneConfigName());
    }

    @Override
    public Action process(TreeContext context) {
        logger.debug("PingOneVerifyCompletionDecisionNode started.");

        NodeState nodeState = context.getStateFor(this);

        // Check if PingOne User ID attribute is set in sharedState
        String pingOneUserId = nodeState.isDefined(PINGONE_USER_ID_KEY)
                ? nodeState.get(PINGONE_USER_ID_KEY).asString()
                : null;
        if (StringUtils.isBlank(pingOneUserId)) {
            return handleFailure(nodeState, FailureReason.MISSING_PINGONE_USER_ID_FROM_SHARED_STATE, null);
        }

        try {
            // Obtain PingOne access token
            TNTPPingOneUtility tntpP1U = TNTPPingOneUtility.getInstance();
            String accessToken = tntpP1U.getAccessToken(realm, tntpPingOneConfig);
            if (accessToken == null) {
                return handleFailure(nodeState, ACCESS_TOKEN, null);
            }

            // Check if user filter script is enabled
            if (config.useFilterScript()) {
                logger.debug("Using script to filter transactions and return status.");
                VerifyTransactionsHelper verifyTransactionsHelper = new VerifyTransactionsHelper(config, client, accessToken, pingOneUserId);
                return executeScript(context, verifyTransactionsHelper);
            } else {
                // Get the last transaction status
                logger.debug("Using last transaction status to determine the outcome.");
                logger.error("Using last transaction status to determine the outcome.");

                VerifyTransactionsHelper helper = new VerifyTransactionsHelper(config, client, accessToken, pingOneUserId);
                JsonValue lastTransaction = new JsonValue(helper.getLastVerifyTransaction());

                logger.error("lastTransaction - JSON VALUE: {}", lastTransaction);
//                logger.error("lastTransaction - TO STRING: {}", helper.getLastVerifyTransaction().toString());

                if (lastTransaction.size() == 0) {
                    logger.debug("Unable to find any verify transaction for PingOne User ID: {}", pingOneUserId);
                    logger.error("Unable to find any verify transaction for PingOne User ID: {}", pingOneUserId);
                    return Action.goTo(OutcomeProvider.NOT_STARTED_OUTCOME_ID).build();
                }

                String status = lastTransaction.get(RESPONSE_TRANSACTION_STATUS).get(RESPONSE_STATUS).asString();
                switch (VerifyTransactionStatus.fromString(status)) {
                case REQUESTED:
                case PARTIAL:
                case INITIATED:
                case IN_PROGRESS:
                    // Set verify transaction ID in sharedState
                    nodeState.putShared(PINGONE_VERIFY_TRANSACTION_ID_KEY, lastTransaction.get(RESPONSE_TRANSACTION_ID).asString());
                    return Action.goTo(OutcomeProvider.NOT_COMPLETED_OUTCOME_ID).build();
                case SUCCESS:
                case NOT_REQUIRED:
                case APPROVED_NO_REQUEST:
                case APPROVED_MANUALLY:
                    return Action.goTo(OutcomeProvider.SUCCESS_OUTCOME_ID).build();
                case FAIL:
                    if (isTransactionTimedOut(lastTransaction)) {
                        return Action.goTo(OutcomeProvider.EXPIRED_OUTCOME_ID).build();
                    } else {
                        return handleFailure(nodeState, FailureReason.IDENTITY_VERIFICATION_FAILED, null);
                    }
                default:
                    return handleFailure(nodeState, FailureReason.UNEXPECTED_VERIFY_STATUS, null);
                }
            }
        } catch (ScriptException e) {
            return handleFailure(nodeState, FailureReason.VERIFY_COMPLETION_SCRIPT_ERROR, e);
        } catch (Exception e) {
            return handleFailure(nodeState, UNEXPECTED_ERROR, e);
        }
    }

    private Action executeScript(TreeContext context, VerifyTransactionsHelper helper) throws ScriptException {
        Script script = config.script();
        String scriptText = script != null ? script.getScript() : null;

        if (StringUtils.isBlank(scriptText)) {
            throw new ScriptException("No script provided in the configuration.");
        }

        // Prepare bindings
        SimpleBindings bindings = new SimpleBindings();
        bindings.put("nodeState", context.getStateFor(this));
        bindings.put("verifyTransactionsHelper", helper);

        // Evaluate script
        ScriptEngine engine = scriptEngineManager.getEngineByName("JavaScript");
        if (engine == null) {
            throw new ScriptException("No JavaScript engine available.");
        }

        engine.eval(scriptText, bindings);

        // Support classic return mechanism
        Object outcome = bindings.get(OUTCOME_IDENTIFIER); // "outcome"
        ActionWrapper action = (ActionWrapper) bindings.get(ACTION); // "action"

        if (action != null && !action.isEmpty()) {
            return action.buildAction();
        }

        if (outcome instanceof String) {
            String outcomeStr = (String) outcome;
            return Action.goTo(outcomeStr).build();
        }

        throw new ScriptException("Script must set an 'outcome' (string) or 'action' (ActionWrapper).");
    }

    private boolean isTransactionTimedOut(JsonValue lastTransaction) {
        JsonValue verificationStatus = lastTransaction.get(RESPONSE_TRANSACTION_STATUS).get(RESPONSE_VERIFICATION_STATUS);
        logger.error("Verification Status: {}", verificationStatus);

        return verificationStatus.toString().contains(RESPONSE_TRANSACTION_TIMED_OUT);
    }

    private Action handleFailure(NodeState nodeState, FailureReason failureReason, Exception exception) {
        logger.error(failureReason.getMessage(), exception);
        if (config.captureFailure()) {
            nodeState.putShared(PINGONE_VERIFY_COMPLETION_FAILURE_REASON_KEY, failureReason.name());
        }
        return Action.goTo(FAILURE_OUTCOME_ID).build();
    }

    @Override
    public OutputState[] getOutputs() {
        return new OutputState[] {
                new OutputState(PINGONE_VERIFY_TRANSACTION_ID_KEY, singletonMap(OutcomeProvider.NOT_COMPLETED_OUTCOME_ID, true)),
                new OutputState(PINGONE_VERIFY_COMPLETION_FAILURE_REASON_KEY, singletonMap(FAILURE_OUTCOME_ID, true))
        };
    }

    @Override
    public InputState[] getInputs() {
        List<InputState> inputs = config.scriptInputs().stream()
                .filter(StringUtils::isNotBlank)
                .map(input -> new InputState(input, false))
                .collect(Collectors.toList());
        inputs.add(new InputState(PINGONE_USER_ID_KEY, true));
        return inputs.toArray(new InputState[0]);
    }

    /**
     * Provides the PingOne Verify Completion Decision node's set of outcomes.
     */
    public static final class OutcomeProvider implements StaticOutcomeProvider {

        /**
         * Success outcome ID.
         */
        public static final String SUCCESS_OUTCOME_ID = "successOutcome";
        /**
         * Not Started outcome ID.
         */
        public static final String NOT_STARTED_OUTCOME_ID = "notStartedOutcome";
        /**
         * Not Completed outcome ID.
         */
        public static final String NOT_COMPLETED_OUTCOME_ID = "notCompletedOutcome";
        /**
         * Failure outcome ID.
         */
        public static final String FAILURE_OUTCOME_ID = "failureOutcome";
        /**
         * Expired outcome ID.
         */
        public static final String EXPIRED_OUTCOME_ID = "expiredOutcome";

        @Override
        public List<Outcome> getOutcomes(PreferredLocales locales) {
            ResourceBundle bundle = locales.getBundleInPreferredLocale(BUNDLE, OutcomeProvider.class.getClassLoader());

            return ImmutableList.of(
                    new Outcome(SUCCESS_OUTCOME_ID, bundle.getString(SUCCESS_OUTCOME_ID)),
                    new Outcome(NOT_STARTED_OUTCOME_ID, bundle.getString(NOT_STARTED_OUTCOME_ID)),
                    new Outcome(NOT_COMPLETED_OUTCOME_ID, bundle.getString(NOT_COMPLETED_OUTCOME_ID)),
                    new Outcome(FAILURE_OUTCOME_ID, bundle.getString(FAILURE_OUTCOME_ID)),
                    new Outcome(EXPIRED_OUTCOME_ID, bundle.getString(EXPIRED_OUTCOME_ID))
            );
        }
    }
}
