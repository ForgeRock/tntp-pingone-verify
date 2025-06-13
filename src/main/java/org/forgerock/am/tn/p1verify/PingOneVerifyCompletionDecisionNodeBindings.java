/*
 * Copyright 2024-2025 Ping Identity Corporation. All Rights Reserved
 *
 * This code is to be used exclusively in connection with Ping Identity
 * Corporation software or services. Ping Identity Corporation only offers
 * such software or services to legal entities who have entered into a
 * binding license agreement with Ping Identity Corporation.
 */

package org.forgerock.am.tn.p1verify;

import org.forgerock.openam.auth.node.api.NodeState;
import org.forgerock.openam.auth.node.api.NodeStateScriptWrapper;
import org.forgerock.openam.auth.nodes.script.ActionWrapper;
import org.forgerock.openam.scripting.domain.BindingsMap;
import org.forgerock.openam.scripting.domain.NextGenScriptBindings;

import javax.security.auth.callback.Callback;
import java.util.List;

import static org.forgerock.openam.auth.node.api.AuthScriptUtilities.ACTION;
import static org.forgerock.openam.auth.nodes.helpers.ScriptedNodeHelper.STATE_IDENTIFIER;

/**
 * Script bindings for the PingOneVerifyCompletionDecisionNode script.
 */
public final class PingOneVerifyCompletionDecisionNodeBindings implements NextGenScriptBindings {

    private static final String VERIFY_TRANSACTIONS_IDENTIFIER = "verifyTransactionsHelper";
    private final NodeState nodeState;
    private final VerifyTransactionsHelper verifyTransactionsHelper;

    private PingOneVerifyCompletionDecisionNodeBindings(Builder builder) {
        this.nodeState = builder.nodeState;
        this.verifyTransactionsHelper = builder.verifyTransactionsHelper;
    }

    /**
     * Static method to get the builder object.
     *
     * @return The first step of the Builder.
     */
    public static PingOneVerifyCompletionDecisionNodeBindingsStep1 builder() {
        return new Builder();
    }

    @Override
    public BindingsMap nextGenBindings() {
        BindingsMap bindings = new BindingsMap();
        bindings.put(STATE_IDENTIFIER, new NodeStateScriptWrapper(nodeState));
        bindings.put(VERIFY_TRANSACTIONS_IDENTIFIER, verifyTransactionsHelper);
        bindings.put(ACTION, new ActionWrapper());
        return bindings;
    }

    /**
     * Step 1 of the builder.
     */
    public interface PingOneVerifyCompletionDecisionNodeBindingsStep1 {
        /**
         * Sets the {@link NodeState}.
         *
         * @param nodeState the node state
         * @return the next step of the {@link Builder}
         */
        PingOneVerifyCompletionDecisionNodeBindingsStep2 withNodeState(NodeState nodeState);
    }

    /**
     * Step 3 of the builder.
     */
    public interface PingOneVerifyCompletionDecisionNodeBindingsStep2 {
        /**
         * Sets the verify transactions.
         *
         * @param verifyTransactionsHelper the Json containing the verify transactions.
         * @return the next step of the {@link Builder}
         */
        PingOneVerifyCompletionDecisionNodeBindingsFinalStep withVerifyTransactionsHelper(
                VerifyTransactionsHelper verifyTransactionsHelper);
    }

    /**
     * Final step of the builder.
     */
    public interface PingOneVerifyCompletionDecisionNodeBindingsFinalStep {
        /**
         * Builds the {@link PingOneVerifyCompletionDecisionNodeBindings}.
         *
         * @return the {@link PingOneVerifyCompletionDecisionNodeBindings}
         */
        PingOneVerifyCompletionDecisionNodeBindings build();
    }

    /**
     * Builder object to construct a {@link PingOneVerifyCompletionDecisionNodeBindings}.
     */
    private static final class Builder implements PingOneVerifyCompletionDecisionNodeBindingsStep1,
            PingOneVerifyCompletionDecisionNodeBindingsStep2, PingOneVerifyCompletionDecisionNodeBindingsFinalStep {

        private NodeState nodeState;
        private List<? extends Callback> callbacks;
        private VerifyTransactionsHelper verifyTransactionsHelper;

        /**
         * Set the nodeState for the builder.
         *
         * @param nodeState The nodeState.
         * @return The next step of the Builder.
         */
        @Override
        public PingOneVerifyCompletionDecisionNodeBindingsStep2 withNodeState(NodeState nodeState) {
            this.nodeState = nodeState;
            return this;
        }

        /**
         * Set the verify transactions.
         *
         * @param verifyTransactionsHelper The Json containing the verify transactions.
         * @return The next step of the Builder.
         */
        public PingOneVerifyCompletionDecisionNodeBindingsFinalStep withVerifyTransactionsHelper(
                VerifyTransactionsHelper verifyTransactionsHelper) {
            this.verifyTransactionsHelper = verifyTransactionsHelper;
            return this;
        }

        /**
         * Builds the {@link PingOneVerifyCompletionDecisionNodeBindings}.
         *
         * @return the {@link PingOneVerifyCompletionDecisionNodeBindings}.
         */
        public PingOneVerifyCompletionDecisionNodeBindings build() {
            return new PingOneVerifyCompletionDecisionNodeBindings(this);
        }
    }
}
