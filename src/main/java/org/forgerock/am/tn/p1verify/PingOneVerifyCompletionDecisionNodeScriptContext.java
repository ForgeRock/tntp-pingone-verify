/*
 * Copyright 2024-2025 Ping Identity Corporation. All Rights Reserved
 *
 * This code is to be used exclusively in connection with Ping Identity
 * Corporation software or services. Ping Identity Corporation only offers
 * such software or services to legal entities who have entered into a
 * binding license agreement with Ping Identity Corporation.
 */

package org.forgerock.am.tn.p1verify;

import com.google.auto.service.AutoService;
import com.google.inject.Singleton;
import org.forgerock.openam.scripting.domain.Script;
import org.forgerock.openam.scripting.domain.ScriptContext;
import org.forgerock.openam.scripting.domain.nextgen.NextGenScriptContext;

import java.util.List;

/**
 * Next Gen script context for the PingOneVerifyCompletionDecisionNode.
 */
@Singleton
@AutoService(ScriptContext.class)
public class PingOneVerifyCompletionDecisionNodeScriptContext
        extends NextGenScriptContext<PingOneVerifyCompletionDecisionNodeBindings> {

    static final String PINGONE_VERIFY_COMPLETION_DECISION_NODE_NAME = "PingOneVerifyCompletionDecisionNode";

    /**
     * Create a new Next Gen script context.
     */
    protected PingOneVerifyCompletionDecisionNodeScriptContext() {
        super(PingOneVerifyCompletionDecisionNodeBindings.class);
    }

    @Override
    protected Script getDefaultScript() {
        return Script.EMPTY_SCRIPT;
    }

    @Override
    protected List<String> getContextWhiteList() {
        return List.of();
    }

    @Override
    public PingOneVerifyCompletionDecisionNodeBindings getExampleBindings() {
        return PingOneVerifyCompletionDecisionNodeBindings.builder()
                .withNodeState(null)
                .withVerifyTransactionsHelper(null)
                .build();
    }

    @Override
    public String name() {
        return PINGONE_VERIFY_COMPLETION_DECISION_NODE_NAME;
    }

    @Override
    public String getI18NKey() {
        return "next-gen-script-type-03";
    }
}
