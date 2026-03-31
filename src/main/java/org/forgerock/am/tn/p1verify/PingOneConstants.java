/*
 * Copyright 2024-2025 Ping Identity Corporation. All Rights Reserved
 *
 * This code is to be used exclusively in connection with Ping Identity
 * Corporation software or services. Ping Identity Corporation only offers
 * such software or services to legal entities who have entered into a
 * binding license agreement with Ping Identity Corporation.
 */

package org.forgerock.am.tn.p1verify;

public final class PingOneConstants {

    /**
     * The name of the shared state key that will hold the transaction id.
     */
    public static final String PINGONE_VERIFY_TRANSACTION_ID_KEY = "pinOneVerifyTransactionId";

    /**
     * The name of the shared state key that will hold the verify transaction metadata.
     */
    public static final String PINGONE_VERIFY_METADATA_KEY = "pingOneVerifyMetadata";

    /**
     * The name of the shared state key that will hold the verify transaction verified data.
     */
    public static final String PINGONE_VERIFY_VERIFIED_DATA_KEY = "pingOneVerifyVerifiedData";

    /**
     * The name of the shared state key that will hold the delivery method for the verify transaction URL.
     */
    public static final String PINGONE_VERIFY_DELIVERY_METHOD_KEY = "pingOneVerifyDeliveryMethod";

    /**
     * The name of the shared state key that will hold the verify node timeout.
     */
    public static final String PINGONE_VERIFY_TIMEOUT_KEY = "pingOneVerifyTimeout";

    /**
     * The name of the shared state key that will hold the reason of failure on verify the completion of a transaction.
     */
    public static final String PINGONE_VERIFY_REDIRECT_FLOW_CODE_KEY = "pingOneVerifyRedirectFlowCode";

    /**
     * The name of the shared state key that will hold the PingOne User ID.
     */
    public static final String PINGONE_USER_ID_KEY = "pingOneUserId";

    /**
     * The name of the shared state key that will hold the reason of failure on identity matching.
     */
    public static final String PINGONE_IDENTITY_MATCH_FAILURE_REASON_KEY = "pingOneIdentityMatchFailureReason";

    /**
     * The name of the shared state key that will hold the reason of failure on user creation.
     */
    public static final String PINGONE_CREATE_USER_FAILURE_REASON_KEY = "pingOneCreateUserFailureReason";

    /**
     * The name of the shared state key that will hold the reason of failure on user deletion.
     */
    public static final String PINGONE_DELETE_USER_FAILURE_REASON_KEY = "pingOneDeleteUserFailureReason";

    /**
     * The name of the shared state key that will hold the reason of failure on verify evaluation.
     */
    public static final String PINGONE_VERIFY_EVALUATION_FAILURE_REASON_KEY = "pingOneVerifyEvaluationFailureReason";

    /**
     * The name of the shared state key that will hold the reason of failure on verify the completion of a transaction.
     */
    public static final String PINGONE_VERIFY_COMPLETION_FAILURE_REASON_KEY = "pingOneVerifyCompletionFailureReason";

    /**
     * Do not construct util classes.
     */
    private PingOneConstants() {
        // do nothing
    }

}
