/*
 * Copyright 2024-2025 Ping Identity Corporation. All Rights Reserved
 *
 * This code is to be used exclusively in connection with Ping Identity
 * Corporation software or services. Ping Identity Corporation only offers
 * such software or services to legal entities who have entered into a
 * binding license agreement with Ping Identity Corporation.
 */

package org.forgerock.am.tn.p1verify;

import org.forgerock.openam.utils.JsonObject;
import org.forgerock.openam.utils.JsonValueBuilder;

/**
 * Used to represent the failure reason in the PingOne nodes.
 */
public enum FailureReason {

    /**
     * Expected PingOne User ID to be set in sharedState.
     */
    MISSING_PINGONE_USER_ID("Expected PingOne User ID to be set in sharedState or user's profile."),

    /**
     * Expected PingOne User ID to be set in sharedState.
     */
    MISSING_PINGONE_USER_ID_FROM_SHARED_STATE("Expected PingOne User ID to be set in sharedState."),

    /**
     * The username is missing.
     */
    MISSING_USERNAME("Could not get the username from the context."),

    /**
     * Unable to get access token from PingOne.
     */
    ACCESS_TOKEN("Unable to get access token for PingOne Worker."),

    /**
     * Unable to get the PingOne user from profile.
     */
    MISSING_ID_FROM_PROFILE("Expected PingOne User ID to be set in user's profile."),

    /**
     * Could not get attribute from user profile.
     */
    MISSING_ATTRIBUTE_FROM_PROFILE("Could not get attribute from user profile."),

    /**
     * The user attribute is missing.
     */
    INVALID_ATTRIBUTE_CONFIGURATION("Could not get the value for the configured user attribute."),

    /**
     * Multiples entries found.
     */
    MULTIPLE_ENTRIES_FOUND("Found multiple entries with the same key attribute value in PingOne."),

    /**
     * Identity not found in the realm.
     */
    IDENTITY_NOT_FOUND("Could not find the identity with username in the realm."),

    /**
     * Error communicating with PingOne.
     */
    PINGONE_COMMUNICATION_ERROR("Error communicating with PingOne."),

    /**
     * Unable to find the PingOne Verify Transaction ID in sharedState.
     */
    MISSING_PINGONE_VERIFY_TRANSACTION_ID("Expected PingOne Verify Transaction ID to be set in sharedState."),

    /**
     * Error processing JSON data.
     */
    JSON_PROCESSING_ERROR("Error processing JSON data."),

    /**
     * Identity verification failed.
     */
    IDENTITY_VERIFICATION_FAILED("Identity verification failed."),

    /**
     * Unexpected status returned from PingOne Verify Transaction.
     */
    UNEXPECTED_VERIFY_STATUS("Unexpected status returned from PingOne Verify Transaction."),

    /**
     * Unexpected key value found in Biographic Matching.
     */
    INVALID_BIOGRAPHIC_MATCHING("Unexpected key value found in Biographic Matching."),

    /**
     * Error evaluating the verify completion decision script.
     */
    VERIFY_COMPLETION_SCRIPT_ERROR("Error evaluating the verify completion decision script."),

    /**
     * The redirect flow failed due to code mismatch.
     */
    REDIRECT_FLOW_FAILED_CODE_MISMATCH("Redirect flow failed. Code mismatch."),

    /**
     * The redirect flow failed due to missing code.
     */
    REDIRECT_FLOW_FAILED_MISSING_CODE("Redirect flow failed. Code not found in request parameters."),

    /**
     * An unexpected error occurred.
     */
    UNEXPECTED_ERROR("An unexpected error occurred.");


    private final String message;


    /**
     * Constructs a new instance of the failure reason.
     *
     * @param message The failure reason message
     */
    FailureReason(String message) {
        this.message = message;
    }

    /**
     * Returns the failure reason message.
     *
     * @return The failure reason message
     */
    public String getMessage() {
        return message;
    }

    /**
     * Returns a JSON string with the failure reason and exception message.
     *
     * @param failureReason The failure reason
     * @param exception     The exception
     * @return A JSON string with the failure reason and exception message
     */
    public static String getFailureJson(FailureReason failureReason, Exception exception) {
        JsonObject failureJson = JsonValueBuilder.jsonValue();
        failureJson.put("code", failureReason.name());
        failureJson.put("message", failureReason.getMessage());
        failureJson.put("exception", exception != null ? exception.getMessage() : "");
        return failureJson.build().toString();
    }
}

