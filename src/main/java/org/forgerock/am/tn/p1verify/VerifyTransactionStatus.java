
/*
 * Copyright 2024-2025 Ping Identity Corporation. All Rights Reserved
 *
 * This code is to be used exclusively in connection with Ping Identity
 * Corporation software or services. Ping Identity Corporation only offers
 * such software or services to legal entities who have entered into a
 * binding license agreement with Ping Identity Corporation.
 */

package org.forgerock.am.tn.p1verify;

/*
 * The VerifyTransactionStatus enum represents the status of a transaction verification.
 */
public enum VerifyTransactionStatus {

    /**
     * The transaction has been requested.
     */
    REQUESTED("REQUESTED"),
    /**
     * The transaction has been partially completed.
     */
    PARTIAL("PARTIAL"),
    /**
     * The transaction has been initiated.
     */
    INITIATED("INITIATED"),
    /**
     * The transaction is in progress.
     */
    IN_PROGRESS("IN_PROGRESS"),
    /**
     * The transaction has been completed successfully.
     */
    SUCCESS("SUCCESS"),
    /**
     * The transaction has been cancelled.
     */
    NOT_REQUIRED("NOT_REQUIRED"),
    /**
     * The transaction has failed.
     */
    FAIL("FAIL"),
    /**
     * The transaction has been rejected.
     */
    APPROVED_NO_REQUEST("APPROVED_NO_REQUEST"),
    /**
     * The transaction has been approved manually.
     */
    APPROVED_MANUALLY("APPROVED_MANUALLY");

    private final String value;

    VerifyTransactionStatus(String value) {
        this.value = value;
    }

    /**
     * Returns the transaction status value.
     *
     * @return the value.
     */
    public String getValue() {
        return value;
    }

    /**
     * Returns the VerifyTransactionStatus enum value from the given string.
     *
     * @param value the string value.
     * @return the VerifyTransactionStatus enum value.
     * @throws IllegalArgumentException if the value is not recognised.
     */
    public static VerifyTransactionStatus fromString(String value) {
        for (VerifyTransactionStatus status : VerifyTransactionStatus.values()) {
            if (status.getValue().equalsIgnoreCase(value)) {
                return status;
            }
        }
        throw new IllegalArgumentException("Unrecognised VerifyTransactionStatus value: " + value);
    }
}
