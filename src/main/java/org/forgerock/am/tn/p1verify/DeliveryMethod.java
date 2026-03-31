/*
 * Copyright 2024-2025 Ping Identity Corporation. All Rights Reserved
 *
 * This code is to be used exclusively in connection with Ping Identity
 * Corporation software or services. Ping Identity Corporation only offers
 * such software or services to legal entities who have entered into a
 * binding license agreement with Ping Identity Corporation.
 */

package org.forgerock.am.tn.p1verify;

/**
 * Delivery Methods of ID Verification URL.
 */
public enum DeliveryMethod {

    /**
     * QR code.
     */
    QRCODE,
    /**
     * E-mail.
     */
    EMAIL,
    /**
     * SMS.
     */
    SMS,
    /**
     * Redirect.
     */
    REDIRECT;

    /**
     * Get the DeliveryMethod from the index.
     * @param index The index of the DeliveryMethod.
     * @return The DeliveryMethod.
     */
    public static DeliveryMethod fromIndex(int index) {
        return DeliveryMethod.values()[index];
    }

}
