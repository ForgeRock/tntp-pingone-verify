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
 * Used to represent the requirement in the Biographic Matching.
 */
public enum BiographicMatchingRequirement {

    /**
     * Reference Selfie.
     */
    REFERENCE_SELFIE("referenceSelfie"),
    /**
     * Phone.
     */
    PHONE("phone"),
    /**
     * E-mail.
     */
    EMAIL("email"),
    /**
     * Given Name.
     */
    GIVEN_NAME("given_name"),
    /**
     * Family Name.
     */
    FAMILY_NAME("family_name"),
    /**
     * Name.
     */
    NAME("name"),
    /**
     * Address.
     */
    ADDRESS("address"),
    /**
     * Birth Date.
     */
    BIRTH_DATE("birth_date");

    private final String value;

    /**
     * The constructor.
     *
     * @param value the value.
     */
    BiographicMatchingRequirement(String value) {
        this.value = value;
    }

    /**
     * Returns the requirement value.
     *
     * @return the value.
     */
    public String getValue() {
        return value;
    }

    /**
     * Get BiographicMatchingRequirement value from string.
     *
     * @param value the value.
     * @return the BiographicMatchingRequirement.
     * @throws IllegalArgumentException if the value is not recognised.
     */
    public static BiographicMatchingRequirement fromString(String value) {
        for (BiographicMatchingRequirement requirement : BiographicMatchingRequirement.values()) {
            if (requirement.getValue().equals(value)) {
                return requirement;
            }
        }
        throw new IllegalArgumentException("Unrecognised BiographicMatchingRequirement value: " + value);
    }
}
