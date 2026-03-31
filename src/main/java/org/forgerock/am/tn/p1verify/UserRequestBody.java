/*
 * Copyright 2024-2025 Ping Identity Corporation. All Rights Reserved
 *
 * This code is to be used exclusively in connection with Ping Identity
 * Corporation software or services. Ping Identity Corporation only offers
 * such software or services to legal entities who have entered into a
 * binding license agreement with Ping Identity Corporation.
 */

package org.forgerock.am.tn.p1verify;

import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * Data Object for PingOne User API Request.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class UserRequestBody {

    private String email;
    private Name name;
    private Population population;
    private String username;
    private String primaryPhone;
    private Address address;
    private String preferredLanguage;

    /**
     * Get the user email.
     *
     * @return The user email.
     */
    public String getEmail() {
        return email;
    }

    /**
     * Set the user email.
     *
     * @param email The user email.
     */
    public void setEmail(String email) {
        this.email = email;
    }

    /**
     * Get the Name data object.
     *
     * @return The Name data object.
     */
    public Name getName() {
        return name;
    }

    /**
     * Set the Name data object.
     *
     * @param name The Name data object.
     */
    public void setName(Name name) {
        this.name = name;
    }

    /**
     * Get the Population data object.
     *
     * @return The Population data object.
     */
    public Population getPopulation() {
        return population;
    }

    /**
     * Set the Population data object.
     *
     * @param population The Population data object.
     */
    public void setPopulation(Population population) {
        this.population = population;
    }

    /**
     * Get the username.
     *
     * @return The username.
     */
    public String getUsername() {
        return username;
    }

    /**
     * Set the username.
     *
     * @param username The username.
     */
    public void setUsername(String username) {
        this.username = username;
    }

    /**
     * Get the primary phone.
     *
     * @return The primary phone.
     */
    public String getPrimaryPhone() {
        return primaryPhone;
    }

    /**
     * Set the primary phone.
     *
     * @param primaryPhone The primary phone.
     */
    public void setPrimaryPhone(String primaryPhone) {
        this.primaryPhone = primaryPhone;
    }

    /**
     * Get the Address data object.
     *
     * @return The Address data object.
     */
    public Address getAddress() {
        return address;
    }

    /**
     * Set the Address data object.
     *
     * @param address The Address data object.
     */
    public void setAddress(Address address) {
        this.address = address;
    }

    /**
     * Get the preferred language.
     * @return The user preferred language.
     */
    public String getPreferredLanguage() {
        return preferredLanguage;
    }

    /**
     * Set the preferred language.
     * @param preferredLanguage The user preferred language.
     */
    public void setPreferredLanguage(String preferredLanguage) {
        this.preferredLanguage = preferredLanguage;
    }

    /**
     * The Name data object.
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class Name {

        private String formatted;
        private String given;
        private String family;

        /**
         * Constructor for Name.
         *
         * @param formatted The formatted name.
         * @param given The given name.
         * @param family The family name.
         */
        public Name(String formatted, String given, String family) {
            this.formatted = formatted;
            this.given = given;
            this.family = family;
        }

        /**
         * Get the formatted name.
         *
         * @return The formatted name.
         */
        public String getFormatted() {
            return formatted;
        }

        /**
         * Set the formatted name.
         *
         * @param formatted The formatted name.
         */
        public void setFormatted(String formatted) {
            this.formatted = formatted;
        }

        /**
         * Get the given name.
         *
         * @return The given name.
         */
        public String getGiven() {
            return given;
        }

        /**
         * Set the given name.
         *
         * @param given The given name.
         */
        public void setGiven(String given) {
            this.given = given;
        }

        /**
         * Get the family name.
         *
         * @return The family name.
         */
        public String getFamily() {
            return family;
        }

        /**
         * Set the family name.
         *
         * @param family The family name.
         */
        public void setFamily(String family) {
            this.family = family;
        }
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class Population {
        private String id;

        /**
         * Constructor for Population data object.
         *
         * @param id The population ID.
         */
        public Population(String id) {
            this.id = id;
        }

        /**
         * Get the population ID.
         * @return The population ID.
         */
        public String getId() {
            return id;
        }

        /**
         * Set the population ID.
         * @param id The population ID.
         */
        public void setId(String id) {
            this.id = id;
        }
    }

    /**
     * The Address data object.
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class Address {
        private String streetAddress;
        private String locality;
        private String region;
        private String postalCode;
        private String countryCode;

        /**
         * Constructor for Address data object.
         *
         * @param streetAddress The street address.
         * @param locality The locality.
         * @param region The region.
         * @param postalCode The postal code.
         * @param countryCode The country code.
         */
        public Address(String streetAddress, String locality, String region, String postalCode, String countryCode) {
            this.streetAddress = streetAddress;
            this.locality = locality;
            this.region = region;
            this.postalCode = postalCode;
            this.countryCode = countryCode;
        }

        /**
         * Get the street address.
         *
         * @return The street address.
         */
        public String getStreetAddress() {
            return streetAddress;
        }

        /**
         * Set the street address.
         *
         * @param streetAddress The street address.
         */
        public void setStreetAddress(String streetAddress) {
            this.streetAddress = streetAddress;
        }

        /**
         * Get the locality.
         *
         * @return The locality.
         */
        public String getLocality() {
            return locality;
        }

        /**
         * Set the locality.
         *
         * @param locality The locality.
         */
        public void setLocality(String locality) {
            this.locality = locality;
        }

        /**
         * Get the region.
         *
         * @return The region.
         */
        public String getRegion() {
            return region;
        }

        /**
         * Set the region.
         *
         * @param region The region.
         */
        public void setRegion(String region) {
            this.region = region;
        }

        /**
         * Get the postal code.
         *
         * @return The postal code.
         */
        public String getPostalCode() {
            return postalCode;
        }

        /**
         * Set the postal code.
         *
         * @param postalCode The postal code.
         */
        public void setPostalCode(String postalCode) {
            this.postalCode = postalCode;
        }

        /**
         * Get the country code.
         *
         * @return The country code.
         */
        public String getCountryCode() {
            return countryCode;
        }

        /**
         * Set the country code.
         *
         * @param countryCode The country code.
         */
        public void setCountryCode(String countryCode) {
            this.countryCode = countryCode;
        }
    }

}
