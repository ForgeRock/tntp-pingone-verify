
/*
 * Copyright 2024-2025 Ping Identity Corporation. All Rights Reserved
 *
 * This code is to be used exclusively in connection with Ping Identity
 * Corporation software or services. Ping Identity Corporation only offers
 * such software or services to legal entities who have entered into a
 * binding license agreement with Ping Identity Corporation.
 */

package org.forgerock.am.tn.p1verify;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;

/**
 * Data Object for PingOne Verify Transaction API Request.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class VerifyRequestBody {

    private SendNotification sendNotification;
    private VerifyPolicy verifyPolicy;
    private Requirements requirements;
    private Redirect redirect;

    /**
     * Get the SendNotification.
     *
     * @return The SendNotification
     */
    public SendNotification getSendNotification() {
        return sendNotification;
    }

    /**
     * Set the SendNotification.
     *
     * @param sendNotification The SendNotification
     */
    public void setSendNotification(SendNotification sendNotification) {
        this.sendNotification = sendNotification;
    }

    /**
     * Get the VerifyPolicy.
     *
     * @return The VerifyPolicy
     */
    public VerifyPolicy getVerifyPolicy() {
        return verifyPolicy;
    }

    /**
     * Set the VerifyPolicy.
     *
     * @param verifyPolicy The VerifyPolicy
     */
    public void setVerifyPolicy(VerifyPolicy verifyPolicy) {
        this.verifyPolicy = verifyPolicy;
    }

    /**
     * Get the Requirements.
     *
     * @return The Requirements
     */
    public Requirements getRequirements() {
        return requirements;
    }

    /**
     * Set the Requirements.
     *
     * @param requirements The Requirements
     */
    public void setRequirements(Requirements requirements) {
        this.requirements = requirements;
    }

    /**
     * Get the Redirect.
     *
     * @return The Redirect
     */
    public Redirect getRedirect() {
        return redirect;
    }

    /**
     * Set the Redirect.
     *
     * @param redirect The Redirect
     */
    public void setRedirect(Redirect redirect) {
        this.redirect = redirect;
    }

    /**
     * The SendNotification data object.
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class SendNotification {
        private String phone;
        private String email;

        /**
         * Constructor for SendNotification data object.
         *
         * @param phone The phone
         * @param email The email
         */
        public SendNotification(String phone, String email) {
            this.phone = phone;
            this.email = email;
        }

        /**
         * Get the phone.
         *
         * @return The phone
         */
        @JsonInclude(JsonInclude.Include.NON_NULL)
        public String getPhone() {
            return phone;
        }

        /**
         * Set the phone.
         *
         * @param phone The phone
         */
        public void setPhone(String phone) {
            this.phone = phone;
        }

        /**
         * Get the email.
         *
         * @return The email
         */
        @JsonInclude(JsonInclude.Include.NON_NULL)
        public String getEmail() {
            return email;
        }

        /**
         * Set the email.
         *
         * @param email The email
         */
        public void setEmail(String email) {
            this.email = email;
        }
    }

    /**
     * The VerifyPolicy data object.
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class VerifyPolicy {
        private String id;

        /**
         * Constructor for VerifyPolicy data object.
         *
         * @param id The Verify Policy id
         */
        public VerifyPolicy(String id) {
            this.id = id;
        }

        /**
         * Get the Verify Policy id.
         *
         * @return The Verify Policy id.
         */
        public String getId() {
            return id;
        }

        /**
         * Set the Verify Policy id.
         *
         * @param id The Verify Policy id.
         */
        public void setId(String id) {
            this.id = id;
        }
    }

    /**
     * The SendNotification data object.
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonDeserialize(builder = Requirements.Builder.class)
    public static class Requirements {
        private Value referenceSelfie;
        private Value phone;
        private Options email;
        @JsonProperty("given_name")
        private Options givenName;
        @JsonProperty("family_name")
        private Value familyName;
        private Value name;
        private Options address;
        @JsonProperty("birth_date")
        private Value birthDate;

        /**
         * Get the referenceSelfie.
         *
         * @return The referenceSelfie
         */
        @JsonInclude(JsonInclude.Include.NON_NULL)
        public Value getReferenceSelfie() {
            return referenceSelfie;
        }

        /**
         * Get the phone.
         *
         * @return The phone
         */
        @JsonInclude(JsonInclude.Include.NON_NULL)
        public Value getPhone() {
            return phone;
        }

        /**
         * Get the email.
         *
         * @return The email
         */
        @JsonInclude(JsonInclude.Include.NON_NULL)
        public Options getEmail() {
            return email;
        }

        /**
         * Get the givenName.
         *
         * @return The givenName
         */
        @JsonInclude(JsonInclude.Include.NON_NULL)
        public Options getGivenName() {
            return givenName;
        }

        /**
         * Get the familyName.
         *
         * @return The familyName
         */
        @JsonInclude(JsonInclude.Include.NON_NULL)
        public Value getFamilyName() {
            return familyName;
        }

        /**
         * Get the name.
         *
         * @return The name
         */
        @JsonInclude(JsonInclude.Include.NON_NULL)
        public Value getName() {
            return name;
        }

        /**
         * Get the address.
         *
         * @return The address
         */
        @JsonInclude(JsonInclude.Include.NON_NULL)
        public Options getAddress() {
            return address;
        }

        /**
         * Get the birthDate.
         *
         * @return The birthDate
         */
        @JsonInclude(JsonInclude.Include.NON_NULL)
        public Value getBirthDate() {
            return birthDate;
        }

        @JsonPOJOBuilder(withPrefix = "set")
        public static class Builder {
            private Value referenceSelfie;
            private Value phone;
            private Options email;
            private Options givenName;
            private Value familyName;
            private Value name;
            private Options address;
            private Value birthDate;

            /**
             * Set the referenceSelfie.
             *
             * @param referenceSelfie The referenceSelfie
             * @return The Builder
             */
            public Builder setReferenceSelfie(Value referenceSelfie) {
                this.referenceSelfie = referenceSelfie;
                return this;
            }

            /**
             * Set the phone.
             *
             * @param phone The phone
             * @return The Builder
             */
            public Builder setPhone(Value phone) {
                this.phone = phone;
                return this;
            }

            /**
             * Set the email.
             *
             * @param email The email
             * @return The Builder
             */
            public Builder setEmail(Options email) {
                this.email = email;
                return this;
            }

            /**
             * Set the givenName.
             *
             * @param givenName The givenName
             * @return The Builder
             */
            public Builder setGivenName(Options givenName) {
                this.givenName = givenName;
                return this;
            }

            /**
             * Set the familyName.
             *
             * @param familyName The familyName
             * @return The Builder
             */
            public Builder setFamilyName(Value familyName) {
                this.familyName = familyName;
                return this;
            }

            /**
             * Set the name.
             *
             * @param name The name
             * @return The Builder
             */
            public Builder setName(Value name) {
                this.name = name;
                return this;
            }

            /**
             * Set the address.
             *
             * @param address The address
             * @return The Builder
             */
            public Builder setAddress(Options address) {
                this.address = address;
                return this;
            }

            /**
             * Set the birthDate.
             *
             * @param birthDate The birthDate
             * @return The Builder
             */
            public Builder setBirthDate(Value birthDate) {
                this.birthDate = birthDate;
                return this;
            }

            /**
             * Build the Requirements object.
             *
             * @return The Requirements object
             */
            public Requirements build() {
                Requirements requirements = new Requirements();
                requirements.referenceSelfie = this.referenceSelfie;
                requirements.phone = this.phone;
                requirements.email = this.email;
                requirements.givenName = this.givenName;
                requirements.familyName = this.familyName;
                requirements.name = this.name;
                requirements.address = this.address;
                requirements.birthDate = this.birthDate;
                return requirements;
            }
        }
    }

    /**
     * Value data object.
     */
    public static class Value {

        private String value;

        /**
         * Constructor for Value data object.
         *
         * @param value The value
         */
        public Value(String value) {
            this.value = value;
        }

        /**
         * Get the value.
         *
         * @return The value
         */
        public String getValue() {
            return value;
        }

        /**
         * Set the value.
         *
         * @param value The value
         */
        public void setValue(String value) {
            this.value = value;
        }

    }

    /**
     * Options object.
     */
    public static class Options {

        private List<String> options;

        /**
         * Constructor for Options object.
         *
         * @param options The options
         */
        public Options(List<String> options) {
            this.options = options;
        }

        /**
         * Constructor for Options object.
         *
         * @param option The options
         */
        public Options(String option) {
            this.options = List.of(option);
        }

        /**
         * Get the options.
         *
         * @return The options
         */
        public List<String> getOptions() {
            return options;
        }

        /**
         * Set the options.
         *
         * @param options The options
         */
        public void setOptions(List<String> options) {
            this.options = options;
        }

    }

    /**
     * The Redirect data object.
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class Redirect {
        private String url;
        private String message;

        /**
         * Constructor for Redirect data object.
         *
         * @param url     The url
         * @param message The message
         */
        public Redirect(String url, String message) {
            this.url = url;
            this.message = message;
        }

        /**
         * Get the url.
         *
         * @return The url
         */
        public String getUrl() {
            return url;
        }

        /**
         * Set the url.
         *
         * @param url The url
         */
        public void setUrl(String url) {
            this.url = url;
        }

        /**
         * Get the message.
         *
         * @return The message
         */
        public String getMessage() {
            return message;
        }

        /**
         * Set the message.
         *
         * @param message The message
         */
        public void setMessage(String message) {
            this.message = message;
        }
    }

}
