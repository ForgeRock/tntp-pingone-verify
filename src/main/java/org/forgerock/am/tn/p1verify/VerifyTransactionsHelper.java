/*
 * Copyright 2024-2025 Ping Identity Corporation. All Rights Reserved
 *
 * This code is to be used exclusively in connection with Ping Identity
 * Corporation software or services. Ping Identity Corporation only offers
 * such software or services to legal entities who have entered into a
 * binding license agreement with Ping Identity Corporation.
 */

package org.forgerock.am.tn.p1verify;

import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.Supported;
import org.forgerock.openam.annotations.SupportedAll;
import org.forgerock.openam.auth.service.marketplace.TNTPPingOneConfig;
import org.forgerock.openam.auth.service.marketplace.TNTPPingOneConfigChoiceValues;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static java.text.MessageFormat.format;

/**
 * Helper for handling the retrieval of a user's verified transactions.
 * To be used with the PingOneVerifyCompletionDecisionNode script.
 */
@Supported(scriptingApi = true, javaApi = false)
public class VerifyTransactionsHelper {

    private static final Logger logger = LoggerFactory.getLogger(VerifyTransactionsHelper.class);

    private final PingOneVerifyCompletionDecisionNode.Config config;
    private final TNTPPingOneConfig tntpPingOneConfig;
    private final String accessToken;
    private final String pingOneUserId;
    private final Helper client;

    /**
     * Constructor for the VerifyTransactionsHelper.
     *
     * @param accessToken          Access token for the user.
     * @param pingOneUserId        PingOne user ID.
     */
    public VerifyTransactionsHelper(PingOneVerifyCompletionDecisionNode.Config config,
                                    Helper client,
                                    String accessToken,
                                    String pingOneUserId) {
        this.config = config;
        this.tntpPingOneConfig = TNTPPingOneConfigChoiceValues.getTNTPPingOneConfig(config.tntpPingOneConfigName());
        this.client = client;
        this.accessToken = accessToken;
        this.pingOneUserId = pingOneUserId;
    }

    /**
     * Retrieves all the user's Verify transactions.
     *
     * @return The user's Verify transactions.
     * @throws ScriptedVerifyTransactionsException if an error occurs while retrieving the transactions.
     */
    @Supported(scriptingApi = true, javaApi = false)
    public Map<String, Object> getAllVerifyTransactions() throws ScriptedVerifyTransactionsException {
        try {
            String uri = Constants.endpoint
                    + tntpPingOneConfig.environmentRegion().getDomainSuffix()
                    + "/v1/environments/" + tntpPingOneConfig.environmentId()
                    + "/users/" + pingOneUserId + "/verifyTransactions";
            return client.makeHTTPClientCall(accessToken, uri, "GET", null).asMap();
        } catch (Exception e) {
            throw new ScriptedVerifyTransactionsException(
                    format("Error retrieving Verify transactions for user: {0}", pingOneUserId), e);
        }
    }

    /**
     * Retrieves the user's last Verify transaction.
     *
     * @return The user's Verify transaction.
     * @throws ScriptedVerifyTransactionsException if an error occurs while retrieving the transaction.
     */
    @Supported(scriptingApi = true, javaApi = false)
    public Map<String, Object> getLastVerifyTransaction() throws ScriptedVerifyTransactionsException {
        try {
            logger.error("INSIDE METHOD - getLastVerifyTransaction");
            // Build the API endpoint URL.
            String uri = Constants.endpoint
                    + tntpPingOneConfig.environmentRegion().getDomainSuffix()
                    + "/v1/environments/" + tntpPingOneConfig.environmentId()
                    + "/users/" + pingOneUserId + "/verifyTransactions";

            logger.error("LAST TRANSACTION URI: {}", uri);

            // Make the HTTP GET call.
            JsonValue response = client.makeHTTPClientCall(accessToken, uri, "GET", null);

            logger.error("LAST TRANSACTION RESPONSE: {}", response);

            // Extract the _embedded object.
            JsonValue embedded = response.get("_embedded");

            logger.error("LAST TRANSACTION _EMBEDDED: {}", embedded);

            if (embedded == null || !embedded.isDefined("verifyTransactions")) {
                // No embedded transactions found; return an empty map.
                logger.debug("No verify transactions found for user: {}", pingOneUserId);
                logger.error("No verify transactions found for user: {}", pingOneUserId);
                return Collections.emptyMap();
            }

            // Get the list of transactions.
            List<JsonValue> transactions = embedded.get("verifyTransactions")
                    .asList()
                    .stream()
                    .map(JsonValue::new)
                    .collect(Collectors.toList());

            logger.error("LAST TRANSACTIONS LIST: {}", transactions);

            if (transactions.isEmpty()) {
                logger.debug("Verify transactions list is empty for user: {}", pingOneUserId);
                logger.error("Verify transactions list is empty for user: {}", pingOneUserId);
                return Collections.emptyMap();
            }

            // Determine the "last" transaction by comparing the "updatedAt" values.
            // This code uses Java's Instant.parse() method to convert ISO-8601 timestamps into an Instant.
            JsonValue lastTransaction = transactions.stream()
                    .max((t1, t2) -> {
                        // Extract the updatedAt timestamp strings for each transaction.
                        String updatedAt1 = t1.get("updatedAt").asString();
                        String updatedAt2 = t2.get("updatedAt").asString();
                        // Parse the timestamp strings into Instant objects.
                        Instant instant1 = Instant.parse(updatedAt1);
                        Instant instant2 = Instant.parse(updatedAt2);
                        // Compare the two Instants.
                        return instant1.compareTo(instant2);
                    })
                    .orElse(transactions.get(0));  // Fallback to the first element if none found

            // Log the chosen transaction for debugging purposes.
            logger.debug("Selected last transaction for user {}: {}", pingOneUserId, lastTransaction);
            logger.error("Selected last transaction for user {}: {}", pingOneUserId, lastTransaction);

            logger.error("LEAVING METHOD - getLastVerifyTransaction");

            // Return the last transaction as a Map.
            return lastTransaction.asMap();
        } catch (Exception e) {
            throw new ScriptedVerifyTransactionsException(format("Error retrieving last Verify transaction for user: {0}", pingOneUserId), e);
        }
    }

    /**
     * Retrieves all the metadata for a transaction.
     *
     * @param transactionId The transaction ID.
     * @return The metadata for the transaction.
     * @throws ScriptedVerifyTransactionsException if an error occurs while retrieving the metadata.
     */
    @Supported(scriptingApi = true, javaApi = false)
    public Map<String, Object> getAllMetadata(String transactionId) throws ScriptedVerifyTransactionsException {
        try {
            String uri = Constants.endpoint
                    + tntpPingOneConfig.environmentRegion().getDomainSuffix()
                    + "/v1/environments/" + tntpPingOneConfig.environmentId()
                    + "/users/" + pingOneUserId
                    + "/verifyTransactions/" + transactionId + "/metaData";

            JsonValue response = client.makeHTTPClientCall(accessToken, uri, "GET", null);

            return response.asMap();
        } catch (Exception e) {
            throw new ScriptedVerifyTransactionsException(
                    format("Error retrieving metadata for transaction: {0}", transactionId), e);
        }
    }

    /**
     * Retrieves the list of all verified data for a transaction.
     * This returns the data submitted for each verification attempt
     * within a short timeframe (usually 30 minutes after a verification decision is reached).
     *
     * @param transactionId The transaction ID.
     * @return The verified data for the transaction as a Map.
     * @throws ScriptedVerifyTransactionsException if an error occurs while retrieving the verified data.
     */
    @Supported(scriptingApi = true, javaApi = false)
    public Map<String, Object> getAllVerifiedData(String transactionId) throws ScriptedVerifyTransactionsException {
        try {
            String uri = Constants.endpoint
                    + tntpPingOneConfig.environmentRegion().getDomainSuffix()
                    + "/v1/environments/" + tntpPingOneConfig.environmentId()
                    + "/users/" + pingOneUserId
                    + "/verifyTransactions/" + transactionId + "/verifiedData";

            JsonValue response = client.makeHTTPClientCall(accessToken, uri, "GET", null);

            // Convert the JsonValue response to a Map and return it.
            return response.asMap();
        } catch (Exception e) {
            throw new ScriptedVerifyTransactionsException(
                    format("Error retrieving verified data for transaction: {0}", transactionId), e);
        }
    }

    /**
     * Retrieves a single verified data submitted for a transaction.
     * The response differs based on the type of the verified data.
     * The data is available for a short timeframe, usually 30 minutes
     * after a verification decision is reached.
     *
     * @param transactionId  The transaction ID.
     * @param verifiedDataId The verified data ID.
     * @return The verified data for the transaction as a Map.
     * @throws ScriptedVerifyTransactionsException if an error occurs while retrieving the verified data.
     */
    @Supported(scriptingApi = true, javaApi = false)
    public Map<String, Object> getVerifiedData(String transactionId, String verifiedDataId)
            throws ScriptedVerifyTransactionsException {
        try {
            String uri = Constants.endpoint
                    + tntpPingOneConfig.environmentRegion().getDomainSuffix()
                    + "/v1/environments/" + tntpPingOneConfig.environmentId()
                    + "/users/" + pingOneUserId
                    + "/verifyTransactions/" + transactionId
                    + "/verifiedData/" + verifiedDataId;

            JsonValue response = client.makeHTTPClientCall(accessToken, uri, "GET", null);

            return response.asMap();
        } catch (Exception e) {
            throw new ScriptedVerifyTransactionsException(
                    format("Error retrieving verified data for transaction: {0}", transactionId), e);
        }
    }


    /**
     * Retrieves the complete data for a type of verified data submitted for a transaction.
     * The data is available for a short timeframe, usually 30 minutes after a verification decision is reached.
     * <p>
     * The type of personally identifiable information (PII) can be one of:
     * GOVERNMENT_ID, BARCODE, FRONT_IMAGE, BACK_IMAGE, SELFIE, CROPPED_SIGNATURE, CROPPED_DOCUMENT,
     * CROPPED_PORTRAIT, VOICE_SAMPLE, VOICE_INPUT, or END_USER_CLIENT.
     *
     * @param transactionId The transaction ID.
     * @param type          The type of the verified data, provided as a comma-delimited string with no spaces.
     * @return The verified data for the transaction as a Map.
     * @throws ScriptedVerifyTransactionsException if an error occurs while retrieving the verified data.
     */
    @Supported(scriptingApi = true, javaApi = false)
    public Map<String, Object> getVerifiedDataByType(String transactionId, String type)
            throws ScriptedVerifyTransactionsException {
        try {
            String uri = Constants.endpoint
                    + tntpPingOneConfig.environmentRegion().getDomainSuffix()
                    + "/v1/environments/" + tntpPingOneConfig.environmentId()
                    + "/users/" + pingOneUserId + "/verifyTransactions/" + transactionId
                    + "/verifiedData?type=" + type;

            // Make the HTTP GET call using your HTTP client helper.
            JsonValue response = client.makeHTTPClientCall(accessToken, uri, "GET", null);

            // Return the response as a Map.
            return response.asMap();
        } catch (Exception e) {
            throw new ScriptedVerifyTransactionsException(
                    format("Error retrieving verified data for transaction: {0}", transactionId), e);
        }
    }

    /**
     * Retrieves the PingOne user's profile using an HTTP GET request.
     *
     * @return The user's profile as a Map.
     * @throws ScriptedVerifyTransactionsException if an error occurs while retrieving the user.
     */
    @Supported(scriptingApi = true, javaApi = false)
    public Map<String, Object> getUser() throws ScriptedVerifyTransactionsException {
        try {
            // Build the API endpoint URL for retrieving the user profile.
            // Endpoint: {Constants.endpoint}{domainSuffix}/v1/environments/{environmentId}/users/{pingOneUserId}
            String uri = Constants.endpoint
                    + tntpPingOneConfig.environmentRegion().getDomainSuffix()
                    + "/v1/environments/" + tntpPingOneConfig.environmentId()
                    + "/users/" + pingOneUserId;

            JsonValue response = client.makeHTTPClientCall(accessToken, uri, "GET", null);

            // Convert the JSON response to a Map and return.
            return response.asMap();
        } catch (Exception e) {
            throw new ScriptedVerifyTransactionsException(
                    format("Error retrieving user: {0}", pingOneUserId), e);
        }
    }

    /**
     * Updates the PingOne user's profile by sending the new user data via an HTTP PUT request.
     *
     * @param body The user data to be updated as a Map.
     * @return The updated user's profile as a Map.
     * @throws ScriptedVerifyTransactionsException if an error occurs while updating the user.
     */
    @Supported(scriptingApi = true, javaApi = false)
    public Map<String, Object> updateUser(Map<String, Object> body) throws ScriptedVerifyTransactionsException {
        try {
            if (body == null || body.isEmpty()) {
                throw new ScriptedVerifyTransactionsException(
                        format("No data provided to update the user: {0}", pingOneUserId), null);
            }
            // Build the API endpoint URL for updating the user.
            // Endpoint: {Constants.endpoint}{domainSuffix}/v1/environments/{environmentId}/users/{pingOneUserId}
            String uri = Constants.endpoint
                    + tntpPingOneConfig.environmentRegion().getDomainSuffix()
                    + "/v1/environments/" + tntpPingOneConfig.environmentId()
                    + "/users/" + pingOneUserId;

            // Convert the update data to JSON
//            JsonValue requestBody = JsonValueBuilder.toJsonValue(JsonValueBuilder.getObjectMapper().writeValueAsString(body));
            JsonValue requestBody = (JsonValue) body;
            // Make the HTTP PUT call with the requestBody.
            JsonValue response = client.makeHTTPClientCall(accessToken, uri, "PUT", requestBody);
            return response.asMap();
        } catch (Exception e) {
            throw new ScriptedVerifyTransactionsException(
                    format("Error updating user: {0}", pingOneUserId), e);
        }
    }

    /**
     * Deletes the PingOne user via an HTTP DELETE request.
     *
     * @throws ScriptedVerifyTransactionsException if an error occurs while deleting the user.
     */
    @Supported(scriptingApi = true, javaApi = false)
    public void deleteUser() throws ScriptedVerifyTransactionsException {
        try {
            // Build the API endpoint URL for deleting the user.
            // Endpoint: {Constants.endpoint}{domainSuffix}/v1/environments/{environmentId}/users/{pingOneUserId}
            String uri = Constants.endpoint
                    + tntpPingOneConfig.environmentRegion().getDomainSuffix()
                    + "/v1/environments/" + tntpPingOneConfig.environmentId()
                    + "/users/" + pingOneUserId;

            // Make the HTTP DELETE call; no response is needed.
            client.makeHTTPClientCall(accessToken, uri, "DELETE", null);
        } catch (Exception e) {
            throw new ScriptedVerifyTransactionsException(
                    format("Error deleting user: {0}", pingOneUserId), e);
        }
    }

    /**
     * Exception thrown when an error occurs while retrieving verified transactions.
     */
    @SupportedAll(scriptingApi = true, javaApi = false)
    public static class ScriptedVerifyTransactionsException extends Exception {

        /**
         * Constructs a new instance of the exception with the specified message.
         *
         * @param message the message
         * @param cause the cause
         */
        public ScriptedVerifyTransactionsException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
