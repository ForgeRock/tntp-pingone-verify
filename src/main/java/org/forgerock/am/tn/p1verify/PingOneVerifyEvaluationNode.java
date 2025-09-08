/*
 * Copyright 2024-2025 Ping Identity Corporation. All Rights Reserved
 *
 * This code is to be used exclusively in connection with Ping Identity
 * Corporation software or services. Ping Identity Corporation only offers
 * such software or services to legal entities who have entered into a
 * binding license agreement with Ping Identity Corporation.
 */

package org.forgerock.am.tn.p1verify;

import static java.util.concurrent.TimeUnit.SECONDS;
import static java.lang.String.format;
import static org.forgerock.am.tn.p1verify.UserHelper.*;
import static org.forgerock.openam.auth.node.api.Action.goTo;
import static org.forgerock.openam.auth.node.api.Action.send;
import static org.forgerock.am.tn.p1verify.FailureReason.ACCESS_TOKEN;
import static org.forgerock.am.tn.p1verify.FailureReason.IDENTITY_NOT_FOUND;
import static org.forgerock.am.tn.p1verify.FailureReason.IDENTITY_VERIFICATION_FAILED;
import static org.forgerock.am.tn.p1verify.FailureReason.INVALID_BIOGRAPHIC_MATCHING;
import static org.forgerock.am.tn.p1verify.FailureReason.JSON_PROCESSING_ERROR;
import static org.forgerock.am.tn.p1verify.FailureReason.MISSING_PINGONE_USER_ID_FROM_SHARED_STATE;
import static org.forgerock.am.tn.p1verify.FailureReason.MISSING_PINGONE_VERIFY_TRANSACTION_ID;
import static org.forgerock.am.tn.p1verify.FailureReason.REDIRECT_FLOW_FAILED_CODE_MISMATCH;
import static org.forgerock.am.tn.p1verify.FailureReason.REDIRECT_FLOW_FAILED_MISSING_CODE;
import static org.forgerock.am.tn.p1verify.FailureReason.UNEXPECTED_ERROR;
import static org.forgerock.am.tn.p1verify.FailureReason.UNEXPECTED_VERIFY_STATUS;
import static org.forgerock.am.tn.p1verify.FailureReason.getFailureJson;
import static org.forgerock.am.tn.p1verify.PingOneConstants.PINGONE_USER_ID_KEY;
import static org.forgerock.am.tn.p1verify.PingOneConstants.PINGONE_VERIFY_DELIVERY_METHOD_KEY;
import static org.forgerock.am.tn.p1verify.PingOneConstants.PINGONE_VERIFY_EVALUATION_FAILURE_REASON_KEY;
import static org.forgerock.am.tn.p1verify.PingOneConstants.PINGONE_VERIFY_METADATA_KEY;
import static org.forgerock.am.tn.p1verify.PingOneConstants.PINGONE_VERIFY_REDIRECT_FLOW_CODE_KEY;
import static org.forgerock.am.tn.p1verify.PingOneConstants.PINGONE_VERIFY_TIMEOUT_KEY;
import static org.forgerock.am.tn.p1verify.PingOneConstants.PINGONE_VERIFY_TRANSACTION_ID_KEY;
import static org.forgerock.am.tn.p1verify.PingOneConstants.PINGONE_VERIFY_VERIFIED_DATA_KEY;
import static org.forgerock.am.tn.p1verify.PingOneVerifyEvaluationNode.OutcomeProvider.FAILURE_OUTCOME_ID;
import static org.forgerock.am.tn.p1verify.PingOneVerifyEvaluationNode.OutcomeProvider.SUCCESS_OUTCOME_ID;
import static org.forgerock.am.tn.p1verify.PingOneVerifyEvaluationNode.OutcomeProvider.TIMEOUT_OUTCOME_ID;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.REALM;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;
import static org.forgerock.am.tn.p1verify.Constants.RESPONSE_CODE;
import static org.forgerock.am.tn.p1verify.Constants.RESPONSE_STATUS;
import static org.forgerock.am.tn.p1verify.Constants.RESPONSE_TRANSACTION_ID;
import static org.forgerock.am.tn.p1verify.Constants.RESPONSE_TRANSACTION_STATUS;
import static org.forgerock.am.tn.p1verify.Constants.RESPONSE_URL;
import static org.forgerock.openam.http.HttpConstants.Methods.GET;

import java.net.URISyntaxException;
import java.util.*;
import java.time.Duration;

import javax.inject.Inject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.ConfirmationCallback;
import javax.security.auth.callback.TextOutputCallback;

import com.sun.identity.authentication.spi.RedirectCallback;
import org.forgerock.am.identity.application.IdentityNotFoundException;
import org.forgerock.http.MutableUri;
import org.forgerock.http.protocol.Form;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.sm.annotations.adapters.TimeUnit;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.*;
import org.forgerock.openam.auth.nodes.helpers.LocalizationHelper;
import org.forgerock.openam.authentication.callbacks.PollingWaitCallback;
import org.forgerock.openam.auth.service.marketplace.TNTPPingOneConfig;
import org.forgerock.openam.auth.service.marketplace.TNTPPingOneConfigChoiceValues;
import org.forgerock.openam.auth.service.marketplace.TNTPPingOneUtility;
import org.forgerock.openam.integration.idm.IdmIntegrationService;
import org.forgerock.openam.core.CoreWrapper;
import org.forgerock.openam.core.realms.Realm;
import org.forgerock.openam.utils.JsonValueBuilder;
import org.forgerock.openam.utils.StringUtils;
import org.forgerock.openam.utils.qr.GenerationUtils;
import org.forgerock.util.annotations.VisibleForTesting;
import org.forgerock.util.i18n.PreferredLocales;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.google.common.collect.ImmutableList;
import com.google.inject.assistedinject.Assisted;
import com.iplanet.sso.SSOException;
import com.sun.identity.authentication.callbacks.HiddenValueCallback;
import com.sun.identity.authentication.callbacks.ScriptTextOutputCallback;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdRepoException;

/**
 * The PingOne Verify Evaluation node allows to process an Identity Verification for the user on the PingOne platform.
 */
@Node.Metadata(
		outcomeProvider = PingOneVerifyEvaluationNode.OutcomeProvider.class,
		configClass = PingOneVerifyEvaluationNode.Config.class,
		tags = {"marketplace", "trustnetwork" }
)
public class PingOneVerifyEvaluationNode implements Node {

	/** How often to poll AM for a response in milliseconds. */
	public static final int TRANSACTION_POLL_INTERVAL = 5000;

	/** The id of the HiddenCallback containing the URI. */
	public static final String HIDDEN_CALLBACK_ID = "pingOneVerifyTransactionUri";

	private static final Logger logger = LoggerFactory.getLogger(PingOneVerifyEvaluationNode.class);
	private static final String BUNDLE = PingOneVerifyEvaluationNode.class.getName();

	static final String DEFAULT_DELIVERY_METHOD_MESSAGE_KEY = "default.deliveryMethodMessage";
	static final String DEFAULT_WAITING_MESSAGE_KEY = "default.waitingMessage";
	static final String DEFAULT_SCAN_QRCODE_MESSAGE_KEY = "default.scanQRCodeMessage";
	static final String DEFAULT_REDIRECT_MESSAGE_KEY = "default.redirectMessage";

	static final String QR_CALLBACK_STRING = "callback_0";
	static final int DEFAULT_TIMEOUT = 120;

	private final CoreWrapper coreWrapper;
	private final Helper client;
	private final TNTPPingOneConfig tntpPingOneConfig;
	private final Config config;
	private final Realm realm;
	private final UserHelper userHelper;
	private final LocalizationHelper localizationHelper;
	private final IdmIntegrationService idmIntegrationService;

	/**
	 * Configuration for the node.
	 */
	public interface Config {
		/**
		 * Reference to the PingOne Worker App.
		 *
		 * @return The PingOne Worker App.
		 */
		@Attribute(order = 100, choiceValuesClass = TNTPPingOneConfigChoiceValues.class)
		default String tntpPingOneConfigName() {
			return TNTPPingOneConfigChoiceValues.createTNTPPingOneConfigName("Global Default");
		};

		/**
		 * PingOne Verify Policy ID.
		 *
		 * @return The Verify Policy ID as String.
		 */
		@Attribute(order = 200)
		default String verifyPolicyId() {
			return "";
		}

		/**
		 * The Verify URL delivery method.
		 *
		 * @return The type of delivery method.
		 */
		@Attribute(order = 300)
		default DeliveryMethod deliveryMethod() {
			return DeliveryMethod.QRCODE;
		}

		/**
		 * Allow user to choose the URL delivery method.
		 *
		 * @return true if user will be prompted for delivery method, false otherwise.
		 */
		@Attribute(order = 400)
		default boolean allowDeliveryMethodSelection() {
			return false;
		}

		/**
		 * The message to display to the user allowing them to choose the delivery method. Keyed on the locale.
		 * Falls back to default.deliverMethodMessage.
		 *
		 * @return The message to display while choosing the delivery method.
		 */
		@Attribute(order = 500)
		default Map<Locale, String> deliveryMethodMessage() {
			return Collections.emptyMap();
		}

		/**
		 * The message to displayed to user to scan the QR code. Keyed on the locale. Falls back to
		 * default.scanQRCodeMessage.
		 *
		 * @return The mapping of locales to scan QR code messages.
		 */
		@Attribute(order = 600)
		default Map<Locale, String> scanQRCodeMessage() {
			return Collections.emptyMap();
		}

		/**
		 * The message to display to the user while waiting, keyed on the locale. Falls back to default.waitingMessage.
		 *
		 * @return The message to display on the waiting indicator.
		 */
		@Attribute(order = 700)
		default Map<Locale, String> waitingMessage() {
			return Collections.emptyMap();
		}

		/**
		 * The message to display to the user while redirecting from PingOne Verify web app, keyed on the locale.
		 * Falls back to default.redirectMessage.
		 *
		 * @return The message to display on the redirect.
		 */
		@Attribute(order = 800)
		default Map<Locale, String> redirectMessage() {
			return Collections.emptyMap();
		}

		/**
		 * The timeout in seconds for the verification process.
		 *
		 * @return The timeout in seconds.
		 */
		@Attribute(order = 900)
		@TimeUnit(SECONDS)
		default Duration timeout() {
			return Duration.ofSeconds(DEFAULT_TIMEOUT);
		}

		/**
		 * The Biographic Matching mapping. The Key is the requirement. The Value AM attribute name. If empty, no
		 * Biographic Matching verification is performed.
		 * Examples:
		 * "name" -> "cn"
		 * "email" -> "mail"
		 * "phone" -> "telephoneNumber"
		 * "given_name" -> "givenName"
		 * "family_name" -> "sn"
		 *
		 * @return the mapping for the Biographic Matching.
		 */
		@Attribute(order = 1000)
		default Map<String, String> biographicMatching() {
			return Collections.emptyMap();
		}

		/**
		 * Create a PingOne user if one does not already exist.
		 * If disabled, the node expects a PingOne user ID to be provided in shared state.
		 *
		 * @return true if the node should create a PingOne user, false otherwise.
		 */
		@Attribute(order = 1100)
		default boolean createPingOneUser() {
			return true;
		}

		/**
		 * The PingOne population ID to assign the user to when creating a new PingOne user.
		 * If not specified, the environment's default population is used.
		 *
		 * @return the PingOne population ID.
		 */
		@Attribute(order = 1200)
		default String populationId() {
			return "";
		}

		/**
		 * Whether the created PingOne user should be anonymized.
		 * An anonymized user only stores minimal identifying information (username and language).
		 *
		 * @return true if the created user should be anonymized, false otherwise.
		 */
		@Attribute(order = 1300)
		default boolean anonymizedUser() {
			return true;
		}

		/**
		 * Whether to source user attributes from shared state instead of
		 * retrieving them from an AM identity profile.
		 *
		 * Affects:
		 * - PingOne user creation (when createPingOneUser is enabled)
		 * - Delivery method attributes (EMAIL, SMS) for Verify transactions
		 * - Biographic matching attribute resolution
		 *
		 * @return true if attributes come from shared state, false otherwise.
		 */
		@Attribute(order = 1400)
		default boolean userAttributesFromSharedState() {
			return true;
		}

		/**
		 * The AM identity attribute used as the key when looking up an existing AM identity
		 * (for example: uid, mail, or another attribute).
		 * Only applies when {@code userAttributesFromSharedState} is false.
		 *
		 * @return the AM identity attribute to use as the lookup key.
		 */
		@Attribute(order = 1500)
		default String amIdentityAttribute() {
			return DEFAULT_AM_IDENTITY_ATTRIBUTE; // = uid
		}

		/**
		 * Store the verification metadata in the shared state.
		 *
		 * @return true if the metadata should be stored, false otherwise.
		 */
		@Attribute(order = 1600)
		default boolean storeVerificationMetadata() {
			return false;
		}

		/**
		 * Store the verified data in the shared state.
		 *
		 * @return true if the verified data should be stored, false otherwise.
		 */
		@Attribute(order = 1700)
		default boolean storeVerifiedData() {
			return false;
		}

		/**
		 * If the node fail, the error detail will be provided in the shared state for analysis by later nodes.
		 *
		 * @return true if the failure will be captured.
		 */
		@Attribute(order = 1800)
		default boolean captureFailure() {
			return false;
		}
	}

	/**
	 * The PingOne Verify Evaluation node constructor.
	 *
	 * @param config               the node configuration.
	 * @param realm                the realm.
	 * @param userHelper           the {@link UserHelper} instance.
	 * @param localizationHelper   the localization helper class.
	 */
	@Inject
	public PingOneVerifyEvaluationNode(@Assisted Config config, @Assisted Realm realm, CoreWrapper coreWrapper, Helper client, UserHelper userHelper, LocalizationHelper localizationHelper, IdmIntegrationService idmIntegrationService) {
		this.coreWrapper = coreWrapper;
		this.config = config;
		this.realm = realm;
		this.tntpPingOneConfig = TNTPPingOneConfigChoiceValues.getTNTPPingOneConfig(config.tntpPingOneConfigName());
		this.client = client;
		this.userHelper = userHelper;
		this.localizationHelper = localizationHelper;
		this.idmIntegrationService = idmIntegrationService;
	}

	/**
	 * Executes the node by:
	 * 1. Acquiring an access token
	 * 2. Ensuring a PingOne user ID (optionally creating a user if configured)
	 * 3. Finally, starts or advances a PingOne Verify transaction based on callbacks and shared state.
	 *
	 * @param context the current tree context
	 *
	 * @return the next {@link Action} for the journey
	 */
	@Override
	public Action process(TreeContext context) {
		logger.debug("PingOneVerifyEvaluationNode started.");

		NodeState nodeState = context.getStateFor(this);

		try {
			// Obtain PingOne access token
			TNTPPingOneUtility tntpP1U = TNTPPingOneUtility.getInstance();
			String accessToken = tntpP1U.getAccessToken(realm, tntpPingOneConfig);
			if (accessToken == null) {
				return handleFailure(nodeState, ACCESS_TOKEN, null);
			}

			// Ensure we have a PingOne User ID
			String pingOneUserId = getPingOneUserId(context, nodeState, accessToken);
			if (StringUtils.isBlank(pingOneUserId)) {
				return handleFailure(nodeState, MISSING_PINGONE_USER_ID_FROM_SHARED_STATE, null);
			}

			logger.error("process - Using PingOne userId: {}", pingOneUserId);

			// Check if a delivery method was chosen
			Optional<ConfirmationCallback> confirmationCallback = context.getCallback(ConfirmationCallback.class);
			if (confirmationCallback.isPresent()) {
				logger.debug("Retrieving selected delivery method and start a new Identity Verification process.");
				int choice = confirmationCallback.get().getSelectedIndex();
				nodeState.putShared(PINGONE_VERIFY_DELIVERY_METHOD_KEY, choice);
				return startVerifyTransaction(context, accessToken, DeliveryMethod.fromIndex(choice), pingOneUserId);
			}

			// Check if transaction was started
			Optional<PollingWaitCallback> pollingWaitCallback = context.getCallback(PollingWaitCallback.class);
			if (pollingWaitCallback.isPresent()) {
				// Transaction already started
				logger.debug("Identity Verification process already started. Waiting for completion...");
				if (!nodeState.isDefined(PINGONE_VERIFY_TRANSACTION_ID_KEY)) {
					return handleFailure(nodeState, MISSING_PINGONE_VERIFY_TRANSACTION_ID, null);
				}
				return getActionFromVerifyTransactionStatus(context, accessToken, pingOneUserId);
			} else {
				// Check if it should handle a redirect flow
				if (nodeState.isDefined(PINGONE_VERIFY_REDIRECT_FLOW_CODE_KEY)) {
					logger.debug("Handling redirect flow.");
					if (context.request.parameters.containsKey("code")) {
						String code = context.request.parameters.get("code").get(0);
						if (code.equals(nodeState.get(PINGONE_VERIFY_REDIRECT_FLOW_CODE_KEY).asString())) {
							logger.debug("Code found in request, completing the Identity Verification process.");
							nodeState.remove(PINGONE_VERIFY_REDIRECT_FLOW_CODE_KEY);
							return getActionFromVerifyTransactionStatus(context, accessToken, pingOneUserId);
						} else {
							return handleFailure(nodeState, REDIRECT_FLOW_FAILED_CODE_MISMATCH, null);
						}
					} else {
						return handleFailure(nodeState, REDIRECT_FLOW_FAILED_MISSING_CODE, null);
					}
				}

				// Check if it should resume a previous transaction set by the Completion Decision node
				if (nodeState.isDefined(PINGONE_VERIFY_TRANSACTION_ID_KEY)) {
					logger.debug("Resuming an Identity Verification process previously started.");
					nodeState.putShared(PINGONE_VERIFY_DELIVERY_METHOD_KEY, 0);
					nodeState.putShared(PINGONE_VERIFY_TIMEOUT_KEY, 0);
					return getActionFromVerifyTransactionStatus(context, accessToken, pingOneUserId);
				}

				// Check if the delivery method should be selected by the user
				if (config.allowDeliveryMethodSelection() && !config.deliveryMethod().equals(DeliveryMethod.REDIRECT)) {
					logger.debug("Present options to select the delivery method.");
					List<Callback> callbacks = createChoiceCallbacks(context);
					return send(callbacks).build();
				} else {
					// Start new transaction
					logger.debug("Start new Identity Verification process.");
					return startVerifyTransaction(context, accessToken, config.deliveryMethod(), pingOneUserId);
				}
			}
		} catch (IdentityNotFoundException e) {
			return handleFailure(nodeState, IDENTITY_NOT_FOUND, e);
		} catch (JsonProcessingException e) {
			return handleFailure(nodeState, JSON_PROCESSING_ERROR, e);
		} catch (IllegalStateException e) {
			return handleFailure(nodeState, UNEXPECTED_VERIFY_STATUS, e);
		} catch (IllegalArgumentException e) {
			return handleFailure(nodeState, INVALID_BIOGRAPHIC_MATCHING, e);
		} catch (Exception e) {
			return handleFailure(nodeState, UNEXPECTED_ERROR, e);
		}
	}

	/**
	 * Resolves the PingOne user ID to use for the verification flow.
	 * IF "createPingOneUser" = false, return any ID from shared state.
	 * IF "createPingOneUser" = true and no ID exists:
	 * 		1. Create a PingOne user using either shared-state attributes or an AM identity
	 * 			• User creation method is determined by "userAttributesFromSharedState" toggle
	 * 		2. Store the new ID in shared state.
	 *
	 * @param context the current tree context
	 * @param nodeState the node-scoped state
	 * @param accessToken a valid PingOne access token
	 *
	 * @return the resolved or newly created PingOne user ID, or {@code null} if unavailable
	 *
	 * @throws Exception when user creation or lookups fail
	 */
	private String getPingOneUserId(TreeContext context, NodeState nodeState, String accessToken) throws Exception {

		logger.error("+++++++++++ Inside getPingOneUserId method +++++++++++");

		// Read any existing id first
		String pingOneUserId = nodeState.isDefined(PINGONE_USER_ID_KEY)
				? nodeState.get(PINGONE_USER_ID_KEY).asString()
				: null;

		logger.error("getPingOneUserId - pingOneUserId: {}", pingOneUserId);

		// If "createPingOneUser" is off, return whatever was found in shared state
		if (!config.createPingOneUser()) {
			logger.error("PingOne User Creation -> OFF");
			return pingOneUserId;
		}

		// If already present, don’t recreate
		if (StringUtils.isNotBlank(pingOneUserId)) {
			logger.error("pingOneUserId Is Not Blank");
			return pingOneUserId;
		}


		// Build the `/users` request body from the configured attribute source
		PingOneUserRequestFactory.BuildResult build;

		// ----------------------------------------
		// Create User w/ Shared State Attributes
		// ----------------------------------------
		if (config.userAttributesFromSharedState()) {
			logger.error("Using attributes in shared state");

			// Requires USERNAME in shared state
			if (!nodeState.isDefined(USERNAME)) {
				throw new NodeProcessException("Missing USERNAME in shared state for user creation.");
			}

			// Retrieve username
			String sharedStateUsername = nodeState.get(USERNAME).asString();
			logger.error("Shared State Username: {}", sharedStateUsername);
			build = PingOneUserRequestFactory.fromSharedState(
					nodeState,
					config.anonymizedUser(),
					config.populationId(),
					sharedStateUsername,
					userHelper
			);
		} else {
			// ----------------------------------------
			// Create User w/ AM Identity Attributes
			// ----------------------------------------
			logger.error("Using AM Identity attributes");

			// Retrieve AM identity attributes
			AMIdentity amIdentity = getIdentity(context);

			// Resolve the PingOne username from the chosen AM attribute
			String amIdentityUsername = userHelper.getUserAttribute(amIdentity, config.amIdentityAttribute());
			logger.error("AM Identity Username: {}", amIdentityUsername);

			if (StringUtils.isEmpty(amIdentityUsername)) {
				throw new NodeProcessException("Missing AM identity attribute for PingOne username.");
			}
			build = PingOneUserRequestFactory.fromAmIdentity(
					amIdentity,
					config.anonymizedUser(),
					config.populationId(),
					amIdentityUsername,
					userHelper
			);
		}

		// PingOne Create User API call
		String uri = Constants.endpoint + tntpPingOneConfig.environmentRegion().getDomainSuffix()
				+ "/v1/environments/" + tntpPingOneConfig.environmentId()
				+ "/users";
		JsonValue response = client.makeHTTPClientCall(accessToken, uri, "POST", build.requestBody());
		String createdUserId = userHelper.getUserIdFromResponse(response);

		// Put user ID into shared state
		nodeState.putShared(PINGONE_USER_ID_KEY, createdUserId);
		logger.debug("Created PingOne userId: {}", createdUserId);

		return createdUserId;
	}

	/**
	 * Polls the PingOne Verify transaction status and decides the next action:
	 * 	• Continue Waiting (with callbacks)
	 * 	• Succeed (optionally storing metadata or verified data)
	 * 	• Fail
	 *
	 * @param context the current tree context
	 * @param accessToken a valid PingOne access token
	 * @param userId the PingOne user ID whose transaction is evaluated
	 *
	 * @return the next {@link Action} based on transaction status
	 *
	 * @throws IllegalStateException if PingOne returns an unknown status
	 */
	private Action getActionFromVerifyTransactionStatus(TreeContext context, String accessToken, String userId) throws IllegalStateException {
		NodeState nodeState = context.getStateFor(this);

		// Retrieve transaction ID from shared state
		String transactionId = Objects.requireNonNull(nodeState.get(PINGONE_VERIFY_TRANSACTION_ID_KEY)).asString();

		// Determine delivery method
		DeliveryMethod deliveryMethod;
		if (config.allowDeliveryMethodSelection() && !config.deliveryMethod().equals(DeliveryMethod.REDIRECT)) {
			int index = Objects.requireNonNull(nodeState.get(PINGONE_VERIFY_DELIVERY_METHOD_KEY)).asInteger();
			deliveryMethod = DeliveryMethod.fromIndex(index);
		} else {
			deliveryMethod = config.deliveryMethod();
		}

		// Check transaction status and take appropriate action
		try{
			// Retrieve the verification transaction status
			String uri = Constants.endpoint + tntpPingOneConfig.environmentRegion().getDomainSuffix()
					+ "/v1/environments/" + tntpPingOneConfig.environmentId()
					+ "/users/" + userId + "/verifyTransactions/" + transactionId;
			JsonValue transactionResult = client.makeHTTPClientCall(accessToken, uri, "GET", null);
			String url = transactionResult.get(RESPONSE_URL).asString();
			String code = transactionResult.get(RESPONSE_CODE).asString();
			String status = transactionResult.get(RESPONSE_TRANSACTION_STATUS).get(RESPONSE_STATUS).asString();

			// Evaluate the transaction status returned from PingOne and decide how to proceed
			switch (VerifyTransactionStatus.fromString(status)) {
				case REQUESTED:
				case PARTIAL:
				case INITIATED:
				case IN_PROGRESS:
					List<Callback> callbacks = getCallbacksForDeliveryMethod(context, deliveryMethod, url, code);
					return waitTransactionCompletion(nodeState, callbacks).build();
				case SUCCESS:
				case NOT_REQUIRED:
				case APPROVED_NO_REQUEST:
				case APPROVED_MANUALLY:
					if (config.storeVerifiedData()) {
						// Retrieve the verified identity data for the transaction
						String readURI = Constants.endpoint + tntpPingOneConfig.environmentRegion().getDomainSuffix()
								+ "/v1/environments/" + tntpPingOneConfig.environmentId()
								+ "/users/" + userId
								+ "/verifyTransactions/" + transactionId + "/verifiedData";
						JsonValue verifiedData = client.makeHTTPClientCall(accessToken, readURI, "GET", null);
						nodeState.putShared(PINGONE_VERIFY_VERIFIED_DATA_KEY, verifiedData);
					}
					if (config.storeVerificationMetadata()) {
						// Retrieve metadata explaining the verification decision
						String readAllVerifiedDataURI = Constants.endpoint + tntpPingOneConfig.environmentRegion().getDomainSuffix()
								+ "/v1/environments/" + tntpPingOneConfig.environmentId()
								+ "/users/" + userId
								+ "/verifyTransactions/" + transactionId + "/metaData";
						JsonValue metadata = client.makeHTTPClientCall(accessToken, readAllVerifiedDataURI, "GET", null);
						nodeState.putShared(PINGONE_VERIFY_METADATA_KEY, metadata);
					}

					return buildAction(SUCCESS_OUTCOME_ID, nodeState);
				case FAIL:
					return handleFailure(nodeState, IDENTITY_VERIFICATION_FAILED, null);
				default:
					throw new IllegalStateException("Unexpected status returned from PingOne Verify Transaction: " + status);
			}
		} catch (Exception e) {
			return handleFailure(context.getStateFor(this), UNEXPECTED_ERROR, e);
		}
	}

	/**
	 * Starts a new PingOne Verify transaction for the given user, persists the
	 * transaction ID in shared state, and returns callbacks appropriate for the
	 * selected delivery method.
	 *
	 * @param context the current tree context
	 * @param accessToken a valid PingOne access token
	 * @param deliveryMethod the chosen delivery method (QR, Email, SMS, Redirect)
	 * @param userId the PingOne user ID
	 *
	 * @return an {@link Action} that sends the initial callbacks
	 *
	 * @throws JsonProcessingException if the request body serialization fails
	 * @throws IdentityNotFoundException if resolving AM identity fails (when needed)
	 * @throws IdRepoException if AM identity access fails
	 * @throws SSOException if AM identity access fails
	 * @throws NodeProcessException on invalid configuration or inputs
	 */
	private Action startVerifyTransaction(TreeContext context, String accessToken, DeliveryMethod deliveryMethod, String userId) throws JsonProcessingException, IdentityNotFoundException, IdRepoException, SSOException, NodeProcessException {

		// Create a new verify transaction
		JsonValue requestBody = getRequestBody(context, deliveryMethod);
		String uri = Constants.endpoint + tntpPingOneConfig.environmentRegion().getDomainSuffix()
				+ "/v1/environments/" + tntpPingOneConfig.environmentId()
				+ "/users/" + userId + "/verifyTransactions";
		try {
			JsonValue result = client.makeHTTPClientCall(accessToken, uri, "POST", requestBody);

			// Retrieve response values
			String transactionId = result.get(RESPONSE_TRANSACTION_ID).asString();
			String url = result.get(RESPONSE_URL).asString();
			String code = result.get(RESPONSE_CODE).asString();

			// Store transaction ID in shared state
			NodeState nodeState = context.getStateFor(this);
			nodeState.putShared(PINGONE_VERIFY_TRANSACTION_ID_KEY, transactionId);
			nodeState.putShared(PINGONE_VERIFY_TIMEOUT_KEY, TRANSACTION_POLL_INTERVAL);

			// Create callbacks and send
			List<Callback> callbacks = getCallbacksForDeliveryMethod(context, deliveryMethod, url, code);
			return send(callbacks).build();

		} catch (Exception e) {
			return handleFailure(context.getStateFor(this), UNEXPECTED_ERROR, e);
		}
	}

	/**
	 * Builds the list of callbacks required by the delivery method:
	 * 	• QR: localized instructions, QR script, hidden URL, and polling wait
	 * 	• Redirect: browser redirect to PingOne Verify
	 * 	• Email/SMS: polling wait only (notification sent server-side)
	 *
	 * @param context the current tree context
	 * @param deliveryMethod the chosen delivery method
	 * @param url the PingOne Verify transaction URL
	 * @param code the short verification code to display (for waiting message)
	 *
	 * @return the callbacks to present to the end user
	 */
	private List<Callback> getCallbacksForDeliveryMethod(TreeContext context, DeliveryMethod deliveryMethod, String url, String code) {
		if (deliveryMethod.equals(DeliveryMethod.QRCODE)) {

			Callback scanTextOutputCallback = createLocalizedTextCallback(context, this.getClass(), config.scanQRCodeMessage(), DEFAULT_SCAN_QRCODE_MESSAGE_KEY);
			Callback qrCodeCallback = new ScriptTextOutputCallback(GenerationUtils.getQRCodeGenerationJavascriptForAuthenticatorAppRegistration(QR_CALLBACK_STRING, url));
			Callback hiddenCallback = new HiddenValueCallback(HIDDEN_CALLBACK_ID, url);

			return ImmutableList.of(
					scanTextOutputCallback,
					qrCodeCallback,
					hiddenCallback,
					createPollingWaitCallback(context, code)
			);
		} else if (deliveryMethod.equals(DeliveryMethod.REDIRECT)) {

			String redirectUrl = url.concat("&dt=1");
			RedirectCallback redirectCallback = new RedirectCallback(redirectUrl, null, GET);
			redirectCallback.setTrackingCookie(true);

			logger.debug("Redirecting to PingOne Verify URL: {}", redirectUrl);
			return ImmutableList.of(
					redirectCallback
			);
		} else {
			logger.debug("Sending PingOne Verify URL via {}.", deliveryMethod);
			return ImmutableList.of(
					createPollingWaitCallback(context, code)
			);
		}
	}

	/**
	 * Creates a {@link PollingWaitCallback} with the configured poll interval and a
	 * localized waiting message that includes the short verification code.
	 *
	 * @param context the current tree context
	 * @param code the short verification code to be displayed in the message
	 *
	 * @return a polling wait callback
	 */
	private Callback createPollingWaitCallback(TreeContext context, String code) {
		String waitingMessage = getWaitingMessage(context, code);
		return new PollingWaitCallback(String.valueOf(TRANSACTION_POLL_INTERVAL), waitingMessage);
	}

	/**
	 * Builds the PingOne Verify request body for starting a transaction.
	 *  1. Sets EMAIL/SMS notification targets from shared state or AM identity based on "userAttributesFromSharedState" and the chosen delivery method.
	 * 	2. Always configures redirect back to the tree resume URI.
	 * 	3. Optionally sets a Verify Policy ID.
	 * 	4. Optionally sets biographic matching requirements, resolving attribute values from shared state or AM identity per configuration.
	 *
	 * @param context the current tree context
	 * @param deliveryMethod the chosen delivery method
	 *
	 * @return the request body as a {@link JsonValue}
	 *
	 * @throws JsonProcessingException if serialization fails
	 * @throws IdRepoException if AM identity access fails (when used)
	 * @throws SSOException if AM identity access fails (when used)
	 * @throws IllegalArgumentException for unknown biographic matching keys
	 * @throws IdentityNotFoundException if AM identity cannot be resolved (when used)
	 * @throws NodeProcessException when required delivery attributes are missing
	 */
	private JsonValue getRequestBody(TreeContext context, DeliveryMethod deliveryMethod) throws JsonProcessingException, IdRepoException, SSOException, IllegalArgumentException, IdentityNotFoundException, NodeProcessException {
		VerifyRequestBody requestBody = new VerifyRequestBody();
		NodeState nodeState = context.getStateFor(this);

		// Config toggle: true = use attributes from shared state, false = use AM identity profile
		boolean useShared = config.userAttributesFromSharedState();

		// AMIdentity will only be resolved if needed
		AMIdentity amIdentity = null;

		// -------------------------
		// Send Notification Section
		// -------------------------
		// Only applies for EMAIL or SMS delivery methods
		if (deliveryMethod.equals(DeliveryMethod.EMAIL) || deliveryMethod.equals(DeliveryMethod.SMS)) {
			String email = null;
			String phone = null;

			if (useShared) {
				// Pull contact info directly from shared state
				email = nodeState.get(AM_EMAIL).asString();
				phone = nodeState.get(AM_PHONE).asString();
			} else {
				// Fall back to AM identity attributes
				amIdentity = getIdentity(context);
				email = userHelper.getUserAttribute(amIdentity, AM_EMAIL);
				phone = userHelper.getUserAttribute(amIdentity, AM_PHONE);
			}

			// Determine which method has been selected
			if (deliveryMethod.equals(DeliveryMethod.EMAIL)) {
				if (StringUtils.isEmpty(email)) {
					throw new NodeProcessException("EMAIL delivery selected but no email found (shared state 'mail' or AM 'mail').");
				}
				// EMAIL
				requestBody.setSendNotification(new VerifyRequestBody.SendNotification(null, email));
			} else {
				if (StringUtils.isEmpty(phone)) {
					throw new NodeProcessException("SMS delivery selected but no phone found (shared state 'telephoneNumber' or AM 'telephoneNumber').");
				}
				// SMS
				requestBody.setSendNotification(new VerifyRequestBody.SendNotification(phone, null));
			}
		}

		// -------------------------
		// Redirect Configuration
		// -------------------------
		// Always set redirect details so PingOne can return control to AM
		String resumeUri = treeResumeUri(context);
		String redirectMessage = localizationHelper.getLocalizedMessage(context, this.getClass(), config.redirectMessage(), DEFAULT_REDIRECT_MESSAGE_KEY);
		requestBody.setRedirect(new VerifyRequestBody.Redirect(resumeUri, redirectMessage));

		// -------------------------
		// Verify Policy
		// -------------------------
		// Include a specific Verify Policy ID if present
		if (StringUtils.isNotEmpty(config.verifyPolicyId())) {
			requestBody.setVerifyPolicy(new VerifyRequestBody.VerifyPolicy(config.verifyPolicyId()));
		}

		// -------------------------
		// Biographic Matching
		// -------------------------
		// Compares user-supplied identity attributes against those stored in AM or Shared State
		if (!config.biographicMatching().isEmpty()) {
			VerifyRequestBody.Requirements.Builder requirementsBuilder = new VerifyRequestBody.Requirements.Builder();
			for (Map.Entry<String, String> entry : config.biographicMatching().entrySet()) {
				String requirementKey = entry.getKey();
				String attributeKey   = entry.getValue();

				// Resolve the attribute value based on configuration
				String value;
				if (useShared) {
					value = nodeState.get(attributeKey).asString();
				} else {
					if (amIdentity == null) {
						amIdentity = getIdentity(context);
					}
					value = userHelper.getUserAttribute(amIdentity, attributeKey);
				}

				// Skip empty fields
				if (StringUtils.isEmpty(value)) {
					continue;
				}

				// Map requirement type to VerifyRequestBody
				switch (BiographicMatchingRequirement.fromString(requirementKey)) {
					case REFERENCE_SELFIE:
						requirementsBuilder.setReferenceSelfie(new VerifyRequestBody.Value(value));
						break;
					case PHONE:
						requirementsBuilder.setPhone(new VerifyRequestBody.Value(value));
						break;
					case FAMILY_NAME:
						requirementsBuilder.setFamilyName(new VerifyRequestBody.Value(value));
						break;
					case NAME:
						requirementsBuilder.setName(new VerifyRequestBody.Value(value));
						break;
					case BIRTH_DATE:
						requirementsBuilder.setBirthDate(new VerifyRequestBody.Value(value));
						break;
					case EMAIL:
						requirementsBuilder.setEmail(new VerifyRequestBody.Options(value));
						break;
					case GIVEN_NAME:
						requirementsBuilder.setGivenName(new VerifyRequestBody.Options(value));
						break;
					case ADDRESS:
						requirementsBuilder.setAddress(new VerifyRequestBody.Options(value));
						break;
					default:
						throw new IllegalArgumentException("Unexpected biographic matching key: " + requirementKey);
				}
			}
			requestBody.setRequirements(requirementsBuilder.build());
		}
		// Convert the VerifyRequestBody into JSON for the PingOne API
		return JsonValueBuilder.toJsonValue(JsonValueBuilder.getObjectMapper().writeValueAsString(requestBody));
	}

	/**
	 * Handles wait-loop behavior for long-running transactions.
	 * Advances an internal elapsed timer and either:
	 * 	• Continues polling (sending callbacks)
	 * 	• Emits the timeout outcome when the configured timeout is reached
	 *
	 * @param nodeState the node-scoped state
	 * @param callbacks the callbacks to send while waiting
	 *
	 * @return an {@link Action.ActionBuilder} that either sends callbacks or goes to timeout
	 */
	private Action.ActionBuilder waitTransactionCompletion(NodeState nodeState, List<Callback> callbacks) {
		long timeOutInMs = config.timeout().getSeconds() * 1000;
		int timeElapsed = nodeState.get(PINGONE_VERIFY_TIMEOUT_KEY).asInteger();

		if (timeElapsed >= timeOutInMs) {
			return goTo(TIMEOUT_OUTCOME_ID);
		} else {
			nodeState.putTransient(PINGONE_VERIFY_TIMEOUT_KEY, timeElapsed + TRANSACTION_POLL_INTERVAL);
		}
		return send(callbacks);
	}

	/**
	 * Builds the delivery-method selection UI when user choice is enabled.
	 *
	 * @param context the current tree context
	 *
	 * @return callbacks to present delivery method options (QR, Email, SMS)
	 */
	private List<Callback> createChoiceCallbacks(TreeContext context) {
		List<Callback> callbacks = new ArrayList<>();
		String message = localizationHelper.getLocalizedMessage(context, this.getClass(), config.deliveryMethodMessage(), DEFAULT_DELIVERY_METHOD_MESSAGE_KEY);

		String[] options = {
				localizationHelper.getLocalizedMessage(context, this.getClass(), null, "deliveryMethod.QRCODE"),
				localizationHelper.getLocalizedMessage(context, this.getClass(), null, "deliveryMethod.EMAIL"),
				localizationHelper.getLocalizedMessage(context, this.getClass(), null, "deliveryMethod.SMS"),
		};

		Callback textOutputCallback = new TextOutputCallback(TextOutputCallback.INFORMATION, message);
		callbacks.add(textOutputCallback);

		ConfirmationCallback deliveryChoiceCallback = new ConfirmationCallback(message, ConfirmationCallback.INFORMATION, options, 0);
		callbacks.add(deliveryChoiceCallback);

		return callbacks;
	}

	/**
	 * Generates a one-time redirect code, stores it in shared state, and returns it.
	 * Used to validate the return from the PingOne Verify web app.
	 *
	 * @param context the current tree context
	 *
	 * @return the generated redirect code
	 */
	private String createRedirectCode(TreeContext context) {
		NodeState nodeState = context.getStateFor(this);
		String code = UUID.randomUUID().toString();
		nodeState.putShared(PINGONE_VERIFY_REDIRECT_FLOW_CODE_KEY, code);
		return code;
	}

	/**
	 * Resolves the localized waiting message and injects the short verification code.
	 *
	 * @param context the current tree context
	 * @param verificationCode the short verification code
	 *
	 * @return the formatted waiting message
	 */
	private String getWaitingMessage(TreeContext context, String verificationCode) {
		String value = localizationHelper.getLocalizedMessage(context, PingOneVerifyEvaluationNode.class, config.waitingMessage(), DEFAULT_WAITING_MESSAGE_KEY);
		return value.replaceAll("\\{\\{verificationCode\\}\\}", verificationCode);
	}

	/**
	 * Creates a localized {@link TextOutputCallback} from a bundle map with fallback key.
	 *
	 * @param context the current tree context
	 * @param bundleClass the resource bundle class owner
	 * @param scanQRCodeMessage per-locale overrides
	 * @param key fallback message key
	 *
	 * @return a text output callback
	 */
	private Callback createLocalizedTextCallback(TreeContext context, Class<?> bundleClass, Map<Locale, String> scanQRCodeMessage, String key) {
		String message = localizationHelper.getLocalizedMessage(context, bundleClass, scanQRCodeMessage, key);
		return new TextOutputCallback(TextOutputCallback.INFORMATION, message);
	}

	/**
	 * Builds a final action for the given outcome and clears transient verify-related
	 * keys from shared state.
	 *
	 * @param outcome the outcome ID to transition to
	 * @param nodeState the node-scoped state
	 *
	 * @return a built {@link Action}
	 */
	private Action buildAction(String outcome, NodeState nodeState) {
		Action.ActionBuilder builder = goTo(outcome);
		return cleanupSharedState(nodeState, builder).build();
	}

	/**
	 * Removes verify-transaction transient keys from shared state before emitting the next action.
	 *
	 * @param nodeState the node-scoped state
	 * @param builder the action builder to finalize
	 *
	 * @return the same builder for chaining
	 */
	private Action.ActionBuilder cleanupSharedState(NodeState nodeState, Action.ActionBuilder builder) {
		nodeState.remove(PINGONE_VERIFY_TRANSACTION_ID_KEY);
		nodeState.remove(PINGONE_VERIFY_DELIVERY_METHOD_KEY);
		nodeState.remove(PINGONE_VERIFY_TIMEOUT_KEY);
		nodeState.remove(PINGONE_VERIFY_REDIRECT_FLOW_CODE_KEY);
		return builder;
	}

	/**
	 * Logs and optionally captures a structured failure reason into shared state,
	 * then transitions to the failure outcome.
	 *
	 * @param nodeState the node-scoped state
	 * @param failureReason the failure category
	 * @param exception the underlying exception (optional)
	 *
	 * @return a built failure {@link Action}
	 */
	private Action handleFailure(NodeState nodeState, FailureReason failureReason, Exception exception) {
		logger.error(failureReason.getMessage(), exception);
		if (config.captureFailure()) {
			String failureJson = getFailureJson(failureReason, exception);
			nodeState.putShared(PINGONE_VERIFY_EVALUATION_FAILURE_REASON_KEY, failureJson);
		}
		return buildAction(FAILURE_OUTCOME_ID, nodeState);
	}

	/**
	 * Builds a resume URI for the current tree execution.
	 * Appends a one-time code used to validate a redirect return from PingOne Verify.
	 *
	 * @param context the current tree context
	 *
	 * @return the absolute ASCII resume URI
	 *
	 * @throws NodeProcessException if URI construction fails
	 */
	@VisibleForTesting
	String treeResumeUri(TreeContext context) throws NodeProcessException {
		// Get server URL
		String serverUrl = context.request.serverUrl;

		// Get query parameters and add code
		Map<String, List<String>> requestQueryParameters = context.request.parameters;
		Form redirectQuery = new Form();
		redirectQuery.putAll(requestQueryParameters);
		redirectQuery.put("code", Collections.singletonList(createRedirectCode(context)));

		// Create resume URI
		MutableUri resumeUri;
		try {
			resumeUri = new MutableUri(serverUrl);
			resumeUri.setPath(resumeUri.getPath());
			resumeUri.setRawQuery(redirectQuery.toQueryString());
		} catch (URISyntaxException e) {
			throw new NodeProcessException(format("Failed to create Tree resume URI for server '%s'", serverUrl));
		}
		return resumeUri.toASCIIString();
	}

	/**
	 * Resolves the AM identity associated with the current state via {@link UserHelper}.
	 *
	 * @param context the current tree context
	 *
	 * @return the resolved {@link AMIdentity}
	 *
	 * @throws IdentityNotFoundException if the identity cannot be found
	 */
	@VisibleForTesting
	AMIdentity getIdentity(TreeContext context) throws IdentityNotFoundException {
		return userHelper.getIdentity(context.getStateFor(this));
	}

	/**
	 * Declares the inputs this node reads from shared state.
	 *
	 * @return the array of inputs consumed by this node
	 */
	@Override
	public InputState[] getInputs() {
		return new InputState[] {
				new InputState(PINGONE_USER_ID_KEY, true),
				new InputState(USERNAME, true),
				new InputState(AM_EMAIL, false),
				new InputState(AM_PHONE, false),
				new InputState(AM_GIVEN_NAME, false),
				new InputState(AM_FAMILY_NAME, false),
				new InputState(AM_COMMON_NAME, false),
				new InputState(AM_STREET, false),
				new InputState(AM_CITY, false),
				new InputState(AM_STATE, false),
				new InputState(AM_POSTAL_CODE, false),
				new InputState(AM_COUNTRY, false),
				new InputState(AM_PREFERRED_LANGUAGE, false),
				new InputState(REALM),
				new InputState(PINGONE_VERIFY_DELIVERY_METHOD_KEY),
				new InputState(PINGONE_VERIFY_TRANSACTION_ID_KEY),
				new InputState(PINGONE_VERIFY_TIMEOUT_KEY),
				new InputState(PINGONE_VERIFY_REDIRECT_FLOW_CODE_KEY),
		};
	}

	/**
	 * Provides the set of outcomes for this node
	 */
	public static final class OutcomeProvider implements StaticOutcomeProvider {

		/**  Success outcome ID. */
		public static final String SUCCESS_OUTCOME_ID = "successOutcome";
		/**  Failure outcome ID. */
		public static final String FAILURE_OUTCOME_ID = "failureOutcome";
		/**  Timeout outcome ID. */
		public static final String TIMEOUT_OUTCOME_ID = "timeoutOutcome";

		/**
		 * Returns the outcomes supported by this node with localized display names.
		 *
		 * @param locales the caller's preferred locales
		 *
		 * @return the list of outcomes
		 */
		@Override
		public List<Outcome> getOutcomes(PreferredLocales locales) {
			ResourceBundle bundle = locales.getBundleInPreferredLocale(BUNDLE, OutcomeProvider.class.getClassLoader());
			return ImmutableList.of(
					new Outcome(SUCCESS_OUTCOME_ID, bundle.getString(SUCCESS_OUTCOME_ID)),
					new Outcome(FAILURE_OUTCOME_ID, bundle.getString(FAILURE_OUTCOME_ID)),
					new Outcome(TIMEOUT_OUTCOME_ID, bundle.getString(TIMEOUT_OUTCOME_ID))
			);
		}
	}
}
