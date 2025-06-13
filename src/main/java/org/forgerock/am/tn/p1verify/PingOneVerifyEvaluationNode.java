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
import static org.forgerock.am.tn.p1verify.UserHelper.AM_EMAIL;
import static org.forgerock.am.tn.p1verify.UserHelper.AM_PHONE;
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
import org.forgerock.openam.auth.nodes.helpers.IdmIntegrationHelper;
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

	private AMIdentity identity = null;

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
		 * @return true if user will be prompted for delivery method, false otherwise.
		 */
		@Attribute(order = 400)
		default boolean allowDeliveryMethodSelection() {
			return false;
		}

		/**
		 * The message to display to the user allowing them to choose the delivery method. Keyed on the locale.
		 * Falls back to default.deliverMethodMessage.
		 * @return The message to display while choosing the delivery method.
		 */
		@Attribute(order = 500)
		default Map<Locale, String> deliveryMethodMessage() {
			return Collections.emptyMap();
		}

		/**
		 * The message to displayed to user to scan the QR code. Keyed on the locale. Falls back to
		 * default.scanQRCodeMessage.
		 * @return The mapping of locales to scan QR code messages.
		 */
		@Attribute(order = 600)
		default Map<Locale, String> scanQRCodeMessage() {
			return Collections.emptyMap();
		}

		/**
		 * The message to display to the user while waiting, keyed on the locale. Falls back to default.waitingMessage.
		 * @return The message to display on the waiting indicator.
		 */
		@Attribute(order = 700)
		default Map<Locale, String> waitingMessage() {
			return Collections.emptyMap();
		}

		/**
		 * The message to display to the user while redirecting from PingOne Verify web app, keyed on the locale.
		 * Falls back to default.redirectMessage.
		 * @return The message to display on the redirect.
		 */
		@Attribute(order = 800)
		default Map<Locale, String> redirectMessage() {
			return Collections.emptyMap();
		}

		/**
		 * The timeout in seconds for the verification process.
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
		 * @return the mapping for the Biographic Matching.
		 */
		@Attribute(order = 1000)
		default Map<String, String> biographicMatching() {
			return Collections.emptyMap();
		}

		/**
		 * Store the verification metadata in the shared state.
		 * @return true if the metadata should be stored, false otherwise.
		 */
		@Attribute(order = 1100)
		default boolean storeVerificationMetadata() {
			return false;
		}

		/**
		 * Store the verified data in the shared state.
		 * @return true if the verified data should be stored, false otherwise.
		 */
		@Attribute(order = 1200)
		default boolean storeVerifiedData() {
			return false;
		}

		/**
		 * If the node fail, the error detail will be provided in the shared state for analysis by later nodes.
		 *
		 * @return true if the failure will be captured.
		 */
		@Attribute(order = 1300)
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

	@Override
	public Action process(TreeContext context) {
		logger.debug("PingOneVerifyEvaluationNode started.");

		NodeState nodeState = context.getStateFor(this);

		// Check if PingOne User ID attribute is set in sharedState
		String pingOneUserId = nodeState.isDefined(PINGONE_USER_ID_KEY)
				? nodeState.get(PINGONE_USER_ID_KEY).asString()
				: null;
		if (StringUtils.isBlank(pingOneUserId)) {
			return handleFailure(nodeState, MISSING_PINGONE_USER_ID_FROM_SHARED_STATE, null);
		}

		logger.debug("Retrieved from shared state - pingOneUserId: {}", pingOneUserId);

		try {
			logger.error("Entering main try statement...");
			// Obtain PingOne access token
			TNTPPingOneUtility tntpP1U = TNTPPingOneUtility.getInstance();
			String accessToken = tntpP1U.getAccessToken(realm, tntpPingOneConfig);
			logger.error("Access Token: {}", accessToken);
			if (accessToken == null) {
				logger.error("Access Token is null");
				return handleFailure(nodeState, ACCESS_TOKEN, null);
			}

			// Check if choice was made
			Optional<ConfirmationCallback> confirmationCallback = context.getCallback(ConfirmationCallback.class);
			logger.error("Confirmation Callback Choice: {}", confirmationCallback);
			if (confirmationCallback.isPresent()) {
				logger.error("Retrieve selected delivery method and start a new Identity Verification process.");
				logger.debug("Retrieve selected delivery method and start a new Identity Verification process.");
				int choice = confirmationCallback.get().getSelectedIndex();
				nodeState.putShared(PINGONE_VERIFY_DELIVERY_METHOD_KEY, choice);
				return startVerifyTransaction(context, accessToken, DeliveryMethod.fromIndex(choice), pingOneUserId);
			}

			// Check if transaction was started
			Optional<PollingWaitCallback> pollingWaitCallback = context.getCallback(PollingWaitCallback.class);
			logger.error("Polling Wait Callback: {}", pollingWaitCallback);
			if (pollingWaitCallback.isPresent()) {
				// Transaction already started
				logger.error("Identity Verification process already started. Waiting for completion...");
				logger.debug("Identity Verification process already started. Waiting for completion...");
				if (!nodeState.isDefined(PINGONE_VERIFY_TRANSACTION_ID_KEY)) {
					logger.error("pinOneVerifyTransactionId not defined...");
					return handleFailure(nodeState, MISSING_PINGONE_VERIFY_TRANSACTION_ID, null);
				}
				return getActionFromVerifyTransactionStatus(context, accessToken, pingOneUserId);
			} else {
				// Check if it should handle a redirect flow
				if (nodeState.isDefined(PINGONE_VERIFY_REDIRECT_FLOW_CODE_KEY)) {
					logger.error("PINGONE_VERIFY_REDIRECT_FLOW_CODE_KEY: {}", PINGONE_VERIFY_REDIRECT_FLOW_CODE_KEY);
					logger.error("Handling redirect flow.");
					logger.debug("Handling redirect flow.");
					if (context.request.parameters.containsKey("code")) {
						String code = context.request.parameters.get("code").get(0);
						logger.error("Redirect code: {}", code);
						if (code.equals(nodeState.get(PINGONE_VERIFY_REDIRECT_FLOW_CODE_KEY).asString())) {
							logger.error("Code found in request, completing the Identity Verification process.");
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
					logger.error("Resuming an Identity Verification process previously started.");
					logger.debug("Resuming an Identity Verification process previously started.");
					nodeState.putShared(PINGONE_VERIFY_DELIVERY_METHOD_KEY, 0);
					nodeState.putShared(PINGONE_VERIFY_TIMEOUT_KEY, 0);
					return getActionFromVerifyTransactionStatus(context, accessToken, pingOneUserId);
				}

				// Check if the delivery method should be selected by the user
				if (config.allowDeliveryMethodSelection() && !config.deliveryMethod().equals(DeliveryMethod.REDIRECT)) {
					logger.error("Present options to select the delivery method.");
					logger.debug("Present options to select the delivery method.");
					List<Callback> callbacks = createChoiceCallbacks(context);
					return send(callbacks).build();
				} else {
					// Start new transaction
					logger.error("Start new Identity Verification process.");
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

	private Action getActionFromVerifyTransactionStatus(TreeContext context, String accessToken, String userId) throws IllegalStateException {
		logger.error("++++++++++++++ Inside getActionFromVerifyTransactionStatus ++++++++++++++");

		logger.error("getActionFromVerifyTransactionStatus - context: {}", context);
		logger.error("getActionFromVerifyTransactionStatus - accessToken: {}", accessToken);
		logger.error("getActionFromVerifyTransactionStatus - userId: {}", userId);

		NodeState nodeState = context.getStateFor(this);

		// Retrieve transaction ID from shared state
		String transactionId = Objects.requireNonNull(nodeState.get(PINGONE_VERIFY_TRANSACTION_ID_KEY)).asString();
		logger.error("getActionFromVerifyTransactionStatus - transactionId: {}", transactionId);

		// Determine delivery method
		DeliveryMethod deliveryMethod;
		if (config.allowDeliveryMethodSelection() && !config.deliveryMethod().equals(DeliveryMethod.REDIRECT)) {
			int index = Objects.requireNonNull(nodeState.get(PINGONE_VERIFY_DELIVERY_METHOD_KEY)).asInteger();
			deliveryMethod = DeliveryMethod.fromIndex(index);
		} else {
			deliveryMethod = config.deliveryMethod();
		}

		logger.error("getActionFromVerifyTransactionStatus - deliveryMethod: {}", deliveryMethod);

		// Check transaction status and take appropriate action
		try{
			// Retrieve the verification transaction status
			String uri = Constants.endpoint + tntpPingOneConfig.environmentRegion().getDomainSuffix()
					+ "/v1/environments/" + tntpPingOneConfig.environmentId()
					+ "/users/" + userId + "/verifyTransactions/" + transactionId;
			JsonValue transactionResult = client.makeHTTPClientCall(accessToken, uri, "GET", null);
			logger.error("getActionFromVerifyTransactionStatus - transactionResult: {}", transactionResult);

			String url = transactionResult.get(RESPONSE_URL).asString();
			logger.error("getActionFromVerifyTransactionStatus - url: {}", url);

			String code = transactionResult.get(RESPONSE_CODE).asString();
			logger.error("getActionFromVerifyTransactionStatus - code: {}", code);

			String status = transactionResult.get(RESPONSE_TRANSACTION_STATUS).get(RESPONSE_STATUS).asString();
			logger.error("getActionFromVerifyTransactionStatus - status: {}", status);

			switch (VerifyTransactionStatus.fromString(status)) {
				case REQUESTED:
				case PARTIAL:
				case INITIATED:
				case IN_PROGRESS:
					logger.error("getActionFromVerifyTransactionStatus - switch path: REQUESTED, PARTIAL, INITIATED, IN_PROGRESS");

					List<Callback> callbacks = getCallbacksForDeliveryMethod(context, deliveryMethod, url, code);
					return waitTransactionCompletion(nodeState, callbacks).build();
				case SUCCESS:
				case NOT_REQUIRED:
				case APPROVED_NO_REQUEST:
				case APPROVED_MANUALLY:
					logger.error("getActionFromVerifyTransactionStatus - switch path: SUCCESS, NOT_REQUIRED, APPROVED_NO_REQUEST, APPROVED_MANUALLY");

					if (config.storeVerifiedData()) {
						logger.error("storeVerifiedData == true");
						// Retrieve the verified identity data for the transaction
						String readURI = Constants.endpoint + tntpPingOneConfig.environmentRegion().getDomainSuffix()
								+ "/v1/environments/" + tntpPingOneConfig.environmentId()
								+ "/users/" + userId
								+ "/verifyTransactions/" + transactionId + "/verifiedData";
						JsonValue verifiedData = client.makeHTTPClientCall(accessToken, readURI, "GET", null);

						logger.error("getActionFromVerifyTransactionStatus - verifiedData: {}", verifiedData);

						nodeState.putShared(PINGONE_VERIFY_VERIFIED_DATA_KEY, verifiedData);
					}
					if (config.storeVerificationMetadata()) {
						logger.error("storeVerificationMetadata == true");
						// Retrieve metadata explaining the verification decision
						String readAllVerifiedDataURI = Constants.endpoint + tntpPingOneConfig.environmentRegion().getDomainSuffix()
								+ "/v1/environments/" + tntpPingOneConfig.environmentId()
								+ "/users/" + userId
								+ "/verifyTransactions/" + transactionId + "/metaData";
						JsonValue metadata = client.makeHTTPClientCall(accessToken, readAllVerifiedDataURI, "GET", null);

						logger.error("getActionFromVerifyTransactionStatus - metadata: {}", metadata);

						nodeState.putShared(PINGONE_VERIFY_METADATA_KEY, metadata);
					}

					return buildAction(SUCCESS_OUTCOME_ID, nodeState);
				case FAIL:
					logger.error("getActionFromVerifyTransactionStatus - switch path: FAIL");

					return handleFailure(nodeState, IDENTITY_VERIFICATION_FAILED, null);
				default:
					logger.error("getActionFromVerifyTransactionStatus - switch path: default");

					throw new IllegalStateException("Unexpected status returned from PingOne Verify Transaction: " + status);
			}
		} catch (Exception e) {
			return handleFailure(context.getStateFor(this), UNEXPECTED_ERROR, e);
		}
	}

	private Action startVerifyTransaction(TreeContext context, String accessToken, DeliveryMethod deliveryMethod, String userId) throws JsonProcessingException, IdentityNotFoundException, IdRepoException, SSOException, NodeProcessException {
		logger.error("++++++++++++++ Inside startVerifyTransaction ++++++++++++++");

		logger.error("startVerifyTransaction - context: {}", context);
		logger.error("startVerifyTransaction - accessToken: {}", accessToken);
		logger.error("startVerifyTransaction - deliveryMethod: {}", deliveryMethod);
		logger.error("startVerifyTransaction - userId: {}", userId);

		// Create a new verify transaction
		JsonValue requestBody = getRequestBody(context, deliveryMethod);
		String uri = Constants.endpoint + tntpPingOneConfig.environmentRegion().getDomainSuffix()
				+ "/v1/environments/" + tntpPingOneConfig.environmentId()
				+ "/users/" + userId + "/verifyTransactions";
		try {
			JsonValue result = client.makeHTTPClientCall(accessToken, uri, "POST", requestBody);

			logger.error("startVerifyTransaction - API Response: {}", result);

			// Retrieve response values
			String transactionId = result.get(RESPONSE_TRANSACTION_ID).asString();
			logger.error("startVerifyTransaction - transactionId: {}", transactionId);
			String url = result.get(RESPONSE_URL).asString();
			logger.error("startVerifyTransaction - url: {}", url);
			String code = result.get(RESPONSE_CODE).asString();
			logger.error("startVerifyTransaction - code: {}", code);

			// Store transaction ID in shared state
			NodeState nodeState = context.getStateFor(this);
			nodeState.putShared(PINGONE_VERIFY_TRANSACTION_ID_KEY, transactionId);
			nodeState.putShared(PINGONE_VERIFY_TIMEOUT_KEY, TRANSACTION_POLL_INTERVAL);
			nodeState.putShared(PINGONE_VERIFY_TIMEOUT_KEY + " - TEST", 0);

			// Create callbacks and send
			List<Callback> callbacks = getCallbacksForDeliveryMethod(context, deliveryMethod, url, code);
			return send(callbacks).build();

		} catch (Exception e) {
			logger.error("startVerifyTransaction - caught exception");
			return handleFailure(context.getStateFor(this), UNEXPECTED_ERROR, e);
		}
	}

	private List<Callback> getCallbacksForDeliveryMethod(TreeContext context, DeliveryMethod deliveryMethod, String url, String code) {
		logger.error("++++++++++++++ Inside getCallbacksForDeliveryMethod ++++++++++++++");

		logger.error("getCallbacksForDeliveryMethod - deliveryMethod: {}", deliveryMethod);
		logger.error("getCallbacksForDeliveryMethod - url: {}", url);
		logger.error("getCallbacksForDeliveryMethod - code: {}", code);

		if (deliveryMethod.equals(DeliveryMethod.QRCODE)) {
			logger.error("getCallbacksForDeliveryMethod - QRCODE delivery method");

			Callback scanTextOutputCallback = createLocalizedTextCallback(context, this.getClass(), config.scanQRCodeMessage(), DEFAULT_SCAN_QRCODE_MESSAGE_KEY);
			Callback qrCodeCallback = new ScriptTextOutputCallback(GenerationUtils.getQRCodeGenerationJavascriptForAuthenticatorAppRegistration(QR_CALLBACK_STRING, url));
			Callback hiddenCallback = new HiddenValueCallback(HIDDEN_CALLBACK_ID, url);

			logger.error("Displaying QR code for PingOne Verify URL: {}", url);
			logger.debug("Displaying QR code for PingOne Verify URL: {}", url);
			return ImmutableList.of(
					scanTextOutputCallback,
					qrCodeCallback,
					hiddenCallback,
					createPollingWaitCallback(context, code)
			);
		} else if (deliveryMethod.equals(DeliveryMethod.REDIRECT)) {
			logger.error("getCallbacksForDeliveryMethod - REDIRECT delivery method");

			String redirectUrl = url.concat("&dt=1");
			RedirectCallback redirectCallback = new RedirectCallback(redirectUrl, null, GET);
			redirectCallback.setTrackingCookie(true);

			logger.error("Redirecting to PingOne Verify URL: {}", redirectUrl);
			logger.debug("Redirecting to PingOne Verify URL: {}", redirectUrl);
			return ImmutableList.of(
					redirectCallback
			);
		} else {
			logger.error("Sending PingOne Verify URL via {}.", deliveryMethod);
			logger.debug("Sending PingOne Verify URL via {}.", deliveryMethod);
			return ImmutableList.of(
					createPollingWaitCallback(context, code)
			);
		}
	}

	private Callback createPollingWaitCallback(TreeContext context, String code) {
		logger.error("++++++++++++++ Inside createPollingWaitCallback ++++++++++++++");
		logger.error("createPollingWaitCallback - code: {}", code);

		String waitingMessage = getWaitingMessage(context, code);
		logger.error("createPollingWaitCallback - waitingMessage: {}", waitingMessage);

//		return PollingWaitCallback.makeCallback()
//				.withWaitTime(String.valueOf(TRANSACTION_POLL_INTERVAL))
//				.withMessage(waitingMessage)
//				.build();
		return new PollingWaitCallback(String.valueOf(TRANSACTION_POLL_INTERVAL), waitingMessage);
	}

	private JsonValue getRequestBody(TreeContext context, DeliveryMethod deliveryMethod) throws JsonProcessingException, IdRepoException, SSOException, IllegalArgumentException, IdentityNotFoundException, NodeProcessException {
		logger.error("++++++++++++++ Inside getRequestBody ++++++++++++++");
		logger.error("getRequestBody - deliveryMethod: {}", deliveryMethod);

		VerifyRequestBody requestBody = new VerifyRequestBody();

		// Get AM Identity
		AMIdentity amIdentity = getIdentity(context);

		// Add send notification if delivery method is email or sms
		if (deliveryMethod.equals(DeliveryMethod.EMAIL)) {
			logger.error("getRequestBody - EMAIL delivery method");
			logger.error("AM EMAIL: {}", userHelper.getUserAttribute(amIdentity, AM_EMAIL));
			requestBody.setSendNotification(
					new VerifyRequestBody.SendNotification(
					null,
					userHelper.getUserAttribute(amIdentity, AM_EMAIL))
			);
		} else if (deliveryMethod.equals(DeliveryMethod.SMS)) {
			logger.error("getRequestBody - SMS delivery method");
			logger.error("AM SMS: {}", userHelper.getUserAttribute(amIdentity, AM_PHONE));
			requestBody.setSendNotification(
					new VerifyRequestBody.SendNotification(
					userHelper.getUserAttribute(amIdentity, AM_PHONE),
					null)
			);
		}

		String resumeUri = treeResumeUri(context);
		String redirectMessage = localizationHelper.getLocalizedMessage(context, this.getClass(), config.redirectMessage(), DEFAULT_REDIRECT_MESSAGE_KEY);
		requestBody.setRedirect(new VerifyRequestBody.Redirect(resumeUri, redirectMessage));

		// Add verify policy id if present
		if (StringUtils.isNotEmpty(config.verifyPolicyId())) {
			logger.error("getRequestBody - verifyPolicyId present: {}", config.verifyPolicyId());
			requestBody.setVerifyPolicy(new VerifyRequestBody.VerifyPolicy(config.verifyPolicyId()));
		}

		logger.error("getRequestBody - biographicMatching: {}", config.biographicMatching());
		// Add biographic matching if present
		if (!config.biographicMatching().isEmpty()) {
			logger.error("getRequestBody - biographicMatching is not empty...");
			VerifyRequestBody.Requirements.Builder requirementsBuilder = new VerifyRequestBody.Requirements.Builder();
			for (Map.Entry<String, String> entry : config.biographicMatching().entrySet()) {
				String requirementEntry = entry.getKey();
				String attributeEntry = entry.getValue();

				String attributeValue = userHelper.getUserAttribute(amIdentity, attributeEntry);
				logger.error("getRequestBody - biographicMatching attribute: {}", attributeValue);
				if (StringUtils.isNotEmpty(attributeValue)) {
					switch (BiographicMatchingRequirement.fromString(requirementEntry)) {
						case REFERENCE_SELFIE:
							logger.error("Inside REFERENCE_SELFIE");
							requirementsBuilder.setReferenceSelfie(new VerifyRequestBody.Value(attributeValue));
							break;
						case PHONE:
							logger.error("Inside PHONE");
							requirementsBuilder.setPhone(new VerifyRequestBody.Value(attributeValue));
							break;
						case FAMILY_NAME:
							logger.error("Inside FAMILY_NAME");
							requirementsBuilder.setFamilyName(new VerifyRequestBody.Value(attributeValue));
							break;
						case NAME:
							logger.error("Inside NAME");
							requirementsBuilder.setName(new VerifyRequestBody.Value(attributeValue));
							break;
						case BIRTH_DATE:
							logger.error("Inside BIRTH_DATE");
							requirementsBuilder.setBirthDate(new VerifyRequestBody.Value(attributeValue));
							break;
						case EMAIL:
							logger.error("Inside EMAIL");
							requirementsBuilder.setEmail(new VerifyRequestBody.Options(attributeValue));
							break;
						case GIVEN_NAME:
							logger.error("Inside GIVEN_NAME");
							requirementsBuilder.setGivenName(new VerifyRequestBody.Options(attributeValue));
							break;
						case ADDRESS:
							logger.error("Inside ADDRESS");
							requirementsBuilder.setAddress(new VerifyRequestBody.Options(attributeValue));
							break;
						default:
							throw new IllegalArgumentException("Unexpected key value found in Biographic " + "Matching: " + requirementEntry);
					}
				}
			}
			requestBody.setRequirements(requirementsBuilder.build());
		}
		return JsonValueBuilder.toJsonValue(JsonValueBuilder.getObjectMapper().writeValueAsString(requestBody));
	}

	private Action.ActionBuilder waitTransactionCompletion(NodeState nodeState, List<Callback> callbacks) {
		logger.error("++++++++++++++ Inside waitTransactionCompletion ++++++++++++++");

		logger.error("Waiting verify transaction to be completed.");
		logger.debug("Waiting verify transaction to be completed.");

		long timeOutInMs = config.timeout().getSeconds() * 1000;
		int timeElapsed = nodeState.get(PINGONE_VERIFY_TIMEOUT_KEY).asInteger();

		logger.error("Timeout In Ms: {}", timeOutInMs);
		logger.error("Time Elapsed: {}", timeElapsed);

		if (timeElapsed >= timeOutInMs) {
			logger.error("Inside 'timeElapsed >= timeOutInMs' IF statement...");
			return goTo(TIMEOUT_OUTCOME_ID);
		} else {
			logger.error("Inside 'timeElapsed >= timeOutInMs' ELSE statement...");
			nodeState.putTransient(PINGONE_VERIFY_TIMEOUT_KEY, timeElapsed + TRANSACTION_POLL_INTERVAL);
		}
		logger.error("After the 'timeElapsed >= timeOutInMs' IF/ELSE statement...");
		return send(callbacks);
	}

	private List<Callback> createChoiceCallbacks(TreeContext context) {
		logger.error("++++++++++++++ Inside createChoiceCallbacks ++++++++++++++");

		List<Callback> callbacks = new ArrayList<>();
		String message = localizationHelper.getLocalizedMessage(context, this.getClass(), config.deliveryMethodMessage(), DEFAULT_DELIVERY_METHOD_MESSAGE_KEY);
		logger.error("createChoiceCallbacks - message: {}", message);

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

	private String createRedirectCode(TreeContext context) {
		logger.error("++++++++++++++ Inside createRedirectCode ++++++++++++++");
		NodeState nodeState = context.getStateFor(this);
		String code = UUID.randomUUID().toString();
		nodeState.putShared(PINGONE_VERIFY_REDIRECT_FLOW_CODE_KEY, code);
		logger.error("createRedirectCode - code: {}", code);
		return code;
	}

	private String getWaitingMessage(TreeContext context, String verificationCode) {
		logger.error("++++++++++++++ Inside getWaitingMessage ++++++++++++++");
		logger.error("getWaitingMessage - verificationCode: {}", verificationCode);
		String value = localizationHelper.getLocalizedMessage(context, PingOneVerifyEvaluationNode.class, config.waitingMessage(), DEFAULT_WAITING_MESSAGE_KEY);
		logger.error("getWaitingMessage - value: {}", value);
		return value.replaceAll("\\{\\{verificationCode\\}\\}", verificationCode);
	}

	private Callback createLocalizedTextCallback(TreeContext context, Class<?> bundleClass, Map<Locale, String> scanQRCodeMessage, String key) {
		logger.error("++++++++++++++ Inside createLocalizedTextCallback ++++++++++++++");
		logger.error("createLocalizedTextCallback - bundleClass: {}", bundleClass);
		logger.error("createLocalizedTextCallback - scanQRCodeMessage: {}", scanQRCodeMessage);
		logger.error("createLocalizedTextCallback - key: {}", key);

		String message = localizationHelper.getLocalizedMessage(context, bundleClass, scanQRCodeMessage, key);
		logger.error("createLocalizedTextCallback - message: {}", message);
		return new TextOutputCallback(TextOutputCallback.INFORMATION, message);
	}

	private Action buildAction(String outcome, NodeState nodeState) {
		logger.error("++++++++++++++ Inside buildAction ++++++++++++++");
		logger.error("buildAction - outcome: {}", outcome);
		Action.ActionBuilder builder = goTo(outcome);
		return cleanupSharedState(nodeState, builder).build();
	}

	private Action.ActionBuilder cleanupSharedState(NodeState nodeState, Action.ActionBuilder builder) {
		logger.error("++++++++++++++ Inside cleanupSharedState ++++++++++++++");
		nodeState.remove(PINGONE_VERIFY_TRANSACTION_ID_KEY);
		nodeState.remove(PINGONE_VERIFY_DELIVERY_METHOD_KEY);
		nodeState.remove(PINGONE_VERIFY_TIMEOUT_KEY);
		nodeState.remove(PINGONE_VERIFY_REDIRECT_FLOW_CODE_KEY);
		return builder;
	}

	private Action handleFailure(NodeState nodeState, FailureReason failureReason, Exception exception) {
		logger.error("++++++++++++++ Inside handleFailure ++++++++++++++");
		logger.error(failureReason.getMessage(), exception);
		if (config.captureFailure()) {
			String failureJson = getFailureJson(failureReason, exception);
			nodeState.putShared(PINGONE_VERIFY_EVALUATION_FAILURE_REASON_KEY, failureJson);
		}
		return buildAction(FAILURE_OUTCOME_ID, nodeState);
	}

	@VisibleForTesting
	String treeResumeUri(TreeContext context) throws NodeProcessException {
		logger.error("++++++++++++++ Inside treeResumeUri ++++++++++++++");
		// Get server URL
		String serverUrl = context.request.serverUrl;
		logger.error("treeResumeUri - serverUrl: {}", serverUrl);

		// Get query parameters and add code
		Map<String, List<String>> requestQueryParameters = context.request.parameters;
		logger.error("treeResumeUri - requestQueryParameters: {}", requestQueryParameters);
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

	@VisibleForTesting
	AMIdentity getIdentity(TreeContext context) throws IdentityNotFoundException {
		logger.error("++++++++++++++ Inside getIdentity ++++++++++++++");
		return userHelper.getIdentity(context.getStateFor(this));
	}

	@Override
	public InputState[] getInputs() {
		return new InputState[] {
				new InputState(PINGONE_USER_ID_KEY, true),
				new InputState(USERNAME),
				new InputState(REALM),
				new InputState(PINGONE_VERIFY_DELIVERY_METHOD_KEY),
				new InputState(PINGONE_VERIFY_TRANSACTION_ID_KEY),
				new InputState(PINGONE_VERIFY_TIMEOUT_KEY),
				new InputState(PINGONE_VERIFY_REDIRECT_FLOW_CODE_KEY),
		};
	}

	/**
	 * Provides the PingOne Verify Evaluation node's set of outcomes.
	 */
	public static final class OutcomeProvider implements StaticOutcomeProvider {

		/**  Success outcome ID. */
		public static final String SUCCESS_OUTCOME_ID = "successOutcome";
		/**  Failure outcome ID. */
		public static final String FAILURE_OUTCOME_ID = "failureOutcome";
		/**  Timeout outcome ID. */
		public static final String TIMEOUT_OUTCOME_ID = "timeoutOutcome";

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
