/*
 * This code is to be used exclusively in connection with Ping Identity Corporation software or services. 
 * Ping Identity Corporation only offers such software or services to legal entities who have entered into 
 * a binding license agreement with Ping Identity Corporation.
 *
 * Copyright 2024 Ping Identity Corporation. All Rights Reserved
 */

package org.forgerock.am.tn.p1verify;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.ResourceBundle;

import javax.inject.Inject;

import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeState;
import org.forgerock.openam.auth.node.api.OutcomeProvider;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.auth.service.marketplace.TNTPPingOneConfig;
import org.forgerock.openam.auth.service.marketplace.TNTPPingOneConfigChoiceValues;
import org.forgerock.openam.core.CoreWrapper;
import org.forgerock.openam.core.realms.Realm;
import org.forgerock.util.i18n.PreferredLocales;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.inject.assistedinject.Assisted;


@Node.Metadata(
		outcomeProvider = Proofing.ProofingOutcomeProvider.class, 
		configClass = Proofing.Config.class, 
		tags = {"marketplace", "trustnetwork" })
public class Proofing implements Node {

	private final Config config;
	private final Realm realm;
	private TNTPPingOneConfig tntpPingOneConfig;
	private final CoreWrapper coreWrapper;
	
	private final Logger logger = LoggerFactory.getLogger(Proofing.class);
	private final String loggerPrefix = "[PingOne Verify Proofing Node]" + PingOneVerifyPlugin.logAppender;
	
	public static final String BUNDLE = Proofing.class.getName();

	/**
	 * Configuration for the node.
	 */
	public interface Config {

		/**
		 * The Configured service
		 */
		@Attribute(order = 100, choiceValuesClass = TNTPPingOneConfigChoiceValues.class)
		default String tntpPingOneConfigName() {
			return TNTPPingOneConfigChoiceValues.createTNTPPingOneConfigName("Global Default");
		};

		@Attribute(order = 200)
		default String verifyPolicyId() {
			return "";
		}

		@Attribute(order = 300)
		default Constants.UserNotification userNotification() {
			return Constants.UserNotification.QR;
		}

		@Attribute(order = 400)
		default boolean userNotificationChoice() {
			return false;
		}
		
		@Attribute(order = 500)
		default Constants.GovId govId() {
			return Constants.GovId.DEFAULT;
		}

		@Attribute(order = 600)
		default String userIdAttribute() {
			return "";
		}
		
		@Attribute(order = 700)
		default Map<String, String> attributeMappingConfiguration() {
			return new HashMap<String, String>() {
				{
					/*
					 * key is DS attribute name, value is the claim name in PingOneVerify verified
					 * claims
					 */
					put("givenName", "firstName");
					put("sn", "lastName");
					put("cn", "fullName");
					put("postalAddress", "address");
					put("country", "country");
					put("birthDateAttribute", "birthDate");
					put("idNumberAttribute", "idNumber");
					put("idTypeAttribute", "idType");
					put("expirationDateAttribute", "expirationDate");
				}
			};
		}

		@Attribute(order = 900)
		default Map<String, String> fuzzyMatchingConfiguration() {
			return new HashMap<String, String>() {
				{
					/*
					 * key is DS attribute name, value is the confidence level required for success
					 */
					put("givenName", "LOW");
					put("sn", "HIGH");
					put("address", "LOW");
					put("cn", "MEDIUM");
					put("birthDateAttribute", "EXACT");
				}
			};
		}


		@Attribute(order = 1100)
		default boolean failExpired() {
			return false;
		}

		@Attribute(order = 1200)
		default int timeOut() {
			return 270;
		}

		@Attribute(order = 1300)
		default boolean saveVerifiedClaims() {
			return false;
		}

		@Attribute(order = 1400)
		default boolean saveMetadata() {
			return false;
		}

		@Attribute(order = 1500)
		default boolean tsAccessToken() {
			return false;
		}

		@Attribute(order = 1600)
		default boolean tsTransactionId() {
			return false;
		}

		@Attribute(order = 1700)
		default boolean demoMode() {
			return false;
		}

	}

	/**
	 * Create the node using Guice injection. Just-in-time bindings can be used to
	 * obtain instances of other classes from the plugin.
	 *
	 * @param config The service config.
	 * @param realm  The realm the node is in.
	 */
	@Inject
	public Proofing(@Assisted Config config, @Assisted Realm realm, CoreWrapper coreWrapper) {
		this.coreWrapper = coreWrapper;
		this.config = config;
		this.realm = realm;
		this.tntpPingOneConfig = TNTPPingOneConfigChoiceValues.getTNTPPingOneConfig(config.tntpPingOneConfigName());
	}

	@Override
	public Action process(TreeContext context) {
		NodeState ns = context.getStateFor(this);
		try {
			logger.debug(loggerPrefix + "Started");

			/* if we're here, something went wrong */
			return Action.goTo(Constants.ERROR).build();
		} catch (Exception ex) {
			String stackTrace = org.apache.commons.lang.exception.ExceptionUtils.getStackTrace(ex);
			logger.error(loggerPrefix + "Exception occurred: " + stackTrace);
			context.getStateFor(this).putShared(loggerPrefix + "Exception", ex.getMessage());
			context.getStateFor(this).putShared(loggerPrefix + "StackTrace", stackTrace);
			return Action.goTo(Constants.ERROR).build();
		}
	}

	public static class ProofingOutcomeProvider implements OutcomeProvider {
		@Override
		public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {
			ResourceBundle bundle = locales.getBundleInPreferredLocale(Proofing.BUNDLE,
					OutcomeProvider.class.getClassLoader());
			List<Outcome> results = new ArrayList<>();
			results.add(new Outcome(Constants.SUCCESS, bundle.getString("successOutcome")));
			results.add(new Outcome(Constants.FAIL, bundle.getString("failOutcome")));
			results.add(new Outcome(Constants.ERROR, bundle.getString("errorOutcome")));
			return Collections.unmodifiableList(results);
		}
	}
}
