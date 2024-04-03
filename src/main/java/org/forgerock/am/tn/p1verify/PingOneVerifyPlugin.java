/*
 * This code is to be used exclusively in connection with Ping Identity Corporation software or services. 
 * Ping Identity Corporation only offers such software or services to legal entities who have entered into 
 * a binding license agreement with Ping Identity Corporation.
 *
 * Copyright 2024 Ping Identity Corporation. All Rights Reserved
 */

package org.forgerock.am.tn.p1verify;

import static java.util.Arrays.asList;

import java.util.Map;

import org.forgerock.openam.auth.node.api.AbstractNodeAmPlugin;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.plugins.PluginException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.ImmutableMap;

/**
 * Definition of an <a href="https://backstage.forgerock.com/docs/am/6/apidocs/org/forgerock/openam/auth/node/api/AbstractNodeAmPlugin.html">AbstractNodeAmPlugin</a>. 
 * Implementations can use {@code @Inject} setters to get access to APIs 
 * available via Guice dependency injection. For example, if you want to add an SMS service on install, you 
 * can add the following setter:
 * <pre><code>
 * {@code @Inject}
 * public void setPluginTools(PluginTools tools) {
 *     this.tools = tools;
 * }
 * </code></pre>
 * So that you can use the addSmsService api to load your schema XML for example.
 * PluginTools javadoc may be found 
 * <a href="https://backstage.forgerock.com/docs/am/6/apidocs/org/forgerock/openam/plugins/PluginTools.html#addSmsService-java.io.InputStream-">here</a> 
 * <p>
 *     It can be assumed that when running, implementations of this class will be singleton instances.
 * </p>
 * <p>
 *     It should <i>not</i> be expected that the runtime singleton instances will be the instances on which
 *     {@link #onAmUpgrade(String, String)} will be called. Guice-injected properties will also <i>not</i> be populated
 *     during that method call.
 * </p>
 * <p>
 *     Plugins should <i>not</i> use the {@code ShutdownManager}/{@code ShutdownListener} API for handling shutdown, as
 *     the order of calling those listeners is not deterministic. The {@link #onShutdown()} method for all plugins will
 *     be called in the reverse order from the order that {@link #onStartup()} was called, with dependent plugins being
 *     notified after their dependencies for startup, and before them for shutdown.
 * </p>
 * @since AM 5.5.0
 */
public class PingOneVerifyPlugin extends AbstractNodeAmPlugin {

	static private String currentVersion = "0.0.64";
	static final String logAppender = "[Version: " + currentVersion + "][Marketplace]";
	private final Logger logger = LoggerFactory.getLogger(PingOneVerifyPlugin.class);
	private String loggerPrefix = "[PingOneVerifyPlugin]" + PingOneVerifyPlugin.logAppender;
	
    /** 
     * Specify the Map of list of node classes that the plugin is providing. These will then be installed and
     *  registered at the appropriate times in plugin lifecycle.
     *
     * @return The list of node classes.
     */
	@Override
	protected Map<String, Iterable<? extends Class<? extends Node>>> getNodesByVersion() {
		return new ImmutableMap.Builder<String, Iterable<? extends Class<? extends Node>>>()
                .put(currentVersion, asList(  
                						PingOneVerifyAuthentication.class,
                						PingOneVerifyProofing.class))
                .build();
	}

    /** 
     * Handle plugin installation. This method will only be called once, on first AM startup once the plugin
     * is included in the classpath. The {@link #onStartup()} method will be called after this one.
     * 
     * No need to implement this unless your AuthNode has specific requirements on install.
     */
	@Override
	public void onInstall() throws PluginException {
		super.onInstall();
	}

    /** 
     * Handle plugin startup. This method will be called every time AM starts, after {@link #onInstall()},
     * {@link #onAmUpgrade(String, String)} and {@link #upgrade(String)} have been called (if relevant).
     * 
     * No need to implement this unless your AuthNode has specific requirements on startup.
     *
     * @param startupType The type of startup that is taking place.
     */
	@Override
	public void onStartup() throws PluginException {
		super.onStartup();
	}

    /** 
     * This method will be called when the version returned by {@link #getPluginVersion()} is higher than the
     * version already installed. This method will be called before the {@link #onStartup()} method.
     * 
     * No need to implement this untils there are multiple versions of your auth node.
     *
     * @param fromVersion The old version of the plugin that has been installed.
     */	
	@Override
	public void upgrade(String fromVersion) throws PluginException {
		logger.error(loggerPrefix + "fromVersion = " + fromVersion);
		logger.error(loggerPrefix + "currentVersion = " + currentVersion);
		try {
			pluginTools.upgradeAuthNode(PingOneVerifyAuthentication.class);
			pluginTools.upgradeAuthNode(PingOneVerifyProofing.class);
		} catch (Exception e) {
			throw new PluginException(e.getMessage());
		}
		super.upgrade(fromVersion);
	}

    /** 
     * The plugin version. This must be in semver (semantic version) format.
     *
     * @return The version of the plugin.
     * @see <a href="https://www.osgi.org/wp-content/uploads/SemanticVersioning.pdf">Semantic Versioning</a>
     */
	@Override
	public String getPluginVersion() {
		return PingOneVerifyPlugin.currentVersion;
	}
}
