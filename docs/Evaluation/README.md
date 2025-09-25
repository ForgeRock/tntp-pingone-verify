<!--
 * This code is to be used exclusively in connection with Ping Identity Corporation software or services. Ping Identity Corporation only offers such software or services to legal entities who have entered into a binding license agreement with Ping Identity Corporation.
 *
 * Copyright 2024-2025 Ping Identity Corporation. All Rights Reserved
-->

# PingOne Verify Evaluation

## Description

The PingOne Verify Evaluation node initiates an identity verification transaction for the user in PingOne Verify. Based on the delivery method setting, the verification link is delivered via QR Code, Email, SMS, or instant Redirect.

## Compatibility

<table>
  <colgroup>
    <col>
    <col>
  </colgroup>
  <thead>
  <tr>
    <th>Product</th>
    <th>Compatible?</th>
  </tr>
  </thead>
  <tbody>
  <tr>
    <td><p>ForgeRock Identity Cloud</p></td>
    <td><p><span>Yes</span></p></td>
  </tr>
  <tr>
    <td><p>ForgeRock Access Management (self-managed)</p></td>
    <td><p><span>Yes</span></p></td>
  </tr>
  <tr>
    <td><p>ForgeRock Identity Platform (self-managed)</p></td>
    <td><p><span>Yes</span></p></td>
  </tr>
  </tbody>
</table>

## Inputs

This node retrieves from the journey state:

* **PingOne User ID (`pingOneUserId`)**
  * Required when `Create PingOne User = false`.
  * Not required when `Create PingOne User = true` (the node will create a user and store the new user ID in shared state).


* **AM Username (`username`)**
  * Required in shared state, or `objectAttributes`, to resolve the desired AM identity.
    * If `Create PingOne User = true` and `User Attributes from Object Attributes = false`:
      * The PingOne user is created from the AM identity attributes of the corresponding `username`.
    * If Delivery method is `EMAIL` or `SMS` and `User Attributes from Object Attributes = false` 
      * Fetches `mail` or `telephoneNumber` from the AM Identity of the corresponding `username`.


* **`objectAttributes`**
  * Required when `User Attributes from Object Attributes = true`.
  * Must at least include the following user attribute keys:
    * `username` for user creation.
    * `mail` if using the `EMAIL` delivery method.
    * `telephoneNumber` if using the `SMS` delivery method.
  * Include any other additional user attributes needed for the new PingOne user.


> Note: All user attributes used within a single run must refer to the same end user. When the node creates the PingOne user, it writes that user’s ID to shared state so subsequent steps use the correct identity automatically.

## Configuration

<table>
  <thead>
  <th>Property</th>
  <th>Usage</th>
  </thead>

  <tr>
    <td>PingOne Service</td>
    <td>Service for PingOne, PingOne DaVinci API, PingOne Protect nodes, and PingOne Verify nodes</td>
  </tr>
  <tr>
    <td>PingOne Verify Policy ID</td>
    <td>The ID of the PingOne Verify Policy.</td>
  </tr>
  <tr>
    <td>Verify URL delivery mode</td>
    <td>Specifies how the verification URL is delivered to the user: QR code, email, SMS, or redirect</td>
  </tr>
  <tr>
    <td>Allow user to choose the URL delivery method</td>
    <td>If enabled, the user is prompted to choose between QR Code, Email, SMS, Redirect. Does not apply if the delivery method is set to <code>Redirect</code></td>
  </tr>
  <tr>
    <td>Delivery Method Message</td>
    <td>The message to display to the user allowing them to choose the delivery method to receive the verify URL (QRCODE, SMS, EMAIL).</td>
  </tr>
  <tr>
    <td>QR Code Message</td>
    <td>The message with instructions to scan the QR code to begin the identity verification process.</td>
  </tr>
  <tr>
    <td>Waiting Message</td>
    <td>Localization overrides for the waiting message. This is a map of locale to message.</td>
  </tr>
  <tr>
    <td>Redirect Message</td>
    <td>The message to display to the user after the identity verification process is complete and the user is redirected back to the Journey.</td>
  </tr>
  <tr>
    <td>Verify Transaction Timeout</td>
    <td>The period of time (in seconds) to wait for a response to the Verify transaction. If no response is received during this time the node times out and the verification process fails.</td>
  </tr>
  <tr>
    <td>Create PingOne User</td>
    <td>If enabled, the node will create a PingOne user if one does not already exist. If disabled, the node expects a PingOne user ID to be present in shared state.</td>
  </tr>
  <tr>
    <td>Population ID</td>
    <td>The unique identifier for the PingOne population. Used only if <code>Create PingOne User</code> is enabled. If not specified, the environment's default population is used.</td>
  </tr>
  <tr>
    <td>Anonymized PingOne User</td>
    <td>Whether to create an anonymized PingOne user. An anonymized user stores only minimal identifying information (username and preferred language). Used only if <code>Create PingOne User</code> is enabled.</td>
  </tr>
  <tr>
    <td>User Attributes from Object Attributes</td>
    <td>If enabled, the node retrieves user attributes from the shared state object <code>objectAttributes</code> instead of retrieving them from an AM identity. This affects PingOne user creation and delivery method attributes (EMAIL/SMS). Typically, this option is only relevant when <code>Create PingOne User</code> is enabled.</td>
  </tr>
  <tr>
    <td>AM Identity Attribute</td>
    <td>The attribute of the existing AM identity object that will be used as the key to identify the user in the PingOne directory. Used only if <code>Create PingOne User</code> is enabled and <code>User Attributes from Object Attributes</code> is disabled.</td>
  </tr>
  <tr>
    <td>Store Verification Metadata</td>
    <td>If enabled, verification metadata is stored in shared state</td>
  </tr>
  <tr>
    <td>Store Verified Data</td>
    <td>Store the list of verified data submitted by the user in the shared state under a key named <code>pingOneVerifyVerifiedData</code>.<br><br> <em>Note</em>: The key is empty if the node is unable to retrieve the verified data from PingOne.</td>
  </tr>
  <tr>
    <td>Capture Failure</td>
    <td>If selected, a failure is captured in shared state under a key named <code>pingOneVerifyEvaluationFailureReason</code> for use by subsequent nodes in the journey.</td>
  </tr>

</table>

## Outputs

This node places the following in shared state:

* The PingOne User ID
* The PingOne Verify Transaction ID 
* Verification decision metadata _(if enabled)_
* Verified identity data _(if enabled)_
* Captured failure reason _(if enabled)_

## Outcomes

`Success` The verification completed successfully.

`Failure` There was an error or verification failed.

`Time Out` The verification process timed out.
