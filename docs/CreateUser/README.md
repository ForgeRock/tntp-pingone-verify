<!--
 * This code is to be used exclusively in connection with Ping Identity Corporation software or services. Ping Identity Corporation only offers such software or services to legal entities who have entered into a binding license agreement with Ping Identity Corporation.
 *
 * Copyright 2024-2025 Ping Identity Corporation. All Rights Reserved
-->

# PingOne Create User

## Description

Creates a new user in PingOne. User attributes can be sourced from either the AM identity profile (based on the AM username in shared state) or from the `objectAttributes` object in shared state.

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

* **AM Username (`username`)**
    * Required when building the PingOne user from the AM identity profile.
      * Must exist either in shared state or in the `objectAttributes` object in shared state.


* **`objectAttributes`**
    * Required in shared state when `User Attributes from Object Attributes = true`.
    * Must include at least `username`. 
      * Additional attributes can be included to populate the PingOne user profile.

Full list of available PingAM attributes:


## Configuration

<table>
  <thead>
  <th>Property</th>
  <th>Usage</th>
  </thead>

  <tr>
    <td>PingOne Service</td>
    <td>Service for PingOne, PingOne Verify, PingOne Protect, and PingOne DaVinci API.</td>
  </tr>
  <tr>
    <td>Population ID</td>
    <td>The unique identifier for the PingOne population. If not specified, the node uses the environment's default population.</td>
  </tr>
  <tr>
    <td>Anonymized PingOne User</td>
    <td>If enabled, the user is created with minimal attributes (username and preferred language only).</td>
  </tr>
  <tr>
    <td>User Attributes from Object Attributes</td>
    <td>If enabled, the node retrieves user attributes from the shared state <code>objectAttributes</code> object to build the PingOne user. If disabled, the node retrieves attributes from the AM identity profile.</td>
  </tr>
  <tr>
    <td>AM Identity Attribute</td>
    <td>The AM identity attribute used as the key to look up the user when building the PingOne user from an AM identity. Only applies if <code>User Attributes from Object Attributes</code> is disabled.</td>
  </tr>
  <tr>
    <td>Capture Failure</td>
    <td>If enabled, failure details are captured in shared state under the key <code>pingOneCreateUserFailureReason</code> for use by subsequent nodes in the journey.</td>
  </tr>

</table>

## Outputs

This node places the following in shared state:

* The PingOne User ID
* Captured failure reason _(if enabled)_

## Outcomes

`Success` The user was created successfully in PingOne.

`Failure` The user could not be created in PingOne.
