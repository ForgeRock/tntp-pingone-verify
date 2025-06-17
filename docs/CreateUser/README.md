<!--
 * This code is to be used exclusively in connection with Ping Identity Corporation software or services. Ping Identity Corporation only offers such software or services to legal entities who have entered into a binding license agreement with Ping Identity Corporation.
 *
 * Copyright 2024-2025 Ping Identity Corporation. All Rights Reserved
-->

# PingOne Create User

## Description

Creates a new user in PingOne using attributes from the local AM identity profile.

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
* **The UserName**

## Configuration

<table>
  <thead>
  <th>Property</th>
  <th>Usage</th>
  </thead>

  <tr>
    <td>PingOne Service</td>
    <td>Service for PingOne, PingOne Verify, PingOne Protect *, and PingOne DaVinci API.</td>
  </tr>
  <tr>
    <td>Population ID</td>
    <td>The unique identifier for the PingOne population. If not specified, the node uses the environment's default population.</td>
  </tr>
  <tr>
    <td>Anonymized user</td>
    <td>If enabled, the user is created with limited attributes (e.g., no name or contact details).</td>
  </tr>
  <tr>
    <td>AM identity attribute</td>
    <td>The attribute of the existing AM identity object that will be used as key to identify the user in the PingOne directory server.</td>
  </tr>
  <tr>
    <td>Capture failure</td>
    <td>If selected, a failure is captured in shared state under a key named <code>pingOneCreateUserFailureReason</code> for use by subsequent nodes in the journey.</td>
  </tr>

</table>

## Outputs

This node places the following in shared state:

* The PingOne user ID under the key <code>pingOneUserId</code>
* Captured failure reason _(if enabled)_

## Outcomes

`Success` The user was created successfully in PingOne.

`Failure` The user could not be created in PingOne.
