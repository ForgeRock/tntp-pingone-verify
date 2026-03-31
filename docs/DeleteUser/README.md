<!--
 * This code is to be used exclusively in connection with Ping Identity Corporation software or services. Ping Identity Corporation only offers such software or services to legal entities who have entered into a binding license agreement with Ping Identity Corporation.
 *
 * Copyright 2024-2025 Ping Identity Corporation. All Rights Reserved
-->

# PingOne Delete User

## Description

Deletes a PingOne user by referencing the user's PingOne ID from shared state.

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
* **PingOne User ID**

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
    <td>Capture Failure</td>
    <td>If selected, a failure is captured in shared state under a key named <code>pingOneDeleteUserFailureReason</code> for use by subsequent nodes in the journey.</td>
  </tr>

</table>

## Outputs

This node places the following in shared state _(if enabled)_:
* Captured failure reason

## Outcomes

`Success` The user was successfully deleted from PingOne.

`Failure` The user could not be deleted due to an error or missing data.
