<!--
 * This code is to be used exclusively in connection with Ping Identity Corporation software or services. Ping Identity Corporation only offers such software or services to legal entities who have entered into a binding license agreement with Ping Identity Corporation.
 *
 * Copyright 2024-2025 Ping Identity Corporation. All Rights Reserved
-->

# PingOne Identity Match

## Description

The PingOne Identity Match node queries PingOne to determine if a user already exists by comparing an AM user attribute against a PingOne user attribute.

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
* **Username**

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
    <td>AM identity attribute</td>
    <td>The attribute on the AM user identity that will be used to search for a match in PingOne.</td>
  </tr>
  <tr>
    <td>PingOne identity attribute</td>
    <td>The attribute on the PingOne user that will be used to match the AM user.</td>
  </tr>
  <tr>
    <td>Capture failure</td>
    <td>If selected, a failure is captured in shared state under a key named <code>pingOneIdentityMatchFailureReason</code> for use by subsequent nodes in the journey.</td>
  </tr>

</table>

## Outputs

This node places the following in shared state:

* PingOne User ID is stored in shared state under the key <code>pingOneUserId</code>
* Error detail will be stored under the key <code>pingOneIdentityMatchFailureReason</code> _(if enabled)_

## Outcomes

`True` A PingOne user match was found.

`False` No matching user was found in PingOne, or an error occurred.
