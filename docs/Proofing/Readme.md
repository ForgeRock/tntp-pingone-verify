# PingOne Verify Registration

The PingOne Verify node lets administrators integrate PingOne Verify for Registration functionality in a Journey
> At this time, no other PingOne Verification is supported by this node.

Identity Cloud provides the following artifacts to enable the PingOne Verify Node:

* [PingOne service](https://github.com/ForgeRock/tntp-ping-service/tree/cloudprep?tab=readme-ov-file#ping-one-service)
* [PingOne Verify node](https://github.com/ForgeRock/tntp-pingone-verify/blob/final-marcin-mods/README.md#pingone-verify-node)

You must set up the following before using the PingOne Verify node:

* [Create a verify policy](https://docs.pingidentity.com/r/en-us/pingone/pingone_creating_verify_policy)
* [Create a worker application](https://docs.pingidentity.com/r/en-us/pingone/p1_add_app_worker)
    * Requires [Identity Data Admin](https://apidocs.pingidentity.com/pingone/platform/v1/api/#roles) role
* [PingOne service](https://github.com/ForgeRock/tntp-ping-service/tree/cloudprep?tab=readme-ov-file#ping-one-service)

For more information on this node, refer to PingOne Verify node

## PingOne Setup
You must set up the following before using the PingOne Verify node:

* [Create a verify policy](https://docs.pingidentity.com/r/en-us/pingone/pingone_creating_verify_policy)
* [Create a worker application](https://docs.pingidentity.com/r/en-us/pingone/p1_add_app_worker)
    * Requires [Identity Data Admin](https://apidocs.pingidentity.com/pingone/platform/v1/api/#roles) role
* [PingOne service](https://github.com/ForgeRock/tntp-ping-service/tree/cloudprep?tab=readme-ov-file#ping-one-service)


## Inputs

`None`

## Configuration
<table>
  <thead>
    <th>Property</th>
    <th>Usage</th>
  </thead>
  <tbody>
    <tr>
      <td>PingOne Service</td>
      <td>Service for PingOne, PingOne DaVinci API, PingOne Protect *, and PingOne Verify *
      </td>
    </tr>
     <tr>
      <td>PingOne Verify Policy ID</td>
      <td>PingOne Verify Policy ID to use</td>
    </tr>
     <tr>
      <td>Verify URL delivery mode</td>
      <td>QR code to display or E-mail/SMS for direct delivery</td>
    </tr>
     <tr>
      <td>Let user choose the delivery method</td>
      <td>If checked user will be prompted for delivery method above</td>
    </tr>
     <tr>
      <td>Document type required</td>
      <td>For any valid government ID leave DEFAULT, otherwise specify the document type to enforce.</td>
    </tr>
     <tr>
      <td>Attribute to store PingOne UserID</td>
      <td>Local attribute name to store the PingOne userID created</td>
    </tr>
     <tr>
      <td>Attribute map</td>
      <td>Map PingOne Verify Claims to objectAttributes. The KEY is objectAttribute Key, and the VALUE is the Verify Claim Key</td>
    </tr>
<tr>
      <td>Preserve matched attributes</td>
      <td>Tick this flag to preserve attributes that the user provided prior to the proofing process. Otherwise PingOne Verify verified claims will override.</td>
    </tr>
<tr>
      <td>Attribute match confidence map</td>
      <td>Optionally, send the attributes entered by the user during registration to verify with imprecise matching in PingOne Verify. Value represents minimum confidence level to mark verification successful (LOW/MEDIUM/HIGH/EXACT)
</td>
    </tr>
<tr>
      <td>Age threshold</td>
      <td>If specified (years), node will extract DOB from the claims and validate if equal or greater than specified (0 or empty to disable age check)</td>
    </tr>
<tr>
      <td>Fail expired documents</td>
      <td>For documents that contain expiration date, fail if out of date</td>
    </tr><tr>
      <td>Submission timeout</td>
      <td>Verification submission timeout in seconds. Value must be under authentication session validity time.
</td>
    </tr><tr>
      <td>Save verified claims from PingOne Verify to sharedState</td>
      <td>Saves verified claims from PingOne Verify API response to sharedState as a JSON object</td>
    </tr><tr>
      <td>Save verification metadata from PingOne Verify to Transient State</td>
      <td>Saves verification explanation data from PingOne Verify to Transient State as a JSON array</td>
    </tr><tr>
      <td>Leave access token in transientState</td>
      <td>If checked, PingOne access token will be preserved in transientState</td>
    </tr><tr>
      <td>Leave PingOne Verify transaction id in transientState</td>
      <td>If checked, PingOne Verify transaction id will be preserved in transientState</td>
    </tr><tr>
      <td>Demo mode</td>
      <td>When checked, the node always returns SUCCESS outcome with example data</td>
    </tr>
  </tbody>
</table>

## Outputs
<ul>
<li>Created UserID</li>
<li>Verified Claims</li>
<li>Verification metadata</li>
<li>Access Token</li>
<li>TransactionID</li>
</ul>

## Outcomes
`Success`

Successfully registered user with PingOne

`Fail`

Registration with PingOne failed

`Error`

There was an error within the Registration process

`Age Fail`

Age is below the Age threshold

## Troubleshooting

If this node logs an error, review the log messages to find the reason for the error and address the issue appropriately.

