# PingOne Verify Verification

The PingOne Verify node utilizes the PingOne Verify service to enable four different types of secure
user verification. These verifications include:
* [Government ID](https://docs.pingidentity.com/r/en-us/pingone/pingone_pingoneverify_types_of_verification)
* [Facial Comparison Government ID](https://docs.pingidentity.com/r/en-us/pingone/pingone_pingoneverify_types_of_verification)
* [Facial Comparison Reference Selfie](https://docs.pingidentity.com/r/en-us/pingone/pingone_pingoneverify_types_of_verification)
* [Liveness](https://docs.pingidentity.com/r/en-us/pingone/pingone_pingoneverify_types_of_verification)

The PingOne Verify Verification node lets administrators integrate PingOne Verify for Verification functionality in a Journey

## Inputs
PingOne Username to verify

## Configuration

<table>
<thead>
<th>Property</th>
<th>Usage</th>
</thead>
<tr>
<td>PingOne Service</td>
<td>Service for PingOne, PingOne DaVinci API, PingOne Protect *, and PingOne Verify
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
</tr><tr>
<td>PingOne UserID Attribute</td>
<td>Local attribute name to retrieve the PingOne userID from.  Will look in sharedState first, then the local datastore</td>
</tr><tr>
<td>Attribute map</td>
<td>Map PingOne Verify Claims to objectAttributes. The KEY is objectAttribute Key, and the VALUE is the Verify Claim Key</td>
</tr>
<tr>
<td>Attribute match confidence map</td>
<td>Optionally, send the attributes entered by the user during registration to verify with imprecise matching in PingOne Verify. Value represents minimum confidence level to mark verification successful (LOW/MEDIUM/HIGH/EXACT)</td>
</tr><tr>
<td>Fail expired documents</td>
<td>For documents that contain expiration date, fail if out of date</td>
</tr>
<tr>
<td>Submission timeout</td>
<td>Verification submission timeout in seconds. Value must be under authentication session validity time.</td>
</tr>
<tr>
<td>Save verified claims from PingOne Verify to sharedState</td>
<td>Saves verified claims from PingOne Verify API response to sharedState as a JSON object</td>
</tr>
<tr>
<td>Save verification metadata from PingOne Verify to Transient State</td>
<td>Saves verification explanation data from PingOne Verify to Transient State as a JSON array</td>
</tr>
<tr>
<td>Leave access token in transientState</td>
<td>If checked, PingOne access token will be preserved in transientState</td>
</tr>
<tr>
<td>Leave PingOne Verify transaction id in transientState</td>
<td>If checked, PingOne Verify transaction id will be preserved in transientState</td>
</tr>
<tr>
<td>Demo Mode</td>
<td>When checked, the node always returns SUCCESS outcome with example data</td>
</tr>

</table>

## Outputs

<ul>
<li>Confidence level of the Verification</li>
<li>Verified Claims</li>
<li>Verification metadata</li>
<li>Access Token</li>
<li>Transaction ID</li>
</ul>

## Outcomes

`Success`

Successfully verified PingOne User

`Fail`

Failed in verifying the User

`Error`


There was an error within the Verification process

`Age Fail`

Age is below the Age threshold

## Troubleshooting


If this node logs an error, review the log messages to find the reason for the error and address the issue appropriately.

