# PingOne Verify Proofing

The PingOne Verify Proofing node lets administrators integrate PingOne Verify Government ID, Facial Comparison, and
Liveness functionality in a Journey.

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

Additionally, the node first looks in the journey state for the following data:
* **Attribute containing the PingOne UserID:**  the existing PingOne User GUID

If that information is not found in the journey state, the node will lookup the user in the local datastore to retrieve
the PingOne UserID.

If the PingOne UserID does not exist in the local datastore, or does not exist in the PingOne datastore, a new user is
created in PingOne to perform the Verification.

## Configuration

<table>
  <thead>
    <th>Property</th>
    <th>Usage</th>
  </thead>
  <tbody>
    <tr>
      <td>PingOne Service</td>
      <td>Service for PingOne, PingOne DaVinci API, PingOne Protect nodes, and PingOne Verify nodes
      </td>
    </tr>
  <tr>
    <td>PingOne Verify Policy ID</td>
    <td>PingOne Verify Policy ID to use.  The policy is expected to have the following details set:<br>

- ID Verification set to REQUIRED
- Facial Comparison set to REQUIRED
- Liveness set to REQUIRED

</td>
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
      <td>Delivery message choice</td>
      <td>The message to display to the user allowing them to choose which delivery route (QR, SMS, eMail) they would
      like to use</td>
    </tr>
     <tr>
      <td>Document type required</td>
      <td>For any valid government ID leave ANY, otherwise specify the document type to enforce.</td>
    </tr>
     <tr>
      <td>PingOne UserID Attribute</td>
      <td>Local attribute name to retrieve the PingOne userID from. Will look in journey state first, then the local
      datastore</td>
    </tr>
    <tr>
      <td>Age threshold</td>
      <td>If specified (years), node will extract DOB from the claims and validate if equal or greater than specified (0
      to disable age check)</td>
    </tr>
     <tr>
      <td>Attribute map</td>
      <td>Map PingOne Verify Claims to objectAttributes. The KEY is objectAttribute Key, and the VALUE is the Verify
      Claim Key</td>
    </tr>
    <tr>
      <td>Attribute match confidence map</td>
      <td>Optionally, send the attributes entered by the user during registration to verify with imprecise matching in
      PingOne Verify. Value represents minimum confidence level to mark verification successful (LOW/MEDIUM/HIGH/EXACT)
      </td>
    </tr>
    <tr>
      <td>Fail expired documents</td>
      <td>For documents that contain expiration date, fail if out of date</td>
    </tr>
    <tr>
      <td>Submission timeout</td>
      <td>Verification submission timeout in seconds. Value must be under authentication session validity time.
      </td>
    </tr>
    <tr>
      <td>Waiting message</td>
      <td>The message to display while waiting for the user to complete the authentication with PingOne Verify.
      </td>
    </tr>
    <tr>
      <td>Save verified claims from PingOne Verify to Transient State</td>
      <td>Saves verified claims from PingOne Verify API response to Transient State, with a key of
      VerifyClaimResult</td>
    </tr>
    <tr>
      <td>Save verification metadata from PingOne Verify to Transient State</td>
      <td>Saves verification explanation data from PingOne Verify to Transient State, with a key of
      VerifyMetadataResult</td>
    </tr>
    <tr>
      <td>Leave access token in transientState</td>
      <td>If checked, PingOne access token will be preserved in transientState</td>
    </tr><tr>
      <td>Leave PingOne Verify transaction id in transientState</td>
      <td>If checked, PingOne access token will be preserved in transientState, with a key of VerifyAT</td>
    </tr>
    <tr>
      <td>Demo mode</td>
      <td>When checked, the node always returns SUCCESS outcome</td>
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

If this node logs an error, review the log messages to find the reason for the error and address the issue
appropriately.

