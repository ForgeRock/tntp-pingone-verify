# PingOne Verify Authentication

The PingOne Verify Authentication node lets administrators integrate PingOne Verify biometric authentication
functionality in a Journey.  This is done by using a stored picture compared to a live selfie.

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

This node retrieves from the shared state:
* **The UserName**

Additionally, the node first looks in the shared state for the following data:
* **Attribute containing the PingOne UserID:**  the existing PingOne User GUID
* **Reference Picture Attribute:** that contains a Base64-encoded reference self-image. Image must be JPEG format.

If that information is not found in the shared state, the node will lookup the user in the local datastore to retrieve
the PingOne UserID and reference picture.

If the PingOne UserID does not exist in the local datastore, or does not exist in the PingOne datastore, a new user is
created in PingOne to perform the Verify facial-biometric authentication.

## Configuration

<table>
  <thead>
  <th>Property</th>
  <th>Usage</th>
  </thead>

  <tr>
    <td>PingOne Service</td>
    <td>Service for PingOne, PingOne DaVinci API, PingOne Protect *, and PingOne Verify Nodes</td>
  </tr>
  <tr>
    <td>PingOne Verify Policy ID</td>
    <td>PingOne Verify Policy ID to use.  The policy is expected to have Facial Comparison set to <b>Required</b></td>
  </tr>
  <tr>
    <td>Verify URL delivery mode</td>
    <td>QR code to display or E-mail/SMS for direct delivery</td>
  </tr>
  <tr>
    <td>Let user choose the delivery method</td>
    <td>If checked user will be prompted for delivery method above
    </td>
  </tr>
  <tr>
    <td>Delivery message choice</td>
    <td>The message to display to the user allowing them to choose which delivery route (QR, SMS, eMail) they would like
      to use
    </td>
  </tr>
  <tr>
    <td>Reference Picture Attribute</td>
    <td>Transient State attribute name that contains the reference picture</td>
  </tr>
  <tr>
    <td>Attribute containing the PingOne UserID</td>
    <td>Local attribute name that contains the PingOne userID</td>
  </tr>
  <tr>
    <td>Submission timeout</td>
    <td>Verification submission timeout in seconds. Value must be under authentication session validity time.</td>
  </tr>
  <tr>
    <td>Waiting message</td>
    <td>The message to display while waiting for the user to complete the authentication with PingOne Verify
    </td>
  </tr>
  <tr>
    <td>Demo mode</td>
    <td>When checked, the node always returns SUCCESS outcome</td>
  </tr>

</table>

## Outputs

If `Success (Patch ID)` or `Fail (Patch ID)` outcome is taken, the `Attribute containing the PingOne UserID` key will be
placed in shared state as well as in `objectAttribute` so the local user can be patched with the new user GUID that was
created in PingOne for the Verification.  Please save the returned GUID to the local user so the node doesn't need to
create a new PingOne user on the next use.


## Outcomes

`Success`

Successfully authenticated the users store selfie and live selfie

`Success (Patch ID)`

Successfully authenticated the users store selfie and live selfie.  Additionally, the Node needed to create a new
PingOne user in PingOne to perform the Verification. This is because either the stored GUID on the local user was
invalid or did exist. The Node stored the new users PingOne GUID in the shared state on the `Attribute containing the
PingOne UserID`key as well as on the objectAttribute so the GUID can be stored on the local users account and used for
future Authentication verifications.

`Fail`

Failed to authenticate the users store selfie and live selfie.

`Fail (Patch ID)`

Failed to authenticate the users store selfie and live selfie.  Additionally, the Node needed to create a new PingOne
user in PingOne to perform the Verification. This is because either the stored GUID on the local user was invalid or did
exist. The Node stored the new users PingOne GUID in the shared state on the `Attribute containing the PingOne UserID`
key as well as on the objectAttribute so the GUID can be stored on the local users account and used for future
Authentication verifications.

`Error`
There was an error during the Authentication process

## Troubleshooting


If this node logs an error, review the log messages to find the reason for the error and address the issue appropriately
