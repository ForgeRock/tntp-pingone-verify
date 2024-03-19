# PingOne Verify Authentication

The PingOne Verify Authentication node lets administrators integrate PingOne Verify for Authentication functionality in a Journey.  This is done by using a stored picture compared to a live selfie


## Inputs

PingOne Username to Authenticate

## Configuration
<table>
<thead>
<th>Property</th>
<th>Usage</th>
</thead>

<tr>
<td>PingOne Service</td>
<td>Service for PingOne, PingOne DaVinci API, PingOne Protect *, and PingOne Verify</td>
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
<td>If checked user will be prompted for delivery method above
</td>
</tr>
<tr>
<td>Delivery message choice</td>
<td>The message to display to the user allowing them to choose which delivery route (QR, SMS, eMail) they would like to use
</td>
</tr>
<tr>
<td>Reference Picture Attribute</td>
<td>Transient State attribute name that contains the reference picture</td>
</tr>
<tr>
<td>Attribute containing the PingOne UserID</td>
<td>Local attribute name to contains the PingOne userID</td>
</tr>
<tr>
<td>Submission timeout</td>
<td>Verification submission timeout in seconds. Value must be under authentication session validity time.</td>
</tr><tr>
<td>Waiting message</td>
<td>The message to display while waiting for the user to complete the authentication with PingOne Verify
</td>
</tr>
<tr>
<td>Demo mode</td>
<td>When checked, the node always returns SUCCESS outcome with example data</td>
</tr>

</table>

## Outputs

`None`

## Outcomes

`Success`

Successfully Authenticated User

`Success (Patch ID)`

Successfully Authenticated User and going to Succesful Patch ID outcome

`Fail`

Failed to Authenticate User

`Fail (Patch ID)`

Failed to Authenticate User and going to Fail Path ID outcome

`Error`
There was an error within the Authentication process

## Troubleshooting


If this node logs an error, review the log messages to find the reason for the error and address the issue appropriately.
