<!--
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2023 ForgeRock AS.
-->
# PingOneVerify

A simple authentication node for ForgeRock's [Identity Platform][forgerock_platform] 7.3.0 and above. This node utilizes the PingOne Verify service to enable sercure user verification based on a government-issued document and live face capture (a selfie).


## Before you begin

Regardless of the configuration method you choose you'll need

<ul>
<li>A <span>PingOne</span> account with at least one environment that includes the <span class="keyword">PingOne Verify</span> service.<p class="p">For more information, see <a class="xref" href="https://docs.pingidentity.com/r/en-us/pingone/p1_start_a_pingone_trial?tocId=WnDBFzVrhcZcDTKV8jBNJQ" target="_blank" data-ft-click-interceptor="ft-internal-link">Starting a <span class="keyword">PingOne</span> trial</a> and <a class="xref" href="https://docs.pingidentity.com/r/en-us/pingone/pingone_tutorial_passwordless_create_environment?tocId=iMH1irb9RViMCilbTCCLEg" target="_blank" data-ft-click-interceptor="ft-internal-link">Creating an environment</a>.</p></li>
<li class="li">A <span class="keyword">PingOne Verify</span> policy.<p class="p">For more information on configuring a policy, see <a class="xref ft-internal-link" href="https://docs.pingidentity.com/r/0ue6NPmZLPN667l6iXUjRg/jWR8wPQq~vaG7r0cfQL~fA" title="A verify policy dictates what is required to verify a user, such as an ID verification, facial comparison, or liveness." data-ft-click-interceptor="ft-internal-link">Creating a verify policy</a>.</p></li>
</ul>


There are four ways to configure PingOne Verify:

<ul>
<li>API integration</li>
<li>PingOne DaVinci</li>
<li>PingFederate Integration Kit</li>
<li>Mobile SDK</li>
</ul>

The configuration method that you choose depends on your role.
Click here to learn more <a href="https://docs.pingidentity.com/r/en-us/pingone/pingone_verify_getting_started_configuring">(Configuring PingOne Verify)</a>

## Inputs

`None`
<table class="table frame-all" id="jzf1692634635960__table_y2d_vml_nyb"><colgroup><col style="width:33.33333333333333%"><col style="width:66.66666666666666%"></colgroup><thead class="thead">
						<tr class="row">
							<th class="entry colsep-1 rowsep-1" id="jzf1692634635960__table_y2d_vml_nyb__entry__1">Property</th>
							<th class="entry colsep-1 rowsep-1" id="jzf1692634635960__table_y2d_vml_nyb__entry__2">Usage</th>
						</tr>
					</thead><tbody class="tbody">
						<tr class="row">
							<td class="entry colsep-1 rowsep-1" headers="jzf1692634635960__table_y2d_vml_nyb__entry__1">
								<p class="p">PingOne Environment ID</p>
							</td>
							<td class="entry colsep-1 rowsep-1" headers="jzf1692634635960__table_y2d_vml_nyb__entry__2">
                PingOne Environmnent ID (Environment->Properties->Environment ID in PingOne console)</td>
						</tr>
						<tr class="row">
							<td class="entry colsep-1 rowsep-1" headers="jzf1692634635960__table_y2d_vml_nyb__entry__1">
                                PingOne client_id</td>
							<td class="entry colsep-1 rowsep-1" headers="jzf1692634635960__table_y2d_vml_nyb__entry__2">
								PingOne client_id for the Verify API</td>
						</tr>
						<tr class="row">
							<td class="entry colsep-1 rowsep-1" headers="jzf1692634635960__table_y2d_vml_nyb__entry__1">
								<p class="p">PingOne client_secret
</p>
							</td>
							<td class="entry colsep-1 rowsep-1" headers="jzf1692634635960__table_y2d_vml_nyb__entry__2">
								PingOne client_secret for the verify API client_id
							</td>
						</tr>
<tr>
    <td>
       PingOne Verify Region
    </td>
    <td>
        PingOne Verify Region
    </td>
</tr>

<tr>
    <td>
        PingOne Verify UserID attribute in DS
    </td>
    <td>
        Attribute name in DS for PingOne pseudoanonymized userId
    </td>
</tr>
<tr>
    <td>
        PingOne Verify Policy ID
    </td>
    <td>
        PingOne Verify Policy ID to be used in this flow
    </td>
</tr>

<tr>
    <td>
        Verify URL delivery mode
    </td>
<td>
QR code to display or E-mail/SMS for direct delivery
</td>
</tr>

<tr>
<td>
Allow user to choose the verification url delivery method
</td>
<td>
If checked user will be prompted for delivery method
</td>
</tr>

<tr>
<td>
Flow Type
</td>

<td>
REGISTRATION (map verified document claims to objectProperties), VERIFICATION (match directory service attributes to verified document claims)
</td>
</tr>

<tr>
<td>
Age threshold
</td>

<td>
If specified (years), node will extract DOB from the claims and validate if equal or greater than specified (0 or empty to disable age check)
</td>
</tr>

<tr>
<td>
Fail expired documents
</td>
<td>
For documents that contain expiration date, fail if out of date
</td>
</tr>

<tr>
<td>
Submission timeout
</td>
<td>
Verification submission timeout in seconds. Value must be under authentication session validity time.
</td>
</tr>

<tr>
<td>Save verified claims from PingOne Verify to sharedState</td>
<td>Saves verified claims from PingOne Verify API response to sharedState as a JSON object</td>
</tr>

<tr>
<td>Save verification metadata from PingOne Verify to sharedState</td>
<td>Saves verification explanation data from PingOne Verify to sharedState as a JSON array</td>
</tr>

<tr>
<td>Attribute Map</td>
<td>Map for picking which PingOne Verify Verified Claims should correspond with ForgeRockLDAP Attributes. The KEY should be the PingOne Verify JSON key and the VALUE should be the corresponding ForgeRock LDAP Attribute. This is used both for REGISTRATION and VERIFICATION scenarios (PingOne verify to ForgeRock and ForgeRock to PingOne Verify</td>
</tr>

<tr>
<td>Attributes to match (ds names)</td>
<td>Specify attributes (ds names) that have to match following successful verification by PingOne Verify (matching existing user attributes to verified claims)</td>
</tr>

<tr>
<td>Preserve matched attributes</td>
<td>If REGISTRATION uses attribute verification, tick this flag to preserve attributes that user provided prior to verification process. Otherwise PingOne Verify verified claims will override.</td>
</tr>

<tr>
<td>Imprecise matching attribute confidence map</td>
<td>If selected, user's profile ds attribute is verified with imprecise matching in PingOne Verify (those attribute(s) must be present in 'attributes to match' object). Value represents minimum confidence level to mark verification successful (LOW/MEDIUM/HIGH)</td>
</tr>

<tr>
<td>Attribute lookup</td>
<td>Determines whether attribute lookup in DS should occur during VERIFICATION flow. If true, existing user is queried. Otherwise, objectAttributes in shared state are used</td>
</tr>

<tr>
<td>Demo mode</td>
<td>When checked, the node always returns SUCCESS outcome with example data</td>
</tr>

</tbody></table>



Copy the .jar file from the ../target directory into the ../web-container/webapps/openam/WEB-INF/lib directory where AM is deployed.  Restart the web container to pick up the new node.  The node will then appear in the authentication trees components palette.


## Outputs

`Verified user's data`

## Outcomes

`Success`

Successful attempt to get verified data


`Fail`

Failed to get verified data


`Error`

Reasons for Error could be that the session expired, UserID not defined, or value
missing in shared state 


## Troubleshooting

<p dir="auto">If this node logs an error, review the log messages the find the reason for the error and address the issue appropriately. There are also many publicly accessible test endpoints which can be used to help test and troubleshoot with this node. For example <a href="https://httpstat.us" rel="nofollow">https://httpstat.us</a> and <a href="https://postman-echo.com" rel="nofollow">https://postman-echo.com</a>.</p>


## Examples

This example journey highlights the use of the PingOne Verify node to authenticate 

![ScreenShot](./example.png)

        

