<!--
 * This code is to be used exclusively in connection with Ping Identity Corporation software or services. Ping Identity Corporation only offers such software or services to legal entities who have entered into a binding license agreement with Ping Identity Corporation.
 *
 * Copyright 2024 Ping Identity Corporation. All Rights Reserved
-->

# PingOne Verify Nodes

The PingOne Verify node utilizes the PingOne Verify service to enable four different types of secure
user verification. These verifications include:
* [Government ID](https://docs.pingidentity.com/r/en-us/pingone/pingone_pingoneverify_types_of_verification)
* [Facial Comparison Government ID](https://docs.pingidentity.com/r/en-us/pingone/pingone_pingoneverify_types_of_verification)
* [Facial Comparison Reference Selfie](https://docs.pingidentity.com/r/en-us/pingone/pingone_pingoneverify_types_of_verification)
* [Liveness](https://docs.pingidentity.com/r/en-us/pingone/pingone_pingoneverify_types_of_verification)

> At this time, no other PingOne Verification is supported by this node.

Identity Cloud provides the following artifacts to enable the PingOne Verify Nodes:

* [PingOne service](https://github.com/ForgeRock/tntp-ping-service/tree/cloudprep?tab=readme-ov-file#ping-one-service)
* [PingOne Verify Authentication node](https://github.com/ForgeRock/tntp-pingone-verify/blob/final-marcin-mods/README.md#pingone-verify-node)
* [PingOne Verify Proofing node](http://todo)

You must set up the following before using the PingOne Verify node:

* [Create a verify policy](https://docs.pingidentity.com/r/en-us/pingone/pingone_creating_verify_policy)
* [Create a worker application](https://docs.pingidentity.com/r/en-us/pingone/p1_add_app_worker)
  * Requires [Identity Data Admin](https://apidocs.pingidentity.com/pingone/platform/v1/api/#roles) role
* [PingOne service](https://github.com/ForgeRock/tntp-ping-service/tree/cloudprep?tab=readme-ov-file#ping-one-service)

For more information on these nodes, refer to PingOne Authentication or Proofing node
