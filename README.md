<!--
 * This code is to be used exclusively in connection with Ping Identity Corporation software or services. Ping Identity Corporation only offers such software or services to legal entities who have entered into a binding license agreement with Ping Identity Corporation.
 *
 * Copyright 2024-2025 Ping Identity Corporation. All Rights Reserved
-->

# PingOne Verify

**Note:** This integration is **deprecated** for AM 8.0.0+ and will no longer receive updates or new feature enhancements.

This integration provides administrators with the ability to perform secure identity verification using PingOne Verify in authentication journeys. The supported verification types include:

* Government ID
* Facial Comparison (Government ID)
* Facial Comparison (Reference Selfie)
* Liveness

[PingOne Verify Documentation](https://docs.pingidentity.com/pingone/identity_verification_using_pingone_verify/p1_verify_types_of_verification.html)

> Only the above verification types are supported at this time.

Identity Cloud provides the following artifacts to enable the PingOne Verify integration:

* [PingOne Verify Evaluation Node](https://github.com/ForgeRock/tntp-pingone-verify/blob/main/docs/Evaluation/README.md)
* [PingOne Verify Completion Decision Node](https://github.com/ForgeRock/tntp-pingone-verify/blob/main/docs/CompletionDecision/README.md)
* [PingOne Identity Match Node](https://github.com/ForgeRock/tntp-pingone-verify/blob/main/docs/IdentityMatch/README.md)
* [PingOne Create User Node](https://github.com/ForgeRock/tntp-pingone-verify/blob/main/docs/CreateUser/README.md)
* [PingOne Delete User Node](https://github.com/ForgeRock/tntp-pingone-verify/blob/main/docs/DeleteUser/README.md)

You must set up the following before using these nodes:

* [Create a verify policy](https://docs.pingidentity.com/r/en-us/pingone/pingone_creating_verify_policy)
* [Create a worker application](https://docs.pingidentity.com/r/en-us/pingone/p1_add_app_worker)

  * Requires the [Identity Data Admin](https://apidocs.pingidentity.com/pingone/platform/v1/api/#roles) role
* [PingOne Service](https://github.com/ForgeRock/tntp-ping-service/)

<!-- SUPPORT -->

## Support

If you encounter any issues, be sure to check our **[Troubleshooting](https://backstage.forgerock.com/knowledge/kb/article/a68547609)** pages.

Support tickets can be raised whenever you need our assistance; here are some examples of when it is appropriate to open a ticket (but not limited to):

* Suspected bugs or problems with Ping Identity software.
* Requests for assistance

You can raise a ticket using **[BackStage](https://backstage.forgerock.com/support/tickets)**, our customer support portal that provides one stop access to Ping Identity services.

BackStage shows all currently open support tickets and allows you to raise a new one by clicking **New Ticket**.

<!-- COLLABORATION -->

## Contributing

This Ping Identity project does not accept third-party code submissions.

<!------------------------------------------------------------------------------------------------------------------------------------>

<!-- LEGAL -->

## Disclaimer

> **This code is provided by Ping Identity on an “as is” basis, without warranty of any kind, to the fullest extent permitted by law.
> Ping Identity does not represent or warrant or make any guarantee regarding the use of this code or the accuracy,
> timeliness or completeness of any data or information relating to this code, and Ping Identity hereby disclaims all warranties whether express,
> or implied or statutory, including without limitation the implied warranties of merchantability, fitness for a particular purpose,
> and any warranty of non-infringement. Ping Identity shall not have any liability arising out of or related to any use,
> implementation or configuration of this code, including but not limited to use for any commercial purpose.
> Any action or suit relating to the use of the code may be brought only in the courts of a jurisdiction wherein
> Ping Identity resides or in which Ping Identity conducts its primary business, and under the laws of that jurisdiction excluding its conflict-of-law provisions.**

<!------------------------------------------------------------------------------------------------------------------------------------>

<!-- LICENSE - Links to the MIT LICENSE file in each repo. -->

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details

---

© Copyright 2024-2025 Ping Identity. All Rights Reserved

[pingidentity-logo]: https://www.pingidentity.com/content/dam/picr/nav/Ping-Logo-2.svg "Ping Identity Logo"
