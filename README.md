# AWS CLI Credentials - Federated Credentials Tool

This is a command line tool to inject an AWS Token into your local credentials file using STS::AssumeRoleWithSAML and a SAML assertion from your forms based identity federation portal.

This is a port of the Python script written by 'Quint Van Demen' on the AWS Security Blog.

[How to Implement a General Solution for Federated API/CLI Access Using SAML 2.0](https://aws.amazon.com/blogs/security/how-to-implement-a-general-solution-for-federated-apicli-access-using-saml-2-0/)

Validated on following OS versions:

Windows 10
macOS Sierra 10.12.6
