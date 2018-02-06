# AWS CLI with Federated Credentials - Tool

***Note: This code is explicitly written for AWS(Amazon Web Services) CLI Tool Credentials.***

This is a command line tool to inject an AWS **aws_access_key_id** and **aws_secret_access_key** into your local credentials file using STS::AssumeRoleWithSAML and a SAML assertion retrieved from your forms based identity federation provider.

This is a port of the Python script written by 'Quint Van Demen' on the AWS Security Blog.

[How to Implement a General Solution for Federated API/CLI Access Using SAML 2.0](https://aws.amazon.com/blogs/security/how-to-implement-a-general-solution-for-federated-apicli-access-using-saml-2-0/)

## Validated OS Versions

- Windows 10 (1607)
- macOS Sierra (10.12.6)

## Pre-Requisites

- AWS CLI tools installed
- Credentials file in the default location
  - macOS :: ~/.aws/
  - Windows :: %UserProfile%/.aws/
- Amend the var 'idpurl' in the code to include your identity provider URL

## Credentials File

Once to tool is executed keys are inserted into a new profile 'saml' in the credentials file.

You can leverage this profile directly by passing the `--profile saml` switch.

Alternatively you can use the `saml` profile for switch-roles. The roles can be defined in the 'config' file and leverage the 'saml' profile for authentication.

Example Switch Role:

```
[profile myprofile]
output = json
region = us-east-1
role_arn = arn:aws:iam::123456789012:role/myrole
source_profile = saml
```

[AWS IAM Documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_switch-role-console.html)
## Behind a Proxy?

If you are behind a proxy the environment variables will need to be set for both HTTP_PROXY and HTTPS_PROXY.
