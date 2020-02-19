# Custom::PrivateRootCertificate
`Custom::PrivateCertificate` manages a server certificate.

## Syntax
To declare this entity in your AWS CloudFormation template, use the following syntax:

```yaml
  Type : Custom::PrivateCertificate
  Properties: 
    CAName: String
    Hostname: String
    Wildcard: Boolean
    RefreshOnUpdate: Boolean
```

## Properties
You can specify the following properties:

    CAName - name of the root ca; can only contain letters and dashes.
    Wildcard - generate a wildcard certificate, default  False
    RefreshOnUpdate - indicates whether the root key and certificate are refreshed on update, default is False

## Return values
With 'Fn::GetAtt' the following values are available:

    CAName - of the ca
    Hostname - password
    Hash - of the public certificate
    PublicCertPEM - the public certificate of the certificate in PEM encoding, issued by the CA
